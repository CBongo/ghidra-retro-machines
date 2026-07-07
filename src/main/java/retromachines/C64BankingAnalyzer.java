/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retromachines;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * "Phase 0" bank-aware analyzer for the Commodore 64 PRG loader.
 * <p>
 * Ghidra's default reference resolution only ever targets the BASE address space, but this
 * loader ({@link C64PrgLoader}) lays the C64's banked memory out "home-in-base": the occupant
 * selected by {@code banking.initial_state} lives directly in the base space, while every
 * alternate occupant of a banked window ({@code RAM_A000}, {@code RAM_D000}, {@code CHARGEN},
 * {@code RAM_E000}) lives in its own OVERLAY address space (same name as the occupant). Code
 * that switches banks and then accesses a banked window is, by default, shown referencing the
 * wrong occupant whenever the tracked bank state differs from the state active at load time.
 * <p>
 * This analyzer performs a simple forward dataflow over instructions to track the banking
 * state (starting from {@code banking.initial_state} at every entry point / function start).
 * Unlike a naive single-value tracker, the state is tracked <b>per bit</b> ({@link PortState}):
 * bit {@code b} of the port is either known (with a value) or unknown, independently of the other
 * tracked bits. This is essential because the two idioms real 6502 code actually uses to switch
 * banks both read the port's current value through a register before writing it back:
 * <pre>
 *     LDA $01 / AND #$F8 / ORA #$05 / STA $01   ; set bank 5, preserving cassette-motor bits
 *     LDA $01 / AND #$FE / STA $01              ; clear LORAM only ("BASIC off")
 * </pre>
 * A whole-value tracker must treat the {@code LDA $01} as poisoning the entire result (the byte
 * read from memory is not statically known); the per-bit model instead lets the {@code AND}/
 * {@code ORA} immediates settle some or all bits on their own, and -- when a bit isn't settled by
 * the mask algebra -- lets it fall back to whatever this same dataflow already knows about that
 * bit at the point of the read (see {@link #resolveStoredValue}). Bank-switch stores (STA/STX/STY
 * of the mechanism register) are resolved with a backward, bit-accumulator ("mask algebra") scan
 * that composes {@code AND #imm} / {@code ORA #imm} against either an immediate load of the same
 * register or a load of the mechanism address itself (using the in-state tracked at the store).
 * The forward dataflow's merge at control-flow joins keeps a bit known only when both predecessors
 * agree on it, so {@code knownMask} only ever shrinks -- the fixpoint still terminates.
 * <p>
 * When retargeting references, any bit left unknown by the tracked {@link PortState} is assumed
 * to hold its {@code banking.initial_state} value (see {@link #effectiveState}); this degrades
 * gracefully to today's behavior when nothing at all is known, and only actually matters when a
 * store leaves some -- but not all -- bits determined. For every instruction reference that lands
 * in a banked window under the resulting effective state, adds an explicit ANALYSIS reference into
 * that occupant's overlay space (read/execute) or into its {@code on_write} occupant's overlay
 * space (write) -- including the "write under ROM" case that applies even in the home banking
 * state.
 * <p>
 * All C64-specific facts (windows, occupants, banking states, the {@code banking.mechanism}
 * register-write description) come from the bundled {@code machines/c64.map} JSON descriptor,
 * loaded the same way {@link C64PrgLoader#loadMap()} does -- nothing about the C64 memory map
 * is hardcoded here beyond the descriptor's schema.
 */
public class C64BankingAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C64 Bank State";
	private static final String DESCRIPTION =
		"Tracks the C64 CPU port ($01) banking state along control flow and retargets " +
			"references into banked windows (RAM_A000/RAM_D000/CHARGEN/RAM_E000 overlays) " +
			"so they point at the occupant actually being read, written (including write-under-" +
			"ROM), or executed -- not just whatever the loader put in the base address space.";

	private static final String MAP_PATH = "machines/c64.map";
	private static final String CATEGORY = "C64BankingAnalyzer";

	private static final int MAX_BACKWARD_SCAN = 16;

	private static final Set<String> A_MODIFIERS = Set.of("LDA", "TXA", "TYA", "PLA", "ADC", "SBC",
		"AND", "ORA", "EOR", "ASL", "LSR", "ROL", "ROR");
	private static final Set<String> X_MODIFIERS = Set.of("LDX", "TAX", "TSX", "INX", "DEX");
	private static final Set<String> Y_MODIFIERS = Set.of("LDY", "TAY", "INY", "DEY");

	public C64BankingAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after Ghidra's own reference analysis has laid down the default (base-space)
		// operand/flow references we need to inspect and, where wrong, supersede.
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Gate on the loader that produced this program: only C64 PRG imports lay out memory
		// "home-in-base" the way this analyzer assumes. AbstractProgramLoader stamps the
		// program's executable-format property with the Loader's own getName().
		String format = program.getExecutableFormat();
		return format != null && format.equals(new C64PrgLoader().getName());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		log.appendMsg(NAME, "C64BankingAnalyzer running");

		JsonObject map;
		try {
			map = loadMap();
		}
		catch (IOException e) {
			log.appendMsg(NAME, "Failed to load machines/c64.map: " + e.getMessage());
			return false;
		}

		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("mechanism")) {
			log.appendMsg(NAME,
				"banking.mechanism missing from machines/c64.map; skipping bank-state analysis");
			return true;
		}

		int initialState = banking.get("initial_state").getAsInt();
		JsonObject mechanism = banking.getAsJsonObject("mechanism");
		long mechAddrOffset = mechanism.get("address").getAsLong();
		int mask = mechanism.get("mask").getAsInt();

		List<String> stateBitNames = new ArrayList<>();
		if (banking.has("state_bits")) {
			for (JsonElement be : banking.getAsJsonArray("state_bits")) {
				stateBitNames.add(be.getAsString());
			}
		}

		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address mechAddr = baseSpace.getAddress(mechAddrOffset);

		// --- Parse windows + banking states ---
		Map<String, WindowModel> windowsByName = new LinkedHashMap<>();
		for (JsonElement we : map.getAsJsonArray("windows")) {
			JsonObject window = we.getAsJsonObject();
			String name = window.get("name").getAsString();
			long start = window.get("start").getAsLong();
			long end = window.get("end").getAsLong();
			Map<String, OccupantModel> occupants = new LinkedHashMap<>();
			for (JsonElement oe : window.getAsJsonArray("occupants")) {
				JsonObject occ = oe.getAsJsonObject();
				String occName = occ.get("name").getAsString();
				String kind = occ.get("kind").getAsString();
				String onWrite = occ.has("on_write") ? occ.get("on_write").getAsString() : null;
				occupants.put(occName, new OccupantModel(occName, kind, onWrite));
			}
			windowsByName.put(name, new WindowModel(name, start, end, occupants));
		}

		Map<Integer, Map<String, String>> occupantByWindowForState = new LinkedHashMap<>();
		for (JsonElement se : banking.getAsJsonArray("states")) {
			JsonObject state = se.getAsJsonObject();
			int value = state.get("value").getAsInt();
			Map<String, String> row = new LinkedHashMap<>();
			for (String windowName : windowsByName.keySet()) {
				if (state.has(windowName)) {
					row.put(windowName, state.get(windowName).getAsString());
				}
			}
			occupantByWindowForState.put(value, row);
		}

		Map<String, String> homeRow = occupantByWindowForState.get(initialState);
		if (homeRow == null) {
			log.appendMsg(NAME, "banking.initial_state " + initialState +
				" not found in banking.states; skipping bank-state analysis");
			return true;
		}
		// home occupant name per window (fixed: the occupant selected by initial_state)
		Map<String, String> homeOccupantByWindow = homeRow;

		// --- Phase 1: forward dataflow to fixpoint (bank state per instruction address) ---
		Listing listing = program.getListing();
		Map<Address, PortState> stateIn = new HashMap<>();
		Map<Address, BankSwitchResult> bankSwitches = new HashMap<>();
		Deque<Address> worklist = new ArrayDeque<>();

		Set<Address> seeds = new LinkedHashSet<>();
		AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
		while (eps.hasNext()) {
			seeds.add(eps.next());
		}
		FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
		for (ghidra.program.model.listing.Function f : funcs) {
			seeds.add(f.getEntryPoint());
		}

		PortState seedState = PortState.fullyKnown(mask, initialState);
		for (Address seed : seeds) {
			mergeAndEnqueue(seed, seedState, stateIn, worklist, listing);
		}

		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Address addr = worklist.poll();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			PortState inState = stateIn.get(addr);
			PortState outState = inState;

			BankSwitchResult bsr = tryComputeBankSwitch(program, instr, mechAddr, mask, inState);
			if (bsr != null) {
				bankSwitches.put(addr, bsr);
				outState = bsr.newState();
			}

			for (Address flow : instr.getFlows()) {
				mergeAndEnqueue(flow, outState, stateIn, worklist, listing);
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough != null) {
				mergeAndEnqueue(fallThrough, outState, stateIn, worklist, listing);
			}
		}

		// --- Phase 2: annotate bank switches + retarget references ---
		ReferenceManager refMgr = program.getReferenceManager();
		int refsAdded = 0;
		int warnings = 0;
		for (Map.Entry<Address, PortState> entry : stateIn.entrySet()) {
			monitor.checkCancelled();
			Address addr = entry.getKey();
			PortState inState = entry.getValue();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}

			BankSwitchResult bsr = bankSwitches.get(addr);
			if (bsr != null) {
				if (bsr.newState().knownMask() == 0) {
					warnings++;
					program.getBookmarkManager()
							.setBookmark(addr, ghidra.program.model.listing.BookmarkType.WARNING,
								CATEGORY,
								"Bank state becomes unknown here: write to $" +
									Long.toHexString(mechAddrOffset) +
									" with a genuinely undeterminable value (mask-algebra scan " +
									"could not pin down even one tracked bank bit -- e.g. a load " +
									"of an unrelated address followed directly by the store, with " +
									"no AND/ORA immediate to constrain it)");
				}
				else {
					annotateBankSwitch(listing, addr, bsr.newState(), initialState, mask,
						stateBitNames, windowsByName.keySet(), occupantByWindowForState);
				}
			}

			int effective = effectiveState(inState, initialState, mask);
			Map<String, String> stateRow = occupantByWindowForState.get(effective);
			if (stateRow == null) {
				continue;
			}

			refsAdded += retargetReferences(program, refMgr, baseSpace, instr, windowsByName,
				stateRow, homeOccupantByWindow, log);
		}

		log.appendMsg(NAME, "C64BankingAnalyzer: " + stateIn.size() + " instructions tracked, " +
			refsAdded + " overlay references added/confirmed, " + warnings +
			" unknown-state warnings");
		return true;
	}

	// ------------------------------------------------------------------
	// Dataflow
	// ------------------------------------------------------------------

	private void mergeAndEnqueue(Address addr, PortState incoming, Map<Address, PortState> stateIn,
			Deque<Address> worklist, Listing listing) {
		if (listing.getInstructionAt(addr) == null) {
			// not (yet) disassembled / not code -- nothing to track here
			return;
		}
		PortState existing = stateIn.get(addr);
		PortState merged = existing == null ? incoming : mergeStates(existing, incoming);
		if (existing == null || !merged.equals(existing)) {
			stateIn.put(addr, merged);
			worklist.add(addr);
		}
		// else: unchanged, already processed with this exact state -- nothing to do
	}

	/**
	 * Joins two {@link PortState}s at a control-flow merge point: a bit is known in the result
	 * only if it is known -- and agrees -- in both inputs. This is monotone ({@code knownMask}
	 * only ever shrinks as more predecessors are merged in), so the worklist fixpoint still
	 * terminates.
	 */
	private static PortState mergeStates(PortState a, PortState b) {
		int agree = ~(a.bits() ^ b.bits());
		int knownMask = a.knownMask() & b.knownMask() & agree;
		int bits = a.bits() & knownMask;
		return new PortState(knownMask, bits);
	}

	/**
	 * Recognizes a write to the banking mechanism address and attempts to determine the new
	 * bank state. Returns null if this instruction does not write the mechanism address at all
	 * (i.e. it is not a bank-switch instruction and the caller should leave the bank state
	 * unchanged).
	 */
	private BankSwitchResult tryComputeBankSwitch(Program program, Instruction instr,
			Address mechAddr, int mask, PortState inState) {
		if (!writesAddress(instr, mechAddr)) {
			return null;
		}

		String mnem = instr.getMnemonicString().toUpperCase();
		if (!(mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY"))) {
			// INC/DEC/ASL/LSR/ROL/ROR and friends read-modify-write in place; we don't attempt
			// to track the resulting value.
			return new BankSwitchResult(PortState.unknown());
		}

		char reg = mnem.charAt(2); // 'A' | 'X' | 'Y'
		PortState newState = resolveStoredValue(program, instr, reg, mask, mechAddr, inState);
		return new BankSwitchResult(newState);
	}

	/**
	 * Scans backward within the same straight-line basic block to determine the {@link PortState}
	 * stored by {@code storeInstr} into the banking mechanism register, using bit-accumulator
	 * ("mask algebra") composition so that the very common bit-preserving idiom
	 * <pre>
	 *     LDA $01      ; read port (other bits must be preserved)
	 *     AND #$F8     ; clear bank bits
	 *     ORA #$05     ; set new bank state
	 *     STA $01
	 * </pre>
	 * resolves to a fully known state even though the initial {@code LDA $01} reads a value this
	 * analyzer cannot know statically -- because the subsequent {@code AND} clears exactly the
	 * bits the {@code ORA} then sets, the base value's bits never actually reach the store. When
	 * the AND/ORA pair does <em>not</em> pin down every bit, the base value -- if it comes from
	 * re-reading the mechanism address itself -- falls back to whatever this dataflow already
	 * knows about the port at that point ({@code inStateAtStore}), so idioms like
	 * {@code LDA $01 / AND #$FE / STA $01} (clear one bit, preserve the rest) still resolve any
	 * bits that were already known in-state.
	 * <p>
	 * Walking backward from the store, we maintain {@code (aAcc, oAcc)} such that the value
	 * eventually stored equals {@code (x & aAcc) | oAcc}, where {@code x} is the register's value
	 * before the earliest instruction examined so far. The accumulator is seeded to the identity
	 * transform {@code aAcc = 0xFF, oAcc = 0x00}. Stepping back over:
	 * <ul>
	 * <li>{@code AND #imm} (register A only) composes {@code aAcc = imm & aAcc}.</li>
	 * <li>{@code ORA #imm} (register A only) composes {@code oAcc = (imm & aAcc) | oAcc}.</li>
	 * <li>{@code LDA/LDX/LDY #imm} into the matching register fully resolves {@code x}, so the
	 * scan folds it through the accumulator and stops.</li>
	 * <li>{@code LDA/LDX/LDY} of the mechanism address itself resolves {@code x} to
	 * {@code inStateAtStore} (per-bit, possibly partial), folds it through the accumulator, and
	 * stops.</li>
	 * <li>Any other instruction that modifies the register (transfers, ADC/SBC, shifts, INC/DEC,
	 * EOR#imm -- deliberately not modeled bit-wise here, a load of any other address, etc.) leaves
	 * {@code x} wholly unknown from that point backward, so the scan stops there.</li>
	 * <li>A write to the mechanism address encountered while scanning backward -- by any of
	 * STA/STX/STY, regardless of which register the current scan is tracking -- means the port
	 * changed mid-chain: whatever {@code x} a further-back load would read predates that
	 * intervening write, so it would be unsound to fall back to {@code inStateAtStore} (which
	 * reflects state <em>after</em> it). The scan aborts to a wholly-unknown base immediately.</li>
	 * <li>Instructions that don't touch the register are skipped.</li>
	 * </ul>
	 * After every composition step (and at every point {@code x} becomes available, known or not)
	 * we fold the base in via {@link #combine} to produce the resulting {@link PortState}; as an
	 * optimization, we eagerly check {@link #fullyDeterminedByAccumulator} after each AND/ORA
	 * composition so we can return without ever inspecting the base when the mask algebra alone
	 * already pins down every tracked bit (e.g. {@code AND #$F8 / ORA #$05} above).
	 * <p>
	 * 6502 has no immediate AND/ORA addressing the X or Y registers, so the mask-algebra
	 * composition only ever applies when {@code reg == 'A'}; the X/Y paths retain the simpler
	 * "immediate load, mechanism-address load, or wholly unknown" behavior.
	 *
	 * @return the resulting {@link PortState}, reduced to {@code mask}; never {@code null} --
	 *         complete non-determination is represented by {@link PortState#unknown()}
	 */
	private PortState resolveStoredValue(Program program, Instruction storeInstr, char reg,
			int mask, Address mechAddr, PortState inStateAtStore) {
		Listing listing = program.getListing();
		Set<String> modifiers = registerModifiers(reg);
		String loadMnemonic = "LD" + reg;

		int aAcc = 0xFF;
		int oAcc = 0x00;

		Instruction cur = storeInstr;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null) {
				return combine(aAcc, oAcc, mask, PortState.unknown());
			}
			Address prevFallThrough = prev.getFallThrough();
			if (prevFallThrough == null || !prevFallThrough.equals(cur.getMinAddress())) {
				// not a straight-line predecessor of cur -- left the basic block
				return combine(aAcc, oAcc, mask, PortState.unknown());
			}

			if (writesAddress(prev, mechAddr)) {
				// the port was written mid-chain; a base value read further back would predate
				// that write, so it's unsound to fall back to inStateAtStore for it.
				return combine(aAcc, oAcc, mask, PortState.unknown());
			}

			String mnem = prev.getMnemonicString().toUpperCase();

			if (reg == 'A' && mnem.equals("AND")) {
				Integer imm = isImmediate(prev) ? immediateOperandValue(prev) : null;
				if (imm == null) {
					// non-immediate AND (or an operand we couldn't pull a scalar out of) is an
					// opaque modifier of A -- the base value is unknown from here backward.
					return combine(aAcc, oAcc, mask, PortState.unknown());
				}
				aAcc = imm & aAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return combine(aAcc, oAcc, mask, PortState.unknown());
				}
				cur = prev;
				continue;
			}

			if (reg == 'A' && mnem.equals("ORA")) {
				Integer imm = isImmediate(prev) ? immediateOperandValue(prev) : null;
				if (imm == null) {
					return combine(aAcc, oAcc, mask, PortState.unknown());
				}
				oAcc = (imm & aAcc) | oAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return combine(aAcc, oAcc, mask, PortState.unknown());
				}
				cur = prev;
				continue;
			}

			if (mnem.equals(loadMnemonic) && isImmediate(prev)) {
				Integer imm = immediateOperandValue(prev);
				if (imm != null) {
					// x is now fully known -- fold it through the accumulated transform.
					return combine(aAcc, oAcc, mask, PortState.fullyKnown(0xFF, imm));
				}
				// Scalar extraction failed; fall through and treat like any other modifier.
			}

			if (mnem.equals(loadMnemonic) && readsAddress(prev, mechAddr)) {
				// x is the port's value as tracked in-state at our own store -- possibly partial.
				return combine(aAcc, oAcc, mask, inStateAtStore);
			}

			if (modifiers.contains(mnem)) {
				// Register modified by something we don't model bit-wise (transfers, ADC/SBC,
				// shifts, INC/DEC, EOR#imm, a load of an unrelated address, or a failed immediate
				// load above): x is wholly unknown from here backward.
				return combine(aAcc, oAcc, mask, PortState.unknown());
			}
			if (prev.getFlowType().isCall()) {
				// A subroutine call may clobber any register; its fall-through satisfies the
				// block-linkage check above, so it must be treated as a clobber explicitly.
				return combine(aAcc, oAcc, mask, PortState.unknown());
			}
			cur = prev;
		}
		return combine(aAcc, oAcc, mask, PortState.unknown());
	}

	/**
	 * Checks whether every bit of {@code mask} is already determined by the accumulator alone,
	 * independent of whatever base register value {@code x} the scan eventually finds, given the
	 * accumulated transform {@code result = (x & aAcc) | oAcc}. Bit {@code b} is so determined
	 * iff {@code aAcc} clears it (so {@code (x & aAcc)} contributes 0 there regardless of
	 * {@code x}) or {@code oAcc} sets it (so the OR forces the result bit to 1 regardless of
	 * {@code x}). Used purely as an early-exit optimization in {@link #resolveStoredValue}; when
	 * this returns {@code true}, {@link #combine} with any base yields the same result.
	 */
	private static boolean fullyDeterminedByAccumulator(int aAcc, int oAcc, int mask) {
		for (int bit = 0; bit < 8; bit++) {
			int bitMask = 1 << bit;
			if ((mask & bitMask) == 0) {
				continue; // not part of the tracked bank-state bits
			}
			boolean aClearsIt = (aAcc & bitMask) == 0;
			boolean oSetsIt = (oAcc & bitMask) != 0;
			if (!aClearsIt && !oSetsIt) {
				return false; // this mask bit still depends on the base value
			}
		}
		return true;
	}

	/**
	 * Folds the accumulated mask-algebra transform {@code result = (x & aAcc) | oAcc} against a
	 * (possibly partially known) base {@link PortState} for {@code x}, producing the resulting
	 * per-bit {@link PortState} for {@code result}, reduced to {@code mask}. For each tracked bit:
	 * {@code oAcc} setting it forces a known 1 (regardless of {@code x}); otherwise {@code aAcc}
	 * clearing it forces a known 0 (regardless of {@code x}); otherwise the bit passes {@code x}
	 * through unchanged, so it is known in the result iff it is known in {@code base} (with the
	 * same value).
	 */
	private static PortState combine(int aAcc, int oAcc, int mask, PortState base) {
		int knownMask = 0;
		int bits = 0;
		for (int bit = 0; bit < 8; bit++) {
			int bitMask = 1 << bit;
			if ((mask & bitMask) == 0) {
				continue;
			}
			if ((oAcc & bitMask) != 0) {
				knownMask |= bitMask;
				bits |= bitMask;
			}
			else if ((aAcc & bitMask) == 0) {
				knownMask |= bitMask;
			}
			else if ((base.knownMask() & bitMask) != 0) {
				knownMask |= bitMask;
				if ((base.bits() & bitMask) != 0) {
					bits |= bitMask;
				}
			}
		}
		return new PortState(knownMask, bits);
	}

	/**
	 * Computes the effective bank state used for reference retargeting and bank-switch comments:
	 * bits known in {@code state} keep their tracked value; any bit left unknown is assumed to
	 * hold its {@code banking.initial_state} value. This degrades gracefully -- a fully known
	 * state is unaffected, and a wholly unknown state (all bits unknown) falls back entirely to
	 * the initial state, matching this analyzer's pre-{@link PortState} seed behavior.
	 */
	private static int effectiveState(PortState state, int initialState, int mask) {
		return (state.bits() & state.knownMask()) | (initialState & ~state.knownMask() & mask);
	}

	private static boolean writesAddress(Instruction instr, Address addr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(addr) && ref.getReferenceType().isWrite()) {
				return true;
			}
		}
		return false;
	}

	private static boolean readsAddress(Instruction instr, Address addr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(addr) && ref.getReferenceType().isRead()) {
				return true;
			}
		}
		return false;
	}

	private static Set<String> registerModifiers(char reg) {
		return switch (reg) {
			case 'A' -> A_MODIFIERS;
			case 'X' -> X_MODIFIERS;
			case 'Y' -> Y_MODIFIERS;
			default -> Set.of();
		};
	}

	private static boolean isImmediate(Instruction instr) {
		String rep = instr.getDefaultOperandRepresentation(0);
		return rep != null && rep.startsWith("#");
	}

	/**
	 * Extracts the constant value of an immediate operand (e.g. the {@code $35} in
	 * {@code LDA #$35}). {@link ghidra.program.model.listing.CodeUnit#getScalar} only resolves
	 * scalars used as addressing components (offsets/displacements), not bare immediate
	 * operands, so we pull the {@link Scalar} directly out of the operand's object list instead.
	 */
	private static Integer immediateOperandValue(Instruction instr) {
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Scalar s) {
				return (int) s.getUnsignedValue();
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Annotation
	// ------------------------------------------------------------------

	/**
	 * Annotates a resolved bank-switch store with an EOL comment. When {@code newState} is fully
	 * known ({@code knownMask == mask}), the comment matches the pre-{@link PortState} format:
	 * {@code bank -> 5 (RAM_A000/IO/RAM_E000)}. When only some bits are known, the comment marks
	 * the effective state with a trailing {@code ?} and spells out, by {@code banking.state_bits}
	 * name, which bits are actually known (with their resolved value) versus merely assumed from
	 * {@code banking.initial_state} -- e.g.
	 * {@code bank -> 7? (BASIC/IO/KERNAL) [known: LORAM=1; assumed from initial: HIRAM,CHAREN]}.
	 */
	private void annotateBankSwitch(Listing listing, Address addr, PortState newState,
			int initialState, int mask, List<String> stateBitNames, Set<String> windowNames,
			Map<Integer, Map<String, String>> occupantByWindowForState) {
		int effective = effectiveState(newState, initialState, mask);
		Map<String, String> stateRow = occupantByWindowForState.get(effective);
		String desc = describeState(windowNames, stateRow);

		String bankComment;
		if (newState.knownMask() == mask) {
			bankComment = "bank -> " + effective + " (" + desc + ")";
		}
		else {
			List<String> known = new ArrayList<>();
			List<String> assumed = new ArrayList<>();
			for (int bit = 0; bit < 8; bit++) {
				int bitMask = 1 << bit;
				if ((mask & bitMask) == 0) {
					continue;
				}
				String name = bit < stateBitNames.size() ? stateBitNames.get(bit)
						: ("bit" + bit);
				if ((newState.knownMask() & bitMask) != 0) {
					known.add(name + "=" + ((newState.bits() & bitMask) != 0 ? 1 : 0));
				}
				else {
					assumed.add(name);
				}
			}
			bankComment = "bank -> " + effective + "? (" + desc + ") [known: " +
				String.join(",", known) + "; assumed from initial: " + String.join(",", assumed) +
				"]";
		}

		String existing = listing.getComment(CommentType.EOL, addr);
		if (existing == null || existing.isBlank()) {
			listing.setComment(addr, CommentType.EOL, bankComment);
		}
		else if (!existing.contains("bank ->")) {
			listing.setComment(addr, CommentType.EOL, existing + "; " + bankComment);
		}
	}

	private static String describeState(Set<String> windowNames, Map<String, String> stateRow) {
		if (stateRow == null) {
			return "?";
		}
		List<String> parts = new ArrayList<>();
		for (String windowName : windowNames) {
			parts.add(stateRow.getOrDefault(windowName, "?"));
		}
		return String.join("/", parts);
	}

	// ------------------------------------------------------------------
	// Reference retargeting
	// ------------------------------------------------------------------

	private int retargetReferences(Program program, ReferenceManager refMgr,
			AddressSpace baseSpace, Instruction instr, Map<String, WindowModel> windowsByName,
			Map<String, String> stateRow, Map<String, String> homeOccupantByWindow,
			MessageLog log) {

		int added = 0;
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (!to.getAddressSpace().equals(baseSpace)) {
				continue;
			}
			long offset = to.getOffset();

			WindowModel window = findWindow(windowsByName, offset);
			if (window == null) {
				continue;
			}
			String occupantName = stateRow.get(window.name);
			if (occupantName == null) {
				continue;
			}
			OccupantModel occupant = window.occupants.get(occupantName);
			if (occupant == null) {
				continue;
			}

			RefType refType = ref.getReferenceType();
			String targetOccupant;
			if (refType.isWrite()) {
				targetOccupant = occupant.onWrite != null ? occupant.onWrite : occupantName;
			}
			else {
				targetOccupant = occupantName;
			}

			String homeOccupant = homeOccupantByWindow.get(window.name);
			if (targetOccupant.equals(homeOccupant)) {
				// resolves to the home occupant, which already lives in base space at this
				// offset -- the default reference the reference analyzer laid down is correct.
				continue;
			}

			AddressSpace overlaySpace = program.getAddressFactory().getAddressSpace(targetOccupant);
			if (overlaySpace == null) {
				log.appendMsg(NAME, "No overlay address space named '" + targetOccupant +
					"' for window '" + window.name + "'; cannot retarget reference from " +
					instr.getMinAddress());
				continue;
			}
			Address overlayAddr = overlaySpace.getAddress(offset);

			int opIndex = ref.getOperandIndex();
			Reference existingAnalysisRef = null;
			for (Reference r : refMgr.getReferencesFrom(instr.getMinAddress(), opIndex)) {
				if (r.getToAddress().equals(overlayAddr)) {
					existingAnalysisRef = r;
					break;
				}
			}
			Reference newRef = existingAnalysisRef != null ? existingAnalysisRef
					: refMgr.addMemoryReference(instr.getMinAddress(), overlayAddr, refType,
						SourceType.ANALYSIS, opIndex);
			refMgr.setPrimary(newRef, true);
			added++;
		}
		return added;
	}

	private static WindowModel findWindow(Map<String, WindowModel> windowsByName, long offset) {
		for (WindowModel w : windowsByName.values()) {
			if (offset >= w.start && offset <= w.end) {
				return w;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Descriptor loading
	// ------------------------------------------------------------------

	private static JsonObject loadMap() throws IOException {
		ResourceFile mapFile = Application.findDataFileInAnyModule(MAP_PATH);
		if (mapFile == null) {
			throw new IOException("Could not find bundled data file " + MAP_PATH);
		}
		try (InputStreamReader reader =
				new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	// ------------------------------------------------------------------
	// Descriptor model
	// ------------------------------------------------------------------

	private record OccupantModel(String name, String kind, String onWrite) {}

	private record WindowModel(String name, long start, long end,
			Map<String, OccupantModel> occupants) {}

	private record BankSwitchResult(PortState newState) {}

	/**
	 * Per-bit knowledge of the banking port: bit {@code b} of {@code bits} is meaningful iff bit
	 * {@code b} of {@code knownMask} is set. Only bits within {@code mechanism.mask} are ever
	 * tracked (every {@code PortState} in this analyzer is constructed already reduced to that
	 * mask). {@code knownMask == 0} is the bottom of the lattice ("nothing known"); the dataflow
	 * merge at control-flow joins ({@link #mergeStates}) only ever shrinks {@code knownMask}, so
	 * the worklist fixpoint still terminates.
	 */
	private record PortState(int knownMask, int bits) {

		private static final PortState BOTTOM = new PortState(0, 0);

		static PortState unknown() {
			return BOTTOM;
		}

		static PortState fullyKnown(int mask, int value) {
			return new PortState(mask, value & mask);
		}
	}
}
