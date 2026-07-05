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
 * state (starting from {@code banking.initial_state} at every entry point / function start),
 * recognizes the {@code LDA #imm / STA $01} bank-switch idiom (generalized to STA/STX/STY of an
 * immediate value previously loaded into the corresponding register), and for every instruction
 * reference that lands in a banked window while a non-home occupant is tracked, adds an
 * explicit ANALYSIS reference into that occupant's overlay space (read/execute) or into its
 * {@code on_write} occupant's overlay space (write) -- including the "write under ROM" case
 * that applies even in the home banking state.
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

	/** Sentinel: bank state could not be determined at this point in the dataflow. */
	private static final int UNKNOWN = -1;

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
		Map<Address, Integer> stateIn = new HashMap<>();
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

		for (Address seed : seeds) {
			mergeAndEnqueue(seed, initialState, stateIn, worklist, listing);
		}

		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Address addr = worklist.poll();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			int inState = stateIn.get(addr);
			int outState = inState;

			BankSwitchResult bsr = tryComputeBankSwitch(program, instr, mechAddr, mask);
			if (bsr != null) {
				bankSwitches.put(addr, bsr);
				outState = bsr.determinable ? bsr.newState : UNKNOWN;
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
		for (Map.Entry<Address, Integer> entry : stateIn.entrySet()) {
			monitor.checkCancelled();
			Address addr = entry.getKey();
			int inState = entry.getValue();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}

			BankSwitchResult bsr = bankSwitches.get(addr);
			if (bsr != null) {
				if (bsr.determinable) {
					annotateBankSwitch(listing, addr, bsr.newState, windowsByName.keySet(),
						occupantByWindowForState.get(bsr.newState));
				}
				else {
					warnings++;
					program.getBookmarkManager()
							.setBookmark(addr, ghidra.program.model.listing.BookmarkType.WARNING,
								CATEGORY,
								"Bank state becomes unknown here: write to $" +
									Long.toHexString(mechAddrOffset) +
									" with an undeterminable value");
				}
			}

			if (inState == UNKNOWN) {
				continue;
			}
			Map<String, String> stateRow = occupantByWindowForState.get(inState);
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

	private void mergeAndEnqueue(Address addr, int newState, Map<Address, Integer> stateIn,
			Deque<Address> worklist, Listing listing) {
		if (listing.getInstructionAt(addr) == null) {
			// not (yet) disassembled / not code -- nothing to track here
			return;
		}
		Integer existing = stateIn.get(addr);
		if (existing == null) {
			stateIn.put(addr, newState);
			worklist.add(addr);
		}
		else if (existing == UNKNOWN) {
			// already at the bottom of the lattice; no new information possible
		}
		else if (existing != newState) {
			stateIn.put(addr, UNKNOWN);
			worklist.add(addr);
		}
		// else: unchanged, already processed with this exact state -- nothing to do
	}

	/**
	 * Recognizes a write to the banking mechanism address and attempts to determine the new
	 * bank state. Returns null if this instruction does not write the mechanism address at all
	 * (i.e. it is not a bank-switch instruction and the caller should leave the bank state
	 * unchanged).
	 */
	private BankSwitchResult tryComputeBankSwitch(Program program, Instruction instr,
			Address mechAddr, int mask) {
		boolean writesMechanism = false;
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(mechAddr) && ref.getReferenceType().isWrite()) {
				writesMechanism = true;
				break;
			}
		}
		if (!writesMechanism) {
			return null;
		}

		String mnem = instr.getMnemonicString().toUpperCase();
		if (!(mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY"))) {
			// INC/DEC/ASL/LSR/ROL/ROR and friends read-modify-write in place; we don't attempt
			// to track the resulting value.
			return new BankSwitchResult(false, UNKNOWN);
		}

		char reg = mnem.charAt(2); // 'A' | 'X' | 'Y'
		Integer imm = resolveStoredImmediate(program, instr, reg);
		if (imm == null) {
			return new BankSwitchResult(false, UNKNOWN);
		}
		int newState = imm & mask;
		return new BankSwitchResult(true, newState);
	}

	/**
	 * Scans backward within the same straight-line basic block for an immediate load
	 * ({@code LDA/LDX/LDY #imm}) into the given register, aborting if the register is
	 * clobbered first or a block boundary is reached.
	 */
	private Integer resolveStoredImmediate(Program program, Instruction storeInstr, char reg) {
		Listing listing = program.getListing();
		Set<String> modifiers = registerModifiers(reg);
		String loadMnemonic = "LD" + reg;

		Instruction cur = storeInstr;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null) {
				return null;
			}
			Address prevFallThrough = prev.getFallThrough();
			if (prevFallThrough == null || !prevFallThrough.equals(cur.getMinAddress())) {
				// not a straight-line predecessor of cur -- left the basic block
				return null;
			}
			String mnem = prev.getMnemonicString().toUpperCase();
			if (mnem.equals(loadMnemonic) && isImmediate(prev)) {
				Integer imm = immediateOperandValue(prev);
				if (imm == null) {
					return null;
				}
				return imm & 0xFF;
			}
			if (modifiers.contains(mnem)) {
				return null; // register clobbered before we found the immediate load
			}
			cur = prev;
		}
		return null;
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

	private void annotateBankSwitch(Listing listing, Address addr, int newState,
			Set<String> windowNames, Map<String, String> stateRow) {
		String desc = describeState(windowNames, stateRow);
		String bankComment = "bank -> " + newState + " (" + desc + ")";
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

	private record BankSwitchResult(boolean determinable, int newState) {}
}
