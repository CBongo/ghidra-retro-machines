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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import com.google.gson.JsonObject;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import retromachines.BankStrategyRegistry.ConfiguredMechanism;
import retromachines.BoardDescriptorModel.BoardModel;

/**
 * The extension-side stand-in for gib.2's context-aware address resolution
 * ({@code docs/rfc-banked-memory.md}): Ghidra resolves an operand statically, to one address,
 * and never consults which bank is switched in at the instruction using it. This asks that
 * question for one use site: "under the bank state that provably holds HERE, which memory does
 * this address reach?"
 *
 * <p>It is usable at ANY analysis priority. It does not read {@link BoardBankAnalyzer}'s
 * dataflow results (which exist only after that analyzer has run) and instead rebuilds the
 * board model, mechanisms and bank universe from the program's own descriptor, exactly as
 * {@code BoardBankAnalyzer.added} does, then answers each query with a LOCAL straight-line
 * simulation (see {@link #stateBefore}). That is deliberately weaker than the whole-program
 * fixpoint: it proves a state only along an unbroken fall-through run, and otherwise says
 * "unknown", which every caller must treat as "no opinion".
 *
 * <p>Built per program by {@link #forProgram}, which returns {@code null} for a program that is
 * not a banked-board import.
 */
final class BankContext {

	/** Most instructions {@link #stateBefore} walks back over. */
	static final int MAX_WALK = 64;

	/**
	 * Per-program cache; the context depends only on the descriptor and the loaded banks.
	 * <b>The values are held WEAKLY on purpose.</b> A context cannot avoid referencing its
	 * Program: the configured strategies snapshot {@code MemoryBlock}s at {@code configure} time
	 * (e.g. {@link MemoryLatchBankSwitchStrategy}), and those are database objects. A strongly
	 * held value in a {@link WeakHashMap} that reaches its own key pins the key forever, which
	 * would keep every program of a batched headless JVM alive. With a weak value the entry
	 * lives only while some caller holds the context (the jump-table analyzer holds one across
	 * a pass) and is simply rebuilt otherwise. The reference is to the context itself, not to a
	 * wrapper callers never see: until grm-uv3l it held an {@code Optional}, which nothing
	 * outside this method kept reachable, so every GC emptied the cache. A program with no
	 * context is remembered in {@link #NO_CONTEXT} instead, which references nothing of the
	 * program's.
	 */
	private static final Map<Program, java.lang.ref.WeakReference<BankContext>> CACHE =
		new WeakHashMap<>();
	private static final Map<Program, Boolean> NO_CONTEXT = new WeakHashMap<>();

	private final Program program;
	private final BoardModel board;
	private final List<ConfiguredMechanism> mechanisms;
	private final Map<String, Set<Integer>> bankUniverse;
	private final Map<String, Integer> placementOverride;
	private final BankState walkSeed;

	private BankContext(Program program, BoardModel board, List<ConfiguredMechanism> mechanisms,
			Map<String, Set<Integer>> bankUniverse, Map<String, Integer> placementOverride,
			BankState walkSeed) {
		this.program = program;
		this.board = board;
		this.mechanisms = mechanisms;
		this.bankUniverse = bankUniverse;
		this.placementOverride = placementOverride;
		this.walkSeed = walkSeed;
	}

	/** The board, bank universe and placement override, in the form the dataflow guards take. */
	HelperDiscovery.BankResolution resolution() {
		return new HelperDiscovery.BankResolution(board, bankUniverse, placementOverride);
	}

	/**
	 * The context for {@code program}, or {@code null} when it is not a banked-board import (no
	 * banking analyzer's loader gate accepts it, it has no descriptor, or no usable mechanism).
	 */
	static BankContext forProgram(Program program) {
		synchronized (CACHE) {
			if (NO_CONTEXT.containsKey(program)) {
				return null;
			}
			java.lang.ref.WeakReference<BankContext> ref = CACHE.get(program);
			BankContext cached = ref == null ? null : ref.get();
			if (cached == null) {
				cached = build(program);
				if (cached == null) {
					NO_CONTEXT.put(program, Boolean.TRUE);
				}
				else {
					CACHE.put(program, new java.lang.ref.WeakReference<>(cached));
				}
			}
			return cached;
		}
	}

	private static BankContext build(Program program) {
		// The same loader gate and map path the analyzers use; each is the authority on its own.
		BoardBankAnalyzer analyzer = null;
		for (BoardBankAnalyzer candidate : List.<BoardBankAnalyzer>of(new NesBankingAnalyzer(),
			new C64BankingAnalyzer())) {
			if (candidate.canAnalyze(program)) {
				analyzer = candidate;
				break;
			}
		}
		if (analyzer == null) {
			return null;
		}
		String mapPath = analyzer.getMapPath(program);
		if (mapPath == null) {
			return null;
		}
		MessageLog log = new MessageLog();
		JsonObject map;
		try {
			map = DescriptorResources.loadMap(mapPath);
		}
		catch (IOException e) {
			return null;
		}
		BoardModel board = BoardModel.parse(map, log, analyzer.getName(), mapPath,
			DescriptorHints.readResolvedInitialState(program), DescriptorHints.readLayoutMode(program));
		if (board == null) {
			return null;
		}
		Map<String, Integer> placementOverride =
			BankAnnotationAdapter.readPlacementOverride(analyzer, program, log);
		JsonObject banking = map.getAsJsonObject("banking");
		List<ConfiguredMechanism> mechanisms = BankStrategyRegistry.configureStrategies(analyzer,
			program, banking.getAsJsonArray("mechanisms"), board, log);
		if (mechanisms.isEmpty()) {
			return null;
		}
		return new BankContext(program, board, mechanisms,
			BankAnnotationAdapter.bankUniverse(program, board), placementOverride,
			walkSeed(program, board));
	}

	/**
	 * What every local walk may assume before its first instruction (grm-vk15): the fields a game
	 * descriptor's {@code banking.fixed_after_init} declares never change after init, at their
	 * initial value (the same bits {@link BankDataflowEngine} seeds asynchronous entries with),
	 * and the layout-mode field at the mode the loader KNEW for this image
	 * ({@link DescriptorHints#LAYOUT_MODE_PROPERTY}). A program imported with a known mode has
	 * only that mode's windows, so no other mode is representable here anyway. Without the mode,
	 * no address in a mode-planned window ever resolves from a local walk: cv3's IRQ never sees
	 * the {@code $5100} write RESET made.
	 */
	private static BankState walkSeed(Program program, BoardModel board) {
		int known = DescriptorHints.readFixedAfterInitMask(program) & board.mask();
		int bits = board.initialState() & known;
		Integer mode = DescriptorHints.readLayoutMode(program);
		if (mode != null && board.modeField() != null) {
			int m = board.modeField().positionedMask() & board.mask();
			known |= m;
			bits = (bits & ~m) | ((mode << board.modeField().lsb()) & m);
		}
		return new BankState(known, bits);
	}

	/**
	 * The bank state provably in force just before {@code use} executes, from a local
	 * straight-line walk: back through fall-through predecessors, stopping at a function entry,
	 * at an instruction with any incoming non-fall-through flow (a join), after a call, or after
	 * {@link #MAX_WALK} instructions. A run that stops at a call to a leaf switch helper continues
	 * from the state that helper leaves ({@link #stateAfterLeafCall}, grm-vk15). Otherwise the
	 * state is seeded from {@link #walkSeed} (fixed-after-init fields and the loader-known layout
	 * mode) and the residence the run's first instruction implies (code in overlay
	 * {@code WINDOW_B<n>} runs only while the field is n;
	 * {@link BankDataflowEngine#clampToResidence}), then each instruction before {@code use} is
	 * applied through the board's mechanisms. Bits nothing proved stay unknown.
	 */
	BankState stateBefore(Instruction use) {
		return stateBefore(use, MAX_CALL_STEPS);
	}

	/**
	 * How many calls {@link #stateBefore} may step back over (grm-vk15). Each step is one more
	 * straight-line run, so this also bounds the walk to {@code (MAX_CALL_STEPS + 1) * MAX_WALK}.
	 */
	static final int MAX_CALL_STEPS = 2;

	private BankState stateBefore(Instruction use, int callSteps) {
		List<Instruction> run = straightLineRun(use);
		BankState state = null;
		if (callSteps > 0) {
			// grm-vk15: a run that starts right after a call to a LEAF switch helper (cv3's IRQ:
			// LDA #$82 / JSR $e2e8, where e2e8 is STA $5115 / RTS) inherits the state the helper
			// leaves, instead of knowing nothing.
			state = stateAfterLeafCall(run.get(0), callSteps - 1);
		}
		if (state == null) {
			state = BankDataflowEngine.clampToResidence(run.get(0).getMinAddress(), walkSeed,
				board, new HashMap<>());
		}
		for (Instruction step : run.subList(0, run.size() - 1)) {
			state = BankDataflowEngine.applyDirectSwitch(program, step, state, mechanisms);
		}
		return state;
	}

	/**
	 * The bank state just after the call that falls into {@code head}, when that call goes to a
	 * LEAF helper: one straight-line run from its entry to an {@code RTS}, with no branch, jump or
	 * call, and at most one mechanism write, which must pin the mechanism's whole field under the
	 * registers the caller's own straight-line run gives it ({@link #switchedByEntry}). A helper
	 * with no write passes the state through. {@code null} when {@code head} does not follow a
	 * direct call, or the callee is anything more than that: a helper that switches, works and
	 * restores (a far-call trampoline) must not leave its inner bank behind, so nothing longer
	 * than a leaf is trusted here. The whole-program dataflow is the place for the rest.
	 */
	private BankState stateAfterLeafCall(Instruction head, int callSteps) {
		Listing listing = program.getListing();
		if (hasIncomingNonFallThroughFlow(head)) {
			return null;
		}
		Instruction call = listing.getInstructionBefore(head.getMinAddress());
		if (call == null || !call.getFlowType().isCall() || call.getFlowType().isComputed() ||
			!head.getMinAddress().equals(call.getFallThrough())) {
			return null;
		}
		Address[] flows = call.getFlows();
		if (flows.length != 1) {
			return null;
		}
		Address entry = flows[0];
		// The callee's run: entry to RTS, straight line, at most one mechanism write.
		Address writeSite = null;
		Instruction cur = listing.getInstructionAt(entry);
		boolean returns = false;
		for (int i = 0; cur != null && i < MAX_WALK; i++) {
			for (ConfiguredMechanism cm : mechanisms) {
				if (cm.strategy().computeSwitchOutcome(program, cur, MechanismState.unknown()) != null) {
					if (writeSite != null) {
						return null; // a second write: not a plain switch helper
					}
					writeSite = cur.getMinAddress();
					break;
				}
			}
			var ft = cur.getFlowType();
			if (ft.isTerminal()) {
				returns = "RTS".equals(cur.getMnemonicString());
				break;
			}
			if (ft.isJump() || ft.isCall() || ft.isConditional() || ft.isComputed()) {
				return null;
			}
			Address next = cur.getFallThrough();
			cur = next == null ? null : listing.getInstructionAt(next);
		}
		if (!returns) {
			return null;
		}
		BankState before = stateBefore(call, callSteps);
		if (writeSite == null) {
			return before;
		}
		Map<String, Integer> regs = registersBefore(straightLineRun(call));
		EntrySwitch sw = switchedByEntry(entry, regByte(regs.get("A")), regByte(regs.get("X")),
			regByte(regs.get("Y")));
		if (sw == null || !sw.writeSite().equals(writeSite)) {
			return null;
		}
		return BankDataflowEngine.overwrite(before, sw.state(), sw.state().knownMask());
	}

	private static PartialByte regByte(Integer v) {
		return v == null ? PartialByte.unknown() : PartialByte.fullyKnown(v);
	}

	/**
	 * A, X and Y as constants just before the LAST instruction of {@code run}, from its p-code: a
	 * {@code COPY} of a constant or of another tracked register propagates, any other write to one
	 * makes it unknown. Registers only, on purpose: a helper's argument is a register, and memory
	 * stores (an interrupt handler's {@code PHA} prologue) cannot change one. (grm-vk15; the
	 * richer {@link IndirectJumpConstantPointer#walkToAddress} gives up on the first store whose
	 * address it cannot pin, which every push is.)
	 */
	private Map<String, Integer> registersBefore(List<Instruction> run) {
		Map<String, Integer> regs = new HashMap<>();
		for (Instruction step : run.subList(0, run.size() - 1)) {
			// The sleigh spec exports an immediate through a temporary (LDA #$82 is
			// "tmp = 0x82; A = tmp"), so constants are followed through unique varnodes, which
			// live only within one instruction's p-code.
			Map<Long, Integer> temps = new HashMap<>();
			for (ghidra.program.model.pcode.PcodeOp op : step.getPcode()) {
				ghidra.program.model.pcode.Varnode out = op.getOutput();
				Integer value = null;
				if (op.getOpcode() == ghidra.program.model.pcode.PcodeOp.COPY) {
					ghidra.program.model.pcode.Varnode in = op.getInput(0);
					if (in.isConstant()) {
						value = (int) (in.getOffset() & 0xff);
					}
					else if (in.isUnique()) {
						value = temps.get(in.getOffset());
					}
					else {
						String from = trackedRegister(in);
						value = from == null ? null : regs.get(from);
					}
				}
				if (out != null && out.isUnique()) {
					if (value == null) {
						temps.remove(out.getOffset());
					}
					else {
						temps.put(out.getOffset(), value);
					}
					continue;
				}
				String name = trackedRegister(out);
				if (name == null) {
					continue;
				}
				if (value == null) {
					regs.remove(name);
				}
				else {
					regs.put(name, value);
				}
			}
		}
		return regs;
	}

	/** "A", "X" or "Y" when {@code vn} is exactly that one-byte register, else null. */
	private String trackedRegister(ghidra.program.model.pcode.Varnode vn) {
		if (vn == null || !vn.isRegister() || vn.getSize() != 1) {
			return null;
		}
		ghidra.program.model.lang.Register r =
			program.getRegister(vn.getAddress(), vn.getSize());
		if (r == null) {
			return null;
		}
		String name = r.getName().toUpperCase(java.util.Locale.ROOT);
		return name.equals("A") || name.equals("X") || name.equals("Y") ? name : null;
	}

	/**
	 * The unbroken fall-through run ending at {@code use} (inclusive) that {@link #stateBefore}
	 * walks: its first element is where the walk stopped.
	 */
	List<Instruction> straightLineRun(Instruction use) {
		Listing listing = program.getListing();
		List<Instruction> run = new ArrayList<>();
		run.add(use);
		Instruction cur = use;
		while (run.size() <= MAX_WALK) {
			if (program.getFunctionManager().getFunctionAt(cur.getMinAddress()) != null ||
				hasIncomingNonFallThroughFlow(cur)) {
				break;
			}
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !FlowEdges.fallsInto(prev, cur) ||
				prev.getFlowType().isCall()) {
				break;
			}
			run.add(prev);
			cur = prev;
		}
		Collections.reverse(run);
		return run;
	}

	/**
	 * Order-independent corroboration that the switched-in bank itself agrees about a table
	 * (grm-pwuh): "does the switched-in bank's copy of this routine read an overlapping table?"
	 * At the same offsets as the straight-line run {@link #stateBefore} walked (run start up to
	 * {@code use}), the bytes of {@code space} are pseudo-disassembled -- from bytes only, never
	 * the listing, and with no listing writes -- and the base address of every indexed absolute
	 * load collected. True iff one of those bases lies in {@code [lo, hi)}. An indexed LOAD is
	 * recognised language-agnostically from the instruction's p-code: it contains a LOAD and no
	 * STORE (so {@code STA abs,X}, read-modify-write forms and indirect jumps through a table
	 * do not count), is a 3-byte instruction, and has a register and a scalar operand.
	 */
	boolean switchedInCopyReadsTableIn(Instruction use, AddressSpace space, long lo, long hi) {
		long end = use.getMinAddress().getOffset();
		List<Instruction> run = straightLineRun(use);
		Address at;
		try {
			at = space.getAddress(run.get(0).getMinAddress().getOffset());
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		if (program.getMemory().getBlock(at) == null) {
			// grm-vk15: the routine lies outside the switched window (cv3's IRQ in the fixed bank),
			// so the switch does not replace it: the bytes that run are the listing's own.
			for (Instruction step : run) {
				Long base = indexedLoadBase(step);
				if (base != null && base >= lo && base < hi) {
					return true;
				}
			}
			return false;
		}
		ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(program);
		for (int n = 0; n <= MAX_WALK && at.getOffset() <= end; n++) {
			ghidra.program.model.listing.Instruction instr;
			try {
				instr = pd.disassemble(at);
			}
			catch (Exception e) {
				return false;
			}
			if (instr == null) {
				return false;
			}
			if (instr.getLength() == 3 && instr.getNumOperands() > 0 && isPureLoad(instr)) {
				boolean indexed = false;
				Long base = null;
				for (Object o : instr.getOpObjects(0)) {
					if (o instanceof ghidra.program.model.lang.Register) {
						indexed = true;
					}
					else if (o instanceof ghidra.program.model.scalar.Scalar sc) {
						base = sc.getUnsignedValue();
					}
				}
				if (indexed && base != null && base >= lo && base < hi) {
					return true;
				}
			}
			try {
				at = at.addNoWrap(instr.getLength());
			}
			catch (AddressOverflowException e) {
				return false;
			}
		}
		return false;
	}

	/**
	 * How far the switched-in bank's copy of this routine moves the table it reads (grm-q4ga).
	 * Bank-switching trampolines are often duplicated in every bank with only the table operand
	 * changed (deadly_towers: bank 0's {@code fc2a} reads {@code LDA $8000,X}, bank 2's copy
	 * {@code LDA $8035,X}). Once the switch lands, the copy's bytes run, so its operand names the
	 * table. Walks the same straight-line run as {@link #switchedInCopyReadsTableIn}. For each
	 * listing instruction that is a 3-byte indexed pure load whose base lies in {@code [lo, hi)},
	 * it pseudo-disassembles the copy at the same offset (bytes only, no listing writes), which
	 * must be an indexed pure load as well. Returns the copy's base minus the routine's base when
	 * every such pair agrees, or null when no pair is found, a copy instruction does not match,
	 * or the pairs disagree.
	 */
	Long switchedInCopyTableShift(Instruction use, AddressSpace space, long lo, long hi) {
		ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(program);
		Long shift = null;
		for (Instruction step : straightLineRun(use)) {
			Long base = indexedLoadBase(step);
			if (base == null || base < lo || base >= hi) {
				continue;
			}
			ghidra.program.model.listing.Instruction copy;
			try {
				copy = pd.disassemble(space.getAddress(step.getMinAddress().getOffset()));
			}
			catch (Exception e) {
				return null;
			}
			Long copyBase = copy == null ? null : indexedLoadBase(copy);
			if (copyBase == null) {
				return null;
			}
			long d = copyBase - base;
			if (shift != null && shift != d) {
				return null;
			}
			shift = d;
		}
		return shift;
	}

	/** The scalar base of a 3-byte indexed pure load, or null for anything else. */
	private static Long indexedLoadBase(Instruction instr) {
		if (instr.getLength() != 3 || instr.getNumOperands() == 0 || !isPureLoad(instr)) {
			return null;
		}
		boolean indexed = false;
		Long base = null;
		for (Object o : instr.getOpObjects(0)) {
			if (o instanceof ghidra.program.model.lang.Register) {
				indexed = true;
			}
			else if (o instanceof ghidra.program.model.scalar.Scalar sc) {
				base = sc.getUnsignedValue();
			}
		}
		return indexed ? base : null;
	}

	private static boolean isPureLoad(Instruction instr) {
		boolean load = false;
		for (ghidra.program.model.pcode.PcodeOp op : instr.getPcode()) {
			if (op.getOpcode() == ghidra.program.model.pcode.PcodeOp.STORE) {
				return false;
			}
			load |= op.getOpcode() == ghidra.program.model.pcode.PcodeOp.LOAD;
		}
		return load;
	}

	private static boolean hasIncomingNonFallThroughFlow(Instruction instr) {
		ReferenceIterator refs = instr.getReferenceIteratorTo();
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The address {@code target} reaches when read by {@code use}, under {@link #stateBefore}:
	 * the same offset in the occupant/bank block the state selects for the window holding it (the
	 * home occupant is the base space). {@code null} when that is the same memory as
	 * {@code target}, or when the state does not fully determine the occupant, or the offset is
	 * in no tracked window.
	 */
	Address resolve(Instruction use, Address target) {
		Address r = resolveUnder(stateBefore(use), target);
		return r == null || r.getAddressSpace().equals(target.getAddressSpace()) ? null : r;
	}

	/**
	 * The address the base-space offset of {@code target} reaches under an explicit
	 * {@code state}: the home occupant's (base-space) address, an overlay address, or
	 * {@code null} when the state does not fully determine the occupant or the offset is in no
	 * tracked window. Unlike {@link #resolve}, "same memory" is answered with the address (grm-v60
	 * needs to tell "home bank" from "undetermined").
	 */
	Address resolveUnder(BankState state, Address target) {
		BankAnnotationAdapter.OffsetResolution r = BankAnnotationAdapter
			.resolveOffsetOccupant(board, bankUniverse, state, target.getOffset(), placementOverride);
		if (r == null || !r.fullyKnown()) {
			return null;
		}
		AddressSpace space = r.home() ? program.getAddressFactory().getDefaultAddressSpace()
				: program.getAddressFactory().getAddressSpace(r.space());
		if (space == null) {
			return null;
		}
		try {
			return space.getAddress(target.getOffset());
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/** The first mechanism write {@link #switchedByEntry} found, and the bank state it sets. */
	record EntrySwitch(Address writeSite, BankState state) {}

	/**
	 * What bank a routine entered at {@code entry} with the given A/X/Y switches in: walks the
	 * unbroken fall-through run from {@code entry} to the first instruction some mechanism
	 * recognizes as a bank write, and re-evaluates that write under the entry registers (the
	 * helper mini-inline, {@link BankSwitchStrategy#depositHelperArgument}). {@code null} when
	 * the run ends (branch, jump, call, return) before a write, or the write does not pin the
	 * mechanism's whole field. The returned state knows only that mechanism's bits (grm-v60).
	 */
	EntrySwitch switchedByEntry(Address entry, PartialByte a, PartialByte x, PartialByte y) {
		RegisterEnv env = new RegisterEnv(entry, null, a, x, y);
		Listing listing = program.getListing();
		Instruction cur = listing.getInstructionAt(entry);
		for (int i = 0; cur != null && i < MAX_WALK; i++) {
			for (ConfiguredMechanism cm : mechanisms) {
				MechanismState unknown = MechanismState.unknown();
				if (cm.strategy().computeSwitchOutcome(program, cur, unknown) == null) {
					continue;
				}
				int width = cm.placement().widthMask();
				BankSwitchStrategy.HelperDeposit deposit =
					cm.strategy().depositHelperArgument(program, cur, a, unknown, width, env);
				if (deposit == null || (deposit.value().knownMask() & width) != width) {
					return null;
				}
				return new EntrySwitch(cur.getMinAddress(),
					cm.placement().position(deposit.value()));
			}
			var ft = cur.getFlowType();
			if (ft.isJump() || ft.isCall() || ft.isTerminal() || ft.isConditional()) {
				return null;
			}
			Address next = cur.getFallThrough();
			cur = next == null ? null : listing.getInstructionAt(next);
		}
		return null;
	}

	/** Which analyzer (if any) would claim the program: a pure gate probe for tests. */
	static boolean isBankedImport(Program program) {
		return forProgram(program) != null;
	}
}
