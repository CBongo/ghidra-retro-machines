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
	 * a pass) and is simply rebuilt otherwise.
	 */
	private static final Map<Program, java.lang.ref.WeakReference<java.util.Optional<BankContext>>> CACHE =
		new WeakHashMap<>();

	private final Program program;
	private final BoardModel board;
	private final List<ConfiguredMechanism> mechanisms;
	private final Map<String, Set<Integer>> bankUniverse;
	private final Map<String, Integer> placementOverride;

	private BankContext(Program program, BoardModel board, List<ConfiguredMechanism> mechanisms,
			Map<String, Set<Integer>> bankUniverse, Map<String, Integer> placementOverride) {
		this.program = program;
		this.board = board;
		this.mechanisms = mechanisms;
		this.bankUniverse = bankUniverse;
		this.placementOverride = placementOverride;
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
			java.lang.ref.WeakReference<java.util.Optional<BankContext>> ref = CACHE.get(program);
			java.util.Optional<BankContext> cached = ref == null ? null : ref.get();
			if (cached == null) {
				cached = java.util.Optional.ofNullable(build(program));
				CACHE.put(program, new java.lang.ref.WeakReference<>(cached));
			}
			return cached.orElse(null);
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
			DescriptorHints.readResolvedInitialState(program));
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
			BankAnnotationAdapter.bankUniverse(program, board), placementOverride);
	}

	/**
	 * The bank state provably in force just before {@code use} executes, from a local
	 * straight-line walk: back through fall-through predecessors, stopping at a function entry,
	 * at an instruction with any incoming non-fall-through flow (a join), after a call, or after
	 * {@link #MAX_WALK} instructions. The state is seeded from the residence the run's first
	 * instruction implies (code in overlay {@code WINDOW_B<n>} runs only while the field is n;
	 * {@link BankDataflowEngine#clampToResidence}), then each instruction before {@code use} is
	 * applied through the board's mechanisms. Bits nothing proved stay unknown.
	 */
	BankState stateBefore(Instruction use) {
		List<Instruction> run = straightLineRun(use);
		BankState state = BankDataflowEngine.clampToResidence(run.get(0).getMinAddress(),
			new BankState(0, 0), board, new HashMap<>());
		for (Instruction step : run.subList(0, run.size() - 1)) {
			state = BankDataflowEngine.applyDirectSwitch(program, step, state, mechanisms);
		}
		return state;
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
			if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough()) ||
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
		Address at;
		try {
			at = space.getAddress(straightLineRun(use).get(0).getMinAddress().getOffset());
		}
		catch (AddressOutOfBoundsException e) {
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
