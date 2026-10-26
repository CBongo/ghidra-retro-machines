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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Bounds decompiler-recovered jump tables by their own lowest target (grm-eyn), running BEFORE
 * Ghidra's stock {@code DecompilerSwitchAnalyzer} so the stock analyzer lays down references,
 * labels and disassembly for the corrected case count instead of the over-read one.
 *
 * <p>The 8-bit 6502 idiom this exists for has no bound on its table index anywhere in the code
 * (a doubled 1-byte index: {@code ASL A / TAY / LDA tbl,Y / STA $04 / LDA tbl+1,Y / STA $05 /
 * JMP ($0004)}), so the decompiler's own {@code sanityCheck} recovers every raw index value the
 * scaled byte can hold -- 128 or 256 entries -- reading straight through the real table into
 * whatever bytes happen to follow it and inventing jump targets from them. See
 * {@link JumpTableBound} for the rule ("a table cannot extend past its own lowest target") and
 * why it is sound. Where the table sits AFTER the code it dispatches to, that rule declines and
 * {@link JumpTableBound#boundBySwitchWindow} is tried instead (grm-akiv): the real entries point
 * between the switch and the table, and the first entry that does not ends it. When both decline
 * on an un-doubled index over 2-byte entries (grm-yjiq, rcproam 9ad4: handlers on both sides of
 * the table), {@link JumpTableBound#boundByValidTargets} cuts at the first even entry whose target
 * is not in initialized, non-volatile memory. Last, when every rule above declines,
 * {@link JumpTableBound#boundByNeighbourTable} cuts where ANOTHER switch's load table begins
 * (grm-2m07, dbz2 cb97 running into cbfd's table) -- which is why {@link #added} decompiles every
 * function first and bounds second: the neighbour is often in a different function.
 *
 * <p><b>Mechanism.</b> This analyzer resolves each computed-jump location to a function EXACTLY
 * as stock {@code DecompilerSwitchAnalyzer.findFunctions}/{@code FindFunctionCallback} do --
 * the real containing {@link Function} if one already exists at {@link
 * AnalysisPriority#CODE_ANALYSIS}{@code .before()} (most don't yet; functions are laid down
 * later, at {@code FUNCTION_ANALYSIS}), else an {@link UndefinedFunction} synthesized with
 * {@link UndefinedFunction#findFunctionUsingSimpleBlockModel} -- then decompiles it (with
 * {@link SwitchAnalysisDecompileConfigurer}'s exact configuration; {@code toggleJumpLoads(true)}
 * is what populates {@link JumpTable#getLoadTables()} at all) and inspects every {@link
 * HighFunction#getJumpTables()} table found. Where {@link JumpTableBound} proves a strictly
 * smaller entry count, it applies the bound one of two ways depending on what actually contains
 * the switch (grm-eyn increment 2, driven by real-ROM measurement -- see design decisions below):
 * <ul>
 * <li>a real, non-thunk {@link Function}: writes a {@link JumpTable} <em>override</em> (the
 * same mechanism a human uses from the GUI's "Override Jump Table" action), naming only the
 * surviving targets. {@code DecompilerSwitchAnalyzer}, running one priority step later, decompiles
 * again, the decompiler honours the override verbatim ({@code JumpBasicOverride} in the C++
 * core), and the stock command lays down the targets, labels and disassembly itself.</li>
 * <li>an {@link UndefinedFunction} (no real function exists yet, so there is no stable namespace
 * an override could be anchored to): pins the table directly by adding {@code COMPUTED_JUMP}
 * mnemonic references from the switch instruction to exactly the kept targets (mirroring {@code
 * DecompilerSwitchAnalysisCmd.disassembleTable}'s own reference/context/disassembly steps), so
 * the switch instruction now carries a computed reference. Stock's own {@code findLocations}/
 * {@code FindFunctionCallback} bail out of any location that already has one, so it never
 * revisits this site and never lays down the over-read -- at the cost of the
 * {@code switchD_}/{@code caseD_} namespace labels the override path gets from letting the stock
 * command do the labelling itself.</li>
 * </ul>
 * In both cases this analyzer creates no function itself. It is a no-op -- nothing written, no
 * comment left -- whenever the bound doesn't apply or doesn't shrink the table.
 *
 * <p><b>Design decisions (grm-eyn):</b>
 * <ul>
 * <li><b>Default case.</b> A trailing case with no {@code getLabelValues()} entry, or whose
 * label value is {@code DecompilerSwitchAnalysisCmd.DEFAULT_CASE_VALUE} ({@code 0xBAD1ABE1}), is
 * the DEFAULT case, not a table entry: excluded from the walk, from the case count handed to
 * {@link JumpTableBound}, and from the override/references this class writes. That constant is
 * duplicated here (the owning class is not public) rather than reflectively poking at it.</li>
 * <li><b>Undefined functions.</b> Increment 1 skipped any location with no already-DEFINED
 * containing function, on the theory that synthesizing one was the stock analyzer's job. Real-ROM
 * measurement (46-corpus run, grm-eyn follow-up) showed most switches are NOT yet inside a
 * defined function at this priority -- functions are created later, at {@code
 * FUNCTION_ANALYSIS} -- so that skip left the majority of real over-reads untouched (227 locations
 * corpus-wide; megaman a734 still 93 targets). This increment resolves an {@link UndefinedFunction}
 * the same way stock does and decompiles it, but still creates no function and still skips thunks
 * (a thunk's own body is a proxy for its target's, not a real switch site of its own).</li>
 * <li><b>Reference-pinning is NOT used for defined functions too.</b> It was considered and
 * rejected: writing refs directly on a defined function's switch would satisfy stock's own {@code
 * hasAllReferences} check and make it skip the site entirely -- silently forfeiting the
 * {@code switchD_}/{@code caseD_} namespace labels and disassembly-fixup that only the override
 * path gets from letting the stock command run its normal labelling machinery afterward.
 * Reference-pinning is reserved for the one case where the override mechanism is structurally
 * unavailable -- no real {@link Function} to anchor a namespace to.</li>
 * <li><b>Logging.</b> Analyzer {@link MessageLog} output is invisible in a headless run (see
 * {@link AnalyzerLog}), so every applied bound also leaves a durable EOL comment at the switch
 * instruction -- the artifact tests and dumps can actually see -- regardless of which of the two
 * mechanisms above applied.</li>
 * </ul>
 *
 * @see <a href="urn:bead:grm-eyn">grm-eyn</a>
 * @see JumpTableBound
 */
public class JumpTableBoundAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Jump Table Bound";
	private static final String DESCRIPTION =
		"Bounds decompiler-recovered 6502-family jump tables by their own lowest target, before " +
			"stock switch analysis disassembles the over-read tail as phantom code (grm-eyn).";

	/** Mirrors {@code DecompilerSwitchAnalysisCmd.DEFAULT_CASE_VALUE}; that class isn't public. */
	private static final int DEFAULT_CASE_VALUE = 0xbad1abe1;

	/** Matches {@code DecompilerSwitchAnalyzer.OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS}. */
	private static final int DECOMPILE_TIMEOUT_SECS = 60;

	/**
	 * Configures {@code ifc} exactly as {@link SwitchAnalysisDecompileConfigurer} does, with one
	 * deliberate exception: no cap on bad-data sites. Ghidra 12.2 (GP-6945) aborts a whole
	 * decompile after 4 flows into undecodable or unmapped bytes, and an over-read table -- the
	 * thing this analyzer exists to bound -- produces exactly those flows (a 3-byte-stride search
	 * table read as 2-byte entries lands on $0282, $1002, $2003, ...). Under the cap the decompile
	 * fails and the table is never seen. Set here rather than relying on the reference machine's
	 * locally patched decompile.exe (which also lifts the cap, grm-6m24) so this analyzer behaves
	 * the same on a stock 12.2 install (grm-75ey).
	 */
	static void configureDecompiler(Program program, DecompInterface ifc) {
		new SwitchAnalysisDecompileConfigurer(program).configure(ifc);
		DecompileOptions opts = ifc.getOptions();
		opts.setMaxBadData(Integer.MAX_VALUE);
		ifc.setOptions(opts);
	}

	public JumpTableBoundAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Must run BEFORE the stock DecompilerSwitchAnalyzer (also CODE_ANALYSIS) so our override
		// is in place when it decompiles and disassembles the switch's targets.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		// The idiom, and the decompiler gap it exploits, is an 8-bit-address-space thing: on a
		// >=32-bit target the decompiler's own sanityCheck bound (a fraction of the address
		// space) is never dead code the way it is here. Gate on pcode support plus address width
		// rather than a specific processor, since every language we ship is one of these.
		return AnalyzerGates.is8BitPcode(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Address> locations = findComputedJumpLocations(listing, set, monitor);
		if (locations.isEmpty()) {
			return true;
		}

		Set<Function> functions = new LinkedHashSet<>();
		int skippedUnresolved = 0;
		int skippedThunk = 0;
		for (Address location : locations) {
			monitor.checkCancelled();
			Function function = program.getFunctionManager().getFunctionContaining(location);
			if (function == null) {
				// No defined function contains it yet (the common case at this priority --
				// functions are laid down later, at FUNCTION_ANALYSIS). Resolve exactly as
				// stock DecompilerSwitchAnalyzer's FindFunctionCallback does: a lightweight,
				// non-persisted stand-in built from the simple block model, decompilable without
				// creating a real function ourselves.
				function = UndefinedFunction.findFunctionUsingSimpleBlockModel(program, location,
					monitor);
			}
			if (function == null) {
				skippedUnresolved++;
				continue;
			}
			if (function.isThunk()) {
				skippedThunk++;
				continue;
			}
			functions.add(function);
		}
		if (skippedUnresolved > 0 || skippedThunk > 0) {
			AnalyzerLog.info(this, "skipped " + skippedUnresolved +
				" location(s) no function (real or synthesized) could be resolved for, and " +
				skippedThunk + " thunk location(s) (not attempted; see class javadoc)");
		}
		int bounded = boundFunctions(program, functions, monitor, log);
		if (bounded > 0) {
			AnalyzerLog.info(this, "bounded " + bounded + " jump table(s)");
		}
		return true;
	}

	/** Decompiles each of {@code functions} and bounds every jump table found; returns how many it
	 *  bounded. The body of {@link #added}, shared with {@link JumpTableOverrideRelocatorAnalyzer},
	 *  which calls it for a switch this analyzer could only pin by references (grm-kon2). */
	int boundFunctions(Program program, Set<Function> functions, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		if (functions.isEmpty()) {
			return 0;
		}
		Listing listing = program.getListing();
		int bounded = 0;
		// Held for the whole pass: BankContext's cache is weak (see BankContext.CACHE), and
		// rebuilding it per switch would be wasteful.
		BankContext keepAlive = BankContext.forProgram(program);
		DecompInterface ifc = new DecompInterface();
		try {
			configureDecompiler(program, ifc);
			if (!ifc.openProgram(program)) {
				AnalyzerLog.warn(this, log, "decompiler failed to open program: " +
					ifc.getLastMessage());
				return 0;
			}
			// Two passes (grm-2m07): every table's load-table starts must be known before ANY
			// table is bounded, because boundByNeighbourTable cuts one table where another
			// begins -- and the neighbour is often in a different function (dbz2's cb97 table
			// runs into the one cbfd reads, inside the IRQ handler). A load table's start does
			// not depend on the count the decompiler guessed, so the first pass's answer is final.
			Map<Function, JumpTable[]> decompiled = new LinkedHashMap<>();
			List<Address> loadTableStarts = new ArrayList<>();
			for (Function function : functions) {
				monitor.checkCancelled();
				DecompileResults results =
					ifc.decompileFunction(function, DECOMPILE_TIMEOUT_SECS, monitor);
				if (!results.decompileCompleted()) {
					continue; // stock analyzer will also fail on this function; not our concern
				}
				HighFunction hfunction = results.getHighFunction();
				if (hfunction == null) {
					continue;
				}
				JumpTable[] tables = hfunction.getJumpTables();
				decompiled.put(function, tables);
				for (JumpTable table : tables) {
					for (JumpTable.LoadTable lt : table.getLoadTables()) {
						if (lt.getNum() > 1) {
							loadTableStarts.add(lt.getAddress());
						}
					}
				}
			}
			// grm-rsxe: a second pass offers every table still declined the kept targets of the
			// tables the first pass bounded (boundByKnownCode). Only this pass's own results feed
			// it, so which tables it cuts does not depend on analysis order.
			List<Address> keptTargets = new ArrayList<>();
			Map<JumpTable, Function> declined = new LinkedHashMap<>();
			for (Map.Entry<Function, JumpTable[]> e : decompiled.entrySet()) {
				for (JumpTable table : e.getValue()) {
					monitor.checkCancelled();
					if (processTable(program, listing, e.getKey(), table, loadTableStarts,
						List.of(), keptTargets, monitor, log)) {
						bounded++;
					}
					else {
						declined.put(table, e.getKey());
					}
				}
			}
			if (!keptTargets.isEmpty()) {
				for (Map.Entry<JumpTable, Function> e : declined.entrySet()) {
					monitor.checkCancelled();
					if (processTable(program, listing, e.getValue(), e.getKey(), loadTableStarts,
						keptTargets, new ArrayList<>(), monitor, log)) {
						bounded++;
					}
				}
			}
		}
		finally {
			ifc.dispose();
			java.lang.ref.Reference.reachabilityFence(keepAlive);
		}
		return bounded;
	}

	/** Finds computed-jump instructions in {@code set}, the same predicate stock
	 *  {@code DecompilerSwitchAnalyzer.findLocations} uses (a jump whose flow is computed),
	 *  skipping any that already carry a computed reference -- either the stock analyzer or an
	 *  earlier round already resolved them, so there is nothing left to over-read. */
	private List<Address> findComputedJumpLocations(Listing listing, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		List<Address> locations = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			FlowType flowType = instr.getFlowType();
			if (!flowType.isJump() || !flowType.isComputed()) {
				continue;
			}
			if (hasComputedReference(instr)) {
				continue;
			}
			locations.add(instr.getMinAddress());
		}
		return locations;
	}

	private boolean hasComputedReference(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}

	/** Whether {@code a} and {@code b} describe the same underlying memory: either they are the
	 *  same space, or one is directly an overlay of the other ({@link AddressSpace#getPhysicalSpace()}
	 *  returns the space itself for a non-overlay space, and the underlying physical space for an
	 *  overlay). Deliberately NOT transitive through a shared physical ancestor -- two sibling
	 *  overlay spaces (different banks of the same window) both report the same physical space
	 *  but are not each other's physical space, so they compare unequal here, exactly as they
	 *  should: they are genuinely different memory. */
	private static boolean sameMemory(AddressSpace a, AddressSpace b) {
		if (a.equals(b)) {
			return true;
		}
		if (a.getPhysicalSpace().equals(b)) {
			return true;
		}
		if (b.getPhysicalSpace().equals(a)) {
			return true;
		}
		return false;
	}

	/** Examines one jump table; if {@link JumpTableBound} proves a strict shrink, applies it --
	 *  by override for a real function, by reference-pinning for an {@link UndefinedFunction}
	 *  (see the class javadoc) -- and leaves the EOL comment. Returns true iff it did so. Left
	 *  untouched (false) when: the table already carries an override (ours from an earlier
	 *  round, or a human's); the shape isn't understood; the table doesn't sit below its
	 *  targets; or the bound doesn't actually shrink the entry count. */
	private boolean processTable(Program program, Listing listing, Function function,
			JumpTable table, List<Address> loadTableStarts, List<Address> knownCode,
			List<Address> keptOut, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Address switchAddr = table.getSwitchAddress();
		if (switchAddr == null) {
			return false;
		}
		boolean isUndefined = function instanceof UndefinedFunction;
		if (!isUndefined) {
			Function owner = program.getFunctionManager().getFunctionContaining(switchAddr);
			if (owner != null && !owner.equals(function)) {
				return false; // switch belongs to a different (already-processed-elsewhere) function
			}
			if (owner == null) {
				// grm-aemp: the decompiler follows flow past the listing body, so a real function
				// can yield a table for a switch no function contains -- often one the listing
				// has not even disassembled yet (dragonpower NMI reaching a546). An override
				// there always throws "Switch is not in function body", and stock switch analysis
				// then over-read the table to 91 cases. No function to anchor an override to is
				// exactly the undefined case, so pin by references instead (pinByReferences
				// disassembles the switch first when it has to).
				isUndefined = true;
			}
		}
		if (!isUndefined) {
			if (relocateStaleOverride(this, program, function, switchAddr, log)) {
				return false;
			}
			if (alreadyOverridden(program, function, switchAddr)) {
				return false;
			}
		}

		Address[] cases = table.getCases();
		Integer[] labelValues = table.getLabelValues();
		List<Address> realCases = new ArrayList<>();
		for (int i = 0; i < cases.length; i++) {
			boolean isDefault = (i >= labelValues.length) ||
				(labelValues[i] != null && labelValues[i] == DEFAULT_CASE_VALUE);
			if (!isDefault) {
				realCases.add(cases[i]);
			}
		}
		if (realCases.size() < 2) {
			return false;
		}
		// Compare by underlying MEMORY, not exact space identity: a switch inside a banked
		// overlay (e.g. PRG_LO_B5::) can have its load table's bytes attributed to a DIFFERENT
		// space representation than its case targets even when both ultimately describe the same
		// physical bytes -- e.g. a table's real entries sitting in a small base-space block with
		// the "over-read" tail and the real targets themselves inside the adjacent overlay. An
		// overlay and its own underlying physical space share the same offset numbering (that is
		// what "overlay" means in Ghidra), so getOffset() values are safe to compare/combine
		// across the two once recognized as the same memory. This does NOT mean any two spaces
		// that happen to share a common physical ancestor are interchangeable: two SIBLING
		// overlays (e.g. a different bank's PRG_LO_B2) both report physical space "ram" too, but
		// neither IS the other's physical space, so #sameMemory correctly keeps them apart --
		// only a direct overlay-of/physical-of relationship counts. Measured on the real-ROM
		// corpus (grm-eyn follow-up): declining every overlay-space switch on exact-space
		// equality alone left 32 tables unbounded corpus-wide (megaman, ff1, etc.) despite the
		// mechanism otherwise working -- this is the fix for that gap, not a loosening of intent.
		AddressSpace targetSpace = realCases.get(0).getAddressSpace();
		// grm-uzep: a case list deduplicated by target (and over-read into other spaces) is bounded
		// from the table's own words: instead of the shape checks when the case list mixes spaces
		// (they decline it outright), else only once every other rule has declined.
		JumpTableBound.Result deduped = boundDistinctWords(program, table, realCases);
		boolean mixed = false;
		List<Long> targets = new ArrayList<>(realCases.size());
		for (Address a : realCases) {
			if (!sameMemory(a.getAddressSpace(), targetSpace)) {
				if (deduped == null) {
					return false; // mixed-space case list; shape not understood, decline
				}
				mixed = true;
			}
			targets.add(a.getOffset());
		}

		List<JumpTableBound.LoadTableEntry> loadTables = new ArrayList<>();
		Address lowestMovingTableAddr = null;
		for (JumpTable.LoadTable lt : table.getLoadTables()) {
			if (!sameMemory(lt.getAddress().getAddressSpace(), targetSpace)) {
				continue; // only consider load tables describing the same memory as the targets
			}
			loadTables.add(
				new JumpTableBound.LoadTableEntry(lt.getAddress().getOffset(), lt.getSize(),
					lt.getNum()));
			if (lt.getNum() > 1 && (lowestMovingTableAddr == null ||
				lt.getAddress().getOffset() < lowestMovingTableAddr.getOffset())) {
				lowestMovingTableAddr = lt.getAddress();
			}
		}

		// grm-fxtp: the table's own memory block, for the below-table-cut refinement's same-block
		// guard (JumpTableBound is pure logic over flat offsets and can't look this up itself).
		// Unresolvable (no moving table, or no block containing it) -- pass none, which disables
		// that refinement and falls back to the plain lowest-target walk.
		JumpTableBound.Block tableBlock = null;
		if (lowestMovingTableAddr != null) {
			MemoryBlock block = program.getMemory().getBlock(lowestMovingTableAddr);
			if (block != null) {
				tableBlock =
					new JumpTableBound.Block(block.getStart().getOffset(), block.getEnd().getOffset());
			}
		}

		// grm-pwuh: the dispatch may read its table from a DIFFERENT bank than the decompiler did
		// (the code switches banks first, then reads). Re-read it from the switched-in bank.
		CrossBank crossBank = null;
		if (lowestMovingTableAddr != null && !mixed) {
			crossBank = crossBankTable(program, listing, switchAddr, table, lowestMovingTableAddr,
				targets);
		}
		if (crossBank != null) {
			realCases = crossBank.cases();
			targets = new ArrayList<>(realCases.size());
			for (Address a : realCases) {
				targets.add(a.getOffset());
			}
			targetSpace = crossBank.table().getAddressSpace();
			// grm-q4ga: the table may have moved to where the switched-in copy reads it, so move the
			// decompiler's load tables with it; the extent rules below measure against them.
			long shift = crossBank.table().getOffset() - lowestMovingTableAddr.getOffset();
			if (shift != 0) {
				List<JumpTableBound.LoadTableEntry> moved = new ArrayList<>(loadTables.size());
				for (JumpTableBound.LoadTableEntry lt : loadTables) {
					moved.add(new JumpTableBound.LoadTableEntry(lt.start() + shift, lt.entrySize(),
						lt.num()));
				}
				loadTables.clear();
				loadTables.addAll(moved);
			}
			lowestMovingTableAddr = crossBank.table();
			MemoryBlock block = program.getMemory().getBlock(lowestMovingTableAddr);
			tableBlock = block == null ? null
					: new JumpTableBound.Block(block.getStart().getOffset(),
						block.getEnd().getOffset());
		}
		boolean isCrossBank = crossBank != null;

		// Other switches' load-table starts, for grm-t223 and grm-2m07 below. Only starts in this
		// table's own memory count (same rule as the load tables above); the rules themselves
		// ignore this table's own starts.
		List<Long> others = new ArrayList<>();
		for (Address a : loadTableStarts) {
			if (sameMemory(a.getAddressSpace(), targetSpace)) {
				others.add(a.getOffset());
			}
		}

		// grm-jt7s: a keyed linear search leaves the index in a value set the code itself states;
		// read the cases from it exactly, ahead of every extent rule (none can cut every third case).
		List<Address> searched = null;
		if (!isCrossBank && !mixed) {
			Instruction switchInstr = listing.getInstructionAt(switchAddr);
			searched = switchInstr == null ? null
					: SearchLoopDispatch.cases(program, switchInstr, realCases);
		}
		JumpTableBound.Result result;
		if (searched != null) {
			long lowest = Long.MAX_VALUE;
			for (Address a : searched) {
				lowest = Math.min(lowest, a.getOffset());
			}
			result = JumpTableBound.boundBySearchLoop(searched.size(), lowest);
		}
		else if (mixed) {
			result = deduped;
		}
		else {
			result = JumpTableBound.bound(targets, loadTables, tableBlock);
		}
		if (!result.isBounded() && sameMemory(switchAddr.getAddressSpace(), targetSpace)) {
			// Table after its code (grm-akiv): the lowest-target rule declines by design. The walk
			// also stops at the next table (grm-t223: contra 849f runs into 8285's table at 86cd).
			result = JumpTableBound.boundBySwitchWindow(switchAddr.getOffset(), targets,
				loadTables, others);
		}
		// Per case, whether its target lies in memory that can hold code: the grm-yjiq and
		// grm-2m07 fallbacks below both consult it.
		List<Boolean> inCode = new ArrayList<>(realCases.size());
		for (Address a : realCases) {
			MemoryBlock block = program.getMemory().getBlock(a);
			inCode.add(block != null && block.isInitialized() && !block.isVolatile());
		}
		if (!result.isBounded()) {
			// grm-yjiq: an overlapping byte table whose handlers straddle it; see the javadoc.
			result = JumpTableBound.boundByValidTargets(targets, loadTables, inCode);
		}
		if (!result.isBounded()) {
			// grm-2m07: the table runs into another switch's table; see the javadoc.
			result = JumpTableBound.boundByNeighbourTable(targets, loadTables, others, inCode);
		}
		if (!result.isBounded() && !knownCode.isEmpty()) {
			// grm-rsxe: the table runs into a handler another table in this pass was bounded to.
			List<Long> codeStarts = new ArrayList<>();
			for (Address a : knownCode) {
				if (sameMemory(a.getAddressSpace(), targetSpace)) {
					codeStarts.add(a.getOffset());
				}
			}
			result = JumpTableBound.boundByKnownCode(targets, loadTables, codeStarts, inCode);
		}
		if (!result.isBounded() && deduped != null) {
			result = deduped; // grm-uzep: nothing else could read this case list
		}
		boolean shrinks = result.isBounded() && result.count() < realCases.size();
		if (!shrinks && !isCrossBank) {
			return false; // decline, or would not shrink the table -- must be a no-op
		}
		// A cross-bank table is pinned whether or not it could be bounded (grm-pwuh): the
		// decompiler's own reading is the wrong bank's, so declining would leave its garbage.
		if (shrinks && result.planarGap() > 0 &&
			!planarBytesMatch(program, lowestMovingTableAddr, result.planarGap(),
				targets.subList(0, result.count()))) {
			return false; // grm-d59c: the merged extent only LOOKED planar; leave it alone
		}

		// Normally the first count() cases; every other one for a grm-yjiq overlapping byte table.
		ArrayList<Address> firstN = !shrinks ? new ArrayList<>(realCases)
				: searched != null ? new ArrayList<>(searched)
				: new ArrayList<>(result.keep(realCases));
		// grm-0pen: the rule above capped the extent; now cut the kept cases at the first target
		// whose bytes do not decode as code (see JumpTableBound.codePrefix for why this is only
		// ever a refinement). Bytes only, never the listing, so analysis order cannot move it.
		List<Boolean> decodes = new ArrayList<>(firstN.size());
		for (Address a : firstN) {
			// grm-6j5q: a target into a word table can pseudo-decode; it is not code either.
			decodes.add(InlineJumpTableDispatch.decodesAsCode(program, a, true) &&
				!JumpTableBound.looksLikeWordTable(bytesAt(program, a, 2 * JumpTableBound.WORD_TABLE_RUN)));
		}
		// An exact search-loop set is not an extent to refine.
		int codePrefix = searched != null ? firstN.size() : JumpTableBound.codePrefix(decodes);
		boolean cutAtData = codePrefix < firstN.size();
		// grm-8x6f: a kept case that still fails to decode means only the trailing run was cut.
		boolean trailingCut = cutAtData && decodes.subList(0, codePrefix).contains(false);
		if (cutAtData) {
			firstN = new ArrayList<>(firstN.subList(0, codePrefix));
		}
		String dataCut = trailingCut ? "trailing targets that do not decode as code"
				: "first target that does not decode as code";
		if (shrinks || cutAtData) {
			keptOut.addAll(firstN);
		}
		// grm-deve: decide now (bytes do not change when the bound lands) whether this table reads as
		// a word array of exactly the kept targets; a previous array of ours goes BEFORE the pin or
		// override so its references cannot shield stale targets from the retraction.
		JumpTableArray.Layout arrayLayout = null;
		Address arrayAt = null;
		List<Address> arrayTargets = null;
		boolean arrayLaid = false;
		if (shrinks && !isCrossBank && searched == null && result.stride() == 1 &&
			result.planarGap() == 0 && !firstN.isEmpty()) {
			boolean distinct = result.rule() == JumpTableBound.Rule.DISTINCT_WORDS;
			JumpTable.LoadTable only = distinct ? singleMovingByteTable(table) : null;
			arrayAt = distinct ? (only == null ? null : only.getAddress()) : lowestMovingTableAddr;
			if (arrayAt != null) {
				int wordCount = distinct ? only.getNum() / 2 : firstN.size();
				List<Long> words = wordsAt(program, arrayAt, wordCount);
				List<Long> keptOffsets = new ArrayList<>(firstN.size());
				for (Address a : firstN) {
					keptOffsets.add(a.getOffset());
				}
				if (words != null) {
					arrayLayout = distinct
							? JumpTableArray.matchDistinct(words, arrayAt.getOffset(), keptOffsets)
							: JumpTableArray.matchOrdered(words, keptOffsets);
				}
				if (arrayLayout != null) {
					arrayTargets = new ArrayList<>(arrayLayout.count());
					for (int idx : arrayLayout.caseIndex()) {
						arrayTargets.add(firstN.get(idx));
					}
					// A target inside the table's own bytes is code over the array (tables that
					// overlap their handlers, deadly_towers ddd0): data there would unmake it.
					long first = arrayAt.getOffset();
					long last = first + 2L * arrayLayout.count() - 1;
					for (Address t : arrayTargets) {
						if (sameMemory(t.getAddressSpace(), arrayAt.getAddressSpace()) &&
							t.getOffset() >= first && t.getOffset() <= last) {
							arrayLayout = null;
							arrayTargets = null;
							break;
						}
					}
				}
				if (arrayLayout != null) {
					arrayLaid = JumpTableArrays.isLaid(program, arrayAt, arrayTargets);
				}
				if (!arrayLaid) {
					JumpTableArrays.unlay(program, arrayAt);
				}
			}
		}
		// grm-rsxe: a KNOWN_CODE cut is pinned by references even in a real function. The one
		// table it exists for (tmnt B5 9474) makes the decompiler reject the override outright
		// ("Overlapping input varnodes" with 23 cases, clean with its own 128), and a rejected
		// override is never applied -- the switch got NO targets at all, worse than the over-read.
		// Checking each override by re-decompiling was tried and dropped: on megaman's FUN_dc21
		// the check itself killed the decompiler process, so a failure there proves nothing, and
		// undoing the override took its switch/case labels with it.
		// A jump-table override cannot carry cross-space targets (the decompiler cannot follow a
		// branch into another address space), so a cross-bank table is always pinned by references.
		if (isUndefined || isCrossBank ||
			(shrinks && result.rule() == JumpTableBound.Rule.KNOWN_CODE)) {
			if (!pinByReferences(program, listing, switchAddr, firstN, monitor)) {
				AnalyzerLog.warn(this, log,
					"could not pin jump table by references at " + switchAddr +
						": no instruction there");
				return false;
			}
		}
		else {
			JumpTable override =
				new JumpTable(switchAddr, firstN, true, EquateSymbol.FORMAT_DEFAULT);
			try {
				override.writeOverride(function);
			}
			catch (InvalidInputException e) {
				AnalyzerLog.warn(this, log,
					"could not write jump table override at " + switchAddr + ": " +
						e.getMessage());
				return false;
			}
			retractStaleCases(program, function, switchAddr, firstN, monitor);
		}

		// grm-deve: the bound has landed and its retraction is done; lay over the kept entries only.
		boolean arrayNow = arrayLayout != null &&
			(arrayLaid || JumpTableArrays.layWords(program, arrayAt, arrayTargets));
		AnalyzerLog.info(this, "jump table array at " + switchAddr + ": " +
			(arrayLayout == null ? "no word layout"
					: arrayNow ? "laid word[" + arrayLayout.count() + "] at " + arrayAt
							: "declined at " + arrayAt));
		long tableStart = 0;
		boolean haveStart = false;
		for (JumpTableBound.LoadTableEntry lt : loadTables) {
			if (lt.num() > 1 && (!haveStart || lt.start() < tableStart)) {
				tableStart = lt.start();
				haveStart = true;
			}
		}
		String why;
		if (!shrinks) {
			// A cross-bank table no extent rule could cut (grm-pwuh), possibly cut by grm-0pen.
			why = cutAtData ? dataCut : "kept all";
		}
		else if (result.rule() == JumpTableBound.Rule.SWITCH_WINDOW) {
			why = "targets between switch and table";
		}
		else if (result.rule() == JumpTableBound.Rule.WINDOW_AT_NEIGHBOUR) {
			why = "targets between switch and table, stopped at next table"; // grm-t223
		}
		else if (result.rule() == JumpTableBound.Rule.BELOW_TABLE_CUT) {
			why = "first target below table"; // grm-fxtp
		}
		else if (result.rule() == JumpTableBound.Rule.VALID_TARGET_CUT) {
			why = "first target outside code memory"; // grm-yjiq
		}
		else if (result.rule() == JumpTableBound.Rule.KNOWN_CODE) {
			why = "ran into another table's target"; // grm-rsxe
		}
		else if (result.rule() == JumpTableBound.Rule.SEARCH_LOOP) {
			why = "index from a keyed search loop"; // grm-jt7s
		}
		else if (result.rule() == JumpTableBound.Rule.DISTINCT_WORDS) {
			why = "lowest target " + Long.toHexString(result.lowestTarget()) +
				", cases deduplicated by target"; // grm-uzep
		}
		else {
			why = "lowest target " + Long.toHexString(result.lowestTarget());
		}
		if (shrinks && result.stride() > 1) {
			why += ", even cases only"; // grm-yjiq: odd cases straddle two entries
		}
		if (shrinks && result.planarGap() > 0) {
			// grm-d59c: two byte tables, low then high, merged by the decompiler into one extent
			why += ", planar lo/hi tables " + Integer.toHexString(result.planarGap()) + " apart";
		}
		if (shrinks && cutAtData) {
			why += ", then " + dataCut; // grm-0pen
		}
		if (arrayNow) {
			why += ", laid word[" + arrayLayout.count() + "]" +
				(arrayLayout.bias() == 1 ? " (RTS-trick: entry = target - 1)" : "");
		}
		if (isCrossBank) {
			why += ", table read from switched-in bank " + targetSpace.getName() + " as " +
				crossBank.model();
		}
		String text = "[JumpTableBound] table at " + Long.toHexString(tableStart) + " bounded " +
			realCases.size() + " -> " + firstN.size() + " entries (" + why + ")";
		// A switch is bounded once per pass that reaches it, and how many passes do depends on
		// analysis order (grm-kon2: dragonpower a546 carried this text 3 or 4 times), hence the
		// text itself as the idempotence marker. Recorded for the exporter (grm-hb6.18).
		AnalyzerCommentRecord.append(program, switchAddr, CommentType.EOL, text, text);
		return true;
	}

	/**
	 * grm-uzep: bounds a table whose decompiler case list is deduplicated by target (see
	 * {@link JumpTableBound#boundByDistinctWords}). The shape: exactly one moving load table, one
	 * byte wide, of an even length that holds more words than the decompiler has cases. Reads the
	 * table's words from memory. Returns null when it is not that shape.
	 */
	private static JumpTableBound.Result boundDistinctWords(Program program, JumpTable table,
			List<Address> realCases) {
		JumpTable.LoadTable found = null;
		for (JumpTable.LoadTable lt : table.getLoadTables()) {
			if (lt.getNum() <= 1) {
				continue;
			}
			if (found != null) {
				return null;
			}
			found = lt;
		}
		if (found == null || found.getSize() != 1 || found.getNum() % 2 != 0 ||
			found.getNum() / 2 <= realCases.size()) {
			return null;
		}
		byte[] bytes = bytesAt(program, found.getAddress(), found.getNum());
		if (bytes.length != found.getNum()) {
			return null;
		}
		List<Long> words = new ArrayList<>(bytes.length / 2);
		for (int i = 0; i < bytes.length; i += 2) {
			words.add((long) ((bytes[i] & 0xff) | (bytes[i + 1] & 0xff) << 8));
		}
		List<Long> caseTargets = new ArrayList<>(realCases.size());
		for (Address a : realCases) {
			caseTargets.add(a.getOffset());
		}
		JumpTableBound.Result r = JumpTableBound.boundByDistinctWords(words,
			found.getAddress().getOffset(), caseTargets);
		return r.isBounded() ? r : null;
	}

	/** grm-deve: the one moving load table of a deduplicated-case-list switch, when it is a byte
	 *  table of an even length (the shape {@link #boundDistinctWords} reads); else null. */
	private static JumpTable.LoadTable singleMovingByteTable(JumpTable table) {
		JumpTable.LoadTable found = null;
		for (JumpTable.LoadTable lt : table.getLoadTables()) {
			if (lt.getNum() <= 1) {
				continue;
			}
			if (found != null) {
				return null;
			}
			found = lt;
		}
		return found == null || found.getSize() != 1 || found.getNum() % 2 != 0 ? null : found;
	}

	/** {@code count} little-endian words at {@code a}, or null when memory does not hold them all. */
	private static List<Long> wordsAt(Program program, Address a, int count) {
		byte[] bytes = bytesAt(program, a, 2 * count);
		if (bytes.length != 2 * count) {
			return null;
		}
		List<Long> words = new ArrayList<>(count);
		for (int i = 0; i < bytes.length; i += 2) {
			words.add((long) ((bytes[i] & 0xff) | (bytes[i + 1] & 0xff) << 8));
		}
		return words;
	}

	/** The jump table as read from the switched-in bank: its table address and case targets there. */
	private record CrossBank(Address table, List<Address> cases, CrossBankTable.Model model) {}

	/**
	 * grm-pwuh: when the bank state in force at the switch makes the table's load address reach a
	 * DIFFERENT bank than the one the decompiler read it from, re-reads the table from that bank.
	 * {@link BankContext} says which bank; {@link CrossBankTable#fit} recovers the layout the
	 * decompiler used from its own (wrong-bank) bytes; the same layout then decodes the right
	 * bank's. Returns null (leave the decompiler's reading alone) when there is no banked
	 * context, the table resolves to the same memory, or no layout reproduces every decompiler
	 * case.
	 */
	private CrossBank crossBankTable(Program program, Listing listing, Address switchAddr,
			JumpTable table, Address tableAddr, List<Long> targets) {
		Instruction switchInstr = listing.getInstructionAt(switchAddr);
		BankContext ctx = BankContext.forProgram(program);
		if (switchInstr == null || ctx == null) {
			return null;
		}
		Address resolved = ctx.resolve(switchInstr, tableAddr);
		AnalyzerLog.debug(this, "cross-bank probe at " + switchAddr + ": table " + tableAddr +
			" -> " + resolved + ", state " + ctx.stateBefore(switchInstr));
		if (resolved == null) {
			return null;
		}
		long gap = 0;
		List<Long> starts = new ArrayList<>();
		for (JumpTable.LoadTable lt : table.getLoadTables()) {
			if (lt.getNum() > 1 &&
				sameMemory(lt.getAddress().getAddressSpace(), tableAddr.getAddressSpace())) {
				starts.add(lt.getAddress().getOffset());
			}
		}
		java.util.Collections.sort(starts);
		if (starts.size() >= 2) {
			gap = starts.get(1) - starts.get(0);
		}
		var memory = program.getMemory();
		AddressSpace readSpace = tableAddr.getAddressSpace();
		AddressSpace newSpace = resolved.getAddressSpace();
		CrossBankTable.Model model = CrossBankTable.fit(tableAddr.getOffset(),
			(int) Math.min(gap, 0xffff), targets, bytesIn(memory, readSpace));
		if (model == null) {
			AnalyzerLog.info(this, "cross-bank jump table at " + switchAddr + " (reads " +
				newSpace.getName() + ", decompiler read " + readSpace.getName() +
				") fits no known layout; left as the decompiler read it");
			return null;
		}
		// grm-q4ga: the switched-in bank's copy of the routine may read its own table at another
		// address (deadly_towers' per-bank trampolines). Its bytes are what run after the switch,
		// so read the table where the copy points.
		long readBase = tableAddr.getOffset();
		Long shift = ctx.switchedInCopyTableShift(switchInstr, newSpace, readBase,
			readBase + (long) model.stride() * targets.size());
		if (shift != null && shift != 0) {
			readBase += shift;
			resolved = newSpace.getAddress(readBase);
		}
		List<Long> entries = model.read(readBase, targets.size(), bytesIn(memory, newSpace));
		if (entries.size() < 2) {
			return null;
		}
		// Valid prefix (see CrossBankTable.validPrefix): inside the switched window and in
		// initialized, non-volatile memory of the resolved space.
		MemoryBlock window = memory.getBlock(resolved);
		CrossBankTable.Prefix prefix = CrossBankTable.validPrefix(entries, off -> {
			if (window == null || off < window.getStart().getOffset() ||
				off > window.getEnd().getOffset()) {
				return false;
			}
			MemoryBlock b = memory.getBlock(newSpace.getAddress(off));
			return b != null && b.isInitialized() && !b.isVolatile();
		});
		if (prefix.count() == 0) {
			AnalyzerLog.info(this, "cross-bank jump table at " + switchAddr + ": " + newSpace.getName() +
				" holds no valid entries at " + resolved + "; left as the decompiler read it");
			return null;
		}
		// Corroboration: the switched-in bank's own copy of the routine must read an
		// overlapping table, or this is not a table in that bank at all.
		long stride = model.stride();
		long lo = readBase;
		long hi = lo + stride * (prefix.skip() + prefix.count());
		// Counterpart of the one-leading-junk-slot allowance above: the switched-in bank's copy
		// may sit exactly ONE stride below our base (its table starts a slot earlier, with the
		// junk slot first), so the corroboration window starts one stride below it.
		if (!ctx.switchedInCopyReadsTableIn(switchInstr, newSpace, lo - stride, hi)) {
			AnalyzerLog.info(this, "cross-bank jump table at " + switchAddr + ": " +
				newSpace.getName() + "'s copy of the routine does not read a table overlapping " +
				Long.toHexString(lo) + ".." + Long.toHexString(hi) + "; left as the decompiler read it");
			return null;
		}
		AnalyzerLog.info(this, "cross-bank jump table at " + switchAddr + ": " + tableAddr + " (" +
			targets.size() + " cases) refit as " + model + " from " + resolved + ", corroborated, kept " +
			prefix.count() + (prefix.skip() > 0 ? " (after 1 junk slot)" : ""));
		List<Address> cases = new ArrayList<>(prefix.count());
		for (long e : entries.subList(prefix.skip(), prefix.skip() + prefix.count())) {
			cases.add(newSpace.getAddress(e));
		}
		return new CrossBank(resolved, cases, model);
	}

	private static CrossBankTable.Bytes bytesIn(ghidra.program.model.mem.Memory memory,
			AddressSpace space) {
		return offset -> {
			try {
				return memory.getByte(space.getAddress(offset)) & 0xff;
			}
			catch (ghidra.program.model.mem.MemoryAccessException |
					ghidra.program.model.address.AddressOutOfBoundsException e) {
				return -1;
			}
		};
	}

	/**
	 * Proves a grm-d59c planar split reading against the table's own bytes: every kept target
	 * {@code i} must be {@code byte(lo+i) | byte(lo+gap+i) << 8}. {@link JumpTableBound} infers the
	 * gap from the merged load-table extent alone, and other non-dividing single-byte extents
	 * could land in the same band; the decompiler built each target from exactly these two bytes
	 * when the layout really is planar, so agreement on every kept entry is what licenses the cut.
	 */
	private static boolean planarBytesMatch(Program program, Address lo, int gap,
			List<Long> keptTargets) {
		if (lo == null) {
			return false;
		}
		try {
			for (int i = 0; i < keptTargets.size(); i++) {
				int low = program.getMemory().getByte(lo.add(i)) & 0xff;
				int high = program.getMemory().getByte(lo.add(gap + i)) & 0xff;
				if ((low | high << 8) != (keptTargets.get(i) & 0xffff)) {
					return false;
				}
			}
			return true;
		}
		catch (ghidra.program.model.mem.MemoryAccessException |
				ghidra.program.model.address.AddressOutOfBoundsException e) {
			return false;
		}
	}

	/** Up to {@code n} bytes at {@code a}: fewer where memory ends or is not initialized. */
	private static byte[] bytesAt(Program program, Address a, int n) {
		byte[] buf = new byte[n];
		try {
			int got = program.getMemory().getBytes(a, buf);
			return got == n ? buf : java.util.Arrays.copyOf(buf, Math.max(got, 0));
		}
		catch (ghidra.program.model.mem.MemoryAccessException e) {
			return new byte[0];
		}
	}

	/** Pins {@code switchAddr}'s table to exactly {@code keptTargets} by writing computed
	 *  references directly on the switch instruction, mirroring {@code
	 *  DecompilerSwitchAnalysisCmd.disassembleTable} step for step: clears any stale references
	 *  first (unless the flow is a call), adds one {@code SourceType.ANALYSIS} mnemonic
	 *  reference per kept target, flows the switch site's context register (if any) onto each
	 *  target the way the stock command's {@code setSwitchTargetContext} does, and disassembles
	 *  whichever kept targets are still undefined in one batch. This is the fallback for when
	 *  there is no real {@link Function} to anchor a {@link JumpTable} override's namespace to
	 *  (see the class javadoc); stock's own {@code FindFunctionCallback} bails out of any
	 *  location that already carries a computed reference, so adding these here is what stops it
	 *  from ever revisiting the site and over-reading it. If the switch instruction is not in
	 *  the listing yet (the decompiler followed flow there first, grm-aemp), disassembles it;
	 *  returns false only if that still leaves no instruction. */
	private boolean pinByReferences(Program program, Listing listing, Address switchAddr,
			List<Address> keptTargets, TaskMonitor monitor) throws CancelledException {
		Instruction instr = listing.getInstructionAt(switchAddr);
		if (instr == null) {
			// grm-aemp: the decompiler reached the switch by following flow the listing has not
			// disassembled yet. Lay the switch down now -- it is real flow from a real function --
			// so the pin lands before stock switch analysis can over-read the table.
			new DisassembleCommand(switchAddr, null, true).applyTo(program);
			instr = listing.getInstructionAt(switchAddr);
			if (instr == null) {
				return false;
			}
		}
		FlowType flowType = instr.getFlowType();
		List<Address> stale = List.of();
		if (flowType.isCall()) {
			flowType = RefType.COMPUTED_JUMP; // matches DecompilerSwitchAnalysisCmd verbatim
		}
		else {
			// grm-vrkk.11: a pin can land after stock switch analysis over-read the switch; the
			// references it drops here are that over-read, retracted below once the pin is in.
			stale = staleCaseTargets(program, switchAddr, keptTargets, false);
			program.getReferenceManager().removeAllReferencesFrom(instr.getMinAddress());
		}

		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue switchContext = null;
		if (baseContextRegister != null) {
			switchContext = programContext.getRegisterValue(baseContextRegister, switchAddr);
			switchContext = programContext.getFlowValue(switchContext);
		}

		AddressSet disSetList = new AddressSet();
		for (Address caseStart : keptTargets) {
			monitor.checkCancelled();
			instr.addMnemonicReference(caseStart, flowType, SourceType.ANALYSIS);
			if (listing.getUndefinedDataAt(caseStart) == null) {
				continue; // already code or defined data there -- nothing to disassemble
			}
			if (disSetList.contains(caseStart)) {
				continue;
			}
			try {
				setSwitchTargetContext(program, programContext, caseStart, switchContext);
			}
			catch (ContextChangeException e) {
				continue; // two threads racing the same function; skip, matches stock
			}
			disSetList.add(caseStart);
		}
		if (!disSetList.isEmpty()) {
			DisassembleCommand cmd = new DisassembleCommand(disSetList, null, true);
			cmd.applyTo(program);
		}
		if (!stale.isEmpty()) {
			int cleared = retractCaseTargets(program, switchAddr, stale, monitor);
			Function owner = program.getFunctionManager().getFunctionContaining(switchAddr);
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(program, owner, monitor);
			}
			AnalyzerLog.info(this, "pin retracted " + stale.size() + " over-read case(s) at " +
				switchAddr + "; cleared flow from " + cleared + " of them");
		}
		return true;
	}

	/**
	 * Undoes stock switch analysis's over-read at a switch this analyzer just bounded by override
	 * (grm-jt7s). Most overrides land late, after stock {@code DecompilerSwitchAnalyzer} already laid
	 * one reference and one {@code switchD_<addr>::caseD_<n>} label per case it read, and
	 * disassembled every target (see the {@code jumptablebound-late-override-load-bearing} memory).
	 * The decompiler then honours the override, but the listing keeps the over-read: megaman2's
	 * {@code 92e4} was bounded 255 -> 15 and still carried 224 targets, one of them {@code da2b},
	 * an {@code ORA ($00,X)} decoded over data that falls into a {@code BRK}, all inside
	 * {@code FUN_925b}'s body.
	 *
	 * <p>For each {@code ANALYSIS} computed-jump reference whose target is not a kept case, this
	 * removes the reference and stock's {@code ANALYSIS} case label there, and then clears the code
	 * from that target when nothing else reaches it -- the guard and the command
	 * {@link DecidedBranchAnalyzer} uses for a dead fall-through. A kept case is matched by offset
	 * alone, so a reference that was retargeted into an overlay copy of a kept target stays. Only
	 * ever called after {@link JumpTable#writeOverride} succeeded; the pin path retracts the
	 * references it replaces the same way ({@link #pinByReferences}, grm-vrkk.11).
	 */
	private void retractStaleCases(Program program, Function function, Address switchAddr,
			List<Address> keptTargets, TaskMonitor monitor) throws CancelledException {
		List<Address> stale = staleCaseTargets(program, switchAddr, keptTargets, true);
		if (stale.isEmpty()) {
			return;
		}
		int cleared = retractCaseTargets(program, switchAddr, stale, monitor);
		if (!function.isDeleted()) {
			CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
		}
		AnalyzerLog.info(this, "retracted " + stale.size() + " over-read case(s) at " + switchAddr +
			"; cleared flow from " + cleared + " of them");
	}

	/** The targets of {@code switchAddr}'s {@code ANALYSIS} computed-jump references that are not
	 *  kept cases (matched by offset alone, see {@link #retractStaleCases}); deletes those
	 *  references when {@code delete} is set. */
	private static List<Address> staleCaseTargets(Program program, Address switchAddr,
			List<Address> keptTargets, boolean delete) {
		Set<Long> keptOffsets = new LinkedHashSet<>();
		for (Address a : keptTargets) {
			keptOffsets.add(a.getOffset());
		}
		List<Address> stale = new ArrayList<>();
		for (Reference ref : program.getReferenceManager().getReferencesFrom(switchAddr)) {
			if (RefType.COMPUTED_JUMP.equals(ref.getReferenceType()) &&
				ref.getSource() == SourceType.ANALYSIS &&
				!keptOffsets.contains(ref.getToAddress().getOffset())) {
				stale.add(ref.getToAddress());
				if (delete) {
					program.getReferenceManager().delete(ref);
				}
			}
		}
		return stale;
	}

	/**
	 * Removes stock's {@code switchD_<switchAddr>} {@code ANALYSIS} case labels at each of
	 * {@code stale} (targets the switch no longer references) and clears the code from each one
	 * nothing else reaches; returns how many it cleared from. Reached means {@link
	 * DecidedBranchAnalyzer#deadCodeStart}'s rule -- a flow reference, a pointer, an entry point, a
	 * function or a named label -- or an instruction falling through into the target that stays
	 * (grm-vrkk.11: an over-read entry can land mid-run in real code, which no reference marks).
	 * A fall-through from code this same retraction clears does not count: a target whose
	 * fall-from chain leads back to another cleared target is cleared too. Code reached only
	 * through an over-read is accidental reach (owner ruling on grm-vrkk.11).
	 */
	static int retractCaseTargets(Program program, Address switchAddr, List<Address> stale,
			TaskMonitor monitor) throws CancelledException {
		SymbolTable symtab = program.getSymbolTable();
		String switchNamespace = "switchD_" + switchAddr;
		Listing listing = program.getListing();
		AddressSet clearStarts = new AddressSet();
		List<Address> fallenInto = new ArrayList<>();
		for (Address target : stale) {
			monitor.checkCancelled();
			for (Symbol symbol : symtab.getSymbols(target)) {
				if (symbol.getSource() == SourceType.ANALYSIS &&
					symbol.getParentNamespace().getName().equals(switchNamespace)) {
					symbol.delete();
				}
			}
			Instruction instr = listing.getInstructionAt(target);
			if (instr == null || !DecidedBranchAnalyzer.deadCodeStart(program, target)) {
				continue;
			}
			if (instr.getFallFrom() == null) {
				clearStarts.add(target);
			}
			else {
				fallenInto.add(target);
			}
		}
		for (Address target : fallenInto) {
			if (fallsFromCleared(listing, target, clearStarts)) {
				clearStarts.add(target);
			}
		}
		if (clearStarts.isEmpty()) {
			return 0;
		}
		// Not clearing data: a defined table among the stale targets is someone's claim.
		new ClearFlowAndRepairCmd(clearStarts, false, false, true).applyTo(program, monitor);
		return (int) clearStarts.getNumAddresses();
	}

	/** Bound on {@link #fallsFromCleared}'s walk back. */
	private static final int FLOW_WALK_LIMIT = 4096;

	/** Whether {@code target}'s chain of fall-from instructions, walked back, reaches one of
	 *  {@code clearStarts} -- i.e. it is entered only by falling out of code being cleared. */
	private static boolean fallsFromCleared(Listing listing, Address target, AddressSet clearStarts) {
		Instruction instr = listing.getInstructionAt(target);
		for (int i = 0; instr != null && i < FLOW_WALK_LIMIT; i++) {
			Address from = instr.getFallFrom();
			if (from == null) {
				return false;
			}
			if (clearStarts.contains(from)) {
				return true;
			}
			instr = listing.getInstructionAt(from);
		}
		return false;
	}

	/** Verbatim port of {@code DecompilerSwitchAnalysisCmd.setSwitchTargetContext}: flows the
	 *  switch site's context register value onto a kept target, combined with whatever non-default
	 *  context the target already has. */
	private void setSwitchTargetContext(Program program, ProgramContext programContext,
			Address targetStart, RegisterValue switchContext) throws ContextChangeException {
		if (switchContext == null) {
			return;
		}
		RegisterValue curContext =
			programContext.getNonDefaultValue(switchContext.getRegister(), targetStart);
		if (curContext != null) {
			switchContext = curContext.combineValues(switchContext);
		}
		if (switchContext == null || !switchContext.hasAnyValue()) {
			return;
		}
		program.getProgramContext().setRegisterValue(targetStart, targetStart, switchContext);
	}

	/**
	 * Moves an override for {@code switchAddr} written under a DIFFERENT function onto
	 * {@code function}, and deletes the stale one. Returns true iff it moved one.
	 * <p>
	 * The override lives in {@code override/jmp_<addr>} under whichever function contained the
	 * switch when it was written, and the decompiler only reads it from the function that
	 * contains the switch now. Newly reachable code changes that: a switch written under a
	 * caller's body becomes part of its own function once the {@code JSR} target is made a
	 * function (dragonpower 8655: first under the body reached from 85a7, then FUN_8645). Before
	 * this, {@link #alreadyOverridden} looked only under the current function, so the switch was
	 * bounded a second time and the first label set was left behind as a dead, non-primary copy
	 * -- present or not depending on which ran first, which made the row flip between 207 and
	 * 259 symbols (grm-v60.1). Moving (rather than skipping, or re-deriving) keeps the result
	 * independent of that order, and carries a human's GUI override along instead of dropping it.
	 * Ghidra function bodies cannot overlap, so the stale function no longer contains the switch;
	 * an override under a function that still does is left alone (not ours to move).
	 * <p>
	 * Called from two places. Here, when this analyzer revisits the switch, but a revisit is not
	 * guaranteed. And from {@link JumpTableOverrideRelocatorAnalyzer} whenever a function is created,
	 * which is the event that strands an override, so the result does not depend on order.
	 */
	static boolean relocateStaleOverride(Analyzer analyzer, Program program, Function function,
			Address switchAddr, MessageLog log) {
		SymbolTable symtab = program.getSymbolTable();
		String jmpName = "jmp_" + switchAddr.toString();
		for (Symbol sym : symtab.getSymbols(switchAddr)) {
			if (!"switch".equals(sym.getName())) {
				continue;
			}
			Namespace jmpSpace = sym.getParentNamespace();
			Namespace overrideSpace = jmpSpace == null ? null : jmpSpace.getParentNamespace();
			if (overrideSpace == null || !jmpName.equals(jmpSpace.getName()) ||
				!"override".equals(overrideSpace.getName()) ||
				!(overrideSpace.getParentNamespace() instanceof Function other) ||
				other.equals(function) || other.getBody().contains(switchAddr)) {
				continue;
			}
			// The destinations are the namespace's case* labels. (JumpTable.readOverride keeps
			// them in a private override field -- its getCases() is null for a read-back table.)
			ArrayList<Address> dests = new ArrayList<>();
			for (Symbol s : symtab.getSymbols(jmpSpace)) {
				if (s.getName().startsWith("case")) {
					dests.add(s.getAddress());
				}
			}
			if (dests.isEmpty()) {
				continue;
			}
			try {
				new JumpTable(switchAddr, dests, true, EquateSymbol.FORMAT_DEFAULT)
						.writeOverride(function);
				HighFunction.clearNamespace(symtab, jmpSpace);
				symtab.getNamespaceSymbol(jmpName, overrideSpace).delete();
			}
			catch (InvalidInputException | RuntimeException e) {
				AnalyzerLog.warn(analyzer, log, "could not move jump table override at " + switchAddr +
					" from " + other.getName() + ": " + e.getMessage());
				return false;
			}
			return true;
		}
		return false;
	}

	/** Whether this analyzer bounded {@code switchAddr} (its EOL comment says so) and no override
	 *  for it exists under any function -- i.e. it was pinned by references only, because no real
	 *  function contained the switch on any pass that reached it (grm-kon2). */
	static boolean boundWithoutOverride(Program program, Address switchAddr) {
		String eol = program.getListing().getComment(CommentType.EOL, switchAddr);
		if (eol == null || !eol.contains("[JumpTableBound] table at ") ||
			eol.contains("read from switched-in bank")) {
			return false; // a cross-bank pin can never carry an override (grm-pwuh)
		}
		String jmpName = "jmp_" + switchAddr.toString();
		for (Symbol sym : program.getSymbolTable().getSymbols(switchAddr)) {
			Namespace jmpSpace = sym.getParentNamespace();
			if ("switch".equals(sym.getName()) && jmpSpace != null &&
				jmpName.equals(jmpSpace.getName())) {
				return false;
			}
		}
		return true;
	}

	/** Whether {@code switchAddr}'s jump table already carries an override -- ours from an
	 *  earlier analysis round, or a human's from the GUI. Mirrors the private namespace naming
	 *  {@code JumpTable}'s own {@code writeOverride}/{@code getSwitchNamespace} use
	 *  ({@code "jmp_" + switchAddr}) under the function's {@code "override"} namespace. */
	private boolean alreadyOverridden(Program program, Function function, Address switchAddr) {
		Namespace overrideSpace = HighFunction.findOverrideSpace(function);
		if (overrideSpace == null) {
			return false;
		}
		SymbolTable symtab = program.getSymbolTable();
		Namespace jmpSpace =
			HighFunction.findNamespace(symtab, overrideSpace, "jmp_" + switchAddr.toString());
		if (jmpSpace == null) {
			return false;
		}
		return JumpTable.readOverride(jmpSpace, symtab) != null;
	}
}
