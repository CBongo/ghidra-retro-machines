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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
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
 * is not in initialized, non-volatile memory.
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
		if (!program.getLanguage().supportsPcode()) {
			return false;
		}
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		return defaultSpace != null && defaultSpace.getSize() <= 16;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Address> locations = findComputedJumpLocations(program, listing, set, monitor);
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
		if (functions.isEmpty()) {
			return true;
		}

		DecompInterface ifc = new DecompInterface();
		try {
			new SwitchAnalysisDecompileConfigurer(program).configure(ifc);
			if (!ifc.openProgram(program)) {
				AnalyzerLog.warn(this, log, "decompiler failed to open program: " +
					ifc.getLastMessage());
				return true;
			}
			int bounded = 0;
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
				for (JumpTable table : hfunction.getJumpTables()) {
					if (processTable(program, listing, function, table, monitor, log)) {
						bounded++;
					}
				}
			}
			if (bounded > 0) {
				AnalyzerLog.info(this, "bounded " + bounded + " jump table(s)");
			}
		}
		finally {
			ifc.dispose();
		}
		return true;
	}

	/** Finds computed-jump instructions in {@code set}, the same predicate stock
	 *  {@code DecompilerSwitchAnalyzer.findLocations} uses (a jump whose flow is computed),
	 *  skipping any that already carry a computed reference -- either the stock analyzer or an
	 *  earlier round already resolved them, so there is nothing left to over-read. */
	private List<Address> findComputedJumpLocations(Program program, Listing listing,
			AddressSetView set, TaskMonitor monitor) throws CancelledException {
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
			JumpTable table, TaskMonitor monitor, MessageLog log) throws CancelledException {
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
		List<Long> targets = new ArrayList<>(realCases.size());
		for (Address a : realCases) {
			if (!sameMemory(a.getAddressSpace(), targetSpace)) {
				return false; // mixed-space case list; shape not understood, decline
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

		JumpTableBound.Result result = JumpTableBound.bound(targets, loadTables, tableBlock);
		if (!result.isBounded() && sameMemory(switchAddr.getAddressSpace(), targetSpace)) {
			// Table after its code (grm-akiv): the lowest-target rule declines by design.
			result = JumpTableBound.boundBySwitchWindow(switchAddr.getOffset(), targets,
				loadTables);
		}
		if (!result.isBounded()) {
			// grm-yjiq: an overlapping byte table whose handlers straddle it; see the javadoc.
			List<Boolean> inCode = new ArrayList<>(realCases.size());
			for (Address a : realCases) {
				MemoryBlock block = program.getMemory().getBlock(a);
				inCode.add(block != null && block.isInitialized() && !block.isVolatile());
			}
			result = JumpTableBound.boundByValidTargets(targets, loadTables, inCode);
		}
		if (!result.isBounded() || result.count() >= realCases.size()) {
			return false; // decline, or would not shrink the table -- must be a no-op
		}

		// Normally the first count() cases; every other one for a grm-yjiq overlapping byte table.
		ArrayList<Address> firstN = new ArrayList<>(result.keep(realCases));
		if (isUndefined) {
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
		}

		long tableStart = 0;
		boolean haveStart = false;
		for (JumpTableBound.LoadTableEntry lt : loadTables) {
			if (lt.num() > 1 && (!haveStart || lt.start() < tableStart)) {
				tableStart = lt.start();
				haveStart = true;
			}
		}
		String why;
		if (result.rule() == JumpTableBound.Rule.SWITCH_WINDOW) {
			why = "targets between switch and table";
		}
		else if (result.rule() == JumpTableBound.Rule.BELOW_TABLE_CUT) {
			why = "first target below table"; // grm-fxtp
		}
		else if (result.rule() == JumpTableBound.Rule.VALID_TARGET_CUT) {
			why = "first target outside code memory"; // grm-yjiq
		}
		else {
			why = "lowest target " + Long.toHexString(result.lowestTarget());
		}
		if (result.stride() > 1) {
			why += ", even cases only"; // grm-yjiq: odd cases straddle two entries
		}
		String text = "[JumpTableBound] table at " + Long.toHexString(tableStart) + " bounded " +
			realCases.size() + " -> " + result.count() + " entries (" + why + ")";
		String existing = listing.getComment(CommentType.EOL, switchAddr);
		listing.setComment(switchAddr, CommentType.EOL,
			existing == null || existing.isBlank() ? text : existing + "; " + text);
		return true;
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
	 *  from ever revisiting the site and over-reading it. Returns false only if the switch
	 *  instruction itself cannot be found (should not happen; the caller just decompiled a
	 *  function containing it). */
	private boolean pinByReferences(Program program, Listing listing, Address switchAddr,
			List<Address> keptTargets, TaskMonitor monitor) throws CancelledException {
		Instruction instr = listing.getInstructionAt(switchAddr);
		if (instr == null) {
			return false;
		}
		FlowType flowType = instr.getFlowType();
		if (flowType.isCall()) {
			flowType = RefType.COMPUTED_JUMP; // matches DecompilerSwitchAnalysisCmd verbatim
		}
		else {
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
		return true;
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
