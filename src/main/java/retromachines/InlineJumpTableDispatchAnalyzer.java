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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves the "JSR inline jump table" / SMB "JumpEngine" idiom (grm-j2kl): a subroutine that
 * pops its own return address and dispatches through a word table laid out immediately after the
 * {@code JSR} that called it, rather than ever returning. Left alone, Ghidra treats the
 * {@code JSR} as an ordinary call, falls through into the table bytes as code, and never reaches
 * any of the real targets -- on {@code smb} this idiom accounts for nearly the entire game's
 * mode/state machine (1067 instructions recovered for a 32 KB cartridge before this analyzer).
 *
 * <p><b>Mechanism</b> (see {@link InlineJumpTableDispatch} for the actual logic, kept separate so
 * it is unit-testable on its own): for every {@code JSR} in the newly-added address set, checks
 * whether its target is a recognized dispatcher body (cached per entry address once the answer is
 * conclusive; a target not yet disassembled is left unresolved for a later round rather than
 * cached as a decline). For each one that is:
 * <ol>
 * <li>marks the dispatcher {@link Function} non-returning ({@link Function#setNoReturn});</li>
 * <li>overrides the {@code JSR}'s flow to {@link FlowOverride#CALL_RETURN} (a call that
 * terminates, matching what stock {@code FindNoReturnFunctionsAnalyzer} does for a call to a
 * known non-returning function) and repairs whatever Ghidra's initial linear disassembly already
 * laid down over the table bytes with {@link ClearFlowAndRepairCmd}, the same mechanism stock
 * uses for exactly this kind of damage;</li>
 * <li>reads and bounds the table right after the {@code JSR} ({@link
 * InlineJumpTableDispatch#tableEntries}), lays it down as pointer data (which itself creates the
 * memory references), disassembles each target (flowing the {@code JSR}'s own context register,
 * mirroring {@code IndirectJumpConstantPointerAnalyzer}/{@code JumpTableBoundAnalyzer}), and
 * schedules a function at each one via {@code AutoAnalysisManager.createFunction} -- a target's
 * own {@code RTS} returns to the CALLER's caller, so each is a function entry in its own right,
 * exactly like a resolved switch case.</li>
 * </ol>
 * A call site with zero recoverable table entries is left completely untouched (no noReturn, no
 * flow override, no clearing) -- there is nothing to be confident about at that address.
 *
 * <p><b>Priority.</b> {@link AnalysisPriority#CODE_ANALYSIS}{@code .before().before()}: one step
 * before {@link JumpTableBoundAnalyzer} and {@link IndirectJumpConstantPointerAnalyzer}, both at
 * {@code CODE_ANALYSIS.before()}. This analyzer needs to run first among that group so that by
 * the time those decompile or walk the dispatcher's own body (or anything downstream of a
 * call-site table this analyzer has just disassembled), the fallthrough garbage is already gone
 * and the real targets are in place -- decompiling a function whose body still contains the
 * mis-disassembled table tail would otherwise feed those analyzers garbage p-code. Being a plain
 * {@link AnalyzerType#INSTRUCTION_ANALYZER} (not one-shot) also means every newly-disassembled
 * address set -- including the call-site targets THIS analyzer itself disassembles, which on smb
 * contain further {@code JSR}s to the same dispatcher -- is re-offered to it automatically by
 * {@link AutoAnalysisManager}, so later-discovered call sites converge without any extra
 * scheduling of our own.
 *
 * @see <a href="urn:bead:grm-j2kl">grm-j2kl</a>
 * @see InlineJumpTableDispatch
 */
public class InlineJumpTableDispatchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Inline Jump Table Dispatch";
	private static final String DESCRIPTION =
		"Resolves the JSR-inline-jump-table (\"JumpEngine\") idiom: a subroutine that pops its " +
			"own return address and dispatches through a word table laid out right after the " +
			"JSR, rather than returning (grm-j2kl).";

	/** Per-dispatcher-entry recognition cache; {@code true}/{@code false} once conclusive. Not
	 *  populated for an inconclusive (not-yet-disassembled) answer, so a later round retries it. */
	private final Map<Address, Boolean> dispatcherCache = new HashMap<>();

	public InlineJumpTableDispatchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// One step before JumpTableBoundAnalyzer/IndirectJumpConstantPointerAnalyzer (both
		// CODE_ANALYSIS.before()) -- see the class javadoc's Priority section.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
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
		List<Instruction> jsrSites = findJsrSites(listing, set, monitor);

		int callSitesResolved = 0;
		int targetsScheduled = 0;
		for (Instruction jsr : jsrSites) {
			monitor.checkCancelled();
			Address target = singleFlowTarget(jsr);
			if (target == null) {
				continue;
			}
			Boolean isDispatcher = dispatcherCache.get(target);
			if (isDispatcher == null) {
				isDispatcher = InlineJumpTableDispatch.recognizeDispatcher(program, target);
				if (isDispatcher != null) {
					dispatcherCache.put(target, isDispatcher);
				}
			}
			if (!Boolean.TRUE.equals(isDispatcher)) {
				continue;
			}

			Address tableStart = jsr.getMinAddress().add(jsr.getLength());
			InlineJumpTableDispatch.CallSiteScan scan =
				InlineJumpTableDispatch.scanTable(program, tableStart);
			AnalyzerLog.debug(this, "call site " + jsr.getMinAddress() + " table " + tableStart +
				": cut=" + scan.cut + " kept=" + scan.kept.size());
			if (!scan.trimmed.isEmpty()) {
				AnalyzerLog.info(this, "call site " + jsr.getMinAddress() + " table " + tableStart +
					": kept " + scan.kept.size() + ", trimmed implausible tail " + scan.trimmed);
			}
			List<Address> entries = scan.kept;
			if (entries.isEmpty()) {
				continue; // nothing recoverable at this specific site -- do nothing (see javadoc)
			}

			applyCallSite(program, listing, jsr, target, entries, monitor, log);
			callSitesResolved++;
			targetsScheduled += entries.size();
		}

		if (callSitesResolved > 0) {
			AnalyzerLog.info(this, "resolved " + callSitesResolved +
				" inline-jump-table call site(s) at " + dispatcherCache.values()
						.stream()
						.filter(Boolean::booleanValue)
						.count() +
				" distinct dispatcher(s), scheduling " + targetsScheduled + " target(s)");
		}
		return true;
	}

	private List<Instruction> findJsrSites(Listing listing, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		List<Instruction> sites = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			if ("JSR".equals(instr.getMnemonicString())) {
				sites.add(instr);
			}
		}
		return sites;
	}

	private Address singleFlowTarget(Instruction instr) {
		Address[] flows = instr.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	/**
	 * Marks the dispatcher non-returning, stops the JSR's fallthrough, repairs whatever garbage
	 * Ghidra's initial disassembly left over the table, and lays down the table plus its targets.
	 */
	private void applyCallSite(Program program, Listing listing, Instruction jsr, Address dispatcher,
			List<Address> entries, TaskMonitor monitor, MessageLog log) throws CancelledException {
		Function function = program.getFunctionManager().getFunctionAt(dispatcher);
		if (function == null) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(dispatcher);
			cmd.applyTo(program, monitor);
			function = program.getFunctionManager().getFunctionAt(dispatcher);
		}
		if (function != null && !function.hasNoReturn()) {
			function.setNoReturn(true);
		}

		FlowType flowType = jsr.getFlowType();
		if (flowType.hasFallthrough()) {
			jsr.setFlowOverride(FlowOverride.CALL_RETURN);
		}

		Address tableStart = jsr.getMinAddress().add(jsr.getLength());
		Address tableEnd = tableStart.add(2L * entries.size() - 1);
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		AddressSet protectedSet = new AddressSet(analysisManager.getProtectedLocations());
		AddressSet clearSet = new AddressSet(tableStart, tableEnd);
		// Repair whatever Ghidra's straight-line disassembly already laid down over the table
		// (and anything that flowed from that garbage), the same mechanism stock
		// FindNoReturnFunctionsAnalyzer uses for a call to a newly-discovered non-returning
		// function.
		ClearFlowAndRepairCmd clearCmd =
			new ClearFlowAndRepairCmd(clearSet, protectedSet, true, false, true);
		clearCmd.applyTo(program, monitor);

		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue siteContext = null;
		if (baseContextRegister != null) {
			siteContext =
				programContext.getRegisterValue(baseContextRegister, jsr.getMinAddress());
			siteContext = programContext.getFlowValue(siteContext);
		}

		for (int i = 0; i < entries.size(); i++) {
			monitor.checkCancelled();
			Address entryAddr = tableStart.add(2L * i);
			Address target = entries.get(i);
			try {
				DataUtilities.createData(program, entryAddr, PointerDataType.dataType, -1,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (Exception e) {
				AnalyzerLog.warn(this, log,
					"could not lay pointer data at " + entryAddr + " (table for JSR at " +
						jsr.getMinAddress() + "): " + e.getMessage());
				continue;
			}
			// Force the pointer's reference to the resolved target explicitly, rather than trust
			// whatever space Ghidra's automatic pointer-data reference would otherwise pick: when
			// the table sits in a banked overlay and the target was resolved into the underlying
			// physical/base space (InlineJumpTableDispatch#resolveTarget, for a target in the
			// fixed, non-switchable part of the map), the raw bytes alone don't carry that space
			// choice, and an automatic reference would default to the pointer's own (overlay)
			// space -- dangling, since that space has no block there.
			program.getReferenceManager().removeAllReferencesFrom(entryAddr);
			program.getReferenceManager()
					.addMemoryReference(entryAddr, target, RefType.DATA, SourceType.ANALYSIS, 0);

			if (InlineJumpTableDispatch.isCrossWindow(program, tableStart, target)) {
				// grm-rnf0: this entry's bytes belong to whichever bank is actually live in that
				// OTHER window when the dispatcher runs, not to the HOME bank these base-space
				// bytes hold. Leave the pointer and its base-space DATA reference (just placed
				// above) for BoardBankAnalyzer's state-side resolution to find and redirect once
				// it knows the call site's live bank state; do not disassemble or create a
				// function against the wrong bank's bytes here.
				continue;
			}

			if (listing.getInstructionAt(target) == null) {
				try {
					setTargetContext(program, programContext, target, siteContext);
				}
				catch (ContextChangeException e) {
					continue; // another thread raced the same target; leave it alone
				}
				DisassembleCommand disCmd = new DisassembleCommand(new AddressSet(target), null, true);
				disCmd.applyTo(program);
			}
			analysisManager.createFunction(target, false);
		}
	}

	/** Verbatim port of {@code DecompilerSwitchAnalysisCmd.setSwitchTargetContext} (see the other
	 *  analyzers' copies in this package). */
	private void setTargetContext(Program program, ProgramContext programContext, Address target,
			RegisterValue siteContext) throws ContextChangeException {
		if (siteContext == null) {
			return;
		}
		RegisterValue curContext =
			programContext.getNonDefaultValue(siteContext.getRegister(), target);
		if (curContext != null) {
			siteContext = curContext.combineValues(siteContext);
		}
		if (siteContext == null || !siteContext.hasAnyValue()) {
			return;
		}
		program.getProgramContext().setRegisterValue(target, target, siteContext);
	}
}
