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

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

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
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Stops the false fall-through after a {@code JSR} to a 6502 subroutine that discards its
 * caller's return address -- a pop-return helper, an inline-table JumpEngine or an inline-argument
 * far-call trampoline, all measured by {@link PopReturnHelper} as unwind level 1 or more
 * (grm-ed6h, grm-0fzb) -- WITHOUT marking that subroutine no-return.
 *
 * <p><b>Why not no-return.</b> Ghidra's function-level no-return flag says "never comes back to
 * anyone", but these helpers come back to the caller's caller. The flag propagates: a far-call
 * stub or a dispatch routine that starts with {@code JSR helper} becomes a THUNK of the helper,
 * a thunk shares the helper's flag, and every caller of the stub loses its fall-through (zelda,
 * smb2, tmnt, dbz2; dbz2 {@code ca9a} then crashed the decompiler, grm-hf5h.13). Stock "calls
 * only non-returning functions" does the same to a routine that ends in such a call (Metroid
 * {@code d4cb}). The accurate model is per call site: each direct {@code JSR} gets a
 * {@link FlowOverride#CALL_RETURN} override and the code decoded at its old fall-through is
 * cleared (unless something else flows into it); the helper itself stays returning.
 *
 * <p><b>Priority: before stock.</b> {@link AnalysisPriority#DISASSEMBLY}{@code .after()}, one
 * step ahead of stock {@code FindNoReturnFunctionsAnalyzer}. Stock counts evidence only at calls
 * that still fall through, so once every {@code JSR} to a helper is overridden it has nothing to
 * count and never flags the helper. Clearing stock's flag AFTER it ran instead fed it the same
 * evidence on the next pass, and an earlier attempt oscillated 583 times (grm-hf5h.12).
 *
 * <p><b>Undoing a flag already set</b> (stock got there first, or an older analysis): a
 * recognized helper with the flag has it cleared, and so does every flagged function the
 * recognizer measures as level 0 that is a caller or a stub of a helper; each such function's
 * callers whose {@code JSR} was overridden to {@code CALL_RETURN} get their fall-through back
 * (override removed, fall-through disassembled). That repeats up the call graph for callers that
 * were flagged in turn.
 *
 * @see <a href="urn:bead:grm-ed6h">grm-ed6h</a>
 * @see <a href="urn:bead:grm-0fzb">grm-0fzb</a>
 * @see PopReturnHelper
 */
public class PopReturnHelperAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 6502 Pop-Return Helpers";
	private static final String DESCRIPTION =
		"Stops the false fall-through after each JSR to a 6502 subroutine that discards its " +
			"caller's return address (PLA/PLA/RTS, JumpEngine, far-call trampoline), without " +
			"marking the subroutine non-returning (grm-ed6h, grm-0fzb).";

	private PopReturnHelper.Levels levels;

	public PopReturnHelperAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return AnalyzerGates.is8BitPcode(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (levels == null) {
			levels = new PopReturnHelper.Levels(program);
		}
		Set<Address> helpers = new LinkedHashSet<>();
		for (Instruction instr : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			if (!"JSR".equals(instr.getMnemonicString()) || !instr.getFlowType().isCall()) {
				continue;
			}
			Address[] flows = instr.getFlows();
			if (flows.length != 1) {
				continue;
			}
			Integer level = levels.of(flows[0]);
			if (level != null && level >= 1) {
				helpers.add(flows[0]);
			}
		}
		int sites = 0;
		Set<Function> unflagged = new LinkedHashSet<>();
		int restored = 0;
		for (Address helper : helpers) {
			monitor.checkCancelled();
			sites += applyHelper(program, helper, unflagged, monitor);
		}
		if (!unflagged.isEmpty()) {
			restored = restoreCallers(program, unflagged, monitor);
		}
		if (sites > 0 || !unflagged.isEmpty()) {
			AnalyzerLog.info(this, "stopped fall-through at " + sites + " JSR site(s) to " +
				helpers.size() + " return-discarding helper(s) " + helpers +
				(unflagged.isEmpty() ? ""
						: "; cleared no-return on " + unflagged.size() + " function(s), " +
							"restored fall-through at " + restored + " call site(s)"));
		}
		return true;
	}

	/** @return the number of call sites whose fall-through was newly stopped */
	private int applyHelper(Program program, Address entry, Set<Function> unflagged,
			TaskMonitor monitor) throws CancelledException {
		Function function = program.getFunctionManager().getFunctionAt(entry);
		if (function == null) {
			new CreateFunctionCmd(entry).applyTo(program, monitor);
			function = program.getFunctionManager().getFunctionAt(entry);
		}
		if (function != null && !function.isThunk() && function.hasNoReturn()) {
			function.setNoReturn(false);
			unflagged.add(function);
		}

		AddressSet clear = new AddressSet();
		Set<Function> callers = new LinkedHashSet<>();
		int sites = 0;
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(entry);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Instruction call = program.getListing().getInstructionAt(ref.getFromAddress());
			if (call == null) {
				continue;
			}
			Function caller =
				program.getFunctionManager().getFunctionContaining(call.getAddress());
			if (caller != null) {
				callers.add(caller);
				unflagIfNormal(caller, unflagged);
			}
			Function stub = program.getFunctionManager().getFunctionAt(call.getAddress());
			if (stub != null) {
				unflagIfNormal(stub, unflagged);
			}
			Address fallthrough = call.getFallThrough();
			if (fallthrough == null) {
				continue; // already stopped (by us earlier, by stock, or by the disassembler)
			}
			call.setFlowOverride(FlowOverride.CALL_RETURN);
			sites++;
			if (!fallthrough.equals(entry) && !hasFlowRefInto(program, fallthrough) &&
				!program.getSymbolTable().isExternalEntryPoint(fallthrough) &&
				program.getListing().getInstructionAt(fallthrough) != null) {
				clear.add(fallthrough);
			}
		}

		fixBodies(program, callers, monitor);

		if (!clear.isEmpty()) {
			AddressSetView protectedSet =
				AutoAnalysisManager.getAnalysisManager(program).getProtectedLocations();
			new ClearFlowAndRepairCmd(clear, protectedSet, true, false, true)
					.applyTo(program, monitor);
		}
		return sites;
	}

	/**
	 * Clears a no-return flag the recognizer contradicts: {@code fn} provably returns to its
	 * caller (level 0). A thunk is skipped -- it shares its target's flag, cleared with the target.
	 */
	private void unflagIfNormal(Function fn, Set<Function> unflagged) {
		if (fn.isThunk() || !fn.hasNoReturn()) {
			return;
		}
		Integer level = levels.of(fn.getEntryPoint());
		if (level != null && level == PopReturnHelper.NORMAL) {
			fn.setNoReturn(false);
			unflagged.add(fn);
		}
	}

	/**
	 * Gives back the fall-through at every {@code JSR} into a function whose no-return flag was
	 * just cleared, or into one of its thunks, when that callee measures as level 0 (a helper's
	 * own call sites stay stopped), then repeats for callers that were themselves
	 * flagged only because of it.
	 *
	 * @return the number of call sites restored
	 */
	private int restoreCallers(Program program, Set<Function> start, TaskMonitor monitor)
			throws CancelledException {
		ArrayDeque<Function> work = new ArrayDeque<>(start);
		Set<Function> done = new HashSet<>();
		Set<Function> bodies = new LinkedHashSet<>();
		AddressSet disassemble = new AddressSet();
		int restored = 0;
		while (!work.isEmpty()) {
			monitor.checkCancelled();
			Function fn = work.poll();
			if (!done.add(fn)) {
				continue;
			}
			Set<Address> entries = new LinkedHashSet<>();
			entries.add(fn.getEntryPoint());
			Address[] thunks = fn.getFunctionThunkAddresses(true);
			if (thunks != null) {
				entries.addAll(Arrays.asList(thunks));
			}
			for (Address entry : entries) {
				Integer entryLevel = levels.of(entry);
				if (entryLevel == null || entryLevel != PopReturnHelper.NORMAL) {
					continue; // a helper's own JSRs stay stopped; only level-0 callees return
				}
				for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
					if (!ref.getReferenceType().isCall()) {
						continue;
					}
					Instruction call =
						program.getListing().getInstructionAt(ref.getFromAddress());
					if (call == null || !"JSR".equals(call.getMnemonicString()) ||
						call.getFlowOverride() != FlowOverride.CALL_RETURN) {
						continue;
					}
					call.setFlowOverride(FlowOverride.NONE);
					restored++;
					Address ft = call.getFallThrough();
					if (ft != null && program.getListing().getInstructionAt(ft) == null) {
						disassemble.add(ft);
					}
					Function caller =
						program.getFunctionManager().getFunctionContaining(call.getAddress());
					if (caller != null) {
						bodies.add(caller);
						if (!caller.isThunk() && caller.hasNoReturn()) {
							Integer level = levels.of(caller.getEntryPoint());
							if (level != null && level == PopReturnHelper.NORMAL) {
								caller.setNoReturn(false);
								work.add(caller);
							}
						}
					}
				}
			}
		}
		if (!disassemble.isEmpty()) {
			new DisassembleCommand(disassemble, null, true).applyTo(program, monitor);
		}
		fixBodies(program, bodies, monitor);
		return restored;
	}

	private static void fixBodies(Program program, Set<Function> functions, TaskMonitor monitor)
			throws CancelledException {
		for (Function fn : functions) {
			monitor.checkCancelled();
			if (!fn.getBody().equals(
				CreateFunctionCmd.getFunctionBody(program, fn.getEntryPoint()))) {
				CreateFunctionCmd.fixupFunctionBody(program, fn, monitor);
			}
		}
	}

	/** A flow (not data) reference into {@code addr}: someone else reaches it as code. */
	private static boolean hasFlowRefInto(Program program, Address addr) {
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(addr);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}
}
