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

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

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
 * Stops the false fall-through after a {@code JSR} to a 6502 "pop-return" helper (grm-ed6h): a
 * subroutine that discards its own return address ({@code PLA / PLA / RTS}) and so returns to its
 * caller's caller. Ghidra assumes every {@code JSR} falls through and decodes whatever follows as
 * code -- on Metroid, {@code e5dd JSR $c376} is followed by data that decodes as
 * {@code JSR $A29E}, a bogus call into a banked window.
 *
 * <p>For every {@code JSR} in the added set whose single target {@link PopReturnHelper#recognize}s
 * (cached per entry once conclusive), this does what stock {@code FindNoReturnFunctionsAnalyzer}
 * does for a function it discovers to be non-returning: marks the helper
 * {@link Function#setNoReturn no-return} (true for every caller, since recognition requires EVERY
 * exit to pop), overrides each call site's flow to {@link FlowOverride#CALL_RETURN}, repairs the
 * calling functions' bodies, and clears the code laid down at each call site's old fall-through
 * with {@link ClearFlowAndRepairCmd} -- unless something else flows into that address, in which
 * case it is real code and stays. A helper that pops on only some paths (Metroid {@code c36b}) is
 * declined: its calls genuinely may fall through.
 *
 * <p><b>Priority.</b> The same slot as {@link InlineJumpTableDispatchAnalyzer}
 * ({@link AnalysisPriority#CODE_ANALYSIS}{@code .before().before()}), for the same reason: the
 * bank and switch analyzers after it should never see the garbage decode.
 *
 * @see <a href="urn:bead:grm-ed6h">grm-ed6h</a>
 * @see PopReturnHelper
 */
public class PopReturnHelperAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 6502 Pop-Return Helpers";
	private static final String DESCRIPTION =
		"Marks 6502 subroutines that discard their own return address (PLA/PLA/RTS) as " +
			"non-returning and removes the false fall-through decode after each JSR to them " +
			"(grm-ed6h).";

	private final Map<Address, Boolean> helperCache = new HashMap<>();

	public PopReturnHelperAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
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
			Address target = flows[0];
			Boolean isHelper = helperCache.get(target);
			if (isHelper == null) {
				isHelper = PopReturnHelper.recognize(program, target);
				if (isHelper != null) {
					helperCache.put(target, isHelper);
				}
			}
			if (Boolean.TRUE.equals(isHelper)) {
				helpers.add(target);
			}
		}
		int sites = 0;
		for (Address helper : helpers) {
			monitor.checkCancelled();
			sites += applyHelper(program, helper, monitor);
		}
		if (sites > 0) {
			AnalyzerLog.info(this, "stopped fall-through at " + sites + " JSR site(s) to " +
				helpers.size() + " pop-return helper(s) " + helpers);
		}
		return true;
	}

	/** @return the number of call sites whose fall-through was newly stopped */
	private int applyHelper(Program program, Address entry, TaskMonitor monitor)
			throws CancelledException {
		Function function = program.getFunctionManager().getFunctionAt(entry);
		if (function == null) {
			new CreateFunctionCmd(entry).applyTo(program, monitor);
			function = program.getFunctionManager().getFunctionAt(entry);
		}
		if (function != null && !function.hasNoReturn()) {
			function.setNoReturn(true);
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
			Address fallthrough = call.getFallThrough();
			if (fallthrough == null) {
				continue; // already stopped (by us earlier, or by the disassembler)
			}
			call.setFlowOverride(FlowOverride.CALL_RETURN);
			sites++;
			Function caller = program.getFunctionManager().getFunctionContaining(call.getAddress());
			if (caller != null) {
				callers.add(caller);
			}
			if (!fallthrough.equals(entry) && !hasFlowRefInto(program, fallthrough) &&
				!program.getSymbolTable().isExternalEntryPoint(fallthrough) &&
				program.getListing().getInstructionAt(fallthrough) != null) {
				clear.add(fallthrough);
			}
		}

		for (Function caller : callers) {
			monitor.checkCancelled();
			if (!caller.getBody().equals(
				CreateFunctionCmd.getFunctionBody(program, caller.getEntryPoint()))) {
				CreateFunctionCmd.fixupFunctionBody(program, caller, monitor);
			}
		}

		if (!clear.isEmpty()) {
			AddressSetView protectedSet =
				AutoAnalysisManager.getAnalysisManager(program).getProtectedLocations();
			new ClearFlowAndRepairCmd(clear, protectedSet, true, false, true)
					.applyTo(program, monitor);
		}
		return sites;
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
