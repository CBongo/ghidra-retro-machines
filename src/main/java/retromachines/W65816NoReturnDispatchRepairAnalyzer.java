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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Undoes stock {@code CallFixupChangeAnalyzer} stopping a dispatch call when
 * {@link W65816NoReturnFlagAnalyzer} flags one of its targets (bead grm-hf5h.33). On the
 * no-return flag change, stock {@code setNoFallThru} puts {@code CALL_RETURN} on EVERY
 * instruction with a call reference to the function, so a {@code JSR ($tbl,X)} whose table
 * holds the flagged routine as one entry among many loses its fall-through (w_ct: six dispatch
 * sites, 14 instructions). This analyzer takes the same function-modifier event one priority step
 * later and gives those calls their fall-through back
 * ({@link W65816NoReturnFlagAnalyzer#repairDispatchCalls}).
 * <p>
 * On by default: it acts only on functions carrying the flag analyzer's own bookmark, so it is a
 * no-op while that analyzer is off.
 */
public class W65816NoReturnDispatchRepairAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 65816 Non-Returning Dispatch Repair";
	private static final String DESCRIPTION =
		"Gives back the fall-through of a computed call (JSR ($tbl,X)) that Ghidra stopped " +
			"because one table entry was flagged no-return by 'Retro 65816 Non-Returning " +
			"Functions' while another entry returns (grm-hf5h.33).";

	public W65816NoReturnDispatchRepairAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_MODIFIERS_ANALYZER);
		// Just after CallFixupChangeAnalyzer (DISASSEMBLY.after()), which cuts the calls.
		setPriority(AnalysisPriority.DISASSEMBLY.after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSet calls = callsToFlagged(program, set, monitor);
		if (calls.isEmpty()) {
			return false;
		}
		int repaired = W65816NoReturnFlagAnalyzer.repairDispatchCalls(program, calls, monitor);
		if (repaired > 0) {
			AnalyzerLog.info(this, "gave back the fall-through of " + repaired + " dispatch " +
				"call(s) stopped because one table entry is flagged no-return (grm-hf5h.33)");
		}
		return true;
	}

	/** Call sites of every flagged function (and its thunks) whose entry is in {@code set}. */
	static AddressSet callsToFlagged(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		AddressSet calls = new AddressSet();
		for (Function fn : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			if (!W65816NoReturnFlagAnalyzer.flaggedHere(program, fn)) {
				continue;
			}
			addCallers(program, fn.getEntryPoint(), calls);
			Address[] thunks = fn.getFunctionThunkAddresses(true);
			if (thunks != null) {
				for (Address t : thunks) {
					addCallers(program, t, calls);
				}
			}
		}
		return calls;
	}

	private static void addCallers(Program program, Address entry, AddressSet calls) {
		for (Reference r : program.getReferenceManager().getReferencesTo(entry)) {
			if (r.getReferenceType().isCall()) {
				calls.add(r.getFromAddress());
			}
		}
	}
}
