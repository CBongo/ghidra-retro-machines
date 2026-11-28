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

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The code-added half of {@link ContiguousFunctionJumpAnalyzer} (grm-q83o), as stock
 * {@code SharedReturnJumpAnalyzer} is of {@code SharedReturnAnalyzer}: it gathers the existing
 * functions that new jumps land on and runs the scan around those. It has the same name, so the
 * options dialog shows one entry.
 */
public class ContiguousFunctionJumpInstructionAnalyzer extends ContiguousFunctionJumpAnalyzer {

	public ContiguousFunctionJumpInstructionAnalyzer() {
		super(AnalyzerType.INSTRUCTION_ANALYZER);
		setSupportsOneTimeAnalysis(false);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ReferenceManager refs = program.getReferenceManager();
		Listing listing = program.getListing();
		AddressSet entries = new AddressSet();
		AddressIterator it = refs.getReferenceSourceIterator(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Address addr = it.next();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null || !instr.getFlowType().isJump()) {
				continue;
			}
			for (Reference ref : refs.getFlowReferencesFrom(addr)) {
				if (ref.getReferenceType().isJump() &&
					program.getFunctionManager().getFunctionAt(ref.getToAddress()) != null) {
					entries.add(ref.getToAddress());
				}
			}
		}
		return super.added(program, entries, monitor, log);
	}
}
