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

import java.util.Set;
import java.util.TreeSet;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The code-added half of {@link ConditionalTailCallNarrowingAnalyzer} (grm-6m24.1): runs ahead of
 * the stock {@code SharedReturnJumpAnalyzer}, which gives a CALL_RETURN to newly disassembled
 * jumps, conditional ones included under "Allow Conditional Jumps", into EXISTING functions. Same
 * name as the function-added half, so the options dialog shows one entry, as the stock pair does.
 */
public class ConditionalTailCallNarrowingJumpAnalyzer extends ConditionalTailCallNarrowingAnalyzer {

	public ConditionalTailCallNarrowingJumpAnalyzer() {
		super(AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Set<Address> fresh = new TreeSet<>();
		for (Instruction instr : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			// Conditional jumps are the candidates; calls are watched too, because a new JSR into
			// a function makes it genuine and hands its pinned branches back.
			FlowType flow = instr.getFlowType();
			if (!(flow.isJump() && flow.isConditional()) && !flow.isCall()) {
				continue;
			}
			for (Reference ref : instr.getReferencesFrom()) {
				Address to = ref.getToAddress();
				if (ref.getReferenceType().isFlow() &&
					program.getFunctionManager().getFunctionAt(to) != null) {
					fresh.add(to);
				}
			}
		}
		return recheck(program, fresh, monitor);
	}
}
