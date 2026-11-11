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
// Narrow probe (written for grm-hf5h.5): one line per direct (non-computed) call instruction, the
// population W65816WidthDump counts as "REALROM calls direct": "CALLSITE <addr> <instr> <flows>
// fn=<containing function or ->". Run as a postScript on two builds and diff the two logs'
// CALLSITE lines to name the call instructions that appeared or vanished:
//   REALROM_EXTRA_POSTSCRIPT=CallSiteListDump.java REALROM_WORK_DIR=<dir outside the repo> \
//     bash tools/banktest/realrom-test.sh check snes --only w_ct,w_fzero
// Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;

public class CallSiteListDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction in = it.next();
			FlowType ft = in.getFlowType();
			if (!ft.isCall() || ft.isComputed()) {
				continue;
			}
			Function f = currentProgram.getFunctionManager().getFunctionContaining(in.getMinAddress());
			println("CALLSITE " + in.getMinAddress() + " " + in + " " +
				java.util.Arrays.toString(in.getFlows()) + " fn=" + (f == null ? "-" : f.getName()));
		}
	}
}
