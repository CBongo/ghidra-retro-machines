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
// Every instruction in the program, one line each, so two runs' listings can be diffed to the
// exact addresses where they part when a real-ROM row's instruction count moves (bead
// grm-hf5h.27: w_ct lost 14 instructions to a change that cut no call). Any platform;
// read-only. The golden dumps carry only counts, and DeterminismProbe covers NES overlays only.
//
//   REALROM_EXTRA_POSTSCRIPT=InstructionListDump.java REALROM_WORK_DIR=<dir> \
//     bash tools/banktest/realrom-test.sh check --only <id> <set>
//
// Output: `ILD <addr> <instruction> <flowtype>[ override=<o>] [fn=<entry>]` per instruction to
// <dir>/<id>.ild (GRM_ILD_OUT overrides the path), and `ILD total=<n>` in the log.

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class InstructionListDump extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String out = System.getenv("GRM_ILD_OUT");
		if (out == null || out.isBlank()) {
			String dir = System.getenv("REALROM_WORK_DIR");
			out = (dir == null ? "." : dir) + "/" + currentProgram.getName().replaceAll("\\.[^.]*$", "") +
				".ild";
		}
		int n = 0;
		try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
			for (Instruction i : currentProgram.getListing().getInstructions(true)) {
				Function fn = getFunctionContaining(i.getAddress());
				w.println("ILD " + i.getAddress() + " " + i + " " + i.getFlowType() +
					(i.getFlowOverride() == FlowOverride.NONE ? "" : " override=" + i.getFlowOverride()) +
					(fn == null ? " fn=-" : " fn=" + fn.getEntryPoint()));
				n++;
			}
		}
		println("ILD total=" + n + " -> " + out);
	}
}
