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
// Decompiles the function containing each address in GRM_DECOMPILE_SITES (comma-separated
// "<space>::<hex>" specs) and reports what the decompiler said about it: whether it completed,
// its error message if not, how many BRANCHIND ops the high function holds and how many jump
// table targets each carries. For attributing a switch-recovery difference between two
// decompile.exe builds to the decompiler itself rather than to Ghidra's Java-side analysis
// (bead grm-qp5x.4). Run as REALROM_EXTRA_POSTSCRIPT. Read-only; emits no listing text.
// GRM_DECOMPILE_DEBUG_DIR (optional, grm-hf5h.4): also write each site's decompiler debug XML
// there, for replay in decomp_test_dbg under WSL.
import java.io.File;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.app.script.GhidraScript;

public class DecompileSiteProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_DECOMPILE_SITES");
		if (spec == null || spec.isBlank()) {
			println("DECOMP no GRM_DECOMPILE_SITES given");
			return;
		}
		String dd = System.getenv("GRM_DECOMPILE_DEBUG_DIR");
		File debugDir = (dd == null || dd.isBlank()) ? null : new File(dd);
		DecompInterface ifc = new DecompInterface();
		// Collect LOAD records the way SwitchAnalysisDecompileConfigurer does: the decompiler's
		// per-entry loadcounts path (and any bound that lives on it) only runs with jumpload on.
		ifc.toggleJumpLoads(true);
		if (debugDir != null) {
			// The debug XML encodes the options, so they must be set explicitly (else an NPE).
			// Only then: without debug the probe keeps the decompiler's defaults as before.
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(currentProgram);
			ifc.setOptions(opts);
		}
		ifc.openProgram(currentProgram);
		try {
			for (String s : spec.split(",")) {
				Address a = ProbeSupport.parseSite(currentProgram, s);
				Function f = a == null ? null : currentProgram.getFunctionManager().getFunctionContaining(a);
				if (f == null) {
					println("DECOMP " + s + " no function contains it");
					continue;
				}
				if (debugDir != null) {
					// One debug XML per site, replayable in decomp_test_dbg ("restore <file>")
					File xml = new File(debugDir, s.trim().replaceAll("[^A-Za-z0-9_]+", "_") + ".xml");
					ifc.enableDebug(xml);
					println("DECOMP " + s + " debug xml " + xml);
				}
				DecompileResults res = ifc.decompileFunction(f, 60, monitor);
				String head = "DECOMP " + s + " fn=" + f.getName() + "@" + f.getEntryPoint();
				if (!res.decompileCompleted()) {
					println(head + " FAILED: " + res.getErrorMessage().trim());
					continue;
				}
				HighFunction hf = res.getHighFunction();
				int branchind = 0;
				StringBuilder tables = new StringBuilder();
				Iterator<PcodeOpAST> ops = hf.getPcodeOps();
				while (ops.hasNext()) {
					PcodeOpAST op = ops.next();
					if (op.getOpcode() == PcodeOp.BRANCHIND) {
						branchind++;
					}
				}
				for (JumpTable jt : hf.getJumpTables()) {
					tables.append(' ').append(jt.getSwitchAddress()).append(":")
							.append(jt.getCases().length);
					for (JumpTable.LoadTable lt : jt.getLoadTables()) {
						tables.append("{load ").append(lt.getAddress()).append(" size=").append(lt.getSize())
								.append(" num=").append(lt.getNum()).append('}');
					}
				}
				String err = res.getErrorMessage() == null ? "" : res.getErrorMessage().trim();
				println(head + " ok branchind=" + branchind + " jumptables=[" + tables.toString().trim() +
					"]" + (err.isEmpty() ? "" : " msg=" + err.replace('\n', ' ')));
			}
		}
		finally {
			ifc.dispose();
		}
	}
}
