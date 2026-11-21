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
// Counts the signatures ParamReturnAnalyzer committed (bead grm-etbh, E2): functions carrying the
// grm_param_return tag, split by parameter registers, return kind and calling convention. Prints
//   PRCOMMIT <row> fns=<n> committed=<n> withParams=<n> withReturn=<n> carryReturns=<n> ...
// and, when GRM_PRC_OUT names a directory, appends the same line to <dir>/<program>.commit.
// GRM_PRC_CALLERS=<hex,...> additionally lists the call-site addresses that reference each
// address, as "PRCOMMIT CALLER <target> <fromAddr>". Read-only. Run as REALROM_EXTRA_POSTSCRIPT.
//@category RetroMachines.Test

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;

public class ParamReturnCommitCount extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String row = currentProgram.getName();
		int fns = 0, committed = 0, withParams = 0, withReturn = 0, carry = 0, zpTag = 0;
		Map<String, Integer> sigs = new TreeMap<>();
		Map<String, Integer> conv = new TreeMap<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			fns++;
			if (f.getTags().stream().noneMatch(t -> t.getName().equals("grm_param_return"))) {
				continue;
			}
			committed++;
			StringBuilder sig = new StringBuilder();
			for (Parameter p : f.getParameters()) {
				sig.append(p.getRegister() == null ? "?" : p.getRegister().getName()).append(',');
			}
			boolean ret = f.getReturn().getRegister() != null;
			if (f.getParameterCount() > 0) {
				withParams++;
			}
			if (ret) {
				withReturn++;
				if (f.getReturnType().getName().equals("bool")) {
					carry++;
				}
			}
			if (f.getTags().stream().anyMatch(t -> t.getName().startsWith("zp_in:"))) {
				zpTag++;
			}
			sig.append("->").append(ret ? f.getReturn().getRegister().getName() : "-");
			sigs.merge(sig.toString(), 1, Integer::sum);
			conv.merge(f.getCallingConventionName(), 1, Integer::sum);
		}
		List<String> out = new ArrayList<>();
		out.add("PRCOMMIT " + row + " fns=" + fns + " committed=" + committed + " withParams=" +
			withParams + " withReturn=" + withReturn + " carryReturns=" + carry + " zpTagged=" +
			zpTag + " conv=" + conv + " sigs=" + sigs);
		String callers = System.getenv("GRM_PRC_CALLERS");
		if (callers != null && !callers.isBlank()) {
			for (String h : callers.split(",")) {
				Address t = currentProgram.getAddressFactory().getDefaultAddressSpace()
					.getAddress(h.trim());
				for (Reference r : currentProgram.getReferenceManager().getReferencesTo(t)) {
					if (r.getReferenceType().isCall()) {
						out.add("PRCOMMIT CALLER " + t + " " + r.getFromAddress());
					}
				}
			}
		}
		for (String l : out) {
			println(l);
		}
		String dir = System.getenv("GRM_PRC_OUT");
		if (dir != null && !dir.isBlank()) {
			try {
				Path p = Paths.get(dir);
				Files.createDirectories(p);
				try (PrintWriter w =
					new PrintWriter(new FileWriter(p.resolve(row + ".commit").toFile()))) {
					for (String l : out) {
						w.println(l);
					}
				}
			}
			catch (IOException e) {
				println("PRCOMMIT " + row + " WARN cannot write GRM_PRC_OUT: " + e);
			}
		}
	}
}
