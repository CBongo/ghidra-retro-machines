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
// Prints the straight-line instructions leading up to each listed switch site, so the index's
// origin can be classified without a disassembler per site (bead grm-hf5h.11: why do 96 switch
// sites still print byte-OFFSET labels -- no shift in the dataflow, stride 3, or other?).
//
// GRM_BACKCHAIN_SITES names a file of `<program name> <address>` lines (address as printed by
// SwitchLabelCensus, e.g. `smb3.nes RAM::d3b9`); lines for other programs are ignored, so one
// file serves a whole batch. For each site in the current program prints
//
//   IBC <program> <site> <n>: <addr> <instruction> [<- from <addr>,...]
//
// walking back up to GRM_BACKCHAIN_DEPTH (default 14) instructions through the fall-through
// chain; at a block head it lists the incoming flow references and continues through the first
// one (a conditional branch or jump), marking it `via`. Then `IBC <program> <site> end`. Run as
// REALROM_EXTRA_POSTSCRIPT. Read-only.

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class IndexBackChainProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String file = System.getenv("GRM_BACKCHAIN_SITES");
		if (file == null) {
			println("IBC error: set GRM_BACKCHAIN_SITES=<file>");
			return;
		}
		String depthEnv = System.getenv("GRM_BACKCHAIN_DEPTH");
		int depth = depthEnv == null ? 14 : Integer.parseInt(depthEnv);
		String prog = currentProgram.getName();
		for (String line : Files.readAllLines(Path.of(file))) {
			String[] f = line.trim().split("\\s+");
			if (f.length < 2 || !f[0].equals(prog)) {
				continue;
			}
			Address site = currentProgram.getAddressFactory().getAddress(f[1]);
			if (site == null && f[1].contains("::")) {
				// The default space prints as e.g. "RAM::d3b9" but does not parse back that way.
				site = currentProgram.getAddressFactory()
						.getDefaultAddressSpace()
						.getAddress(Long.parseLong(f[1].substring(f[1].indexOf("::") + 2), 16));
			}
			if (site == null) {
				println("IBC " + prog + " " + f[1] + " unresolved");
				continue;
			}
			walk(prog, f[1], site, depth);
		}
	}

	private void walk(String prog, String label, Address site, int depth) {
		Instruction in = currentProgram.getListing().getInstructionAt(site);
		for (int n = 0; in != null && n < depth; n++) {
			List<String> from = new ArrayList<>();
			Address via = null;
			for (Reference r : currentProgram.getReferenceManager()
					.getReferencesTo(in.getMinAddress())) {
				if (r.getReferenceType().isFlow() && !r.getReferenceType().isCall()) {
					from.add(r.getFromAddress().toString());
					if (via == null) {
						via = r.getFromAddress();
					}
				}
			}
			println("IBC " + prog + " " + label + " " + n + ": " + in.getMinAddress() + " " + in +
				(from.isEmpty() ? "" : " <- from " + String.join(",", from)));
			Address prev = in.getFallFrom();
			if (prev == null && via != null) {
				prev = via;
				println("IBC " + prog + " " + label + " via " + via);
			}
			in = prev == null ? null : currentProgram.getListing().getInstructionAt(prev);
		}
		println("IBC " + prog + " " + label + " end");
	}
}
