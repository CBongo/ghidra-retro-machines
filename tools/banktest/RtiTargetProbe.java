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
// Narrow probe (grm-9nxj.44): list every 65816 RTI with its E/M/X context, containing function,
// flow targets and the 12 instructions before it, so a "computed RTI withTargets" movement in
// W65816WidthDump can be attributed to a site. Run as REALROM_EXTRA_POSTSCRIPT=RtiTargetProbe.java.
//@category RetroMachines.Probe

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

public class RtiTargetProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Listing listing = currentProgram.getListing();
		Register e = currentProgram.getRegister("ctx_EF");
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (!ins.getMnemonicString().equalsIgnoreCase("RTI")) {
				continue;
			}
			StringBuilder targets = new StringBuilder();
			for (Address a : ins.getFlows()) {
				targets.append(' ').append(a);
			}
			for (Reference r : ins.getReferencesFrom()) {
				if (r.getReferenceType().isFlow()) {
					targets.append(" ref:").append(r.getToAddress());
				}
			}
			if (targets.length() == 0) {
				continue;   // unresolved, the common case
			}
			Function f = getFunctionContaining(ins.getAddress());
			String ef = e == null ? "?" : String.valueOf(ins.getValue(e, false));
			println("RTIPROBE " + ins.getAddress() + " E=" + ef + " fn=" +
				(f == null ? "-" : f.getName() + "@" + f.getEntryPoint()) + " ->" + targets);
			if (f != null) {
				// The prologue, with M/X, to compare push widths against the epilogue's pulls.
				Register m = currentProgram.getRegister("ctx_MF");
				Register x = currentProgram.getRegister("ctx_XF");
				Instruction q = listing.getInstructionAt(f.getEntryPoint());
				for (int i = 0; i < 14 && q != null; i++) {
					println("RTIPROBE   <" + q.getAddress() + " M=" + q.getValue(m, false) +
						" X=" + q.getValue(x, false) + "  " + q);
					q = q.getNext();
				}
			}
			Instruction p = ins;
			for (int i = 0; i < 12 && p != null; i++) {
				p = p.getPrevious();
				if (p != null) {
					println("RTIPROBE   " + p.getAddress() + " M=" +
						p.getValue(currentProgram.getRegister("ctx_MF"), false) + " X=" +
						p.getValue(currentProgram.getRegister("ctx_XF"), false) + "  " + p);
				}
			}
			for (Address a : ins.getFlows()) {
				Instruction t = listing.getInstructionAt(a);
				for (int i = 0; i < 10 && t != null; i++) {
					println("RTIPROBE   >" + t.getAddress() + " E=" +
						(e == null ? "?" : t.getValue(e, false)) + "  " + t);
					t = t.getNext();
				}
			}
		}
	}
}
