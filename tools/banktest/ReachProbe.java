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
// For each address in GRM_REACH_SITES (comma-separated "<space>::<hex>" specs) reports how the
// disassembly got there: whether an instruction exists at the address, which function contains
// it, and every reference INTO that function's entry point and into the address itself, with the
// referencing instruction's own containing function. Answers "was this site only ever reached
// through a phantom seed?" when a jump-table bound (bead grm-eyn) makes a site disappear from one
// build's listing. Run as REALROM_EXTRA_POSTSCRIPT. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ReachProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_REACH_SITES");
		if (spec == null || spec.isBlank()) {
			println("REACH no GRM_REACH_SITES given");
			return;
		}
		for (String s : spec.split(",")) {
			Address a = currentProgram.getAddressFactory().getAddress(s.trim());
			if (a == null && s.contains("::")) {
				// "RAM::bd2e" (the default space, as JumpTableProbe prints it) does not parse
				// through the factory; a bare offset resolves in the default space.
				a = toAddr(s.substring(s.indexOf("::") + 2).trim());
			}
			if (a == null) {
				println("REACH " + s + " unparseable");
				continue;
			}
			Instruction instr = currentProgram.getListing().getInstructionAt(a);
			Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
			println("REACH " + s + " instr=" + (instr == null ? "NONE" : instr.getMnemonicString()) +
				" fn=" + (f == null ? "NONE" : f.getName() + "@" + f.getEntryPoint()));
			refsTo(s, "site", a);
			if (instr != null) {
				// Walk the fall-through chain backwards to the first instruction that is not
				// simply fallen into: that is where flow entered this run of code.
				Instruction head = instr;
				while (true) {
					Instruction prev = head.getPrevious();
					if (prev == null || prev.getFallThrough() == null ||
						!prev.getFallThrough().equals(head.getMinAddress())) {
						break;
					}
					head = prev;
				}
				if (!head.getMinAddress().equals(a)) {
					println("REACH " + s + " fallthrough-head=" + head.getMinAddress() + " " +
						head.getMnemonicString());
					refsTo(s, "head", head.getMinAddress());
				}
			}
			if (f != null && !f.getEntryPoint().equals(a)) {
				refsTo(s, "entry", f.getEntryPoint());
			}
		}
	}

	private void refsTo(String s, String what, Address to) {
		ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(to);
		int n = 0;
		while (it.hasNext()) {
			Reference r = it.next();
			Function ff = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
			println("REACH " + s + " " + what + " <- " + r.getFromAddress() + " " + r.getReferenceType() +
				" in " + (ff == null ? "NONE" : ff.getName()));
			n++;
		}
		if (n == 0) {
			println("REACH " + s + " " + what + " <- (no references)");
		}
	}
}
