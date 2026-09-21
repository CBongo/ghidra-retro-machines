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
// Lists every computed-jump site in the program with the references Ghidra's switch
// recovery attached to it (bead grm-qp5x.4): one `JTAB site <space>::<addr> <mnemonic>
// targets=<n>` line per indirect/computed JMP, followed by `JTAB target <site> <to>` lines.
// Two toolchains that disagree on how many entries a jump table has -- the grm-eyn family of
// size-recovery differences -- show up as a differing targets= count at the same site, which is
// far more specific than a whole-program instruction count. Run as REALROM_EXTRA_POSTSCRIPT.
// Read-only; no ROM bytes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

public class JumpTableProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			FlowType flow = instr.getFlowType();
			if (!flow.isJump() || !flow.isComputed()) {
				continue;
			}
			Reference[] refs = instr.getReferencesFrom();
			int n = 0;
			for (Reference r : refs) {
				if (r.getReferenceType().isFlow()) {
					n++;
				}
			}
			String site = fmt(instr.getMinAddress());
			println("JTAB site " + site + " " + instr.getMnemonicString() + " targets=" + n);
			for (Reference r : refs) {
				if (r.getReferenceType().isFlow()) {
					println("JTAB target " + site + " " + fmt(r.getToAddress()));
				}
			}
		}
	}

	private static String fmt(Address a) {
		return a.getAddressSpace().getName() + "::" + String.format("%04x", a.getOffset());
	}
}
