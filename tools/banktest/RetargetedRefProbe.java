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
// Prints EVERY retargeted reference (bead grm-6m24): one `RETREF <from> -> <space>::<to>
// <RefType> <mnemonic>` line per reference from a base-space instruction into an overlay space,
// the same population RealRomDump counts as refs.intoOverlay.retargeted but only samples. When
// that count moves between two runs, diff these lines to name the references that moved. Run as
// REALROM_EXTRA_POSTSCRIPT. Read-only; no ROM bytes.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

public class RetargetedRefProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		int n = 0;
		while (it.hasNext()) {
			Instruction instr = it.next();
			if (instr.getMinAddress().getAddressSpace().isOverlaySpace()) {
				continue;
			}
			for (Reference r : instr.getReferencesFrom()) {
				if (r.getToAddress().getAddressSpace().isOverlaySpace()) {
					n++;
					println("RETREF " + fmt(instr.getMinAddress()) + " -> " + fmt(r.getToAddress()) +
						" " + r.getReferenceType() + " " + instr.getMnemonicString());
				}
			}
		}
		println("RETREF total " + n);
	}

	private static String fmt(Address a) {
		return a.getAddressSpace().getName() + "::" + String.format("%04x", a.getOffset());
	}
}
