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
// Lists every instruction carrying a flow override (bead grm-6m24): one `FLOWOV <space>::<addr>
// <mnemonic> override=<FlowOverride> flow=<effective FlowType>` line,
// followed by `FLOWOV ref <site> -> <to> <RefType>` for each flow reference. Shared Return Calls
// (SharedReturnAnalysisCmd) writes CALL_RETURN overrides, so two toolchains or option settings
// that disagree on which branches are tail calls show up as a diff of these lines -- e.g. Ghidra
// 12.2's GP-6976 conditional-target filter, or 'Allow Conditional Jumps'. Run as
// REALROM_EXTRA_POSTSCRIPT. Read-only; no ROM bytes.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

public class FlowOverrideProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		int n = 0;
		while (it.hasNext()) {
			Instruction instr = it.next();
			FlowOverride ov = instr.getFlowOverride();
			if (ov == FlowOverride.NONE) {
				continue;
			}
			n++;
			String site = fmt(instr.getMinAddress());
			println("FLOWOV " + site + " " + instr.getMnemonicString() + " override=" + ov +
				" flow=" + instr.getFlowType());
			for (Reference r : instr.getReferencesFrom()) {
				if (r.getReferenceType().isFlow()) {
					println("FLOWOV ref " + site + " -> " + fmt(r.getToAddress()) + " " +
						r.getReferenceType());
				}
			}
		}
		println("FLOWOV total " + n);
	}

	private static String fmt(Address a) {
		return a.getAddressSpace().getName() + "::" + String.format("%04x", a.getOffset());
	}
}
