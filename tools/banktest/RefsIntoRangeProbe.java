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
// Lists every reference INTO an address range from OUTSIDE it (bead grm-6m24): one
// `RANGEREF <from> -> <to> <RefType> <source> <from-mnemonic-or-DATA>` line each. Answers "how does
// analysis first reach this block of code?" for a cluster whose internal calls only point at each
// other (dodge's a00a/a226 under GP-7003), which SiteStateProbe, being per-site, cannot. Input:
// GRM_RANGE=<space>::<hexstart>-<hexend>, inclusive (e.g. W8000_B3::a00a-a2ff). Run as
// REALROM_EXTRA_POSTSCRIPT. Read-only; no ROM bytes.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class RefsIntoRangeProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_RANGE");
		if (spec == null || !spec.contains("::") || !spec.contains("-")) {
			println("RANGEREF bad or missing GRM_RANGE (want <space>::<start>-<end>): " + spec);
			return;
		}
		String spaceName = spec.substring(0, spec.indexOf("::"));
		String[] bounds = spec.substring(spec.indexOf("::") + 2).split("-");
		AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			println("RANGEREF no address space named " + spaceName);
			return;
		}
		Address lo = space.getAddress(Long.parseLong(bounds[0].trim(), 16));
		Address hi = space.getAddress(Long.parseLong(bounds[1].trim(), 16));
		int n = 0;
		for (Address to = lo; to != null && to.compareTo(hi) <= 0; to = next(to, hi)) {
			for (Reference r : getReferencesTo(to)) {
				Address from = r.getFromAddress();
				if (from.getAddressSpace().equals(space) && from.compareTo(lo) >= 0 &&
					from.compareTo(hi) <= 0) {
					continue;
				}
				CodeUnit cu = currentProgram.getListing().getCodeUnitAt(from);
				String what = cu instanceof Instruction ins ? ins.getMnemonicString() : "DATA";
				println("RANGEREF " + fmt(from) + " -> " + fmt(to) + " " + r.getReferenceType() +
					" " + r.getSource() + " " + what);
				n++;
			}
		}
		println("RANGEREF total " + n);
	}

	private static Address next(Address a, Address hi) {
		return a.equals(hi) ? null : a.next();
	}

	private static String fmt(Address a) {
		return a.getAddressSpace().getName() + "::" + String.format("%04x", a.getOffset());
	}
}
