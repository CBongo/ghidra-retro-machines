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
// Prints every symbol at each GRM_NS_SITES address (comma-separated offsets in the default space)
// with its full namespace path and, for any Function in that path, whether its body contains the
// site. GRM_NS_SITES=ALL lists every symbol in the program instead, for diffing two runs. Found
// grm-v60.1's stranded jump-table overrides. Run as REALROM_EXTRA_POSTSCRIPT. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

public class SymbolNamespaceProbe extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_NS_SITES");
		if (spec == null) {
			return;
		}
		if (spec.equals("ALL")) {
			for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(true)) {
				println("NSA " + sym.getAddress() + " " + sym.getName(true) + " " + sym.getSymbolType() +
					" " + sym.getSource());
			}
			return;
		}
		for (String s : spec.split(",")) {
			Address a = toAddr(s.trim());
			Function owner = currentProgram.getFunctionManager().getFunctionContaining(a);
			println("NSP " + a + " owner=" + (owner == null ? "NONE" : owner.getName()));
			for (Symbol sym : currentProgram.getSymbolTable().getSymbols(a)) {
				StringBuilder path = new StringBuilder();
				String fnInfo = "";
				for (Namespace ns = sym.getParentNamespace(); ns != null && !ns.isGlobal();
						ns = ns.getParentNamespace()) {
					path.insert(0, ns.getName() + "::");
					if (ns instanceof Function f) {
						fnInfo += " [" + f.getName() + "@" + f.getEntryPoint() + " contains=" +
							f.getBody().contains(a) + "]";
					}
				}
				println("NSP " + a + " sym " + path + sym.getName() + " primary=" + sym.isPrimary() +
					" src=" + sym.getSource() + fnInfo);
			}
		}
	}
}
