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
// Prints, for each GRM_SITES address (comma-separated offsets in the default space), the owning
// function, the EOL comment, and every outgoing reference with its type and source. Written for
// grm-kon2 to tell JumpTableBoundAnalyzer's override path from its reference-pinning path at a
// switch. Run as REALROM_EXTRA_POSTSCRIPT. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class SiteStateProbe extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_SITES");
		if (spec == null) {
			return;
		}
		for (String s : spec.split(",")) {
			Address a = toAddr(s.trim());
			Function owner = currentProgram.getFunctionManager().getFunctionContaining(a);
			println("SSP " + a + " owner=" + (owner == null ? "NONE" : owner.getName() + "@" +
				owner.getEntryPoint()));
			println("SSP " + a + " eol=" +
				currentProgram.getListing().getComment(CommentType.EOL, a));
			for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(a)) {
				println("SSP " + a + " ref " + r.getToAddress() + " " + r.getReferenceType() + " " +
					r.getSource() + " primary=" + r.isPrimary());
			}
		}
	}
}
