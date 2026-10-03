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
// Phase B of the descriptor export round trip (bead grm-hb6.17): run as a post-verify
// -postScript on a re-import of the same bytes with the YAML written by ExportGameDescriptor.java
// planted as an overlay. Asserts what SeedExportAnnotations.java added in phase A came back,
// as IMPORTED (never USER_DEFINED -- design section 3c.3) annotations at the same addresses,
// and that the analyzer-created label and its comment did not travel.
//
// Prints one DESCEXPORT check=<id> ok=<bool> line per check and
//   DESCEXPORT verdict=PASS|FAIL
//
//@category RetroMachines.Test

import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class AssertExportedAnnotations extends GhidraScript {

	private boolean allOk = true;

	@Override
	protected void run() throws Exception {
		MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
		Arrays.sort(blocks, (a, b) -> a.getName().compareTo(b.getName()));
		MemoryBlock overlay = null;
		for (MemoryBlock b : blocks) {
			if (b.isOverlay()) {
				overlay = b;
				break;
			}
		}
		check("overlay-block-present", overlay != null);
		if (overlay == null) {
			println("DESCEXPORT verdict=FAIL");
			return;
		}
		Address banked = overlay.getStart().add(0x10);

		expect("user_main", toAddr(0xC010), "my note");
		expect("user_data", toAddr(0xC020), null);
		expect("banked_routine", banked, "lives in banked window");

		Address guess = toAddr(0xC030);
		check("analyzer-label-absent", currentProgram.getSymbolTable().getSymbols(guess).length == 0);
		check("analyzer-comment-absent",
			currentProgram.getListing().getComment(CommentType.EOL, guess) == null);

		println("DESCEXPORT verdict=" + (allOk ? "PASS" : "FAIL"));
	}

	private void expect(String name, Address addr, String eol) {
		Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(addr);
		check(name + ":label", s != null && s.getName().equals(name));
		check(name + ":source-imported", s != null && s.getSource() == SourceType.IMPORTED);
		check(name + ":one-symbol", currentProgram.getSymbolTable().getSymbols(addr).length == 1);
		String got = currentProgram.getListing().getComment(CommentType.EOL, addr);
		check(name + ":eol", eol == null ? got == null : eol.equals(got));
	}

	private void check(String id, boolean ok) {
		allOk &= ok;
		println("DESCEXPORT check=" + id + " ok=" + ok);
	}
}
