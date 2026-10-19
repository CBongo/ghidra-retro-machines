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
// Phase A seeding for the descriptor export round trip (bead grm-hb6.17): adds the annotations
// ExportGameDescriptor.java is then run over. Mirrors GameDescriptorExportRoundTripTest.annotated().
// Shared constants live in AssertExportedAnnotations.java's counterpart expectations -- keep the
// two files in step.
//
//   $C010  user_main       USER_DEFINED  EOL "my note"          -> exported
//   $C020  user_data       USER_DEFINED  (no comment)           -> exported
//   <first overlay block>+0x10  banked_routine USER_DEFINED, EOL "lives in banked window" -> exported
//   $C030  analyzer_guess  ANALYSIS      EOL "analyzer prose; bank -> 3" -> NOT exported
//   $C010  PRE "seeded pre" (labelled address, non-EOL)    -> exported via comments:
//   $C040  PLATE "seeded plate" (unlabelled)                -> exported via comments:
//   $C050  EOL "seeded unlabelled eol" (unlabelled)         -> exported via comments:
//   <overlay>+0x20 POST "seeded banked post" (unlabelled)   -> exported via comments:
// The C030 comment is RECORDED as extension-written in the analyzer-comment map (as an analyzer
// would have), which is what makes it non-exportable (grm-hb6.18).
//
// Prints SEEDEXPORT ok=<bool> outside the BANKDUMP markers.
//
//@category RetroMachines.Test

import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class SeedExportAnnotations extends GhidraScript {

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
		if (overlay == null) {
			println("SEEDEXPORT ok=false (no overlay block)");
			return;
		}
		Address banked = overlay.getStart().add(0x10);
		println("SEEDEXPORT overlay=" + overlay.getName() + " banked=" + banked);

		int tx = currentProgram.startTransaction("seed export annotations");
		try {
			var st = currentProgram.getSymbolTable();
			var listing = currentProgram.getListing();
			st.createLabel(toAddr(0xC010), "user_main", SourceType.USER_DEFINED);
			listing.setComment(toAddr(0xC010), CommentType.EOL, "my note");
			st.createLabel(toAddr(0xC020), "user_data", SourceType.USER_DEFINED);
			st.createLabel(toAddr(0xC030), "analyzer_guess", SourceType.ANALYSIS);
			listing.setComment(toAddr(0xC030), CommentType.EOL, "analyzer prose; bank -> 3");
			st.createLabel(banked, "banked_routine", SourceType.USER_DEFINED);
			listing.setComment(banked, CommentType.EOL, "lives in banked window");

			// grm-hb6.18: the analyzer's comment at $C030 is recorded as extension-written, the
			// way AnalyzerCommentRecord does it (segments joined by U+001F).
			var pm = currentProgram.getUsrPropertyManager();
			String mapName = "Retro Machines.Analyzer Comment EOL";
			var rec = pm.getStringPropertyMap(mapName);
			if (rec == null) {
				rec = pm.createStringPropertyMap(mapName);
			}
			rec.add(toAddr(0xC030), "analyzer prose\u001fbank -> 3");

			// grm-hb6.18: comments the symbol entries cannot carry (comments: carrier).
			listing.setComment(toAddr(0xC010), CommentType.PRE, "seeded pre");
			listing.setComment(toAddr(0xC040), CommentType.PLATE, "seeded plate");
			listing.setComment(toAddr(0xC050), CommentType.EOL, "seeded unlabelled eol");
			listing.setComment(banked.add(0x10), CommentType.POST, "seeded banked post");
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		println("SEEDEXPORT ok=true");
	}
}
