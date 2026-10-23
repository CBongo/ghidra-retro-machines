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
package retromachines;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.util.task.TaskMonitor;

/**
 * grm-2854: a descriptor entry naming a memory block that does not resolve must leave a
 * headless-visible WARNING bookmark (MessageLog is invisible headlessly), with a "did you mean"
 * suggestion; and the deliberate base-space fallback for loader-carved names stays silent.
 */
public class DescriptorUnresolvedBlockTest extends AbstractBundledLanguageTest {

	private static final String MAP_TEMPLATE = """
		{
		  "regions": [
		    { "name": "ZEROPAGE", "start": 2, "end": 255, "kind": "ram",
		      "copied_from": [
		        { "name": "CHRGET", "start": 115, "end": 138, "source": "@SRC@",
		          "source_addr": 58274 } ] }
		  ]
		}
		""";

	private ProgramBuilder builder(String sourceBlockName) throws Exception {
		ProgramBuilder b = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(b, "ZEROPAGE", "0x0002", 0xFE);
		b.createMemory(sourceBlockName, "0xE000", 0x2000);
		byte[] pattern = new byte[0x2000];
		for (int i = 0; i < pattern.length; i++) {
			pattern[i] = (byte) i;
		}
		b.setBytes("0xE000", pattern);
		return b;
	}

	private static void applyHint(ProgramDB p, String source) {
		JsonObject map = JsonParser.parseString(MAP_TEMPLATE.replace("@SRC@", source))
				.getAsJsonObject();
		inTx(p, "copy hints", () -> new DescriptorCopyHintAnalyzer().applyAll(p, map,
			TaskMonitor.DUMMY, new MessageLog()));
	}

	private static Bookmark[] warnings(ProgramDB p) {
		return p.getBookmarkManager().getBookmarks(p.getMinAddress(), BookmarkType.WARNING);
	}

	@Test
	public void staleOverlayNameWarnsAndSkipsTheHint() throws Exception {
		// The bank's block is W8000_B1 (post grm-ic5); the descriptor still says W8000_M3_B1.
		ProgramBuilder b = builder("W8000_B1");
		ProgramDB p = b.getProgram();
		applyHint(p, "W8000_M3_B1");

		assertNull("the hint must not silently read the base space",
			p.getMemory().getBlock("COPY_0073"));
		Bookmark[] w = warnings(p);
		assertEquals(1, w.length);
		assertTrue(w[0].getComment(), w[0].getComment().contains("W8000_M3_B1"));
		assertTrue(w[0].getComment(), w[0].getComment().contains("did you mean W8000_B1?"));
	}

	@Test
	public void carvedFallbackStaysSilent() throws Exception {
		// No block called KERNAL and nothing near it: the loader-carve case. Falls back to the
		// base space, materializes, and leaves no warning.
		ProgramBuilder b = builder("ROM_E000");
		ProgramDB p = b.getProgram();
		applyHint(p, "KERNAL");

		assertNotNull(p.getMemory().getBlock("COPY_0073"));
		assertEquals(0, warnings(p).length);
	}

	@Test
	public void commentWithUnknownBlockWarnsWithSuggestion() throws Exception {
		ProgramBuilder b = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(b, "RAM", "0x1000", 0x100);
		uninitializedRamOverlay(b, "W8000_B1", "0x8000", 0x100);
		ProgramDB p = b.getProgram();
		JsonObject set = JsonParser.parseString("""
			{ "block": "W8000_M3_B1", "entries": [ { "addr": 32768, "eol": "x" } ] }
			""").getAsJsonObject();
		int[] written = new int[1];
		inTx(p, "comments", () -> written[0] = DescriptorApply.applyCommentSet(p,
			p.getAddressFactory().getDefaultAddressSpace(), set, new MessageLog()));

		assertEquals(0, written[0]);
		Bookmark[] w = warnings(p);
		assertEquals(1, w.length);
		assertTrue(w[0].getComment(), w[0].getComment().contains("did you mean W8000_B1?"));
		assertNull(p.getListing().getComment(CommentType.EOL, b.addr("0x8000")));
	}
}
