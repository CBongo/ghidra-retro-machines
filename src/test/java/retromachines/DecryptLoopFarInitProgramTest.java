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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.util.task.TaskMonitor;

/**
 * {@link C64DecryptLoopAnalyzer} with the loop's {@code LDX #imm} too far back for the linear
 * lookback (grm-29ua, the decrypt twin of grm-7pp), on a SYNTHETIC hand-built routine:
 * <pre>
 *   8000  LDX #$05
 *   8002  NOP x10                    ; pushes the init out of the 8-instruction lookback
 *   800c  LDA $8020,X / EOR #$AA / STA $8020,X / DEX / BPL $800c
 *   8017  JMP $8020                  ; into the rewritten range -> AUTO
 *   8020  six bytes of ciphertext
 * </pre>
 * The init dominates the loop, so it is bounded; bookmarks and the comment land on the loop's own
 * LDA ($800c), not on the (possibly shared) init at $8000.
 */
public class DecryptLoopFarInitProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final String CATEGORY = "C64DecryptLoopAnalyzer";
	private static final String NOPS = "ea ea ea ea ea ea ea ea ea ea ";
	private static final String LOOP =
		"bd 20 80 49 aa 9d 20 80 ca 10 f5 4c 20 80 ";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB build(String extra) throws Exception {
		builder = newBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x1000);
		builder.setBytes("0x8000", "a2 05 " + NOPS + LOOP, true);
		// ciphertext of 01..06
		builder.setBytes("0x8020", "ab a8 a9 ae af ac", false);
		if (extra != null) {
			builder.setBytes("0x8300", extra, true);
		}
		return builder.getProgram();
	}

	private void run(ProgramDB program) throws Exception {
		inTx(program, "analyze", () -> {
			program.setExecutableFormat(C64PrgLoader.NAME);
			C64DecryptLoopAnalyzer analyzer = new C64DecryptLoopAnalyzer();
			assertTrue(analyzer.canAnalyze(program));
			analyzer.added(program, program.getMemory().getLoadedAndInitializedAddressSet(),
				TaskMonitor.DUMMY, new MessageLog());
		});
	}

	private Bookmark bookmarkAt(ProgramDB program, Address at) {
		for (Bookmark b : program.getBookmarkManager().getBookmarks(at)) {
			if (CATEGORY.equals(b.getCategory())) {
				return b;
			}
		}
		return null;
	}

	@Test
	public void farDominatingInitBoundsTheLoopAndAnchorsOnTheLda() throws Exception {
		ProgramDB program = build(null);
		run(program);

		assertNotNull("overlay materialized",
			program.getMemory().getBlock("DECRYPTED_8020"));
		Bookmark onLda = bookmarkAt(program, addr(0x800c));
		assertNotNull("bookmark on the loop's LDA", onLda);
		assertTrue(onLda.getComment(), onLda.getComment().startsWith("decrypted "));
		assertNull("nothing on the far init", bookmarkAt(program, addr(0x8000)));
		assertEquals("decrypt loop -> DECRYPTED_8020",
			program.getListing().getComment(CommentType.EOL, addr(0x800c)));
		assertNull(program.getListing().getComment(CommentType.EOL, addr(0x8000)));
	}

	@Test
	public void initOnOnlyOnePathStaysUnbounded() throws Exception {
		// Another way into the loop head that never loaded X: the init no longer dominates.
		ProgramDB program = build("4c 0c 80");
		run(program);

		assertNull(program.getMemory().getBlock("DECRYPTED_8020"));
		Bookmark b = bookmarkAt(program, addr(0x800c));
		assertNotNull(b);
		assertTrue(b.getComment(), b.getComment().contains("could not be bounded"));
	}
}
