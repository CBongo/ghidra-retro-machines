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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * The up-counting form of {@link C64DecryptLoopAnalyzer} (grm-430b) on synthetic routines:
 * INX/INY + CPX/CPY #end + BNE, range {@code [base+start, base+end-1]}, execution evidence by
 * fall-through, and a back branch whose operand lies inside the range (self-patched).
 */
public class DecryptLoopUpCountProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final String CATEGORY = "C64DecryptLoopAnalyzer";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB build(String code, String payload) throws Exception {
		builder = newBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x1000);
		builder.setBytes("0x8000", code, true);
		builder.setBytes(String.format("0x%x", 0x8000 + code.trim().split(" ").length), payload,
			false);
		return builder.getProgram();
	}

	private void run(ProgramDB program) throws Exception {
		inTx(program, "analyze", () -> {
			program.setExecutableFormat(C64PrgLoader.NAME);
			new C64DecryptLoopAnalyzer().added(program,
				program.getMemory().getLoadedAndInitializedAddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
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

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02x ", x & 0xFF));
		}
		return sb.toString();
	}

	@Test
	public void constantKeyUpCountFallsThroughIntoRange() throws Exception {
		// LDX #0; LDA $800f,X; EOR #$AA; STA $800f,X; INX; CPX #8; BNE $8002; <payload at $800f>
		ProgramDB program = build("a2 00 bd 0f 80 49 aa 9d 0f 80 e8 e0 08 d0 f3",
			"03 bb 08 88 0a 99 40 ca"); // plaintext a9 11 a2 22 a0 33 ea 60, ^ aa
		run(program);
		MemoryBlock block = program.getMemory().getBlock("DECRYPTED_800f");
		assertNotNull("overlay materialized", block);
		assertEquals(8, block.getSize());
		byte[] got = new byte[8];
		block.getBytes(block.getStart(), got);
		assertEquals("a9 11 a2 22 a0 33 ea 60 ", hex(got));
		Bookmark b = bookmarkAt(program, addr(0x8000));
		assertNotNull(b);
		assertTrue(b.getComment(), !b.getComment().contains("self-patched"));
	}

	@Test
	public void emptyRangeIsNotBounded() throws Exception {
		// start == end: CPX #8 after LDX #8.
		ProgramDB program = build("a2 08 bd 0f 80 49 aa 9d 0f 80 e8 e0 08 d0 f3", "00 00 00 00");
		run(program);
		assertNull(program.getMemory().getBlock("DECRYPTED_8017"));
		Bookmark b = bookmarkAt(program, addr(0x8002));
		assertNotNull(b);
		assertTrue(b.getComment(), b.getComment().contains("could not be bounded"));
	}

	private static String selfPatchedImage(int branchOperand) {
		// LDY #$0D; LDA $8001,Y; EOR #$AA; STA $8001,Y; INY; CPY #$20; BNE <operand in range>
		// range = $800E..$8020: the operand ($800E) plus 18 payload bytes.
		String code = "a0 0d b9 01 80 49 aa 99 01 80 c8 c0 20 d0 ";
		StringBuilder sb = new StringBuilder(code);
		sb.append(String.format("%02x ", branchOperand));
		for (int i = 0; i < 17; i++) {
			sb.append(String.format("%02x ", 0xEA ^ 0xAA));
		}
		sb.append(String.format("%02x ", 0x60 ^ 0xAA));
		return sb.toString();
	}

	@Test
	public void constantKeySelfPatchedBranchIsAccepted() throws Exception {
		// operand $59 ^ $AA = $F3 -> BNE $8002 (next insn is $800F) (the LDA) once decrypted.
		String image = selfPatchedImage(0x59);
		ProgramDB program = build(image.substring(0, 15 * 3), image.substring(15 * 3));
		run(program);
		MemoryBlock block = program.getMemory().getBlock("DECRYPTED_800e");
		assertNotNull("overlay materialized", block);
		assertEquals(19, block.getSize());
		byte[] got = new byte[1];
		block.getBytes(block.getStart(), got);
		assertEquals(0xF3, got[0] & 0xFF);
		Bookmark b = bookmarkAt(program, addr(0x8000));
		assertNotNull(b);
		assertTrue(b.getComment(), b.getComment().contains("self-patched"));
	}

	@Test
	public void constantKeySelfPatchedBranchToElsewhereIsRejected() throws Exception {
		String image = selfPatchedImage(0x58); // patches to $F2, not the loop head
		ProgramDB program = build(image.substring(0, 15 * 3), image.substring(15 * 3));
		run(program);
		assertNull(program.getMemory().getBlock("DECRYPTED_800e"));
	}
}
