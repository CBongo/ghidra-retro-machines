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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Pure-logic tests of the SPC700 IPL handshake model, driven by synthetic port writes. */
public class SpcIplModelTest {

	private final SpcIplModel ipl = new SpcIplModel();
	private long step;

	/** One 65816 instruction that stores the given (port, value) pairs in order, then finishes. */
	private void insn(long pc, int... portValuePairs) {
		for (int i = 0; i < portValuePairs.length; i += 2) {
			ipl.portWritten(portValuePairs[i], portValuePairs[i + 1]);
		}
		ipl.instructionBoundary(pc, ++step);
	}

	private void command(long pc, int dest, int p1, int cmd) {
		insn(pc - 2, 2, dest & 0xFF, 3, dest >> 8);
		insn(pc - 1, 1, p1);
		insn(pc, 0, cmd);
	}

	@Test
	public void startsWithSignatureAndWaitsForKick() {
		assertEquals(0xAA, ipl.portRead(0));
		assertEquals(0xBB, ipl.portRead(1));
		assertEquals(SpcIplModel.State.WAIT_KICK, ipl.state());
		insn(0x8000, 0, 0x55);
		assertEquals(SpcIplModel.State.WAIT_KICK, ipl.state());
		assertEquals(0xAA, ipl.portRead(0));
	}

	@Test
	public void singleBlockThenEntry() {
		command(0x8100, 0x0200, 1, 0xCC);
		assertEquals(0xCC, ipl.portRead(0));
		assertEquals(SpcIplModel.State.WAIT_FIRST, ipl.state());
		insn(0x8110, 1, 0x11, 0, 0);
		assertEquals(0, ipl.portRead(0));
		insn(0x8111, 1, 0x22, 0, 1);
		assertEquals(1, ipl.portRead(0));
		insn(0x8112, 1, 0x33, 0, 2);
		command(0x8120, 0x0200, 0, 0x05);
		assertTrue(ipl.isDone());
		assertEquals(0x0200, ipl.entry());
		assertEquals(1, ipl.blocks().size());
		SpcIplModel.Block b = ipl.blocks().get(0);
		assertEquals(0x0200, b.dest());
		assertEquals(0, b.ordinal());
		assertEquals(0x8100, b.issuerPc());
		assertArrayEquals(new byte[] { 0x11, 0x22, 0x33 }, b.bytes());
	}

	@Test
	public void multipleBlocks() {
		command(0x9000, 0x0500, 1, 0xCC);
		insn(1, 1, 0xA0, 0, 0);
		insn(2, 1, 0xA1, 0, 1);
		command(0x9100, 0x3CC0, 1, 0x04);
		assertEquals(2, ipl.blocks().size());
		insn(3, 1, 0xB0, 0, 0);
		command(0x9200, 0x0800, 0, 0x06);
		assertTrue(ipl.isDone());
		assertEquals(0x0800, ipl.entry());
		assertEquals(0x3CC0, ipl.blocks().get(1).dest());
		assertEquals(1, ipl.blocks().get(1).ordinal());
		assertEquals(0x9100, ipl.blocks().get(1).issuerPc());
		assertArrayEquals(new byte[] { (byte) 0xA0, (byte) 0xA1 }, ipl.blocks().get(0).bytes());
		assertArrayEquals(new byte[] { (byte) 0xB0 }, ipl.blocks().get(1).bytes());
	}

	@Test
	public void sixteenBitStoreLandsPort0BeforePort1WithinOneInstruction() {
		command(0xA000, 0x0200, 1, 0xCC);
		// STA $2140 (16-bit): port 0 byte stored first, port 1 second, ONE boundary.
		insn(0xA010, 0, 0, 1, 0x7E);
		assertArrayEquals(new byte[] { 0x7E }, ipl.blocks().get(0).bytes());
		insn(0xA011, 0, 1, 1, 0x7F);
		assertArrayEquals(new byte[] { 0x7E, 0x7F }, ipl.blocks().get(0).bytes());
	}

	@Test
	public void reactionDeferredUntilInstructionBoundary() {
		command(0xA000, 0x0200, 1, 0xCC);
		ipl.portWritten(0, 0);
		assertEquals(0xCC, ipl.portRead(0));    // not yet stored
		ipl.portWritten(1, 0x42);
		ipl.instructionBoundary(0xA001, 99);
		assertArrayEquals(new byte[] { 0x42 }, ipl.blocks().get(0).bytes());
	}

	@Test
	public void staleAndRepeatedIndexWritesAreIgnored() {
		command(0xA000, 0x0200, 1, 0xCC);
		insn(1, 1, 0x10, 0, 0);
		insn(2, 1, 0x11, 0, 1);
		insn(3, 1, 0x99, 0, 1);      // repeat of an index already stored: behind, ignored
		insn(4, 1, 0x98, 0, 0);      // stale
		assertEquals(2, ipl.blocks().get(0).length());
		assertEquals(SpcIplModel.State.TRANSFER, ipl.state());
		insn(5, 1, 0x12, 0, 2);
		assertArrayEquals(new byte[] { 0x10, 0x11, 0x12 }, ipl.blocks().get(0).bytes());
	}

	@Test
	public void firstByteWaitsForPortZero() {
		command(0xA000, 0x0200, 1, 0xCC);
		insn(1, 1, 0x10, 0, 5);      // not the first-byte marker
		assertEquals(0, ipl.blocks().get(0).length());
		insn(2, 1, 0x10, 0, 0);
		assertEquals(1, ipl.blocks().get(0).length());
	}

	@Test
	public void indexWrapsAt256() {
		command(0xA000, 0x0200, 1, 0xCC);
		for (int i = 0; i < 300; i++) {
			insn(0xB000 + i, 1, i & 0xFF, 0, i & 0xFF);
		}
		assertEquals(300, ipl.blocks().get(0).length());
		assertEquals(299 & 0xFF, ipl.blocks().get(0).bytes()[299] & 0xFF);
		assertFalse(ipl.isDone());
		// index is now 300 & 0xFF = 44; kick 46 is ahead of it
		command(0xC000, 0x0900, 0, 46);
		assertTrue(ipl.isDone());
		assertEquals(0x0900, ipl.entry());
	}

	@Test
	public void noEntryUntilJumpCommand() {
		assertEquals(-1, ipl.entry());
		command(0xA000, 0x0200, 1, 0xCC);
		assertEquals(-1, ipl.entry());
		assertFalse(ipl.isDone());
	}
}
