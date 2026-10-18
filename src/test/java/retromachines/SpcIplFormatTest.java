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

import java.io.ByteArrayOutputStream;

import org.junit.Test;

/** Pure-JUnit coverage of {@link SpcIplFormat} (bead grm-1.7.3) on synthetic streams. */
public class SpcIplFormatTest {

	/** Builds a block header + {@code len} bytes of {@code fill}+index data. */
	static void block(ByteArrayOutputStream o, int len, int addr, int fill) {
		o.write(len);
		o.write(len >> 8);
		o.write(addr);
		o.write(addr >> 8);
		for (int i = 0; i < len; i++) {
			o.write(fill + i);
		}
	}

	static void terminator(ByteArrayOutputStream o, int entry) {
		o.write(0);
		o.write(0);
		o.write(entry);
		o.write(entry >> 8);
	}

	@Test
	public void singleBlock() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		block(o, 5, 0x0800, 0x10);
		terminator(o, 0x0802);
		byte[] in = o.toByteArray();

		SpcIplFormat.Result r = SpcIplFormat.parse(in, 0);
		assertTrue(r.ok());
		SpcIplFormat.Stream s = r.stream();
		assertEquals(1, s.blocks().size());
		assertEquals(0x0800, s.blocks().get(0).addr());
		assertEquals(5, s.blocks().get(0).length());
		assertEquals(4, s.blocks().get(0).sourceOffset());
		assertArrayEquals(new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14 }, s.blocks().get(0).data());
		assertEquals(0x0802, s.entry());
		assertEquals(in.length, s.consumed());
		assertEquals(5, s.payloadBytes());
	}

	@Test
	public void multiBlockAtNonZeroOffset() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		o.write(0xEE);
		o.write(0xEE);
		o.write(0xEE);
		block(o, 3, 0x0500, 1);
		block(o, 300, 0x4000, 7);
		block(o, 1, 0xFFFF, 9);
		terminator(o, 0x0500);
		o.write(0xAA); // trailing junk is not consumed
		byte[] in = o.toByteArray();

		SpcIplFormat.Result r = SpcIplFormat.parse(in, 3);
		assertTrue(r.ok());
		SpcIplFormat.Stream s = r.stream();
		assertEquals(3, s.blocks().size());
		assertEquals(0x4000, s.blocks().get(1).addr());
		assertEquals(300, s.blocks().get(1).length());
		assertEquals(3 + 4 + 3 + 4, s.blocks().get(1).sourceOffset());
		assertEquals(0xFFFF, s.blocks().get(2).addr());
		assertEquals(304, s.payloadBytes());
		assertEquals(3, s.offset());
		assertEquals(in.length - 1, s.end());
		assertEquals(0x0500, s.entry());
	}

	@Test
	public void truncatedInData() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		block(o, 10, 0x0800, 0);
		byte[] in = o.toByteArray();
		byte[] cut = java.util.Arrays.copyOf(in, in.length - 1);
		SpcIplFormat.Result r = SpcIplFormat.parse(cut, 0);
		assertFalse(r.ok());
		assertEquals(SpcIplFormat.Failure.TRUNCATED, r.failure());
	}

	@Test
	public void truncatedBeforeTerminatorEntry() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		block(o, 2, 0x0800, 0);
		o.write(0);
		o.write(0);
		o.write(0x00); // entry's second byte missing
		SpcIplFormat.Result r = SpcIplFormat.parse(o.toByteArray(), 0);
		assertEquals(SpcIplFormat.Failure.TRUNCATED, r.failure());
	}

	@Test
	public void overflowPast64K() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		block(o, 0x20, 0xFFF1, 0);
		terminator(o, 0xFFF1);
		SpcIplFormat.Result r = SpcIplFormat.parse(o.toByteArray(), 0);
		assertEquals(SpcIplFormat.Failure.ADDRESS_OVERFLOW, r.failure());
	}

	@Test
	public void exactlyFillingTheTopIsFine() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		block(o, 0x10, 0xFFF0, 0);
		terminator(o, 0xFFF0);
		assertTrue(SpcIplFormat.parse(o.toByteArray(), 0).ok());
	}

	@Test
	public void missingTerminator() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		for (int i = 0; i < SpcIplFormat.MAX_BLOCKS + 5; i++) {
			block(o, 1, 0x0800, 0);
		}
		SpcIplFormat.Result r = SpcIplFormat.parse(o.toByteArray(), 0);
		assertEquals(SpcIplFormat.Failure.NO_TERMINATOR, r.failure());
	}

	@Test
	public void streamEndingWithoutTerminatorIsTruncated() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		block(o, 4, 0x0800, 0);
		assertEquals(SpcIplFormat.Failure.TRUNCATED,
			SpcIplFormat.parse(o.toByteArray(), 0).failure());
	}

	@Test
	public void terminatorAloneIsNotAnUpload() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		terminator(o, 0x0800);
		assertEquals(SpcIplFormat.Failure.NO_BLOCKS,
			SpcIplFormat.parse(o.toByteArray(), 0).failure());
	}

	@Test
	public void badOffset() {
		assertEquals(SpcIplFormat.Failure.BAD_OFFSET, SpcIplFormat.parse(new byte[4], 9).failure());
	}
}
