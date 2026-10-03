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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import retromachines.SnesImageLayout.Mode;
import retromachines.SnesRomHeader.MapType;

/**
 * Interleaved / chunk-reordered image support (bead grm-9nxj.19). Each test builds a CANONICAL
 * image, then rearranges it BY HAND (explicit array copies, not {@link SnesImageLayout}) so the
 * layout code is checked against an independent construction.
 */
public class SnesImageLayoutTest {

	private static final int HALF = 0x8000;
	private static final int UNIT = 0x10000;
	private static final int CHUNK = 0x400000;

	/** Writes a valid header at logical {@code at} in a canonical, 0xEE-filled image. */
	private static void header(byte[] img, int at, String title, int mapMode) {
		byte[] name = String.format("%-21s", title).getBytes();
		System.arraycopy(name, 0, img, at, 21);
		img[at + 0x15] = (byte) mapMode;
		img[at + 0x16] = 0;
		img[at + 0x17] = 0x0A;
		img[at + 0x18] = 0;
		int sum = 0x1234;
		img[at + 0x1E] = (byte) sum;
		img[at + 0x1F] = (byte) (sum >> 8);
		img[at + 0x1C] = (byte) ((sum ^ 0xFFFF));
		img[at + 0x1D] = (byte) ((sum ^ 0xFFFF) >> 8);
		img[at + 0x20 + 0x1C] = 0x00;
		img[at + 0x20 + 0x1D] = (byte) 0x80;
	}

	private static byte[] canonical(int size) {
		byte[] img = new byte[size];
		Arrays.fill(img, (byte) 0xEE);
		// Distinguishable content so a wrong placement is visible in the mapping assertions.
		for (int i = 0; i < size; i += 0x1000) {
			img[i] = (byte) (i >> 12);
		}
		return img;
	}

	/** Swaps the 32 KiB halves of every complete 64 KiB unit. */
	private static byte[] interleave(byte[] img) {
		byte[] out = img.clone();
		for (int u = 0; u + UNIT <= img.length; u += UNIT) {
			System.arraycopy(img, u, out, u + HALF, HALF);
			System.arraycopy(img, u + HALF, out, u, HALF);
		}
		return out;
	}

	/** Stores the (size-4M) second chunk first, then the 4 MiB first chunk. */
	private static byte[] smallFirst(byte[] img) {
		byte[] out = new byte[img.length];
		int rest = img.length - CHUNK;
		System.arraycopy(img, CHUNK, out, 0, rest);
		System.arraycopy(img, 0, out, rest, CHUNK);
		return out;
	}

	private static byte[] hiRom() {
		byte[] img = canonical(0x100000);
		header(img, 0xFFC0, "HIROM TITLE", 0x31);
		return img;
	}

	private static byte[] exHiRom() {
		byte[] img = canonical(0x600000);
		header(img, 0xFFC0, "EXHIROM TITLE", 0x35);
		header(img, 0x40FFC0, "EXHIROM TITLE", 0x35);
		return img;
	}

	@Test
	public void interleavedHiRomIsDeinterleavedByAuto() {
		byte[] file = interleave(hiRom());

		SnesRomHeader auto = SnesRomHeader.parse(file, Mode.AUTO);
		assertNotNull(auto);
		assertTrue(auto.layout().interleaved());
		assertFalse(auto.layout().chunkSwapped());
		assertEquals(0xFFC0, auto.headerOffset());
		assertEquals(MapType.HIROM, auto.mapType());
		assertTrue(auto.mapTypeMatchesLocation());
		assertEquals("HIROM TITLE", auto.title());
		assertEquals(0x8000, auto.resetVector());

		// Off is today's behaviour: the header is found at the LoROM position, contradicting.
		SnesRomHeader off = SnesRomHeader.parse(file, Mode.OFF);
		assertEquals(0x7FC0, off.headerOffset());
		assertFalse(off.mapTypeMatchesLocation());
		assertTrue(off.layout().isCanonical());

		SnesRomHeader force = SnesRomHeader.parse(file, Mode.FORCE);
		assertEquals(auto, force);
	}

	@Test
	public void exHiRomInterleavedAndSmallFirstIsFullyRecovered() {
		byte[] canon = exHiRom();
		byte[] file = interleave(smallFirst(canon));

		SnesRomHeader auto = SnesRomHeader.parse(file, Mode.AUTO);
		assertNotNull(auto);
		assertTrue(auto.layout().interleaved());
		assertTrue(auto.layout().chunkSwapped());
		assertEquals(0x40FFC0, auto.headerOffset());
		assertEquals(MapType.EXHIROM, auto.mapType());
		assertTrue(auto.mapTypeMatchesLocation());

		// The stored positions from the bead: 0x7FC0 and 0x207FC0 in the file.
		SnesImageLayout lay = auto.layout();
		assertEquals(0x7FC0, lay.fileOffsetOf(0x40FFC0));
		assertEquals(0x207FC0, lay.fileOffsetOf(0xFFC0));

		// And the mapping reproduces the canonical image byte for byte, at every sample.
		for (long logical : new long[] { 0, 0x7FFF, 0x8000, 0xFFC0, 0x1FFFF, 0x3FFFFF,
			0x400000, 0x40FFC0, 0x5FFFFF }) {
			assertEquals("logical " + Long.toHexString(logical), canon[(int) logical],
				file[(int) lay.fileOffsetOf(logical)]);
		}

		// Off leaves it as stored: header at 0x7FC0, contradicting.
		SnesRomHeader off = SnesRomHeader.parse(file, Mode.OFF);
		assertEquals(0x7FC0, off.headerOffset());
		assertFalse(off.mapTypeMatchesLocation());
	}

	@Test
	public void exHiRomSmallFirstOnlyIsRecoveredWithoutInterleave() {
		byte[] canon = exHiRom();
		byte[] file = smallFirst(canon);

		SnesRomHeader auto = SnesRomHeader.parse(file, Mode.AUTO);
		assertNotNull(auto);
		assertFalse("chunk order is an independent axis", auto.layout().interleaved());
		assertTrue(auto.layout().chunkSwapped());
		assertEquals(0x40FFC0, auto.headerOffset());
		assertTrue(auto.mapTypeMatchesLocation());
		assertEquals(0xFFC0, auto.layout().fileOffsetOf(0x40FFC0));

		SnesRomHeader off = SnesRomHeader.parse(file, Mode.OFF);
		assertFalse(off.mapTypeMatchesLocation());
	}

	/** Canonical ExHiROM (big chunk first, valid header at 0x40FFC0) is left alone by Auto. */
	@Test
	public void canonicalExHiRomStaysCanonical() {
		byte[] file = exHiRom();
		SnesRomHeader auto = SnesRomHeader.parse(file, Mode.AUTO);
		assertTrue(auto.layout().isCanonical());
		// The $FFC0 copy ties the real $40FFC0 header; the location tie-break picks the one
		// whose map type matches, in every mode.
		assertEquals(0x40FFC0, auto.headerOffset());
		assertTrue(auto.mapTypeMatchesLocation());
		assertEquals(SnesRomHeader.parse(file, Mode.OFF), auto);
	}

	/**
	 * Mario's Early Years shape: a canonical HiROM image with a stray valid HiROM-mapMode header
	 * at $7FC0 as well as the real one at $FFC0. It is a well-formed cartridge as stored; Auto
	 * must not read the decoy as an interleave signal, and the location tie-break picks the
	 * real header at $FFC0 in every mode.
	 */
	@Test
	public void strayHeaderAtLoRomPositionDoesNotTriggerDeinterleave() {
		byte[] img = hiRom();
		header(img, 0x7FC0, "HIROM TITLE", 0x31);
		SnesRomHeader auto = SnesRomHeader.parse(img, Mode.AUTO);
		assertTrue(auto.layout().isCanonical());
		assertEquals(0xFFC0, auto.headerOffset());
		assertTrue(auto.mapTypeMatchesLocation());
		assertEquals(SnesRomHeader.parse(img, Mode.OFF), auto);
	}

	@Test
	public void canonicalHiRomAndLoRomAreUnaffectedByAuto() {
		byte[] hi = hiRom();
		assertEquals(SnesRomHeader.parse(hi), SnesRomHeader.parse(hi, Mode.AUTO));
		assertTrue(SnesRomHeader.parse(hi, Mode.AUTO).layout().isCanonical());

		byte[] lo = canonical(0x100000);
		header(lo, 0x7FC0, "LOROM TITLE", 0x20);
		SnesRomHeader auto = SnesRomHeader.parse(lo, Mode.AUTO);
		assertTrue(auto.layout().isCanonical());
		assertEquals(0x7FC0, auto.headerOffset());
		assertEquals(SnesRomHeader.parse(lo), auto);
	}

	/**
	 * Corpus case (WWF Super WrestleMania): a header at the LoROM position whose map mode claims
	 * HiROM through a MALFORMED byte ($41). Not a strong enough signal to de-interleave.
	 */
	@Test
	public void malformedMapModeAtLoRomPositionStaysCanonical() {
		byte[] img = canonical(0x100000);
		header(img, 0x7FC0, "ODD MAP MODE", 0x41);
		SnesRomHeader auto = SnesRomHeader.parse(img, Mode.AUTO);
		assertTrue(auto.layout().isCanonical());
		assertEquals(0x7FC0, auto.headerOffset());
		// Force still does what it is told.
		assertTrue(SnesRomHeader.parse(img, Mode.FORCE).layout().interleaved());
	}

	@Test
	public void copierHeaderedInterleavedImageUsesTheCopierOffset() {
		byte[] body = interleave(hiRom());
		byte[] file = new byte[body.length + 0x200];
		System.arraycopy(body, 0, file, 0x200, body.length);

		SnesRomHeader auto = SnesRomHeader.parse(file, Mode.AUTO);
		assertNotNull(auto);
		assertTrue(auto.copierHeader());
		assertTrue(auto.layout().interleaved());
		assertEquals(0xFFC0, auto.headerOffset());
		assertEquals(0x200 + 0x7FC0, auto.layout().fileOffsetOf(0xFFC0));
	}

	@Test
	public void layoutMappingAndContiguousRuns() {
		SnesImageLayout il = new SnesImageLayout(0, 0x100000, true, false);
		assertEquals(0x8000, il.physicalOf(0));
		assertEquals(0, il.physicalOf(0x8000));
		assertEquals(0x17FFF, il.physicalOf(0x1FFFF));
		assertEquals(0x8000, il.contiguousRun(0));
		assertEquals(1, il.contiguousRun(0x7FFF));

		SnesImageLayout cs = new SnesImageLayout(0x200, 0x600000, false, true);
		assertEquals(0x200 + 0x200000, cs.fileOffsetOf(0));
		assertEquals(0x200, cs.fileOffsetOf(0x400000));
		assertEquals(0x400000, cs.contiguousRun(0));
		assertEquals(0x200000, cs.contiguousRun(0x400000));

		// A trailing partial unit is not swapped.
		SnesImageLayout partial = new SnesImageLayout(0, 0x18000, true, false);
		assertEquals(0x10000, partial.physicalOf(0x10000));
		assertEquals(0x8000, partial.physicalOf(0));

		SnesImageLayout canon = SnesImageLayout.canonical(0x200, 0x80000);
		assertEquals(0x200 + 0x1234, canon.fileOffsetOf(0x1234));
		assertEquals(0x80000 - 0x1234, canon.contiguousRun(0x1234));
	}

	@Test
	public void chunkSwapNeedsAnAlignedRemainderOverFourMiB() {
		assertFalse(SnesImageLayout.chunkSwapPossible(0x400000));
		assertFalse(SnesImageLayout.chunkSwapPossible(0x408000));
		assertTrue(SnesImageLayout.chunkSwapPossible(0x600000));
	}

	@Test
	public void modeParsingIsForgiving() {
		assertEquals(Mode.OFF, Mode.parse("off"));
		assertEquals(Mode.FORCE, Mode.parse(" Force "));
		assertEquals(Mode.AUTO, Mode.parse("nonsense"));
		assertEquals(Mode.AUTO, Mode.parse(null));
	}

	@Test
	public void garbageIsStillRefusedInEveryMode() {
		byte[] file = new byte[0x80000];
		Arrays.fill(file, (byte) 0xEE);
		for (Mode m : Mode.values()) {
			assertEquals(null, SnesRomHeader.parse(file, m));
		}
	}
}
