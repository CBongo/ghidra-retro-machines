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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import retromachines.SnesRomHeader.MapType;

/**
 * Fixtures for {@link SnesRomHeader} (bead grm-9nxj.9). Images are synthesized here rather than
 * committed: real SNES ROMs cannot ship with this repo. The shapes below mirror what the project
 * owner's 11-ROM corpus actually contains -- LoROM and HiROM at 512 KB to 4 MB, ten of eleven
 * with a copier header -- and the detection algorithm they exercise was validated against that
 * corpus by hand before this class existed (see the class doc on {@link SnesRomHeader}).
 */
public class SnesRomHeaderTest {

	/**
	 * Builds a cartridge image with a valid header at {@code headerOffset}.
	 *
	 * @param copier whether to prepend a 512-byte copier header, as ten of eleven corpus ROMs do
	 */
	private static byte[] image(int sizeBytes, int headerOffset, String title, int mapMode,
			int chipset, int romSizeExp, boolean copier) {
		byte[] file = new byte[sizeBytes + (copier ? 0x200 : 0)];
		// Fill with a byte that is NOT printable ASCII, so a wrong candidate offset cannot
		// accidentally score well on title printability.
		Arrays.fill(file, (byte) 0xEE);
		int at = (copier ? 0x200 : 0) + headerOffset;

		byte[] name = String.format("%-21s", title).getBytes();
		System.arraycopy(name, 0, file, at, 21);
		file[at + 0x15] = (byte) mapMode;
		file[at + 0x16] = (byte) chipset;
		file[at + 0x17] = (byte) romSizeExp;
		file[at + 0x18] = 0x03; // 8 KB of cartridge RAM

		// The pair the detector keys on: checksum and its ones' complement.
		int checksum = 0x1234;
		write16(file, at + 0x1E, checksum);
		write16(file, at + 0x1C, checksum ^ 0xFFFF);

		// A reset vector, in the table that follows the header at +0x20 ($FFE0); the emulation
		// reset slot is at +0x1C within it.
		write16(file, at + 0x20 + 0x1C, 0x8000);
		return file;
	}

	private static void write16(byte[] file, int at, int value) {
		file[at] = (byte) (value & 0xFF);
		file[at + 1] = (byte) ((value >> 8) & 0xFF);
	}

	@Test
	public void detectsLoRomWithACopierHeader() {
		byte[] file = image(0x80000, 0x7FC0, "F-ZERO", 0x20, 0x02, 0x09, true);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull("a valid LoROM header was not detected", header);
		assertEquals(0x7FC0, header.headerOffset());
		assertTrue("copier header not detected from the file size", header.copierHeader());
		assertEquals("cartridge content should start past the copier header", 0x200,
			header.dataOffset());
		assertEquals("F-ZERO", header.title());
		assertEquals(MapType.LOROM, header.mapType());
		assertFalse("map mode $20 is slow ROM", header.fastRom());
		assertTrue(header.checksumValid());
		assertTrue(header.mapTypeMatchesLocation());
		assertEquals(512 * 1024, header.romSizeBytes());
		assertEquals(8 * 1024, header.ramSizeBytes());
		assertEquals(0x8000, header.resetVector());
	}

	/** {@code lemmings.smc} in the corpus: exactly 1 MB, no copier header. */
	@Test
	public void detectsLoRomWithoutACopierHeader() {
		byte[] file = image(0x100000, 0x7FC0, "LEMMINGS", 0x20, 0x00, 0x0A, false);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertFalse("a 1 MB file is a whole number of 1 KB blocks -- no copier header",
			header.copierHeader());
		assertEquals(0, header.dataOffset());
		assertEquals(MapType.LOROM, header.mapType());
		assertEquals(1024 * 1024, header.romSizeBytes());
	}

	/** {@code chrono.smc}: HiROM with the FastROM bit set, 4 MB, copier header. */
	@Test
	public void detectsHiRomFastRom() {
		byte[] file = image(0x400000, 0xFFC0, "CHRONO TRIGGER", 0x31, 0x02, 0x0C, true);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertEquals(0xFFC0, header.headerOffset());
		assertEquals(MapType.HIROM, header.mapType());
		assertTrue("map mode $31 sets the FastROM bit", header.fastRom());
		assertTrue(header.mapTypeMatchesLocation());
		assertEquals(4 * 1024 * 1024, header.romSizeBytes());
	}

	@Test
	public void detectsExHiRom() {
		byte[] file = image(0x600000, 0x40FFC0, "EXHIROM TITLE", 0x35, 0x02, 0x0D, false);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertEquals(0x40FFC0, header.headerOffset());
		assertEquals(MapType.EXHIROM, header.mapType());
		assertTrue(header.fastRom());
		assertTrue(header.mapTypeMatchesLocation());
	}

	/**
	 * The point of scoring: a LoROM image also HAS bytes at {@code $FFC0}, and they must not win.
	 * Here the decoy carries a perfectly printable title but no valid checksum pair, which is
	 * exactly the case the checksum bonus exists to break.
	 */
	@Test
	public void checksumPairBeatsAPrintableDecoy() {
		byte[] file = image(0x80000, 0x7FC0, "REAL HEADER", 0x20, 0x00, 0x09, false);
		byte[] decoy = String.format("%-21s", "DECOY AT FFC0").getBytes();
		System.arraycopy(decoy, 0, file, 0xFFC0, decoy.length);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertEquals("the checksum-valid candidate must win over a printable decoy", 0x7FC0,
			header.headerOffset());
		assertEquals("REAL HEADER", header.title());
	}

	/**
	 * A file that is not a SNES ROM must be REFUSED, not mapped from whatever bytes sit at a
	 * candidate offset. Silent mis-detection here would poison every later step -- the map type
	 * decides the whole block layout.
	 */
	@Test
	public void refusesAnImageWithNoPlausibleHeader() {
		byte[] file = new byte[0x80000];
		Arrays.fill(file, (byte) 0xEE);

		assertNull("garbage was accepted as a SNES cartridge", SnesRomHeader.parse(file));
	}

	@Test
	public void refusesAnImageTooSmallToHoldAHeader() {
		assertNull(SnesRomHeader.parse(new byte[0x100]));
	}

	/**
	 * A header whose declared mapping contradicts where it was found is reported, not silently
	 * accepted: the loader has to decide what to do with the contradiction, and cannot if this
	 * class picks one of the two facts on its behalf.
	 */
	@Test
	public void reportsWhenTheDeclaredMappingContradictsTheLocation() {
		byte[] file = image(0x80000, 0x7FC0, "CONFUSED", 0x21, 0x00, 0x09, false);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertEquals(MapType.HIROM, header.mapType());
		assertEquals(0x7FC0, header.headerOffset());
		assertFalse("a HiROM map mode found at the LoROM offset should not read as consistent",
			header.mapTypeMatchesLocation());
	}

	/** An unmodelled map-mode nibble is UNKNOWN rather than a wrong guess. */
	@Test
	public void unmodelledMapModeIsUnknown() {
		byte[] file = image(0x80000, 0x7FC0, "WEIRD", 0x2F, 0x00, 0x09, false);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertEquals(MapType.UNKNOWN, header.mapType());
		assertFalse(header.mapTypeMatchesLocation());
	}

	/** A corrupt size exponent yields zero rather than an absurd size. */
	@Test
	public void absurdSizeExponentIsClampedToZero() {
		byte[] file = image(0x80000, 0x7FC0, "CORRUPT SIZE", 0x20, 0x00, 0x7F, false);

		SnesRomHeader header = SnesRomHeader.parse(file);
		assertNotNull(header);
		assertEquals(0, header.romSizeBytes());
	}
}
