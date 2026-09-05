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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import retromachines.SnesAddressMap.Kind;
import retromachines.SnesRomHeader.MapType;

/**
 * Fixtures for {@link SnesAddressMap} (bead grm-9nxj.9). The mapping arithmetic is small enough
 * to state exactly, and wrong arithmetic here would put every later block, entry point and
 * mirror in the wrong place — so each case names the hardware fact it encodes rather than just
 * asserting a number.
 */
public class SnesAddressMapTest {

	private static final long ONE_MB = 0x100000L;

	// ---------------------------------------------------------------- LoROM

	/** LoROM maps 32 KiB per bank into the bank's UPPER half: bank 0's ROM starts at $008000. */
	@Test
	public void loRomMapsThirtyTwoKilobyteChunksToUpperHalves() {
		SnesAddressMap map = new SnesAddressMap(MapType.LOROM, ONE_MB);

		assertEquals(Long.valueOf(0x0000), map.fileOffsetOf(0x008000));
		assertEquals(Long.valueOf(0x7FFF), map.fileOffsetOf(0x00FFFF));
		assertEquals("bank 1's chunk follows bank 0's", Long.valueOf(0x8000),
			map.fileOffsetOf(0x018000));
		assertEquals(Long.valueOf(0x10000), map.fileOffsetOf(0x028000));
	}

	/** The lower half of a LoROM bank is not cartridge ROM — the cartridge's A15 is unconnected. */
	@Test
	public void loRomLowerHalvesAreNotRom() {
		SnesAddressMap map = new SnesAddressMap(MapType.LOROM, ONE_MB);

		assertNull(map.fileOffsetOf(0x018000 - 1));
		assertEquals(Kind.UNMODELLED, map.kindOf(0x014000));
	}

	// ---------------------------------------------------------------- HiROM

	/** HiROM is linear in banks $C0-$FF: bank $C0 offset 0 is file offset 0. */
	@Test
	public void hiRomIsLinearFromBankC0() {
		SnesAddressMap map = new SnesAddressMap(MapType.HIROM, 4 * ONE_MB);

		assertEquals(Long.valueOf(0x0000), map.fileOffsetOf(0xC00000));
		assertEquals(Long.valueOf(0xFFFF), map.fileOffsetOf(0xC0FFFF));
		assertEquals(Long.valueOf(0x10000), map.fileOffsetOf(0xC10000));
	}

	/**
	 * The system banks show the UPPER HALF of the corresponding HiROM bank — the same physical
	 * bytes, which is why $00:8000 and $C0:8000 are one address' worth of ROM, not two.
	 */
	@Test
	public void hiRomSystemBanksShowTheUpperHalfOfTheSameBank() {
		SnesAddressMap map = new SnesAddressMap(MapType.HIROM, 4 * ONE_MB);

		assertEquals(map.fileOffsetOf(0xC08000), map.fileOffsetOf(0x008000));
		assertEquals(map.fileOffsetOf(0xC1FFFF), map.fileOffsetOf(0x01FFFF));
		assertEquals("and HiROM's canonical home is the linear view, not the low banks",
			0xC08000, map.canonicalAddressOf(0x008000));
		assertNull("the lower half of a HiROM system bank is not ROM", map.fileOffsetOf(0x004000));
	}

	// ---------------------------------------------------------------- mirrors

	/** Banks $80-$FF are the same physical bytes as $00-$7F: the FastROM mirror. */
	@Test
	public void highBanksMirrorLowBanks() {
		SnesAddressMap map = new SnesAddressMap(MapType.LOROM, ONE_MB);

		assertEquals(0x008000, map.canonicalAddressOf(0x808000));
		assertEquals(map.fileOffsetOf(0x008000), map.fileOffsetOf(0x808000));
		assertTrue(map.isHighMirror(0x808000));
		assertTrue("a canonical address is not a mirror", !map.isHighMirror(0x008000));
	}

	// ---------------------------------------------------------------- RAM and IO

	@Test
	public void workRamIsTheFullBankPairAtSevenE() {
		SnesAddressMap map = new SnesAddressMap(MapType.LOROM, ONE_MB);

		assertEquals(Kind.WRAM, map.kindOf(0x7E0000));
		assertEquals(Kind.WRAM, map.kindOf(0x7FFFFF));
		// $80:0000 is NOT past work RAM -- it is the low-RAM mirror in bank $80, which mirrors
		// bank $00. (This test originally asserted UNMODELLED here and was wrong, not the code.)
		assertEquals(Kind.WRAM, map.kindOf(0x800000));
		assertEquals("the WRAM banks themselves stop after $7F:FFFF", Kind.UNMODELLED,
			map.kindOf(0x7D4000));
	}

	/** The first 8 KiB of work RAM is mirrored into the bottom of every system bank. */
	@Test
	public void lowRamMirrorsIntoSystemBanks() {
		SnesAddressMap map = new SnesAddressMap(MapType.LOROM, ONE_MB);

		assertEquals(Kind.WRAM, map.kindOf(0x000000));
		assertEquals(Kind.WRAM, map.kindOf(0x001FFF));
		assertEquals(Kind.WRAM, map.kindOf(0x3F1000));
		assertEquals("the mirror is 8 KiB, not 16", Kind.UNMODELLED, map.kindOf(0x002000));
	}

	@Test
	public void ioWindowsAreRecognised() {
		SnesAddressMap map = new SnesAddressMap(MapType.LOROM, ONE_MB);

		assertEquals("PPU/APU", Kind.IO, map.kindOf(0x002100));
		assertEquals(Kind.IO, map.kindOf(0x0021FF));
		assertEquals("CPU/DMA", Kind.IO, map.kindOf(0x004200));
		assertEquals(Kind.IO, map.kindOf(0x0043FF));
		assertEquals("IO is mirrored into the high banks too", Kind.IO, map.kindOf(0x802100));
	}

	// ---------------------------------------------------------------- bounds

	/** An address past the end of THIS image is not ROM, even though the wiring would map it. */
	@Test
	public void addressesPastTheImageAreNotRom() {
		SnesAddressMap small = new SnesAddressMap(MapType.LOROM, 0x8000);

		assertEquals(Long.valueOf(0), small.fileOffsetOf(0x008000));
		assertNull("bank 1 is past the end of a 32 KiB image", small.fileOffsetOf(0x018000));
	}

	@Test
	public void unknownMapTypeMapsNothing() {
		SnesAddressMap map = new SnesAddressMap(MapType.UNKNOWN, ONE_MB);

		assertNull(map.fileOffsetOf(0x008000));
		assertNull(map.fileOffsetOf(0xC00000));
	}
}
