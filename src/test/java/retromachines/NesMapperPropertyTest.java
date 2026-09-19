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

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;

/**
 * Pure-JUnit coverage of {@link NesRomLoader#mapperPropertyValue} and the mapper/submapper
 * decoding it reads from {@link NesRomLoader.InesHeader} (bead grm-3ppn): the owner wants the
 * iNES mapper number -- and, on an NES 2.0 header, the submapper -- recorded as a Program
 * property, because board names alone are not memorable the way mapper numbers are.
 * <p>
 * Mirrors {@link NesGameIdentityTest}'s synthetic-image approach: {@link ByteArrayProvider} is
 * bootstrap-free, so this runs at plain-JUnit speed with no {@code AbstractGenericTest}.
 */
public class NesMapperPropertyTest {

	private static final int INES_HEADER_LEN = 16;
	private static final int PRG_BANK_LEN = 0x4000;

	/** Deterministic non-trivial filler, matching {@code NesGameIdentityTest}'s helper. */
	private static byte[] filler(int length, int seed) {
		byte[] out = new byte[length];
		for (int i = 0; i < length; i++) {
			out[i] = (byte) (i * 7 + 3 + seed);
		}
		return out;
	}

	private static byte[] concat(byte[] a, byte[] b) {
		byte[] out = new byte[a.length + b.length];
		System.arraycopy(a, 0, out, 0, a.length);
		System.arraycopy(b, 0, out, a.length, b.length);
		return out;
	}

	/**
	 * Builds a synthetic iNES/NES 2.0 header. {@code mapperLow} is the mapper's low nibble
	 * (header byte 6 high nibble); {@code mapperMid} is byte 7's high nibble (iNES 1.0/archaic
	 * mapper bits 4-7, also NES 2.0 mapper bits 4-7); {@code mapperHiAndSubmapper} is byte 8 as a
	 * whole -- low nibble mapper bits 8-11, high nibble the submapper -- meaningful only when
	 * {@code nes2} is true.
	 */
	private static byte[] ines(int mapperLow, int mapperMid, int mapperHiAndSubmapper,
			boolean nes2, int prgBanks) {
		byte[] header = new byte[INES_HEADER_LEN];
		header[0] = 'N';
		header[1] = 'E';
		header[2] = 'S';
		header[3] = 0x1A;
		header[4] = (byte) prgBanks;
		header[6] = (byte) ((mapperLow & 0x0F) << 4);
		header[7] = (byte) ((mapperMid & 0x0F) << 4);
		if (nes2) {
			header[7] |= 0x08;
			header[8] = (byte) mapperHiAndSubmapper;
		}
		return concat(header, filler(prgBanks * PRG_BANK_LEN, 0));
	}

	private static NesRomLoader.InesHeader parse(byte[] image) throws IOException {
		NesRomLoader.InesHeader header = NesRomLoader.InesHeader.parse(new ByteArrayProvider(image));
		assertNotNull(header);
		return header;
	}

	@Test
	public void ines1MapperFormatsAsPlainDecimal() throws IOException {
		// Mapper 4 (MMC3): low nibble 4, mid nibble 0.
		NesRomLoader.InesHeader header = parse(ines(4, 0, 0, false, 1));
		assertEquals(4, header.mapper());
		assertEquals("4", NesRomLoader.mapperPropertyValue(header));
	}

	@Test
	public void ines1MapperCombinesLowAndMidNibbles() throws IOException {
		// Mapper 34 (BNROM): low nibble 2, mid nibble 2 -> 0x22 = 34.
		NesRomLoader.InesHeader header = parse(ines(2, 2, 0, false, 1));
		assertEquals(34, header.mapper());
		assertEquals("34", NesRomLoader.mapperPropertyValue(header));
	}

	@Test
	public void nes2MapperAppendsSubmapper() throws IOException {
		// Mapper 4 (MMC3) with submapper 1 (MMC6-style): byte 8 = 0x10 (submapper 1, mapper hi 0).
		NesRomLoader.InesHeader header = parse(ines(4, 0, 0x10, true, 1));
		assertEquals(4, header.mapper());
		assertEquals(1, header.submapper());
		assertEquals("4 (submapper 1)", NesRomLoader.mapperPropertyValue(header));
	}

	@Test
	public void nes2SubmapperZeroIsStillReported() throws IOException {
		// NES 2.0 with an explicit submapper of 0 must still say so -- 0 is a real submapper
		// value on an NES 2.0 header, distinct from "no submapper field" on iNES 1.0.
		NesRomLoader.InesHeader header = parse(ines(4, 0, 0x00, true, 1));
		assertEquals(4, header.mapper());
		assertEquals(0, header.submapper());
		assertEquals("4 (submapper 0)", NesRomLoader.mapperPropertyValue(header));
	}

	@Test
	public void nes2MapperUsesHighNibbleOfByte8ForMapperBitsEightToEleven() throws IOException {
		// Mapper bits 8-11 come from byte 8's LOW nibble; set them to 1 (mapper += 256) alongside
		// mid nibble 0xF and low nibble 0xF, i.e. mapper = 0x1FF = 511, submapper 3 (hi nibble).
		NesRomLoader.InesHeader header = parse(ines(0xF, 0xF, 0x31, true, 1));
		assertEquals(0x1FF, header.mapper());
		assertEquals(3, header.submapper());
		assertEquals("511 (submapper 3)", NesRomLoader.mapperPropertyValue(header));
	}

	@Test
	public void ines1HeaderReportsNoSubmapper() throws IOException {
		NesRomLoader.InesHeader header = parse(ines(4, 0, 0, false, 1));
		assertEquals(0, header.submapper());
		assertEquals(false, header.nes2());
	}
}
