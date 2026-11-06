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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link EaBootImage} (bead grm-t3n.6). The loader and the boot image are
 * synthetic; only the key-step vectors use the ACS key pair ({@code $73}/{@code $14}) the
 * owner's rip derived from the real loader.
 */
public class EaBootImageTest {

	/** A 2562-byte loader PRG with the three machine-code anchors and a header. */
	static byte[] syntheticLoader(int startPage, int endPage, int checksum) {
		byte[] prg = new byte[EaBootImage.LOADER_LENGTH];
		prg[1] = (byte) 0xC0;
		for (int i = 2; i < prg.length; i++) {
			prg[i] = (byte) (i * 31 + 7);
		}
		prg[2 + 3] = (byte) startPage;
		prg[2 + 4] = (byte) endPage;
		prg[2 + 5] = (byte) checksum;
		put(prg, 0xC293, 0xA9, 0x00, 0x85, 0x2C, 0xAD, 0x03, 0xC0);
		put(prg, 0xC4D3, 0xEE, 0xBF, 0xC6, 0xAD, 0xBF, 0xC6);
		put(prg, 0xC4E0, 0xFF);
		put(prg, 0xC4EB, 0xA0, 0x00, 0x98, 0x0A, 0x71, 0x2C);
		return prg;
	}

	private static void put(byte[] prg, int addr, int... bytes) {
		for (int i = 0; i < bytes.length; i++) {
			prg[2 + addr - 0xC000 + i] = (byte) bytes[i];
		}
	}

	static byte[] plainImage(int pages) {
		byte[] b = new byte[pages * 256];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) (i * 13 + (i >> 8) + 5);
		}
		return b;
	}

	static int sum(byte[] b) {
		int s = 0;
		for (byte x : b) {
			s += x & 0xff;
		}
		return s & 0xff;
	}

	/** Builds a disk: the loader as a PRG file, the encrypted image in raw T1S0.. sectors. */
	static byte[] syntheticDisk(byte[] loader, byte[] plain, int startPage) {
		D64ImageTest.Builder b = new D64ImageTest.Builder(D64Image.SIZE_35);
		b.nextTrack = 5;
		b.file(0x82, D64ImageTest.name("EA2"), loader);
		int[] key = EaBootImage.deriveKey(loader);
		byte[] enc = EaBootImage.decrypt(plain, startPage << 8, key[0], key[1]);
		int track = 1;
		int sector = 0;
		for (int p = 0; p < enc.length / 256; p++) {
			System.arraycopy(enc, p * 256, b.img, D64ImageTest.Builder.off(track, sector), 256);
			if (++sector == 20) {
				sector = 0;
				track++;
			}
		}
		return b.img;
	}

	@Test
	public void keyStepAcsPair() {
		// First key is C6BF-1 = $72 for the first pair, then (page ^ $7F) = $77 for the rest.
		byte[] out = EaBootImage.decrypt(new byte[8], 0x0800, 0x73, 0x14);
		assertArrayEquals(new byte[] { 0x72, 0x72, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77 }, out);
	}

	@Test
	public void keyStepWrapsThroughF1() {
		// C6BF-1 meets C6C0: C6BF = $F1, C6C0 = $15, and the returned key is the new C6C0.
		byte[] out = EaBootImage.decrypt(new byte[16], 0x0800, 0x15, 0x14);
		assertEquals(0x15, out[0] & 0xff);
		// The second step continues from C6BF = $F1: $F0.
		assertEquals(0xF0, out[8] & 0xff);
	}

	@Test
	public void decryptIsInvolutive() {
		byte[] plain = plainImage(3);
		byte[] enc = EaBootImage.decrypt(plain, 0x0800, 0x73, 0x14);
		assertEquals(false, java.util.Arrays.equals(plain, enc));
		assertArrayEquals(plain, EaBootImage.decrypt(enc, 0x0800, 0x73, 0x14));
	}

	@Test
	public void rotSumEndAroundCarry() {
		// 0x80 then 0x00: a = $80; next ASL carries out, so a = 0 + 0 + 1.
		assertEquals(1, EaBootImage.rotSum(new byte[] { (byte) 0x80, 0 }, 0, 2));
		assertEquals(0x5, EaBootImage.rotSum(new byte[] { 1, 3 }, 0, 2));
	}

	@Test
	public void recoversSyntheticBootImage() {
		byte[] plain = plainImage(5);
		byte[] loader = syntheticLoader(0x08, 0x0D, sum(plain));
		D64Image d = D64Image.parse(syntheticDisk(loader, plain, 0x08));
		assertNotNull(d);
		assertTrue(d.problems().toString(), d.problems().isEmpty());
		D64Image.Member m = D64ImageTest.find(d, "EA_BOOT_IMAGE.prg");
		assertNotNull(m);
		byte[] prg = m.data();
		assertEquals(plain.length + 2, prg.length);
		assertEquals(0x00, prg[0]);
		assertEquals(0x08, prg[1]);
		byte[] body = new byte[plain.length];
		System.arraycopy(prg, 2, body, 0, body.length);
		assertArrayEquals(plain, body);
		assertNotNull(D64ImageTest.find(d, "EA2.prg"));
	}

	@Test
	public void wrongChecksumFailsLoudlyWithoutMember() {
		byte[] plain = plainImage(5);
		byte[] loader = syntheticLoader(0x08, 0x0D, sum(plain) + 1);
		D64Image d = D64Image.parse(syntheticDisk(loader, plain, 0x08));
		assertNotNull(d);
		assertNull(D64ImageTest.find(d, "EA_BOOT_IMAGE.prg"));
		assertEquals(1, d.problems().size());
		assertTrue(d.problems().get(0), d.problems().get(0).contains("checksum mismatch"));
	}

	/** Real ACS1.D64 when a GRM_C64_ROM_DIR dir holds it (the real-ROM tier's env); else skipped. */
	@Test
	public void realAcsDiskWhenAvailable() throws java.io.IOException {
		String dirs = System.getenv("GRM_C64_ROM_DIR");
		org.junit.Assume.assumeTrue(dirs != null);
		java.nio.file.Path found = null;
		for (String dir : dirs.split(";")) {
			java.nio.file.Path p = java.nio.file.Path.of(dir.strip(), "ACS1.D64");
			if (java.nio.file.Files.isRegularFile(p)) {
				found = p;
			}
		}
		org.junit.Assume.assumeTrue(found != null);
		D64Image d = D64Image.parse(java.nio.file.Files.readAllBytes(found));
		assertNotNull(d);
		D64Image.Member m = D64ImageTest.find(d, "EA_BOOT_IMAGE.prg");
		assertNotNull(d.problems().toString(), m);
		byte[] prg = m.data();
		assertEquals(0x1E00 + 2, prg.length);
		// NEXT at $08C4 and DOCOL at $08E2.
		byte[] next = { (byte) 0xA0, 0x01, (byte) 0xB1, 0x7E, (byte) 0x85, (byte) 0x82 };
		byte[] docol = { (byte) 0xA5, 0x7F, 0x48, (byte) 0xA5, 0x7E, 0x48 };
		assertArrayEquals(next, java.util.Arrays.copyOfRange(prg, 2 + 0xC4, 2 + 0xC4 + 6));
		assertArrayEquals(docol, java.util.Arrays.copyOfRange(prg, 2 + 0xE2, 2 + 0xE2 + 6));
	}

	@Test
	public void unrelatedDiskGetsNoMember() {
		D64ImageTest.Builder b = new D64ImageTest.Builder(D64Image.SIZE_35);
		b.file(0x82, D64ImageTest.name("X"), D64ImageTest.pattern(2562, 4));
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertEquals(1, d.members().size());
		assertTrue(d.problems().isEmpty());
	}
}
