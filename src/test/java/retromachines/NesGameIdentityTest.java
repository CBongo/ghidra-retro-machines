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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;

/**
 * Pure-JUnit coverage of {@link NesRomLoader#gameIdentity} (bead grm-hb6.1): which bytes of an
 * iNES image the per-game key is computed over, and which malformed images the loader declines
 * to key at all. Drives the real method over synthetic images built in-test.
 * <p>
 * The one {@code ghidra.*} import, {@link ByteArrayProvider}, is bootstrap-free: its
 * constructor only stores the array and {@code getInputStream} only wraps it in a
 * {@code ByteArrayInputStream} -- no {@code Application}, no FSRL resolution -- so this class
 * still runs in a plain JUnit JVM at Tier 1 speed, with no {@code AbstractGenericTest}.
 * <p>
 * The property the whole tier rests on is
 * {@link #headerOnlyDifferenceKeepsPrgHashAndChangesFileHash}: header rot (a scribbled archaic
 * header, a regenerated NES 2.0 header, a stripped or added trainer) changes the file hash but
 * must never change the PRG hash, because every claim a descriptor makes is about the PRG
 * content and is equally true of all those files.
 */
public class NesGameIdentityTest {

	private static final int INES_HEADER_LEN = 16;
	private static final int TRAINER_LEN = 512;
	private static final int PRG_BANK_LEN = 0x4000;

	// ------------------------------------------------------------------
	// Synthetic image construction
	// ------------------------------------------------------------------

	/**
	 * Builds a synthetic iNES image: a 16-byte header (magic, {@code prgBanks} in byte 4, the
	 * trainer flag in byte 6, the NES 2.0 marker in byte 7, and optional bytes 12-15), then 512
	 * filler bytes when {@code trainer} is set, then {@code body} (PRG followed by whatever CHR
	 * or footer bytes the caller wants).
	 *
	 * @param prgBanks value for header byte 4 (16 KiB units)
	 * @param trainer whether to set the trainer flag and emit a 512-byte trainer
	 * @param nes2 whether to mark the header NES 2.0 ({@code h[7] & 0x0C == 0x08})
	 * @param tail1215 four bytes for header bytes 12-15, or {@code null} for a clean zero tail
	 * @param body everything after the header and trainer
	 */
	private static byte[] ines(int prgBanks, boolean trainer, boolean nes2, byte[] tail1215,
			byte[] body) {
		byte[] header = new byte[INES_HEADER_LEN];
		header[0] = 'N';
		header[1] = 'E';
		header[2] = 'S';
		header[3] = 0x1A;
		header[4] = (byte) prgBanks;
		header[5] = 0; // CHR bank count; the identity path never reads it
		if (trainer) {
			header[6] |= 0x04;
		}
		if (nes2) {
			header[7] |= 0x08;
		}
		if (tail1215 != null) {
			System.arraycopy(tail1215, 0, header, 12, tail1215.length);
		}
		byte[] image = trainer ? concat(header, filler(TRAINER_LEN, 99), body)
				: concat(header, body);
		return image;
	}

	/** Deterministic non-trivial filler, so a hash over the wrong slice cannot coincide. */
	private static byte[] filler(int length, int seed) {
		byte[] out = new byte[length];
		for (int i = 0; i < length; i++) {
			out[i] = (byte) (i * 7 + 3 + seed);
		}
		return out;
	}

	private static byte[] concat(byte[]... parts) {
		int total = 0;
		for (byte[] part : parts) {
			total += part.length;
		}
		byte[] out = new byte[total];
		int at = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, out, at, part.length);
			at += part.length;
		}
		return out;
	}

	private static DescriptorSupport.GameIdentity identityOf(byte[] image) throws IOException {
		return NesRomLoader.gameIdentity(new ByteArrayProvider(image));
	}

	/**
	 * An independent SHA-256 oracle: deliberately NOT {@code DescriptorSupport.sha256Hex}, so a
	 * bug in the production digest or its hex formatting cannot cancel itself out here.
	 */
	private static String sha256Hex(byte[] data) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
			StringBuilder hex = new StringBuilder(digest.length * 2);
			for (byte b : digest) {
				hex.append(String.format("%02x", b));
			}
			return hex.toString();
		}
		catch (NoSuchAlgorithmException e) {
			throw new AssertionError("SHA-256 unavailable", e);
		}
	}

	// ------------------------------------------------------------------
	// Slice bounds
	// ------------------------------------------------------------------

	@Test
	public void prgHashCoversExactlyThePrgSlice() throws IOException {
		byte[] prg = filler(PRG_BANK_LEN, 0);
		byte[] chr = filler(2048, 41);
		byte[] image = ines(1, true, false, null, concat(prg, chr));

		DescriptorSupport.GameIdentity id = identityOf(image);
		assertNotNull(id);
		assertEquals(sha256Hex(prg), id.prgSha256());
		assertEquals(sha256Hex(image), id.fileSha256());
	}

	@Test
	public void headerOnlyDifferenceKeepsPrgHashAndChangesFileHash() throws IOException {
		// The keystone property: a "DiskDude!"-style tool that scribbled ASCII into header
		// bytes 12-15 produced a different file, but the same cartridge. The primary key must
		// follow the cartridge, not the container.
		byte[] prg = filler(PRG_BANK_LEN, 0);
		byte[] clean = ines(1, false, false, null, prg);
		byte[] scribbled = ines(1, false, false, new byte[] { 'u', 'd', 'e', '!' }, prg);

		DescriptorSupport.GameIdentity cleanId = identityOf(clean);
		DescriptorSupport.GameIdentity scribbledId = identityOf(scribbled);
		assertNotNull(cleanId);
		assertNotNull(scribbledId);
		assertEquals(cleanId.prgSha256(), scribbledId.prgSha256());
		assertNotEquals(cleanId.fileSha256(), scribbledId.fileSha256());
	}

	@Test
	public void trainerIsExcludedFromPrgHash() throws IOException {
		byte[] prg = filler(PRG_BANK_LEN, 0);
		byte[] plain = ines(1, false, false, null, prg);
		byte[] trained = ines(1, true, false, null, prg);
		assertEquals(TRAINER_LEN, trained.length - plain.length);

		DescriptorSupport.GameIdentity plainId = identityOf(plain);
		DescriptorSupport.GameIdentity trainedId = identityOf(trained);
		assertNotNull(plainId);
		assertNotNull(trainedId);
		assertEquals(plainId.prgSha256(), trainedId.prgSha256());
		assertNotEquals(plainId.fileSha256(), trainedId.fileSha256());
	}

	@Test
	public void nes2AndInes1PrgSizeEncodingsHashTheSameSlice() throws IOException {
		// NES 2.0 splits the PRG unit count across h[4] and the low nibble of h[9]; with that
		// nibble zero it names the same two banks iNES 1.0 names in h[4] alone.
		byte[] prg = filler(2 * PRG_BANK_LEN, 0);
		byte[] ines1 = ines(2, false, false, null, prg);
		byte[] nes2 = ines(2, false, true, null, prg);
		assertEquals(0, nes2[9] & 0x0F);

		DescriptorSupport.GameIdentity ines1Id = identityOf(ines1);
		DescriptorSupport.GameIdentity nes2Id = identityOf(nes2);
		assertNotNull(ines1Id);
		assertNotNull(nes2Id);
		assertEquals(sha256Hex(prg), ines1Id.prgSha256());
		assertEquals(ines1Id.prgSha256(), nes2Id.prgSha256());
	}

	@Test
	public void trailingChrBytesChangeOnlyTheFileHash() throws IOException {
		byte[] prg = filler(PRG_BANK_LEN, 0);
		byte[] prgOnly = ines(1, false, false, null, prg);
		byte[] withChr = ines(1, false, false, null, concat(prg, filler(8192, 17)));

		DescriptorSupport.GameIdentity prgOnlyId = identityOf(prgOnly);
		DescriptorSupport.GameIdentity withChrId = identityOf(withChr);
		assertNotNull(prgOnlyId);
		assertNotNull(withChrId);
		assertEquals(prgOnlyId.prgSha256(), withChrId.prgSha256());
		assertNotEquals(prgOnlyId.fileSha256(), withChrId.fileSha256());
	}

	@Test
	public void flippedPrgByteChangesPrgHash() throws IOException {
		byte[] prg = filler(PRG_BANK_LEN, 0);
		byte[] original = ines(1, false, false, null, prg);
		byte[] patched = original.clone();
		patched[INES_HEADER_LEN + 1234] ^= 0x01;

		DescriptorSupport.GameIdentity originalId = identityOf(original);
		DescriptorSupport.GameIdentity patchedId = identityOf(patched);
		assertNotNull(originalId);
		assertNotNull(patchedId);
		assertNotEquals(originalId.prgSha256(), patchedId.prgSha256());
	}

	/**
	 * The NES 2.0 exponent PRG-size form (bead grm-dfj), which three local images use: h[9]'s
	 * low nibble == 0xF makes h[4] {@code EEEEEEMM} rather than a count of 16 KiB units, and
	 * the size is {@code 2^E * (2M+1)} bytes. h[4] = 0x34 is E = 13, M = 0 -- an 8 KiB PRG,
	 * HALF of one unit, which is exactly what the linear form cannot express and why real
	 * cartridges (both Galaxian (J) revisions, Controller Test Program (J)) use this form.
	 * <p>
	 * The assertion that matters is the slice: keying over h[4] read as a unit count would run
	 * 832K past EOF and decline, and keying over one whole unit would swallow the CHR that
	 * follows. Only the decoded 8 KiB gives the PRG digest below.
	 */
	@Test
	public void exponentPrgSizeFormKeysOverTheDecodedSlice() throws IOException {
		byte[] prg = filler(0x2000, 5);
		byte[] chr = filler(0x2000, 6);
		byte[] image = ines(0x34, false, true, null, concat(prg, chr));
		image[9] = 0x0F;

		DescriptorSupport.GameIdentity id = identityOf(image);
		assertNotNull(id);
		assertEquals(sha256Hex(prg), id.prgSha256());
		assertEquals(sha256Hex(image), id.fileSha256());
	}

	// ------------------------------------------------------------------
	// Images the loader declines to key
	// ------------------------------------------------------------------

	@Test
	public void absurdExponentPrgSizeYieldsNoIdentity() throws IOException {
		// The exponent field is 6 bits, so it can name a size no cartridge could have; those
		// decode to 0 rather than to an overflowed (possibly negative) length, and a zero PRG
		// size is declined here for the same reason a zero unit count is. h[4] = 0xFC is E = 63.
		byte[] image = ines(0xFC, false, true, null, filler(PRG_BANK_LEN, 0));
		image[9] = 0x0F;
		assertNull(identityOf(image));
	}

	@Test
	public void zeroPrgBanksYieldsNoIdentity() throws IOException {
		// Otherwise every such file would share the fixed empty-input digest as its key.
		assertNull(identityOf(ines(0, false, false, null, filler(PRG_BANK_LEN, 0))));
	}

	@Test
	public void truncatedImageYieldsNoIdentity() throws IOException {
		// Header declares two banks; only one bank of content follows.
		assertNull(identityOf(ines(2, false, false, null, filler(PRG_BANK_LEN, 0))));
	}

	@Test
	public void badMagicYieldsNoIdentity() throws IOException {
		byte[] image = ines(1, false, false, null, filler(PRG_BANK_LEN, 0));
		image[3] = 0x00;
		assertNull(identityOf(image));

		// Shorter than the header itself -- nothing to parse at all.
		assertNull(identityOf(new byte[] { 'N', 'E', 'S', 0x1A, 1, 0, 0, 0 }));
	}
}
