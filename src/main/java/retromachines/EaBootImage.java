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

import java.io.ByteArrayOutputStream;

/**
 * Recovers the boot image of an early Electronic Arts C64 disk (bead grm-t3n.6): raw sectors from
 * track 1 sector 0 onward, read by the EA loader straight off the disk (no directory file) and
 * decrypted with a rolling key. Pure logic; imports nothing from {@code ghidra.*}.
 * <p>
 * <b>Why there is no per-game table.</b> Every parameter is stored in, or computable from, the
 * loader file {@code EA2.PRG} that sits on the same disk (a PRG at {@code $C000}, 2562 bytes; the
 * directory name is {@code EA"<$9D>}), which is what lets this work on any disk using the
 * scheme without a curated key list:
 * <ul>
 * <li>{@code $C003/$C004/$C005} are the start page, end page (exclusive) and checksum of the
 * image. The image is {@code end - start} sectors, loaded at {@code start << 8}.</li>
 * <li>The sectors are read in the loader's own order: track 1 sector 0..19, then track 2
 * sector 0..19, and so on (20 per track although the zone has 21; the sector counter rolls at
 * 20).</li>
 * <li>The key's initial state is two checksums of the loader's own code ({@code $C4A1..}):
 * {@code C6BF = rotsum($C008, $2E6 bytes) + $C004} and {@code C6C0 = rotsum($C309, $227
 * bytes)}, where rotsum is the loader's {@code ASL; ADC (ptr),Y} loop. The loader measures
 * itself AFTER two self-modifications (the copy-protection success path turns the {@code INC}
 * at {@code $C4D3} into {@code DEC}; the sector loader stores {@code $F1} into the
 * {@code $FF} operand at {@code $C4E0}), so those two patches are applied before summing.</li>
 * <li>{@code $C293} accepts the image when the plain sum of all decrypted bytes minus
 * {@code $C005} is zero. We apply the same test, so a loader variant with a different key
 * derivation fails loudly (no member) instead of yielding garbage.</li>
 * </ul>
 * Derived from the owner's disassembly (game-music-extraction c64/acs: ripsectors.pl, ldwork.txt,
 * ea2.txt) and checked byte for byte against ACS1.D64: NEXT at {@code $08C4}, DOCOL at
 * {@code $08E2}, sum {@code $F9} = {@code $C005}.
 */
public final class EaBootImage {

	/** Host name of the synthetic member (becomes {@code EA_BOOT_IMAGE.prg}). */
	public static final String MEMBER_BASE_NAME = "EA_BOOT_IMAGE";

	static final int LOADER_LENGTH = 2562;
	static final int LOADER_ADDRESS = 0xC000;
	static final int SECTORS_PER_TRACK_USED = 20;
	/** Key-step wrap value the loader stores at {@code $C4E0} before decrypting. */
	static final int WRAP_KEY = 0xF1;
	private static final int DEC_ABS = 0xCE;
	private static final int INC_ABS = 0xEE;
	private static final int PAGE_XOR = 0x7F;

	private EaBootImage() {
	}

	/** A recovered image: {@code data} is the 2-byte load address followed by the decrypted bytes. */
	public static final class Result {
		private final byte[] prg;
		private final int loadAddress;

		Result(byte[] prg, int loadAddress) {
			this.prg = prg;
			this.loadAddress = loadAddress;
		}

		public byte[] prg() {
			return prg;
		}

		public int loadAddress() {
			return loadAddress;
		}
	}

	/** Either an image or the reason the loader was recognized but no image could be built. */
	public record Outcome(Result result, String problem) {
	}

	/**
	 * Looks for the EA loader among {@code image}'s members; null when the disk has none (the
	 * common case: nothing to report).
	 */
	public static Outcome recover(D64Image image) {
		byte[] loader = null;
		for (D64Image.Member m : image.members()) {
			// Any file kind: a real disk has it as PRG, and the headless fixture stores it as USR
			// so that only the synthetic boot member is imported as a program.
			if (looksLikeLoader(m.data())) {
				loader = m.data();
				break;
			}
		}
		if (loader == null) {
			return null;
		}
		int startPage = loader[2 + 3] & 0xff;
		int endPage = loader[2 + 4] & 0xff;
		int checksum = loader[2 + 5] & 0xff;
		int pages = endPage - startPage;
		if (pages <= 0 || endPage > 0x80) {
			return new Outcome(null, "EA loader header has an implausible page range $" +
				hex2(startPage) + "-$" + hex2(endPage));
		}
		ByteArrayOutputStream raw = new ByteArrayOutputStream();
		int track = 1;
		int sector = 0;
		for (int n = 0; n < pages; n++) {
			byte[] s = image.rawSector(track, sector);
			if (s == null) {
				return new Outcome(null,
					"EA boot sector " + track + "/" + sector + " is missing or has a disk error");
			}
			raw.write(s, 0, s.length);
			if (++sector == SECTORS_PER_TRACK_USED) {
				sector = 0;
				track++;
			}
		}
		int[] key = deriveKey(loader);
		int loadAddress = startPage << 8;
		byte[] data = decrypt(raw.toByteArray(), loadAddress, key[0], key[1]);
		int sum = 0;
		for (byte b : data) {
			sum += b & 0xff;
		}
		if ((sum & 0xff) != checksum) {
			return new Outcome(null, "EA boot image checksum mismatch: decrypted sum $" +
				hex2(sum & 0xff) + ", loader header says $" + hex2(checksum) +
				" (unknown loader variant?)");
		}
		byte[] prg = new byte[data.length + 2];
		prg[0] = (byte) loadAddress;
		prg[1] = (byte) (loadAddress >> 8);
		System.arraycopy(data, 0, prg, 2, data.length);
		return new Outcome(new Result(prg, loadAddress), null);
	}

	/**
	 * True for the loader PRG: {@code $C000}, 2562 bytes, and the three machine-code anchors the
	 * key derivation depends on (the checksum routine at {@code $C293}, the key step at
	 * {@code $C4D3}, the rotating sum at {@code $C4EB}). The mandatory checksum in
	 * {@link #recover} is the real guard; this only keeps unrelated files from being tried.
	 */
	static boolean looksLikeLoader(byte[] prg) {
		if (prg.length != LOADER_LENGTH || (prg[0] & 0xff) != 0 ||
			(prg[1] & 0xff) != 0xC0) {
			return false;
		}
		return at(prg, 0xC293, 0xA9, 0x00, 0x85, 0x2C, 0xAD, 0x03, 0xC0) &&
			at(prg, 0xC4D3, INC_ABS, 0xBF, 0xC6, 0xAD, 0xBF, 0xC6) &&
			at(prg, 0xC4EB, 0xA0, 0x00, 0x98, 0x0A, 0x71, 0x2C);
	}

	private static boolean at(byte[] prg, int addr, int... bytes) {
		for (int i = 0; i < bytes.length; i++) {
			if ((prg[2 + addr - LOADER_ADDRESS + i] & 0xff) != bytes[i]) {
				return false;
			}
		}
		return true;
	}

	/** The loader's {@code ASL A; ADC (ptr),Y} sum over {@code count} bytes from {@code start}. */
	static int rotSum(byte[] mem, int start, int count) {
		int a = 0;
		for (int i = 0; i < count; i++) {
			int carry = (a >> 7) & 1;
			a = ((a << 1) & 0xff) + (mem[start + i] & 0xff) + carry;
			a &= 0xff;
		}
		return a;
	}

	/** {@code {C6BF, C6C0}} for the loader PRG (file bytes, load address included). */
	static int[] deriveKey(byte[] prg) {
		byte[] mem = new byte[prg.length - 2];
		System.arraycopy(prg, 2, mem, 0, mem.length);
		int endPage = mem[4] & 0xff;
		// The two run-time self-modifications that precede the self-checksum (class comment).
		mem[0xC4D3 - LOADER_ADDRESS] = (byte) DEC_ABS;
		mem[0xC4E0 - LOADER_ADDRESS] = (byte) WRAP_KEY;
		int c6bf = (rotSum(mem, 0xC008 - LOADER_ADDRESS, 0x2E6) + endPage) & 0xff;
		int c6c0 = rotSum(mem, 0xC309 - LOADER_ADDRESS, 0x227);
		return new int[] { c6bf, c6c0 };
	}

	/**
	 * The loader's decrypt loop ({@code $C4BE}): per key step ({@code $C4D3}, DEC form) four
	 * {@code EOR2C} operations, each XORing two bytes with the current key and then re-keying
	 * with {@code (next address high byte) ^ $7F}. Stops at the end of {@code raw} (the real loop
	 * runs on into whatever follows in RAM) or, like the loader, when the key reaches zero after
	 * a group.
	 */
	static byte[] decrypt(byte[] raw, int loadAddress, int c6bf, int c6c0) {
		byte[] out = raw.clone();
		int idx = 0;
		int key;
		do {
			// $C4D3 (DEC): wrap through $F1 when the pair meets.
			c6bf = (c6bf - 1) & 0xff;
			if (c6bf == c6c0) {
				c6bf = WRAP_KEY;
				c6c0 = (c6c0 + 1) & 0xff;
				key = c6c0;
			}
			else {
				key = c6bf;
			}
			for (int op = 0; op < 4; op++) {
				for (int b = 0; b < 2; b++) {
					if (idx < out.length) {
						out[idx] ^= (byte) key;
					}
					idx++;
				}
				key = (((loadAddress + idx) >> 8) & 0xff) ^ PAGE_XOR;
			}
		}
		while (key != 0 && idx < out.length);
		return out;
	}

	private static String hex2(int v) {
		return String.format("%02X", v);
	}
}
