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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.util.bin.ByteProvider;

/**
 * The SNES cartridge header (bead grm-9nxj.9), and the search that locates it.
 *
 * <p><b>Why locating it is a search rather than a lookup.</b> The header lives at {@code $FFC0}
 * in the mapping the cartridge declares -- but which mapping that is, is what the header itself
 * says, so its file offset cannot be known before it is found. In practice there are three
 * candidate offsets ({@code $7FC0} LoROM, {@code $FFC0} HiROM, {@code $40FFC0} ExHiROM), and the
 * header carries its own integrity check: a 16-bit checksum and its ones' complement, which must
 * XOR to {@code $FFFF}. Scoring each candidate on that pair plus the printability of its 21-byte
 * title separates the real header from whatever bytes happen to sit at the other offsets.
 *
 * <p><b>Provenance of this algorithm.</b> It was validated by hand against the 11 SNES ROMs in
 * the project owner's local corpus before being written down (bead grm-9nxj.6's evidence pass):
 * all 11 checksum/complement pairs validate, yielding 6 LoROM and 5 HiROM, 512 KB to 4 MB, and
 * no enhancement chips. Those ROMs cannot be committed, so the tests here build synthetic images
 * instead; the corpus run is the reason to believe the synthetic cases model reality.
 *
 * <p><b>The copier header.</b> Ten of those 11 files carry a 512-byte copier header prepended by
 * the dumping hardware, and one ({@code lemmings.smc}, exactly 1 MB) does not. It is detected by
 * size alone -- a cartridge image is a whole number of 1 KB blocks, so a file with
 * {@code size % 0x400 == 0x200} has 512 extra bytes on the front. Every offset in this class is
 * relative to the CARTRIDGE image; {@link #dataOffset()} says where that starts in the file.
 *
 * <p><b>Two known images defeat the size rule, and that is an ACCEPTED limitation</b> (grm-9nxj.16,
 * closed 2026-09-06 by the project owner -- do not re-open it as a bug). The 921-image corpus
 * survey found {@code NHL94USA.smc}, whose cartridge body is truncated 41 bytes short so the
 * remainder is neither 0 nor 0x200, and {@code oml-megamanx.sfc}, whose body is itself 0x200
 * short of a block boundary so the two irregularities cancel exactly. Both carry a real copier
 * header with a validating checksum pair, and both are therefore parsed at base 0, match nothing,
 * and are REFUSED. The ruling: 2 refusals in 921 (0.2%), both irregular dumps, and a refusal is
 * honest rather than silently wrong -- not worth giving the copier rule a second, search-based
 * path that only ever runs on malformed input. Keeping it a pure function of file length means it
 * has no way to pick wrong on a well-formed image. The corpus tier reports these two under
 * "checksum pair found only at the base the size rule did NOT pick"; that section is the tripwire
 * for a genuine detection regression, which would move dozens of rows into it at once.
 *
 * <p>Field layout, relative to the header's own base: title at {@code +0x00} (21 bytes), map mode
 * {@code +0x15}, chipset {@code +0x16}, ROM size {@code +0x17}, RAM size {@code +0x18}, checksum
 * complement {@code +0x1C}, checksum {@code +0x1E}. The CPU vector table follows at {@code +0x20}
 * (i.e. {@code $FFE0}), which is where {@link #vectors()} reads from.
 */
public record SnesRomHeader(int headerOffset, boolean copierHeader, String title, int mapMode,
		int chipset, long romSizeBytes, long ramSizeBytes, int checksum, int checksumComplement,
		boolean checksumValid, MapType mapType, boolean fastRom, Map<String, Integer> vectors) {

	/** Cartridge mapping declared by the map-mode byte's low nibble. */
	public enum MapType {
		LOROM, HIROM, EXHIROM,
		/** A map-mode byte this class does not model; the loader must refuse rather than guess. */
		UNKNOWN
	}

	/** Candidate header offsets within the cartridge image, in the order they are scored. */
	static final int[] CANDIDATE_OFFSETS = { 0x7FC0, 0xFFC0, 0x40FFC0 };

	private static final int TITLE_LEN = 21;
	private static final int HEADER_LEN = 0x20;
	private static final int COPIER_HEADER_LEN = 0x200;

	/**
	 * A candidate must look at least this much like a header to be accepted at all. The score is
	 * printable title characters (0-21) plus {@link #CHECKSUM_BONUS} when the checksum pair
	 * validates, so this threshold accepts any candidate whose checksum is right, and otherwise
	 * demands a mostly-printable title. It exists so that a file which is not a SNES ROM is
	 * REFUSED rather than silently mapped from garbage -- see the class doc on why guessing here
	 * would poison every later step.
	 */
	private static final int MIN_SCORE = 12;

	private static final int CHECKSUM_BONUS = 40;

	/** The ten CPU vectors, by name and offset from the vector table's base at {@code +0x20}. */
	private static final Map<String, Integer> VECTOR_SLOTS = Map.of(
		"VEC_COP_NATIVE", 0x04, "VEC_BRK_NATIVE", 0x06, "VEC_ABORT_NATIVE", 0x08,
		"VEC_NMI_NATIVE", 0x0A, "VEC_IRQ_NATIVE", 0x0E, "VEC_COP_EMULATION", 0x14,
		"VEC_ABORT_EMULATION", 0x18, "VEC_NMI_EMULATION", 0x1A, "VEC_RESET_EMULATION", 0x1C,
		"VEC_IRQ_EMULATION", 0x1E);

	/** Where the cartridge image starts in the file: past the copier header, if any. */
	public long dataOffset() {
		return copierHeader ? COPIER_HEADER_LEN : 0;
	}

	/**
	 * Whether the declared mapping agrees with where the header was actually found. A LoROM
	 * header belongs at {@code $7FC0} and a HiROM one at {@code $FFC0}; a mismatch means either
	 * an unusual cartridge or a mis-detection, and the loader should say so rather than proceed
	 * on one of the two contradictory facts.
	 */
	public boolean mapTypeMatchesLocation() {
		return switch (mapType) {
			case LOROM -> headerOffset == 0x7FC0;
			case HIROM -> headerOffset == 0xFFC0;
			case EXHIROM -> headerOffset == 0x40FFC0;
			case UNKNOWN -> false;
		};
	}

	/** The reset vector -- always an emulation-mode vector, since a 65816 resets into it. */
	public int resetVector() {
		return vectors.getOrDefault("VEC_RESET_EMULATION", 0);
	}

	public static SnesRomHeader parse(ByteProvider provider) throws IOException {
		long length = provider.length();
		if (length <= 0 || length > Integer.MAX_VALUE) {
			return null;
		}
		return parse(provider.readBytes(0, length));
	}

	/**
	 * Locates and parses the header, or returns {@code null} when {@code file} does not look like
	 * a SNES cartridge. Returning null rather than throwing matches this project's other loaders
	 * ({@code NesRomLoader}'s {@code InesHeader.parse}), whose callers treat "not my format" as
	 * ordinary.
	 */
	public static SnesRomHeader parse(byte[] file) {
		boolean copier = (file.length % 0x400) == COPIER_HEADER_LEN;
		int base = copier ? COPIER_HEADER_LEN : 0;

		int bestOffset = -1;
		int bestScore = Integer.MIN_VALUE;
		for (int offset : CANDIDATE_OFFSETS) {
			int score = score(file, base + offset);
			if (score > bestScore) {
				bestScore = score;
				bestOffset = offset;
			}
		}
		if (bestOffset < 0 || bestScore < MIN_SCORE) {
			return null;
		}
		return at(file, base, bestOffset, copier);
	}

	/** Scores one candidate; a candidate that does not fit inside the image scores below every
	 *  real one so it can never win. */
	private static int score(byte[] file, int at) {
		if (at < 0 || at + HEADER_LEN > file.length) {
			return Integer.MIN_VALUE;
		}
		int printable = 0;
		for (int i = 0; i < TITLE_LEN; i++) {
			int c = file[at + i] & 0xFF;
			if (c >= 0x20 && c < 0x7F) {
				printable++;
			}
		}
		return printable + (checksumValid(file, at) ? CHECKSUM_BONUS : 0);
	}

	private static boolean checksumValid(byte[] file, int at) {
		return (read16(file, at + 0x1C) ^ read16(file, at + 0x1E)) == 0xFFFF;
	}

	private static SnesRomHeader at(byte[] file, int base, int offset, boolean copier) {
		int at = base + offset;
		StringBuilder title = new StringBuilder(TITLE_LEN);
		for (int i = 0; i < TITLE_LEN; i++) {
			int c = file[at + i] & 0xFF;
			title.append(c >= 0x20 && c < 0x7F ? (char) c : ' ');
		}
		int mapMode = file[at + 0x15] & 0xFF;
		int chipset = file[at + 0x16] & 0xFF;

		Map<String, Integer> vectors = new LinkedHashMap<>();
		for (Map.Entry<String, Integer> slot : VECTOR_SLOTS.entrySet()) {
			int vectorAt = at + 0x20 + slot.getValue();
			vectors.put(slot.getKey(),
				vectorAt + 1 < file.length ? read16(file, vectorAt) : 0);
		}

		return new SnesRomHeader(offset, copier, title.toString().trim(), mapMode, chipset,
			sizeBytes(file[at + 0x17] & 0xFF), sizeBytes(file[at + 0x18] & 0xFF),
			read16(file, at + 0x1E), read16(file, at + 0x1C), checksumValid(file, at),
			mapTypeOf(mapMode), (mapMode & 0x10) != 0, Map.copyOf(vectors));
	}

	/**
	 * The size bytes are a log2 of kilobytes, so {@code 0x0A} means 1 MB. A zero means "not
	 * stated" (common for RAM on cartridges without any), and absurd exponents are clamped to
	 * zero rather than shifted into nonsense -- a corrupt byte should not produce a petabyte.
	 */
	private static long sizeBytes(int exponent) {
		return exponent == 0 || exponent > 0x1F ? 0 : 1024L << exponent;
	}

	/**
	 * Map type from the low nibble. {@code 0x2} (LoROM + S-DD1) and {@code 0x3} (SA-1) are
	 * LoROM-shaped for layout purposes and are reported as such; the coprocessor they imply is
	 * the {@link #chipset} byte's business, and enhancement-chip banking is out of scope until
	 * someone builds it (grm-9nxj.6 section 4).
	 */
	private static MapType mapTypeOf(int mapMode) {
		return switch (mapMode & 0x0F) {
			case 0x0, 0x2, 0x3 -> MapType.LOROM;
			case 0x1 -> MapType.HIROM;
			case 0x5 -> MapType.EXHIROM;
			default -> MapType.UNKNOWN;
		};
	}

	private static int read16(byte[] file, int at) {
		if (at < 0 || at + 1 >= file.length) {
			return 0;
		}
		return (file[at] & 0xFF) | ((file[at + 1] & 0xFF) << 8);
	}
}
