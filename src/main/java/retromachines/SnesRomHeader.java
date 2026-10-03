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

import retromachines.SnesImageLayout.Mode;

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
 * <p><b>Image layout (grm-9nxj.19).</b> Some dumps store the cartridge in a copier arrangement:
 * INTERLEAVED (the two 32 KiB halves of every 64 KiB unit swapped) and/or, for ExHiROM images over
 * 4 MiB, with the small second chunk stored BEFORE the 4 MiB first chunk. {@code tofphant.smc}, the
 * corpus's only real ExHiROM cartridge, is both. {@link SnesImageLayout} is the one logical-offset
 * to file-offset mapping; every offset in this class -- candidates, {@link #headerOffset()}, vector
 * addresses -- is LOGICAL, and the header search and the loader's block builder both go through
 * that mapping. {@link #parse(byte[], Mode)} chooses the layout (Off / Auto / Force; the rules are
 * on that method). The copier-header rule above is untouched and still a pure function of length.
 *
 * <p>Field layout, relative to the header's own base: title at {@code +0x00} (21 bytes), map mode
 * {@code +0x15}, chipset {@code +0x16}, ROM size {@code +0x17}, RAM size {@code +0x18}, checksum
 * complement {@code +0x1C}, checksum {@code +0x1E}. The CPU vector table follows at {@code +0x20}
 * (i.e. {@code $FFE0}), which is where {@link #vectors()} reads from.
	 *
	 * @param headerOffset logical cartridge offset of the selected internal header
	 * @param copierHeader whether the image has a 512-byte copier header
	 * @param title decoded cartridge title
	 * @param mapMode raw map-mode byte
	 * @param chipset raw chipset byte
	 * @param romSizeBytes ROM capacity declared by the header
	 * @param ramSizeBytes RAM capacity declared by the header
	 * @param checksum raw checksum word
	 * @param checksumComplement raw checksum-complement word
	 * @param checksumValid whether the checksum pair is internally consistent
	 * @param mapType decoded cartridge mapping type
	 * @param fastRom whether the map-mode byte requests fast ROM timing
	 * @param vectors decoded CPU-vector names and addresses
	 * @param layout how the image is arranged in the file (grm-9nxj.19); {@code headerOffset}
	 *     and every other offset here is a LOGICAL cartridge offset under it
 */
public record SnesRomHeader(int headerOffset, boolean copierHeader, String title, int mapMode,
		int chipset, long romSizeBytes, long ramSizeBytes, int checksum, int checksumComplement,
		boolean checksumValid, MapType mapType, boolean fastRom, Map<String, Integer> vectors,
		SnesImageLayout layout) {

	/** Cartridge mapping declared by the map-mode byte's low nibble. */
	public enum MapType {
		/** LoROM's 32-KiB-per-bank wiring. */
		LOROM,
		/** HiROM's 64-KiB-per-bank wiring. */
		HIROM,
		/** Extended HiROM wiring for images larger than 4 MiB. */
		EXHIROM,
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

	/**
	 * Returns where the cartridge image starts in the file: past the copier header, if any.
	 *
	 * @return the cartridge-data offset
	 */
	public long dataOffset() {
		return copierHeader ? COPIER_HEADER_LEN : 0;
	}

	/**
	 * Whether the declared mapping agrees with where the header was actually found. A LoROM
	 * header belongs at {@code $7FC0} and a HiROM one at {@code $FFC0}; a mismatch means either
	 * an unusual cartridge or a mis-detection, and the loader should say so rather than proceed
	 * on one of the two contradictory facts.
	 *
	 * @return whether the declared map type agrees with the selected header location
	 */
	public boolean mapTypeMatchesLocation() {
		return switch (mapType) {
			case LOROM -> headerOffset == 0x7FC0;
			case HIROM -> headerOffset == 0xFFC0;
			case EXHIROM -> headerOffset == 0x40FFC0;
			case UNKNOWN -> false;
		};
	}

	/**
	 * Returns the reset vector, always an emulation-mode vector since a 65816 resets into it.
	 *
	 * @return the reset-vector address, or zero when absent
	 */
	public int resetVector() {
		return vectors.getOrDefault("VEC_RESET_EMULATION", 0);
	}

	/**
	 * Reads and parses a candidate cartridge image in its CANONICAL layout (no de-interleave).
	 *
	 * @param provider the candidate image bytes
	 * @return the parsed header, or {@code null} when the input is not a plausible cartridge
	 * @throws IOException if the provider cannot supply its bytes
	 */
	public static SnesRomHeader parse(ByteProvider provider) throws IOException {
		return parse(provider, Mode.OFF);
	}

	/**
	 * Reads and parses a candidate cartridge image under a layout policy.
	 *
	 * @param provider the candidate image bytes
	 * @param mode the "ROM layout" policy
	 * @return the parsed header, or {@code null} when the input is not a plausible cartridge
	 * @throws IOException if the provider cannot supply its bytes
	 */
	public static SnesRomHeader parse(ByteProvider provider, Mode mode) throws IOException {
		long length = provider.length();
		if (length <= 0 || length > Integer.MAX_VALUE) {
			return null;
		}
		return parse(provider.readBytes(0, length), mode);
	}

	/**
	 * Locates and parses the header in the CANONICAL layout, or returns {@code null} when
	 * {@code file} does not look like a SNES cartridge. Returning null rather than throwing
	 * matches this project's other loaders ({@code NesRomLoader}'s {@code InesHeader.parse}),
	 * whose callers treat "not my format" as ordinary. Equivalent to
	 * {@code parse(file, Mode.OFF)}.
	 *
	 * @param file the complete candidate cartridge image
	 * @return the parsed header, or {@code null} when no candidate is plausible
	 */
	public static SnesRomHeader parse(byte[] file) {
		return parse(file, Mode.OFF);
	}

	/**
	 * Locates and parses the header under a layout policy (grm-9nxj.19).
	 *
	 * <ul>
	 * <li>{@link Mode#OFF}: canonical layout only.</li>
	 * <li>{@link Mode#FORCE}: de-interleave unconditionally; for an image over 4 MiB the chunk
	 *     order is still chosen by header position (below).</li>
	 * <li>{@link Mode#AUTO}: two independent, verified decisions.
	 *     <b>Interleave</b> -- only when the canonical parse found a header at {@code +0x7FC0}
	 *     (the LoROM position) whose map mode says HiROM/ExHiROM and is itself well-formed
	 *     (top three bits {@code 001}; the 921-image corpus has a LoROM-looking
	 *     {@code WWF Super WrestleMania} with map mode {@code $41} that would otherwise
	 *     be de-interleaved on a malformed byte), and the stored image has no checksum-valid
	 *     header of matching map type anywhere (so a well-formed cartridge is never second-guessed),
	 *     AND the de-interleaved parse
	 *     yields a checksum-valid header whose map type matches its location.
	 *     <b>Chunk order</b> -- only for an image over 4 MiB (remainder a whole number of 64 KiB
	 *     units), snes9x-style: swap exactly when the stored order has no checksum-valid
	 *     header at logical {@code 0x40FFC0} and the swapped order has one, there, whose map
	 *     type matches. Chunk order is deliberately NOT a fourth option value: it is a fact about
	 *     the file, decided by a signal strong enough (a valid pair at one specific offset) that
	 *     there is no case for a user to want it Off while interleave detection is On, and
	 *     {@code Off} already disables it. It is applied under Auto and Force.</li>
	 * </ul>
	 * The returned header's {@link #layout()} says what was chosen and every offset it reports
	 * is LOGICAL.
	 *
	 * @param file the complete candidate cartridge image
	 * @param mode the layout policy
	 * @return the parsed header, or {@code null} when no candidate is plausible
	 */
	public static SnesRomHeader parse(byte[] file, Mode mode) {
		boolean copier = (file.length % 0x400) == COPIER_HEADER_LEN;
		long data = copier ? COPIER_HEADER_LEN : 0;
		long cart = file.length - data;

		SnesRomHeader canonical = parseWith(file, SnesImageLayout.canonical(data, cart), copier);
		if (mode == Mode.OFF) {
			return canonical;
		}
		if (mode == Mode.FORCE) {
			boolean swap = chooseChunkSwap(file, data, cart, true);
			return parseWith(file, new SnesImageLayout(data, cart, true, swap), copier);
		}

		// AUTO.
		if (canonical != null && canonical.headerOffset == 0x7FC0 &&
			(canonical.mapType == MapType.HIROM || canonical.mapType == MapType.EXHIROM) &&
			(canonical.mapMode & 0xE0) == 0x20 &&
			!hasValidMatchingCandidate(file, SnesImageLayout.canonical(data, cart))) {
			boolean swap = chooseChunkSwap(file, data, cart, true);
			SnesRomHeader d =
				parseWith(file, new SnesImageLayout(data, cart, true, swap), copier);
			if (d != null && d.checksumValid && d.mapTypeMatchesLocation()) {
				return d;
			}
		}
		if (chooseChunkSwap(file, data, cart, false)) {
			SnesRomHeader d =
				parseWith(file, new SnesImageLayout(data, cart, false, true), copier);
			if (d != null && d.checksumValid && d.mapTypeMatchesLocation()) {
				return d;
			}
		}
		return canonical;
	}

	/**
	 * The chunk-order axis: for a >4 MiB image, whether the swapped order (and not the stored
	 * one) puts a checksum-valid header at logical {@code 0x40FFC0}. Checked at that single
	 * offset directly -- not via the best-scoring search -- because a canonical ExHiROM image
	 * usually carries a second copy at {@code 0xFFC0}, and the question is only where
	 * the CPU-visible one is.
	 */
	private static boolean chooseChunkSwap(byte[] file, long data, long cart, boolean interleaved) {
		if (!SnesImageLayout.chunkSwapPossible(cart)) {
			return false;
		}
		if (validPairAt(file, new SnesImageLayout(data, cart, interleaved, false), 0x40FFC0)) {
			return false;
		}
		return validPairAt(file, new SnesImageLayout(data, cart, interleaved, true), 0x40FFC0);
	}

	/**
	 * Whether the layout already carries a checksum-valid header, at ANY candidate offset, whose
	 * map type agrees with where it sits. Such an image is a well-formed cartridge as stored, so
	 * Auto must not second-guess it: Mario's Early Years has a stray "SNES Kernel" header with a
	 * valid pair and a HiROM map mode at $7FC0 that ties the real one at $FFC0. The location
	 * tie-break now picks the real one, but this guard is what keeps Auto independent of the
	 * tie-break: an image already valid as stored is never read as an interleave signal.
	 */
	private static boolean hasValidMatchingCandidate(byte[] file, SnesImageLayout lay) {
		for (int offset : CANDIDATE_OFFSETS) {
			if (validPairAt(file, lay, offset) && matchesLocation(file, lay, offset)) {
				return true;
			}
		}
		return false;
	}

	private static boolean validPairAt(byte[] file, SnesImageLayout lay, int logical) {
		return logical + HEADER_LEN <= lay.cartBytes() && checksumValid(file, lay, logical);
	}

	private static SnesRomHeader parseWith(byte[] file, SnesImageLayout lay, boolean copier) {
		int bestOffset = -1;
		int bestScore = Integer.MIN_VALUE;
		boolean bestMatches = false;
		for (int offset : CANDIDATE_OFFSETS) {
			int score = score(file, lay, offset);
			// Ties go to the candidate whose declared map type agrees with its location (a
			// canonical ExHiROM image carries a copy at $FFC0 AND $40FFC0, equal in every way
			// but this). Applied to every layout, canonical included, by owner ruling on
			// grm-9nxj.19: before it, the earlier candidate won outright, which picked Mario's
			// Early Years' checksum-valid "SNES Kernel" decoy at $7FC0 over its real HiROM
			// header at $FFC0.
			boolean matches = score != Integer.MIN_VALUE &&
				matchesLocation(file, lay, offset);
			if (score > bestScore || (score == bestScore && matches && !bestMatches)) {
				bestScore = score;
				bestOffset = offset;
				bestMatches = matches;
			}
		}
		if (bestOffset < 0 || bestScore < MIN_SCORE) {
			return null;
		}
		return at(file, lay, bestOffset, copier);
	}

	private static boolean matchesLocation(byte[] file, SnesImageLayout lay, int offset) {
		return switch (mapTypeOf(byteAt(file, lay, offset + 0x15))) {
			case LOROM -> offset == 0x7FC0;
			case HIROM -> offset == 0xFFC0;
			case EXHIROM -> offset == 0x40FFC0;
			case UNKNOWN -> false;
		};
	}

	/** The byte at a LOGICAL cartridge offset; the caller has bounds-checked it. */
	private static int byteAt(byte[] file, SnesImageLayout lay, long logical) {
		return file[(int) lay.fileOffsetOf(logical)] & 0xFF;
	}

	/** Scores one candidate; a candidate that does not fit inside the image scores below every
	 *  real one so it can never win. */
	private static int score(byte[] file, SnesImageLayout lay, int offset) {
		if (offset < 0 || offset + HEADER_LEN > lay.cartBytes()) {
			return Integer.MIN_VALUE;
		}
		int printable = 0;
		for (int i = 0; i < TITLE_LEN; i++) {
			int c = byteAt(file, lay, offset + i);
			if (c >= 0x20 && c < 0x7F) {
				printable++;
			}
		}
		return printable + (checksumValid(file, lay, offset) ? CHECKSUM_BONUS : 0);
	}

	private static boolean checksumValid(byte[] file, SnesImageLayout lay, int at) {
		return (read16(file, lay, at + 0x1C) ^ read16(file, lay, at + 0x1E)) == 0xFFFF;
	}

	private static SnesRomHeader at(byte[] file, SnesImageLayout lay, int offset, boolean copier) {
		StringBuilder title = new StringBuilder(TITLE_LEN);
		for (int i = 0; i < TITLE_LEN; i++) {
			int c = byteAt(file, lay, offset + i);
			title.append(c >= 0x20 && c < 0x7F ? (char) c : ' ');
		}
		int mapMode = byteAt(file, lay, offset + 0x15);
		int chipset = byteAt(file, lay, offset + 0x16);

		Map<String, Integer> vectors = new LinkedHashMap<>();
		for (Map.Entry<String, Integer> slot : VECTOR_SLOTS.entrySet()) {
			int vectorAt = offset + 0x20 + slot.getValue();
			vectors.put(slot.getKey(),
				vectorAt + 1 < lay.cartBytes() ? read16(file, lay, vectorAt) : 0);
		}

		return new SnesRomHeader(offset, copier, title.toString().trim(), mapMode, chipset,
			sizeBytes(byteAt(file, lay, offset + 0x17)),
			sizeBytes(byteAt(file, lay, offset + 0x18)), read16(file, lay, offset + 0x1E),
			read16(file, lay, offset + 0x1C), checksumValid(file, lay, offset),
			mapTypeOf(mapMode), (mapMode & 0x10) != 0, Map.copyOf(vectors), lay);
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

	private static int read16(byte[] file, SnesImageLayout lay, long at) {
		if (at < 0 || at + 1 >= lay.cartBytes()) {
			return 0;
		}
		return byteAt(file, lay, at) | (byteAt(file, lay, at + 1) << 8);
	}
}
