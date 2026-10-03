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

/**
 * How a SNES cartridge image is ARRANGED in its file (bead grm-9nxj.19): the single mapping from
 * a LOGICAL cartridge offset -- the offset the cartridge's own wiring uses, and the one every
 * header offset, {@link SnesAddressMap} and block address is expressed in -- to the byte of the
 * file that holds it. The header search and the block builder both go through
 * {@link #fileOffsetOf}, so they cannot disagree about where a byte is.
 *
 * <p>Three independent facts describe an arrangement:
 * <ul>
 * <li><b>{@code dataOffset}</b> -- the 512-byte copier header, if any. Still a pure function of
 *     file length (see {@link SnesRomHeader}'s grm-9nxj.16 paragraph).</li>
 * <li><b>{@code interleaved}</b> -- the two 32 KiB halves of every complete 64 KiB unit are
 *     swapped. (A trailing partial unit is left alone.)</li>
 * <li><b>{@code chunkSwapped}</b> -- for an image over 4 MiB, the ExHiROM chunks are stored
 *     small-chunk-first: the 4 MiB first chunk is at the END of the file and the remainder
 *     (the second chunk) at the front. Only expressible when the remainder is a whole number of
 *     64 KiB units; see {@link #chunkSwapPossible}.</li>
 * </ul>
 * The two transforms commute under that alignment, so their order in {@link #physicalOf} is
 * immaterial.
 *
 * @param dataOffset file offset where the cartridge image starts (0 or 0x200)
 * @param cartBytes the number of cartridge-image bytes in the file
 * @param interleaved whether the 32 KiB halves of each 64 KiB unit are swapped
 * @param chunkSwapped whether an over-4 MiB image stores its small chunk first
 */
public record SnesImageLayout(long dataOffset, long cartBytes, boolean interleaved,
		boolean chunkSwapped) {

	/** The "ROM layout" loader option / entry-point policy. */
	public enum Mode {
		/** De-interleave / re-order chunks only on a strong, verified signal. The default. */
		AUTO("Auto"),
		/** Never transform: the canonical layout, exactly as before grm-9nxj.19. */
		OFF("Off"),
		/** De-interleave unconditionally; chunk order still chosen by header position. */
		FORCE("Force");

		private final String label;

		Mode(String label) {
			this.label = label;
		}

		/** Returns the option-value spelling. */
		public String label() {
			return label;
		}

		/**
		 * Parses an option value case-insensitively.
		 *
		 * @param text the option text
		 * @return the mode, or {@link #AUTO} for null/blank/unrecognised text
		 */
		public static Mode parse(String text) {
			if (text != null) {
				for (Mode m : values()) {
					if (m.label.equalsIgnoreCase(text.trim())) {
						return m;
					}
				}
			}
			return AUTO;
		}
	}

	static final long HALF = 0x8000L;
	static final long UNIT = 0x10000L;
	/** ExHiROM's first chunk is 4 MiB. */
	static final long CHUNK = 0x400000L;

	/**
	 * The canonical (untransformed) layout.
	 *
	 * @param dataOffset file offset of the cartridge image
	 * @param cartBytes cartridge-image size in bytes
	 * @return the identity layout
	 */
	public static SnesImageLayout canonical(long dataOffset, long cartBytes) {
		return new SnesImageLayout(dataOffset, cartBytes, false, false);
	}

	/**
	 * Whether a chunk reorder is expressible for an image of this size: it must exceed 4 MiB and
	 * the remainder must be a whole number of 64 KiB units.
	 *
	 * @param cartBytes cartridge-image size
	 * @return whether {@code chunkSwapped} may be set
	 */
	public static boolean chunkSwapPossible(long cartBytes) {
		return cartBytes > CHUNK && (cartBytes - CHUNK) % UNIT == 0;
	}

	/** Returns whether this layout applies no transform. */
	public boolean isCanonical() {
		return !interleaved && !chunkSwapped;
	}

	/**
	 * Logical cartridge offset to physical offset within the cartridge image (copier header not
	 * included).
	 *
	 * @param logical the logical cartridge offset
	 * @return where that byte is stored, relative to the start of the cartridge image
	 */
	public long physicalOf(long logical) {
		long p = logical;
		if (chunkSwapped) {
			p = p < CHUNK ? p + (cartBytes - CHUNK) : p - CHUNK;
		}
		if (interleaved && (p & ~(UNIT - 1)) + UNIT <= cartBytes) {
			p ^= HALF;
		}
		return p;
	}

	/**
	 * Logical cartridge offset to FILE offset.
	 *
	 * @param logical the logical cartridge offset
	 * @return the file offset of that byte
	 */
	public long fileOffsetOf(long logical) {
		return dataOffset + physicalOf(logical);
	}

	/**
	 * How many bytes starting at {@code logical} are stored contiguously in the file. A block can
	 * be cut from the file as one {@code FileBytes} range exactly when it stays within this run.
	 *
	 * @param logical the starting logical offset
	 * @return the length of the physically contiguous run, at least 1 while in range
	 */
	public long contiguousRun(long logical) {
		long end = cartBytes;
		if (chunkSwapped && logical < CHUNK) {
			end = CHUNK;
		}
		if (interleaved) {
			end = Math.min(end, (logical | (HALF - 1)) + 1);
		}
		return end - logical;
	}

	/** A short human description for the import log. */
	public String describe() {
		if (isCanonical()) {
			return "canonical";
		}
		StringBuilder sb = new StringBuilder();
		if (interleaved) {
			sb.append("interleaved (32 KiB halves swapped)");
		}
		if (chunkSwapped) {
			if (sb.length() > 0) {
				sb.append(" + ");
			}
			sb.append("small-chunk-first ExHiROM");
		}
		return sb.toString();
	}
}
