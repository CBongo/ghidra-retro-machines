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

import retromachines.SnesRomHeader.MapType;

/**
 * Where a 24-bit SNES address comes from (bead grm-9nxj.9, second increment): cartridge ROM at
 * some file offset, work RAM, an IO register block, or nothing modelled.
 *
 * <p>This is the arithmetic every later step needs -- block layout, entry points, and the
 * mirror policy `grm-9nxj.6` ruled on -- kept as pure logic so it can be tested without a
 * {@code Program}. It answers two questions: what KIND of thing lives at an address, and for
 * ROM, WHICH FILE BYTE is visible there.
 *
 * <p><b>The two mappings.</b> The 65816 addresses 16 MB while cartridges top out at 8 MB, so
 * nothing here is a bank-switching window -- it is a fixed wiring, and the two common wirings
 * differ in one pin:
 * <ul>
 * <li><b>LoROM</b> maps 32 KiB chunks into the upper half of every bank: {@code $8000-$FFFF} of
 *     bank {@code b} shows file offset {@code b * 0x8000 + (addr - 0x8000)}. The cartridge's
 *     A15 is not connected, which is why the lower half of each bank is not ROM.</li>
 * <li><b>HiROM</b> maps the ROM linearly into banks {@code $C0-$FF}: bank {@code b} at
 *     {@code addr} shows file offset {@code (b - 0xC0) * 0x10000 + addr}. Banks
 *     {@code $00-$3F} additionally show the UPPER HALF of the corresponding HiROM bank at
 *     {@code $8000-$FFFF} -- the same bytes, not a second copy.</li>
 * </ul>
 * ExHiROM extends HiROM with a second 4 MiB reachable through banks {@code $40-$7D}; it is
 * modelled here only as far as {@link MapType#EXHIROM} being accepted with HiROM arithmetic for
 * its first 4 MiB, and {@link #isModelled} reports false beyond that rather than returning a
 * confident wrong offset.
 *
 * <p><b>Mirroring.</b> Banks {@code $80-$FF} mirror {@code $00-$7F} (the FastROM half), and the
 * first 8 KiB of work RAM is mirrored into {@code $0000-$1FFF} of the system banks. Mirrors are
 * reported as such by {@link #canonicalAddressOf}, which is what lets a loader materialize one
 * copy and byte-map the other, per grm-9nxj.6.
 *
 * <p><b>Not modelled, deliberately: SRAM.</b> The header states a RAM SIZE but not a location,
 * and the placement genuinely varies per cartridge -- SNESdev's own memory map says LoROM SRAM
 * is "often at $F0-FF" with "many variations" and does not state a HiROM location at all.
 * Guessing an address here would put a block where a game's data really lives, so SRAM is left
 * to a later increment that can key it off something better than folklore.
 */
public final class SnesAddressMap {

	/** What lives at an address. */
	public enum Kind {
		ROM,
		/** Work RAM: the full 128 KiB at {@code $7E-$7F}, or its low mirror in a system bank. */
		WRAM,
		/** PPU/APU ({@code $2100-$21FF}) or CPU/DMA ({@code $4200-$43FF}) registers. */
		IO,
		/** Nothing this class models -- open bus, SRAM, or an expansion chip's window. */
		UNMODELLED
	}

	private static final long BANK = 0x10000L;
	private static final long WRAM_START = 0x7E0000L;
	private static final long WRAM_SIZE = 0x20000L;

	private final MapType mapType;
	private final long romSize;

	public SnesAddressMap(MapType mapType, long romSize) {
		this.mapType = mapType;
		this.romSize = romSize;
	}

	/** Convenience: the map a parsed header describes, sized by the FILE rather than by the
	 *  header's declared size, since a declared size can disagree with the image on disk. */
	public static SnesAddressMap of(SnesRomHeader header, long romBytesInFile) {
		return new SnesAddressMap(header.mapType(), romBytesInFile);
	}

	public MapType mapType() {
		return mapType;
	}

	/** Whether this class claims to model {@code address} at all. */
	public boolean isModelled(long address) {
		return kindOf(address) != Kind.UNMODELLED;
	}

	public Kind kindOf(long address) {
		long a = address & 0xFFFFFF;
		int bank = (int) ((a >> 16) & 0xFF);
		int offset = (int) (a & 0xFFFF);

		if (a >= WRAM_START && a < WRAM_START + WRAM_SIZE) {
			return Kind.WRAM;
		}
		if (isSystemBank(bank)) {
			if (offset < 0x2000) {
				return Kind.WRAM;             // the low mirror of $7E0000
			}
			if ((offset >= 0x2100 && offset <= 0x21FF) || (offset >= 0x4200 && offset <= 0x43FF)) {
				return Kind.IO;
			}
		}
		return romFileOffset(a) != null ? Kind.ROM : Kind.UNMODELLED;
	}

	/**
	 * The file offset of the ROM byte visible at {@code address}, or {@code null} when the
	 * address is not cartridge ROM (or lies past the end of this image). The offset is into the
	 * CARTRIDGE image, so a caller reading a file with a copier header must add
	 * {@link SnesRomHeader#dataOffset()}.
	 */
	public Long fileOffsetOf(long address) {
		return romFileOffset(address);
	}

	/**
	 * The canonical address for {@code address}: the one place a loader need materialize these
	 * bytes, with every other address showing them being a mirror of it.
	 *
	 * <p><b>Which address that is depends on the mapping, and a blanket "fold the high banks
	 * down" rule is wrong.</b> LoROM's home is the low banks, so {@code $80:8000} folds to
	 * {@code $00:8000}. HiROM's ROM home is the LINEAR view at {@code $C0-$FF} -- it is
	 * {@code $40-$7D} and the system banks' upper halves that are the mirrors there, so
	 * {@code $00:8000} canonicalizes UP to {@code $C0:8000}. Getting this backwards puts a
	 * HiROM loader's canonical blocks in the mirror and vice versa.
	 *
	 * <p>Non-ROM addresses (work RAM, IO) always canonicalize by folding the high banks down,
	 * since those really are a straight {@code $80-$FF} over {@code $00-$7F} mirror.
	 *
	 * <p>Note this says nothing about WHICH copy a loader should PREFER to materialize --
	 * grm-9nxj.6 measured that the header's FastROM bit does not predict which half a title
	 * executes in, and ruled that a loader option. This reports the hardware relationship only.
	 */
	public long canonicalAddressOf(long address) {
		long a = address & 0xFFFFFF;
		Long file = romFileOffset(a);
		if (file != null) {
			return romHomeAddress(file);
		}
		int bank = (int) ((a >> 16) & 0xFF);
		return bank >= 0x80 ? a - 0x800000L : a;
	}

	/** Where a ROM file offset lives in its mapping's canonical (home) view. */
	private long romHomeAddress(long fileOffset) {
		return switch (mapType) {
			case LOROM -> ((fileOffset / 0x8000) << 16) | (0x8000 + (fileOffset % 0x8000));
			case HIROM, EXHIROM -> 0xC00000L + fileOffset;
			default -> fileOffset;
		};
	}

	/** Whether {@code address} is in the high (FastROM) mirror rather than its canonical home. */
	public boolean isHighMirror(long address) {
		return ((address >> 16) & 0xFF) >= 0x80;
	}

	/** The banks carrying the system's RAM mirror and IO windows: $00-$3F and their $80-$BF
	 *  mirror. */
	private static boolean isSystemBank(int bank) {
		return bank <= 0x3F || (bank >= 0x80 && bank <= 0xBF);
	}

	/**
	 * The file offset visible at a RAW address -- every mirror handled here directly, rather
	 * than by folding first, because the fold itself is mapping-dependent (see
	 * {@link #canonicalAddressOf}).
	 */
	private Long romFileOffset(long address) {
		int bank = (int) ((address >> 16) & 0xFF);
		int offset = (int) (address & 0xFFFF);
		long fileOffset;

		switch (mapType) {
			case LOROM -> {
				// 32 KiB in the upper half of every bank; the lower half is not ROM (the
				// cartridge's A15 is unconnected). Banks $80-$FF mirror $00-$7F.
				if (offset < 0x8000) {
					return null;
				}
				int romBank = bank & 0x7F;
				if (romBank > 0x7D) {
					return null;
				}
				fileOffset = romBank * 0x8000L + (offset - 0x8000);
			}
			case HIROM, EXHIROM -> {
				if (bank >= 0xC0) {
					fileOffset = (bank - 0xC0) * BANK + offset;    // the linear home view
				}
				else if (bank >= 0x40 && bank <= 0x7D) {
					fileOffset = (bank - 0x40) * BANK + offset;    // slow mirror of $C0-$FD
				}
				else if ((bank <= 0x3F || (bank >= 0x80 && bank <= 0xBF)) && offset >= 0x8000) {
					// The system banks show the UPPER HALF of the corresponding HiROM bank.
					fileOffset = (bank & 0x3F) * BANK + offset;
				}
				else {
					return null;
				}
			}
			default -> {
				return null;
			}
		}
		return fileOffset < romSize ? fileOffset : null;
	}
}
