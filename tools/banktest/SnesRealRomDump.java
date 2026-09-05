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
// Read-only golden dump for the SNES rows of the OPTIONAL, hash-pinned real-ROM tier
// (tools/banktest/realrom-test.sh --snes), bead grm-9nxj.15.
//
// SEPARATE FROM RealRomDump.java ON PURPOSE, and separate from VerifyBankTest.java for a
// sharper reason. VerifyBankTest dispatches on FIXTURE NAME and an unrecognized name falls
// through to the C64 default, printing plausible nonsense instead of failing (see the
// `fixture-dispatch-two-sided` bd memory); its snestest branch is also written against the
// SYNTHETIC fixture's specifics -- reset target $008000, a single ROM_00_8000 block, two
// magic bytes at offset 0 -- none of which a real cartridge shares. RealRomDump, meanwhile,
// is entirely about the NES banking model: overlay spaces, cross-bank references,
// bank-switch comments. The SNES loader creates NO overlays at all (machines/snes.yaml ships
// `windows: []`, see docs/snes-memory-map-decision.md), so every one of those counters would
// read zero on every row forever. What a SNES cartridge import actually establishes is a
// STATIC LAYOUT: which canonical ROM blocks exist, which byte-mapped mirrors view them, work
// RAM and its low mirrors, the descriptor's IO typing, and the reset entry point.
//
// Emits a BOUNDED, NORMALIZED, COPYRIGHT-SAFE block between
//   === REALROM BEGIN ===  /  === REALROM END ===
// -- the SAME fence realrom-test.sh carves for the NES rows, so the carve logic is shared.
//
// NO ROM BYTES ARE EVER EMITTED. The mirror check reports a BOOLEAN ("do the first 16 bytes
// read through this byte-mapped block equal the bytes at its mapped source?") rather than the
// bytes themselves, unlike the synthetic snestest golden which prints `bytesThroughMirror=18 fb`.
// The cartridge title and the CPU vector values are derived header metadata, already carried
// in the manifest or trivially re-derivable, and are not cartridge content.
//
// DETERMINISM IS THE WHOLE GAME. Every list is sorted before printing, no timestamp and no
// absolute path is emitted, and the vector table is sorted BY NAME rather than printed in
// SnesRomHeader's iteration order -- that map is built from a `Map.of`, whose iteration order
// is randomized per JVM run, so printing it as-iterated would produce a golden that fails
// against itself. Long lists carry RealRomDump's truncation marker so one 8 MB cartridge
// cannot produce a ten-thousand-line golden.
//
// These rows are imported with -noanalysis (see realrom-test.sh): nothing here depends on
// auto-analysis, and skipping it is both much faster on a 4-6 MB cartridge and immune to the
// analyzer jitter that makes two NES rows unstable.
//@category RetroMachines.Test

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import retromachines.SnesRomHeader;

public class SnesRealRomDump extends GhidraScript {

	// A 6 MB ExHiROM cartridge produces ~230 blocks and a 4 MB LoROM ~260, so this clears
	// every row in the current sample with headroom while still bounding an 8 MB import.
	// The layout IS the subject of this tier, so unlike RealRomDump's refs sample there is
	// no category here worth capping tightly.
	private static final int SAMPLE_BLOCKS = 600;

	// The descriptor's IO register names dominate this list and are identical on every row;
	// the one row-specific symbol (RESET) is emitted separately by the ENTRY line, so a small
	// sample plus an exact count is all the signal there is here.
	private static final int SAMPLE_SYMBOLS = 25;

	// Program-info property SnesRomLoader stamps with the descriptor path
	// (DescriptorSupport.MAP_PATH_PROPERTY -- kept as a literal, as RealRomDump does, so the
	// line does not depend on an extension constant that may be refactored).
	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	@Override
	protected void run() throws Exception {
		println("=== REALROM BEGIN ===");
		println("REALROM program " + currentProgram.getName());

		String sha = currentProgram.getExecutableSHA256();
		println("REALROM sha256 " + (sha == null ? "NONE" : sha));

		String mapPath = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(MAP_PATH_PROPERTY, null);
		println("REALROM format " + currentProgram.getExecutableFormat());
		println("REALROM language " + currentProgram.getLanguageID().getIdAsString());
		println("REALROM map " + (mapPath == null ? "NONE" : mapPath));

		emitHeader();
		emitBlocks();
		emitSymbolsAndEntry();

		println("=== REALROM END ===");
	}

	// ------------------------------------------------------------------
	// Cartridge header
	// ------------------------------------------------------------------

	/**
	 * Re-reads the imported file and parses it with the SHIPPED {@link SnesRomHeader}, rather
	 * than re-implementing the header search here. That is deliberate: a second copy of the
	 * scoring heuristic could drift from the loader's, and then a golden would pin the COPY's
	 * opinion while the loader acted on a different one -- the failure that looks like success.
	 * The cost is that this script needs the extension on its script classpath, which it has
	 * (VerifyBankTest.java imports retromachines classes the same way).
	 */
	private void emitHeader() {
		SnesRomHeader header;
		try {
			header = SnesRomHeader.parse(Files.readAllBytes(imagePath()));
		}
		catch (IOException e) {
			// Never expected: the file realrom-test.sh just imported is a copy it made in the
			// work dir. Report rather than throw, so the rest of the block still lands and the
			// diff says what went wrong instead of the row failing with an empty dump.
			println("REALROM header UNREADABLE " + e.getMessage());
			return;
		}
		if (header == null) {
			println("REALROM header NONE (no plausible SNES cartridge header)");
			return;
		}

		println("REALROM header maptype=" + header.mapType() +
			" offset=" + hex24(header.headerOffset()) +
			" copier=" + header.copierHeader() +
			" matchesLocation=" + header.mapTypeMatchesLocation());
		println("REALROM header mapmode=" + hex8(header.mapMode()) +
			" chipset=" + hex8(header.chipset()) +
			" fastrom=" + header.fastRom());
		println("REALROM header romsize=" + kib(header.romSizeBytes()) +
			" ramsize=" + kib(header.ramSizeBytes()) +
			" checksumValid=" + header.checksumValid());
		println("REALROM header title [" + header.title() + "]");

		// SORTED BY NAME, not as iterated. SnesRomHeader builds this from a `Map.of`, whose
		// iteration order is salted per JVM run -- printing it as-iterated would give a golden
		// that fails against itself on the next run.
		Map<String, Integer> vectors = new TreeMap<>(header.vectors());
		for (Map.Entry<String, Integer> e : vectors.entrySet()) {
			println("REALROM vector " + e.getKey() + " " + hex16(e.getValue()));
		}
	}

	/**
	 * The imported file as a readable {@link Path}. {@code getExecutablePath()} may be a Windows
	 * path with mixed separators (which {@code Path.of} handles) and Ghidra sometimes records it
	 * in a URL-ish {@code /C:/dir/file} form (which needs the leading slash trimmed), so both
	 * spellings are tried. Same helper as VerifyBankTest's {@code resolveImagePath}.
	 * <p>
	 * The path itself is NEVER printed: it is per-machine, and a golden containing one would
	 * fail everywhere else.
	 */
	private Path imagePath() throws IOException {
		String executablePath = currentProgram.getExecutablePath();
		if (executablePath == null || executablePath.isBlank()) {
			throw new IOException("program records no executable path");
		}
		List<String> candidates = new ArrayList<>();
		candidates.add(executablePath);
		if (executablePath.matches("^/[A-Za-z]:.*")) {
			candidates.add(executablePath.substring(1));
		}
		for (String candidate : candidates) {
			try {
				Path p = Path.of(candidate);
				if (Files.isReadable(p)) {
					return p;
				}
			}
			catch (InvalidPathException e) {
				// not spellable as a path on this platform; try the next candidate
			}
		}
		throw new IOException("no readable file at the recorded executable path");
	}

	// ------------------------------------------------------------------
	// Block layout
	// ------------------------------------------------------------------

	private void emitBlocks() {
		List<String> lines = new ArrayList<>();
		int total = 0;
		int overlay = 0;
		int byteMapped = 0;
		int initialized = 0;
		int volatiles = 0;
		int mirrorBad = 0;

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			total++;
			if (block.isOverlay()) {
				overlay++;
			}
			if (block.isInitialized()) {
				initialized++;
			}
			if (block.isVolatile()) {
				volatiles++;
			}

			StringBuilder line = new StringBuilder();
			line.append(block.getName())
					.append(' ').append(fmt(block.getStart()))
					.append('-').append(fmt(block.getEnd()))
					.append(" type=").append(typeName(block.getType()))
					.append(" init=").append(block.isInitialized())
					.append(" overlay=").append(block.isOverlay())
					.append(" perm=").append(block.isRead() ? "r" : "-")
					.append(block.isWrite() ? "w" : "-")
					.append(block.isExecute() ? "x" : "-")
					.append(" vol=").append(block.isVolatile());

			if (block.getType() == MemoryBlockType.BYTE_MAPPED) {
				byteMapped++;
				AddressRange mapped = mappedRange(block);
				if (mapped == null) {
					line.append(" mapped=UNKNOWN mirrorOk=unknown");
					mirrorBad++;
				}
				else {
					// The low-RAM mirrors view UNINITIALIZED work RAM, which owns no bytes to
					// compare -- reporting that as a mismatch would put a permanent 2 on the
					// mirrorMismatch counter and destroy its only job, which is to be zero.
					// So: check only mirrors whose source has bytes, and say n/a for the rest.
					String ok = "n/a";
					MemoryBlock src = currentProgram.getMemory()
							.getBlock(mapped.getMinAddress());
					if (src != null && src.isInitialized()) {
						ok = mirrorAgrees(block.getStart(), mapped.getMinAddress());
						if (!"true".equals(ok)) {
							mirrorBad++;
						}
					}
					line.append(" mapped=").append(fmt(mapped.getMinAddress()))
							.append('-').append(fmt(mapped.getMaxAddress()))
							.append(" mirrorOk=").append(ok);
				}
			}
			lines.add(line.toString());
		}

		int spacesOverlay = 0;
		for (AddressSpace space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
			if (space.isOverlaySpace()) {
				spacesOverlay++;
			}
		}

		Collections.sort(lines);
		emitSample("block", lines, SAMPLE_BLOCKS);

		println("REALROM count blocks.total " + total);
		println("REALROM count blocks.overlay " + overlay);
		println("REALROM count blocks.byteMapped " + byteMapped);
		println("REALROM count blocks.initialized " + initialized);
		println("REALROM count blocks.volatile " + volatiles);
		// A non-zero value here is the single loudest thing this dump can say: every mirror
		// this loader creates is supposed to read back as its source, so a mismatch means the
		// byte-mapped view is pointed somewhere wrong -- exactly what a copier-offset
		// regression looks like from the inside.
		println("REALROM count blocks.mirrorMismatch " + mirrorBad);
		println("REALROM count spaces.overlay " + spacesOverlay);
	}

	/** The range a byte-mapped block views, or null when the block reports none. */
	private AddressRange mappedRange(MemoryBlock block) {
		for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
			AddressRange range = info.getMappedRange().orElse(null);
			if (range != null) {
				return range;
			}
		}
		return null;
	}

	/**
	 * Whether reading through a byte-mapped block yields its source's bytes. Compares a short
	 * prefix (16 bytes, or less for a tiny block) and reports a BOOLEAN -- the bytes themselves
	 * are cartridge content and are never emitted.
	 */
	private String mirrorAgrees(Address mirror, Address source) {
		int n = 16;
		byte[] a = new byte[n];
		byte[] b = new byte[n];
		try {
			int got = currentProgram.getMemory().getBytes(mirror, a);
			int want = currentProgram.getMemory().getBytes(source, b);
			if (got != n || want != n) {
				return "short";
			}
		}
		catch (Exception e) {
			return "unreadable";
		}
		for (int i = 0; i < n; i++) {
			if (a[i] != b[i]) {
				return "false";
			}
		}
		return "true";
	}

	private static String typeName(MemoryBlockType type) {
		// MemoryBlockType.toString() is "Byte Mapped" -- a space in a field would make the
		// line awkward to split, so normalize to a single token.
		return type.toString().replace(' ', '_');
	}

	// ------------------------------------------------------------------
	// Symbols and the reset entry point
	// ------------------------------------------------------------------

	private void emitSymbolsAndEntry() {
		// IMPORTED/USER_DEFINED only, same filter and same reasoning as RealRomDump (bead
		// grm-mej.4): an ANALYSIS-sourced name tracks disassembly rather than intent. On these
		// rows the filter is nearly moot anyway -- they import with -noanalysis -- but keeping
		// it means the line does not change meaning if that ever stops being true.
		List<String> symbols = new ArrayList<>();
		long symbolCount = 0;
		for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(false)) {
			SourceType src = sym.getSource();
			if (src == SourceType.IMPORTED || src == SourceType.USER_DEFINED) {
				symbolCount++;
				symbols.add(fmt(sym.getAddress()) + " " + sym.getName() + " " + src);
			}
		}
		Collections.sort(symbols);

		List<String> entries = new ArrayList<>();
		for (Address entry : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
			entries.add(fmt(entry));
		}
		Collections.sort(entries);

		println("REALROM count symbols " + symbolCount);
		println("REALROM count entryPoints " + entries.size());
		for (String entry : entries) {
			println("REALROM entry " + entry);
		}
		emitSample("sample.symbol", symbols, SAMPLE_SYMBOLS);
	}

	// ------------------------------------------------------------------
	// Formatting helpers
	// ------------------------------------------------------------------

	/**
	 * RealRomDump's truncation idiom (bead grm-3pnz): print a prefix of a SORTED list, and when
	 * the cap actually bites SAY SO IN THE GOLDEN, so "absent from the sample" can never be
	 * mistaken for "absent from the program".
	 */
	private void emitSample(String tag, List<String> lines, int cap) {
		int n = Math.min(cap, lines.size());
		for (int i = 0; i < n; i++) {
			println("REALROM " + tag + " " + lines.get(i));
		}
		if (n < lines.size()) {
			println("REALROM " + tag + ".truncated " + n + " of " + lines.size());
		}
	}

	/** 65816 addresses are 24-bit; every offset fits in 6 hex digits. */
	private String fmt(Address addr) {
		return String.format("%06x", addr.getOffset());
	}

	private static String hex8(int v) {
		return String.format("0x%02x", v & 0xFF);
	}

	private static String hex16(int v) {
		return String.format("0x%04x", v & 0xFFFF);
	}

	private static String hex24(int v) {
		return String.format("0x%06x", v & 0xFFFFFF);
	}

	/** Sizes as KiB, so a golden reads in cartridge units rather than raw byte counts. */
	private static String kib(long bytes) {
		return (bytes / 1024) + "K";
	}
}
