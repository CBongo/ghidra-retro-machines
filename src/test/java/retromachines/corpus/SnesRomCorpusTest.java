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
package retromachines.corpus;

import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.junit.Test;

import retromachines.SnesRomHeader;

/**
 * Survey of {@link SnesRomHeader#parse(byte[])} over a large local SNES cartridge collection
 * (bead grm-9nxj.13). Opt-in via {@code GRM_SNES_ROM_DIR}.
 *
 * <p><b>Why this tier exists.</b> {@code SnesRomHeader}'s provenance is eleven ROMs hand-checked
 * during bead grm-9nxj.6 -- 6 LoROM / 5 HiROM, ten of the eleven copier-headered, no enhancement
 * chips. The reference corpus behind this class is ~84x larger and differently shaped in exactly
 * the ways the detection heuristic depends on: measured 2026-09-05 over 921 cartridge images,
 * 899 accepted (LoROM 729 / HiROM 163 / ExHiROM 2 / UNKNOWN 5) and 22 refused, 120 copier-headered
 * against 801 clean -- the copier ratio is <em>inverted</em> relative to the original eleven, and
 * copier detection is by file size alone and shifts every later offset. 890 of the 921 carry a
 * valid checksum/complement pair at the base that rule selects (two more carry one at the other
 * base -- see {@code checksumPairFound}); 13 accepted images disagree with
 * {@link SnesRomHeader#mapTypeMatchesLocation()}.
 *
 * <p><b>It is a report, not a gate, and it must never become a golden-count test.</b> The corpus
 * is user-supplied and differs per machine, so not one of the numbers above may be asserted. The
 * assertions below are the ones that hold for <em>any</em> corpus; everything else is written to
 * {@code build/snes-rom-corpus/} ({@code roms.tsv} per image, {@code summary.txt} for the
 * distribution) and printed, for a human to read. In particular
 * {@code mapTypeMatchesLocation() == false} and {@link SnesRomHeader.MapType#UNKNOWN} are
 * <em>report rows</em>: the 13 disagreements on the reference corpus are checksum-valid commercial
 * cartridges (5 of them UNKNOWN, and therefore refused by the loader today), and they are the
 * subject of bead grm-9nxj.14 -- a missing loader feature, not a defect to fail a build over. For
 * the same reason this class must never grow golden-file assertions over the corpus, the same
 * warning {@link Spc700DisCorpusTest} carries.
 *
 * <p><b>What is asserted</b>, all corpus-independent:
 * <ul>
 * <li><b>{@code parse} is total.</b> Every regular file in the directories is fed to it, not only
 *     the cartridge extensions -- save states, IPS patches, screenshots, cheat lists, zero-length
 *     files. The only requirement is that it return a header or {@code null}, never throw. This is
 *     the cheapest real fuzz coverage available and it costs nothing.
 * <li><b>Every image whose checksum/complement pair validates is accepted.</b> This is the
 *     load-bearing one: {@code CHECKSUM_BONUS} (40) over {@code MIN_SCORE} (12) is what makes it
 *     true by construction, so a reordering of the scoring breaks it. The test finds the pair
 *     itself, scanning the three candidate offsets from the copier base the file's size selects,
 *     rather than reading back {@code header.checksumValid()} -- which would be circular. The
 *     other base is scanned too, but only to <em>report</em> images carrying a copier header the
 *     size rule cannot see (two on the reference corpus); see {@code checksumPairFound}.
 * <li><b>Structural self-consistency</b> of any accepted header: the header offset is one of the
 *     three candidates; {@code dataOffset()} is 512 exactly when {@code size % 0x400 == 0x200} and
 *     0 otherwise; and the whole 32-byte header fits inside the file.
 * <li><b>Determinism</b>: parsing the same bytes twice yields an equal record.
 * </ul>
 *
 * <p><b>{@code GRM_SNES_ROM_DIR} holds one or more SPACE-SEPARATED directories, indexed at depth 1
 * only</b> -- the same convention {@code GRM_ROM_DIR} uses for the real-ROM tier, and with the same
 * caveat: because the value is split on whitespace with no escaping, a single directory whose own
 * name contains a space cannot be represented this way. Nothing here reads a subdirectory, so a
 * collection filed one-title-per-folder will look empty rather than wrong.
 *
 * <p><b>When {@code GRM_SNES_ROM_DIR} is unset (or names nothing that exists) this Assume-skips</b>,
 * following {@link Spc700DisCorpusTest} rather than the vector tiers, which fail loudly. The
 * difference is deliberate and follows what a green run is allowed to mean: a vector tier is a
 * correctness gate whose silent absence would flatter us, while this class asserts weak invariants
 * and exists to produce a report. There is no green here worth protecting. It is excluded from the
 * {@code test} task because the corpus cannot be shipped, and runs from the
 * {@code snesRomCorpusTest} Gradle task / the {@code snes-rom-corpus} chunk.
 */
public class SnesRomCorpusTest {

	private static final String CORPUS_ENV = "GRM_SNES_ROM_DIR";

	/** Cartridge image extensions, lowercased. Everything else in these directories is save
	 *  states, patches, cheat files and screenshots -- fuzzed, but not surveyed. */
	private static final Set<String> ROM_EXTENSIONS = Set.of("sfc", "smc", "fig", "swc");

	/**
	 * The candidate header offsets, restated here rather than read from {@code SnesRomHeader}:
	 * {@code CANDIDATE_OFFSETS} is package-private, and an independent restatement is what makes
	 * the "the offset is one of the three" assertion worth anything.
	 */
	private static final int[] CANDIDATE_OFFSETS = { 0x7FC0, 0xFFC0, 0x40FFC0 };

	private static final int HEADER_LEN = 0x20;
	private static final int COPIER_HEADER_LEN = 0x200;

	/** Guard against reading something enormous into memory whole; nothing in a SNES collection
	 *  is anywhere near this (the reference corpus tops out at 6 MB). Oversized files are noted
	 *  in the summary and skipped rather than silently ignored. */
	private static final long MAX_READ_BYTES = 64L * 1024 * 1024;

	@Test
	public void surveyRomCorpus() throws Exception {
		String configured = System.getenv(CORPUS_ENV);
		assumeTrue(CORPUS_ENV + " is not set -- skipping the SNES ROM corpus survey (grm-9nxj.13)",
			configured != null && !configured.isBlank());

		// Space-separated dirs, depth 1 only -- see the class doc.
		List<Path> dirs = new ArrayList<>();
		for (String part : configured.trim().split("\\s+")) {
			Path dir = Path.of(part);
			if (Files.isDirectory(dir)) {
				dirs.add(dir);
			}
		}
		assumeTrue(CORPUS_ENV + "=" + configured + " names no existing directory -- skipping",
			!dirs.isEmpty());

		List<Path> files = new ArrayList<>();
		for (Path dir : dirs) {
			try (Stream<Path> entries = Files.list(dir)) {
				entries.filter(Files::isRegularFile).forEach(files::add);
			}
		}
		files.sort(Comparator.comparing(p -> p.getFileName().toString().toLowerCase(Locale.ROOT)));
		assumeTrue("no regular files at depth 1 under " + dirs + " -- skipping", !files.isEmpty());

		Path outDir = Path.of("build", "snes-rom-corpus");
		Files.createDirectories(outDir);

		List<String> rows = new ArrayList<>();
		rows.add("file\tsize\tsha256\taccepted\tcopier\theaderOffset\tmapType\tmapMatchesLocation\t" +
			"mapMode\tchipset\tromSize\tchecksumValid\tfastRom\ttitle\treset");
		List<String> problems = new ArrayList<>();
		List<String> refused = new ArrayList<>();
		List<String> mismatched = new ArrayList<>();
		List<String> oversized = new ArrayList<>();
		List<String> hiddenCopier = new ArrayList<>();

		Map<String, Integer> byMapType = new TreeMap<>();
		Map<String, Integer> byChipset = new TreeMap<>();
		Map<String, Integer> bySize = new TreeMap<>();
		int scanned = 0;
		int images = 0;
		int nonImages = 0;
		int accepted = 0;
		int copiered = 0;
		int checksumOk = 0;

		for (Path file : files) {
			String name = file.getFileName().toString();
			boolean isImage = ROM_EXTENSIONS.contains(extensionOf(name));
			long size = Files.size(file);
			if (size > MAX_READ_BYTES) {
				oversized.add(name + "\t" + size);
				continue;
			}
			byte[] bytes = Files.readAllBytes(file);
			scanned++;

			SnesRomHeader header;
			try {
				// (a) parse is total: a header or null, never a throw, for ANY bytes.
				header = SnesRomHeader.parse(bytes);
			}
			catch (Throwable t) {
				problems.add("SnesRomHeader.parse threw on " + name + " (" + size + " bytes): " + t);
				continue;
			}
			if (!isImage) {
				nonImages++;
				continue;
			}
			images++;

			// (d) determinism -- same bytes in, equal record out.
			SnesRomHeader again = SnesRomHeader.parse(bytes);
			if (header == null ? again != null : !header.equals(again)) {
				problems.add("SnesRomHeader.parse is not deterministic on " + name);
			}

			// The base parse itself will look at, from the size rule -- see checksumPairFound.
			long detectedBase = (size % 0x400) == COPIER_HEADER_LEN ? COPIER_HEADER_LEN : 0;
			boolean pairFound = checksumPairFound(bytes, (int) detectedBase);
			boolean pairAtOtherBase =
				checksumPairFound(bytes, (int) (COPIER_HEADER_LEN - detectedBase));
			if (pairFound) {
				checksumOk++;
			}
			// (b) the load-bearing one: a validating checksum pair must always be accepted.
			if (pairFound && header == null) {
				problems.add(name + ": a checksum/complement pair validates at a candidate offset, " +
					"but parse REFUSED the image -- CHECKSUM_BONUS over MIN_SCORE is supposed to " +
					"make that impossible");
			}
			if (!pairFound && pairAtOtherBase) {
				hiddenCopier.add(name + "\t" + size + "\tsize%0x400=0x" +
					Long.toHexString(size % 0x400) + "\taccepted=" + (header != null));
			}

			if (header == null) {
				refused.add(name + "\t" + size + "\tchecksumPair=" + pairFound +
					"\tpairAtOtherBase=" + pairAtOtherBase);
				rows.add(String.join("\t", name, Long.toString(size), sha256(bytes), "no",
					"", "", "", "", "", "", "", Boolean.toString(pairFound), "", "", ""));
				continue;
			}
			accepted++;

			// (c) structural self-consistency of an accepted header.
			if (!isCandidateOffset(header.headerOffset())) {
				problems.add(name + ": headerOffset 0x" +
					Integer.toHexString(header.headerOffset()) + " is not a candidate offset");
			}
			long expectedData = (size % 0x400) == COPIER_HEADER_LEN ? COPIER_HEADER_LEN : 0;
			if (header.dataOffset() != expectedData) {
				problems.add(name + ": dataOffset " + header.dataOffset() + " but size " + size +
					" implies " + expectedData);
			}
			if (header.copierHeader() != (expectedData != 0)) {
				problems.add(name + ": copierHeader=" + header.copierHeader() + " but size " + size +
					" says otherwise");
			}
			if (header.headerOffset() + header.dataOffset() + HEADER_LEN > size) {
				problems.add(name + ": header at 0x" + Integer.toHexString(header.headerOffset()) +
					" + data offset " + header.dataOffset() + " does not fit in " + size + " bytes");
			}

			if (header.copierHeader()) {
				copiered++;
			}
			bump(byMapType, header.mapType().name());
			bump(byChipset, String.format("0x%02x", header.chipset()));
			bump(bySize, String.format("%8d", size));
			if (!header.mapTypeMatchesLocation()) {
				mismatched.add(name + "\t" + header.mapType() + "\t0x" +
					Integer.toHexString(header.headerOffset()) + "\tmapMode=0x" +
					Integer.toHexString(header.mapMode()) + "\tchecksumValid=" +
					header.checksumValid());
			}
			rows.add(String.join("\t", name, Long.toString(size), sha256(bytes), "yes",
				header.copierHeader() ? "yes" : "no",
				String.format("0x%06x", header.headerOffset()), header.mapType().name(),
				Boolean.toString(header.mapTypeMatchesLocation()),
				String.format("0x%02x", header.mapMode()),
				String.format("0x%02x", header.chipset()), Long.toString(header.romSizeBytes()),
				Boolean.toString(header.checksumValid()),
				Boolean.toString(header.fastRom()), header.title(),
				String.format("0x%04x", header.resetVector())));
		}

		List<String> summary = new ArrayList<>();
		summary.add("SNES ROM corpus survey (grm-9nxj.13)");
		summary.add("dirs: " + dirs);
		summary.add("files scanned (all extensions): " + scanned);
		summary.add("cartridge images: " + images + "  (non-images fuzzed: " + nonImages + ")");
		summary.add("accepted: " + accepted + "   refused: " + (images - accepted));
		summary.add("copier-headered: " + copiered + "   clean: " + (accepted - copiered) +
			"   (of accepted)");
		summary.add("checksum pair valid (at the size-detected base): " + checksumOk +
			"   invalid: " + (images - checksumOk));
		summary.add("checksum pair only at the OTHER copier base: " + hiddenCopier.size());
		summary.add("mapTypeMatchesLocation false: " + mismatched.size());
		summary.add("");
		summary.add("by map type:");
		byMapType.forEach((k, v) -> summary.add("  " + k + "\t" + v));
		summary.add("");
		summary.add("by chipset byte:");
		byChipset.forEach((k, v) -> summary.add("  " + k + "\t" + v));
		summary.add("");
		summary.add("by file size:");
		bySize.forEach((k, v) -> summary.add("  " + k + "\t" + v));
		summary.add("");
		summary.add("refused images (file, size, whether a checksum pair was found):");
		refused.forEach(r -> summary.add("  " + r));
		summary.add("");
		summary.add("checksum pair found only at the base the size rule did NOT pick -- a copier " +
			"header the size-alone test cannot see (report, not a failure):");
		hiddenCopier.forEach(h -> summary.add("  " + h));
		summary.add("");
		summary.add("mapTypeMatchesLocation == false (grm-9nxj.14 material, NOT failures):");
		mismatched.forEach(m -> summary.add("  " + m));
		if (!oversized.isEmpty()) {
			summary.add("");
			summary.add("skipped, larger than " + MAX_READ_BYTES + " bytes:");
			oversized.forEach(o -> summary.add("  " + o));
		}

		Files.write(outDir.resolve("roms.tsv"), rows, StandardCharsets.UTF_8);
		Files.write(outDir.resolve("summary.txt"), summary, StandardCharsets.UTF_8);
		summary.forEach(System.out::println);
		System.out.println();
		System.out.println("per-image detail: " + outDir.resolve("roms.tsv").toAbsolutePath());

		if (!problems.isEmpty()) {
			fail(problems.size() + " corpus invariant violation(s):\n" + String.join("\n", problems));
		}
	}

	/**
	 * Whether any candidate offset, measured from {@code base}, carries a checksum and complement
	 * that XOR to {@code $FFFF}. Deliberately computed from the raw bytes and not from
	 * {@code header.checksumValid()}: the assertion it feeds is "parse accepts every image with a
	 * valid pair", which is vacuous if the pair is whatever parse already decided it was.
	 *
	 * <p><b>Called at both copier bases, but the two answers mean different things.</b> The base the
	 * size rule picks ({@code size % 0x400 == 0x200}) is the one {@code parse} will look at, so a
	 * pair found there is what the acceptance assertion is entitled to demand. A pair found ONLY at
	 * the other base means the file carries a 512-byte copier header its size does not advertise,
	 * which the size rule cannot see and which this class therefore reports rather than fails over:
	 * it is a property of the dump, not a regression. The reference corpus has exactly two, both
	 * refused -- {@code NHL94USA.smc} (1049047 bytes: copier header present, image truncated 41
	 * bytes short of 1 MB) and {@code oml-megamanx.sfc} (1576960: copier header on a cartridge
	 * image that is itself not a whole number of 1 KB blocks, so the two remainders cancel). They
	 * get their own summary section so that a real copier-detection regression, which would move
	 * dozens of rows into it at once, is visible instead of silent.
	 */
	private static boolean checksumPairFound(byte[] file, int base) {
		for (int offset : CANDIDATE_OFFSETS) {
			int at = base + offset;
			if (at < 0 || at + HEADER_LEN > file.length) {
				continue;
			}
			if ((read16(file, at + 0x1C) ^ read16(file, at + 0x1E)) == 0xFFFF) {
				return true;
			}
		}
		return false;
	}

	private static int read16(byte[] file, int at) {
		return (file[at] & 0xFF) | ((file[at + 1] & 0xFF) << 8);
	}

	private static boolean isCandidateOffset(int offset) {
		for (int candidate : CANDIDATE_OFFSETS) {
			if (candidate == offset) {
				return true;
			}
		}
		return false;
	}

	private static String extensionOf(String name) {
		int dot = name.lastIndexOf('.');
		return dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
	}

	private static void bump(Map<String, Integer> counts, String key) {
		counts.merge(key, 1, Integer::sum);
	}

	/** Included per image because bead grm-9nxj.15 picks hash-pinned sample rows out of
	 *  {@code roms.tsv}; this file is that selection tool. */
	private static String sha256(byte[] bytes) throws IOException {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
			StringBuilder out = new StringBuilder(64);
			for (byte b : digest) {
				out.append(Character.forDigit((b >> 4) & 0xF, 16))
						.append(Character.forDigit(b & 0xF, 16));
			}
			return out.toString();
		}
		catch (java.security.NoSuchAlgorithmException e) {
			throw new IOException("SHA-256 unavailable", e);
		}
	}
}
