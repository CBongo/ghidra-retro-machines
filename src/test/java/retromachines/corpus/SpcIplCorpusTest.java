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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import org.junit.Test;

import retromachines.SpcIplFormat;
import retromachines.SpcIplScanner;
import retromachines.SpcIplScanner.Candidate;

/**
 * Static-tier check of {@link SpcIplScanner} against the project owner's game-music-extraction
 * working tree (bead grm-1.7.3). Opt-in via {@code GRM_SPC700_DIS_CORPUS}, which names the
 * {@code snes/} directory holding the per-title subdirectories (the same variable
 * {@code Spc700DisCorpusTest} uses); Assume-skips when unset.
 *
 * <p>The ROMs and the {@code .bin} extracts beside them are copyrighted and are read in place,
 * never copied. The {@code .bin} files are not an independent oracle for the <em>location</em>
 * of a stream (the owner's {@code dumpspc.pl} scripts carry the offsets), but they are for the
 * <em>content</em>: bytes the scanner extracts must equal what the scripts extracted.
 *
 * <p><b>Asserted ground truth</b> (from {@code dumpspc.pl}/{@code minidumpspc.pl}):
 * <ul>
 * <li>{@code fzero/fzero.smc} (copier header) carries a seven-block stream at file offset
 *     0x8200 (= stripped 0x8000), entry 0x0800, whose blocks equal the {@code fzspc-*.bin}
 *     files that exist and {@code fzerospc.bin} (a synthesized single-block container).
 * <li>{@code lem/lemmings.smc} (no copier header) carries a stream at 0x467D7 whose first block
 *     equals {@code lemspc.bin}'s block.
 * </ul>
 * <b>Reported, never asserted:</b> the top candidates for every title with a ROM, to
 * {@code build/spc-ipl-corpus/candidates.tsv} and stdout, so false positives are visible. Som
 * and ff3 keep the destination out of line, so no inline stream is EXPECTED for them.
 */
public class SpcIplCorpusTest {

	private static final String CORPUS_ENV = "GRM_SPC700_DIS_CORPUS";
	private static final String[] TITLES =
		{ "ct", "ff2", "ff3", "ff5", "fzero", "gradius3", "lem", "lufia", "mario", "sd3", "som" };

	@Test
	public void scanCorpus() throws Exception {
		String configured = System.getenv(CORPUS_ENV);
		assumeTrue(CORPUS_ENV + " is not set -- skipping the SPC700 IPL corpus scan (grm-1.7.3)",
			configured != null && !configured.isBlank());
		Path root = Path.of(configured);
		Path outDir = Path.of("build", "spc-ipl-corpus");
		Files.createDirectories(outDir);

		List<String> tsv = new ArrayList<>();
		tsv.add("title\trom\tcopier\trank\tfileOffset\tstrippedOffset\tblocks\tpayload\tentry\t" +
			"score\tdominantByteShare\tsuppressedTails\tblockList");
		for (String title : TITLES) {
			Path dir = root.resolve(title);
			Path rom = findRom(dir);
			if (rom == null) {
				tsv.add(title + "\t(no rom)");
				continue;
			}
			byte[] file = Files.readAllBytes(rom);
			List<Candidate> cands = SpcIplScanner.scan(file);
			if (cands.isEmpty()) {
				tsv.add(String.format("%s\t%s\t\t-\t\t\t0\t0\t\t0\t\t(none)", title,
					rom.getFileName()));
			}
			int rank = 0;
			for (Candidate c : cands) {
				rank++;
				StringBuilder bl = new StringBuilder();
				for (SpcIplFormat.Block b : c.stream().blocks()) {
					bl.append(b).append("; ");
				}
				tsv.add(String.format("%s\t%s\t%b\t%d\t0x%x\t0x%x\t%d\t%d\t0x%04x\t%d\t%.3f\t%s\t%s", title,
					rom.getFileName(), c.copierHeader(), rank, c.fileOffset(), c.strippedOffset(),
					c.stream().blocks().size(), c.stream().payloadBytes(), c.stream().entry(),
					c.score(), SpcIplScanner.dominantByteShare(c.stream()), c.suppressedTails().stream().map(t -> "0x" + Integer.toHexString(t)).toList(),
					bl.toString().trim()));
			}
		}
		Files.write(outDir.resolve("candidates.tsv"), tsv, StandardCharsets.UTF_8);
		// stdout: top 3 per title only
		int shown = 0;
		String last = "";
		for (String line : tsv) {
			String t = line.substring(0, line.indexOf('\t'));
			if (!t.equals(last)) {
				shown = 0;
				last = t;
			}
			if (shown++ < 4) { // header row counts for the first
				System.out.println(line);
			}
		}

		assertFzero(root.resolve("fzero"));
		assertFf2(root.resolve("ff2"));
		assertLemmings(root.resolve("lem"));
	}

	private static void assertFzero(Path dir) throws IOException {
		byte[] file = Files.readAllBytes(dir.resolve("fzero.smc"));
		Candidate c = candidateAt(SpcIplScanner.scan(file), 0x8000);
		assertNotNull("fzero: no candidate at stripped 0x8000", c);
		assertTrue(c.copierHeader());
		assertEquals(0x8200L, c.fileOffset());
		int[][] expected = { { 0x0270, 0x0500 }, { 0x01a6, 0x3cc0 }, { 0x33fa, 0x0800 },
			{ 0x288d, 0xa080 }, { 0x0001, 0x07fe }, { 0x0090, 0x3c00 }, { 0x6080, 0x4000 } };
		List<SpcIplFormat.Block> blocks = c.stream().blocks();
		assertEquals(expected.length, blocks.size());
		for (int i = 0; i < expected.length; i++) {
			assertEquals("block " + i + " len", expected[i][0], blocks.get(i).length());
			assertEquals("block " + i + " addr", expected[i][1], blocks.get(i).addr());
		}
		assertEquals(0x0800, c.stream().entry());

		// dumpspc.pl names files fzspc-<addr>-<n>.bin with n the 0-based block index.
		int[] withBin = { 0, 1, 2, 3, 4 };
		for (int i : withBin) {
			Path bin = dir.resolve(String.format("fzspc-%04x-%d.bin", expected[i][1], i));
			if (Files.isRegularFile(bin)) {
				assertArrayEquals("block " + i + " vs " + bin.getFileName(),
					Files.readAllBytes(bin), blocks.get(i).data());
			}
		}
		// minidumpspc.pl: stripped offset 0x841e, a single-block container with synthesized
		// terminator reusing the block address as entry.
		Path mini = dir.resolve("fzerospc.bin");
		if (Files.isRegularFile(mini)) {
			SpcIplFormat.Block b = blocks.get(2);
			assertEquals(0x841e + 4, b.sourceOffset());
			assertArrayEquals(container(b), Files.readAllBytes(mini));
		}
	}

	/**
	 * ff2/notes.txt lists the eight blocks of the upload whose table starts at ROM 04/8683
	 * (LoROM, copier header: stripped 0x20683, file 0x20883). The top-ranked candidate is a
	 * LONGER parse that begins two junk-or-earlier blocks before it and chains into it, so the
	 * true start is asserted via the scanner's reported suppressed tail, not as its own row.
	 */
	private static void assertFf2(Path dir) throws IOException {
		byte[] file = Files.readAllBytes(dir.resolve("ff2.smc"));
		List<Candidate> cands = SpcIplScanner.scan(file);
		Candidate owner = null;
		for (Candidate c : cands) {
			if (c.strippedOffset() == 0x20683 || c.suppressedTails().contains(0x20683)) {
				owner = c;
				break;
			}
		}
		assertNotNull("ff2: stripped 0x20683 neither a candidate nor a suppressed tail", owner);
		// Re-parse at the true start (the owner may be the longer chain).
		SpcIplFormat.Result r = SpcIplFormat.parse(Arrays.copyOfRange(file, 0x200, file.length),
			0x20683);
		assertTrue(r.ok());
		int[][] expected = { { 0x11A9, 0x0800 }, { 0x20, 0xFF00 }, { 0x20, 0x1E00 },
			{ 0x590, 0xCA70 }, { 0x400, 0xF900 }, { 0x40, 0x1D00 }, { 0x1770, 0xB300 },
			{ 0x200, 0xFD00 } };
		List<SpcIplFormat.Block> blocks = r.stream().blocks();
		assertEquals(expected.length, blocks.size());
		for (int i = 0; i < expected.length; i++) {
			assertEquals("ff2 block " + i + " len", expected[i][0], blocks.get(i).length());
			assertEquals("ff2 block " + i + " addr", expected[i][1], blocks.get(i).addr());
		}
		assertEquals(0x0800, r.stream().entry());
	}

	private static void assertLemmings(Path dir) throws IOException {
		byte[] file = Files.readAllBytes(dir.resolve("lemmings.smc"));
		Candidate c = candidateAt(SpcIplScanner.scan(file), 0x467D7);
		assertNotNull("lem: no candidate at 0x467d7", c);
		assertTrue(!c.copierHeader());
		Path bin = dir.resolve("lemspc.bin");
		if (Files.isRegularFile(bin)) {
			assertArrayEquals(container(c.stream().blocks().get(0)), Files.readAllBytes(bin));
		}
	}

	/** The single-block container the corpus scripts synthesize: block, then [0][addr]. */
	private static byte[] container(SpcIplFormat.Block b) throws IOException {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		le16(o, b.length());
		le16(o, b.addr());
		o.write(b.data());
		le16(o, 0);
		le16(o, b.addr());
		return o.toByteArray();
	}

	private static void le16(OutputStream o, int v) throws IOException {
		o.write(v & 0xff);
		o.write((v >> 8) & 0xff);
	}

	private static Candidate candidateAt(List<Candidate> cands, int stripped) {
		for (Candidate c : cands) {
			if (c.strippedOffset() == stripped) {
				return c;
			}
		}
		return null;
	}

	private static Path findRom(Path dir) throws IOException {
		if (!Files.isDirectory(dir)) {
			return null;
		}
		try (Stream<Path> s = Files.list(dir)) {
			return s.filter(Files::isRegularFile).filter(p -> {
				String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
				return n.endsWith(".smc") || n.endsWith(".fig") || n.endsWith(".sfc") ||
					n.endsWith(".swc") || n.endsWith(".rom");
			}).sorted().findFirst().orElse(null);
		}
	}
}
