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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.Assume;
import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link D64Image} (bead grm-t3n.2) over d64 images built in the test.
 * Nothing here is derived from a real disk.
 */
public class D64ImageTest {

	// ------------------------------------------------------------------
	// Synthetic image builder
	// ------------------------------------------------------------------

	/** Builds a d64; files are laid out on tracks 1.. in order, skipping track 18. */
	static final class Builder {
		final int tracks;
		final byte[] img;
		final boolean errors;
		int nextTrack = 1;
		int nextSector = 0;
		int dirEntries = 0;

		Builder(int size) {
			img = new byte[size];
			tracks = (size == D64Image.SIZE_35 || size == D64Image.SIZE_35_ERRORS) ? 35 : 40;
			errors = size == D64Image.SIZE_35_ERRORS || size == D64Image.SIZE_40_ERRORS;
			if (errors) {
				int sectors = D64Image.sectorsPerTrack(1) * 17 + 7 * 19 + 6 * 18 +
					(tracks - 30) * 17;
				for (int i = 0; i < sectors; i++) {
					img[size - sectors + i] = 1;
				}
			}
			int bam = off(18, 0);
			img[bam] = 18;
			img[bam + 1] = 1;
			img[bam + 2] = 0x41;
			img[off(18, 1) + 1] = (byte) 0xff;
		}

		static int off(int track, int sector) {
			return D64Image.sectorIndexForTest(track, sector) * 256;
		}

		int[] alloc() {
			if (nextTrack == 18) {
				nextTrack++;
				nextSector = 0;
			}
			int[] ts = { nextTrack, nextSector };
			if (++nextSector >= D64Image.sectorsPerTrack(nextTrack)) {
				nextTrack++;
				nextSector = 0;
			}
			return ts;
		}

		/** Writes data as a sector chain; returns {track, sector} of the first sector. */
		int[] writeChain(byte[] data) {
			int[] first = alloc();
			int[] cur = first;
			int pos = 0;
			do {
				int base = off(cur[0], cur[1]);
				int n = Math.min(254, data.length - pos);
				System.arraycopy(data, pos, img, base + 2, n);
				pos += n;
				if (pos < data.length) {
					int[] next = alloc();
					img[base] = (byte) next[0];
					img[base + 1] = (byte) next[1];
					cur = next;
				}
				else {
					img[base] = 0;
					img[base + 1] = (byte) (n + 1);
					break;
				}
			}
			while (true);
			return first;
		}

		Builder file(int type, byte[] petName, byte[] data) {
			int[] first = writeChain(data);
			entry(type, petName, first[0], first[1]);
			return this;
		}

		Builder entry(int type, byte[] petName, int track, int sector) {
			int sectorNo = 1 + dirEntries / 8;
			int base = off(18, sectorNo);
			if (dirEntries % 8 == 0 && dirEntries > 0) {
				// link the previous directory sector to this one
				int prev = off(18, sectorNo - 1);
				img[prev] = 18;
				img[prev + 1] = (byte) sectorNo;
				img[base + 1] = (byte) 0xff;
			}
			int e = base + (dirEntries % 8) * 32;
			img[e + 2] = (byte) type;
			img[e + 3] = (byte) track;
			img[e + 4] = (byte) sector;
			for (int i = 0; i < 16; i++) {
				img[e + 5 + i] = i < petName.length ? petName[i] : (byte) 0xa0;
			}
			dirEntries++;
			return this;
		}
	}

	static byte[] name(String s) {
		return s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
	}

	static byte[] pattern(int len, int seed) {
		byte[] b = new byte[len];
		for (int i = 0; i < len; i++) {
			b[i] = (byte) (seed + i * 7);
		}
		return b;
	}

	static D64Image.Member find(D64Image d, String fileName) {
		for (D64Image.Member m : d.members()) {
			if (m.fileName().equals(fileName)) {
				return m;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Geometry
	// ------------------------------------------------------------------

	@Test
	public void zonesAndTotals() {
		assertEquals(21, D64Image.sectorsPerTrack(1));
		assertEquals(21, D64Image.sectorsPerTrack(17));
		assertEquals(19, D64Image.sectorsPerTrack(18));
		assertEquals(19, D64Image.sectorsPerTrack(24));
		assertEquals(18, D64Image.sectorsPerTrack(25));
		assertEquals(18, D64Image.sectorsPerTrack(30));
		assertEquals(17, D64Image.sectorsPerTrack(31));
		assertEquals(17, D64Image.sectorsPerTrack(40));
		assertEquals(0, D64Image.sectorsPerTrack(41));
		assertEquals(683, D64Image.sectorIndexForTest(36, 0));
		assertEquals(357, D64Image.sectorIndexForTest(18, 0));
		assertEquals(358, D64Image.sectorIndexForTest(18, 1));
		assertEquals(682, D64Image.sectorIndexForTest(35, 16));
		assertEquals(-1, D64Image.sectorIndexForTest(35, 17));
		assertEquals(-1, D64Image.sectorIndexForTest(0, 0));
		assertEquals(-1, D64Image.sectorIndexForTest(36, 0 - 1));
	}

	// ------------------------------------------------------------------
	// Directory, chains
	// ------------------------------------------------------------------

	@Test
	public void directoryParseMultiSectorChainAndLastSectorLength() {
		byte[] one = pattern(10, 1);
		byte[] multi = pattern(254 * 3 + 100, 2);
		byte[] exact = pattern(254 * 2, 3);
		Builder b = new Builder(D64Image.SIZE_35);
		b.file(0x82, name("ONE"), one);
		b.file(0x82, name("MULTI"), multi);
		b.file(0x82, name("EXACT"), exact);
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertEquals(3, d.members().size());
		assertArrayEquals(one, find(d, "ONE.prg").data());
		assertArrayEquals(multi, find(d, "MULTI.prg").data());
		assertArrayEquals(exact, find(d, "EXACT.prg").data());
	}

	@Test
	public void directorySpanningSeveralSectors() {
		Builder b = new Builder(D64Image.SIZE_35);
		for (int i = 0; i < 20; i++) {
			b.file(0x82, name("F" + i), pattern(5, i));
		}
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertEquals(20, d.members().size());
		assertArrayEquals(pattern(5, 19), find(d, "F19.prg").data());
	}

	@Test
	public void kindsScratchedUnclosedAndRel() {
		Builder b = new Builder(D64Image.SIZE_35);
		b.file(0x81, name("S"), pattern(4, 1));
		b.file(0x82, name("P"), pattern(4, 2));
		b.file(0x83, name("U"), pattern(4, 3));
		b.file(0x84, name("R"), pattern(4, 4));
		b.file(0x00, name("DEL"), pattern(4, 5));
		b.file(0x02, name("UNCLOSED"), pattern(4, 6));
		b.file(0xc2, name("LOCKED"), pattern(4, 7));
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertNotNull(find(d, "S.seq"));
		assertNotNull(find(d, "P.prg"));
		assertNotNull(find(d, "U.usr"));
		assertNotNull(find(d, "LOCKED.prg"));
		assertEquals(4, d.members().size());
		assertEquals(1, d.problems().size());
		assertTrue(d.problems().get(0).contains("REL"));
	}

	@Test
	public void fortyTrackImage() {
		Builder b = new Builder(D64Image.SIZE_40);
		b.file(0x82, name("X"), pattern(300, 9));
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertArrayEquals(pattern(300, 9), find(d, "X.prg").data());
	}

	// ------------------------------------------------------------------
	// Naming
	// ------------------------------------------------------------------

	@Test
	public void namePaddingSanitizeAndDedupe() {
		Builder b = new Builder(D64Image.SIZE_35);
		b.file(0x82, new byte[] { 'G', 'A', 'M', 'E', (byte) 0xa0, (byte) 0xa0 }, pattern(3, 1));
		b.file(0x82, name("A/B:C|D\\E"), pattern(3, 2));
		b.file(0x82, new byte[] { 'X', 0x01, (byte) 0x93, 'Y' }, pattern(3, 3));
		b.file(0x82, new byte[] { (byte) 0xc1, (byte) 0xc2 }, pattern(3, 4));
		b.file(0x82, name("DUP"), pattern(3, 5));
		b.file(0x82, name("DUP"), pattern(3, 6));
		b.file(0x82, name("DUP"), pattern(3, 7));
		b.file(0x81, name("DUP"), pattern(3, 8));
		b.file(0x82, new byte[0], pattern(3, 9));
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertNotNull(find(d, "GAME.prg"));
		assertNotNull(find(d, "A_B_C_D_E.prg"));
		assertNotNull(find(d, "X__Y.prg"));
		assertNotNull(find(d, "AB.prg"));
		assertArrayEquals(pattern(3, 5), find(d, "DUP.prg").data());
		assertArrayEquals(pattern(3, 6), find(d, "DUP~2.prg").data());
		assertArrayEquals(pattern(3, 7), find(d, "DUP~3.prg").data());
		assertArrayEquals(pattern(3, 8), find(d, "DUP.seq").data());
		assertNotNull(find(d, "UNNAMED.prg"));
	}

	// ------------------------------------------------------------------
	// Probe
	// ------------------------------------------------------------------

	@Test
	public void probeAcceptsAllFourSizes() {
		for (int size : new int[] { D64Image.SIZE_35, D64Image.SIZE_35_ERRORS,
			D64Image.SIZE_40, D64Image.SIZE_40_ERRORS }) {
			assertTrue("size " + size, D64Image.looksLikeD64(new Builder(size).img));
		}
	}

	@Test
	public void probeRejectsArbitraryFilesAndWrongSizes() {
		assertFalse(D64Image.looksLikeD64(new byte[D64Image.SIZE_35]));
		byte[] noise = new byte[D64Image.SIZE_35];
		new java.util.Random(1).nextBytes(noise);
		assertFalse(D64Image.looksLikeD64(noise));
		byte[] ff = new byte[D64Image.SIZE_35];
		java.util.Arrays.fill(ff, (byte) 0xff);
		assertFalse(D64Image.looksLikeD64(ff));
		assertFalse(D64Image.looksLikeD64(
			java.util.Arrays.copyOf(new Builder(D64Image.SIZE_35).img, 174849)));
		assertNull(D64Image.parse(new byte[10]));
	}

	@Test
	public void probeRejectsBadBamOrDirectory() {
		Builder b = new Builder(D64Image.SIZE_35);
		b.file(0x82, name("OK"), pattern(3, 1));
		byte[] good = b.img;
		assertTrue(D64Image.looksLikeD64(good));

		byte[] wrongTrack = good.clone();
		wrongTrack[Builder.off(18, 0)] = 17;
		assertFalse(D64Image.looksLikeD64(wrongTrack));

		byte[] badSector = good.clone();
		badSector[Builder.off(18, 0) + 1] = 99;
		assertFalse(D64Image.looksLikeD64(badSector));

		byte[] badDos = good.clone();
		badDos[Builder.off(18, 0) + 2] = 0x55;
		assertFalse(D64Image.looksLikeD64(badDos));

		byte[] badType = good.clone();
		badType[Builder.off(18, 1) + 2] = (byte) 0x87;
		assertFalse(D64Image.looksLikeD64(badType));

		byte[] loop = good.clone();
		loop[Builder.off(18, 1)] = 18;
		loop[Builder.off(18, 1) + 1] = 1;
		assertFalse("directory loop", D64Image.looksLikeD64(loop));

		byte[] leaves = good.clone();
		leaves[Builder.off(18, 1)] = 5;
		leaves[Builder.off(18, 1) + 1] = 0;
		assertFalse("directory leaves track 18", D64Image.looksLikeD64(leaves));
	}

	// ------------------------------------------------------------------
	// Robustness
	// ------------------------------------------------------------------

	@Test
	public void chainLoopFailsOnlyThatFile() {
		Builder b = new Builder(D64Image.SIZE_35);
		b.file(0x82, name("GOOD"), pattern(600, 1));
		b.file(0x82, name("LOOPY"), pattern(600, 2));
		b.file(0x82, name("GOOD2"), pattern(20, 3));
		// LOOPY starts at the 4th data sector (1/3); point its second sector back at itself.
		int loopy = Builder.off(1, 3);
		b.img[loopy] = 1;
		b.img[loopy + 1] = 3;
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertNotNull(find(d, "GOOD.prg"));
		assertNotNull(find(d, "GOOD2.prg"));
		assertNull(find(d, "LOOPY.prg"));
		assertEquals(1, d.problems().size());
		assertTrue(d.problems().get(0).contains("loops"));
	}

	@Test
	public void outOfRangeLinkFailsFile() {
		Builder b = new Builder(D64Image.SIZE_35);
		b.file(0x82, name("BAD"), pattern(600, 1));
		b.file(0x82, name("OK"), pattern(10, 2));
		int first = Builder.off(1, 0);
		b.img[first] = 50;
		b.img[first + 1] = 0;
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertNull(find(d, "BAD.prg"));
		assertNotNull(find(d, "OK.prg"));
		assertTrue(d.problems().get(0).contains("out of range"));
	}

	@Test
	public void entryPointingAtTrackZeroFailsFile() {
		Builder b = new Builder(D64Image.SIZE_35);
		b.entry(0x82, name("ZERO"), 0, 0);
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertTrue(d.members().isEmpty());
		assertEquals(1, d.problems().size());
	}

	@Test
	public void errorByteInChainFailsFileButOkCodesPass() {
		Builder b = new Builder(D64Image.SIZE_35_ERRORS);
		b.file(0x82, name("BADSEC"), pattern(600, 1));
		b.file(0x82, name("FINE"), pattern(600, 2));
		b.file(0x82, name("ZEROERR"), pattern(10, 3));
		int base = D64Image.SIZE_35;
		// BADSEC occupies 1/0..1/2; FINE 1/3..1/5; ZEROERR 1/6. Error on its middle sector.
		b.img[base + D64Image.sectorIndexForTest(1, 1)] = 5;
		// ZEROERR's error byte 0 is tolerated (unexamined), as is 1.
		b.img[base + D64Image.sectorIndexForTest(1, 6)] = 0;
		// An error on a sector no file uses does not matter.
		b.img[base + D64Image.sectorIndexForTest(30, 3)] = 4;
		D64Image d = D64Image.parse(b.img);
		assertNotNull(d);
		assertNull(find(d, "BADSEC.prg"));
		assertNotNull(find(d, "FINE.prg"));
		assertNotNull(find(d, "ZEROERR.prg"));
		assertTrue(d.problems().get(0).contains("error code 5"));
	}

	// ------------------------------------------------------------------
	// Local oracle (not run in the gate): compare against extracted PRGs
	// ------------------------------------------------------------------

	/**
	 * Throwaway cross-check against an owner's image and a folder of extracted files. Run with
	 * {@code -Dgrm.d64=<image> -Dgrm.d64dir=<folder>}; skipped otherwise. Nothing from those
	 * paths is committed.
	 */
	@Test
	public void localOracle() throws IOException {
		String img = System.getProperty("grm.d64");
		String dir = System.getProperty("grm.d64dir");
		Assume.assumeTrue(img != null && dir != null);
		D64Image d = D64Image.parse(Files.readAllBytes(Path.of(img)));
		assertNotNull("image rejected", d);
		List<Path> extracted;
		try (var s = Files.list(Path.of(dir))) {
			extracted = s.filter(Files::isRegularFile).toList();
		}
		int match = 0;
		int mismatch = 0;
		for (D64Image.Member m : d.members()) {
			String stem = m.fileName().substring(0, m.fileName().lastIndexOf('.'));
			Path hit = null;
			for (Path p : extracted) {
				String n = p.getFileName().toString();
				String ns = n.contains(".") ? n.substring(0, n.lastIndexOf('.')) : n;
				if (ns.equalsIgnoreCase(stem)) {
					hit = p;
				}
			}
			if (hit == null) {
				System.out.println("ORACLE no-counterpart " + m.fileName() + " " +
					m.data().length + " bytes");
				continue;
			}
			boolean same = java.util.Arrays.equals(Files.readAllBytes(hit), m.data());
			System.out.println("ORACLE " + (same ? "MATCH " : "MISMATCH ") + m.fileName() +
				" vs " + hit.getFileName() + " (" + m.data().length + " vs " +
				Files.size(hit) + ")");
			if (same) {
				match++;
			}
			else {
				mismatch++;
			}
		}
		for (String p : d.problems()) {
			System.out.println("ORACLE problem: " + p);
		}
		System.out.println("ORACLE total members=" + d.members().size() + " match=" + match +
			" mismatch=" + mismatch + " extractedFiles=" + extracted.size());
	}
}
