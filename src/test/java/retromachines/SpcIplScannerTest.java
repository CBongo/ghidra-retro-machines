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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Random;

import org.junit.Test;

/** Pure-JUnit coverage of {@link SpcIplScanner} (bead grm-1.7.3) on synthetic images. */
public class SpcIplScannerTest {

	private static byte[] stream(int[][] blocks, int entry) {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		for (int[] b : blocks) {
			SpcIplFormatTest.block(o, b[0], b[1], b[2]);
		}
		SpcIplFormatTest.terminator(o, entry);
		return o.toByteArray();
	}

	/** Noise that cannot itself contain a plausible stream: all 0xFF (len 0xFFFF overflows). */
	private static byte[] noise(int n) {
		byte[] b = new byte[n];
		java.util.Arrays.fill(b, (byte) 0xFF);
		return b;
	}

	private static byte[] embed(byte[] prefix, byte[] payload, byte[] suffix) {
		byte[] out = new byte[prefix.length + payload.length + suffix.length];
		System.arraycopy(prefix, 0, out, 0, prefix.length);
		System.arraycopy(payload, 0, out, prefix.length, payload.length);
		System.arraycopy(suffix, 0, out, prefix.length + payload.length, suffix.length);
		return out;
	}

	private static final int[][] TWO_BLOCKS = { { 400, 0x0800, 1 }, { 300, 0x4000, 2 } };

	@Test
	public void findsStreamEmbeddedInNoise() {
		byte[] image = embed(noise(1000), stream(TWO_BLOCKS, 0x0810), noise(500));
		List<SpcIplScanner.Candidate> c = SpcIplScanner.scanImage(image, false);
		assertEquals(1, c.size());
		SpcIplScanner.Candidate top = c.get(0);
		assertEquals(1000, top.strippedOffset());
		assertEquals(1000L, top.fileOffset());
		assertFalse(top.copierHeader());
		assertEquals(2, top.stream().blocks().size());
		assertEquals(0x0810, top.stream().entry());
		assertEquals(700, top.stream().payloadBytes());
	}

	@Test
	public void suppressesTailRefoundAtLaterBlockBoundary() {
		// The second block alone (300 bytes, entry inside it) is itself a plausible stream, so
		// without suppression the scan would report it as a second candidate.
		byte[] image = embed(noise(16), stream(TWO_BLOCKS, 0x4010), noise(16));
		byte[] tailOnly = stream(new int[][] { TWO_BLOCKS[1] }, 0x4010);
		assertEquals("tail must be independently plausible for this test to mean anything", 1,
			SpcIplScanner.scanImage(tailOnly, false).size());

		List<SpcIplScanner.Candidate> c = SpcIplScanner.scanImage(image, false);
		assertEquals(1, c.size());
		assertEquals(16, c.get(0).strippedOffset());
	}

	@Test
	public void rejectsImplausibleStreams() {
		// too small
		assertTrue(SpcIplScanner.scanImage(stream(new int[][] { { 20, 0x0800, 1 } }, 0x0800), false)
				.isEmpty());
		// entry outside every block
		assertTrue(SpcIplScanner.scanImage(stream(TWO_BLOCKS, 0x9000), false).isEmpty());
		// overlapping blocks
		assertTrue(SpcIplScanner
				.scanImage(stream(new int[][] { { 400, 0x0800, 1 }, { 300, 0x0900, 2 } }, 0x0800),
					false)
				.isEmpty());
		// writes the SPC700 register page
		assertTrue(SpcIplScanner
				.scanImage(stream(new int[][] { { 400, 0x00F0, 1 } }, 0x0100), false).isEmpty());
	}

	@Test
	public void zeroPageBelowRegistersIsAllowed() {
		List<SpcIplScanner.Candidate> c = SpcIplScanner
				.scanImage(stream(new int[][] { { 0xF0, 0x0000, 1 }, { 300, 0x0100, 1 } }, 0x0100),
					false);
		assertEquals(1, c.size());
	}

	@Test
	public void rankedByScore() {
		byte[] small = stream(new int[][] { { 300, 0x0800, 1 } }, 0x0800);
		byte[] big = stream(new int[][] { { 2000, 0x0800, 1 }, { 500, 0x8000, 1 } }, 0x0800);
		byte[] image = embed(embed(noise(8), small, noise(8)), big, noise(8));
		List<SpcIplScanner.Candidate> c = SpcIplScanner.scanImage(image, false);
		assertEquals(2, c.size());
		assertEquals(2500, c.get(0).stream().payloadBytes());
		assertEquals(300, c.get(1).stream().payloadBytes());
	}

	@Test
	public void copierHeaderIsStrippedAndReported() {
		byte[] body = embed(noise(0x400), stream(TWO_BLOCKS, 0x0800), noise(0x400 - 0x200));
		// Pad so the cartridge is a whole number of KiB, then prepend 512 header bytes.
		int cart = ((body.length + 0x3FF) / 0x400) * 0x400;
		byte[] cartImage = java.util.Arrays.copyOf(body, cart);
		java.util.Arrays.fill(cartImage, body.length, cart, (byte) 0xFF);
		byte[] file = embed(new byte[0x200], cartImage, new byte[0]);
		assertEquals(0x200, file.length % 0x400);

		List<SpcIplScanner.Candidate> c = SpcIplScanner.scan(file);
		assertEquals(1, c.size());
		assertTrue(c.get(0).copierHeader());
		assertEquals(0x400, c.get(0).strippedOffset());
		assertEquals(0x600L, c.get(0).fileOffset());
	}

	@Test
	public void noCopierHeaderOnWholeKiBFile() {
		byte[] file = new byte[0x1000];
		java.util.Arrays.fill(file, (byte) 0xFF);
		byte[] s = stream(TWO_BLOCKS, 0x0800);
		System.arraycopy(s, 0, file, 0x100, s.length);
		List<SpcIplScanner.Candidate> c = SpcIplScanner.scan(file);
		assertEquals(1, c.size());
		assertFalse(c.get(0).copierHeader());
		assertEquals(0x100L, c.get(0).fileOffset());
	}

	@Test
	public void randomDataYieldsFewCandidates() {
		byte[] b = new byte[1 << 20];
		new Random(12345).nextBytes(b);
		List<SpcIplScanner.Candidate> c = SpcIplScanner.scanImage(b, false);
		System.out.println("random 1 MiB false positives: " + c.size());
		// Honest bound, not "zero": the format has little redundancy, so chance chains exist.
		// This pins the rate (deterministic seed) so a rule change that loosens it is noticed.
		assertTrue("false-positive rate on random data: " + c.size(), c.size() <= 3);
	}
}
