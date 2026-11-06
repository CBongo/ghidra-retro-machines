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
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import retromachines.CbmAutostart.Config;
import retromachines.CbmAutostart.Entry;
import retromachines.CbmAutostart.Kind;
import retromachines.CbmAutostart.Result;
import retromachines.CbmAutostart.Vector;

/** Pure-JUnit coverage of {@link CbmAutostart} (bead grm-w0j7); no Ghidra runtime. */
public class CbmAutostartTest {

	private static final Config CONFIG = new Config(
		List.of(new Vector("IBSOUT", 0x0326, 0xF1CA), new Vector("CINV", 0x0314, 0xEA31)),
		0x0100, 0x01FF,
		List.of(new Vector("NMI", 0xFFFA, -1), new Vector("RESET", 0xFFFC, -1)));

	/** Test PRG: a sparse byte image by CPU address. */
	private static final class Image implements CbmAutostart.Bytes {
		private final int[] mem = new int[0x10000];

		Image() {
			java.util.Arrays.fill(mem, -1);
		}

		Image put(int addr, int... bytes) {
			for (int i = 0; i < bytes.length; i++) {
				mem[addr + i] = bytes[i];
			}
			return this;
		}

		Image putWord(int addr, int w) {
			return put(addr, w & 0xFF, w >> 8);
		}

		/** Fills [from, to] with a repeating little-endian word starting at {@code from}. */
		Image fillWords(int from, int to, int w) {
			for (int a = from; a <= to; a++) {
				mem[a] = ((a - from) & 1) == 0 ? w & 0xFF : w >> 8;
			}
			return this;
		}

		@Override
		public int at(int a) {
			return mem[a];
		}
	}

	private static Result run(Image img) {
		return CbmAutostart.detect(CONFIG, img);
	}

	@Test
	public void ramVectorWithNonDefaultWordIsAnEntry() {
		Result r = run(new Image().putWord(0x0326, 0x1234));
		assertEquals(1, r.entries().size());
		Entry e = r.entries().get(0);
		assertEquals(Kind.RAM_VECTOR, e.kind());
		assertEquals("autostart_IBSOUT", e.label());
		assertEquals(0x1234, e.target());
	}

	@Test
	public void defaultEqualWordIsIgnored() {
		assertTrue(run(new Image().putWord(0x0326, 0xF1CA)).entries().isEmpty());
	}

	@Test
	public void oneByteOverwriteIsIgnored() {
		assertTrue(run(new Image().put(0x0326, 0x34)).entries().isEmpty());
		assertTrue(run(new Image().put(0x0327, 0x12)).entries().isEmpty());
	}

	@Test
	public void zeroWordIsPaddingNotEntry() {
		Result r = run(new Image().putWord(0x0314, 0));
		assertTrue(r.entries().isEmpty());
		assertEquals(1, r.notes().size());
	}

	@Test
	public void emptyConfigDetectsNothing() {
		Config none = CbmAutostart.fromMap(new JsonObject());
		assertTrue(none.isEmpty());
		assertTrue(CbmAutostart.detect(none, new Image().putWord(0x0326, 0x1234)).entries()
				.isEmpty());
	}

	@Test
	public void configParsesFromCompiledMap() {
		JsonObject map = JsonParser.parseString("{\"autostart\":{\"vectors\":[{\"name\":\"X\","
			+ "\"addr\":768,\"default\":1}],\"stack\":{\"start\":256,\"end\":511},"
			+ "\"hardware\":[{\"name\":\"NMI\",\"addr\":65530}]}}").getAsJsonObject();
		Config c = CbmAutostart.fromMap(map);
		assertEquals(new Vector("X", 768, 1), c.vectors().get(0));
		assertEquals(0x100, c.stackStart());
		assertEquals(new Vector("NMI", 0xFFFA, -1), c.hardware().get(0));
	}

	@Test
	public void repeatedStackWordIsRtsEntryPlusOne() {
		// 0x4A00 repeated: parity-0 slots hold 0x4A00, parity-1 slots hold 0x004A (target < $0100
		// would be rejected), so exactly one candidate survives.
		Result r = run(new Image().fillWords(0x0100, 0x01FF, 0x4A00).put(0x4A01, 0xEA));
		assertEquals(1, r.entries().size());
		Entry e = r.entries().get(0);
		assertEquals(Kind.STACK, e.kind());
		assertEquals("autostart_stack", e.label());
		assertEquals(0x4A00, e.word());
		assertEquals(0x4A01, e.target());
	}

	@Test
	public void repeatedStackWordAtOddParityIsFound() {
		// Fill begins on an odd address: the word sits at odd slots.
		Result r = run(new Image().fillWords(0x0101, 0x01FF, 0x4A00).put(0x4A01, 0xEA));
		assertEquals(1, r.entries().size());
		assertEquals(0x4A00, r.entries().get(0).word());
	}

	@Test
	public void ambiguousStrideTwoFillPrefersTargetInsidePrg() {
		// Word 0x2A30 vs 0x302A at equal counts; only $2A31 is inside PRG bytes.
		Image img = new Image().fillWords(0x0100, 0x01FF, 0x2A30).put(0x2A31, 0xEA);
		Result r = run(img);
		assertEquals(1, r.entries().size());
		assertEquals(0x2A31, r.entries().get(0).target());
	}

	@Test
	public void ambiguousStrideTwoFillWithNoTiebreakIsOnlyANote() {
		Result r = run(new Image().fillWords(0x0100, 0x01FF, 0x2A30));
		assertTrue(r.entries().isEmpty());
		assertEquals(1, r.notes().size());
	}

	@Test
	public void nonRepeatedStackContentIsNotAnEntry() {
		Image img = new Image();
		for (int a = 0x0100; a <= 0x01FF; a++) {
			img.put(a, (a * 7 + 3) & 0xFF);
		}
		Result r = run(img);
		assertTrue(r.entries().isEmpty());
		assertEquals(1, r.notes().size());
	}

	@Test
	public void fewRepeatsBelowThresholdIsNotAnEntry() {
		Image img = new Image().put(0x5601, 0xEA);
		for (int a = 0x0100; a <= 0x01FF; a++) {
			img.put(a, (a * 7 + 3) & 0xFF);
		}
		for (int i = 0; i < CbmAutostart.STACK_MIN_REPEATS - 1; i++) {
			img.putWord(0x0120 + 2 * i, 0x5600);
		}
		assertTrue(run(img).entries().isEmpty());
	}

	@Test
	public void paddingFillsAreNotEntries() {
		assertTrue(run(new Image().fillWords(0x0100, 0x01FF, 0x0000)).entries().isEmpty());
		assertTrue(run(new Image().fillWords(0x0100, 0x01FF, 0x2020)).entries().isEmpty());
		assertTrue(run(new Image().fillWords(0x0100, 0x01FF, 0xFFFF)).entries().isEmpty());
	}

	@Test
	public void uncoveredStackIsSilent() {
		Result r = run(new Image());
		assertTrue(r.entries().isEmpty());
		assertTrue(r.notes().isEmpty());
	}

	@Test
	public void hardwareVectorsNeedBothBytes() {
		Result r = run(new Image().putWord(0xFFFA, 0x0810).put(0xFFFC, 0x00));
		assertEquals(1, r.entries().size());
		Entry e = r.entries().get(0);
		assertEquals(Kind.HARDWARE_VECTOR, e.kind());
		assertEquals("autostart_NMI", e.label());
		assertEquals(0x0810, e.target());
	}

	@Test
	public void bothParitiesEligibleAndEqualIsAmbiguous() {
		Image img = new Image().fillWords(0x0100, 0x01FF, 0x2A30).put(0x2A31, 0xEA).put(0x302B, 0xEA);
		Result r = run(img);
		assertTrue(r.entries().isEmpty());
		assertEquals(1, r.notes().size());
	}

	@Test
	public void zeroPaddingDoesNotMaskARealFill() {
		// Mostly zeros with a $0202 tail and code at $0203 (the ea.prg shape).
		Image img = new Image().fillWords(0x0100, 0x01DF, 0x0000).fillWords(0x01E0, 0x01FF, 0x0202)
				.put(0x0203, 0xAF);
		Result r = run(img);
		assertEquals(1, r.entries().size());
		assertEquals(0x0203, r.entries().get(0).target());
	}

	@Test
	public void repeatedWordTargetingOutsideThePrgIsDataNotAnEntry() {
		Result r = run(new Image().fillWords(0x0100, 0x01FF, 0x6D6D));
		assertTrue(r.entries().isEmpty());
	}

	@Test
	public void bulkVectorOverwriteIsDataNotEntries() {
		Image img = new Image().putWord(0x0326, 0x1234).putWord(0x0314, 0x5678);
		Result r = run(img);
		assertTrue(r.entries().isEmpty());
		assertEquals(1, r.notes().size());
	}

	@Test
	public void zeroHardwareVectorIsIgnored() {
		assertTrue(run(new Image().putWord(0xFFFA, 0).putWord(0xFFFC, 0)).entries().isEmpty());
	}
}
