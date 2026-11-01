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
import static org.junit.Assert.assertNull;

import java.util.List;

import org.junit.Test;

import retromachines.IndexGuard.Branch;
import retromachines.IndexGuard.Op;
import retromachines.IndexGuard.Range;

/** grm-c9d.8.2: the pure range arithmetic of {@link IndexGuard}; no Ghidra types. */
public class IndexGuardTest {

	@Test
	public void bccNotTakenMeansAtOrAboveTheImmediate() {
		assertEquals(new Range(0xda, 0xff, 1), IndexGuard.fallThrough(Branch.BCC, 0xda));
	}

	@Test
	public void bcsNotTakenMeansBelowTheImmediate() {
		assertEquals(new Range(0, 0x0f, 1), IndexGuard.fallThrough(Branch.BCS, 0x10));
	}

	@Test
	public void emptyOrOutOfRangeGuardsGiveNothing() {
		assertNull(IndexGuard.fallThrough(Branch.BCS, 0)); // nothing is below zero
		assertEquals(new Range(255, 255, 1), IndexGuard.fallThrough(Branch.BCC, 255));
		assertNull(IndexGuard.fallThrough(Branch.BCC, 256));
		assertNull(IndexGuard.fallThrough(Branch.BCC, -1));
	}

	/** SMW 0d44: A in da..ff, ASL A, X = 2A mod 256 = b4..fe, slots 90..127 of word entries. */
	@Test
	public void smwDispatchRange() {
		Range a = IndexGuard.fallThrough(Branch.BCC, 0xda);
		Range x = IndexGuard.apply(a, List.of(Op.ASL1));
		assertEquals(new Range(0xb4, 0xfe, 2), x);
		assertArrayEquals(new int[] { 90, 127 }, IndexGuard.slotSpan(x, 2));
	}

	@Test
	public void doublingBelowHalfStaysPlain() {
		Range x = IndexGuard.apply(new Range(0, 0x0f, 1), Op.ASL1);
		assertEquals(new Range(0, 0x1e, 2), x);
		assertArrayEquals(new int[] { 0, 15 }, IndexGuard.slotSpan(x, 2));
	}

	/** 0x70..0x8f doubles to 0xe0..0x1fe: the image straddles 256, so it is two runs. */
	@Test
	public void doublingAcrossTheWrapIsNotContiguous() {
		assertNull(IndexGuard.apply(new Range(0x70, 0x8f, 1), Op.ASL1));
	}

	@Test
	public void shiftRightHalvesTheRange() {
		assertEquals(new Range(0x10, 0x1f, 1), IndexGuard.apply(new Range(0x20, 0x3f, 1), Op.LSR1));
		// doubled then halved: back to the original
		Range back = IndexGuard.apply(new Range(0x20, 0x3f, 1), List.of(Op.ASL1, Op.LSR1));
		assertEquals(new Range(0x20, 0x3f, 1), back);
		assertNull(IndexGuard.apply(new Range(1, 9, 4), Op.LSR1)); // odd start, even step
	}

	@Test
	public void plainByteOffsetsDoNotMakeWholeWordSlots() {
		assertNull(IndexGuard.slotSpan(new Range(0, 10, 1), 2)); // reaches the odd bytes
		assertNull(IndexGuard.slotSpan(new Range(1, 9, 2), 2)); // odd start
		assertNull(IndexGuard.slotSpan(new Range(0, 12, 4), 2)); // skips slots
		assertNull(IndexGuard.slotSpan(null, 2));
		assertArrayEquals(new int[] { 3, 9 }, IndexGuard.slotSpan(new Range(6, 18, 2), 2));
	}

	@Test
	public void hullOfDifferentCallersCoversBoth() {
		Range h = IndexGuard.hull(new Range(0xb4, 0xfe, 2), new Range(0xb0, 0xc0, 2));
		assertEquals(new Range(0xb0, 0xfe, 2), h);
		// misaligned callers fall back to a step of one
		assertEquals(1, IndexGuard.hull(new Range(0, 10, 2), new Range(3, 7, 2)).step());
	}
}
