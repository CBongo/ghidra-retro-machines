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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.LongUnaryOperator;

import org.junit.Test;

import retromachines.JumpTableBound.LoadTableEntry;
import retromachines.JumpTableBound.Result;
import retromachines.JumpTableBound.Rule;

/**
 * Pure-logic tests for {@link JumpTableBound#boundByExtentOverlap} (grm-c9d.8.6), the tail form
 * of the extent-overlap rule: a table cut where its own bytes run into an earlier target's code.
 */
public class JumpTableBoundExtentTest {

	private static List<Long> targets(long... values) {
		List<Long> list = new ArrayList<>();
		for (long v : values) {
			list.add(v);
		}
		return list;
	}

	private static List<Boolean> allInCode(int n) {
		return new ArrayList<>(Collections.nCopies(n, true));
	}

	/** An extent function: each listed {start, end} pair, every other target one byte long. */
	private static LongUnaryOperator extents(long... startEnd) {
		return t -> {
			for (int i = 0; i < startEnd.length; i += 2) {
				if (startEnd[i] == t) {
					return startEnd[i + 1];
				}
			}
			return t + 1;
		};
	}

	/** The real-ROM shape (dragonpower 803e) in miniature: 3 real entries, one below the table
	 *  (so the lowest-target rule declines), then the handler 8006 the second entry points at,
	 *  whose code runs over the next slots; then junk. */
	@Test
	public void cutsWhereTheTableRunsIntoItsOwnHandler() {
		List<Long> t = targets(0x7000, 0x8006, 0x8100, 0x1234, 0x5678, 0x2222);
		List<LoadTableEntry> lt = List.of(new LoadTableEntry(0x8000, 2, 6));
		assertFalse("lowest target declines: a handler sits below the table",
			JumpTableBound.bound(t, lt).isBounded());
		Result r = JumpTableBound.boundByExtentOverlap(t, lt, extents(0x8006, 0x8010), allInCode(6));
		assertTrue(r.isBounded());
		assertEquals(Rule.EXTENT_OVERLAP, r.rule());
		assertEquals(3, r.count());
	}

	/** A later (junk) target whose code covers EARLIER slots never cuts them: only kept targets
	 *  are judged. */
	@Test
	public void laterTargetsNeverCutEarlierSlots() {
		List<Long> t = targets(0x7000, 0x7100, 0x7200, 0x7300, 0x7400, 0x8000);
		List<LoadTableEntry> lt = List.of(new LoadTableEntry(0x8000, 2, 6));
		Result r = JumpTableBound.boundByExtentOverlap(t, lt, extents(0x8000, 0x8010), allInCode(6));
		assertFalse(r.isBounded());
	}

	/** A handler below the table that decodes on into it (table after code) is not an overlap. */
	@Test
	public void ignoresHandlersBelowTheTable() {
		List<Long> t = targets(0x7ff0, 0x7000, 0x7100, 0x7200);
		List<LoadTableEntry> lt = List.of(new LoadTableEntry(0x8000, 2, 4));
		Result r = JumpTableBound.boundByExtentOverlap(t, lt, extents(0x7ff0, 0x8010), allInCode(4));
		assertFalse(r.isBounded());
	}

	@Test
	public void declinesWhenFewerThanTwoWouldStay() {
		List<Long> t = targets(0x8002, 0x7000, 0x7100);
		List<LoadTableEntry> lt = List.of(new LoadTableEntry(0x8000, 2, 3));
		Result r = JumpTableBound.boundByExtentOverlap(t, lt, extents(0x8002, 0x8010), allInCode(3));
		assertFalse(r.isBounded());
	}

	@Test
	public void declinesWhenAKeptEntryIsNotInCode() {
		List<Long> t = targets(0x7000, 0x8006, 0x0200, 0x1234);
		List<LoadTableEntry> lt = List.of(new LoadTableEntry(0x8000, 2, 4));
		List<Boolean> inCode = allInCode(4);
		inCode.set(2, false);
		Result r = JumpTableBound.boundByExtentOverlap(t, lt, extents(0x8006, 0x8010), inCode);
		assertFalse(r.isBounded());
	}

	/** Split lo/hi tables: an entry overlaps when either half's byte does. */
	@Test
	public void splitTablesCutOnEitherHalf() {
		// lo at 8000, hi at 8004 (4 entries each); entry 1's target 8006 is the hi table's 3rd byte.
		List<Long> t = targets(0x7000, 0x8006, 0x7100, 0x7200);
		List<LoadTableEntry> lt = List.of(new LoadTableEntry(0x8000, 1, 4),
			new LoadTableEntry(0x8004, 1, 4));
		Result r = JumpTableBound.boundByExtentOverlap(t, lt, extents(0x8006, 0x8008), allInCode(4));
		assertTrue(r.isBounded());
		assertEquals(2, r.count());
	}
}
