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
import java.util.List;
import java.util.Map;

import org.junit.Test;

import retromachines.JumpTableBound.CodeRun;
import retromachines.JumpTableBound.LeadingRule;
import retromachines.JumpTableBound.LoadTableEntry;
import retromachines.JumpTableBound.Result;
import retromachines.JumpTableBound.Rule;
import retromachines.JumpTableBound.SlotCodeProbe;

/**
 * Pure-logic tests for {@link JumpTableBound#boundBySlotCode} and
 * {@link JumpTableBound#leadingBySlotCode} (grm-c9d.8.8): the table's own slot bytes decoding as a
 * coherent code run. The decode itself is faked by a map from slot address to run.
 */
public class JumpTableBoundSlotCodeTest {

	private static final long TABLE = 0x803e;

	/** n junk targets, so only the rule under test decides the cut. */
	private static List<Long> targets(int n) {
		List<Long> list = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			list.add(0x8100L + i);
		}
		return list;
	}

	private static List<LoadTableEntry> table(int n) {
		return List.of(new LoadTableEntry(TABLE, 2, n));
	}

	private static CodeRun run(boolean legal, boolean terminated, long end, Long... calls) {
		return new CodeRun(legal, terminated, end, List.of(calls));
	}

	/** Probe: runs from the map (anything else undecodable); every target outside 0x9000 up is
	 *  "code" unless listed in {@code notCode}. */
	private static SlotCodeProbe probe(Map<Long, CodeRun> runs) {
		return new SlotCodeProbe(a -> runs.getOrDefault(a, run(false, false, a)),
			t -> t >= 0x9000);
	}

	private static long slot(int k) {
		return TABLE + 2L * k;
	}

	/** dragonpower 803e in miniature: 9 real slots, then JSR $99FB / LDY / JSR $988B / ... */
	@Test
	public void cutsAtTheFirstSlotWhoseBytesAreCode() {
		Result r = JumpTableBound.boundBySlotCode(targets(128), table(128), probe(
			Map.of(slot(9), run(true, true, slot(9) + 12, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertTrue(r.isBounded());
		assertEquals(Rule.SLOT_CODE, r.rule());
		assertEquals(9, r.count());
		assertEquals(0x8100L, r.lowestTarget());
	}

	@Test
	public void cutsAtTheSmallestQualifyingSlot() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(Map.of(
			slot(9), run(true, false, slot(9) + 64, 0x99fbL, 0x988bL, 0x9a1cL),
			slot(12), run(true, true, slot(12) + 8, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertEquals(9, r.count());
	}

	@Test
	public void declinesWithOnlyOneAbsoluteCall() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(
			Map.of(slot(9), run(true, true, slot(9) + 8, 0x99fbL))));
		assertFalse(r.isBounded());
	}

	/** deadly_towers bbfd: real entries followed by a routine with one JSR and one JMP. */
	@Test
	public void declinesWithOnlyTwoAbsoluteCalls() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(
			Map.of(slot(9), run(true, true, slot(9) + 8, 0x99fbL, 0x988bL))));
		assertFalse(r.isBounded());
	}

	/** deadly_towers bbfd (grm-c9d.8.10): 8 entries, then two-call routines at slots 8/13/18/25,
	 *  each ending where the next starts, and the first three-call run at slot 32. Slot 7's decode
	 *  also ends at slot 13 (ASL zp, then slot 8's routine), and slots 19/26 are the BEQ after
	 *  each routine's LDA, ending at 25/32 too: neither kind may be stepped to. */
	@Test
	public void walksBackThroughAbuttingTwoCallRoutines() {
		Map<Long, CodeRun> runs = new java.util.HashMap<>();
		runs.put(slot(7), run(true, true, slot(13), 0xc27aL, 0xbd13L));
		runs.put(slot(8), run(true, true, slot(13), 0xc27aL, 0xbd13L));
		runs.put(slot(13), run(true, true, slot(18), 0xc28fL, 0xbd13L));
		runs.put(slot(18), run(true, true, slot(25), 0xc2b5L, 0xbd13L));
		runs.put(slot(19), run(true, true, slot(25), 0xc2b5L, 0xbd13L));
		runs.put(slot(25), run(true, true, slot(32), 0xc2a7L, 0xbd13L));
		runs.put(slot(26), run(true, true, slot(32), 0xc2a7L, 0xbd13L));
		runs.put(slot(32), run(true, true, slot(32) + 16, 0xbc7dL, 0xc27aL, 0xc2b5L, 0xbd13L));
		Result r = JumpTableBound.boundBySlotCode(targets(64), table(64), new SlotCodeProbe(
			a -> runs.getOrDefault(a, run(false, false, a)), t -> t >= 0xbc00));
		assertEquals(Rule.SLOT_CODE, r.rule());
		assertEquals(8, r.count());
	}

	/** A run that falls through into the cut (step cap, no terminator) does not extend it. */
	@Test
	public void aRunThatOnlyFallsIntoTheCutDoesNotExtend() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(Map.of(
			slot(5), run(true, false, slot(9), 0x99fbL, 0x988bL),
			slot(9), run(true, true, slot(9) + 12, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertEquals(9, r.count());
	}

	/** An abutting run with a single outside call is not enough to extend. */
	@Test
	public void anAbuttingRunNeedsTwoCalls() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(Map.of(
			slot(5), run(true, true, slot(9), 0x99fbL),
			slot(9), run(true, true, slot(9) + 12, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertEquals(9, r.count());
	}

	/** dbz_saiyan d1aa: a jump back into the over-read tail (the code itself) still counts. */
	@Test
	public void aCallIntoTheOverReadTailCounts() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), new SlotCodeProbe(
			a -> a == slot(9) ? run(true, true, a + 8, 0x99fbL, 0x988bL, slot(12))
					: run(false, false, a),
			t -> true));
		assertEquals(9, r.count());
	}

	@Test
	public void declinesWhenTheCallTargetsLieInsideTheTable() {
		// both calls land in the table's own bytes (0x803e .. 0x803e + 64), so they do not count
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), new SlotCodeProbe(
			a -> a == slot(9) ? run(true, true, a + 8, 0x8041L, 0x8045L, 0x8049L) : run(false, false, a),
			t -> true));
		assertFalse(r.isBounded());
	}

	@Test
	public void declinesOnADecodeFailureMidRun() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(
			Map.of(slot(9), run(false, false, slot(9) + 6, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertFalse(r.isBounded());
	}

	/** A real table whose bytes happen to decode, but without two outside calls: no cut. */
	@Test
	public void aRealHandlerTableThatMerelyDecodesDoesNotFire() {
		Map<Long, CodeRun> runs = new java.util.HashMap<>();
		for (int k = 2; k < 32; k++) {
			runs.put(slot(k), run(true, false, slot(k) + 64)); // legal run, no calls at all
		}
		assertFalse(JumpTableBound.boundBySlotCode(targets(32), table(32), probe(runs))
				.isBounded());
	}

	@Test
	public void neverCutsBeforeSlotTwo() {
		Result r = JumpTableBound.boundBySlotCode(targets(32), table(32), probe(
			Map.of(slot(1), run(true, true, slot(1) + 8, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertFalse(r.isBounded());
	}

	@Test
	public void declinesForAByteTable() {
		Result r = JumpTableBound.boundBySlotCode(targets(32),
			List.of(new LoadTableEntry(TABLE, 1, 32)), probe(
				Map.of(slot(9), run(true, true, slot(9) + 8, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertFalse(r.isBounded());
	}

	/** The decompiler can describe a word table as 2n byte loads (dragonpower 803e). */
	@Test
	public void firesOnAWordTableDescribedAsBytes() {
		Result r = JumpTableBound.boundBySlotCode(targets(32),
			List.of(new LoadTableEntry(TABLE, 1, 64)), probe(
				Map.of(slot(9), run(true, true, slot(9) + 8, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertEquals(9, r.count());
	}

	@Test
	public void leadingDropsTheSlotsOfATerminatedRunFromSlotZero() {
		JumpTableBound.Leading l = JumpTableBound.leadingBySlotCode(targets(20), table(20),
			probe(Map.of(TABLE, run(true, true, TABLE + 8, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertEquals(LeadingRule.SLOT_CODE, l.rule());
		assertEquals(4, l.drop());
	}

	@Test
	public void leadingIgnoresARunThatOnlyHitTheStepCap() {
		JumpTableBound.Leading l = JumpTableBound.leadingBySlotCode(targets(20), table(20),
			probe(Map.of(TABLE, run(true, false, TABLE + 8, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertFalse(l.applies());
	}

	@Test
	public void leadingIgnoresARunEndingMidSlot() {
		JumpTableBound.Leading l = JumpTableBound.leadingBySlotCode(targets(20), table(20),
			probe(Map.of(TABLE, run(true, true, TABLE + 7, 0x99fbL, 0x988bL, 0x9a1cL))));
		assertFalse(l.applies());
	}
}
