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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.LongUnaryOperator;

import org.junit.Test;

import retromachines.JumpTableBound.Leading;
import retromachines.JumpTableBound.LeadingRule;
import retromachines.JumpTableBound.LoadTableEntry;

/**
 * Pure-logic tests for the leading (start-side) trim rules of {@link JumpTableBound}
 * (grm-c9d.8.3). Each mirrors the tail rule it is the two-ended form of; see
 * {@link JumpTableBoundTest} for those. Views are {@code (start, perEntryBytes, keptCount)}.
 */
public class JumpTableBoundLeadingTest {

	private static List<Long> targets(long... values) {
		List<Long> list = new ArrayList<>();
		for (long v : values) {
			list.add(v);
		}
		return list;
	}

	private static List<Boolean> flags(boolean... values) {
		List<Boolean> list = new ArrayList<>();
		for (boolean v : values) {
			list.add(v);
		}
		return list;
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

	// ---- rule 1: extent overlap -------------------------------------------------------------

	/** The SMW 0d44 shape in miniature: the first slots are bytes of the handlers the later (real)
	 *  slots point at. 4 of 8 slots lie inside handler 2000's extent. */
	@Test
	public void extentDropsTheSlotsInsideKeptHandlers() {
		List<Long> t = targets(0x9000, 0x9100, 0x9200, 0x9300, 0x2000, 0x2020, 0x2100, 0x2200);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 8));
		Leading l = JumpTableBound.leadingByExtent(t, view, extents(0x2000, 0x2008));
		assertTrue(l.applies());
		assertEquals(LeadingRule.EXTENT_OVERLAP, l.rule());
		assertEquals(4, l.drop());
	}

	/** A junk early target whose decoded extent covers real slots costs the junk, not the slots. */
	@Test
	public void extentDropsTheLowerIndexedSideOfAPair() {
		List<Long> t = targets(0x2000, 0x2100, 0x2200, 0x2300, 0x2400, 0x2500);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 6));
		// target 0 decodes through the whole table: every slot but 0 is inside it; each pair
		// (i, 0) drops min(i, 0) + 1 = 1
		Leading l = JumpTableBound.leadingByExtent(t, view, extents(0x2000, 0x2100));
		assertEquals(1, l.drop());
	}

	@Test
	public void extentDeclinesWithoutAnOverlapOrWithTooFewLeft() {
		List<Long> t = targets(0x2100, 0x2200, 0x2300, 0x2400);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 4));
		assertFalse(JumpTableBound.leadingByExtent(t, view, extents()).applies());
		// slots 0..2 inside the last handler: only one slot would stay
		List<Long> t2 = targets(0x9000, 0x9100, 0x9200, 0x2000);
		assertFalse(JumpTableBound.leadingByExtent(t2, view, extents(0x2000, 0x2007)).applies());
		// a shape no rule understands (num does not divide): decline
		assertFalse(JumpTableBound.leadingByExtent(t, List.of(new LoadTableEntry(0x2000, 1, 1)),
			extents()).applies());
	}

	/** megaman c847 (real-ROM sweep): the last handler falls through (BPL/BMI pair) into the table
	 *  after it, so its linear extent covers the table. A handler starting BELOW the table is the
	 *  table-after-code layout, not an overlap. */
	@Test
	public void extentIgnoresHandlersThatRunOnIntoTheTableFromBelow() {
		List<Long> t = targets(0xc84a, 0xc855, 0xc859, 0xc85d, 0xc861, 0xc866, 0xc873, 0xc883,
			0xc88b, 0xc893);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0xc89e, 2, 10));
		assertFalse(JumpTableBound.leadingByExtent(t, view, extents(0xc883, 0xc8c0)).applies());
	}

	// ---- rule 7: known code of other tables ---------------------------------------------------

	@Test
	public void knownCodeDropsSlotsInsideAnotherTablesHandler() {
		List<Long> t = new ArrayList<>(Collections.nCopies(12, 0x9000L));
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 12));
		// foreign handler 2004..2010 covers slots 2..7 of a 12-slot table
		Leading l = JumpTableBound.leadingByKnownCode(t, view, List.of(0x2004L), extents(0x2004, 0x2010));
		assertEquals(LeadingRule.KNOWN_CODE_OVERLAP, l.rule());
		assertEquals(8, l.drop());
	}

	@Test
	public void knownCodeSkipsSharedHandlersAndDeclinesShort() {
		List<Long> t = targets(0x9000, 0x2004, 0x9200, 0x9300);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 4));
		// 2004 is also one of this table's own targets: not foreign
		assertFalse(JumpTableBound.leadingByKnownCode(t, view, List.of(0x2004L),
			extents(0x2004, 0x2010)).applies());
		assertFalse(JumpTableBound.leadingByKnownCode(t, view, List.of(0x2002L),
			extents(0x2002, 0x2005)).applies()); // slots 1..2 are the handler's: only 1 would stay
	}

	// ---- rule 2: below table (mirror of grm-fxtp) --------------------------------------------

	private static final JumpTableBound.Block PRG = new JumpTableBound.Block(0x8000, 0xffff);

	/** lwings dcaf mirrored: out-of-block garbage first, then the table's real handlers above it. */
	@Test
	public void belowTableCutsALeadingRunOutsideTheBlock() {
		List<Long> t = targets(0x1000, 0x2000, 0x9100, 0x9200, 0x9300, 0x9400);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x9000, 2, 6));
		Leading l = JumpTableBound.leadingByBelowTable(t, view, PRG);
		assertEquals(LeadingRule.BELOW_TABLE, l.rule());
		assertEquals(2, l.drop());
	}

	@Test
	public void belowTableGuardsMirrorTheTailRule() {
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x9000, 2, 6));
		// confirm: an in-block entry above the table sits before the cut
		assertFalse(JumpTableBound.leadingByBelowTable(
			targets(0x9100, 0x2000, 0x9100, 0x9200, 0x9300, 0x9400), view, PRG).applies());
		// same-block: a kept entry outside the block
		assertFalse(JumpTableBound.leadingByBelowTable(
			targets(0x1000, 0x2000, 0x9100, 0x9200, 0x3000, 0x9400), view, PRG).applies());
		// block unknown disables it, as for the tail rule
		assertFalse(JumpTableBound.leadingByBelowTable(
			targets(0x1000, 0x2000, 0x9100, 0x9200, 0x9300, 0x9400), view, null).applies());
		// the last entry must be above the table (the idiom's anchor)
		assertFalse(JumpTableBound.leadingByBelowTable(
			targets(0x1000, 0x2000, 0x9100, 0x9200, 0x9300, 0x1400), view, PRG).applies());
		// grm-rsxe: an in-block handler below the table is skipped, not cut
		assertFalse(JumpTableBound.leadingByBelowTable(
			targets(0x8100, 0x8200, 0x9100, 0x9200, 0x9300, 0x9400), view, PRG).applies());
	}

	// ---- rule 3: switch window ---------------------------------------------------------------

	/** megaman e000 mirrored: strays first (the switchable window, RAM), real handlers after. */
	@Test
	public void windowCutsALeadingRunOutsideIt() {
		List<Long> t = targets(0xa1ad, 0xf006, 0xe003, 0xe06f, 0xe076, 0xe065);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0xe0ed, 1, 12));
		Leading l = JumpTableBound.leadingBySwitchWindow(0xe000, t, view);
		assertEquals(LeadingRule.SWITCH_WINDOW, l.rule());
		assertEquals(2, l.drop());
	}

	@Test
	public void windowDeclinesOtherLayoutsAndAmbiguousCuts() {
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0xe0ed, 1, 12));
		// the table comes back into the window before the cut
		assertFalse(JumpTableBound.leadingBySwitchWindow(0xe000,
			targets(0xe010, 0xa1ad, 0xe003, 0xe06f, 0xe076, 0xe065), view).applies());
		// last entry outside the window: no anchor
		assertFalse(JumpTableBound.leadingBySwitchWindow(0xe000,
			targets(0xa1ad, 0xf006, 0xe003, 0xe06f, 0xe076, 0x1234), view).applies());
		// table before the switch
		assertFalse(JumpTableBound.leadingBySwitchWindow(0xf000,
			targets(0xa1ad, 0xf006, 0xe003, 0xe06f, 0xe076, 0xe065), view).applies());
	}

	// ---- rule 5: valid targets (mirror of grm-yjiq) ------------------------------------------

	@Test
	public void validTargetCutsALeadingRunThatCannotBeCode() {
		List<Long> t = targets(0x2120, 0x2725, 0x11a9, 0x8160, 0x9b05, 0x919d, 0x8d61);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x9aeb, 2, 7));
		Leading l = JumpTableBound.leadingByValidTargets(t, view,
			flags(false, false, false, true, true, true, true));
		assertEquals(LeadingRule.VALID_TARGET, l.rule());
		assertEquals(3, l.drop());
	}

	@Test
	public void validTargetDeclines() {
		List<Long> t = targets(1, 2, 3, 4, 5, 6);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x9000, 2, 6));
		assertFalse(JumpTableBound.leadingByValidTargets(t, view,
			flags(true, true, true, true, true, true)).applies());
		// a plausible entry before the failing one: ambiguous
		assertFalse(JumpTableBound.leadingByValidTargets(t, view,
			flags(true, false, false, true, true, true)).applies());
		// fewer than 2 would stay
		assertFalse(JumpTableBound.leadingByValidTargets(t, view,
			flags(false, false, false, false, false, true)).applies());
	}

	// ---- rule 6: neighbour end (mirror of grm-2m07) ------------------------------------------

	/** dbz2 mirrored: the previous table ends 10 bytes into this one. */
	@Test
	public void neighbourEndCutsWhereTheOtherTableEnds() {
		List<Long> t = new ArrayList<>(Collections.nCopies(20, 0xc800L));
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0xdd47, 2, 20));
		List<Boolean> inCode = new ArrayList<>(Collections.nCopies(20, true));
		Leading l = JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L + 10), inCode);
		assertEquals(LeadingRule.NEIGHBOUR_END, l.rule());
		assertEquals(5, l.drop());
		// the last end inside the extent wins
		assertEquals(8, JumpTableBound.leadingByNeighbourEnd(t, view,
			List.of(0xdd47L + 10, 0xdd47L + 16), inCode).drop());
	}

	@Test
	public void neighbourEndDeclines() {
		List<Long> t = new ArrayList<>(Collections.nCopies(20, 0xc800L));
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0xdd47, 2, 20));
		List<Boolean> inCode = new ArrayList<>(Collections.nCopies(20, true));
		// off an entry boundary, at the own start, at the own end, past the extent
		assertFalse(JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L + 9), inCode).applies());
		assertFalse(JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L), inCode).applies());
		assertFalse(JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L + 40), inCode).applies());
		assertFalse(JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L + 80), inCode).applies());
		// a kept entry that cannot be code
		List<Boolean> bad = new ArrayList<>(inCode);
		bad.set(12, false);
		assertFalse(JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L + 10), bad).applies());
		// fewer than 2 entries would stay
		assertFalse(JumpTableBound.leadingByNeighbourEnd(t, view, List.of(0xdd47L + 38), inCode).applies());
	}

	// ---- rule 8: code prefix (mirror of grm-0pen) --------------------------------------------

	@Test
	public void leadingCodePrefixDropsTheLeadingNonDecodingRun() {
		Leading l = JumpTableBound.leadingByCodePrefix(
			flags(false, false, false, true, true, true, true, true, true, true));
		assertEquals(LeadingRule.CODE_PREFIX, l.rule());
		assertEquals(3, l.drop());
	}

	@Test
	public void leadingCodePrefixNeedsTheCutConfirmed() {
		// failure at 3, entry 2 decodes again: ambiguous, only the leading non-decoding run goes
		assertEquals(1, JumpTableBound.leadingByCodePrefix(
			flags(false, true, true, false, true, true, true)).drop());
		// confirmed: both entries before the failure fail too
		assertEquals(4, JumpTableBound.leadingByCodePrefix(
			flags(true, false, false, false, true, true, true)).drop());
	}

	@Test
	public void leadingCodePrefixLeavesShortRunsAndFullTablesAlone() {
		assertFalse(JumpTableBound.leadingByCodePrefix(flags(false, false, false, true)).applies());
		assertFalse(JumpTableBound.leadingByCodePrefix(flags(true, true, true)).applies());
		assertFalse(JumpTableBound.leadingByCodePrefix(flags(true, false, true, true)).applies());
		assertFalse(JumpTableBound.leadingByCodePrefix(flags()).applies());
	}

	// ---- rule 10: distinct words -------------------------------------------------------------

	@Test
	public void distinctWordsLeadingFormIsRuleOneOverTheWords() {
		List<Long> words = targets(0x9000, 0x9100, 0x2000, 0x2020, 0x2100, 0x2200);
		Leading l = JumpTableBound.leadingByDistinctWords(words, 0x2000, 6,
			extents(0x2000, 0x2004));
		assertEquals(LeadingRule.DISTINCT_WORDS_EXTENT, l.rule());
		assertEquals(2, l.drop());
		assertFalse(JumpTableBound.leadingByDistinctWords(words, 0x2000, 1, extents()).applies());
	}

	// ---- the view ---------------------------------------------------------------------------

	@Test
	public void viewDescribesTheKeptEntries() {
		// megaman shape: one interleaved size-1 table of 256 bytes over 128 cases, 8 kept
		List<LoadTableEntry> v = JumpTableBound.leadingView(128, List.of(new LoadTableEntry(0xa737, 1, 256)),
			8, 1, 0);
		assertEquals(1, v.size());
		assertEquals(2, v.get(0).entrySize());
		assertEquals(8, v.get(0).num());
		assertEquals(0xa737 + 16, JumpTableBound.viewEnd(v));
		// fixed loads are not part of the table
		assertEquals(1, JumpTableBound.leadingView(128, List.of(new LoadTableEntry(0xa737, 1, 256),
			new LoadTableEntry(0x10, 1, 1)), 8, 1, 0).size());
		// overlapping byte table: even cases as 2-byte entries
		List<LoadTableEntry> ov = JumpTableBound.leadingView(25, List.of(new LoadTableEntry(0x9aeb, 1, 26)),
			11, 2, 0);
		assertEquals(2, ov.get(0).entrySize());
		assertEquals(11, ov.get(0).num());
		// planar: both halves
		List<LoadTableEntry> pl = JumpTableBound.leadingView(30, List.of(new LoadTableEntry(0x8254, 1, 54)),
			8, 1, 24);
		assertEquals(2, pl.size());
		assertEquals(0x8254 + 24, pl.get(1).start());
		// not divisible: no view
		assertNull(JumpTableBound.leadingView(7, List.of(new LoadTableEntry(0x8000, 1, 10)), 4, 1, 0));
	}

	// ---- the cascade and the checks ---------------------------------------------------------

	@Test
	public void checksReportEachRuleAndTheCascade() {
		// 4 junk slots inside the real handlers' extent, then real handlers inside the window
		List<Long> t = targets(0x9000, 0x9100, 0x9200, 0x9300, 0x2000, 0x2020, 0x2100, 0x2200);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 8));
		JumpTableBound.LeadingFacts f = new JumpTableBound.LeadingFacts(0x1f00, null,
			extents(0x2000, 0x2008), null, null, null, flags(false, false, false, true, true, true,
				true, true), false, JumpTableBound.Rule.LOWEST_TARGET);
		List<Leading> out = JumpTableBound.leadingChecks(t, view, f);
		assertEquals(LeadingRule.EXTENT_OVERLAP, out.get(0).rule());
		assertEquals(4, out.get(0).drop());
		assertEquals(LeadingRule.CODE_PREFIX, out.get(1).rule());
		assertEquals(3, out.get(1).drop());
		// cascade: extent drops 4 (slots 0..3), the code prefix then has nothing left to drop
		Leading cascade = out.get(out.size() - 1);
		assertEquals(LeadingRule.CASCADE, cascade.rule());
		assertEquals(4, cascade.drop());
	}

	/** A leading form runs only where its tail rule would: dodge 810d, bounded by the lowest-target
	 *  rule with handlers on both sides of the table, must not be window-cut. */
	@Test
	public void leadingFormsAreGatedOnTheTailRule() {
		List<Long> t = targets(0x9100, 0x9200, 0x9300, 0x9400, 0x8010, 0x8020);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x8100, 2, 6));
		JumpTableBound.LeadingFacts none = new JumpTableBound.LeadingFacts(0x8000, null, null, null,
			null, null, null, false, null);
		assertEquals(LeadingRule.SWITCH_WINDOW, JumpTableBound.leadingChecks(t, view, none).get(0).rule());
		JumpTableBound.LeadingFacts lowest = new JumpTableBound.LeadingFacts(0x8000, null, null,
			null, null, null, null, false, JumpTableBound.Rule.LOWEST_TARGET);
		assertTrue(JumpTableBound.leadingChecks(t, view, lowest).isEmpty());
	}

	/** An unbounded table has no tail-verified end to anchor the extent forms on: dragonpower 803e
	 *  is 35 real entries, then its own handlers, then junk -- dropping the front would keep the junk. */
	@Test
	public void extentFormsNeedABoundedTable() {
		List<Long> t = targets(0x9000, 0x9100, 0x9200, 0x9300, 0x2000, 0x2020, 0x2100, 0x2200);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 8));
		JumpTableBound.LeadingFacts f = new JumpTableBound.LeadingFacts(0x1f00, null,
			extents(0x2000, 0x2008), List.of(0x2000L), null, null, null, false, null);
		List<Leading> out = JumpTableBound.leadingChecks(t, view, f);
		assertEquals(1, out.size()); // reported, but outside the cascade
		assertEquals(LeadingRule.EXTENT_OVERLAP_UNANCHORED, out.get(0).rule());
		assertEquals(4, out.get(0).drop());
	}

	@Test
	public void checksSayNothingWhenNothingApplies() {
		List<Long> t = targets(0x2100, 0x2200, 0x2300, 0x2400);
		List<LoadTableEntry> view = List.of(new LoadTableEntry(0x2000, 2, 4));
		JumpTableBound.LeadingFacts f = new JumpTableBound.LeadingFacts(0x1f00, PRG, extents(), List.of(),
			List.of(), flags(true, true, true, true), flags(true, true, true, true), false, null);
		assertTrue(JumpTableBound.leadingChecks(t, view, f).isEmpty());
	}
}
