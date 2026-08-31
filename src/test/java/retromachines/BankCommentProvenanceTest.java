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

import org.junit.Test;

import retromachines.BankCommentProvenance.Plan;

/**
 * Pure-JUnit coverage of {@link BankCommentProvenance}'s decision rule (bead grm-3mg0) -- the
 * whole of what makes a bank comment retractable and refreshable without ever cutting into text
 * a human wrote. Imports nothing from {@code ghidra.*}: {@code plan} and {@code removeSegment}
 * are static and take only strings, which is why they were written that way (same discipline as
 * {@link BankWrapCanonicalizationTest} and {@link ImpossibleBankInAllLayoutsTest}).
 * <p>
 * <b>The defect being fixed.</b> {@link AnnotationGuard#addComment} is append-only and
 * idempotent on a marker substring, so once any round leaves a {@code bank ->} comment at an
 * address every later round is a no-op there -- first-writer-wins. A round that would write
 * nothing leaves a stale attribution standing ({@code nesskiptest} c00c keeps
 * {@code via FUN_c170} from a pre-repair round), and a round that would write BETTER text cannot
 * replace a stale partial. Both make the output depend on the sequence of analysis rounds
 * instead of on the final program state.
 */
public class BankCommentProvenanceTest {

	private static final String MARKER = "bank ->";

	private static final String OURS = "bank -> 2 (bank=2) via FUN_c170";
	private static final String REFRESHED = "bank -> 2 (bank=2) via FUN_c173";
	private static final String USER = "loop counter, see $c150";

	// ------------------------------------------------------------------
	// The write-free settled case -- a correctness requirement, not an optimization
	// ------------------------------------------------------------------

	/**
	 * A round that recomputes exactly what is already there must perform NO write. The
	 * redundant-re-run gate in {@code BoardBankAnalyzer} compares a stored stamp against
	 * {@code getModificationNumber()}, and its own comment warns that a path mutating when it
	 * should not degrades the gate to "hit, miss, hit, miss".
	 */
	@Test
	public void recomputingTheSameTextWritesNothing() {
		assertEquals(Plan.UNCHANGED, BankCommentProvenance.plan(OURS, OURS, OURS, MARKER));
	}

	/** Same, with the user's text alongside ours: still settled, still write-free. */
	@Test
	public void recomputingTheSameTextBesideUserTextWritesNothing() {
		assertEquals(Plan.UNCHANGED,
			BankCommentProvenance.plan(OURS, USER + "; " + OURS, OURS, MARKER));
	}

	// ------------------------------------------------------------------
	// Refresh: the half the bead does not mention
	// ------------------------------------------------------------------

	/**
	 * A later round computing DIFFERENT text replaces ours. Under the old append-only rule the
	 * marker made this a silent no-op, freezing round 1's attribution forever.
	 */
	@Test
	public void aLaterRoundReplacesItsOwnEarlierText() {
		Plan plan = BankCommentProvenance.plan(OURS, OURS, REFRESHED, MARKER);
		assertTrue(plan.write());
		assertEquals(REFRESHED, plan.comment());
		assertEquals(REFRESHED, plan.record());
	}

	/** Replacing ours must leave the user's text exactly where it was, verbatim. */
	@Test
	public void refreshPreservesUserTextAndItsPosition() {
		Plan plan = BankCommentProvenance.plan(OURS, USER + "; " + OURS, REFRESHED, MARKER);
		assertTrue(plan.write());
		assertEquals(USER + "; " + REFRESHED, plan.comment());
	}

	/** Ours first, user's second: the user's half still survives and stays second. */
	@Test
	public void refreshPreservesUserTextWrittenAfterOurs() {
		Plan plan = BankCommentProvenance.plan(OURS, OURS + "; " + USER, REFRESHED, MARKER);
		assertTrue(plan.write());
		assertEquals(USER + "; " + REFRESHED, plan.comment());
	}

	// ------------------------------------------------------------------
	// First write
	// ------------------------------------------------------------------

	/** Nothing recorded and no comment: plain set. */
	@Test
	public void firstWriteOnAnEmptyCommentJustSets() {
		Plan plan = BankCommentProvenance.plan(null, null, OURS, MARKER);
		assertTrue(plan.write());
		assertEquals(OURS, plan.comment());
	}

	/** Nothing recorded but a user comment present: append, never replace. */
	@Test
	public void firstWriteAppendsToUserText() {
		Plan plan = BankCommentProvenance.plan(null, USER, OURS, MARKER);
		assertTrue(plan.write());
		assertEquals(USER + "; " + OURS, plan.comment());
	}

	/** A blank existing comment counts as empty, not as text worth preserving. */
	@Test
	public void blankExistingCommentIsTreatedAsAbsent() {
		Plan plan = BankCommentProvenance.plan(null, "   ", OURS, MARKER);
		assertTrue(plan.write());
		assertEquals(OURS, plan.comment());
	}

	// ------------------------------------------------------------------
	// Failing safe when the record and the listing disagree
	// ------------------------------------------------------------------

	/**
	 * THE CASE THE PROPERTY MAP EXISTS FOR. A human typed something starting with our marker.
	 * Nothing is recorded, so it is theirs -- and the marker rule defers to it rather than
	 * stacking beside it, exactly as before. A segment-matching implementation without a
	 * provenance record would have deleted this, which is the hazard AnnotationGuard's whole
	 * class javadoc is about.
	 */
	@Test
	public void aUserCommentThatLooksLikeOursIsNeverTouched() {
		Plan plan = BankCommentProvenance.plan(null, "bank -> 5 (I checked this by hand)", OURS,
			MARKER);
		assertFalse(plan.write());
		assertNull(plan.comment());
	}

	/**
	 * We recorded writing here, but the text is gone -- a human edited or deleted it. Touch
	 * nothing and do not re-add: their edit is the more recent statement about this address.
	 */
	@Test
	public void ourRecordedTextHavingVanishedMeansHandsOff() {
		Plan plan = BankCommentProvenance.plan(OURS, "actually this is the sound driver",
			REFRESHED, MARKER);
		assertFalse(plan.write());
		assertNull(plan.comment());
	}

	/** A human editing our text mid-string counts as vanished, not as a partial match. */
	@Test
	public void aHumanEditOfOurTextCountsAsVanished() {
		Plan plan =
			BankCommentProvenance.plan(OURS, OURS + " -- WRONG, it is bank 3", REFRESHED, MARKER);
		assertFalse(plan.write());
	}

	// ------------------------------------------------------------------
	// Deferral between the two bank-comment writers
	// ------------------------------------------------------------------

	/**
	 * {@code annotatePlacementProvenance} defers to a bank-switch annotation written earlier in
	 * the SAME round, which both writers express by sharing one marker. Preserved here: with
	 * nothing recorded and a marker already present, we decline.
	 */
	@Test
	public void aSecondWriterInTheSameRoundDefersToTheFirst() {
		Plan plan = BankCommentProvenance.plan(null, OURS, "bank -> 4 [user override]", MARKER);
		assertFalse(plan.write());
	}

	// ------------------------------------------------------------------
	// Segment removal is whole-segment, never substring
	// ------------------------------------------------------------------

	/** Removing the only segment leaves nothing. */
	@Test
	public void removingTheSoleSegmentLeavesEmpty() {
		assertEquals("", BankCommentProvenance.removeSegment(OURS, OURS));
	}

	/** Removal works at either end and in the middle, rejoining cleanly each time. */
	@Test
	public void removalWorksAtEveryPosition() {
		assertEquals("a; b",
			BankCommentProvenance.removeSegment(OURS + "; a; b", OURS));
		assertEquals("a; b",
			BankCommentProvenance.removeSegment("a; b; " + OURS, OURS));
		assertEquals("a; b",
			BankCommentProvenance.removeSegment("a; " + OURS + "; b", OURS));
	}

	/**
	 * A recorded text that appears only INSIDE a longer segment is not a match. Whole-segment
	 * equality is what keeps a human quoting our annotation in a sentence from being cut apart.
	 */
	@Test
	public void aSubstringOccurrenceIsNotASegment() {
		assertNull(BankCommentProvenance.removeSegment("see \"" + OURS + "\" above", OURS));
	}

	/** Absent, null and empty inputs all report "not found" rather than throwing. */
	@Test
	public void missingOrDegenerateInputsReportNotFound() {
		assertNull(BankCommentProvenance.removeSegment("a; b", OURS));
		assertNull(BankCommentProvenance.removeSegment(null, OURS));
		assertNull(BankCommentProvenance.removeSegment(OURS, null));
		assertNull(BankCommentProvenance.removeSegment(OURS, ""));
	}

	/**
	 * Only the FIRST matching segment is removed. Two identical segments should not both
	 * disappear on one call -- we recorded writing one, so we retract one.
	 */
	@Test
	public void onlyOneOccurrenceIsRemoved() {
		assertEquals(OURS, BankCommentProvenance.removeSegment(OURS + "; " + OURS, OURS));
	}
}
