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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * Pure-logic tests for {@link W65816JumpTables} (grm-9nxj.5.4). Shapes are taken from the
 * real-ROM tables the bound was measured on.
 */
public class W65816JumpTablesTest {

	private static int bound(long start, int cap, int[] words, List<Long> out) {
		return W65816JumpTables.bound(start, cap, i -> i < words.length ? words[i] : null,
			b -> true, t -> true, out);
	}

	/** FF3 $C2:0F47: thirteen handlers start right after the table; the walk stops there. */
	@Test
	public void stopsAtItsOwnLowestTarget() {
		int[] words = { 0x0f67, 0x0f61, 0x0f68, 0x0f6f, 0x0f61, 0x0f67, 0x0f6b, 0x0f67, 0x0f68,
			0x0f64, 0x0f67, 0x0f67, 0x0f68, 0x7420, 0x9c0f };
		List<Long> out = new ArrayList<>();
		assertEquals(13, bound(0xc20f47L, 128, words, out));
		assertEquals(0xc20f67L, (long) out.get(0));
	}

	/** Targets below the table never bound it; the cap does. */
	@Test
	public void targetsBelowTheTableLeaveTheCap() {
		int[] words = { 0x469b, 0x45a3, 0x469b, 0x45cb, 0x45df, 0x460b };
		assertEquals(4, bound(0xc246b0L, 4, words, new ArrayList<>()));
		assertEquals(6, bound(0xc246b0L, 128, words, new ArrayList<>()));
	}

	@Test
	public void anEntryPointingIntoTheTableEndsIt() {
		int[] words = { 0x9000, 0x8002, 0x9010 };
		assertEquals(1, bound(0x008000L, 128, words, new ArrayList<>()));
	}

	@Test
	public void takenBytesAndImplausibleTargetsEndIt() {
		List<Long> out = new ArrayList<>();
		int n = W65816JumpTables.bound(0x008000L, 128, i -> 0x9000 + i,
			b -> b < 0x008006L, t -> true, out);
		assertEquals(3, n);
		n = W65816JumpTables.bound(0x008000L, 128, i -> 0x9000 + i, b -> true,
			t -> t != 0x009002L, new ArrayList<>());
		assertEquals(2, n);
	}

	@Test
	public void neverWrapsPastTheBank() {
		assertEquals(2, bound(0x00fffcL, 128, new int[] { 0x8000, 0x8000, 0x8000 },
			new ArrayList<>()));
	}

	/**
	 * grm-gipk.11's same-half term (RTS trick only): Madden '94 {@code $C5:A748} runs from its
	 * {@code $82xx-$A5xx} handlers into a following table pointing into the low half.
	 */
	@Test
	public void sameHalfEndsAtTheOtherHalf() {
		int[] words = { 0x8210, 0xa5f0, 0x22b6, 0x2340 };
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0xc5a748L,
			0xc50000L, 128, true, i -> i < words.length ? words[i] : null, b -> true, t -> true);
		assertEquals(2, r.count());
		assertEquals(W65816JumpTables.End.OTHER_HALF, r.endedBy());
		r = W65816JumpTables.score(0xc5a748L, 0xc50000L, 128, false,
			i -> i < words.length ? words[i] : null, b -> true, t -> true);
		assertEquals(4, r.count());
		assertEquals(W65816JumpTables.End.UNREADABLE, r.endedBy());
	}

	private static TableScorer.Result<Long, W65816JumpTables.End> zeroWalk(boolean sameHalf,
			int[] words) {
		return W65816JumpTables.score(0x00e2e6L, 0x000000L, 128, sameHalf, true,
			i -> i < words.length ? words[i] : null, b -> true, t -> (t & 0xffff) != 0,
			i -> null);
	}

	/** grm-8lr2: a zero word between real entries is a placeholder, and the walk goes on. */
	@Test
	public void aZeroWordInTheMiddleIsAPlaceholder() {
		TableScorer.Result<Long, W65816JumpTables.End> r = zeroWalk(false,
			new int[] { 0xe400, 0, 0xe410, 0xe420 });
		assertEquals(4, r.count());
		assertEquals(W65816JumpTables.UNUSED_ENTRY, (long) r.targets().get(1));
		assertEquals(1, W65816JumpTables.unusedCount(r.targets()));
	}

	@Test
	public void trailingPlaceholdersAreTrimmed() {
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.trimUnused(
			zeroWalk(false, new int[] { 0xe400, 0xe410, 0, 0 }));
		assertEquals(2, r.count());
		assertEquals(2, r.scores().size());
	}

	@Test
	public void threeZerosInARowEndTheTableBeforeThem() {
		TableScorer.Result<Long, W65816JumpTables.End> r = zeroWalk(false,
			new int[] { 0xe400, 0xe410, 0, 0, 0, 0xe420 });
		assertEquals(4, r.count());   // the two allowed placeholders; trimUnused drops them
		assertEquals(W65816JumpTables.End.UNUSED_SLOT, r.endedBy());
		assertEquals(2, W65816JumpTables.trimUnused(r).count());
	}

	@Test
	public void aFirstZeroWordStillEndsTheTableAtOnce() {
		TableScorer.Result<Long, W65816JumpTables.End> r = zeroWalk(false,
			new int[] { 0, 0xe410, 0xe420 });
		assertEquals(0, r.count());
		assertEquals(W65816JumpTables.End.IMPLAUSIBLE, r.endedBy());
	}

	/** Where $xx:0000 is a plausible target (HiROM ROM) a zero run is not cut: FF3 $C0:7807. */
	@Test
	public void whereZeroIsPlausibleZerosArePlaceholdersWithNoRunLimit() {
		// grm-gipk.16.10: HiROM, $C0:0000 is ROM. FF3 $C0:7807's real zero runs of 4 are kept,
		// but as placeholders, not as flows to $C0:0000; trailing zeros still go.
		int[] words = { 0xe400, 0, 0, 0, 0, 0xe410, 0, 0 };
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.trimUnused(
			W65816JumpTables.score(0xc07807L, 0xc00000L, 128, false, true,
				i -> i < words.length ? words[i] : null, b -> true, t -> true, i -> null));
		assertEquals(6, r.count());
		assertEquals(4, W65816JumpTables.unusedCount(r.targets()));
		assertEquals(false, r.targets().contains(0xc00000L));
	}

	/** A placeholder still ends the table at a strong outside reference to its position. */
	@Test
	public void aReferencedPlaceholderPositionEndsTheTable() {
		int[] words = { 0xe400, 0, 0xe410 };
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0xc07807L,
			0xc00000L, 128, false, true, i -> i < words.length ? words[i] : null, b -> true,
			t -> true, i -> i == 1 ? new EntryReferences.Hit(true, "test") : null);
		assertEquals(1, r.count());
		assertEquals(W65816JumpTables.End.ENTRY_REFERENCED, r.endedBy());
	}

	/** Without the opt-in (the RTS trick's call), a zero word is still target $xx:0000. */
	@Test
	public void withoutTheOptInAZeroWordStillEndsIt() {
		int[] words = { 0xe400, 0, 0xe410 };
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0x00e2e6L,
			0x000000L, 128, true, i -> i < words.length ? words[i] : null, b -> true,
			t -> (t & 0xffff) != 0);
		assertEquals(1, r.count());
		assertEquals(W65816JumpTables.End.IMPLAUSIBLE, r.endedBy());
	}

	private static TableScorer.Result<Long, W65816JumpTables.End> rtsTrick(long start,
			int[] words) {
		return W65816JumpTables.score(start, start & 0xff0000L, 256, true,
			i -> i < words.length ? words[i] : null, b -> true, t -> true);
	}

	/** grm-gipk.16.4: a HiROM table whose handlers straddle $8000 resolves in full. */
	@Test
	public void aTableStraddlingTheHalfResolvesInFull() {
		int[] words = { 0x7f00, 0x7f80, 0x8010, 0x8100, 0x7fc0, 0x8240 };
		TableScorer.Result<Long, W65816JumpTables.End> r = rtsTrick(0xc09000L, words);
		assertEquals(6, r.count());
		assertEquals(W65816JumpTables.End.UNREADABLE, r.endedBy());
	}

	private static TableScorer.Result<Long, W65816JumpTables.End> fillerWalk(int[] words) {
		// RTS trick bias +1 is folded in by the caller's words, as W65816RtsTrickAnalyzer does.
		return W65816JumpTables.trimFillerOverrun(W65816JumpTables.score(0xc6b8deL, 0xc60000L, 128, true,
			false, true, i -> i < words.length ? (words[i] + 1) & 0xffff : null, b -> true,
			t -> t != 0xc67ef5L, i -> null));
	}

	/**
	 * grm-gipk.16.12: Madden NFL 95 {@code $C6:B892} (table {@code $C6:B8DE}, bias +1). Thirteen of
	 * its 19 slots are {@code $B8DD}, whose +1 is the table's own first byte: filler, skipped, so the
	 * six real handlers all resolve and none points at {@code $C6:B8DE}.
	 */
	@Test
	public void fillerSlotsAreSkippedNotCuts() {
		int[] words = { 0xb8a7, 0xb892, 0xb89b, 0xb8dd, 0xb8dd, 0xb8dd, 0xb8c5, 0xb8dd, 0xb8b6,
			0xb8dd, 0xb8dd, 0xb8d0, 0xb8dd, 0xb8dd, 0xb8dd, 0xb8dd, 0xb8dd, 0xb8dd, 0xb8dd,
			0x7ef4 };
		TableScorer.Result<Long, W65816JumpTables.End> r = fillerWalk(words);
		assertEquals(19, r.count());
		assertEquals(13, W65816JumpTables.unusedCount(r.targets()));
		assertTrue(!r.targets().contains(0xc6b8deL));
		assertEquals(0xc6b8a8L, (long) r.targets().get(0));
		assertEquals(0xc6b8d1L, (long) r.targets().get(11));
		assertEquals(W65816JumpTables.End.IMPLAUSIBLE, r.endedBy());
	}

	/** A trailing filler run is kept when the walk ends on real evidence; entry 0 is always real. */
	@Test
	public void aTrailingFillerRunIsKeptWhenRealEvidenceEndsTheWalk() {
		int[] words = { 0xb8a7, 0xb892, 0xb8dd, 0xb8dd, 0xb8dd };
		TableScorer.Result<Long, W65816JumpTables.End> r = fillerWalk(words);
		assertEquals(5, r.count());
		assertEquals(3, W65816JumpTables.unusedCount(r.targets()));
	}

	/** Entry 0 pointing at the table, and any OTHER in-table target, keep the hard cut. */
	@Test
	public void otherInTableTargetsStillCutWithFillerOn() {
		assertEquals(0, fillerWalk(new int[] { 0xb8dd, 0xb8a7 }).count());
		TableScorer.Result<Long, W65816JumpTables.End> r =
			fillerWalk(new int[] { 0xb8a7, 0xb8dd, 0xb8e1, 0xb8a7 });
		assertEquals(2, r.count());   // the real entry and the filler between; the cut is at the in-table target
		assertEquals(W65816JumpTables.End.INTO_TABLE, r.endedBy());
	}

	/** A filler run longer than {@link W65816JumpTables#MAX_FILLER_RUN} ends the table before it. */
	@Test
	public void anEndlessFillerRunEndsTheTable() {
		int[] words = new int[40];
		words[0] = 0xb8a7;
		for (int i = 1; i < 40; i++) {
			words[i] = i == 39 ? 0xb8b0 : 0xb8dd;
		}
		TableScorer.Result<Long, W65816JumpTables.End> r = fillerWalk(words);
		assertEquals(1, r.count());
	}

	/** Madden '94 shape, over-read long: the table ends before a sustained far, cross-half run. */
	@Test
	public void aSustainedFarRunEndsTheTable() {
		int[] words = new int[20];
		for (int i = 0; i < 10; i++) {
			words[i] = 0x8210 + 0x0400 * i;   // $8210..$A610
		}
		for (int i = 10; i < 20; i++) {
			words[i] = 0x22b6 + 0x40 * (i - 10);
		}
		TableScorer.Result<Long, W65816JumpTables.End> r = rtsTrick(0xc5a748L, words);
		assertEquals(10, r.count());
		assertEquals(W65816JumpTables.End.OTHER_HALF, r.endedBy());
	}

	/**
	 * Madden NFL 97 {@code $CD:8580}: two far crossing entries and then a far one in the same half;
	 * the last cannot vouch for the two before it, so the table stays at its 8 handlers.
	 */
	@Test
	public void aFarSameHalfEntryDoesNotVouch() {
		int[] words = { 0x85c4, 0x85d0, 0x85ef, 0x85ff, 0x8622, 0x862e, 0x8651, 0x865d, 0x04c0,
			0x7f01, 0xe539 };
		TableScorer.Result<Long, W65816JumpTables.End> r = rtsTrick(0xcd8580L, words);
		assertEquals(8, r.count());
		assertEquals(W65816JumpTables.End.OTHER_HALF, r.endedBy());
	}

	/** A far entry in the table's own half, with no crossing, never ends the table by itself. */
	@Test
	public void aFarSameHalfEntryAloneIsKept() {
		int[] words = { 0x85c4, 0x85d0, 0xe539, 0x85ef };
		assertEquals(4, rtsTrick(0xcd8580L, words).count());
	}

	/** One far entry between good ones is kept: it does not hide the entries after it. */
	@Test
	public void aSingleFarEntryIsKept() {
		int[] words = { 0x8210, 0x8400, 0x22b6, 0x8600, 0x8800 };
		assertEquals(5, rtsTrick(0xc5a748L, words).count());
	}

	/** Each former cut is now named by the term that ended the walk. */
	@Test
	public void theEndingTermIsNamed() {
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0x008000L,
			0x000000L, 128, false, i -> 0x9000 + i, b -> b < 0x008006L, t -> true);
		assertEquals(W65816JumpTables.End.BYTE_TAKEN, r.endedBy());
		r = W65816JumpTables.score(0x008000L, 0x000000L, 3, false, i -> 0x9000 + i, b -> true,
			t -> true);
		assertEquals(3, r.count());
		assertEquals(null, r.endedBy());   // the cap
	}

	/** grm-gipk.16.7: a strong hit at an entry position (i >= 1) is a hard end; entry 0 is not asked. */
	@Test
	public void aReferencedEntryEndsTheTable() {
		int[] words = { 0x9000, 0x9010, 0x9020, 0x9030 };
		var asked = new ArrayList<Integer>();
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0x008000L,
			0x000000L, 128, false, i -> i < words.length ? words[i] : null, b -> true, t -> true,
			i -> {
				asked.add(i);
				return i == 0 || i == 2 ? new EntryReferences.Hit(true, "from 00a000 (DATA)") : null;
			});
		assertEquals(2, r.count());
		assertEquals(W65816JumpTables.End.ENTRY_REFERENCED, r.endedBy());
		assertEquals(List.of(1, 2), asked);
	}

	/** A label-only hit is soft: no end under the hard-only policy, and the sameHalf run policy
	 *  does not read 0.5 as doubt. */
	@Test
	public void aLabelledEntryIsKept() {
		int[] words = { 0x9000, 0x9010, 0x9020 };
		for (boolean sameHalf : new boolean[] { false, true }) {
			TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0x008000L,
				0x000000L, 128, sameHalf, i -> i < words.length ? words[i] : null, b -> true,
				t -> true, i -> new EntryReferences.Hit(false, "from x (label)"));
			assertEquals(3, r.count());
		}
	}

	/** An earlier hard check keeps its own name where both apply. */
	@Test
	public void existingHardChecksKeepTheirReason() {
		int[] words = { 0x9000, 0x9010 };
		TableScorer.Result<Long, W65816JumpTables.End> r = W65816JumpTables.score(0x008000L,
			0x000000L, 128, false, i -> i < words.length ? words[i] : null, b -> true, t -> true,
			i -> i == 2 ? new EntryReferences.Hit(true, "x") : null);
		assertEquals(W65816JumpTables.End.UNREADABLE, r.endedBy());
	}

	/** FF3 $C2:1B02: AND #$0F / ASL A / TAX -- sixteen entries. */
	@Test
	public void maskCap() {
		assertEquals(16, W65816JumpTables.maskCap(0x0f, 1));
		assertEquals(4, W65816JumpTables.maskCap(0x06, 0));   // AND #$06 / TAX: 0,2,4,6
		assertEquals(W65816JumpTables.MAX_ENTRIES, W65816JumpTables.maskCap(0xff, 1));
	}

	private static W65816JumpTables.IndexOp op(W65816JumpTables.IndexOp.Kind k, long v) {
		return new W65816JumpTables.IndexOp(k, v);
	}

	private static final W65816JumpTables.IndexOp.Kind SHIFT = W65816JumpTables.IndexOp.Kind.SHIFT;
	private static final W65816JumpTables.IndexOp.Kind MASK = W65816JumpTables.IndexOp.Kind.MASK;
	private static final W65816JumpTables.IndexOp.Kind BELOW = W65816JumpTables.IndexOp.Kind.BELOW;
	private static final W65816JumpTables.IndexOp.Kind AT_LEAST =
		W65816JumpTables.IndexOp.Kind.AT_LEAST;

	/** grm-9nxj.24: the mask-then-shift chain agrees with {@link W65816JumpTables#maskCap}. */
	@Test
	public void derivedCapReproducesMaskCap() {
		assertEquals(16, W65816JumpTables.derivedCap(List.of(op(MASK, 0x0f), op(SHIFT, 1))));
		assertEquals(4, W65816JumpTables.derivedCap(List.of(op(MASK, 0x06))));
		assertEquals(W65816JumpTables.MAX_ENTRIES, W65816JumpTables.derivedCap(List.of()));
		assertEquals(W65816JumpTables.MAX_ENTRIES,
			W65816JumpTables.derivedCap(List.of(op(SHIFT, 1))));
	}

	/**
	 * CT $C7:0173: CMP #$10 / BCC / CMP #$18 / BCS / AND #$0F / ASL A -- the guards leave
	 * $10..$17, the mask folds them to 0..7: eight entries, where the mask alone allows sixteen.
	 */
	@Test
	public void derivedCapFoldsGuardsThroughTheMask() {
		assertEquals(8, W65816JumpTables.derivedCap(List.of(op(AT_LEAST, 0x10), op(BELOW, 0x18),
			op(MASK, 0x0f), op(SHIFT, 1))));
	}

	/** A plain upper guard: CMP #$05 / BCS / ASL A -- indices 0..4. */
	@Test
	public void derivedCapFromUpperGuardAlone() {
		assertEquals(5, W65816JumpTables.derivedCap(List.of(op(BELOW, 5), op(SHIFT, 1))));
	}

	/** A lower guard alone bounds nothing above: still the uncapped count. */
	@Test
	public void derivedCapLowerGuardAloneIsNoCap() {
		assertEquals(W65816JumpTables.MAX_ENTRIES,
			W65816JumpTables.derivedCap(List.of(op(AT_LEAST, 0x10), op(SHIFT, 1))));
	}

	/** Contradictory guards (dead code) bound nothing rather than reading zero entries. */
	@Test
	public void derivedCapEmptySetIsNoCap() {
		assertEquals(W65816JumpTables.MAX_ENTRIES,
			W65816JumpTables.derivedCap(List.of(op(AT_LEAST, 0x20), op(BELOW, 0x10))));
	}

	/** A shift before the mask: ASL A / AND #$1E -- even indices up to $1E, sixteen entries. */
	@Test
	public void derivedCapShiftBeforeMask() {
		assertEquals(16, W65816JumpTables.derivedCap(List.of(op(SHIFT, 1), op(MASK, 0x1e))));
		// AND #$1F after the shift still cannot set bit 0: same sixteen.
		assertEquals(16, W65816JumpTables.derivedCap(List.of(op(SHIFT, 1), op(MASK, 0x1f))));
	}
}
