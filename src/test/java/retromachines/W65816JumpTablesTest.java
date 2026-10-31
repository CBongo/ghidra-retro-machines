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

	/** FF3 $C2:1B02: AND #$0F / ASL A / TAX -- sixteen entries. */
	@Test
	public void maskCap() {
		assertEquals(16, W65816JumpTables.maskCap(0x0f, 1));
		assertEquals(4, W65816JumpTables.maskCap(0x06, 0));   // AND #$06 / TAX: 0,2,4,6
		assertEquals(W65816JumpTables.MAX_ENTRIES, W65816JumpTables.maskCap(0xff, 1));
	}
}
