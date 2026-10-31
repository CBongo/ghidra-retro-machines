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
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/** Pure-logic tests for {@link TableScorer} (grm-gipk.16). */
public class TableScorerTest {

	private enum Why {
		BAD, WEAK
	}

	@Test
	public void hardTermEndsTheTableAtThatEntry() {
		TableScorer.Result<Integer, Why> r = TableScorer.walk(10,
			(i, before) -> i == 3 ? TableScorer.Entry.rejected(Why.BAD)
					: TableScorer.Entry.accepted(i * 10, List.of()),
			TableScorer.HARD_ONLY);
		assertEquals(List.of(0, 10, 20), r.targets());
		assertEquals(Why.BAD, r.endedBy());
	}

	@Test
	public void theCapEndsWithNoReason() {
		TableScorer.Result<Integer, Why> r = TableScorer.walk(4,
			(i, before) -> TableScorer.Entry.accepted(i, List.of()), TableScorer.HARD_ONLY);
		assertEquals(4, r.count());
		assertNull(r.endedBy());
	}

	/** Under HARD_ONLY a soft term is carried but never ends the table. */
	@Test
	public void hardOnlyIgnoresSoftScores() {
		TableScorer.Result<Integer, Why> r = TableScorer.walk(5,
			(i, before) -> TableScorer.Entry.accepted(i,
				List.of(new TableScorer.Term<>(Why.WEAK, 0.01))),
			TableScorer.HARD_ONLY);
		assertEquals(5, r.count());
	}

	/** Each evaluation sees exactly the targets kept before it. */
	@Test
	public void evidenceSeesTheTargetsBeforeIt() {
		List<List<Integer>> seen = new ArrayList<>();
		TableScorer.<Integer, Why> walk(3, (i, before) -> {
			seen.add(List.copyOf(before));
			return TableScorer.Entry.accepted(i + 100, List.of());
		}, TableScorer.HARD_ONLY);
		assertEquals(List.of(List.<Integer> of(), List.of(100), List.of(100, 101)), seen);
	}

	/** A policy may stop early and keep fewer than it read; the first dropped entry names why. */
	@Test
	public void aPolicyEndIsNamedByTheFirstDroppedEntrysWeakestTerm() {
		TableScorer.EndPolicy twoLowInARow = new TableScorer.EndPolicy() {
			@Override
			public int end(List<Double> scores) {
				int n = scores.size();
				return n >= 2 && scores.get(n - 1) < 0.5 && scores.get(n - 2) < 0.5 ? n - 2 : -1;
			}

			@Override
			public int settle(List<Double> scores) {
				return scores.size();
			}
		};
		TableScorer.Result<Integer, Why> r = TableScorer.walk(10,
			(i, before) -> TableScorer.Entry.accepted(i,
				i < 4 ? List.of() : List.of(new TableScorer.Term<>(Why.WEAK, 0.1))),
			twoLowInARow);
		assertEquals(List.of(0, 1, 2, 3), r.targets());
		assertEquals(Why.WEAK, r.endedBy());
	}

	private static TableScorer.Result<Integer, Why> doubtRun(boolean... low) {
		return TableScorer.<Integer, Why> walk(low.length + 1,
			(i, before) -> i == low.length ? TableScorer.Entry.rejected(Why.BAD)
					: TableScorer.Entry.accepted(i,
						low[i] ? List.of(new TableScorer.Term<>(Why.WEAK, 0.1)) : List.of()),
			TableScorer.doubtRun(0.5, 1.0, 3));
	}

	@Test
	public void doubtRunEndsBeforeASustainedRun() {
		TableScorer.Result<Integer, Why> r = doubtRun(false, false, true, true, true, false);
		assertEquals(List.of(0, 1), r.targets());
		assertEquals(Why.WEAK, r.endedBy());
	}

	@Test
	public void doubtRunKeepsAShortRunBetweenGoodEntries() {
		assertEquals(7, doubtRun(false, true, true, false, false, true, false).count());
	}

	/** At a hard end, a trailing low run too short to have ended the table is still dropped. */
	@Test
	public void doubtRunDropsATrailingShortRunAtAHardEnd() {
		TableScorer.Result<Integer, Why> r = doubtRun(false, false, false, true, true);
		assertEquals(3, r.count());
		assertEquals(Why.WEAK, r.endedBy());
	}

	/** An entry between the cuts extends open doubt but never opens or closes it. */
	@Test
	public void aMiddlingEntryNeitherOpensNorClosesDoubt() {
		TableScorer.EndPolicy p = TableScorer.doubtRun(0.5, 1.0, 3);
		assertEquals(-1, p.end(List.of(1.0, 0.7, 0.7, 0.7)));
		assertEquals(4, p.settle(List.of(1.0, 0.7, 0.7, 0.7)));
		assertEquals(1, p.end(List.of(1.0, 0.1, 0.7, 0.7)));
		assertEquals(1, p.settle(List.of(1.0, 0.1, 0.7)));
	}

	/** A walk of {@code n} accepted entries, the last {@code soft} of them scoring 0.5. */
	private static TableScorer.Result<Integer, Why> walkOf(int n, int soft) {
		return TableScorer.<Integer, Why> walk(n + 1,
			(i, before) -> i == n ? TableScorer.Entry.rejected(Why.BAD)
					: TableScorer.Entry.accepted(i, i >= n - soft
							? List.of(new TableScorer.Term<>(Why.WEAK, 0.5)) : List.of()),
			TableScorer.HARD_ONLY);
	}

	@Test
	public void expectedIsTheSumOfKeptScores() {
		assertEquals(3.0, walkOf(4, 2).expected(), 1e-12);
	}

	/** The code-derived reading wins unless the bytes beat its prior by the prior's ratio. */
	@Test
	public void rankWeighsThePrior() {
		List<TableScorer.Candidate<Integer>> c = List.of(new TableScorer.Candidate<>(1, 1.0),
			new TableScorer.Candidate<>(0, 0.25));
		// code b=1 keeps 10; b=0 keeps 30: 0.25*30 = 7.5 < 10, the code stands.
		List<TableScorer.Ranked<Integer, Integer, Why>> r =
			TableScorer.rank(c, b -> walkOf(b == 1 ? 10 : 30, 0));
		assertEquals(1, (int) r.get(0).key());
		assertNull(TableScorer.disagreement(r, 1));
		// code b=1 keeps 2; b=0 keeps 40: 0.25*40 = 10 > 2, the bytes disagree.
		r = TableScorer.rank(c, b -> walkOf(b == 1 ? 2 : 40, 0));
		assertEquals(0, (int) r.get(0).key());
		assertEquals("code 1 keeps 2; 0 keeps 40 (quality x5.00)", TableScorer.disagreement(r, 1));
	}

	@Test
	public void rankTiesKeepInputOrder() {
		List<TableScorer.Candidate<String>> c = List.of(new TableScorer.Candidate<>("k=0", 1.0),
			new TableScorer.Candidate<>("k=1", 1.0));
		assertEquals("k=0", TableScorer.rank(c, k -> walkOf(5, 0)).get(0).key());
	}

	@Test
	public void scoreIsTheProductOfTerms() {
		TableScorer.Entry<Integer, Why> e = TableScorer.Entry.accepted(1,
			List.of(new TableScorer.Term<>(Why.WEAK, 0.5), new TableScorer.Term<>(Why.BAD, 0.4)));
		assertEquals(0.2, e.score(), 1e-12);
		assertEquals(Why.BAD, e.weakest().reason());
		assertNull(e.hard());
	}
}
