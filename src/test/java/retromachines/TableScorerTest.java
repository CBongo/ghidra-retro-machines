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

	@Test
	public void scoreIsTheProductOfTerms() {
		TableScorer.Entry<Integer, Why> e = TableScorer.Entry.accepted(1,
			List.of(new TableScorer.Term<>(Why.WEAK, 0.5), new TableScorer.Term<>(Why.BAD, 0.4)));
		assertEquals(0.2, e.score(), 1e-12);
		assertEquals(Why.BAD, e.weakest().reason());
		assertNull(e.hard());
	}
}
