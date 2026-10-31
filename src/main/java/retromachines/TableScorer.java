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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * Pure logic for grm-gipk.16: one model for "how long is this table", shared by every walk that
 * reads a jump/dispatch table entry by entry.
 *
 * <p>Each walk used to be its own loop that stopped at the first entry failing any check, with
 * a {@code Cut} enum saying which. Here each check is instead an evidence {@link Term}: a reason
 * (the implementation's own enum, so logs still say why a table ended) and a probability that the
 * entry is real. A term of probability 0 is <b>hard</b> -- unreadable memory, a target pointing
 * into the table, the index cap, bytes already taken -- and always ends the table at that entry.
 * A term between 0 and 1 is a heuristic, weighted by how much it is a rule of thumb rather than a
 * fact; an entry's score is the product of its terms.
 *
 * <p>Where a table ends among soft scores is the {@link EndPolicy}'s decision, separate from the
 * evidence. Stage 1 of grm-gipk.16 uses {@link #HARD_ONLY}, under which every port reproduces its
 * old first-failure loop exactly (each former cut is a hard term); later stages soften terms one
 * at a time and choose the end from the score sequence.
 *
 * <p>Evidence is evaluated in entry order and may depend on the entries before it (the lowest
 * target above the table, the first target's bank half), so the walk hands each evaluation the
 * targets it has not rejected so far.
 */
final class TableScorer {

	private TableScorer() {
	}

	/** One piece of evidence about an entry: why, and the probability the entry is real. */
	record Term<R>(R reason, double p) {
		static <R> Term<R> hard(R reason) {
			return new Term<>(reason, 0.0);
		}

		boolean isHard() {
			return p <= 0.0;
		}
	}

	/** What the evidence says about one entry: its target (null when there is none) and terms. */
	record Entry<T, R>(T target, List<Term<R>> terms) {
		/** An entry a hard term rules out; any terms checked before it passed. */
		static <T, R> Entry<T, R> rejected(R reason) {
			return new Entry<>(null, List.of(Term.hard(reason)));
		}

		/** An entry no check rules out, with {@code soft} terms (none: a certain entry). */
		static <T, R> Entry<T, R> accepted(T target, List<Term<R>> soft) {
			return new Entry<>(target, soft);
		}

		/** The product of every term's probability. */
		double score() {
			double s = 1.0;
			for (Term<R> t : terms) {
				s *= t.p();
			}
			return s;
		}

		/** The first hard term, or null. */
		Term<R> hard() {
			for (Term<R> t : terms) {
				if (t.isHard()) {
					return t;
				}
			}
			return null;
		}

		/** The lowest-probability term, or null when there are none. */
		Term<R> weakest() {
			Term<R> w = null;
			for (Term<R> t : terms) {
				if (w == null || t.p() < w.p()) {
					w = t;
				}
			}
			return w;
		}
	}

	/** Evaluates entry {@code i} given the targets not rejected before it, in order. */
	@FunctionalInterface
	interface Evidence<T, R> {
		Entry<T, R> entry(int i, List<T> before);
	}

	/** Chooses where a table ends among entries no hard term has ruled out. */
	interface EndPolicy {
		/**
		 * After each entry: the number of entries to keep if the walk should stop now, or -1 to
		 * read on. {@code scores} holds every entry read so far, none of them hard.
		 */
		int end(List<Double> scores);

		/** When a hard term or the cap stopped the walk: how many of {@code scores} to keep. */
		int settle(List<Double> scores);
	}

	/** Only hard terms end a table; soft scores are carried but never decide (stage 1). */
	static final EndPolicy HARD_ONLY = new EndPolicy() {
		@Override
		public int end(List<Double> scores) {
			return -1;
		}

		@Override
		public int settle(List<Double> scores) {
			return scores.size();
		}
	};

	/**
	 * Doubt opens at an entry scoring below {@code low} and closes only at a later one scoring at
	 * least {@code sure}; the table ends where doubt opened once it has stayed open for {@code run}
	 * entries. So one doubtful entry between sure ones is kept (it does not hide the valid entries
	 * after it), an entry between the two thresholds neither opens doubt nor vouches for it, and
	 * when a hard term or the cap stops the walk with doubt still open, everything from where it
	 * opened is dropped: nothing after it vouches for it.
	 */
	static EndPolicy doubtRun(double low, double sure, int run) {
		return new EndPolicy() {
			@Override
			public int end(List<Double> scores) {
				int open = openedAt(scores);
				return open >= 0 && scores.size() - open >= run ? open : -1;
			}

			@Override
			public int settle(List<Double> scores) {
				int open = openedAt(scores);
				return open >= 0 ? open : scores.size();
			}

			// Where the currently open doubt began, or -1.
			private int openedAt(List<Double> scores) {
				int open = -1;
				for (int i = 0; i < scores.size(); i++) {
					double s = scores.get(i);
					if (s >= sure) {
						open = -1;
					}
					else if (s < low && open < 0) {
						open = i;
					}
				}
				return open;
			}
		};
	}

	/**
	 * A walked table: the kept targets, in entry order, and the reason it ended -- the hard term,
	 * or for a policy end the weakest term of the first entry dropped. Null when the cap ended it.
	 */
	record Result<T, R>(List<T> targets, R endedBy, List<Double> scores) {
		int count() {
			return targets.size();
		}

		/** The sum of the kept entries' scores: how many real entries the evidence expects. */
		double expected() {
			double s = 0;
			for (double d : scores) {
				s += d;
			}
			return s;
		}
	}

	/**
	 * One candidate reading of a table for {@link #rank} (grm-gipk.16.6): which entry is entry 0
	 * (offset {@code k}), or what each word adds to make its target (bias {@code b}), with the
	 * prior the dispatch code gives it. The code-derived reading carries the strong prior; the
	 * neighbours searched around it a weak one, so the bytes overturn the code only by a wide
	 * margin.
	 */
	record Candidate<K>(K key, double prior) {
	}

	/** A candidate walked: its result and quality, {@code prior * result.expected()}. */
	record Ranked<K, T, R>(K key, double prior, Result<T, R> result) {
		double quality() {
			return prior * result.expected();
		}
	}

	/**
	 * Walks every candidate with {@code walk} and returns them best first by quality; ties keep
	 * the input order, so list the code-derived reading first and it wins a tie. A table read at
	 * the wrong start or bias meets implausible targets early (code-tail bytes before the real
	 * entry 0, handlers one byte off), so its walk ends short and its expected count is low.
	 */
	static <K, T, R> List<Ranked<K, T, R>> rank(List<Candidate<K>> candidates,
			Function<K, Result<T, R>> walk) {
		List<Ranked<K, T, R>> out = new ArrayList<>(candidates.size());
		for (Candidate<K> c : candidates) {
			out.add(new Ranked<>(c.key(), c.prior(), walk.apply(c.key())));
		}
		out.sort(Comparator.comparingDouble((Ranked<K, T, R> r) -> r.quality()).reversed());
		return out;
	}

	/**
	 * When a candidate other than {@code chosen} ranks above it, a log fragment naming both and
	 * the quality ratio; null when {@code chosen} ranks first. Check mode: the caller still uses
	 * the code-derived reading, and this only reports where the bytes disagree with it.
	 */
	static <K, T, R> String disagreement(List<Ranked<K, T, R>> ranked, K chosen) {
		if (ranked.isEmpty() || ranked.get(0).key().equals(chosen)) {
			return null;
		}
		Ranked<K, T, R> best = ranked.get(0);
		Ranked<K, T, R> code = null;
		for (Ranked<K, T, R> r : ranked) {
			if (r.key().equals(chosen)) {
				code = r;
			}
		}
		if (code == null) {
			return null;
		}
		String ratio = code.quality() > 0
				? String.format(Locale.ROOT, "%.2f", best.quality() / code.quality()) : "inf";
		return "code " + chosen + " keeps " + code.result().count() + "; " + best.key() +
			" keeps " + best.result().count() + " (quality x" + ratio + ")";
	}

	/** Reads up to {@code cap} entries and keeps the prefix {@code policy} chooses. */
	static <T, R> Result<T, R> walk(int cap, Evidence<T, R> evidence, EndPolicy policy) {
		List<Entry<T, R>> read = new ArrayList<>();
		List<T> targets = new ArrayList<>();
		List<Double> scores = new ArrayList<>();
		R hardReason = null;
		int keep = -1;
		for (int i = 0; i < cap; i++) {
			Entry<T, R> e = evidence.entry(i, targets);
			Term<R> hard = e.hard();
			if (hard != null) {
				hardReason = hard.reason();
				break;
			}
			read.add(e);
			targets.add(e.target());
			scores.add(e.score());
			keep = policy.end(scores);
			if (keep >= 0) {
				break;
			}
		}
		R endedBy = hardReason;
		if (keep < 0) {
			keep = policy.settle(scores);
		}
		if (keep < read.size()) {
			Term<R> w = read.get(keep).weakest();
			endedBy = w == null ? null : w.reason();
		}
		return new Result<>(List.copyOf(targets.subList(0, keep)), endedBy,
			List.copyOf(scores.subList(0, keep)));
	}
}
