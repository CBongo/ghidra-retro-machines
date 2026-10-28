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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Pure logic for grm-deve: decides whether the words of a bounded jump table are exactly its kept
 * case targets, so the table can be laid as a {@code word[n]} array with one reference per entry.
 * No Ghidra types; {@link JumpTableArrays} does the listing work.
 *
 * <p>Two encodings are recognised, never mixed within a table: an entry equal to its target
 * ({@link Layout#bias} 0), and the RTS-trick entry, the target minus one, which the dispatch
 * pushes and {@code RTS} increments ({@link Layout#bias} 1). Anything else is no match, and the
 * caller keeps today's behaviour.
 */
final class JumpTableArray {

	private JumpTableArray() {}

	/**
	 * A matched layout: {@code count} words, each entry {@code i} referring to kept case
	 * {@code caseIndex.get(i)}; {@code bias} is what an entry's word plus gives its target.
	 */
	record Layout(int count, int bias, List<Integer> caseIndex) {}

	/**
	 * One case per slot, in order: the first {@code kept.size()} words must be the kept targets
	 * (or, all of them, the targets minus one). Null when too few words or any entry disagrees.
	 */
	static Layout matchOrdered(List<Long> words, List<Long> kept) {
		int n = kept.size();
		if (n < 2 || words.size() < n) {
			return null;
		}
		for (int bias = 0; bias <= 1; bias++) {
			boolean all = true;
			for (int i = 0; i < n && all; i++) {
				all = target(words.get(i), bias) == kept.get(i);
			}
			if (all) {
				List<Integer> index = new ArrayList<>(n);
				for (int i = 0; i < n; i++) {
					index.add(i);
				}
				return new Layout(n, bias, index);
			}
		}
		return null;
	}

	/**
	 * A case list deduplicated by target (grm-uzep): the words in the bounded extent, whose count
	 * can exceed the case count, must each be a kept target and together cover every kept target.
	 * The extent is the {@link JumpTableBound#distinctWordSlots} walk, cut at the first word that
	 * is not a kept target (a code cut can have trimmed the kept list). A table that reads as both
	 * encodings, or as neither, is no match.
	 */
	static Layout matchDistinct(List<Long> words, long tableStart, List<Long> kept) {
		int slots = JumpTableBound.distinctWordSlots(words, tableStart);
		Set<Long> keptSet = new HashSet<>(kept);
		if (slots < 2 || kept.size() < 2 || keptSet.size() != kept.size()) {
			return null;
		}
		Layout found = null;
		for (int bias = 0; bias <= 1; bias++) {
			int p = 0;
			Set<Long> covered = new LinkedHashSet<>();
			while (p < slots && keptSet.contains(target(words.get(p), bias))) {
				covered.add(target(words.get(p), bias));
				p++;
			}
			if (p < 2 || !covered.equals(keptSet)) {
				continue;
			}
			if (found != null) {
				return null; // reads both ways: never guess
			}
			List<Integer> index = new ArrayList<>(p);
			for (int i = 0; i < p; i++) {
				index.add(kept.indexOf(target(words.get(i), bias)));
			}
			found = new Layout(p, bias, index);
		}
		return found;
	}

	/**
	 * grm-d3tu: a planar lo/hi table. Entry {@code i} is {@code lo[i] | hi[i] << 8} (or that plus
	 * one, the RTS-trick, never mixed) and must equal kept target {@code i}, for every kept target.
	 * Null when fewer than two targets, short byte arrays, or any entry disagrees.
	 */
	static Layout matchPlanar(byte[] lo, byte[] hi, List<Long> kept) {
		int n = kept.size();
		if (n < 2 || lo.length < n || hi.length < n) {
			return null;
		}
		for (int bias = 0; bias <= 1; bias++) {
			boolean all = true;
			for (int i = 0; i < n && all; i++) {
				all = target((lo[i] & 0xff) | (hi[i] & 0xff) << 8, bias) == kept.get(i);
			}
			if (all) {
				List<Integer> index = new ArrayList<>(n);
				for (int i = 0; i < n; i++) {
					index.add(i);
				}
				return new Layout(n, bias, index);
			}
		}
		return null;
	}

	/** The address offset an entry's word designates under {@code bias}, in 16 bits. */
	private static long target(long word, int bias) {
		return (word + bias) & 0xffff;
	}
}
