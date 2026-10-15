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
import java.util.List;

/**
 * Pure logic for re-reading a jump table from the bank that is actually switched in when the
 * dispatch runs (grm-pwuh). The decompiler reads a table from the switch's own bank; when the
 * code switches banks first and reads the table afterwards (Deadly Towers' bus-conflict-safe
 * BNROM trampoline), the bytes it decoded are the wrong bank's. The decompiler does not tell us
 * HOW it decoded an entry, so this recovers the layout by <em>model fitting</em>: the one
 * layout that reproduces EVERY case target the decompiler reported from the bytes it read. The
 * same layout then decodes the right bank's bytes.
 *
 * <p>Entry {@code i} is a 16-bit little-endian value whose low byte is at
 * {@code base + stride*i} and high byte at {@code base + stride*i + hiOffset}, plus a constant
 * {@code k} (0, or +1 for the RTS-trick shape). Two layouts are tried: an interleaved word table
 * (stride 2, hiOffset 1) and, when the decompiler reported a second load table, planar lo/hi
 * byte tables (stride 1, hiOffset = the gap between the two tables' starts).
 */
final class CrossBankTable {

	private CrossBankTable() {
	}

	/** Byte source over one memory; offsets are within the table's address space. */
	interface Bytes {
		/** The byte at {@code offset} (0-255), or -1 when it cannot be read. */
		int get(long offset);
	}

	/** A fitted layout. */
	record Model(int stride, int hiOffset, int k) {

		/** The entry at index {@code i}, or -1 when a byte could not be read. */
		long entry(long base, int i, Bytes bytes) {
			long at = base + (long) stride * i;
			int lo = bytes.get(at);
			int hi = bytes.get(at + hiOffset);
			if (lo < 0 || hi < 0) {
				return -1;
			}
			return (((hi << 8) | lo) + k) & 0xffff;
		}

		/** Up to {@code count} entries from {@code bytes}, stopping at the first unreadable one. */
		List<Long> read(long base, int count, Bytes bytes) {
			List<Long> out = new ArrayList<>();
			for (int i = 0; i < count; i++) {
				long e = entry(base, i, bytes);
				if (e < 0) {
					break;
				}
				out.add(e);
			}
			return out;
		}

		@Override
		public String toString() {
			return (hiOffset == 1 && stride == 2 ? "word-LE" : "planar(gap=" + hiOffset + ")") +
				(k != 0 ? "+" + k : "");
		}
	}

	/**
	 * The layout that reproduces every one of {@code targets} (the decompiler's case targets, as
	 * 16-bit offsets, in case order) from {@code decompilerBytes} read at {@code base}; null when
	 * none does. {@code planarGap} is the distance between the first two moving load tables, or 0
	 * when there is no second one.
	 */
	static Model fit(long base, int planarGap, List<Long> targets, Bytes decompilerBytes) {
		if (targets.size() < 2) {
			return null;
		}
		List<Model> candidates = new ArrayList<>();
		for (int k = 0; k <= 1; k++) {
			candidates.add(new Model(2, 1, k));
		}
		if (planarGap > 0) {
			for (int k = 0; k <= 1; k++) {
				candidates.add(new Model(1, planarGap, k));
			}
		}
		for (Model m : candidates) {
			boolean all = true;
			for (int i = 0; i < targets.size() && all; i++) {
				all = m.entry(base, i, decompilerBytes) == (targets.get(i) & 0xffff);
			}
			if (all) {
				return m;
			}
		}
		return null;
	}

	/** Result of {@link #validPrefix}: {@code skip} leading junk slots (0 or 1) then {@code count} kept. */
	record Prefix(int skip, int count) {}

	/**
	 * The valid prefix of a re-read table (grm-pwuh): at most ONE leading invalid entry is
	 * skipped (a table base one slot early reads a junk word first), then entries are kept up to,
	 * but not including, the first invalid one. {@code count == 0} means nothing is kept, and the
	 * caller must decline.
	 */
	static Prefix validPrefix(List<Long> entries, java.util.function.LongPredicate valid) {
		int skip = !entries.isEmpty() && !valid.test(entries.get(0)) ? 1 : 0;
		int end = skip;
		while (end < entries.size() && valid.test(entries.get(end))) {
			end++;
		}
		return new Prefix(skip, end - skip);
	}
}
