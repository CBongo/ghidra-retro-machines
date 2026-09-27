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

import java.util.List;

/**
 * Pure logic for grm-eyn: bound a decompiler-recovered jump table by its own lowest target.
 *
 * <p><b>The rule</b> ("a table cannot extend past its own lowest target", proven exact on 7/7
 * hand-read real-ROM tables via a C++ fork patch -- see
 * {@code D:/git/ghidra-fork/build-variants/lowest-target-475cf359.patch},
 * {@code boundByLowestTarget} in {@code jumptable.cc}): walk the table's entries in order,
 * tracking the lowest target address seen so far, and cut the table off at the first entry
 * whose own table bytes would reach (overlap) that lowest target. The table and the code it
 * dispatches to cannot occupy the same memory, so once an entry's own bytes would run into
 * the lowest address already claimed as a jump target, every entry from there on is bogus: the
 * classic 6502 idiom is a doubled 1-byte index (e.g. {@code ASL A / TAY / LDA tbl,Y / STA $04 /
 * LDA tbl+1,Y / STA $05 / JMP ($0004)}) with no bound on the index anywhere in the code, so
 * Ghidra's decompiler recovers all 128/256 raw index values and reads straight through the real
 * table into whatever bytes follow it.
 *
 * <p>This only ever <b>shrinks</b> a table, and only applies at all when every one of these
 * holds; failing any of them, the caller must change nothing ("decline"):
 * <ul>
 * <li>at least 2 entries (a single entry can't be told from a fixed lookup);</li>
 * <li>every "moving" load table (one whose collapsed {@code num > 1}) divides evenly into the
 * case count -- {@code size*num % caseCount == 0} -- so a uniform per-entry byte extent
 * ({@code chunk = size*num/caseCount}) can be reconstructed; a load table with {@code num == 1}
 * is a fixed lookup, not part of the table, and is ignored entirely, exactly as the C++
 * reference ignores a LOAD whose address does not move with the index;</li>
 * <li>there is at least one such moving table (otherwise there is no table shape to bound at
 * all);</li>
 * <li>the table's lowest address (the minimum start of any moving load table) sits <b>below</b>
 * the lowest recovered target -- the idiom only holds for a table that precedes the code it
 * jumps to; a table stored above or far from its targets is left untouched.</li>
 * </ul>
 *
 * <p><b>Java-only difference from the C++ reference.</b> The C++ patch runs inside
 * {@code JumpBasic::sanityCheck}, before {@code LoadTable::collapseTable}, so it sees one LOAD
 * per entry in execution order. The Java side only has {@link
 * ghidra.program.model.pcode.JumpTable#getLoadTables()} -- already collapsed, sorted, and merged
 * across same-size contiguous LOADs (so e.g. an interleaved lo/hi byte table arrives as a single
 * collapsed table of size 1 covering both halves). {@link LoadTableEntry} therefore carries a
 * collapsed table verbatim ({@code start, entrySize, num}), and this class reconstructs each
 * entry's byte extent under the uniform-stride assumption above, rather than being handed the
 * extent directly.
 *
 * <p><b>Default case.</b> The caller is responsible for excluding the DEFAULT case (a trailing
 * case in {@code JumpTable.getCases()} with no corresponding label value, or whose label value is
 * {@code DecompilerSwitchAnalysisCmd.DEFAULT_CASE_VALUE == 0xBAD1ABE1}) from both the {@code
 * targets} list and the case count before calling {@link #bound}; it is not a table entry and
 * must not be walked, counted toward {@code caseCount}, or included in the override this class's
 * caller builds.
 *
 * @see <a href="urn:bead:grm-eyn">grm-eyn</a>
 */
public final class JumpTableBound {

	private JumpTableBound() {
	}

	/**
	 * One of {@link ghidra.program.model.pcode.JumpTable.LoadTable}'s <em>collapsed</em> load
	 * descriptions: a run of same-size LOADs starting at {@code start}, one entry
	 * {@code entrySize} bytes wide, {@code num} of them.
	 */
	public static final class LoadTableEntry {
		private final long start;
		private final int entrySize;
		private final int num;

		public LoadTableEntry(long start, int entrySize, int num) {
			this.start = start;
			this.entrySize = entrySize;
			this.num = num;
		}

		public long start() {
			return start;
		}

		public int entrySize() {
			return entrySize;
		}

		public int num() {
			return num;
		}
	}

	/** The outcome of {@link #bound}: either a recovered entry count, or a decline. */
	public static final class Result {
		private final boolean bounded;
		private final int count;
		private final long lowestTarget;

		private Result(boolean bounded, int count, long lowestTarget) {
			this.bounded = bounded;
			this.count = count;
			this.lowestTarget = lowestTarget;
		}

		private static Result decline() {
			return new Result(false, -1, -1);
		}

		private static Result bounded(int count, long lowestTarget) {
			return new Result(true, count, lowestTarget);
		}

		/** Whether the rule applied at all (the shape was understood and the table precedes
		 *  its targets). A {@code true} result does not by itself mean the table shrank --
		 *  compare {@link #count()} against the original case count for that. */
		public boolean isBounded() {
			return bounded;
		}

		/** The recovered entry count. Only meaningful when {@link #isBounded()}; never exceeds
		 *  the input case count. */
		public int count() {
			return count;
		}

		/** The lowest target address seen among the entries kept. Only meaningful when
		 *  {@link #isBounded()}. */
		public long lowestTarget() {
			return lowestTarget;
		}
	}

	/**
	 * Apply the lowest-target bound.
	 *
	 * @param targets ordered target addresses (as flat offsets in the targets' address space),
	 *                one per case, in table order, with the DEFAULT case already excluded
	 * @param loadTables the jump table's collapsed load tables, in any order
	 * @return a bounded result, or {@link Result#isBounded()} false ("decline") if the shape
	 *         isn't understood, there are fewer than 2 entries, or the table doesn't sit below
	 *         its targets
	 */
	public static Result bound(List<Long> targets, List<LoadTableEntry> loadTables) {
		int caseCount = targets.size();
		if (caseCount < 2) {
			return Result.decline(); // need two entries to tell a table from a fixed load
		}

		// Only "moving" tables (num > 1) are part of the table shape; num == 1 is a fixed
		// lookup and is ignored entirely, like the C++ reference ignoring a non-moving LOAD.
		int movingCount = 0;
		long tableStart = 0;
		boolean haveStart = false;
		long[] chunk = new long[loadTables.size()];
		long[] start = new long[loadTables.size()];
		boolean[] moving = new boolean[loadTables.size()];
		for (int k = 0; k < loadTables.size(); k++) {
			LoadTableEntry t = loadTables.get(k);
			if (t.num() <= 1) {
				continue;
			}
			long extent = (long) t.entrySize() * (long) t.num();
			if (extent % caseCount != 0) {
				return Result.decline(); // non-uniform shape; not understood
			}
			moving[k] = true;
			chunk[k] = extent / caseCount;
			start[k] = t.start();
			movingCount++;
			if (!haveStart || t.start() < tableStart) {
				tableStart = t.start();
				haveStart = true;
			}
		}
		if (movingCount == 0 || !haveStart) {
			return Result.decline(); // no table shape to bound at all
		}

		long minTarget = 0;
		boolean haveTarget = false;
		int i;
		for (i = 0; i < caseCount; i++) {
			long entryEnd = 0;
			for (int k = 0; k < loadTables.size(); k++) {
				if (!moving[k]) {
					continue;
				}
				long end = start[k] + (long) (i + 1) * chunk[k];
				if (end > entryEnd) {
					entryEnd = end;
				}
			}
			if (haveTarget && entryEnd > minTarget) {
				break; // this entry's own bytes would collide with the lowest target so far
			}
			long target = targets.get(i);
			if (!haveTarget || target < minTarget) {
				minTarget = target;
				haveTarget = true;
			}
		}
		if (i == 0 || !haveTarget) {
			return Result.decline();
		}
		if (minTarget <= tableStart) {
			return Result.decline(); // table does not precede its targets; idiom doesn't apply
		}
		return Result.bounded(i, minTarget);
	}
}
