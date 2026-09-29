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
import java.util.function.BiFunction;

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
 * holds; failing any of them, the caller must change nothing ("decline") -- or, for the
 * table-after-code layout the last condition excludes, try {@link #boundBySwitchWindow}:
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
 * <p><b>grm-fxtp: an over-read entry below the table.</b> The condition above used to decline the
 * whole table whenever an over-read entry happened to point BELOW {@code tableStart}: that entry
 * drags {@code minTarget} down with it, so by the time the walk ends {@code minTarget <=
 * tableStart} and the idiom looks like it doesn't apply, even though the table genuinely precedes
 * its real targets (lwings dcaf: entries 0..63 are plausible code above the table, entry 64 is
 * garbage below it). Now, once entry 0 establishes the table-before-code idiom (its target is
 * above {@code tableStart}), the first entry at index &gt;= 2 whose target falls below {@code
 * tableStart} cuts the walk there instead of dragging {@code minTarget} down -- but only when a
 * {@link Block} for the table's own memory block is supplied (the 2-arg {@link #bound(List, List)}
 * overload always passes none, disabling this refinement and matching pre-grm-fxtp behaviour
 * exactly), and only subject to two guards, both of which decline rather than cut when they fail:
 * <ul>
 * <li><b>same-block:</b> every kept entry (0 through the cut) must resolve inside that block --
 * "below the table" means nothing when the table and its targets sit in different blocks
 * (cv3 e137: table at 9f31 in a switchable window, targets in the fixed bank);</li>
 * <li><b>confirm:</b> the {@link #WINDOW_CONFIRM} entries after the cut (as many as exist) must
 * each be either below {@code tableStart} or outside the block -- one coming back above the table
 * inside the block means a real case reaches shared code past the garbage, exactly as {@link
 * #boundBySwitchWindow}'s own confirm check guards.</li>
 * </ul>
 *
 * <p><b>grm-yjiq: an un-doubled index over 2-byte entries.</b> When the game keeps its switch
 * variable pre-doubled in RAM ({@code LDX $0d / LDA tbl,X / STA $1e / LDA tbl+1,X / STA $1f /
 * JMP ($001e)}, rcproam 9ad4), the code itself never scales the index, so the decompiler walks it
 * at stride 1: every case reads two bytes and consecutive cases OVERLAP by one, which collapses
 * to a single size-1 load table of {@code caseCount + 1} bytes. That extent does not divide by
 * the case count, so {@link Shape#of} declines it -- and it must not simply be walked at stride 1
 * anyway, because every odd case straddles two real entries (the high byte of one, the low byte
 * of the next) and yields a garbage target that would drag {@code minTarget} down. Both rules
 * therefore recognise this one shape explicitly (see {@link #overlappingByteTable}) and re-run
 * on the EVEN cases alone, re-described as the non-overlapping 2-byte table they really are; the
 * result carries {@link Result#stride()} 2, and {@link Result#keep} selects those cases. rcproam
 * itself needs a third rule on top, {@link #boundByValidTargets}, because its handlers sit on both
 * sides of the table and both of these decline on it.
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
		private final Rule rule;
		private final int stride;

		private Result(boolean bounded, int count, long lowestTarget, Rule rule, int stride) {
			this.bounded = bounded;
			this.count = count;
			this.lowestTarget = lowestTarget;
			this.rule = rule;
			this.stride = stride;
		}

		private static Result decline() {
			return new Result(false, -1, -1, null, 1);
		}

		private static Result bounded(int count, long lowestTarget, Rule rule) {
			return new Result(true, count, lowestTarget, rule, 1);
		}

		private Result withStride(int newStride) {
			return new Result(bounded, count, lowestTarget, rule, newStride);
		}

		/** Whether the rule applied at all (the shape was understood and the table precedes
		 *  its targets). A {@code true} result does not by itself mean the table shrank --
		 *  compare {@link #count()} against the original case count for that. */
		public boolean isBounded() {
			return bounded;
		}

		/** The recovered entry count -- how many cases {@link #keep} returns, not the index of
		 *  the last one. Only meaningful when {@link #isBounded()}; never exceeds the input case
		 *  count. */
		public int count() {
			return count;
		}

		/** The lowest target address seen among the entries kept. Only meaningful when
		 *  {@link #isBounded()}. */
		public long lowestTarget() {
			return lowestTarget;
		}

		/** Which rule applied. Only meaningful when {@link #isBounded()}. */
		public Rule rule() {
			return rule;
		}

		/** The step between kept cases: 1 normally, 2 for the grm-yjiq overlapping byte table,
		 *  whose odd cases are never real entries. */
		public int stride() {
			return stride;
		}

		/** The cases this result keeps, in order: {@link #count()} of them, taken every
		 *  {@link #stride()} from case 0. Only meaningful when {@link #isBounded()}. */
		public <T> List<T> keep(List<T> cases) {
			List<T> kept = new ArrayList<>(count);
			for (int k = 0; k < count; k++) {
				kept.add(cases.get(k * stride));
			}
			return kept;
		}
	}

	/**
	 * A memory block's [start, end] flat-offset range, inclusive on both ends (as
	 * {@code MemoryBlock#getStart()}/{@code getEnd()} report). Carries the table's own block into
	 * {@link #bound(List, List, Block)} so the grm-fxtp below-table-cut refinement can confirm the
	 * table and its kept targets share it (see the class javadoc's same-block guard).
	 */
	public static final class Block {
		private final long start;
		private final long end;

		public Block(long start, long end) {
			this.start = start;
			this.end = end;
		}

		boolean contains(long offset) {
			return offset >= start && offset <= end;
		}
	}

	/**
	 * Apply the lowest-target bound, with the grm-fxtp below-table-cut refinement disabled (as if
	 * the table's block were unknown). Equivalent to {@code bound(targets, loadTables, null)}; see
	 * {@link #bound(List, List, Block)}.
	 */
	public static Result bound(List<Long> targets, List<LoadTableEntry> loadTables) {
		return bound(targets, loadTables, null);
	}

	/**
	 * Apply the lowest-target bound.
	 *
	 * @param targets ordered target addresses (as flat offsets in the targets' address space),
	 *                one per case, in table order, with the DEFAULT case already excluded
	 * @param loadTables the jump table's collapsed load tables, in any order
	 * @param tableBlock the memory block containing the table, for the grm-fxtp below-table-cut
	 *                    refinement (see the class javadoc), or {@code null} ("block unknown") to
	 *                    disable that refinement entirely and fall back to the plain lowest-target
	 *                    walk -- the same as the 2-arg {@link #bound(List, List)} overload
	 * @return a bounded result, or {@link Result#isBounded()} false ("decline") if the shape
	 *         isn't understood, there are fewer than 2 entries, or the table doesn't sit below
	 *         its targets
	 */
	public static Result bound(List<Long> targets, List<LoadTableEntry> loadTables,
			Block tableBlock) {
		Shape shape = Shape.of(targets.size(), loadTables);
		if (shape == null) {
			return onEvenCases(targets, loadTables, (t, l) -> bound(t, l, tableBlock));
		}
		int caseCount = targets.size();
		// Established once entry 0's own target sits above the table: the table-before-code idiom
		// that makes a later below-table entry meaningful as a cut point rather than noise.
		boolean tableBeforeCode = tableBlock != null && targets.get(0) > shape.tableStart;
		long minTarget = 0;
		boolean haveTarget = false;
		int i;
		int belowTableCut = -1;
		for (i = 0; i < caseCount; i++) {
			if (haveTarget && shape.entryEnd(i) > minTarget) {
				break; // this entry's own bytes would collide with the lowest target so far
			}
			long target = targets.get(i);
			if (tableBeforeCode && i >= 2 && target < shape.tableStart) {
				belowTableCut = i; // grm-fxtp: cut here instead of dragging minTarget below tableStart
				break;
			}
			if (!haveTarget || target < minTarget) {
				minTarget = target;
				haveTarget = true;
			}
		}
		if (belowTableCut >= 0) {
			return boundBelowTableCut(targets, tableBlock, shape.tableStart, belowTableCut, minTarget);
		}
		if (i == 0 || !haveTarget) {
			return Result.decline();
		}
		if (minTarget <= shape.tableStart) {
			return Result.decline(); // table does not precede its targets; idiom doesn't apply
		}
		return Result.bounded(i, minTarget, Rule.LOWEST_TARGET);
	}

	/**
	 * Guards grm-fxtp's below-table cut: declines (never cuts) unless every kept entry (indices
	 * {@code 0..cut-1}) resolves inside {@code tableBlock}, and the {@link #WINDOW_CONFIRM} entries
	 * after the cut (as many as exist) are each either below the table or outside the block -- see
	 * the class javadoc's same-block and confirm guards.
	 */
	private static Result boundBelowTableCut(List<Long> targets, Block tableBlock, long tableStart,
			int cut, long minTarget) {
		for (int k = 0; k < cut; k++) {
			if (!tableBlock.contains(targets.get(k))) {
				return Result.decline(); // table and its targets don't share a block; not the idiom
			}
		}
		int confirmEnd = Math.min(targets.size(), cut + 1 + WINDOW_CONFIRM);
		for (int k = cut + 1; k < confirmEnd; k++) {
			long t = targets.get(k);
			if (t >= tableStart && tableBlock.contains(t)) {
				return Result.decline(); // a later entry comes back above the table in-block: ambiguous
			}
		}
		return Result.bounded(cut, minTarget, Rule.BELOW_TABLE_CUT);
	}

	/**
	 * How many entries after the cut must also lie outside the window for
	 * {@link #boundBySwitchWindow} to trust it. One real case that jumps back to shared code
	 * before the switch would otherwise truncate the table there; requiring the next entries to
	 * stay out as well turns that into a decline. On the grm-akiv survey (34 NES rows) the
	 * nearest re-entry after any cut was 5 entries on.
	 */
	static final int WINDOW_CONFIRM = 2;

	/**
	 * Apply the switch-window bound (grm-akiv), for the TABLE-AFTER-CODE layout that
	 * {@link #bound} declines by design: {@code JMP ($0004)} at {@code switchAddr}, the case
	 * bodies right after it, and the table after those (megaman e000: switch e000, cases
	 * e003..e0ca, table e0ed). There, "cannot overlap its own lowest target" says nothing -- every
	 * real target is already below the table -- so the signal is where the code is instead: the
	 * table's real entries all point into {@code [switchAddr, tableStart)}, and the first entry
	 * that points anywhere else is past the table's end. That entry is often plainly bogus (RAM,
	 * another bank's window), but not always: tables are laid end to end, so the over-read can
	 * run into the NEXT table and yield valid code addresses (megaman eb82 into ea93's table,
	 * tmnt 8f34 into 894e's). Only the window catches those.
	 *
	 * <p>Declines unless: the table shape is understood (as for {@link #bound}); the table
	 * starts after the switch; entry 0 lies in the window; at least 2 entries are kept; and the
	 * {@link #WINDOW_CONFIRM} entries after the cut (as many as exist) also lie outside it.
	 * Only ever shrinks a table. This is a heuristic, not a layout proof: a table whose real
	 * cases jump outside the window would be cut short, which is what the confirm check guards.
	 *
	 * @param switchAddr flat offset of the switch instruction, in the targets' address space
	 * @param targets as for {@link #bound}
	 * @param loadTables as for {@link #bound}
	 * @return a bounded result whose {@link Result#lowestTarget()} is the lowest kept target, or
	 *         a decline
	 */
	public static Result boundBySwitchWindow(long switchAddr, List<Long> targets,
			List<LoadTableEntry> loadTables) {
		Shape shape = Shape.of(targets.size(), loadTables);
		if (shape == null) {
			return onEvenCases(targets, loadTables,
				(t, l) -> boundBySwitchWindow(switchAddr, t, l));
		}
		if (shape.tableStart <= switchAddr) {
			return Result.decline();
		}
		long lo = switchAddr;
		long hi = shape.tableStart;
		int caseCount = targets.size();
		int cut = 0;
		long minTarget = Long.MAX_VALUE;
		while (cut < caseCount && targets.get(cut) >= lo && targets.get(cut) < hi) {
			minTarget = Math.min(minTarget, targets.get(cut));
			cut++;
		}
		if (cut < 2) {
			return Result.decline();
		}
		for (int j = cut + 1; j < Math.min(caseCount, cut + 1 + WINDOW_CONFIRM); j++) {
			long t = targets.get(j);
			if (t >= lo && t < hi) {
				return Result.decline(); // the table comes back into the window; ambiguous
			}
		}
		return Result.bounded(cut, minTarget, Rule.SWITCH_WINDOW);
	}

	/**
	 * The grm-yjiq overlapping byte table (see the class javadoc), or null: exactly one moving
	 * load table, one byte wide, spanning {@code caseCount + 1} bytes -- 2-byte entries read at
	 * {@code tbl+i} and {@code tbl+1+i} for case {@code i}. Fixed ({@code num == 1}) loads are
	 * ignored, as in {@link Shape#of}. Needs at least 4 cases, so the even half has the 2 entries
	 * every rule requires.
	 */
	static LoadTableEntry overlappingByteTable(int caseCount, List<LoadTableEntry> loadTables) {
		if (caseCount < 4) {
			return null;
		}
		LoadTableEntry found = null;
		for (LoadTableEntry t : loadTables) {
			if (t.num() <= 1) {
				continue;
			}
			if (found != null) {
				return null; // more than one moving table; not this shape
			}
			found = t;
		}
		if (found == null || found.entrySize() != 1 || found.num() != caseCount + 1) {
			return null;
		}
		return found;
	}

	/** Re-runs {@code rule} over the even cases of a grm-yjiq overlapping byte table, described
	 *  as the non-overlapping 2-byte table they really are, and marks a bounded result stride 2.
	 *  Declines when the tables are not that shape. */
	private static Result onEvenCases(List<Long> targets, List<LoadTableEntry> loadTables,
			BiFunction<List<Long>, List<LoadTableEntry>, Result> rule) {
		LoadTableEntry table = overlappingByteTable(targets.size(), loadTables);
		if (table == null) {
			return Result.decline();
		}
		List<Long> even = new ArrayList<>();
		for (int i = 0; i < targets.size(); i += 2) {
			even.add(targets.get(i));
		}
		Result r = rule.apply(even, List.of(new LoadTableEntry(table.start(), 2, even.size())));
		return r.isBounded() ? r.withStride(2) : r;
	}

	/**
	 * Apply the valid-target bound (grm-yjiq), for the one table shape where both rules above can
	 * decline yet the decompiler's count is still provably wrong: the overlapping byte table (see
	 * the class javadoc), whose odd cases are never real. rcproam 9ad4 is the case: its eleven
	 * handlers sit on BOTH sides of the table (8160..9d8e, d0c8), so there is no lowest target to
	 * stop at and no window to stay in. What ends it is that the next even entries point at
	 * memory no code lives in (2120 and 2725, the unmapped PPU mirror; then 11a9). So, over the
	 * even cases: keep entries while {@code inCode} holds, cut at the first that fails, and trust
	 * the cut only if the {@link #WINDOW_CONFIRM} entries after it (as many as exist) fail too.
	 *
	 * <p>Declines for any other shape -- there, keeping the decompiler's count when the extent
	 * rules decline stays the conservative default -- and when fewer than 2 entries are kept, when
	 * every even entry passes (nothing to cut at), or when the confirm check fails.
	 *
	 * @param targets as for {@link #bound}
	 * @param loadTables as for {@link #bound}
	 * @param inCode per case, in the same order as {@code targets}: whether that target lies in
	 *               memory that can hold code (the caller decides; initialized memory, in practice)
	 * @return a stride-2 bounded result, or a decline
	 */
	public static Result boundByValidTargets(List<Long> targets, List<LoadTableEntry> loadTables,
			List<Boolean> inCode) {
		if (overlappingByteTable(targets.size(), loadTables) == null ||
			inCode.size() != targets.size()) {
			return Result.decline();
		}
		int m = (targets.size() + 1) / 2; // even cases
		int cut = 0;
		long minTarget = Long.MAX_VALUE;
		while (cut < m && inCode.get(2 * cut)) {
			minTarget = Math.min(minTarget, targets.get(2 * cut));
			cut++;
		}
		if (cut < 2 || cut == m) {
			return Result.decline();
		}
		for (int k = cut + 1; k < Math.min(m, cut + 1 + WINDOW_CONFIRM); k++) {
			if (inCode.get(2 * k)) {
				return Result.decline(); // a later entry is plausible again; ambiguous
			}
		}
		return Result.bounded(cut, minTarget, Rule.VALID_TARGET_CUT).withStride(2);
	}

	/** Which rule produced a bounded {@link Result}. */
	public enum Rule {
		/** {@link #bound}: the table precedes its targets and cannot overlap the lowest one. */
		LOWEST_TARGET,
		/** {@link #boundBySwitchWindow}: the table follows its targets, which lie between the
		 *  switch and the table. */
		SWITCH_WINDOW,
		/** {@link #bound}: grm-fxtp -- the table precedes its targets, but the walk was cut at the
		 *  first over-read entry falling below the table's own start rather than dragging
		 *  {@code minTarget} below it and declining. */
		BELOW_TABLE_CUT,
		/** {@link #boundByValidTargets}: grm-yjiq -- an overlapping byte table, cut at the first
		 *  even entry whose target cannot hold code. */
		VALID_TARGET_CUT
	}

	/** The reconstructed table shape both rules share: each moving load table's start and
	 *  per-entry byte extent, and the table's lowest address. */
	private static final class Shape {
		private final long[] start;
		private final long[] chunk;
		private final long tableStart;

		private Shape(long[] start, long[] chunk, long tableStart) {
			this.start = start;
			this.chunk = chunk;
			this.tableStart = tableStart;
		}

		/** Null if there are fewer than 2 cases, no moving table, or a moving table that does
		 *  not divide evenly into the case count (see the class javadoc). */
		static Shape of(int caseCount, List<LoadTableEntry> loadTables) {
			if (caseCount < 2) {
				return null; // need two entries to tell a table from a fixed load
			}
			// Only "moving" tables (num > 1) are part of the table shape; num == 1 is a fixed
			// lookup and is ignored entirely, like the C++ reference ignoring a non-moving LOAD.
			List<LoadTableEntry> moving = new ArrayList<>();
			for (LoadTableEntry t : loadTables) {
				if (t.num() <= 1) {
					continue;
				}
				if ((long) t.entrySize() * t.num() % caseCount != 0) {
					return null; // non-uniform shape; not understood
				}
				moving.add(t);
			}
			if (moving.isEmpty()) {
				return null; // no table shape to bound at all
			}
			long[] start = new long[moving.size()];
			long[] chunk = new long[moving.size()];
			long tableStart = Long.MAX_VALUE;
			for (int k = 0; k < moving.size(); k++) {
				LoadTableEntry t = moving.get(k);
				start[k] = t.start();
				chunk[k] = (long) t.entrySize() * t.num() / caseCount;
				tableStart = Math.min(tableStart, t.start());
			}
			return new Shape(start, chunk, tableStart);
		}

		/** One past the last byte entry {@code i} occupies, across every moving table. */
		long entryEnd(int i) {
			long end = 0;
			for (int k = 0; k < start.length; k++) {
				end = Math.max(end, start[k] + (long) (i + 1) * chunk[k]);
			}
			return end;
		}
	}
}
