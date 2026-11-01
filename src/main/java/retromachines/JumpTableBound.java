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
import java.util.Collection;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.LongUnaryOperator;
import java.util.function.Predicate;

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
		private final int planarGap;

		private Result(boolean bounded, int count, long lowestTarget, Rule rule, int stride,
				int planarGap) {
			this.bounded = bounded;
			this.count = count;
			this.lowestTarget = lowestTarget;
			this.rule = rule;
			this.stride = stride;
			this.planarGap = planarGap;
		}

		private static Result decline() {
			return new Result(false, -1, -1, null, 1, 0);
		}

		private static Result bounded(int count, long lowestTarget, Rule rule) {
			return new Result(true, count, lowestTarget, rule, 1, 0);
		}

		private Result withStride(int newStride) {
			return new Result(bounded, count, lowestTarget, rule, newStride, planarGap);
		}

		private Result withPlanarGap(int gap) {
			return new Result(bounded, count, lowestTarget, rule, stride, gap);
		}

		/** The distance between the low-byte and high-byte tables when this result came from a
		 *  grm-d59c planar split table (see {@link #planarGap(int, List)}), else 0. */
		public int planarGap() {
			return planarGap;
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
			Result planar = onPlanarPrefix(targets, loadTables, (t, l) -> bound(t, l, tableBlock));
			if (planar.isBounded()) {
				return planar;
			}
			return onEvenCases(targets, loadTables, (t, l) -> bound(t, l, tableBlock));
		}
		int caseCount = targets.size();
		// Established once entry 0's own target sits above the table: the table-before-code idiom
		// that makes a later below-table entry meaningful as a cut point rather than noise.
		boolean tableBeforeCode = tableBlock != null && targets.get(0) > shape.tableStart;
		// grm-rsxe: when the table dispatches into its OWN block (entry 0 is there), a below-table
		// target in that block is a real handler on the other side of the table (tmnt B5 940a:
		// handlers 864b..9464 and 9464..a59f), not an over-read -- it is skipped rather than cut, and
		// the table keeps bounding by the lowest target ABOVE the table. Over-read garbage lands
		// outside the block (lwings dcb3's 8c84 is the switchable window, the table the fixed bank).
		// When entry 0 is outside the block the table's real targets live elsewhere and an in-block
		// one is the garbage (cv3 e137): no skip. A skipped entry still counts as a kept entry.
		Predicate<Long> skipped = t -> tableBeforeCode && t < shape.tableStart &&
			tableBlock.contains(t) && tableBlock.contains(targets.get(0));
		TableScorer.Result<Long, Stop> walk = TableScorer.walk(caseCount, (i, before) -> {
			Long lowest = lowestExcept(before, skipped);
			if (lowest != null && shape.entryEnd(i) > lowest) {
				// this entry's own bytes would collide with the lowest target so far
				return TableScorer.Entry.rejected(Stop.OVERLAPS_LOWEST_TARGET);
			}
			long target = targets.get(i);
			if (!skipped.test(target) && tableBeforeCode && i >= 2 && target < shape.tableStart) {
				// grm-fxtp: cut here instead of dragging minTarget below tableStart
				return TableScorer.Entry.rejected(Stop.BELOW_TABLE);
			}
			return TableScorer.Entry.accepted(target, List.of());
		}, TableScorer.HARD_ONLY);
		int i = walk.count();
		Long lowest = lowestExcept(walk.targets(), skipped);
		long minTarget = lowest == null ? 0 : lowest;
		boolean haveTarget = lowest != null;
		int belowTableCut = walk.endedBy() == Stop.BELOW_TABLE ? i : -1;
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
		return boundBySwitchWindow(switchAddr, targets, loadTables, List.of());
	}

	/**
	 * {@link #boundBySwitchWindow(long, List, List)}, also stopped at the next table (grm-t223).
	 * Tables after their code are routinely packed back to back, each owned by a different
	 * dispatcher, and when the next table's targets happen to fall inside THIS switch's window the
	 * window walk reads straight through it: contra 849f's table 86bf is 7 entries, but the four
	 * after them are 8285's table at 86cd, whose targets (8500 8522 855c 84a2) all lie in
	 * {@code [849f, 86bf)}, so the window alone keeps 11. So the walk also stops where the nearest
	 * of {@code otherStarts} begins, admitted as for {@link #boundByNeighbourTable} (strictly
	 * inside the extent, not one of this table's own starts, on one of its entry boundaries) --
	 * except that a start failing those is skipped, never a reason to decline. A cut there skips
	 * the confirm check: the entries after it are the neighbour's, in the window by construction
	 * (the very case this exists for), and the neighbour's start is independent evidence the
	 * confirm check only stands in for.
	 *
	 * @param otherStarts flat offsets of OTHER jump tables' moving load-table starts, as for
	 *                    {@link #boundByNeighbourTable}
	 * @return as for {@link #boundBySwitchWindow(long, List, List)}, with rule
	 *         {@link Rule#WINDOW_AT_NEIGHBOUR} when the neighbour, not the window, ended the walk
	 */
	public static Result boundBySwitchWindow(long switchAddr, List<Long> targets,
			List<LoadTableEntry> loadTables, Collection<Long> otherStarts) {
		Shape shape = Shape.of(targets.size(), loadTables);
		if (shape == null) {
			return onEvenCases(targets, loadTables,
				(t, l) -> boundBySwitchWindow(switchAddr, t, l, otherStarts));
		}
		if (shape.tableStart <= switchAddr) {
			return Result.decline();
		}
		long lo = switchAddr;
		long hi = shape.tableStart;
		int caseCount = targets.size();
		long neighbour = shape.nearestNeighbour(otherStarts, shape.entryEnd(caseCount - 1));
		TableScorer.Result<Long, Stop> walk = TableScorer.walk(caseCount, (i, before) -> {
			long target = targets.get(i);
			if (target < lo || target >= hi) {
				return TableScorer.Entry.rejected(Stop.LEFT_WINDOW);
			}
			if (shape.entryEnd(i) > neighbour) {
				return TableScorer.Entry.rejected(Stop.AT_NEIGHBOUR);
			}
			return TableScorer.Entry.accepted(target, List.of());
		}, TableScorer.HARD_ONLY);
		int cut = walk.count();
		long minTarget = lowestOf(walk.targets());
		if (cut < 2) {
			return Result.decline();
		}
		if (walk.endedBy() == Stop.AT_NEIGHBOUR) {
			// Only the neighbour ended the walk (when the window would have too, as at tmnt 8fb8
			// running into 8fc4, the plain window rule and its confirm check apply unchanged).
			return Result.bounded(cut, minTarget, Rule.WINDOW_AT_NEIGHBOUR);
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
	 * grm-d59c: the gap between the two halves of a PLANAR split pointer table, or -1. The game
	 * keeps the low bytes of N pointers at {@code tbl} and the high bytes at {@code tbl+g}
	 * ({@code LDA lo,X / STA $63 / LDA hi,X / STA $64 / JMP ($0063)} -- dodge 8251, lo 8254 and
	 * hi 826e), and the decompiler, recovering more cases than there are entries, reads both
	 * halves past their ends. The two moving byte LOADs then overlap and arrive merged as ONE
	 * size-1 load table of {@code caseCount + g} bytes, which divides by nothing, so
	 * {@link Shape#of} declines it outright and no rule ever runs.
	 * <p>
	 * The merged extent itself gives the gap away, and the gap caps the table: entry {@code i}'s
	 * low byte sits at {@code tbl+i}, so a {@code g+1}-th entry would read its low byte out of the
	 * high table. The band {@code 2 <= g < caseCount} is exactly the one no other shape claims: a
	 * gap of 1 is grm-yjiq's overlapping 2-byte table ({@link #overlappingByteTable}), and a gap of
	 * {@code caseCount} or more means the halves do not overlap and arrive as a shape
	 * {@link Shape#of} already understands. Exactly one moving table, as for grm-yjiq.
	 */
	static int planarGap(int caseCount, List<LoadTableEntry> loadTables) {
		LoadTableEntry found = null;
		for (LoadTableEntry t : loadTables) {
			if (t.num() <= 1) {
				continue;
			}
			if (found != null) {
				return -1; // more than one moving table; not this shape
			}
			found = t;
		}
		if (found == null || found.entrySize() != 1) {
			return -1;
		}
		int gap = found.num() - caseCount;
		return gap >= 2 && gap < caseCount ? gap : -1;
	}

	/** Re-runs {@code rule} over the first {@link #planarGap} cases of a grm-d59c planar split
	 *  table, re-described as the two {@code gap}-entry byte tables it really is (fixed loads kept
	 *  as they were), so the rule walks BOTH halves -- the lowest-target cut then also stops the
	 *  high table short of the code it dispatches to. The gap only ever shrinks the case list, and
	 *  the rule only ever shrinks it further. Declines when the tables are not that shape. */
	private static Result onPlanarPrefix(List<Long> targets, List<LoadTableEntry> loadTables,
			BiFunction<List<Long>, List<LoadTableEntry>, Result> rule) {
		int gap = planarGap(targets.size(), loadTables);
		if (gap < 0) {
			return Result.decline();
		}
		List<LoadTableEntry> halves = new ArrayList<>();
		for (LoadTableEntry t : loadTables) {
			if (t.num() <= 1) {
				halves.add(t);
			}
			else {
				halves.add(new LoadTableEntry(t.start(), 1, gap));
				halves.add(new LoadTableEntry(t.start() + gap, 1, gap));
			}
		}
		Result r = rule.apply(targets.subList(0, gap), halves);
		return r.isBounded() ? r.withPlanarGap(gap) : r;
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
		TableScorer.Result<Long, Stop> walk = TableScorer.walk(m, (i, before) -> inCode.get(2 * i) ?
			TableScorer.Entry.accepted(targets.get(2 * i), List.of()) :
			TableScorer.Entry.rejected(Stop.NOT_IN_CODE), TableScorer.HARD_ONLY);
		int cut = walk.count();
		long minTarget = lowestOf(walk.targets());
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

	/**
	 * Apply the neighbour-table bound (grm-2m07): cut this table where ANOTHER jump table's load
	 * table begins. Dispatch tables are routinely laid end to end, and a neighbour's entries are
	 * valid code addresses by construction, so the extent rules above (and grm-os9b's measured
	 * attempt to run {@link #boundByValidTargets} on ordinary shapes) cannot see where one table
	 * stops and the next starts. dbz2 is the case: {@code cb97 JMP ($0021)} reads its table at
	 * dd47, {@code cbfd JMP ($0026)} (inside the IRQ handler) reads its own at dd65, so cb97 has
	 * exactly 15 entries; its targets sit below both the switch and the table, so neither
	 * {@link #bound} nor {@link #boundBySwitchWindow} applies.
	 *
	 * <p>The neighbour start must be independently established by the caller -- another switch's
	 * own decompiled load table, never something inferred from this table's entries -- and must
	 * fall on one of this table's entry boundaries (an off-by-one start is likelier a split
	 * lo/hi layout than a neighbour, so it declines). Declines when no start lies strictly inside
	 * the extent, when fewer than 2 entries would be kept, and when ANY kept entry fails
	 * {@code inCode}: a real neighbour sits right after this table's last real entry, so a cut
	 * that keeps a RAM or I/O target has found a start far past the over-read, not the idiom.
	 *
	 * <p><b>The shape this cannot tell apart</b>: a second switch indexing into a SUFFIX of this
	 * same table (two entry points into one table). Its start looks exactly like a neighbour's,
	 * and the table bytes cannot distinguish the two; the cut would then drop real cases. That is
	 * why this runs only as the last fallback, after every extent rule has declined, where the
	 * alternative is the decompiler's own over-read.
	 *
	 * @param targets as for {@link #bound}
	 * @param loadTables as for {@link #bound}
	 * @param otherStarts flat offsets of OTHER jump tables' moving load-table starts, in this
	 *                    table's memory; this table's own starts are ignored if present
	 * @param inCode as for {@link #boundByValidTargets}
	 * @return a bounded result, or a decline
	 */
	public static Result boundByNeighbourTable(List<Long> targets, List<LoadTableEntry> loadTables,
			Collection<Long> otherStarts, List<Boolean> inCode) {
		if (inCode.size() != targets.size()) {
			return Result.decline();
		}
		Shape shape = Shape.of(targets.size(), loadTables);
		if (shape == null) {
			if (overlappingByteTable(targets.size(), loadTables) == null) {
				return Result.decline();
			}
			List<Boolean> evenInCode = new ArrayList<>();
			for (int i = 0; i < inCode.size(); i += 2) {
				evenInCode.add(inCode.get(i));
			}
			return onEvenCases(targets, loadTables,
				(t, l) -> boundByNeighbourTable(t, l, otherStarts, evenInCode));
		}
		int caseCount = targets.size();
		long extentEnd = shape.entryEnd(caseCount - 1);
		long neighbour = Long.MAX_VALUE;
		for (long n : otherStarts) {
			if (n > shape.tableStart && n < extentEnd && !shape.isOwnStart(n)) {
				neighbour = Math.min(neighbour, n);
			}
		}
		if (neighbour == Long.MAX_VALUE || !shape.isEntryBoundary(neighbour)) {
			return Result.decline();
		}
		final long cutAt = neighbour;
		TableScorer.Result<Long, Stop> walk = TableScorer.walk(caseCount, (i, before) -> {
			if (shape.entryEnd(i) > cutAt) {
				return TableScorer.Entry.rejected(Stop.AT_NEIGHBOUR);
			}
			if (!inCode.get(i)) {
				return TableScorer.Entry.rejected(Stop.NOT_IN_CODE);
			}
			return TableScorer.Entry.accepted(targets.get(i), List.of());
		}, TableScorer.HARD_ONLY);
		if (walk.endedBy() == Stop.NOT_IN_CODE) {
			// A kept entry that cannot be code means the neighbour lies past garbage this table
			// already over-read (measured: dbz2/dbz_saiyan tables whose cut would have labelled
			// zero-page and PPU targets as cases) -- not the idiom, decline.
			return Result.decline();
		}
		int cut = walk.count();
		long minTarget = lowestOf(walk.targets());
		if (cut < 2) {
			return Result.decline();
		}
		return Result.bounded(cut, minTarget, Rule.NEIGHBOUR_TABLE);
	}

	/**
	 * Apply the known-code bound (grm-rsxe): cut this table at the first entry whose own bytes
	 * contain a target ANOTHER table was already bounded to. Dispatch tables are routinely laid
	 * right before a handler, and when that handler belongs to a different switch, nothing in this
	 * table's own entries marks where it ends. tmnt is the case: bank 5's {@code 9474 JMP ($0000)}
	 * reads its table at 9477; its entry 0 is 9464, BELOW the table, so {@link #bound} declines,
	 * and the switch window does not apply -- but {@code 9407}'s table (940a, bounded by
	 * {@link #bound}) dispatches to 94a5, which is exactly where 9477's 23 entries end.
	 *
	 * <p>{@code codeStarts} must be the kept targets of tables bounded in the SAME pass, never the
	 * decompiler's raw (possibly over-read) cases and never something read off the listing: the
	 * former would cut at phantom targets, the latter would make the result depend on what
	 * analysis order happened to disassemble first. Declines for a shape {@link Shape#of} does not
	 * understand, when no code start lies inside the extent above the table, when fewer than 2
	 * entries would be kept, and when any kept entry fails {@code inCode}.
	 *
	 * @param targets as for {@link #bound}
	 * @param loadTables as for {@link #bound}
	 * @param codeStarts flat offsets of other bounded tables' kept targets, in this table's memory
	 * @param inCode as for {@link #boundByValidTargets}
	 * @return a bounded result, or a decline
	 */
	public static Result boundByKnownCode(List<Long> targets, List<LoadTableEntry> loadTables,
			Collection<Long> codeStarts, List<Boolean> inCode) {
		if (inCode.size() != targets.size()) {
			return Result.decline();
		}
		Shape shape = Shape.of(targets.size(), loadTables);
		if (shape == null) {
			return Result.decline();
		}
		int caseCount = targets.size();
		TableScorer.Result<Long, Stop> walk = TableScorer.walk(caseCount, (i, before) -> {
			for (long c : codeStarts) {
				if (shape.entryContains(i, c)) {
					return TableScorer.Entry.rejected(Stop.CONTAINS_CODE_START);
				}
			}
			return TableScorer.Entry.accepted(targets.get(i), List.of());
		}, TableScorer.HARD_ONLY);
		// No entry contains a code start: nothing to cut at.
		int cut = walk.endedBy() == Stop.CONTAINS_CODE_START ? walk.count() : -1;
		if (cut < 2) {
			return Result.decline();
		}
		long minTarget = Long.MAX_VALUE;
		for (int k = 0; k < cut; k++) {
			if (!inCode.get(k)) {
				return Result.decline(); // the code start lies past garbage already over-read
			}
			minTarget = Math.min(minTarget, targets.get(k));
		}
		return Result.bounded(cut, minTarget, Rule.KNOWN_CODE);
	}

	/**
	 * Apply the extent-overlap bound (grm-c9d.8.6), the tail form of {@link #leadingByExtent}: cut
	 * the table at the first entry whose bytes lie inside the decoded extent of an EARLIER entry's
	 * target. A table cannot overlap the code it dispatches to -- the rule {@link #bound} applies to
	 * the lowest target -- but {@link #bound} declines outright once any target lies below the
	 * table (handlers on both sides of it), so a table that runs straight into its own handler
	 * above it is never cut there. This rule ignores below-table targets and measures only the code
	 * that actually starts at each above-table target, so it still sees the table end where its
	 * handler begins. rcproam c632 is the case: its table at c635 has handlers on both sides
	 * (c605..c622 below, c649..c701 above), and entry 9's handler c649 starts exactly at slot 10,
	 * so the 102 cases the decompiler read are 10 -- what follows is that handler's code.
	 *
	 * <p>Earlier targets only: walking from slot 0, every target judged is one already kept, so a
	 * junk target read from the over-read can never cut the real entries before it. Runs only as
	 * the last fallback, after every other tail rule has declined.
	 *
	 * <p>Declines for a shape {@link Shape#of} does not understand, when no entry lies inside an
	 * earlier handler (nothing to cut at), when fewer than 2 entries would be kept, and when any
	 * kept entry fails {@code inCode} (the handler lies past garbage already over-read, as for
	 * {@link #boundByKnownCode}).
	 *
	 * @param targets as for {@link #bound}
	 * @param loadTables as for {@link #bound}
	 * @param extentEnd the exclusive end of the code decoded linearly from a target, as for
	 *                  {@link LeadingFacts#extentEnd()}
	 * @param inCode as for {@link #boundByValidTargets}
	 * @return a bounded result, or a decline
	 */
	public static Result boundByExtentOverlap(List<Long> targets, List<LoadTableEntry> loadTables,
			LongUnaryOperator extentEnd, List<Boolean> inCode) {
		if (inCode.size() != targets.size()) {
			return Result.decline();
		}
		Shape shape = Shape.of(targets.size(), loadTables);
		if (shape == null) {
			return Result.decline();
		}
		int caseCount = targets.size();
		long[] end = new long[caseCount];
		TableScorer.Result<Long, Stop> walk = TableScorer.walk(caseCount, (i, before) -> {
			for (int k = 0; k < i; k++) {
				long t = targets.get(k);
				if (t >= shape.tableStart && shape.entryOverlaps(i, t, end[k])) {
					return TableScorer.Entry.rejected(Stop.INSIDE_HANDLER);
				}
			}
			long t = targets.get(i);
			end[i] = Math.max(extentEnd.applyAsLong(t), t + 1);
			return TableScorer.Entry.accepted(t, List.of());
		}, TableScorer.HARD_ONLY);
		int cut = walk.endedBy() == Stop.INSIDE_HANDLER ? walk.count() : -1;
		if (cut < 2) {
			return Result.decline();
		}
		for (int k = 0; k < cut; k++) {
			if (!inCode.get(k)) {
				return Result.decline(); // the handler lies past garbage already over-read
			}
		}
		return Result.bounded(cut, lowestOf(walk.targets()), Rule.EXTENT_OVERLAP);
	}

	/**
	 * How many of a bounded table's kept cases to keep once each one's target bytes have been
	 * judged as code (grm-0pen): the cases up to, but not including, the first whose target does
	 * not decode as code -- trusted only when the {@link #CODE_CUT_CONFIRM} cases after it (as many
	 * as exist) fail too, as {@link #boundByValidTargets} confirms its cut. Otherwise, or when the
	 * prefix would hold fewer than 2 (nothing trustworthy to cut to), or every case decodes, all of
	 * them. The confirm is what stops one odd real handler from truncating a real table.
	 *
	 * <p>When that first cut is ambiguous, the TRAILING run of cases that do not decode is still
	 * cut (grm-8x6f), keeping at least 2: nothing follows it to vouch for it, which is why a first
	 * failure on the last case already stands unconfirmed. megaman2 92e4's 14 real entries hold
	 * one odd one (entry 10, e6b5, an undefined opcode), and the planar extent's 15th entry is
	 * $ff filler; the odd entry alone used to keep the filler.
	 *
	 * <p>This is a REFINEMENT of a bound some rule above already proved, never a rule of its own:
	 * it can only shorten a kept list, so it cannot add a phantom case. That is the line grm-os9b
	 * drew. A first-non-code cut used as a last-resort bound sails through an adjacent table's
	 * (valid) entries and stamps them as this switch's cases. Here the extent is already capped,
	 * and the bytes test is far stronger than "in code memory": Deadly Towers' bank-2 trampoline
	 * table is capped at 96 entries by its lowest target, but only 6 are real (its 31 callers pass
	 * indices 0..5); entry 6 onward point into 3-byte data records that decode to an undefined
	 * opcode or a BRK within a few steps.
	 *
	 * @param decodes per kept case, in order: whether its target decodes as code
	 * @return the number of leading cases to keep, between 2 and {@code decodes.size()}, or
	 *         {@code decodes.size()} unchanged
	 */
	static int codePrefix(List<Boolean> decodes) {
		int n = 0;
		while (n < decodes.size() && decodes.get(n)) {
			n++;
		}
		if (n < 2 || n == decodes.size()) {
			return decodes.size();
		}
		for (int k = n + 1; k < Math.min(decodes.size(), n + 1 + CODE_CUT_CONFIRM); k++) {
			if (decodes.get(k)) {
				// A case right after the cut decodes again; ambiguous. Cut only the trailing run,
				// which stops at case k, so at least the n >= 2 prefix stays.
				int tail = decodes.size();
				while (!decodes.get(tail - 1)) {
					tail--;
				}
				return tail;
			}
		}
		return n;
	}

	/** How many cases after a {@link #codePrefix} cut must also fail to decode for it to stand. */
	static final int CODE_CUT_CONFIRM = 2;

	/**
	 * Whether the bytes at a kept case's target read as the start of a table of little-endian
	 * words into one page, rather than a handler (grm-6j5q): {@link #WORD_TABLE_RUN} words sharing
	 * one high byte, with strictly increasing low bytes. Such bytes can pseudo-decode for the
	 * whole of {@link InlineJumpTableDispatch#decodesAsCode}'s budget -- cv3 a04f's over-read
	 * entries 19..28 point into a table of {@code xx a1} words, which decodes as a run of
	 * {@code ORA abs,Y} / {@code LDA (zp,X)} -- and so make the first {@link #codePrefix} cut look
	 * ambiguous. Real code rarely repeats one byte at every other position: 6502 instructions are
	 * 1 to 3 bytes long.
	 *
	 * @param bytes the bytes at the target; fewer than {@code 2 * WORD_TABLE_RUN} never match
	 */
	static boolean looksLikeWordTable(byte[] bytes) {
		if (bytes.length < 2 * WORD_TABLE_RUN) {
			return false;
		}
		for (int k = 1; k < WORD_TABLE_RUN; k++) {
			if (bytes[2 * k + 1] != bytes[1] ||
				(bytes[2 * k] & 0xff) <= (bytes[2 * k - 2] & 0xff)) {
				return false;
			}
		}
		return true;
	}

	/** How many words {@link #looksLikeWordTable} needs. */
	static final int WORD_TABLE_RUN = 4;

	/** Why a per-entry walk ended at an entry (the reason type of its {@link TableScorer} walk). */
	private enum Stop {
		/** {@link #bound}: grm-fxtp -- a target below the table's own start, from entry 2 on. */
		BELOW_TABLE,
		/** {@link #bound}: the entry's own bytes would reach the lowest target so far. */
		OVERLAPS_LOWEST_TARGET,
		/** {@link #boundBySwitchWindow}: the target lies outside the switch window. */
		LEFT_WINDOW,
		/** The entry's bytes would reach another table's start. */
		AT_NEIGHBOUR,
		/** The target lies in memory that cannot hold code. */
		NOT_IN_CODE,
		/** {@link #boundByKnownCode}: the entry's bytes contain another table's target. */
		CONTAINS_CODE_START,
		/** {@link #boundByExtentOverlap}: the entry's bytes lie in an earlier target's code. */
		INSIDE_HANDLER
	}

	/** The lowest of {@code ts} that {@code skip} does not exclude, or null when there is none. */
	private static Long lowestExcept(List<Long> ts, Predicate<Long> skip) {
		Long lowest = null;
		for (long t : ts) {
			if (!skip.test(t) && (lowest == null || t < lowest)) {
				lowest = t;
			}
		}
		return lowest;
	}

	/** The lowest of {@code ts}, or {@link Long#MAX_VALUE} when empty. */
	private static long lowestOf(List<Long> ts) {
		long lowest = Long.MAX_VALUE;
		for (long t : ts) {
			lowest = Math.min(lowest, t);
		}
		return lowest;
	}

	/** Which rule produced a bounded {@link Result}. */
	public enum Rule {
		/** {@link #bound}: the table precedes its targets and cannot overlap the lowest one. */
		LOWEST_TARGET,
		/** {@link #boundBySwitchWindow}: the table follows its targets, which lie between the
		 *  switch and the table. */
		SWITCH_WINDOW,
		/** {@link #boundBySwitchWindow}: grm-t223 -- as {@link #SWITCH_WINDOW}, but the walk was
		 *  ended by the start of another switch's table packed right after this one. */
		WINDOW_AT_NEIGHBOUR,
		/** {@link #bound}: grm-fxtp -- the table precedes its targets, but the walk was cut at the
		 *  first over-read entry falling below the table's own start rather than dragging
		 *  {@code minTarget} below it and declining. */
		BELOW_TABLE_CUT,
		/** {@link #boundByValidTargets}: grm-yjiq -- an overlapping byte table, cut at the first
		 *  even entry whose target cannot hold code. */
		VALID_TARGET_CUT,
		/** {@link #boundByNeighbourTable}: grm-2m07 -- cut where another jump table's load table
		 *  begins. */
		NEIGHBOUR_TABLE,
		/** {@link #boundByKnownCode}: grm-rsxe -- cut where another bounded table's target
		 *  begins. */
		KNOWN_CODE,
		/** {@link #boundBySearchLoop}: grm-jt7s -- the index comes from a keyed linear search,
		 *  whose value set {@link SearchLoopDispatch} reads exactly. */
		SEARCH_LOOP,
		/** {@link #boundByDistinctWords}: grm-uzep -- lowest-target walk over the table's own
		 *  words, for a decompiler case list deduplicated by target. */
		DISTINCT_WORDS,
		/** {@link #boundByIndexGuard}: grm-c9d.8.2 -- the slots a recovered {@code CMP #imm}
		 *  guard says the dispatch reaches ({@link IndexGuardRecovery}). */
		INDEX_GUARD,
		/** {@link #boundByExtentOverlap}: grm-c9d.8.6 -- cut at the first entry whose bytes lie in
		 *  an earlier target's decoded code (the table runs into its own handler). */
		EXTENT_OVERLAP
	}

	/**
	 * grm-uzep: the lowest-target bound for a table whose decompiler case list is DEDUPLICATED --
	 * one case per distinct target in first-seen order, not one per slot. That is what a
	 * {@code LDA tbl,X / STA $61 / LDA tbl+1,X / STA $62 / JMP ($0061)} dispatch yields (dodge
	 * 82ba): the switch is on the loaded pointer value, so a handler shared by many slots appears
	 * once, and the load table (one size-1 byte table of {@code 2 * words}) divides by no case
	 * count, so {@link #bound} cannot run. Instead the table's own little-endian words are read and
	 * walked with the lowest-target rule (the table cannot extend past its own lowest target), and
	 * the distinct targets of the kept words must be exactly the leading cases, or it declines.
	 *
	 * @param words the table's words, in slot order, over the whole load-table extent
	 * @param tableStart flat offset of the table's first byte
	 * @param caseTargets the decompiler's case targets, in its order (default excluded)
	 * @return bounded with the number of kept CASES (distinct targets), or a decline when a word
	 *         does not lie above the table, the table never reaches its lowest target within
	 *         {@code words}, or the kept words' distinct targets are not a prefix of the cases
	 */
	public static Result boundByDistinctWords(List<Long> words, long tableStart,
			List<Long> caseTargets) {
		int slots = distinctWordSlots(words, tableStart);
		if (slots < 0) {
			return Result.decline(); // table does not precede its targets; idiom doesn't apply
		}
		long minTarget = Long.MAX_VALUE;
		List<Long> distinct = new ArrayList<>();
		for (int i = 0; i < slots; i++) {
			long target = words.get(i);
			minTarget = Math.min(minTarget, target);
			if (!distinct.contains(target)) {
				distinct.add(target);
			}
		}
		if (slots < 2 || slots == words.size() || distinct.size() < 2 ||
			distinct.size() >= caseTargets.size() ||
			!caseTargets.subList(0, distinct.size()).equals(distinct)) {
			return Result.decline();
		}
		return Result.bounded(distinct.size(), minTarget, Rule.DISTINCT_WORDS);
	}

	/**
	 * The number of words (slots) {@link #boundByDistinctWords} keeps: the lowest-target walk over
	 * the table's own words, stopping where the next entry's bytes would collide with the lowest
	 * target so far. -1 when a word does not lie above the table.
	 */
	public static int distinctWordSlots(List<Long> words, long tableStart) {
		long minTarget = Long.MAX_VALUE;
		int slots = 0;
		for (int i = 0; i < words.size(); i++) {
			if (tableStart + 2L * (i + 1) > minTarget) {
				break; // this entry's own bytes would collide with the lowest target so far
			}
			long target = words.get(i);
			if (target <= tableStart) {
				return -1;
			}
			minTarget = Math.min(minTarget, target);
			slots = i + 1;
		}
		return slots;
	}

	/**
	 * grm-jt7s: the bound {@link SearchLoopDispatch} recovered, {@code count} cases. Its cases are
	 * that class's own list, not a prefix or stride of the decompiler's, so {@link Result#keep}
	 * does not apply to it.
	 */
	public static Result boundBySearchLoop(int count, long lowestTarget) {
		return Result.bounded(count, lowestTarget, Rule.SEARCH_LOOP);
	}

	/**
	 * grm-c9d.8.2: the bound a recovered index guard states, {@code count} slots. Like the search
	 * loop it is exact, not an extent to refine: its slots start where the guard says, not at the
	 * decompiler's table start, so {@link Result#keep} does not apply.
	 */
	public static Result boundByIndexGuard(int count, long lowestTarget) {
		return Result.bounded(count, lowestTarget, Rule.INDEX_GUARD);
	}

	// ---------------------------------------------------------------------------------------------
	// grm-c9d.8.3: two-ended forms of the trim rules above -- the LEADING cuts, run in shadow mode.
	// ---------------------------------------------------------------------------------------------

	/**
	 * The leading (start-side) forms of the trim rules, grm-c9d.8.3 (owner ruling 2026-11-01: every
	 * trim rule applies to both ends wherever that makes sense). Each one drops the first
	 * {@link Leading#drop()} slots of an already tail-bounded table and keeps the rest.
	 *
	 * <p>Common frame, shared by every leading form below:
	 * <ul>
	 * <li><b>The tail-verified end is the anchor.</b> The tail rules (and the decompiler's own
	 * end) fixed the LAST kept entry; a leading rule only ever drops slots from the front, never
	 * the last one, and an interior violation drops the side before it (owner ruling).</li>
	 * <li><b>At least 2 slots survive</b>, as for every tail rule; otherwise the rule declines.</li>
	 * <li>The input is the post-tail view: {@code targets} are the kept entries in slot order and
	 * {@code view} describes exactly their bytes, one {@link LoadTableEntry} per moving table as
	 * {@code (start, perEntryBytes, keptCount)} (see {@link #leadingView}).</li>
	 * <li>A recovered {@link Rule#INDEX_GUARD} beats all of these: the caller does not run them for
	 * a guarded table.</li>
	 * </ul>
	 */
	public enum LeadingRule {
		/** {@link #leadingByExtent}: no kept entry's bytes inside another kept target's code. */
		EXTENT_OVERLAP,
		/** {@link #leadingByKnownCode}: no kept entry's bytes inside another table's handler. */
		KNOWN_CODE_OVERLAP,
		/** {@link #leadingByBelowTable}: mirror of grm-fxtp's below-table cut. */
		BELOW_TABLE,
		/** {@link #leadingBySwitchWindow}: mirror of the grm-akiv switch window. */
		SWITCH_WINDOW,
		/** {@link #leadingByValidTargets}: mirror of grm-yjiq's valid-target cut. */
		VALID_TARGET,
		/** {@link #leadingByNeighbourEnd}: mirror of grm-2m07's neighbour-table cut. */
		NEIGHBOUR_END,
		/** {@link #leadingByCodePrefix}: mirror of grm-0pen's codePrefix. */
		CODE_PREFIX,
		/** {@link #leadingByExtent} on a table NO tail rule bounded, so with no verified end to
		 *  anchor on: reported for the sweep, never part of {@link #CASCADE}. */
		EXTENT_OVERLAP_UNANCHORED,
		/** {@link #leadingByDistinctWords}: grm-uzep's table, read as words. */
		DISTINCT_WORDS_EXTENT,
		/** All of the above applied in sequence (EXTENT, KNOWN_CODE, BELOW_TABLE, WINDOW,
		 *  VALID_TARGET, NEIGHBOUR_END, CODE_PREFIX): the total a stage-4 cascade would drop. */
		CASCADE
	}

	/** What one leading rule says: drop the first {@link #drop()} slots, or ({@code drop == 0})
	 *  nothing to say. */
	public static final class Leading {
		private final LeadingRule rule;
		private final int drop;

		private Leading(LeadingRule rule, int drop) {
			this.rule = rule;
			this.drop = drop;
		}

		static Leading none(LeadingRule rule) {
			return new Leading(rule, 0);
		}

		/** Which rule. */
		public LeadingRule rule() {
			return rule;
		}

		/** How many leading slots the rule drops; 0 when it declines or finds nothing. */
		public int drop() {
			return drop;
		}

		/** Whether the rule would drop anything. */
		public boolean applies() {
			return drop > 0;
		}
	}

	/**
	 * The inputs the leading rules need beyond the post-tail targets and view. Every list is aligned
	 * with the kept targets; any member may be null to switch off the rules that need it.
	 *
	 * @param switchAddr flat offset of the switch instruction
	 * @param block the table's memory block, for {@link #leadingByBelowTable}
	 * @param extentEnd the exclusive end of the code run decoded linearly from a target (bytes
	 *                  only, to a return or unconditional jump, stopping at calls): the extent a
	 *                  table's own bytes must not lie in
	 * @param foreignCodeStarts kept targets of OTHER tables bounded in the same pass
	 * @param otherTableEnds exclusive ends of OTHER tables' bounded extents
	 * @param inCode per kept entry, as for {@link #boundByValidTargets}
	 * @param decodes per kept entry, as for {@link #codePrefix}
	 * @param overlappingByte whether the table is a grm-yjiq overlapping byte table (kept entries
	 *                        are its even cases)
	 * @param tailRule the tail rule that bounded the table, or null when none did. A leading form
	 *                 runs only where its tail rule would have: the window form for a table after
	 *                 its code, the below-table form for one before it, the neighbour and
	 *                 known-code forms only as last fallbacks (the tail order of the analyzer). The
	 *                 two extent forms need a bound: they anchor on the tail-verified end, and an
	 *                 unbounded table has none -- there an overlap of slots with handlers is as
	 *                 likely an over-read TAIL (real-ROM sweep: tmnt 823b, dbz_saiyan d286,
	 *                 dragonpower 803e, rcproam c635, each a real table followed by its own
	 *                 handlers and then junk) as a bad start
	 */
	public record LeadingFacts(long switchAddr, Block block, LongUnaryOperator extentEnd,
			Collection<Long> foreignCodeStarts, Collection<Long> otherTableEnds,
			List<Boolean> inCode, List<Boolean> decodes, boolean overlappingByte, Rule tailRule) {

		/** Whether a leading form gated on the tail rules {@code allowed} (or none) may run. */
		boolean gate(Rule... allowed) {
			if (tailRule == null) {
				return true;
			}
			for (Rule r : allowed) {
				if (r == tailRule) {
					return true;
				}
			}
			return false;
		}
	}

	/**
	 * The load-table view the leading rules measure against, for the first {@code kept} entries of
	 * a table the tail rules bounded (or left whole): one {@code (start, perEntryBytes, kept)} per
	 * moving table. {@code stride} 2 is the grm-yjiq overlapping byte table (re-described as 2-byte
	 * entries, as the tail rules do) and {@code planarGap > 0} the grm-d59c planar split table (two
	 * byte tables {@code gap} apart), so both halves of a planar table move together when the start
	 * shifts, and a start shift applies under stride 2 as well (those normalisers are not cuts).
	 * Null when the shape is not understood, exactly where {@link Shape#of} declines.
	 */
	public static List<LoadTableEntry> leadingView(int originalCases,
			List<LoadTableEntry> loadTables, int kept, int stride, int planarGap) {
		if (stride == 2) {
			LoadTableEntry table = overlappingByteTable(originalCases, loadTables);
			return table == null ? null : List.of(new LoadTableEntry(table.start(), 2, kept));
		}
		List<LoadTableEntry> view = new ArrayList<>();
		if (planarGap > 0) {
			for (LoadTableEntry t : loadTables) {
				if (t.num() > 1) {
					view.add(new LoadTableEntry(t.start(), 1, kept));
					view.add(new LoadTableEntry(t.start() + planarGap, 1, kept));
				}
			}
			return view.isEmpty() ? null : view;
		}
		if (originalCases < 2 || kept < 1) {
			return null;
		}
		for (LoadTableEntry t : loadTables) {
			if (t.num() <= 1) {
				continue;
			}
			long bytes = (long) t.entrySize() * t.num();
			if (bytes % originalCases != 0) {
				return null;
			}
			view.add(new LoadTableEntry(t.start(), (int) (bytes / originalCases), kept));
		}
		return view.isEmpty() ? null : view;
	}

	/** The exclusive end of the lowest moving table of a {@link #leadingView}, or -1 when empty. */
	public static long viewEnd(List<LoadTableEntry> view) {
		LoadTableEntry lowest = null;
		for (LoadTableEntry t : view) {
			if (lowest == null || t.start() < lowest.start()) {
				lowest = t;
			}
		}
		return lowest == null ? -1 : lowest.start() + (long) lowest.entrySize() * lowest.num();
	}

	/** {@code view} with its first {@code drop} slots removed. */
	private static List<LoadTableEntry> shiftView(List<LoadTableEntry> view, int drop) {
		if (drop <= 0) {
			return view;
		}
		List<LoadTableEntry> out = new ArrayList<>(view.size());
		for (LoadTableEntry t : view) {
			out.add(new LoadTableEntry(t.start() + (long) drop * t.entrySize(), t.entrySize(),
				t.num() - drop));
		}
		return out;
	}

	private static <T> List<T> tailFrom(List<T> l, int drop) {
		return drop <= 0 ? l : l.subList(Math.min(drop, l.size()), l.size());
	}

	/**
	 * Every leading rule on the post-tail view: one result per rule that would drop something, then
	 * a {@link LeadingRule#CASCADE} total when any did. Each rule is evaluated on the whole view
	 * independently -- the log wants to know which rule fires where -- except that
	 * {@link #leadingBySwitchWindow} runs on what {@link #leadingByExtent} left: a biased start
	 * leaves the window's top (the table start) unknown until the extent rule has placed it. The
	 * cascade total applies the rules in sequence instead, each on what the previous left.
	 */
	public static List<Leading> leadingChecks(List<Long> targets, List<LoadTableEntry> view,
			LeadingFacts f) {
		List<Leading> out = new ArrayList<>();
		LongUnaryOperator ext = f.extentEnd();
		Collection<Long> foreign = f.foreignCodeStarts();
		boolean valid = f.overlappingByte() && f.inCode() != null;
		boolean verified = f.tailRule() != null;
		Leading extent = ext == null || !verified ? Leading.none(LeadingRule.EXTENT_OVERLAP)
				: leadingByExtent(targets, view, ext);
		Leading unanchored = ext == null || verified ? Leading.none(LeadingRule.EXTENT_OVERLAP_UNANCHORED)
				: new Leading(LeadingRule.EXTENT_OVERLAP_UNANCHORED,
					leadingByExtent(targets, view, ext).drop());
		boolean useKnown = ext != null && foreign != null && verified && f.gate(Rule.KNOWN_CODE);
		boolean useBelow = f.gate(Rule.LOWEST_TARGET, Rule.BELOW_TABLE_CUT);
		boolean useWindow = f.gate(Rule.SWITCH_WINDOW, Rule.WINDOW_AT_NEIGHBOUR);
		boolean useNeighbour = f.otherTableEnds() != null && f.inCode() != null &&
			f.gate(Rule.NEIGHBOUR_TABLE);
		Leading known = !useKnown ? Leading.none(LeadingRule.KNOWN_CODE_OVERLAP)
				: leadingByKnownCode(targets, view, foreign, ext);
		Leading below = !useBelow ? Leading.none(LeadingRule.BELOW_TABLE)
				: leadingByBelowTable(targets, view, f.block());
		Leading window = !useWindow ? Leading.none(LeadingRule.SWITCH_WINDOW)
				: leadingBySwitchWindow(f.switchAddr(), tailFrom(targets, extent.drop()),
					shiftView(view, extent.drop()));
		Leading validCut = valid ? leadingByValidTargets(targets, view, f.inCode())
				: Leading.none(LeadingRule.VALID_TARGET);
		Leading neighbour = !useNeighbour ? Leading.none(LeadingRule.NEIGHBOUR_END)
				: leadingByNeighbourEnd(targets, view, f.otherTableEnds(), f.inCode());
		Leading prefix = f.decodes() == null ? Leading.none(LeadingRule.CODE_PREFIX)
				: leadingByCodePrefix(f.decodes());
		for (Leading l : List.of(extent, unanchored, known, below, window, validCut, neighbour,
			prefix)) {
			if (l.applies()) {
				out.add(l);
			}
		}
		if (out.isEmpty() || (out.size() == 1 && out.get(0) == unanchored)) {
			return out;
		}
		// The cascade: sequential, each rule on the remainder. Window comes after extent and known
		// code, which place the table start.
		int d = extent.drop();
		if (useKnown) {
			d += leadingByKnownCode(tailFrom(targets, d), shiftView(view, d), foreign, ext).drop();
		}
		if (useBelow) {
			d += leadingByBelowTable(tailFrom(targets, d), shiftView(view, d), f.block()).drop();
		}
		if (useWindow) {
			d += leadingBySwitchWindow(f.switchAddr(), tailFrom(targets, d), shiftView(view, d))
					.drop();
		}
		if (valid) {
			d += leadingByValidTargets(tailFrom(targets, d), shiftView(view, d),
				tailFrom(f.inCode(), d)).drop();
		}
		if (useNeighbour) {
			d += leadingByNeighbourEnd(tailFrom(targets, d), shiftView(view, d),
				f.otherTableEnds(), tailFrom(f.inCode(), d)).drop();
		}
		if (f.decodes() != null) {
			d += leadingByCodePrefix(tailFrom(f.decodes(), d)).drop();
		}
		if (d > 0) {
			out.add(new Leading(LeadingRule.CASCADE, d));
		}
		return out;
	}

	/**
	 * Leading form of {@link #bound}'s lowest-target rule ("a table cannot overlap the code it
	 * dispatches to"): no kept entry's bytes may lie inside the decoded extent of another kept
	 * target. Evaluated from the tail-verified end: every violating pair (slot {@code i} inside the
	 * extent of target {@code k}, {@code i != k}) is resolved by dropping its lower-indexed side, so
	 * the drop is the highest {@code min(i, k) + 1}; slots after it, the verified end included, stay.
	 * That is also what keeps a junk early target (whose extent happens to cover real slots) from
	 * costing real entries: its pair drops the junk, not the slot it covers.
	 *
	 * <p>Only targets AT or ABOVE the table's start count. A handler that starts below the table
	 * and decodes on into it is the ordinary table-after-code layout, not an overlap: the decode
	 * falls through the last instruction into the data (megaman c847: the last handler ends
	 * {@code BPL / BMI}, a branch-always pair, and its linear extent runs through all of the table at
	 * c89e). A table that overlaps its OWN handlers (SMW 0d44, dragonpower 803b) has them above its
	 * start. Hazard: handlers that call a routine with inline data after the {@code JSR} (db3,
	 * deadly_towers). The caller's {@code extentEnd} stops AT a call, so the inline bytes are never
	 * part of an extent. Declines for a shape {@link Shape#of} does not understand.
	 */
	public static Leading leadingByExtent(List<Long> targets, List<LoadTableEntry> view,
			LongUnaryOperator extentEnd) {
		Shape shape = Shape.of(targets.size(), view);
		if (shape == null) {
			return Leading.none(LeadingRule.EXTENT_OVERLAP);
		}
		int n = targets.size();
		long[] end = new long[n];
		for (int k = 0; k < n; k++) {
			end[k] = Math.max(extentEnd.applyAsLong(targets.get(k)), targets.get(k) + 1);
		}
		int drop = 0;
		for (int i = 0; i < n; i++) {
			for (int k = 0; k < n; k++) {
				if (k != i && targets.get(k) >= shape.tableStart &&
					shape.entryOverlaps(i, targets.get(k), end[k])) {
					drop = Math.max(drop, Math.min(i, k) + 1);
				}
			}
		}
		return checked(LeadingRule.EXTENT_OVERLAP, drop, n);
	}

	/**
	 * Leading form of {@link #boundByKnownCode} (grm-rsxe): the tail rule cuts where a handler of
	 * ANOTHER table begins inside this table's bytes. Its mirror is the same predicate on the
	 * handler's decoded extent: a slot inside {@code [c, extentEnd(c))} of another table's kept
	 * target {@code c} is that handler's bytes, not an entry. An interior hit drops everything
	 * before it (the tail-verified end stays). A foreign start equal to one of this table's own
	 * targets is skipped -- a shared handler, and {@link #leadingByExtent} already judges that pair
	 * -- and so is one below the table, for the reason given there.
	 */
	public static Leading leadingByKnownCode(List<Long> targets, List<LoadTableEntry> view,
			Collection<Long> foreignCodeStarts, LongUnaryOperator extentEnd) {
		Shape shape = Shape.of(targets.size(), view);
		if (shape == null) {
			return Leading.none(LeadingRule.KNOWN_CODE_OVERLAP);
		}
		int n = targets.size();
		int drop = 0;
		for (long c : foreignCodeStarts) {
			if (c < shape.tableStart || targets.contains(c)) {
				continue; // below the table: a handler running on into it is table-after-code
			}
			long end = Math.max(extentEnd.applyAsLong(c), c + 1);
			for (int i = 0; i < n; i++) {
				if (shape.entryOverlaps(i, c, end)) {
					drop = Math.max(drop, i + 1);
				}
			}
		}
		return checked(LeadingRule.KNOWN_CODE_OVERLAP, drop, n);
	}

	/**
	 * Leading form of grm-fxtp's below-table cut. The tail rule: entry 0's target above the table
	 * establishes the table-before-code idiom, and the first later entry below the table (and not
	 * an in-block handler on the table's other side, grm-rsxe) is where the over-read starts. The
	 * mirror anchors on the LAST kept entry: if its target is above the table, the last entry
	 * (index {@code <= n - 3}) below the table and not skipped ends a leading run of garbage, and
	 * everything up to it is dropped. The guards mirror too -- same-block (every entry after the cut
	 * lies in {@code block}) and confirm (the {@link #WINDOW_CONFIRM} entries BEFORE the cut, as
	 * many as exist, are each below the table or outside the block). Needs the block; declines
	 * without one, as the tail rule does.
	 */
	public static Leading leadingByBelowTable(List<Long> targets, List<LoadTableEntry> view,
			Block block) {
		Shape shape = Shape.of(targets.size(), view);
		int n = targets.size();
		if (shape == null || block == null || !(targets.get(n - 1) > shape.tableStart)) {
			return Leading.none(LeadingRule.BELOW_TABLE);
		}
		boolean anchorInBlock = block.contains(targets.get(n - 1));
		int cut = -1;
		for (int i = n - 3; i >= 0; i--) {
			long t = targets.get(i);
			boolean skipped = t < shape.tableStart && block.contains(t) && anchorInBlock;
			if (t < shape.tableStart && !skipped) {
				cut = i;
				break;
			}
		}
		if (cut < 0) {
			return Leading.none(LeadingRule.BELOW_TABLE);
		}
		for (int k = cut + 1; k < n; k++) {
			if (!block.contains(targets.get(k))) {
				return Leading.none(LeadingRule.BELOW_TABLE); // not the idiom
			}
		}
		for (int k = Math.max(0, cut - WINDOW_CONFIRM); k < cut; k++) {
			long t = targets.get(k);
			if (t >= shape.tableStart && block.contains(t)) {
				return Leading.none(LeadingRule.BELOW_TABLE); // ambiguous: comes back above the table
			}
		}
		return checked(LeadingRule.BELOW_TABLE, cut + 1, n);
	}

	/**
	 * Leading form of {@link #boundBySwitchWindow} (grm-akiv), for a table that follows its switch:
	 * the real entries lie in {@code [switchAddr, tableStart)}. Mirror: anchored on the last kept
	 * entry (it must lie in the window), the last entry outside the window ends a leading run of
	 * strays; everything up to it is dropped when the {@link #WINDOW_CONFIRM} entries before it
	 * (as many as exist) are outside too. The window's top is the table start, which a biased
	 * start leaves unknown, so {@link #leadingChecks} runs this only on the view
	 * {@link #leadingByExtent} left. (The tail rule's neighbour stop has its own mirror,
	 * {@link #leadingByNeighbourEnd}.)
	 */
	public static Leading leadingBySwitchWindow(long switchAddr, List<Long> targets,
			List<LoadTableEntry> view) {
		Shape shape = Shape.of(targets.size(), view);
		int n = targets.size();
		if (shape == null || shape.tableStart <= switchAddr) {
			return Leading.none(LeadingRule.SWITCH_WINDOW);
		}
		long lo = switchAddr;
		long hi = shape.tableStart;
		if (targets.get(n - 1) < lo || targets.get(n - 1) >= hi) {
			return Leading.none(LeadingRule.SWITCH_WINDOW);
		}
		int cut = -1;
		for (int i = n - 3; i >= 0; i--) {
			long t = targets.get(i);
			if (t < lo || t >= hi) {
				cut = i;
				break;
			}
		}
		if (cut < 0) {
			return Leading.none(LeadingRule.SWITCH_WINDOW);
		}
		for (int k = Math.max(0, cut - WINDOW_CONFIRM); k < cut; k++) {
			long t = targets.get(k);
			if (t >= lo && t < hi) {
				return Leading.none(LeadingRule.SWITCH_WINDOW); // the table comes back into the window
			}
		}
		return checked(LeadingRule.SWITCH_WINDOW, cut + 1, n);
	}

	/**
	 * Leading form of {@link #boundByValidTargets} (grm-yjiq), for the same one shape only (the
	 * overlapping byte table, the kept entries being its even cases; grm-os9b measured the rule on
	 * ordinary shapes and it ran through neighbouring tables): walking back from the last kept
	 * entry, the last entry that cannot hold code ends a leading run of invalid targets, cut when
	 * the {@link #WINDOW_CONFIRM} entries before it fail too and at least 2 entries stay. Declines
	 * when every entry is in code (nothing to cut).
	 */
	public static Leading leadingByValidTargets(List<Long> targets, List<LoadTableEntry> view,
			List<Boolean> inCode) {
		int n = targets.size();
		if (inCode.size() != n || Shape.of(n, view) == null) {
			return Leading.none(LeadingRule.VALID_TARGET);
		}
		int cut = n - 1;
		while (cut >= 0 && inCode.get(cut)) {
			cut--;
		}
		if (cut < 0 || n - 1 - cut < 2) {
			return Leading.none(LeadingRule.VALID_TARGET);
		}
		for (int k = Math.max(0, cut - WINDOW_CONFIRM); k < cut; k++) {
			if (inCode.get(k)) {
				return Leading.none(LeadingRule.VALID_TARGET); // plausible again; ambiguous
			}
		}
		return checked(LeadingRule.VALID_TARGET, cut + 1, n);
	}

	/**
	 * Leading form of {@link #boundByNeighbourTable} (grm-2m07): cut this table where ANOTHER
	 * table's bounded extent ENDS. Dispatch tables are laid end to end, so when a table starts
	 * early (a biased base, an over-read start) the previous table's end falls strictly inside this
	 * one's extent, on one of its entry boundaries, and the entries before it are the neighbour's.
	 * The last such end wins (the mirror of the tail rule's nearest start). Every entry that stays
	 * must be in code, as for the tail rule ("a cut that keeps a RAM target found something far
	 * from the idiom"). The neighbour end must be independently established -- another table's
	 * bounded extent, never inferred from this table's entries -- which is why this is a second
	 * pass over the bounded results.
	 */
	public static Leading leadingByNeighbourEnd(List<Long> targets, List<LoadTableEntry> view,
			Collection<Long> otherEnds, List<Boolean> inCode) {
		int n = targets.size();
		Shape shape = Shape.of(n, view);
		if (shape == null || inCode.size() != n) {
			return Leading.none(LeadingRule.NEIGHBOUR_END);
		}
		long extentEnd = shape.entryEnd(n - 1);
		long best = -1;
		for (long e : otherEnds) {
			if (e > shape.tableStart && e < extentEnd && shape.isEntryBoundary(e)) {
				best = Math.max(best, e);
			}
		}
		if (best < 0) {
			return Leading.none(LeadingRule.NEIGHBOUR_END);
		}
		int drop = shape.slotsBefore(best);
		for (int k = drop; k < n; k++) {
			if (!inCode.get(k)) {
				return Leading.none(LeadingRule.NEIGHBOUR_END);
			}
		}
		return checked(LeadingRule.NEIGHBOUR_END, drop, n);
	}

	/**
	 * Leading form of {@link #codePrefix} (grm-0pen): keep the TRAILING run of entries that decode
	 * as code. With at least 2 entries in that run and a failing entry before it, the cut is
	 * trusted when the {@link #CODE_CUT_CONFIRM} entries before the failure fail too; otherwise
	 * (an odd real handler may sit there) only the leading non-decoding run is dropped, as
	 * {@link #codePrefix} cuts only the trailing run then. Weak where junk decodes: Super Mario
	 * World's over-read targets decode as TCALLs.
	 */
	public static Leading leadingByCodePrefix(List<Boolean> decodes) {
		int n = decodes.size();
		int run = 0;
		while (run < n && decodes.get(n - 1 - run)) {
			run++;
		}
		if (run < 2 || run == n) {
			return Leading.none(LeadingRule.CODE_PREFIX);
		}
		int fail = n - run - 1;
		for (int k = Math.max(0, fail - CODE_CUT_CONFIRM); k < fail; k++) {
			if (decodes.get(k)) {
				int lead = 0;
				while (lead < n && !decodes.get(lead)) {
					lead++;
				}
				return checked(LeadingRule.CODE_PREFIX, lead, n);
			}
		}
		return checked(LeadingRule.CODE_PREFIX, fail + 1, n);
	}

	/**
	 * Leading form of {@link #boundByDistinctWords} (grm-uzep): the table's own words, in slot
	 * order, walked with {@link #leadingByExtent} (the lowest-target walk's mirror). The words, not
	 * the deduplicated case list, are the slots, so the extent check is slot-positional. {@code
	 * slots} is the count the tail rule kept ({@link #distinctWordSlots}).
	 */
	public static Leading leadingByDistinctWords(List<Long> words, long tableStart, int slots,
			LongUnaryOperator extentEnd) {
		if (slots < 2 || slots > words.size()) {
			return Leading.none(LeadingRule.DISTINCT_WORDS_EXTENT);
		}
		Leading l = leadingByExtent(words.subList(0, slots),
			List.of(new LoadTableEntry(tableStart, 2, slots)), extentEnd);
		return l.applies() ? new Leading(LeadingRule.DISTINCT_WORDS_EXTENT, l.drop())
				: Leading.none(LeadingRule.DISTINCT_WORDS_EXTENT);
	}

	/** {@code drop} of {@code n} slots as a result, or nothing when fewer than 2 would stay. */
	private static Leading checked(LeadingRule rule, int drop, int n) {
		return drop > 0 && n - drop >= 2 ? new Leading(rule, drop) : Leading.none(rule);
	}

	// Rules with NO leading form, and why (owner ruling: a one-ended rule says so):
	//  * looksLikeWordTable (inventory rule 9) is a per-target predicate, already end-agnostic.
	//  * boundBySearchLoop (rule 11) states the exact value set; it is two-ended already.
	//  * the normalisers (planarGap, overlappingByteTable; rule 4) are not cuts: a start shift
	//    applies to every half, see leadingView.
	//  * maskCap / indexCap (rule 15) bound the index from above only; the lower bound is the
	//    recovered index guard (INDEX_GUARD), which sets both ends.

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

		/** Whether {@code addr} lies in the bytes entry {@code i} occupies in any moving table. */
		boolean entryContains(int i, long addr) {
			for (int k = 0; k < start.length; k++) {
				long lo = start[k] + (long) i * chunk[k];
				if (addr >= lo && addr < lo + chunk[k]) {
					return true;
				}
			}
			return false;
		}

		/** Whether any entry-{@code i} byte of any moving table lies in {@code [lo, hi)}. */
		boolean entryOverlaps(int i, long lo, long hi) {
			for (int k = 0; k < start.length; k++) {
				long elo = start[k] + (long) i * chunk[k];
				if (elo < hi && lo < elo + chunk[k]) {
					return true;
				}
			}
			return false;
		}

		/** How many whole entries of the lowest moving table lie before {@code boundary}. */
		int slotsBefore(long boundary) {
			for (int k = 0; k < start.length; k++) {
				if (start[k] == tableStart) {
					return (int) ((boundary - tableStart) / chunk[k]);
				}
			}
			return 0;
		}

		/** The lowest of {@code otherStarts} strictly inside {@code (tableStart, extentEnd)} that is
		 *  not one of this table's own starts and lies on one of its entry boundaries, or
		 *  {@link Long#MAX_VALUE} when there is none. */
		long nearestNeighbour(Collection<Long> otherStarts, long extentEnd) {
			long best = Long.MAX_VALUE;
			for (long n : otherStarts) {
				if (n > tableStart && n < extentEnd && !isOwnStart(n) && isEntryBoundary(n)) {
					best = Math.min(best, n);
				}
			}
			return best;
		}

		/** Whether {@code n} is one of this table's own moving load-table starts. */
		boolean isOwnStart(long n) {
			for (long s : start) {
				if (s == n) {
					return true;
				}
			}
			return false;
		}

		/** Whether {@code n} is where some entry of the lowest moving table begins. */
		boolean isEntryBoundary(long n) {
			for (int k = 0; k < start.length; k++) {
				if (start[k] == tableStart) {
					return (n - tableStart) % chunk[k] == 0;
				}
			}
			return false;
		}
	}
}
