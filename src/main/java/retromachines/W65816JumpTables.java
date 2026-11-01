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
import java.util.function.IntFunction;
import java.util.function.LongPredicate;

/**
 * Pure logic for grm-9nxj.5.4: how many entries a 65816 {@code JMP (abs,X)} / {@code JSR (abs,X)}
 * table really has.
 *
 * <p>The CPU reads a 16-bit pointer from {@code K:abs+X} and jumps within the same program bank
 * {@code K}, so the table is a run of little-endian words whose targets share its bank. Nothing in
 * the instruction says how long it is; most real dispatches scale an unbounded variable ({@code
 * LDA var / ASL A / TAX}). So the walk takes entries in order and stops at the first one that
 * cannot be a table entry -- the same shape as {@link JumpTableBound}'s "a table cannot extend
 * past its own lowest target", generalized to the evidence a listing offers:
 * <ul>
 * <li>{@code cap}: an explicit index bound ({@code AND #mask} before the scaling), the 128 entries
 * an 8-bit X can reach, or a hard ceiling;</li>
 * <li>the entry's own two bytes must be free -- not already code, data, or the start of another
 * table ({@code tableByteFree});</li>
 * <li>the table cannot run into any of its own targets (FF3 {@code $C2:0F47}: thirteen handlers
 * start right after it, and the walk stops exactly there), nor may an entry point into the table
 * itself;</li>
 * <li>the target must look like an entry ({@code targetPlausible}: in ROM, not mid-instruction or
 * inside data, no desync opcode in its first few instructions).</li>
 * </ul>
 * Each check only ever SHORTENS the table, so a wrong guess under-recovers rather than decoding
 * garbage.
 */
final class W65816JumpTables {

	/** Ceiling for a table with no other bound. */
	static final int MAX_ENTRIES = 256;

	private W65816JumpTables() {
	}

	/**
	 * The number of leading entries that pass every check, appending each accepted target to
	 * {@code targets}.
	 *
	 * @param tableStart the table's first byte (24-bit)
	 * @param cap the most entries the index can reach
	 * @param word the little-endian word at entry {@code i}, or null when unreadable
	 * @param tableByteFree whether a byte may belong to the table
	 * @param targetPlausible whether a 24-bit target can start a handler
	 * @param targets receives the accepted targets, in entry order
	 */
	static int bound(long tableStart, int cap, IntFunction<Integer> word,
			LongPredicate tableByteFree, LongPredicate targetPlausible, List<Long> targets) {
		return bound(tableStart, tableStart & 0xff0000L, cap, word, tableByteFree, targetPlausible,
			targets);
	}

	/**
	 * As {@link #bound(long, int, IntFunction, LongPredicate, LongPredicate, List)}, for a table
	 * whose targets lie in {@code targetBank} rather than the table's own bank: a pointer loaded
	 * by {@code LDA long,X} from another bank and jumped through with {@code JMP (abs)} (program
	 * bank) or {@code JML [abs]} (a constant bank byte), grm-9nxj.5.8.
	 */
	static int bound(long tableStart, long targetBank, int cap, IntFunction<Integer> word,
			LongPredicate tableByteFree, LongPredicate targetPlausible, List<Long> targets) {
		TableScorer.Result<Long, End> r = score(tableStart, targetBank, cap, false, word,
			tableByteFree, targetPlausible);
		targets.addAll(r.targets());
		return r.count();
	}

	/** Why a table ended; each is one of {@link #score}'s evidence terms. */
	enum End {
		/** The entry's bytes would wrap past the end of the bank. */
		BANK_END,
		/** The entry's bytes reach the lowest accepted target above the table. */
		ABOVE_TABLE_TARGET,
		/** One of the entry's bytes is already code, data, or another table's start. */
		BYTE_TAKEN,
		UNREADABLE,
		/** The target points into the table's own bytes. */
		INTO_TABLE,
		/**
		 * Soft (RTS trick only): the target lies in the other 32 KB half of the bank from entry
		 * 0's AND outside the cluster the confident targets so far span; see {@link #score}.
		 */
		OTHER_HALF,
		/**
		 * Soft, weaker (RTS trick only): outside that cluster without crossing. It neither opens
		 * doubt nor vouches for an entry that did; see {@link #score}.
		 */
		FAR_FROM_CLUSTER,
		/** {@code targetPlausible} rejects the target. */
		IMPLAUSIBLE,
		/**
		 * The entry's position carries an outside reference (hard) or a non-default label (soft,
		 * p {@link #LABEL_P}); see {@link EntryReferences} (grm-gipk.16.7).
		 */
		ENTRY_REFERENCED,
		/** Soft (record tables only): an unused slot, {@link #UNUSED_ENTRY}; p {@link #UNUSED_P}. */
		UNUSED_SLOT
	}

	/**
	 * grm-gipk.14: the target {@link #scoreRecords}'s {@code entryTarget} returns for a record that
	 * is a placeholder, not a handler (a word of $FFFF with the RTL trick's +1 bias is offset 0:
	 * ABC Monday Night Football $00:84E1 holds {@code C6A3, FFFF x6, DDD9, ...}, indexed by state).
	 * It is accepted with no plausibility checks and carries no reference.
	 */
	static final long UNUSED_ENTRY = -1L;

	/** Probability of an {@link End#UNUSED_SLOT} entry: counts half in a candidate's quality. */
	static final double UNUSED_P = 0.5;

	/** Probability of a label-only {@link End#ENTRY_REFERENCED} entry: inert under both policies. */
	static final double LABEL_P = 0.5;

	/** Probability of an {@link End#OTHER_HALF} entry: well under the run policy's cut. */
	static final double OTHER_HALF_P = 0.1;

	/** Probability of a {@link End#FAR_FROM_CLUSTER} entry: between the policy's two cuts. */
	static final double FAR_P = 0.5;

	/** Entries doubt must stay open for to end an RTS-trick table there. */
	static final int DOUBT_RUN = 3;

	/**
	 * The least half-width of the confident cluster: a cluster of one or two handlers says nothing
	 * about how far apart its handlers are, and 1 KB is a few handler bodies.
	 */
	static final int CLUSTER_FLOOR = 0x400;

	/**
	 * The table walk behind {@link #bound}, through {@link TableScorer}; {@code sameHalf} adds the
	 * soft {@link End#OTHER_HALF} term and ends the table at a sustained run of such entries.
	 *
	 * <p>A HiROM bank maps both halves to ROM, so an RTS-trick table can run on into a following
	 * one whose words point into the other half: Madden NFL '94 {@code $C5:A748} has 66 handlers
	 * at {@code $82xx-$A5xx}, then {@code $22B6, $2340, ...}, which decode as plausible code and
	 * took the count to 120 (grm-gipk.11). But the half has no hardware meaning in HiROM: a table
	 * whose handlers sit near {@code $8000} has targets on both sides. So crossing alone is no
	 * evidence (grm-gipk.16.4); crossing to a target far from the handlers seen so far is. "Far"
	 * is outside the confident targets' own span, widened by that span on each side (at least
	 * {@link #CLUSTER_FLOOR}): Madden's {@code $22B6} lies {@code $5F00} below a {@code $23E0}-wide
	 * cluster. Only sure entries define the cluster, so an over-read run cannot vouch for itself.
	 *
	 * <p>A far target that does NOT cross is weaker evidence ({@link End#FAR_FROM_CLUSTER}): a real
	 * table's handlers can spread across its own half. It cannot open doubt on its own, but it cannot
	 * close it either. Madden NFL 97 {@code $CD:8580} has 8 handlers at {@code $85C4-$865D}, then
	 * {@code $04C0, $7F01} (crossing) and {@code $E539} (not): only a sure entry may vouch for the
	 * two before it, and none comes.
	 */
	static TableScorer.Result<Long, End> score(long tableStart, long targetBank, int cap,
			boolean sameHalf, IntFunction<Integer> word, LongPredicate tableByteFree,
			LongPredicate targetPlausible) {
		return score(tableStart, targetBank, cap, sameHalf, word, tableByteFree, targetPlausible,
			i -> null);
	}

	/**
	 * As above, plus the {@link End#ENTRY_REFERENCED} term (grm-gipk.16.7): {@code entryRef} gives
	 * what Ghidra already has at entry {@code i}'s position (null: nothing). It is asked only for
	 * {@code i >= 1} and after every other hard check. A strong hit ends the table; a label-only
	 * hit is a soft term.
	 */
	static TableScorer.Result<Long, End> score(long tableStart, long targetBank, int cap,
			boolean sameHalf, IntFunction<Integer> word, LongPredicate tableByteFree,
			LongPredicate targetPlausible, IntFunction<EntryReferences.Hit> entryRef) {
		return scoreCore(tableStart, 2, cap, sameHalf, false, n -> {
			Integer w = word.apply(n);
			return w == null ? null : (targetBank & 0xff0000L) | (w & 0xffff);
		}, tableByteFree, targetPlausible, entryRef);
	}

	/**
	 * grm-gipk.14: the walk for a table of fixed-size RECORDS ({@code stride} bytes apart) that each
	 * name their own full 24-bit target, the 65816 RTL trick's bank:word records. {@code entryTarget}
	 * gives entry {@code i}'s target, or null when its bytes are unreadable; the first three bytes
	 * of every record, the whole {@code stride}, must be free. Only same-bank targets bound the
	 * table from above, since a target in another bank says nothing about where this one ends.
	 */
	static TableScorer.Result<Long, End> scoreRecords(long tableStart, int stride, int cap,
			IntFunction<Long> entryTarget, LongPredicate tableByteFree,
			LongPredicate targetPlausible, IntFunction<EntryReferences.Hit> entryRef) {
		return scoreCore(tableStart, stride, cap, false, true, entryTarget, tableByteFree,
			targetPlausible, entryRef);
	}

	private static TableScorer.Result<Long, End> scoreCore(long tableStart, int stride, int cap,
			boolean sameHalf, boolean bankFilter, IntFunction<Long> entryTarget,
			LongPredicate tableByteFree, LongPredicate targetPlausible,
			IntFunction<EntryReferences.Hit> entryRef) {
		long bank = tableStart & 0xff0000L;
		List<Boolean> sure = new ArrayList<>();   // per accepted entry, in order
		TableScorer.EndPolicy policy = sameHalf ? TableScorer.doubtRun(0.5, 1.0, DOUBT_RUN)
				: TableScorer.HARD_ONLY;
		return TableScorer.walk(cap, (n, before) -> {
			long at = tableStart + (long) stride * n;
			long last = at + stride - 1;
			if ((last & 0xff0000L) != bank) {
				return TableScorer.Entry.rejected(End.BANK_END);
			}
			if (last >= lowestAbove(tableStart, stride, bankFilter, before)) {
				return TableScorer.Entry.rejected(End.ABOVE_TABLE_TARGET);
			}
			for (long b = at; b <= last; b++) {
				if (!tableByteFree.test(b)) {
					return TableScorer.Entry.rejected(End.BYTE_TAKEN);
				}
			}
			Long target = entryTarget.apply(n);
			if (target == null) {
				return TableScorer.Entry.rejected(End.UNREADABLE);
			}
			if (target == UNUSED_ENTRY) {
				sure.add(true);
				return TableScorer.Entry.accepted(target,
					List.of(new TableScorer.Term<>(End.UNUSED_SLOT, UNUSED_P)));
			}
			if (target >= tableStart && target <= last) {
				return TableScorer.Entry.rejected(End.INTO_TABLE);
			}
			boolean far = sameHalf && !before.isEmpty() && farFromCluster(before, sure, target);
			if (!targetPlausible.test(target)) {
				return TableScorer.Entry.rejected(End.IMPLAUSIBLE);
			}
			EntryReferences.Hit hit = n >= 1 ? entryRef.apply(n) : null;
			if (hit != null && hit.strong()) {
				return TableScorer.Entry.rejected(End.ENTRY_REFERENCED);
			}
			List<TableScorer.Term<End>> soft = new ArrayList<>();
			if (hit != null) {
				soft.add(new TableScorer.Term<>(End.ENTRY_REFERENCED, LABEL_P));
			}
			sure.add(!far);
			if (far) {
				boolean crosses = ((before.get(0) ^ target) & 0x8000L) != 0;
				soft.add(crosses ? new TableScorer.Term<>(End.OTHER_HALF, OTHER_HALF_P)
						: new TableScorer.Term<>(End.FAR_FROM_CLUSTER, FAR_P));
			}
			return TableScorer.Entry.accepted(target, soft);
		}, policy);
	}

	/** Whether {@code target} lies outside the widened span of the sure {@code before}. */
	private static boolean farFromCluster(List<Long> before, List<Boolean> sure, long target) {
		long lo = Long.MAX_VALUE;
		long hi = Long.MIN_VALUE;
		for (int j = 0; j < before.size(); j++) {
			if (sure.get(j)) {
				lo = Math.min(lo, before.get(j));
				hi = Math.max(hi, before.get(j));
			}
		}
		long reach = Math.max(CLUSTER_FLOOR, hi - lo);
		return target < lo - reach || target > hi + reach;
	}

	/**
	 * The lowest of {@code before} lying past its own entry's bytes, else MAX_VALUE; with
	 * {@code bankFilter}, only targets in the table's own bank count.
	 */
	private static long lowestAbove(long tableStart, int stride, boolean bankFilter,
			List<Long> before) {
		long lowest = Long.MAX_VALUE;
		for (int j = 0; j < before.size(); j++) {
			long t = before.get(j);
			if (bankFilter && (t & 0xff0000L) != (tableStart & 0xff0000L)) {
				continue;
			}
			if (t > tableStart + (long) stride * j + (stride - 1)) {
				lowest = Math.min(lowest, t);
			}
		}
		return lowest;
	}

	/**
	 * The entry count an {@code AND #mask} reaching the index register through {@code shifts}
	 * left shifts allows: indices 0..{@code mask << shifts}, two bytes per entry.
	 */
	static int maskCap(int mask, int shifts) {
		long maxIndex = ((long) mask) << shifts;
		return (int) Math.min(MAX_ENTRIES, maxIndex / 2 + 1);
	}
}
