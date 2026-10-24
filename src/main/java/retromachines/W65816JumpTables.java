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
		long bank = tableStart & 0xff0000L;
		long lowestAbove = Long.MAX_VALUE;   // lowest accepted target at or above the table
		int n = 0;
		for (; n < cap; n++) {
			long at = tableStart + 2L * n;
			// Wrapping past the bank end is not a table.
			if (((at + 1) & 0xff0000L) != bank) {
				break;
			}
			if (at + 1 >= lowestAbove || !tableByteFree.test(at) || !tableByteFree.test(at + 1)) {
				break;
			}
			Integer w = word.apply(n);
			if (w == null) {
				break;
			}
			long target = bank | (w & 0xffff);
			if (target >= tableStart && target <= at + 1) {
				break;   // points into the table itself
			}
			if (!targetPlausible.test(target)) {
				break;
			}
			targets.add(target);
			if (target > at + 1) {
				lowestAbove = Math.min(lowestAbove, target);
			}
		}
		return n;
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
