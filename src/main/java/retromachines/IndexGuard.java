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
 * The pure range arithmetic of a recovered INDEX GUARD (grm-c9d.8.2): {@code CMP reg,#imm}
 * followed by a conditional carry branch bounds an 8-bit register on the path that falls through
 * the branch, and a few affine register moves carry that range to the register a table is indexed
 * by. No Ghidra types: {@link IndexGuardRecovery} reads the listing, this class only decides what
 * the numbers mean. CMP, BCC and BCS are the same instructions on 6502, 65816 and SPC700 (carry
 * set when {@code reg >= imm}, unsigned), so one core serves them all.
 *
 * <p>A {@link Range} is the set {@code lo, lo+step, ..., hi} of 8-bit values. Only the maps that
 * keep a range contiguous (modulo 256) are modelled, and everything else yields {@code null}:
 * a caller must treat that as "no guard", never as a guess.
 */
final class IndexGuard {

	private IndexGuard() {}

	/** The carry branch after the CMP; named for the branch, not for the path analysed. */
	enum Branch {
		/** Taken when the register is below the immediate (carry clear). */
		BCC,
		/** Taken when the register is at or above the immediate (carry set). */
		BCS
	}

	/** The register-to-register maps carried along a straight run; plain copies are not listed. */
	enum Op {
		/** {@code ASL A}: x2, modulo 256. */
		ASL1,
		/** {@code LSR A}: logical shift right by one. */
		LSR1
	}

	/** {@code lo, lo+step, ..., hi}: {@code step >= 1}, {@code (hi - lo) % step == 0}. */
	record Range(int lo, int hi, int step) {
		Range {
			if (lo < 0 || hi > 255 || lo > hi || step < 1 || (hi - lo) % step != 0) {
				throw new IllegalArgumentException("bad range " + lo + ".." + hi + "/" + step);
			}
		}

		@Override
		public String toString() {
			return String.format("%02x..%02x%s", lo, hi, step == 1 ? "" : " step " + step);
		}
	}

	/**
	 * The values {@code reg} can hold on the path that does NOT take {@code branch} after
	 * {@code CMP reg,#imm}: BCC not taken means {@code reg >= imm}, BCS not taken means
	 * {@code reg < imm}. Null when that set is empty, which no real guard produces.
	 */
	static Range fallThrough(Branch branch, int imm) {
		if (imm < 0 || imm > 255) {
			return null;
		}
		if (branch == Branch.BCC) {
			return new Range(imm, 255, 1);
		}
		return imm == 0 ? null : new Range(0, imm - 1, 1);
	}

	/** The image of {@code r} under one {@code op}, or null when it is not a contiguous range. */
	static Range apply(Range r, Op op) {
		switch (op) {
			case ASL1:
				// 2x stays in one 256-block only if the whole range is below 128 or at/above 128
				if (r.hi() * 2 <= 255) {
					return new Range(r.lo() * 2, r.hi() * 2, r.step() * 2);
				}
				if (r.lo() * 2 >= 256) {
					return new Range(r.lo() * 2 - 256, r.hi() * 2 - 256, r.step() * 2);
				}
				return null;
			case LSR1:
				if (r.step() == 1) {
					return new Range(r.lo() >> 1, r.hi() >> 1, 1);
				}
				// an even step maps even-aligned values to distinct neighbours; odd steps do not
				return r.step() % 2 == 0 && r.lo() % 2 == 0
						? new Range(r.lo() >> 1, r.hi() >> 1, r.step() / 2)
						: null;
			default:
				return null;
		}
	}

	/** {@link #apply(Range, Op)} for each of {@code ops} in program order; null if any declines. */
	static Range apply(Range r, List<Op> ops) {
		Range cur = r;
		for (Op op : ops) {
			if (cur == null) {
				return null;
			}
			cur = apply(cur, op);
		}
		return cur;
	}

	/** The smallest range holding both: what every caller of a routine may pass in. */
	static Range hull(Range a, Range b) {
		int step = gcd(gcd(a.step(), b.step()), Math.abs(a.lo() - b.lo()));
		int lo = Math.min(a.lo(), b.lo());
		int hi = Math.max(a.hi(), b.hi());
		return new Range(lo, hi, Math.max(1, step));
	}

	private static int gcd(int a, int b) {
		return b == 0 ? a : gcd(b, a % b);
	}

	/**
	 * The table slots a register range reaches when the register is a BYTE OFFSET into a table of
	 * {@code entryBytes}-wide entries: slots {@code lo/entryBytes .. hi/entryBytes}, returned as
	 * {@code {first, last}}. Null unless every reachable offset starts an entry, i.e. the step is
	 * the entry width and {@code lo} is a multiple of it (a step of 1 into word entries reaches
	 * the odd bytes between entries, and a step wider than the entry skips some, so neither is a
	 * contiguous run of slots).
	 */
	static int[] slotSpan(Range offsets, int entryBytes) {
		if (offsets == null || entryBytes < 1 || offsets.step() != entryBytes ||
			offsets.lo() % entryBytes != 0) {
			return null;
		}
		return new int[] { offsets.lo() / entryBytes, offsets.hi() / entryBytes };
	}
}
