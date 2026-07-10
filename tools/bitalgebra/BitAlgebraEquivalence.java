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
// Exhaustive equivalence check for the bit-parallel collapse of
// StoredValueScanner.combine() and .fullyDeterminedByAccumulator() (bead grm-5tl.11).
//
// The two production methods are pure bit algebra over five 8-bit inputs
// (aAcc, oAcc, mask, base.knownMask, base.bits). This standalone tool holds a REFERENCE
// implementation transcribed bit-for-bit from the original per-bit for-loops, and the
// COLLAPSED one-line forms that replaced them, and proves them identical.
//
// Because every operation is bitwise-independent (AND/OR/NOT/mask, no carries or shifts
// across positions), enumerating all 32 single-bit input combinations across all 8 bit
// positions is a COMPLETE proof of equivalence; a large full-width random fuzz is added
// on top to guard the byte assembly and masking. Run via `gradle verifyBitAlgebra` (no
// Ghidra dependency) or plainly: javac + java BitAlgebraEquivalence.
//
// Exits non-zero (throws) on the first mismatch, printing the offending inputs; prints
// "BITALGEBRA PASS (<n> cases)" when every case agrees.

import java.util.Random;

public final class BitAlgebraEquivalence {

	private BitAlgebraEquivalence() {
	}

	// ------------------------------------------------------------------
	// Reference implementations: transcribed bit-for-bit from the ORIGINAL
	// StoredValueScanner per-bit for-loops (the behavior that must be preserved).
	// ------------------------------------------------------------------

	private static boolean refFullyDetermined(int aAcc, int oAcc, int mask) {
		for (int bit = 0; bit < 8; bit++) {
			int bm = 1 << bit;
			if ((mask & bm) == 0) {
				continue;
			}
			boolean aClearsIt = (aAcc & bm) == 0;
			boolean oSetsIt = (oAcc & bm) != 0;
			if (!aClearsIt && !oSetsIt) {
				return false;
			}
		}
		return true;
	}

	/** Returns {@code knownMask << 8 | bits}. */
	private static int refCombine(int aAcc, int oAcc, int mask, int baseKnown, int baseBits) {
		int knownMask = 0;
		int bits = 0;
		for (int bit = 0; bit < 8; bit++) {
			int bm = 1 << bit;
			if ((mask & bm) == 0) {
				continue;
			}
			if ((oAcc & bm) != 0) {
				knownMask |= bm;
				bits |= bm;
			}
			else if ((aAcc & bm) == 0) {
				knownMask |= bm;
			}
			else if ((baseKnown & bm) != 0) {
				knownMask |= bm;
				if ((baseBits & bm) != 0) {
					bits |= bm;
				}
			}
		}
		return (knownMask << 8) | bits;
	}

	// ------------------------------------------------------------------
	// Collapsed one-line forms that replaced the loops in production.
	// ------------------------------------------------------------------

	private static boolean oneLineFullyDetermined(int aAcc, int oAcc, int mask) {
		return (((~aAcc | oAcc) & mask) & 0xFF) == (mask & 0xFF);
	}

	private static int oneLineCombine(int aAcc, int oAcc, int mask, int baseKnown, int baseBits) {
		int knownMask = mask & (oAcc | ~aAcc | baseKnown) & 0xFF;
		int bits = mask & (oAcc | (aAcc & baseKnown & baseBits)) & 0xFF;
		return (knownMask << 8) | bits;
	}

	// ------------------------------------------------------------------

	public static void main(String[] args) {
		long cases = 0;

		// Complete per-bit enumeration: every 32-way (aBit,oBit,maskBit,kBit,bBit) combo,
		// placed at each of the 8 positions (with all other positions zero). Independence
		// of the algebra makes this an exhaustive proof.
		for (int pos = 0; pos < 8; pos++) {
			int bm = 1 << pos;
			for (int combo = 0; combo < 32; combo++) {
				int aAcc = (combo & 1) != 0 ? bm : 0;
				int oAcc = (combo & 2) != 0 ? bm : 0;
				int mask = (combo & 4) != 0 ? bm : 0;
				int baseKnown = (combo & 8) != 0 ? bm : 0;
				int baseBits = (combo & 16) != 0 ? bm : 0;
				check(aAcc, oAcc, mask, baseKnown, baseBits);
				cases++;
			}
		}

		// Full-width random fuzz to guard byte assembly / cross-bit masking.
		Random rng = new Random(0xB17A16EBL); // fixed seed -> reproducible
		for (int i = 0; i < 20_000_000; i++) {
			check(rng.nextInt(256), rng.nextInt(256), rng.nextInt(256), rng.nextInt(256),
				rng.nextInt(256));
			cases++;
		}

		System.out.println("BITALGEBRA PASS (" + cases + " cases)");
	}

	private static void check(int aAcc, int oAcc, int mask, int baseKnown, int baseBits) {
		boolean refFd = refFullyDetermined(aAcc, oAcc, mask);
		boolean oneFd = oneLineFullyDetermined(aAcc, oAcc, mask);
		if (refFd != oneFd) {
			throw new AssertionError(String.format(
				"fullyDetermined mismatch: aAcc=%02x oAcc=%02x mask=%02x -> ref=%b oneLine=%b",
				aAcc, oAcc, mask, refFd, oneFd));
		}

		int ref = refCombine(aAcc, oAcc, mask, baseKnown, baseBits);
		int one = oneLineCombine(aAcc, oAcc, mask, baseKnown, baseBits);
		if (ref != one) {
			throw new AssertionError(String.format(
				"combine mismatch: aAcc=%02x oAcc=%02x mask=%02x baseKnown=%02x baseBits=%02x " +
					"-> ref(known=%02x bits=%02x) oneLine(known=%02x bits=%02x)",
				aAcc, oAcc, mask, baseKnown, baseBits, ref >> 8, ref & 0xFF, one >> 8, one & 0xFF));
		}
	}
}
