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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import retromachines.BoardBankAnalyzer.FieldSpec;

/**
 * Pure-JUnit coverage of {@link FieldSpec#fullyKnownIn} (bead grm-v6o). Imports nothing from
 * {@code ghidra.*} -- the predicate is bit algebra over {@link BankState}, so no Ghidra
 * runtime bootstrap is needed (same discipline as {@link BankStateTest}).
 * <p>
 * The defect this pins: the reference-retargeting site tested {@code (knownMask & mask) != 0}
 * ("some bit known") where the contract is {@code == mask} ("every bit known"). A partially
 * known multi-bit bank field therefore counted as knowledge, {@code valueIn} filled the
 * unknown bits from the board's initial state, and the user's placement override -- which
 * only applies when flow does NOT know -- was suppressed in favour of a fabricated bank.
 */
public class FieldSpecKnownTest {

	/** A 4-bit bank select at bits 2..5, i.e. positioned mask 0x3C. */
	private static final FieldSpec BANK4 = new FieldSpec("bank", 2, 4);

	/** A 1-bit mode select at bit 7. */
	private static final FieldSpec MODE1 = new FieldSpec("mode", 7, 1);

	@Test
	public void allBitsKnownIsKnown() {
		assertTrue(BANK4.fullyKnownIn(new BankState(0x3C, 0x14)));
	}

	@Test
	public void everyProperSubsetOfKnownBitsIsNotKnown() {
		// The regression case: one known bit inside the field is not knowledge of the field.
		for (int sub = 0x3C; sub > 0; sub = (sub - 1) & 0x3C) {
			if (sub == 0x3C) {
				continue;
			}
			assertFalse("partial knownMask 0x" + Integer.toHexString(sub) + " must not count",
				BANK4.fullyKnownIn(new BankState(sub, sub)));
		}
	}

	@Test
	public void nothingKnownIsNotKnown() {
		assertFalse(BANK4.fullyKnownIn(BankState.unknown()));
	}

	@Test
	public void knowledgeOfBitsOutsideTheFieldDoesNotCount() {
		// Neighbouring fields being pinned says nothing about this one.
		assertFalse(BANK4.fullyKnownIn(new BankState(~0x3C, 0)));
	}

	@Test
	public void extraKnownBitsOutsideTheFieldDoNotDisqualify() {
		assertTrue(BANK4.fullyKnownIn(new BankState(0xFF, 0x14)));
	}

	@Test
	public void singleBitFieldIsKnownOnlyWhenItsOwnBitIsKnown() {
		// The case where the buggy "!= 0" and correct "== mask" forms coincide -- which is
		// exactly why the wrong test survived. Both directions must still hold.
		assertTrue(MODE1.fullyKnownIn(new BankState(0x80, 0x80)));
		assertFalse(MODE1.fullyKnownIn(new BankState(0x7F, 0x7F)));
	}
}
