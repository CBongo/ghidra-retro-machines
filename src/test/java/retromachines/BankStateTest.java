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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link BankState}'s public lattice operations (bead grm-32f.1
 * spike): deliberately imports nothing from {@code ghidra.*}, proving this class's logic
 * is testable with zero Ghidra runtime bootstrap, in contrast to
 * {@link BankStrategyProgramTest}'s {@code ProgramBuilder}-backed fixture.
 */
public class BankStateTest {

	@Test
	public void mergeOfAgreeingFullyKnownStatesKeepsBitsKnown() {
		BankState a = BankState.fullyKnown(0xFF, 0x05);
		BankState b = BankState.fullyKnown(0xFF, 0x05);

		BankState merged = BankState.merge(a, b);

		assertEquals(0xFF, merged.knownMask());
		assertEquals(0x05, merged.bits());
	}

	@Test
	public void mergeOfDisagreeingStatesDropsOnlyTheDisputedBit() {
		// bit 0 differs (1 vs 0); every other bit of the mask agrees.
		BankState a = BankState.fullyKnown(0xFF, 0b0000_0001);
		BankState b = BankState.fullyKnown(0xFF, 0b0000_0000);

		BankState merged = BankState.merge(a, b);

		assertEquals(0xFE, merged.knownMask());
		assertEquals(0x00, merged.bits());
	}

	@Test
	public void mergeIsMonotoneShrinkNotGrowth() {
		// A three-way merge (folded pairwise, as the dataflow worklist would) can only ever
		// shrink knownMask relative to any single input -- never recover a bit once lost.
		BankState a = BankState.fullyKnown(0xFF, 0x05);
		BankState b = BankState.fullyKnown(0xFF, 0x05);
		BankState c = BankState.fullyKnown(0xFF, 0x85); // disagrees with a/b on bit 7

		BankState ab = BankState.merge(a, b);
		BankState abc = BankState.merge(ab, c);

		assertEquals(0xFF, ab.knownMask());
		assertEquals(0x7F, abc.knownMask());
	}

	@Test
	public void mergeWithUnknownYieldsNothingKnown() {
		BankState known = BankState.fullyKnown(0xFF, 0x05);

		BankState merged = BankState.merge(known, BankState.unknown());

		assertEquals(0, merged.knownMask());
	}

	@Test
	public void effectiveFallsBackToInitialStateForUnknownBits() {
		// Only the low nibble is tracked/known; the high nibble must fall back to the
		// initial state's bits (still reduced to mask).
		BankState partial = new BankState(0x0F, 0x05);

		int effective = partial.effective(0xF0, 0xFF);

		assertEquals(0xF5, effective);
	}

	@Test
	public void fullyKnownMasksValueToMask() {
		BankState state = BankState.fullyKnown(0x0F, 0xFF);

		assertEquals(0x0F, state.knownMask());
		assertEquals(0x0F, state.bits());
	}
}
