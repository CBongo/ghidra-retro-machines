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

import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.Test;

import retromachines.BoardDescriptorModel.BankWrap;

/**
 * Pure-JUnit coverage of {@link BankAnnotationAdapter#canonicalBank} (bead grm-p25h) -- the
 * rule that turns a bank number wider than the cartridge into the bank the hardware would
 * really have selected. Imports nothing from {@code ghidra.*}: the rule is set algebra over a
 * realized-bank set and a policy string, so no Ghidra runtime bootstrap is needed (same
 * discipline as {@link BankStateTest} and {@link FieldSpecKnownTest}).
 * <p>
 * The case that motivates it, from a real cartridge: Romance of the Three Kingdoms 2 is a
 * 256 KiB MMC5 cart (32 x 8 KiB banks) whose init writes 96/97/126 to $5114/$5115/$5116 --
 * all with bit 7 set, so all genuine ROM-select writes -- meaning banks 0/1/30. Before this
 * rule those three values named banks the image has no slice for, nothing retargeted, and the
 * title resolved zero overlays.
 * <p>
 * Every DECLINE case below returns the raw value deliberately, not a best guess: the raw value
 * is what stays visible to the impossible-bank diagnostic, and folding an unexplained bank into
 * a plausible neighbour is exactly the failure mode the diagnostic exists to catch.
 */
public class BankWrapCanonicalizationTest {

	/** {@code banking.bank_wrap: image} -- the DERIVED form, and the only guarded one. */
	private static final BankWrap WRAP = BankWrap.IMAGE;

	/** The contiguous realized set {@code {0 .. n-1}}, as the loader's overlays produce it. */
	private static Set<Integer> range(int n) {
		Set<Integer> banks = new LinkedHashSet<>();
		for (int i = 0; i < n; i++) {
			banks.add(i);
		}
		return banks;
	}

	private static Set<Integer> setOf(int... values) {
		Set<Integer> banks = new LinkedHashSet<>();
		for (int v : values) {
			banks.add(v);
		}
		return banks;
	}

	// ------------------------------------------------------------------
	// Accept: contiguous {0 .. n-1}, n a power of two
	// ------------------------------------------------------------------

	/** rtk2's three init writes against its own 32-bank image -- the bead's worked example. */
	@Test
	public void rtk2InitBanksWrapToRealBanks() {
		Set<Integer> realized = range(32);
		assertEquals(0, BankAnnotationAdapter.canonicalBank(WRAP, realized, 96));
		assertEquals(1, BankAnnotationAdapter.canonicalBank(WRAP, realized, 97));
		assertEquals(30, BankAnnotationAdapter.canonicalBank(WRAP, realized, 126));
	}

	/** An in-range value is its own canonical form, so cv3-shaped carts do not move at all. */
	@Test
	public void inRangeBankIsUnchanged() {
		Set<Integer> realized = range(32);
		for (int bank : new int[] { 0, 2, 24, 26, 30, 31 }) {
			assertEquals(bank, BankAnnotationAdapter.canonicalBank(WRAP, realized, bank));
		}
	}

	/** The mask is the realized COUNT, not a fixed width: 8 banks mask with 7, not with 31. */
	@Test
	public void maskWidthFollowsTheRealizedCount() {
		assertEquals(1, BankAnnotationAdapter.canonicalBank(WRAP, range(8), 41));
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, range(16), 41));
		assertEquals(0, BankAnnotationAdapter.canonicalBank(WRAP, range(1), 41));
	}

	// ------------------------------------------------------------------
	// Decline: every way the realized set fails to be a truncation image
	// ------------------------------------------------------------------

	/** A hole means the set is not the image of any {@code & (n-1)}; leave the value alone. */
	@Test
	public void holeInTheRealizedSetDeclines() {
		// Four values, so the power-of-two test passes on COUNT alone -- it is the missing 2
		// that must make this decline, which is the point of checking membership and not size.
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, setOf(0, 1, 3, 4), 9));
	}

	/** A non-power-of-two bank count (legal under NES 2.0) has board-specific behaviour. */
	@Test
	public void nonPowerOfTwoCountDeclines() {
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, range(6), 9));
		assertEquals(100, BankAnnotationAdapter.canonicalBank(WRAP, range(24), 100));
	}

	/** A set that does not start at 0 is not {@code {0 .. n-1}} however contiguous it is. */
	@Test
	public void setNotStartingAtZeroDeclines() {
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, setOf(4, 5, 6, 7), 9));
	}

	/** No {@code banking.bank_wrap} -- every board but MMC5 -- means nothing ever wraps. */
	@Test
	public void absentBankWrapDeclines() {
		assertEquals(96, BankAnnotationAdapter.canonicalBank(null, range(32), 96));
		assertEquals(9, BankAnnotationAdapter.canonicalBank(null, range(4), 9));
	}

	/** No realized set at all (a window the loader placed nothing for) cannot license a mask. */
	@Test
	public void missingOrEmptyRealizedSetDeclines() {
		assertEquals(96, BankAnnotationAdapter.canonicalBank(WRAP, null, 96));
		assertEquals(96, BankAnnotationAdapter.canonicalBank(WRAP, setOf(), 96));
	}

	// ------------------------------------------------------------------
	// The EXPLICIT form: a stated hardware fact, so no guard at all
	// ------------------------------------------------------------------

	/** {@code bank_wrap: 0x1F} masks the same values the derived form would on a 32-bank set. */
	@Test
	public void explicitMaskWrapsLikeTheDerivedFormWhereBothApply() {
		BankWrap explicit = BankWrap.ofMask(0x1F);
		assertEquals(0, BankAnnotationAdapter.canonicalBank(explicit, range(32), 96));
		assertEquals(1, BankAnnotationAdapter.canonicalBank(explicit, range(32), 97));
		assertEquals(30, BankAnnotationAdapter.canonicalBank(explicit, range(32), 126));
	}

	/**
	 * The load-bearing difference, and the reason the explicit form exists: it applies on
	 * exactly the realized sets the DERIVED form declines. A declared mask is a statement about
	 * how many PRG address lines the cartridge wires, not an inference from what got placed, so
	 * there is nothing for a self-guard to be unsure about.
	 */
	@Test
	public void explicitMaskAppliesWhereTheDerivedFormDeclines() {
		BankWrap explicit = BankWrap.ofMask(0x07);

		// Non-power-of-two realized count: derived declines, explicit masks anyway.
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, range(6), 9));
		assertEquals(1, BankAnnotationAdapter.canonicalBank(explicit, range(6), 9));

		// A hole in the realized set: same split.
		Set<Integer> holey = setOf(0, 1, 3, 4);
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, holey, 9));
		assertEquals(1, BankAnnotationAdapter.canonicalBank(explicit, holey, 9));

		// A set not starting at 0: same split.
		Set<Integer> offset = setOf(4, 5, 6, 7);
		assertEquals(9, BankAnnotationAdapter.canonicalBank(WRAP, offset, 9));
		assertEquals(1, BankAnnotationAdapter.canonicalBank(explicit, offset, 9));
	}

	/** The explicit form does not consult the realized set at all, so it needs none. */
	@Test
	public void explicitMaskIgnoresTheRealizedSetEntirely() {
		BankWrap explicit = BankWrap.ofMask(0x0F);
		assertEquals(6, BankAnnotationAdapter.canonicalBank(explicit, null, 0x76));
		assertEquals(6, BankAnnotationAdapter.canonicalBank(explicit, setOf(), 0x76));
		assertEquals(6, BankAnnotationAdapter.canonicalBank(explicit, range(2), 0x76));
	}
}
