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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import retromachines.BankAnnotationAdapter.Impossible;
import retromachines.BankAnnotationAdapter.ImpossibleBank;
import retromachines.BankAnnotationAdapter.ImpossibleInAllLayouts;
import retromachines.BoardDescriptorModel.BankWrap;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.ComputedWindowModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.ModeWindowModel;

/**
 * Pure-JUnit coverage of {@link BankAnnotationAdapter#impossibleBank}, and specifically of the
 * universally-quantified branch bead grm-fick added (bead grm-hum built the confident branch).
 * Imports nothing from {@code ghidra.*}: the rule is set algebra over a {@link BoardModel}, a
 * {@link BankState} and a realized-bank map, so no Ghidra runtime bootstrap is needed -- the same
 * discipline as {@link BankWrapCanonicalizationTest} and {@link FieldSpecKnownTest}.
 * <p>
 * <b>The board modeled here is MMC5-shaped, because MMC5 is what makes the branch necessary.</b>
 * It has a two-bit {@code prg_mode} and a seven-bit bank field, and -- the load-bearing part --
 * NO mode-invariant computed window, so {@code board.computedWindows()} is empty and the
 * confident branch has nothing at all to check. Before grm-fick that meant the diagnostic was
 * structurally unreachable on such a board whenever the mode was merely assumed from
 * {@code banking.initial_state} rather than recovered, which on rtk2 was every bank write it has.
 * <p>
 * The measurement that made this worth fixing rather than documenting: across all 33 pinned
 * real-ROM rows the impossible-bank diagnostic fired exactly ZERO times.
 */
public class ImpossibleBankInAllLayoutsTest {

	// ------------------------------------------------------------------
	// Board fixture
	// ------------------------------------------------------------------

	/** {@code prg_mode}: state bits 0-1. Four modes, as MMC5 has. */
	private static final FieldSpec MODE = new FieldSpec("prg_mode", 0, 2);

	/** {@code bank_5115}: state bits 2-8. Seven bits wide on every cart, as MMC5's are. */
	private static final FieldSpec BANK = new FieldSpec("bank_5115", 2, 7);

	/** A second bank field, to prove per-field quantification rather than per-board. */
	private static final FieldSpec OTHER_BANK = new FieldSpec("bank_5114", 9, 7);

	private static final int BOARD_MASK = 0xFFFF;

	/** The window every mode-varying instance below belongs to. */
	private static final String WINDOW = "PRG_8000";

	private static ModeWindowModel switchable(String name, int mode, FieldSpec bankField) {
		return new ModeWindowModel(name, 0x8000, 0x9fff, mode, bankField, null);
	}

	/** A mode-varying FIXED instance: a constant {@code maps:} expr, so no bank field at all. */
	private static ModeWindowModel fixed(String name, int mode) {
		return new ModeWindowModel(name, 0x8000, 0x9fff, mode, null, null);
	}

	private static BoardModel board(BankWrap bankWrap, List<ModeWindowModel> modeWindows,
			Map<String, ComputedWindowModel> computed) {
		return new BoardModel(BOARD_MASK, 0, List.of(), List.of(MODE, BANK, OTHER_BANK), Map.of(),
			computed, Map.of(), Map.of(), MODE, 0, modeWindows, bankWrap);
	}

	private static BoardModel board(List<ModeWindowModel> modeWindows) {
		return board(null, modeWindows, Map.of());
	}

	// ------------------------------------------------------------------
	// State fixture
	// ------------------------------------------------------------------

	/**
	 * A state in which {@code bank} is FULLY recovered into {@link #BANK} and the mode field has
	 * only the bits in {@code knownModeMask} pinned (to the corresponding bits of {@code mode}).
	 * {@code knownModeMask == 0} is "nothing at all is known about the mode", the case rtk2 is in.
	 */
	private static BankState state(int bank, int knownModeMask, int mode) {
		int knownMask = BANK.positionedMask() | (knownModeMask & 0x3);
		int bits = ((bank & 0x7f) << BANK.lsb()) | (mode & knownModeMask & 0x3);
		return new BankState(knownMask, bits);
	}

	/** {@code bank} recovered, mode entirely unknown -- the situation this branch exists for. */
	private static BankState bankKnownModeUnknown(int bank) {
		return state(bank, 0, 0);
	}

	// ------------------------------------------------------------------
	// Bank-universe fixture
	// ------------------------------------------------------------------

	private static Set<Integer> range(int n) {
		Set<Integer> banks = new LinkedHashSet<>();
		for (int i = 0; i < n; i++) {
			banks.add(i);
		}
		return banks;
	}

	/** Builds a {@link BankAnnotationAdapter#bankUniverse}-shaped map from mode -> bank count. */
	private static Map<String, Set<Integer>> universe(String window, int... countByMode) {
		Map<String, Set<Integer>> universe = new LinkedHashMap<>();
		for (int mode = 0; mode < countByMode.length; mode++) {
			if (countByMode[mode] > 0) {
				universe.put(BankAnnotationAdapter.modeBankKey(window, mode),
					range(countByMode[mode]));
			}
		}
		return universe;
	}

	/** The four-mode board where every mode is switchable on {@link #BANK}. */
	private static List<ModeWindowModel> allModesSwitchable() {
		List<ModeWindowModel> windows = new ArrayList<>();
		for (int mode = 0; mode < 4; mode++) {
			windows.add(switchable(WINDOW, mode, BANK));
		}
		return windows;
	}

	// ------------------------------------------------------------------
	// The branch itself
	// ------------------------------------------------------------------

	/**
	 * The headline case: mode unknown, bank recovered, out of range under every layout. Before
	 * grm-fick this returned null and the site was annotated with a bank the image cannot supply
	 * -- now it warns, and the count in the message is the number of layouts actually quantified
	 * over.
	 */
	@Test
	public void outOfRangeInEveryLayoutWarnsWithoutKnowingTheMode() {
		Impossible bad = BankAnnotationAdapter.impossibleBank(board(allModesSwitchable()),
			bankKnownModeUnknown(40), universe(WINDOW, 8, 8, 16, 32));

		assertTrue("expected the weaker, universally-quantified claim",
			bad instanceof ImpossibleInAllLayouts);
		ImpossibleInAllLayouts all = (ImpossibleInAllLayouts) bad;
		assertEquals("bank_5115", all.field());
		assertEquals(40, all.bank());
		assertEquals(4, all.layouts());
	}

	/**
	 * The quantifier is UNIVERSAL, and this is the test that proves it rather than assuming it:
	 * one layout out of four can hold bank 40, so the claim fails and nothing is reported. This is
	 * the case that separates an honest diagnostic from a noisy one.
	 */
	@Test
	public void oneLayoutThatCanHoldTheBankSuppressesTheWarning() {
		assertNull(BankAnnotationAdapter.impossibleBank(board(allModesSwitchable()),
			bankKnownModeUnknown(40), universe(WINDOW, 8, 8, 16, 64)));
	}

	/**
	 * A partially recovered mode NARROWS the candidate set, and the narrowing is load-bearing in
	 * both directions. Mode bit 0 known: with it set the reachable modes are 1 and 3, and mode 3's
	 * 64-bank instance can hold bank 40, so no warning. With it clear the reachable modes are 0
	 * and 2, both too small, so the warning fires over exactly those two.
	 */
	@Test
	public void partiallyKnownModeRestrictsWhichLayoutsAreQuantifiedOver() {
		BoardModel board = board(allModesSwitchable());
		Map<String, Set<Integer>> universe = universe(WINDOW, 8, 8, 16, 64);

		assertNull("mode bit 0 set reaches mode 3, which has 64 banks",
			BankAnnotationAdapter.impossibleBank(board, state(40, 0x1, 0x1), universe));

		Impossible bad = BankAnnotationAdapter.impossibleBank(board, state(40, 0x1, 0x0), universe);
		assertTrue(bad instanceof ImpossibleInAllLayouts);
		assertEquals("only modes 0 and 2 are reachable", 2,
			((ImpossibleInAllLayouts) bad).layouts());
	}

	/**
	 * A partially known BANK field is never checked, exactly as in the confident branch: an
	 * unknown bit renders from {@code banking.initial_state}, so flagging it would be flagging the
	 * descriptor's own in-range fallback rather than anything the code wrote (bead grm-v6o).
	 */
	@Test
	public void partiallyKnownBankFieldIsNotChecked() {
		// Every BANK bit known but the topmost -- enough to look like a huge bank, not enough to be one.
		int partial = BANK.positionedMask() & ~(1 << (BANK.lsb() + BANK.width() - 1));
		BankState state = new BankState(partial, 40 << BANK.lsb());

		assertNull(BankAnnotationAdapter.impossibleBank(board(allModesSwitchable()), state,
			universe(WINDOW, 8, 8, 8, 8)));
	}

	// ------------------------------------------------------------------
	// The three abstentions
	// ------------------------------------------------------------------

	/**
	 * A candidate layout the loader realized nothing for abstains for the WHOLE field, not just
	 * for itself: a universal claim cannot be built over a branch we know nothing about. Modes 0-2
	 * are too small and mode 3 is absent from the universe entirely, which under a
	 * per-layout-optimistic reading would still warn. It must not.
	 */
	@Test
	public void aLayoutWithNoRealizedBanksAbstainsForTheEntireField() {
		assertNull(BankAnnotationAdapter.impossibleBank(board(allModesSwitchable()),
			bankKnownModeUnknown(40), universe(WINDOW, 8, 8, 8, 0)));
	}

	/**
	 * A field that feeds no window under any reachable mode is dead configuration, not a recovery
	 * failure. Here every mode-varying instance is FIXED, so {@link #BANK} has zero candidates.
	 */
	@Test
	public void aFieldWithNoCandidateLayoutsIsNotADiagnostic() {
		List<ModeWindowModel> allFixed = new ArrayList<>();
		for (int mode = 0; mode < 4; mode++) {
			allFixed.add(fixed(WINDOW, mode));
		}
		assertNull(BankAnnotationAdapter.impossibleBank(board(allFixed),
			bankKnownModeUnknown(40), universe(WINDOW, 8, 8, 8, 8)));
	}

	/**
	 * A mode-INVARIANT computed window that can hold the bank makes "no reachable layout provides
	 * a slice" false, whatever the mode windows say -- such a window is live under every mode. The
	 * guard is inert on MMC5 (which has no such window) and exists so the claim stays true on the
	 * boards that do.
	 */
	@Test
	public void aModeInvariantWindowThatCanHoldTheBankSuppressesTheWarning() {
		Map<String, ComputedWindowModel> computed = Map.of("PRG_C000",
			new ComputedWindowModel("PRG_C000", 0xc000, 0xdfff, BANK, null));
		Map<String, Set<Integer>> universe = new LinkedHashMap<>(universe(WINDOW, 8, 8, 8, 8));
		universe.put("PRG_C000", range(64));

		assertNull(BankAnnotationAdapter.impossibleBank(
			board(null, allModesSwitchable(), computed), bankKnownModeUnknown(40), universe));
	}

	// ------------------------------------------------------------------
	// Interaction with canonicalization (bead grm-p25h)
	// ------------------------------------------------------------------

	/**
	 * rtk2's shape: a 7-bit register on a cartridge with fewer PRG lines. Bank 96 is out of range
	 * as written, but {@code banking.bank_wrap} truncates it to 0 on real hardware, so it is not
	 * impossible and must not warn. This is the bead's explicit warning that grm-p25h HIDES the
	 * symptom on rtk2 without fixing the structural gap -- pinned here so the two stay separable.
	 */
	@Test
	public void aBankThatWrapsIntoRangeIsNotImpossible() {
		assertNull(BankAnnotationAdapter.impossibleBank(
			board(BankWrap.IMAGE, allModesSwitchable(), Map.of()), bankKnownModeUnknown(96),
			universe(WINDOW, 32, 32, 32, 32)));
	}

	/** A value still out of range AFTER wrapping is still impossible; wrapping is not amnesty. */
	@Test
	public void aBankStillOutOfRangeAfterWrappingStillWarns() {
		// 8 realized banks mask with 7, and the realized set is a proper truncation image, so the
		// wrap applies -- but no non-power-of-two remainder can save a value here, so instead use
		// a realized set the derived form DECLINES on, leaving the raw value exposed.
		Map<String, Set<Integer>> declining = new LinkedHashMap<>();
		for (int mode = 0; mode < 4; mode++) {
			declining.put(BankAnnotationAdapter.modeBankKey(WINDOW, mode), range(6));
		}
		Impossible bad = BankAnnotationAdapter.impossibleBank(
			board(BankWrap.IMAGE, allModesSwitchable(), Map.of()), bankKnownModeUnknown(40),
			declining);

		assertTrue(bad instanceof ImpossibleInAllLayouts);
		assertEquals("the RAW value is reported, not a wrapped one", 40,
			((ImpossibleInAllLayouts) bad).bank());
	}

	// ------------------------------------------------------------------
	// The confident branch is unchanged
	// ------------------------------------------------------------------

	/**
	 * With the mode FULLY recovered the original, stronger diagnostic still runs and still names
	 * the window -- grm-fick adds a branch, it does not reroute the existing one. The distinction
	 * is visible in the type, so a future refactor that collapses the two cannot pass this.
	 */
	@Test
	public void aFullyKnownModeStillYieldsTheConfidentWindowNamedClaim() {
		Impossible bad = BankAnnotationAdapter.impossibleBank(board(allModesSwitchable()),
			state(40, 0x3, 0x2), universe(WINDOW, 8, 8, 16, 64));

		assertTrue("a known mode must keep the window-named claim",
			bad instanceof ImpossibleBank);
		ImpossibleBank one = (ImpossibleBank) bad;
		assertEquals(WINDOW, one.window());
		assertEquals(40, one.bank());
		assertEquals(16, one.realized());
	}

	/**
	 * The two messages must not read as the same claim: only the confident one may name a window
	 * as the thing the bank was wrong for. See {@link ImpossibleInAllLayouts}'s javadoc for why
	 * that distinction is the whole point of the second record.
	 */
	@Test
	public void theTwoDiagnosticsAreWordedAsDifferentClaims() {
		String confident = new ImpossibleBank(WINDOW, 40, 16).message();
		String universal = new ImpossibleInAllLayouts("bank_5115", 40, 4).message();

		assertTrue(confident.contains("for window " + WINDOW));
		assertTrue(universal.contains("NO layout reachable at this site"));
		assertTrue("the weaker claim must not name a window as if it were live",
			!universal.contains("for window "));
	}

	/** An empty bank universe means the loader placed nothing switchable; never a diagnostic. */
	@Test
	public void anEmptyBankUniverseIsNeverADiagnostic() {
		assertNull(BankAnnotationAdapter.impossibleBank(board(allModesSwitchable()),
			bankKnownModeUnknown(40), Map.of()));
	}
}
