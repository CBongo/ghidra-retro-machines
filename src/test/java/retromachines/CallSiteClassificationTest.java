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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import retromachines.BankDataflowEngine.ArgumentSought;
import retromachines.BankDataflowEngine.CallSwitch;
import retromachines.BankSwitchStrategy.ValueStop;
import retromachines.BoardBankAnalyzer.CallVerdict;

/**
 * Pure-JUnit coverage of {@link BoardBankAnalyzer#classifyCallSite} (bead grm-rx1i.8): every
 * verdict branch, with no {@code ProgramBuilder}. Only an {@code Address} is needed from Ghidra,
 * and a {@link GenericAddressSpace} makes one without any bootstrap.
 */
public class CallSiteClassificationTest {

	private static final AddressSpace SPACE =
		new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);
	private static final Address CELL = SPACE.getAddress(0x0769);
	private static final String MULTI = "multi-valued text";
	private static final String HELPER = "FUN_c000";

	private static StoredValueScanner.ReadBack readBack() {
		return new StoredValueScanner.ReadBack(CELL, SPACE.getAddress(0x8000), null, null, null,
			null, List.of());
	}

	private static CallSwitch call(boolean argumentResolved, boolean noInbound,
			boolean secondTier, Address restoreCell, StoredValueScanner.ReadBack readBack,
			boolean armsDenied, ArgumentSought sought) {
		return new CallSwitch(HELPER, BankState.unknown(), BankState.unknown(), argumentResolved,
			noInbound, secondTier, restoreCell, readBack, List.of(), armsDenied, sought);
	}

	private static CallVerdict classify(CallSwitch cs, SwitchSiteHints.HintNote note,
			String callerRestore) {
		return BoardBankAnalyzer.classifyCallSite(cs, note, () -> MULTI, () -> callerRestore);
	}

	@Test
	public void plainUnrecoveredArgumentIsAnalyzerLimitWithGenericWarning() {
		CallVerdict v = classify(call(false, false, false, null, null, false,
			ArgumentSought.SOUGHT), null, null);

		assertEquals(ValueStop.ANALYZER_LIMIT, v.stop());
		assertTrue(v.warningText().endsWith(HELPER + " whose bank argument could not be " +
			"recovered at this call site"));
		assertNull(v.honestDetail());
	}

	@Test
	public void warningWordingFollowsNoInboundArgumentThenArgumentSought() {
		CallVerdict noInbound = classify(call(false, true, false, null, null, false,
			ArgumentSought.SOUGHT), null, null);
		CallVerdict noRegister = classify(call(false, false, false, null, null, false,
			ArgumentSought.NO_ARGUMENT_REGISTER), null, null);
		CallVerdict reDerived = classify(call(false, false, false, null, null, false,
			ArgumentSought.RE_DERIVED_IN_HELPER), null, null);

		assertTrue(noInbound.warningText().contains("takes NO INBOUND ARGUMENT"));
		assertTrue(noRegister.warningText().contains("models with no argument register"));
		assertTrue(reDerived.warningText().contains("re-derived inside the helper"));
		// none of the wording cases changes the classification: all stay warnings
		assertEquals(ValueStop.ANALYZER_LIMIT, noInbound.stop());
		assertEquals(ValueStop.ANALYZER_LIMIT, noRegister.stop());
		assertEquals(ValueStop.ANALYZER_LIMIT, reDerived.stop());
	}

	@Test
	public void secondTierRelayIsSecondTierArgumentAndCarriesTheHintNoteDetail() {
		CallSwitch relay = call(false, false, true, null, null, false, ArgumentSought.SOUGHT);
		SwitchSiteHints.HintNote note =
			new SwitchSiteHints.HintNote(0, true, null, null, "relay detail");

		CallVerdict withNote = classify(relay, note, null);
		CallVerdict withoutNote = classify(relay, null, null);

		assertEquals(ValueStop.SECOND_TIER_ARGUMENT, withNote.stop());
		assertEquals("relay detail", withNote.honestDetail());
		assertEquals(ValueStop.SECOND_TIER_ARGUMENT, withoutNote.stop());
		assertNull(withoutNote.honestDetail());
	}

	@Test
	public void deniedArmsAreMultiValuedAtMergeWithTheSuppliedWarning() {
		CallVerdict v = classify(call(false, false, false, null, null, true,
			ArgumentSought.SOUGHT), null, null);

		assertEquals(ValueStop.MULTI_VALUED_AT_MERGE, v.stop());
		assertEquals(MULTI, v.warningText());
		assertNull(v.honestDetail());
	}

	@Test
	public void restoreCellWithHintDetailUsesTheHintsOwnText() {
		SwitchSiteHints.HintNote note =
			new SwitchSiteHints.HintNote(0, true, null, null, "shadow detail");

		CallVerdict v = classify(call(false, false, false, CELL, null, false,
			ArgumentSought.SOUGHT), note, null);

		assertEquals(ValueStop.RESTORED_BANK, v.stop());
		assertEquals("shadow detail", v.honestDetail());
	}

	@Test
	public void restoreCellWithoutHintDetailGetsTheProvenRestoreText() {
		SwitchSiteHints.HintNote noDetail =
			new SwitchSiteHints.HintNote(0, true, null, null, null);

		CallVerdict v = classify(call(false, false, false, CELL, null, false,
			ArgumentSought.SOUGHT), noDetail, null);

		assertEquals(ValueStop.RESTORED_BANK, v.stop());
		assertTrue(v.honestDetail().startsWith("Bank value is RESTORED here, not resolved"));
		assertTrue(v.honestDetail().contains(HELPER));
		assertTrue(v.honestDetail().contains(CELL.toString()));
	}

	@Test
	public void callerReadBackWithEstablishedPremiseIsRestoredBank() {
		CallVerdict v = classify(call(false, false, false, null, readBack(), false,
			ArgumentSought.SOUGHT), null, "caller restore detail");

		assertEquals(ValueStop.RESTORED_BANK, v.stop());
		assertEquals("caller restore detail", v.honestDetail());
	}

	@Test
	public void callerReadBackWithUnestablishedPremiseFallsThroughToAnalyzerLimit() {
		CallVerdict v = classify(call(false, false, false, null, readBack(), false,
			ArgumentSought.SOUGHT), null, null);

		assertEquals(ValueStop.ANALYZER_LIMIT, v.stop());
		assertNull(v.honestDetail());
	}

	@Test
	public void aResolvedArgumentNeverTakesTheHonestBranches() {
		// every honest-gap test is guarded by !argumentResolved
		CallVerdict v = classify(call(true, false, true, CELL, readBack(), true,
			ArgumentSought.SOUGHT), new SwitchSiteHints.HintNote(0, true, null, null, "x"),
			"never asked");

		assertEquals(ValueStop.ANALYZER_LIMIT, v.stop());
		assertNull(v.honestDetail());
		assertFalse(v.warningText().isEmpty());
	}

	@Test
	public void callerRestoreDetailIsOnlyAskedWhenEarlierTestsFallThrough() {
		boolean[] asked = {false};
		CallSwitch denied = call(false, false, false, null, readBack(), true,
			ArgumentSought.SOUGHT);

		BoardBankAnalyzer.classifyCallSite(denied, null, () -> MULTI, () -> {
			asked[0] = true;
			return "x";
		});

		assertFalse(asked[0]);
	}
}
