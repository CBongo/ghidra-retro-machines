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

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import retromachines.BankDataflowEngine.DataflowResult;
import retromachines.BankDataflowEngine.SwitchResult;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.FixedWindowModel;

/**
 * {@link BankAnnotationAdapter#descriptorFixedBanks} (bead grm-hsv.8): the descriptor's fixed
 * banks, in the scanned window's numbering, minus any a resolved switch commits into it.
 */
public class DescriptorFixedBanksTest {

	/** MMC1-shaped: {@code prg_bank} in state bits 0-3. */
	private static final FieldSpec BANK = new FieldSpec("prg_bank", 0, 4);

	private static final Set<Integer> EIGHT = Set.of(0, 1, 2, 3, 4, 5, 6, 7);

	private static BoardModel board(FixedWindowModel... fixed) {
		return new BoardModel(0xFF, 0, List.of(), List.of(BANK), Map.of(), Map.of(), Map.of(),
			Map.of(), null, 0, List.of(), null, List.of(fixed));
	}

	private static FixedWindowModel fixed(String name, Integer mode, String expr) {
		return new FixedWindowModel(name, 0xC000, 0xFFFF, mode, expr);
	}

	private static DataflowResult flowCommitting(int... banks) {
		GenericAddressSpace space = new GenericAddressSpace("RAM", 16,
			ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
		Map<Address, SwitchResult> results = new java.util.LinkedHashMap<>();
		int i = 0;
		for (int b : banks) {
			results.put(space.getAddress(0x8000 + i++),
				new SwitchResult(new BankState(0xF, b), 0xF, 0, null, null));
		}
		return new DataflowResult(Map.of(), results, Map.of(), Map.of(), null, null, null,
			Map.of());
	}

	private static Set<Integer> fixedBanks(BoardModel board, Integer mode, DataflowResult flow) {
		return BankAnnotationAdapter.descriptorFixedBanks(board, "W8000", 0x8000, 0xBFFF, mode,
			EIGHT, BANK, 0xF, flow);
	}

	@Test
	public void lastIsTheTopBankInTheScannedWindowsNumbering() {
		assertEquals(Set.of(7),
			fixedBanks(board(fixed("WC000", null, "last")), null, flowCommitting()));
	}

	@Test
	public void secondLastAndLiteralBothCount() {
		assertEquals(Set.of(6, 0), fixedBanks(
			board(fixed("WC000", null, "second_last"), fixed("WE000", null, "0")), null,
			flowCommitting()));
	}

	@Test
	public void aResolvedSwitchCommittingTheFixedBankRemovesIt() {
		assertEquals(Set.of(), fixedBanks(board(fixed("WC000", null, "last")), null,
			flowCommitting(3, 7)));
	}

	@Test
	public void aResolvedSwitchCommittingOtherBanksLeavesItAlone() {
		assertEquals(Set.of(7), fixedBanks(board(fixed("WC000", null, "last")), null,
			flowCommitting(1, 2)));
	}

	@Test
	public void aModeInstanceCountsOnlyUnderItsOwnMode() {
		BoardModel b = board(fixed("WC000", 3, "last"));
		assertEquals(Set.of(7), fixedBanks(b, 3, flowCommitting()));
		assertEquals(Set.of(), fixedBanks(b, 2, flowCommitting()));
		assertEquals(Set.of(), fixedBanks(b, null, flowCommitting()));
	}

	@Test
	public void noFixedWindowMeansNoExemption() {
		assertEquals(Set.of(), fixedBanks(board(), null, flowCommitting()));
	}

	@Test
	public void aNonInjectiveWindowGetsNoExemption() {
		assertEquals(Set.of(), BankAnnotationAdapter.descriptorFixedBanks(
			board(fixed("WC000", null, "last")), "W8000", 0x8000, 0xBFFF, null, EIGHT, BANK, 0xE,
			flowCommitting()));
	}
}
