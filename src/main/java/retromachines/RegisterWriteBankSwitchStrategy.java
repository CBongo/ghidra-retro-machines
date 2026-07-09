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

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/**
 * The {@code register-write} mechanism class: the bank state changes when the CPU stores
 * to one fixed address (C64 {@code $01}; Spectrum-style latches and Apple II softswitch
 * pokes are the same shape). Params: {@code address} (the mechanism register),
 * {@code mask} (which stored bits are bank-state bits).
 * <p>
 * Value recovery is the shared backward mask-algebra scan ({@link StoredValueScanner}),
 * so the two idioms real 6502 code actually uses to switch banks resolve even though
 * both read the port through a register first:
 * <pre>
 *     LDA $01 / AND #$F8 / ORA #$05 / STA $01   ; set bank 5, preserving cassette bits
 *     LDA $01 / AND #$FE / STA $01              ; clear LORAM only ("BASIC off")
 * </pre>
 * This strategy's hooks into the scan: a write to the mechanism address (by any store)
 * aborts the scan, and a {@code LD<reg>} of the mechanism address itself resolves the
 * base value to the dataflow's tracked in-state at the store (per-bit, possibly
 * partial) -- the port reads back what was stored, unlike a memory latch.
 */
public class RegisterWriteBankSwitchStrategy implements BankSwitchStrategy {

	private Address mechAddr;
	private int mask;

	@Override
	public String strategyName() {
		return "register-write";
	}

	@Override
	public void configure(Program program, JsonObject params, int stateMask) {
		long address = params.get("address").getAsLong();
		mechAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		mask = params.has("mask") ? params.get("mask").getAsInt() : stateMask;
	}

	private final StoredValueScanner.Hooks hooks = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return StoredValueScanner.writesAddress(instr, mechAddr);
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, BankState inStateAtStore) {
			// x is the port's value as tracked in-state at our own store.
			return StoredValueScanner.readsAddress(loadInstr, mechAddr) ? inStateAtStore : null;
		}
	};

	@Override
	public BankState computeSwitch(Program program, Instruction instr, BankState inState) {
		if (!StoredValueScanner.writesAddress(instr, mechAddr)) {
			return null;
		}

		String mnem = instr.getMnemonicString().toUpperCase();
		if (!(mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY"))) {
			// INC/DEC/ASL/LSR/ROL/ROR and friends read-modify-write in place; we don't
			// attempt to track the resulting value.
			return BankState.unknown();
		}

		char reg = mnem.charAt(2); // 'A' | 'X' | 'Y'
		return StoredValueScanner.resolveStoredValue(program, instr, reg, inState, mask, hooks);
	}
}
