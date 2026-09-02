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
import ghidra.program.model.lang.Register;
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
 * This strategy's hooks into the scan: a write to the mechanism (by any store) aborts the
 * scan, and a {@code LD<reg>} of the mechanism itself resolves the base value to the
 * dataflow's tracked in-state at the store (per-bit, possibly partial) -- the port reads
 * back what was stored, unlike a memory latch.
 * <p>
 * The mechanism is recognized by <em>either</em> a memory address (stock 6502: the port is
 * memory-mapped, so {@code STA $01} references {@code $0001}) <em>or</em> an on-die CPU
 * register (the bundled 6510 language models the $01 port as the {@code PORT} register, so
 * {@code STA $01} decodes to {@code PORT = A} with no memory reference at all). The
 * descriptor supplies the register name via the optional {@code register} param; when the
 * loaded language lacks that register (the 6502 fallback), only the address path fires.
 */
public class RegisterWriteBankSwitchStrategy implements BankSwitchStrategy {

	private Address mechAddr;
	private Register mechReg;
	private int mask;

	@Override
	public String strategyName() {
		return "register-write";
	}

	@Override
	public void configure(Program program, JsonObject params, int stateMask) {
		long address = params.get("address").getAsLong();
		mechAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		mechReg = params.has("register") ? program.getRegister(params.get("register").getAsString())
				: null;
		mask = params.has("mask") ? params.get("mask").getAsInt() : stateMask;
	}

	/** Whether {@code instr} writes the mechanism, however it is modeled (address/register). */
	private boolean writesMechanism(Instruction instr) {
		return StoredValueScanner.writesAddress(instr, mechAddr) ||
			(mechReg != null && StoredValueScanner.writesRegister(instr, mechReg));
	}

	/** Whether {@code instr} reads the mechanism back (LDA $01 / LDA PORT). */
	private boolean readsMechanism(Instruction instr) {
		return StoredValueScanner.readsAddress(instr, mechAddr) ||
			(mechReg != null && StoredValueScanner.readsRegister(instr, mechReg));
	}

	private final StoredValueScanner.Hooks hooks = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return writesMechanism(instr);
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			// x is the port's value as tracked in-state at our own store. resolvedTarget is
			// irrelevant here: the mechanism is a CPU register, matched by identity.
			return readsMechanism(loadInstr) ? inStateAtStore : null;
		}
	};

	@Override
	public SwitchOutcome computeSwitchOutcome(Program program, Instruction instr,
			BankState inState) {
		if (!writesMechanism(instr)) {
			return null;
		}

		Character reg = StoredValueScanner.storeRegister(instr);
		if (reg == null) {
			// A mechanism write whose stored register we cannot even identify. Nothing was
			// scanned, so there is no honest runtime gap to report -- this is our limitation.
			return SwitchOutcome.of(BankState.unknown(), ValueStop.ANALYZER_LIMIT);
		}
		StoredValueScanner.Scan scan = StoredValueScanner.resolveStoredValueScan(program, instr,
			reg, inState, mask, hooks, RegisterEnv.NONE);
		return SwitchOutcome.of(scan.value(), scan.stop());
	}

	@Override
	public ValueStop classifyHelperBodyGap(Program program, Instruction switchSite,
			BankState inState, Address helperEntry) {
		Character reg = StoredValueScanner.storeRegister(switchSite);
		if (reg == null) {
			return ValueStop.ANALYZER_LIMIT;
		}
		// The same scan again, differing only in that it stops at the helper's entry. See
		// BankSwitchStrategy.classifyHelperBodyGap: the value is discarded, so this can only
		// reclassify. An all-unknown env is what makes the stop mean "the register is live here"
		// rather than "here is the caller's value" -- there is no caller in scope on this path.
		StoredValueScanner.Scan atEntry = StoredValueScanner.resolveStoredValueScan(program,
			switchSite, reg, inState, mask, hooks, RegisterEnv.entryStopOnly(helperEntry));
		return atEntry.stop() == ValueStop.HELPER_ARGUMENT ? ValueStop.HELPER_ARGUMENT
				: ValueStop.ANALYZER_LIMIT;
	}
}
