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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * {@code ProgramBuilder} coverage of bead grm-hsv.9: a RAM cell's store is forwarded across a
 * {@code JSR} whose callee closure provably never writes the cell, and the helper-argument stop
 * survives the spill. The shape is dodge's {@code FUN_fe96}: {@code STA $69 / SEI / ... / JSR
 * $FE8A / LDA $69 / STA <mechanism>}.
 */
public class CallCrossingCellForwardingProgramTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		inTx(program, "set block write permission", () -> {
			zp.setWrite(true);
		});
	}

	private static StoredValueScanner.Hooks hooks(boolean oracle) {
		return new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
					MechanismState inStateAtStore) {
				return null;
			}

			@Override
			public MechanismState stateAt(Address addr) {
				return MechanismState.unknown();
			}

			@Override
			public boolean hasStateOracle() {
				return oracle;
			}
		};
	}

	private StoredValueScanner.Scan scan(String site, RegisterEnv env, boolean oracle) {
		return StoredValueScanner.resolveStoredValueScan(program, instructionAt(site), 'A',
			MechanismState.unknown(), 0xFF, hooks(oracle), env);
	}

	/** {@code <source> / STA $69 / JSR $C040 / LDA $69 / STA $8000}; the site is $C009. */
	private void spillAcrossCall(String sourceHex) throws Exception {
		put("0xc000", sourceHex);
		put("0xc002", "85 69"); // STA $69
		put("0xc004", "20 40 c0"); // JSR $C040
		put("0xc007", "a5 69"); // LDA $69
		put("0xc009", "8d 00 80"); // STA $8000
	}

	@Test
	public void cleanCalleeIsCrossed() throws Exception {
		spillAcrossCall("a9 05"); // LDA #$05
		put("0xc040", "e6 10"); // INC $10   -- a different cell
		put("0xc042", "60"); // RTS
		PartialByte v = scan("0xc009", RegisterEnv.NONE, true).value();
		assertEquals(0xFF, v.knownMask());
		assertEquals(5, v.bits());
	}

	@Test
	public void cleanCalleeIsCrossedWithoutAnOracleToo() throws Exception {
		spillAcrossCall("a9 05");
		put("0xc040", "60");
		PartialByte v = scan("0xc009", RegisterEnv.NONE, false).value();
		assertEquals(0xFF, v.knownMask());
		assertEquals(5, v.bits());
	}

	@Test
	public void calleeWritingTheCellDeclines() throws Exception {
		spillAcrossCall("a9 05");
		put("0xc040", "85 69"); // STA $69
		put("0xc042", "60");
		assertEquals(0, scan("0xc009", RegisterEnv.NONE, true).value().knownMask());
	}

	@Test
	public void calleeWithAComputedJumpDeclines() throws Exception {
		spillAcrossCall("a9 05");
		put("0xc040", "6c 00 02"); // JMP ($0200)
		assertEquals(0, scan("0xc009", RegisterEnv.NONE, true).value().knownMask());
	}

	/** The inbound register spilled across a clean call is still the helper's ARGUMENT. */
	@Test
	public void spilledInboundRegisterStaysTheHelperArgument() throws Exception {
		put("0xc000", "85 69"); // STA $69     -- helper entry
		put("0xc002", "20 40 c0"); // JSR $C040
		put("0xc005", "a5 69"); // LDA $69
		put("0xc007", "8d 00 80"); // STA $8000
		put("0xc040", "60");
		StoredValueScanner.Scan scan =
			scan("0xc007", RegisterEnv.entryStopOnly(builder.addr("0xc000")), true);
		assertEquals(BankSwitchStrategy.ValueStop.HELPER_ARGUMENT, scan.stop());
	}

	/** ... but not when the callee may overwrite the cell. */
	@Test
	public void spilledInboundRegisterAcrossADirtyCallIsNotTheArgument() throws Exception {
		put("0xc000", "85 69");
		put("0xc002", "20 40 c0");
		put("0xc005", "a5 69");
		put("0xc007", "8d 00 80");
		put("0xc040", "e6 69"); // INC $69
		put("0xc042", "60");
		StoredValueScanner.Scan scan =
			scan("0xc007", RegisterEnv.entryStopOnly(builder.addr("0xc000")), true);
		assertEquals(BankSwitchStrategy.ValueStop.ANALYZER_LIMIT, scan.stop());
	}
}
