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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins the operations {@link Mos6502ConstantSemantics} added when grm-as0m turned
 * {@link StoredValueScanner#constantRegisterValue} into a location-and-operation evaluator:
 * {@code SBC}, {@code ROL}/{@code ROR}, the memory-operand forms of the logical and arithmetic
 * operations, and the p-code half of {@link Mos6502ConstantSemantics#writes}. The
 * carry-through-{@code ADC} cases live in {@link AdcCarryConstantValueProgramTest}.
 */
public class ConstantSemanticsProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	private void build(String languageId) throws Exception {
		builder = new ProgramBuilder("Test", languageId);
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		int tx = program.startTransaction("set block write permission");
		try {
			zp.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/** Hooks that resolve no load. */
	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};

	/** Hooks that answer a load of {@code $9000} with {@code $3C}, as a ROM-byte hook would. */
	private static final StoredValueScanner.Hooks ROM_9000 = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return resolvedTarget != null && resolvedTarget.getOffset() == 0x9000
					? BankState.fullyKnown(0xFF, 0x3C)
					: null;
		}
	};

	private Integer before(String address, char reg, StoredValueScanner.Hooks hooks) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return StoredValueScanner.constantRegisterValue(program, instr, reg, hooks,
			RegisterEnv.NONE, new StoredValueScanner.Budget(64));
	}

	// ------------------------------------------------------------------
	// SBC
	// ------------------------------------------------------------------

	/** {@code SEC / SBC} is a plain subtraction: {@code $10 - $03 = $0D}. */
	@Test
	public void secSbcSubtracts() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 10", true); // LDA #$10
		builder.setBytes("0x8002", "38", true); // SEC
		builder.setBytes("0x8003", "e9 03", true); // SBC #$03
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x0D), before("0x8005", 'A', NO_HOOKS));
	}

	/** {@code CLC} is a borrow: {@code $10 - $03 - 1 = $0C}. */
	@Test
	public void clcSbcBorrows() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 10", true); // LDA #$10
		builder.setBytes("0x8002", "18", true); // CLC
		builder.setBytes("0x8003", "e9 03", true); // SBC #$03
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x0C), before("0x8005", 'A', NO_HOOKS));
	}

	/** An {@code SBC} that underflows clears carry (a borrow out), which the next {@code ADC}
	 *  then adds in as 0: {@code $01 - $02 = $FF}, C = 0; {@code $FF + $05 + 0 = $04}. */
	@Test
	public void sbcBorrowOutFeedsTheNextAdc() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 01", true); // LDA #$01
		builder.setBytes("0x8002", "38", true); // SEC
		builder.setBytes("0x8003", "e9 02", true); // SBC #$02  -- A = $FF, C = 0
		builder.setBytes("0x8005", "69 05", true); // ADC #$05  -- A = $04
		builder.setBytes("0x8007", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x04), before("0x8007", 'A', NO_HOOKS));
	}

	// ------------------------------------------------------------------
	// ROL / ROR
	// ------------------------------------------------------------------

	/** {@code SEC / ROL A} rotates the carry into bit 0: {@code $40 -> $81}. */
	@Test
	public void rolRotatesTheCarryIn() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 40", true); // LDA #$40
		builder.setBytes("0x8002", "38", true); // SEC
		builder.setBytes("0x8003", "2a", true); // ROL A
		builder.setBytes("0x8004", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x81), before("0x8004", 'A', NO_HOOKS));
	}

	/** {@code LSR A} of {@code $03} leaves {@code $01} and shifts a 1 out; {@code ROR A} then
	 *  rotates it into bit 7: {@code $80}. The carry comes from the shift, not a flag op. */
	@Test
	public void rorRotatesTheShiftedOutBitIn() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "4a", true); // LSR A     -- A = $01, C = 1
		builder.setBytes("0x8003", "6a", true); // ROR A     -- A = $80
		builder.setBytes("0x8004", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x80), before("0x8004", 'A', NO_HOOKS));
	}

	/** Nothing establishes the carry before this {@code ROL}, so it declines. */
	@Test
	public void rolWithUnknownCarryDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 40", true); // LDA #$40
		builder.setBytes("0x8002", "2a", true); // ROL A
		builder.setBytes("0x8003", "8d 01 80", true); // STA $8001

		assertNull(before("0x8003", 'A', NO_HOOKS));
	}

	// ------------------------------------------------------------------
	// Memory operands
	// ------------------------------------------------------------------

	/** {@code AND $9000} folds when the strategy's hook pins the byte it reads:
	 *  {@code $F0 & $3C = $30}. */
	@Test
	public void andOverResolvedMemoryFolds() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 f0", true); // LDA #$F0
		builder.setBytes("0x8002", "2d 00 90", true); // AND $9000 -- reads $3C
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x30), before("0x8005", 'A', ROM_9000));
	}

	/** The same {@code AND} declines when nothing pins the byte. */
	@Test
	public void andOverUnresolvedMemoryDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 f0", true); // LDA #$F0
		builder.setBytes("0x8002", "2d 00 90", true); // AND $9000
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertNull(before("0x8005", 'A', NO_HOOKS));
	}

	/** {@code CPX $9000} decides the carry from a resolved memory byte: {@code $3C >= $3C}. */
	@Test
	public void compareOverResolvedMemoryDecidesTheCarry() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a2 3c", true); // LDX #$3C
		builder.setBytes("0x8002", "a9 00", true); // LDA #$00
		builder.setBytes("0x8004", "ec 00 90", true); // CPX $9000 -- C = 1
		builder.setBytes("0x8007", "69 00", true); // ADC #$00  -- A = 1
		builder.setBytes("0x8009", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x01), before("0x8009", 'A', ROM_9000));
	}

	// ------------------------------------------------------------------
	// writes(): the p-code half of the union
	// ------------------------------------------------------------------

	/** The undocumented {@code LAX} writes A and X but is in no mnemonic modifier table, so
	 *  before grm-as0m the X query stepped straight over it to the {@code LDX #$05} and answered
	 *  5 -- a confident wrong value. Its p-code result objects now stop the walk there, and
	 *  since this table does not evaluate {@code LAX} the query declines. */
	@Test
	public void undocumentedWriterIsNotSteppedOver() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "a2 05", true); // LDX #$05
		builder.setBytes("0x8002", "a7 10", true); // LAX $10   -- A = X = [$10]
		builder.setBytes("0x8004", "8e 01 80", true); // STX $8001

		assertNull(before("0x8004", 'X', NO_HOOKS));
	}
}
