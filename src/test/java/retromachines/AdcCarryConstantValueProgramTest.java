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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins {@link StoredValueScanner}'s {@code ADC #imm} model (bead grm-4bgh.2): exact once the
 * carry it adds in is itself known, which on 6502 means a {@code CLC} or {@code SEC} reaches
 * the {@code ADC} with no carry-writer in between.
 * <p>
 * River City Ransom's {@code FUN_fed1} is the motivating shape -- it computes the odd half of
 * an MMC3 8 KB register pair as {@code ASL A / CLC / ADC #$01}. The {@code ASL} is itself a
 * carry-writer, so the {@code CLC} in that sequence is load-bearing rather than decorative,
 * which is what {@link #carryWriterBetweenClcAndAdcDeclines} pins.
 * <p>
 * These call the evaluator directly rather than going through a strategy: it is a
 * package-private all-or-nothing evaluator with its own semantics, separate from
 * {@code resolveStoredValue}'s mask algebra, and this increment moves no golden by design.
 * <p>
 * Fixture note inherited from {@link StackRelativeReloadProgramTest}: {@link ProgramBuilder}
 * blocks are created read-only, so every RAM block must be made writable explicitly.
 */
public class AdcCarryConstantValueProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(zp);
		makeWritable(ram);
	}

	private void makeWritable(MemoryBlock block) {
		int tx = program.startTransaction("set block write permission");
		try {
			block.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/** Hooks that answer neither question -- same shape as every other test file's NO_HOOKS. */
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

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/** The byte A holds immediately before {@code address}, or null when unmodeled. */
	private Integer accumulatorBefore(String address) {
		return StoredValueScanner.constantRegisterValue(program, instructionAt(address), 'A',
			NO_HOOKS, RegisterEnv.NONE, new StoredValueScanner.Budget(64));
	}

	// ------------------------------------------------------------------
	// 1. The fed1 arithmetic: CLC + ADC #imm after a shift
	// ------------------------------------------------------------------

	/** {@code LDA #$05 / ASL A / CLC / ADC #$01} -- fed1's r7 = A*2+1, with A = 5, so 11. */
	@Test
	public void clcAdcAfterShiftResolvesExactly() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "0a", true); // ASL A     -- A = 10, and WRITES carry
		builder.setBytes("0x8003", "18", true); // CLC       -- so this is load-bearing
		builder.setBytes("0x8004", "69 01", true); // ADC #$01  -- A = 11
		builder.setBytes("0x8006", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(11), accumulatorBefore("0x8006"));
	}

	// ------------------------------------------------------------------
	// 2. SEC adds the carry bit in
	// ------------------------------------------------------------------

	/** {@code LDA #$05 / SEC / ADC #$01} adds the carry too: 5 + 1 + 1 = 7. */
	@Test
	public void secAdcAddsTheCarryBit() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "38", true); // SEC
		builder.setBytes("0x8003", "69 01", true); // ADC #$01
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(7), accumulatorBefore("0x8005"));
	}

	// ------------------------------------------------------------------
	// 3. The result is a byte
	// ------------------------------------------------------------------

	/** {@code LDA #$FF / CLC / ADC #$02} wraps: this evaluator deals in bytes, not integers. */
	@Test
	public void resultWrapsToEightBits() throws Exception {
		builder.setBytes("0x8000", "a9 ff", true); // LDA #$FF
		builder.setBytes("0x8002", "18", true); // CLC
		builder.setBytes("0x8003", "69 02", true); // ADC #$02
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x01), accumulatorBefore("0x8005"));
	}

	// ------------------------------------------------------------------
	// 4. Decline: nothing establishes the carry
	// ------------------------------------------------------------------

	/** With no {@code CLC}/{@code SEC} anywhere before it the {@code ADC} declines -- adding an
	 *  unknown bit is a wrong answer, not a missing one. */
	@Test
	public void adcWithNoCarryEstablishedDeclines() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "69 01", true); // ADC #$01
		builder.setBytes("0x8004", "8d 01 80", true); // STA $8001

		assertNull(accumulatorBefore("0x8004"));
	}

	// ------------------------------------------------------------------
	// 5. Decline: a carry-writer between the CLC and the ADC
	// ------------------------------------------------------------------

	/** {@code CLC / LDA #$05 / ASL A / ADC #$01} -- the {@code ASL} writes carry AFTER the
	 *  {@code CLC}, so that {@code CLC} says nothing about the carry the {@code ADC} adds in.
	 *  This is fed1's own sequence with its {@code CLC} misplaced. */
	@Test
	public void carryWriterBetweenClcAndAdcDeclines() throws Exception {
		builder.setBytes("0x8000", "18", true); // CLC
		builder.setBytes("0x8001", "a9 05", true); // LDA #$05
		builder.setBytes("0x8003", "0a", true); // ASL A     -- writes carry
		builder.setBytes("0x8004", "69 01", true); // ADC #$01
		builder.setBytes("0x8006", "8d 01 80", true); // STA $8001

		assertNull(accumulatorBefore("0x8006"));
	}

	// ------------------------------------------------------------------
	// 6. Decline: a comparison between the CLC and the ADC
	// ------------------------------------------------------------------

	/** {@code CMP} does not touch A, so the accumulator walk steps straight over it -- but it
	 *  DOES write carry, so the separate carry walk must not. Isolates the carry walk from the
	 *  value walk, which the {@code ASL} case above cannot. */
	@Test
	public void comparisonBetweenClcAndAdcDeclines() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "18", true); // CLC
		builder.setBytes("0x8003", "c9 03", true); // CMP #$03  -- writes carry, leaves A alone
		builder.setBytes("0x8005", "69 01", true); // ADC #$01
		builder.setBytes("0x8007", "8d 01 80", true); // STA $8001

		assertNull(accumulatorBefore("0x8007"));
	}

	// ------------------------------------------------------------------
	// 7. Decline: a non-immediate ADC
	// ------------------------------------------------------------------

	/** Only the immediate form is modeled: {@code ADC $10} adds a memory byte this evaluator
	 *  makes no attempt to resolve. */
	@Test
	public void nonImmediateAdcDeclines() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "18", true); // CLC
		builder.setBytes("0x8003", "65 10", true); // ADC $10
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertNull(accumulatorBefore("0x8005"));
	}

	// ------------------------------------------------------------------
	// 8. Decline: a control-flow join between the CLC and the ADC
	// ------------------------------------------------------------------

	/** Another path reaches the {@code ADC} and may arrive with the other carry, so the
	 *  {@code CLC} on this path cannot be attributed to it. */
	@Test
	public void joinBetweenClcAndAdcDeclines() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "18", true); // CLC       -- falls straight through
		builder.setBytes("0x8003", "69 01", true); // ADC #$01  -- also a branch target below
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001
		// An unrelated incoming edge into the ADC, making it a control-flow join.
		builder.setBytes("0x9000", "4c 03 80", true); // JMP $8003

		assertNull(accumulatorBefore("0x8005"));
	}

	// ------------------------------------------------------------------
	// 9. Composes with the stack-relative reload (grm-4bgh.1)
	// ------------------------------------------------------------------

	/** fed1's r7 arithmetic over a stack-passed argument, with the intervening mechanism write
	 *  left out (the real fed1 has an {@code STA $8000} between its two halves, which aborts
	 *  every backward walk -- see grm-4bgh's fifth-blocker comment; this pins the arithmetic
	 *  that applies wherever the scan does reach it). {@code $2A * 2 + 1 = $55}. */
	@Test
	public void composesWithTheStackRelativeReload() throws Exception {
		builder.setBytes("0x8000", "a9 2a", true); // LDA #$2A   -- the caller's bank argument
		builder.setBytes("0x8002", "48", true); // PHA        -- push 1: the argument
		builder.setBytes("0x8003", "8a", true); // TXA
		builder.setBytes("0x8004", "48", true); // PHA        -- push 2: X
		builder.setBytes("0x8005", "ba", true); // TSX
		builder.setBytes("0x8006", "bd 02 01", true); // LDA $0102,X -- reloads the argument
		builder.setBytes("0x8009", "0a", true); // ASL A
		builder.setBytes("0x800a", "18", true); // CLC
		builder.setBytes("0x800b", "69 01", true); // ADC #$01
		builder.setBytes("0x800d", "8d 01 80", true); // STA $8001

		assertEquals(Integer.valueOf(0x55), accumulatorBefore("0x800d"));
	}
}
