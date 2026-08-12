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

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins {@link StoredValueScanner}'s intra-block PHA/PLA VALUE carrying (grm-mej.3 increment 2):
 * a {@code PLA} the backward walk meets is paired to its {@code PHA} BY STACK DEPTH, and the
 * value it recovers is whatever A held immediately before that push, with the accumulated
 * AND/ORA transform composed after the pop still applying.
 * <p>
 * Fixture note inherited from {@link StoreForwardingProgramTest}: {@link ProgramBuilder} blocks
 * are created read-only, so every RAM block must be made writable explicitly.
 */
public class PushPullValueCarryingProgramTest extends AbstractBundledLanguageTest {

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

	/** An AxROM-shaped latch: the whole ROM area, no address decode, 3-bit field. */
	private MemoryLatchBankSwitchStrategy axromLatch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x07);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0x07);
		return strategy;
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private void assertBank(int expected, BankState actual) {
		assertEquals("tracked bits not fully known: " + actual, 0x07, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	private void assertUnresolved(BankState actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
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

	// ------------------------------------------------------------------
	// 1. Simple pair
	// ------------------------------------------------------------------

	/** {@code LDA #imm / PHA / <A clobbered> / PLA / STA <chain>} recovers the immediate. */
	@Test
	public void simplePairRecoversTheImmediate() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "a9 ff", true); // LDA #$FF   -- clobber A
		builder.setBytes("0x8005", "68", true); // PLA
		builder.setBytes("0x8006", "8d 00 80", true); // STA $8000

		assertBank(5, axromLatch().computeSwitch(program, instructionAt("0x8006"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 2. Arithmetic composed after the pop
	// ------------------------------------------------------------------

	/** {@code LDA #imm / PHA / ... / PLA / AND #$0f / STA} still applies the mask after the pop. */
	@Test
	public void arithmeticComposedAfterThePopStillApplies() throws Exception {
		builder.setBytes("0x8000", "a9 1f", true); // LDA #$1F
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "a9 ff", true); // LDA #$FF   -- clobber A
		builder.setBytes("0x8005", "68", true); // PLA
		builder.setBytes("0x8006", "29 0f", true); // AND #$0F   -- $1F & $0F = $0F
		builder.setBytes("0x8008", "8d 00 80", true); // STA $8000

		// $0F reduced to the 3-bit latch field is $07.
		assertBank(7, axromLatch().computeSwitch(program, instructionAt("0x8008"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 3. PHP/PLP interleaved does not desync the pairing
	// ------------------------------------------------------------------

	/** {@code PHA / PHP / PLP / <clobber> / PLA} -- the interleaved status pair balances on
	 *  its own, so the outer {@code PLA} still pairs with the outer {@code PHA}. */
	@Test
	public void interleavedPhpPlpDoesNotDesyncThePairing() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA        -- outer push
		builder.setBytes("0x8003", "08", true); // PHP        -- status push
		builder.setBytes("0x8004", "28", true); // PLP        -- status pop, balances
		builder.setBytes("0x8005", "a9 ff", true); // LDA #$FF   -- clobber
		builder.setBytes("0x8007", "68", true); // PLA        -- pairs with the outer PHA
		builder.setBytes("0x8008", "8d 00 80", true); // STA $8000

		assertBank(5, axromLatch().computeSwitch(program, instructionAt("0x8008"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 4. A PLA whose matching push is a PHP is unknown
	// ------------------------------------------------------------------

	/** The matching push is {@code PHP}: a status byte is never a value. */
	@Test
	public void plaMatchingAPhpIsUnknown() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "08", true); // PHP
		builder.setBytes("0x8003", "68", true); // PLA        -- pops the flags, not a value
		builder.setBytes("0x8004", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8004"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 5. Nested pairs pair correctly
	// ------------------------------------------------------------------

	/** An inner {@code PHA}/{@code PLA} pair sits fully between the outer pair; the outer
	 *  {@code PLA} must still find the OUTER {@code PHA}, skipping the balanced inner one. */
	@Test
	public void nestedPairsPairCorrectly() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05   -- outer value
		builder.setBytes("0x8002", "48", true); // PHA        -- outer push
		builder.setBytes("0x8003", "a9 aa", true); // LDA #$AA   -- inner value
		builder.setBytes("0x8005", "48", true); // PHA        -- inner push
		builder.setBytes("0x8006", "a9 00", true); // LDA #$00   -- clobber
		builder.setBytes("0x8008", "68", true); // PLA        -- inner pop (discarded)
		builder.setBytes("0x8009", "a9 ff", true); // LDA #$FF   -- clobber again
		builder.setBytes("0x800b", "68", true); // PLA        -- outer pop
		builder.setBytes("0x800c", "8d 00 80", true); // STA $8000

		assertBank(5, axromLatch().computeSwitch(program, instructionAt("0x800c"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 6. TXS between PHA and PLA -- the base-register trap regression test
	// ------------------------------------------------------------------

	/**
	 * {@code TXS} between the push and the pull desynchronises the stack depth this walk tracks,
	 * so the pairing must abandon. This is specifically the base-register comparison's own test:
	 * the 6502 declares a two-byte {@code SP} and a one-byte {@code S} over the same bytes, and
	 * {@code TXS}'s p-code writes {@code S} while {@code CompilerSpec.getStackPointer()} answers
	 * {@code SP}. An {@code equals} comparison would miss this and pair across the {@code TXS}
	 * regardless.
	 */
	@Test
	public void txsBetweenPushAndPullAbandonsByBaseRegister() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "a2 ff", true); // LDX #$FF
		builder.setBytes("0x8005", "9a", true); // TXS        -- stack pointer moved
		builder.setBytes("0x8006", "68", true); // PLA
		builder.setBytes("0x8007", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8007"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 7. A branch between PHA and PLA abandons
	// ------------------------------------------------------------------

	/** A branch instruction sitting between the push and the pull means the walk is no longer
	 *  provably straight-line, so the pairing must abandon whichever way the branch goes. */
	@Test
	public void branchBetweenPushAndPullAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "d0 00", true); // BNE $8005  -- branches to its own fall-through
		builder.setBytes("0x8005", "68", true); // PLA
		builder.setBytes("0x8006", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8006"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 8. Exceeding MAX_BACKWARD_SCAN across the pair degrades to unknown
	// ------------------------------------------------------------------

	/** More filler instructions between the push and the pull than the shared
	 *  {@code MAX_BACKWARD_SCAN} budget allows -- the pairing search must not silently borrow a
	 *  fresh budget, so this degrades to unknown rather than finding the distant {@code PHA}. */
	@Test
	public void exceedingTheSharedBudgetAcrossThePairDegradesToUnknown() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA

		// 20 NOPs -- comfortably more than MAX_BACKWARD_SCAN (16) instructions of filler.
		int cursor = 0x8003;
		for (int i = 0; i < 20; i++) {
			builder.setBytes(String.format("0x%x", cursor), "ea", true); // NOP
			cursor += 1;
		}
		builder.setBytes(String.format("0x%x", cursor), "68", true); // PLA
		cursor += 1;
		builder.setBytes(String.format("0x%x", cursor), "8d 00 80", true); // STA $8000
		String storeAddr = String.format("0x%x", cursor);

		assertUnresolved(
			axromLatch().computeSwitch(program, instructionAt(storeAddr), BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 9. Acceptance: the dodge FUN_ff08 shape, Change 1 + Change 2 together
	// ------------------------------------------------------------------

	/**
	 * The motivating end-to-end shape from the bead: dodge's {@code FUN_ff08} parks its argument
	 * at {@code $0103} (a stack-page cell, Change 2) via a {@code PHA}/{@code PLA} save/restore
	 * (Change 1) and later reloads it past an intervening, unrelated {@code PHA}.
	 * <pre>
	 *   ff08 PHA / ff09 SEI / ff0a LDA $FF / ff0c AND #$7F / ff0e STA $2000 / ff11 PLA
	 *   ff12 STA $0103 / ff15 LDA $FF / ff17 PHA / ff18 AND #$7F / ff1a STA $FF
	 *   ff1c LDA $0103 / ff1f STA $FFFF
	 * </pre>
	 * The value pushed at {@code ff08} is pinned by an {@code LDA #$99} placed immediately before
	 * it (bit 7 set, deliberately outside the {@code AND #$7F} range used elsewhere in this
	 * routine, so an implementation that accidentally picked up one of THOSE masked values instead
	 * of genuinely carrying {@code $99} through the push/pop and the stack-page forward would be
	 * caught: any such wrong answer has bit 7 clear).
	 */
	@Test
	public void dodgeFun_ff08ShapeResolvesEndToEnd() throws Exception {
		builder.setBytes("0xff06", "a9 99", true); // LDA #$99   -- pins the value PHA pushes
		builder.setBytes("0xff08", "48", true); // PHA
		builder.setBytes("0xff09", "78", true); // SEI
		builder.setBytes("0xff0a", "a5 ff", true); // LDA $FF
		builder.setBytes("0xff0c", "29 7f", true); // AND #$7F
		builder.setBytes("0xff0e", "8d 00 20", true); // STA $2000
		builder.setBytes("0xff11", "68", true); // PLA        -- pairs with ff08, recovers $99
		builder.setBytes("0xff12", "8d 03 01", true); // STA $0103  -- stack-page parking cell
		builder.setBytes("0xff15", "a5 ff", true); // LDA $FF
		builder.setBytes("0xff17", "48", true); // PHA        -- unrelated, intervenes on $0103
		builder.setBytes("0xff18", "29 7f", true); // AND #$7F
		builder.setBytes("0xff1a", "85 ff", true); // STA $FF
		builder.setBytes("0xff1c", "ad 03 01", true); // LDA $0103  -- forwards through the stack page
		builder.setBytes("0xff1f", "8d ff ff", true); // STA $FFFF

		BankState result = StoredValueScanner.resolveStoredValue(program, instructionAt("0xff1f"),
			'A', BankState.unknown(), 0xFF, NO_HOOKS);

		assertEquals("tracked bits not fully known: " + result, 0xFF, result.knownMask());
		assertEquals(0x99, result.bits());
	}

	// ------------------------------------------------------------------
	// 10. Unbalanced PLA
	// ------------------------------------------------------------------

	/** A {@code PLA} with no matching {@code PHA} anywhere in range must decline rather than
	 *  guess what is really under it. */
	@Test
	public void unbalancedPlaWithNoMatchingPhaIsUnknown() throws Exception {
		builder.setBytes("0x8000", "a9 ff", true); // LDA #$FF   -- irrelevant clobber
		builder.setBytes("0x8002", "68", true); // PLA        -- no PHA anywhere before it
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8003"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 11. A mechanism write between the PHA and the PLA
	// ------------------------------------------------------------------

	/**
	 * A mechanism write sitting between the {@code PHA} and the {@code PLA} must abandon the
	 * pairing, not just be stepped over. This is deliberately built with a MIRROR LOAD
	 * ({@code LDA $10}, resolved via {@link StoredValueScanner.Hooks#resolveLoad} against
	 * {@code inStateAtStore}) rather than an immediate: an immediate's value does not depend on
	 * {@code inStateAtStore} at all, so a test built on one would pass whether or not the
	 * mechanism-write check exists and would not actually catch a regression.
	 * <p>
	 * Without the check, {@code findMatchingPush} would step straight over {@code STA $9000} and
	 * pair the {@code PLA} to the {@code PHA} at {@code 0x8002}, and the outer walk would then
	 * resume resolving from before it, straight into {@code LDA $10} -- which this fixture's hook
	 * answers from {@code inStateAtStore}, the state at the FINAL store ({@code 0x8007}), i.e.
	 * AFTER the mechanism write. That would attribute a pre-write read the post-write bank: a
	 * confident WRONG value, not a missing one. With the check, the mechanism write is seen while
	 * searching backward from the {@code PLA} and the pairing abandons before ever reaching the
	 * {@code LDA}, so the result is unknown rather than the wrong bank.
	 */
	@Test
	public void mechanismWriteBetweenPushAndPullAbandonsThePairing() throws Exception {
		builder.setBytes("0x8000", "a5 10", true); // LDA $10    -- mirror load, resolved via hooks
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "8d 00 90", true); // STA $9000  -- the mechanism write
		builder.setBytes("0x8006", "68", true); // PLA
		builder.setBytes("0x8007", "8d 10 80", true); // STA $8010  -- the store being resolved

		Address mechanismWriteAt = builder.addr("0x8003");
		Address mirrorCell = builder.addr("0x10");
		StoredValueScanner.Hooks hooks = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return instr.getMinAddress().equals(mechanismWriteAt);
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return resolvedTarget != null && resolvedTarget.equals(mirrorCell) ? inStateAtStore
						: null;
			}
		};

		BankState result = StoredValueScanner.resolveStoredValue(program,
			instructionAt("0x8007"), 'A', BankState.fullyKnown(0xFF, 0x42), 0xFF, hooks);

		assertEquals("a mechanism write between the PHA and the PLA must abandon the pairing -- "
			+ "otherwise the mirror load resolves against inStateAtStore, the state AFTER this "
			+ "mechanism write, attributing a pre-write read the post-write bank", 0,
			result.knownMask());
	}
}
