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
 * Pins {@link StoredValueScanner}'s STACK-RELATIVE RELOAD resolution (bead grm-4bgh.1): a load
 * shaped {@code LD<reg> $01nn,X} following a {@code TSX} reads a byte pushed earlier WITHOUT
 * popping it, which is how 6502 code reads a stack-passed value more than once. River City
 * Ransom's {@code FUN_fed1} is the motivating shape ({@code PHA / TXA / PHA / ... / TSX /
 * LDA $0102,X}), reproduced in {@link #funFed1ShapeResolvesTheFirstPushNotTheSecond}.
 * <p>
 * Fixture note inherited from {@link PushPullValueCarryingProgramTest}: {@link ProgramBuilder}
 * blocks are created read-only, so every RAM block must be made writable explicitly.
 */
public class StackRelativeReloadProgramTest extends AbstractBundledLanguageTest {

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
	// 1. FUN_fed1 shape: the reload must recover the FIRST push, not the second
	// ------------------------------------------------------------------

	/**
	 * {@code LDA #$05 / PHA / TXA / PHA / LDA #$06 / STA $FB / TSX / LDA $0102,X / STA <target>}
	 * -- the two pushes ({@code $05}, then X's value) leave {@code X = S} two deep, so
	 * {@code $0102,X} reads back the SECOND-most-recent push: the {@code $05} pushed at the very
	 * first {@code PHA}, not the {@code $06} loaded afterward and never pushed at all. A wrong
	 * implementation that instead resolved the nearer {@code PHA} (X's value) or the unrelated
	 * {@code LDA #$06} would report something other than 5.
	 */
	@Test
	public void funFed1ShapeResolvesTheFirstPushNotTheSecond() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05   -- the bank argument
		builder.setBytes("0x8002", "48", true); // PHA        -- push 1: the argument
		builder.setBytes("0x8003", "8a", true); // TXA
		builder.setBytes("0x8004", "48", true); // PHA        -- push 2: X
		builder.setBytes("0x8005", "a9 06", true); // LDA #$06   -- unrelated, must NOT be picked up
		builder.setBytes("0x8007", "85 fb", true); // STA $FB
		builder.setBytes("0x8009", "ba", true); // TSX
		builder.setBytes("0x800a", "bd 02 01", true); // LDA $0102,X -- reloads push 1 (the argument)
		builder.setBytes("0x800d", "8d 00 80", true); // STA $8000

		assertBank(5, axromLatch().computeSwitch(program, instructionAt("0x800d"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 2. n == 1: a single push, reloaded via the most recent slot
	// ------------------------------------------------------------------

	/** A single {@code PHA} then {@code TSX / LDA $0101,X} resolves the most recent push. */
	@Test
	public void singlePushReloadedAtDepthOneResolves() throws Exception {
		builder.setBytes("0x8000", "a9 07", true); // LDA #$07
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "a9 ff", true); // LDA #$FF   -- clobber, must not be picked up
		builder.setBytes("0x8005", "ba", true); // TSX
		builder.setBytes("0x8006", "bd 01 01", true); // LDA $0101,X
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000

		assertBank(7, axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 3. Composition across the reload still applies
	// ------------------------------------------------------------------

	/** {@code ... TSX / LDA $0102,X / AND #$03 / STA} -- the AND applied after the reload still
	 *  composes, exactly as it does after a {@code PLA}. */
	@Test
	public void compositionAcrossTheReloadStillApplies() throws Exception {
		builder.setBytes("0x8000", "a9 1f", true); // LDA #$1F   -- pushed argument
		builder.setBytes("0x8002", "48", true); // PHA        -- push 1
		builder.setBytes("0x8003", "8a", true); // TXA
		builder.setBytes("0x8004", "48", true); // PHA        -- push 2
		builder.setBytes("0x8005", "a9 00", true); // LDA #$00   -- clobber
		builder.setBytes("0x8007", "ba", true); // TSX
		builder.setBytes("0x8008", "bd 02 01", true); // LDA $0102,X -- reloads $1F
		builder.setBytes("0x800b", "29 03", true); // AND #$03   -- $1F & $03 = $03
		builder.setBytes("0x800d", "8d 00 80", true); // STA $8000

		assertBank(3, axromLatch().computeSwitch(program, instructionAt("0x800d"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 4. Abandon: a PHA between the TSX and the load
	// ------------------------------------------------------------------

	/** An intervening {@code PHA} between {@code TSX} and the reload could overwrite the exact
	 *  slot being reloaded -- abandon rather than attribute a possibly-stale byte. */
	@Test
	public void phaBetweenTsxAndLoadAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "ba", true); // TSX
		builder.setBytes("0x8004", "a9 aa", true); // LDA #$AA
		builder.setBytes("0x8006", "48", true); // PHA        -- could overwrite $0101,X
		builder.setBytes("0x8007", "bd 01 01", true); // LDA $0101,X
		builder.setBytes("0x800a", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x800a"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 5. Abandon: a PLA between the TSX and the load
	// ------------------------------------------------------------------

	/** Same hazard, the pop half: a {@code PLA} between {@code TSX} and the reload could be
	 *  immediately followed elsewhere by a push landing on the reloaded slot -- and in general a
	 *  {@code PLA}/{@code PHA} pair in this window is exactly the aliasing case the javadoc warns
	 *  about, so it abandons regardless of whether a paired push follows before the load. */
	@Test
	public void plaBetweenTsxAndLoadAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "48", true); // PHA        -- second push, so a pop below balances
		builder.setBytes("0x8004", "ba", true); // TSX
		builder.setBytes("0x8005", "68", true); // PLA        -- intervenes between TSX and the load
		builder.setBytes("0x8006", "bd 01 01", true); // LDA $0101,X
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 6. Abandon: an instruction writing X between the TSX and the load
	// ------------------------------------------------------------------

	/** {@code LDX #$00} between {@code TSX} and the reload changes the index the operand uses,
	 *  so the address the load actually reaches is no longer the one this walk computed. */
	@Test
	public void writeToXBetweenTsxAndLoadAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "ba", true); // TSX
		builder.setBytes("0x8004", "a2 00", true); // LDX #$00   -- clobbers X after TSX set it
		builder.setBytes("0x8006", "bd 01 01", true); // LDA $0101,X
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 7. Abandon: base outside $0101..$01FF
	// ------------------------------------------------------------------

	/** {@code LDA $0202,X} is absolute-indexed by X but its base is not in the stack page at
	 *  all, so this is not the stack-relative-reload idiom. */
	@Test
	public void baseOutsideStackPageAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "ba", true); // TSX
		builder.setBytes("0x8004", "bd 02 02", true); // LDA $0202,X -- not the stack page
		builder.setBytes("0x8007", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8007"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 8. Abandon: index register Y
	// ------------------------------------------------------------------

	/** {@code LDA $0102,Y} -- nothing on 6502 copies {@code S} into Y, so a Y-indexed operand
	 *  into the stack page can never be this idiom regardless of what precedes it. */
	@Test
	public void indexRegisterYAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "8a", true); // TXA
		builder.setBytes("0x8004", "48", true); // PHA
		builder.setBytes("0x8005", "a0 00", true); // LDY #$00
		builder.setBytes("0x8007", "b9 02 01", true); // LDA $0102,Y
		builder.setBytes("0x800a", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x800a"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 9. Abandon: a control-flow join between the TSX and the load
	// ------------------------------------------------------------------

	/** The load itself is also reached by a branch from elsewhere, making it a control-flow join:
	 *  some other path could reach it with a different {@code X}, so the reload must abandon.
	 *  Built so {@code TSX} falls straight through to the load (no intervening jump), which
	 *  keeps this test isolated to the join guard rather than the separate fall-through guard. */
	@Test
	public void controlFlowJoinAtTheLoadAbandons() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "48", true); // PHA
		builder.setBytes("0x8003", "ba", true); // TSX        -- falls straight through to $8004
		builder.setBytes("0x8004", "bd 01 01", true); // LDA $0101,X  -- also a join target below
		builder.setBytes("0x8007", "8d 00 80", true); // STA $8000
		// An unrelated incoming edge into $8004, making it a control-flow join.
		builder.setBytes("0x9000", "4c 04 80", true); // JMP $8004

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8007"),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 10. End-to-end via the raw scanner API, mirroring the bead's exact bytes
	// ------------------------------------------------------------------

	/** Same shape as test 1, run through {@link StoredValueScanner#resolveStoredValue} directly
	 *  (rather than a strategy) so the exact byte sequence from the bead can be pinned literally. */
	@Test
	public void funFed1ShapeViaRawScannerApi() throws Exception {
		builder.setBytes("0xfed1", "48", true); // PHA        -- save the caller's bank argument
		builder.setBytes("0xfed2", "8a", true); // TXA
		builder.setBytes("0xfed3", "48", true); // PHA        -- save X
		builder.setBytes("0xfed4", "a9 06", true); // LDA #$06
		builder.setBytes("0xfed6", "85 fb", true); // STA $FB
		builder.setBytes("0xfed8", "8d 00 80", true); // STA $8000
		builder.setBytes("0xfedb", "ba", true); // TSX        -- X = S
		builder.setBytes("0xfedc", "bd 02 01", true); // LDA $0102,X -- reads the byte pushed at fed1
		builder.setBytes("0xfedf", "8d 10 80", true); // STA $8010

		// Pin what the caller's bank argument was (the value PHA'd at fed1): $2A.
		builder.setBytes("0xfece", "a9 2a", true); // LDA #$2A
		builder.setBytes("0xfed0", "ea", true); // NOP        -- filler so 0xfed1 is a fresh instr

		BankState result = StoredValueScanner.resolveStoredValue(program,
			instructionAt("0xfedf"), 'A', BankState.unknown(), 0xFF, NO_HOOKS);

		assertEquals("tracked bits not fully known: " + result, 0xFF, result.knownMask());
		assertEquals(0x2a, result.bits());
	}
}
