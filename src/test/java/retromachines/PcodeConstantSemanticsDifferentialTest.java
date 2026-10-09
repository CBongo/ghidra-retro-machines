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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.BoardBankAnalyzer.ConstantSemanticsMode;
import retromachines.ConstantSemantics.Loc;

/**
 * Differential test for bead grm-4wqd: runs {@link Mos6502ConstantSemantics} (TABLE) and
 * {@link PcodeConstantSemantics} (PCODE) over the same fixtures and asserts they agree, with
 * every EXPECTED difference an explicit, separately named and commented test rather than a
 * silent exclusion.
 * <p>
 * <b>Almost all of the replay methods below (mirroring every case in
 * {@code ConstantSemanticsProgramTest} and {@code AdcCarryConstantValueProgramTest}) assert
 * AGREEMENT.</b> That is mostly a real finding, not an oversight: those fixtures use
 * {@code 6502:LE:16:default} (the STOCK Ghidra language, which never reads {@code D}), and most
 * either decline under both evaluators for the same structural reason (an unresolved operand, a
 * control-flow join, a call) or ask only for a register that grm-o9k's carry-drop alone would
 * not move. TWO fixtures turned out to genuinely diverge once actually run both ways --
 * {@code sbcBorrowOutFeedsTheNextAdc} and {@code composesWithTheStackRelativeReload} from
 * {@code AdcCarryConstantValueProgramTest} -- and are deliberately NOT replayed under that name
 * here; each has its own {@code expectedDifference*} method below instead, discovered (not
 * predicted) while writing this suite. Every genuine difference, predicted or discovered, lives
 * in an {@code expectedDifference*} (or, for one case that turned out to AGREE despite looking
 * like it should not, {@code agreeingLax*}) method, each constructed specifically to land on it.
 */
public class PcodeConstantSemanticsDifferentialTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	private void build(String languageId) throws Exception {
		builder = new ProgramBuilder("Test", languageId);
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

	/** Sets the {@code Constant Evaluator} option directly (no {@code AutoAnalysisManager} runs
	 * under a plain {@link ProgramBuilder} fixture) -- under BOTH analyzer names, since a test
	 * program carries neither loader's marker and either sub-{@link Options} would do. */
	private void setMode(ConstantSemanticsMode mode) {
		int tx = program.startTransaction("set constant evaluator mode");
		try {
			ghidra.framework.options.Options analysisOptions =
				program.getOptions(Program.ANALYSIS_PROPERTIES);
			analysisOptions.getOptions(NesBankingAnalyzer.NAME)
					.setEnum(BoardBankAnalyzer.CONSTANT_SEMANTICS_OPTION, mode);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/** Hooks that resolve no load -- same shape as every other test file's NO_HOOKS. */
	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore) {
			return null;
		}
	};

	/** Hooks that answer a load of {@code $9000} with {@code $3C}. */
	private static final StoredValueScanner.Hooks ROM_9000 = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore) {
			return resolvedTarget != null && resolvedTarget.getOffset() == 0x9000
					? PartialByte.fullyKnown(0x3C)
					: null;
		}
	};

	/** Hooks that answer a load of {@code $0010} with {@code $7A} (for the {@code LAX} case). */
	private static final StoredValueScanner.Hooks ROM_0010 = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore) {
			return resolvedTarget != null && resolvedTarget.getOffset() == 0x0010
					? PartialByte.fullyKnown(0x7A)
					: null;
		}
	};

	private Integer valueOfRegister(String address, char reg, StoredValueScanner.Hooks hooks,
			ConstantSemanticsMode mode) {
		setMode(mode);
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return StoredValueScanner.constantRegisterValue(program, instr, reg, hooks,
			RegisterEnv.NONE, new StoredValueScanner.Budget(64));
	}

	private Integer valueOfLoc(String address, Loc loc, StoredValueScanner.Hooks hooks,
			ConstantSemanticsMode mode) {
		setMode(mode);
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return StoredValueScanner.constantLocValue(program, instr, loc, hooks, RegisterEnv.NONE,
			new StoredValueScanner.Budget(64));
	}

	private void assertAgreeRegister(String address, char reg, StoredValueScanner.Hooks hooks) {
		Integer table = valueOfRegister(address, reg, hooks, ConstantSemanticsMode.TABLE);
		Integer pcode = valueOfRegister(address, reg, hooks, ConstantSemanticsMode.PCODE);
		assertEquals("TABLE vs PCODE for register " + reg + " at " + address, table, pcode);
	}

	// ------------------------------------------------------------------
	// Replay of ConstantSemanticsProgramTest -- all agree.
	// ------------------------------------------------------------------

	@Test
	public void secSbcSubtracts() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 10", true);
		builder.setBytes("0x8002", "38", true);
		builder.setBytes("0x8003", "e9 03", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	@Test
	public void clcSbcBorrows() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 10", true);
		builder.setBytes("0x8002", "18", true);
		builder.setBytes("0x8003", "e9 03", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	// sbcBorrowOutFeedsTheNextAdc is NOT replayed here -- it is
	// expectedDifferenceSbcBorrowFlagBug below, a genuine divergence discovered while writing
	// this suite (see that test's javadoc).

	@Test
	public void rolRotatesTheCarryIn() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 40", true);
		builder.setBytes("0x8002", "38", true);
		builder.setBytes("0x8003", "2a", true);
		builder.setBytes("0x8004", "8d 01 80", true);
		assertAgreeRegister("0x8004", 'A', NO_HOOKS);
	}

	@Test
	public void rorRotatesTheShiftedOutBitIn() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 03", true);
		builder.setBytes("0x8002", "4a", true);
		builder.setBytes("0x8003", "6a", true);
		builder.setBytes("0x8004", "8d 01 80", true);
		assertAgreeRegister("0x8004", 'A', NO_HOOKS);
	}

	@Test
	public void rolWithUnknownCarryDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 40", true);
		builder.setBytes("0x8002", "2a", true);
		builder.setBytes("0x8003", "8d 01 80", true);
		assertAgreeRegister("0x8003", 'A', NO_HOOKS);
	}

	@Test
	public void andOverResolvedMemoryFolds() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 f0", true);
		builder.setBytes("0x8002", "2d 00 90", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', ROM_9000);
	}

	@Test
	public void andOverUnresolvedMemoryDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 f0", true);
		builder.setBytes("0x8002", "2d 00 90", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	@Test
	public void compareOverResolvedMemoryDecidesTheCarry() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a2 3c", true);
		builder.setBytes("0x8002", "a9 00", true);
		builder.setBytes("0x8004", "ec 00 90", true);
		builder.setBytes("0x8007", "69 00", true);
		builder.setBytes("0x8009", "8d 01 80", true);
		assertAgreeRegister("0x8009", 'A', ROM_9000);
	}

	/** {@code LAX} with {@code NO_HOOKS}: both decline (TABLE has no case for it; PCODE's
	 * {@code LOAD} resolves to {@link ConstantSemantics.Inputs#memoryOperand}, but LAX's
	 * addressing structurally defeats {@code effectiveTarget()} regardless of hooks -- see
	 * {@link #agreeingLaxDespiteAResolvingHook}, which pins that this is not a hooks question). */
	@Test
	public void undocumentedWriterIsNotSteppedOver() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "a2 05", true);
		builder.setBytes("0x8002", "a7 10", true);
		builder.setBytes("0x8004", "8e 01 80", true);
		assertAgreeRegister("0x8004", 'X', NO_HOOKS);
	}

	// ------------------------------------------------------------------
	// Replay of AdcCarryConstantValueProgramTest -- all agree.
	// ------------------------------------------------------------------

	@Test
	public void clcAdcAfterShiftResolvesExactly() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "0a", true);
		builder.setBytes("0x8003", "18", true);
		builder.setBytes("0x8004", "69 01", true);
		builder.setBytes("0x8006", "8d 01 80", true);
		assertAgreeRegister("0x8006", 'A', NO_HOOKS);
	}

	@Test
	public void secAdcAddsTheCarryBit() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "38", true);
		builder.setBytes("0x8003", "69 01", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	@Test
	public void resultWrapsToEightBits() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 ff", true);
		builder.setBytes("0x8002", "18", true);
		builder.setBytes("0x8003", "69 02", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	@Test
	public void adcWithNoCarryEstablishedDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "69 01", true);
		builder.setBytes("0x8004", "8d 01 80", true);
		assertAgreeRegister("0x8004", 'A', NO_HOOKS);
	}

	@Test
	public void carryWriterBetweenClcAndAdcDecidesTheCarry() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "18", true);
		builder.setBytes("0x8001", "a9 05", true);
		builder.setBytes("0x8003", "0a", true);
		builder.setBytes("0x8004", "69 01", true);
		builder.setBytes("0x8006", "8d 01 80", true);
		assertAgreeRegister("0x8006", 'A', NO_HOOKS);
	}

	@Test
	public void shiftedOutCarryIsAddedIn() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "18", true);
		builder.setBytes("0x8001", "a9 85", true);
		builder.setBytes("0x8003", "0a", true);
		builder.setBytes("0x8004", "69 01", true);
		builder.setBytes("0x8006", "8d 01 80", true);
		assertAgreeRegister("0x8006", 'A', NO_HOOKS);
	}

	@Test
	public void comparisonBetweenClcAndAdcDecidesTheCarry() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "18", true);
		builder.setBytes("0x8003", "c9 03", true);
		builder.setBytes("0x8005", "69 01", true);
		builder.setBytes("0x8007", "8d 01 80", true);
		assertAgreeRegister("0x8007", 'A', NO_HOOKS);
	}

	@Test
	public void failedComparisonClearsTheCarry() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 02", true);
		builder.setBytes("0x8002", "38", true);
		builder.setBytes("0x8003", "c9 03", true);
		builder.setBytes("0x8005", "69 01", true);
		builder.setBytes("0x8007", "8d 01 80", true);
		assertAgreeRegister("0x8007", 'A', NO_HOOKS);
	}

	@Test
	public void comparisonOfUnknownRegisterDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "18", true);
		builder.setBytes("0x8003", "e0 03", true);
		builder.setBytes("0x8005", "69 01", true);
		builder.setBytes("0x8007", "8d 01 80", true);
		assertAgreeRegister("0x8007", 'A', NO_HOOKS);
	}

	@Test
	public void nonImmediateAdcOverUnknownMemoryDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "18", true);
		builder.setBytes("0x8003", "65 10", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	@Test
	public void joinBetweenClcAndAdcDeclines() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 05", true);
		builder.setBytes("0x8002", "18", true);
		builder.setBytes("0x8003", "69 01", true);
		builder.setBytes("0x8005", "8d 01 80", true);
		builder.setBytes("0x9000", "4c 03 80", true);
		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
	}

	/**
	 * River City Ransom-style stack-relative reload ({@code PHA / TXA / PHA / TSX / LDA
	 * $0102,X}, grm-4bgh.1) -- the origin of this idiom (bead grm-4wqd increment 2's
	 * diagnosis of a real-ROM PCODE regression on {@code rcransom}, whose {@code FUN_fed1}
	 * is exactly this shape). Agrees, not diverges: PCODE's operand-read rule declines a
	 * memory read ONLY on a PROVEN address disagreement, never merely because its own
	 * address computation (here, needing {@code X} from an unmodeled {@code TSX}) failed to
	 * resolve -- so it still reaches {@link ConstantSemantics.Inputs#memoryOperand}
	 * unconditionally here, exactly as {@link Mos6502ConstantSemantics#operand} always does,
	 * and {@code memoryOperand}'s own stack-relative-reload last resort (which needs no
	 * address at all) resolves it for both. An earlier version of this evaluator required an
	 * independently-confirmed address match before trusting the hook at all, which made this
	 * decline under PCODE only -- see {@code PcodeConstantSemantics}'s class javadoc for the
	 * current rule.
	 */
	@Test
	public void composesWithTheStackRelativeReload() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 2a", true);
		builder.setBytes("0x8002", "48", true);
		builder.setBytes("0x8003", "8a", true);
		builder.setBytes("0x8004", "48", true);
		builder.setBytes("0x8005", "ba", true);
		builder.setBytes("0x8006", "bd 02 01", true);
		builder.setBytes("0x8009", "0a", true);
		builder.setBytes("0x800a", "18", true);
		builder.setBytes("0x800b", "69 01", true);
		builder.setBytes("0x800d", "8d 01 80", true);
		assertAgreeRegister("0x800d", 'A', NO_HOOKS);
	}

	// ------------------------------------------------------------------
	// Expected differences -- named, commented, and asserted as such.
	// ------------------------------------------------------------------

	/**
	 * grm-o9k: stock {@code 6502:LE:16:default}'s {@code ADC} computes {@code C = carry(A, op1)}
	 * BEFORE adding the carry-in, so a carry that arises SOLELY from the carry-in ({@code A +
	 * op1} does not overflow a byte, but {@code A + op1 + carry-in} does) is dropped. {@code A =
	 * $FF}, {@code op1 = $00}, carry-in {@code = 1}: the real/TABLE answer is carry-out
	 * {@code 1} ({@code $FF+0+1 = $100}); PCODE, interpreting the language's own (buggy) p-code
	 * literally, answers {@code 0} ({@code carry($FF, $00)} alone does not overflow). This is
	 * the known blocker recorded in {@link PcodeConstantSemantics}'s class javadoc, not a bug in
	 * this evaluator -- it is doing exactly what design (b) promises: following the language.
	 */
	@Test
	public void expectedDifferenceGrm09kCarryFromCarryInAlone() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 ff", true); // LDA #$FF
		builder.setBytes("0x8002", "38", true); // SEC          -- carry-in = 1
		builder.setBytes("0x8003", "69 00", true); // ADC #$00
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		Integer table = valueOfLoc("0x8005", Loc.C, NO_HOOKS, ConstantSemanticsMode.TABLE);
		Integer pcode = valueOfLoc("0x8005", Loc.C, NO_HOOKS, ConstantSemanticsMode.PCODE);
		assertEquals("TABLE: correct carry-out", Integer.valueOf(1), table);
		assertEquals("PCODE: stock language's carry(A,op1) alone, dropping the carry-in", Integer.valueOf(0),
			pcode);
	}

	/**
	 * The bundled {@code 6502:LE:16:undoc} language's {@code adcNmos} branches on {@code D}
	 * (bead grm-hzv8). With {@code SED} in the window PCODE follows the language into its
	 * decimal-mode arithmetic ({@code $15 + $27} in BCD {@code = $42}); TABLE assumes binary
	 * unconditionally regardless of {@code D} ({@code $15 + $27 = $3C}). Owner ruling 2026-09-26
	 * (grm-4wqd) made PCODE assume {@code D = 0} only when the walk cannot ESTABLISH it -- a
	 * {@code SED} the walk finds still wins, which is exactly what this pins.
	 */
	@Test
	public void expectedDifferenceSedInWindowMakesPcodeDecimal() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "f8", true); // SED
		builder.setBytes("0x8001", "a9 15", true); // LDA #$15
		builder.setBytes("0x8003", "18", true); // CLC
		builder.setBytes("0x8004", "69 27", true); // ADC #$27
		builder.setBytes("0x8006", "8d 01 80", true); // STA $8001

		Integer table = valueOfRegister("0x8006", 'A', NO_HOOKS, ConstantSemanticsMode.TABLE);
		Integer pcode = valueOfRegister("0x8006", 'A', NO_HOOKS, ConstantSemanticsMode.PCODE);
		assertEquals("TABLE: binary-mode assumption, ignores D entirely", Integer.valueOf(0x3C), table);
		assertEquals("PCODE: SED established D=1, so the language's decimal path runs",
			Integer.valueOf(0x42), pcode);
	}

	/**
	 * Same shape with NO {@code SED}/{@code CLD} anywhere in the window: the walk cannot
	 * establish {@code D}, so PCODE falls back to the assumed value (binary, {@code 0} --
	 * {@link PcodeConstantSemantics}'s {@code assumedDecimalFlag}) and AGREES with TABLE. This
	 * is the owner-ruling case that made most of the bundled-language "D not established"
	 * decline disappear.
	 */
	@Test
	public void unestablishedDAgreesAsBinary() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "a9 15", true); // LDA #$15
		builder.setBytes("0x8002", "18", true); // CLC
		builder.setBytes("0x8003", "69 27", true); // ADC #$27
		builder.setBytes("0x8005", "8d 01 80", true); // STA $8001

		assertAgreeRegister("0x8005", 'A', NO_HOOKS);
		// And it is specifically the binary answer, not a decline, on both sides:
		assertEquals(Integer.valueOf(0x3C),
			valueOfRegister("0x8005", 'A', NO_HOOKS, ConstantSemanticsMode.PCODE));
	}

	/**
	 * {@code LAX $10}, with a hook that WOULD resolve a load of {@code $0010} if ever asked:
	 * TABLE declines (no {@code LAX} case), and PCODE ALSO declines -- agreeing, but not for a
	 * PCODE-specific reason. {@code LAX} hand-rolls its own zero-page/absolute addressing
	 * instead of routing through the {@code OP1}/{@code OP2} addressing subtables the rest of
	 * the instruction set shares, so {@code instr.getOpObjects(0)} never yields an
	 * {@code Address} and {@link StoredValueScanner#plainAbsoluteTarget} -- and so
	 * {@link StoredValueScanner#effectiveOperandTarget}, which
	 * {@link ConstantSemantics.Inputs#effectiveTarget} calls through the real walk -- always
	 * declines for it. {@code WalkInputs.memoryOperand()} (the ONE implementation of
	 * {@link ConstantSemantics.Inputs#memoryOperand} either evaluator ever calls) uses that
	 * SAME {@code effectiveTarget()} to decide what address to hand the hook in the first
	 * place, and hands it {@code null} here -- so {@code ROM_0010}'s own check
	 * ({@code resolvedTarget != null && ...}) never even gets asked about {@code $10}, for
	 * TABLE exactly as much as for PCODE. Nothing about which {@link ConstantSemantics} answers
	 * the query changes that: the gap is entirely inside the shared {@code memoryOperand()}
	 * implementation, one level below either evaluator.
	 * {@code PcodeConstantSemanticsProgramTest.undocumentedOpcodeEvaluatesViaPcode} proves the
	 * INTERPRETER itself resolves {@code LAX} fine when handed a working
	 * {@code effectiveTarget()} directly (bypassing the real walk's {@code plainAbsoluteTarget}
	 * limitation) -- confirming the gap is there, not in this evaluator's own {@code LOAD}
	 * handling (which, as of the operand-read rule described in {@code PcodeConstantSemantics}'s
	 * class javadoc, no longer requires an independently-confirmed address before trusting
	 * {@code memoryOperand} at all).
	 */
	@Test
	public void agreeingLaxDespiteAResolvingHook() throws Exception {
		build("6502:LE:16:undoc");
		builder.setBytes("0x8000", "a7 10", true); // LAX $10
		builder.setBytes("0x8002", "8e 01 80", true); // STX $8001

		Integer table = valueOfRegister("0x8002", 'X', ROM_0010, ConstantSemanticsMode.TABLE);
		Integer pcode = valueOfRegister("0x8002", 'X', ROM_0010, ConstantSemanticsMode.PCODE);
		assertNull("TABLE has no LAX case", table);
		assertNull("PCODE's LOAD never matches effectiveTarget for LAX's addressing", pcode);
	}

	/**
	 * grm-4wqd (rediscovered writing this suite; ALREADY KNOWN as grm-ef46 defect (2), fixed
	 * in the bundled {@code 6502core.sinc} and in upstream PR NationalSecurityAgency/ghidra#9656,
	 * see grm-2g7g): stock
	 * {@code 6502:LE:16:default}'s {@code SBC}'s {@code subtraction_flags1} computes the carry
	 * (NOT-borrow) flag via a bit-7 trick over the ALREADY-TRUNCATED byte {@code result}, and
	 * that trick comes out wrong on at least this input. {@code A=$01, SBC #$02} with carry-in
	 * 1 (i.e. no incoming borrow): the real/TABLE answer is a borrow OUT (carry {@code = 0}),
	 * since {@code 1 < 2}; PCODE, interpreting the stock language's p-code literally, computes
	 * carry {@code = 1} (WRONG -- verified by hand against the trick's own bit formula). The
	 * next {@code ADC #$05} then adds that wrong carry-in, so the final {@code A} differs:
	 * TABLE {@code $FF+5+0=$04}, PCODE {@code $FF+5+1=$05}. The trick is the textbook
	 * borrow-out, so the polarity is simply inverted (C is not-borrow on the 6502). It is a
	 * different defect from grm-o9k's {@code ADC} carry-in drop, and the same class of blocker: PCODE inherits whatever the target language's own p-code gets
	 * wrong, which is the tradeoff design (b) makes explicit.
	 */
	@Test
	public void expectedDifferenceSbcBorrowFlagBug() throws Exception {
		build("6502:LE:16:default");
		builder.setBytes("0x8000", "a9 01", true); // LDA #$01
		builder.setBytes("0x8002", "38", true); // SEC        -- carry-in = 1, no incoming borrow
		builder.setBytes("0x8003", "e9 02", true); // SBC #$02   -- $01 - $02 borrows: real C = 0
		builder.setBytes("0x8005", "69 05", true); // ADC #$05
		builder.setBytes("0x8007", "8d 01 80", true); // STA $8001

		Integer table = valueOfRegister("0x8007", 'A', NO_HOOKS, ConstantSemanticsMode.TABLE);
		Integer pcode = valueOfRegister("0x8007", 'A', NO_HOOKS, ConstantSemanticsMode.PCODE);
		assertEquals("TABLE: correct borrow-out", Integer.valueOf(0x04), table);
		assertEquals("PCODE: stock subtraction_flags1's bit-trick gets carry wrong here",
			Integer.valueOf(0x05), pcode);
	}

}
