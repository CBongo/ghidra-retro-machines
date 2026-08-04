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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

/**
 * Pins {@link BoardBankAnalyzer#argumentSurvivesPrologue} (grm-mu7): whether a value the caller
 * left in the helper's argument register is still that register's content when the helper's
 * first switch site consumes it.
 * <p>
 * The hazard is structural, not exotic. {@code findHelpers} can only learn a helper's argument
 * register from the register its mechanism write STORES, so a helper that reloads the bank from
 * a RAM shadow -- Bionic Commando's {@code FUN_dca8}:
 * <pre>
 *   $DCA8  LDA $65      ; the bank really comes from RAM
 *   $DCAA  STA $E000    ; ...but argReg='A' is recorded HERE
 * </pre>
 * looks identical, from the store alone, to one that takes its bank in A. Called as
 * {@code LDA #$09 / JSR $DCA8} the engine would report bank 9 for a helper that never reads A,
 * and a wrong bank is worse here than no bank.
 * <p>
 * These tests stay at the predicate level: it is a pure function of
 * {@code (program, entry, firstSite, reg)} -- no analyzer state, no board descriptor, no helper
 * map -- which is what lets them run in the fast JUnit tier. The analyzer-level consequence
 * (call site 8 of {@code nesmmc1test}, criterion M14) is pinned by the headless fixture, whose
 * A/B pair with call site 6 is what proves the decline comes from this check rather than from a
 * failed caller-side scan.
 */
public class HelperPrologueProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		// The save/restore tests park the argument in RAM, and the "was this cell overwritten"
		// half of that model reads Ghidra's write REFERENCES -- which only exist for an operand
		// that names real memory. Without a RAM block those stores reference nothing, every cell
		// looks permanently untouched, and the overwrite tests would pass for the wrong reason.
		builder.createMemory("RAM", "0x0000", 0x800);
		program = builder.getProgram();
	}

	/** The predicate over a helper entered at {@code entry} whose first site is {@code first}. */
	private boolean survives(String entry, String first, char reg) {
		return BoardBankAnalyzer.argumentSurvivesPrologue(program, builder.addr(entry),
			first == null ? null : builder.addr(first), reg);
	}

	// ------------------------------------------------------------------
	// The argument survives
	// ------------------------------------------------------------------

	/**
	 * The overwhelmingly common shape: the helper IS the chain, so there is no prologue at all
	 * and the walk covers an empty range. Every Zelda1/FF1/Metroid-style {@code SwitchBank} is
	 * this, and it must stay resolvable -- the guard exists to lose nothing here.
	 */
	@Test
	public void aHelperWithNoPrologueKeepsItsArgument() throws Exception {
		builder.setBytes("0x9000", "8d 00 e0", true); // STA $E000  <- entry == first site

		assertTrue(survives("0x9000", "0x9000", 'A'));
	}

	/**
	 * <b>The bound is the FIRST site, not the last.</b> A serial-shift chain clobbers A four
	 * times between its first store and its commit ({@code STA/LSR A/STA/...}) entirely by
	 * design -- the mechanism consumes the argument at the first write and shifts what is left.
	 * Walking to {@code switchSite} instead would decline every serial-shift helper there is,
	 * which would "fix" the bug by deleting the feature.
	 */
	@Test
	public void clobbersAfterTheFirstSiteAreTheMechanismsOwnBusiness() throws Exception {
		builder.setBytes("0x9000", "8d 00 e0", true); // STA $E000  <- first site
		builder.setBytes("0x9003", "4a", true); // LSR A     -- writes A, and must not matter
		builder.setBytes("0x9004", "8d 00 e0", true); // STA $E000  -- switchSite, later

		assertTrue(survives("0x9000", "0x9000", 'A'));
	}

	/** A prologue that touches other registers says nothing about the argument's register. */
	@Test
	public void aPrologueWritingADifferentRegisterIsHarmless() throws Exception {
		builder.setBytes("0x9000", "a2 00", true); // LDX #$00
		builder.setBytes("0x9002", "78", true); // SEI
		builder.setBytes("0x9003", "8d 00 e0", true); // STA $E000  <- first site

		assertTrue(survives("0x9000", "0x9003", 'A'));
		// ...and the mirror: the same prologue is fatal to an X-argument helper.
		assertFalse(survives("0x9000", "0x9003", 'X'));
	}

	/**
	 * Bionic Commando's second convention, and the reason this keys on {@code entry} rather
	 * than the function's entry point. {@code FUN_dca8} has two argument conventions: enter at
	 * the top and the bank comes from {@code $65}; enter at {@code $DCAA} -- which its jump
	 * table really does -- and the {@code LDA} is skipped, so the bank IS in A. One function,
	 * two answers, told apart by nothing but the address control arrived at.
	 */
	@Test
	public void aMidBodyEntryPastTheClobberKeepsItsArgument() throws Exception {
		builder.setBytes("0x9000", "a5 65", true); // LDA $65    -- skipped by this entry
		builder.setBytes("0x9002", "8d 00 e0", true); // STA $E000  <- entry AND first site

		assertTrue(survives("0x9002", "0x9002", 'A'));
		// The same body entered at the top is the hazard case, immediately below.
		assertFalse(survives("0x9000", "0x9002", 'A'));
	}

	// ------------------------------------------------------------------
	// Save and restore: a clobber is not a loss when the prologue saved first
	// ------------------------------------------------------------------

	/**
	 * <b>Castlevania 2's {@code FUN_c187}, byte-exact, and the case that proves the whole
	 * save/restore model necessary.</b> The first version of this guard tested only "does
	 * anything write the register", declined here, and destroyed three real ROMs — Kid Icarus
	 * lost all 215 of its overlay instructions, Dodgeball all 10692, Castlevania 2 both of its
	 * bank comments — while all 45 synthetic goldens passed, because none of them saves and
	 * restores. The argument survives perfectly well; it just spends the middle of the prologue
	 * on the stack.
	 */
	@Test
	public void anArgumentSavedAndRestoredAcrossTheStackSurvives() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA        -- save the argument
		builder.setBytes("0x9001", "a9 01", true); // LDA #$01   -- the naive test declined HERE
		builder.setBytes("0x9003", "8d 03 01", true); // STA $0103
		builder.setBytes("0x9006", "68", true); // PLA        -- and this puts it back
		builder.setBytes("0x9007", "8d 00 e0", true); // STA $E000  <- first site

		assertTrue(survives("0x9000", "0x9007", 'A'));
	}

	/**
	 * The depth has to be right, not just the pairing: a status push between the {@code PHA} and
	 * the {@code PLA} would make a naive "pop whatever" model return the flags byte as if it were
	 * the bank. {@code PHP}/{@code PLP} are modelled for exactly this reason.
	 */
	@Test
	public void anInterleavedStatusPushKeepsTheStackDepthHonest() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "08", true); // PHP
		builder.setBytes("0x9002", "a9 01", true); // LDA #$01
		builder.setBytes("0x9004", "28", true); // PLP
		builder.setBytes("0x9005", "68", true); // PLA  -- must pop the argument, not the flags
		builder.setBytes("0x9006", "8d 00 e0", true); // STA $E000  <- first site

		assertTrue(survives("0x9000", "0x9006", 'A'));
	}

	/**
	 * <b>Double Dribble's {@code FUN_ff08}</b>, the memory half of the same idiom: the argument
	 * comes back off the stack, is immediately parked in RAM because A is needed for an unrelated
	 * shadow, and is reloaded just before the chain. A stack-only model still declines this one.
	 */
	@Test
	public void anArgumentParkedInMemoryAndReloadedSurvives() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "a5 ff", true); // LDA $ff     -- A reused
		builder.setBytes("0x9003", "68", true); // PLA         -- argument back
		builder.setBytes("0x9004", "8d 03 01", true); // STA $0103   -- parked in memory
		builder.setBytes("0x9007", "a5 ff", true); // LDA $ff     -- A reused again
		builder.setBytes("0x9009", "85 ff", true); // STA $ff
		builder.setBytes("0x900b", "ad 03 01", true); // LDA $0103   -- reloaded HERE
		builder.setBytes("0x900e", "8d 00 e0", true); // STA $E000   <- first site

		assertTrue(survives("0x9000", "0x900e", 'A'));
	}

	/**
	 * The cell has to still hold the argument. Here something else overwrites {@code $0103}
	 * between the park and the reload, so the reload brings back the wrong byte.
	 */
	@Test
	public void aCellOverwrittenBeforeTheReloadIsNoLongerTheArgument() throws Exception {
		builder.setBytes("0x9000", "8d 03 01", true); // STA $0103  -- park the argument
		builder.setBytes("0x9003", "a9 07", true); // LDA #$07
		builder.setBytes("0x9005", "8d 03 01", true); // STA $0103  -- ...overwritten
		builder.setBytes("0x9008", "ad 03 01", true); // LDA $0103  -- reloads a 7, not the bank
		builder.setBytes("0x900b", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x900b", 'A'));
	}

	/**
	 * A load from a cell the argument was never stored to is an ordinary clobber -- this is
	 * Bionic Commando's {@code LDA $65}, the shape the whole guard exists for, and it must keep
	 * declining now that loads can also be restores.
	 */
	@Test
	public void aLoadFromAnUnrelatedCellIsStillAClobber() throws Exception {
		builder.setBytes("0x9000", "8d 03 01", true); // STA $0103  -- park the argument
		builder.setBytes("0x9003", "a5 65", true); // LDA $65    -- ...but read a DIFFERENT cell
		builder.setBytes("0x9005", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9005", 'A'));
	}

	/** A save with no matching restore is just a clobber with extra steps. */
	@Test
	public void aPushWithoutAMatchingPullDoesNotRestore() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "a9 01", true); // LDA #$01
		builder.setBytes("0x9003", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9003", 'A'));
	}

	/**
	 * A pull this walk never watched being pushed takes its byte from the caller's frame, not
	 * from a save, so it is an ordinary clobber.
	 */
	@Test
	public void aPullWithoutAPushIsAnOrdinaryClobber() throws Exception {
		builder.setBytes("0x9000", "68", true); // PLA
		builder.setBytes("0x9001", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9001", 'A'));
	}

	/**
	 * The soundness limit, asserted rather than assumed. The clobber half of the walk errs safe
	 * under the linear-order approximation, but "restored" is a claim that points the UNSAFE way
	 * if a branch could skip the {@code PLA} — so any non-fall-through flow abandons the shadow
	 * stack and the {@code PLA} degrades to an ordinary clobber.
	 */
	@Test
	public void aBranchInTheRangeAbandonsTheSaveRestoreModel() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "a9 01", true); // LDA #$01
		builder.setBytes("0x9003", "d0 00", true); // BNE $9005  -- the walk is no longer a path
		builder.setBytes("0x9005", "68", true); // PLA
		builder.setBytes("0x9006", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9006", 'A'));
	}

	/**
	 * Anything that moves the stack pointer outside the modelled pushes desynchronises the depth,
	 * so a later {@code PLA} would pop the wrong byte. Abandon the model rather than guess.
	 */
	@Test
	public void aStackPointerWriteAbandonsTheSaveRestoreModel() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "a9 01", true); // LDA #$01
		builder.setBytes("0x9003", "9a", true); // TXS  -- stack pointer moved out from under us
		builder.setBytes("0x9004", "68", true); // PLA
		builder.setBytes("0x9005", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9005", 'A'));
	}

	// ------------------------------------------------------------------
	// The argument does not survive
	// ------------------------------------------------------------------

	/** The bead's case, byte for byte: the bank arrives from RAM and the caller's A is stale. */
	@Test
	public void aPrologueLoadFromRamClobbersTheArgument() throws Exception {
		builder.setBytes("0x9000", "a5 65", true); // LDA $65
		builder.setBytes("0x9002", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9002", 'A'));
	}

	/**
	 * A transfer, not a load. The check asks the LANGUAGE what an instruction writes rather
	 * than matching mnemonics, so a register write that arrives by any route is caught --
	 * which also means an undocumented or synthetic opcode cannot slip past it.
	 */
	@Test
	public void aPrologueTransferClobbersTheArgument() throws Exception {
		builder.setBytes("0x9000", "8a", true); // TXA
		builder.setBytes("0x9001", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9001", 'A'));
	}

	/** A callee's register effects are not modeled at all, so a call in the prologue declines. */
	@Test
	public void aCallInThePrologueDeclines() throws Exception {
		builder.setBytes("0x9000", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9003", "8d 00 e0", true); // STA $E000  <- first site
		builder.setBytes("0x9500", "60", true); // RTS

		assertFalse(survives("0x9000", "0x9003", 'A'));
	}

	/**
	 * Undisassembled bytes in the middle of a helper body are bytes whose register effects are
	 * unknown, which is not the same as harmless -- so a walk that cannot reach the first site
	 * through contiguous instructions declines rather than stepping over the hole.
	 */
	@Test
	public void aGapInTheDisassemblyDeclines() throws Exception {
		builder.setBytes("0x9000", "ea", true); // NOP
		// 0x9001 deliberately left undefined -- the gap
		builder.setBytes("0x9002", "8d 00 e0", true); // STA $E000  <- first site

		assertFalse(survives("0x9000", "0x9002", 'A'));
	}

	/**
	 * {@code findHelpers}' multi-mechanism degrade case nulls {@code firstSite}: the model no
	 * longer describes one coherent mechanism, so there is nothing meaningful to walk to.
	 * ({@code recoverCallArgument} short-circuits on the null {@code argReg} that accompanies
	 * it, so this is belt-and-braces -- but it is the answer that stays safe if that ever
	 * changes.)
	 */
	@Test
	public void aMissingFirstSiteDeclines() throws Exception {
		builder.setBytes("0x9000", "8d 00 e0", true); // STA $E000

		assertFalse(survives("0x9000", null, 'A'));
	}

	/** An entry past the first site is not a prologue at all; nothing about it is verifiable. */
	@Test
	public void anEntryAfterTheFirstSiteDeclines() throws Exception {
		builder.setBytes("0x9000", "8d 00 e0", true); // STA $E000  <- first site
		builder.setBytes("0x9003", "60", true); // RTS

		assertFalse(survives("0x9003", "0x9000", 'A'));
	}

	/**
	 * A register name the language does not know cannot be asked about, so the favorable answer
	 * is not assumed.
	 * <p>
	 * {@code 'Q'} rather than some other stand-in letter on purpose: the 6502's status flags are
	 * themselves single-letter registers ({@code N V B D I Z C}), so most letters DO resolve --
	 * a lookup by name is not the "obviously fails for anything unexpected" fallback it looks
	 * like. Nothing can actually reach this branch today, since the argument register only ever
	 * comes from {@code StoredValueScanner.storeRegister}, which answers A/X/Y or nothing; the
	 * branch exists so that if it ever could, it declines instead of throwing.
	 */
	@Test
	public void anUnknownRegisterDeclines() throws Exception {
		builder.setBytes("0x9000", "8d 00 e0", true); // STA $E000

		assertFalse(survives("0x9000", "0x9000", 'Q'));
	}
}
