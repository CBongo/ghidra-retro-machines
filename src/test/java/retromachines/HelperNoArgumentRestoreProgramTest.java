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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperDiscovery.HelperModel;
import retromachines.HelperDiscovery.Relay;

/**
 * Pins {@link HelperArgumentRecovery#restoreSourceCell} (bead grm-yflf, the classification half
 * of grm-jqt0's fix (B)): the RECOGNIZER that decides whether a call whose helper takes no
 * inbound argument ({@link HelperArgumentRecovery#argumentDefinitelyClobbered}) is specifically a
 * no-argument RESTORE entry -- one whose entire clobbering span is a single, plain, non-indexed
 * load from a writable RAM cell that reaches the mechanism unmodified -- as opposed to some other
 * reason the caller's argument does not survive (most importantly, a CONSTANT the helper's own
 * body supplies, smb3's {@code LDA #imm} shape).
 * <p>
 * zelda2's {@code FUN_ffc9} ({@code LDA $0769}, falling straight through into the real setter
 * {@code FUN_ffcc}) is the worked case throughout, transcribed at a made-up address since these
 * tests need no board descriptor or real ROM -- see {@code HelperInboundCellProgramTest} and
 * {@code HelperPrologueProgramTest} for the established precedent of pinning this family of
 * predicate at the fast JUnit tier rather than as a headless golden fixture. The real ROM is
 * covered separately by {@code tools/banktest/realrom-test.sh}'s zelda2 row.
 * <p>
 * The class javadoc on {@link BankSwitchStrategy.ValueStop#RESTORED_BANK} and the method javadoc
 * on {@link HelperArgumentRecovery#restoreSourceCell} explain, title by title, why this
 * recognizer's narrowness is exactly what keeps it from firing on FOUR of the other five
 * grm-jqt0 titles (cv2, smb2, smb3, rcransom) without any title-specific gating -- the fifth,
 * bionic, DOES qualify and is the second real customer of this classification, per
 * {@link #zeroPageLoadIsARestore}. A zero-page cell is just as valid a save slot as an absolute
 * one (megaman2's own motivating {@code $29} shadow is zero page); "ABSOLUTE" in the bead's
 * design brief meant a fixed, statically-certain address -- the contrast is with
 * indexed/indirect addressing, not with 6502 instruction ENCODING length. An earlier increment
 * of this recognizer got that wrong and excluded zero page, which was caught by
 * {@code nesmmc1test}'s M13/M14 and {@code neswrappertest}'s W5 (which transcribe bionic's exact
 * shape) failing in the full synthetic gate; those criteria were then corrected to accept the
 * new honest NOTE rather than the recognizer narrowed to dodge them.
 */
public class HelperNoArgumentRestoreProgramTest extends AbstractBundledLanguageTest {

	private static final int FULL_MASK = 0x0F;

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		// Writable, like HelperInboundCellProgramTest's RAM block: ProgramBuilder blocks default
		// to read-only, and the writability test is exactly what distinguishes a genuine save
		// cell from a load of a ROM constant (see aLoadFromNonWritableMemoryDeclines below).
		MemoryBlock ram = builder.createMemory("RAM", "0x0000", 0x800);
		program = builder.getProgram();
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

	private Address addr(long a) {
		return builder.addr(String.format("0x%04x", a));
	}

	/** A pass-through-wrapper-shaped model: {@code function} is the wrapper itself, relay null. */
	private HelperModel wrapperModel(Function f, long entry, long firstSite, char reg) {
		return new HelperModel(f, addr(entry), null, reg, FULL_MASK, 0, null, addr(firstSite),
			addr(firstSite), null);
	}

	// ------------------------------------------------------------------
	// The recognizer itself: HelperArgumentRecovery.restoreSourceCell
	// ------------------------------------------------------------------

	/**
	 * zelda2's {@code FUN_ffc9} shape, byte for byte (Data Crystal: {@code $0769} is "bank to
	 * switch back to after changing banks in the NMI handler"): the ENTIRE clobbering span is one
	 * instruction, a plain absolute load from a writable RAM cell, landing exactly on the switch.
	 * This is the affirmative case the whole feature exists for.
	 */
	@Test
	public void zelda2ShapeRestoreIsRecognized() throws Exception {
		builder.setBytes("0x9000", "ad 10 07", true); // LDA $0710  -- the whole clobbering span
		builder.setBytes("0x9003", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9006", "60", true); // RTS
		Function f = builder.createEmptyFunction("ffc9", "0x9000", 7, null);

		HelperModel model = wrapperModel(f, 0x9000, 0x9003, 'A');

		assertEquals(addr(0x0710), HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/**
	 * <b>The sharpest positive control in this file.</b> Bionic Commando's {@code FUN_dca8}
	 * shape, byte-for-byte ({@code LDA $65 / STA $E000}) -- syntactically IDENTICAL to
	 * {@link #zelda2ShapeRestoreIsRecognized} in every way this recognizer checks (one-instruction
	 * span, unconditional, non-indexed, writable target, landing exactly on the switch). The only
	 * difference from zelda2's cell is that {@code $65} fits the zero page while {@code $0710}/
	 * {@code $0769} do not -- and that difference does NOT matter: a zero-page cell is just as
	 * valid a save slot (megaman2's own motivating {@code $29} shadow is zero page too). An
	 * EARLIER increment of this recognizer excluded zero-page addresses, on a misreading of the
	 * bead's "ABSOLUTE" as an encoding-length claim rather than a fixed-vs-indexed one; that
	 * exclusion was reviewed and reverted (bead grm-yflf), and {@code nesmmc1test}'s M13/M14 and
	 * {@code neswrappertest}'s W5 -- whose fixtures transcribe bionic's {@code FUN_dca8} shape --
	 * were updated to accept the resulting NOTE rather than treated as a boundary to preserve.
	 * This test pins the CORRECT behavior (recognized, not excluded) at the predicate level.
	 */
	@Test
	public void zeroPageLoadIsARestore() throws Exception {
		builder.setBytes("0x9090", "a5 65", true); // LDA $65    -- zero page, still a restore
		builder.setBytes("0x9092", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9095", "60", true); // RTS
		Function f = builder.createEmptyFunction("bionicShape", "0x9090", 6, null);

		HelperModel model = wrapperModel(f, 0x9090, 0x9092, 'A');

		assertEquals(addr(0x0065), HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/**
	 * smb3's shape: the register is redefined from an IMMEDIATE, not a memory read. There is no
	 * cell to name -- a constant the helper's own body supplies is a fundamentally different claim
	 * than a value restored from a save slot the game populated earlier, and must not be reported
	 * as one. {@code argumentReloadSource} already declines an immediate; this pins that the
	 * decline survives all the way to this recognizer.
	 */
	@Test
	public void anImmediateLoadIsAConstantNotARestore() throws Exception {
		builder.setBytes("0x9010", "a9 47", true); // LDA #$47   -- a constant, not a reload
		builder.setBytes("0x9012", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9015", "60", true); // RTS
		Function f = builder.createEmptyFunction("smb3Shape", "0x9010", 6, null);

		HelperModel model = wrapperModel(f, 0x9010, 0x9012, 'A');

		assertNull(HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/** An indexed load has a runtime-dependent target -- no fixed cell exists to name. */
	@Test
	public void anIndexedLoadDeclines() throws Exception {
		builder.setBytes("0x9020", "bd 10 07", true); // LDA $0710,X -- indexed
		builder.setBytes("0x9023", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9026", "60", true); // RTS
		Function f = builder.createEmptyFunction("indexed", "0x9020", 7, null);

		HelperModel model = wrapperModel(f, 0x9020, 0x9023, 'A');

		assertNull(HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/**
	 * A generic negative case for the "nothing between it and the switch" requirement: the load
	 * IS a perfectly good absolute, writable, non-indexed reload, but an instruction sits between
	 * it and the mechanism write. "Nothing between it and the switch" is not merely a convenience
	 * narrowing; it is what makes the relational claim ("unchanged from what was saved there")
	 * provably true rather than merely plausible, so this must decline regardless of what the
	 * intervening instruction does. (None of the six grm-jqt0 titles happen to need this specific
	 * guard today -- rcransom is excluded by the stack-relative guard instead -- but the span
	 * requirement is load-bearing on its own terms, not redundant with that guard, so it is pinned
	 * here directly.)
	 */
	@Test
	public void somethingBetweenTheLoadAndTheSwitchDeclines() throws Exception {
		builder.setBytes("0x9030", "ad 10 07", true); // LDA $0710
		builder.setBytes("0x9033", "ea", true); // NOP        -- something in between
		builder.setBytes("0x9034", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9037", "60", true); // RTS
		Function f = builder.createEmptyFunction("gapBeforeSwitch", "0x9030", 8, null);

		HelperModel model = wrapperModel(f, 0x9030, 0x9034, 'A');

		assertNull(HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/**
	 * A load from NON-WRITABLE memory (the PRG/ROM block, never marked writable in {@code setUp})
	 * is not a save cell the game populated at runtime -- it is a ROM constant, and the
	 * writability test is exactly what tells the two apart.
	 */
	@Test
	public void aLoadFromNonWritableMemoryDeclines() throws Exception {
		builder.setBytes("0x9500", "00", true); // an arbitrary ROM byte to load, never written
		builder.setBytes("0x9040", "ad 00 95", true); // LDA $9500  -- ROM, not RAM
		builder.setBytes("0x9043", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9046", "60", true); // RTS
		Function f = builder.createEmptyFunction("romLoad", "0x9040", 7, null);

		HelperModel model = wrapperModel(f, 0x9040, 0x9043, 'A');

		assertNull(HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/**
	 * A cell inside the live stack page ($0100-$01FF) is refused -- not a stable, named save
	 * slot, and the caller's own {@code JSR} return address lives on exactly that page.
	 */
	@Test
	public void aStackPageCellDeclines() throws Exception {
		builder.setBytes("0x9050", "ad 50 01", true); // LDA $0150  -- inside the stack page
		builder.setBytes("0x9053", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9056", "60", true); // RTS
		Function f = builder.createEmptyFunction("stackPageLoad", "0x9050", 7, null);

		HelperModel model = wrapperModel(f, 0x9050, 0x9053, 'A');

		assertNull(HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	/**
	 * A call-edge wrapper (two clobber segments, the load in segment 1 crossing a {@code JSR}
	 * before segment 2's switch) is refused outright: the load in segment 1 does not directly
	 * reach the switch at all, so "nothing between it and the switch" is false on its face
	 * regardless of what either segment's own bytes look like.
	 */
	@Test
	public void aCallEdgeWrapperTwoSegmentSpanDeclines() throws Exception {
		builder.setBytes("0x9060", "ad 10 07", true); // LDA $0710  -- segment 1
		builder.setBytes("0x9063", "20 00 96", true); // JSR $9600  <- relay call site
		builder.setBytes("0x9066", "60", true); // RTS (wrapper's own tail)
		builder.setBytes("0x9600", "8d 00 e0", true); // STA $E000  <- segment 2 / firstSite
		builder.setBytes("0x9603", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("callEdgeWrapper", "0x9060", 7, null);
		builder.createEmptyFunction("callee", "0x9600", 4, null);

		HelperModel model = new HelperModel(wrapper, addr(0x9060), null, 'A', FULL_MASK, 0, null,
			addr(0x9600), addr(0x9600), new Relay(addr(0x9063), addr(0x9600)));

		assertNull(HelperArgumentRecovery.restoreSourceCell(program, model, 'A'));
	}

	// ------------------------------------------------------------------
	// End to end through the production entry point, recoverCallArgument,
	// proving the wiring (definitelyNoInboundArgument -> restoreSourceCell ->
	// CallEffect.restoreCell) rather than only the isolated predicate above.
	// ------------------------------------------------------------------

	private CallEffect recover(HelperModel helper, String callSite) throws Exception {
		Instruction callInstr = program.getListing().getInstructionAt(builder.addr(callSite));
		Map<HelperArgumentRecovery.CallSiteRegKey, RegisterEnv> envCache = new HashMap<>();
		Set<Function> restoringTrampolines = new HashSet<>();
		return HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.unknown(), envCache, restoringTrampolines);
	}

	/**
	 * The full production path for zelda2's shape: a real call site ({@code JSR $9000}) into the
	 * restore-entry helper, through {@code recoverCallArgument} rather than the isolated
	 * predicate. Pins that {@code definitelyNoInboundArgument} being true is what gates
	 * {@code restoreSourceCell} being consulted at all, and that the result reaches
	 * {@code CallEffect.restoreCell()} unmodified -- the same field
	 * {@code BankDataflowEngine.runDataflow} copies onto {@code CallSwitch.restoreCell()} and
	 * {@code BoardBankAnalyzer} reads to classify the site {@code ValueStop.RESTORED_BANK}.
	 */
	@Test
	public void recoverCallArgumentThreadsTheRestoreCellThrough() throws Exception {
		builder.setBytes("0x9000", "ad 10 07", true); // LDA $0710  -- FUN_ffc9 shape
		builder.setBytes("0x9003", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9006", "60", true); // RTS
		Function f = builder.createEmptyFunction("ffc9", "0x9000", 7, null);
		HelperModel model = wrapperModel(f, 0x9000, 0x9003, 'A');

		builder.setBytes("0x9100", "20 00 90", true); // JSR $9000
		builder.setBytes("0x9103", "60", true); // RTS
		builder.createEmptyFunction("caller", "0x9100", 4, null);

		CallEffect effect = recover(model, "0x9100");

		assertTrue("the call site genuinely has no inbound argument (A is dead on every path)",
			effect.noInboundArgument());
		assertEquals("the restore cell must reach CallEffect unmodified", addr(0x0710),
			effect.restoreCell());
	}

	/**
	 * The negative twin, through the same production path: smb3's shape has
	 * {@code noInboundArgument() == true} (fix (A)'s existing proof) but {@code restoreCell()}
	 * must stay null -- there is no cell to name, and the two questions ("does the argument
	 * survive" vs. "is the redefinition specifically a bare memory restore") must not collapse
	 * into one just because both run over the same clobbering span.
	 */
	@Test
	public void recoverCallArgumentLeavesRestoreCellNullForAConstantRedefinition() throws Exception {
		builder.setBytes("0x9010", "a9 47", true); // LDA #$47   -- a constant, not a reload
		builder.setBytes("0x9012", "8d 00 e0", true); // STA $E000  <- firstSite/switchSite
		builder.setBytes("0x9015", "60", true); // RTS
		Function f = builder.createEmptyFunction("smb3Shape", "0x9010", 6, null);
		HelperModel model = wrapperModel(f, 0x9010, 0x9012, 'A');

		builder.setBytes("0x9110", "20 10 90", true); // JSR $9010
		builder.setBytes("0x9113", "60", true); // RTS
		builder.createEmptyFunction("caller2", "0x9110", 4, null);

		CallEffect effect = recover(model, "0x9110");

		assertTrue(effect.noInboundArgument());
		assertNull("a constant redefinition must not be reported as a restore cell",
			effect.restoreCell());
	}

	// ------------------------------------------------------------------
	// CallEffect#asSecondTierRelay must not disturb restoreCell
	// ------------------------------------------------------------------

	/** Mirrors {@code SecondTierHelperProgramTest#asSecondTierRelayFlipsOnlyItsOwnField}. */
	@Test
	public void asSecondTierRelayCarriesRestoreCellThroughUnchanged() {
		Address cell = addr(0x0710);
		CallEffect base =
			new CallEffect(BankState.unknown(), FULL_MASK, false, true, cell);

		CallEffect flipped = base.asSecondTierRelay();

		assertEquals(cell, base.restoreCell());
		assertEquals(cell, flipped.restoreCell());
		assertTrue(flipped.secondTierRelay());
	}
}
