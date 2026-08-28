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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins {@link HelperArgumentRecovery#inboundArgumentCell} (grm-67g): the memory cell a bank-switch
 * helper takes its argument IN, when the caller passes the bank through RAM rather than a
 * register.
 * <p>
 * The regression this bead tracks shipped a confidently wrong bank. {@code findHelpers} learns a
 * helper's argument register from the register its recognized mechanism write STORES -- but a
 * helper that reloads the bank from a RAM shadow before committing looks, from that store alone,
 * identical to one that genuinely takes its bank in that register. smb3's {@code FUN_ffc2} is the
 * worked example this whole file is built around:
 * <pre>
 *   ffc2  LDA #$47      ; clears the tracked cell -- an immediate is not a reload
 *   ffc4  STA $0721     ; a DIFFERENT cell than the one about to be read back
 *   ffc6  STA $8000     ; the select-data byte, walked THROUGH (not the bank)
 *   ffc7  LDA $0720     ; the reload -- the answer this predicate must find
 *   ffc9  STA $8001     ; the value site: select-data consumes here, not at firstSite
 * </pre>
 * The caller side ({@code ca23 LDA #$1b / STA $0720 / JSR $ffc2}) is a separate predicate
 * ({@link StoredValueScanner#callerCellValue}, pinned by {@code StoreForwardingProgramTest}) --
 * this file only pins "does the helper body prove {@code $0720} arrives unmodified", not what
 * value ends up there.
 * <p>
 * These tests stay at the predicate level, exactly like {@link HelperPrologueProgramTest}: it is
 * a pure function of {@code (program, entry, valueSite, reg)}, so they run in the fast JUnit
 * tier with no analyzer, no board descriptor, no helper map.
 */
public class HelperInboundCellProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		// A RAM block is needed for two independent reasons, both inherited from sibling
		// fixtures. HelperPrologueProgramTest needs it because the save/restore half of that
		// predicate reads write REFERENCES, which only exist for an operand naming real memory.
		// StoreForwardingProgramTest needs the block made WRITABLE, because ProgramBuilder
		// blocks default to read-only and bankInvariantRomByte -- consulted deep inside
		// effectiveOperandTarget's plumbing -- otherwise treats a RAM load as a constant ROM
		// byte, which would make at least one decline test below pass for the wrong reason
		// (the walk would "resolve" a byte instead of merely placing a store's target).
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

	/** The predicate over a helper entered at {@code entry} whose value site is {@code valueSite}. */
	private Address inboundCell(String entry, String valueSite, char reg) {
		return HelperArgumentRecovery.inboundArgumentCell(program, builder.addr(entry),
			valueSite == null ? null : builder.addr(valueSite), reg);
	}

	// ------------------------------------------------------------------
	// The argument arrives through memory
	// ------------------------------------------------------------------

	/**
	 * smb3's {@code FUN_ffc2}, byte for byte, quoted in the class javadoc. This is the whole bead
	 * in one test: the immediate clears the tracked cell, the select-data byte at {@code $8000}
	 * is walked through rather than treated as the answer, {@code STA $0721} proves a DIFFERENT
	 * cell than the one the reload names, and only the {@code LDA $0720} immediately before the
	 * value site survives to be returned.
	 */
	@Test
	public void smb3FUN_ffc2ShapeYieldsTheShadowCell() throws Exception {
		builder.setBytes("0xffc2", "a9 47", true); // LDA #$47
		builder.setBytes("0xffc4", "8d 21 07", true); // STA $0721
		builder.setBytes("0xffc7", "8d 00 80", true); // STA $8000
		builder.setBytes("0xffca", "ad 20 07", true); // LDA $0720
		builder.setBytes("0xffcd", "8d 01 80", true); // STA $8001  <- value site

		assertEquals(builder.addr("0x0720"), inboundCell("0xffc2", "0xffcd", 'A'));
	}

	/**
	 * Bionic Commando's {@code FUN_dca8} shape, entered at the top: a single reload immediately
	 * followed by the mechanism write, {@code written} empty throughout.
	 */
	@Test
	public void aOneWriteShadowHelperYieldsItsCell() throws Exception {
		builder.setBytes("0x9000", "a5 65", true); // LDA $65
		builder.setBytes("0x9002", "8d 00 e0", true); // STA $E000  <- value site

		assertEquals(builder.addr("0x0065"), inboundCell("0x9000", "0x9002", 'A'));
	}

	// ------------------------------------------------------------------
	// The argument does not provably arrive through memory
	// ------------------------------------------------------------------

	/**
	 * <b>The sharpest control in this file.</b> Same shape as {@link #smb3FUN_ffc2ShapeYieldsTheShadowCell}
	 * except {@code $FFC4} stores to {@code $0720} -- the very cell the later reload reads back --
	 * so the helper is supplying its OWN byte, not receiving the caller's. Without the
	 * {@code written} set this would confidently return {@code $0720} carrying {@code $47}, which
	 * is the exact regression this bead tracks: the analyzer would ship {@code $47} as the bank.
	 */
	@Test
	public void aCellTheHelperItselfWroteIsNotInbound() throws Exception {
		builder.setBytes("0x9000", "a9 47", true); // LDA #$47
		builder.setBytes("0x9002", "8d 20 07", true); // STA $0720  <- the helper's OWN byte
		builder.setBytes("0x9005", "8d 00 80", true); // STA $8000
		builder.setBytes("0x9008", "ad 20 07", true); // LDA $0720
		builder.setBytes("0x900b", "8d 01 80", true); // STA $8001  <- value site

		assertNull(inboundCell("0x9000", "0x900b", 'A'));
	}

	/**
	 * An indirect store between entry and reload has no statically certain target, so
	 * {@link StoredValueScanner#effectiveOperandTarget} returns null and the write cannot be
	 * placed in {@code written} at all. This is the test that fails if the reference-only
	 * {@code writesAddress} is ever substituted for {@link StoredValueScanner#writesMemory} --
	 * under-reporting here is directly a confident wrong bank, not merely a forfeited forward.
	 */
	@Test
	public void aStoreThatCannotBePlacedDeclines() throws Exception {
		builder.setBytes("0x9000", "91 10", true); // STA ($10),Y  -- unplaceable target
		builder.setBytes("0x9002", "ad 20 07", true); // LDA $0720
		builder.setBytes("0x9005", "8d 01 80", true); // STA $8001  <- value site

		assertNull(inboundCell("0x9000", "0x9005", 'A'));
	}

	/**
	 * A transform after the reload clears the tracked cell just like it does in
	 * {@code argumentSurvivesPrologue}'s model: {@code ASL A} writes A, and
	 * {@code argumentReloadSource} does not recognize it as a reload, so {@code cell} resets to
	 * null and stays null through the value site.
	 */
	@Test
	public void aTransformAfterTheLoadDeclines() throws Exception {
		builder.setBytes("0x9000", "ad 20 07", true); // LDA $0720
		builder.setBytes("0x9003", "0a", true); // ASL A      -- clobbers the tracked cell
		builder.setBytes("0x9004", "8d 01 80", true); // STA $8001  <- value site

		assertNull(inboundCell("0x9000", "0x9004", 'A'));
	}

	/**
	 * Kid Icarus' shape: the helper supplies its own value with an immediate load, which
	 * {@code argumentReloadSource} never treats as a reload (its target is not an address at
	 * all). {@code valueSuppliedInsideHelper} is what must keep resolving this case; this
	 * predicate has nothing to offer it.
	 */
	@Test
	public void anImmediateLoadIsNotAReload() throws Exception {
		builder.setBytes("0x9000", "a9 0f", true); // LDA #$0F
		builder.setBytes("0x9002", "8d ff 9f", true); // STA $9FFF  <- value site

		assertNull(inboundCell("0x9000", "0x9002", 'A'));
	}

	/**
	 * smb3's {@code FUN_ffbf} shape: a call anywhere in the walk declines outright, matching
	 * {@code argumentSurvivesPrologue}'s identical refusal (a callee's register AND memory
	 * effects are unmodeled here).
	 */
	@Test
	public void aCallInTheWalkDeclines() throws Exception {
		builder.setBytes("0x9000", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9003", "ad 20 07", true); // LDA $0720
		builder.setBytes("0x9006", "8d 01 80", true); // STA $8001  <- value site
		builder.setBytes("0x9500", "60", true); // RTS

		assertNull(inboundCell("0x9000", "0x9006", 'A'));
	}

	/**
	 * A conditional branch anywhere in the walk declines: unlike
	 * {@code argumentSurvivesPrologue}, which merely stops trusting its save/restore model on a
	 * branch, EVERY flow declines here -- a linear-by-address walk that let a branch through could
	 * skip a write to the cell, or count one that never executes, and either mistake points the
	 * unsafe way.
	 */
	@Test
	public void aBranchInTheWalkDeclines() throws Exception {
		builder.setBytes("0x9000", "ad 20 07", true); // LDA $0720
		builder.setBytes("0x9003", "d0 00", true); // BNE $9005  -- a flow, taken or not
		builder.setBytes("0x9005", "8d 01 80", true); // STA $8001  <- value site

		assertNull(inboundCell("0x9000", "0x9005", 'A'));
	}

	/**
	 * The walk must land EXACTLY on the value site. Here {@code valueSite} names an address
	 * interior to the three-byte {@code LDA $0720} instruction, so the linear walk's cursor steps
	 * straight past it (to {@code $9003}) without ever equaling it, and the method declines rather
	 * than reading a half-executed instruction as an answer.
	 */
	@Test
	public void theWalkMustLandExactlyOnTheSite() throws Exception {
		builder.setBytes("0x9000", "ad 20 07", true); // LDA $0720  -- spans 0x9000-0x9002

		assertNull(inboundCell("0x9000", "0x9001", 'A'));
	}

	/**
	 * Bionic Commando's second convention, mirroring
	 * {@link HelperPrologueProgramTest#aMidBodyEntryPastTheClobberKeepsItsArgument} but with the
	 * opposite outcome: entering AT the store (past the {@code LDA $65}) makes the walk empty, so
	 * no reload is ever seen and the register scan -- not this predicate -- is what has to answer
	 * for that entry.
	 */
	@Test
	public void aMidBodyEntryPastTheLoadDeclines() throws Exception {
		builder.setBytes("0x9000", "a5 65", true); // LDA $65    -- skipped by this entry
		builder.setBytes("0x9002", "8d 00 e0", true); // STA $E000  <- entry AND value site

		assertNull(inboundCell("0x9002", "0x9002", 'A'));
	}
}
