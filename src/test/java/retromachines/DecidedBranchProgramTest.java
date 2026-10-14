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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;

/**
 * {@link DecidedBranchAnalyzer} on a synthetic reduction of blmaster's ebf2 (grm-kdgv):
 * <pre>
 *   8000  LDA #imm
 *   8002  STA $2006
 *   8005  Bcc $800b   ; BEQ after LDA #0 is always taken
 *   8007  NOP / NOP / NOP / BRK   ; a data table Ghidra decoded as code
 *   800b  RTS
 * </pre>
 * The function at 8000 is created BEFORE the analyzer runs, so the body fix-up is exercised too.
 */
public class DecidedBranchProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	/** {@code lda} is the LDA instruction's two bytes, {@code branch} the opcode at 8005;
	 *  {@code jumpToDead} adds a JMP $8007 at 8010. */
	private ProgramDB build(String lda, int branch, boolean jumpToDead) throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x100);
		builder.setBytes("0x8000",
			String.format("%s 8d 06 20 %02x 04 ea ea ea 00 60", lda, branch), true);
		if (jumpToDead) {
			builder.setBytes("0x8010", "4c 07 80", true);
		}
		return builder.getProgram();
	}

	private Function runAnalyzer(ProgramDB program) throws Exception {
		int tx = program.startTransaction("analyze");
		try {
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr(0x8000));
			cmd.applyTo(program, TaskMonitor.DUMMY);
			Function function = cmd.getFunction();
			assertTrue("control: body starts out including the dead table",
				function.getBody().contains(addr(0x8007)));
			DecidedBranchAnalyzer analyzer = new DecidedBranchAnalyzer();
			assertTrue(analyzer.canAnalyze(program));
			analyzer.added(program, program.getMemory().getLoadedAndInitializedAddressSet(),
				TaskMonitor.DUMMY, new MessageLog());
			return function;
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Instruction instr(ProgramDB program, long offset) {
		return program.getListing().getInstructionAt(addr(offset));
	}

	@Test
	public void takenBranchDropsAndClearsItsDeadFallThrough() throws Exception {
		ProgramDB program = build("a9 00", 0xf0, false); // LDA #0 / BEQ
		Function function = runAnalyzer(program);

		assertTrue(instr(program, 0x8005).isFallThroughOverridden());
		for (long a = 0x8007; a <= 0x800a; a++) {
			assertNull("dead table byte still code at " + Long.toHexString(a),
				program.getListing().getInstructionContaining(addr(a)));
		}
		assertNotNull("branch target must survive", instr(program, 0x800b));
		assertFalse(function.getBody().contains(addr(0x8007)));
		assertEquals(addr(0x800b), function.getBody().getMaxAddress());
	}

	/** Something jumps straight into the dead region: the code there is reached, so only the
	 *  override is set and nothing is cleared. */
	@Test
	public void deadRegionReachedElsewhereIsKept() throws Exception {
		ProgramDB program = build("a9 00", 0xf0, true);
		runAnalyzer(program);

		assertTrue(instr(program, 0x8005).isFallThroughOverridden());
		assertNotNull(instr(program, 0x8007));
		assertNotNull(instr(program, 0x800a));
	}

	/**
	 * tmnt bank 4 b786: {@code LDA #$10 / BNE c / LDA #$11 / BNE c / LDA #$12 / BNE c /
	 * LDA #$13 / RTS}, with no table: nothing reaches the later entries, so they are cleared. The
	 * first entry and the common tail stay. (In tmnt a pointer table does name them; see
	 * {@link #multiEntryChainNamedByAPointerTableIsKept}.)
	 */
	@Test
	public void unreachedMultiEntryChainIsCleared() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x100);
		builder.setBytes("0x8000", "a9 10 d0 0a a9 11 d0 06 a9 12 d0 02 a9 13 60", true);
		ProgramDB program = builder.getProgram();
		int tx = program.startTransaction("analyze");
		try {
			new DecidedBranchAnalyzer().added(program,
				program.getMemory().getLoadedAndInitializedAddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertTrue(instr(program, 0x8002).isFallThroughOverridden());
		for (long a : new long[] { 0x8004, 0x8008, 0x800c }) {
			assertNull("unreached entry still code at " + Long.toHexString(a),
				instr(program, a));
		}
		assertNotNull(instr(program, 0x8000));
		assertNotNull("common tail must survive", instr(program, 0x800e));
	}

	/**
	 * The same chain, but a JumpEngine table names its entries (grm-x51h; tmnt's {@code $B5A2}):
	 * {@link InlineJumpTableDispatchAnalyzer} lays them as pointer data before any function exists
	 * at them, so the pointer's DATA reference alone must keep each entry.
	 */
	@Test
	public void multiEntryChainNamedByAPointerTableIsKept() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x100);
		builder.setBytes("0x8000", "a9 10 d0 0a a9 11 d0 06 a9 12 d0 02 a9 13 60", true);
		// Pointer table at 8040: 8000, 8004, 8008 -- the last entry, 800c, is left unnamed.
		builder.setBytes("0x8040", "00 80 04 80 08 80");
		ProgramDB program = builder.getProgram();
		int tx = program.startTransaction("analyze");
		try {
			for (long a = 0x8040; a < 0x8046; a += 2) {
				DataUtilities.createData(program, addr(a), PointerDataType.dataType, -1,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			assertTrue("control: the pointer laid its reference",
				program.getReferenceManager().getReferencesTo(addr(0x8004)).hasNext());
			new DecidedBranchAnalyzer().added(program,
				program.getMemory().getLoadedAndInitializedAddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertTrue("the override is still set", instr(program, 0x8002).isFallThroughOverridden());
		assertNotNull("pointed-at entry kept", instr(program, 0x8004));
		assertNotNull("pointed-at entry kept", instr(program, 0x8008));
		assertNull("unnamed entry still cleared", instr(program, 0x800c));
	}

	/**
	 * ultimaav {@code FUN_f34b}: {@code LDA #$0E / BNE $f351 / LDA #$0F / f351 LDX #$05 /
	 * STA $9FFF}. Clearing the second entry leaves a hole in the helper's prologue span, and
	 * {@link HelperArgumentRecovery#argumentDefinitelyClobbered}'s address-order walk must step
	 * over it along the decided branch rather than give up -- A is still redefined by the
	 * helper's own {@code LDA #$0E}, so its call sites keep the "no inbound argument" warning.
	 */
	@Test
	public void prologueWalkFollowsADecidedBranchOverTheClearedGap() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		builder.createMemory(".text", "0x9000", 0x100);
		builder.setBytes("0x9000", "a9 0e d0 02 a9 0f a2 05 8d ff 9f 60", true);
		ProgramDB program = builder.getProgram();
		assertTrue("control: clobbered before the analyzer runs",
			HelperArgumentRecovery.argumentDefinitelyClobbered(program, addr(0x9000),
				addr(0x9008), 'A'));
		int tx = program.startTransaction("analyze");
		try {
			new DecidedBranchAnalyzer().added(program,
				program.getMemory().getLoadedAndInitializedAddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertNull("second entry cleared", instr(program, 0x9004));
		assertTrue(HelperArgumentRecovery.argumentDefinitelyClobbered(program, addr(0x9000),
			addr(0x9008), 'A'));
	}

	/** LDA from memory: Z is unknown, so the branch is undecided. */
	@Test
	public void undecidedBranchIsLeftAlone() throws Exception {
		ProgramDB program = build("a5 10", 0xf0, false); // LDA $10 / BEQ
		runAnalyzer(program);

		assertFalse(instr(program, 0x8005).isFallThroughOverridden());
		assertNotNull(instr(program, 0x8007));
	}

	/** LDA #0 / BNE is provably NOT taken; this analyzer only acts on taken branches. */
	@Test
	public void notTakenBranchIsLeftAlone() throws Exception {
		ProgramDB program = build("a9 00", 0xd0, false); // LDA #0 / BNE
		runAnalyzer(program);

		assertFalse(instr(program, 0x8005).isFallThroughOverridden());
		assertNotNull(instr(program, 0x8007));
		assertNotNull(instr(program, 0x800b));
	}
}
