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

import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@link ProvablyReturningFlagAnalyzer} (bead grm-z0d7.2). Each test builds
 * the state stock FindNoReturnFunctions leaves behind: the callee flagged no-return with its
 * "Non-Returning Function" bookmark, every call overridden to CALL_RETURN, and the code after
 * each call cleared.
 */
public class ProvablyReturningFlagProgramTest extends AbstractBundledLanguageTest {

	private static final int CALLEE = 0x8100;
	private static final int[] CALLERS = { 0x8000, 0x8010, 0x8020 };

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".zp", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private Address addr(int a) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(a);
	}

	/** Callee bytes at {@link #CALLEE}; three callers {@code JSR callee / NOP / RTS}. */
	private void stockState(String calleeBytes, boolean functionAfterEachCall) throws Exception {
		builder.setBytes(String.format("0x%x", CALLEE), calleeBytes, true);
		for (int c : CALLERS) {
			builder.setBytes(String.format("0x%x", c), "20 00 81 ea 60", true);
		}
		int tx = program.startTransaction("stock");
		try {
			new CreateFunctionCmd(addr(CALLEE)).applyTo(program);
			Function fn = program.getFunctionManager().getFunctionAt(addr(CALLEE));
			fn.setNoReturn(true);
			program.getBookmarkManager().setBookmark(addr(CALLEE), BookmarkType.ANALYSIS,
				ProvablyReturningFlagAnalyzer.STOCK_BOOKMARK_CATEGORY, "Non-Returning Function Found");
			for (int c : CALLERS) {
				Instruction call = program.getListing().getInstructionAt(addr(c));
				call.setFlowOverride(FlowOverride.CALL_RETURN);
				program.getListing().clearCodeUnits(addr(c + 3), addr(c + 4), false);
				if (functionAfterEachCall) {
					builder.setBytes(String.format("0x%x", c + 3), "60", false);
				}
			}
		}
		finally {
			program.endTransaction(tx, true);
		}
		if (functionAfterEachCall) {
			for (int c : CALLERS) {
				builder.disassemble(String.format("0x%x", c + 3), 1, false);
				int tx2 = program.startTransaction("fn-after");
				try {
					new CreateFunctionCmd(addr(c + 3)).applyTo(program);
				}
				finally {
					program.endTransaction(tx2, true);
				}
			}
		}
	}

	private Set<Function> run() {
		int tx = program.startTransaction("run");
		try {
			return ProvablyReturningFlagAnalyzer.run(new ProvablyReturningFlagAnalyzer(), program,
				TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private boolean flagged() {
		return program.getFunctionManager().getFunctionAt(addr(CALLEE)).hasNoReturn();
	}

	/** Returning body, three stopped callers: unflagged, fall-through restored. */
	@Test
	public void provablyReturningFunctionIsUnflaggedAndCallersResume() throws Exception {
		stockState("49 ff 18 69 01 60", false); // EOR #$FF / CLC / ADC #1 / RTS

		Set<Function> cleared = run();

		assertEquals(1, cleared.size());
		assertFalse(flagged());
		for (int c : CALLERS) {
			Instruction call = program.getListing().getInstructionAt(addr(c));
			assertEquals(FlowOverride.NONE, call.getFlowOverride());
			assertNotNull("fall-through decoded again", program.getListing().getInstructionAt(
				addr(c + 3)));
		}
		assertNotNull(program.getBookmarkManager().getBookmark(addr(CALLEE),
			BookmarkType.ANALYSIS, ProvablyReturningFlagAnalyzer.BOOKMARK_CATEGORY));
		assertNull(program.getBookmarkManager().getBookmark(addr(CALLEE), BookmarkType.ANALYSIS,
			ProvablyReturningFlagAnalyzer.STOCK_BOOKMARK_CATEGORY));
		assertTrue("a second run changes nothing", run().isEmpty());
	}

	/** A genuine endless loop never returns: left alone. */
	@Test
	public void infiniteLoopStaysFlagged() throws Exception {
		stockState("4c 00 81", false); // JMP self

		assertTrue(run().isEmpty());
		assertTrue(flagged());
		assertNull(program.getListing().getInstructionAt(addr(CALLERS[0] + 3)));
	}

	/** PLA/PLA/RTS discards the caller's return address: not a normal return. */
	@Test
	public void popReturnHelperStaysFlagged() throws Exception {
		stockState("68 68 60", false);

		assertTrue(run().isEmpty());
		assertTrue(flagged());
	}

	/** Returns, but a function starts right after each call: stock would flag it again. */
	@Test
	public void restoredEvidenceAtTheThresholdKeepsTheFlag() throws Exception {
		stockState("49 ff 60", true);

		assertTrue(run().isEmpty());
		assertTrue(flagged());
		assertEquals(3, ProvablyReturningFlagAnalyzer.evidence(program, addr(CALLEE)));
	}

	/** Overlay banks over the callee's block: PopReturnHelper declines everything in it. */
	private void bankTheWindow() throws Exception {
		builder.createOverlayMemory("PRG_B1", "0x8000", 0x4000);
	}

	/** A self-contained RTS body in an overlapped block is judged locally. */
	@Test
	public void selfContainedBodyInABankedBlockIsUnflagged() throws Exception {
		bankTheWindow();
		stockState("49 ff 18 69 01 60", false);
		assertTrue("Levels declines a banked block",
			new PopReturnHelper.Levels(program).of(addr(CALLEE)).declined());

		assertEquals(1, run().size());
		assertFalse(flagged());
		for (int c : CALLERS) {
			assertEquals(FlowOverride.NONE,
				program.getListing().getInstructionAt(addr(c)).getFlowOverride());
			assertNotNull("fall-through restored",
				program.getListing().getInstructionAt(addr(c + 3)));
		}
	}

	/** A JSR in a banked block is not self-contained, and Levels declines the block. */
	@Test
	public void bodyWithAJsrInABankedBlockStaysFlagged() throws Exception {
		bankTheWindow();
		builder.setBytes("0x8200", "60", true);
		stockState("20 00 82 60", false);

		assertTrue(run().isEmpty());
		assertTrue(flagged());
	}

	/** grm-z0d7.3: a forward BCC to a shared RTS tail outside the body is admitted. */
	@Test
	public void forwardBranchToASharedTailOutsideTheBodyIsUnflagged() throws Exception {
		bankTheWindow();
		builder.setBytes("0x8180", "60", true); // shared tail, not in the body
		// BCC $8180 (rel +0x7e from 0x8102) / RTS
		stockState("90 7e 60", false);

		assertEquals(1, run().size());
		assertFalse(flagged());
		for (int c : CALLERS) {
			assertNotNull(program.getListing().getInstructionAt(addr(c + 3)));
		}
	}

	/** grm-z0d7.3: a backward-branch loop with an RTS on another path is not a proof. */
	@Test
	public void backwardBranchLoopWithAnRtsElsewhereStaysFlagged() throws Exception {
		bankTheWindow();
		// LDX #0 / BNE +3 / DEX / BNE -3 (back to DEX) / RTS... path via backward branch
		stockState("a2 00 d0 03 ca d0 fd 60", false);

		assertTrue(run().isEmpty());
		assertTrue(flagged());
	}

	/** grm-z0d7.3: a path that falls off into non-instruction bytes is not a proof. */
	@Test
	public void pathFallingIntoDataStaysFlagged() throws Exception {
		bankTheWindow();
		// BCC +1 / NOP (falls into 0x8103: undecoded) / RTS at 0x8104 reached by the branch
		builder.setBytes("0x8103", "60", false);
		stockState("90 01 ea", false);

		assertTrue(run().isEmpty());
		assertTrue(flagged());
	}
}
