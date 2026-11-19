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

import java.math.BigInteger;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

/**
 * {@link W65816NoReturnProof} and {@link W65816NoReturnFlagAnalyzer} (bead grm-hf5h.27). The
 * worked shape is FF3's boot routine {@code FUN_c00019}: it calls helpers that return, then
 * loops forever.
 */
public class W65816NoReturnFlagTest extends AbstractProgramTest {

	private static final int BOOT = 0x8100;
	private static final int HELPER = 0x8200;
	private static final int[] CALLERS = { 0x8000, 0x8010, 0x8020 };
	/** A caller with a path around the call: it still returns. */
	private static final int BYPASS = 0x8030;
	/** A caller that is nothing but the call. */
	private static final int LONE = 0x8040;
	/** Offset of the JSR in each of {@link #CALLERS}. */
	private static final int CALL = 2;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
		setContext("ctx_EF", 0);
		setContext("ctx_MF", 1);
		setContext("ctx_XF", 1);
	}

	private void setContext(String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull("no context field named " + field, register);
		inTx(program, "set " + field, () -> program.getProgramContext()
				.setValue(register, addr("0x8000"), addr("0x8fff"), BigInteger.valueOf(value)));
	}

	private Boolean scan(String hex) throws Exception {
		builder.setBytes(String.format("0x%x", BOOT), hex, true);
		return W65816NoReturnProof.neverReturns(program, addr(BOOT));
	}

	// ---- the scan -----------------------------------------------------------------------------

	@Test
	public void endlessLoopNeverReturns() throws Exception {
		assertEquals(Boolean.TRUE, scan("80 fe")); // BRA self
	}

	/** The c00019 shape: a returning call is stepped over, then the main loop. */
	@Test
	public void callThenMainLoopNeverReturns() throws Exception {
		builder.setBytes(String.format("0x%x", HELPER), "60", true);
		assertEquals(Boolean.TRUE, scan("20 00 82 80 fb")); // JSR $8200 ; BRA -5 (to entry)
	}

	@Test
	public void loopWithAnExitReturns() throws Exception {
		assertEquals(Boolean.FALSE, scan("a5 20 d0 fc 60")); // LDA $20 ; BNE -4 ; RTS
	}

	@Test
	public void rtiCountsAsAReturn() throws Exception {
		assertEquals(Boolean.FALSE, scan("40")); // RTI
	}

	/** BRK vectors through $FFE6: a computed jump with no resolved target proves nothing. */
	@Test
	public void brkProvesNothing() throws Exception {
		assertNull(scan("00 00"));
	}

	@Test
	public void unresolvedComputedJumpProvesNothing() throws Exception {
		assertNull(scan("7c 00 90")); // JMP ($9000,X)
	}

	/** A return elsewhere still decides it even when one path is unproven. */
	@Test
	public void returnBesideAnUnprovenPathReturns() throws Exception {
		assertEquals(Boolean.FALSE, scan("d0 03 7c 00 90 60")); // BNE +3 ; JMP ($9000,X) ; RTS
	}

	// ---- the analyzer -------------------------------------------------------------------------

	private void bootState() throws Exception {
		builder.setBytes(String.format("0x%x", HELPER), "60", true);
		builder.setBytes(String.format("0x%x", BOOT), "20 00 82 80 fb", true);
		for (int c : CALLERS) {
			// LDA #0 / JSR $8100 / NOP / RTS: a body of its own, so not a one-JSR thunk
			builder.setBytes(String.format("0x%x", c), "a9 00 20 00 81 ea 60", true);
		}
		builder.setBytes(String.format("0x%x", LONE), "20 00 81 60", true); // JSR $8100 / RTS
		// BNE +3 (to the RTS) ; JSR $8100 ; RTS
		builder.setBytes(String.format("0x%x", BYPASS), "d0 03 20 00 81 60", true);
		inTx(program, "functions", () -> {
			for (int a : new int[] { HELPER, BOOT, CALLERS[0], CALLERS[1], CALLERS[2], BYPASS,
				LONE }) {
				new CreateFunctionCmd(addr(a)).applyTo(program);
			}
		});
	}

	private Set<Function> run() {
		int tx = program.startTransaction("run");
		try {
			return W65816NoReturnFlagAnalyzer.run(new W65816NoReturnFlagAnalyzer(), program,
				TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Function fn(int a) {
		return program.getFunctionManager().getFunctionAt(addr(a));
	}

	@Test
	public void analyzerRunsOn65816() {
		assertTrue(new W65816NoReturnFlagAnalyzer().canAnalyze(program));
	}

	@Test
	public void bootRoutineIsFlaggedAndCallsToItEnd() throws Exception {
		bootState();

		run();

		assertTrue(fn(BOOT).hasNoReturn());
		assertFalse("the helper returns", fn(HELPER).hasNoReturn());
		assertNotNull(program.getBookmarkManager().getBookmark(addr(BOOT), BookmarkType.ANALYSIS,
			W65816NoReturnFlagAnalyzer.BOOKMARK_CATEGORY));
		for (int c : CALLERS) {
			assertEquals(FlowOverride.CALL_RETURN,
				instructionAt(addr(c + CALL)).getFlowOverride());
			assertNull("the false decode after the call is cleared at " + Integer.toHexString(c),
				program.getListing().getInstructionAt(addr(c + CALL + 3)));
		}
		assertEquals(FlowOverride.CALL_RETURN, instructionAt(addr(BYPASS + 2)).getFlowOverride());
		assertNotNull("the RTS after the bypass caller's call is still reached by the branch",
			program.getListing().getInstructionAt(addr(BYPASS + 5)));
	}

	/** A caller whose only way out was the call never returns either; one with a bypass does. */
	@Test
	public void flagSpreadsToCallersWithNoOtherWayOut() throws Exception {
		bootState();

		Set<Function> flagged = run();

		assertEquals(1 + CALLERS.length, flagged.size());
		for (int c : CALLERS) {
			assertTrue(fn(c).hasNoReturn());
		}
		assertFalse(fn(BYPASS).hasNoReturn());
	}

	/**
	 * Ghidra makes a function that is nothing but a call into no-return code a thunk of it (as
	 * it does after stock flags a callee), so it reports the flag through its target.
	 */
	@Test
	public void loneCallBecomesAThunkOfTheBootRoutine() throws Exception {
		bootState();

		run();

		Function lone = fn(LONE);
		assertTrue(lone.isThunk());
		assertEquals(addr(BOOT), lone.getThunkedFunction(true).getEntryPoint());
		assertTrue(lone.hasNoReturn());
	}

	@Test
	public void secondRunChangesNothing() throws Exception {
		bootState();
		run();

		assertTrue(run().isEmpty());
	}

	/** A flag the user cleared after this analyzer set it is not set again. */
	@Test
	public void userClearedFlagIsNotSetAgain() throws Exception {
		bootState();
		run();
		inTx(program, "user", () -> fn(BOOT).setNoReturn(false));

		assertTrue(run().isEmpty());
		assertFalse(fn(BOOT).hasNoReturn());
	}

	// ---- Disassembler.java:1331 repair ------------------------------------------------------

	private static final int DISPATCH = 0x8050;

	/**
	 * A {@code JSR ($9000,X)} whose table's first slot is the flagged boot routine, in the state
	 * Ghidra's Disassembler leaves it: CALL_RETURN on the whole call, fall-through undecoded.
	 */
	private void stoppedDispatch(int... targets) throws Exception {
		bootState();
		run();
		builder.setBytes("0x9000", "00 81 00 82", false); // table: BOOT, HELPER
		builder.setBytes(String.format("0x%x", DISPATCH), "fc 00 90 ea 60", true); // JSR (,X) / NOP / RTS
		inTx(program, "stopped dispatch", () -> {
			program.getListing().createData(addr(0x9000), new ghidra.program.model.data.WordDataType());
			program.getReferenceManager().addMemoryReference(addr(0x9000), addr(BOOT),
				ghidra.program.model.symbol.RefType.DATA, ghidra.program.model.symbol.SourceType.ANALYSIS, 0);
			for (int t : targets) {
				program.getReferenceManager().addMemoryReference(addr(DISPATCH), addr(t),
					ghidra.program.model.symbol.RefType.COMPUTED_CALL,
					ghidra.program.model.symbol.SourceType.ANALYSIS, 0);
			}
			instructionAt(addr(DISPATCH)).setFlowOverride(FlowOverride.CALL_RETURN);
			program.getListing().clearCodeUnits(addr(DISPATCH + 3), addr(DISPATCH + 4), false);
		});
	}

	private int repair() {
		int tx = program.startTransaction("repair");
		try {
			return W65816NoReturnFlagAnalyzer.repairDispatchCalls(program, program.getMemory(),
				TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void dispatchWithAReturningTargetGetsItsFallThroughBack() throws Exception {
		stoppedDispatch(BOOT, HELPER);

		assertEquals(1, repair());
		assertEquals(FlowOverride.NONE, instructionAt(addr(DISPATCH)).getFlowOverride());
		assertNotNull("the code after the dispatch is decoded again",
			program.getListing().getInstructionAt(addr(DISPATCH + 3)));
	}

	@Test
	public void dispatchWhoseTargetsAllNeverReturnStaysStopped() throws Exception {
		stoppedDispatch(BOOT);

		assertEquals(0, repair());
		assertEquals(FlowOverride.CALL_RETURN, instructionAt(addr(DISPATCH)).getFlowOverride());
	}

	@Test
	public void returningRoutineIsLeftAlone() throws Exception {
		builder.setBytes(String.format("0x%x", BOOT), "a5 20 d0 fc 60", true);
		inTx(program, "fn", () -> new CreateFunctionCmd(addr(BOOT)).applyTo(program));

		assertTrue(run().isEmpty());
		assertFalse(fn(BOOT).hasNoReturn());
	}
}
