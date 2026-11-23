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
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;

/**
 * {@link W65816ReturnProof} and {@link ProvablyReturningFlagAnalyzer} on the 65816 (bead
 * grm-9nxj.39). The shapes are the three real routines stock wrongly flagged no-return: w_ff2
 * {@code 01818a} (PHA, vblank poll loop, PLA, RTS), w_ff3 {@code c3072d} (a JSR inside) and
 * {@code c381c7} (a branch back to a shared RTS before the entry).
 */
public class W65816ReturnProofTest extends AbstractProgramTest {

	private static final int CALLEE = 0x8100;
	private static final int[] CALLERS = { 0x8000, 0x8010, 0x8020 };

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

	private String proof(String hex) throws Exception {
		builder.setBytes(String.format("0x%x", CALLEE), hex, true);
		return W65816ReturnProof.provenReturn(program, addr(CALLEE));
	}

	/** w_ff2 01818a: PHA / poll $4210 until bit 7 clears (a backward loop) / PLA / RTS. */
	@Test
	public void balancedPushAroundAPollLoopReturns() throws Exception {
		// PHA ; LDA $4210 ; AND #$80 ; BNE -7 ; PLA ; RTS
		assertEquals("RTS", proof("48 ad 10 42 29 80 d0 f9 68 60"));
	}

	/** w_ff3 c381c7: a branch back to an RTS that sits before the entry. */
	@Test
	public void branchBackToASharedRtsReturns() throws Exception {
		builder.setBytes(String.format("0x%x", CALLEE - 1), "60", true); // the shared RTS
		// LDA $20 ; BNE -5 (to CALLEE-1) ; RTS
		assertEquals("RTS", proof("a5 20 d0 fb 60"));
	}

	/** w_ff3 c3072d: a direct call to a returning routine is stepped over. */
	@Test
	public void callToAReturningRoutineIsSteppedOver() throws Exception {
		builder.setBytes("0x8200", "60", true);
		assertEquals("RTS", proof("20 00 82 60")); // JSR $8200 ; RTS
	}

	@Test
	public void rtlLeafIsReportedAsRtl() throws Exception {
		assertEquals("RTL", proof("8b 4b ab ab 6b")); // PHB ; PHK ; PLB ; PLB ; RTL
	}

	@Test
	public void unbalancedPushDoesNotReturn() throws Exception {
		assertNull(proof("48 60")); // PHA ; RTS: returns into the pushed byte
	}

	@Test
	public void pullingTheReturnAddressDeclines() throws Exception {
		assertNull(proof("68 68 60")); // PLA ; PLA ; RTS
	}

	@Test
	public void endlessLoopDeclines() throws Exception {
		assertNull(proof("80 fe")); // BRA self
	}

	@Test
	public void mixedRtsAndRtlDeclines() throws Exception {
		assertNull(proof("d0 01 60 6b")); // BNE +1 ; RTS ; RTL
	}

	/** PHA at 16 bits, PLA at 8: the pull leaves a byte behind. */
	@Test
	public void pushAndPullAtDifferentWidthsDecline() throws Exception {
		assertNull(proof("c2 20 48 e2 20 68 60")); // REP #$20 ; PHA ; SEP #$20 ; PLA ; RTS
	}

	/** The same pair at one width balances. */
	@Test
	public void pushAndPullAtOneWidthReturn() throws Exception {
		assertEquals("RTS", proof("c2 20 48 68 e2 20 60")); // REP #$20 ; PHA ; PLA ; SEP ; RTS
	}

	/** grm-9nxj.52: {@code PHK / JSR} into an RTL routine pulls the PHK byte too. */
	@Test
	public void phkJsrIntoRtlRoutineIsAHandRolledJsl() throws Exception {
		builder.setBytes("0x8200", "6b", true);   // RTL
		assertEquals("RTL", proof("4b 20 00 82 6b")); // PHK ; JSR $8200 ; RTL
	}

	/** The same JSR into an RTS routine leaves the PHK byte: the RTL is one byte deep. */
	@Test
	public void phkJsrIntoRtsRoutineDeclines() throws Exception {
		builder.setBytes("0x8200", "60", true);   // RTS
		assertNull(proof("4b 20 00 82 6b")); // PHK ; JSR $8200 ; RTL
	}

	/**
	 * F-Zero's RTL trampoline {@code $03:8015 PEA $86FB / JML $00:86A9}: the RTS routine returns
	 * to the {@code RTL} byte after the pushed address, which nothing has decoded.
	 */
	@Test
	public void peaJmpIntoRtsRoutineReturnsThroughATrampolineRtl() throws Exception {
		builder.setBytes("0x82fa", "60 ea 6b", false);   // RTS ; NOP ; RTL (undecoded)
		builder.setBytes("0x8300", "60", true);          // the RTS routine
		assertEquals("RTL", proof("f4 fb 82 4c 00 83")); // PEA $82FB ; JMP $8300
		assertNull(program.getListing().getInstructionAt(addr(0x82fc)));
	}

	/** The F-Zero shape whole: {@code PHK / JSR} into that trampoline, then the routine's RTL. */
	@Test
	public void phkJsrIntoATrampolineReturnsByRtl() throws Exception {
		builder.setBytes("0x82fa", "60 ea 6b", false);
		builder.setBytes("0x8300", "60", true);
		builder.setBytes("0x8400", "f4 fb 82 4c 00 83", true);   // the trampoline
		assertEquals("RTL", proof("4b 20 00 84 6b"));      // PHK ; JSR $8400 ; RTL
	}

	@Test
	public void tailJumpIntoAnotherFunctionDeclines() throws Exception {
		builder.setBytes("0x8200", "60", true);
		inTx(program, "fn", () -> new CreateFunctionCmd(addr(0x8200)).applyTo(program));
		assertNull(proof("4c 00 82")); // JMP $8200
	}

	// ---- the analyzer, on the state stock leaves behind --------------------------------------

	/** Callee flagged with stock's bookmark, its callers stopped, the first a call-site thunk. */
	private void stockState(String calleeBytes) throws Exception {
		builder.setBytes(String.format("0x%x", CALLEE), calleeBytes, true);
		for (int c : CALLERS) {
			builder.setBytes(String.format("0x%x", c), "20 00 81 ea 60", true); // JSR / NOP / RTS
		}
		inTx(program, "stock", () -> {
			new CreateFunctionCmd(addr(CALLEE)).applyTo(program);
			Function fn = program.getFunctionManager().getFunctionAt(addr(CALLEE));
			fn.setNoReturn(true);
			program.getBookmarkManager().setBookmark(addr(CALLEE), BookmarkType.ANALYSIS,
				ProvablyReturningFlagAnalyzer.STOCK_BOOKMARK_CATEGORY, "Non-Returning Function Found");
			for (int c : CALLERS) {
				Instruction call = program.getListing().getInstructionAt(addr(c));
				call.setFlowOverride(FlowOverride.CALL_RETURN);
				program.getListing().clearCodeUnits(addr(c + 3), addr(c + 4), false);
			}
			new CreateFunctionCmd(addr(CALLERS[0])).applyTo(program);
			Function thunk = program.getFunctionManager().getFunctionAt(addr(CALLERS[0]));
			thunk.setThunkedFunction(fn);
		});
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

	@Test
	public void analyzerRunsOn65816() {
		assertTrue(new ProvablyReturningFlagAnalyzer().canAnalyze(program));
	}

	/** The 01818a shape: unflagged, callers resume at the caller's width, the thunk undone. */
	@Test
	public void provablyReturningRoutineIsUnflaggedAndCallersResume() throws Exception {
		stockState("48 ad 10 42 29 80 d0 f9 68 60");

		Set<Function> cleared = run();

		assertEquals(1, cleared.size());
		assertFalse(program.getFunctionManager().getFunctionAt(addr(CALLEE)).hasNoReturn());
		Register m = program.getRegister("ctx_MF");
		for (int c : CALLERS) {
			assertEquals(FlowOverride.NONE, instructionAt(addr(c)).getFlowOverride());
			Instruction cont = program.getListing().getInstructionAt(addr(c + 3));
			assertNotNull("fall-through decoded again at " + Integer.toHexString(c + 3), cont);
			assertEquals("decoded at the call's M", BigInteger.ONE, cont.getValue(m, false));
		}
		Function site = program.getFunctionManager().getFunctionAt(addr(CALLERS[0]));
		assertFalse("the call-site thunk is an ordinary function again", site.isThunk());
		assertTrue("a second run changes nothing", run().isEmpty());
	}

	/** PLA/PLA/RTS discards the return address: the flag stays. */
	@Test
	public void popReturnRoutineStaysFlagged() throws Exception {
		stockState("68 68 60");

		assertTrue(run().isEmpty());
		assertTrue(program.getFunctionManager().getFunctionAt(addr(CALLEE)).hasNoReturn());
	}

	/** An RTL routine reached by JSR does not return to the JSR: left flagged. */
	@Test
	public void rtlRoutineCalledByJsrStaysFlagged() throws Exception {
		stockState("6b");

		assertTrue(run().isEmpty());
	}
}
