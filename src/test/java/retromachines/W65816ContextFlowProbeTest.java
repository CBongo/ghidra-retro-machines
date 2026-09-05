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

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

/**
 * Scoping probe for bead `grm-9nxj.5`: HOW FAR does M/X decode context travel on its own?
 *
 * <p>The bead assumes an ArmAnalyzer-shaped Java pass is needed to carry accumulator/index width
 * into routines that do not set it locally (~70% of routine entries, per the corpus measurement).
 * That is worth checking before building one, because SLEIGH's {@code globalset} already stamps
 * context at flow targets and Ghidra's disassembler carries context along flow: if a plain
 * {@code JSR} already delivers the caller's width to the callee, the analyzer's job is only the
 * cases flow cannot reach (computed jumps, {@code PLP}/{@code RTI}, dual-width callees), which is
 * a much smaller piece of work than the bead assumes.
 *
 * <p>Each case below therefore records a FACT about the toolchain rather than about our code, and
 * the assertions are written to state what was measured. If a future Ghidra changes any of this,
 * the analyzer's scope changes with it, and this test is what says so.
 */
public class W65816ContextFlowProbeTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "65816:LE:24:retro");
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
		// Native mode throughout: emulation mode forces 8-bit and would mask the question.
		setContext("0x8000", "0x8fff", "ctx_EF", 0);
	}

	/**
	 * Baseline: {@code REP #$20} widens the accumulator for the instruction that FALLS THROUGH
	 * after it. Already covered by {@code W65816LanguageTest}; repeated here as the control the
	 * other cases are measured against.
	 */
	@Test
	public void contextReachesTheFallThroughSuccessor() throws Exception {
		builder.setBytes("0x8000", "c2 20 a9 34 12", false); // REP #$20 ; LDA #$1234
		builder.disassemble("0x8000", 5, true);

		Instruction lda = instructionAt("0x8002");
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals("fall-through did not inherit the widened accumulator", 3, lda.getLength());
	}

	/**
	 * THE QUESTION THIS PROBE EXISTS FOR, and the answer narrows bead grm-9nxj.5 considerably:
	 * <b>a direct {@code JSR} DOES carry the caller's width into the callee.</b> {@code REP #$20}
	 * then {@code JSR $8100}, where {@code $8100} holds {@code A9 34 12}: it decodes as a 3-byte
	 * {@code LDA #$1234}, not a 2-byte {@code LDA #$34}. Ghidra propagates the context register
	 * along call flow the same way it does along fall-through, so no analyzer is needed for the
	 * ordinary case the bead's ~70% figure describes — only for flows the disassembler cannot
	 * follow (see the computed-jump case below), for {@code PLP}/{@code RTI}, and for callees
	 * genuinely entered at two different widths (see the dual-width case below).
	 */
	@Test
	public void contextFlowsThroughADirectCall() throws Exception {
		// The callee's bytes are placed WITHOUT disassembling: disassembling them here would
		// decode $8100 under the default context before any call ever reaches it, and the test
		// would then measure its own setup rather than context propagation.
		builder.setBytes("0x8000", "c2 20 20 00 81 ea", false); // REP #$20 ; JSR $8100 ; NOP
		builder.setBytes("0x8100", "a9 34 12 60", false);       // LDA #$1234 ; RTS
		// The range must cover the callee too: disassembly follows flow only WITHIN the address
		// set it is given, so a 6-byte range stops at the call and never decodes $8100 at all.
		builder.disassemble("0x8000", 0x200, true);             // follow flows, including the call

		Instruction lda = instructionAt("0x8100");
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals("MEASURED: a direct JSR carries the caller's accumulator width into the " +
			"callee (length 3 = 16-bit immediate)", 3, lda.getLength());
	}

	/**
	 * The case Ghidra structurally cannot represent, pinned so the analyzer bead scopes around it
	 * rather than pretending to fix it: a callee entered at TWO different widths. The first flow
	 * to reach it wins; the second does not re-decode (Disassembler's
	 * {@code setInconsistentPrototypeConflict} path). Here the 16-bit caller is disassembled first,
	 * so the callee is 16-bit, and the 8-bit caller's view of it is silently wrong.
	 *
	 * <p>This is why grm-9nxj.5's brief says dual-width routines must be REPORTED rather than
	 * papered over: no stamping strategy can make one address decode two ways.
	 */
	@Test
	public void aCalleeEnteredAtTwoWidthsKeepsOnlyTheFirst() throws Exception {
		builder.setBytes("0x8000", "c2 20 20 00 81 ea", false); // REP #$20 ; JSR $8100 ; NOP
		builder.setBytes("0x8010", "e2 20 20 00 81 ea", false); // SEP #$20 ; JSR $8100 ; NOP
		builder.setBytes("0x8100", "a9 34 12 60", false);       // LDA #$1234 / LDA #$34 ; RTS
		builder.disassemble("0x8000", 0x200, true);
		builder.disassemble("0x8010", 0x200, true);

		Instruction lda = instructionAt("0x8100");
		assertEquals("the first flow's width should stick", 3, lda.getLength());
	}

	/**
	 * A computed jump: {@code JMP ($8200,X)}. The disassembler cannot follow it without knowing
	 * X, so the table's targets are never reached by flow and never receive context. THIS is the
	 * shape the analyzer exists for -- the same one {@code ArmAnalyzer} handles for Thumb by
	 * reading the propagated mode at a computed flow and calling
	 * {@code ProgramContext.setValue} on the target.
	 */
	@Test
	public void aComputedJumpTargetIsNeverReachedByFlow() throws Exception {
		builder.setBytes("0x8000", "c2 20 fc 00 82", false); // REP #$20 ; JMP ($8200,X)
		builder.setBytes("0x8300", "a9 34 12 60", false);    // the table's target, unreachable
		builder.disassemble("0x8000", 0x400, true);

		assertNull("a computed-jump target was disassembled after all -- if Ghidra grew the " +
			"ability to follow this, the analyzer's scope shrinks again",
			program.getListing().getInstructionAt(builder.addr("0x8300")));
	}

	/**
	 * The same question for a direct branch, which is ordinary flow rather than a call — the case
	 * SLEIGH's own {@code globalset} machinery is most likely to already cover.
	 */
	@Test
	public void contextReachesABranchTarget() throws Exception {
		builder.setBytes("0x8000", "c2 20 80 01 ea a9 34 12", false); // REP #$20 ; BRA +1 ; NOP ; LDA
		builder.disassemble("0x8000", 8, true);

		Instruction lda = instructionAt("0x8005");
		assertNotNull("branch target did not disassemble", lda);
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals("branch target did not inherit the widened accumulator", 3, lda.getLength());
	}

	private Instruction instructionAt(String address) {
		Instruction instruction = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("no instruction at " + address, instruction);
		return instruction;
	}

	private void setContext(String start, String end, String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull("no context field named " + field, register);
		int tx = program.startTransaction("set " + field);
		try {
			program.getProgramContext()
					.setValue(register, builder.addr(start), builder.addr(end),
						BigInteger.valueOf(value));
		}
		finally {
			program.endTransaction(tx, true);
		}
	}
}
