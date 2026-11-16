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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Coverage for grm-ed6h: 6502 pop-return helpers. Hand-built minimal shapes after Metroid
 * {@code c376} ({@code LDA #$00 / STA $07a1,X / PLA / PLA / RTS}) and {@code c36b} (the same tail
 * behind a {@code BCC} to the shared RTS); no ROM bytes are copied.
 */
public class PopReturnHelperAnalyzerTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB freshProgram() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		return builder.getProgram();
	}

	private Boolean recognize(String bytes) throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", bytes, true);
		return PopReturnHelper.recognize(program, addr(0xc000));
	}

	@Test
	public void recognizesMetroidC376Shape() throws Exception {
		// LDA #$00 / STA $07a1,X / PLA / PLA / RTS
		assertEquals(Boolean.TRUE, recognize("a9 00 9d a1 07 68 68 60"));
	}

	@Test
	public void recognizesTsxInxInxTxs() throws Exception {
		// TSX / INX / INX / TXS / RTS
		assertEquals(Boolean.TRUE, recognize("ba e8 e8 9a 60"));
	}

	@Test
	public void recognizesBothArmsPopping() throws Exception {
		// BEQ +3 / PLA / PLA / RTS / PLA / PLA / RTS
		assertEquals(Boolean.TRUE, recognize("f0 03 68 68 60 68 68 60"));
	}

	@Test
	public void recognizesAJmpToASharedPopTail() throws Exception {
		// $c000: JMP $c010 ; $c010: PLA / PLA / RTS
		ProgramDB program = freshProgram();
		builder.setBytes("0xc010", "68 68 60", true);
		builder.setBytes("0xc000", "4c 10 c0", true);
		assertEquals(Boolean.TRUE, PopReturnHelper.recognize(program, addr(0xc000)));
	}

	@Test
	public void declinesMetroidC36bConditionalReturn() throws Exception {
		// STA $07a1,X / INX / CPX #$4f / BCC rts / LDA #$00 / PLA / PLA / rts: RTS
		// the BCC lands on the RTS with nothing popped: that path returns normally
		assertEquals(Boolean.FALSE, recognize("9d a1 07 e8 e0 4f 90 04 a9 00 68 68 60"));
	}

	@Test
	public void declinesAnOrdinaryRts() throws Exception {
		assertEquals(Boolean.FALSE, recognize("a9 00 60"));
	}

	@Test
	public void declinesBalancedPushPull() throws Exception {
		// PHA / PHA / PLA / PLA / RTS
		assertEquals(Boolean.FALSE, recognize("48 48 68 68 60"));
	}

	/** grm-0fzb: the JumpEngine's dispatched target returns to the caller's caller. */
	@Test
	public void recognizesTheJumpEngineIndirectJump() throws Exception {
		// PLA / STA $04 / PLA / STA $05 / JMP ($0006)
		assertEquals(Boolean.TRUE, recognize("68 85 04 68 85 05 6c 06 00"));
	}

	/** db3 db4c shape: PLA/STA lo, PLA/STA hi, then push the address back plus 2. */
	private static final String SKIP2 =
		"68 85 31 68 85 32 a5 31 18 69 02 a8 a5 32 69 00 48 98 48 60";

	/** grm-tysk: pop, advance by the two inline bytes, push back, RTS: returns to JSR+5. */
	@Test
	public void measuresAPopAdvancePushHelperAsSkipTwo() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", SKIP2, true);
		assertEquals(new PopReturnHelper.Unwind(0, 2, 0, false),
			new PopReturnHelper.Levels(program).of(addr(0xc000)));
	}

	/**
	 * grm-tysk, drmario b74b/b6c2: b74b advances its CALLER'S return address in place (TSX /
	 * LDA $0103,X / ... / STA $0103,X), so b6c2 = JSR b74b / JMP interpreter returns past its
	 * inline word -- with the interpreter, whose exits a static walk cannot reconcile, ASSUMED
	 * stack-neutral (owner ruling).
	 */
	@Test
	public void measuresAnInPlaceCallerRewriteAndAnAssumedTail() throws Exception {
		ProgramDB program = freshProgram();
		// TSX / LDA $0103,X / STA $05 / LDA $0104,X / STA $06 / CLC / LDA #2 / ADC $05 /
		// STA $0103,X / LDA #0 / ADC $06 / STA $0104,X / RTS
		builder.setBytes("0xc000",
			"ba bd 03 01 85 05 bd 04 01 85 06 18 a9 02 65 05 9d 03 01 a9 00 65 06 9d 04 01 60",
			true);
		// interpreter stand-in whose exits disagree: BEQ +3 / PLA / PLA / RTS / RTS
		builder.setBytes("0xc200", "f0 03 68 68 60 60", true);
		// b6c2: JSR $c000 / JMP $c200
		builder.setBytes("0xc100", "20 00 c0 4c 00 c2", true);
		PopReturnHelper.Levels levels = new PopReturnHelper.Levels(program);
		assertEquals(new PopReturnHelper.Unwind(0, 0, 2, false), levels.of(addr(0xc000)));
		assertTrue(levels.of(addr(0xc200)).declined());
		assertEquals(new PopReturnHelper.Unwind(0, 2, 0, true), levels.of(addr(0xc100)));
	}

	/** Without a rewritten return address, a tail jump into unmeasurable code stays a decline. */
	@Test
	public void noAssumptionWithoutARewrite() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc200", "f0 03 68 68 60 60", true);
		builder.setBytes("0xc100", "a9 00 4c 00 c2", true);
		assertTrue(new PopReturnHelper.Levels(program).of(addr(0xc100)).declined());
	}

	/** An RTS through a COPY of the return address pushed higher leaves the stack unbalanced. */
	@Test
	public void declinesAnUnbalancedCopyReturn() throws Exception {
		// PLA / STA $31 / PLA / PHA / LDA $31 / PHA / ... push copy again: PHA hi / PHA lo / RTS
		// simplified: PLA / TAY / PLA / PHA / TYA / PHA / PHA(junk) ... RTS at depth 1 via copy
		assertEquals(Boolean.FALSE, recognize("68 a8 68 48 98 48 48 48 68 68 a9 00 48 60"));
	}

	/** The analyzer re-points the JSR past the inline word, lays it as data, decodes the rest. */
	@Test
	public void analyzerResumesPastInlineBytes() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", SKIP2, true);
		// e000: JSR $c000 / .word $1234 / e005: LDA #5 / RTS
		builder.setBytes("0xe000", "20 00 c0 34 12 a9 05 60", false);
		builder.disassemble("0xe000", 3, false);
		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe000), addr(0xe002)), TaskMonitor.DUMMY, new MessageLog()));
		assertEquals(addr(0xe005), instrAt(program, 0xe000).getFallThrough());
		assertNotNull("the inline word is data", program.getListing().getDefinedDataAt(addr(0xe003)));
		assertNotNull("the resume code is decoded", instrAt(program, 0xe005));
		assertNotNull(instrAt(program, 0xe007));
	}

	/** grm-0fzb, dbz_saiyan c9c2: pop, read the inline bytes, jump on; the trailing RTS is dead. */
	@Test
	public void recognizesTheFarCallTrampoline() throws Exception {
		// STA $1e / PLA / STA $19 / PLA / STA $1a / LDY #1 / LDA ($19),Y / STA $1b / JMP ($001b)
		// / RTS
		assertEquals(Boolean.TRUE,
			recognize("85 1e 68 85 19 68 85 1a a0 01 b1 19 85 1b 6c 1b 00 60"));
	}

	@Test
	public void declinesAnIndirectJumpThatPoppedNothing() throws Exception {
		// LDA #0 / JMP ($0006): a plain tail dispatch, not evidence of anything
		assertEquals(Boolean.FALSE, recognize("a9 00 6c 06 00"));
	}

	/** grm-0fzb (owner): a double pop discards two caller frames. */
	@Test
	public void measuresADoublePopAsLevelTwo() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", "68 68 68 68 60", true);
		assertEquals(2, new PopReturnHelper.Levels(program).of(addr(0xc000)).level());
	}

	@Test
	public void declinesAnOddPop() throws Exception {
		// PLA / PLA / PLA / RTS
		assertEquals(Boolean.FALSE, recognize("68 68 68 60"));
	}

	/**
	 * Unwinding composes through calls: a JSR to a level-2 helper at depth 0 leaves its caller
	 * at level 1, and a far-call stub (JSR level-1 helper + inline bytes) is level 0.
	 */
	@Test
	public void levelsComposeThroughCalls() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", "68 68 68 68 60", true);
		builder.setBytes("0xc100", "20 00 c0", true);
		builder.setBytes("0xc200", "68 68 60", true);
		builder.setBytes("0xc300", "20 00 c2 0c 13 80", false);
		builder.disassemble("0xc300", 3, false);
		PopReturnHelper.Levels levels = new PopReturnHelper.Levels(program);
		assertEquals(1, levels.of(addr(0xc100)).level());
		assertEquals(PopReturnHelper.Unwind.NORMAL, levels.of(addr(0xc300)));
	}

	@Test
	public void declinesAnUntrackedTxs() throws Exception {
		// LDX #$ff / TXS / RTS (a stack reset, not a pop)
		assertEquals(Boolean.FALSE, recognize("a2 ff 9a 60"));
	}

	/** The dodge/smb3 regression: base-space bytes of a banked window are not trusted. */
	@Test
	public void declinesAHelperInTheBaseCopyOfABankedWindow() throws Exception {
		builder = newBuilder("Banked", LANG);
		builder.createMemory("PRG_LO", "0x8000", 0x4000);
		builder.createMemory("PRG_FIXED", "0xc000", 0x4000);
		builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000);
		ProgramDB program = builder.getProgram();
		builder.setBytes("0x8100", "68 68 60", true);
		assertEquals(Boolean.FALSE, PopReturnHelper.recognize(program, addr(0x8100)));
		// the fixed part of the same map is still trusted
		builder.setBytes("0xc100", "68 68 60", true);
		assertEquals(Boolean.TRUE, PopReturnHelper.recognize(program, addr(0xc100)));
	}

	@Test
	public void inconclusiveWhenAPathIsNotYetDisassembled() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", "4c 10 c0", true);
		builder.setBytes("0xc010", "68 68 60", false);
		inTx(program, "clear", () -> program.getListing()
				.clearCodeUnits(addr(0xc010), addr(0xc012), false));
		assertNull(PopReturnHelper.recognize(program, addr(0xc000)));
	}

	/** The bead's acceptance shape: e5dd JSR $c376, then data that decodes as JSR $A29E. */
	@Test
	public void analyzerStopsFallThroughAndClearsTheFalseDecode() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc376", "a9 00 9d a1 07 68 68 60", true);
		builder.setBytes("0xe5dd", "20 76 c3 20 9e a2 60", true);
		builder.setBytes("0xa29e", "60", true);
		assertNotNull("precondition: the false decode exists", instrAt(program, 0xe5e0));

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe5dd), addr(0xe5e3)), TaskMonitor.DUMMY, new MessageLog()));

		assertNull("no instruction at e5e0", instrAt(program, 0xe5e0));
		for (Reference ref : program.getReferenceManager().getReferencesTo(addr(0xa29e))) {
			assertFalse("no A29E ref from e5e0", ref.getFromAddress().equals(addr(0xe5e0)));
		}
		Function helper = program.getFunctionManager().getFunctionAt(addr(0xc376));
		assertNotNull(helper);
		assertFalse("the helper returns to its caller's caller: not no-return (grm-0fzb)",
			helper.hasNoReturn());
		assertNull(instrAt(program, 0xe5dd).getFallThrough());
	}

	/** Code after the JSR that something else branches into is real and must stay. */
	@Test
	public void analyzerKeepsAFallThroughThatIsABranchTarget() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc376", "68 68 60", true);
		// e000: BEQ $e005 / JSR $c376 / e005: RTS
		builder.setBytes("0xe000", "f0 03 20 76 c3 60", true);

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe000), addr(0xe005)), TaskMonitor.DUMMY, new MessageLog()));

		assertNull(instrAt(program, 0xe002).getFallThrough());
		assertNotNull("branch target kept", instrAt(program, 0xe005));
	}

	/** A conditional pop-return helper is left alone: its JSR keeps its fall-through. */
	@Test
	public void analyzerLeavesConditionalHelpersAlone() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc36b", "9d a1 07 e8 e0 4f 90 04 a9 00 68 68 60", true);
		builder.setBytes("0xe000", "20 6b c3 60", true);

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe000), addr(0xe003)), TaskMonitor.DUMMY, new MessageLog()));

		assertNotNull(instrAt(program, 0xe000).getFallThrough());
		assertNotNull(instrAt(program, 0xe003));
	}

	/**
	 * grm-hf5h.12, dbz_saiyan c405 JSR c2ad: a far-call STUB (JSR helper + inline data) returns to
	 * its own caller, because the helper pops only the stub's return address. The stub's own JSR
	 * stops (its inline bytes are not code); the stub may become a thunk of the helper, which is
	 * harmless now that the helper is never no-return (grm-0fzb).
	 */
	@Test
	public void aStubAroundAHelperStillReturnsToItsCaller() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc9c2", "68 68 60", true);
		// stub: JSR c9c2 / .byte 0c 13 80
		builder.setBytes("0xc2ad", "20 c2 c9 0c 13 80", true);
		// caller: JSR c2ad / LDA #5 / RTS
		builder.setBytes("0xc405", "20 ad c2 a9 05 60", true);

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "functions", () -> {
			new CreateFunctionCmd(addr(0xc2ad)).applyTo(program);
			new CreateFunctionCmd(addr(0xc405)).applyTo(program);
		});
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xc2ad), addr(0xc40a)), TaskMonitor.DUMMY, new MessageLog()));

		assertNull("the stub's JSR stops", instrAt(program, 0xc2ad).getFallThrough());
		assertNull("the stub's inline bytes are not code", instrAt(program, 0xc2b0));
		assertNotNull("the stub's caller keeps its fall-through",
			instrAt(program, 0xc405).getFallThrough());
		assertNotNull(instrAt(program, 0xc408));
		Function stub = program.getFunctionManager().getFunctionAt(addr(0xc2ad));
		assertNotNull(stub);
		assertFalse(stub.hasNoReturn());
	}

	/**
	 * grm-0fzb: stock got there first (dbz2 d136). The helper's flag is cleared, and the stub's
	 * caller, stranded through the thunk, gets its fall-through back and disassembled.
	 */
	@Test
	public void undoesAStaleNoReturnAndRestoresTheStrandedCaller() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc9c2", "68 68 60", true);
		builder.setBytes("0xc2ad", "20 c2 c9 0c 13 80", false);
		builder.disassemble("0xc2ad", 3, false);
		builder.setBytes("0xc405", "20 ad c2 a9 05 60", false);
		builder.disassemble("0xc405", 3, false);
		inTx(program, "stock no-return", () -> {
			new CreateFunctionCmd(addr(0xc9c2)).applyTo(program);
			program.getFunctionManager().getFunctionAt(addr(0xc9c2)).setNoReturn(true);
			instrAt(program, 0xc2ad).setFlowOverride(FlowOverride.CALL_RETURN);
			new CreateFunctionCmd(addr(0xc2ad)).applyTo(program);
			instrAt(program, 0xc405).setFlowOverride(FlowOverride.CALL_RETURN);
			new CreateFunctionCmd(addr(0xc405)).applyTo(program);
		});
		assertTrue("precondition: the stub is a thunk sharing the flag",
			program.getFunctionManager().getFunctionAt(addr(0xc2ad)).hasNoReturn());
		assertNull("precondition: nothing after the stranded call", instrAt(program, 0xc408));

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xc2ad), addr(0xc2af)), TaskMonitor.DUMMY, new MessageLog()));

		assertFalse(program.getFunctionManager().getFunctionAt(addr(0xc9c2)).hasNoReturn());
		assertFalse(program.getFunctionManager().getFunctionAt(addr(0xc2ad)).hasNoReturn());
		assertNull("the stub's own JSR stays stopped", instrAt(program, 0xc2ad).getFallThrough());
		assertNotNull("the stranded caller falls through again",
			instrAt(program, 0xc405).getFallThrough());
		assertNotNull("and the code after it is disassembled", instrAt(program, 0xc408));
	}

	/** A genuinely non-returning routine (stack reset) is never unflagged. */
	@Test
	public void leavesAStackResetNoReturnAlone() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc200", "68 68 60", true);
		// c000: LDX #$ff / TXS / JSR $c200 -- a reset routine that is itself the helper's caller
		builder.setBytes("0xc000", "a2 ff 9a 20 00 c2", true);
		inTx(program, "flag", () -> {
			new CreateFunctionCmd(addr(0xc000)).applyTo(program);
			program.getFunctionManager().getFunctionAt(addr(0xc000)).setNoReturn(true);
		});
		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xc000), addr(0xc005)), TaskMonitor.DUMMY, new MessageLog()));
		assertTrue(program.getFunctionManager().getFunctionAt(addr(0xc000)).hasNoReturn());
	}

	private ghidra.program.model.listing.Instruction instrAt(ProgramDB program, long a) {
		return program.getListing().getInstructionAt(addr(a));
	}
}
