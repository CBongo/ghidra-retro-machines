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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.CalleeRegisterSummary.AbandonReason;
import retromachines.CalleeRegisterSummary.Memo;
import retromachines.CalleeRegisterSummary.StackAssumption;
import retromachines.CalleeRegisterSummary.StackDiscipline;
import retromachines.CalleeRegisterSummary.Summary;

/**
 * Bead grm-mej.11: {@link CalleeRegisterSummary} over hand-assembled routines. Every scenario
 * runs on the stock {@code 6502:LE:16:default} language AND on the repo's custom variants
 * ({@code 6502:LE:16:undoc}, {@code 6510:LE:16:default}; the same set
 * {@code PcodeConstantSemanticsDifferentialTest} uses) -- the summary reads raw p-code, so a
 * language whose stack or register p-code differs must not change an answer.
 * <p>
 * Layout: {@code $0000} zero page, {@code $0100-$07FF} RAM, {@code $8000-$BFFF} "PRG", and a
 * separate {@code $C000-$FFFF} "FIX" block. Nothing is banked unless a test makes it so.
 */
public class CalleeRegisterSummaryProgramTest extends AbstractBundledLanguageTest {

	private static final String[] LANGUAGES =
		{ "6502:LE:16:default", "6502:LE:16:undoc", "6510:LE:16:default" };

	private ProgramBuilder builder;
	private ProgramDB program;

	@After
	public void dispose() {
		if (builder != null) {
			builder.dispose();
			builder = null;
		}
	}

	private interface Scenario {
		void run() throws Exception;
	}

	/** Runs {@code body} on a fresh program for every language, naming the language on failure. */
	private void eachLanguage(Scenario body) throws Exception {
		for (String id : LANGUAGES) {
			dispose();
			build(id);
			try {
				body.run();
			}
			catch (AssertionError e) {
				throw new AssertionError("[" + id + "] " + e.getMessage(), e);
			}
		}
	}

	private void build(String languageId) throws Exception {
		builder = new ProgramBuilder("Test", languageId);
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x4000);
		builder.createMemory("FIX", "0xC000", 0x4000);
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

	/** Writes {@code hex} at {@code addr} and disassembles exactly those bytes (no flow chasing). */
	private void code(String addr, String hex) throws Exception {
		builder.setBytes(addr, hex, false);
		builder.disassemble(addr, hex.replace(" ", "").length() / 2, false);
	}

	private Summary summarize(String addr) {
		return summarize(addr, new Memo());
	}

	private Summary summarize(String addr, Memo memo) {
		return CalleeRegisterSummary.summarize(program, builder.addr(addr), memo);
	}

	private static void assertPreserves(Summary s, boolean a, boolean x, boolean y) {
		assertFalse("abandoned: " + s, s.isAbandoned());
		assertEquals("A in " + s, a, s.preserves('A'));
		assertEquals("X in " + s, x, s.preserves('X'));
		assertEquals("Y in " + s, y, s.preserves('Y'));
	}

	private static void assertAbandoned(Summary s, AbandonReason reason) {
		assertTrue("expected abandon, got " + s, s.isAbandoned());
		assertEquals(s.toString(), reason, s.reason());
		assertFalse(s.preserves('A') || s.preserves('X') || s.preserves('Y'));
	}

	// ------------------------------------------------------------------
	// Preservation shapes
	// ------------------------------------------------------------------

	/** The blmaster e61b shape: save X and Y on the stack, call twice (one conditional), restore. */
	@Test
	public void saveRestoreBodyPreservesXandYButNotA() throws Exception {
		eachLanguage(() -> {
			code("0x8100", "a9 01 a2 02 a0 03 60"); // stub: LDA #1 / LDX #2 / LDY #3 / RTS
			code("0x8200", "a9 04 a2 05 a0 06 60"); // stub
			code("0x8000", "8a 48 98 48"); // TXA / PHA / TYA / PHA
			code("0x8004", "20 00 81"); // JSR $8100
			code("0x8007", "d0 03"); // BNE $800C
			code("0x8009", "20 00 82"); // JSR $8200
			code("0x800c", "68 a8 68 aa 60"); // PLA / TAY / PLA / TAX / RTS
			Summary s = summarize("0x8000");
			assertPreserves(s, false, true, true);
			assertTrue(s.disciplines().contains(StackDiscipline.CROSSED_CALL_IS_STACK_NEUTRAL));
			assertTrue("no indirect store in the body", s.assumptions().isEmpty());
		});
	}

	@Test
	public void emptyRoutinePreservesEverything() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "60");
			Summary s = summarize("0x8000");
			assertPreserves(s, true, true, true);
			assertTrue(s.disciplines().isEmpty());
		});
	}

	@Test
	public void untouchedRegistersArePreserved() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "a9 05 60"); // LDA #5 / RTS
			assertPreserves(summarize("0x8000"), false, true, true);
			code("0x8010", "e8 60"); // INX / RTS
			assertPreserves(summarize("0x8010"), true, false, true);
			code("0x8020", "aa 60"); // TAX / RTS -- copies A into X; A itself still holds
			assertPreserves(summarize("0x8020"), true, false, true);
		});
	}

	/** PHA / PLA round trip through a stack slot keeps the entry token. */
	@Test
	public void pushPullRoundTripKeepsEntryToken() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "48 a9 07 68 60"); // PHA / LDA #7 / PLA / RTS
			assertPreserves(summarize("0x8000"), true, true, true);
		});
	}

	@Test
	public void nestedCompositionKeepsWhatTheCalleePreserves() throws Exception {
		eachLanguage(() -> {
			// g: TXA / PHA / LDX #1 / LDY #2 / PLA / TAX / RTS -- preserves X only (A = old X)
			code("0x8100", "8a 48 a2 01 a0 02 68 aa 60");
			assertPreserves(summarize("0x8100"), false, true, false);
			code("0x8000", "20 00 81 60"); // JSR g / RTS
			assertPreserves(summarize("0x8000"), false, true, false);
			code("0x8010", "a2 09 20 00 81 60"); // LDX #9 / JSR g / RTS -- X now a constant
			assertPreserves(summarize("0x8010"), false, false, false);
		});
	}

	@Test
	public void tailJumpIsWalkedInlineInTheSameFrame() throws Exception {
		eachLanguage(() -> {
			code("0x8100", "a2 01 60"); // LDX #1 / RTS
			code("0x8000", "4c 00 81"); // JMP $8100
			assertPreserves(summarize("0x8000"), true, false, true);
			code("0x8200", "60");
			code("0x8010", "4c 00 82"); // JMP $8200 (a bare RTS)
			assertPreserves(summarize("0x8010"), true, true, true);
		});
	}

	// ------------------------------------------------------------------
	// Control flow / fixpoint
	// ------------------------------------------------------------------

	@Test
	public void zeroNetStackLoopConverges() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "48 68 d0 fc 60"); // loop: PHA / PLA / BNE loop / RTS
			assertPreserves(summarize("0x8000"), true, true, true);
		});
	}

	@Test
	public void agreeingDiamondJoinsCleanly() throws Exception {
		eachLanguage(() -> {
			// BEQ else / PHA / JMP join / else: PHA / join: PLA / RTS
			code("0x8000", "f0 04 48 4c 07 80 48 68 60");
			assertPreserves(summarize("0x8000"), true, true, true);
		});
	}

	@Test
	public void disagreeingArmsMakeRegisterTop() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "f0 02 a2 01 60"); // BEQ rts / LDX #1 / rts: RTS
			assertPreserves(summarize("0x8000"), true, false, true);
		});
	}

	// ------------------------------------------------------------------
	// ABANDON cases
	// ------------------------------------------------------------------

	@Test
	public void txsAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "a2 ff 9a 60"); // LDX #$FF / TXS / RTS
			assertAbandoned(summarize("0x8000"), AbandonReason.SP_PARTIAL_WRITE);
		});
	}

	@Test
	public void tsxAloneDoesNotAbandon() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "ba 60"); // TSX / RTS -- reads S, X becomes unknown
			assertPreserves(summarize("0x8000"), true, false, true);
		});
	}

	@Test
	public void stackDepthMismatchAtAJoinAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "f0 01 48 68 60"); // BEQ j / PHA / j: PLA / RTS
			assertAbandoned(summarize("0x8000"), AbandonReason.JOIN_STACK_MISMATCH);
		});
	}

	@Test
	public void netPushAtRtsAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "48 48 60"); // PHA / PHA / RTS -- push-then-RTS dispatch
			assertAbandoned(summarize("0x8000"), AbandonReason.BAD_RETURN_STACK);
			code("0x8010", "68 60"); // PLA / RTS -- pops into the return address
			assertAbandoned(summarize("0x8010"), AbandonReason.BAD_RETURN_STACK);
		});
	}

	@Test
	public void writeToReturnAddressSlotAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "68 48 60"); // PLA / PHA / RTS -- rewrites the low return byte
			assertAbandoned(summarize("0x8000"), AbandonReason.WRITES_CALLER_FRAME);
		});
	}

	@Test
	public void rtiAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "40");
			assertAbandoned(summarize("0x8000"), AbandonReason.RTI);
		});
	}

	@Test
	public void brkAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "00 ea 60");
			assertAbandoned(summarize("0x8000"), AbandonReason.BRK);
		});
	}

	@Test
	public void indirectJumpAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "6c 34 12"); // JMP ($1234)
			assertAbandoned(summarize("0x8000"), AbandonReason.BRANCH_INDIRECT);
		});
	}

	@Test
	public void undisassembledBranchTargetAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "d0 7e 60"); // BNE $8080 (no code there) / RTS
			assertAbandoned(summarize("0x8000"), AbandonReason.UNDISASSEMBLED);
		});
	}

	@Test
	public void undisassembledEntryAbandons() throws Exception {
		eachLanguage(() -> assertAbandoned(summarize("0x8000"), AbandonReason.UNDISASSEMBLED));
	}

	@Test
	public void routineThatNeverReturnsAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "4c 00 80"); // JMP self
			assertAbandoned(summarize("0x8000"), AbandonReason.NO_RETURN);
		});
	}

	// ------------------------------------------------------------------
	// Stores
	// ------------------------------------------------------------------

	@Test
	public void constantStoreIntoTheStackAbandonsButBelowTheFloorDoesNot() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "8d 50 01 60"); // STA $0150 -- above the $0140 floor
			assertAbandoned(summarize("0x8000"), AbandonReason.STORE_ALIASES_STACK);
			code("0x8010", "8d 10 01 60"); // STA $0110 -- below the floor
			assertPreserves(summarize("0x8010"), true, true, true);
			code("0x8020", "85 20 8e 00 20 60"); // STA $20 / STX $2000 -- plain stores
			assertPreserves(summarize("0x8020"), true, true, true);
		});
	}

	@Test
	public void indexedStoreWindowOverTheStackAbandons() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "9d 00 01 60"); // STA $0100,X -- window $0100-$01FF
			assertAbandoned(summarize("0x8000"), AbandonReason.STORE_ALIASES_STACK);
			code("0x8010", "9d 00 02 60"); // STA $0200,X -- clear of the stack
			assertPreserves(summarize("0x8010"), true, true, true);
			code("0x8020", "95 00 60"); // STA $00,X -- zero page wraps, stays in page 0
			assertPreserves(summarize("0x8020"), true, true, true);
			code("0x8030", "ba 9d 00 02 60"); // TSX / STA $0200,X -- still just the window
			assertPreserves(summarize("0x8030"), true, false, true);
			code("0x8040", "99 80 00 60"); // STA $0080,Y -- window $0080-$017F reaches $0140+
			assertAbandoned(summarize("0x8040"), AbandonReason.STORE_ALIASES_STACK);
		});
	}

	/** Owner ruling O3: a true indirect store is assumed not to hit the stack, and says so. */
	@Test
	public void indirectStoreIsAssumedNotToHitTheStackAndRecordsIt() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "91 10 60"); // STA ($10),Y / RTS
			Summary s = summarize("0x8000");
			assertPreserves(s, true, true, true);
			assertTrue(s.assumptions()
					.contains(StackAssumption.INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME));
			code("0x8010", "81 10 60"); // STA ($10,X) / RTS
			Summary s2 = summarize("0x8010");
			assertPreserves(s2, true, true, true);
			assertTrue(s2.assumptions()
					.contains(StackAssumption.INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME));
		});
	}

	@Test
	public void indirectStoreAssumptionPropagatesThroughComposition() throws Exception {
		eachLanguage(() -> {
			code("0x8100", "91 10 60");
			code("0x8000", "20 00 81 60"); // JSR g / RTS
			Summary s = summarize("0x8000");
			assertPreserves(s, true, true, true);
			assertTrue(s.assumptions()
					.contains(StackAssumption.INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME));
		});
	}

	// ------------------------------------------------------------------
	// Nested calls: unknown callees, recursion, caps
	// ------------------------------------------------------------------

	@Test
	public void unresolvedCalleeClobbersAllButCallersOwnRestoreStillHolds() throws Exception {
		eachLanguage(() -> {
			// TXA / PHA / JSR $8F00 (no code) / PLA / TAX / RTS
			code("0x8000", "8a 48 20 00 8f 68 aa 60");
			Summary s = summarize("0x8000");
			assertPreserves(s, false, true, false);
			assertTrue(s.disciplines().contains(StackDiscipline.CROSSED_CALL_IS_STACK_NEUTRAL));
		});
	}

	@Test
	public void abandonedCalleeIsAnUnknownCalleeNotAnAbandonedCaller() throws Exception {
		eachLanguage(() -> {
			code("0x8100", "a2 ff 9a 60"); // TXS -- abandons
			code("0x8000", "8a 48 20 00 81 68 aa 60");
			assertPreserves(summarize("0x8000"), false, true, false);
		});
	}

	@Test
	public void calleeInABankedWindowFromOutsideItsBlockIsUnknown() throws Exception {
		eachLanguage(() -> {
			// An overlay over PRG makes PRG a banked window. FIX (not banked) calls into it.
			builder.createOverlayMemory("PRG_B1", "0x8000", 0x100);
			code("0x9000", "60"); // a bare RTS in the window: would preserve Y if looked into
			code("0xc000", "8a 48 20 00 90 68 aa 60"); // TXA/PHA/JSR $9000/PLA/TAX/RTS
			Summary banked = summarize("0xc000");
			assertPreserves(banked, false, true, false);
			// Control: the same body calling a bare RTS inside FIX keeps Y.
			code("0xc100", "60");
			code("0xc200", "8a 48 20 00 c1 68 aa 60");
			assertPreserves(summarize("0xc200"), false, true, true);
		});
	}

	@Test
	public void tailJumpIntoABankedWindowFromOutsideAbandons() throws Exception {
		eachLanguage(() -> {
			builder.createOverlayMemory("PRG_B1", "0x8000", 0x100);
			code("0x9000", "60");
			code("0xc000", "4c 00 90"); // JMP $9000
			assertAbandoned(summarize("0xc000"), AbandonReason.BANKED_TRANSFER);
		});
	}

	@Test
	public void overlayImagesAreSummarizedSeparately() throws Exception {
		eachLanguage(() -> {
			MemoryBlock b1 = builder.createOverlayMemory("PRG_B1", "0x8000", 0x100);
			MemoryBlock b2 = builder.createOverlayMemory("PRG_B2", "0x8000", 0x100);
			Address e1 = b1.getStart();
			Address e2 = b2.getStart();
			assertNotEquals(e1, e2);
			code(e1.toString(), "60"); // bank 1: bare RTS
			code(e2.toString(), "a2 01 60"); // bank 2: LDX #1 / RTS
			Memo memo = new Memo();
			Summary s1 = CalleeRegisterSummary.summarize(program, e1, memo);
			Summary s2 = CalleeRegisterSummary.summarize(program, e2, memo);
			assertPreserves(s1, true, true, true);
			assertPreserves(s2, true, false, true);
			assertEquals("one memo entry per overlay image", 2, memo.size());
		});
	}

	@Test
	public void callWithinOneOverlayImageResolvesInThatImage() throws Exception {
		eachLanguage(() -> {
			MemoryBlock b1 = builder.createOverlayMemory("PRG_B1", "0x8000", 0x200);
			Address base = b1.getStart();
			Address callee = base.getAddressSpace().getAddress(0x8100);
			code(callee.toString(), "a2 01 60"); // LDX #1 / RTS
			code(base.toString(), "20 00 81 60"); // JSR $8100 / RTS -- same image
			assertPreserves(CalleeRegisterSummary.summarize(program, base, new Memo()), true,
				false, true);
		});
	}

	@Test
	public void recursionTerminatesAndClobbers() throws Exception {
		eachLanguage(() -> {
			code("0x8000", "20 00 80 60"); // f: JSR f / RTS
			Memo memo = new Memo();
			assertPreserves(summarize("0x8000", memo), false, false, false);
			// mutual recursion: g: JSR h / RTS ; h: JSR g / RTS
			code("0x8100", "20 10 81 60");
			code("0x8110", "20 00 81 60");
			assertPreserves(summarize("0x8100"), false, false, false);
			assertPreserves(summarize("0x8110"), false, false, false);
		});
	}

	/** {@code MAX_INSTRUCTIONS} distinct instructions is the largest accepted entry. */
	@Test
	public void instructionCapBoundary() throws Exception {
		eachLanguage(() -> {
			int n = CalleeRegisterSummary.MAX_INSTRUCTIONS;
			StringBuilder ok = new StringBuilder();
			for (int i = 0; i < n - 1; i++) {
				ok.append("ea ");
			}
			ok.append("60"); // n instructions in all
			code("0x8000", ok.toString());
			assertPreserves(summarize("0x8000"), true, true, true);

			StringBuilder over = new StringBuilder();
			for (int i = 0; i < n; i++) {
				over.append("ea ");
			}
			over.append("60"); // n + 1
			code("0xa000", over.toString());
			assertAbandoned(summarize("0xa000"), AbandonReason.INSTRUCTION_CAP);
		});
	}

	/** A chain of {@code MAX_NESTING} nested callees composes; one deeper is unknown. */
	@Test
	public void nestingCapBoundary() throws Exception {
		eachLanguage(() -> {
			int max = CalleeRegisterSummary.MAX_NESTING;
			assertTrue("deepest f_" + max + " is still summarized and preserves X",
				chainPreservesX(0x8000, max));
			assertFalse("one deeper is capped: unknown callee, X clobbered",
				chainPreservesX(0x8800, max + 1));
		});
	}

	/** f_0 -> f_1 -> ... -> f_k, f_k a bare RTS; whether f_0 preserves X. */
	private boolean chainPreservesX(int base, int k) throws Exception {
		for (int i = 0; i < k; i++) {
			int next = base + 0x10 * (i + 1);
			code(String.format("0x%x", base + 0x10 * i),
				String.format("20 %02x %02x 60", next & 0xFF, next >> 8));
		}
		code(String.format("0x%x", base + 0x10 * k), "60");
		Summary s = summarize(String.format("0x%x", base));
		assertFalse(s.toString(), s.isAbandoned());
		return s.preserves('X');
	}

	// ------------------------------------------------------------------
	// Real bytes: blmaster's switch helper e61b
	// ------------------------------------------------------------------

	/**
	 * Bytes of blmaster's {@code e61b..e650} (bank switch helper), copied verbatim from the
	 * listing ({@code dis6502.py blmaster o1c000@c000 e61b e650}), including the real
	 * {@code e63c} bank-write callee; {@code eb98} (a deferred-frame handler whose closure is
	 * banked) is stubbed because only e61b's own save/restore frame is under test.
	 */
	@Test
	public void blmasterE61bShapePreservesXAndY() throws Exception {
		eachLanguage(() -> {
			String bytes = BLMASTER_E61B_BYTES;
			assertNotNull(bytes);
			// FIX block is $C000-$FFFF; e61b lies in it. Stub every JSR target with a clobbering RTS.
			code("0xe61b", bytes);
			for (String stub : BLMASTER_STUB_TARGETS) {
				code(stub, "a9 00 a2 00 a0 00 60");
			}
			Summary s = summarize("0xe61b");
			assertPreserves(s, false, true, true);
		});
	}

	private static final String BLMASTER_E61B_BYTES =
		"85 db 8a 48 98 48 a9 40 85 12 a5 db 20 3c e6 a5 12 29 20 f0 03 20 98 eb " +
			"a9 00 85 12 68 a8 68 aa 60 " + // e61b..e63b
			"8d ff ff 4a 8d ff ff 4a 8d ff ff 4a 8d ff ff 4a 8d ff ff 60"; // e63c..e64f
	private static final String[] BLMASTER_STUB_TARGETS = { "0xeb98" };
}
