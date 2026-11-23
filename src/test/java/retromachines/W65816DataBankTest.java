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
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * grm-9nxj.32: {@link W65816DataBankAnalyzer}. Code at bank 0 ($8000-$8fff), WRAM at
 * $7E:0000-$1FFF, M=X=E=0 unless a test says otherwise.
 */
public class W65816DataBankTest extends AbstractProgramTest {

	private static final String LDA_1234 = "ad 34 12";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		MemoryBlock rom = builder.createMemory(".rom", "0x8000", 0x1000);
		builder.createMemory(".wram", "0x7e0000", 0x2000);
		program = builder.getProgram();
		setWritable(rom, false);
		inTx(program, "rom executable", () -> rom.setExecute(true));
		for (String f : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
			Register r = program.getLanguage().getRegister(f);
			inTx(program, "set " + f, () -> program.getProgramContext()
					.setValue(r, builder.addr("0x8000"), builder.addr("0x8fff"), BigInteger.ZERO));
		}
	}

	/** Lays code at {@code at} and makes a function over it. */
	private void lay(String at, String bytes, String name) throws Exception {
		builder.setBytes(at, bytes, false);
		int n = bytes.split(" ").length;
		builder.disassemble(at, n, false);
		Address start = addr(Long.decode(at));
		inTx(program, "function " + name, () -> program.getFunctionManager().createFunction(name,
			start, new AddressSet(start, start.add(n - 1)), SourceType.ANALYSIS));
	}

	private void analyze() throws Exception {
		W65816DataBankAnalyzer a = new W65816DataBankAnalyzer();
		assertTrue(a.canAnalyze(program));
		inTx(program, "analyze", () -> a.added(program,
			new AddressSet(addr(0x8000), addr(0x8fff)), TaskMonitor.DUMMY, new MessageLog()));
	}

	private Integer dbrAt(long at) {
		RegisterValue v = program.getProgramContext().getRegisterValue(
			program.getRegister("DBR"), addr(at));
		return v != null && v.hasValue() ? v.getUnsignedValue().intValue() : null;
	}

	private Reference dataRef(long at) {
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(at))) {
			if (r.isMemoryReference() && !r.getReferenceType().isFlow()) {
				return r;
			}
		}
		return null;
	}

	private String convention(long at) {
		return program.getFunctionManager().getFunctionAt(addr(at)).getCallingConventionName();
	}

	// ---- PLB sources ----

	@Test
	public void peaPlbPlbSetsDbrAndReferencesWram() throws Exception {
		lay("0x8000", "f4 7e 7e ab ab " + LDA_1234 + " 60", "F");   // PEA #$7e7e ; PLB ; PLB ; LDA
		analyze();
		assertNull("entry DBR is unknown", dbrAt(0x8000));
		assertNull("DBR is the OLD value while the first PLB executes", dbrAt(0x8003));
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8004));
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8005));
		Reference r = dataRef(0x8005);
		assertNotNull(r);
		assertEquals(addr(0x7e1234), r.getToAddress());
		assertEquals(RefType.READ, r.getReferenceType());
	}

	@Test
	public void peaBytesPullInPlbOrder() throws Exception {
		lay("0x8000", "f4 00 7f ab 60", "F");   // PEA #$7f00 ; PLB (low byte: 00)
		lay("0x8100", "f4 00 7f ab ab " + LDA_1234 + " 60", "G");   // ... ; PLB ; PLB (high: 7f)
		analyze();
		assertEquals(Integer.valueOf(0x00), dbrAt(0x8004));
		assertEquals(Integer.valueOf(0x7f), dbrAt(0x8105));
	}

	@Test
	public void phkPlbIsTheBankOfTheInstruction() throws Exception {
		lay("0x8000", "4b ab " + LDA_1234 + " 60", "F");
		analyze();
		assertEquals(Integer.valueOf(0), dbrAt(0x8002));
	}

	@Test
	public void aWrongBankReferenceIsReplacedAndAUserOneKept() throws Exception {
		lay("0x8000", "f4 7e 7e ab ab " + LDA_1234 + " 60", "F");
		lay("0x8100", "f4 7e 7e ab ab " + LDA_1234 + " 60", "G");
		inTx(program, "refs", () -> {
			var rm = program.getReferenceManager();
			rm.addMemoryReference(addr(0x8005), addr(0x001234), RefType.READ, SourceType.ANALYSIS, 0);
			rm.addMemoryReference(addr(0x8105), addr(0x001234), RefType.READ, SourceType.USER_DEFINED, 0);
		});
		analyze();
		int analyzed = 0;
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(0x8005))) {
			if (r.isMemoryReference()) {
				assertEquals(addr(0x7e1234), r.getToAddress());
				analyzed++;
			}
		}
		assertEquals(1, analyzed);
		boolean user = false;
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(0x8105))) {
			user |= r.getToAddress().equals(addr(0x001234));
		}
		assertTrue("the user's reference stays", user);
	}

	@Test
	public void eightBitLdaPhaPlb() throws Exception {
		lay("0x8000", "e2 20 a9 7e 48 ab " + LDA_1234 + " 60", "F");   // SEP #$20 ; LDA #$7e ; PHA ; PLB
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8006));
		assertEquals(addr(0x7e1234), dataRef(0x8006).getToAddress());
	}

	@Test
	public void sixteenBitLdaPhaPushesTwoBytes() throws Exception {
		lay("0x8000", "a9 7e 00 48 ab " + LDA_1234 + " 60", "F");   // LDA #$007e ; PHA ; PLB (low byte)
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8005));
	}

	@Test
	public void ldxPhxPlbUnderXWidth() throws Exception {
		lay("0x8000", "e2 10 a2 7e da ab " + LDA_1234 + " 60", "F");   // SEP #$10 ; LDX #$7e ; PHX ; PLB
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8006));
	}

	@Test
	public void unknownPulledByteLeavesDbrUnknown() throws Exception {
		lay("0x8000", "08 ab " + LDA_1234 + " 60", "F");   // PHP ; PLB
		analyze();
		assertNull(dbrAt(0x8002));
	}

	@Test
	public void mvnSetsDbrToTheDestinationBank() throws Exception {
		lay("0x8000", "54 7e 7f " + LDA_1234 + " 60", "F");   // MVN $7f,$7e (dest, src in the encoding)
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8003));
	}

	// ---- preservation, summaries, seeds ----

	@Test
	public void phbPlbBracketPreservesAndEarnsTheConvention() throws Exception {
		// PHB ; PEA #$7e7e ; PLB ; PLB ; LDA ; PLB ; RTS
		lay("0x8100", "8b f4 7e 7e ab ab " + LDA_1234 + " ab 60", "G");
		// PEA #$7e7e ; PLB ; PLB ; JSR G ; LDA
		lay("0x8000", "f4 7e 7e ab ab 20 00 81 " + LDA_1234 + " 60", "F");
		analyze();
		assertEquals("the callee keeps the caller's bank", Integer.valueOf(0x7e), dbrAt(0x8008));
		assertEquals(W65816DataBankAnalyzer.DBR_PRESERVED, convention(0x8100));
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8100));   // seeded from its only caller
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8106));
		assertEquals(addr(0x7e1234), dataRef(0x8106).getToAddress());
	}

	@Test
	public void calleeReturningConstantPassesItBack() throws Exception {
		lay("0x8100", "f4 7e 7e ab ab 60", "G");   // sets $7e and returns
		lay("0x8000", "20 00 81 " + LDA_1234 + " 60", "F");
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8003));
		assertTrue("G changes DBR, so no DBR-preserving prototype",
			!W65816DataBankAnalyzer.hasDbr(convention(0x8100)));
	}

	@Test
	public void calleeWithUnknownExitLosesDbr() throws Exception {
		lay("0x8100", "08 ab 60", "G");   // PHP ; PLB ; RTS : DBR = a status byte
		lay("0x8000", "f4 7e 7e ab ab 20 00 81 " + LDA_1234 + " 60", "F");
		analyze();
		assertNull(dbrAt(0x8008));
	}

	@Test
	public void mixedExitsAreExactForACallerThatAgreesWithTheConstant() throws Exception {
		lay("0x8100", "f0 02 4b ab 60", "G");   // BEQ over PHK/PLB: exits with entry DBR or 0
		lay("0x8000", "4b ab 20 00 81 " + LDA_1234 + " 60", "F");   // caller in bank 0
		lay("0x8200", "f4 7e 7e ab ab 20 00 81 " + LDA_1234 + " 60", "H");   // caller at $7e
		analyze();
		assertEquals(Integer.valueOf(0), dbrAt(0x8005));
		assertNull(dbrAt(0x8208));
		assertTrue(!W65816DataBankAnalyzer.hasDbr(convention(0x8100)));
	}

	@Test
	public void agreeingCallersSeedTheEntry() throws Exception {
		lay("0x8200", LDA_1234 + " 60", "H");
		lay("0x8000", "f4 7e 7e ab ab 20 00 82 60", "C1");
		lay("0x8100", "f4 7e 7e ab ab 20 00 82 60", "C2");
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8200));
		assertEquals(addr(0x7e1234), dataRef(0x8200).getToAddress());
	}

	@Test
	public void disagreeingCallersLeaveTheEntryUnknown() throws Exception {
		lay("0x8200", LDA_1234 + " 60", "H");
		lay("0x8000", "f4 7e 7e ab ab 20 00 82 60", "C1");
		lay("0x8100", "4b ab 20 00 82 60", "C2");   // DBR 0
		analyze();
		assertNull(dbrAt(0x8200));
	}

	@Test
	public void resetIsEnteredWithDbrZero() throws Exception {
		lay("0x8000", LDA_1234 + " 60", "F");
		inTx(program, "RESET", () -> {
			program.getSymbolTable().createLabel(addr(0x8000), "RESET", SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(addr(0x8000));
		});
		analyze();
		assertEquals(Integer.valueOf(0), dbrAt(0x8000));
	}

	@Test
	public void otherVectorsAreNotSeeded() throws Exception {
		lay("0x8000", LDA_1234 + " 60", "F");
		inTx(program, "NMI", () -> {
			program.getSymbolTable().createLabel(addr(0x8000), "NMI", SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(addr(0x8000));
		});
		analyze();
		assertNull(dbrAt(0x8000));
	}

	@Test
	public void jmpThunkReturnsWhatItsTargetReturns() throws Exception {
		lay("0x8200", "4c 00 83", "THUNK");   // JMP $8300
		lay("0x8300", "8b ab 60", "BODY");     // PHB ; PLB ; RTS : preserves
		lay("0x8000", "f4 7e 7e ab ab 20 00 82 " + LDA_1234 + " 60", "F");
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8008));
		assertEquals(W65816DataBankAnalyzer.DBR_PRESERVED, convention(0x8200));
	}

	@Test
	public void agreeingMergeKeepsDbrDisagreeingLosesIt() throws Exception {
		// PEA #$7e7e ; PLB ; PLB ; BEQ +1 ; NOP ; LDA ; RTS
		lay("0x8000", "f4 7e 7e ab ab f0 01 ea " + LDA_1234 + " 60", "F");
		// BEQ over a PLB that changes it: PEA #$7e7e ; PLB ; PLB ; BEQ +4 ; PEA #$7f7f ; PLB ; LDA
		lay("0x8100", "f4 7e 7e ab ab f0 04 f4 7f 7f ab " + LDA_1234 + " 60", "G");
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8008));
		assertNull(dbrAt(0x810b));
	}

	@Test
	public void dispatchHandlersInTheBodyAreStampedFromTheJump() throws Exception {
		// PEA #$7e7e ; PLB ; PLB ; JMP ($8100,X) | handler: LDA $1234 ; RTS
		lay("0x8000", "f4 7e 7e ab ab 7c 00 81 " + LDA_1234 + " 60", "F");
		inTx(program, "dispatch ref", () -> program.getReferenceManager().addMemoryReference(
			addr(0x8005), addr(0x8008), RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0));
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8008));
		assertEquals(addr(0x7e1234), dataRef(0x8008).getToAddress());
	}

	/** Sets a DBR value over [from, to] as a user would (no analyzer mark). */
	private void userDbr(long from, long to, int v) throws Exception {
		inTx(program, "user DBR", () -> program.getProgramContext().setValue(
			program.getRegister("DBR"), addr(from), addr(to), BigInteger.valueOf(v)));
	}

	@Test
	public void aStaleAnalyzerStampIsClearedWhereDbrIsNowUnknown() throws Exception {
		lay("0x8000", "08 ab " + LDA_1234 + " 60", "F");   // PLB of a status byte: unknown
		// A stamp the analyzer wrote on an earlier, better-informed run: value plus its mark.
		userDbr(0x8002, 0x8004, 0x7e);
		inTx(program, "mark", () -> {
			try {
				program.getUsrPropertyManager().createIntPropertyMap(
					W65816DataBankAnalyzer.STAMP_MAP).add(addr(0x8002), 0x7e);
			}
			catch (Exception e) {
				throw new AssertionError(e);
			}
		});
		analyze();
		assertNull(dbrAt(0x8002));
	}

	@Test
	public void aUserDbrAtAnEntrySeedsTheWalkAndIsNotRemoved() throws Exception {
		lay("0x8000", "4b ab 20 00 81 60", "C");   // calls G with DBR 0
		lay("0x8100", LDA_1234 + " 60", "G");
		userDbr(0x8100, 0x8103, 0x7e);
		analyze();
		assertEquals("the user's value beats the caller's", Integer.valueOf(0x7e), dbrAt(0x8100));
		assertEquals(addr(0x7e1234), dataRef(0x8100).getToAddress());
		analyze();   // re-analysis
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8100));
	}

	@Test
	public void aUserDbrMidFunctionSurvivesReanalysis() throws Exception {
		lay("0x8000", "08 ab " + LDA_1234 + " 60", "F");   // PLB of a status byte: unknown
		userDbr(0x8002, 0x8004, 0x7e);
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8002));
		assertEquals(addr(0x7e1234), dataRef(0x8002).getToAddress());
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8002));
	}

	@Test
	public void aUserDbrMidFunctionFeedsTheInstructionsAfterIt() throws Exception {
		lay("0x8000", "08 ab ea " + LDA_1234 + " 60", "F");   // PLB (unknown) ; NOP ; LDA
		userDbr(0x8002, 0x8002, 0x7e);   // the user says DBR is $7e from the NOP on
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8003));
	}

	// ---- grm-9nxj.42 ----

	@Test
	public void aSharedPlbRtsEpilogueReachedByJumpPullsTheJumpersPhb() throws Exception {
		// F: PHB ; PEA #$7f7f ; PLB ; PLB ; LDA $1234 ; JMP $8100 -> G: PLB ; RTS (its own function)
		lay("0x8000", "8b f4 7f 7f ab ab " + LDA_1234 + " 4c 00 81", "F");
		lay("0x8100", "ab 60", "G");
		// H: PEA #$7e7e ; PLB ; PLB ; JSR F ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "H");
		analyze();
		assertEquals(Integer.valueOf(0x7f), dbrAt(0x8006));
		assertEquals("F restores the caller's DBR through G", Integer.valueOf(0x7e),
			dbrAt(0x8208));
		assertEquals(addr(0x7e1234), dataRef(0x8208).getToAddress());
		assertEquals(W65816DataBankAnalyzer.DBR_PRESERVED, convention(0x8000));
	}

	@Test
	public void aDispatchIntoSharedEpiloguesExitsWithTheDispatchersPhb() throws Exception {
		// F: PHB ; PEA #$7f7f ; PLB ; PLB ; JMP ($8100,X) -> handler G: LDA $1234 ; PLB ; RTS
		lay("0x8000", "8b f4 7f 7f ab ab 7c 00 81", "F");
		lay("0x8200", LDA_1234 + " ab 60", "G");
		inTx(program, "dispatch ref", () -> program.getReferenceManager().addMemoryReference(
			addr(0x8006), addr(0x8200), RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0));
		// C: PEA #$7e7e ; PLB ; PLB ; JSR F ; LDA $1234 ; RTS
		lay("0x8300", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "C");
		analyze();
		assertEquals("the handler runs under the dispatcher's DBR", Integer.valueOf(0x7f),
			dbrAt(0x8200));
		assertEquals("F returns the caller's DBR through the handler's PLB",
			Integer.valueOf(0x7e), dbrAt(0x8308));
	}

	/**
	 * grm-9nxj.49 (FF3's script interpreter {@code $EE:7084}): F = PHP ; LDX #0 ;
	 * JMP ($8100,X), with two handlers in F's own body: one does its work and jumps back to the
	 * LDX (LDA $1234 ; JMP $8001), the other leaves (PLP ; RTS). Taken as a rule-A exit the
	 * dispatch leaves the PHP byte pushed and F's summary unknown; followed, every exit is the
	 * PLP / RTS, so F preserves DBR and C's LDA after the call is under $7e. (A single handler
	 * that ends in PLP / RTS is a shared epilogue, which grm-9nxj.42 already followed.)
	 */
	@Test
	public void aDispatchIntoTheRoutinesOwnBodyIsFollowedNotAnExit() throws Exception {
		lay("0x8000", "08 a2 00 00 7c 00 81 " + LDA_1234 + " 4c 01 80 28 60", "F");
		inTx(program, "dispatch refs", () -> {
			program.getReferenceManager().addMemoryReference(addr(0x8004), addr(0x8007),
				RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
			program.getReferenceManager().addMemoryReference(addr(0x8004), addr(0x800d),
				RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 1);
		});
		lay("0x8300", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "C");
		analyze();
		assertEquals("preserves",
			new W65816DataBankAnalyzer.CallSummaries(program).verdict(addr(0x8000)));
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8308));
	}

	@Test
	public void aTailJumpWithACallReturnOverrideIsATailExit() throws Exception {
		lay("0x8100", "4b ab 60", "G");        // PHK ; PLB ; RTS : returns bank $00
		lay("0x8000", "4c 00 81", "F");        // JMP G, overridden CALL_RETURN by Ghidra
		inTx(program, "override", () -> program.getListing().getInstructionAt(addr(0x8000))
				.setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN));
		// C: PEA #$7e7e ; PLB ; PLB ; JSR F ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "C");
		analyze();
		assertEquals("F returns what G returns", Integer.valueOf(0x00), dbrAt(0x8208));
	}

	@Test
	public void anRtlThatPullsBelowItsEntryDoesNotMakeTheHelperAnRtlRoutine() throws Exception {
		// F: PHB ; PEA #$7f7f ; PLB ; PLB ; JSR H ; PLB ; RTL
		lay("0x8000", "8b f4 7f 7f ab ab 20 00 81 ab 6b", "F");
		// H: BEQ +3 ; JMP $8009 (into F's PLB / RTL, for F's frame) ; RTS
		lay("0x8100", "f0 03 4c 09 80 60", "H");
		// C: PEA #$7e7e ; PLB ; PLB ; JSL F ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 22 00 80 00 " + LDA_1234 + " 60", "C");
		analyze();
		assertEquals("H returns by RTS for its JSR: F's stack is intact at its PLB",
			Integer.valueOf(0x7e), dbrAt(0x8209));
	}

	@Test
	public void phkJsrIntoAnRtlRoutineComesBack() throws Exception {
		lay("0x8100", "6b", "G");   // RTL
		// C: PEA #$7e7e ; PLB ; PLB ; PHK ; JSR G ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 4b 20 00 81 " + LDA_1234 + " 60", "C");
		analyze();
		assertEquals("G's RTL pulls the PHK byte and returns to the fall-through",
			Integer.valueOf(0x7e), dbrAt(0x8209));
	}

	@Test
	public void phbJsrIntoAnRtlRoutineHasNoFallThrough() throws Exception {
		// grm-9nxj.49 (FF3 ee74a4 PHB / JSR $0DBC): the RTL pulls the PHB byte as a bank, so it
		// does not come back here; walking on would leave the caller one byte short.
		lay("0x8100", "6b", "G");   // RTL
		// C: PEA #$7e7e ; PLB ; PLB ; PHB ; JSR G ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 8b 20 00 81 " + LDA_1234 + " 60", "C");
		analyze();
		assertNull("no DBR flows past a JSR whose RTL cannot return to it", dbrAt(0x8209));
	}

	@Test
	public void phkPerJmlIsAFarCallThatComesBack() throws Exception {
		lay("0x8100", "4b ab 6b", "G");   // PHK ; PLB ; RTL : returns bank $00
		// F: PHK ; PER +3 (pushes $8007) ; JML G ; [$8008] LDA $1234 ; RTS
		lay("0x8000", "4b 62 03 00 5c 00 81 00 " + LDA_1234 + " 60", "F");
		builder.disassemble("0x8008", 4, false);
		// C: PEA #$7e7e ; PLB ; PLB ; JSR F ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "C");
		analyze();
		assertEquals("G's RTL comes back to $8008 with G's bank", Integer.valueOf(0x00),
			dbrAt(0x8008));
		assertEquals("F returns G's bank, not an unknown one", Integer.valueOf(0x00),
			dbrAt(0x8208));
	}

	private void farCalls() throws Exception {
		W65816FarCallContinuationAnalyzer a = new W65816FarCallContinuationAnalyzer();
		assertTrue(a.canAnalyze(program));
		inTx(program, "far calls", () -> a.added(program,
			new AddressSet(addr(0x8000), addr(0x8fff)), TaskMonitor.DUMMY, new MessageLog()));
	}

	private int mAt(long at) {
		return program.getListing().getInstructionAt(addr(at))
				.getValue(program.getRegister("ctx_MF"), false).intValue();
	}

	@Test
	public void aFarCallContinuationIsDecodedAtTheCalleesWidthAndWalked() throws Exception {
		lay("0x8100", "e2 20 6b", "G");   // SEP #$20 ; RTL : returns with M=1
		// F: PHK ; PER +3 (pushes $8007) ; JML G ; then, undecoded, at $8008:
		// LDA #$7f (two bytes at M=1) ; PHA ; PLB ; RTS
		lay("0x8000", "4b 62 03 00 5c 00 81 00", "F");
		builder.setBytes("0x8008", "a9 7f 48 ab 60", false);
		// C: PEA #$7e7e ; PLB ; PLB ; JSR F ; LDA $1234 ; RTS
		lay("0x8200", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "C");
		farCalls();
		assertNotNull("the continuation is decoded",
			program.getListing().getInstructionAt(addr(0x8008)));
		assertEquals("at the width G returns with", 1, mAt(0x8008));
		assertEquals(2, program.getListing().getInstructionAt(addr(0x8008)).getLength());
		assertEquals("RTS", program.getListing().getInstructionAt(addr(0x800c)).getMnemonicString());
		analyze();
		assertEquals("F returns the bank its continuation sets", Integer.valueOf(0x7f),
			dbrAt(0x8208));
	}

	@Test
	public void aFarCallIntoACalleeOfMixedWidthIsNotDecoded() throws Exception {
		lay("0x8100", "f0 02 e2 20 6b", "G");   // BEQ +2 ; SEP #$20 ; RTL : M mixed on return
		lay("0x8000", "4b 62 03 00 5c 00 81 00", "F");
		builder.setBytes("0x8008", "a9 7f 48 ab 60", false);
		farCalls();
		assertNull(program.getListing().getInstructionAt(addr(0x8008)));
	}

	@Test
	public void aPushedAddressOtherThanTheFallThroughIsNotDecoded() throws Exception {
		lay("0x8100", "6b", "G");   // RTL
		lay("0x8000", "4b 62 04 00 5c 00 81 00", "F");   // PER +4: returns to $8009, not $8008
		builder.setBytes("0x8008", "ea ea ea 60", false);
		farCalls();
		assertNull(program.getListing().getInstructionAt(addr(0x8008)));
		assertNull(program.getListing().getInstructionAt(addr(0x8009)));
	}

	@Test
	public void aFarCallIntoAnRtsRoutineIsNotDecoded() throws Exception {
		lay("0x8100", "60", "G");   // RTS: a PHK / PER push would be pulled wrongly
		lay("0x8000", "4b 62 03 00 5c 00 81 00", "F");
		builder.setBytes("0x8008", "ea 60", false);
		farCalls();
		assertNull(program.getListing().getInstructionAt(addr(0x8008)));
	}

	@Test
	public void tdcPhaPlbTakesDpsLowByte() throws Exception {
		// SEP #$20 ; TDC ; PHA ; PLB ; LDA $1234 ; RTS, with DP = $007e stamped at the TDC
		lay("0x8000", "e2 20 7b 48 ab " + LDA_1234 + " 60", "F");
		inTx(program, "DP", () -> program.getProgramContext().setValue(program.getRegister("DP"),
			addr(0x8002), addr(0x8002), BigInteger.valueOf(0x007e)));
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8005));
	}

	@Test
	public void tdcWithNoKnownDpLeavesDbrUnknown() throws Exception {
		lay("0x8000", "e2 20 7b 48 ab " + LDA_1234 + " 60", "F");
		analyze();
		assertNull(dbrAt(0x8005));
	}

	@Test
	public void txaPhaPlbCarriesAnImmediateThroughX() throws Exception {
		// SEP #$30 ; LDX #$7e ; TXA ; PHA ; PLB ; LDA $1234 ; RTS
		lay("0x8000", "e2 30 a2 7e 8a 48 ab " + LDA_1234 + " 60", "F");
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8007));
	}

	// ---- conventions ----

	@Test
	public void conventionNamesCompose() {
		assertEquals("__dp_dbr_preserved", W65816DataBankAnalyzer.compose(true, true));
		assertEquals("__dp_preserved", W65816DataBankAnalyzer.compose(true, false));
		assertEquals("__dbr_preserved", W65816DataBankAnalyzer.compose(false, true));
		assertEquals("unknown", W65816DataBankAnalyzer.compose(false, false));
	}

	@Test
	public void bothVerdictsGiveTheCombinedPrototype() throws Exception {
		lay("0x8100", "60", "G");   // RTS: preserves everything
		lay("0x8000", "20 00 81 60", "F");
		W65816DirectPageAnalyzer dp = new W65816DirectPageAnalyzer();
		inTx(program, "dp", () -> dp.added(program, new AddressSet(addr(0x8000), addr(0x8fff)),
			TaskMonitor.DUMMY, new MessageLog()));
		assertEquals(W65816DirectPageAnalyzer.DP_PRESERVED, convention(0x8100));
		analyze();
		assertEquals(W65816DataBankAnalyzer.DP_DBR_PRESERVED, convention(0x8100));
		inTx(program, "dp again", () -> dp.added(program, new AddressSet(addr(0x8000), addr(0x8fff)),
			TaskMonitor.DUMMY, new MessageLog()));
		assertEquals("a rerun of the DP analyzer keeps the DBR half",
			W65816DataBankAnalyzer.DP_DBR_PRESERVED, convention(0x8100));
	}

	@Test
	public void aDbrChangerKeepsOnlyTheDpHalf() throws Exception {
		lay("0x8100", "4b ab 60", "G");   // PHK ; PLB ; RTS : DBR = 0 (constant), DP untouched
		lay("0x8000", "20 00 81 60", "F");
		W65816DirectPageAnalyzer dp = new W65816DirectPageAnalyzer();
		inTx(program, "dp", () -> dp.added(program, new AddressSet(addr(0x8000), addr(0x8fff)),
			TaskMonitor.DUMMY, new MessageLog()));
		analyze();
		assertEquals(W65816DirectPageAnalyzer.DP_PRESERVED, convention(0x8100));
	}

	// ---- callee drops its caller's arguments (grm-9nxj.46, FF3 $C2:5864) ----

	/**
	 * H sets DBR $7e and calls F; F pushes two argument words and calls P, which moves its return
	 * address over them ({@code LDA $01,S ; STA $05,S}), pulls four bytes and returns. F's stack
	 * is empty again at its RTS, so F preserves DBR and H's LDA after the call is under $7e.
	 */
	@Test
	public void calleeThatDropsItsArgumentsBalancesTheCaller() throws Exception {
		lay("0x8100", "a3 01 83 05 68 68 60", "P");
		lay("0x8000", "f4 11 11 f4 22 22 20 00 81 60", "F");
		lay("0x8200", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "H");
		analyze();
		assertEquals(Integer.valueOf(0x7e), dbrAt(0x8208));
	}

	/** The same tail storing to $03,S does not move the return address over the pulled bytes. */
	@Test
	public void aMisplacedReturnAddressCopyIsNotAnArgumentDrop() throws Exception {
		lay("0x8100", "a3 01 83 03 68 68 60", "P");
		lay("0x8000", "f4 11 11 f4 22 22 20 00 81 60", "F");
		lay("0x8200", "f4 7e 7e ab ab 20 00 80 " + LDA_1234 + " 60", "H");
		analyze();
		assertNull(dbrAt(0x8208));
	}
}
