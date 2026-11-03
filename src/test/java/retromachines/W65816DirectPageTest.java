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

/** grm-9nxj.22 slice 1: {@link W65816DirectPageAnalyzer}. Code at $8000, M=X=E=0. */
public class W65816DirectPageTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		MemoryBlock rom = builder.createMemory(".rom", "0x8000", 0x1000);
		program = builder.getProgram();
		setWritable(rom, false);
		inTx(program, "rom executable", () -> rom.setExecute(true));
		for (String f : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
			Register r = program.getLanguage().getRegister(f);
			inTx(program, "set " + f, () -> program.getProgramContext()
					.setValue(r, builder.addr("0x8000"), builder.addr("0x8fff"), BigInteger.ZERO));
		}
	}

	/** Lays, decodes, makes a function over [8000, 8000+n) and analyzes it. */
	private void run(String bytes) throws Exception {
		builder.setBytes("0x8000", bytes, false);
		int n = bytes.split(" ").length;
		builder.disassemble("0x8000", n, false);
		Address end = addr(0x8000L + n - 1);
		inTx(program, "function", () -> program.getFunctionManager().createFunction("F",
			addr(0x8000), new AddressSet(addr(0x8000), end), SourceType.ANALYSIS));
		W65816DirectPageAnalyzer a = new W65816DirectPageAnalyzer();
		assertTrue(a.canAnalyze(program));
		inTx(program, "analyze", () -> a.added(program, new AddressSet(addr(0x8000), end),
			TaskMonitor.DUMMY, new MessageLog()));
	}

	private Integer dpAt(long at) {
		RegisterValue v = program.getProgramContext().getRegisterValue(
			program.getRegister("DP"), addr(at));
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

	@Test
	public void ldxPhxPldSetsDp() throws Exception {
		run("a2 00 06 da 2b 85 3d 60");   // LDX #$0600 ; PHX ; PLD ; STA <$3d ; RTS
		assertNull(dpAt(0x8000));
		assertNull("DP is the OLD value while PLD executes", dpAt(0x8004));
		assertEquals(Integer.valueOf(0x600), dpAt(0x8005));
		Reference r = dataRef(0x8005);
		assertNotNull(r);
		assertEquals(addr(0x063d), r.getToAddress());
		assertEquals(RefType.WRITE, r.getReferenceType());
	}

	@Test
	public void peaPldSetsDp() throws Exception {
		run("f4 00 06 2b a5 3d 60");   // PEA #$0600 ; PLD ; LDA <$3d ; RTS
		assertEquals(Integer.valueOf(0x600), dpAt(0x8004));
		Reference r = dataRef(0x8004);
		assertNotNull(r);
		assertEquals(addr(0x063d), r.getToAddress());
		assertEquals(RefType.READ, r.getReferenceType());
	}

	@Test
	public void phdPldRestoresKnownDp() throws Exception {
		// LDX #$0600 ; PHX ; PLD ; PHD ; LDX #$0700 ; PHX ; PLD ; PLD ; STA <$3d ; RTS
		run("a2 00 06 da 2b 0b a2 00 07 da 2b 2b 85 3d 60");
		assertEquals(Integer.valueOf(0x600), dpAt(0x800c));
		assertEquals(addr(0x063d), dataRef(0x800c).getToAddress());
	}

	@Test
	public void eightBitImmediateIsRejected() throws Exception {
		run("e2 10 a2 06 da 2b 85 3d 60");   // SEP #$10 ; LDX #$06 ; PHX(1 byte) ; PLD ; STA <$3d
		assertNull(dpAt(0x8006));
		assertNull(dataRef(0x8006));
	}

	@Test
	public void conflictingDpAtMergeStaysUnknown() throws Exception {
		// LDX #$600 ; PHX ; PLD ; BEQ +5 ; LDX #$700 ; PHX ; PLD ; STA <$3d ; RTS
		run("a2 00 06 da 2b f0 05 a2 00 07 da 2b 85 3d 60");
		assertEquals(Integer.valueOf(0x600), dpAt(0x8005));   // the BEQ itself
		assertNull(dpAt(0x800c));
		assertNull(dataRef(0x800c));
	}

	@Test
	public void agreeingDpAtMergeStaysKnown() throws Exception {
		// LDX #$600 ; PHX ; PLD ; BEQ +1 ; NOP ; STA <$3d ; RTS
		run("a2 00 06 da 2b f0 01 ea 85 3d 60");
		assertEquals(Integer.valueOf(0x600), dpAt(0x8008));
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

	private void analyzeAll() throws Exception {
		W65816DirectPageAnalyzer a = new W65816DirectPageAnalyzer();
		inTx(program, "analyze", () -> a.added(program,
			new AddressSet(addr(0x8000), addr(0x8fff)), TaskMonitor.DUMMY, new MessageLog()));
	}

	/** A -> B -> A, and A also calls D (TCD): B must not be cached as preserving. */
	@Test
	public void mutualRecursionIsNotCachedOptimistically() throws Exception {
		lay("0x8100", "20 00 82 20 00 83 60", "A");   // JSR B ; JSR D ; RTS
		lay("0x8200", "20 00 81 60", "B");            // JSR A ; RTS
		lay("0x8300", "5b 60", "D");                  // TCD ; RTS
		// LDX #$600 ; PHX ; PLD ; JSR A ; LDX #$600 ; PHX ; PLD ; JSR B ; STA <$3d ; RTS
		lay("0x8000", "a2 00 06 da 2b 20 00 81 a2 00 06 da 2b 20 00 82 85 3d 60", "C");
		analyzeAll();
		assertEquals(Integer.valueOf(0x600), dpAt(0x8005));
		assertNull("A does not preserve", dpAt(0x8008));
		assertEquals(Integer.valueOf(0x600), dpAt(0x800d));
		assertNull("B reaches D's TCD through A", dpAt(0x8010));
	}

	/** A callee that tail-jumps to a function doing TCD does not preserve DP. */
	@Test
	public void tailJumpToTcdFunctionDoesNotPreserve() throws Exception {
		lay("0x8200", "4c 00 83", "E");   // JMP $8300
		lay("0x8300", "5b 60", "D");      // TCD ; RTS
		lay("0x8000", "a2 00 06 da 2b 20 00 82 85 3d 60", "C");
		analyzeAll();
		assertNull(dpAt(0x8008));
	}

	/** A callee that tail-jumps to a harmless function keeps DP. */
	@Test
	public void tailJumpToHarmlessFunctionPreserves() throws Exception {
		lay("0x8200", "4c 00 83", "E");   // JMP $8300
		lay("0x8300", "ea 60", "D");      // NOP ; RTS
		lay("0x8000", "a2 00 06 da 2b 20 00 82 85 3d 60", "C");
		analyzeAll();
		assertEquals(Integer.valueOf(0x600), dpAt(0x8008));
	}

	/**
	 * FF2's RESET shape: a loop back to the entry after TXS merges a poisoned stack in, and the
	 * LDX/PHX/PLD after it must still set DP, since a push onto an unknown stack pulls back exactly.
	 */
	@Test
	public void pushAfterPoisonedStackStillPairs() throws Exception {
		// LDX #$0600 ; PHX ; PLD ; LDX #$02ff ; TXS ; STA <$3d ; JMP $8000
		run("a2 00 06 da 2b a2 ff 02 9a 85 3d 4c 00 80");
		assertRef(0x8009, 0x063d, RefType.WRITE);
	}

	// ---- slice 2 (grm-9nxj.26): entry DP seeded from agreeing callers ----

	private static final String SET_600_CALL_8200 = "a2 00 06 da 2b 20 00 82 60";   // ... JSR $8200

	/** A callee whose only caller has DP=$0600 starts with DP=$0600. */
	@Test
	public void callerSeedsCallee() throws Exception {
		lay("0x8200", "85 3d 60", "S");   // STA <$3d ; RTS
		lay("0x8000", SET_600_CALL_8200, "C");
		analyzeAll();
		assertEquals(Integer.valueOf(0x600), dpAt(0x8200));
		assertRef(0x8200, 0x063d, RefType.WRITE);
	}

	/** Seeding is transitive: C -> S -> T. */
	@Test
	public void seedReachesCalleesCallee() throws Exception {
		lay("0x8300", "a5 10 60", "T");      // LDA <$10 ; RTS
		lay("0x8200", "20 00 83 60", "S");   // JSR $8300 ; RTS
		lay("0x8000", SET_600_CALL_8200, "C");
		analyzeAll();
		assertRef(0x8300, 0x0610, RefType.READ);
	}

	/** Two callers with different DP leave the callee unknown. */
	@Test
	public void disagreeingCallersLeaveEntryUnknown() throws Exception {
		lay("0x8200", "85 3d 60", "S");
		lay("0x8000", SET_600_CALL_8200, "C");
		lay("0x8100", "a2 00 07 da 2b 20 00 82 60", "D");   // DP=$0700 ; JSR $8200
		analyzeAll();
		assertNull(dpAt(0x8200));
		assertNull(dataRef(0x8200));
	}

	/** One caller with an unknown DP is enough to leave the callee unknown. */
	@Test
	public void unknownCallerLeavesEntryUnknown() throws Exception {
		lay("0x8200", "85 3d 60", "S");
		lay("0x8000", SET_600_CALL_8200, "C");
		lay("0x8100", "20 00 82 60", "D");   // JSR $8200 with D's own (unknown) entry DP
		analyzeAll();
		assertNull(dpAt(0x8200));
	}

	/** A callee that sets DP to a constant and returns hands that DP back to its caller. */
	@Test
	public void calleeExitDpReturnsToCaller() throws Exception {
		lay("0x8200", "a2 00 06 da 2b 60", "S");   // LDX #$0600 ; PHX ; PLD ; RTS
		lay("0x8000", "20 00 82 85 3d 60", "C");   // JSR $8200 ; STA <$3d ; RTS
		analyzeAll();
		assertRef(0x8003, 0x063d, RefType.WRITE);
	}

	/** A callee that pulls its own return address does not plainly return: no exit DP. */
	@Test
	public void calleePullingItsReturnHasNoExitDp() throws Exception {
		lay("0x8200", "68 a2 00 06 da 2b 60", "S");   // PLA ; LDX #$0600 ; PHX ; PLD ; RTS
		lay("0x8000", "20 00 82 85 3d 60", "C");
		analyzeAll();
		assertNull(dataRef(0x8003));
	}

	/** A pointer to the entry that no dispatch resolved is an unknown way in. */
	@Test
	public void dataReferenceToEntryLeavesItUnknown() throws Exception {
		lay("0x8200", "85 3d 60", "S");
		lay("0x8000", SET_600_CALL_8200, "C");
		inTx(program, "pointer", () -> program.getReferenceManager().addMemoryReference(
			addr(0x8800), addr(0x8200), RefType.DATA, SourceType.ANALYSIS, 0));
		analyzeAll();
		assertNull(dpAt(0x8200));
	}

	/** An external entry point (a vector target) is never seeded. */
	@Test
	public void externalEntryIsNotSeeded() throws Exception {
		lay("0x8200", "85 3d 60", "S");
		lay("0x8000", SET_600_CALL_8200, "C");
		inTx(program, "entry", () -> program.getSymbolTable().addExternalEntryPoint(addr(0x8200)));
		analyzeAll();
		assertNull(dpAt(0x8200));
	}

	/** Indexed, indirect, long and indexed-indirect dp forms all reference DP + dp. */
	@Test
	public void indexedAndIndirectFormsReferenceDpPlusOffset() throws Exception {
		// LDX #$0600 ; PHX ; PLD ; STA <$10,X ; LDA (<$10),Y ; LDA [<$10] ; LDA (<$10,X) ; RTS
		run("a2 00 06 da 2b 95 10 b1 10 a7 10 a1 10 60");
		assertRef(0x8005, 0x0610, RefType.WRITE);
		assertRef(0x8007, 0x0610, RefType.READ);
		assertRef(0x8009, 0x0610, RefType.READ);
		assertRef(0x800b, 0x0610, RefType.READ);
	}

	private void assertRef(long from, long to, RefType type) {
		Reference r = dataRef(from);
		assertNotNull("no reference at " + Long.toHexString(from), r);
		assertEquals(addr(to), r.getToAddress());
		assertEquals(type, r.getReferenceType());
	}
}
