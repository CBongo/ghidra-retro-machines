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

import java.util.List;

import org.junit.After;
import org.junit.Test;

import ghidra.program.model.mem.MemoryBlock;

import retromachines.ParamReturnEvidence.FnEvidence;
import retromachines.ParamReturnEvidence.Proposal;
import retromachines.ParamReturnEvidence.Result;

/**
 * Bead grm-etbh (stage E1): {@link ParamReturnEvidence} over hand-assembled routines, on the stock
 * 6502 and the repo's custom 6502/6510 languages.
 */
public class ParamReturnEvidenceProgramTest extends AbstractProgramTest {

	private static final String[] LANGUAGES =
		{ "6502:LE:16:default", "6502:LE:16:undoc", "6510:LE:16:default" };

	private static final int A = 1, X = 2;

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

	private void eachLanguage(Scenario body) throws Exception {
		for (String id : LANGUAGES) {
			dispose();
			builder = newBuilder("Test", id);
			MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
			MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
			builder.createMemory("PRG", "0x8000", 0x4000);
			program = builder.getProgram();
			makeWritable(zp);
			makeWritable(ram);
			try {
				body.run();
			}
			catch (AssertionError e) {
				throw new AssertionError("[" + id + "] " + e.getMessage(), e);
			}
		}
	}

	/** Assembles {@code hex} at {@code addr} and makes it a function. */
	private void fn(String addr, String hex) throws Exception {
		int len = hex.replace(" ", "").length() / 2;
		builder.setBytes(addr, hex, false);
		builder.disassemble(addr, len, false);
		builder.createEmptyFunction("f" + addr.substring(2), addr, len, null);
	}

	/** Assembles {@code hex} without a function (data/unknown target). */
	private void code(String addr, String hex) throws Exception {
		builder.setBytes(addr, hex, false);
		builder.disassemble(addr, hex.replace(" ", "").length() / 2, false);
	}

	private FnEvidence ev(Result r, String addr) {
		FnEvidence e = r.get(builder.addr(addr));
		assertNotNull("no evidence at " + addr, e);
		return e;
	}

	@Test
	public void registerAInput() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "8d 00 02 60"); // STA $0200 / RTS
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertEquals(A, e.inMask);
			assertEquals(0, e.outMask);
			assertTrue(e.complete);
		});
	}

	@Test
	public void xOnlyInput() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "8e 00 02 60"); // STX $0200 / RTS
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertEquals(X, e.inMask);
			assertEquals(0, e.outMask);
		});
	}

	@Test
	public void savedAndRestoredAIsNeitherInputNorOutput() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "48 a9 05 68 60"); // PHA / LDA #5 / PLA / RTS
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertEquals("inputs", 0, e.inMask);
			assertEquals("outputs", 0, e.outMask);
			assertTrue(e.complete);
		});
	}

	@Test
	public void registerCopyMovesTheEntryValue() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "aa 60"); // TAX / RTS
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertEquals("A flows through", A, e.inMask);
			assertEquals("X is the result", X, e.outMask);
		});
	}

	@Test
	public void carryConstantReturnConfirmedByCallerBcs() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "38 60"); // SEC / RTS
			fn("0x8100", "20 00 80 b0 02 ea ea 60"); // JSR / BCS +2 / NOP NOP / RTS
			Result r = ParamReturnEvidence.analyze(program);
			FnEvidence e = ev(r, "0x8000");
			assertEquals(ParamReturnEvidence.C_ONE, e.carry);
			assertTrue(e.carryWritten());
			assertTrue((e.afterBranch & (1 << ParamReturnEvidence.RC)) != 0);
			Proposal p = ParamReturnEvidence.propose(e, false);
			assertEquals("carry", p.ret());
			assertTrue(p.params().isEmpty());
			assertTrue(p.complete());
		});
	}

	@Test
	public void aReturnReadByCaller() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "a9 05 60"); // LDA #5 / RTS
			fn("0x8100", "20 00 80 8d 00 02 60"); // JSR / STA $0200 / RTS
			Result r = ParamReturnEvidence.analyze(program);
			FnEvidence e = ev(r, "0x8000");
			assertEquals(A, e.outMask);
			assertEquals(A, e.afterRead);
			assertEquals("A", ParamReturnEvidence.propose(e, false).ret());
		});
	}

	@Test
	public void leftOverRegisterNobodyReadsIsNotAReturn() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "a9 05 60"); // LDA #5 / RTS
			fn("0x8100", "20 00 80 60"); // JSR / RTS (passes A up, never reads it)
			Result r = ParamReturnEvidence.analyze(program);
			FnEvidence e = ev(r, "0x8000");
			assertEquals(A, e.outMask);
			assertEquals(0, e.afterRead);
			assertNull(ParamReturnEvidence.propose(e, false).ret());
		});
	}

	@Test
	public void twoResultsReturnAWithCarryInComment() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "a9 05 38 60"); // LDA #5 / SEC / RTS
			fn("0x8100", "20 00 80 b0 03 8d 00 02 60"); // JSR / BCS +3 / STA $0200 / RTS
			Result r = ParamReturnEvidence.analyze(program);
			Proposal p = ParamReturnEvidence.propose(ev(r, "0x8000"), false);
			assertEquals("A", p.ret());
			assertTrue(p.comments().toString(),
				p.comments().contains("Carry status on return: always set"));
		});
	}

	@Test
	public void tailJumpInheritsTheTargetsSummary() throws Exception {
		eachLanguage(() -> {
			fn("0x8200", "8d 00 02 a9 01 60"); // STA $0200 / LDA #1 / RTS
			fn("0x8000", "4c 00 82"); // JMP $8200
			Result r = ParamReturnEvidence.analyze(program);
			FnEvidence e = ev(r, "0x8000");
			assertEquals(A, e.inMask);
			assertEquals(A, e.outMask);
			assertEquals(1, e.returns);
			assertTrue(e.tail);
		});
	}

	@Test
	public void wrapperInheritsTheHelpersInputsAndOutputs() throws Exception {
		eachLanguage(() -> {
			fn("0x8200", "8d 00 02 a9 01 60"); // helper: A in, A out
			fn("0x8000", "20 00 82 60"); // JSR helper / RTS
			Result r = ParamReturnEvidence.analyze(program);
			FnEvidence e = ev(r, "0x8000");
			assertEquals(A, e.inMask);
			assertEquals(A, e.outMask);
			assertTrue(e.complete);
		});
	}

	@Test
	public void recursionTerminates() throws Exception {
		eachLanguage(() -> {
			// DEC $10 / BNE +3 / JSR $8000 / RTS
			fn("0x8000", "c6 10 d0 03 20 00 80 60");
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertTrue(e.returns > 0);
			assertTrue(e.zpIn.contains(0x10));
			assertTrue(e.complete);
		});
	}

	@Test
	public void computedJumpIsIncomplete() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "6c 00 02"); // JMP ($0200)
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertFalse(e.complete);
			assertEquals(1, e.indirect);
		});
	}

	@Test
	public void callToUnknownTargetIsIncomplete() throws Exception {
		eachLanguage(() -> {
			code("0x9000", "60"); // RTS, but no function there
			fn("0x8000", "20 00 90 60"); // JSR $9000 / RTS
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertFalse(e.complete);
		});
	}

	@Test
	public void zeroPageInputSetByCallerIsCommentOnly() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "a5 10 60"); // LDA $10 / RTS
			fn("0x8100", "85 10 20 00 80 60"); // STA $10 / JSR / RTS
			Result r = ParamReturnEvidence.analyze(program);
			FnEvidence e = ev(r, "0x8000");
			assertTrue(e.zpIn.contains(0x10));
			assertTrue(e.zpSetBefore);
			Proposal p = ParamReturnEvidence.propose(e, false);
			assertTrue(p.params().isEmpty());
			List<String> c = p.comments();
			assertTrue(c.toString(), c.contains("Zero-page inputs: $10"));
		});
	}

	@Test
	public void storedBeforeLoadedZeroPageCellIsNotAnInput() throws Exception {
		eachLanguage(() -> {
			fn("0x8000", "a9 01 85 10 a5 10 60"); // LDA #1 / STA $10 / LDA $10 / RTS
			FnEvidence e = ev(ParamReturnEvidence.analyze(program), "0x8000");
			assertTrue(e.zpIn.isEmpty());
			assertTrue(e.zpWritten.contains(0x10));
		});
	}
}
