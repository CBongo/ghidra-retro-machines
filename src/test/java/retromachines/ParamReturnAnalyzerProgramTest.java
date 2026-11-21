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
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.After;
import org.junit.Test;

import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Bead grm-etbh (stage E2): what {@link ParamReturnAnalyzer} writes into function signatures.
 */
public class ParamReturnAnalyzerProgramTest extends AbstractProgramTest {

	private static final String[] LANGUAGES = { "6502:LE:16:default", "6510:LE:16:default" };

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

	private Function fn(String addr, String hex) throws Exception {
		int len = hex.replace(" ", "").length() / 2;
		builder.setBytes(addr, hex, false);
		builder.disassemble(addr, len, false);
		Function[] out = new Function[1];
		inTx(program, "create function", () -> {
			try {
				ghidra.program.model.address.Address a = builder.addr(addr);
				out[0] = program.getFunctionManager().createFunction(null, a,
					new ghidra.program.model.address.AddressSet(a, a.add(len - 1)),
					SourceType.DEFAULT);
			}
			catch (Exception e) {
				throw new AssertionError(e);
			}
		});
		return out[0];
	}

	private int run() {
		int[] n = new int[1];
		inTx(program, "param return", () -> {
			try {
				n[0] = ParamReturnAnalyzer.apply(program, ParamReturnEvidence.analyze(program),
					TaskMonitor.DUMMY);
			}
			catch (Exception e) {
				throw new AssertionError(e);
			}
		});
		return n[0];
	}

	@Test
	public void aInputIsCommittedAsARegisterParameter() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "8d 00 02 60"); // STA $0200 / RTS
			assertEquals(1, run());
			assertEquals(List.of("A"), ParamReturnAnalyzer.parameterRegisters(f));
			assertTrue(f.hasCustomVariableStorage());
			assertEquals(SourceType.ANALYSIS, f.getSignatureSource());
			assertEquals("the default model, not 'unknown'",
				program.getCompilerSpec().getDefaultCallingConvention().getName(),
				f.getCallingConventionName());
			assertEquals(1, f.getParameter(0).getLength());
			assertTrue("return stays undefined", f.getReturnType().isEquivalent(DataType.DEFAULT));
			assertTrue(f.getTags().stream().anyMatch(t -> t.getName().equals("grm_param_return")));
		});
	}

	@Test
	public void xOnlyInput() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "8e 00 02 60"); // STX $0200 / RTS
			assertEquals(1, run());
			assertEquals(List.of("X"), ParamReturnAnalyzer.parameterRegisters(f));
		});
	}

	@Test
	public void callerConfirmedAReturn() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "a9 05 60"); // LDA #5 / RTS
			fn("0x8100", "20 00 80 8d 00 02 60"); // JSR / STA $0200 / RTS
			run();
			assertTrue(f.getParameters().length == 0);
			assertEquals("A", f.getReturn().getRegister().getName());
			assertEquals(1, f.getReturn().getLength());
		});
	}

	@Test
	public void carryIsTheReturnWhenItIsTheOnlyResult() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "38 60"); // SEC / RTS
			fn("0x8100", "20 00 80 b0 02 ea ea 60"); // JSR / BCS / NOP NOP / RTS
			run();
			assertTrue(f.getReturnType() instanceof BooleanDataType);
			assertEquals(CpuRegs.of(program.getLanguage()).carry().reg(),
				f.getReturn().getRegister());
		});
	}

	@Test
	public void twoResultsReturnAAndNameCarryInThePlateComment() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "a9 05 38 60"); // LDA #5 / SEC / RTS
			fn("0x8100", "20 00 80 b0 03 8d 00 02 60"); // JSR / BCS +3 / STA / RTS
			run();
			assertEquals("A", f.getReturn().getRegister().getName());
			String c = program.getListing().getComment(CommentType.PLATE, f.getEntryPoint());
			assertNotNull(c);
			assertTrue(c, c.contains("Carry status on return: always set"));
		});
	}

	@Test
	public void rerunIsIdempotentAndPreservesOtherPlateText() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "a9 05 38 60");
			fn("0x8100", "20 00 80 b0 03 8d 00 02 60");
			run();
			String once = program.getListing().getComment(CommentType.PLATE, f.getEntryPoint());
			long mod = program.getModificationNumber();
			run();
			assertEquals(once,
				program.getListing().getComment(CommentType.PLATE, f.getEntryPoint()));
			assertEquals("a settled rerun mutates nothing", mod, program.getModificationNumber());
			inTx(program, "human", () -> program.getListing().setComment(f.getEntryPoint(),
				CommentType.PLATE, once + "; human note"));
			run();
			String after =
				program.getListing().getComment(CommentType.PLATE, f.getEntryPoint());
			assertTrue(after, after.contains("human note"));
			assertEquals(after.indexOf("Param/return inference:"),
				after.lastIndexOf("Param/return inference:"));
		});
	}

	@Test
	public void userDefinedSignatureIsNeverTouched() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "8d 00 02 60");
			inTx(program, "user sig", () -> {
				try {
					f.setName("mine", SourceType.USER_DEFINED);
					f.updateFunction(null, null, List.of(), Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
						true, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					throw new AssertionError(e);
				}
			});
			assertEquals(SourceType.USER_DEFINED, f.getSignatureSource());
			assertEquals(0, run());
			assertEquals(0, f.getParameterCount());
			assertFalse(f.getTags().stream().anyMatch(t -> t.getName().equals("grm_param_return")));
		});
	}

	@Test
	public void voidVoidIsNotCommitted() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "ea 60"); // NOP / RTS
			assertEquals(0, run());
			assertEquals(SourceType.DEFAULT, f.getSignatureSource());
		});
	}

	@Test
	public void incompleteFunctionIsNotCommitted() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "8d 00 02 6c 00 02"); // STA $0200 / JMP ($0200)
			assertEquals(0, run());
			assertEquals(SourceType.DEFAULT, f.getSignatureSource());
		});
	}

	@Test
	public void zeroPageInputIsTagAndCommentOnly() throws Exception {
		eachLanguage(() -> {
			Function f = fn("0x8000", "a5 10 8e 00 02 60"); // LDA $10 / STX $0200 / RTS (X in)
			fn("0x8100", "85 10 20 00 80 60"); // STA $10 / JSR / RTS
			run();
			assertTrue(f.getTags().stream().anyMatch(t -> t.getName().equals("zp_in:$10")));
			assertEquals("only X is a parameter", List.of("X"),
				ParamReturnAnalyzer.parameterRegisters(f));
		});
	}
}
