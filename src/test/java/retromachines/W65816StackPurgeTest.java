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

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.task.TaskMonitor;

/**
 * {@link W65816StackPurgeAnalyzer} and the call stack model it completes (bead grm-9nxj.47):
 * the w65816 prototypes have {@code extrapop="unknown"} and SP in {@code <unaffected>}, so the
 * purge decides what SP is after a call, in constant propagation and in the decompiler.
 * <p>
 * The decisive shape is the one grm-9nxj.44 found: {@code PHA ; JSR ; PLA ; STA $10}. With
 * extrapop 0 and SP unaffected the pull read the JSR's return-address byte instead of the pushed
 * value; with the purge it reads the pushed value; with no proven return it reads nothing known.
 */
public class W65816StackPurgeTest extends AbstractProgramTest {

	private static final long CALLER = 0x8000;
	private static final long CALLEE = 0x8100;

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

	private Function function(long entry, String hex) throws Exception {
		builder.setBytes(String.format("0x%x", entry), hex, true);
		inTx(program, "fn", () -> new CreateFunctionCmd(addr(entry)).applyTo(program));
		Function fn = program.getFunctionManager().getFunctionAt(addr(entry));
		assertNotNull(fn);
		return fn;
	}

	private int analyze() throws Exception {
		int[] n = new int[1];
		inTx(program, "purge", () -> n[0] = W65816StackPurgeAnalyzer.run(program,
			program.getMemory(), TaskMonitor.DUMMY));
		return n[0];
	}

	// ---- the analyzer ----------------------------------------------------------------------

	@Test
	public void rtsRoutinePurgesTwo() throws Exception {
		Function fn = function(CALLEE, "48 68 60"); // PHA ; PLA ; RTS
		assertFalse(fn.isStackPurgeSizeValid());
		assertEquals(1, analyze());
		assertEquals(2, fn.getStackPurgeSize());
		assertEquals("the default convention is named, so the decompiler keeps the purge",
			"__unknowncall", fn.getCallingConventionName());
		assertEquals("a second run changes nothing", 0, analyze());
	}

	@Test
	public void rtlRoutinePurgesThree() throws Exception {
		Function fn = function(CALLEE, "8b 4b ab ab 6b"); // PHB ; PHK ; PLB ; PLB ; RTL
		analyze();
		assertEquals(3, fn.getStackPurgeSize());
	}

	/** An interrupt handler: no proven return, so the purge stays unknown. */
	@Test
	public void rtiHandlerStaysUnknown() throws Exception {
		Function fn = function(CALLEE, "48 68 40"); // PHA ; PLA ; RTI
		assertEquals(0, analyze());
		assertFalse(fn.isStackPurgeSizeValid());
	}

	/** An RTS trick (push a target, RTS to it) returns somewhere else: unknown. */
	@Test
	public void rtsTrickStaysUnknown() throws Exception {
		Function fn = function(CALLEE, "f4 ff 80 60"); // PEA $80ff ; RTS
		analyze();
		assertFalse(fn.isStackPurgeSizeValid());
	}

	/** A purge someone else set is not ours to change. */
	@Test
	public void foreignPurgeIsKept() throws Exception {
		Function fn = function(CALLEE, "60");
		inTx(program, "user", () -> fn.setStackPurgeSize(5));
		assertEquals(0, analyze());
		assertEquals(5, fn.getStackPurgeSize());
	}

	// ---- the model it completes ------------------------------------------------------------

	/** LDA #$42 ; PHA ; JSR CALLEE ; PLA ; STA $10 ; RTS. The JSR at 8003 pushes 8005. */
	private static final String PHA_JSR_PLA = "a9 42 48 20 00 81 68 85 10 60";
	private static final long STA = CALLER + 7;

	/** A's value at the STA after the call, from Ghidra's constant propagation. */
	private Long propagatedA(Function caller) throws Exception {
		SymbolicPropogator prop = new SymbolicPropogator(program);
		prop.flowConstants(caller.getEntryPoint(), caller.getBody(),
			new ConstantPropagationContextEvaluator(TaskMonitor.DUMMY, true), true,
			TaskMonitor.DUMMY);
		SymbolicPropogator.Value v = prop.getRegisterValue(addr(STA), program.getRegister("A"));
		return v == null || v.isRegisterRelativeValue() ? null : v.getValue();
	}

	private String decompile(Function fn) {
		DecompInterface ifc = new DecompInterface();
		try {
			assertTrue(ifc.getLastMessage(), ifc.openProgram(program));
			DecompileResults r = ifc.decompileFunction(fn, 30, TaskMonitor.DUMMY);
			assertTrue(r.getErrorMessage(), r.decompileCompleted());
			return r.getDecompiledFunction().getC();
		}
		finally {
			ifc.dispose();
		}
	}

	@Test
	public void pushedValueSurvivesAProvenCall() throws Exception {
		function(CALLEE, "60");
		Function caller = function(CALLER, PHA_JSR_PLA);
		analyze();
		assertEquals(2, program.getFunctionManager().getFunctionAt(addr(CALLEE))
				.getStackPurgeSize());

		assertEquals("propagation reads the pushed value", Long.valueOf(0x42),
			propagatedA(caller));
		String c = decompile(caller);
		assertEquals("the pull reads the pushed value, never the return-address byte: " + c,
			"0x42", storedValue(c));
	}

	/** RTL purges 3: a JSL to it restores SP as well. */
	@Test
	public void pushedValueSurvivesAProvenLongCall() throws Exception {
		function(CALLEE, "6b");
		// LDA #$42 ; PHA ; JSL $008100 ; PLA ; STA $10 ; RTS
		Function caller = function(CALLER, "a9 42 48 22 00 81 00 68 85 10 60");
		analyze();
		assertEquals(3, program.getFunctionManager().getFunctionAt(addr(CALLEE))
				.getStackPurgeSize());
		SymbolicPropogator prop = new SymbolicPropogator(program);
		prop.flowConstants(caller.getEntryPoint(), caller.getBody(),
			new ConstantPropagationContextEvaluator(TaskMonitor.DUMMY, true), true,
			TaskMonitor.DUMMY);
		SymbolicPropogator.Value v =
			prop.getRegisterValue(addr(CALLER + 8), program.getRegister("A"));
		assertNotNull(v);
		assertEquals(0x42, v.getValue());
		String c = decompile(caller);
		assertEquals(c, "0x42", storedValue(c));
	}

	/**
	 * A callee with no proven return (an RTI) leaves SP unknown after the call: neither
	 * consumer may fold the pull to any constant -- not the return-address byte, and not an
	 * older push. Without the cspec's eval_called_prototype the decompiler guessed an extrapop
	 * of 4 here and stored 0x11, the first push.
	 */
	@Test
	public void unprovenCallFoldsNothing() throws Exception {
		assertUnprovenCallFoldsNothing(null);
	}

	/** The same through a locked model with an unknown extrapop (the DP analyzer's). */
	@Test
	public void unprovenCallToANamedModelFoldsNothing() throws Exception {
		assertUnprovenCallFoldsNothing("__dp_preserved");
	}

	private void assertUnprovenCallFoldsNothing(String convention) throws Exception {
		Function callee = function(CALLEE, "40"); // RTI
		if (convention != null) {
			inTx(program, "cc", () -> callee.setCallingConvention(convention));
		}
		// LDA #$11 ; PHA ; LDA #$22 ; PHA ; LDA #$42 ; PHA ; JSR CALLEE ; PLA ; STA $10 ; RTS
		Function caller = function(CALLER, "a9 11 48 a9 22 48 a9 42 48 20 00 81 68 85 10 60");
		analyze();
		assertFalse(callee.isStackPurgeSizeValid());
		SymbolicPropogator prop = new SymbolicPropogator(program);
		prop.flowConstants(caller.getEntryPoint(), caller.getBody(),
			new ConstantPropagationContextEvaluator(TaskMonitor.DUMMY, true), true,
			TaskMonitor.DUMMY);
		SymbolicPropogator.Value v =
			prop.getRegisterValue(addr(CALLER + 13), program.getRegister("A"));
		assertTrue("propagation must not fold the pull: " + v,
			v == null || v.isRegisterRelativeValue());
		String c = decompile(caller);
		String stored = storedAt0x10(c);
		assertFalse("decompiler folded the pull to a constant: " + c, stored.startsWith("0x"));
		assertFalse("decompiler read the pull from a push slot: " + c,
			c.contains(stored + " = 0x"));
	}

	/**
	 * The value the STA $10 stores: the constant itself, or the constant a stack variable holds
	 * when the decompiler keeps the pushed slot live across the call (it does: the callee could
	 * read it).
	 */
	private static String storedValue(String c) {
		String stored = storedAt0x10(c);
		for (String line : c.split("\\R")) {
			String t = line.trim();
			if (t.startsWith(stored + " = ")) {
				return t.substring(stored.length() + 3).replace(";", "").trim();
			}
		}
		return stored;
	}

	/** The right-hand side of the STA $10's store in decompiled C. */
	private static String storedAt0x10(String c) {
		for (String line : c.split("\\R")) {
			int k = line.indexOf("0x10) = ");
			if (k >= 0) {
				return line.substring(k + 8).replace(";", "").trim();
			}
		}
		throw new AssertionError("no store to DP+0x10 in:\n" + c);
	}

	/** The control: today's extrapop-0 failure, reproduced by a purge of 0 on the callee. */
	@Test
	public void zeroPurgeReadsTheReturnAddress() throws Exception {
		Function callee = function(CALLEE, "60");
		Function caller = function(CALLER, PHA_JSR_PLA);
		inTx(program, "zero", () -> callee.setStackPurgeSize(0));
		assertEquals(Long.valueOf(0x05), propagatedA(caller));
	}

	/** The analyzer is 65816-only. */
	@Test
	public void analyzerRunsOn65816() {
		Program p = program;
		assertTrue(new W65816StackPurgeAnalyzer().canAnalyze(p));
	}
}
