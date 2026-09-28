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
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

/**
 * {@link BranchAlwaysPairAnalyzer} on a synthetic reduction of blmaster's f237/f239 (grm-78b):
 * <pre>
 *   8000  LDA $10
 *   8002  BNE $8008
 *   8004  BEQ $8008   ; always taken
 *   8006  NOP         ; the next routine -- must not join the function at 8000
 *   8007  RTS
 *   8008  RTS
 * </pre>
 * The function at 8000 is created BEFORE the analyzer runs, so the body fix-up is exercised too.
 */
public class BranchAlwaysPairProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	/** {@code secondBranch} is the opcode at 8004; {@code jumpToSecond} adds a JMP $8004 at 8010. */
	private ProgramDB build(int secondBranch, boolean jumpToSecond) throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x100);
		builder.setBytes("0x8000",
			String.format("a5 10 d0 04 %02x 02 ea 60 60", secondBranch), true);
		if (jumpToSecond) {
			builder.setBytes("0x8010", "4c 04 80", true);
		}
		return builder.getProgram();
	}

	private Function runAnalyzer(ProgramDB program) throws Exception {
		int tx = program.startTransaction("analyze");
		try {
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr(0x8000));
			cmd.applyTo(program, TaskMonitor.DUMMY);
			Function function = cmd.getFunction();
			assertTrue("control: body starts out including the next routine",
				function.getBody().contains(addr(0x8006)));
			BranchAlwaysPairAnalyzer analyzer = new BranchAlwaysPairAnalyzer();
			assertTrue(analyzer.canAnalyze(program));
			analyzer.added(program, program.getMemory().getLoadedAndInitializedAddressSet(),
				TaskMonitor.DUMMY, new MessageLog());
			return function;
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void pairEndsTheFunctionBody() throws Exception {
		ProgramDB program = build(0xf0, false); // BEQ
		Function function = runAnalyzer(program);

		assertTrue(program.getListing().getInstructionAt(addr(0x8004)).isFallThroughOverridden());
		assertFalse(function.getBody().contains(addr(0x8006)));
		assertFalse(function.getBody().contains(addr(0x8007)));
		assertTrue(function.getBody().contains(addr(0x8008)));
		assertEquals(addr(0x8008), function.getBody().getMaxAddress());

		DecompInterface ifc = new DecompInterface();
		try {
			assertTrue(ifc.openProgram(program));
			DecompileResults results = ifc.decompileFunction(function, 30, TaskMonitor.DUMMY);
			assertTrue("decompile failed: " + results.getErrorMessage(),
				results.decompileCompleted());
		}
		finally {
			ifc.dispose();
		}
	}

	/** Something jumps straight to the second branch, with flags of its own: the fall-through is
	 *  live, so it must stay. */
	@Test
	public void secondBranchReachedElsewhereIsLeftAlone() throws Exception {
		ProgramDB program = build(0xf0, true);
		Function function = runAnalyzer(program);

		assertFalse(program.getListing().getInstructionAt(addr(0x8004)).isFallThroughOverridden());
		assertTrue(function.getBody().contains(addr(0x8006)));
	}

	/** BNE then BCC test different flags: not a pair. */
	@Test
	public void differentFlagsAreNotAPair() throws Exception {
		ProgramDB program = build(0x90, false); // BCC
		runAnalyzer(program);

		assertFalse(program.getListing().getInstructionAt(addr(0x8004)).isFallThroughOverridden());
	}
}
