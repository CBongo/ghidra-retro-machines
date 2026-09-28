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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;

/**
 * {@link JumpTableBoundAnalyzer#relocateStaleOverride} (grm-v60.1): an override written while a
 * switch sat in a caller's body must move to the function that contains the switch once one is
 * carved out around it, and must not move while its function still contains the switch.
 */
public class JumpTableOverrideRelocationProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long CALLER = 0x8000;
	private static final long CALLEE = 0x8010; // holds the switch
	private static final long SWITCH = 0x8014;
	private static final long[] CASES = { 0x8030, 0x8040 };

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB build() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x100);
		// Byte content only matters for the addresses existing; the test drives the bodies.
		builder.setBytes("0x8014", "6c 00 00", true); // JMP ($0000)
		return builder.getProgram();
	}

	private Function createFunction(ProgramDB program, String name, long start, long end)
			throws Exception {
		return program.getFunctionManager().createFunction(name, addr(start),
			new AddressSet(addr(start), addr(end)), SourceType.USER_DEFINED);
	}

	private void writeOverride(Function function) throws Exception {
		List<Address> dests = new ArrayList<>();
		for (long c : CASES) {
			dests.add(addr(c));
		}
		new JumpTable(addr(SWITCH), new ArrayList<>(dests), true, EquateSymbol.FORMAT_DEFAULT)
				.writeOverride(function);
	}

	private Namespace overrideOf(ProgramDB program, Function function) {
		Namespace space = HighFunction.findOverrideSpace(function);
		return space == null ? null
				: program.getSymbolTable().getNamespace("jmp_" + addr(SWITCH), space);
	}

	@Test
	public void movesOverrideOntoTheFunctionNowContainingTheSwitch() throws Exception {
		ProgramDB program = build();
		int tx = program.startTransaction("t");
		try {
			Function caller = createFunction(program, "caller", CALLER, 0x801f);
			writeOverride(caller);
			// A JSR target becomes a function: the caller's body shrinks, the callee owns SWITCH.
			caller.setBody(new AddressSet(addr(CALLER), addr(CALLEE - 1)));
			Function callee = createFunction(program, "callee", CALLEE, 0x801f);

			assertTrue(JumpTableBoundAnalyzer.relocateStaleOverride(
				new JumpTableOverrideRelocatorAnalyzer(), program, callee, addr(SWITCH),
				new MessageLog()));

			Namespace moved = overrideOf(program, callee);
			assertNotNull("override should now live under the callee", moved);
			JumpTable read = JumpTable.readOverride(moved, program.getSymbolTable());
			assertNotNull(read);
			assertNull("the stale override under the caller should be gone",
				overrideOf(program, caller));
			assertEquals(1 + CASES.length, countSymbols(program, moved));
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void leavesOverrideAloneWhileItsFunctionStillContainsTheSwitch() throws Exception {
		ProgramDB program = build();
		int tx = program.startTransaction("t");
		try {
			Function caller = createFunction(program, "caller", CALLER, 0x801f);
			writeOverride(caller);
			Function other = createFunction(program, "other", 0x8050, 0x805f);

			assertFalse(JumpTableBoundAnalyzer.relocateStaleOverride(
				new JumpTableOverrideRelocatorAnalyzer(), program, other, addr(SWITCH),
				new MessageLog()));
			assertNotNull(overrideOf(program, caller));
			assertNull(overrideOf(program, other));
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private static int countSymbols(ProgramDB program, Namespace space) {
		int n = 0;
		for (var s : program.getSymbolTable().getSymbols(space)) {
			n++;
		}
		return n;
	}
}
