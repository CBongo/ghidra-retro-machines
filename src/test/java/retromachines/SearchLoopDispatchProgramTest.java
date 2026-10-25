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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.JumpTable;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SearchLoopDispatch} and its {@link JumpTableBoundAnalyzer} rule (grm-jt7s) against a
 * SYNTHETIC dispatch in megaman's bank-5 shape -- hand-built bytes, nothing copied from the ROM:
 * <pre>
 *   8000  LDY #$09            ; the last of 4 three-byte (id, lo, hi) records at $8040
 *   8002  CMP $8040,Y         ; L
 *   8005  BEQ $800e
 *   8007  DEY / DEY / DEY
 *   800a  BPL $8002
 *   800c  LDY #$00            ; not found: the first record
 *   800e  LDA $8041,Y         ; J
 *   8011  STA $04 / LDA $8042,Y / STA $05
 *   8018  JMP ($0004)
 * </pre>
 * The 4 records point at $8200, $8210, $8220, $8230. Past them the bytes are $80, so every index
 * the decompiler over-reads lands on $8080: a valid address, so its recovery keeps going.
 */
public class SearchLoopDispatchProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long SWITCH = 0x8018;
	private static final long[] REAL = { 0x8200, 0x8210, 0x8220, 0x8230 };

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	/** {@code extraEntry}: a JMP elsewhere into J, which makes Y at J unknown to the rule. */
	private ProgramDB build(boolean extraEntry) throws Exception {
		return build(extraEntry, Y_CODE);
	}

	private static final String Y_CODE =
		"a0 09 d9 40 80 f0 07 88 88 88 10 f6 a0 00 b9 41 80 85 04 b9 42 80 85 05 6c 04 00";
	/** The same dispatch with X for the index register (grm-gcwb). */
	private static final String X_CODE =
		"a2 09 dd 40 80 f0 07 ca ca ca 10 f6 a2 00 bd 41 80 85 04 bd 42 80 85 05 6c 04 00";
	/** LDX / DEX / LDA,X as X_CODE, but the search compares through Y: not this idiom. */
	private static final String MIXED_CODE =
		"a2 09 d9 40 80 f0 07 ca ca ca 10 f6 a2 00 bd 41 80 85 04 bd 42 80 85 05 6c 04 00";

	private ProgramDB build(boolean extraEntry, String code) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		StringBuilder fill = new StringBuilder();
		for (int i = 0x804c; i < 0x8160; i++) {
			fill.append("80 ");
		}
		builder.setBytes("0x804c", fill.toString().trim(), false);
		builder.setBytes("0x8040",
			"01 00 82  02 10 82  03 20 82  04 30 82".replace("  ", " "), false);
		for (long t : REAL) {
			builder.setBytes(String.format("0x%x", t), "60", true); // RTS
		}
		builder.setBytes("0x8000", code, true);
		if (extraEntry) {
			builder.setBytes("0x8300", "a4 10 4c 0e 80", true); // LDY $10 / JMP $800e
		}
		return builder.getProgram();
	}

	private Function createFunction(ProgramDB program) {
		return inTxGet(program, "fn", () -> {
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr(0x8000));
			cmd.applyTo(program, TaskMonitor.DUMMY);
			return cmd.getFunction();
		});
	}

	private JumpTable decompiledTable(ProgramDB program, Function function) {
		DecompInterface ifc = new DecompInterface();
		try {
			JumpTableBoundAnalyzer.configureDecompiler(program, ifc);
			assertTrue(ifc.openProgram(program));
			DecompileResults res = ifc.decompileFunction(function, 30, TaskMonitor.DUMMY);
			assertTrue(res.getErrorMessage(), res.decompileCompleted());
			JumpTable[] tables = res.getHighFunction().getJumpTables();
			assertEquals(1, tables.length);
			return tables[0];
		}
		finally {
			ifc.dispose();
		}
	}

	@Test
	public void loopValuesStepDownWhileBit7IsClear() {
		assertEquals(Arrays.asList(9, 6, 3, 0), SearchLoopDispatch.loopValues(9, 3));
		assertEquals(Arrays.asList(0x2d, 0x2a, 0x27, 0x24, 0x21, 0x1e, 0x1b, 0x18, 0x15, 0x12,
			0x0f, 0x0c, 0x09, 0x06, 0x03, 0x00), SearchLoopDispatch.loopValues(0x2d, 3));
		assertEquals(Arrays.asList(5, 3, 1), SearchLoopDispatch.loopValues(5, 2));
		assertNull("BPL never loops from a start with bit 7 set",
			SearchLoopDispatch.loopValues(0x80, 1));
		assertNull(SearchLoopDispatch.loopValues(9, 0));
	}

	/** The control: the decompiler reads far past the 4 records, and the rule reads exactly them. */
	@Test
	public void casesAreTheFourRecordsInIndexOrder() throws Exception {
		ProgramDB program = build(false);
		Function function = createFunction(program);
		JumpTable table = decompiledTable(program, function);
		List<Address> realCases = new ArrayList<>(Arrays.asList(table.getCases()));
		assertTrue("control: expected an over-read, got " + realCases.size(),
			realCases.size() > REAL.length);

		List<Address> cases = SearchLoopDispatch.cases(program,
			program.getListing().getInstructionAt(addr(SWITCH)), realCases);
		assertNotNull(cases);
		List<Address> expected = new ArrayList<>();
		for (long t : REAL) {
			expected.add(addr(t));
		}
		assertEquals(expected, cases);
	}

	@Test
	public void analyzerBoundsTheSwitchToTheSearchedRecords() throws Exception {
		ProgramDB program = build(false);
		Function function = createFunction(program);
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
				TaskMonitor.DUMMY, new MessageLog());
		});
		JumpTable table = decompiledTable(program, function);
		assertEquals(REAL.length, table.getCases().length);
		String eol = program.getListing().getComment(CommentType.EOL, addr(SWITCH));
		assertNotNull(eol);
		assertTrue(eol, eol.contains("-> 4 entries (index from a keyed search loop)"));
	}

	/** Another way into J brings a Y the loop does not explain: the rule must not claim it. */
	@Test
	public void secondEntryIntoTheJoinDeclines() throws Exception {
		ProgramDB program = build(true);
		Function function = createFunction(program);
		JumpTable table = decompiledTable(program, function);
		assertNull(SearchLoopDispatch.cases(program,
			program.getListing().getInstructionAt(addr(SWITCH)),
			new ArrayList<>(Arrays.asList(table.getCases()))));
	}

	@Test
	public void xIndexedFormResolvesTheSameFourRecords() throws Exception {
		ProgramDB program = build(false, X_CODE);
		Function function = createFunction(program);
		JumpTable table = decompiledTable(program, function);
		List<Address> cases = SearchLoopDispatch.cases(program,
			program.getListing().getInstructionAt(addr(SWITCH)),
			new ArrayList<>(Arrays.asList(table.getCases())));
		assertNotNull(cases);
		List<Address> expected = new ArrayList<>();
		for (long t : REAL) {
			expected.add(addr(t));
		}
		assertEquals(expected, cases);
	}

	/** LDX #n / CMP tbl,Y / ... / LDA tbl,X is neither form: it must decline. */
	@Test
	public void mixedRegisterLoopDeclines() throws Exception {
		ProgramDB program = build(false, MIXED_CODE);
		Function function = createFunction(program);
		JumpTable table = decompiledTable(program, function);
		assertNull(SearchLoopDispatch.cases(program,
			program.getListing().getInstructionAt(addr(SWITCH)),
			new ArrayList<>(Arrays.asList(table.getCases()))));
	}
}
