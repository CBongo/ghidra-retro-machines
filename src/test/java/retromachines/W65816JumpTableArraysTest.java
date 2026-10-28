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
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * grm-iv4i: {@link W65816JumpTableAnalyzer} lays its word tables through
 * {@link JumpTableArrays#layWords}, so every kept entry carries one {@code ANALYSIS} DATA
 * reference to its bank:word target -- both when a table is first bounded and when a later
 * dispatch shortens it -- and no reference sits on bytes past the bound.
 */
public class W65816JumpTableArraysTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		MemoryBlock rom = builder.createMemory(".rom", "0x8000", 0x1000);
		program = builder.getProgram();
		setWritable(rom, false);
		inTx(program, "rom executable", () -> rom.setExecute(true));
		setContext("ctx_EF", 0);
		setContext("ctx_MF", 1);
		setContext("ctx_XF", 1);
		// Handlers: one RTS each, undecoded until the analyzer reaches them.
		for (long t = 0x8200; t <= 0x8230; t += 0x10) {
			builder.setBytes(hex(t), "60", false);
		}
		// Four entries, then $0000 (unmapped: implausible) ends the table.
		builder.setBytes("0x8100", "00 82 10 82 20 82 30 82 00 00", false);
	}

	@Test
	public void eachKeptEntryReferencesItsTarget() throws Exception {
		dispatchAt("0x8000", 0x8100);

		assertWordArray(0x8100, 4);
		assertEntryRefs(0x8100, 0x8200, 0x8210, 0x8220, 0x8230);
		assertEquals("no reference past the bound", 0, dataRefsFrom(0x8108).size());
	}

	/**
	 * A dispatch decoded later reads a table starting inside the first one, which
	 * {@code repairOverreads} then cuts there: the shortened array keeps a reference per entry.
	 */
	@Test
	public void aShortenedTableKeepsItsEntryReferences() throws Exception {
		dispatchAt("0x8000", 0x8100);
		assertWordArray(0x8100, 4);

		dispatchAt("0x8010", 0x8104);

		assertWordArray(0x8100, 2);
		assertEntryRefs(0x8100, 0x8200, 0x8210);
		assertWordArray(0x8104, 2);
		assertEntryRefs(0x8104, 0x8220, 0x8230);
	}

	/** {@code JMP ($table,X)} at {@code site}, disassembled, then the analyzer run over it. */
	private void dispatchAt(String site, long table) throws Exception {
		builder.setBytes(site,
			String.format("7c %02x %02x", table & 0xff, (table >> 8) & 0xff), false);
		builder.disassemble(site, 3, false);
		Address s = addr(site);
		inTx(program, "analyze", () -> new W65816JumpTableAnalyzer().added(program,
			new AddressSet(s, s.add(2)), TaskMonitor.DUMMY, new MessageLog()));
	}

	private void assertWordArray(long at, int n) {
		Data d = program.getListing().getDefinedDataAt(addr(at));
		assertNotNull("no table at " + hex(at), d);
		assertTrue("not an array at " + hex(at), d.getDataType() instanceof Array);
		Array a = (Array) d.getDataType();
		assertTrue(a.getDataType() instanceof WordDataType);
		assertEquals("entries at " + hex(at), n, a.getNumElements());
	}

	private void assertEntryRefs(long table, long... targets) {
		for (int i = 0; i < targets.length; i++) {
			List<Reference> refs = dataRefsFrom(table + 2L * i);
			assertEquals("refs from entry " + i + " of " + hex(table), 1, refs.size());
			assertEquals(addr(targets[i]), refs.get(0).getToAddress());
		}
	}

	private List<Reference> dataRefsFrom(long from) {
		List<Reference> out = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(from))) {
			if (RefType.DATA.equals(r.getReferenceType()) && r.getSource() == SourceType.ANALYSIS) {
				out.add(r);
			}
		}
		return out;
	}

	private void setContext(String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull("no context field named " + field, register);
		inTx(program, "set " + field, () -> program.getProgramContext()
				.setValue(register, addr("0x8000"), addr("0x8fff"), BigInteger.valueOf(value)));
	}
}
