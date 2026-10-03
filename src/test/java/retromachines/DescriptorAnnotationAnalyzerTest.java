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

import java.io.File;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@link DescriptorAnnotationAnalyzer} (grm-hb6.14), driven through its
 * {@code applyAll} seam for the same reason as {@link DescriptorCopyHintAnalyzerTest}: the
 * descriptor lookup resolves against installed module data dirs only.
 */
public class DescriptorAnnotationAnalyzerTest extends AbstractBundledLanguageTest {

	private static final String V1 = """
		{ "symbols": [
		  { "set": "vectors", "default": true, "entries": [
		    { "addr": 4096, "name": "ALPHA", "kind": "label", "comment": "first" } ] },
		  { "set": "extras", "default": true, "entries": [
		    { "addr": 4100, "name": "EXTRA", "kind": "label" } ] },
		  { "set": "optional", "default": false, "entries": [
		    { "addr": 4104, "name": "OPT", "kind": "label" } ] } ] }
		""";

	/** V1 plus one newly shipped label in the default-on "vectors" set. */
	private static final String V2 = """
		{ "symbols": [
		  { "set": "vectors", "default": true, "entries": [
		    { "addr": 4096, "name": "ALPHA", "kind": "label", "comment": "first" },
		    { "addr": 4098, "name": "BETA", "kind": "label" } ] },
		  { "set": "extras", "default": true, "entries": [
		    { "addr": 4100, "name": "EXTRA", "kind": "label" } ] },
		  { "set": "optional", "default": false, "entries": [
		    { "addr": 4104, "name": "OPT", "kind": "label" } ] } ] }
		""";

	private static JsonObject json(String s) {
		return JsonParser.parseString(s).getAsJsonObject();
	}

	private ProgramBuilder newBuilder() throws Exception {
		ProgramBuilder b = new ProgramBuilder("Test", "6502:LE:16:default");
		uninitializedRam(b, "RAM", "0x1000", 0x100);
		return b;
	}

	private void apply(ProgramDB program, JsonObject map, FileDataTypeManager gdt) {
		int tx = program.startTransaction("descriptor annotations");
		try {
			new DescriptorAnnotationAnalyzer().applyAll(program, map, gdt, true, true,
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private void record(ProgramDB program, String set, boolean applied) {
		int tx = program.startTransaction("record");
		try {
			DescriptorAnnotationAnalyzer.recordSymbolSetChoice(program, set, applied);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private static Symbol primary(Program p, Address a) {
		return p.getSymbolTable().getPrimarySymbol(a);
	}

	@Test
	public void reapplyAddsNewlyShippedLabel() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		apply(p, json(V1), null);
		assertNull(primary(p, b.addr("0x1002")));

		apply(p, json(V2), null);

		Symbol beta = primary(p, b.addr("0x1002"));
		assertNotNull("the label shipped in V2 must appear on re-analysis", beta);
		assertEquals("BETA", beta.getName());
		assertEquals("ALPHA", primary(p, b.addr("0x1000")).getName());
	}

	@Test
	public void reapplyDoesNotClobberUserDefinedLabelOrComment() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		int tx = p.startTransaction("user work");
		p.getSymbolTable().createLabel(b.addr("0x1002"), "my_label", SourceType.USER_DEFINED);
		p.getListing().setComment(b.addr("0x1000"), CommentType.EOL, "mine");
		p.endTransaction(tx, true);

		apply(p, json(V2), null);

		Symbol s = primary(p, b.addr("0x1002"));
		assertEquals("my_label", s.getName());
		assertEquals(SourceType.USER_DEFINED, s.getSource());
		assertEquals("no BETA may be stacked beside a user label", 1,
			p.getSymbolTable().getSymbols(b.addr("0x1002")).length);
		String comment = p.getListing().getComment(CommentType.EOL, b.addr("0x1000"));
		assertTrue("user comment survives verbatim", comment.startsWith("mine"));
	}

	@Test
	public void secondRunIsIdempotent() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		apply(p, json(V2), null);
		long symbols = p.getSymbolTable().getNumSymbols();
		String comment = p.getListing().getComment(CommentType.EOL, b.addr("0x1000"));

		apply(p, json(V2), null);

		assertEquals(symbols, p.getSymbolTable().getNumSymbols());
		assertEquals(comment, p.getListing().getComment(CommentType.EOL, b.addr("0x1000")));
	}

	@Test
	public void recordedChoicesAreHonoured() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		record(p, "extras", false);   // user turned a default-on set off at import
		record(p, "optional", true);  // ...and a default-off set on

		apply(p, json(V2), null);

		assertNull("a recorded disabled toggle must be honoured",
			primary(p, b.addr("0x1004")));
		assertNotNull("a recorded enabled toggle must be honoured",
			primary(p, b.addr("0x1008")));
		assertNotNull("a set with no recorded choice falls back to its default (on)",
			primary(p, b.addr("0x1000")));
	}

	@Test
	public void legacyProgramFallsBackToDescriptorDefaults() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();

		apply(p, json(V2), null);

		assertNotNull(primary(p, b.addr("0x1004")));
		assertNull("default-off set stays off without a recorded choice",
			primary(p, b.addr("0x1008")));
	}

	@Test
	public void structTypeIsReappliedOnceAndNeverOverDefinedData() throws Exception {
		ProgramBuilder b = newBuilder();
		uninitializedRam(b, "REGS", "0x2000", 4);
		ProgramDB p = b.getProgram();
		File f = new File(getTestDirectoryPath(), "annot-" + System.nanoTime() + ".gdt");
		FileDataTypeManager gdt = FileDataTypeManager.createFileArchive(f);
		try {
			int tx = gdt.startTransaction("types");
			StructureDataType st = new StructureDataType("TESTREGS", 0);
			st.add(ByteDataType.dataType, "A", null);
			st.add(ByteDataType.dataType, "B", null);
			gdt.addDataType(st, null);
			gdt.endTransaction(tx, true);

			JsonObject map = json("""
				{ "regions": [ { "name": "REGS", "start": 8192, "end": 8195,
				    "kind": "io", "type": "TESTREGS" } ] }
				""");
			apply(p, map, gdt);
			Data d = p.getListing().getDataAt(b.addr("0x2000"));
			assertNotNull(d);
			assertEquals("TESTREGS", d.getDataType().getName());

			apply(p, map, gdt);
			assertEquals("TESTREGS",
				p.getListing().getDataAt(b.addr("0x2000")).getDataType().getName());
		}
		finally {
			gdt.close();
		}
	}
}
