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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import gdtbuilder.GameCompiler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * The {@code comments:} carrier end to end (bead grm-hb6.18): export -> compile -> apply onto a
 * fresh program, the apply seam's idempotence / no-clobber / toggle behaviour.
 */
public class GameDescriptorCommentsCarrierTest extends AbstractBundledLanguageTest {

	private static final String PRG =
		"f4130ba655229d9999fa3b2c59984165810c9b9b125c43b1ff899872e7fedff4";
	private static final String FILE =
		"4377a7f5e6eb50bdd2ac6f249bf1a7085500aca8eb41f38545c3a2731c51a579";

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	private ProgramBuilder newBuilder() throws Exception {
		ProgramBuilder b = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(b, "RAM", "0x1000", 0x100);
		uninitializedRamOverlay(b, "PRG_LO_B1", "0x8000", 0x100);
		return b;
	}

	private static void tx(ProgramDB p, Runnable r) {
		inTx(p, "edit", () -> r.run());
	}

	private static void comment(ProgramDB p, Address a, CommentType t, String text) {
		tx(p, () -> p.getListing().setComment(a, t, text));
	}

	private static String get(ProgramDB p, Address a, CommentType t) {
		return p.getListing().getComment(t, a);
	}

	private JsonObject exportAndCompile(ProgramDB p) throws Exception {
		GameDescriptorExporter.Result r = GameDescriptorExporter.export(p,
			new GameDescriptorExporter.Request("g", "G (U)", "nes_mmc1", "test", PRG, FILE, null));
		File f = new File(tmp.getRoot(), "g.yaml");
		Files.writeString(f.toPath(), r.yaml());
		GameCompiler.CompileResult cr = GameCompiler.compileOverlay(f);
		assertTrue(r.yaml() + cr.errors(), cr.ok());
		return new Gson().toJsonTree(cr.gameDoc()).getAsJsonObject();
	}

	private ProgramDB annotatedSource() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		tx(p, () -> {
			try {
				p.getSymbolTable().createLabel(b.addr("0x1000"), "lab", SourceType.USER_DEFINED);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		Address banked = p.getMemory().getBlock("PRG_LO_B1").getStart().add(0x20);
		comment(p, b.addr("0x1000"), CommentType.EOL, "eol on label");
		comment(p, b.addr("0x1000"), CommentType.PRE, "pre on label");
		comment(p, b.addr("0x1010"), CommentType.EOL, "eol unlabelled");
		comment(p, b.addr("0x1010"), CommentType.PLATE, "plate unlabelled");
		comment(p, b.addr("0x1020"), CommentType.POST, "post");
		comment(p, b.addr("0x1030"), CommentType.REPEATABLE, "repeatable");
		comment(p, banked, CommentType.PLATE, "banked plate");
		comment(p, banked, CommentType.EOL, "banked eol");
		return p;
	}

	@Test
	public void everyCommentTypeRoundTripsLabelledUnlabelledAndBanked() throws Exception {
		JsonObject doc = exportAndCompile(annotatedSource());
		assertEquals(1, doc.getAsJsonArray("comments").size());
		assertEquals("g-comments",
			doc.getAsJsonArray("comments").get(0).getAsJsonObject().get("set").getAsString());

		ProgramBuilder fresh = newBuilder();
		ProgramDB p = fresh.getProgram();
		MessageLog log = new MessageLog();
		tx(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc, TaskMonitor.DUMMY,
			log));
		Address banked = p.getMemory().getBlock("PRG_LO_B1").getStart().add(0x20);
		assertEquals("eol on label", get(p, fresh.addr("0x1000"), CommentType.EOL));
		assertEquals("pre on label", get(p, fresh.addr("0x1000"), CommentType.PRE));
		assertEquals("eol unlabelled", get(p, fresh.addr("0x1010"), CommentType.EOL));
		assertEquals("plate unlabelled", get(p, fresh.addr("0x1010"), CommentType.PLATE));
		assertEquals("post", get(p, fresh.addr("0x1020"), CommentType.POST));
		assertEquals("repeatable", get(p, fresh.addr("0x1030"), CommentType.REPEATABLE));
		assertEquals("banked plate", get(p, banked, CommentType.PLATE));
		assertEquals("banked eol", get(p, banked, CommentType.EOL));
	}

	@Test
	public void secondApplyWritesNothing() throws Exception {
		JsonObject doc = exportAndCompile(annotatedSource());
		ProgramDB p = newBuilder().getProgram();
		MessageLog log = new MessageLog();
		tx(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc, TaskMonitor.DUMMY,
			log));
		long before = p.getModificationNumber();
		int[] written = new int[1];
		tx(p, () -> {
			for (var se : doc.getAsJsonArray("comments")) {
				written[0] += DescriptorSupport.applyCommentSet(p,
					p.getAddressFactory().getDefaultAddressSpace(), se.getAsJsonObject(), log);
			}
		});
		assertEquals(0, written[0]);
		assertEquals(before, p.getModificationNumber());
	}

	@Test
	public void descriptorCommentsAreNotRecordedAsAnalyzerWrites() throws Exception {
		JsonObject doc = exportAndCompile(annotatedSource());
		ProgramBuilder fresh = newBuilder();
		ProgramDB p = fresh.getProgram();
		tx(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc, TaskMonitor.DUMMY,
			new MessageLog()));
		assertFalse(AnalyzerCommentRecord.hasAnyMap(p));
		// ...so they re-export (correct round trip)
		assertTrue(GameDescriptorExporter.export(p, new GameDescriptorExporter.Request("g", "G",
			"nes_mmc1", "t", PRG, FILE, null)).yaml().contains("pre on label"));
	}

	@Test
	public void aUserCommentIsNeverClobbered() throws Exception {
		JsonObject doc = exportAndCompile(annotatedSource());
		ProgramBuilder fresh = newBuilder();
		ProgramDB p = fresh.getProgram();
		comment(p, fresh.addr("0x1010"), CommentType.PLATE, "mine");
		tx(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc, TaskMonitor.DUMMY,
			new MessageLog()));
		assertEquals("mine; plate unlabelled", get(p, fresh.addr("0x1010"), CommentType.PLATE));
	}

	@Test
	public void aDisabledSetIsSkippedAndTheToggleIsNamespaced() throws Exception {
		JsonObject doc = exportAndCompile(annotatedSource());
		ProgramBuilder fresh = newBuilder();
		ProgramDB p = fresh.getProgram();
		// a symbols set of the same name being off must not switch the comments set off...
		tx(p, () -> DescriptorAnnotationAnalyzer.recordSymbolSetChoice(p, "g-comments", false));
		tx(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc, TaskMonitor.DUMMY,
			new MessageLog()));
		assertEquals("post", get(p, fresh.addr("0x1020"), CommentType.POST));
		// ...but the comments set's own recorded choice does
		ProgramBuilder fresh2 = newBuilder();
		ProgramDB p2 = fresh2.getProgram();
		tx(p2, () -> DescriptorAnnotationAnalyzer.recordCommentSetChoice(p2, "g-comments", false));
		tx(p2, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p2, doc, TaskMonitor.DUMMY,
			new MessageLog()));
		assertNull(get(p2, fresh2.addr("0x1020"), CommentType.POST));
	}

	@Test
	public void anUnresolvableBlockLogsAndIgnoresTheEntry() throws Exception {
		JsonObject doc = exportAndCompile(annotatedSource());
		ProgramDB p = newBuilder("Test", "6502:LE:16:default").getProgram();
		MessageLog log = new MessageLog();
		tx(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc, TaskMonitor.DUMMY,
			log));
		assertTrue(log.toString(), log.toString().contains("PRG_LO_B1"));
	}

	@Test
	public void noCommentsMeansNoCommentsKey() throws Exception {
		ProgramBuilder b = newBuilder();
		String yaml = GameDescriptorExporter.export(b.getProgram(),
			new GameDescriptorExporter.Request("g", "G", "nes_mmc1", "t", PRG, FILE, null)).yaml();
		assertFalse(yaml, yaml.contains("comments:"));
	}
}
