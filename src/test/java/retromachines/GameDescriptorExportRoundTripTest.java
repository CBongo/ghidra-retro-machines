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

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import gdtbuilder.GameCompiler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * The bead-required round trip for {@link GameDescriptorExporter} (grm-hb6.5, design section
 * 7): annotate a program, export, validate the output through BOTH {@link GameCompiler}
 * dispositions (overlay and curated build) and the registry's own parse, re-consume it into a
 * fresh program, and assert the same annotations at the same addresses. The source type
 * returns as {@code IMPORTED}, never {@code USER_DEFINED} -- design section 3c.3's rule for
 * descriptor-applied annotations.
 */
public class GameDescriptorExportRoundTripTest extends AbstractBundledLanguageTest {

	private static final String PRG =
		"f4130ba655229d9999fa3b2c59984165810c9b9b125c43b1ff899872e7fedff4";
	private static final String FILE =
		"4377a7f5e6eb50bdd2ac6f249bf1a7085500aca8eb41f38545c3a2731c51a579";

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	private ProgramBuilder newBuilder() throws Exception {
		ProgramBuilder b = new ProgramBuilder("Test", "6502:LE:16:default");
		uninitializedRam(b, "RAM", "0x1000", 0x100);
		uninitializedRamOverlay(b, "PRG_LO_B1", "0x8000", 0x100);
		return b;
	}

	private static GameDescriptorExporter.Request request(Map<String, Integer> initialState) {
		return new GameDescriptorExporter.Request("roundtrip", "Round Trip (U)", "nes_mmc1",
			"exported by a test", PRG, FILE, initialState);
	}

	private static void edit(ProgramDB p, Runnable r) {
		int tx = p.startTransaction("edit");
		try {
			r.run();
		}
		finally {
			p.endTransaction(tx, true);
		}
	}

	private static void label(ProgramDB p, Address a, String name, SourceType src) {
		edit(p, () -> {
			try {
				p.getSymbolTable().createLabel(a, name, src);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}

	private static void comment(ProgramDB p, Address a, CommentType t, String text) {
		edit(p, () -> p.getListing().setComment(a, t, text));
	}

	private static Symbol primary(ProgramDB p, Address a) {
		return p.getSymbolTable().getPrimarySymbol(a);
	}

	/** Annotates a program the way a person plus the analyzers would have. */
	private ProgramBuilder annotated() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		label(p, b.addr("0x1000"), "user_main", SourceType.USER_DEFINED);
		// user text plus an analyzer segment: only the user text may be exported
		comment(p, b.addr("0x1000"), CommentType.EOL, "my note; bank -> 3");
		label(p, b.addr("0x1010"), "user_data", SourceType.USER_DEFINED);
		label(p, b.addr("0x1020"), "analyzer_guess", SourceType.ANALYSIS);
		comment(p, b.addr("0x1020"), CommentType.EOL, "analyzer prose");
		label(p, b.addr("0x1030"), "imported_name", SourceType.IMPORTED);
		comment(p, b.addr("0x1010"), CommentType.PLATE, "plate has no carrier");
		Address banked = b.getProgram().getMemory().getBlock("PRG_LO_B1").getStart()
				.add(0x10);
		label(p, banked, "banked_routine", SourceType.USER_DEFINED);
		comment(p, banked, CommentType.EOL, "lives in bank 1");
		return b;
	}

	@Test
	public void exportIsValidAsOverlayAndCuratedAndReconsumesIdentically() throws Exception {
		ProgramBuilder src = annotated();
		GameDescriptorExporter.Result result = GameDescriptorExporter.export(src.getProgram(),
			request(Map.of("prg_mode", 0)));
		String yaml = result.yaml();

		assertEquals(3, result.labels());
		assertEquals(2, result.comments());
		assertFalse("analyzer-created labels must not be exported", yaml.contains("analyzer_guess"));
		assertFalse("IMPORTED labels must not be exported", yaml.contains("imported_name"));
		assertFalse("analyzer comment segments must be stripped", yaml.contains("bank ->"));
		assertFalse(yaml.contains("include"));
		assertTrue(yaml, yaml.contains("0x1000"));
		assertEquals(1, result.skipped().size());   // the plate comment

		File dir = tmp.getRoot();
		File overlay = new File(dir, "roundtrip.yaml");
		Files.writeString(overlay.toPath(), yaml);

		// Disposition 1: the runtime overlay validator.
		GameCompiler.CompileResult overlayResult = GameCompiler.compileOverlay(overlay);
		assertTrue(overlayResult.errors().toString(), overlayResult.ok());

		// Disposition 2: the curated build, byte for byte the same document.
		File gmap = new File(dir, "roundtrip.gmap");
		GameCompiler.main(new String[] { overlay.getPath(), gmap.getPath() });
		JsonObject curated = JsonParser.parseString(Files.readString(gmap.toPath()))
				.getAsJsonObject();
		JsonObject viaOverlay = new Gson().toJsonTree(overlayResult.gameDoc()).getAsJsonObject();
		assertEquals(curated, viaOverlay);

		// The registry's own scan accepts it and keys it on the identity we wrote.
		MessageLog log = new MessageLog();
		List<GameDescriptorRegistry.GameDescriptor> found =
			GameDescriptorRegistry.scanOverlay(List.of(overlay), log);
		assertEquals(log.toString(), 1, found.size());
		assertEquals(PRG, found.get(0).prgSha256());
		assertEquals("nes_mmc1", found.get(0).board());
		assertEquals(0, curated.getAsJsonObject("banking").getAsJsonObject("initial_state")
				.get("prg_mode").getAsInt());

		// Re-consume into a fresh program of the same shape.
		ProgramBuilder fresh = newBuilder();
		ProgramDB p = fresh.getProgram();
		for (int round = 0; round < 2; round++) {   // second round: idempotence
			edit(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, curated,
				TaskMonitor.DUMMY, log));
		}

		Symbol main = primary(p, fresh.addr("0x1000"));
		assertEquals("user_main", main.getName());
		assertEquals(SourceType.IMPORTED, main.getSource());
		assertEquals("my note", p.getListing().getComment(CommentType.EOL, fresh.addr("0x1000")));
		assertEquals("user_data", primary(p, fresh.addr("0x1010")).getName());
		assertNull(p.getListing().getComment(CommentType.EOL, fresh.addr("0x1010")));
		assertNull("analyzer guesses must not travel", primary(p, fresh.addr("0x1020")));
		assertNull(primary(p, fresh.addr("0x1030")));
		Address banked = p.getMemory().getBlock("PRG_LO_B1").getStart().add(0x10);
		assertEquals("banked_routine", primary(p, banked).getName());
		assertEquals("lives in bank 1", p.getListing().getComment(CommentType.EOL, banked));
		assertEquals(1, p.getSymbolTable().getSymbols(banked).length);
		assertNotNull(log);
	}

	@Test
	public void unresolvableBlockIsIgnoredAndLogged() throws Exception {
		ProgramBuilder src = annotated();
		String yaml = GameDescriptorExporter.export(src.getProgram(), request(null)).yaml();
		File f = new File(tmp.getRoot(), "x.yaml");
		Files.writeString(f.toPath(), yaml);
		JsonObject doc = new Gson().toJsonTree(GameCompiler.compileOverlay(f).gameDoc())
				.getAsJsonObject();

		ProgramBuilder noOverlay = new ProgramBuilder("Test", "6502:LE:16:default");
		uninitializedRam(noOverlay, "RAM", "0x1000", 0x100);
		ProgramDB p = noOverlay.getProgram();
		MessageLog log = new MessageLog();
		edit(p, () -> new DescriptorAnnotationAnalyzer().applyGameSymbols(p, doc,
			TaskMonitor.DUMMY, log));

		assertEquals("user_main", primary(p, noOverlay.addr("0x1000")).getName());
		assertTrue(log.toString(), log.toString().contains("PRG_LO_B1"));
	}

	@Test
	public void programWithoutIdentityRefusesToExport() throws Exception {
		ProgramBuilder b = newBuilder();
		try {
			GameDescriptorExporter.export(b.getProgram(), new GameDescriptorExporter.Request(
				"x", "x", "nes_mmc1", "p", null, null, null));
			throw new AssertionError("expected IllegalStateException");
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("identity"));
		}
	}

	@Test
	public void noAnnotationsStillExportsValidIdentityOnlyDescriptor() throws Exception {
		ProgramBuilder b = newBuilder();
		String yaml = GameDescriptorExporter.export(b.getProgram(), request(null)).yaml();
		File f = new File(tmp.getRoot(), "empty.yaml");
		Files.writeString(f.toPath(), yaml);
		assertTrue(GameCompiler.compileOverlay(f).ok());
	}
}
