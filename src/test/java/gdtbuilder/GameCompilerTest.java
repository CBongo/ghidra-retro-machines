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
package gdtbuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * {@link GameCompiler}: the curated per-game descriptor build step (bead {@code grm-hb6.12}).
 * Same TemporaryFolder + gson-round-trip pattern as {@link MapCompilerTest}.
 */
public class GameCompilerTest {

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	private static final String PRG_SHA =
		"f4130ba655229d9999fa3b2c59984165810c9b9b125c43b1ff899872e7fedff4";
	private static final String FILE_SHA =
		"4377a7f5e6eb50bdd2ac6f249bf1a7085500aca8eb41f38545c3a2731c51a579";

	private JsonObject compile(String name, String yaml) throws Exception {
		Path dir = tmp.getRoot().toPath();
		Path yamlPath = dir.resolve(name + ".yaml");
		Path gmapPath = dir.resolve(name + ".gmap");
		Files.writeString(yamlPath, yaml);
		GameCompiler.main(new String[] { yamlPath.toString(), gmapPath.toString() });
		return JsonParser.parseString(Files.readString(gmapPath)).getAsJsonObject();
	}

	private String validYaml() {
		return """
			schema: 2
			game:
			  id: smb3
			  title: "Super Mario Bros 3 (PRG 1) (U)"
			  board: nes_mmc3
			  identity:
			    prg_sha256: "%s"
			    file_sha256: "%s"
			  provenance: "test fixture"
			banking:
			  initial_state: { prg_mode: 1 }
			""".formatted(PRG_SHA, FILE_SHA);
	}

	@Test
	public void compilesIdentityAndHint() throws Exception {
		JsonObject doc = compile("smb3", validYaml());
		assertEquals(2, doc.get("schema").getAsInt());

		JsonObject game = doc.getAsJsonObject("game");
		assertEquals("smb3", game.get("id").getAsString());
		assertEquals("Super Mario Bros 3 (PRG 1) (U)", game.get("title").getAsString());
		assertEquals("nes_mmc3", game.get("board").getAsString());
		assertEquals("test fixture", game.get("provenance").getAsString());

		JsonObject identity = game.getAsJsonObject("identity");
		assertEquals(PRG_SHA, identity.get("prg_sha256").getAsString());
		assertEquals(FILE_SHA, identity.get("file_sha256").getAsString());

		JsonObject initialState =
			doc.getAsJsonObject("banking").getAsJsonObject("initial_state");
		assertEquals(1, initialState.get("prg_mode").getAsInt());
	}

	@Test
	public void hashesAreLowercased() throws Exception {
		String yaml = validYaml().replace(PRG_SHA, PRG_SHA.toUpperCase())
			.replace(FILE_SHA, FILE_SHA.toUpperCase());
		JsonObject doc = compile("upper", yaml);
		JsonObject identity = doc.getAsJsonObject("game").getAsJsonObject("identity");
		assertEquals(PRG_SHA, identity.get("prg_sha256").getAsString());
		assertEquals(FILE_SHA, identity.get("file_sha256").getAsString());
	}

	@Test
	public void noBankingSectionIsFine() throws Exception {
		String yaml = """
			schema: 2
			game:
			  id: nohints
			  title: "No Hints"
			  board: nes_nrom
			  identity:
			    prg_sha256: "%s"
			    file_sha256: "%s"
			  provenance: "test fixture"
			""".formatted(PRG_SHA, FILE_SHA);
		JsonObject doc = compile("nohints", yaml);
		assertFalse("banking: must be omitted, not emitted empty, when the descriptor has none",
			doc.has("banking"));
	}

	@Test
	public void missingSchemaIsRejected() throws Exception {
		Path dir = tmp.getRoot().toPath();
		Path yamlPath = dir.resolve("bad.yaml");
		Files.writeString(yamlPath, "game: { id: x }\n");
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> GameCompiler.main(
				new String[] { yamlPath.toString(), dir.resolve("bad.gmap").toString() }));
		assertTrue(e.getMessage(), e.getMessage().contains("schema"));
	}

	@Test
	public void wrongSchemaVersionIsRejected() throws Exception {
		String yaml = validYaml().replace("schema: 2", "schema: 1");
		expectError("wrongschema", yaml, "schema");
	}

	@Test
	public void missingGameSectionIsRejected() throws Exception {
		expectError("nogame", "schema: 2\n", "game:");
	}

	@Test
	public void missingIdentityIsRejected() throws Exception {
		String yaml = """
			schema: 2
			game:
			  id: x
			  title: X
			  board: nes_nrom
			  provenance: test
			""";
		expectError("noidentity", yaml, "identity");
	}

	@Test
	public void malformedShaIsRejected() throws Exception {
		String yaml = validYaml().replace(PRG_SHA, "not-a-hash");
		expectError("badsha", yaml, "64 hex digits");
	}

	@Test
	public void packedIntegerInitialStateIsRejected() throws Exception {
		// The game tier must not know the board's bit layout -- only a field-name map is
		// accepted, never a pre-packed integer (docs/per-game-descriptors-design.md;
		// bead grm-hb6.12).
		String yaml = validYaml().replace("{ prg_mode: 1 }", "3");
		expectError("packedint", yaml, "field-name map");
	}

	@Test
	public void emptyInitialStateIsRejected() throws Exception {
		String yaml = validYaml().replace("{ prg_mode: 1 }", "{}");
		expectError("emptyhint", yaml, "names no fields");
	}

	private void expectError(String name, String yaml, String messagePart) throws Exception {
		Path dir = tmp.getRoot().toPath();
		Path yamlPath = dir.resolve(name + ".yaml");
		Files.writeString(yamlPath, yaml);
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> GameCompiler.main(
				new String[] { yamlPath.toString(), dir.resolve(name + ".gmap").toString() }));
		assertTrue("expected error containing '" + messagePart + "', got: " + e.getMessage(),
			e.getMessage().contains(messagePart));
	}
}
