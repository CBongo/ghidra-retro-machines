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
	public void compilesFixedAfterInit() throws Exception {
		String yaml = validYaml().replace("initial_state: { prg_mode: 1 }",
			"fixed_after_init: [prg_mode, mirroring]");
		JsonObject doc = compile("fixed", yaml);
		var list = doc.getAsJsonObject("banking").getAsJsonArray("fixed_after_init");
		assertEquals(2, list.size());
		assertEquals("prg_mode", list.get(0).getAsString());
		assertEquals("mirroring", list.get(1).getAsString());
	}

	@Test
	public void emptyFixedAfterInitIsRejected() throws Exception {
		expectError("fixedempty", validYaml().replace("initial_state: { prg_mode: 1 }",
			"fixed_after_init: []"), "names no fields");
	}

	@Test
	public void nonListFixedAfterInitIsRejected() throws Exception {
		expectError("fixedmap", validYaml().replace("initial_state: { prg_mode: 1 }",
			"fixed_after_init: { prg_mode: 1 }"), "list of field names");
	}

	@Test
	public void nonStringFixedAfterInitEntryIsRejected() throws Exception {
		expectError("fixedint", validYaml().replace("initial_state: { prg_mode: 1 }",
			"fixed_after_init: [3]"), "field-name strings");
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

	private static final String SYMBOLS = """
		symbols:
		  - set: mine
		    default: true
		    provenance: "me"
		    inline:
		      - { addr: 0x1000, name: a, kind: label, comment: "hi" }
		      - { addr: 0x1000, name: dup, kind: label }
		      - { addr: 0x1000, name: b, kind: entry, block: W8000_M3_B1 }
		""";

	@Test
	public void compilesSymbolSetsWithBlockQualifierAndDedup() throws Exception {
		JsonObject doc = compile("syms", validYaml() + SYMBOLS);
		JsonObject set = doc.getAsJsonArray("symbols").get(0).getAsJsonObject();
		assertEquals("mine", set.get("set").getAsString());
		assertEquals("me", set.get("provenance").getAsString());
		assertEquals(2, set.getAsJsonArray("entries").size());   // same addr in another block is kept
		JsonObject first = set.getAsJsonArray("entries").get(0).getAsJsonObject();
		assertEquals("a", first.get("name").getAsString());
		assertEquals("hi", first.get("comment").getAsString());
		assertEquals("W8000_M3_B1",
			set.getAsJsonArray("entries").get(1).getAsJsonObject().get("block").getAsString());
	}

	@Test
	public void symbolSetNeedsProvenanceAndRejectsSource() throws Exception {
		expectError("noprov", validYaml() + SYMBOLS.replace("    provenance: \"me\"\n", ""),
			"provenance");
		expectError("src", validYaml() + SYMBOLS.replace("    inline:", "    source: x.yaml\n    inline:"),
			"source:");
		expectError("kind", validYaml() + SYMBOLS.replace("kind: entry", "kind: vector"),
			"unsupported kind");
	}

	// ---- banking.bank_identifying_offsets (bead grm-mej.7) ----

	private static final String IDENTIFYING = """
		  bank_identifying_offsets:
		    - address: 0xBFFF
		      shift: 1
		      low: 1
		      provenance: "fed1 commits 2*A+1; checks $BFFF at $FEFB"
		""";

	@Test
	public void compilesBankIdentifyingOffsets() throws Exception {
		JsonObject doc = compile("ident", validYaml() + IDENTIFYING);
		JsonObject banking = doc.getAsJsonObject("banking");
		assertEquals(1, banking.getAsJsonObject("initial_state").get("prg_mode").getAsInt());
		JsonObject entry =
			banking.getAsJsonArray("bank_identifying_offsets").get(0).getAsJsonObject();
		assertEquals(0xBFFF, entry.get("address").getAsInt());
		assertEquals(1, entry.get("shift").getAsInt());
		assertEquals(1, entry.get("low").getAsInt());
		assertEquals("fed1 commits 2*A+1; checks $BFFF at $FEFB",
			entry.get("provenance").getAsString());
	}

	@Test
	public void bankIdentifyingOffsetsAloneIsABankingSection() throws Exception {
		String yaml = validYaml().replace("  initial_state: { prg_mode: 1 }\n", "") + IDENTIFYING;
		JsonObject banking = compile("identonly", yaml).getAsJsonObject("banking");
		assertFalse(banking.has("initial_state"));
		assertEquals(1, banking.getAsJsonArray("bank_identifying_offsets").size());
	}

	@Test
	public void malformedBankIdentifyingOffsetsAreRejected() throws Exception {
		expectError("shift3", validYaml() + IDENTIFYING.replace("shift: 1", "shift: 3"),
			"shift must be");
		expectError("lowwide", validYaml() + IDENTIFYING.replace("low: 1", "low: 2"),
			"low must be");
		expectError("noprov", validYaml() + IDENTIFYING.replace(
			"      provenance: \"fed1 commits 2*A+1; checks $BFFF at $FEFB\"\n", ""),
			"provenance");
		expectError("extra", validYaml() + IDENTIFYING.replace("low: 1", "low: 1\n      bank: 3"),
			"unknown key 'bank'");
		expectError("notlist", validYaml() + "  bank_identifying_offsets: 0xBFFF\n",
			"non-empty list");
	}

	// ---- biased bank_identifying_offsets and banking.save_cells (bead grm-mej.9) ----

	private static final String BIASED = """
		  bank_identifying_offsets:
		    - address: 0xA000
		      shift: 0
		      low: 0
		      bias: 32
		      modulus_bits: 1
		      provenance: "byte 0 of even bank N is $20+N"
		""";

	private static final String SAVE_CELLS = """
		  save_cells:
		    - address: 0xF0
		      provenance: "dedicated save cell of FUN_919e/FUN_91d1"
		""";

	@Test
	public void compilesBiasedIdentifyingOffsetAndSaveCells() throws Exception {
		JsonObject banking =
			compile("biased", validYaml() + BIASED + SAVE_CELLS).getAsJsonObject("banking");
		JsonObject entry =
			banking.getAsJsonArray("bank_identifying_offsets").get(0).getAsJsonObject();
		assertEquals(32, entry.get("bias").getAsInt());
		assertEquals(1, entry.get("modulus_bits").getAsInt());
		JsonObject cell = banking.getAsJsonArray("save_cells").get(0).getAsJsonObject();
		assertEquals(0xF0, cell.get("address").getAsInt());
		assertEquals("dedicated save cell of FUN_919e/FUN_91d1",
			cell.get("provenance").getAsString());
	}

	@Test
	public void classicIdentifyingOffsetEmitsNoBiasKeys() throws Exception {
		JsonObject entry = compile("classic", validYaml() + IDENTIFYING)
			.getAsJsonObject("banking").getAsJsonArray("bank_identifying_offsets").get(0)
			.getAsJsonObject();
		assertFalse(entry.has("bias"));
		assertFalse(entry.has("modulus_bits"));
	}

	@Test
	public void saveCellsAloneIsABankingSection() throws Exception {
		String yaml = validYaml().replace("  initial_state: { prg_mode: 1 }\n", "") + SAVE_CELLS;
		JsonObject banking = compile("cellsonly", yaml).getAsJsonObject("banking");
		assertEquals(1, banking.getAsJsonArray("save_cells").size());
	}

	@Test
	public void malformedBiasedOffsetsAndSaveCellsAreRejected() throws Exception {
		expectError("biashuge", validYaml() + BIASED.replace("bias: 32", "bias: 300"),
			"bias must be");
		expectError("biasshift", validYaml() + BIASED.replace("shift: 0", "shift: 1"),
			"must have shift 0");
		expectError("modlow", validYaml() + BIASED.replace("modulus_bits: 1", "modulus_bits: 0")
			.replace("low: 0", "low: 1"),
			"low must be");
		expectError("modbig", validYaml() + BIASED.replace("modulus_bits: 1", "modulus_bits: 3"),
			"modulus_bits must be");
		expectError("cellsnotlist", validYaml() + "  save_cells: 0xF0\n", "non-empty list");
		expectError("cellsempty", validYaml() + "  save_cells: []\n", "non-empty list");
		expectError("cellsnoprov", validYaml() + SAVE_CELLS.replace(
			"      provenance: \"dedicated save cell of FUN_919e/FUN_91d1\"\n", ""), "provenance");
		expectError("cellswide", validYaml() + SAVE_CELLS.replace("0xF0", "0x10000"), "16-bit");
		expectError("cellsextra",
			validYaml() + SAVE_CELLS.replace("address: 0xF0", "address: 0xF0\n      size: 2"),
			"unknown key 'size'");
		expectError("cellsdup", validYaml() + SAVE_CELLS +
			"    - address: 0xF0\n      provenance: \"again\"\n", "listed twice");
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
