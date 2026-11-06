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
import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import gdtbuilder.GameCompiler;
import ghidra.app.util.importer.MessageLog;
import retromachines.C64GameDescriptors.Descriptor;
import retromachines.C64GameDescriptors.Resolution;

/** C64 game descriptors (bead grm-hb6.30): compile, resolve by member sha, merge, forth passthrough. */
public class C64GameDescriptorsTest {

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	private static final String SHA_A = "a".repeat(64);
	private static final String SHA_B = "b".repeat(64);

	private static final String YAML = """
		schema: 2
		game: { id: demo, title: Demo, platform: c64, provenance: "synthetic" }
		entries:
		  - { addr: 0xC010, name: game_init }
		  - { addr: 0xC020, name: game_table, kind: label, comment: "a table" }
		forth:
		  ip: 0x7E
		  handlers: { 0x08F9: DOCON }
		members:
		  - sha256: "%s"
		    name: A.PRG
		    entries:
		      - { addr: 0xC010, name: a_init }
		      - { addr: 0xC030, name: a_extra }
		    forth:
		      names: { 0x0B2E: { name: EXIT } }
		  - sha256: "%s"
		    name: B.PRG
		""".formatted(SHA_A, SHA_B);

	private Descriptor compile(String yaml, boolean overlay) throws Exception {
		File f = tmp.newFile();
		Files.writeString(f.toPath(), yaml);
		GameCompiler.CompileResult r = GameCompiler.compileOverlay(f);
		assertTrue(String.valueOf(r.errors()), r.ok());
		JsonObject doc = new Gson().toJsonTree(r.gameDoc()).getAsJsonObject();
		Descriptor d = C64GameDescriptors.parse(doc, f.getPath(), overlay);
		assertNotNull(d);
		return d;
	}

	@Test
	public void resolvesMemberAndMergesEntries() throws Exception {
		Descriptor d = compile(YAML, false);
		MessageLog log = new MessageLog();
		Resolution a = C64GameDescriptors.resolve(List.of(d), SHA_A, log);
		assertEquals("demo", a.gameId());
		assertEquals("A.PRG", a.memberName());
		List<JsonObject> entries = a.entries();
		assertEquals(3, entries.size());
		// member entry replaces the game entry at the same address
		assertEquals("a_init", entries.get(0).get("name").getAsString());
		assertEquals("label", entries.get(1).get("kind").getAsString());
		assertEquals("function", entries.get(0).get("kind").getAsString());

		Resolution b = C64GameDescriptors.resolve(List.of(d), SHA_B, log);
		assertEquals(2, b.entries().size());
		assertNull(b.memberForth());
		assertNull(C64GameDescriptors.resolve(List.of(d), "c".repeat(64), log));
	}

	@Test
	public void forthIsPassedThroughVerbatim() throws Exception {
		Resolution a = C64GameDescriptors.resolve(List.of(compile(YAML, false)), SHA_A,
			new MessageLog());
		assertEquals(0x7E, a.gameForth().get("ip").getAsInt());
		// YAML integer keys become JSON string keys (decimal), values untouched.
		assertEquals("DOCON",
			a.gameForth().getAsJsonObject("handlers").get(String.valueOf(0x08F9)).getAsString());
		assertEquals("EXIT", a.memberForth().getAsJsonObject("names")
				.getAsJsonObject(String.valueOf(0x0B2E)).get("name").getAsString());
	}

	@Test
	public void overlayShadowsCuratedAndDuplicatesAreAmbiguous() throws Exception {
		Descriptor curated = compile(YAML, false);
		Descriptor overlay = compile(YAML.replace("id: demo", "id: mine"), true);
		MessageLog log = new MessageLog();
		assertEquals("mine", C64GameDescriptors.resolve(List.of(curated, overlay), SHA_A, log)
				.gameId());
		assertTrue(log.toString().contains("shadows curated"));

		MessageLog log2 = new MessageLog();
		List<Descriptor> two = new ArrayList<>(List.of(curated, compile(
			YAML.replace("id: demo", "id: other"), false)));
		assertNull(C64GameDescriptors.resolve(two, SHA_A, log2));
		assertTrue(log2.toString().contains("ambiguous"));
	}

	@Test
	public void nesDescriptorIsNotAC64Descriptor() {
		JsonObject doc = new JsonObject();
		JsonObject game = new JsonObject();
		game.addProperty("id", "x");
		doc.add("game", game);
		assertNull(C64GameDescriptors.parse(doc, "p", false));
	}

	@Test
	public void compilerRejectsBadShapes() throws Exception {
		assertRejected(YAML.replace("kind: label", "kind: bogus"), "unsupported kind");
		assertRejected(YAML.replace("addr: 0xC030", "addr: 0xC010"), "listed twice");
		assertRejected(YAML.replace(SHA_B, SHA_A), "listed twice");
		assertRejected(YAML.replace(SHA_B, "xyz"), "64 hex digits");
		assertRejected(YAML.replace("forth:\n  ip: 0x7E\n  handlers: { 0x08F9: DOCON }",
			"forth: [1]"), "must be a mapping");
		assertRejected(YAML.replace("platform: c64,", "platform: c64, board: x,"),
			"unknown key 'board'");
		assertRejected(YAML + "banking: {}\n", "unknown top-level key");
		assertRejected(YAML.replace("addr: 0xC030", "addr: 0x10000"), "16-bit");
	}

	private void assertRejected(String yaml, String fragment) throws Exception {
		File f = tmp.newFile();
		Files.writeString(f.toPath(), yaml);
		GameCompiler.CompileResult r = GameCompiler.compileOverlay(f);
		assertFalse(r.ok());
		assertTrue(r.errors().toString(), r.errors().toString().contains(fragment));
	}
}
