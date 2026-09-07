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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

import retromachines.GameDescriptorRegistry.GameDescriptor;

/**
 * Pure-JUnit coverage of {@link GameDescriptorRegistry}'s two testable seams (bead
 * {@code grm-hb6.12}): {@link GameDescriptorRegistry#parse}, which turns one compiled
 * {@code .gmap} document into a {@link GameDescriptor} or refuses it with a logged reason, and
 * {@link GameDescriptorRegistry#resolve}, the pure matching function above
 * {@link GameDescriptorRegistry#scan}'s file I/O -- mirroring how {@link
 * InitialStateResolutionTest} and {@link GameInitialStateHintTest} stay off the Ghidra
 * {@code Application}/file-I/O path entirely.
 */
public class GameDescriptorRegistryTest {

	private static final String PRG_A =
		"f4130ba655229d9999fa3b2c59984165810c9b9b125c43b1ff899872e7fedff4";
	private static final String FILE_A =
		"4377a7f5e6eb50bdd2ac6f249bf1a7085500aca8eb41f38545c3a2731c51a579";
	private static final String PRG_B = "1".repeat(64);
	private static final String FILE_B = "2".repeat(64);

	private static GameDescriptor descriptor(String id, String board, String prg, String file,
			String path) {
		JsonObject doc = JsonParser.parseString(("""
				{ "schema": 2, "game": { "id": "%s", "board": "%s",
				  "identity": { "prg_sha256": "%s", "file_sha256": "%s" } } }
				""").formatted(id, board, prg, file)).getAsJsonObject();
		GameDescriptorRegistry.GameDescriptor gd =
			GameDescriptorRegistry.parse(doc, path, new MessageLog());
		assertNotNullFixture(gd, path);
		return gd;
	}

	private static void assertNotNullFixture(GameDescriptor gd, String path) {
		if (gd == null) {
			throw new AssertionError("test fixture " + path + " failed to parse");
		}
	}

	// ---- resolve(): identity matching ----

	@Test
	public void matchesOnPrgShaPrimary() {
		GameDescriptor smb3 = descriptor("smb3", "nes_mmc3", PRG_A, FILE_A, "games/smb3.gmap");
		DescriptorSupport.GameIdentity identity = new DescriptorSupport.GameIdentity(PRG_A, FILE_B);
		GameDescriptor match =
			GameDescriptorRegistry.resolve(List.of(smb3), identity, "nes_mmc3", new MessageLog());
		assertEquals(smb3, match);
	}

	@Test
	public void matchesOnFileShaAliasWhenPrgDoesNotMatch() {
		GameDescriptor smb3 = descriptor("smb3", "nes_mmc3", PRG_A, FILE_A, "games/smb3.gmap");
		DescriptorSupport.GameIdentity identity = new DescriptorSupport.GameIdentity(PRG_B, FILE_A);
		GameDescriptor match =
			GameDescriptorRegistry.resolve(List.of(smb3), identity, "nes_mmc3", new MessageLog());
		assertEquals(smb3, match);
	}

	@Test
	public void prgMatchIsNeverOverriddenByAFileAliasMatch() {
		// Two candidates: one matches identity's prg, the other matches identity's file. The
		// PRG match must win outright -- section 2.3's "a whole-file match never overrides a
		// PRG match".
		GameDescriptor prgMatch = descriptor("prg-match", "nes_mmc3", PRG_A, "a".repeat(64),
			"games/prg-match.gmap");
		GameDescriptor fileMatch = descriptor("file-match", "nes_mmc3", "b".repeat(64), FILE_A,
			"games/file-match.gmap");
		DescriptorSupport.GameIdentity identity = new DescriptorSupport.GameIdentity(PRG_A, FILE_A);
		GameDescriptor match = GameDescriptorRegistry.resolve(List.of(fileMatch, prgMatch),
			identity, "nes_mmc3", new MessageLog());
		assertEquals(prgMatch, match);
	}

	@Test
	public void noMatchReturnsNull() {
		GameDescriptor smb3 = descriptor("smb3", "nes_mmc3", PRG_A, FILE_A, "games/smb3.gmap");
		DescriptorSupport.GameIdentity identity = new DescriptorSupport.GameIdentity(PRG_B, FILE_B);
		assertNull(GameDescriptorRegistry.resolve(List.of(smb3), identity, "nes_mmc3",
			new MessageLog()));
	}

	@Test
	public void boardMismatchIgnoresTheWholeFileAndLogs() {
		GameDescriptor smb3 = descriptor("smb3", "nes_mmc1", PRG_A, FILE_A, "games/smb3.gmap");
		DescriptorSupport.GameIdentity identity = new DescriptorSupport.GameIdentity(PRG_A, FILE_A);
		MessageLog log = new MessageLog();
		assertNull(GameDescriptorRegistry.resolve(List.of(smb3), identity, "nes_mmc3", log));
		assertTrue(log.toString(), log.toString().contains("nes_mmc1"));
		assertTrue(log.toString(), log.toString().contains("nes_mmc3"));
	}

	@Test
	public void ambiguousPrgMatchRefusesBothAndLogs() {
		GameDescriptor first = descriptor("first", "nes_mmc3", PRG_A, "c".repeat(64),
			"games/first.gmap");
		GameDescriptor second = descriptor("second", "nes_mmc3", PRG_A, "d".repeat(64),
			"games/second.gmap");
		DescriptorSupport.GameIdentity identity = new DescriptorSupport.GameIdentity(PRG_A, FILE_A);
		MessageLog log = new MessageLog();
		assertNull(GameDescriptorRegistry.resolve(List.of(first, second), identity, "nes_mmc3",
			log));
		assertTrue(log.toString(), log.toString().contains("first.gmap"));
		assertTrue(log.toString(), log.toString().contains("second.gmap"));
	}

	// ---- parse(): malformed / incompatible .gmap documents (log and skip, never throw) ----

	@Test
	public void wrongSchemaVersionIsSkippedAndLogged() {
		JsonObject doc = JsonParser.parseString(
			"{ \"schema\": 1, \"game\": { \"id\": \"x\", \"board\": \"b\", " +
				"\"identity\": { \"prg_sha256\": \"" + PRG_A + "\", \"file_sha256\": \"" +
				FILE_A + "\" } } }").getAsJsonObject();
		MessageLog log = new MessageLog();
		assertNull(GameDescriptorRegistry.parse(doc, "games/bad.gmap", log));
		assertTrue(log.toString(), log.toString().contains("schema"));
	}

	@Test
	public void missingGameSectionIsSkippedAndLogged() {
		JsonObject doc = JsonParser.parseString("{ \"schema\": 2 }").getAsJsonObject();
		MessageLog log = new MessageLog();
		assertNull(GameDescriptorRegistry.parse(doc, "games/bad.gmap", log));
		assertTrue(log.toString(), log.toString().contains("game:"));
	}

	@Test
	public void malformedIdentityIsSkippedAndLogged() {
		JsonObject doc = JsonParser.parseString(
			"{ \"schema\": 2, \"game\": { \"id\": \"x\", \"board\": \"b\", " +
				"\"identity\": { \"prg_sha256\": \"not-hex\", \"file_sha256\": \"" + FILE_A +
				"\" } } }").getAsJsonObject();
		MessageLog log = new MessageLog();
		assertNull(GameDescriptorRegistry.parse(doc, "games/bad.gmap", log));
		assertTrue(log.toString(), log.toString().contains("64 hex digits"));
	}

	@Test
	public void validDocumentParsesWithLowercasedHashes() {
		JsonObject doc = JsonParser.parseString(
			"{ \"schema\": 2, \"game\": { \"id\": \"smb3\", \"board\": \"nes_mmc3\", " +
				"\"identity\": { \"prg_sha256\": \"" + PRG_A.toUpperCase() +
				"\", \"file_sha256\": \"" + FILE_A + "\" } } }").getAsJsonObject();
		MessageLog log = new MessageLog();
		GameDescriptor gd = GameDescriptorRegistry.parse(doc, "games/smb3.gmap", log);
		assertNotNullFixture(gd, "games/smb3.gmap");
		assertEquals(PRG_A, gd.prgSha256());
		assertEquals("", log.toString().trim());
	}
}
