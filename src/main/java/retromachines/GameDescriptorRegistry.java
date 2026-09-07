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

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;

/**
 * Registry of curated per-game descriptors (docs/per-game-descriptors-design.md; first
 * increment bead {@code grm-hb6.12}) -- the title-tier counterpart of
 * {@link NesBoardRegistry}, scanning the extension's bundled {@code machines/games/*.gmap}
 * files (compiled by {@code gdtbuilder.GameCompiler}) and resolving one against a program's
 * per-game identity ({@link DescriptorSupport.GameIdentity}, bead {@code grm-hb6.1}).
 * <p>
 * <b>Deliberately holds no static cache, unlike {@link NesBoardRegistry#boards}.</b> This
 * increment is curated-only (no user-writable overlay directory yet -- that is bead
 * {@code grm-hb6.2}), so nothing here can change mid-session today. But the eventual overlay
 * half WILL be user-writable, and {@code docs/per-game-descriptors-design.md} section 5.3
 * rules that the registry must never memoize because a mid-session drop-in would then never
 * be re-scanned. Scanning fresh per import costs one directory listing plus a handful of
 * small JSON parses (bundled game descriptors are tiny), which is cheap next to a full
 * program import -- not worth a cache that would need to be un-added later.
 */
final class GameDescriptorRegistry {

	/**
	 * One resolved game descriptor: its declared identity/board (for matching) and the raw
	 * compiled document (for consumers, e.g. {@link DescriptorSupport#applyGameInitialStateHint}
	 * reading {@code banking.initial_state}).
	 */
	record GameDescriptor(String id, String board, String prgSha256, String fileSha256,
			String gmapPath, JsonObject doc) {}

	private GameDescriptorRegistry() {
	}

	/**
	 * Scans every bundled {@code machines/games/*.gmap} file, parsing each into a
	 * {@link GameDescriptor}. A file that fails to parse as JSON, or whose structure {@link
	 * #parse} rejects, is logged and skipped -- never thrown, per CLAUDE.md's "loader
	 * validation: {@code load()} is authoritative" failure discipline extended to this tier
	 * (a malformed or unreadable {@code .gmap} costs only that file, docs/per-game-descriptors-
	 * design.md section 5.4).
	 */
	static List<GameDescriptor> scan(MessageLog log) {
		List<GameDescriptor> found = new ArrayList<>();
		for (ResourceFile gmapFile : Application.findFilesByExtensionInMyModule(".gmap")) {
			// Scope to games/, the same way NesBoardRegistry.scan scopes to machines/ -- belt
			// and suspenders alongside the .gmap-vs-.map extension split (bead grm-hb6.10).
			ResourceFile parent = gmapFile.getParentFile();
			if (parent == null || !"games".equals(parent.getName())) {
				continue;
			}
			String path = "games/" + gmapFile.getName();
			try (InputStreamReader reader =
					new InputStreamReader(gmapFile.getInputStream(), StandardCharsets.UTF_8)) {
				JsonObject doc = JsonParser.parseReader(reader).getAsJsonObject();
				GameDescriptor gd = parse(doc, path, log);
				if (gd != null) {
					found.add(gd);
				}
			}
			catch (Exception e) {
				log.appendMsg("Skipping unparseable game descriptor " + path + ": " +
					e.getMessage());
			}
		}
		return found;
	}

	/**
	 * Parses one compiled {@code .gmap} document's identity fields, or returns {@code null}
	 * (logging why) for a schema mismatch or a structurally incomplete {@code game:} section.
	 * Package-private and split out from {@link #scan} as the testable seam -- a pure-JUnit
	 * test hands this a hand-built {@link JsonObject}, exactly the way {@code
	 * DescriptorCopyHintAnalyzer.applyAll} is split out for the same reason.
	 * <p>
	 * Schema is compared, not duck-typed (docs/per-game-descriptors-design.md section 3.3): a
	 * game descriptor is the first artifact in this repo that can be read by a different
	 * extension version than the one that produced it, so a version mismatch is reported
	 * rather than silently mis-parsed.
	 */
	static GameDescriptor parse(JsonObject doc, String path, MessageLog log) {
		if (!doc.has("schema") || doc.get("schema").getAsInt() != 2) {
			log.appendMsg(path + ": declares schema " +
				(doc.has("schema") ? doc.get("schema") : "<missing>") +
				"; this extension reads schema 2 -- skipping");
			return null;
		}
		if (!doc.has("game")) {
			log.appendMsg(path + ": missing top-level 'game:' section -- skipping");
			return null;
		}
		JsonObject game = doc.getAsJsonObject("game");
		if (!game.has("id") || !game.has("board") || !game.has("identity")) {
			log.appendMsg(path + ": 'game:' section is missing id/board/identity -- skipping");
			return null;
		}
		JsonObject identity = game.getAsJsonObject("identity");
		if (!identity.has("prg_sha256") || !identity.has("file_sha256")) {
			log.appendMsg(
				path + ": 'game.identity' is missing prg_sha256/file_sha256 -- skipping");
			return null;
		}
		String prg = identity.get("prg_sha256").getAsString().toLowerCase();
		String file = identity.get("file_sha256").getAsString().toLowerCase();
		if (!prg.matches("[0-9a-f]{64}") || !file.matches("[0-9a-f]{64}")) {
			log.appendMsg(path +
				": game.identity prg_sha256/file_sha256 must each be 64 hex digits -- skipping");
			return null;
		}
		return new GameDescriptor(game.get("id").getAsString(), game.get("board").getAsString(),
			prg, file, path, doc);
	}

	/**
	 * Resolves the game descriptor matching {@code identity} and {@code boardId} among
	 * {@code candidates}, or {@code null} when nothing matches. Pure function over an
	 * already-scanned list -- {@link #scan}'s file I/O lives above this seam so it, too, is
	 * directly testable with hand-built candidates and no installed extension.
	 * <p>
	 * Resolution order (docs/per-game-descriptors-design.md section 2.3): {@code prg_sha256}
	 * first, {@code file_sha256} only if no PRG match was found -- a whole-file match never
	 * overrides a PRG match. Two candidates sharing the key being matched on is reported as an
	 * ambiguous match and refuses BOTH, rather than picking one by list order (section 2.3:
	 * "a silently-picked winner among duplicate claims is unreproducible").
	 * <p>
	 * {@code game.board} is a cross-check, not a selector (section 3.2): a match whose declared
	 * board disagrees with the board the loader actually resolved is logged and the whole file
	 * is ignored, never applied against a board it was not reasoned about.
	 */
	static GameDescriptor resolve(List<GameDescriptor> candidates,
			DescriptorSupport.GameIdentity identity, String boardId, MessageLog log) {
		GameDescriptor match = pickOne(
			matching(candidates, gd -> gd.prgSha256().equals(identity.prgSha256())),
			"prg_sha256 " + identity.prgSha256(), log);
		if (match == null) {
			match = pickOne(
				matching(candidates, gd -> gd.fileSha256().equals(identity.fileSha256())),
				"file_sha256 " + identity.fileSha256(), log);
		}
		if (match == null) {
			return null;
		}
		if (!match.board().equals(boardId)) {
			log.appendMsg("game descriptor " + match.gmapPath() + " ('" + match.id() +
				"') declares board '" + match.board() + "', which does not match the " +
				"resolved board '" + boardId + "'; ignoring it (docs/per-game-descriptors-" +
				"design.md section 3.2)");
			return null;
		}
		return match;
	}

	private static List<GameDescriptor> matching(List<GameDescriptor> candidates,
			Predicate<GameDescriptor> pred) {
		List<GameDescriptor> out = new ArrayList<>();
		for (GameDescriptor gd : candidates) {
			if (pred.test(gd)) {
				out.add(gd);
			}
		}
		return out;
	}

	private static GameDescriptor pickOne(List<GameDescriptor> matches, String key,
			MessageLog log) {
		if (matches.isEmpty()) {
			return null;
		}
		if (matches.size() > 1) {
			List<String> paths = new ArrayList<>();
			for (GameDescriptor gd : matches) {
				paths.add(gd.gmapPath());
			}
			log.appendMsg("multiple game descriptors match " + key + ": " + paths +
				"; ignoring all of them (ambiguous match)");
			return null;
		}
		return matches.get(0);
	}
}
