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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Standalone build-time tool: compiles a curated per-game descriptor YAML
 * ({@code machines/games/*.yaml}, docs/per-game-descriptors-design.md) into its runtime
 * artifact, {@code data/games/<name>.gmap} -- JSON, exactly like {@link MapCompiler}'s
 * compiled machine {@code .map}, but for the much smaller title tier: a {@code game:}
 * identity block plus, in this first increment (bead {@code grm-hb6.12}), one load-time
 * banking hint.
 * <p>
 * <b>Why a sibling class and not a mode of {@link MapCompiler}.</b> {@code MapCompiler.main}
 * requires a top-level {@code system:} section (see its {@code buildSystem}), which a game
 * descriptor never has, and the great bulk of that ~1700-line class (physical spaces,
 * windows, mode-dependent layouts, the {@code banking.mechanisms}/{@code states} truth
 * table) is board schema a game descriptor never touches either. Bolting a "game mode" flag
 * onto that file would mean threading null-checks for an absent {@code system:}/
 * {@code memory:} through code that currently assumes they exist. A handful of small,
 * generic parsing helpers ({@link MapCompiler#requireString}, {@link MapCompiler#requireAddr},
 * {@link MapCompiler#toInt}) are shared by having {@code MapCompiler} widen their visibility
 * to package-private, rather than duplicated here.
 * <p>
 * <b>The compiled artifact's extension is deliberately {@code .gmap}, not {@code .map}.</b>
 * {@code NesBoardRegistry.scan} enumerates {@code Application.findFilesByExtensionInMyModule(
 * ".map")} looking for board descriptors (a {@code system.board.ines_mappers} key); a game
 * descriptor compiled to {@code data/games/<name>.map} would land in that scan by accident.
 * See docs/per-game-descriptors-design.md section 4.1.
 * <p>
 * <b>The {@code banking.initial_state} hint is emitted as a plain field-name -&gt; integer
 * map, never packed against a bit layout.</b> A game descriptor deliberately does not
 * declare its own {@code banking.state} tuple -- the whole point of the tier (bead
 * {@code grm-hb6.12}) is that the game tier must not know the board's bit layout. Packing
 * happens at LOAD time, in {@code DescriptorSupport.applyGameInitialStateHint}, against the
 * matched board descriptor's own parsed {@code banking.state} field tuple -- the only place
 * both the field name and its width are known together.
 * <p>
 * This class now ships with the extension (bead {@code grm-hb6.2}) so the runtime overlay scan
 * validates through the same code; {@link #main} still runs as part of the Gradle build (see
 * the per-file {@code buildXxxGame} tasks in build.gradle). Usage:
 * {@code GameCompiler <descriptor.yaml> <output.gmap>}
 */
public class GameCompiler {

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: GameCompiler <descriptor.yaml> <output.gmap>");
			System.exit(1);
		}
		File descriptorFile = new File(args[0]).getCanonicalFile();
		File outputGmap = new File(args[1]).getCanonicalFile();

		Map<String, Object> gameDoc = compile(descriptorFile);

		outputGmap.getParentFile().mkdirs();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new FileWriter(outputGmap)) {
			gson.toJson(gameDoc, w);
		}

		System.err.println("Wrote game descriptor to " + outputGmap.getAbsolutePath() + " (" +
			outputGmap.length() + " bytes)");
	}

	/**
	 * Compiles one curated descriptor YAML (build-time {@code include:} composition expanded)
	 * to its in-memory game document. The sole build logic -- {@link #main} writes the result,
	 * and {@link #compileOverlay} reuses {@link #compileDocument} for the runtime overlay.
	 */
	static Map<String, Object> compile(File descriptorFile) throws IOException {
		return compileDocument(YamlSupport.loadComposed(descriptorFile));
	}

	/**
	 * The result of {@link #compileOverlay}: the compiled game document, or a non-empty
	 * error list attributing the failure to the file (then {@code gameDoc} is {@code null}).
	 */
	public record CompileResult(Map<String, Object> gameDoc, List<String> errors) {

		public boolean ok() {
			return gameDoc != null;
		}
	}

	/**
	 * Error-collecting entry point for the user-directory overlay scan (bead {@code grm-hb6.2},
	 * docs/per-game-descriptors-design.md sections 5.4 and 5.5): one malformed overlay file
	 * costs only itself. It runs the SAME {@link #compileDocument} validator the build does
	 * ("one validator, two dispositions"); only the disposition differs (collect, not throw).
	 * <p>
	 * {@code include:} is REJECTED here, loudly (section 5.5): composition is a build-time
	 * convenience that only curated files keep, and an overlay file must be self-contained to
	 * be shareable (and to not reach outside its directory). The file is read raw
	 * ({@link YamlSupport#load}), never through {@link YamlSupport#loadComposed}, so no
	 * include is ever followed. Compiles on every call -- no caching (section 4.4).
	 */
	public static CompileResult compileOverlay(File descriptorFile) {
		try {
			Map<String, Object> descriptor = YamlSupport.load(descriptorFile);
			if (descriptor.containsKey("include")) {
				throw new IllegalArgumentException("'include:' is not allowed in an overlay " +
					"descriptor -- it is a build-time-only key; an overlay file must be " +
					"self-contained (composition is for curated files under machines/games/)");
			}
			return new CompileResult(compileDocument(descriptor), List.of());
		}
		catch (IOException | RuntimeException e) {
			String message = e.getMessage() != null ? e.getMessage() : e.toString();
			return new CompileResult(null, List.of(descriptorFile + ": " + message));
		}
	}

	private static Map<String, Object> compileDocument(Map<String, Object> descriptor) {
		int schemaVersion = MapCompiler.requireAddr(descriptor, "schema", "descriptor");
		if (schemaVersion != 2) {
			throw new IllegalArgumentException("unsupported 'schema: " + schemaVersion +
				"' -- this GameCompiler builds descriptor schema 2 (see docs/SCHEMA.md)");
		}

		Map<String, Object> gameDoc = new LinkedHashMap<>();
		gameDoc.put("schema", 2);
		gameDoc.put("game", buildGame(descriptor));
		Map<String, Object> banking = buildBanking(descriptor);
		if (banking != null) {
			gameDoc.put("banking", banking);
		}
		return gameDoc;
	}

	// ---- game: identity block ----

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildGame(Map<String, Object> descriptor) {
		Object gameObj = descriptor.get("game");
		if (!(gameObj instanceof Map)) {
			throw new IllegalArgumentException("descriptor is missing top-level 'game:' " +
				"section (docs/per-game-descriptors-design.md section 3.0)");
		}
		Map<String, Object> game = (Map<String, Object>) gameObj;
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("id", MapCompiler.requireString(game, "id", "game"));
		out.put("title", MapCompiler.requireString(game, "title", "game"));
		out.put("board", MapCompiler.requireString(game, "board", "game"));
		out.put("identity", buildIdentity(game));
		out.put("provenance", MapCompiler.requireString(game, "provenance", "game"));
		return out;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildIdentity(Map<String, Object> game) {
		Object identityObj = game.get("identity");
		if (!(identityObj instanceof Map)) {
			throw new IllegalArgumentException(
				"game descriptor's 'game:' section is missing 'identity:'");
		}
		Map<String, Object> identity = (Map<String, Object>) identityObj;
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("prg_sha256", requireSha256(identity, "prg_sha256"));
		out.put("file_sha256", requireSha256(identity, "file_sha256"));
		return out;
	}

	private static String requireSha256(Map<String, Object> identity, String key) {
		String value = MapCompiler.requireString(identity, key, "game.identity");
		if (!value.matches("(?i)[0-9a-f]{64}")) {
			throw new IllegalArgumentException(
				"game.identity." + key + " must be 64 hex digits, got: " + value);
		}
		return value.toLowerCase();
	}

	// ---- banking.initial_state hint (bead grm-hb6.12) ----

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildBanking(Map<String, Object> descriptor) {
		Object bankingObj = descriptor.get("banking");
		if (bankingObj == null) {
			return null;
		}
		if (!(bankingObj instanceof Map)) {
			throw new IllegalArgumentException("descriptor 'banking:' must be a mapping");
		}
		Map<String, Object> banking = (Map<String, Object>) bankingObj;
		Object initialStateObj = banking.get("initial_state");
		if (initialStateObj == null) {
			return null;
		}
		if (!(initialStateObj instanceof Map)) {
			throw new IllegalArgumentException(
				"game descriptor 'banking.initial_state:' must be a field-name map (e.g. " +
					"{ prg_mode: 1 }), never a packed integer -- the game tier must not know " +
					"the board's bit layout");
		}
		Map<String, Object> initialState = (Map<String, Object>) initialStateObj;
		if (initialState.isEmpty()) {
			throw new IllegalArgumentException(
				"game descriptor 'banking.initial_state:' is present but names no fields");
		}
		Map<String, Object> fields = new LinkedHashMap<>();
		for (Map.Entry<String, Object> entry : initialState.entrySet()) {
			fields.put(entry.getKey(), MapCompiler.toInt(entry.getValue()));
		}
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("initial_state", fields);
		return out;
	}
}
