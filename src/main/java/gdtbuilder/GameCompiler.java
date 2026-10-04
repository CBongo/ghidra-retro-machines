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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
		List<Map<String, Object>> symbols = buildSymbols(descriptor);
		if (symbols != null) {
			gameDoc.put("symbols", symbols);
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

	// ---- symbols: the annotation layer (bead grm-hb6.5) ----

	/**
	 * Compiles the optional {@code symbols:} list: named, user-toggleable sets of
	 * {@code inline:} entries ({@code addr}/{@code name}/{@code kind}/optional {@code comment}),
	 * the same entry shape as a machine descriptor's symbol set (docs/SCHEMA.md), plus the
	 * per-game bank qualifier {@code block:} (design section 3b.3) at set level (a default)
	 * and entry level (an override), naming a memory block of the imported program.
	 * <p>
	 * A game set must carry {@code provenance:} (the design's licensing answer). Entries dedup
	 * per (block, address) -- first wins. {@code source:} files are NOT supported yet (that is
	 * the harvester's carrier, bead grm-hb6.6) and are rejected loudly rather than silently
	 * dropped, as is a {@code kind} other than {@code label}/{@code entry}.
	 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildSymbols(Map<String, Object> descriptor) {
		Object symbolsObj = descriptor.get("symbols");
		if (symbolsObj == null) {
			return null;
		}
		if (!(symbolsObj instanceof List)) {
			throw new IllegalArgumentException("descriptor 'symbols:' must be a list of sets");
		}
		List<Map<String, Object>> out = new ArrayList<>();
		Set<String> setNames = new LinkedHashSet<>();
		for (Object setObj : (List<Object>) symbolsObj) {
			if (!(setObj instanceof Map)) {
				throw new IllegalArgumentException("each 'symbols:' item must be a mapping");
			}
			Map<String, Object> set = (Map<String, Object>) setObj;
			String setName = MapCompiler.requireString(set, "set", "symbols[]");
			if (!setNames.add(setName)) {
				throw new IllegalArgumentException("duplicate symbols set name: " + setName);
			}
			if (set.containsKey("source")) {
				throw new IllegalArgumentException("symbols set '" + setName + "' uses " +
					"'source:', which game descriptors do not support yet; use 'inline:'");
			}
			Map<String, Object> s = new LinkedHashMap<>();
			s.put("set", setName);
			s.put("default", MapCompiler.parseDefault(set));
			s.put("provenance",
				MapCompiler.requireString(set, "provenance", "symbols set '" + setName + "'"));
			String setBlock = set.get("block") == null ? null : set.get("block").toString();
			if (setBlock != null) {
				s.put("block", setBlock);
			}
			Object inlineObj = set.get("inline");
			if (inlineObj != null && !(inlineObj instanceof List)) {
				throw new IllegalArgumentException(
					"symbols set '" + setName + "' 'inline:' must be a list");
			}
			List<Map<String, Object>> entries = new ArrayList<>();
			Set<String> seen = new LinkedHashSet<>();
			if (inlineObj != null) {
				for (Object eo : (List<Object>) inlineObj) {
					if (!(eo instanceof Map)) {
						throw new IllegalArgumentException(
							"symbols set '" + setName + "' has a non-mapping entry");
					}
					Map<String, Object> entry = (Map<String, Object>) eo;
					String ctx = "symbols set '" + setName + "' entry";
					int addr = MapCompiler.requireAddr(entry, "addr", ctx);
					String block =
						entry.get("block") == null ? null : entry.get("block").toString();
					if (!seen.add((block != null ? block : setBlock) + "@" + addr)) {
						continue;
					}
					Map<String, Object> e = new LinkedHashMap<>();
					e.put("addr", addr);
					e.put("name", MapCompiler.requireString(entry, "name", ctx));
					String kind =
						entry.get("kind") == null ? "label" : entry.get("kind").toString();
					if (!kind.equals("label") && !kind.equals("entry")) {
						throw new IllegalArgumentException(
							ctx + " has unsupported kind '" + kind + "' (label|entry)");
					}
					e.put("kind", kind);
					if (block != null) {
						e.put("block", block);
					}
					if (entry.get("comment") != null) {
						e.put("comment", entry.get("comment").toString());
					}
					entries.add(e);
				}
			}
			s.put("entries", entries);
			out.add(s);
		}
		return out;
	}

	// ---- banking hints: initial_state (bead grm-hb6.12), bank_identifying_offsets (grm-mej.7) ----

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
		Map<String, Object> out = new LinkedHashMap<>();
		Map<String, Object> initialState = buildInitialState(banking.get("initial_state"));
		if (initialState != null) {
			out.put("initial_state", initialState);
		}
		List<Map<String, Object>> identifying =
			buildIdentifyingOffsets(banking.get("bank_identifying_offsets"));
		if (identifying != null) {
			out.put("bank_identifying_offsets", identifying);
		}
		return out.isEmpty() ? null : out;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildInitialState(Object initialStateObj) {
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
		return fields;
	}

	/**
	 * {@code banking.bank_identifying_offsets:} (bead grm-mej.7, in grm-hb6.11's
	 * {@code bank_identifying_offset} vocabulary): a list of {@code { address, shift, low,
	 * provenance }} entries, each stating that at every read of the bank-identifying ROM byte at
	 * {@code address} the live bank is one its encoding ({@code bank = (byte << shift) + low})
	 * holds for. Validated for SHAPE only here; whether the cell and encoding are real is checked
	 * against the ROM bytes at analysis time (BankMirrors.withMembershipHints), where a hint
	 * that does not verify is refused with a logged reason.
	 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildIdentifyingOffsets(Object listObj) {
		if (listObj == null) {
			return null;
		}
		if (!(listObj instanceof List) || ((List<Object>) listObj).isEmpty()) {
			throw new IllegalArgumentException(
				"game descriptor 'banking.bank_identifying_offsets:' must be a non-empty list");
		}
		List<Map<String, Object>> out = new ArrayList<>();
		for (Object entryObj : (List<Object>) listObj) {
			if (!(entryObj instanceof Map)) {
				throw new IllegalArgumentException("each 'banking.bank_identifying_offsets:' " +
					"entry must be a mapping with address, shift, low and provenance");
			}
			Map<String, Object> entry = (Map<String, Object>) entryObj;
			for (String key : entry.keySet()) {
				if (!Set.of("address", "shift", "low", "provenance").contains(key)) {
					throw new IllegalArgumentException("'banking.bank_identifying_offsets:' " +
						"entry has unknown key '" + key + "'");
				}
			}
			String where = "banking.bank_identifying_offsets entry";
			int address = MapCompiler.requireAddr(entry, "address", where);
			int shift = MapCompiler.requireAddr(entry, "shift", where);
			int low = MapCompiler.requireAddr(entry, "low", where);
			if (address < 0 || address > 0xFFFF) {
				throw new IllegalArgumentException(where + ": address must be a 16-bit CPU address");
			}
			if (shift < 0 || shift > 2) {
				throw new IllegalArgumentException(where + ": shift must be 0, 1 or 2 (the " +
					"encodings the derivation tries)");
			}
			if (low < 0 || low >= (1 << shift)) {
				throw new IllegalArgumentException(where + ": low must be in [0, 2^shift)");
			}
			String provenance = MapCompiler.requireString(entry, "provenance", where);
			Map<String, Object> e = new LinkedHashMap<>();
			e.put("address", address);
			e.put("shift", shift);
			e.put("low", low);
			e.put("provenance", provenance);
			out.add(e);
		}
		return out;
	}
}
