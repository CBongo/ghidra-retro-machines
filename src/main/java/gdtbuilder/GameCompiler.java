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
		List<Map<String, Object>> comments = buildComments(descriptor);
		if (comments != null) {
			gameDoc.put("comments", comments);
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

	/** The comment-type keys of a {@code comments:} entry, in compiled/exported order. */
	public static final List<String> COMMENT_KEYS = List.of("eol", "pre", "plate", "post", "repeatable");

	/**
	 * Compiles the optional top-level {@code comments:} list (bead grm-hb6.18): named,
	 * user-toggleable sets in the same shape as {@code symbols:} ({@code set}, {@code default},
	 * required {@code provenance}, optional set-level {@code block:}, {@code inline:} entries), but
	 * each entry is {@code { addr, [block], eol|pre|plate|post|repeatable: <text> ... }} -- at
	 * least one comment key, any number of them -- and names no symbol. This is the carrier for
	 * comments {@code symbols:} cannot hold: non-EOL comments, and comments at unlabelled
	 * addresses (a labelled address may still use {@code comment:} on its symbol entry as the EOL
	 * shorthand). Set names are unique among comments sets (a symbols set may share the name; the
	 * two toggles are namespaced apart). Unknown keys, an entry with no comment key, blank text and
	 * a duplicate (block, addr) within a set are rejected. {@code block:} gets the same
	 * grammar-only check as everywhere else; whether it exists is an apply-time matter.
	 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildComments(Map<String, Object> descriptor) {
		Object commentsObj = descriptor.get("comments");
		if (commentsObj == null) {
			return null;
		}
		if (!(commentsObj instanceof List) || ((List<Object>) commentsObj).isEmpty()) {
			throw new IllegalArgumentException(
				"descriptor 'comments:' must be a non-empty list of sets");
		}
		List<Map<String, Object>> out = new ArrayList<>();
		Set<String> setNames = new LinkedHashSet<>();
		for (Object setObj : (List<Object>) commentsObj) {
			if (!(setObj instanceof Map)) {
				throw new IllegalArgumentException("each 'comments:' item must be a mapping");
			}
			Map<String, Object> set = (Map<String, Object>) setObj;
			for (String key : set.keySet()) {
				if (!Set.of("set", "default", "provenance", "block", "inline").contains(key)) {
					throw new IllegalArgumentException(
						"'comments:' set has unknown key '" + key + "'");
				}
			}
			String setName = MapCompiler.requireString(set, "set", "comments[]");
			String setCtx = "comments set '" + setName + "'";
			if (!setNames.add(setName)) {
				throw new IllegalArgumentException("duplicate comments set name: " + setName);
			}
			if (set.get("default") == null) {
				throw new IllegalArgumentException(setCtx + " is missing 'default:'");
			}
			boolean def;
			try {
				def = MapCompiler.parseDefault(set);
			}
			catch (IllegalArgumentException e) {
				throw new IllegalArgumentException(setCtx + " has unrecognized default: " +
					set.get("default"));
			}
			Map<String, Object> s = new LinkedHashMap<>();
			s.put("set", setName);
			s.put("default", def);
			s.put("provenance", MapCompiler.requireString(set, "provenance", setCtx));
			String setBlock = optionalBlock(set, setCtx);
			if (setBlock != null) {
				s.put("block", setBlock);
			}
			Object inlineObj = set.get("inline");
			if (!(inlineObj instanceof List) || ((List<Object>) inlineObj).isEmpty()) {
				throw new IllegalArgumentException(setCtx + " 'inline:' must be a non-empty list");
			}
			List<Map<String, Object>> entries = new ArrayList<>();
			Set<String> seen = new LinkedHashSet<>();
			String ctx = setCtx + " entry";
			for (Object eo : (List<Object>) inlineObj) {
				if (!(eo instanceof Map)) {
					throw new IllegalArgumentException(setCtx + " has a non-mapping entry");
				}
				Map<String, Object> entry = (Map<String, Object>) eo;
				for (String key : entry.keySet()) {
					if (!key.equals("addr") && !key.equals("block") && !COMMENT_KEYS.contains(key)) {
						throw new IllegalArgumentException(ctx + " has unknown key '" + key + "'");
					}
				}
				int addr = MapCompiler.requireAddr(entry, "addr", ctx);
				String block = optionalBlock(entry, ctx);
				Map<String, Object> e = new LinkedHashMap<>();
				e.put("addr", addr);
				if (block != null) {
					e.put("block", block);
				}
				int texts = 0;
				for (String key : COMMENT_KEYS) {
					if (entry.get(key) == null) {
						continue;
					}
					String text = entry.get(key).toString();
					if (text.isBlank()) {
						throw new IllegalArgumentException(ctx + " at " + addr + ": '" + key +
							":' must not be blank");
					}
					e.put(key, text);
					texts++;
				}
				if (texts == 0) {
					throw new IllegalArgumentException(ctx + " at " + addr + " carries no comment (" +
						"one or more of eol|pre|plate|post|repeatable)");
				}
				if (!seen.add((block != null ? block : setBlock) + "@" + addr)) {
					throw new IllegalArgumentException(ctx + " at " + addr + " is listed twice");
				}
				entries.add(e);
			}
			s.put("entries", entries);
			out.add(s);
		}
		return out;
	}

	/** The optional {@code block:} of {@code map} (null if absent), grammar-checked. */
	private static String optionalBlock(Map<String, Object> map, String context) {
		Object v = map.get("block");
		return v == null ? null : checkBlockName(v.toString(), context);
	}

	/**
	 * Grammar-only validation of a {@code block:} name (bead grm-hb6.18); whether the block exists
	 * in the program stays an apply-time check, as this compiler is board-agnostic. Rejects a
	 * blank name, whitespace or control characters, and any {@code _}-segment (after the first) shaped like a
	 * botched overlay suffix -- {@code B}/{@code M} then a digit then a non-digit
	 * ({@code W8000_B3x}, {@code W8000_M0B5}), or a number with a leading zero
	 * ({@code W8000_B05}) -- since the loader never produces those. Everything else passes.
	 * Package-private for tests.
	 *
	 * @return {@code name}, for chaining
	 */
	static String checkBlockName(String name, String context) {
		if (name == null || name.isBlank()) {
			throw new IllegalArgumentException(context + ": 'block:' must not be blank");
		}
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (Character.isWhitespace(c) || Character.isISOControl(c)) {
				throw new IllegalArgumentException(context + ": block name '" + name +
					"' contains whitespace or a control character");
			}
		}
		String[] parts = name.split("_", -1);
		for (int i = 1; i < parts.length; i++) {
			String seg = parts[i];
			if (seg.length() >= 2 && (seg.charAt(0) == 'B' || seg.charAt(0) == 'M') &&
				Character.isDigit(seg.charAt(1))) {
				String digits = seg.substring(1);
				boolean allDigits = digits.chars().allMatch(ch -> ch >= '0' && ch <= '9');
				if (!allDigits || (digits.length() > 1 && digits.charAt(0) == '0')) {
					throw new IllegalArgumentException(context + ": block name '" + name +
						"' has segment '_" + seg + "', which looks like an overlay suffix but is " +
						"not one the loader produces (_B<n> / _M<n>, no leading zeros)");
				}
			}
		}
		return name;
	}

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
			String setBlock = optionalBlock(set, "symbols set '" + setName + "'");
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
					String block = optionalBlock(entry, ctx);
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
		for (HintSpec spec : HINT_SPECS) {
			List<Map<String, Object>> entries = buildHintList(spec, banking.get(spec.key()));
			if (entries != null) {
				out.put(spec.key(), entries);
			}
		}
		List<String> fixed = buildFixedAfterInit(banking.get("fixed_after_init"));
		if (fixed != null) {
			out.put("fixed_after_init", fixed);
		}
		return out.isEmpty() ? null : out;
	}

	/** One state-list-of-mappings {@code banking.*} hint's compile spec (bead grm-rx1i.10). */
	private record HintSpec(String key, String shape, Set<String> allowedKeys, HintEntry entry) {
	}

	/**
	 * Validates and normalizes ONE entry of a hint list. {@code where} is the error-message
	 * prefix; {@code seen} is the list's duplicate-detection set, which the hook alone keys.
	 */
	@FunctionalInterface
	private interface HintEntry {
		Map<String, Object> build(Map<String, Object> entry, String where, Set<Object> seen);
	}

	private static final HintSpec BANK_IDENTIFYING_OFFSETS = new HintSpec("bank_identifying_offsets",
		"address, shift, low and provenance",
		Set.of("address", "shift", "low", "bias", "modulus_bits", "provenance"),
		GameCompiler::identifyingOffsetEntry);

	private static final HintSpec SWITCH_SITES = new HintSpec("switch_sites",
		"addr and provenance",
		Set.of("addr", "block", "entry", "comment", "provenance", "bank"),
		GameCompiler::switchSiteEntry);

	private static final HintSpec SAVE_CELLS = new HintSpec("save_cells",
		"address and provenance",
		Set.of("address", "provenance"),
		GameCompiler::saveCellEntry);

	private static final HintSpec BANK_STACKS = new HintSpec("bank_stacks",
		"pointer, slots and provenance",
		Set.of("pointer", "slots", "provenance"),
		GameCompiler::bankStackEntry);

	private static final HintSpec SHADOW_COMMITS = new HintSpec("shadow_commits",
		"helper, cell, field and provenance",
		Set.of("helper", "cell", "field", "provenance"),
		GameCompiler::shadowCommitEntry);

	private static final HintSpec PAIRED_FIELDS = new HintSpec("paired_fields",
		"high, low, offset and provenance",
		Set.of("high", "low", "offset", "provenance"),
		GameCompiler::pairedFieldEntry);

	/** The list-shaped hints in output order (mirrors {@code retromachines.BankingHintKind}). */
	private static final List<HintSpec> HINT_SPECS = List.of(BANK_IDENTIFYING_OFFSETS,
		SWITCH_SITES, SAVE_CELLS, BANK_STACKS, SHADOW_COMMITS, PAIRED_FIELDS);

	/**
	 * The shared skeleton of every list-of-mappings {@code banking.*} hint: absent -> null; else
	 * a non-empty list of mappings with only the spec's keys, each normalized by the spec's hook.
	 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildHintList(HintSpec spec, Object listObj) {
		if (listObj == null) {
			return null;
		}
		if (!(listObj instanceof List) || ((List<Object>) listObj).isEmpty()) {
			throw new IllegalArgumentException(
				"game descriptor 'banking." + spec.key() + ":' must be a non-empty list");
		}
		List<Map<String, Object>> out = new ArrayList<>();
		Set<Object> seen = new java.util.HashSet<>();
		for (Object entryObj : (List<Object>) listObj) {
			if (!(entryObj instanceof Map)) {
				throw new IllegalArgumentException("each 'banking." + spec.key() +
					":' entry must be a mapping with " + spec.shape());
			}
			Map<String, Object> entry = (Map<String, Object>) entryObj;
			for (String key : entry.keySet()) {
				if (!spec.allowedKeys().contains(key)) {
					throw new IllegalArgumentException("'banking." + spec.key() +
						":' entry has unknown key '" + key + "'");
				}
			}
			out.add(spec.entry().build(entry, "banking." + spec.key() + " entry", seen));
		}
		return out;
	}

	/**
	 * {@code banking.bank_stacks:} (bead grm-mej.10): a non-empty list of {@code { pointer,
	 * slots, provenance }} entries, each naming a RAM bank stack: {@code pointer} is the stack
	 * pointer cell and {@code slots} the base of the slot array it indexes (a push stores the
	 * live bank's identity byte at {@code slots[pointer]} and increments the pointer; a pop
	 * decrements it and reloads the slot). SHAPE only here; the analyzer
	 * ({@code BankStackBrackets}) uses it as the premise of its push/pop pairing proof.
	 */
	private static Map<String, Object> bankStackEntry(Map<String, Object> entry, String where,
			Set<Object> seen) {
		int pointer = MapCompiler.requireAddr(entry, "pointer", where);
		int slots = MapCompiler.requireAddr(entry, "slots", where);
		if (pointer < 0 || pointer > 0xFFFF || slots < 0 || slots > 0xFFFF) {
			throw new IllegalArgumentException(
				where + ": pointer and slots must be 16-bit CPU addresses");
		}
		if (!seen.add(pointer)) {
			throw new IllegalArgumentException(where + ": pointer " + pointer + " listed twice");
		}
		String provenance = MapCompiler.requireString(entry, "provenance", where);
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("pointer", pointer);
		e.put("slots", slots);
		e.put("provenance", provenance);
		return e;
	}

	/**
	 * {@code banking.shadow_commits:} (bead grm-hb6.26): a non-empty list of {@code { helper,
	 * cell, field, provenance }} entries, each stating that a call to the bank-switch helper at
	 * {@code helper} commits board state field {@code field} from the RAM cell {@code cell}
	 * (identity encoding), and that the cell is coherent with the live field. SHAPE only here;
	 * whether the helper, the field and the coherence premise hold in the image is checked at
	 * analysis time ({@code ShadowCommits}).
	 */
	private static Map<String, Object> shadowCommitEntry(Map<String, Object> entry, String where,
			Set<Object> seen) {
		int helper = MapCompiler.requireAddr(entry, "helper", where);
		int cell = MapCompiler.requireAddr(entry, "cell", where);
		if (helper < 0 || helper > 0xFFFF || cell < 0 || cell > 0xFFFF) {
			throw new IllegalArgumentException(
				where + ": helper and cell must be 16-bit CPU addresses");
		}
		String field = MapCompiler.requireString(entry, "field", where);
		if (!seen.add(helper + "/" + field)) {
			throw new IllegalArgumentException(where + ": helper " + helper + " with field '" +
				field + "' listed twice");
		}
		if (!(entry.get("field") instanceof String) || field.isBlank()) {
			throw new IllegalArgumentException(where + ": field must be a non-blank name");
		}
		String provenance = MapCompiler.requireString(entry, "provenance", where);
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("helper", helper);
		e.put("cell", cell);
		e.put("field", field);
		e.put("provenance", provenance);
		return e;
	}

	/**
	 * {@code banking.paired_fields:} (bead grm-mej.10): a non-empty list of {@code { high, low,
	 * offset, provenance }} entries, each asserting that board state field {@code high} always
	 * holds field {@code low}'s bank plus {@code offset} (tmnt3: r6 == r7 + 1). Names only here;
	 * whether they name real fields of the matched board is checked at analysis time.
	 */
	private static Map<String, Object> pairedFieldEntry(Map<String, Object> entry, String where,
			Set<Object> seen) {
		String high = MapCompiler.requireString(entry, "high", where);
		String low = MapCompiler.requireString(entry, "low", where);
		if (high.equals(low)) {
			throw new IllegalArgumentException(where + ": high and low name the same field");
		}
		int offset = MapCompiler.requireAddr(entry, "offset", where);
		if (offset < 1 || offset > 0xFF) {
			throw new IllegalArgumentException(where + ": offset must be in [1, 255]");
		}
		if (!seen.add(high + "/" + low)) {
			throw new IllegalArgumentException(
				where + ": " + high + "/" + low + " listed twice");
		}
		String provenance = MapCompiler.requireString(entry, "provenance", where);
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("high", high);
		e.put("low", low);
		e.put("offset", offset);
		e.put("provenance", provenance);
		return e;
	}

	/**
	 * {@code banking.fixed_after_init:} (bead grm-mej.12): a non-empty list of board state-field
	 * NAMES the game never changes after initialization, so asynchronously reached entries
	 * (NMI/IRQ) may be seeded with those fields known at their effective initial value. Names
	 * only here -- whether each names a real field of the matched board is checked at import
	 * (DescriptorSupport.resolveFixedAfterInitMask), where the board's bit layout is known.
	 */
	@SuppressWarnings("unchecked")
	private static List<String> buildFixedAfterInit(Object listObj) {
		if (listObj == null) {
			return null;
		}
		if (!(listObj instanceof List)) {
			throw new IllegalArgumentException(
				"game descriptor 'banking.fixed_after_init:' must be a list of field names " +
					"(e.g. [ prg_mode ])");
		}
		List<Object> raw = (List<Object>) listObj;
		if (raw.isEmpty()) {
			throw new IllegalArgumentException(
				"game descriptor 'banking.fixed_after_init:' is present but names no fields");
		}
		List<String> out = new ArrayList<>();
		for (Object o : raw) {
			if (!(o instanceof String) || ((String) o).isBlank()) {
				throw new IllegalArgumentException(
					"game descriptor 'banking.fixed_after_init:' entries must be non-empty " +
						"field-name strings, got: " + o);
			}
			if (out.contains(o)) {
				throw new IllegalArgumentException(
					"game descriptor 'banking.fixed_after_init:' names '" + o + "' twice");
			}
			out.add((String) o);
		}
		return out;
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
	private static Map<String, Object> identifyingOffsetEntry(Map<String, Object> entry, String where,
			Set<Object> seen) {
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
		// grm-mej.9: optional BIASED form (byte = bank + bias on banks == low mod
		// 2^modulus_bits). Both default to the classic form's values.
		int bias = entry.containsKey("bias") ? MapCompiler.requireAddr(entry, "bias", where) : 0;
		int modBits = entry.containsKey("modulus_bits")
				? MapCompiler.requireAddr(entry, "modulus_bits", where) : shift;
		if (bias < 0 || bias > 0xFF) {
			throw new IllegalArgumentException(where + ": bias must be in [0, 255]");
		}
		if (modBits < shift || modBits > 2) {
			throw new IllegalArgumentException(where +
				": modulus_bits must be in [shift, 2]");
		}
		if (bias != 0 && shift != 0) {
			throw new IllegalArgumentException(where + ": a biased encoding (bias != 0) " +
				"must have shift 0");
		}
		if (low < 0 || low >= (1 << modBits)) {
			throw new IllegalArgumentException(where +
				": low must be in [0, 2^modulus_bits) (modulus_bits defaults to shift)");
		}
		String provenance = MapCompiler.requireString(entry, "provenance", where);
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("address", address);
		e.put("shift", shift);
		e.put("low", low);
		if (entry.containsKey("bias")) {
			e.put("bias", bias);
		}
		if (entry.containsKey("modulus_bits")) {
			e.put("modulus_bits", modBits);
		}
		e.put("provenance", provenance);
		return e;
	}

	/**
	 * {@code banking.switch_sites:} (bead grm-hb6.4): a non-empty list of SITE hints, each
	 * {@code { addr, provenance, [block], [entry], [comment], [bank] }} stating "there is a
	 * bank-switch store here". SHAPE only here; the analyzer disassembles the address if need be
	 * and seeds it into the dataflow, whose own strategy still decides whether anything is
	 * annotated (docs/per-game-descriptors-design.md section 6.2: seeds, not injected results).
	 * {@code block:} is the same memory-block qualifier {@code symbols:} uses (omitted = the base
	 * space). {@code bank:} (bead grm-hb6.20, design section 6.3 as amended by the 2026-10-18
	 * owner ruling) is the optional VALUE hint: a non-negative bank number the analyzer applies at
	 * the site in preference to anything it recovered. Only its SHAPE (a non-negative integer) is
	 * checked here; whether the board's window can hold it, and whether the site is a latch store
	 * or a bank-switch helper call, are the analyzer's checks (they need the board and the ROM).
	 */
	private static Map<String, Object> switchSiteEntry(Map<String, Object> entry, String where,
			Set<Object> seen) {
		int addr = MapCompiler.requireAddr(entry, "addr", where);
		if (addr < 0 || addr > 0xFFFF) {
			throw new IllegalArgumentException(where + ": addr must be a 16-bit CPU address");
		}
		String block = null;
		if (entry.containsKey("block")) {
			block = checkBlockName(MapCompiler.requireString(entry, "block", where), where);
		}
		if (!seen.add((block == null ? "" : block) + ":" + addr)) {
			throw new IllegalArgumentException(where + ": addr " + addr +
				(block == null ? "" : " in block '" + block + "'") + " listed twice");
		}
		boolean isEntry = false;
		if (entry.containsKey("entry")) {
			if (!(entry.get("entry") instanceof Boolean)) {
				throw new IllegalArgumentException(where + ": 'entry' must be true or false");
			}
			isEntry = (Boolean) entry.get("entry");
		}
		Integer bank = null;
		if (entry.containsKey("bank")) {
			Object raw = entry.get("bank");
			if (!(raw instanceof Integer) && !(raw instanceof Long)) {
				throw new IllegalArgumentException(where +
					": 'bank' must be a non-negative integer (a bank number)");
			}
			long v = ((Number) raw).longValue();
			if (v < 0 || v > Integer.MAX_VALUE) {
				throw new IllegalArgumentException(where +
					": 'bank' must be a non-negative integer (a bank number)");
			}
			bank = (int) v;
		}
		String provenance = MapCompiler.requireString(entry, "provenance", where);
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("addr", addr);
		if (block != null) {
			e.put("block", block);
		}
		if (isEntry) {
			e.put("entry", true);
		}
		if (entry.containsKey("comment")) {
			e.put("comment", MapCompiler.requireString(entry, "comment", where));
		}
		if (bank != null) {
			e.put("bank", bank);
		}
		e.put("provenance", provenance);
		return e;
	}

	/**
	 * {@code banking.save_cells:} (bead grm-mej.9): a non-empty list of {@code { address,
	 * provenance }} entries, each stating that a RAM cell at {@code address} (zero page or
	 * 16-bit CPU address) is a dedicated save cell: a store of the entry bank into it by a
	 * bank-switch helper is still there after that helper's inner call. SHAPE only here; the
	 * analyzer (SaveRestoreTrampolines) uses it only as a premise of the restoring-trampoline
	 * walk and never as a source of any bank value.
	 */
	private static Map<String, Object> saveCellEntry(Map<String, Object> entry, String where,
			Set<Object> seen) {
		int address = MapCompiler.requireAddr(entry, "address", where);
		if (address < 0 || address > 0xFFFF) {
			throw new IllegalArgumentException(where + ": address must be a 16-bit CPU address");
		}
		if (!seen.add(address)) {
			throw new IllegalArgumentException(where + ": address " + address + " listed twice");
		}
		String provenance = MapCompiler.requireString(entry, "provenance", where);
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("address", address);
		e.put("provenance", provenance);
		return e;
	}
}
