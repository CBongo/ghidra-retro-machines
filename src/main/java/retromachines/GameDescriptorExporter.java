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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import gdtbuilder.GameCompiler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.StringPropertyMap;

/**
 * Selective export of a program's human annotation layer as a per-game descriptor (bead
 * {@code grm-hb6.5}, docs/per-game-descriptors-design.md sections 3c and 7). The Ghidra script
 * {@code ghidra_scripts/ExportGameDescriptor.java} is a thin argument-collecting front-end over
 * {@link #export}; everything testable lives here.
 *
 * <p><b>The output is valid, unedited, as BOTH an overlay file and a {@code machines/games/}
 * pull request</b> -- it carries no {@code include:}, no {@code source:}, and only keys
 * {@code gdtbuilder.GameCompiler} reads. The round-trip test
 * ({@code GameDescriptorExportRoundTripTest}) compiles it through both dispositions.
 *
 * <p><b>What is exported, and why only that.</b>
 * <ul>
 * <li><b>Identity</b>, read back from the {@code Retro Machines.Game Identity} property the
 * loader wrote, so the export cannot disagree with the import.</li>
 * <li><b>Labels:</b> only {@code USER_DEFINED} symbols in the global namespace (labels and
 * function names). An analyzer- or descriptor-created label is a guess or someone else's fact;
 * exporting it would launder it into a recorded fact under the user's name (design section
 * 3c.3). Namespaced (function-local) labels are skipped because the schema has no namespace
 * qualifier; they are counted in {@link Result#skipped()}.</li>
 * <li><b>Comments:</b> an EOL comment at an exported label's address rides on that symbol entry's
 * {@code comment} field (the EOL shorthand). Every other user comment -- EOL at an unlabelled
 * address, and pre/plate/post/repeatable anywhere -- goes into ONE {@code comments:} set named
 * {@code <id>-comments} (bead grm-hb6.18, owner ruling 2026-10-18). Ghidra comments have no
 * {@code SourceType}, so the extension records the EXACT segments its analyzers and loaders
 * wrote ({@link BankCommentProvenance} for bank EOL comments, {@link AnalyzerCommentRecord}
 * for every other extension writer, per comment type, bead grm-hb6.18); those are removed as
 * whole {@code "; "}-joined segments and anything else at a user-labelled address is the
 * user's -- including a human's own {@code bank -> 5}. Only a program with no
 * analyzer-comment record at all (analyzed before this existed) falls back to the old
 * text-prefix list, with a note in {@link Result#skipped()}. Only a comment in an overlay
 * address with no containing block (nothing to name) cannot travel and is counted as skipped.</li>
 * <li><b>Bank qualifier:</b> a label in an overlay (banked) address space is exported with
 * {@code block:} naming the memory block that holds it; the consumer resolves the block by name
 * and ignores the entry (logging) if the fresh import lacks it.</li>
 * <li><b>{@code banking.initial_state}:</b> copied from the descriptor that was in force
 * ({@link Request#initialState}), because an overlay file shadows a curated one wholesale -- an
 * export that dropped the hint would silently regress the import.</li>
 * <li><b>{@code banking.bank_identifying_offsets}:</b> copied, provenance and all, from the
 * {@code Retro Machines.Bank Identifying Hints} property the loader recorded from the
 * descriptor in force (bead grm-hb6.19), for the same shadowing reason. Never derived from
 * the ROM bytes: the key states a human-established membership premise.</li>
 * <li><b>{@code banking.switch_sites}:</b> the site hints the descriptor in force stated, copied
 * verbatim (bead grm-hb6.4), including the optional {@code bank:} value hint (grm-hb6.20). Bank-switch sites the analysis itself recovered are NOT exported:
 * they are analysis output, not a human fact.</li>
 * </ul>
 *
 * <p>The consumer ({@code DescriptorAnnotationAnalyzer}) applies entries as {@code IMPORTED},
 * never {@code USER_DEFINED}, so a re-import shows the same names at the same addresses with
 * source {@code IMPORTED} -- a deliberate asymmetry (design section 3c.3).
 */
public final class GameDescriptorExporter {

	/** The symbol set name used for the exported labels. */
	public static final String SET_NAME = "user-annotations";

	/** Appended to the game id to name the {@code comments:} set (bead grm-hb6.18). */
	public static final String COMMENTS_SET_SUFFIX = "-comments";

	/**
	 * Legacy fallback only (programs with no analyzer-comment record, i.e. analyzed before comment
	 * provenance existed): text prefixes of what extension writers emit.
	 */
	private static final String[] ANALYZER_PREFIXES =
		{ "bank ->", "bank ?", "bank mirror:", "[JumpTableBound]" };

	private GameDescriptorExporter() {
	}

	/**
	 * What the caller supplies. {@code initialState} may be null/empty; the rest are required.
	 * {@code prgSha256}/{@code fileSha256} are normally read from the program (see
	 * {@link #identityOf}).
	 */
	public record Request(String id, String title, String boardId, String provenance,
			String prgSha256, String fileSha256, Map<String, Integer> initialState) {}

	/** The YAML text plus what was and was not carried. */
	public record Result(String yaml, int labels, int comments, List<String> skipped) {}

	/** The program's recorded identity as {prg, file}, or null if it has none. */
	public static String[] identityOf(Program program) {
		String spec = DescriptorHints.programInfoString(program,
			DescriptorHints.GAME_IDENTITY_PROPERTY);
		if (spec == null) {
			return null;
		}
		GameIdentities.GameIdentity id = GameIdentities.parseGameIdentity(spec);
		return id == null ? null : new String[] { id.prgSha256(), id.fileSha256() };
	}

	/**
	 * The script's request: identity and board read back from the program's recorded properties,
	 * {@code banking.initial_state} copied from the game descriptor currently resolved for it
	 * (curated or overlay), and a provenance naming the program, user and date. {@code id} and
	 * {@code title} default from the program name when null; {@code note} is appended to the
	 * provenance when non-blank. Needs an initialised Ghidra {@code Application} (board registry).
	 */
	public static Request defaultRequest(Program program, String id, String title,
			String note) {
		String[] identity = identityOf(program);
		String mapPath =
			DescriptorHints.programInfoString(program, DescriptorHints.MAP_PATH_PROPERTY);
		String boardId = null;
		for (NesBoardRegistry.Board board : NesBoardRegistry.boards()) {
			if (board.mapPath().equals(mapPath)) {
				boardId = board.id();
			}
		}
		Map<String, Integer> initialState = new LinkedHashMap<>();
		if (identity != null && boardId != null) {
			var match = GameDescriptorRegistry.resolve(
				GameDescriptorRegistry.scan(new ghidra.app.util.importer.MessageLog()),
				new GameIdentities.GameIdentity(identity[0], identity[1]), boardId,
				new ghidra.app.util.importer.MessageLog());
			if (match != null && match.doc().has("banking") &&
				match.doc().getAsJsonObject("banking").has("initial_state")) {
				for (var f : match.doc().getAsJsonObject("banking")
						.getAsJsonObject("initial_state").entrySet()) {
					initialState.put(f.getKey(), f.getValue().getAsInt());
				}
			}
		}
		String name = program.getName();
		String slug = name.toLowerCase(Locale.ROOT).replaceAll("\\.[a-z0-9]{1,4}$", "")
				.replaceAll("[^a-z0-9]+", "_").replaceAll("^_+|_+$", "");
		String provenance = "exported from Ghidra program '" + name + "' by " +
			System.getProperty("user.name", "unknown") + " on " + java.time.LocalDate.now(java.time.ZoneId.systemDefault()) +
			" (USER_DEFINED labels and user comments)" +
			(note == null || note.isBlank() ? "" : "; " + note.strip());
		return new Request(id != null ? id : slug.isEmpty() ? "exported_game" : slug,
			title != null ? title : name, boardId, provenance,
			identity == null ? null : identity[0], identity == null ? null : identity[1],
			initialState);
	}

	/** Builds the descriptor YAML for {@code program}'s annotation layer. */
	public static Result export(Program program, Request req) {
		List<String> skipped = new ArrayList<>();
		List<Map<String, Object>> entries = new ArrayList<>();
		Listing listing = program.getListing();
		Map<Address, Boolean> exportedAddrs = new LinkedHashMap<>();

		TreeMap<String, Map<Long, Symbol>> byKey = new TreeMap<>();
		int nonGlobal = 0;
		for (Symbol sym : program.getSymbolTable().getAllSymbols(false)) {
			if (sym.getSource() != SourceType.USER_DEFINED || !sym.getAddress().isMemoryAddress()) {
				continue;
			}
			SymbolType type = sym.getSymbolType();
			if (!SymbolType.LABEL.equals(type) && !SymbolType.FUNCTION.equals(type)) {
				continue;
			}
			if (sym.getParentNamespace() == null ||
				sym.getParentNamespace().getID() != Namespace.GLOBAL_NAMESPACE_ID) {
				nonGlobal++;
				continue;
			}
			String block = blockKey(program, sym.getAddress());
			if (block == null) {
				skipped.add("label " + sym.getName() + " at " + sym.getAddress() +
					": overlay address with no containing block");
				continue;
			}
			Map<Long, Symbol> perBlock = byKey.computeIfAbsent(block, k -> new TreeMap<>());
			long off = sym.getAddress().getOffset();
			Symbol prior = perBlock.get(off);
			// One label per (block, address): the primary if it qualifies, else the first.
			if (prior == null || (sym.isPrimary() && !prior.isPrimary())) {
				perBlock.put(off, sym);
			}
		}
		if (nonGlobal > 0) {
			skipped.add(nonGlobal + " user label(s) in a non-global namespace (the schema has " +
				"no namespace qualifier)");
		}

		int comments = 0;
		AtomicBoolean fallbackDropped = new AtomicBoolean();
		for (Map.Entry<String, Map<Long, Symbol>> be : byKey.entrySet()) {
			String block = be.getKey();
			for (Map.Entry<Long, Symbol> se : be.getValue().entrySet()) {
				Symbol sym = se.getValue();
				Address a = sym.getAddress();
				Map<String, Object> e = new LinkedHashMap<>();
				e.put("addr", new HexInt(se.getKey()));
				e.put("name", sym.getName());
				e.put("kind", SymbolType.FUNCTION.equals(sym.getSymbolType()) ? "entry" : "label");
				if (!block.isEmpty()) {
					e.put("block", block);
				}
				String comment = userComment(program, a, CommentType.EOL,
					listing.getComment(CommentType.EOL, a), fallbackDropped);
				if (comment != null) {
					e.put("comment", comment);
					comments++;
				}
				exportedAddrs.put(a, comment != null);
				entries.add(e);
			}
		}
		entries.sort(Comparator.comparing((Map<String, Object> m) -> (String) m.getOrDefault("block", ""))
				.thenComparingInt(m -> ((HexInt) m.get("addr")).value()));

		// Every user comment the symbol entries do not already carry goes into ONE comments set
		// (bead grm-hb6.18): EOL at a non-exported address, and every other type anywhere. EOL at
		// an exported label's address stays on that symbol entry as the shorthand.
		TreeMap<String, TreeMap<Long, Map<String, Object>>> commentRows = new TreeMap<>();
		int unnamedBlock = 0;
		var it = listing.getCommentAddressIterator(program.getMemory(), true);
		while (it.hasNext()) {
			Address a = it.next();
			Map<String, Object> row = null;
			String block = null;
			boolean blockResolved = false;
			boolean unresolvable = false;
			for (String key : GameCompiler.COMMENT_KEYS) {
				CommentType t = CommentType.valueOf(key.toUpperCase(Locale.ROOT));
				if (t == CommentType.EOL && exportedAddrs.containsKey(a)) {
					continue;
				}
				String c = listing.getComment(t, a);
				String text = userComment(program, a, t, c, fallbackDropped);
				if (text == null) {
					continue;
				}
				if (!blockResolved) {
					block = blockKey(program, a);
					blockResolved = true;
				}
				if (block == null) {
					unresolvable = true;
					continue;
				}
				if (row == null) {
					row = new LinkedHashMap<>();
					row.put("addr", new HexInt(a.getOffset()));
					if (!block.isEmpty()) {
						row.put("block", block);
					}
				}
				row.put(key, text);
				comments++;
			}
			if (unresolvable) {
				unnamedBlock++;
			}
			if (row != null) {
				commentRows.computeIfAbsent(block, k -> new TreeMap<>()).put(a.getOffset(), row);
			}
		}
		List<Map<String, Object>> commentEntries = new ArrayList<>();
		commentRows.values().forEach(m -> commentEntries.addAll(m.values()));
		if (unnamedBlock > 0) {
			skipped.add(unnamedBlock + " commented address(es) not carried (overlay address with " +
				"no containing block to name)");
		}

		if (fallbackDropped.get()) {
			skipped.add("comment filtering used the legacy text-prefix heuristic because the " +
				"program predates comment provenance (re-run analysis to record it)");
		}

		if (req.prgSha256() == null || req.fileSha256() == null) {
			throw new IllegalStateException("program has no game identity (not an image the " +
				"loader fingerprints); nothing to key a descriptor on");
		}
		if (req.boardId() == null) {
			throw new IllegalStateException("program has no resolved board; a game descriptor " +
				"must name one (game.board)");
		}

		Map<String, Object> identity = new LinkedHashMap<>();
		identity.put("prg_sha256", req.prgSha256());
		identity.put("file_sha256", req.fileSha256());
		Map<String, Object> game = new LinkedHashMap<>();
		game.put("id", req.id());
		game.put("title", req.title());
		game.put("board", req.boardId());
		game.put("identity", identity);
		game.put("provenance", req.provenance());

		Map<String, Object> doc = new LinkedHashMap<>();
		doc.put("schema", 2);
		doc.put("game", game);
		Map<String, Object> banking = new LinkedHashMap<>();
		if (req.initialState() != null && !req.initialState().isEmpty()) {
			banking.put("initial_state", new LinkedHashMap<String, Object>(req.initialState()));
		}
		for (BankingHintKind kind : BankingHintKind.values()) {
			List<Map<String, Object>> hints = verbatimBankingList(program, skipped, kind);
			if (!hints.isEmpty()) {
				banking.put(kind.yamlKey, hints);
			}
		}
		if (!banking.isEmpty()) {
			doc.put("banking", banking);
		}
		if (!entries.isEmpty()) {
			Map<String, Object> set = new LinkedHashMap<>();
			set.put("set", SET_NAME);
			set.put("default", true);
			set.put("provenance", req.provenance());
			set.put("inline", entries);
			doc.put("symbols", List.of(set));
		}
		if (!commentEntries.isEmpty()) {
			Map<String, Object> set = new LinkedHashMap<>();
			set.put("set", req.id() + COMMENTS_SET_SUFFIX);
			set.put("default", true);
			set.put("provenance", req.provenance());
			set.put("inline", commentEntries);
			doc.put("comments", List.of(set));
		}

		DumperOptions opts = new DumperOptions();
		opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
		opts.setIndent(2);
		opts.setIndicatorIndent(0);
		opts.setSplitLines(false);
		HexRepresenter hex = new HexRepresenter(opts);
		String header = "# Per-game descriptor exported by ghidra_scripts/ExportGameDescriptor.java.\n" +
			"# Valid as a drop-in overlay (<Ghidra user settings>/retro-machines/games/) and as a\n" +
			"# machines/games/*.yaml pull request. Only USER_DEFINED labels and user\n" +
			"# comments are carried; see docs/per-game-descriptors-design.md section 7.\n";
		return new Result(header + new Yaml(hex, opts).dump(doc), entries.size(), comments,
			skipped);
	}

	/**
	 * A hand-stated banking hint list (bead grm-mej.10), copied verbatim, provenance included,
	 * from the program property the loader recorded. {@code hexKeys} are written as hex
	 * addresses, {@code plainKeys} as recorded (a string or small integer); {@code optionalKeys}
	 * are carried as recorded only when present (a boolean only when true), between the plain keys
	 * and the provenance. Never derived: the key records a human-established fact, and exporting
	 * a ROM-byte derivation would launder one into it (grm-hb6.19). A malformed property is
	 * reported in {@code skipped} and carries nothing.
	 */
	private static List<Map<String, Object>> verbatimBankingList(Program program,
			List<String> skipped, BankingHintKind kind) {
		List<Map<String, Object>> out = new ArrayList<>();
		String spec = DescriptorHints.programInfoString(program, kind.property);
		if (spec == null || spec.isBlank()) {
			return out;
		}
		try {
			JsonObject root = JsonParser.parseString(spec).getAsJsonObject();
			for (JsonElement el : root.getAsJsonArray(kind.arrayKey)) {
				JsonObject o = el.getAsJsonObject();
				Map<String, Object> e = new LinkedHashMap<>();
				for (String k : kind.hexKeys) {
					e.put(k, new HexInt(o.get(k).getAsLong()));
				}
				for (String k : kind.plainKeys) {
					var v = o.get(k).getAsJsonPrimitive();
					e.put(k, v.isNumber() ? (Object) v.getAsInt() : v.getAsString());
				}
				for (String k : kind.optionalKeys) {
					if (!o.has(k)) {
						continue;
					}
					var v = o.get(k).getAsJsonPrimitive();
					if (v.isBoolean()) {
						if (v.getAsBoolean()) {
							e.put(k, true);
						}
					}
					else {
						e.put(k, v.isNumber() ? (Object) v.getAsInt() : v.getAsString());
					}
				}
				e.put("provenance", o.get("provenance").getAsString());
				out.add(e);
			}
		}
		catch (RuntimeException e) {
			skipped.add(kind.notCarriedMessage(e.getMessage()));
			return new ArrayList<>();
		}
		return out;
	}

	/** "" for the default space, the block name for an overlay space, null if unresolvable. */
	private static String blockKey(Program program, Address a) {
		AddressSpace space = a.getAddressSpace();
		if (!space.isOverlaySpace()) {
			return "";
		}
		MemoryBlock block = program.getMemory().getBlock(a);
		return block == null ? null : block.getName();
	}

	/**
	 * The comment at {@code addr} of {@code type} with extension-written segments removed, or
	 * null if nothing is left. Callable for ANY comment type.
	 */
	static String userComment(Program program, Address addr, CommentType type, String text) {
		return userComment(program, addr, type, text, new AtomicBoolean());
	}

	/**
	 * As {@link #userComment(Program, Address, CommentType, String)}; sets
	 * {@code fallbackDropped} when the legacy prefix heuristic (used only for a program with no
	 * analyzer-comment record) actually removed a segment.
	 */
	static String userComment(Program program, Address addr, CommentType type, String text,
			AtomicBoolean fallbackDropped) {
		if (text == null || text.isBlank()) {
			return null;
		}
		String remaining = text;
		if (AnalyzerCommentRecord.hasAnyMap(program)) {
			List<String> recorded = new ArrayList<>();
			if (type == CommentType.EOL) {
				StringPropertyMap bank = program.getUsrPropertyManager()
						.getStringPropertyMap(BankCommentProvenance.PROPERTY_MAP);
				String bankText = bank == null ? null : bank.getString(addr);
				if (bankText != null) {
					recorded.add(bankText);
				}
			}
			recorded.addAll(AnalyzerCommentRecord.recorded(program, addr, type));
			for (String segment : recorded) {
				String cut = BankCommentProvenance.removeSegment(remaining, segment);
				if (cut != null) {
					remaining = cut;
				}
			}
		}
		else {
			List<String> kept = new ArrayList<>();
			for (String segment : text.split("; ")) {
				boolean analyzer = false;
				for (String prefix : ANALYZER_PREFIXES) {
					if (segment.startsWith(prefix)) {
						analyzer = true;
					}
				}
				if (analyzer) {
					fallbackDropped.set(true);
				}
				else {
					kept.add(segment);
				}
			}
			remaining = String.join("; ", kept);
		}
		String out = remaining.strip();
		return out.isEmpty() ? null : out;
	}

	/** An address rendered as bare hex in the YAML (still an int scalar to every reader). */
	record HexInt(int value) {
		HexInt(long v) {
			this((int) v);
		}
	}

	private static final class HexRepresenter extends Representer {
		HexRepresenter(DumperOptions opts) {
			super(opts);
			this.representers.put(HexInt.class,
				data -> representScalar(Tag.INT, String.format("0x%04X", ((HexInt) data).value())));
		}
	}
}
