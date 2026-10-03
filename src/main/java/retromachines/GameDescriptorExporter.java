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
import java.util.Map;
import java.util.TreeMap;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

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
 * <li><b>Comments:</b> the {@code comment} field of a symbol entry is the only comment carrier
 * the schema has (design section 9 q4), and the consumer applies it as an EOL comment. So only
 * EOL comments at an exported label's address are carried. Ghidra comments have no
 * {@code SourceType}, so "user comment" cannot be told from an analyzer one by provenance;
 * segments the bank analyzer writes ({@code bank ->}, {@code bank ?}) are filtered out by
 * their prefix, and anything else at a user-labelled address is treated as the user's. Comments
 * at unlabelled addresses, and non-EOL comments, are counted as skipped, never invented a
 * carrier for.</li>
 * <li><b>Bank qualifier:</b> a label in an overlay (banked) address space is exported with
 * {@code block:} naming the memory block that holds it; the consumer resolves the block by name
 * and ignores the entry (logging) if the fresh import lacks it.</li>
 * <li><b>{@code banking.initial_state}:</b> copied from the descriptor that was in force
 * ({@link Request#initialState}), because an overlay file shadows a curated one wholesale -- an
 * export that dropped the hint would silently regress the import.</li>
 * </ul>
 * Bank-switch sites are NOT exported: nothing reads {@code banking.switch_sites} yet (grm-hb6.4),
 * and recovered sites are analysis output, not a human fact.
 *
 * <p>The consumer ({@code DescriptorAnnotationAnalyzer}) applies entries as {@code IMPORTED},
 * never {@code USER_DEFINED}, so a re-import shows the same names at the same addresses with
 * source {@code IMPORTED} -- a deliberate asymmetry (design section 3c.3).
 */
public final class GameDescriptorExporter {

	/** The symbol set name used for the exported labels. */
	public static final String SET_NAME = "user-annotations";

	private static final String[] ANALYZER_PREFIXES = { "bank ->", "bank ?" };

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
		String spec = DescriptorSupport.programInfoString(program,
			DescriptorSupport.GAME_IDENTITY_PROPERTY);
		if (spec == null) {
			return null;
		}
		DescriptorSupport.GameIdentity id = DescriptorSupport.parseGameIdentity(spec);
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
			DescriptorSupport.programInfoString(program, DescriptorSupport.MAP_PATH_PROPERTY);
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
				new DescriptorSupport.GameIdentity(identity[0], identity[1]), boardId,
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
		String slug = name.toLowerCase().replaceAll("\\.[a-z0-9]{1,4}$", "")
				.replaceAll("[^a-z0-9]+", "_").replaceAll("^_+|_+$", "");
		String provenance = "exported from Ghidra program '" + name + "' by " +
			System.getProperty("user.name", "unknown") + " on " + java.time.LocalDate.now() +
			" (USER_DEFINED labels and their EOL comments only)" +
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
			if (type != SymbolType.LABEL && type != SymbolType.FUNCTION) {
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
		for (Map.Entry<String, Map<Long, Symbol>> be : byKey.entrySet()) {
			String block = be.getKey();
			for (Map.Entry<Long, Symbol> se : be.getValue().entrySet()) {
				Symbol sym = se.getValue();
				Address a = sym.getAddress();
				Map<String, Object> e = new LinkedHashMap<>();
				e.put("addr", new HexInt(se.getKey()));
				e.put("name", sym.getName());
				e.put("kind", sym.getSymbolType() == SymbolType.FUNCTION ? "entry" : "label");
				if (!block.isEmpty()) {
					e.put("block", block);
				}
				String comment = userComment(listing.getComment(CommentType.EOL, a));
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

		int stray = 0;
		var it = listing.getCommentAddressIterator(program.getMemory(), true);
		while (it.hasNext()) {
			Address a = it.next();
			boolean carried = Boolean.TRUE.equals(exportedAddrs.get(a));
			boolean hasOther = false;
			for (CommentType t : CommentType.values()) {
				String c = listing.getComment(t, a);
				if (c == null || c.isBlank()) {
					continue;
				}
				if (t == CommentType.EOL) {
					if (!carried && userComment(c) != null) {
						hasOther = true;
					}
				}
				else {
					hasOther = true;
				}
			}
			if (hasOther) {
				stray++;
			}
		}
		if (stray > 0) {
			skipped.add(stray + " commented address(es) not carried (comments ride on a " +
				"user label's entry as EOL text; plate/pre/post/repeatable comments and " +
				"comments at unlabelled addresses have no carrier in the schema yet)");
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
		if (req.initialState() != null && !req.initialState().isEmpty()) {
			Map<String, Object> banking = new LinkedHashMap<>();
			banking.put("initial_state", new LinkedHashMap<String, Object>(req.initialState()));
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

		DumperOptions opts = new DumperOptions();
		opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
		opts.setIndent(2);
		opts.setIndicatorIndent(0);
		opts.setSplitLines(false);
		HexRepresenter hex = new HexRepresenter(opts);
		String header = "# Per-game descriptor exported by ghidra_scripts/ExportGameDescriptor.java.\n" +
			"# Valid as a drop-in overlay (<Ghidra user settings>/retro-machines/games/) and as a\n" +
			"# machines/games/*.yaml pull request. Only USER_DEFINED labels (and their EOL\n" +
			"# comments) are carried; see docs/per-game-descriptors-design.md section 7.\n";
		return new Result(header + new Yaml(hex, opts).dump(doc), entries.size(), comments,
			skipped);
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

	/** The comment with analyzer-written segments removed, or null if nothing is left. */
	static String userComment(String comment) {
		if (comment == null || comment.isBlank()) {
			return null;
		}
		List<String> kept = new ArrayList<>();
		for (String segment : comment.split("; ")) {
			boolean analyzer = false;
			for (String prefix : ANALYZER_PREFIXES) {
				if (segment.startsWith(prefix)) {
					analyzer = true;
				}
			}
			if (!analyzer) {
				kept.add(segment);
			}
		}
		String out = String.join("; ", kept).strip();
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
