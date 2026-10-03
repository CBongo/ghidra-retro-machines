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

import java.io.IOException;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Re-applies a program's descriptor symbol sets and struct types on (re-)analysis (bead
 * {@code grm-hb6.14}), so installing a new extension version lets an existing program pick up
 * labels and register structs that shipped with it. Before this, only the loaders applied them,
 * and only at import time.
 *
 * <p><b>Never clobbers.</b> Everything here routes through the existing guards: labels go in via
 * {@link AnnotationGuard#applyLabel} (a {@code USER_DEFINED} symbol at the address wins; an
 * identical name is a no-op), comments via {@link AnnotationGuard#addComment} (append-only, keyed
 * on the comment text), and struct types are skipped wherever any defined data already exists.
 * So a second run over the same program changes nothing. Two honest limits: a label a user
 * <em>deleted</em> comes back, and a descriptor that <em>renames</em> a label adds the new name
 * beside the old one (the old one is not ours to remove).
 *
 * <p><b>Which symbol sets.</b> The per-set toggles live in loader import options, which are not
 * program state, so the loaders record what they decided in {@link #SYMBOL_SETS_PROPERTY}
 * ({@link #recordSymbolSetChoice}) and this analyzer honours it. A set with no recorded choice
 * -- a program imported before the property existed, or a set that only a newer descriptor
 * declares -- falls back to the descriptor's own {@code default:}, which is exactly what an
 * unattended import applies.
 *
 * <p><b>Struct types</b> are applied at each {@code regions[]} entry and occupant
 * {@code subregions[]} entry carrying {@code type:}, at the start of the program's block of the
 * same name. Where no such block exists (a fragment the loader renamed, a banked occupant that
 * was never placed in this program) the entry is skipped silently rather than guessed.
 *
 * <p><b>Per-game initial-state hints are deliberately not handled here.</b> They are resolved at
 * import from the image bytes plus the game descriptor and written to the initial-state program
 * property that analyzers read as input; re-writing it on re-analysis would change analysis
 * input rather than annotate, and is not an additive idempotent operation the way a label is.
 * Re-resolving them belongs with the export/reapply work (grm-hb6.5).
 *
 * <p>Shaped like {@link DescriptorCopyHintAnalyzer}: a byte analyzer at
 * {@link AnalysisPriority#BLOCK_ANALYSIS} (fires over whole memory once per run, including
 * Analysis &rarr; Reanalyze), one-shot capable. The {@code kind: entry} function marking the
 * loaders do is not repeated; {@code applySymbolSet} still registers the external entry point,
 * which Ghidra's own disassembly seeds from.
 */
public class DescriptorAnnotationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Descriptor Annotations";
	private static final String DESCRIPTION =
		"Re-applies the machine descriptor's symbol sets and struct types (idempotent; never " +
			"overwrites user-defined labels or comments), so a newer extension picks up newly " +
			"shipped labels on re-analysis.";

	/**
	 * Program-info property recording which symbol sets the loader applied: a JSON object
	 * {@code {"<set name>": true|false}}. Absent keys mean "use the descriptor default".
	 */
	static final String SYMBOL_SETS_PROPERTY = "Retro Machines.Symbol Sets";

	private static final String OPT_SYMBOLS = "Apply symbol sets";
	private static final String OPT_STRUCTS = "Apply struct types";

	private boolean applySymbols = true;
	private boolean applyStructs = true;

	/** Creates the descriptor annotation re-application analyzer. */
	public DescriptorAnnotationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_SYMBOLS, applySymbols, null,
			"Re-apply the descriptor's symbol sets (honouring the sets chosen at import).");
		options.registerOption(OPT_STRUCTS, applyStructs, null,
			"Re-apply the descriptor's register struct types where no data is defined yet.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applySymbols = options.getBoolean(OPT_SYMBOLS, applySymbols);
		applyStructs = options.getBoolean(OPT_STRUCTS, applyStructs);
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			if (identityOf(program) != null) {
				return true;   // a per-game descriptor (curated or overlay) may carry symbols
			}
			JsonObject map = loadMap(program);
			return map != null && (map.has("symbols") || map.has("regions"));
		}
		catch (IOException | RuntimeException e) {
			return false;
		}
	}

	private static String mapPath(Program program) {
		String p = DescriptorSupport.programInfoString(program, DescriptorSupport.MAP_PATH_PROPERTY);
		return p == null || p.isBlank() ? null : p;
	}

	private static JsonObject loadMap(Program program) throws IOException {
		String path = mapPath(program);
		return path == null ? null : DescriptorResources.loadMap(path);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		JsonObject map;
		try {
			map = loadMap(program);
		}
		catch (IOException | RuntimeException e) {
			AnalyzerLog.warn(this, log, "could not read the descriptor: " + e.getMessage());
			return false;
		}
		if (applySymbols) {
			applyGameSymbols(program, log);
		}
		if (map == null) {
			return true;
		}
		FileDataTypeManager gdt = null;
		if (applyStructs) {
			String path = mapPath(program);
			String gdtPath = path.endsWith(".map") ? path.substring(0, path.length() - 4) + ".gdt"
					: path + ".gdt";
			try {
				gdt = DescriptorResources.openGdt(gdtPath);
			}
			catch (IOException | RuntimeException e) {
				AnalyzerLog.warn(this, log,
					"no type archive, skipping struct types: " + e.getMessage());
			}
		}
		try {
			return applyAll(program, map, gdt, applySymbols, applyStructs, monitor, log);
		}
		finally {
			if (gdt != null) {
				gdt.close();
			}
		}
	}

	// ------------------------------------------------------------------
	// Recorded loader choices
	// ------------------------------------------------------------------

	/**
	 * Called by a loader, inside its import transaction, for every symbol set it decided on
	 * (applied or not), so re-analysis can honour the choice.
	 */
	static void recordSymbolSetChoice(Program program, String setName, boolean applied) {
		Options info = program.getOptions(Program.PROGRAM_INFO);
		JsonObject choices = parseChoices(info.getString(SYMBOL_SETS_PROPERTY, ""));
		choices.addProperty(setName, applied);
		info.setString(SYMBOL_SETS_PROPERTY, choices.toString());
	}

	private static JsonObject parseChoices(String json) {
		if (json == null || json.isBlank()) {
			return new JsonObject();
		}
		try {
			return JsonParser.parseString(json).getAsJsonObject();
		}
		catch (RuntimeException e) {
			return new JsonObject();
		}
	}

	/** Whether {@code set} is enabled for this program: the recorded choice, else the default. */
	static boolean symbolSetEnabled(Program program, JsonObject set) {
		JsonObject choices =
			parseChoices(DescriptorSupport.programInfoString(program, SYMBOL_SETS_PROPERTY));
		String name = set.get("set").getAsString();
		if (choices.has(name)) {
			return choices.get(name).getAsBoolean();
		}
		return set.has("default") && set.get("default").getAsBoolean();
	}

	// ------------------------------------------------------------------
	// Application (the testable seam)
	// ------------------------------------------------------------------

	/**
	 * Apply the descriptor's symbol sets and struct types. {@code gdt} may be null (no struct
	 * types then). The caller owns the transaction (auto-analysis supplies one).
	 */
	boolean applyAll(Program program, JsonObject map, FileDataTypeManager gdt, boolean symbols,
			boolean structs, TaskMonitor monitor, MessageLog log) {
		AddressSpace base = program.getAddressFactory().getDefaultAddressSpace();
		if (symbols && map.has("symbols")) {
			for (JsonElement se : map.getAsJsonArray("symbols")) {
				if (monitor.isCancelled()) {
					return false;
				}
				JsonObject set = se.getAsJsonObject();
				if (!symbolSetEnabled(program, set)) {
					continue;
				}
				DescriptorSupport.applySymbolSet(program, base, set, (name, addr) -> {
				}, log);
			}
		}
		if (structs && gdt != null) {
			String source = mapPath(program);
			if (map.has("regions")) {
				applyStructs(program, map.getAsJsonArray("regions"), gdt, source, log, monitor);
			}
			if (map.has("windows")) {
				applyStructsInWindows(program, map.getAsJsonArray("windows"), gdt, source, log,
					monitor);
			}
		}
		return !monitor.isCancelled();
	}

	// ------------------------------------------------------------------
	// Per-game symbol sets (bead grm-hb6.5)
	// ------------------------------------------------------------------

	/**
	 * Re-resolves the program's per-game descriptor against its recorded identity (a fresh scan,
	 * so an overlay file dropped in after import is picked up, design section 3c.2) and applies
	 * its {@code symbols:} sets. Never throws: a failure costs only the game layer.
	 */
	private void applyGameSymbols(Program program, MessageLog log) {
		try {
			GameDescriptorRegistry.GameDescriptor game = resolveGame(program, log);
			if (game != null) {
				applyGameSymbols(program, game.doc(), TaskMonitor.DUMMY, log);
			}
		}
		catch (RuntimeException e) {
			AnalyzerLog.warn(this, log, "game descriptor symbols skipped: " + e.getMessage());
		}
	}

	/** The program's recorded game identity, or null when absent or malformed. */
	private static DescriptorSupport.GameIdentity identityOf(Program program) {
		String spec = DescriptorSupport.programInfoString(program,
			DescriptorSupport.GAME_IDENTITY_PROPERTY);
		if (spec == null) {
			return null;
		}
		try {
			return DescriptorSupport.parseGameIdentity(spec);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static GameDescriptorRegistry.GameDescriptor resolveGame(Program program,
			MessageLog log) {
		DescriptorSupport.GameIdentity identity = identityOf(program);
		String path = mapPath(program);
		if (identity == null || path == null) {
			return null;
		}
		String boardId = null;
		for (NesBoardRegistry.Board board : NesBoardRegistry.boards()) {
			if (board.mapPath().equals(path)) {
				boardId = board.id();
			}
		}
		if (boardId == null) {
			return null;
		}
		return GameDescriptorRegistry.resolve(GameDescriptorRegistry.scan(log), identity,
			boardId, log);
	}

	/**
	 * Applies the {@code symbols:} sets of a compiled game descriptor document -- the testable
	 * seam. Same guards and idempotence as the machine sets ({@link DescriptorSupport#
	 * applySymbolSet}); entries land as {@code IMPORTED}, never {@code USER_DEFINED}
	 * (design section 3c.3), so an exported user label returns as an imported one.
	 */
	void applyGameSymbols(Program program, JsonObject gameDoc, TaskMonitor monitor,
			MessageLog log) {
		if (!gameDoc.has("symbols")) {
			return;
		}
		AddressSpace base = program.getAddressFactory().getDefaultAddressSpace();
		for (JsonElement se : gameDoc.getAsJsonArray("symbols")) {
			if (monitor.isCancelled()) {
				return;
			}
			JsonObject set = se.getAsJsonObject();
			if (symbolSetEnabled(program, set)) {
				DescriptorSupport.applySymbolSet(program, base, set, (name, addr) -> {
				}, log);
			}
		}
	}

	private void applyStructsInWindows(Program program, JsonArray windows,
			FileDataTypeManager gdt, String source, MessageLog log, TaskMonitor monitor) {
		for (JsonElement we : windows) {
			JsonObject w = we.getAsJsonObject();
			if (!w.has("occupants")) {
				continue;
			}
			for (JsonElement oe : w.getAsJsonArray("occupants")) {
				JsonObject occ = oe.getAsJsonObject();
				if (occ.has("subregions")) {
					applyStructs(program, occ.getAsJsonArray("subregions"), gdt, source, log,
						monitor);
				}
			}
		}
	}

	/** Struct-typed entries of {@code entries} (regions or subregions), plus their subregions. */
	private void applyStructs(Program program, JsonArray entries, FileDataTypeManager gdt,
			String source, MessageLog log, TaskMonitor monitor) {
		for (JsonElement ee : entries) {
			if (monitor.isCancelled()) {
				return;
			}
			JsonObject entry = ee.getAsJsonObject();
			if (entry.has("type") && entry.has("start") && entry.has("name")) {
				applyOneStruct(program, entry, gdt, source, log);
			}
			if (entry.has("subregions")) {
				applyStructs(program, entry.getAsJsonArray("subregions"), gdt, source, log,
					monitor);
			}
		}
	}

	private void applyOneStruct(Program program, JsonObject entry, FileDataTypeManager gdt,
			String source, MessageLog log) {
		MemoryBlock block = program.getMemory().getBlock(entry.get("name").getAsString());
		if (block == null) {
			return;
		}
		AddressSpace space = block.getStart().getAddressSpace();
		Address addr = space.getAddress(entry.get("start").getAsLong());
		if (!block.contains(addr)) {
			return;
		}
		Data existing = program.getListing().getDataContaining(addr);
		if (existing != null && existing.isDefined()) {
			return;   // applied before, or the user typed it: either way, not ours to redo
		}
		DescriptorSupport.applyStructType(program, space, gdt, entry, source, log);
	}
}
