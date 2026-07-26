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
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.InvalidAddressException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.AssertException;

/**
 * The system-neutral half of the descriptor-driven loader stack: everything a loader
 * does with a compiled machine descriptor (`machines/&lt;id&gt;.map` JSON + companion
 * `.gdt` type archive) that is not specific to any one system. Extracted from
 * {@link C64PrgLoader} so the NES loader (and later systems) consume descriptors
 * through the same code paths — none of these helpers knows any hardware fact; they
 * only interpret the descriptor schema (docs/MAP_FORMAT.md).
 */
final class DescriptorSupport {

	/**
	 * Program-info property where a loader that chose among several board descriptors
	 * (e.g. {@link NesRomLoader} via the iNES mapper registry) records the winning
	 * descriptor's resource path, so downstream analyzers ({@link BoardBankAnalyzer}
	 * subclasses) interpret the program with the same board the loader used.
	 */
	static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	/**
	 * Program-info property where a loader records a user-supplied bank-placement override:
	 * space-separated {@code window:bank} pairs pinning a mode-varying switchable window
	 * instance to hold PRG bank {@code N}. {@link BoardBankAnalyzer} consults it only where
	 * dataflow did not determine the bank at a reference site (flow always wins when it
	 * knows). Grammar and semantics: {@link #parsePlacementOverride}. Engine-generic
	 * (window -> bank), so the read side lives in the machine-independent analyzer.
	 */
	static final String PLACEMENT_OVERRIDE_PROPERTY = "Retro Machines.Placement Override";

	/** One {@code window:bank} token: capture group 1 = window name, 2 = bank digits. The
	 *  separator is a colon, not '=': the headless {@code analyzeHeadless.bat} arg parser
	 *  (cmd.exe) splits values on '=', so an '='-based grammar can't be passed on Windows. */
	private static final Pattern PLACEMENT_PAIR = Pattern.compile("([A-Za-z0-9_]+):(\\d+)");

	private DescriptorSupport() {
	}

	/**
	 * Parses a placement-override spec -- space-separated {@code window:bank} pairs (e.g.
	 * {@code "W8000:5 WC000:3"}, read as "window W8000 holds PRG bank 5") -- into an
	 * insertion-ordered window-name -> bank map. Blank/null input yields an empty map.
	 * Throws {@link IllegalArgumentException} with a user-facing message on malformed syntax
	 * (bad token shape, out-of-range bank, or a repeated window). Window names and bank
	 * ranges are deliberately NOT validated here -- that needs the board descriptor and is
	 * the loader's job in {@code validateOptions}; this is the shared grammar both the loader
	 * (validate) and analyzer (read) go through.
	 */
	static Map<String, Integer> parsePlacementOverride(String spec) {
		Map<String, Integer> byWindow = new LinkedHashMap<>();
		if (spec == null || spec.isBlank()) {
			return byWindow;
		}
		for (String token : spec.trim().split("\\s+")) {
			Matcher m = PLACEMENT_PAIR.matcher(token);
			if (!m.matches()) {
				throw new IllegalArgumentException("malformed placement override '" + token +
					"'; expected window:bank (e.g. W8000:5)");
			}
			String window = m.group(1);
			int bank;
			try {
				bank = Integer.parseInt(m.group(2));
			}
			catch (NumberFormatException e) {
				throw new IllegalArgumentException(
					"placement override '" + token + "': bank number out of range");
			}
			if (byWindow.putIfAbsent(window, bank) != null) {
				throw new IllegalArgumentException(
					"placement override names window '" + window + "' more than once");
			}
		}
		return byWindow;
	}

	// ------------------------------------------------------------------
	// Descriptor / archive loading
	// ------------------------------------------------------------------

	/** Loads a bundled compiled descriptor, e.g. {@code machines/c64.map}. */
	static JsonObject loadMap(String mapPath) throws IOException {
		ResourceFile mapFile = Application.findDataFileInAnyModule(mapPath);
		if (mapFile == null) {
			throw new IOException("Could not find bundled data file " + mapPath);
		}
		try (InputStreamReader reader =
				new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	/**
	 * Resolves the processor language a descriptor should load with: the compiled map's
	 * {@code system.language} when that language is actually available to Ghidra (bundled
	 * or installed), otherwise {@code safetyFallbackId}. This is how a loader "stops
	 * passing a fallback language" once the descriptor's real language is bundled (bead
	 * grm-bk6): the descriptor names {@code 6510:LE:16:default}, the extension ships it,
	 * and this returns it; the hard-coded 6502 fallback only fires in a broken install
	 * where even the descriptor's language is missing.
	 */
	static String resolveLanguageId(JsonObject map, String safetyFallbackId) {
		JsonObject system = map.getAsJsonObject("system");
		String declared =
			system != null && system.has("language") ? system.get("language").getAsString() : null;
		if (declared != null && languageAvailable(declared)) {
			return declared;
		}
		return safetyFallbackId;
	}

	/** Variant field of the language IDs that decode the undocumented NMOS opcodes. */
	private static final String UNDOC_VARIANT = "undoc";

	/**
	 * The undocumented-opcode sibling of {@code languageId} -- e.g.
	 * {@code 6510:LE:16:default} to {@code 6510:LE:16:undoc} (bead grm-azg) -- or
	 * {@code null} when this build ships no such variant. A Ghidra language ID is
	 * {@code processor:endian:size:variant}, so the sibling differs only in the last field.
	 * <p>
	 * Loaders use this to OFFER the variant as an additional, non-preferred
	 * {@link ghidra.app.util.opinion.LoadSpec}, so returning {@code null} for anything
	 * unrecognized or unavailable is the point: a missing variant must quietly mean "don't
	 * offer it", never an exception on an import path.
	 */
	static String undocVariantOf(String languageId) {
		if (languageId == null) {
			return null;
		}
		int lastColon = languageId.lastIndexOf(':');
		if (lastColon < 0) {
			return null;
		}
		String sibling = languageId.substring(0, lastColon + 1) + UNDOC_VARIANT;
		if (sibling.equals(languageId) || !languageAvailable(sibling)) {
			return null;
		}
		return sibling;
	}

	private static boolean languageAvailable(String id) {
		try {
			DefaultLanguageService.getLanguageService()
					.getLanguageDescription(new LanguageID(id));
			return true;
		}
		catch (LanguageNotFoundException e) {
			return false;
		}
	}

	/** Opens a bundled data-type archive, e.g. {@code machines/c64.gdt}. */
	static FileDataTypeManager openGdt(String gdtPath) throws IOException {
		ResourceFile gdtFile = Application.findDataFileInAnyModule(gdtPath);
		if (gdtFile == null) {
			throw new IOException("Could not find bundled data file " + gdtPath);
		}
		return FileDataTypeManager.openFileArchive(gdtFile, false);
	}

	// ------------------------------------------------------------------
	// Block permissions by descriptor kind
	// ------------------------------------------------------------------
	// Centralized so every block-creation site agrees. Kind-derived defaults: RAM:
	// read/write/execute (8-bit systems routinely run code from RAM). ROM: read/execute,
	// not writable. IO: read/write, not executable, and marked volatile (hardware
	// registers with side effects on read/write). Read is always permitted by default.
	//
	// A node (region/occupant/subregion JSON object) may carry sparse boolean overrides
	// (`readable`/`writable`/`executable`) for hardware quirks that deviate from the kind
	// default on a single attribute (e.g. C64 CHARGEN is kind:rom but its glyph data is
	// never executed). Multi-attribute deviations should get a new `kind` instead.

	/** Effective permissions for a block: kind default, overridden by explicit JSON fields. */
	record Perms(boolean readable, boolean writable, boolean executable) {}

	private static boolean canWrite(String kind) {
		return !kind.equals("rom");
	}

	private static boolean canExecute(String kind) {
		return !kind.equals("io");
	}

	static Perms perms(JsonObject node, String kind) {
		boolean r = node.has("readable") ? node.get("readable").getAsBoolean() : true;
		boolean w = node.has("writable") ? node.get("writable").getAsBoolean() : canWrite(kind);
		boolean x = node.has("executable") ? node.get("executable").getAsBoolean() : canExecute(kind);
		return new Perms(r, w, x);
	}

	/** IO-kind blocks have side effects on access; mark them volatile so Ghidra doesn't cache
	 *  or fold reads/writes to them. Never applied to ram/rom (e.g. C64 COLOR_RAM inside the
	 *  IO window is kind:ram and stays non-volatile). */
	static void markVolatileIfIo(MemoryBlock block, String kind) {
		if (block != null && kind.equals("io")) {
			block.setVolatile(true);
		}
	}

	/**
	 * Creates the language's pspec-declared default memory blocks (e.g. 6502 ZERO_PAGE and
	 * STACK), quietly skipping any that conflict with blocks already in memory. Descriptor
	 * loaders override {@code AbstractProgramLoader.createDefaultMemoryBlocks} with this
	 * because their memory maps already cover those ranges, making the conflict expected
	 * rather than an error worth logging.
	 */
	static void createDefaultMemoryBlocksQuietly(Program program, MessageLog log) {
		int id = program.startTransaction("Create default blocks");
		try {
			for (MemoryBlockDefinition blockDef : program.getLanguage().getDefaultMemoryBlocks()) {
				try {
					blockDef.createBlock(program);
				}
				catch (LockException e) {
					throw new AssertException("Unexpected Error", e);
				}
				catch (MemoryConflictException e) {
					// Descriptor-defined memory already covers this range.
				}
				catch (AddressOverflowException | InvalidAddressException e) {
					log.appendMsg("Failed to add language defined memory block " + blockDef +
						": " + e.getMessage());
				}
			}
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	// ------------------------------------------------------------------
	// Always-visible regions
	// ------------------------------------------------------------------

	/**
	 * Creates the uninitialized block for a {@code regions[]} entry and applies its
	 * {@code type:} struct (when declared and an archive is available).
	 */
	static void createRegionBlock(Program program, AddressSpace baseSpace, JsonObject region,
			String source, FileDataTypeManager gdtMgr, MessageLog log) {

		String name = region.get("name").getAsString();
		long start = region.get("start").getAsLong();
		long end = region.get("end").getAsLong();
		String kind = region.get("kind").getAsString();
		String comment = region.has("comment") ? region.get("comment").getAsString() : null;

		Address startAddr = baseSpace.getAddress(start);
		long length = end - start + 1;
		Perms p = perms(region, kind);
		MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name, startAddr,
			length, comment, source, p.readable(), p.writable(), p.executable(), log);
		markVolatileIfIo(block, kind);

		if (region.has("type") && gdtMgr != null) {
			applyStructType(program, baseSpace, gdtMgr, region, source, log);
		}
	}

	// ------------------------------------------------------------------
	// IO subregions (chip register carve-up inside an io occupant/region)
	// ------------------------------------------------------------------

	static void createIoSubregions(Program program, AddressSpace baseSpace, JsonObject ioOccupant,
			String source, FileDataTypeManager gdtMgr, MessageLog log) {

		JsonArray subregions = ioOccupant.getAsJsonArray("subregions");
		for (JsonElement sre : subregions) {
			JsonObject sub = sre.getAsJsonObject();
			String name = sub.get("name").getAsString();
			long start = sub.get("start").getAsLong();

			long end;
			if (sub.has("repeat_to")) {
				end = sub.get("repeat_to").getAsLong();
			}
			else if (sub.has("end")) {
				end = sub.get("end").getAsLong();
			}
			else if (sub.has("size")) {
				end = start + sub.get("size").getAsLong() - 1;
			}
			else {
				throw new IllegalArgumentException("I/O subregion '" + name +
					"' needs end:, size:, or repeat_to:");
			}
			long length = end - start + 1;
			String kind = sub.has("kind") ? sub.get("kind").getAsString() : "io";
			String comment = sub.has("comment") ? sub.get("comment").getAsString() : name;

			Address startAddr = baseSpace.getAddress(start);
			Perms p = perms(sub, kind);
			MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
				startAddr, length, comment, source, p.readable(), p.writable(), p.executable(), log);
			markVolatileIfIo(block, kind);

			if (sub.has("type") && gdtMgr != null) {
				applyStructType(program, baseSpace, gdtMgr, sub, source, log);
			}
		}
	}

	// ------------------------------------------------------------------
	// Data types
	// ------------------------------------------------------------------

	static void applyStructType(Program program, AddressSpace baseSpace,
			FileDataTypeManager gdtMgr, JsonObject withTypeAndStart, String source,
			MessageLog log) {

		String typeName = withTypeAndStart.get("type").getAsString();
		long start = withTypeAndStart.get("start").getAsLong();

		DataType archiveType = gdtMgr.getDataType(CategoryPath.ROOT, typeName);
		if (archiveType == null) {
			log.appendMsg("Data type '" + typeName + "' not found in " + source + " archive; skipping");
			return;
		}

		DataTypeManager programDtm = program.getDataTypeManager();
		DataType resolved = programDtm.resolve(archiveType, DataTypeConflictHandler.DEFAULT_HANDLER);

		Address addr = baseSpace.getAddress(start);
		try {
			DataUtilities.createData(program, addr, resolved, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (Exception e) {
			log.appendMsg(
				"Failed to apply data type '" + typeName + "' at 0x" + Long.toHexString(start) +
					": " + e.getMessage());
		}
	}

	// ------------------------------------------------------------------
	// Symbols
	// ------------------------------------------------------------------

	/**
	 * Applies one {@code symbols[]} set: labels every entry, EOL-comments the ones that
	 * carry comments, and hands {@code kind: entry} addresses to {@code functionMarker}
	 * (the loader's {@code markAsFunction}, which is protected and cannot be called from
	 * here) after registering them as external entry points.
	 */
	static void applySymbolSet(Program program, AddressSpace baseSpace, JsonObject set,
			BiConsumer<String, Address> functionMarker, MessageLog log) {

		JsonArray entries = set.getAsJsonArray("entries");
		for (JsonElement ee : entries) {
			JsonObject entry = ee.getAsJsonObject();
			long addr = entry.get("addr").getAsLong();
			String name = entry.get("name").getAsString();
			String kind = entry.has("kind") ? entry.get("kind").getAsString() : "entry";
			String comment = entry.has("comment") ? entry.get("comment").getAsString() : null;

			Address symAddr = baseSpace.getAddress(addr);
			try {
				program.getSymbolTable().createLabel(symAddr, name, SourceType.IMPORTED);
				if (kind.equals("entry")) {
					program.getSymbolTable().addExternalEntryPoint(symAddr);
					functionMarker.accept(name, symAddr);
				}
				if (comment != null) {
					program.getListing().setComment(symAddr, CommentType.EOL, comment);
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to create symbol '" + name + "' at 0x" +
					Long.toHexString(addr) + ": " + e.getMessage());
			}
		}
	}

	// ------------------------------------------------------------------
	// Computed-window expressions (constant subset)
	// ------------------------------------------------------------------

	/**
	 * Evaluates a computed-window {@code maps:} expression whose value does not depend
	 * on bank state — integer literals (decimal or 0x hex), {@code last} /
	 * {@code second_last} (byte offsets of the last / second-to-last window-sized bank
	 * in the image), {@code + - * >>} with normal precedence, and parentheses. This
	 * covers every fixed window (NROM's whole map, the fixed banks of UxROM/MMC3).
	 * State-field identifiers throw {@link IllegalArgumentException} — resolving those
	 * is the bank engine's job (M2+), not the loader's.
	 * <p>
	 * {@code >>} (bead {@code grm-hsv.2}, added for MMC1's 32K PRG mode, which ignores
	 * {@code prg_bank}'s LSB: {@code PRG[(prg_bank >> 1) * 0x8000]}) is a logical
	 * right-shift on the running {@code long} accumulator, binding at the SAME
	 * precedence as {@code *} (left-associative, mirroring how {@code *} is folded into
	 * {@link ExprParser#parseProduct}) — deliberately NOT C's looser-than-{@code +-}
	 * shift precedence, since this grammar has no use case that needs the distinction
	 * and a single, easy-to-state rule ("*, >> chain left-to-right, both bind tighter
	 * than + -") is less surprising here than importing C's historical quirk.
	 * Parenthesize when mixing {@code >>} with {@code *} if a specific grouping is
	 * required. Divide ({@code /}) was considered and rejected: MMC1's actual hardware
	 * operation is a bit shift, and {@code >>} makes that literal rather than relying on
	 * integer-division truncation to coincidentally match.
	 *
	 * @param expr       the expression text from the map's {@code maps.expr}
	 * @param imageSize  size in bytes of the physical space's image
	 * @param windowSize size in bytes of the window being mapped
	 * @return byte offset into the physical space
	 */
	static long evalConstantExpr(String expr, long imageSize, long windowSize) {
		return evalExpr(expr, imageSize, windowSize, Map.of());
	}

	/**
	 * Evaluates a computed-window {@code maps:} expression with concrete values bound
	 * to the bank-state fields it references — the bank-dependent complement of
	 * {@link #evalConstantExpr}, used to place switchable windows (one evaluation per
	 * candidate bank value) and to resolve a reference's effective target bank.
	 * Identifiers not in {@code env} (and not {@code last}/{@code second_last}) throw
	 * {@link IllegalArgumentException}.
	 */
	static long evalExpr(String expr, long imageSize, long windowSize, Map<String, Long> env) {
		ExprParser p = new ExprParser(expr, imageSize, windowSize, env);
		long v = p.parseSum();
		p.expectEnd();
		return v;
	}

	/**
	 * The state-field identifiers a {@code maps:} expression references (everything that
	 * is not a number or the {@code last}/{@code second_last} keywords). The MapCompiler
	 * already validated each against the descriptor's {@code banking.state} tuple.
	 */
	static Set<String> referencedFields(String expr) {
		Set<String> fields = new LinkedHashSet<>();
		Matcher m = IDENT.matcher(expr);
		while (m.find()) {
			String ident = m.group();
			if (!ident.equals("last") && !ident.equals("second_last")) {
				fields.add(ident);
			}
		}
		return fields;
	}

	// lookbehind keeps the 'x4000' inside a hex literal from matching as an identifier
	private static final Pattern IDENT = Pattern.compile("(?<!\\w)[A-Za-z_]\\w*");

	/** Minimal recursive-descent parser for {@code maps:} expressions. */
	private static final class ExprParser {
		private final String expr;
		private final long imageSize;
		private final long windowSize;
		private final Map<String, Long> env;
		private int pos;

		ExprParser(String expr, long imageSize, long windowSize, Map<String, Long> env) {
			this.expr = expr;
			this.imageSize = imageSize;
			this.windowSize = windowSize;
			this.env = env;
		}

		long parseSum() {
			long v = parseProduct();
			while (true) {
				skipSpace();
				if (eat('+')) {
					v += parseProduct();
				}
				else if (eat('-')) {
					v -= parseProduct();
				}
				else {
					return v;
				}
			}
		}

		long parseProduct() {
			long v = parseFactor();
			while (true) {
				skipSpace();
				if (eat('*')) {
					v *= parseFactor();
				}
				else if (eatShr()) {
					v >>>= parseFactor();
				}
				else {
					return v;
				}
			}
		}

		/** Matches the two-character {@code >>} operator (not a bare {@code >}, which
		 *  this grammar has no other use for and so leaves unrecognized). */
		private boolean eatShr() {
			if (pos + 1 < expr.length() && expr.charAt(pos) == '>' && expr.charAt(pos + 1) == '>') {
				pos += 2;
				return true;
			}
			return false;
		}

		long parseFactor() {
			skipSpace();
			if (eat('(')) {
				long v = parseSum();
				skipSpace();
				if (!eat(')')) {
					throw new IllegalArgumentException("unbalanced parentheses in '" + expr + "'");
				}
				return v;
			}
			if (pos < expr.length() && Character.isDigit(expr.charAt(pos))) {
				return parseNumber();
			}
			String ident = parseIdent();
			switch (ident) {
				case "last":
					return imageSize - windowSize;
				case "second_last":
					return imageSize - 2 * windowSize;
				default:
					Long bound = env.get(ident);
					if (bound != null) {
						return bound;
					}
					throw new IllegalArgumentException("expression '" + expr +
						"' depends on bank state ('" + ident +
						"'); only constant windows can be placed at load time");
			}
		}

		private long parseNumber() {
			int start = pos;
			if (expr.startsWith("0x", pos) || expr.startsWith("0X", pos)) {
				pos += 2;
				while (pos < expr.length() && isHexDigit(expr.charAt(pos))) {
					pos++;
				}
				return Long.parseLong(expr.substring(start + 2, pos), 16);
			}
			while (pos < expr.length() && Character.isDigit(expr.charAt(pos))) {
				pos++;
			}
			return Long.parseLong(expr.substring(start, pos));
		}

		private String parseIdent() {
			int start = pos;
			while (pos < expr.length() &&
				(Character.isLetterOrDigit(expr.charAt(pos)) || expr.charAt(pos) == '_')) {
				pos++;
			}
			if (pos == start) {
				throw new IllegalArgumentException(
					"malformed expression '" + expr + "' at offset " + pos);
			}
			return expr.substring(start, pos);
		}

		private static boolean isHexDigit(char c) {
			return Character.digit(c, 16) >= 0;
		}

		private void skipSpace() {
			while (pos < expr.length() && Character.isWhitespace(expr.charAt(pos))) {
				pos++;
			}
		}

		private boolean eat(char c) {
			if (pos < expr.length() && expr.charAt(pos) == c) {
				pos++;
				return true;
			}
			return false;
		}

		void expectEnd() {
			skipSpace();
			if (pos != expr.length()) {
				throw new IllegalArgumentException(
					"trailing garbage in expression '" + expr + "' at offset " + pos);
			}
		}
	}

	// ------------------------------------------------------------------
	// Bank-state field parsing (banking.state / initial_state)
	// ------------------------------------------------------------------

	/**
	 * One {@code banking.state} field: its name, LSB position, and bit width within the
	 * packed state int. Fields pack LSB-first in declaration order (mirrors
	 * {@code MapCompiler.packState} at build time and {@code BoardBankAnalyzer.FieldSpec}
	 * at analysis time -- all three must agree on this layout).
	 */
	record StateField(String name, int lsb, int width) {

		long mask() {
			return (1L << width) - 1;
		}

		/** This field's value as packed into {@code packedState}. */
		long valueIn(long packedState) {
			return (packedState >> lsb) & mask();
		}
	}

	/**
	 * Parses {@code banking.state} into its ordered field tuple, LSB-first. Returns an
	 * empty list when the descriptor has no {@code banking} section (or no {@code state}).
	 */
	static List<StateField> parseStateFields(JsonObject map) {
		List<StateField> fields = new ArrayList<>();
		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("state")) {
			return fields;
		}
		int lsb = 0;
		for (JsonElement fe : banking.getAsJsonArray("state")) {
			JsonObject f = fe.getAsJsonObject();
			String name = f.get("name").getAsString();
			int bits = f.get("bits").getAsInt();
			fields.add(new StateField(name, lsb, bits));
			lsb += bits;
		}
		return fields;
	}

	/**
	 * {@code banking.initial_state}, the packed power-on state -- null when the descriptor
	 * has no {@code banking} section or omits {@code initial_state}.
	 */
	static Long initialState(JsonObject map) {
		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("initial_state")) {
			return null;
		}
		return banking.get("initial_state").getAsLong();
	}

	/** Finds a field by name in a {@link #parseStateFields} result, or null. */
	static StateField findField(List<StateField> fields, String name) {
		for (StateField f : fields) {
			if (f.name().equals(name)) {
				return f;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Window-plan normalization (memory.windows[] + memory.layouts[])
	// ------------------------------------------------------------------

	/**
	 * One window instance in the normalized flat plan produced by {@link #planWindows}.
	 * {@code expr} is null for an enumerated-{@code occupants:} window (C64-style; not
	 * supported by the computed-window loaders -- callers should skip it and log).
	 * {@code modeValue} is null for a mode-invariant window (a top-level
	 * {@code memory.windows[]} entry, or a layout window hoisted because every layout
	 * defines it identically); otherwise it is this instance's {@code when:} value of
	 * {@link LayoutPlan#modeField()}.
	 */
	record PlannedWindow(String name, long start, long end, String expr, String onWrite,
			Integer modeValue) {

		long length() {
			return end - start + 1;
		}
	}

	/**
	 * The normalized result of {@link #planWindows}: {@code invariant} windows are placed
	 * once, unconditionally; {@code varying} windows are one instance per
	 * {@code (name, modeValue)} pair (callers group by name to realize a window's full set
	 * of per-mode instances together, the way {@link #placeHomeInBaseWindow} expects one
	 * candidate list per window). {@code modeField} is the single banking.state field every
	 * layout's {@code when:} keys off of, or null when the descriptor has no
	 * {@code memory.layouts} (or they were ignored -- see {@link #planWindows}), in which
	 * case {@code varying} is always empty.
	 */
	record LayoutPlan(String modeField, List<PlannedWindow> invariant, List<PlannedWindow> varying) {}

	/**
	 * Normalizes a descriptor's window set -- {@code memory.windows[]} (always
	 * mode-invariant) plus {@code memory.layouts[]} (mode-dependent window sets), when
	 * present -- into a flat plan both loaders and (a later bead) the bank analyzer can
	 * consume without re-walking the JSON.
	 *
	 * <p>Runtime constraint, conservative by design (logs and ignores {@code layouts}
	 * entirely rather than guessing): every layout's {@code when:} must name exactly one
	 * field, and it must be the <em>same</em> field across every layout (the "mode field").
	 * Duplicate {@code when:} values across layouts are likewise rejected. Both MMC1 and
	 * MMC3 satisfy this.
	 *
	 * <p>Invariant hoisting: a window name that appears in <em>every</em> layout with an
	 * identical compiled definition (same start/end/maps/on_write -- compared as JSON) is
	 * mode-invariant and is folded into {@link LayoutPlan#invariant()} exactly like a
	 * top-level window (e.g. MMC3's WA000/WE000, which are unchanged across both
	 * {@code prg_mode} layouts). Every other layout window is mode-varying and lands in
	 * {@link LayoutPlan#varying()}.
	 */
	static LayoutPlan planWindows(JsonObject map, MessageLog log, String source) {
		List<PlannedWindow> invariant = new ArrayList<>();
		List<PlannedWindow> varying = new ArrayList<>();

		JsonArray topWindows = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
		for (JsonElement we : topWindows) {
			invariant.add(toPlannedWindow(we.getAsJsonObject(), null));
		}

		if (!map.has("layouts")) {
			return new LayoutPlan(null, invariant, varying);
		}

		String modeField = null;
		List<JsonObject> layoutObjs = new ArrayList<>();
		Set<Integer> seenValues = new LinkedHashSet<>();
		for (JsonElement le : map.getAsJsonArray("layouts")) {
			JsonObject layout = le.getAsJsonObject();
			JsonObject when = layout.getAsJsonObject("when");
			if (when == null || when.entrySet().size() != 1) {
				log.appendMsg(source, "memory.layouts[].when must name exactly one field; " +
					"ignoring memory.layouts[] entirely");
				return new LayoutPlan(null, invariant, varying);
			}
			Map.Entry<String, JsonElement> cond = when.entrySet().iterator().next();
			if (modeField == null) {
				modeField = cond.getKey();
			}
			else if (!modeField.equals(cond.getKey())) {
				log.appendMsg(source, "memory.layouts[] mix mode fields ('" + modeField +
					"' vs '" + cond.getKey() + "'); ignoring memory.layouts[] entirely");
				return new LayoutPlan(null, invariant, varying);
			}
			if (!seenValues.add(cond.getValue().getAsInt())) {
				log.appendMsg(source, "memory.layouts[] has a duplicate when: " + modeField +
					"=" + cond.getValue().getAsInt() + "; ignoring memory.layouts[] entirely");
				return new LayoutPlan(null, invariant, varying);
			}
			layoutObjs.add(layout);
		}

		Map<String, List<JsonObject>> byName = new LinkedHashMap<>();
		for (JsonObject layout : layoutObjs) {
			for (JsonElement lwe : layout.getAsJsonArray("windows")) {
				JsonObject w = lwe.getAsJsonObject();
				byName.computeIfAbsent(w.get("name").getAsString(), k -> new ArrayList<>()).add(w);
			}
		}
		for (Map.Entry<String, List<JsonObject>> entry : byName.entrySet()) {
			List<JsonObject> defs = entry.getValue();
			if (defs.size() == layoutObjs.size() && allIdentical(defs)) {
				invariant.add(toPlannedWindow(defs.get(0), null));
				continue;
			}
			for (JsonObject layout : layoutObjs) {
				int modeValue = layout.getAsJsonObject("when").get(modeField).getAsInt();
				for (JsonElement lwe : layout.getAsJsonArray("windows")) {
					JsonObject w = lwe.getAsJsonObject();
					if (w.get("name").getAsString().equals(entry.getKey())) {
						varying.add(toPlannedWindow(w, modeValue));
					}
				}
			}
		}
		return new LayoutPlan(modeField, invariant, varying);
	}

	private static boolean allIdentical(List<JsonObject> defs) {
		JsonObject first = defs.get(0);
		for (int i = 1; i < defs.size(); i++) {
			if (!first.equals(defs.get(i))) {
				return false;
			}
		}
		return true;
	}

	private static PlannedWindow toPlannedWindow(JsonObject w, Integer modeValue) {
		String name = w.get("name").getAsString();
		long start = w.get("start").getAsLong();
		long end = w.has("end") ? w.get("end").getAsLong()
				: start + w.get("size").getAsLong() - 1;
		String expr = w.has("maps") ? w.getAsJsonObject("maps").get("expr").getAsString() : null;
		String onWrite = w.has("on_write") ? w.get("on_write").getAsString() : null;
		return new PlannedWindow(name, start, end, expr, onWrite, modeValue);
	}

	// ------------------------------------------------------------------
	// Home-in-base window placement
	// ------------------------------------------------------------------

	/**
	 * One way to materialize a named candidate occupying a computed window: given
	 * whether it is the home candidate, creates whatever block(s) (if any) it needs
	 * and returns the representative {@link MemoryBlock}, or {@code null} if it
	 * created none (legal -- e.g. an io-kind occupant that only carves subregions,
	 * or a candidate skipped for a loader-specific reason).
	 */
	@FunctionalInterface
	interface WindowCandidate {
		MemoryBlock place(Program program, AddressSpace baseSpace, boolean isHome, MessageLog log);
	}

	/** A named candidate occupant/bank of a computed window, paired with how to place it. */
	record NamedCandidate(String name, WindowCandidate candidate) {}

	/**
	 * Shared "home-in-base" window placement policy used by both banked loaders: of
	 * {@code candidates} occupying one computed window, the one named
	 * {@code homeName} is placed non-overlay (it lives directly in {@code baseSpace},
	 * so references resolve there by default); every other candidate is placed as an
	 * overlay. If no candidate's name equals {@code homeName} (e.g. the home bank
	 * fell out of the image's range), nothing is treated as home -- callers may log
	 * that themselves before calling, since the exact message differs by loader.
	 *
	 * <p>Loader-specific concerns -- which candidates exist, their content, and any
	 * bookkeeping the caller needs about the home candidate (e.g. NES's
	 * {@code PlacedWindow} list) -- stay in the loaders' {@link WindowCandidate}
	 * closures and surrounding code; this helper only owns the placement decision.
	 */
	static void placeHomeInBaseWindow(Program program, AddressSpace baseSpace,
			List<NamedCandidate> candidates, String homeName, MessageLog log) {
		for (NamedCandidate c : candidates) {
			boolean isHome = c.name().equals(homeName);
			c.candidate().place(program, baseSpace, isHome, log);
		}
	}

	// ------------------------------------------------------------------
	// Non-home-bank overlay naming
	// ------------------------------------------------------------------

	/**
	 * Naming convention for a computed window's non-home overlay blocks:
	 * {@code <windowName>_B<bankValue>} for a mode-invariant switchable window (the
	 * original, single-mode form), extended by mode-dependent-layout support (bead
	 * grm-aqf) with two mode-qualified forms: {@code <windowName>_M<modeValue>} for a
	 * mode-varying <em>fixed</em> window's non-home layout instance, and
	 * {@code <windowName>_M<modeValue>_B<bankValue>} for a mode-varying
	 * <em>switchable</em> window's non-home (layout, bank) instance. Used both when a
	 * loader creates an instance's overlay block at load time and when an analyzer later
	 * needs to resolve a bank/mode value back out of an overlay {@link AddressSpace}'s
	 * name.
	 *
	 * <p>The block name also becomes the overlay {@link AddressSpace}'s name --
	 * {@code MemoryBlockUtils} names the overlay space after the block when
	 * {@code isOverlay=true} -- empirically confirmed unmangled (tools/banktest
	 * checkNesBanktest N3, bead grm-5tl.17): {@code AddressSpace.getName()} equals
	 * this exact string, so callers like {@link BoardBankAnalyzer}'s
	 * {@code addOverlayRef()} can look the space up by {@code "<window>_B<bank>"}
	 * with no separate name-mapping table.
	 *
	 * <p><b>Naming-contract caveat:</b> the three suffix forms ({@code _B<n>},
	 * {@code _M<n>}, {@code _M<n>_B<n>}) are told apart purely by string shape (digits
	 * after {@code _B} / {@code _M}, an optional {@code _B} segment after the mode
	 * digits). A window name that itself ends in something shaped like {@code _M3} or
	 * {@code _B2} would be ambiguous with these suffixes and must be avoided by
	 * descriptor authors; none of the shipped or sketch descriptors do this.
	 */
	static final class OverlayNaming {
		private OverlayNaming() {
		}

		/** Builds the {@code <windowName>_B<bankValue>} name for a non-home bank overlay
		 *  of a mode-invariant switchable window. */
		static String bankBlockName(String windowName, int bankValue) {
			return windowName + "_B" + bankValue;
		}

		/**
		 * Parses a bank value back out of an overlay space name, given the owning
		 * window's name. Returns {@code null} if {@code spaceName} does not start
		 * with {@code "<windowName>_B"} or the remainder is not all decimal digits
		 * (e.g. a differently-named overlay space, such as a C64 occupant overlay, or
		 * one of the {@code _M...} mode-qualified forms below).
		 */
		static Integer parseBankValue(String windowName, String spaceName) {
			String prefix = windowName + "_B";
			if (!spaceName.startsWith(prefix)) {
				return null;
			}
			return parseDigits(spaceName.substring(prefix.length()));
		}

		/** Builds the {@code <windowName>_M<modeValue>} name for a mode-varying
		 *  <em>fixed</em> window's non-home layout instance. */
		static String modeBlockName(String windowName, int modeValue) {
			return windowName + "_M" + modeValue;
		}

		/**
		 * Parses a mode value back out of an overlay space name for a mode-varying
		 * fixed window, given the owning window's name. Returns {@code null} if
		 * {@code spaceName} does not start with {@code "<windowName>_M"} or the
		 * remainder is not all decimal digits -- in particular, a
		 * {@code "<windowName>_M<m>_B<v>"} space (see {@link #modeBankBlockName})
		 * fails to parse here because its remainder contains {@code "_B"}.
		 */
		static Integer parseModeValue(String windowName, String spaceName) {
			String prefix = windowName + "_M";
			if (!spaceName.startsWith(prefix)) {
				return null;
			}
			return parseDigits(spaceName.substring(prefix.length()));
		}

		/** A parsed {@code <windowName>_M<mode>_B<bank>} overlay name's (mode, bank)
		 *  pair; see {@link #modeBankBlockName} / {@link #parseModeBankValue}. */
		record ModeBank(int mode, int bank) {}

		/** Builds the {@code <windowName>_M<modeValue>_B<bankValue>} name for a
		 *  mode-varying <em>switchable</em> window's non-home (layout, bank) instance. */
		static String modeBankBlockName(String windowName, int modeValue, int bankValue) {
			return windowName + "_M" + modeValue + "_B" + bankValue;
		}

		/**
		 * Parses the (mode, bank) pair back out of a {@code "<windowName>_M<m>_B<v>"}
		 * overlay space name, given the owning window's name. Returns {@code null} if
		 * {@code spaceName} does not have exactly that shape (both {@code <m>} and
		 * {@code <v>} all decimal digits).
		 */
		static ModeBank parseModeBankValue(String windowName, String spaceName) {
			String prefix = windowName + "_M";
			if (!spaceName.startsWith(prefix)) {
				return null;
			}
			String rest = spaceName.substring(prefix.length());
			int bIdx = rest.indexOf("_B");
			if (bIdx < 0) {
				return null;
			}
			Integer mode = parseDigits(rest.substring(0, bIdx));
			Integer bank = parseDigits(rest.substring(bIdx + 2));
			if (mode == null || bank == null) {
				return null;
			}
			return new ModeBank(mode, bank);
		}

		/** Strict decimal parse: non-empty, decimal digits only (no sign, no
		 *  whitespace -- stricter than {@code Integer.parseInt}), else null. */
		private static Integer parseDigits(String s) {
			if (s.isEmpty()) {
				return null;
			}
			int v = 0;
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				if (c < '0' || c > '9') {
					return null;
				}
				v = v * 10 + (c - '0');
			}
			return v;
		}
	}
}
