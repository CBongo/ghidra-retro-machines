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
import java.util.function.BiConsumer;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

/**
 * The system-neutral half of the descriptor-driven loader stack: everything a loader
 * does with a compiled machine descriptor (`machines/&lt;id&gt;.map` JSON + companion
 * `.gdt` type archive) that is not specific to any one system. Extracted from
 * {@link C64PrgLoader} so the NES loader (and later systems) consume descriptors
 * through the same code paths — none of these helpers knows any hardware fact; they
 * only interpret the descriptor schema (docs/MAP_FORMAT.md).
 */
final class DescriptorSupport {

	private DescriptorSupport() {
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
			else {
				end = sub.get("end").getAsLong();
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
	 * in the image), {@code + - *} with normal precedence, and parentheses. This covers
	 * every fixed window (NROM's whole map, the fixed banks of UxROM/MMC3). State-field
	 * identifiers throw {@link IllegalArgumentException} — resolving those is the bank
	 * engine's job (M2+), not the loader's.
	 *
	 * @param expr       the expression text from the map's {@code maps.expr}
	 * @param imageSize  size in bytes of the physical space's image
	 * @param windowSize size in bytes of the window being mapped
	 * @return byte offset into the physical space
	 */
	static long evalConstantExpr(String expr, long imageSize, long windowSize) {
		ExprParser p = new ExprParser(expr, imageSize, windowSize);
		long v = p.parseSum();
		p.expectEnd();
		return v;
	}

	/** Minimal recursive-descent parser for the constant expression subset. */
	private static final class ExprParser {
		private final String expr;
		private final long imageSize;
		private final long windowSize;
		private int pos;

		ExprParser(String expr, long imageSize, long windowSize) {
			this.expr = expr;
			this.imageSize = imageSize;
			this.windowSize = windowSize;
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
				else {
					return v;
				}
			}
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
}
