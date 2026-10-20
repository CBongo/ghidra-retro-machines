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

import java.util.function.BiConsumer;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.util.importer.MessageLog;
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
 * Applies descriptor content to a {@link Program}: struct types from the companion type archive,
 * {@code symbols[]} sets and {@code comments[]} sets. Split out of the former
 * {@code DescriptorSupport} (bead grm-rx1i.12).
 */
final class DescriptorApply {

	private DescriptorApply() {
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
		applySymbolSet(program, baseSpace, set, functionMarker, log, true);
	}

	/**
	 * As above; {@code recordComments} says whether the EOL comments written are recorded in
	 * {@link AnalyzerCommentRecord} (bead grm-hb6.18). True for MACHINE descriptor sets -- loader
	 * output that must never be exported into a game descriptor -- and false for GAME descriptor
	 * sets, whose comments came from a human-curated descriptor, so re-exporting them is a correct
	 * round trip.
	 */
	static void applySymbolSet(Program program, AddressSpace baseSpace, JsonObject set,
			BiConsumer<String, Address> functionMarker, MessageLog log, boolean recordComments) {

		JsonArray entries = set.getAsJsonArray("entries");
		for (JsonElement ee : entries) {
			JsonObject entry = ee.getAsJsonObject();
			long addr = entry.get("addr").getAsLong();
			String name = entry.get("name").getAsString();
			String kind = entry.has("kind") ? entry.get("kind").getAsString() : "entry";
			String comment = entry.has("comment") ? entry.get("comment").getAsString() : null;

			// Optional bank qualifier (per-game tier, design section 3b.3): an entry-level
			// `block:` overrides the set-level one; neither means the base space. An
			// unresolvable block ignores that one entry and logs (section 3.1).
			String block = entry.has("block") ? entry.get("block").getAsString()
					: set.has("block") ? set.get("block").getAsString() : null;
			Address symAddr = block == null ? baseSpace.getAddress(addr)
					: blockAddress(program, block, addr);
			if (symAddr == null) {
				log.appendMsg("Symbol '" + name + "' at 0x" + Long.toHexString(addr) +
					" names block '" + block + "', which has no such address in this program; " +
					"ignored");
				continue;
			}
			try {
				AnnotationGuard.applyLabel(program, symAddr, name, SourceType.IMPORTED);
				if (kind.equals("entry")) {
					program.getSymbolTable().addExternalEntryPoint(symAddr);
					functionMarker.accept(name, symAddr);
				}
				if (comment != null) {
					// AnnotationGuard.addComment (grm-mej.4): descriptor-applied comments must
					// never clobber a USER_DEFINED one. Comments carry no SourceType, so the
					// guard uses the append-only proxy documented on that method; the comment
					// text itself is the idempotence marker, since (unlike the analyzer's
					// "bank ->" annotations) there is no shared prefix across descriptor
					// comments to key on.
					if (recordComments) {
						AnalyzerCommentRecord.append(program, symAddr, CommentType.EOL, comment,
							comment);
					}
					else {
						AnnotationGuard.addComment(program.getListing(), symAddr, CommentType.EOL,
							comment, comment);
					}
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to create symbol '" + name + "' at 0x" +
					Long.toHexString(addr) + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Applies one {@code comments[]} set of a game descriptor (bead grm-hb6.18): each entry's
	 * {@code eol/pre/plate/post/repeatable} text goes in through {@link AnnotationGuard#addComment}
	 * with the text itself as the idempotence marker -- append-only, so a user's comment is never
	 * clobbered and a second application writes nothing. Deliberately NOT recorded in
	 * {@link AnalyzerCommentRecord}: these came from a descriptor, and re-exporting them is a
	 * correct round trip. An unresolvable block/address logs once and ignores that entry
	 * (design section 3.1). Returns how many comments were written.
	 */
	static int applyCommentSet(Program program, AddressSpace baseSpace, JsonObject set,
			MessageLog log) {
		int written = 0;
		for (JsonElement ee : set.getAsJsonArray("entries")) {
			JsonObject entry = ee.getAsJsonObject();
			long addr = entry.get("addr").getAsLong();
			String block = entry.has("block") ? entry.get("block").getAsString()
					: set.has("block") ? set.get("block").getAsString() : null;
			Address at;
			try {
				at = block == null ? baseSpace.getAddress(addr) : blockAddress(program, block, addr);
			}
			catch (RuntimeException e) {
				at = null;
			}
			if (at == null || !program.getMemory().contains(at)) {
				log.appendMsg("Comment at 0x" + Long.toHexString(addr) +
					(block == null ? "" : " in block '" + block + "'") +
					" has no such address in this program; ignored");
				continue;
			}
			for (CommentType type : CommentType.values()) {
				String key = type.name().toLowerCase();
				if (entry.has(key)) {
					String text = entry.get(key).getAsString();
					if (AnnotationGuard.addComment(program.getListing(), at, type, text, text)) {
						written++;
					}
				}
			}
		}
		return written;
	}

	/** {@code offset} in the address space of memory block {@code blockName}, or null. */
	static Address blockAddress(Program program, String blockName, long offset) {
		MemoryBlock block = program.getMemory().getBlock(blockName);
		if (block == null) {
			return null;
		}
		try {
			Address a = block.getStart().getAddressSpace().getAddress(offset);
			return block.contains(a) ? a : null;
		}
		catch (RuntimeException e) {
			return null;
		}
	}
}
