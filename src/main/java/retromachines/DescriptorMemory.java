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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.InvalidAddressException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.AssertException;

/**
 * Memory-realization helpers split out of {@link DescriptorSupport} (QR-12 increment 5):
 * block permissions by descriptor kind, always-visible regions, and IO subregion carve-up.
 * {@code applyStructType} (Data types) stays on {@link DescriptorSupport}, so
 * {@link #createRegionBlock} and {@link #createIoSubregions} call back into it.
 */
final class DescriptorMemory {

	private DescriptorMemory() {
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
			DescriptorSupport.applyStructType(program, baseSpace, gdtMgr, region, source, log);
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
				DescriptorSupport.applyStructType(program, baseSpace, gdtMgr, sub, source, log);
			}
		}
	}
}
