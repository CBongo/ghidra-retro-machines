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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

/**
 * Loader for Commodore 64 {@code .prg} files.
 * <p>
 * Reads the 2-byte little-endian load address header, places the program bytes at that
 * address, and builds the full C64 memory map (always-visible regions, banked windows, IO
 * chip register structs, and KERNAL API symbols) entirely from the bundled
 * {@code machines/c64.map} JSON descriptor and {@code machines/c64.gdt} archive of
 * data types. None of the C64 hardware layout is hardcoded in this class beyond the bits
 * needed to interpret the descriptor's schema.
 */
public class C64PrgLoader extends AbstractProgramWrapperLoader {

	private static final String LANGUAGE_ID = "6502:LE:16:default";
	private static final String COMPILER_SPEC_ID = "default";
	private static final String MAP_PATH = "machines/c64.map";
	private static final String GDT_PATH = "machines/c64.gdt";

	@Override
	public String getName() {
		return "Commodore 64 PRG";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		String name = provider.getName();
		if (name == null || !name.toLowerCase().endsWith(".prg")) {
			return loadSpecs;
		}
		if (provider.length() < 2) {
			return loadSpecs;
		}

		LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_SPEC_ID);
		loadSpecs.add(new LoadSpec(this, 0, pair, true));
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();

		// --- Load the descriptor JSON ---
		JsonObject map;
		try {
			map = loadMap();
		}
		catch (IOException e) {
			log.appendMsg("Failed to load machines/c64.map: " + e.getMessage());
			return;
		}

		// --- Open the bundled IO-chip register struct archive ---
		FileDataTypeManager gdtMgr = null;
		try {
			gdtMgr = openGdt();
		}
		catch (IOException e) {
			log.appendMsg("Failed to open machines/c64.gdt: " + e.getMessage());
		}

		try {
			AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

			// --- Read the 2-byte LE load address header ---
			int loadAddrLow = provider.readByte(0) & 0xFF;
			int loadAddrHigh = provider.readByte(1) & 0xFF;
			long loadAddr = (loadAddrHigh << 8) | loadAddrLow;
			long prgLength = provider.length() - 2;

			// --- Always-visible regions ---
			JsonArray regions = map.getAsJsonArray("regions");
			Map<String, JsonObject> regionsByName = new HashMap<>();
			for (JsonElement re : regions) {
				JsonObject region = re.getAsJsonObject();
				regionsByName.put(region.get("name").getAsString(), region);
			}

			for (JsonObject region : regionsByName.values()) {
				createRegionBlock(program, baseSpace, region, loadAddr, prgLength, log);
			}

			// --- PRG image block ---
			createPrgBlock(program, baseSpace, provider, loadAddr, prgLength, log);

			// --- Banked windows: home occupant in base space, alternates in overlay spaces ---
			JsonObject banking = map.getAsJsonObject("banking");
			int initialState = banking.get("initial_state").getAsInt();
			JsonObject homeState = null;
			for (JsonElement se : banking.getAsJsonArray("states")) {
				JsonObject state = se.getAsJsonObject();
				if (state.get("value").getAsInt() == initialState) {
					homeState = state;
					break;
				}
			}
			if (homeState == null) {
				log.appendMsg("banking.initial_state " + initialState +
					" not found in banking.states; skipping window setup");
			}

			JsonArray windows = map.getAsJsonArray("windows");
			for (JsonElement we : windows) {
				JsonObject window = we.getAsJsonObject();
				String windowName = window.get("name").getAsString();
				String homeOccupantName = homeState != null && homeState.has(windowName)
						? homeState.get(windowName).getAsString()
						: null;

				JsonArray occupants = window.getAsJsonArray("occupants");
				for (JsonElement oe : occupants) {
					JsonObject occupant = oe.getAsJsonObject();
					String occupantName = occupant.get("name").getAsString();
					boolean isHome = occupantName.equals(homeOccupantName);
					createWindowOccupant(program, baseSpace, occupant, window, isHome, gdtMgr, log);
				}
			}

			// --- P6510 struct at address 0 ---
			if (gdtMgr != null && regionsByName.containsKey("P6510")) {
				JsonObject p6510 = regionsByName.get("P6510");
				applyStructType(program, baseSpace, gdtMgr, p6510, log);
			}

			// --- KERNAL API symbols ---
			JsonArray symbolSets = map.getAsJsonArray("symbols");
			for (JsonElement se : symbolSets) {
				JsonObject set = se.getAsJsonObject();
				boolean isDefault = set.has("default") && set.get("default").getAsBoolean();
				if (!isDefault) {
					continue;
				}
				applySymbolSet(program, baseSpace, set, log);
			}

			// --- Program entry point ---
			try {
				Address entryAddr = baseSpace.getAddress(loadAddr);
				program.getSymbolTable().addExternalEntryPoint(entryAddr);
				program.getSymbolTable().createLabel(entryAddr, "entry", SourceType.IMPORTED);
				markAsFunction(program, "entry", entryAddr);
			}
			catch (Exception e) {
				log.appendMsg("Failed to set entry point: " + e.getMessage());
			}
		}
		finally {
			if (gdtMgr != null) {
				gdtMgr.close();
			}
		}
	}

	// ------------------------------------------------------------------
	// Descriptor / archive loading
	// ------------------------------------------------------------------

	private static JsonObject loadMap() throws IOException {
		ResourceFile mapFile = Application.findDataFileInAnyModule(MAP_PATH);
		if (mapFile == null) {
			throw new IOException("Could not find bundled data file " + MAP_PATH);
		}
		try (InputStreamReader reader =
				new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	private static FileDataTypeManager openGdt() throws IOException {
		ResourceFile gdtFile = Application.findDataFileInAnyModule(GDT_PATH);
		if (gdtFile == null) {
			throw new IOException("Could not find bundled data file " + GDT_PATH);
		}
		return FileDataTypeManager.openFileArchive(gdtFile, false);
	}

	// ------------------------------------------------------------------
	// Block permissions by descriptor kind
	// ------------------------------------------------------------------
	// Centralized so every block-creation site agrees. RAM: read/write/execute (C64 code
	// routinely runs from RAM). ROM: read/execute, not writable (write-through to the RAM
	// beneath, per the map's on_write, is deferred to gib.2). IO: read/write, not
	// executable. Read is always permitted.

	private static boolean canWrite(String kind) {
		return !kind.equals("rom");
	}

	private static boolean canExecute(String kind) {
		return !kind.equals("io");
	}

	// ------------------------------------------------------------------
	// Always-visible regions
	// ------------------------------------------------------------------

	private void createRegionBlock(Program program, AddressSpace baseSpace, JsonObject region,
			long loadAddr, long prgLength, MessageLog log) {

		String name = region.get("name").getAsString();
		long start = region.get("start").getAsLong();
		long end = region.get("end").getAsLong();
		String kind = region.get("kind").getAsString();
		String comment = region.has("comment") ? region.get("comment").getAsString() : null;

		// RAM_MAIN is carved around the PRG image; handled separately in createRamMainSplit().
		if (name.equals("RAM_MAIN")) {
			createRamMainSplit(program, baseSpace, start, end, comment, loadAddr, prgLength, log);
			return;
		}

		Address startAddr = baseSpace.getAddress(start);
		long length = end - start + 1;
		MemoryBlockUtils.createUninitializedBlock(program, false, name, startAddr, length, comment,
			"c64.map", true, canWrite(kind), canExecute(kind), log);
	}

	private void createRamMainSplit(Program program, AddressSpace baseSpace, long start, long end,
			String comment, long loadAddr, long prgLength, MessageLog log) {

		long prgEnd = loadAddr + prgLength - 1;
		boolean prgInRange = prgLength > 0 && loadAddr >= start && prgEnd <= end;

		if (!prgInRange) {
			// PRG doesn't land cleanly inside RAM_MAIN (POC scope: log and create the plain
			// RAM_MAIN block; the PRG block created separately may overlap/land elsewhere).
			log.appendMsg("PRG load address 0x" + Long.toHexString(loadAddr) +
				" (length " + prgLength + ") does not fit within RAM_MAIN [0x" +
				Long.toHexString(start) + ",0x" + Long.toHexString(end) +
				"]; creating RAM_MAIN as a single block");
			Address startAddr = baseSpace.getAddress(start);
			MemoryBlockUtils.createUninitializedBlock(program, false, "RAM_MAIN", startAddr,
				end - start + 1, comment, "c64.map", true, canWrite("ram"), canExecute("ram"), log);
			return;
		}

		// The PRG initialized block occupies part of RAM_MAIN's range, so the surrounding RAM
		// is emitted as separate blocks (Ghidra can't overlap blocks, and join() can't merge an
		// initialized FileBytes block with uninitialized RAM). Address-suffix the carved halves
		// so the two blocks never share the name "RAM_MAIN".
		if (loadAddr > start) {
			Address belowStart = baseSpace.getAddress(start);
			MemoryBlockUtils.createUninitializedBlock(program, false,
				String.format("RAM_MAIN_%04X", (int) start), belowStart,
				loadAddr - start, comment, "c64.map", true, canWrite("ram"), canExecute("ram"), log);
		}
		if (prgEnd < end) {
			Address aboveStart = baseSpace.getAddress(prgEnd + 1);
			MemoryBlockUtils.createUninitializedBlock(program, false,
				String.format("RAM_MAIN_%04X", (int) (prgEnd + 1)), aboveStart,
				end - prgEnd, comment, "c64.map", true, canWrite("ram"), canExecute("ram"), log);
		}
	}

	private void createPrgBlock(Program program, AddressSpace baseSpace, ByteProvider provider,
			long loadAddr, long prgLength, MessageLog log) {

		if (prgLength <= 0) {
			log.appendMsg("PRG file has no program bytes past the 2-byte load address header");
			return;
		}
		try {
			FileBytes fileBytes =
				MemoryBlockUtils.createFileBytes(program, provider, ghidra.util.task.TaskMonitor.DUMMY);
			Address loadAddress = baseSpace.getAddress(loadAddr);
			MemoryBlockUtils.createInitializedBlock(program, false, "PRG", loadAddress, fileBytes, 2,
				prgLength, "PRG image loaded at $" + Long.toHexString(loadAddr), "c64prg", true, true,
				true, log);
		}
		catch (Exception e) {
			log.appendMsg("Failed to create PRG block: " + e.getMessage());
		}
	}

	// ------------------------------------------------------------------
	// Banked windows
	// ------------------------------------------------------------------

	private void createWindowOccupant(Program program, AddressSpace baseSpace, JsonObject occupant,
			JsonObject window, boolean isHome, FileDataTypeManager gdtMgr, MessageLog log) {

		String occupantName = occupant.get("name").getAsString();
		String kind = occupant.get("kind").getAsString();
		long start = window.get("start").getAsLong();
		long end = window.get("end").getAsLong();
		long length = end - start + 1;

		if (kind.equals("io")) {
			// The IO occupant is only meaningful when home (CHARIO/IO for POC); its subregions
			// are laid out individually.
			if (isHome) {
				createIoSubregions(program, baseSpace, occupant, gdtMgr, log);
			}
			return;
		}

		boolean isOverlay = !isHome;
		Address startAddr = baseSpace.getAddress(start);
		String comment = occupantName + " (" + kind + ")";
		MemoryBlockUtils.createUninitializedBlock(program, isOverlay, occupantName, startAddr, length,
			comment, "c64.map", true, canWrite(kind), canExecute(kind), log);
	}

	private void createIoSubregions(Program program, AddressSpace baseSpace, JsonObject ioOccupant,
			FileDataTypeManager gdtMgr, MessageLog log) {

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
			MemoryBlockUtils.createUninitializedBlock(program, false, name, startAddr, length, comment,
				"c64.map", true, canWrite(kind), canExecute(kind), log);

			if (sub.has("type") && gdtMgr != null) {
				applyStructType(program, baseSpace, gdtMgr, sub, log);
			}
		}
	}

	// ------------------------------------------------------------------
	// Data types
	// ------------------------------------------------------------------

	private void applyStructType(Program program, AddressSpace baseSpace, FileDataTypeManager gdtMgr,
			JsonObject withTypeAndStart, MessageLog log) {

		String typeName = withTypeAndStart.get("type").getAsString();
		long start = withTypeAndStart.get("start").getAsLong();

		DataType archiveType = gdtMgr.getDataType(CategoryPath.ROOT, typeName);
		if (archiveType == null) {
			log.appendMsg("Data type '" + typeName + "' not found in machines/c64.gdt; skipping");
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

	private void applySymbolSet(Program program, AddressSpace baseSpace, JsonObject set,
			MessageLog log) {

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
					markAsFunction(program, name, symAddr);
				}
				if (comment != null) {
					program.getListing()
							.setComment(symAddr, ghidra.program.model.listing.CommentType.EOL, comment);
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to create symbol '" + name + "' at 0x" +
					Long.toHexString(addr) + ": " + e.getMessage());
			}
		}
	}
}
