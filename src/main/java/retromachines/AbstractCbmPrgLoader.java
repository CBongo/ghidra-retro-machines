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

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import retromachines.DescriptorSupport.Perms;

/**
 * Shared descriptor-driven loader for Commodore-family {@code .prg} files.
 * <p>
 * Reads the 2-byte little-endian load address header, places the program bytes at that
 * address, and builds the selected machine's memory map (always-visible regions, optional
 * banked windows, register structs, symbols, and user-supplied ROM slots) from its bundled
 * compiled descriptor and data-type archive. Machine-specific behavior is confined to
 * small subclass hooks.
 */
abstract class AbstractCbmPrgLoader extends AbstractProgramWrapperLoader {

	// Safety fallback only: each descriptor names its preferred language. Stock 6502 is
	// used solely if that language is unavailable.
	private static final String FALLBACK_LANGUAGE_ID = "6502:LE:16:default";
	private static final String COMPILER_SPEC_ID = "default";
	static final String PRG_LOAD_ADDRESS_PROPERTY = "Retro Machines.CBM PRG Load Address";
	static final String PRG_LENGTH_PROPERTY = "Retro Machines.CBM PRG Payload Length";
	static final String PRG_WRAPPED_PROPERTY = "Retro Machines.CBM PRG Wrapped";
	static final String PRG_SLICES_PROPERTY = "Retro Machines.CBM PRG Slices";

	protected abstract String getMapPath();

	protected String getGdtPath() {
		String mapPath = getMapPath();
		return mapPath.endsWith(".map") ? mapPath.substring(0, mapPath.length() - 4) + ".gdt"
				: mapPath + ".gdt";
	}

	protected abstract String getMachineId();

	protected boolean isAdditionalPrgTarget(JsonObject node) {
		return false;
	}

	/** Extra recognition after the generic .prg/header/length checks. */
	protected boolean recognizesPrg(ByteProvider provider, long loadAddress, long payloadLength) {
		return true;
	}

	protected void afterPrgPlacement(Program program, List<PrgSlice> slices, MessageLog log) {
	}

	private record SourceSpan(long start, long length, long fileOffset) {
		long end() {
			return start + length - 1;
		}
	}

	static record RamTarget(String name, long start, long end, String kind) {}

	static record PrgSlice(RamTarget target, long start, long length, long fileOffset) {
		long end() {
			return start + length - 1;
		}
	}

	/** One persisted PRG slice, in original file order. */
	static record LoadedSlice(long fileOffset, long length, String spaceName, long start) {
		boolean contains(long cpuAddress) {
			return cpuAddress >= start && cpuAddress < start + length;
		}
	}

	// --- Optional user-supplied ROM loading (bead grm-mbm) --------------------------------
	// Slots are derived from the compiled descriptor's rom_images object. Its `occupant`
	// names the target block; despite that historical field name, a fixed region is also a
	// valid target (PET), as is a banked-window occupant (C64).
	private record RomSlot(String image, String target, String optionName, String cmdArg,
			String prefKey, long size) {}

	private List<RomSlot> romSlots() throws IOException {
		List<RomSlot> result = new ArrayList<>();
		JsonObject images = loadMap().getAsJsonObject("rom_images");
		if (images == null) {
			return result;
		}
		for (Map.Entry<String, JsonElement> entry : images.entrySet()) {
			String image = entry.getKey();
			JsonObject descriptor = entry.getValue().getAsJsonObject();
			String optionStem = optionStem(image);
			result.add(new RomSlot(image, descriptor.get("occupant").getAsString(),
				image.toUpperCase() + " ROM path",
				Loader.COMMAND_LINE_ARG_PREFIX + "-" + optionStem + "Rom",
				"retromachines." + getMachineId() + "." + optionStem + "RomPath",
				descriptor.get("size").getAsLong()));
		}
		return result;
	}

	private static String optionStem(String image) {
		StringBuilder result = new StringBuilder();
		boolean capitalize = false;
		for (int i = 0; i < image.length(); i++) {
			char c = image.charAt(i);
			if (!Character.isLetterOrDigit(c)) {
				capitalize = result.length() > 0;
				continue;
			}
			result.append(capitalize ? Character.toUpperCase(c) : c);
			capitalize = false;
		}
		return result.toString();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		// Pre-fill from remembered paths in the GUI only; a headless/command-line import must
		// not draw ROM paths from the persistent preferences (only from the -<arg> value).
		boolean gui = !SystemUtilities.isInHeadlessMode();
		try {
			for (RomSlot slot : romSlots()) {
			String saved = gui ? Preferences.getProperty(slot.prefKey(), "", true) : "";
			options.add(new RomFileOption(slot.optionName(), saved, slot.cmdArg()));
			}
		}
		catch (IOException e) {
			// load() reports an unreadable descriptor; omit only its derived ROM options here.
		}
		// A checkbox per descriptor symbol set (bead grm-zlj), defaulting to the set's
		// descriptor `default:`. Lets the user apply or skip any set at import -- notably to
		// enable the off-by-default BASIC/KERNAL zero-page and page-2/3 variable labels.
		for (Map.Entry<String, Boolean> set : symbolSetDefaults().entrySet()) {
			options.add(new Option(symbolOptionName(set.getKey()), Boolean.class, set.getValue(),
				symbolOptionArg(set.getKey()), "Symbol sets"));
		}
		return options;
	}

	/** Ordered map of symbol-set name -&gt; descriptor {@code default:}, read from the compiled
	 *  map. Empty if the map cannot be read (the checkboxes are then simply omitted and
	 *  {@link #load} applies each set's descriptor default). */
	private Map<String, Boolean> symbolSetDefaults() {
		Map<String, Boolean> result = new LinkedHashMap<>();
		try {
			JsonArray symbolSets = loadMap().getAsJsonArray("symbols");
			if (symbolSets != null) {
				for (JsonElement se : symbolSets) {
					JsonObject set = se.getAsJsonObject();
					result.put(set.get("set").getAsString(),
						set.has("default") && set.get("default").getAsBoolean());
				}
			}
		}
		catch (IOException e) {
			// No map -> no symbol checkboxes; load() falls back to descriptor defaults.
		}
		return result;
	}

	private static String symbolOptionName(String setName) {
		return "Apply symbols: " + setName;
	}

	private static String symbolOptionArg(String setName) {
		return Loader.COMMAND_LINE_ARG_PREFIX + "-symbols-" + setName;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		List<RomSlot> slots;
		try {
			slots = romSlots();
		}
		catch (IOException e) {
			return "Failed to read " + getMapPath() + ": " + e.getMessage();
		}
		for (RomSlot slot : slots) {
			String path = OptionUtils.getOption(slot.optionName(), options, "");
			if (path == null || path.isBlank()) {
				continue;
			}
			File f = new File(path.trim());
			if (!f.isFile()) {
				return slot.optionName() + ": file not found: " + path;
			}
			if (f.length() != slot.size()) {
				return slot.optionName() + ": expected " + slot.size() + " bytes but " +
					f.getName() + " is " + f.length() + " bytes";
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
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
		long loadAddress = (provider.readByte(1) & 0xffL) << 8 |
			(provider.readByte(0) & 0xffL);
		if (!recognizesPrg(provider, loadAddress, provider.length() - 2)) {
			return loadSpecs;
		}

		// Load with the descriptor's declared language; fall back to stock 6502 only if that
		// language is unavailable. See DescriptorSupport.resolveLanguageId.
		String languageId = FALLBACK_LANGUAGE_ID;
		try {
			languageId = DescriptorSupport.resolveLanguageId(loadMap(), FALLBACK_LANGUAGE_ID);
		}
		catch (IOException e) {
			// descriptor unreadable here -> keep the safety fallback; load() will report it
		}
		LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair(languageId, COMPILER_SPEC_ID);
		loadSpecs.add(new LoadSpec(this, 0, pair, true));
		return loadSpecs;
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// The descriptor memory map already covers the 6502 pspec's ZERO_PAGE/STACK
		// ranges; suppress the stock loader's conflict log noise (bead grm-rua).
		DescriptorSupport.createDefaultMemoryBlocksQuietly(program, settings.log());
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();

		// Optional user-supplied ROM images (bead grm-mbm), keyed by descriptor image name.
		Map<String, String> romPaths = new HashMap<>();
		for (RomSlot slot : romSlots()) {
			String path = OptionUtils.getOption(slot.optionName(), settings.options(), "");
			if (path != null && !path.isBlank()) {
				romPaths.put(slot.target(), path.trim());
			}
		}

		// --- Load the descriptor JSON ---
		JsonObject map;
		try {
			map = loadMap();
		}
		catch (IOException e) {
			log.appendMsg("Failed to load " + getMapPath() + ": " + e.getMessage());
			return;
		}

		// --- Open the bundled IO-chip register struct archive ---
		FileDataTypeManager gdtMgr = null;
		try {
			gdtMgr = openGdt();
		}
		catch (IOException e) {
			log.appendMsg("Failed to open " + getGdtPath() + ": " + e.getMessage());
		}

		try {
			AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

			// --- Read the 2-byte LE load address header ---
			int loadAddrLow = provider.readByte(0) & 0xFF;
			int loadAddrHigh = provider.readByte(1) & 0xFF;
			long loadAddr = (loadAddrHigh << 8) | loadAddrLow;
			long prgLength = provider.length() - 2;
			// grm-z15: a bare 2-byte load-address header with no payload is a legal (if
			// degenerate) PRG -- accept it and build the full memory map/symbols, just
			// with no PRG bytes to place. See the prgLength == 0 handling below.
			if (prgLength > 0x10000) {
				throw new IOException("PRG payload is " + prgLength +
					" bytes; a 16-bit CBM image may contain at most 65536 bytes");
			}
			boolean wrapped = prgLength > 0x10000 - loadAddr;
			List<PrgSlice> prgSlices = planPrgSlices(map, loadAddr, prgLength);
			Map<String, List<PrgSlice>> slicesByTarget = new HashMap<>();
			for (PrgSlice slice : prgSlices) {
				slicesByTarget.computeIfAbsent(slice.target().name(), k -> new ArrayList<>())
					.add(slice);
			}
			// grm-z15: skip wrapping an empty provider in FileBytes for a zero-payload PRG --
			// planPrgSlices returns no slices for length == 0, so nothing downstream needs
			// prgFileBytes in that case, and an unused FileBytes over a 2-byte file would be
			// a stray reference with no purpose.
			FileBytes prgFileBytes = prgLength == 0 ? null
					: MemoryBlockUtils.createFileBytes(program, provider, TaskMonitor.DUMMY);
			Map<String, AddressSpace> placementSpaces = new HashMap<>();

			// --- Always-visible regions ---
			JsonArray regions = map.getAsJsonArray("regions");
			Map<String, JsonObject> regionsByName = new LinkedHashMap<>();
			for (JsonElement re : regions) {
				JsonObject region = re.getAsJsonObject();
				regionsByName.put(region.get("name").getAsString(), region);
			}

			for (JsonObject region : regionsByName.values()) {
				String regionName = region.get("name").getAsString();
				List<PrgSlice> slices = slicesByTarget.get(regionName);
				if (slices != null) {
					createCarvedTarget(program, baseSpace, region, regionName, false, prgFileBytes,
						slices, gdtMgr, placementSpaces, log);
				}
				else {
					createRegionBlock(program, baseSpace, region, romPaths.get(regionName),
						gdtMgr, log);
				}
			}

			// --- Banked windows: home occupant in base space, alternates in overlay spaces ---
			JsonArray windows = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
			JsonObject banking = map.getAsJsonObject("banking");
			if (windows.isEmpty()) {
				// A fixed-map machine such as the PET has no banked-window work.
			}
			else if (banking == null || !banking.has("initial_state") ||
					!banking.has("states")) {
				log.appendMsg(getMapPath() + " banking section incomplete " +
					"(need initial_state and states); skipping banked-window setup");
			}
			else {
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

				for (JsonElement we : windows) {
					JsonObject window = we.getAsJsonObject();
					String windowName = window.get("name").getAsString();
					String homeOccupantName = homeState != null && homeState.has(windowName)
							? homeState.get(windowName).getAsString()
							: null;

					List<DescriptorSupport.NamedCandidate> occupantCandidates = new ArrayList<>();
					JsonArray occupants = window.getAsJsonArray("occupants");
					FileDataTypeManager gdtMgrForCandidates = gdtMgr;
					for (JsonElement oe : occupants) {
						JsonObject occupant = oe.getAsJsonObject();
						String occupantName = occupant.get("name").getAsString();
						occupantCandidates.add(new DescriptorSupport.NamedCandidate(occupantName,
							(p, bs, isHome, l) -> createWindowOccupant(p, bs, occupant, window,
								isHome, gdtMgrForCandidates, romPaths,
								slicesByTarget.get(occupantName), prgFileBytes, placementSpaces, l)));
					}
					DescriptorSupport.placeHomeInBaseWindow(program, baseSpace, occupantCandidates,
						homeOccupantName, log);
				}
			}

			persistPrgPlacement(program, loadAddr, prgLength, wrapped, prgSlices,
				placementSpaces);
			program.getOptions(Program.PROGRAM_INFO).setString(
				DescriptorSupport.MAP_PATH_PROPERTY, getMapPath());
			afterPrgPlacement(program, prgSlices, log);

			// --- Descriptor symbol sets ---
			JsonArray symbolSets = map.getAsJsonArray("symbols");
			for (JsonElement se : symbolSets) {
				JsonObject set = se.getAsJsonObject();
				String setName = set.get("set").getAsString();
				// Whether to apply this set is exactly the per-set checkbox value (grm-zlj) --
				// NOT OR-ed with the descriptor default. The checkbox's own default was seeded
				// (in getDefaultOptions) to the descriptor `default:`, so an unattended import
				// applies precisely the descriptor defaults, while a user can turn any set on
				// or off (including unchecking an on-by-default set). The isDefault fallback
				// here only applies if the checkbox is absent, e.g. the map failed to load
				// during getDefaultOptions.
				boolean isDefault = set.has("default") && set.get("default").getAsBoolean();
				boolean enabled = OptionUtils.getOption(symbolOptionName(setName),
					settings.options(), Boolean.valueOf(isDefault));
				if (!enabled) {
					continue;
				}
				DescriptorSupport.applySymbolSet(program, baseSpace, set,
					(name, addr) -> markAsFunction(program, name, addr), log);
			}

			// --- Program entry point ---
			// A BASIC-start PRG's bytes at the load address are the first BASIC line's
			// link, not machine code -- marking a function there (the unconditional
			// behavior prior to grm-odt.1) mislabels every such PRG. A CBM BASIC analyzer
			// walks the tokenized line chain and, if it finds a SYS line, marks the real
			// ML entry point instead; this loader's job is only to recognize the case (a
			// structural sniff of the line-link chain -- see CbmBasicWalker.isBasicStart,
			// which never compares loadAddr against a hardcoded address such as $0801)
			// and stay out of the analyzer's way.
			if (prgLength == 0) {
				// grm-z15: a zero-payload PRG places no bytes anywhere, so planPrgSlices/
				// resolvePrgAddress have nothing to resolve -- the old code fell through to
				// the "No placed PRG slice contains load address" IOException below, caught
				// and logged as an ugly "Failed to set entry point". The memory map was
				// already fully built above; just label the load address in base space
				// directly. Not attempting basicStart detection here: a zero-length payload
				// is trivially not a BASIC program.
				try {
					Address entryAddr = baseSpace.getAddress(loadAddr);
					program.getSymbolTable().createLabel(entryAddr, "entry", SourceType.IMPORTED);
					program.getSymbolTable().addExternalEntryPoint(entryAddr);
					MemoryBlock entryBlock = program.getMemory().getBlock(entryAddr);
					if (entryBlock != null && entryBlock.isExecute()) {
						markAsFunction(program, "entry", entryAddr);
					}
					log.appendMsg("zero-payload PRG: built the memory map; no program bytes to " +
						"place (labelled the load address $" + Long.toHexString(loadAddr) + ")");
				}
				catch (Exception e) {
					log.appendMsg("Failed to set entry point: " + e.getMessage());
				}
			}
			else {
				boolean basicStart = !wrapped && looksLikeBasicStart(provider, loadAddr, prgLength);
				try {
					Address entryAddr = resolvePrgAddress(program, loadAddr);
					if (entryAddr == null) {
						throw new IOException("No placed PRG slice contains load address $" +
							Long.toHexString(loadAddr));
					}
					program.getSymbolTable().createLabel(entryAddr,
						entryAddr.getAddressSpace().equals(baseSpace) ? "entry" : "load_start",
						SourceType.IMPORTED);
					MemoryBlock entryBlock = program.getMemory().getBlock(entryAddr);
					boolean executableEntry = entryBlock != null && entryBlock.isExecute();
					// grm-z15: addExternalEntryPoint (SymbolTable) merely records the address in
					// the entry-point set -- it has no executability requirement and makes no
					// code assumption, so call it unconditionally (this restores the pre-rework
					// behavior; a load address landing in a non-executable block, e.g. the
					// P6510 io block at $0000, must not be silently dropped from the entry-point
					// set). Only the function mark below stays gated on executability.
					program.getSymbolTable().addExternalEntryPoint(entryAddr);
					if (basicStart) {
						log.appendMsg("PRG looks like a BASIC-start program (well-formed line-link " +
							"chain at 0x" + Long.toHexString(loadAddr) + "); not marking a function " +
							"there -- a CBM BASIC analyzer can locate the real ML entry from a SYS line");
					}
					else if (executableEntry) {
						markAsFunction(program, "entry", entryAddr);
					}
					else {
						log.appendMsg("PRG load start $" + Long.toHexString(loadAddr) +
							" is in non-executable block " +
							(entryBlock == null ? "<none>" : entryBlock.getName()) +
							"; recorded an external entry point but did not mark a function there");
					}
					if (!entryAddr.getAddressSpace().equals(baseSpace)) {
						log.appendMsg("PRG load start $" + Long.toHexString(loadAddr) + " is in " +
							entryAddr.getAddressSpace().getName() +
							" beneath the initial-state ROM/IO mapping; no duplicate base entry was created");
					}
				}
				catch (Exception e) {
					log.appendMsg("Failed to set entry point: " + e.getMessage());
				}
			}

			// Remember the ROM paths used (GUI only) so the next import defaults to them.
			saveRomPreferences(settings);
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

	/** {@link CbmBasicWalker#isBasicStart} over this PRG's raw bytes (2-byte load-address
	 *  header already consumed by the caller). */
	protected static boolean looksLikeBasicStart(ByteProvider provider, long loadAddr,
			long prgLength) {
		long limitAddr = loadAddr + prgLength;
		CbmBasicWalker.ByteSource src = addr -> {
			if (addr < loadAddr || addr >= limitAddr) {
				return -1;
			}
			try {
				return provider.readByte((addr - loadAddr) + 2) & 0xFF;
			}
			catch (IOException e) {
				return -1;
			}
		};
		return CbmBasicWalker.isBasicStart(src, loadAddr, limitAddr);
	}

	private JsonObject loadMap() throws IOException {
		return DescriptorSupport.loadMap(getMapPath());
	}

	private FileDataTypeManager openGdt() throws IOException {
		return DescriptorSupport.openGdt(getGdtPath());
	}

	// ------------------------------------------------------------------
	// Descriptor-derived PRG placement (grm-dvx)
	// ------------------------------------------------------------------

	private List<PrgSlice> planPrgSlices(JsonObject map, long loadAddr, long length)
			throws IOException {
		if (length == 0) {
			return List.of();
		}

		List<RamTarget> targets = new ArrayList<>();
		for (JsonElement re : map.getAsJsonArray("regions")) {
			JsonObject region = re.getAsJsonObject();
			String name = region.get("name").getAsString();
			String kind = region.get("kind").getAsString();
			// $0000/$0001 are address-visible 6510 registers, not general RAM, but wrapped
			// PRGs in the wild deliberately place bytes across them on their way to low RAM.
			if (kind.equals("ram") || isAdditionalPrgTarget(region)) {
				targets.add(new RamTarget(name, region.get("start").getAsLong(),
					region.get("end").getAsLong(), kind));
			}
		}
		for (JsonElement we : map.getAsJsonArray("windows")) {
			JsonObject window = we.getAsJsonObject();
			long start = window.get("start").getAsLong();
			long end = window.get("end").getAsLong();
			for (JsonElement oe : window.getAsJsonArray("occupants")) {
				JsonObject occupant = oe.getAsJsonObject();
				if (occupant.get("kind").getAsString().equals("ram")) {
					targets.add(new RamTarget(occupant.get("name").getAsString(), start, end,
						"ram"));
				}
			}
		}
		for (int i = 0; i < targets.size(); i++) {
			RamTarget left = targets.get(i);
			for (int j = i + 1; j < targets.size(); j++) {
				RamTarget right = targets.get(j);
				if (left.start() <= right.end() && right.start() <= left.end()) {
					throw new IOException("CBM PRG placement targets " + left.name() + " and " +
						right.name() + " overlap at $" +
						String.format("%04X", Math.max(left.start(), right.start())));
				}
			}
		}

		long firstLength = Math.min(length, 0x10000 - loadAddr);
		List<SourceSpan> spans = new ArrayList<>();
		spans.add(new SourceSpan(loadAddr, firstLength, 2));
		if (length > firstLength) {
			spans.add(new SourceSpan(0, length - firstLength, 2 + firstLength));
		}

		List<PrgSlice> slices = new ArrayList<>();
		for (SourceSpan span : spans) {
			long cursor = span.start();
			while (cursor <= span.end()) {
				long address = cursor;
				List<RamTarget> matching = targets.stream()
					.filter(t -> address >= t.start() && address <= t.end()).toList();
				if (matching.size() != 1) {
					throw new IOException("PRG address $" + String.format("%04X", cursor) +
						" has " + matching.size() + " physical placement targets in " +
						getMapPath());
				}
				RamTarget target = matching.get(0);
				long sliceEnd = Math.min(span.end(), target.end());
				long fileOffset = span.fileOffset() + cursor - span.start();
				slices.add(new PrgSlice(target, cursor, sliceEnd - cursor + 1, fileOffset));
				cursor = sliceEnd + 1;
			}
		}
		return List.copyOf(slices);
	}

	private void createRegionBlock(Program program, AddressSpace baseSpace, JsonObject region,
			String romPath, FileDataTypeManager gdtMgr, MessageLog log) {
		String name = region.get("name").getAsString();
		String kind = region.get("kind").getAsString();
		long start = region.get("start").getAsLong();
		long length = region.get("end").getAsLong() - start + 1;
		if (romPath != null && kind.equals("rom")) {
			MemoryBlock block = createRomBlock(program, name, baseSpace.getAddress(start), length,
				false, romPath, DescriptorSupport.perms(region, kind), log);
			if (block != null) {
				if (region.has("type") && gdtMgr != null) {
					DescriptorSupport.applyStructType(program, baseSpace, gdtMgr, region,
						getMapPath(), log);
				}
				return;
			}
		}
		DescriptorSupport.createRegionBlock(program, baseSpace, region, getMapPath(), gdtMgr, log);
	}

	private void createCarvedTarget(Program program, AddressSpace baseSpace, JsonObject region,
			String targetName, boolean overlay, FileBytes fileBytes, List<PrgSlice> slices,
			FileDataTypeManager gdtMgr, Map<String, AddressSpace> placementSpaces, MessageLog log)
			throws IOException {
		AddressSpace targetSpace = createCarvedTarget(program, baseSpace, targetName,
			region.get("start").getAsLong(), region.get("end").getAsLong(),
			region.get("kind").getAsString(),
			region.has("comment") ? region.get("comment").getAsString() : null, region, overlay,
			fileBytes, slices, placementSpaces);
		if (region.has("type") && gdtMgr != null) {
			DescriptorSupport.applyStructType(program, targetSpace, gdtMgr, region, getMapPath(), log);
		}
	}

	private AddressSpace createCarvedTarget(Program program, AddressSpace baseSpace,
			String targetName, long targetStart, long targetEnd, String kind, String comment,
			JsonObject permsSource, boolean overlay, FileBytes fileBytes, List<PrgSlice> slices,
			Map<String, AddressSpace> placementSpaces) throws IOException {
		try {
			AddressSpace targetSpace = baseSpace;
			if (overlay) {
				targetSpace = program.getAddressFactory().getAddressSpace(targetName);
				if (targetSpace == null) {
					targetSpace = program.createOverlaySpace(targetName, baseSpace);
				}
			}
			placementSpaces.put(targetName, targetSpace);

			List<PrgSlice> ordered = slices.stream()
				.sorted((a, b) -> Long.compare(a.start(), b.start())).toList();
			long cursor = targetStart;
			for (PrgSlice slice : ordered) {
				if (cursor < slice.start()) {
					createDirectBlock(program, targetSpace, targetName, targetStart,
						cursor, slice.start() - cursor, kind, comment, permsSource, null, 0);
				}
				createDirectBlock(program, targetSpace, targetName, targetStart,
					slice.start(), slice.length(), kind,
					"PRG image bytes at $" + String.format("%04X", slice.start()), permsSource,
					fileBytes, slice.fileOffset());
				cursor = slice.end() + 1;
			}
			if (cursor <= targetEnd) {
				createDirectBlock(program, targetSpace, targetName, targetStart,
					cursor, targetEnd - cursor + 1, kind, comment, permsSource, null, 0);
			}
			return targetSpace;
		}
		catch (Exception e) {
			throw new IOException("Failed to carve PRG bytes into " + targetName + ": " +
				e.getMessage(), e);
		}
	}

	private MemoryBlock createDirectBlock(Program program, AddressSpace space, String targetName,
			long targetStart, long start, long length, String kind, String comment,
			JsonObject permsSource, FileBytes fileBytes, long fileOffset) throws Exception {
		boolean initialized = fileBytes != null;
		String name;
		if (start == targetStart && space.isOverlaySpace()) {
			name = targetName; // preserve the block/space naming contract used by the analyzer
		}
		else if (start == targetStart && kind.equals("io")) {
			name = targetName; // preserve P6510 for register typing and navigation
		}
		else if (initialized && fileOffset == 2 && !space.isOverlaySpace()) {
			name = "PRG";
		}
		else {
			name = (initialized ? "PRG" : targetName) + String.format("_%04X", start);
		}

		Memory memory = program.getMemory();
		// An empty ProgramOverlayAddressSpace.getAddress(offset) deliberately falls back to
		// the base space until a block covers that offset. Force the first fragment into the
		// newly-created overlay; subsequent fragments can use the same form safely too.
		Address address = space.isOverlaySpace()
				? space.getAddressInThisSpaceOnly(start) : space.getAddress(start);
		MemoryBlock block = initialized
				? memory.createInitializedBlock(name, address, fileBytes, fileOffset, length, false)
				: memory.createUninitializedBlock(name, address, length, false);
		Perms p = DescriptorSupport.perms(permsSource, kind);
		block.setComment(comment);
		block.setSourceName(initialized ? getMachineId() + "prg" : getMapPath());
		block.setRead(p.readable());
		block.setWrite(p.writable());
		block.setExecute(p.executable());
		DescriptorSupport.markVolatileIfIo(block, kind);
		return block;
	}

	private static void persistPrgPlacement(Program program, long loadAddr, long length,
			boolean wrapped, List<PrgSlice> slices, Map<String, AddressSpace> placementSpaces)
			throws IOException {
		JsonArray serialized = new JsonArray();
		for (PrgSlice slice : slices) {
			AddressSpace space = placementSpaces.get(slice.target().name());
			if (space == null) {
				throw new IOException("No address space was created for PRG target " +
					slice.target().name());
			}
			JsonObject item = new JsonObject();
			item.addProperty("file_offset", slice.fileOffset());
			item.addProperty("length", slice.length());
			item.addProperty("space", space.getName());
			item.addProperty("start", slice.start());
			serialized.add(item);
		}
		Options info = program.getOptions(Program.PROGRAM_INFO);
		info.setLong(PRG_LOAD_ADDRESS_PROPERTY, loadAddr);
		info.setLong(PRG_LENGTH_PROPERTY, length);
		info.setBoolean(PRG_WRAPPED_PROPERTY, wrapped);
		info.setString(PRG_SLICES_PROPERTY, new Gson().toJson(serialized));
	}

	static List<LoadedSlice> getLoadedSlices(Program program) {
		Options info = program.getOptions(Program.PROGRAM_INFO);
		String json = info.getString(PRG_SLICES_PROPERTY, null);
		if (json == null) {
			// Compatibility with C64 programs saved before the shared CBM loader extraction.
			json = info.getString("Retro Machines.C64 PRG Slices", "[]");
		}
		try {
			List<LoadedSlice> result = new ArrayList<>();
			for (JsonElement element : JsonParser.parseString(json).getAsJsonArray()) {
				JsonObject item = element.getAsJsonObject();
				result.add(new LoadedSlice(item.get("file_offset").getAsLong(),
					item.get("length").getAsLong(), item.get("space").getAsString(),
					item.get("start").getAsLong()));
			}
			return List.copyOf(result);
		}
		catch (RuntimeException e) {
			return List.of();
		}
	}

	static Address resolvePrgAddress(Program program, long cpuAddress) {
		return resolvePrgAddress(program, cpuAddress, getLoadedSlices(program));
	}

	static Address resolvePrgAddress(Program program, long cpuAddress,
			List<LoadedSlice> loadedSlices) {
		long address = cpuAddress & 0xFFFF;
		for (LoadedSlice slice : loadedSlices) {
			if (!slice.contains(address)) {
				continue;
			}
			AddressSpace space = program.getAddressFactory().getAddressSpace(slice.spaceName());
			if (space != null) {
				return space.getAddress(address);
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Banked windows
	// ------------------------------------------------------------------

	private MemoryBlock createWindowOccupant(Program program, AddressSpace baseSpace,
			JsonObject occupant, JsonObject window, boolean isHome, FileDataTypeManager gdtMgr,
			Map<String, String> romPaths, List<PrgSlice> prgSlices, FileBytes prgFileBytes,
			Map<String, AddressSpace> placementSpaces, MessageLog log) {

		String occupantName = occupant.get("name").getAsString();
		String kind = occupant.get("kind").getAsString();
		long start = window.get("start").getAsLong();
		long end = window.get("end").getAsLong();
		long length = end - start + 1;

		if (kind.equals("io")) {
			// The IO occupant is only meaningful when home (CHARIO/IO for POC); its subregions
			// are laid out individually, so there's no single representative block to return.
			if (isHome) {
				DescriptorSupport.createIoSubregions(program, baseSpace, occupant, getMapPath(),
					gdtMgr, log);
			}
			return null;
		}

		boolean isOverlay = !isHome;
		Address startAddr = baseSpace.getAddress(start);
		String comment = occupantName + " (" + kind + ")";
		Perms p = DescriptorSupport.perms(occupant, kind);

		if (prgSlices != null && !prgSlices.isEmpty()) {
			try {
				AddressSpace targetSpace = createCarvedTarget(program, baseSpace, occupantName,
					start, end, kind, comment, occupant, isOverlay, prgFileBytes, prgSlices,
					placementSpaces);
				return program.getMemory().getBlock(targetSpace.getAddress(start));
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		// If this is a ROM occupant the user supplied a dump for, initialize it from that file
		// (bead grm-mbm) instead of leaving it empty -- makes ROM code disassemblable and gives
		// ROM->RAM copies (e.g. CHRGET) a real source. Any failure falls back to uninitialized.
		if (occupant.has("image")) {
			String path = romPaths.get(occupantName);
			if (path != null) {
				MemoryBlock rom = createRomBlock(program, occupantName, startAddr, length,
					isOverlay, path, p, log);
				if (rom != null) {
					return rom;
				}
			}
		}

		return MemoryBlockUtils.createUninitializedBlock(program, isOverlay, occupantName, startAddr,
			length, comment, getMapPath(), p.readable(), p.writable(), p.executable(), log);
	}

	/** Initialize a ROM occupant block from a user-supplied dump file, mirroring
	 *  the PRG slice FileBytes pattern. Returns null (caller falls back to an
	 *  uninitialized block) if the file is the wrong size or cannot be read. */
	private MemoryBlock createRomBlock(Program program, String name, Address start, long length,
			boolean isOverlay, String path, Perms p, MessageLog log) {
		File file = new File(path);
		if (file.length() != length) {
			log.appendMsg(name + ": ROM file " + path + " is " + file.length() + " bytes, expected "
				+ length + "; leaving " + name + " uninitialized");
			return null;
		}
		try (FileByteProvider romProvider = new FileByteProvider(file, null, AccessMode.READ)) {
			FileBytes fileBytes =
				MemoryBlockUtils.createFileBytes(program, romProvider, TaskMonitor.DUMMY);
			return MemoryBlockUtils.createInitializedBlock(program, isOverlay, name, start,
				fileBytes, 0, length, name + " (user-supplied ROM: " + file.getName() + ")",
				"user-rom", p.readable(), p.writable(), p.executable(), log);
		}
		catch (Exception e) {
			log.appendMsg(name + ": failed to load ROM " + path + ": " + e.getMessage() +
				"; leaving " + name + " uninitialized");
			return null;
		}
	}

	/** Remember the supplied ROM paths so the next GUI import defaults to them. Skipped in
	 *  headless mode: a command-line import must neither read nor write these preferences. */
	private void saveRomPreferences(ImporterSettings settings) {
		if (SystemUtilities.isInHeadlessMode()) {
			return;
		}
		boolean changed = false;
		List<RomSlot> slots;
		try {
			slots = romSlots();
		}
		catch (IOException e) {
			return;
		}
		for (RomSlot slot : slots) {
			String path = OptionUtils.getOption(slot.optionName(), settings.options(), "");
			if (path != null && !path.isBlank()) {
				Preferences.setProperty(slot.prefKey(), path.trim());
				changed = true;
			}
		}
		if (changed) {
			Preferences.store();
		}
	}
}
