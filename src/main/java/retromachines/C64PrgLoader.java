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
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

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
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import retromachines.DescriptorSupport.Perms;

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

	// Safety fallback only: the descriptor names the bundled 6510 language, which this
	// loader resolves at import time; stock 6502 is used solely if the 6510 is unavailable.
	private static final String FALLBACK_LANGUAGE_ID = "6502:LE:16:default";
	private static final String COMPILER_SPEC_ID = "default";
	private static final String MAP_PATH = "machines/c64.map";
	private static final String GDT_PATH = "machines/c64.gdt";

	/** The executable-format name stamped on imports; gated on by {@link C64BankingAnalyzer}. */
	public static final String NAME = "Commodore 64 PRG";

	@Override
	public String getName() {
		return NAME;
	}

	// --- Optional user-supplied ROM loading (bead grm-mbm) --------------------------------
	// Each slot ties a descriptor image name to its import-dialog option, command-line arg,
	// persisted-preference key, and expected byte size (fixed C64 ROM sizes). The paths let
	// the user initialize the otherwise-empty KERNAL/BASIC/CHARGEN blocks; the GUI remembers
	// them in Preferences, while a command-line import neither reads nor writes those prefs.
	private record RomSlot(String image, String optionName, String cmdArg, String prefKey,
			long size) {}

	// The command-line argument is the full "-loader-<name>" form: LoaderArgsOptionChooser
	// matches a headless "-loader-kernalRom <path>" flag verbatim against Option.getArg().
	private static final List<RomSlot> ROM_SLOTS = List.of(
		new RomSlot("kernal", "KERNAL ROM path", Loader.COMMAND_LINE_ARG_PREFIX + "-kernalRom",
			"retromachines.c64.kernalRomPath", 0x2000),
		new RomSlot("basic", "BASIC ROM path", Loader.COMMAND_LINE_ARG_PREFIX + "-basicRom",
			"retromachines.c64.basicRomPath", 0x2000),
		new RomSlot("chargen", "CHARGEN ROM path", Loader.COMMAND_LINE_ARG_PREFIX + "-chargenRom",
			"retromachines.c64.chargenRomPath", 0x1000));

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		// Pre-fill from remembered paths in the GUI only; a headless/command-line import must
		// not draw ROM paths from the persistent preferences (only from the -<arg> value).
		boolean gui = !SystemUtilities.isInHeadlessMode();
		for (RomSlot slot : ROM_SLOTS) {
			String saved = gui ? Preferences.getProperty(slot.prefKey(), "", true) : "";
			options.add(new RomFileOption(slot.optionName(), saved, slot.cmdArg()));
		}
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		for (RomSlot slot : ROM_SLOTS) {
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

		// Load with the descriptor's declared language (the bundled 6510, which models the
		// on-die $00/$01 port as a register); fall back to stock 6502 only if that language
		// is somehow unavailable. See DescriptorSupport.resolveLanguageId.
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
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();

		// Optional user-supplied ROM images (bead grm-mbm), keyed by descriptor image name.
		Map<String, String> romPaths = new HashMap<>();
		for (RomSlot slot : ROM_SLOTS) {
			String path = OptionUtils.getOption(slot.optionName(), settings.options(), "");
			if (path != null && !path.isBlank()) {
				romPaths.put(slot.image(), path.trim());
			}
		}

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

			boolean sawLoadTarget = false;
			for (JsonObject region : regionsByName.values()) {
				// The region flagged load_target: true (c64.map's RAM_MAIN) is carved around
				// the PRG image; everything else is generic. Which region (if any) plays this
				// role is entirely descriptor-driven -- see docs/MAP_FORMAT.md's load_target.
				if (region.has("load_target") && region.get("load_target").getAsBoolean()) {
					sawLoadTarget = true;
					createRamMainSplit(program, baseSpace, region, loadAddr, prgLength, log);
				}
				else {
					DescriptorSupport.createRegionBlock(program, baseSpace, region, "c64.map",
						gdtMgr, log);
				}
			}
			if (!sawLoadTarget) {
				log.appendMsg("c64.map has no region flagged load_target: true; PRG image will " +
					"not be carved into any region (all regions created as generic uninitialized " +
					"blocks)");
			}

			// --- PRG image block ---
			createPrgBlock(program, baseSpace, provider, loadAddr, prgLength, log);

			// --- Banked windows: home occupant in base space, alternates in overlay spaces ---
			JsonObject banking = map.getAsJsonObject("banking");
			if (banking == null || !banking.has("initial_state") || !banking.has("states") ||
				!map.has("windows")) {
				log.appendMsg("c64.map banking section or windows incomplete " +
					"(need initial_state, states, windows); skipping banked-window setup");
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

				JsonArray windows = map.getAsJsonArray("windows");
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
								isHome, gdtMgrForCandidates, romPaths, l)));
					}
					DescriptorSupport.placeHomeInBaseWindow(program, baseSpace, occupantCandidates,
						homeOccupantName, log);
				}
			}

			// --- KERNAL API symbols ---
			// (the P6510 struct is applied by createRegionBlock from the region's type:)
			JsonArray symbolSets = map.getAsJsonArray("symbols");
			for (JsonElement se : symbolSets) {
				JsonObject set = se.getAsJsonObject();
				boolean isDefault = set.has("default") && set.get("default").getAsBoolean();
				if (!isDefault) {
					continue;
				}
				DescriptorSupport.applySymbolSet(program, baseSpace, set,
					(name, addr) -> markAsFunction(program, name, addr), log);
			}

			// --- Program entry point ---
			// A BASIC-start PRG's bytes at the load address are the first BASIC line's
			// link, not machine code -- marking a function there (the unconditional
			// behavior prior to grm-odt.1) mislabels every such PRG. C64BasicAnalyzer
			// walks the tokenized line chain and, if it finds a SYS line, marks the real
			// ML entry point instead; this loader's job is only to recognize the case (a
			// structural sniff of the line-link chain -- see C64BasicWalker.isBasicStart,
			// which never compares loadAddr against a hardcoded address such as $0801)
			// and stay out of the analyzer's way.
			boolean basicStart = looksLikeBasicStart(provider, loadAddr, prgLength);
			try {
				Address entryAddr = baseSpace.getAddress(loadAddr);
				program.getSymbolTable().addExternalEntryPoint(entryAddr);
				program.getSymbolTable().createLabel(entryAddr, "entry", SourceType.IMPORTED);
				if (basicStart) {
					log.appendMsg("PRG looks like a BASIC-start program (well-formed line-link " +
						"chain at 0x" + Long.toHexString(loadAddr) + "); not marking a function " +
						"there -- C64BasicAnalyzer will locate the real ML entry from a SYS line");
				}
				else {
					markAsFunction(program, "entry", entryAddr);
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to set entry point: " + e.getMessage());
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

	/** {@link C64BasicWalker#isBasicStart} over this PRG's raw bytes (2-byte load-address
	 *  header already consumed by the caller). */
	private static boolean looksLikeBasicStart(ByteProvider provider, long loadAddr,
			long prgLength) {
		long limitAddr = loadAddr + prgLength;
		C64BasicWalker.ByteSource src = addr -> {
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
		return C64BasicWalker.isBasicStart(src, loadAddr, limitAddr);
	}

	private static JsonObject loadMap() throws IOException {
		return DescriptorSupport.loadMap(MAP_PATH);
	}

	private static FileDataTypeManager openGdt() throws IOException {
		return DescriptorSupport.openGdt(GDT_PATH);
	}

	// ------------------------------------------------------------------
	// load_target region carve (the one region the generic path can't build: the
	// PRG image lands inside it, and Ghidra can't overlap blocks)
	// ------------------------------------------------------------------

	private void createRamMainSplit(Program program, AddressSpace baseSpace, JsonObject region,
			long loadAddr, long prgLength, MessageLog log) {

		String regionName = region.get("name").getAsString();
		long start = region.get("start").getAsLong();
		long end = region.get("end").getAsLong();
		String comment = region.has("comment") ? region.get("comment").getAsString() : null;
		Perms p = DescriptorSupport.perms(region, "ram");
		long prgEnd = loadAddr + prgLength - 1;
		boolean prgInRange = prgLength > 0 && loadAddr >= start && prgEnd <= end;

		if (!prgInRange) {
			// PRG doesn't land cleanly inside the load-target region (POC scope: log and
			// create the plain region block; the PRG block created separately may
			// overlap/land elsewhere).
			log.appendMsg("PRG load address 0x" + Long.toHexString(loadAddr) +
				" (length " + prgLength + ") does not fit within " + regionName + " [0x" +
				Long.toHexString(start) + ",0x" + Long.toHexString(end) +
				"]; creating " + regionName + " as a single block");
			Address startAddr = baseSpace.getAddress(start);
			MemoryBlockUtils.createUninitializedBlock(program, false, regionName, startAddr,
				end - start + 1, comment, "c64.map", p.readable(), p.writable(), p.executable(), log);
			return;
		}

		// The PRG initialized block occupies part of the region's range, so the surrounding
		// RAM is emitted as separate blocks (Ghidra can't overlap blocks, and join() can't
		// merge an initialized FileBytes block with uninitialized RAM). Address-suffix the
		// carved halves so they never share the region's plain name.
		if (loadAddr > start) {
			Address belowStart = baseSpace.getAddress(start);
			MemoryBlockUtils.createUninitializedBlock(program, false,
				regionName + String.format("_%04X", (int) start), belowStart,
				loadAddr - start, comment, "c64.map", p.readable(), p.writable(), p.executable(), log);
		}
		if (prgEnd < end) {
			Address aboveStart = baseSpace.getAddress(prgEnd + 1);
			MemoryBlockUtils.createUninitializedBlock(program, false,
				regionName + String.format("_%04X", (int) (prgEnd + 1)), aboveStart,
				end - prgEnd, comment, "c64.map", p.readable(), p.writable(), p.executable(), log);
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

	private MemoryBlock createWindowOccupant(Program program, AddressSpace baseSpace,
			JsonObject occupant, JsonObject window, boolean isHome, FileDataTypeManager gdtMgr,
			Map<String, String> romPaths, MessageLog log) {

		String occupantName = occupant.get("name").getAsString();
		String kind = occupant.get("kind").getAsString();
		long start = window.get("start").getAsLong();
		long end = window.get("end").getAsLong();
		long length = end - start + 1;

		if (kind.equals("io")) {
			// The IO occupant is only meaningful when home (CHARIO/IO for POC); its subregions
			// are laid out individually, so there's no single representative block to return.
			if (isHome) {
				DescriptorSupport.createIoSubregions(program, baseSpace, occupant, "c64.map",
					gdtMgr, log);
			}
			return null;
		}

		boolean isOverlay = !isHome;
		Address startAddr = baseSpace.getAddress(start);
		String comment = occupantName + " (" + kind + ")";
		Perms p = DescriptorSupport.perms(occupant, kind);

		// If this is a ROM occupant the user supplied a dump for, initialize it from that file
		// (bead grm-mbm) instead of leaving it empty -- makes ROM code disassemblable and gives
		// ROM->RAM copies (e.g. CHRGET) a real source. Any failure falls back to uninitialized.
		if (occupant.has("image")) {
			String path = romPaths.get(occupant.get("image").getAsString());
			if (path != null) {
				MemoryBlock rom = createRomBlock(program, occupantName, startAddr, length,
					isOverlay, path, p, log);
				if (rom != null) {
					return rom;
				}
			}
		}

		return MemoryBlockUtils.createUninitializedBlock(program, isOverlay, occupantName, startAddr,
			length, comment, "c64.map", p.readable(), p.writable(), p.executable(), log);
	}

	/** Initialize a ROM occupant block from a user-supplied dump file, mirroring
	 *  {@link #createPrgBlock}'s FileBytes pattern. Returns null (caller falls back to an
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
		for (RomSlot slot : ROM_SLOTS) {
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
