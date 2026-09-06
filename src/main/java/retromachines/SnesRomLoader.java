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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import retromachines.SnesAddressMap.Kind;
import retromachines.SnesRomHeader.MapType;

/**
 * Loader for SNES cartridge images ({@code .smc}, {@code .sfc}, {@code .fig}), bead grm-9nxj.9.
 *
 * <p><b>No overlays, no banked windows.</b> Unlike every other loader here, this one lays out a
 * STATIC map: the 65816 addresses 16 MB, cartridges reach 8 MB, and where ROM lands is a
 * cartridge-header lookup rather than a runtime switch. See {@code machines/snes.yaml}'s
 * deliberately empty {@code windows: []}, {@code docs/snes-memory-map-decision.md} for the
 * evidence behind that ruling, and {@code docs/SCHEMA.md}'s "When windows do not apply".
 *
 * <p><b>Mirrors are byte-mapped, not copied.</b> One physical byte of ROM is visible at several
 * addresses (banks {@code $80-$FF} mirror {@code $00-$7F}; a HiROM cartridge is also visible
 * through the system banks' upper halves), and 40% of real call targets measured across 13
 * titles are in the high mirror -- so the mirrors must exist, and duplicating the bytes would
 * double the program for no gain. Each mirror is a {@code createByteMappedBlock} view of the
 * canonical block, which {@code ByteMappedMirrorTest} pins as disassemblable.
 *
 * <p><b>Validation lives in {@link #load}, not in {@code validateOptions}.</b> Per CLAUDE.md,
 * {@code validateOptions()} runs only from the interactive import dialogs -- never headlessly --
 * so a header this loader refuses must be refused HERE, where the banktest harness and
 * {@code analyzeHeadless} actually go through.
 */
public class SnesRomLoader extends AbstractProgramWrapperLoader {

	/** The executable-format name stamped on imports. */
	public static final String NAME = "SNES ROM (LoROM/HiROM)";

	private static final String LANGUAGE_ID = "65816:LE:24:retro";
	private static final String COMPILER_SPEC_ID = "default";
	private static final String MAP_PATH = "machines/snes.map";

	/** Work RAM: the flat 128 KiB at $7E-$7F, and the 8 KiB window mirrored into system banks. */
	private static final long WRAM_START = 0x7E0000L;
	private static final long WRAM_SIZE = 0x20000L;
	private static final long LOW_RAM_SIZE = 0x2000L;

	/**
	 * The system banks that get low-RAM and IO mirrors. Hardware mirrors these into all of
	 * {@code $00-$3F} and {@code $80-$BF}; materializing 128 banks' worth would add several
	 * hundred blocks for windows that are the same registers every time, so this loader creates
	 * them in the two banks real code overwhelmingly uses -- {@code $00} and its FastROM
	 * counterpart {@code $80} -- and says so in the log rather than pretending to be complete.
	 */
	private static final int[] SYSTEM_MIRROR_BANKS = { 0x00, 0x80 };

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		SnesRomHeader header = SnesRomHeader.parse(provider);
		if (header == null || header.mapType() == MapType.UNKNOWN) {
			return loadSpecs;
		}
		String languageId = LANGUAGE_ID;
		try {
			languageId = DescriptorResources.resolveLanguageId(
				DescriptorResources.loadMap(MAP_PATH), LANGUAGE_ID);
		}
		catch (IOException e) {
			// Descriptor unreadable here -> keep the fallback; load() reports it properly.
		}
		loadSpecs.add(new LoadSpec(this,
			0, new LanguageCompilerSpecPair(languageId, COMPILER_SPEC_ID), true));
		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		options.add(new Option(OPTION_MIRRORS, Boolean.TRUE, Boolean.class, null));
		return options;
	}

	/** Whether to materialize the address-space mirrors as byte-mapped views. */
	public static final String OPTION_MIRRORS = "Create mirror blocks";

	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		try {
			loadCartridge(program, settings);
		}
		catch (AddressOverflowException e) {
			// A block that would run past the end of the 24-bit space. That means the image and
			// the declared mapping disagree about how big the cartridge is, which is a refusal
			// rather than something to patch around silently.
			settings.log().appendMsg(NAME + ": memory layout overflows the address space (" +
				e.getMessage() + "); the image and its declared map mode disagree");
		}
	}

	private void loadCartridge(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException,
			AddressOverflowException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		// AUTHORITATIVE VALIDATION. findSupportedLoadSpecs already parsed the header, but a
		// headless caller can reach load() without it, and validateOptions() never runs
		// headlessly at all -- so the refusal has to be here (CLAUDE.md's loader rule).
		SnesRomHeader header = SnesRomHeader.parse(provider);
		if (header == null) {
			log.appendMsg(NAME + ": no plausible SNES cartridge header " +
				"(searched $7FC0/$FFC0/$40FFC0); refusing to guess a memory map");
			return;
		}
		if (header.mapType() == MapType.UNKNOWN) {
			log.appendMsg(NAME + ": unmodelled map mode $" +
				Integer.toHexString(header.mapMode()) + "; refusing to guess a memory map");
			return;
		}
		if (!header.mapTypeMatchesLocation()) {
			// Reported, not refused: the header validated its own checksum, so this is a real
			// cartridge saying something surprising rather than a mis-detection. The map mode
			// is what the hardware wires, so it wins -- but a reader should know.
			log.appendMsg(NAME + ": header declares " + header.mapType() +
				" but was found at offset $" + Integer.toHexString(header.headerOffset()) +
				"; using the declared mapping");
		}
		log.appendMsg(NAME + ": " + header.title() + " -- " + header.mapType() +
			(header.fastRom() ? " (FastROM)" : "") + ", " + (header.romSizeBytes() / 1024) +
			" KiB declared" + (header.copierHeader() ? ", copier header present" : ""));

		long dataOffset = header.dataOffset();
		long cartBytes = provider.length() - dataOffset;
		SnesAddressMap map = SnesAddressMap.of(header, cartBytes);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		boolean mirrors = settings.options() == null ||
			OptionUtils.getBooleanOptionValue(OPTION_MIRRORS, settings.options(), true);

		List<Long> canonicalStarts =
			createRomBlocks(program, space, provider, map, dataOffset, cartBytes, log, monitor);
		createWorkRam(program, space, log);
		if (mirrors) {
			createRomMirrors(program, space, map, canonicalStarts, log);
			createSystemMirrors(program, space, log);
		}
		else {
			log.appendMsg(NAME + ": mirror blocks suppressed by option; addresses in " +
				"banks $80-$FF will not resolve");
		}
		applyDescriptor(program, space, log);
		createVectors(program, space, header, map, log);
	}

	/**
	 * The canonical ROM blocks -- one per mapping unit (32 KiB per bank for LoROM, 64 KiB for
	 * HiROM), initialized from the file. Returns each block's start address so the mirror pass
	 * can map onto them.
	 *
	 * <p>The blocks are cut from the program's {@link FileBytes} rather than from a per-block
	 * {@link java.io.InputStream} (grm-9nxj.10), so each one records WHERE in the image its
	 * bytes came from. Ghidra uses that provenance for re-import, for "restore original bytes"
	 * after a patch, and for telling a user which part of the file a block is; a stream-built
	 * block reports {@code fileOffset=-1} and can offer none of it. The offset stored is into
	 * the FILE, so on a copier-headered image it includes {@code dataOffset} -- the cartridge
	 * offset is in the block comment.
	 */
	private List<Long> createRomBlocks(Program program, AddressSpace space, ByteProvider provider,
			SnesAddressMap map, long dataOffset, long cartBytes, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException,
			AddressOverflowException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		long unit = map.mapType() == MapType.LOROM ? 0x8000L : 0x10000L;
		List<Long> starts = new ArrayList<>();
		for (long fileOffset = 0; fileOffset < cartBytes; fileOffset += unit) {
			monitor.checkCancelled();
			long size = Math.min(unit, cartBytes - fileOffset);
			long address = map.canonicalAddressOf(homeProbe(map, fileOffset));
			Address start = space.getAddress(address);
			String name = String.format("ROM_%02X_%04X", (address >> 16) & 0xFF, address & 0xFFFF);
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name,
				start, fileBytes, dataOffset + fileOffset, size,
				"Cartridge ROM, file offset $" + Long.toHexString(fileOffset), NAME,
				true, false, true, log);
			if (block != null) {
				starts.add(address);
			}
		}
		log.appendMsg(NAME + ": " + starts.size() + " canonical ROM block(s), " +
			(cartBytes / 1024) + " KiB");
		return starts;
	}

	/** An address that maps to {@code fileOffset}, for asking the map where its home is. */
	private static long homeProbe(SnesAddressMap map, long fileOffset) {
		return map.mapType() == MapType.LOROM
				? (((fileOffset / 0x8000) << 16) | (0x8000 + (fileOffset % 0x8000)))
				: 0xC00000L + fileOffset;
	}

	/** Work RAM: one home block for the full 128 KiB. */
	private void createWorkRam(Program program, AddressSpace space, MessageLog log) {
		MemoryBlockUtils.createUninitializedBlock(program, false, "WRAM",
			space.getAddress(WRAM_START), WRAM_SIZE,
			"128 KiB work RAM", NAME, true, true, false, log);
	}

	/** Byte-mapped views of the canonical ROM blocks at every other address they appear. */
	private void createRomMirrors(Program program, AddressSpace space, SnesAddressMap map,
			List<Long> canonicalStarts, MessageLog log) {

		int created = 0;
		for (long canonical : canonicalStarts) {
			MemoryBlock home = program.getMemory().getBlock(space.getAddress(canonical));
			if (home == null) {
				continue;
			}
			for (Mirror mirror : mirrorsOf(map, canonical, home.getSize())) {
				String name = String.format("ROM_%02X_%04X_mirror",
					(mirror.at >> 16) & 0xFF, mirror.at & 0xFFFF);
				try {
					MemoryBlock block = program.getMemory().createByteMappedBlock(name,
						space.getAddress(mirror.at), space.getAddress(mirror.from), mirror.size,
						false);
					block.setRead(true);
					block.setExecute(true);
					block.setComment("Mirror of $" + Long.toHexString(mirror.from));
					created++;
				}
				catch (Exception e) {
					log.appendMsg(NAME + ": could not mirror $" + Long.toHexString(mirror.from) +
						" at $" + Long.toHexString(mirror.at) + ": " + e.getMessage());
				}
			}
		}
		log.appendMsg(NAME + ": " + created + " byte-mapped ROM mirror block(s)");
	}

	/**
	 * One byte-mapped view: {@code size} bytes appearing at {@code at}, sourced from {@code from}
	 * inside a canonical block. All three fields are needed because a mirror is not always the
	 * WHOLE home block -- a HiROM system-bank window shows only its upper half (grm-9nxj.18).
	 */
	private record Mirror(long at, long from, long size) {}

	/**
	 * Every OTHER place the bytes of the canonical block at {@code canonical} appear. LoROM's
	 * home is the low banks, so its one mirror is the whole block at {@code +$800000}; HiROM's
	 * home is the linear {@code $C0-$FF} view, whose UPPER HALF also appears at
	 * {@code $8000-$FFFF} of the corresponding system bank (and, for the first 4 MiB, in
	 * {@code $40-$7D} -- not materialized here, see the log line in load()).
	 *
	 * <p>The half-bank arithmetic is the point (grm-9nxj.18): sizing a system-bank mirror with
	 * the home block's full 64 KiB spills 32 KiB into the NEXT bank's low half, which is RAM/IO
	 * territory where no cartridge ROM is mapped at all, and sourcing it from the bank's low
	 * half shows the wrong bytes. A trailing home block shorter than 32 KiB has nothing in its
	 * upper half and so has no system-bank mirror.
	 */
	private List<Mirror> mirrorsOf(SnesAddressMap map, long canonical, long homeSize) {
		List<Mirror> out = new ArrayList<>();
		if (map.mapType() == MapType.LOROM) {
			out.add(new Mirror(canonical + 0x800000L, canonical, homeSize));
			return out;
		}
		long fileOffset = canonical - 0xC00000L;
		long bank = fileOffset / 0x10000L;
		if (bank > 0x3F || homeSize <= 0x8000L) {
			return out;
		}
		long from = canonical + 0x8000L;
		long size = homeSize - 0x8000L;
		out.add(new Mirror((bank << 16) | 0x8000L, from, size));
		out.add(new Mirror(((bank + 0x80) << 16) | 0x8000L, from, size));
		return out;
	}

	/** Low-RAM mirrors in the banks real code uses. */
	private void createSystemMirrors(Program program, AddressSpace space, MessageLog log) {
		for (int bank : SYSTEM_MIRROR_BANKS) {
			long at = ((long) bank) << 16;
			if (program.getMemory().getBlock(space.getAddress(at)) != null) {
				continue;
			}
			try {
				MemoryBlock block = program.getMemory().createByteMappedBlock(
					String.format("LOWRAM_%02X", bank), space.getAddress(at),
					space.getAddress(WRAM_START), LOW_RAM_SIZE, false);
				block.setRead(true);
				block.setWrite(true);
				block.setComment("First 8 KiB of work RAM, mirrored into bank $" +
					Integer.toHexString(bank));
			}
			catch (Exception e) {
				log.appendMsg(NAME + ": could not mirror low RAM into bank $" +
					Integer.toHexString(bank) + ": " + e.getMessage());
			}
		}
		log.appendMsg(NAME + ": low-RAM mirrors created in banks $00 and $80 only; other " +
			"system banks mirror the same registers and are left unmapped");
	}

	/** IO regions, their typed subregions, and the register names, from machines/snes.map. */
	private void applyDescriptor(Program program, AddressSpace space, MessageLog log) {
		JsonObject map;
		try {
			map = DescriptorResources.loadMap(MAP_PATH);
		}
		catch (IOException e) {
			log.appendMsg(NAME + ": descriptor " + MAP_PATH + " unreadable (" + e.getMessage() +
				"); IO regions and register names will be missing");
			return;
		}
		// Record WHICH descriptor this program was loaded against. Analyzers read it back
		// (see CopyLoopAnalyzer, DescriptorCopyHintAnalyzer) rather than re-deriving the
		// machine from the executable format, so a program without it is a program later
		// passes cannot interpret.
		program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorSupport.MAP_PATH_PROPERTY, MAP_PATH);

		for (JsonElement e : map.getAsJsonArray("regions")) {
			JsonObject region = e.getAsJsonObject();
			if (!"io".equals(region.get("kind").getAsString())) {
				continue;   // WRAM is created above, with its mirrors
			}
			DescriptorMemory.createRegionBlock(program, space, region, NAME, null, log);
			if (region.has("subregions")) {
				DescriptorMemory.createIoSubregions(program, space, region, NAME, null, log);
			}
		}

		// The register names and the vector labels. Without this the IO blocks exist but every
		// store reads as a bare address, which is most of what a descriptor is FOR.
		for (JsonElement e : map.getAsJsonArray("symbols")) {
			JsonObject set = e.getAsJsonObject();
			if (set.has("default") && set.get("default").getAsBoolean()) {
				DescriptorSupport.applySymbolSet(program, space, set, null, log);
			}
		}
	}

	/**
	 * The CPU vectors as labels, and the reset vector's target as the program's entry point.
	 * The vectors' own addresses are labelled from the descriptor; the RESET target is what
	 * gives analysis somewhere to start.
	 */
	private void createVectors(Program program, AddressSpace space, SnesRomHeader header,
			SnesAddressMap map, MessageLog log) {

		int reset = header.resetVector();
		long resetAddress = reset;                  // the reset vector runs in bank $00
		if (map.kindOf(resetAddress) != Kind.ROM) {
			log.appendMsg(NAME + ": reset vector $" + Integer.toHexString(reset) +
				" does not point into ROM; no entry point created");
			return;
		}
		try {
			Address entry = space.getAddress(resetAddress);
			program.getSymbolTable().createLabel(entry, "RESET", SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(entry);
			log.appendMsg(NAME + ": entry point at $" + Long.toHexString(resetAddress) +
				" (emulation-mode reset)");
		}
		catch (Exception e) {
			log.appendMsg(NAME + ": could not create the reset entry point: " + e.getMessage());
		}
	}
}
