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
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

/**
 * Loader for NES ROM images in iNES format ({@code .nes}).
 * <p>
 * Parses the 16-byte iNES header (magic, PRG/CHR sizes, mapper number, trainer flag),
 * resolves the mapper number to a board descriptor through {@link NesBoardRegistry}
 * (user-overridable via the "NES Board" import option), and builds the CPU-space
 * memory map entirely from the bundled {@code machines/&lt;board&gt;.map} descriptor:
 * always-visible regions with MMIO register structs and symbols, plus computed PRG
 * windows placed by evaluating their {@code maps:} expressions against the image size
 * (NROM: {@code PRG[0]} and {@code PRG[last]}, which yields the NROM-128 mirror and
 * the NROM-256 split with no special-casing). Reset/NMI/IRQ vector targets are
 * labeled and registered as entry points so analysis disassembles them.
 * <p>
 * CHR ROM is deliberately <b>not</b> loaded into CPU space (it lives on the PPU bus;
 * modeling non-CPU spaces is deferred — vision doc §5.4). Bank-state-dependent
 * windows (the discrete mappers' switchable PRG) get the "home-in-base" overlay
 * layout: the initial-state bank in base space, every other bank as an overlay block
 * {@code <window>_B<bank>} for {@link NesBankingAnalyzer} to retarget references into.
 * Mode-dependent window sets ({@code memory.layouts[]}, e.g. MMC3's prg_mode) are
 * normalized through {@link DescriptorSupport#planWindows} and realized the same way
 * per layout, with non-home layouts' instances as mode-qualified overlays
 * ({@code <window>_M<mode>} / {@code <window>_M<mode>_B<bank>}).
 */
public class NesRomLoader extends AbstractProgramWrapperLoader {

	static final String BOARD_OPTION_NAME = "NES Board";

	/**
	 * User bank-placement override: space-separated {@code window:bank} pairs (e.g.
	 * {@code "W8000:5"}) pinning a mode-varying switchable window to hold PRG bank N where
	 * dataflow could not recover it. Persisted verbatim into
	 * {@link DescriptorSupport#PLACEMENT_OVERRIDE_PROPERTY}; {@link NesBankingAnalyzer}
	 * re-parses and applies it. Headless arg: {@code -loader-placement W8000:5} (colon
	 * separator, not '=': cmd.exe's analyzeHeadless.bat splits arg values on '=').
	 */
	static final String PLACEMENT_OPTION_NAME = "NES Placement Override";

	private static final String PLACEMENT_CMD_ARG = Loader.COMMAND_LINE_ARG_PREFIX + "-placement";

	private static final String LANGUAGE_ID = "6502:LE:16:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final int INES_HEADER_LEN = 16;
	private static final int TRAINER_LEN = 512;
	private static final long TRAINER_ADDR = 0x7000;

	/** A computed window this load placed: where it sits in CPU space and which PRG
	 *  offset backs it. Used to route vector-table reads through the same mapping. */
	private record PlacedWindow(String name, long cpuStart, long cpuEnd, long srcOffset) {}

	/** The iNES header facts this loader consumes. Sizes are BYTES, not header unit counts:
	 *  NES 2.0's exponent form (see {@link InesHeader#nes2RomSize}) can express a size that is
	 *  not a whole number of 16 KiB PRG / 8 KiB CHR units, so a unit count cannot represent every
	 *  legal header. */
	private record InesHeader(long prgSize, long chrSize, int mapper, boolean trainer) {

		/** File offset where PRG content starts (header, then optional trainer). */
		long prgFileOffset() {
			return INES_HEADER_LEN + (trainer ? TRAINER_LEN : 0);
		}

		/**
		 * Decodes one of NES 2.0's two ROM-size pairs to a byte count: {@code low} is the
		 * unit-count low byte (h[4] for PRG, h[5] for CHR), {@code hi} the matching nibble of
		 * h[9], and {@code unit} that ROM's unit size.
		 * <p>
		 * {@code hi == 0xF} selects the EXPONENT form, where {@code low} is not a count at all but
		 * {@code EEEEEEMM}, and the size is {@code 2^E * (2M+1)} <em>bytes</em>. It exists to
		 * express what the linear form cannot, at both ends of the range -- oversized multicarts
		 * above the 4095-unit ceiling, and images BELOW one unit. The local corpus holds only the
		 * latter (bead grm-dfj): both Galaxian (J) revisions and Controller Test Program (J) carry
		 * h[4] = 0x34, i.e. E = 13 and M = 0, for a PRG of 2^13 = 8 KiB -- half of one 16 KiB unit.
		 * Before this was decoded, those three fell back to h[4] alone, claimed 52 banks = 832K
		 * against a 16400-byte file, and were rejected by {@code load}'s truncation guard as
		 * corrupt.
		 * <p>
		 * The exponent is 6 bits, so an absurd one would overflow {@code long} and could go
		 * negative -- which the truncation guard compares as smaller than the file and would wave
		 * through, the one failure mode worse than refusing the image. Anything at or above 2^48
		 * (far past any conceivable cartridge) is therefore reported as 0, joining a zero unit
		 * count on the existing "no usable PRG slice" path.
		 */
		private static long nes2RomSize(int low, int hi, int unit) {
			if (hi != 0x0F) {
				return (((hi << 8) | low) & 0xFFFL) * (long) unit;
			}
			int exponent = low >> 2;
			if (exponent >= 48) {
				return 0;
			}
			return (1L << exponent) * (((low & 0x03) * 2L) + 1);
		}

		static InesHeader parse(ByteProvider provider) throws IOException {
			if (provider.length() < INES_HEADER_LEN) {
				return null;
			}
			byte[] h = provider.readBytes(0, INES_HEADER_LEN);
			if (h[0] != 'N' || h[1] != 'E' || h[2] != 'S' || h[3] != 0x1A) {
				return null;
			}
			int lowMapper = (h[6] & 0xFF) >> 4;
			boolean nes2 = (h[7] & 0x0C) == 0x08;
			int mapper;
			long prgSize;
			long chrSize;
			if (nes2) {
				// NES 2.0: 12-bit mapper (flags6 hi | flags7 hi | flags8 lo); each ROM size is a
				// low byte (h[4] / h[5]) plus a nibble of h[9], in either a linear or an exponent
				// form -- nes2RomSize decodes both.
				mapper = ((h[8] & 0x0F) << 8) | (h[7] & 0xF0) | lowMapper;
				prgSize = nes2RomSize(h[4] & 0xFF, h[9] & 0x0F, 0x4000);
				chrSize = nes2RomSize(h[5] & 0xFF, (h[9] & 0xFF) >> 4, 0x2000);
			}
			else {
				// Archaic iNES: "DiskDude!"-style tools scribbled ASCII into bytes 7-15, so a
				// non-zero tail (bytes 12-15) means flags7's high nibble is not a real mapper
				// nibble -- trust only the low nibble. A clean iNES 1.0 header has 12-15 zero.
				boolean archaic = h[12] != 0 || h[13] != 0 || h[14] != 0 || h[15] != 0;
				mapper = archaic ? lowMapper : ((h[7] & 0xF0) | lowMapper);
				prgSize = (h[4] & 0xFF) * 0x4000L;
				chrSize = (h[5] & 0xFF) * 0x2000L;
			}
			return new InesHeader(prgSize, chrSize, mapper, (h[6] & 0x04) != 0);
		}
	}

	/**
	 * This image's per-game identity (bead grm-hb6.1) -- SHA-256 over the PRG slice, excluding
	 * the 16-byte iNES header and any trainer, plus SHA-256 over the whole file -- or
	 * {@code null} when the image has no identity this loader is willing to claim.
	 * <p>
	 * The PRG digest is the primary key precisely because header rot is endemic: headerless
	 * dumps, headers "corrected" by a ROM manager, NES 2.0 headers regenerated over iNES 1.0
	 * originals and {@code DiskDude!}-scribbled archaic headers (special-cased in
	 * {@link InesHeader#parse}) all differ as whole files while carrying identical PRG content,
	 * about which every claim in a descriptor is equally true.
	 * <p>
	 * Computed from the {@link ByteProvider} at import, never read back from {@code Memory}:
	 * that would mean reassembling PRG order from the window/overlay layout -- loader policy,
	 * and mode-dependent -- and would silently change meaning the first time an analyzer patched
	 * a byte.
	 * <p>
	 * Declines (returns {@code null}) for bad magic, a zero declared PRG size, and a PRG slice
	 * running past EOF. Each of those would still yield a well-formed 64-hex key -- for a zero
	 * size, the fixed empty-input digest that every such file would share -- and a wrong key is
	 * invisible where an absent one is diagnosable. The NES 2.0 exponent PRG-size form was on
	 * that list until grm-dfj decoded it; those images now key over their true slice like any
	 * other.
	 * Package-private so a pure-JUnit test can drive it over synthetic images.
	 */
	static DescriptorSupport.GameIdentity gameIdentity(ByteProvider provider) throws IOException {
		InesHeader header = InesHeader.parse(provider);
		if (header == null || header.prgSize() == 0) {
			return null;
		}
		long prgOffset = header.prgFileOffset();
		long prgLength = header.prgSize();
		if (prgOffset + prgLength > provider.length()) {
			return null;
		}
		String prgSha;
		try (InputStream in = provider.getInputStream(prgOffset)) {
			prgSha = DescriptorSupport.sha256Hex(in, prgLength);
		}
		String fileSha;
		try (InputStream in = provider.getInputStream(0)) {
			fileSha = DescriptorSupport.sha256Hex(in, -1);
		}
		return new DescriptorSupport.GameIdentity(prgSha, fileSha);
	}

	/** The executable-format name stamped on imports; gated on by {@link NesBankingAnalyzer}. */
	public static final String NAME = "NES ROM (iNES)";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		InesHeader header = InesHeader.parse(provider);
		if (header == null || header.prgSize() == 0) {
			return loadSpecs;
		}
		// Only offer the loader when a board descriptor exists for the mapper; other
		// mappers fall through to the raw-binary loader until their boards land.
		NesBoardRegistry.Board board = NesBoardRegistry.forMapper(header.mapper());
		if (board == null) {
			return loadSpecs;
		}

		// Load with the descriptor's declared language; fall back to the stock constant only
		// if that language is unavailable. See DescriptorResources.resolveLanguageId.
		String languageId = LANGUAGE_ID;
		try {
			languageId = DescriptorResources.resolveLanguageId(DescriptorResources.loadMap(board.mapPath()),
				LANGUAGE_ID);
		}
		catch (IOException e) {
			// descriptor unreadable here -> keep the safety fallback; load() will report it
		}
		LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair(languageId, COMPILER_SPEC_ID);
		loadSpecs.add(new LoadSpec(this, 0, pair, true));

		// Second, NON-preferred choice: the undocumented-opcode variant (bead grm-azg). NES
		// games lean on these at least as hard as C64 code does. Kept out of the default for
		// the usual reason -- with all 256 bytes decodable, disassembly runs through the
		// graphics and music tables that fill a PRG bank instead of stopping.
		String undocId = DescriptorResources.undocVariantOf(languageId);
		if (undocId != null) {
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(undocId, COMPILER_SPEC_ID), false));
		}
		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		String defaultBoard = "";
		try {
			InesHeader header = InesHeader.parse(provider);
			if (header != null) {
				NesBoardRegistry.Board board = NesBoardRegistry.forMapper(header.mapper());
				if (board != null) {
					defaultBoard = board.id();
				}
			}
		}
		catch (IOException e) {
			// leave the default empty; validateOptions/load will complain if it matters
		}
		options.add(new Option(BOARD_OPTION_NAME, defaultBoard));
		options.add(new Option(PLACEMENT_OPTION_NAME, "", String.class, PLACEMENT_CMD_ARG));
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String boardId = OptionUtils.getOption(BOARD_OPTION_NAME, options, "");
		if (!boardId.isEmpty() && NesBoardRegistry.forId(boardId) == null) {
			List<String> known =
				NesBoardRegistry.boards().stream().map(NesBoardRegistry.Board::id).toList();
			return "Unknown NES board '" + boardId + "'; known boards: " + known;
		}

		String placement = OptionUtils.getOption(PLACEMENT_OPTION_NAME, options, "");
		if (placement != null && !placement.isBlank()) {
			Map<String, Integer> pairs;
			try {
				pairs = DescriptorSupport.parsePlacementOverride(placement);
			}
			catch (IllegalArgumentException e) {
				return PLACEMENT_OPTION_NAME + ": " + e.getMessage();
			}
			// Window-name / bank-range checks need the descriptor + header. If the image can't
			// be read, skip them (syntax is already validated; load() surfaces image errors).
			// NB: in Ghidra 12.x validateOptions runs only from the GUI import dialogs, NOT the
			// headless ProgramLoader path -- load() re-runs this same check as the headless
			// safety net (see placementError there).
			try {
				InesHeader header = InesHeader.parse(provider);
				NesBoardRegistry.Board board = boardId.isEmpty()
						? (header == null ? null : NesBoardRegistry.forMapper(header.mapper()))
						: NesBoardRegistry.forId(boardId);
				if (header != null && board != null) {
					String err = placementError(pairs, board, header);
					if (err != null) {
						return err;
					}
				}
			}
			catch (IOException e) {
				// best-effort semantic check only; load() reports a truncated/bad image
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	/**
	 * First validation error in a parsed placement override against {@code board}'s
	 * descriptor -- an unknown window name, a window with no bank to place, or a bank the
	 * image cannot back -- or null if every pair is well-formed. Shared by
	 * {@link #validateOptions} (GUI reject) and {@link #load} (headless safety net), so both
	 * routes accept exactly the same overrides.
	 * <p>
	 * The legal bank set is per window, computed by
	 * {@link DescriptorSupport#placeableBanks} from that window's own expression and length
	 * against the PRG byte size -- <em>not</em> from the iNES header's 16 KiB bank count,
	 * which is a container unit unrelated to what a given window's bank field selects
	 * (bead grm-n5f: a 32 KiB MMC3 image has four placeable 8 KiB banks but a header bank
	 * count of 2). This is the same predicate the realization loops in
	 * {@link #realizeInvariantWindow} / {@link #realizeVaryingWindows} use to decide which
	 * bank overlays to create, so validation accepts a bank exactly when the load can
	 * realize a block for it.
	 */
	private static String placementError(Map<String, Integer> pairs, NesBoardRegistry.Board board,
			InesHeader header) throws IOException {
		JsonObject map = DescriptorResources.loadMap(board.mapPath());
		Map<String, NavigableSet<Integer>> placeable = DescriptorSupport.placeableBanks(map,
			header.prgSize(), new MessageLog(), board.mapPath());
		return placementError(pairs, placeable, board.id(), header.prgSize());
	}

	/**
	 * The descriptor-free half of {@link #placementError(Map, NesBoardRegistry.Board,
	 * InesHeader)}: checks parsed pairs against an already-computed legal bank set. Split out
	 * so the rule is exercisable without an {@code Application} bootstrap
	 * ({@code NesPlacementValidationTest}); the loader route only adds descriptor loading.
	 */
	static String placementError(Map<String, Integer> pairs,
			Map<String, NavigableSet<Integer>> placeable, String boardId, long prgSize) {
		for (Map.Entry<String, Integer> pair : pairs.entrySet()) {
			NavigableSet<Integer> banks = placeable.get(pair.getKey());
			if (banks == null) {
				return PLACEMENT_OPTION_NAME + ": unknown window '" + pair.getKey() +
					"' for board " + boardId + "; known windows: " + placeable.keySet();
			}
			if (banks.isEmpty()) {
				return PLACEMENT_OPTION_NAME + ": window '" + pair.getKey() + "' on board " +
					boardId + " holds no switchable bank, so there is nothing to override";
			}
			if (!banks.contains(pair.getValue())) {
				return PLACEMENT_OPTION_NAME + ": bank " + pair.getValue() +
					" out of range for window '" + pair.getKey() + "' (board " + boardId +
					", " + (prgSize / 1024) + "K PRG); placeable banks: " + describeBanks(banks);
			}
		}
		return null;
	}

	/** Compact rendering of a legal bank set for an error message: {@code "0-3"} when the
	 *  set is the contiguous run it almost always is, the explicit set otherwise (a
	 *  descriptor whose expression skips values -- e.g. an alignment mask -- must not be
	 *  described as a range it isn't). */
	private static String describeBanks(NavigableSet<Integer> banks) {
		int lo = banks.first();
		int hi = banks.last();
		if (hi - lo + 1 == banks.size()) {
			return lo == hi ? String.valueOf(lo) : lo + "-" + hi;
		}
		return banks.toString();
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// The descriptor memory map already covers the 6502 pspec's ZERO_PAGE/STACK
		// ranges; suppress the stock loader's conflict log noise (bead grm-rua).
		DescriptorMemory.createDefaultMemoryBlocksQuietly(program, settings.log());
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();

		InesHeader header = InesHeader.parse(provider);
		if (header == null) {
			log.appendMsg("Not an iNES file (bad magic)");
			return;
		}

		// The header's declared PRG size is trusted throughout (window placement, the
		// $FFFA-$FFFF vector read); a body shorter than declared would place windows over
		// bytes past EOF, and the unguarded vector read would then throw IOException out of
		// load() -- an exception dialog instead of a diagnosable message. Reject up front.
		long declaredEnd = header.prgFileOffset() + header.prgSize();
		if (declaredEnd > provider.length()) {
			log.appendMsg("Truncated iNES image: header declares PRG through file offset " +
				declaredEnd + " but the file is only " + provider.length() +
				" bytes; refusing to load a truncated ROM");
			return;
		}

		// Per-game identity (bead grm-hb6.1, docs/per-game-descriptors-design.md section 2): a
		// fact about the FILE, so it is derived here -- after the truncation guard above proves
		// the PRG slice readable, and before any board policy runs, since identity neither
		// depends on which board won nor may be lost to the no-board return below. It is
		// recorded even when nothing consumes it: the logged value is the key a user pastes
		// into an overlay descriptor.
		DescriptorSupport.GameIdentity identity = gameIdentity(provider);
		if (identity != null) {
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorSupport.GAME_IDENTITY_PROPERTY,
						identity.toPropertyValue());
			log.appendMsg("game identity " + identity.toPropertyValue());
		}
		else {
			log.appendMsg("iNES header declares no usable PRG slice; skipping game identity");
		}

		String boardId = OptionUtils.getOption(BOARD_OPTION_NAME, settings.options(), "");
		NesBoardRegistry.Board board = boardId.isEmpty() ? NesBoardRegistry.forMapper(header.mapper())
				: NesBoardRegistry.forId(boardId);
		if (board == null) {
			log.appendMsg("No board descriptor for iNES mapper " + header.mapper() +
				" (and no override given); cannot load");
			return;
		}
		log.appendMsg("iNES mapper " + header.mapper() + " -> board " + board.id() + " (" +
			board.name() + "); PRG " + (header.prgSize() / 1024) + "K, CHR " +
			(header.chrSize() / 1024) + "K" + (header.trainer() ? ", trainer" : ""));

		// record the chosen board so the bank analyzer interprets with the same descriptor
		program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorSupport.MAP_PATH_PROPERTY, board.mapPath());

		// record a user placement override for the analyzer to apply to unresolved bank
		// placements. validateOptions already vetted this in the GUI, but the headless
		// ProgramLoader path never calls validateOptions (Ghidra 12.x), so re-check here and
		// refuse a malformed/inapplicable override rather than persisting a misleading one.
		String placement = OptionUtils.getOption(PLACEMENT_OPTION_NAME, settings.options(), "");
		if (placement != null && !placement.isBlank()) {
			Map<String, Integer> pairs;
			try {
				pairs = DescriptorSupport.parsePlacementOverride(placement);
			}
			catch (IllegalArgumentException e) {
				log.appendMsg(PLACEMENT_OPTION_NAME + ": " + e.getMessage() +
					" -- refusing to import with an invalid placement override");
				return;
			}
			String err = placementError(pairs, board, header);
			if (err != null) {
				log.appendMsg(err + " -- refusing to import with an invalid placement override");
				return;
			}
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorSupport.PLACEMENT_OVERRIDE_PROPERTY, placement.trim());
			log.appendMsg("placement override: " + placement.trim());
		}

		JsonObject map = DescriptorResources.loadMap(board.mapPath());

		FileDataTypeManager gdtMgr = null;
		try {
			gdtMgr = DescriptorResources.openGdt(board.gdtPath());
		}
		catch (IOException e) {
			log.appendMsg("No data-type archive " + board.gdtPath() + ": " + e.getMessage());
		}

		try {
			AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

			// --- Always-visible regions (MMIO structs applied from their type:) ---
			for (JsonElement re : map.getAsJsonArray("regions")) {
				DescriptorMemory.createRegionBlock(program, baseSpace, re.getAsJsonObject(),
					board.mapPath(), gdtMgr, log);
			}

			FileBytes fileBytes =
				MemoryBlockUtils.createFileBytes(program, provider, settings.monitor());

			// --- Trainer (rare; 512 bytes conventionally mapped at $7000) ---
			if (header.trainer()) {
				try {
					MemoryBlockUtils.createInitializedBlock(program, false, "TRAINER",
						baseSpace.getAddress(TRAINER_ADDR), fileBytes, INES_HEADER_LEN, TRAINER_LEN,
						"iNES trainer", board.mapPath(), true, true, true, log);
				}
				catch (Exception e) {
					log.appendMsg("Failed to create TRAINER block: " + e.getMessage());
				}
			}

			// --- PRG windows: computed slices of the PRG image ---
			// Fixed windows (constant maps: expr) become one base-space block. Bank-state-
			// dependent windows get the "home-in-base" overlay layout: the initial-state
			// bank's slice is the base-space block (references resolve there by default);
			// every other in-range bank value gets an overlay block <name>_B<value> that
			// the bank analyzer retargets references into.
			List<PlacedWindow> placed = new ArrayList<>();
			List<DescriptorSupport.StateField> fields = DescriptorSupport.parseStateFields(map);
			// Image-relative seeds (banking.initial_state_expr, bead grm-y0ml) resolve HERE:
			// the PRG size is a load-time fact, so the .map keeps the expression symbolic and
			// this is the first place it can be evaluated. Published below for the analyzer,
			// which has no image size of its own.
			Long initialState =
				DescriptorSupport.resolveInitialState(map, header.prgSize(), log, board.mapPath());
			if (initialState != null &&
				!initialState.equals(DescriptorSupport.initialState(map))) {
				program.getOptions(Program.PROGRAM_INFO).setString(
					DescriptorSupport.INITIAL_STATE_PROPERTY, Long.toString(initialState));
				log.appendMsg("banking.initial_state resolved to " + initialState +
					" against the " + header.prgSize() + "-byte PRG image");
			}
			DescriptorSupport.LayoutPlan plan =
				DescriptorSupport.planWindows(map, log, board.mapPath());

			for (DescriptorSupport.PlannedWindow pw : plan.invariant()) {
				realizeInvariantWindow(program, baseSpace, pw, fields, initialState, header,
					fileBytes, board.mapPath(), placed, log);
			}
			if (plan.modeField() != null && !plan.varying().isEmpty()) {
				realizeVaryingWindows(program, baseSpace, plan, fields, initialState, header,
					fileBytes, board.mapPath(), placed, log);
			}

			if (header.chrSize() > 0) {
				log.appendMsg("CHR ROM (" + (header.chrSize() / 1024) +
					"K) not loaded: PPU address space modeling is deferred");
			}

			// --- Default-on symbol sets (MMIO labels, vector slot labels) ---
			for (JsonElement se : map.getAsJsonArray("symbols")) {
				JsonObject set = se.getAsJsonObject();
				if (set.has("default") && set.get("default").getAsBoolean()) {
					DescriptorSupport.applySymbolSet(program, baseSpace, set,
						(name, addr) -> markAsFunction(program, name, addr), log);
				}
			}

			// --- Vectors: label targets and register entry points ---
			labelVectorTargets(program, baseSpace, provider, header, placed, log);
		}
		finally {
			if (gdtMgr != null) {
				gdtMgr.close();
			}
		}
	}

	/**
	 * Reads the 6502 vector table ($FFFA NMI, $FFFC RESET, $FFFE IRQ) out of whichever
	 * placed window covers it, labels each handler, and registers it as an external
	 * entry point (with a function) so auto-analysis disassembles from it. Also types
	 * the three vector slots as pointers so the table reads as a table.
	 */
	private void labelVectorTargets(Program program, AddressSpace baseSpace, ByteProvider provider,
			InesHeader header, List<PlacedWindow> placedWindows, MessageLog log)
			throws IOException {

		// 'async' marks a vector the CPU takes from arbitrary mainline context, so a handler
		// reached through it starts with the bank the interrupted code left live -- not
		// banking.initial_state. RESET is the one entry the initial state is actually true
		// for. Recorded for the analyzer's dataflow seeding (bead grm-913).
		record Vector(long slot, String handlerName, boolean async) {}
		List<Vector> vectors = List.of(new Vector(0xFFFA, "NMI", true),
			new Vector(0xFFFC, "RESET", false), new Vector(0xFFFE, "IRQ", true));
		// A set, not a list: a ROM whose NMI and IRQ vectors point at the same stub -- which
		// every synthetic fixture here does, and real cartridges do too -- would otherwise
		// list that address twice. Harmless to the read side, which is a set, but the property
		// is user-visible in Program Info.
		Set<Address> asyncEntries = new LinkedHashSet<>();

		for (Vector vector : vectors) {
			Long fileOffset = fileOffsetOf(vector.slot(), header, placedWindows);
			if (fileOffset == null) {
				log.appendMsg("No placed window covers vector slot $" +
					Long.toHexString(vector.slot()) + "; skipping it");
				continue; // other slots may still be covered (e.g. RESET/IRQ after NMI)
			}
			byte[] bytes = provider.readBytes(fileOffset, 2);
			long target = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8);
			if (fileOffsetOf(target, header, placedWindows) == null) {
				log.appendMsg("Vector " + vector.handlerName() + " target $" +
					Long.toHexString(target) + " is not in mapped ROM; skipping");
				continue;
			}
			try {
				Address slotAddr = baseSpace.getAddress(vector.slot());
				DataUtilities.createData(program, slotAddr, PointerDataType.dataType, -1,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

				Address targetAddr = baseSpace.getAddress(target);
				program.getSymbolTable().createLabel(targetAddr, vector.handlerName(),
					SourceType.IMPORTED);
				program.getSymbolTable().addExternalEntryPoint(targetAddr);
				markAsFunction(program, vector.handlerName(), targetAddr);
				if (vector.async()) {
					asyncEntries.add(targetAddr);
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to label vector " + vector.handlerName() + ": " +
					e.getMessage());
			}
		}

		// Written only when non-empty: an absent property and an empty one mean the same
		// thing to the read side, and not writing it keeps the Program Info display clean
		// for a ROM whose vector table fell outside the mapped windows.
		if (!asyncEntries.isEmpty()) {
			program.getOptions(Program.PROGRAM_INFO).setString(
				DescriptorSupport.ASYNC_ENTRY_POINTS_PROPERTY,
				DescriptorSupport.formatAsyncEntryPoints(asyncEntries));
		}
	}

	/**
	 * Realizes one mode-invariant window (a top-level {@code memory.windows[]} entry, or a
	 * {@code memory.layouts[]} window hoisted because every layout defines it identically):
	 * a fixed {@code maps:} expression becomes one base-space block; a switchable
	 * expression (referencing exactly one {@code banking.state} field, resolved by name
	 * against {@code fields} -- not necessarily the first declared field) gets the
	 * "home-in-base" overlay layout ({@code name} in base space for the initial-state bank,
	 * {@code <name>_B<bank>} overlays for every other in-range bank).
	 */
	private static void realizeInvariantWindow(Program program, AddressSpace baseSpace,
			DescriptorSupport.PlannedWindow pw, List<DescriptorSupport.StateField> fields,
			Long initialState, InesHeader header, FileBytes fileBytes, String mapPath,
			List<PlacedWindow> placed, MessageLog log) {

		String name = pw.name();
		if (pw.expr() == null) {
			log.appendMsg("Window '" + name +
				"' has enumerated occupants; not supported by this loader (C64-style " +
				"overlay layout is the C64 loader's job)");
			return;
		}
		long start = pw.start();
		long end = pw.end();
		long length = pw.length();
		String expr = pw.expr();

		try {
			long srcOffset = DescriptorExpressions.evalConstantExpr(expr, header.prgSize(), length);
			WindowBacking backing = resolveBacking(name, expr, srcOffset, length, header, log);
			if (backing != null) {
				createWindowBlocks(program, baseSpace, false, name,
					name + " = PRG[" + expr + "] (offset 0x" +
						Long.toHexString(backing.srcOffset()) + ")",
					start, length, fileBytes, header.prgFileOffset() + backing.srcOffset(),
					backing.repeats(), mapPath, log);
				placed.add(new PlacedWindow(name, start, end, backing.srcOffset()));
			}
			return;
		}
		catch (IllegalArgumentException e) {
			// falls through to the bank-state-dependent path below
		}

		Set<String> exprFields = DescriptorExpressions.referencedFields(expr);
		DescriptorSupport.StateField field = exprFields.size() == 1
				? DescriptorSupport.findField(fields, exprFields.iterator().next())
				: null;
		if (field == null) {
			log.appendMsg("Window '" + name + "' skipped: '" + expr +
				"' needs exactly one banking.state field" +
				(fields.isEmpty() ? " but the descriptor has no banking section"
						: " (references " + exprFields + ")"));
			return;
		}
		long fieldInitial = initialState == null ? 0 : field.valueIn(initialState);

		// Build one named candidate per in-range bank value, then hand them to the shared
		// home-in-base placement policy (DescriptorSupport.placeHomeInBaseWindow); only the
		// home candidate's srcOffset is needed here (for PlacedWindow bookkeeping), so we
		// stash offsets by block name as we build the list.
		Map<String, Long> srcOffsetsByName = new HashMap<>();
		List<DescriptorSupport.NamedCandidate> candidates = new ArrayList<>();
		for (long v = 0; v < (1L << field.width()); v++) {
			long srcOffset =
				DescriptorExpressions.evalExpr(expr, header.prgSize(), length, Map.of(field.name(), v));
			if (srcOffset < 0 || srcOffset + length > header.prgSize()) {
				continue; // bank values beyond the image simply don't exist
			}
			boolean home = v == fieldInitial;
			// see DescriptorSupport.OverlayNaming for why blockName doubling as the overlay
			// AddressSpace's name is safe to rely on here.
			String blockName =
				home ? name : DescriptorSupport.OverlayNaming.bankBlockName(name, (int) v);
			srcOffsetsByName.put(blockName, srcOffset);
			String windowComment = name + " = PRG[" + expr + "], " + field.name() + "=" + v +
				" (offset 0x" + Long.toHexString(srcOffset) +
				(home ? ", home bank in base space)" : ")");
			long fileOffset = header.prgFileOffset() + srcOffset;
			candidates.add(new DescriptorSupport.NamedCandidate(blockName,
				(p, bs, isHome, l) -> createWindowBlock(p, bs, !isHome, blockName, windowComment,
					start, length, fileBytes, fileOffset, mapPath, l)));
		}
		DescriptorSupport.placeHomeInBaseWindow(program, baseSpace, candidates, name, log);
		Long homeSrcOffset = srcOffsetsByName.get(name);
		if (homeSrcOffset != null) {
			placed.add(new PlacedWindow(name, start, end, homeSrcOffset));
		}
	}

	/**
	 * Realizes every mode-varying window (from {@code memory.layouts[]}), grouped by
	 * window name across all layouts so each window's full set of per-mode instances is
	 * handed to {@link DescriptorSupport#placeHomeInBaseWindow} together -- exactly one
	 * instance across every (layout, bank) combination is "home": the layout whose mode
	 * value equals the mode field's {@code initial_state} value, and (for a switchable
	 * expression) the bank value equal to that field's own initial value. Every other
	 * instance becomes a mode-qualified overlay ({@code <name>_M<mode>} for a fixed
	 * expression's non-home layout, {@code <name>_M<mode>_B<bank>} for a switchable
	 * expression's non-home (layout, bank) pair).
	 */
	private static void realizeVaryingWindows(Program program, AddressSpace baseSpace,
			DescriptorSupport.LayoutPlan plan, List<DescriptorSupport.StateField> fields,
			Long initialState, InesHeader header, FileBytes fileBytes, String mapPath,
			List<PlacedWindow> placed, MessageLog log) {

		DescriptorSupport.StateField modeFieldSpec =
			DescriptorSupport.findField(fields, plan.modeField());
		if (modeFieldSpec == null || initialState == null) {
			log.appendMsg("memory.layouts[] present but mode field '" + plan.modeField() +
				"' not found in banking.state (or initial_state missing); skipping " +
				"mode-varying windows");
			return;
		}
		long homeModeValue = modeFieldSpec.valueIn(initialState);

		Map<String, List<DescriptorSupport.PlannedWindow>> byName = new LinkedHashMap<>();
		for (DescriptorSupport.PlannedWindow pw : plan.varying()) {
			byName.computeIfAbsent(pw.name(), k -> new ArrayList<>()).add(pw);
		}

		for (Map.Entry<String, List<DescriptorSupport.PlannedWindow>> entry : byName.entrySet()) {
			String name = entry.getKey();
			List<DescriptorSupport.PlannedWindow> instances = entry.getValue();
			if (instances.stream().anyMatch(pw -> pw.expr() == null)) {
				log.appendMsg("Window '" + name +
					"' has enumerated occupants; not supported by this loader");
				continue;
			}
			Map<String, Long> srcOffsetsByName = new HashMap<>();
			List<DescriptorSupport.NamedCandidate> candidates = new ArrayList<>();
			// The home layout's instance defines where the base-space block (and the
			// PlacedWindow used for vector reads) sits; layouts normally agree on a
			// window's CPU-space location, but each instance's block uses its own
			// declared start/length regardless.
			long homeStart = instances.get(0).start();
			long homeEnd = instances.get(0).end();

			for (DescriptorSupport.PlannedWindow pw : instances) {
				int m = pw.modeValue();
				boolean isHomeLayout = m == homeModeValue;
				String expr = pw.expr();
				long start = pw.start();
				long length = pw.length();
				if (isHomeLayout) {
					homeStart = pw.start();
					homeEnd = pw.end();
				}

				try {
					long srcOffset = DescriptorExpressions.evalConstantExpr(expr, header.prgSize(), length);
					if (!checkRange(name, expr, srcOffset, length, header, log)) {
						continue;
					}
					String blockName = isHomeLayout ? name
							: DescriptorSupport.OverlayNaming.modeBlockName(name, m);
					srcOffsetsByName.put(blockName, srcOffset);
					String comment = name + " = PRG[" + expr + "] (mode " + plan.modeField() + "=" +
						m + ", offset 0x" + Long.toHexString(srcOffset) +
						(isHomeLayout ? ", home mode in base space)" : ")");
					long fileOffset = header.prgFileOffset() + srcOffset;
					candidates.add(new DescriptorSupport.NamedCandidate(blockName,
						(p, bs, isHome, l) -> createWindowBlock(p, bs, !isHome, blockName, comment,
							start, length, fileBytes, fileOffset, mapPath, l)));
					continue;
				}
				catch (IllegalArgumentException e) {
					// falls through: bank-state-dependent within this mode
				}

				Set<String> exprFields = DescriptorExpressions.referencedFields(expr);
				DescriptorSupport.StateField bankField = exprFields.size() == 1
						? DescriptorSupport.findField(fields, exprFields.iterator().next())
						: null;
				if (bankField == null) {
					log.appendMsg("Window '" + name + "' (mode " + plan.modeField() + "=" + m +
						") skipped: '" + expr + "' needs exactly one banking.state field" +
						" (references " + exprFields + ")");
					continue;
				}
				long bankInitial = bankField.valueIn(initialState);
				for (long v = 0; v < (1L << bankField.width()); v++) {
					long srcOffset = DescriptorExpressions.evalExpr(expr, header.prgSize(), length,
						Map.of(bankField.name(), v));
					if (srcOffset < 0 || srcOffset + length > header.prgSize()) {
						continue;
					}
					boolean home = isHomeLayout && v == bankInitial;
					String blockName = home ? name
							: DescriptorSupport.OverlayNaming.modeBankBlockName(name, m, (int) v);
					srcOffsetsByName.put(blockName, srcOffset);
					String comment = name + " = PRG[" + expr + "], mode " + plan.modeField() + "=" + m +
						", " + bankField.name() + "=" + v + " (offset 0x" +
						Long.toHexString(srcOffset) + (home ? ", home in base space)" : ")");
					long fileOffset = header.prgFileOffset() + srcOffset;
					candidates.add(new DescriptorSupport.NamedCandidate(blockName,
						(p, bs, isHome, l) -> createWindowBlock(p, bs, !isHome, blockName, comment,
							start, length, fileBytes, fileOffset, mapPath, l)));
				}
			}

			DescriptorSupport.placeHomeInBaseWindow(program, baseSpace, candidates, name, log);
			Long homeSrcOffset = srcOffsetsByName.get(name);
			if (homeSrcOffset != null) {
				placed.add(new PlacedWindow(name, homeStart, homeEnd, homeSrcOffset));
			}
		}
	}

	/**
	 * How a fixed window is backed by the PRG image: the image offset its first byte comes
	 * from, and how many times the image repeats across the window. {@code repeats} is 1 for
	 * every normal image; see {@link #resolveBacking} for the sub-window case.
	 */
	private record WindowBacking(long srcOffset, int repeats) {}

	/**
	 * Resolves a fixed window's backing, or {@code null} (with a logged reason) if the window
	 * cannot be placed.
	 * <p>
	 * <b>The sub-window case (bead grm-7e5o).</b> A PRG image SMALLER than the window it has to
	 * fill is not a truncated image -- it is a smaller ROM chip, whose high address lines the
	 * board simply does not connect. The window therefore shows the whole image repeated:
	 * NROM-128's single 16 KiB bank appears twice across $8000-$FFFF (which is the only reason
	 * {@code PRG[last]} means anything on it), and the three known 8 KiB mapper-0 images --
	 * both Galaxian (J) revisions and Controller Test Program (J), all using NES 2.0's exponent
	 * size form precisely to express half of one 16 KiB unit -- appear four times.
	 * <p>
	 * Because the decode is by unconnected address lines, the byte a CPU address sees is
	 * {@code image[addr mod imageSize]} whatever the {@code maps:} expression intended, and the
	 * expression's own offset is not representable on the hardware. So the offset is reduced
	 * modulo the image size (which is what makes {@code PRG[last]}'s negative
	 * {@code imageSize - windowSize} resolve correctly rather than being skipped), and a
	 * reduction that does NOT land on zero is refused rather than placed: that would be a
	 * rotated view, which no board decodes and which this loader has no way to build.
	 * <p>
	 * This is deliberately a LOADER concern rather than a descriptor one, per the bead's ruling:
	 * it is uniform across boards, needs no addition to the {@code maps:} mini-language, and no
	 * board is known where an undersized image does something other than mirror. A board that
	 * left the gap OPEN BUS instead would need the descriptor route, and would be the reason to
	 * revisit this.
	 */
	private static WindowBacking resolveBacking(String name, String expr, long srcOffset,
			long length, InesHeader header, MessageLog log) {

		long imageSize = header.prgSize();
		if (imageSize > 0 && imageSize < length) {
			if (length % imageSize != 0) {
				log.appendMsg("Window '" + name + "' skipped: the " + imageSize +
					"-byte PRG image is smaller than the " + length +
					"-byte window but does not divide it, so it cannot mirror to fill it");
				return null;
			}
			// Math.floorMod, spelled out: srcOffset is negative for 'last' on a sub-window image.
			long reduced = ((srcOffset % imageSize) + imageSize) % imageSize;
			if (reduced != 0) {
				log.appendMsg("Window '" + name + "' skipped: '" + expr + "' resolves to " +
					srcOffset + ", which reduces to offset " + reduced + " within the " +
					imageSize + "-byte PRG image -- a rotated view, which no board decodes");
				return null;
			}
			int repeats = (int) (length / imageSize);
			log.appendMsg("Window '" + name + "': the " + imageSize +
				"-byte PRG image mirrors " + repeats + "x to fill the " + length +
				"-byte window (undecoded high address lines)");
			return new WindowBacking(0, repeats);
		}
		return checkRange(name, expr, srcOffset, length, header, log)
				? new WindowBacking(srcOffset, 1)
				: null;
	}

	/**
	 * Creates a fixed window's block(s): normally one initialized block spanning the whole
	 * window, but {@code repeats} copies when the image is smaller than the window. The first
	 * copy is the real, FileBytes-backed block and carries the window's name; the rest are
	 * {@code createByteMappedBlock} views of it, matching {@code SnesRomLoader}'s ROM mirrors
	 * rather than duplicating the bytes -- the mirrors ARE the same chip, and a byte-mapped
	 * view says so.
	 */
	private static MemoryBlock createWindowBlocks(Program program, AddressSpace baseSpace,
			boolean isOverlay, String blockName, String comment, long start, long length,
			FileBytes fileBytes, long fileOffset, int repeats, String source, MessageLog log) {

		long unit = length / repeats;
		MemoryBlock home = createWindowBlock(program, baseSpace, isOverlay, blockName,
			comment + (repeats > 1 ? ", mirrored " + repeats + "x" : ""),
			start, unit, fileBytes, fileOffset, source, log);
		if (home == null) {
			return null;
		}
		for (int i = 1; i < repeats; i++) {
			long at = start + i * unit;
			String mirrorName = blockName + "_mirror_" + Long.toHexString(at);
			try {
				MemoryBlock block = program.getMemory().createByteMappedBlock(mirrorName,
					baseSpace.getAddress(at), baseSpace.getAddress(start), unit, false);
				block.setRead(true);
				block.setExecute(true);
				block.setComment("Mirror of " + blockName + " at $" + Long.toHexString(start) +
					" (PRG image smaller than the window)");
			}
			catch (Exception e) {
				log.appendMsg("Failed to mirror '" + blockName + "' at $" +
					Long.toHexString(at) + ": " + e.getMessage());
			}
		}
		return home;
	}

	/**
	 * Range gate for the BANK-DEPENDENT window paths, which place one block per candidate bank
	 * value. Unlike {@link #resolveBacking} it never mirrors a sub-window image: mirroring is a
	 * property of an image smaller than a single window, and a board with {@code banking.state}
	 * has at least one bank per window by construction, so the case cannot arise there without
	 * the descriptor already being wrong. Extending mirroring here would also mean byte-mapped
	 * views into overlay spaces, which is a different problem than the one grm-7e5o describes.
	 */
	private static boolean checkRange(String name, String expr, long srcOffset, long length,
			InesHeader header, MessageLog log) {
		if (srcOffset < 0 || srcOffset + length > header.prgSize()) {
			log.appendMsg("Window '" + name + "' skipped: '" + expr + "' resolves to [" +
				srcOffset + ", " + (srcOffset + length) + ") outside the " + header.prgSize() +
				"-byte PRG image");
			return false;
		}
		return true;
	}

	/** ROM-kind permissions: readable + executable, not writable. */
	private static MemoryBlock createWindowBlock(Program program, AddressSpace baseSpace,
			boolean isOverlay, String blockName, String comment, long start, long length,
			FileBytes fileBytes, long fileOffset, String source, MessageLog log) {
		try {
			return MemoryBlockUtils.createInitializedBlock(program, isOverlay, blockName,
				baseSpace.getAddress(start), fileBytes, fileOffset, length, comment, source,
				true, false, true, log);
		}
		catch (Exception e) {
			log.appendMsg("Failed to create window block '" + blockName + "': " + e.getMessage());
			return null;
		}
	}

	/** File offset of a CPU address through the placed windows, or null if unmapped. */
	private static Long fileOffsetOf(long cpuAddr, InesHeader header,
			List<PlacedWindow> placedWindows) {
		for (PlacedWindow window : placedWindows) {
			if (cpuAddr >= window.cpuStart() && cpuAddr <= window.cpuEnd()) {
				// Reduced modulo the image so a sub-window image's mirrors read through to the
				// bytes they mirror (bead grm-7e5o) -- this is how the vector table at
				// $FFFA-$FFFF is found on an 8 KiB NROM, where it lives in the window's fourth
				// copy. A no-op for every image at least as large as its window, since the
				// in-window offset then cannot reach the image size.
				long offset = window.srcOffset() + (cpuAddr - window.cpuStart());
				if (header.prgSize() > 0) {
					offset %= header.prgSize();
				}
				return header.prgFileOffset() + offset;
			}
		}
		return null;
	}
}
