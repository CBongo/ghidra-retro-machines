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
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
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
 */
public class NesRomLoader extends AbstractProgramWrapperLoader {

	static final String BOARD_OPTION_NAME = "NES Board";

	private static final String LANGUAGE_ID = "6502:LE:16:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final int INES_HEADER_LEN = 16;
	private static final int TRAINER_LEN = 512;
	private static final long TRAINER_ADDR = 0x7000;

	/** A computed window this load placed: where it sits in CPU space and which PRG
	 *  offset backs it. Used to route vector-table reads through the same mapping. */
	private record PlacedWindow(String name, long cpuStart, long cpuEnd, long srcOffset) {}

	/** The iNES header facts this loader consumes. */
	private record InesHeader(int prgBanks, int chrBanks, int mapper, boolean trainer) {

		long prgSize() {
			return prgBanks * 0x4000L;
		}

		/** File offset where PRG content starts (header, then optional trainer). */
		long prgFileOffset() {
			return INES_HEADER_LEN + (trainer ? TRAINER_LEN : 0);
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
			int prgBanks;
			if (nes2) {
				// NES 2.0: 12-bit mapper (flags6 hi | flags7 hi | flags8 lo); PRG-ROM unit
				// count is h[4] plus a high nibble in h[9]. h[9] low nibble == 0xF selects a
				// rare exponent size form we don't model -- fall back to the low byte there.
				mapper = ((h[8] & 0x0F) << 8) | (h[7] & 0xF0) | lowMapper;
				int prgHi = h[9] & 0x0F;
				prgBanks = prgHi == 0x0F ? (h[4] & 0xFF) : ((prgHi << 8) | (h[4] & 0xFF));
			}
			else {
				// Archaic iNES: "DiskDude!"-style tools scribbled ASCII into bytes 7-15, so a
				// non-zero tail (bytes 12-15) means flags7's high nibble is not a real mapper
				// nibble -- trust only the low nibble. A clean iNES 1.0 header has 12-15 zero.
				boolean archaic = h[12] != 0 || h[13] != 0 || h[14] != 0 || h[15] != 0;
				mapper = archaic ? lowMapper : ((h[7] & 0xF0) | lowMapper);
				prgBanks = h[4] & 0xFF;
			}
			return new InesHeader(prgBanks, h[5] & 0xFF, mapper, (h[6] & 0x04) != 0);
		}
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
		if (header == null || header.prgBanks() == 0) {
			return loadSpecs;
		}
		// Only offer the loader when a board descriptor exists for the mapper; other
		// mappers fall through to the raw-binary loader until their boards land.
		if (NesBoardRegistry.forMapper(header.mapper()) == null) {
			return loadSpecs;
		}

		LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_SPEC_ID);
		loadSpecs.add(new LoadSpec(this, 0, pair, true));
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
		return super.validateOptions(provider, loadSpec, options, program);
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
			(header.chrBanks() * 8) + "K" + (header.trainer() ? ", trainer" : ""));

		// record the chosen board so the bank analyzer interprets with the same descriptor
		program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorSupport.MAP_PATH_PROPERTY, board.mapPath());

		JsonObject map = DescriptorSupport.loadMap(board.mapPath());

		FileDataTypeManager gdtMgr = null;
		try {
			gdtMgr = DescriptorSupport.openGdt(board.gdtPath());
		}
		catch (IOException e) {
			log.appendMsg("No data-type archive " + board.gdtPath() + ": " + e.getMessage());
		}

		try {
			AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

			// --- Always-visible regions (MMIO structs applied from their type:) ---
			for (JsonElement re : map.getAsJsonArray("regions")) {
				DescriptorSupport.createRegionBlock(program, baseSpace, re.getAsJsonObject(),
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
			BankedFieldInfo bankedField = BankedFieldInfo.parse(map);
			JsonArray windowArr = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
			for (JsonElement we : windowArr) {
				JsonObject window = we.getAsJsonObject();
				String name = window.get("name").getAsString();
				if (!window.has("maps")) {
					log.appendMsg("Window '" + name +
						"' has enumerated occupants; not supported by this loader (C64-style " +
						"overlay layout is the C64 loader's job)");
					continue;
				}
				long start = window.get("start").getAsLong();
				long end = window.get("end").getAsLong();
				long length = end - start + 1;
				String expr = window.getAsJsonObject("maps").get("expr").getAsString();

				try {
					long srcOffset =
						DescriptorSupport.evalConstantExpr(expr, header.prgSize(), length);
					if (checkRange(name, expr, srcOffset, length, header, log)) {
						createWindowBlock(program, baseSpace, false, name,
							name + " = PRG[" + expr + "] (offset 0x" + Long.toHexString(srcOffset) +
								")",
							start, length, fileBytes, header.prgFileOffset() + srcOffset,
							board.mapPath(), log);
						placed.add(new PlacedWindow(name, start, end, srcOffset));
					}
					continue;
				}
				catch (IllegalArgumentException e) {
					// falls through to the bank-state-dependent path below
				}

				Set<String> fields = DescriptorSupport.referencedFields(expr);
				if (bankedField == null || fields.size() != 1 ||
					!fields.iterator().next().equals(bankedField.name())) {
					log.appendMsg("Window '" + name + "' skipped: '" + expr +
						"' needs exactly one banking.state field" +
						(bankedField == null ? " but the descriptor has no banking section"
								: " (first field '" + bankedField.name() + "')"));
					continue;
				}
				for (int v = 0; v < (1 << bankedField.bits()); v++) {
					long srcOffset = DescriptorSupport.evalExpr(expr, header.prgSize(), length,
						Map.of(bankedField.name(), (long) v));
					if (srcOffset < 0 || srcOffset + length > header.prgSize()) {
						continue; // bank values beyond the image simply don't exist
					}
					boolean home = v == bankedField.initialValue();
					String blockName = home ? name : name + "_B" + v;
					createWindowBlock(program, baseSpace, !home, blockName,
						name + " = PRG[" + expr + "], " + bankedField.name() + "=" + v +
							" (offset 0x" + Long.toHexString(srcOffset) +
							(home ? ", home bank in base space)" : ")"),
						start, length, fileBytes, header.prgFileOffset() + srcOffset,
						board.mapPath(), log);
					if (home) {
						placed.add(new PlacedWindow(name, start, end, srcOffset));
					}
				}
			}

			if (header.chrBanks() > 0) {
				log.appendMsg("CHR ROM (" + (header.chrBanks() * 8) +
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

		record Vector(long slot, String handlerName) {}
		List<Vector> vectors = List.of(new Vector(0xFFFA, "NMI"), new Vector(0xFFFC, "RESET"),
			new Vector(0xFFFE, "IRQ"));

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
			}
			catch (Exception e) {
				log.appendMsg("Failed to label vector " + vector.handlerName() + ": " +
					e.getMessage());
			}
		}
	}

	/**
	 * The single bank-state field this loader can drive switchable windows with: the
	 * <em>first</em> field of {@code banking.state} (matching the memory-latch
	 * strategy's field-placement constraint), its width, and its {@code initial_state}
	 * value (the home bank). Null when the descriptor has no banking section.
	 */
	private record BankedFieldInfo(String name, int bits, int initialValue) {

		static BankedFieldInfo parse(JsonObject map) {
			JsonObject banking = map.getAsJsonObject("banking");
			if (banking == null || !banking.has("state") || !banking.has("initial_state")) {
				return null;
			}
			JsonArray state = banking.getAsJsonArray("state");
			if (state.isEmpty()) {
				return null;
			}
			JsonObject first = state.get(0).getAsJsonObject();
			int bits = first.get("bits").getAsInt();
			int initial = banking.get("initial_state").getAsInt() & ((1 << bits) - 1);
			return new BankedFieldInfo(first.get("name").getAsString(), bits, initial);
		}
	}

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
	private static void createWindowBlock(Program program, AddressSpace baseSpace,
			boolean isOverlay, String blockName, String comment, long start, long length,
			FileBytes fileBytes, long fileOffset, String source, MessageLog log) {
		try {
			MemoryBlockUtils.createInitializedBlock(program, isOverlay, blockName,
				baseSpace.getAddress(start), fileBytes, fileOffset, length, comment, source,
				true, false, true, log);
		}
		catch (Exception e) {
			log.appendMsg("Failed to create window block '" + blockName + "': " + e.getMessage());
		}
	}

	/** File offset of a CPU address through the placed windows, or null if unmapped. */
	private static Long fileOffsetOf(long cpuAddr, InesHeader header,
			List<PlacedWindow> placedWindows) {
		for (PlacedWindow window : placedWindows) {
			if (cpuAddr >= window.cpuStart() && cpuAddr <= window.cpuEnd()) {
				return header.prgFileOffset() + window.srcOffset() + (cpuAddr - window.cpuStart());
			}
		}
		return null;
	}
}
