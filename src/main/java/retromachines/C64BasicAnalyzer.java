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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recognizes a descriptor-declared tokenized-CBM-BASIC PRG, walks the
 * line-link chain ({@link CbmBasicWalker}), types the link/line-number words, writes a
 * petcat-compatible detokenized comment per line, and fixes the loader's
 * function-at-load-address wart for these programs by locating the real machine-language
 * entry point from a {@code SYS <decimal>} line and marking a function there instead
 * (bead grm-odt.1).
 * <p>
 * <b>Token source of truth:</b> this class transcribes no token table. It reads the
 * descriptor-selected primary and optional prefix-page enums directly out of that machine's
 * bundled GDT archive (see {@link BasicDescriptorTokenLookup}) -- the same archive the
 * descriptor loader uses for IO-chip register structs. The enums are read from the archive's
 * own data type manager, not resolved into the
 * program's, because it is only ever queried for member names here (token bytes are
 * rendered into a listing comment, never typed onto the byte itself -- see the
 * class-level data-typing note below).
 * <p>
 * <b>Text rendering:</b> every non-token PETSCII byte (including everything inside a
 * quoted string, or raw comment/DATA text) goes through {@link PetsciiMapper} using the
 * descriptor-selected power-up variant. Dynamic charset changes remain out of scope.
 * <p>
 * <b>Data typing:</b> only the 2-byte link and 2-byte line-number fields are typed
 * ({@link WordDataType}, with an EOL comment naming the field); the tokenized text bytes
 * between the line number and the {@code $00} terminator are left undefined. The
 * detokenized rendering already carries the full meaning of those bytes in a PRE comment
 * at the line's start address (petcat-style: {@code "<line number> <rendered text>"});
 * typing them as a byte array would duplicate that information less readably (a raw hex
 * dump next to a comment that already says what it means) and would block any more
 * specific future typing (e.g. per-opcode structuring) of the same bytes.
 */
public class C64BasicAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "CBM BASIC Detokenizer";
	private static final String DESCRIPTION =
		"Walks a descriptor-declared tokenized CBM BASIC PRG's line-link chain, types the line link/" +
			"number words, writes petcat-compatible detokenized comments, and marks the " +
			"real ML entry point from a SYS line (instead of the loader's load-address " +
			"function mark, which is wrong for BASIC-start programs).";

	private static final String CATEGORY = "C64BasicAnalyzer";
	private static final String LEGACY_C64_MAP_PATH = "machines/c64.map";

	/**
	 * Fingerprint of the last <em>completed</em> {@link #added} run per program (grm-52z,
	 * mirrors {@code BoardBankAnalyzer.LAST_COMPLETED}/{@code RunStamp} from grm-5tl.13.3).
	 * {@code added()} is a BYTE_ANALYZER callback that re-fires per DECRYPTED_ overlay
	 * block the emulation-recovery analyzer produces; every round otherwise re-walks the
	 * line chain, re-opens the GDT, reloads the PETSCII map, and re-types/re-comments every
	 * line, all of which are no-ops once this analyzer's actual inputs -- the descriptor
	 * path, the PRG's placement (load address/length), and the persisted slice list (the
	 * PRG image bytes themselves are immutable after load) -- have not changed since the
	 * last completed run. Session-local only (never persisted): this cache's only job is
	 * skipping <em>provably</em> redundant re-runs within one session, so a fresh session
	 * is entitled to (and does) run the analysis again. Keyed weakly by {@link Program}
	 * identity so closed programs drop out; synchronized because distinct programs may be
	 * analyzed on distinct threads.
	 */
	private static final Map<Program, RunStamp> LAST_COMPLETED =
		Collections.synchronizedMap(new WeakHashMap<>());

	/** What {@link #LAST_COMPLETED} remembers. {@code wrapped} is carried for documentation
	 * parity with the analyzer's real input set even though only {@code false} ever reaches
	 * the comparison site (a wrapped PRG returns before this stamp is built). */
	/** Fingerprint of the inputs a completed run consumed, for the redundant-re-run gate.
	 *  Carries the slice list and not the load address / payload length / wrap flag,
	 *  because those are pure functions of the slices (grm-hap item 4): including them
	 *  could not change when two stamps compare equal, only give the same fact three more
	 *  chances to be recorded inconsistently. */
	private record RunStamp(String mapPath,
			List<AbstractCbmPrgLoader.LoadedSlice> loadedSlices) {
	}

	/** Descriptor-selected analyzer policy. The class/category remain C64-named for saved
	 * Program compatibility; only the token/archive policy varies. */
	private record BasicConfig(String mapPath, String gdtPath, String tokenEnum,
			List<BasicDescriptorTokenLookup.PrefixDefinition> prefixEnums,
			PetsciiMapper.Variant petsciiVariant) {
	}

	public C64BasicAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Run early -- right after format analysis, before Ghidra's own block/disassembly
		// analyzers reach the load address -- so the function this analyzer marks at the
		// SYS target (not the load address, which the loader now deliberately leaves
		// unmarked for BASIC-start PRGs) is what downstream disassembly/reference/
		// function analysis sees.
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return basicConfig(program) != null;
		}
		catch (IOException | RuntimeException e) {
			return false;
		}
	}

	/** Resolves the compiled descriptor selected by the importing loader. C64 Programs saved
	 * before the common map-path property retain their historical BASIC V2 behavior. */
	private static BasicConfig basicConfig(Program program) throws IOException {
		String format = program.getExecutableFormat();
		String mapPath = program.getOptions(Program.PROGRAM_INFO).getString(
			DescriptorSupport.MAP_PATH_PROPERTY, "");
		if (mapPath == null || mapPath.isBlank()) {
			return C64PrgLoader.NAME.equals(format) ? legacyC64Config() : null;
		}

		JsonObject map = DescriptorSupport.loadMap(mapPath);
		JsonObject formats = map.getAsJsonObject("formats");
		JsonObject prg = formats == null ? null : formats.getAsJsonObject("prg");
		JsonObject basic = prg == null ? null : prg.getAsJsonObject("basic");
		if (basic == null) {
			// The C64 map predates formats.prg.basic. Keep it analyzable until a rebuilt
			// descriptor carries the declarative form, and preserve old saved Programs too.
			return LEGACY_C64_MAP_PATH.equals(mapPath) && C64PrgLoader.NAME.equals(format)
					? legacyC64Config() : null;
		}

		String tokenEnum = requiredString(basic, "token_enum", "formats.prg.basic");
		PetsciiMapper.Variant variant = parsePetsciiVariant(basic);
		List<BasicDescriptorTokenLookup.PrefixDefinition> prefixes = new ArrayList<>();
		JsonArray prefixArray = basic.has("prefix_enums")
				? basic.getAsJsonArray("prefix_enums") : new JsonArray();
		for (JsonElement element : prefixArray) {
			JsonObject prefix = element.getAsJsonObject();
			int value = prefix.get("prefix").getAsInt();
			if (value < 0 || value > 0xff) {
				throw new IllegalArgumentException("formats.prg.basic prefix is outside a byte: " +
					value);
			}
			String enumName = requiredString(prefix, "enum", "formats.prg.basic.prefix_enums");
			if (prefixes.stream().anyMatch(p -> p.prefix() == value)) {
				throw new IllegalArgumentException("formats.prg.basic declares prefix 0x" +
					Integer.toHexString(value) + " twice");
			}
			prefixes.add(new BasicDescriptorTokenLookup.PrefixDefinition(value, enumName));
		}
		return new BasicConfig(mapPath, gdtPathFor(mapPath), tokenEnum, List.copyOf(prefixes),
			variant);
	}

	private static BasicConfig legacyC64Config() {
		return new BasicConfig(LEGACY_C64_MAP_PATH, gdtPathFor(LEGACY_C64_MAP_PATH),
			"BASIC_V2_TOKEN", List.of(), PetsciiMapper.Variant.UNSHIFTED_GRAPHICS);
	}

	private static String gdtPathFor(String mapPath) {
		return mapPath.endsWith(".map")
				? mapPath.substring(0, mapPath.length() - 4) + ".gdt" : mapPath + ".gdt";
	}

	private static String requiredString(JsonObject object, String key, String context) {
		if (!object.has(key) || object.get(key).getAsString().isBlank()) {
			throw new IllegalArgumentException(context + " is missing '" + key + "'");
		}
		return object.get(key).getAsString();
	}

	private static PetsciiMapper.Variant parsePetsciiVariant(JsonObject basic) {
		String configured = basic.has("petscii_variant")
				? basic.get("petscii_variant").getAsString() : "unshifted_graphics";
		return switch (configured) {
			case "unshifted_graphics" -> PetsciiMapper.Variant.UNSHIFTED_GRAPHICS;
			case "shifted_lowercase" -> PetsciiMapper.Variant.SHIFTED_LOWERCASE;
			default -> throw new IllegalArgumentException(
				"formats.prg.basic has unknown petscii_variant '" + configured + "'");
		};
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return analyze(program, set, monitor, log);
	}

	/**
	 * Performs one analyzer run. Split out from {@link #added} when that method also had to
	 * record persistent completion state for the initial-run logging policy; grm-6jfp
	 * deleted that policy, so this is now a plain body with one caller, kept separate only
	 * because the return value's meaning (this run completed / it reported a failure and is
	 * worth retrying) is easier to state on its own.
	 */
	private boolean analyze(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		BasicConfig config;
		try {
			config = basicConfig(program);
		}
		catch (IOException | RuntimeException e) {
			AnalyzerLog.warn(this, log, "Failed to read CBM BASIC descriptor policy: " +
				e.getMessage());
			return false;
		}
		if (config == null) {
			return true;
		}

		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		// One read of the one persisted fact, then derive (grm-hap item 4). This used to be
		// three Options reads, each with a fallback to a parallel "Retro Machines.C64 PRG *"
		// key, followed by a fourth fallback that reconstructed the interval from the "PRG"
		// memory block for Programs imported before grm-dvx -- four ways to answer one
		// question, three of which could disagree with the slice list read just below.
		List<AbstractCbmPrgLoader.LoadedSlice> loadedSlices =
			AbstractCbmPrgLoader.getLoadedSlices(program);
		AbstractCbmPrgLoader.PrgPlacement placement =
			AbstractCbmPrgLoader.placementOf(loadedSlices);
		if (placement.wrapped()) {
			return true; // a tokenized BASIC line chain is not a wrapping address interval
		}
		if (!placement.isPlaced()) {
			return true; // zero-payload PRG: no bytes were placed, so there is no line chain
		}
		long loadAddr = placement.loadAddress();
		long prgLength = placement.length();
		long limitAddr = loadAddr + prgLength;
		final long imageLoadAddr = loadAddr;
		final long imageLimitAddr = limitAddr;

		// Redundant-re-run gate (grm-52z): see LAST_COMPLETED for the invariants. Checked
		// before any walk/GDT-open/PETSCII-load work, since those are exactly what a
		// same-inputs repeat round would otherwise redo for nothing.
		RunStamp stamp = new RunStamp(config.mapPath(), loadedSlices);
		if (stamp.equals(LAST_COMPLETED.get(program))) {
			AnalyzerLog.info(this, NAME + ": descriptor/placement/slices unchanged since " +
				"the last completed run; skipping redundant re-analysis");
			return true;
		}

		// One bulk-read pass per LoadedSlice (plus one per gap in legacy/unsliced
		// coverage) instead of a per-byte resolvePrgAddress()+getByte() -- see
		// buildByteCache's javadoc (grm-52z).
		int[] byteCache = buildByteCache(program, baseSpace, loadedSlices, loadAddr, limitAddr);

		CbmBasicWalker.ByteSource src = addr -> {
			if (addr < imageLoadAddr || addr >= imageLimitAddr) {
				return -1;
			}
			return byteCache[(int) (addr - imageLoadAddr)];
		};

		// Same structural sniff C64PrgLoader used to decide whether to skip its
		// load-address function mark -- see CbmBasicWalker.isBasicStart's javadoc for why
		// this (not "walk() found >= 1 line") is the right gate: plain machine code can
		// spuriously produce a single bogus "line" out of a coincidental $00 byte, and
		// without this same check here this analyzer would type/comment that bogus line
		// (which is exactly what happened before this check was added -- see grm-odt.1).
		if (!CbmBasicWalker.isBasicStart(src, loadAddr, limitAddr)) {
			LAST_COMPLETED.put(program, stamp);
			return true;
		}
		CbmBasicWalker.WalkResult result = CbmBasicWalker.walk(src, loadAddr, limitAddr);
		if (result.lines().isEmpty()) {
			LAST_COMPLETED.put(program, stamp);
			return true; // trivially empty BASIC program; nothing to annotate
		}
		AnalyzerLog.info(this, NAME + " running: " + result.lines().size() +
			" BASIC line(s) at 0x" + Long.toHexString(loadAddr));

		FileDataTypeManager gdtMgr;
		try {
			gdtMgr = DescriptorSupport.openGdt(config.gdtPath());
		}
		catch (IOException e) {
			AnalyzerLog.warn(this, log,
				"Failed to open " + config.gdtPath() + ": " + e.getMessage());
			return false;
		}
		PetsciiMapper petscii;
		try {
			petscii = PetsciiMapper.load();
		}
		catch (IOException e) {
			AnalyzerLog.warn(this, log, "Failed to load petscii.map: " + e.getMessage());
			gdtMgr.close();
			return false;
		}

		try {
			BasicDescriptorTokenLookup tokenLookup = BasicDescriptorTokenLookup.fromGdt(gdtMgr,
				config.tokenEnum(), config.prefixEnums());
			if (tokenLookup == null) {
				AnalyzerLog.warn(this, log,
					config.tokenEnum() + " enum not found in " + config.gdtPath() +
						"; token bytes will " +
					"render as raw PETSCII escapes only");
			}
			else if (!tokenLookup.missingPrefixEnums().isEmpty()) {
				AnalyzerLog.warn(this, log, "Configured BASIC prefix enum(s) missing from " +
					config.gdtPath() + ": " + String.join(", ", tokenLookup.missingPrefixEnums()) +
					"; affected prefix pairs will render as raw PETSCII");
			}

			boolean sysHandled = false;
			for (CbmBasicWalker.BasicLine line : result.lines()) {
				monitor.checkCancelled();

				Address lineAddr = placedAddress(program, baseSpace, loadedSlices, line.lineAddr());
				Address lineNumAddr =
					placedAddress(program, baseSpace, loadedSlices, line.lineAddr() + 2);
				typeWord(program, lineAddr, "line link", log);
				typeWord(program, lineNumAddr, "line number", log);

				int textLen = (int) (line.terminatorAddr() - line.textStart());
				byte[] textBytes = new byte[textLen];
				// Same cache the ByteSource lambda uses (grm-52z) -- a missing/unreadable byte
				// reports -1 there exactly as a failed Memory.getByte() did before, so this
				// mirrors the previous per-line skip+log on any unavailable byte.
				boolean textOk = true;
				for (int i = 0; i < textBytes.length; i++) {
					long taddr = line.textStart() + i;
					int cached = (taddr >= imageLoadAddr && taddr < imageLimitAddr)
							? byteCache[(int) (taddr - imageLoadAddr)] : -1;
					if (cached < 0) {
						textOk = false;
						break;
					}
					textBytes[i] = (byte) cached;
				}
				if (!textOk) {
					AnalyzerLog.warn(this, log, "Failed to read line text at 0x" +
						Long.toHexString(line.textStart()));
					continue;
				}

				LineRender rendered = renderLine(textBytes, tokenLookup, petscii,
					config.petsciiVariant());
				String listing = line.lineNumber() + " " + rendered.text();
				program.getListing().setComment(lineAddr, CommentType.PRE, listing);

				if (!sysHandled && (rendered.sysTarget() != null || rendered.sysNonLiteral())) {
					sysHandled = true;
					if (rendered.sysTarget() != null) {
						markSysEntry(program, monitor, baseSpace, loadedSlices,
							rendered.sysTarget(), line.lineNumber(), log);
					}
					else {
						program.getBookmarkManager().setBookmark(lineAddr, BookmarkType.NOTE,
							CATEGORY, "SYS argument on line " + line.lineNumber() +
								" is not a simple decimal literal; not marking a function");
					}
				}
			}

			if (result.isMalformed()) {
				Address at =
					placedAddress(program, baseSpace, loadedSlices, result.malformedAt());
				String detail = result.expectedNextAddr() == null
						? "line link 0x" + Long.toHexString(result.malformedLink()) +
							" is not readable/parseable as a valid next line"
						: "line link 0x" + Long.toHexString(result.malformedLink()) +
							" does not match the address reached by scanning to this line's " +
							"terminator (0x" + Long.toHexString(result.expectedNextAddr()) + ")";
				program.getBookmarkManager().setBookmark(at, BookmarkType.WARNING, CATEGORY,
					"Malformed BASIC line link at 0x" + Long.toHexString(result.malformedAt()) +
						": " + detail + "; stopped walking the line chain here");
				AnalyzerLog.warn(this, log, "Malformed BASIC line link: " + detail);
			}
		}
		finally {
			gdtMgr.close();
		}

		LAST_COMPLETED.put(program, stamp);
		return true;
	}

	/**
	 * Builds a one-shot byte cache over the CPU-address interval {@code [loadAddr,
	 * limitAddr)}, indexed by {@code addr - loadAddr}: {@code -1} for an address this
	 * program cannot supply a byte for, else the byte value (0-255). Replaces the previous
	 * per-byte {@code resolvePrgAddress()} (linear slice scan + address-space name lookup)
	 * + {@code Memory.getByte()} the walker and line-text loop used to do for every single
	 * byte of the PRG (grm-52z) with one bulk {@link ghidra.program.model.mem.Memory#getBytes}
	 * call per {@link AbstractCbmPrgLoader.LoadedSlice} (slices are assumed non-overlapping,
	 * true of every producer of this metadata today) plus one per gap not covered by any
	 * slice. The gap pass is kept general rather than tied to any one cause; the caller no
	 * longer reaches here with an empty slice list at all, since a Program with no placed
	 * slices has no load interval and is declined before the cache is built. Gaps fall back
	 * to {@code baseSpace}, matching
	 * {@link #placedAddress}'s own fallback policy exactly (this method calls that helper
	 * for the one Address it still needs per slice/gap, rather than re-implementing
	 * {@code resolvePrgAddress}'s space-resolution policy here).
	 */
	private static int[] buildByteCache(Program program, AddressSpace baseSpace,
			List<AbstractCbmPrgLoader.LoadedSlice> loadedSlices, long loadAddr, long limitAddr) {
		int size = (int) (limitAddr - loadAddr);
		int[] cache = new int[size];
		Arrays.fill(cache, -1);
		boolean[] covered = new boolean[size];

		for (AbstractCbmPrgLoader.LoadedSlice slice : loadedSlices) {
			long overlapStart = Math.max(slice.start(), loadAddr);
			long overlapEnd = Math.min(slice.start() + slice.length(), limitAddr);
			if (overlapStart >= overlapEnd) {
				continue;
			}
			Address placedStart = placedAddress(program, baseSpace, loadedSlices, overlapStart);
			readBulkInto(program, cache, covered, (int) (overlapStart - loadAddr), placedStart,
				(int) (overlapEnd - overlapStart));
		}

		// Legacy/gap fallback: any stretch no slice claimed (including the whole interval
		// when getLoadedSlices() is empty) is read from baseSpace in one shot per
		// contiguous run, matching placedAddress's per-byte fallback exactly.
		int i = 0;
		while (i < size) {
			if (covered[i]) {
				i++;
				continue;
			}
			int start = i;
			while (i < size && !covered[i]) {
				i++;
			}
			Address gapStart = baseSpace.getAddress(loadAddr + start);
			readBulkInto(program, cache, covered, start, gapStart, i - start);
		}
		return cache;
	}

	/** Reads {@code len} bytes starting at {@code start} into {@code cache} at
	 * {@code cacheOffset}, marking the whole requested run {@code covered} regardless of
	 * how many bytes actually resolved -- an unreadable byte inside a claimed slice/gap
	 * must report -1 (via the {@code cache} entry staying at its {@code Arrays.fill(-1)}
	 * default), never be revisited by a later fallback pass. */
	private static void readBulkInto(Program program, int[] cache, boolean[] covered,
			int cacheOffset, Address start, int len) {
		byte[] buf = new byte[len];
		int n;
		try {
			n = program.getMemory().getBytes(start, buf);
		}
		catch (MemoryAccessException e) {
			n = 0;
		}
		for (int j = 0; j < n; j++) {
			cache[cacheOffset + j] = buf[j] & 0xFF;
		}
		Arrays.fill(covered, cacheOffset, cacheOffset + len, true);
	}

	private static Address placedAddress(Program program, AddressSpace baseSpace,
			List<AbstractCbmPrgLoader.LoadedSlice> loadedSlices, long offset) {
		Address placed = AbstractCbmPrgLoader.resolvePrgAddress(program, offset, loadedSlices);
		return placed != null ? placed : baseSpace.getAddress(offset);
	}

	private void typeWord(Program program, Address at, String fieldName, MessageLog log) {
		try {
			DataUtilities.createData(program, at, WordDataType.dataType, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			program.getListing().setComment(at, CommentType.EOL, fieldName);
		}
		catch (Exception e) {
			AnalyzerLog.warn(this, log,
				"Failed to type " + fieldName + " word at 0x" + at + ": " + e.getMessage());
		}
	}

	private void markSysEntry(Program program, TaskMonitor monitor, AddressSpace baseSpace,
			List<AbstractCbmPrgLoader.LoadedSlice> loadedSlices, int sysTarget, int lineNumber,
			MessageLog log) {
		try {
			Address sysAddr =
				placedAddress(program, baseSpace, loadedSlices, sysTarget & 0xFFFF);
			program.getSymbolTable().addExternalEntryPoint(sysAddr);
			if (program.getSymbolTable().getPrimarySymbol(sysAddr) == null) {
				program.getSymbolTable().createLabel(sysAddr, "sys_entry", SourceType.IMPORTED);
			}
			new CreateFunctionCmd(sysAddr).applyTo(program, monitor);
			program.getListing().setComment(sysAddr, CommentType.PLATE,
				"SYS target from BASIC line " + lineNumber);
		}
		catch (Exception e) {
			AnalyzerLog.warn(this, log, "Failed to mark SYS entry at " + sysTarget + ": " +
				e.getMessage());
		}
	}

	// ------------------------------------------------------------------
	// Detokenizer
	// ------------------------------------------------------------------

	/** One line's rendering: the petcat-style text (line number not included), plus SYS
	 *  detection state (see grm-odt.1's SYS-detection scope: simple decimal literal only). */
	private record LineRender(String text, Integer sysTarget, boolean sysNonLiteral) {
	}

	/**
	 * Renders one BASIC line's tokenized text bytes into petcat-style display text, and
	 * (as a side effect of the same single pass) detects a {@code SYS <decimal>}
	 * occurrence in this line.
	 * <p>
	 * State machine: outside quotes and not in a raw tail, a byte &gt;= $80 is looked up as
	 * a descriptor-supplied token; a {@code $22} toggles quote state. Every byte inside
	 * quotes is literal PETSCII. {@code REM} makes the remainder of the line literal.
	 * {@code DATA} makes its item text literal only through the next <em>unquoted</em>
	 * colon, after which normal token scanning resumes; quote bytes remain significant in
	 * DATA mode solely to distinguish a literal colon from a statement separator.
	 */
	private LineRender renderLine(byte[] data, BasicTokenLookup tokenLookup, PetsciiMapper petscii,
			PetsciiMapper.Variant petsciiVariant) {
		StringBuilder sb = new StringBuilder();
		boolean inQuotes = false;
		boolean afterRem = false;
		boolean afterData = false;
		Integer sysTarget = null;
		boolean sysNonLiteral = false;
		int i = 0;
		int n = data.length;

		while (i < n) {
			int b = data[i] & 0xFF;

			if (afterRem) {
				sb.append(petscii.toDisplayEscaped(b, petsciiVariant));
				i++;
				continue;
			}
			if (afterData) {
				// BASIC leaves DATA item bytes untokenized until an unquoted statement
				// separator. The bytes are literal PETSCII, but quotes still protect a colon
				// from ending DATA mode (and are rendered normally themselves).
				boolean dataColon = !inQuotes && b == 0x3a;
				if (b == 0x22) {
					inQuotes = !inQuotes;
				}
				sb.append(petscii.toDisplayEscaped(b, petsciiVariant));
				i++;
				if (dataColon) {
					afterData = false;
				}
				continue;
			}

			if (!inQuotes && b >= 0x80 && tokenLookup != null) {
				BasicTokenLookup.Match m = tokenLookup.lookup(data, i);
				if (m != null) {
					if (m.name() == null) {
						// A configured prefix owns its selector even when that pair is unknown.
						// Keep both bytes raw and do not rescan the selector as a token, quote, or
						// DATA/statement delimiter.
						for (int j = 0; j < m.bytesConsumed(); j++) {
							sb.append(petscii.toDisplayEscaped(data[i + j] & 0xff, petsciiVariant));
						}
						i += m.bytesConsumed();
						continue;
					}
					sb.append(m.name());
					if ("REM".equals(m.name())) {
						afterRem = true;
					}
					else if ("DATA".equals(m.name())) {
						afterData = true;
					}
					else if ("SYS".equals(m.name()) && sysTarget == null && !sysNonLiteral) {
						int j = i + m.bytesConsumed();
						while (j < n && (data[j] & 0xFF) == 0x20) {
							j++;
						}
						long value = 0;
						boolean any = false;
						boolean outOfRange = false;
						while (j < n) {
							int d = data[j] & 0xFF;
							if (d < 0x30 || d > 0x39) {
								break;
							}
							int digit = d - 0x30;
							if (value > (0xffff - digit) / 10) {
								outOfRange = true;
							}
							else {
								value = value * 10 + digit;
							}
							any = true;
							j++;
						}
						while (j < n && (data[j] & 0xFF) == 0x20) {
							j++;
						}
						if (any && !outOfRange && (j == n || (data[j] & 0xFF) == 0x3a)) {
							sysTarget = (int) value;
						}
						else {
							sysNonLiteral = true;
						}
					}
					i += m.bytesConsumed();
					continue;
				}
				// Unassigned token-range byte (e.g. BASIC 2's $CC-$FF) falls through to
				// the raw PETSCII render below, escaped like any other byte.
			}

			if (b == 0x22) {
				inQuotes = !inQuotes;
			}
			sb.append(petscii.toDisplayEscaped(b, petsciiVariant));
			i++;
		}

		return new LineRender(sb.toString(), sysTarget, sysNonLiteral);
	}
}
