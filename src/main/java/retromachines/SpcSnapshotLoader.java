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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

/**
 * Loader for SPC700 sound-state snapshots ({@code .spc}), bead grm-c9d.4.
 *
 * <p>A {@code .spc} file is a header (registers at the moment of capture, optional ID666 tag),
 * the S-SMP's whole 64 KiB RAM, the 128 DSP registers, and the 64 bytes of RAM that the IPL boot
 * ROM hides at {@code $FFC0}. This loader maps it as:
 * <ul>
 * <li>{@code RAM_0000}, {@code RAM_0100}: the RAM, in the two pieces around the I/O page;</li>
 * <li>{@code IO_F0}: the sixteen S-SMP registers at {@code $F0-$FF}, volatile, each labelled and
 * typed. The names are the hardware's: {@code $FA-$FC} are the three timer TARGETS and
 * {@code $FD-$FF} the three timer OUTPUTS (so {@code $FC} is timer 2's target and {@code $FF}
 * its counter -- SPCdra mislabels them TIMER3/COUNTER3, there being no third timer index);</li>
 * <li>{@code $FFC0-$FFFF} follows {@code CONTROL} bit 7 (see {@code createTopWindow}): clear, it
 * is RAM ({@code RAM_FFC0}); set, it is {@code IPL_ROM} -- initialized from the user's own file
 * only if those bytes hash to the stock IPL (the project ships no IPL, Sony's), otherwise
 * uninitialized, with the file's hidden bytes in a {@code RAM_UNDER_IPL} overlay. The file's
 * separate 'extra RAM' area becomes an {@code EXTRA_RAM} overlay when it differs;</li>
 * <li>{@code DSP_REGS}: an overlay block of the 128 DSP registers, each a labelled, typed
 * data item ({@code V0VOLL}, {@code KON}, {@code FLG}, {@code ESA}...). The DSP is reached through
 * {@code DSPADDR}/{@code DSPDATA} ({@code $F2}/{@code $F3}), not through the address space, so an
 * overlay is the honest place for it.</li>
 * </ul>
 *
 * <p><b>Entry point.</b> The PC in the header is where the CPU happened to be when the snapshot
 * was taken -- typically the driver's idle/wait loop or mid-routine, not the driver entry. It is
 * used as the default entry (labelled {@code SPC_ENTRY}) and can be overridden with the
 * {@code Entry point} option; the registers, PSW and the header PC are all recorded in Program
 * Info so a reader can see what the default was. The loader does not try to guess the driver
 * start from the RAM image; whole-image driver discovery is separate work.
 *
 * <p>The ID666 tag fields (title, game, dumper, comments, date, play/fade time, artist, default
 * channel mask, emulator) go to Program Info under {@code SPC.*}.
 *
 * <p>Validation lives in {@link #load} ({@code validateOptions} runs only from the GUI), via the
 * shared {@link #entryOverrideError} helper.
 */
public class SpcSnapshotLoader extends AbstractProgramWrapperLoader {
	/** Creates a loader for SPC700 snapshot files. */
	public SpcSnapshotLoader() {
	}

	/** The executable-format name stamped on imports. */
	public static final String NAME = "SPC700 Sound Snapshot (.spc)";

	/** The language this loader targets. */
	public static final String LANGUAGE_ID = SpcProgramMaterializer.LANGUAGE_ID;

	/** Option holding an entry-point override (hex address); empty means use the header PC. */
	public static final String OPTION_ENTRY = "Entry point override";

	private static final String ENTRY_CMD_ARG = Loader.COMMAND_LINE_ARG_PREFIX + "-entry";

	/** Prefix of the Program Info properties this loader writes. */
	public static final String INFO_PREFIX = "SPC.";

	static final String SIGNATURE = "SNES-SPC700 Sound File Data";
	static final int OFF_HAS_ID666 = 0x23;
	static final int OFF_PC = 0x25;
	static final int OFF_RAM = 0x100;
	static final int OFF_DSP = 0x10100;
	static final int OFF_EXTRA = 0x101C0;
	static final int RAM_SIZE = 0x10000;
	static final int DSP_SIZE = 0x80;
	static final int EXTRA_SIZE = 0x40;
	/** Smallest accepted file: header, RAM and the DSP registers. */
	static final int MIN_SIZE = OFF_DSP + DSP_SIZE;

	private static final int IO_START = 0xF0;
	private static final int IPL_START = 0xFFC0;

	/**
	 * SHA-256 of the stock SPC700 IPL boot ROM, to say "stock" or "modified" in a comment. This is
	 * a fingerprint, not the ROM.
	 */
	static final String STOCK_IPL_SHA256 =
		"c95f88b299030d5afa55b1031e2b5ef2dff650c4b4e6bb6f8b1359436521278f";

	/** Returns the executable-format name stamped on imported programs. */
	@Override
	public String getName() {
		return NAME;
	}

	/** Finds a load specification when the file carries the SPC signature and enough data.
	 *
	 * @param provider candidate file
	 * @return one load spec, or an empty collection
	 * @throws IOException if the provider cannot be read
	 */
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() >= MIN_SIZE && hasSignature(provider)) {
			specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANGUAGE_ID, "default"),
				true));
		}
		return specs;
	}

	private static boolean hasSignature(ByteProvider provider) throws IOException {
		byte[] head = provider.readBytes(0, SIGNATURE.length());
		return new String(head, java.nio.charset.StandardCharsets.ISO_8859_1).equals(SIGNATURE);
	}

	/** Returns default import options. */
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		options.add(Option.newString(OPTION_ENTRY)
				.value("")
				.commandLineArgument(ENTRY_CMD_ARG)
				.description(OptionTooltip.of("Hex address to use as the entry point instead of " +
					"the PC stored in the .spc header. The header PC is wherever the CPU was " +
					"when the snapshot was taken, not the driver's entry. Empty keeps the " +
					"header PC.", ENTRY_CMD_ARG + " 0400"))
				.build());
		return options;
	}

	/** GUI-only early rejection of an unparsable override; {@link #load} re-checks it. */
	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		return entryOverrideError(OptionUtils.getOption(OPTION_ENTRY, options, ""));
	}

	/**
	 * Why an entry override string is unusable, or null if it is empty or a 16-bit hex address
	 * (optionally prefixed {@code $} or {@code 0x}).
	 *
	 * @param text the option text
	 * @return an error message, or null
	 */
	static String entryOverrideError(String text) {
		if (text == null || text.isBlank()) {
			return null;
		}
		return parseEntry(text) < 0
				? "Entry point override '" + text + "' is not a hex address in $0000-$FFFF"
				: null;
	}

	/**
	 * Parses an entry override.
	 *
	 * @param text hex digits, optionally prefixed {@code $} or {@code 0x}
	 * @return the address, or -1 if unparsable or out of range
	 */
	static int parseEntry(String text) {
		String t = text.trim();
		if (t.startsWith("$")) {
			t = t.substring(1);
		}
		else if (t.startsWith("0x") || t.startsWith("0X")) {
			t = t.substring(2);
		}
		if (t.isEmpty() || t.length() > 4) {
			return -1;
		}
		try {
			return Integer.parseInt(t, 16);
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}

	/** Loads the snapshot. */
	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		if (provider.length() < MIN_SIZE || !hasSignature(provider)) {
			log.appendMsg(NAME + ": not an SPC snapshot (need the '" + SIGNATURE +
				"' signature and at least " + MIN_SIZE + " bytes); refusing");
			return;
		}
		String override = settings.options() == null ? ""
				: OptionUtils.getOption(OPTION_ENTRY, settings.options(), "");
		String problem = entryOverrideError(override);
		if (problem != null) {
			log.appendMsg(NAME + ": " + problem + "; using the header PC");
			override = "";
		}

		BinaryReader reader = new BinaryReader(provider, true);
		int headerPc = reader.readUnsignedShort(OFF_PC);
		int regA = reader.readUnsignedByte(OFF_PC + 2);
		int regX = reader.readUnsignedByte(OFF_PC + 3);
		int regY = reader.readUnsignedByte(OFF_PC + 4);
		int psw = reader.readUnsignedByte(OFF_PC + 5);
		int sp = reader.readUnsignedByte(OFF_PC + 6);
		byte[] ram = provider.readBytes(OFF_RAM, RAM_SIZE);

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider,
			settings.monitor());
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		makeBlock(program, fileBytes, space, "RAM_0000", 0, OFF_RAM, IO_START,
			"RAM $0000-$00EF (file offset $100)", true, true, false, log);
		MemoryBlock io = makeBlock(program, fileBytes, space, "IO_F0", IO_START,
			OFF_RAM + IO_START, 0x10, "S-SMP registers $F0-$FF as captured", true, true, false,
			log);
		if (io != null) {
			io.setVolatile(true);
		}
		makeBlock(program, fileBytes, space, "RAM_0100", 0x100, OFF_RAM + 0x100,
			IPL_START - 0x100, "RAM $0100-$FFBF", true, true, true, log);
		createTopWindow(program, provider, fileBytes, space, ram, log);

		MemoryBlock dsp = null;
		try {
			dsp = MemoryBlockUtils.createInitializedBlock(program, true, "DSP_REGS",
				space.getAddress(0), fileBytes, OFF_DSP, DSP_SIZE,
				"DSP registers 0-$7F as captured; the CPU reaches them through DSPADDR/DSPDATA " +
					"($F2/$F3)",
				NAME, true, true, false, log);
		}
		catch (Exception e) {
			log.appendMsg(NAME + ": could not create DSP_REGS: " + e.getMessage());
		}
		if (dsp != null) {
			dsp.setVolatile(true);
			labelDsp(program, dsp.getStart(), log);
		}
		labelIo(program, space, log);

		Options info = program.getOptions(Program.PROGRAM_INFO);
		recordInfo(provider, info, headerPc, regA, regX, regY, psw, sp,
			(ram[0xF1] & 0x80) != 0);

		int entry = headerPc;
		boolean overridden = false;
		if (!override.isBlank()) {
			entry = parseEntry(override);
			overridden = entry != headerPc;
		}
		info.setString(INFO_PREFIX + "Entry", String.format("$%04X", entry));
		info.setString(INFO_PREFIX + "Entry source", overridden ? "option" : "header PC");
		createEntry(program, space, entry, headerPc, psw, overridden, log);
		RetroAnalysisDefaults.apply(program, log, NAME);
	}

	private MemoryBlock makeBlock(Program program, FileBytes fileBytes, AddressSpace space,
			String name, int start, int fileOffset, int size, String comment, boolean r, boolean w,
			boolean x, MessageLog log) {
		try {
			return MemoryBlockUtils.createInitializedBlock(program, false, name,
				space.getAddress(start), fileBytes, fileOffset, size, comment, NAME, r, w, x, log);
		}
		catch (Exception e) {
			log.appendMsg(NAME + ": could not create block " + name + ": " + e.getMessage());
			return null;
		}
	}

	/**
	 * The 64 bytes at $FFC0. With CONTROL bit 7 set the IPL boot ROM is what the CPU sees there;
	 * clear, it is RAM. The IPL is Sony's and this project does not ship it, so an initialized
	 * {@code IPL_ROM} block is created only when the user's own file demonstrably carries the stock
	 * IPL (SHA-256 match); otherwise it is an uninitialized block and the file's bytes go to an
	 * overlay. A clear bit 7 makes the window plain RAM.
	 */
	private void createTopWindow(Program program, ByteProvider provider, FileBytes fileBytes,
			AddressSpace space, byte[] ram, MessageLog log) throws IOException {
		boolean iplEnabled = (ram[0xF1] & 0x80) != 0;
		String sha = sha256(ram, IPL_START, 0x40);
		boolean stock = STOCK_IPL_SHA256.equals(sha);
		boolean haveExtra = provider.length() >= OFF_EXTRA + EXTRA_SIZE;
		byte[] extra = haveExtra ? provider.readBytes(OFF_EXTRA, EXTRA_SIZE) : null;
		boolean extraDiffers = haveExtra &&
			!java.util.Arrays.equals(extra, java.util.Arrays.copyOfRange(ram, IPL_START, RAM_SIZE));
		String where = "CONTROL bit 7 is " + (iplEnabled ? "set: the IPL ROM is mapped in. "
				: "clear: the IPL ROM is disabled and $FFC0-$FFFF is RAM. ") +
			"RAM-image bytes at $FFC0 have SHA-256 " + sha + (stock ? " = the stock IPL" : "");
		if (iplEnabled && stock) {
			makeBlock(program, fileBytes, space, "IPL_ROM", IPL_START, OFF_RAM + IPL_START, 0x40,
				"SPC700 IPL boot ROM, from the user's file. " + where, true, false, true, log);
		}
		else if (iplEnabled) {
			try {
				MemoryBlockUtils.createUninitializedBlock(program, false, "IPL_ROM",
					space.getAddress(IPL_START), 0x40, "SPC700 IPL boot ROM, not included (Sony's, " +
						"not redistributed; this file's image does not carry it). " + where,
					NAME, true, false, true, log);
			}
			catch (Exception e) {
				log.appendMsg(NAME + ": could not create IPL_ROM: " + e.getMessage());
			}
			makeOverlay(program, fileBytes, space, "RAM_UNDER_IPL", OFF_RAM + IPL_START,
				"RAM image at $FFC0 hidden under the IPL ROM", log);
		}
		else {
			makeBlock(program, fileBytes, space, "RAM_FFC0", IPL_START, OFF_RAM + IPL_START, 0x40,
				"RAM $FFC0-$FFFF. " + where, true, true, true, log);
		}
		if (extraDiffers) {
			makeOverlay(program, fileBytes, space, "EXTRA_RAM", OFF_EXTRA,
				"The file's 'extra RAM' area, which differs from the RAM image at $FFC0", log);
		}
	}

	private void makeOverlay(Program program, FileBytes fileBytes, AddressSpace space, String name,
			int fileOffset, String comment, MessageLog log) {
		try {
			MemoryBlockUtils.createInitializedBlock(program, true, name, space.getAddress(IPL_START),
				fileBytes, fileOffset, EXTRA_SIZE, comment, NAME, true, true, true, log);
		}
		catch (Exception e) {
			log.appendMsg(NAME + ": could not create " + name + ": " + e.getMessage());
		}
	}

	static String sha256(byte[] data, int off, int len) {
		try {
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
			md.update(data, off, len);
			StringBuilder sb = new StringBuilder();
			for (byte b : md.digest()) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		}
		catch (java.security.NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	// ---- register tables ---------------------------------------------------------------

	/** S-SMP registers $F0-$FF: name per offset from $F0. */
	static final String[] IO_NAMES = { "TEST", "CONTROL", "DSPADDR", "DSPDATA", "CPUIO0", "CPUIO1",
		"CPUIO2", "CPUIO3", "AUXIO4", "AUXIO5", "T0TARGET", "T1TARGET", "T2TARGET", "T0OUT",
		"T1OUT", "T2OUT" };

	private static final String[] VOICE_REGS =
		{ "VOLL", "VOLR", "PITCHL", "PITCHH", "SRCN", "ADSR1", "ADSR2", "GAIN", "ENVX", "OUTX" };

	/** Global DSP registers by address (x$0C, x$1C, ... x$7D). */
	private static String globalDspName(int reg) {
		return switch (reg) {
			case 0x0C -> "MVOLL";
			case 0x1C -> "MVOLR";
			case 0x2C -> "EVOLL";
			case 0x3C -> "EVOLR";
			case 0x4C -> "KON";
			case 0x5C -> "KOF";
			case 0x6C -> "FLG";
			case 0x7C -> "ENDX";
			case 0x0D -> "EFB";
			case 0x2D -> "PMON";
			case 0x3D -> "NON";
			case 0x4D -> "EON";
			case 0x5D -> "DIR";
			case 0x6D -> "ESA";
			case 0x7D -> "EDL";
			default -> null;
		};
	}

	/**
	 * The name of DSP register {@code reg} (0-$7F): {@code V<n><field>}, a global name,
	 * {@code COEF<n>}, or {@code DSP_<hh>} for the unused slots.
	 *
	 * @param reg the DSP register number
	 * @return its name
	 */
	static String dspName(int reg) {
		int lo = reg & 0x0F;
		if (lo <= 9) {
			return "V" + (reg >> 4) + VOICE_REGS[lo];
		}
		if (lo == 0x0F) {
			return "COEF" + (reg >> 4);
		}
		String g = globalDspName(reg);
		return g != null ? g : String.format("DSP_%02X", reg);
	}

	private void labelIo(Program program, AddressSpace space, MessageLog log) {
		for (int i = 0; i < IO_NAMES.length; i++) {
			define(program, space.getAddress(IO_START + i), IO_NAMES[i], ByteDataType.dataType,
				log);
		}
	}

	private void labelDsp(Program program, Address base, MessageLog log) {
		for (int reg = 0; reg < DSP_SIZE; reg++) {
			int lo = reg & 0x0F;
			if (lo == 3) {
				continue;   // PITCHH: covered by the word at PITCHL
			}
			boolean pitch = lo == 2;
			Address a = base.add(reg);
			String name = dspName(reg);
			if (pitch) {
				name = "V" + (reg >> 4) + "PITCH";
			}
			define(program, a, name, pitch ? WordDataType.dataType : ByteDataType.dataType, log);
			if (pitch) {
				try {
					program.getSymbolTable().createLabel(a.add(1), dspName(reg + 1),
						SourceType.IMPORTED);
				}
				catch (Exception e) {
					log.appendMsg(NAME + ": could not label " + dspName(reg + 1));
				}
			}
		}
	}

	private void define(Program program, Address a, String name, DataType type, MessageLog log) {
		try {
			program.getSymbolTable().createLabel(a, name, SourceType.IMPORTED);
			DataUtilities.createData(program, a, type, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (Exception e) {
			log.appendMsg(NAME + ": could not define " + name + " at " + a + ": " +
				e.getMessage());
		}
	}

	// ---- header / ID666 ----------------------------------------------------------------

	private void recordInfo(ByteProvider provider, Options info, int headerPc,
			int a, int x, int y, int psw, int sp, boolean iplEnabled)
			throws IOException {
		info.setString(INFO_PREFIX + "Header PC", String.format("$%04X", headerPc));
		info.setString(INFO_PREFIX + "A", String.format("$%02X", a));
		info.setString(INFO_PREFIX + "X", String.format("$%02X", x));
		info.setString(INFO_PREFIX + "Y", String.format("$%02X", y));
		info.setString(INFO_PREFIX + "PSW", String.format("$%02X", psw));
		info.setString(INFO_PREFIX + "SP", String.format("$%02X (stack at $01%02X)", sp, sp));
		info.setString(INFO_PREFIX + "Direct page", (psw & 0x20) != 0 ? "$0100 (P set)" : "$0000");
		info.setString(INFO_PREFIX + "IPL mapped in", Boolean.toString(iplEnabled));
		info.setString(INFO_PREFIX + "File version",
			String.valueOf(provider.readByte(0x24) & 0xFF));
		boolean tag = (provider.readByte(OFF_HAS_ID666) & 0xFF) == 26;
		info.setString(INFO_PREFIX + "ID666", tag ? "present" : "absent");
		if (!tag) {
			return;
		}
		tagField(provider, info, "Song title", 0x2E, 32);
		tagField(provider, info, "Game title", 0x4E, 32);
		tagField(provider, info, "Dumper", 0x6E, 16);
		tagField(provider, info, "Comments", 0x7E, 32);
		tagField(provider, info, "Dump date", 0x9E, 11);
		tagField(provider, info, "Seconds to play", 0xA9, 3);
		tagField(provider, info, "Fade length (ms)", 0xAC, 5);
		tagField(provider, info, "Artist", 0xB1, 32);
		info.setString(INFO_PREFIX + "Default channel disable",
			String.format("$%02X", provider.readByte(0xD1) & 0xFF));
		info.setString(INFO_PREFIX + "Emulator used",
			String.format("$%02X", provider.readByte(0xD2) & 0xFF));
	}

	private static void tagField(ByteProvider provider, Options info, String name, int off,
			int len) throws IOException {
		byte[] raw = provider.readBytes(off, len);
		StringBuilder sb = new StringBuilder();
		for (byte b : raw) {
			int c = b & 0xFF;
			if (c == 0) {
				break;
			}
			sb.append(c >= 0x20 && c < 0x7F ? (char) c : '?');
		}
		info.setString(INFO_PREFIX + name, sb.toString().trim());
	}

	// ---- entry -------------------------------------------------------------------------

	private void createEntry(Program program, AddressSpace space, int entry, int headerPc,
			int psw, boolean overridden, MessageLog log) {
		Address a = space.getAddress(entry);
		try {
			program.getSymbolTable().addExternalEntryPoint(a);
			program.getSymbolTable().createLabel(a, SpcProgramMaterializer.ENTRY_LABEL,
				SourceType.IMPORTED);
			markAsFunction(program, SpcProgramMaterializer.ENTRY_LABEL, a);
			String note = overridden
					? String.format("Entry point from the loader option (header PC was $%04X).",
						headerPc)
					: "Entry point = the PC stored in the .spc header: where the CPU was when the " +
						"snapshot was taken, usually a driver wait loop or mid-routine, not the " +
						"driver's start.";
			if ((psw & 0x20) != 0) {
				note += " The captured PSW has P set (direct page $0100); the language models " +
					"P at run time, so direct-page operands decode relative to P=0.";
			}
			AnalyzerCommentRecord.set(program, a, CommentType.PLATE, note);
		}
		catch (Exception e) {
			log.appendMsg(NAME + ": could not create the entry point at " + a + ": " +
				e.getMessage());
		}
		log.appendMsg(NAME + ": entry point $" + Integer.toHexString(entry) +
			(overridden ? " (override)" : " (header PC)"));
	}
}
