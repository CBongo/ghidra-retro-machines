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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import ghidra.pcode.emu.EmulatorUtilities;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the sound-driver uploads of a SNES ROM by running the 65816 under p-code emulation
 * against an {@link SpcIplModel} (the SPC700 IPL boot-ROM handshake on {@code $2140-$2143}),
 * recording every block the ROM sends to the SPC700 and the entry address it finally jumps to
 * (bead grm-1.7.3). One model, no per-game recognizer: the only route that places uploads whose
 * destinations are looked up through the uploader's own long loads (Secret of Mana, FF3 and the
 * like) rather than sitting in a static block list.
 *
 * <p><b>Two entry strategies, tried in order.</b>
 * <ol>
 * <li>{@link Strategy#RESET} -- run from the reset vector ({@code $00:FFFC}, emulation mode).
 * Most games upload during boot.</li>
 * <li>{@link Strategy#UPLOADER} -- some games (Secret of Mana) boot into an interrupt-driven
 * loop and upload only when the game asks for music. The handshake has a fixed fingerprint -- a
 * {@code CMP}/{@code CPX}/{@code CPY} of {@code $2140} against {@code #$BBAA}, loaded as a 16-bit
 * immediate just before -- so {@link #findUploaderCandidates} locates those sites, derives
 * candidate routine entries (the containing Ghidra function if there is one, otherwise the
 * nearest {@code JMP}/{@code JSR}/{@code JSL} target within {@code $100} bytes before the site)
 * and runs each directly, in native mode with 8-bit registers.</li>
 * </ol>
 *
 * <p><b>Model facts</b> (all hardware, none per game; learned by the spike, see the bead):
 * <ul>
 * <li>The SPC side reacts at 65816 <em>instruction boundaries</em> (see {@link SpcIplModel}).</li>
 * <li>{@code EmulatorUtilities.loadProgram} copies only initialized blocks and skips byte-mapped
 * ones, so HiROM's bank-{@code $00} code window would fault at step 0; mapped blocks are loaded
 * explicitly here, except the {@code LOWRAM_xx} views, which must stay coherent with WRAM:
 * accesses to {@code $00-$3F/$80-$BF:0000-1FFF} are redirected to {@code $7E:xxxx}.</li>
 * <li>M/X/E context: {@code SEP}/{@code REP} flow through emulation correctly, but {@code XCE},
 * {@code PLP} and {@code RTI} change context bits the decoder cannot know, so the thread's
 * context is overridden after each from the carry flag / pulled status byte, and the
 * {@code unknown_native_status_pull} userop is answered.</li>
 * <li>NMI is injected when {@code $4200} bit 7 is set (and on {@code WAI}), a timer IRQ when
 * {@code $4200} bits 4-5 are set and the I flag is clear. Reads of other I/O registers
 * ({@code $2100-$21FF}, {@code $4000-$43FF}) alternate {@code $FF}/{@code $00} per address so
 * wait loops of either polarity exit.</li>
 * </ul>
 *
 * <p>Every run is bounded by {@link StopConditions} (instruction fuel and wall clock). The
 * result never claims success unless the IPL model actually saw the jump command.
 */
public class SpcUploadRecovery {

	/** The only language this recovery runs over. */
	public static final String LANGUAGE_ID = "65816:LE:24:retro";

	/** Default instruction budget per attempt (the spike's slowest corpus title needed 1.5M). */
	public static final long DEFAULT_FUEL = 5_000_000L;
	/** Default wall-clock budget per attempt, in milliseconds. */
	public static final long DEFAULT_WALLCLOCK_MILLIS = 120_000L;

	/** Instructions between injected NMIs (and a quarter of that between timer IRQs). */
	private static final long INTERRUPT_PERIOD = 40_000L;
	/** The most uploader candidates {@link #recover} will try. */
	private static final int MAX_CANDIDATES = 8;
	/** Budget cap per uploader candidate: a real uploader reaches the jump in well under this. */
	private static final long CANDIDATE_FUEL = 1_000_000L;
	private static final long CANDIDATE_WALLCLOCK_MILLIS = 15_000L;
	/** How far back from a handshake site a call/jump target may be to count as its routine. */
	private static final int ENTRY_REACH = 0x100;
	/** How far before the compare the {@code #$BBAA} immediate load may sit. */
	private static final int LOAD_REACH = 24;
	private static final int IO_HISTOGRAM_CAP = 256;
	private static final int USEROP_LOG_CAP = 16;

	/** Which entry strategy produced a result. */
	public enum Strategy {
		/** Emulation from the reset vector. */
		RESET,
		/** Direct entry at a routine located by the {@code #$BBAA} handshake signature. */
		UPLOADER
	}

	/** Why one attempt stopped. */
	public enum Stop {
		/** The IPL model received the jump/entry command: the upload is complete. */
		IPL_DONE,
		/** Instruction budget exhausted. */
		FUEL,
		/** Wall-clock budget exhausted. */
		WALLCLOCK,
		/** The emulated code reached memory the image does not populate. */
		DECODE_FAULT,
		/** The monitor was cancelled. */
		CANCELLED,
		/** The program image could not be copied into the emulator. */
		LOAD_FAILED,
		/** Any other emulation failure. */
		ERROR
	}

	/** One emulation attempt. */
	public record Attempt(Strategy strategy, Address entry, Stop stop, long steps, int blocks) {}

	/** The outcome of a recovery. */
	public static final class Result {
		private final Strategy strategy;
		private final Address uploaderEntry;
		private final Stop stop;
		private final long steps;
		private final List<SpcIplModel.Block> blocks;
		private final int entry;
		private final List<Attempt> attempts;
		private final ProvenanceLog log;
		private final Map<Integer, Integer> ioReads;
		private final String programName;

		Result(Strategy strategy, Address uploaderEntry, Stop stop, long steps,
				List<SpcIplModel.Block> blocks, int entry, List<Attempt> attempts, ProvenanceLog log,
				Map<Integer, Integer> ioReads, String programName) {
			this.strategy = strategy;
			this.uploaderEntry = uploaderEntry;
			this.stop = stop;
			this.steps = steps;
			this.blocks = blocks;
			this.entry = entry;
			this.attempts = attempts;
			this.log = log;
			this.ioReads = ioReads;
			this.programName = programName;
		}

		/** Whether the IPL handshake completed (the jump command was seen).
		 * @return true on a complete upload
		 */
		public boolean success() {
			return stop == Stop.IPL_DONE;
		}

		/** The strategy of the attempt this result describes.
		 * @return the strategy
		 */
		public Strategy strategy() {
			return strategy;
		}

		/** The direct-entry address for {@link Strategy#UPLOADER}; null for {@link Strategy#RESET}.
		 * @return the uploader entry, or null
		 */
		public Address uploaderEntry() {
			return uploaderEntry;
		}

		/** Why the described attempt stopped.
		 * @return the stop reason
		 */
		public Stop stop() {
			return stop;
		}

		/** Instructions executed by the described attempt.
		 * @return the step count
		 */
		public long steps() {
			return steps;
		}

		/** The blocks uploaded, in order.
		 * @return an unmodifiable list
		 */
		public List<SpcIplModel.Block> blocks() {
			return blocks;
		}

		/** The SPC700 entry address the ROM finally jumped to.
		 * @return the entry address, or -1 if the jump was never seen
		 */
		public int entry() {
			return entry;
		}

		/** Every attempt made, in order (for diagnostics).
		 * @return an unmodifiable list
		 */
		public List<Attempt> attempts() {
			return attempts;
		}

		/** Diagnostics: attempt summaries, unhandled userops, warnings. Bounded.
		 * @return the log
		 */
		public ProvenanceLog provenance() {
			return log;
		}

		/** Histogram of reads of unmodelled I/O registers (CPU offset to count), bounded in
		 *  distinct keys; the APU ports are not included.
		 * @return an unmodifiable sorted map
		 */
		public Map<Integer, Integer> ioReads() {
			return ioReads;
		}

		/** Name of the program the result was recovered from.
		 * @return the source program name
		 */
		public String programName() {
			return programName;
		}
	}

	private final Program program;
	private final Language lang;
	private final AddressSpace ram;

	/**
	 * Creates a runner over one loaded SNES program.
	 *
	 * @param program the loaded program; must use the {@value #LANGUAGE_ID} language
	 */
	public SpcUploadRecovery(Program program) {
		this.program = Objects.requireNonNull(program, "program");
		this.lang = program.getLanguage();
		this.ram = program.getAddressFactory().getDefaultAddressSpace();
		if (!applies(program)) {
			throw new IllegalArgumentException("not a 65816 program: " + program.getLanguageID());
		}
	}

	/**
	 * Whether this recovery can run on a program.
	 *
	 * @param program the program to test
	 * @return true for the {@value #LANGUAGE_ID} language
	 */
	public static boolean applies(Program program) {
		return program != null && LANGUAGE_ID.equals(program.getLanguageID().getIdAsString());
	}

	/**
	 * Whether a program is a SNES cartridge imported by {@link SnesRomLoader} -- the gate for
	 * anything that runs unasked (the analyzer) or assumes the SNES machine. The APU ports at
	 * {@code $2140}, the {@code $7E} low-RAM mirror and the vector layout belong to the SNES, not
	 * to the 65816, so {@link #applies} (a language check, which is what the emulator itself needs)
	 * is not enough: another 65816 machine, e.g. an Apple IIgs, must not be treated as one.
	 *
	 * @param program the program to test
	 * @return whether the program came from the SNES ROM loader and uses the 65816 language
	 */
	public static boolean isSnesRom(Program program) {
		return applies(program) && SnesRomLoader.NAME.equals(program.getExecutableFormat());
	}

	/**
	 * Run both strategies in order: the reset vector first, then uploader candidates until one
	 * completes the IPL handshake. If none does, the attempt that got furthest is returned
	 * (check {@link Result#success()}).
	 *
	 * @param stop per-attempt bounds for the reset run; null uses {@link #DEFAULT_FUEL} /
	 *             {@link #DEFAULT_WALLCLOCK_MILLIS}. Candidate runs are further capped.
	 * @param monitor cancellation monitor; null for none
	 * @return the result; never null
	 */
	public Result recover(StopConditions stop, TaskMonitor monitor) {
		TaskMonitor mon = monitor != null ? monitor : TaskMonitor.DUMMY;
		long fuel = stop != null ? stop.instructionFuel() : DEFAULT_FUEL;
		long wall = stop != null ? stop.wallClockMillis() : DEFAULT_WALLCLOCK_MILLIS;
		ProvenanceLog log = new ProvenanceLog();
		List<Attempt> attempts = new ArrayList<>();
		Result best = attempt(Strategy.RESET, null, fuel, wall, mon, log, attempts);
		if (best.success() || mon.isCancelled()) {
			return best;
		}
		List<Address> candidates = findUploaderCandidates(program);
		int tried = 0;
		for (Address cand : candidates) {
			if (tried++ >= MAX_CANDIDATES || mon.isCancelled()) {
				break;
			}
			Result r = attempt(Strategy.UPLOADER, cand, Math.min(fuel, CANDIDATE_FUEL),
				Math.min(wall, CANDIDATE_WALLCLOCK_MILLIS), mon, log, attempts);
			if (r.success()) {
				return r;
			}
			if (r.blocks().size() > best.blocks().size()) {
				best = r;
			}
		}
		return best;
	}

	/**
	 * Run only the uploader strategy at an explicit routine address.
	 *
	 * @param uploaderEntry the routine to run directly (native mode, 8-bit registers)
	 * @param stop bounds; null uses the defaults
	 * @param monitor cancellation monitor; null for none
	 * @return the result; never null
	 */
	public Result recoverFrom(Address uploaderEntry, StopConditions stop, TaskMonitor monitor) {
		TaskMonitor mon = monitor != null ? monitor : TaskMonitor.DUMMY;
		long fuel = stop != null ? stop.instructionFuel() : DEFAULT_FUEL;
		long wall = stop != null ? stop.wallClockMillis() : DEFAULT_WALLCLOCK_MILLIS;
		return attempt(Strategy.UPLOADER, uploaderEntry, fuel, wall, mon, new ProvenanceLog(),
			new ArrayList<>());
	}

	// ------------------------------------------------------------------
	// Uploader-candidate discovery
	// ------------------------------------------------------------------

	/**
	 * Locate routines that talk the IPL handshake. A <em>site</em> is a {@code CMP} (absolute or
	 * long), {@code CPX} or {@code CPY} of {@code $2140} within {@value #LOAD_REACH} bytes after
	 * an {@code LDA}/{@code LDX}/{@code LDY} of the 16-bit immediate {@code #$BBAA}. For each
	 * site the candidate entries are: the Ghidra function containing it, if the program has been
	 * analyzed; then the targets of {@code JMP abs}/{@code JSR abs}/{@code JSL} in the same bank
	 * lying within {@code $100} bytes before the site, nearest first.
	 *
	 * @param program the SNES program
	 * @return candidate routine entries, most likely first, without duplicates
	 */
	public static List<Address> findUploaderCandidates(Program program) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Set<Address> out = new LinkedHashSet<>();
		for (Address site : findHandshakeSites(program)) {
			Function fn = program.getFunctionManager().getFunctionContaining(site);
			if (fn != null) {
				out.add(fn.getEntryPoint());
			}
			long bank = site.getOffset() >> 16;
			long siteOff = site.getOffset() & 0xFFFF;
			byte[] image = readBank(program, (int) bank);
			if (image == null) {
				continue;
			}
			TreeMap<Long, Boolean> targets = new TreeMap<>();
			for (int i = 0; i + 3 < image.length; i++) {
				int op = image[i] & 0xFF;
				if (op != 0x4C && op != 0x20 && op != 0x22) {
					continue;
				}
				long t = (image[i + 1] & 0xFF) | ((image[i + 2] & 0xFF) << 8);
				if (op == 0x22) {
					int tb = image[i + 3] & 0xFF;
					if (!sameBankView(tb, (int) bank)) {
						continue;
					}
				}
				if (t <= siteOff && siteOff - t <= ENTRY_REACH) {
					targets.put(t, Boolean.TRUE);
				}
			}
			for (Long t : targets.descendingKeySet()) {
				out.add(space.getAddress((bank << 16) | t));
			}
		}
		return new ArrayList<>(out);
	}

	/** Whether a JSL target bank is the same ROM bank as the site's, allowing for the
	 *  FastROM/system mirrors ({@code $80} apart, or HiROM's {@code $00-$3F} view of {@code $C0-$FF}). */
	private static boolean sameBankView(int targetBank, int siteBank) {
		if (targetBank == siteBank || (targetBank ^ 0x80) == siteBank) {
			return true;
		}
		return siteBank >= 0xC0 && sysBank((long) targetBank << 16) &&
			(targetBank & 0x3F) == (siteBank & 0x3F);
	}

	/**
	 * Cheap pre-filter for the analyzer: does the ROM contain any absolute or long load, store
	 * or compare of {@code $2140}/{@code $2141}? A program with none cannot be talking to the
	 * IPL, so emulating it would only burn the fuel budget.
	 *
	 * @param program the SNES program
	 * @return true if some ROM instruction addresses the APU port window
	 */
	public static boolean usesApuPort(Program program) {
		for (MemoryBlock blk : program.getMemory().getBlocks()) {
			if (!blk.isInitialized() || blk.isMapped() || blk.isVolatile() ||
				!blk.getName().startsWith("ROM") || blk.getSize() > 0x1000000L) {
				continue;
			}
			byte[] b = new byte[(int) blk.getSize()];
			try {
				blk.getBytes(blk.getStart(), b);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			for (int i = 0; i + 2 < b.length; i++) {
				if ((b[i + 2] & 0xFF) != 0x21 || ((b[i + 1] & 0xFF) | 0x01) != 0x41) {
					continue;
				}
				switch (b[i] & 0xFF) {
					case 0xAD, 0xCD, 0x8D, 0xAF, 0xCF, 0x8F, 0xEC, 0xCC, 0xAE, 0xAC, 0x8E, 0x8C:
						return true;
					default:
						break;
				}
			}
		}
		return false;
	}

	/** Sites of the handshake signature, in address order. */
	static List<Address> findHandshakeSites(Program program) {
		List<Address> sites = new ArrayList<>();
		for (MemoryBlock blk : program.getMemory().getBlocks()) {
			if (!blk.isInitialized() || blk.isMapped() || blk.isVolatile() ||
				!blk.getName().startsWith("ROM") || blk.getSize() > 0x1000000L) {
				continue;
			}
			byte[] b = new byte[(int) blk.getSize()];
			try {
				blk.getBytes(blk.getStart(), b);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			for (int i = 0; i < b.length; i++) {
				int op = b[i] & 0xFF;
				boolean hit = false;
				if (i + 2 < b.length && (op == 0xCD || op == 0xEC || op == 0xCC)) {
					hit = (b[i + 1] & 0xFF) == 0x40 && (b[i + 2] & 0xFF) == 0x21;
				}
				else if (i + 3 < b.length && op == 0xCF) {
					hit = (b[i + 1] & 0xFF) == 0x40 && (b[i + 2] & 0xFF) == 0x21 &&
						sysBank((long) (b[i + 3] & 0xFF) << 16);
				}
				if (hit && loadsBBAABefore(b, i)) {
					sites.add(blk.getStart().add(i));
				}
			}
		}
		return sites;
	}

	private static boolean loadsBBAABefore(byte[] b, int site) {
		for (int j = Math.max(0, site - LOAD_REACH); j + 2 < site; j++) {
			int op = b[j] & 0xFF;
			if ((op == 0xA9 || op == 0xA2 || op == 0xA0) && (b[j + 1] & 0xFF) == 0xAA &&
				(b[j + 2] & 0xFF) == 0xBB) {
				return true;
			}
		}
		return false;
	}

	/** The 64K of one bank as the CPU sees it, or null when nothing is mapped there. */
	private static byte[] readBank(Program program, int bank) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		byte[] image = new byte[0x10000];
		boolean any = false;
		for (int off = 0; off < 0x10000; off++) {
			try {
				image[off] = program.getMemory().getByte(space.getAddress(((long) bank << 16) | off));
				any = true;
			}
			catch (MemoryAccessException | RuntimeException e) {
				image[off] = 0;
			}
		}
		return any ? image : null;
	}

	// ------------------------------------------------------------------
	// Address classification
	// ------------------------------------------------------------------

	static boolean sysBank(long a) {
		int bank = (int) ((a >> 16) & 0xFF);
		return bank <= 0x3F || (bank >= 0x80 && bank <= 0xBF);
	}

	static boolean isLowRamMirror(long a) {
		return sysBank(a) && (a & 0xFFFF) < 0x2000;
	}

	static int apuPort(long a) {
		if (!sysBank(a)) {
			return -1;
		}
		int off = (int) (a & 0xFFFF);
		return (off >= 0x2140 && off <= 0x217F) ? (off & 3) : -1;
	}

	static boolean isOtherIo(long a) {
		if (!sysBank(a)) {
			return false;
		}
		int off = (int) (a & 0xFFFF);
		return (off >= 0x2100 && off <= 0x21FF) || (off >= 0x4000 && off <= 0x43FF);
	}

	// ------------------------------------------------------------------
	// One emulation attempt
	// ------------------------------------------------------------------

	private Result attempt(Strategy strategy, Address uploaderEntry, long fuel, long wallMillis,
			TaskMonitor monitor, ProvenanceLog log, List<Attempt> attempts) {
		Session s = new Session(log);
		Stop stop = s.run(strategy, uploaderEntry, fuel, wallMillis, monitor);
		attempts.add(new Attempt(strategy, uploaderEntry, stop, s.steps, s.ipl.blocks().size()));
		log.add(ProvenanceLog.Kind.INFO, uploaderEntry, 0,
			strategy + " attempt: " + stop + " steps=" + s.steps + " blocks=" + s.ipl.blocks().size());
		return new Result(strategy, uploaderEntry, stop, s.steps,
			Collections.unmodifiableList(new ArrayList<>(s.ipl.blocks())), s.ipl.entry(),
			Collections.unmodifiableList(new ArrayList<>(attempts)), log,
			Collections.unmodifiableMap(new TreeMap<>(s.ioReads)), program.getName());
	}

	/** All state of one run; also the emulator callbacks. */
	private final class Session implements PcodeEmulationCallbacks<byte[]> {
		final SpcIplModel ipl = new SpcIplModel();
		final ProvenanceLog log;
		final Map<Integer, Integer> ioReads = new HashMap<>();
		final Map<String, Integer> userops = new TreeMap<>();
		long steps;
		long lastPc;
		boolean nmiEnabled;
		boolean irqEnabled;
		boolean waiPending;
		Integer pendingE;
		Integer pendingM;
		Integer pendingX;
		int pulledP = -1;
		Register rS, rCF, rNF, rVF, rDF, rIF, rZF, rMF, rXF, rEF;

		Session(ProvenanceLog log) {
			this.log = log;
			rS = lang.getRegister("SP");
			rCF = lang.getRegister("CF");
			rNF = lang.getRegister("NF");
			rVF = lang.getRegister("VF");
			rDF = lang.getRegister("DF");
			rIF = lang.getRegister("IF");
			rZF = lang.getRegister("ZF");
			rMF = lang.getRegister("ctx_MF");
			rXF = lang.getRegister("ctx_XF");
			rEF = lang.getRegister("ctx_EF");
		}

		Stop run(Strategy strategy, Address uploaderEntry, long fuel, long wallMillis,
				TaskMonitor monitor) {
			PcodeEmulator emu = new PcodeEmulator(lang, this);
			try {
				return runIn(emu, strategy, uploaderEntry, fuel, wallMillis, monitor);
			}
			finally {
				EmulationRecovery.releaseUseropSymbols(emu);
			}
		}

		private Stop runIn(PcodeEmulator emu, Strategy strategy, Address uploaderEntry, long fuel,
				long wallMillis, TaskMonitor monitor) {
			try {
				EmulatorUtilities.loadProgram(emu, program);
				// loadProgram skips byte-mapped blocks (HiROM's bank-$00 code window is one);
				// copy them in, but not the LOWRAM views, which alias WRAM (see class doc).
				for (MemoryBlock blk : program.getMemory().getBlocks()) {
					if (!blk.isMapped() || blk.getName().startsWith("LOWRAM")) {
						continue;
					}
					byte[] buf = new byte[(int) blk.getSize()];
					int n = blk.getBytes(blk.getStart(), buf);
					emu.getSharedState().setConcrete(blk.getStart(),
						n == buf.length ? buf : java.util.Arrays.copyOf(buf, n));
				}
			}
			catch (MemoryAccessException | RuntimeException e) {
				log.add(ProvenanceLog.Kind.WARNING, uploaderEntry, 0, "load failed: " + e);
				return Stop.LOAD_FAILED;
			}

			Address entry;
			PcodeThread<byte[]> t = emu.newThread();
			try {
				if (strategy == Strategy.RESET) {
					entry = ram.getAddress(read16(0xFFFC));
					EmulatorUtilities.initializeRegisters(t, program, entry);
					setReg(t, rS, 0x01FF);
				}
				else {
					entry = uploaderEntry;
					EmulatorUtilities.initializeRegisters(t, program, entry);
					// A JSL/JSR caller leaves native mode with 8-bit registers.
					RegisterValue c = t.getContext();
					c = c.assign(rEF, BigInteger.ZERO).assign(rMF, BigInteger.ONE).assign(rXF,
						BigInteger.ONE);
					t.overrideContext(c);
					setReg(t, rS, 0x1FF0);
				}
			}
			catch (RuntimeException e) {
				log.add(ProvenanceLog.Kind.WARNING, uploaderEntry, 0, "start failed: " + e);
				return Stop.LOAD_FAILED;
			}

			// Power-on register values. Reading a never-written register makes the emulator log a
			// warning on every read (tens of thousands of lines), so define them all up front.
			for (String n : new String[] { "C", "X", "Y", "DP", "DBR", "NF", "VF", "DF", "ZF",
				"CF" }) {
				Register r = lang.getRegister(n);
				if (r != null) {
					setReg(t, r, 0);
				}
			}
			setReg(t, rIF, 1);

			final long deadline = System.currentTimeMillis() + wallMillis;
			long lastNmi = 0;
			long lastIrq = 0;
			Stop stop = Stop.FUEL;
			try {
				while (true) {
					if (ipl.isDone()) {
						stop = Stop.IPL_DONE;
						break;
					}
					if (monitor.isCancelled()) {
						stop = Stop.CANCELLED;
						break;
					}
					if (steps >= fuel) {
						stop = Stop.FUEL;
						break;
					}
					if ((steps & 0x3FF) == 0 && System.currentTimeMillis() >= deadline) {
						stop = Stop.WALLCLOCK;
						break;
					}
					if (nmiEnabled && (waiPending || steps - lastNmi >= INTERRUPT_PERIOD)) {
						interrupt(t, 0xFFEA, 0xFFFA);
						lastNmi = steps;
						waiPending = false;
					}
					else if (irqEnabled && reg(t, rIF) == 0 &&
						steps - lastIrq >= INTERRUPT_PERIOD / 4) {
						interrupt(t, 0xFFEE, 0xFFFE);
						lastIrq = steps;
					}
					t.stepInstruction();
					steps++;
				}
			}
			catch (DecodePcodeExecutionException e) {
				log.add(ProvenanceLog.Kind.INFO, safePc(t), 0,
					"decode into uninitialized memory: " + e.getMessage());
				stop = Stop.DECODE_FAULT;
			}
			catch (PcodeExecutionException e) {
				log.add(ProvenanceLog.Kind.WARNING, safePc(t), 0,
					"pcode execution aborted: " + e.getMessage());
				stop = Stop.ERROR;
			}
			catch (RuntimeException e) {
				log.add(ProvenanceLog.Kind.WARNING, safePc(t), 0, "emulation error: " + e);
				stop = Stop.ERROR;
			}
			for (Map.Entry<String, Integer> e : userops.entrySet()) {
				log.add(ProvenanceLog.Kind.INFO, null, 0,
					"unhandled userop " + e.getKey() + " x" + e.getValue());
			}
			return stop;
		}

		private Address safePc(PcodeThread<byte[]> t) {
			try {
				return t.getCounter();
			}
			catch (RuntimeException e) {
				return null;
			}
		}

		// ---- callbacks ----

		private byte[] b1(int v) {
			return new byte[] { (byte) v };
		}

		@Override
		public void beforeLoad(PcodeThread<byte[]> t, PcodeOp op, AddressSpace space, byte[] offset,
				int size) {
			if (!ram.equals(space)) {
				return;
			}
			long a0 = t.getArithmetic().toLong(offset, Purpose.LOAD);
			for (int i = 0; i < size; i++) {
				long a = (a0 + i) & 0xFFFFFF;
				if (isLowRamMirror(a)) {
					long canon = 0x7E0000L | (a & 0x1FFF);
					byte[] v = t.getState().getVar(ram, canon, 1, true, Reason.INSPECT);
					t.getState().setVar(ram, a, 1, true, v);
					continue;
				}
				int p = apuPort(a);
				if (p >= 0) {
					t.getState().setVar(ram, a, 1, true, b1(ipl.portRead(p)));
				}
				else if (isOtherIo(a)) {
					int key = (int) (a & 0xFFFF);
					Integer cur = ioReads.get(key);
					if (cur == null && ioReads.size() >= IO_HISTOGRAM_CAP) {
						// Histogram is bounded; the value alternation still needs a count, but an
						// untracked key just reads $FF first, which is the same policy.
						t.getState().setVar(ram, a, 1, true, b1(0xFF));
						continue;
					}
					int n = cur == null ? 1 : cur + 1;
					ioReads.put(key, n);
					t.getState().setVar(ram, a, 1, true, b1((n & 1) == 1 ? 0xFF : 0x00));
				}
			}
		}

		@Override
		public void afterStore(PcodeThread<byte[]> t, PcodeOp op, AddressSpace space, byte[] offset,
				int size, byte[] value) {
			if (!ram.equals(space)) {
				return;
			}
			long a0 = t.getArithmetic().toLong(offset, Purpose.STORE);
			for (int i = 0; i < size; i++) {
				long a = (a0 + i) & 0xFFFFFF;
				// Little-endian language: value[i] is the byte at a0+i.
				int bv = value[i] & 0xFF;
				if (isLowRamMirror(a)) {
					long canon = 0x7E0000L | (a & 0x1FFF);
					t.getState().setVar(ram, canon, 1, true, b1(bv));
				}
				int p = apuPort(a);
				if (p >= 0) {
					ipl.portWritten(p, bv);
				}
				else if (isOtherIo(a) && (a & 0xFFFF) == 0x4200) {
					nmiEnabled = (bv & 0x80) != 0;
					irqEnabled = (bv & 0x30) != 0;
				}
			}
		}

		@Override
		public boolean handleMissingUserop(PcodeThread<byte[]> t, PcodeOp op, PcodeFrame frame,
				String opName, PcodeUseropLibrary<byte[]> library) {
			if (opName.equals("unknown_native_status_pull")) {
				// X-flag of the status byte just pulled, for the sleigh that sizes the index regs.
				int x16 = (pulledP >= 0 && (pulledP & 0x10) == 0) ? 1 : 0;
				if (op.getOutput() != null) {
					t.getState().setVar(op.getOutput(), b1(x16));
				}
				return true;
			}
			if (opName.equals("wai")) {
				waiPending = true;
				return true;
			}
			if (userops.size() < USEROP_LOG_CAP || userops.containsKey(opName)) {
				userops.merge(opName, 1, Integer::sum);
			}
			return true;
		}

		@Override
		public void beforeExecuteInstruction(PcodeThread<byte[]> t, Instruction ins,
				PcodeProgram pcode) {
			lastPc = t.getCounter().getOffset();
			String m = ins.getMnemonicString();
			pendingE = pendingM = pendingX = null;
			pulledP = -1;
			if (m.equals("XCE")) {
				int cf = reg(t, rCF);
				int e = ctx(t, rEF);
				pendingE = cf;
				if (cf == 1 || e == 1) {
					pendingM = 1;
					pendingX = 1;
				}
				else {
					pendingM = ctx(t, rMF);
					pendingX = ctx(t, rXF);
				}
			}
			else if (m.equals("PLP") || m.equals("RTI")) {
				int sp = reg(t, rS);
				int e = ctx(t, rEF);
				long pa = e == 1 ? (0x0100 | ((sp + 1) & 0xFF)) : ((sp + 1) & 0xFFFF);
				byte[] v =
					t.getState().getVar(ram, 0x7E0000L | (pa & 0x1FFF), 1, true, Reason.INSPECT);
				pulledP = v[0] & 0xFF;
				if (e == 1) {
					pendingM = 1;
					pendingX = 1;
				}
				else {
					pendingM = (pulledP >> 5) & 1;
					pendingX = (pulledP >> 4) & 1;
				}
				pendingE = e;
			}
		}

		@Override
		public void afterExecuteInstruction(PcodeThread<byte[]> t, Instruction ins) {
			ipl.instructionBoundary(lastPc, steps + 1);
			if (pendingE != null) {
				RegisterValue c = t.getContext();
				c = c.assign(rEF, BigInteger.valueOf(pendingE));
				c = c.assign(rMF, BigInteger.valueOf(pendingM));
				c = c.assign(rXF, BigInteger.valueOf(pendingX));
				t.overrideContext(c);
			}
		}

		// ---- register and memory helpers ----

		int reg(PcodeThread<byte[]> t, Register r) {
			return (int) t.getArithmetic().toLong(t.getState().getVar(r, Reason.INSPECT),
				Purpose.INSPECT);
		}

		int ctx(PcodeThread<byte[]> t, Register r) {
			return t.getContext().getRegisterValue(r).getUnsignedValueIgnoreMask().intValue();
		}

		void setReg(PcodeThread<byte[]> t, Register r, long v) {
			t.getState().setVar(r, t.getArithmetic().fromConst(v, r.getMinimumByteSize()));
		}

		void push(PcodeThread<byte[]> t, int v, boolean emulationMode) {
			int sp = reg(t, rS);
			long a = emulationMode ? (0x0100 | (sp & 0xFF)) : (sp & 0xFFFF);
			t.getState().setVar(ram, 0x7E0000L | (a & 0x1FFF), 1, true, b1(v));
			sp = emulationMode ? (0x0100 | ((sp - 1) & 0xFF)) : ((sp - 1) & 0xFFFF);
			setReg(t, rS, sp);
		}

		/** Take an interrupt: push PBR/PC/P, set I, clear D, vector through ROM. */
		void interrupt(PcodeThread<byte[]> t, int nativeVec, int emuVec) {
			int e = ctx(t, rEF);
			long pc = t.getCounter().getOffset();
			int p = (reg(t, rNF) << 7) | (reg(t, rVF) << 6) | (ctx(t, rMF) << 5) |
				(ctx(t, rXF) << 4) | (reg(t, rDF) << 3) | (reg(t, rIF) << 2) |
				(reg(t, rZF) << 1) | reg(t, rCF);
			boolean emu = e == 1;
			if (!emu) {
				push(t, (int) ((pc >> 16) & 0xFF), false);
			}
			push(t, (int) ((pc >> 8) & 0xFF), emu);
			push(t, (int) (pc & 0xFF), emu);
			push(t, emu ? (p & ~0x10) : p, emu);
			setReg(t, rIF, 1);
			setReg(t, rDF, 0);
			int vec = read16(emu ? emuVec : nativeVec);
			t.overrideCounter(ram.getAddress(vec & 0xFFFF));
		}
	}

	/** Reads a little-endian word from program memory (vectors live in ROM). */
	private int read16(long a) {
		try {
			return (program.getMemory().getByte(ram.getAddress(a)) & 0xFF) |
				((program.getMemory().getByte(ram.getAddress(a + 1)) & 0xFF) << 8);
		}
		catch (MemoryAccessException e) {
			throw new IllegalStateException("cannot read vector at " + Long.toHexString(a), e);
		}
	}
}
