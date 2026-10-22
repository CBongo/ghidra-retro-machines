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
package retromachines.vectors;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

import retromachines.vectors.VectorRunner.CaseResult;

/**
 * Shared plumbing for the two NMOS 6502 vector JUnit tests (bead grm-hzv8):
 * {@code Mos6502VectorSampleTest} (the vendored 8192-case sample, {@code unit} chunk) and
 * {@code Mos6502VectorExhaustiveTest} (the full 2,560,000-case suite against
 * {@code GRM_6502_VECTORS}, {@code 6502-vectors} chunk). Mirrors
 * {@code Spc700VectorHarnessSupport}'s shape and role; see that class for the general design
 * this one specializes, and {@code W65816VectorHarnessSupport} for the idea (borrowed below)
 * of splitting a packed status field into per-flag synthetic fields.
 *
 * <p>Language id: {@code 6502:LE:16:undoc} (this module's {@code data/languages/6502undoc.slaspec}
 * = {@code 6502core.sinc} + {@code 6510_illegal.sinc}) -- the NMOS 6502 WITH decimal mode and the
 * documented illegal/undocumented opcodes, decoding the SingleStepTests/65x02 {@code 6502/v1/}
 * corpus (256 opcode files, 10,000 cases each).
 *
 * <h2>The packed {@code p} field has no backing register</h2>
 * {@code 6502core.sinc} defines {@code N V B D I Z C} as separate one-byte registers (offset
 * 0x30) -- there is no packed status register kept in sync in this language at all, unlike
 * SPC700's single {@code PSW} byte. Exactly as {@code W65816VectorHarnessSupport} does for its
 * own packed {@code p}, {@link #adapt} splits each case's {@code p} into six synthetic,
 * register-backed fields ({@code p_c/p_z/p_i/p_d/p_v/p_n}) before handing the case to
 * {@link VectorRunner}. Bit layout (verified against {@code define register ... [ N V B D I Z C
 * ]}, which lists them MSB to LSB: N=7, V=6, B=4, D=3, I=2, Z=1, C=0): bit 5 is unused (never a
 * real 6502 status bit) and is skipped entirely.
 *
 * <p>(Since grm-m9nu {@code PHP}/{@code BRK} push bit 4 as a constant 1, as hardware does, so the
 * seed below no longer reaches the pushed byte; it is kept because it is harmless and the
 * reasoning still holds for anything that reads the {@code B} register.)
 *
 * <p><b>The break flag ({@code B}, bit 4) is SEEDED into the initial state only, never
 * compared</b> -- the identical asymmetry {@code W65816VectorHarnessSupport} documents for its
 * own break flag, and for the same reason: {@code B} is not a real, continuously-tracked 6502
 * register in the sense the other flags are (there is no NMOS 6502 instruction that reads or
 * writes it directly under normal operation), but {@code PHP}/{@code BRK} push it onto the stack
 * as a literal bit in the pushed status byte, where the corpus's {@code ram} comparison DOES
 * check it -- so an initial case that omits it would report a spurious stack-byte mismatch on
 * every {@code PHP}/{@code BRK} case. Comparing it in the FINAL register map was tried and
 * rejected for the same reason as the 65816: nothing in this instruction set ever restores
 * {@code B} from a pulled status byte into a tracked flag (there is no corresponding "restore B"
 * operation the way {@code PLP} restores every other flag), so a final-state comparison would
 * either always trivially agree (if the language never touches the register post-seed) or
 * demand a value nothing in the instruction set is modeled as producing.
 *
 * <h2>The stack pointer's high byte ({@code SH}) is hardwired, not tracked by the corpus</h2>
 * {@code 6502core.sinc} defines {@code S} (the corpus's {@code s} field) as the LOW byte of a
 * 2-byte {@code SP} register, with {@code SH} the high byte (offset 0x20, size 1, group
 * {@code [PCL PCH S SH]} -- confirmed directly against the {@code define register} lines). Real
 * NMOS 6502 hardware hardwires the stack to page 1 ({@code $0100}-{@code $01FF}): {@code SH} is
 * never anything but {@code $01}. The corpus's vectors carry only the 8-bit {@code s} field and
 * say nothing about a high byte at all, so {@link #adapt} adds a synthetic {@code sh} field,
 * forced to {@code 1}, to BOTH the initial and final maps of every case -- unlike the break flag
 * above, this one IS compared in the final state, because on real 6502 hardware {@code SH} truly
 * never changes across any instruction; a language that ever left it at something else after a
 * single step would be a genuine, catchable bug (e.g. a stack macro that Wrote a full 16-bit
 * value to {@code SP} instead of routing through {@code S} alone).
 */
final class Mos6502VectorHarnessSupport {

	static final String LANGUAGE_ID = "6502:LE:16:undoc";

	/**
	 * Corpus field name -> Ghidra register name. The {@code p_*}/{@code sh} entries are synthetic
	 * fields {@link #adapt} manufactures -- see the class doc.
	 */
	private static final Map<String, String> REGISTER_NAMES = new LinkedHashMap<>();
	static {
		REGISTER_NAMES.put("pc", "PC");
		REGISTER_NAMES.put("s", "S");
		REGISTER_NAMES.put("sh", "SH");
		REGISTER_NAMES.put("a", "A");
		REGISTER_NAMES.put("x", "X");
		REGISTER_NAMES.put("y", "Y");
		REGISTER_NAMES.put("p_c", "C");
		REGISTER_NAMES.put("p_z", "Z");
		REGISTER_NAMES.put("p_i", "I");
		REGISTER_NAMES.put("p_d", "D");
		REGISTER_NAMES.put("p_v", "V");
		REGISTER_NAMES.put("p_n", "N");
		// Emulation-mode-style asymmetry (see class doc): seeded into the INITIAL map only by
		// adapt(), never emitted into the final map, so it can never be requested from a register
		// map entry that does not exist for the final side. Kept here anyway so registerMap()
		// resolves it once, the same way W65816VectorHarnessSupport keeps its own p_b entry.
		REGISTER_NAMES.put("p_b", "B");
	}

	/**
	 * The full 8-bit layout of the corpus's {@code p} field, for documentation and bit extraction
	 * (via {@link FlagLayout.FlagBit#valueIn}) -- see the class doc. Bit 5 is listed for
	 * completeness but is never turned into a synthetic field: it is not a real 6502 status bit
	 * (verified against {@code 6502core.sinc}'s {@code define register offset=0x30 size=1 [ N V B
	 * D I Z C ]}, which defines exactly those seven bits and nothing at bit 5).
	 */
	static final FlagLayout P_FLAGS = new FlagLayout(List.of(
		new FlagLayout.FlagBit("N", 7, 1),
		new FlagLayout.FlagBit("V", 6, 1),
		// bit 5 UNUSED -- no real 6502 status bit; never turned into a synthetic field.
		new FlagLayout.FlagBit("B", 4, 1), // seeded into the INITIAL map only; see class doc
		new FlagLayout.FlagBit("D", 3, 1),
		new FlagLayout.FlagBit("I", 2, 1),
		new FlagLayout.FlagBit("Z", 1, 1),
		new FlagLayout.FlagBit("C", 0, 1)));

	/** Every {@code p} bit turned into a synthetic field in BOTH initial and final maps. */
	private static final List<String> COMPARED_P_FLAG_NAMES =
		List.of("N", "V", "D", "I", "Z", "C");

	private static final List<FlagLayout.FlagBit> COMPARED_P_BITS = P_FLAGS.fields().stream()
			.filter(b -> COMPARED_P_FLAG_NAMES.contains(b.name()))
			.toList();

	private static final FlagLayout.FlagBit BREAK_FLAG_BIT = P_FLAGS.fields().stream()
			.filter(b -> b.name().equals("B"))
			.findFirst()
			.orElseThrow();

	private Mos6502VectorHarnessSupport() {
	}

	/** Resolves the 6502 undocumented-opcode language via a {@link ProgramBuilder}, throwing if
	 *  unavailable. */
	static Language resolveLanguage() throws Exception {
		return VectorHarnessCommon.resolveLanguage(LANGUAGE_ID);
	}

	/** Builds the vector-field -> {@link Register} map for {@link #LANGUAGE_ID}. */
	static Map<String, Register> registerMap(Language language) {
		Map<String, Register> map = new LinkedHashMap<>();
		for (Map.Entry<String, String> e : REGISTER_NAMES.entrySet()) {
			Register reg = language.getRegister(e.getValue());
			if (reg == null) {
				throw new IllegalStateException("language " + language.getLanguageID() +
					" has no register named '" + e.getValue() + "' (expected for vector field '" +
					e.getKey() + "')");
			}
			map.put(e.getKey(), reg);
		}
		return map;
	}

	/**
	 * Top-of-address-space window (bytes) within which a {@code DecodePcodeExecutionException} is
	 * classified as a decode-boundary harness artifact rather than a semantic failure -- see
	 * {@link VectorRunner#isDecodeBoundaryCase}. Same 8-byte value as SPC700/W65816's (a decoder
	 * lookahead concern, not something specific to any one language's encoding).
	 */
	private static final int DECODE_BOUNDARY_WINDOW_BYTES = 8;

	/**
	 * Hard cap on the TOTAL number of decode-boundary cases across a whole run, enforced by
	 * {@link #assertDecodeBoundaryCapNotExceeded}. Same reasoning as
	 * {@code Spc700VectorHarnessSupport#DECODE_BOUNDARY_CAP}: this is an ESTIMATE (no measurement
	 * existed while writing this harness), scaled from SPC700's measured 30-in-256,000 for the
	 * identical 16-bit address space and 8-byte window, but a 10x larger case count here
	 * (2,560,000 vs 256,000) -- so the estimate is on the order of 300. 500 is generous headroom.
	 * <b>Revisit with a measured value once a real exhaustive run has been executed.</b>
	 */
	static final int DECODE_BOUNDARY_CAP = 500;

	static VectorRunner newRunner(Language language) {
		return new VectorRunner(language, registerMap(language), "pc", Map.of(),
			VectorRunner.DEFAULT_REBUILD_INTERVAL, DECODE_BOUNDARY_WINDOW_BYTES);
	}

	/**
	 * Fails loudly (not a quiet skip) if the total decode-boundary case count across every row in
	 * {@code rows} exceeds {@link #DECODE_BOUNDARY_CAP}. See
	 * {@code Spc700VectorHarnessSupport#assertDecodeBoundaryCapNotExceeded} for the identical
	 * rationale.
	 */
	static void assertDecodeBoundaryCapNotExceeded(List<OpcodeBaseline> rows) {
		VectorHarnessCommon.assertEstimatedDecodeBoundaryCapNotExceeded(rows, DECODE_BOUNDARY_CAP);
	}

	/**
	 * Opcodes with NO correct single-step post-state to check against: the twelve JAM/KIL
	 * opcodes, which lock up the processor (real NMOS 6502 hardware genuinely halts on these --
	 * "JAM"/"KIL"/"HLT" are all names for the same undocumented lockup). {@code 6510_illegal.sinc}
	 * implements every one of them as {@code goto inst_start;} -- an unconditional jump back to
	 * the instruction's own start, forever. Confirmed directly (grm-hzv8): stepping opcode
	 * {@code 0x02} via a standalone probe does NOT hang the interpreter -- it throws a
	 * {@code DecodePcodeExecutionException} ("Unknown disassembly error") immediately, the same
	 * exception type {@code Spc700VectorHarnessSupport}'s {@code SLEEP}/{@code STOP} entries
	 * document, just from a different underlying cause (a decode-time rejection of the
	 * infinite-loop construct itself, not a callout with no registered behavior). Every one of the
	 * twelve shares the identical {@code :JAM is (op=... | ...)} constructor, so the same holds
	 * for all twelve opcodes below -- verified for the representative case, not independently
	 * re-run twelve times, since they are one shared constructor differing only in which {@code op}
	 * value selects it.
	 */
	private static final Map<String, String> NOT_APPLICABLE_OPCODES = new LinkedHashMap<>();
	static {
		String jamReason = "JAM/KIL: unconditional 'goto inst_start' locks up the processor; " +
			"every case throws DecodePcodeExecutionException (verified directly against 0x02) " +
			"rather than reaching a post-single-step state";
		NOT_APPLICABLE_OPCODES.put("02", jamReason);
		NOT_APPLICABLE_OPCODES.put("12", jamReason);
		NOT_APPLICABLE_OPCODES.put("22", jamReason);
		NOT_APPLICABLE_OPCODES.put("32", jamReason);
		NOT_APPLICABLE_OPCODES.put("42", jamReason);
		NOT_APPLICABLE_OPCODES.put("52", jamReason);
		NOT_APPLICABLE_OPCODES.put("62", jamReason);
		NOT_APPLICABLE_OPCODES.put("72", jamReason);
		NOT_APPLICABLE_OPCODES.put("92", jamReason);
		NOT_APPLICABLE_OPCODES.put("B2", jamReason);
		NOT_APPLICABLE_OPCODES.put("D2", jamReason);
		NOT_APPLICABLE_OPCODES.put("F2", jamReason);
	}

	/**
	 * Runs every case in one upstream-shaped opcode file ({@code <hex>.json}) and summarizes the
	 * result as one {@link OpcodeBaseline} row -- one row per opcode, mirroring
	 * {@code Spc700VectorHarnessSupport#runOpcodeFile} (this corpus, unlike the 65816's, does not
	 * partition by mode).
	 */
	static OpcodeBaseline runOpcodeFile(VectorRunner runner, File jsonFile) throws IOException {
		String opcodeHex = jsonFile.getName().replaceFirst("\\.json$", "").toUpperCase(Locale.ROOT);
		List<VectorCase> rawCases;
		try (FileInputStream in = new FileInputStream(jsonFile)) {
			rawCases = VectorParser.parse(in);
		}
		String mnemonic = rawCases.isEmpty() ? "-" : mnemonicOf(rawCases.get(0));

		String naReason = NOT_APPLICABLE_OPCODES.get(opcodeHex);
		if (naReason != null) {
			return new OpcodeBaseline(opcodeHex, mnemonic, OpcodeBaseline.Status.NOT_APPLICABLE, 0,
				rawCases.size(), List.of(naReason), 0);
		}

		int passed = 0;
		int decodeBoundary = 0;
		int unmodelled = 0;
		TreeSet<String> mismatchedFields = new TreeSet<>();
		for (VectorCase raw : rawCases) {
			if (unmodelledReason(opcodeHex, raw) != null) {
				unmodelled++;
				continue;
			}
			VectorCase adapted = adapt(raw);
			CaseResult result = runner.run(adapted);
			if (result.decodeBoundary()) {
				decodeBoundary++;
				continue;
			}
			if (result.pass()) {
				passed++;
			}
			else {
				for (String mismatch : result.mismatches()) {
					mismatchedFields.add(VectorHarnessCommon.fieldNameOf(mismatch));
				}
			}
		}
		int total = rawCases.size() - decodeBoundary - unmodelled;
		OpcodeBaseline.Status status =
			passed == total ? OpcodeBaseline.Status.PASS : OpcodeBaseline.Status.FAIL;
		return new OpcodeBaseline(opcodeHex, mnemonic, status, passed, total,
			List.copyOf(mismatchedFields), decodeBoundary, 0, 0, unmodelled);
	}

	/**
	 * Names the case classes the oracle gets right but this language deliberately does not model
	 * (bead grm-m9nu), or returns null for a case that is compared. Each class is decided from the
	 * case's INITIAL state alone, before running it, and is excluded from the ratio but counted in
	 * the open as {@code (N unmodelled)} -- see {@link OpcodeBaseline}.
	 *
	 * <ul>
	 * <li><b>A push or pull that wraps {@code S} past {@code $00}/{@code $FF}</b>
	 * ({@code BRK PHP JSR PHA} push 3/1/2/1 bytes, {@code PLP PLA RTS RTI} pull 1/1/2/3). Hardware
	 * keeps the stack in page 1 by wrapping {@code S} alone; {@code 6502core.sinc} does linear
	 * arithmetic on the 2-byte {@code SP} because every stack analysis here models it as
	 * {@code EntrySP + k} -- a stack overflow is not worth breaking them for. About 1 case in
	 * 256 per opcode.</li>
	 * <li><b>{@code JSR} overwriting its own operand.</b> Hardware fetches the target's high byte
	 * AFTER pushing the return address, so a {@code JSR} sitting in page 1 whose push lands on
	 * {@code pc+2} jumps somewhere else (corpus case {@code "20 55 13"}: {@code JSR} at
	 * {@code $017B}, {@code S=$7D}, target {@code $1355} becomes {@code $0155}). Modelling it
	 * would make every {@code JSR} a computed call for flow analysis.</li>
	 * <li><b>{@code SHA}/{@code SHX}/{@code SHY}/{@code TAS} with a page-crossing index</b>
	 * ({@code 93 9B 9C 9E 9F}). Measured against all 50,000 cases: with no page cross the oracle
	 * stores {@code REG & (high(base)+1)} at {@code base+index}, exactly the vendored
	 * {@code 6510_illegal.sinc}, 25,168/25,168. On a page cross it stores the same value but
	 * replaces the target's high byte with it, 100% of the remaining cases. The vendored file
	 * documents page-cross behaviour as unstable and intentionally not modelled, and it is kept
	 * byte-identical to upstream.</li>
	 * </ul>
	 */
	static String unmodelledReason(String opcodeHex, VectorCase c) {
		int pc = c.initialRegs().get("pc");
		int s = c.initialRegs().get("s");
		Integer stackBytes = STACK_BYTES.get(opcodeHex);
		if (stackBytes != null && (stackBytes < 0 ? s < -stackBytes : s > 0xff - stackBytes)) {
			return "stack push/pull wraps S within page 1; the language's SP arithmetic is linear";
		}
		switch (opcodeHex) {
			case "20": {
				int operandHi = (pc + 2) & 0xffff;
				if (operandHi == (0x100 | s) || operandHi == (0x100 | ((s - 1) & 0xff))) {
					return "JSR return-address push overwrites its own operand";
				}
				return null;
			}
			case "93": {
				int zp = ram(c, pc + 1);
				int base = ram(c, zp) | (ram(c, (zp + 1) & 0xff) << 8);
				return pageCross(base, c.initialRegs().get("y"));
			}
			case "9B":
			case "9E":
			case "9F":
				return pageCross(ram(c, pc + 1) | (ram(c, pc + 2) << 8), c.initialRegs().get("y"));
			case "9C":
				return pageCross(ram(c, pc + 1) | (ram(c, pc + 2) << 8), c.initialRegs().get("x"));
			default:
				return null;
		}
	}

	/** Bytes each stack opcode moves: negative pushes, positive pulls. */
	private static final Map<String, Integer> STACK_BYTES = Map.of(
		"00", -3, "08", -1, "20", -2, "48", -1,
		"28", 1, "68", 1, "60", 2, "40", 3);

	private static String pageCross(int base, int index) {
		return (base & 0xff) + index > 0xff
				? "unstable store with page-crossing index: hardware replaces the target's high byte"
				: null;
	}

	private static int ram(VectorCase c, int address) {
		int a = address & 0xffff;
		for (VectorCase.RamByte b : c.initialRam()) {
			if (b.address() == a) {
				return b.value();
			}
		}
		return 0;
	}

	/**
	 * Adapts one raw corpus {@link VectorCase} into the shape {@link VectorRunner} can compare
	 * generically -- see the class doc's two sections. {@code p} is dropped and replaced with six
	 * comparable synthetic fields plus (initial-only) the break flag; a synthetic {@code sh} field
	 * (forced to 1) is added to BOTH maps. Every other field ({@code pc/s/a/x/y}) passes through
	 * unchanged.
	 */
	private static VectorCase adapt(VectorCase c) {
		return new VectorCase(c.name(), adaptRegs(c.initialRegs(), true), c.initialRam(),
			adaptRegs(c.finalRegs(), false), c.finalRam());
	}

	/** @param initialState whether this is the case's INITIAL map -- only it carries the break
	 *  flag; see the class doc. */
	private static Map<String, Integer> adaptRegs(Map<String, Integer> raw, boolean initialState) {
		Map<String, Integer> out = new LinkedHashMap<>();
		for (Map.Entry<String, Integer> e : raw.entrySet()) {
			String key = e.getKey();
			if (key.equals("p")) {
				continue; // no Register backs the packed field -- see class doc
			}
			out.put(key, e.getValue());
		}
		Integer p = raw.get("p");
		if (p != null) {
			for (FlagLayout.FlagBit bit : COMPARED_P_BITS) {
				out.put("p_" + bit.name().toLowerCase(Locale.ROOT), bit.valueIn(p));
			}
			if (initialState) {
				// SEEDED ONLY, NEVER COMPARED -- see class doc for why the final map never gets
				// this field (PHP/BRK push it into memory, where the corpus's RAM comparison
				// checks it independently; nothing restores it into a tracked register to verify
				// against a final value).
				out.put("p_b", BREAK_FLAG_BIT.valueIn(p));
			}
		}
		// SH is hardwired to $01 on real hardware and untracked by the corpus entirely -- forced
		// into BOTH maps (see class doc: unlike the break flag, this one IS meaningfully
		// comparable in the final state, since it must never move).
		out.put("sh", 1);
		return out;
	}

	// ------------------------------------------------------------------
	// Mnemonic-column disassembly (readability only; never allowed to fail a run)
	// ------------------------------------------------------------------

	// Lazily built, reused across every opcode file in one test run -- see
	// Spc700VectorHarnessSupport's identical fields for the rationale.
	private static ProgramBuilder mnemonicBuilder;
	private static ProgramDB mnemonicProgram;
	// Each opcode gets its own scratch address, well clear of any previous instruction's
	// bytes/operands -- 256 opcodes x 16 bytes is 4 KiB, trivial against the 64 KiB scratch block.
	private static long nextMnemonicAddr = 0x0200;

	/**
	 * The mnemonic + full operand text for {@code c}'s own instruction encoding, or {@code "-"} if
	 * that cannot be produced for any reason -- see
	 * {@code Spc700VectorHarnessSupport#mnemonicOf}'s identical contract and rationale.
	 */
	private static synchronized String mnemonicOf(VectorCase c) {
		try {
			byte[] bytes = instructionBytes(c);
			if (bytes.length == 0) {
				return "-";
			}
			if (mnemonicBuilder == null) {
				mnemonicBuilder = new ProgramBuilder("Mos6502MnemonicScratch", LANGUAGE_ID);
				mnemonicBuilder.createMemory(".ram", "0x0", 0x10000);
				mnemonicProgram = mnemonicBuilder.getProgram();
			}
			long addr = nextMnemonicAddr;
			nextMnemonicAddr += 16;
			if (addr + 16 > 0x10000) {
				return "-"; // ran out of scratch space; should not happen for 256 opcodes
			}
			String addrStr = "0x" + Long.toHexString(addr);
			mnemonicBuilder.setBytes(addrStr, VectorHarnessCommon.toHexString(bytes), true);
			Instruction instr =
				mnemonicProgram.getListing().getInstructionAt(mnemonicBuilder.addr(addrStr));
			return instr != null ? instr.toString() : "-";
		}
		catch (Exception e) {
			return "-";
		}
	}

	/**
	 * The contiguous run of bytes in {@code c.initialRam()} starting at {@code c}'s initial
	 * {@code pc}, up to a generous safety cap -- the instruction's own encoding only. Stops at the
	 * first gap. Empty if {@code c} has no {@code pc} field or nothing at it.
	 */
	private static byte[] instructionBytes(VectorCase c) {
		Integer pc = c.initialRegs().get("pc");
		if (pc == null) {
			return new byte[0];
		}
		// 8: generously above any real 6502 encoding (max 3 bytes)
		return VectorHarnessCommon.contiguousBytes(c, pc, 8);
	}

	/** Every {@code <hex>.json} file directly under {@code dir}, sorted by name. */
	static List<File> opcodeFilesIn(File dir) {
		return VectorHarnessCommon.opcodeFilesIn(dir);
	}
}
