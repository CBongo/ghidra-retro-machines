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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;

import retromachines.vectors.VectorRunner.CaseResult;

/**
 * Shared plumbing for the two W65816 vector JUnit tests (bead grm-9nxj.3):
 * {@code W65816VectorSampleTest} (the vendored 16-opcode/32-cases-per-file sample, {@code unit}
 * chunk) and {@code W65816VectorExhaustiveTest} (the full 5.12M-case suite against
 * {@code GRM_W65816_VECTORS}, {@code w65816-vectors} chunk). Mirrors
 * {@code Spc700VectorHarnessSupport}'s shape and role; see that class for the general design
 * this one specializes.
 *
 * <p>Language id and register names: {@code 65816:LE:24:retro} (bead grm-9nxj.1's vendored
 * decode table). Corpus field -> Ghidra register, VERIFIED against {@code 658xx.sinc}'s
 * {@code define register} lines (bead grm-9nxj.3's point 4 -- every name below was read out of
 * the language, not assumed): {@code pc->PC} (16-bit; the low half of {@code PC_FULL}),
 * {@code s->SP}, {@code a->C} (the corpus's "accumulator" field is the FULL 16-bit register --
 * {@code A}/{@code B} are only its low/high 8-bit halves, so mapping to {@code A} would silently
 * drop the top byte), {@code x->X}, {@code y->Y}, {@code dbr->DBR}, {@code d->DP},
 * {@code pbr->PBR}. All eight names exist in the language; none needed substituting.
 *
 * <h2>1. CONTEXT: {@code p}'s M/X bits and the case's {@code e} scalar, per case</h2>
 * {@code 658xx.sinc} decodes on {@code ctx_MF}/{@code ctx_XF}/{@code ctx_EF} context fields, not
 * program registers -- see {@code w65816.pspec}. Bead grm-wrmf's {@link VectorRunner
 * #withContextProvider} is what makes feeding a per-case context possible at all;
 * {@link #newRunner} wires one up here. Per case: {@code mf = (p>>5)&1}, {@code xf = (p>>4)&1}
 * when {@code e == 0} (native mode, where the corpus's own bits govern). <b>When {@code e == 1}
 * (emulation mode), this harness FORCES {@code mf = xf = 1} rather than trusting {@code p}'s
 * bits 5/4</b> -- decision, and reasoning: on real hardware, emulation mode architecturally
 * forces an 8-bit accumulator and 8-bit index registers (there is no way to be in emulation mode
 * with a 16-bit A or X on a real 65816), so a genuine corpus case should already carry
 * {@code p} bits 5/4 = 1 whenever {@code e = 1} -- forcing merely defends against ever asking the
 * decoder for a combination ({@code e=1} with {@code mf=0} or {@code xf=0}) that no real 65816
 * state machine can produce and the corpus is not expected to generate, rather than trusting an
 * assumption about upstream's exact byte packing under {@code e=1}.
 *
 * <h2>2. THE PROGRAM COUNTER IS BANKED</h2>
 * Confirmed directly against the real corpus (fetched a sample {@code a9.n.json} case): a
 * case's {@code initial.ram} entries are keyed at the FULL 24-bit address
 * {@code (pbr<<16)|pc} -- e.g. {@code pc=64793 (0xFD19), pbr=98 (0x62)} has its opcode byte at
 * ram address {@code 6487321 = 0x62FD19}, not at {@code 0xFD19} alone. {@link VectorRunner#seed}
 * (pre-grm-9nxj.3) builds the starting counter address from {@code pcField} alone, which is
 * correct for SPC700/6502 (whose one field IS the whole address) and silently wrong here: it
 * would fetch from bank 0 every time regardless of {@code pbr}, corrupting the executed bytes
 * for nearly every case (the corpus randomizes {@code pbr} across its full range). Bead
 * grm-9nxj.3 added {@link VectorRunner#withCounterAddressProvider} as the sibling of
 * {@link VectorRunner#withContextProvider} to fix this; {@link #newRunner} supplies
 * {@code (pbr<<16)|pc} via it.
 *
 * <h2>3. THE {@code p} REGISTER CANNOT BE COMPARED WHOLESALE</h2>
 * {@code 658xx.sinc} models N/V/D/I/Z/C as separate one-byte registers ({@code NF VF DF IF ZF
 * CF}) -- there is no packed status register in the language at all, unlike SPC700's single
 * {@code PSW} byte, so {@link FlagLayout}'s usual role (decomposing ONE register's raw diff into
 * named-bit mismatches) does not apply directly. Instead, {@link #P_FLAGS} documents the full
 * 8-bit layout of the corpus's {@code p} field (reusing {@link FlagLayout.FlagBit#valueIn} to
 * extract bits), and {@link #adapt} splits each case's {@code p} value into six synthetic
 * per-case fields ({@code p_n/p_v/p_d/p_i/p_z/p_c}) that DO map onto real registers
 * ({@code NF/VF/DF/IF/ZF/CF}), before handing the case to {@link VectorRunner}, whose generic
 * per-field register comparison then verifies them exactly like any other register.
 *
 * <p><b>Bits 5 (M) and 4 (X in native mode / B in emulation mode) of {@code p} are NEVER
 * compared, in either mode -- this is a permanent, documented gap, not an oversight:</b>
 * <ul>
 * <li>Bit 5 (M) has NO corresponding program register in this language at all -- it lives only
 *     in {@code ctx_MF}, which this harness feeds IN (as decode context) but Ghidra's
 *     interpreted {@code PcodeEmulator} has no register read-back for a context field, so there
 *     is nothing to compare it against post-step even in principle.</li>
 * <li>Bit 4 is mode-dependent in hardware itself (X in native mode, B -- the break flag -- in
 *     emulation mode) and the language reflects that split: {@code BF} is a real register, but
 *     it is only meaningfully written by emulation-mode code paths ({@code PHP}/{@code BRK}
 *     with {@code ctx_EF=1}); the native-mode X flag is context-only, exactly like M. A single
 *     static field-name mapping cannot switch which register (if any) bit 4 means per case, so
 *     this harness excludes it uniformly rather than adding mode-conditional comparison
 *     machinery for one bit.</li>
 * </ul>
 * An unverified bit that looks verified is worse than a stated gap (project convention) -- this
 * gap is also called out in {@code docs/testing.md}.
 *
 * <p>The corpus's {@code e} scalar is likewise never compared as a final-state register: it has
 * no register either, and (unlike M/X) this harness does not even attempt to track it forward
 * across the one instruction being stepped -- a case whose instruction is {@code XCE} genuinely
 * changes {@code e}, but single-instruction stepping has no next-instruction decode to prove that
 * change actually took hold, so verifying it is out of scope for this harness by construction.
 */
final class W65816VectorHarnessSupport {

	static final String LANGUAGE_ID = "65816:LE:24:retro";

	/**
	 * Corpus register field name -&gt; Ghidra register name. See the class doc's opening
	 * paragraph for why each mapping is what it is (particularly {@code a->C}, not {@code A}).
	 * The {@code p_*} entries are synthetic fields {@link #adapt} manufactures from the corpus's
	 * packed {@code p} -- see the class doc's CONTEXT/point-3 sections.
	 */
	private static final Map<String, String> REGISTER_NAMES = new LinkedHashMap<>();
	static {
		REGISTER_NAMES.put("pc", "PC");
		REGISTER_NAMES.put("s", "SP");
		REGISTER_NAMES.put("a", "C");
		REGISTER_NAMES.put("x", "X");
		REGISTER_NAMES.put("y", "Y");
		REGISTER_NAMES.put("dbr", "DBR");
		REGISTER_NAMES.put("d", "DP");
		REGISTER_NAMES.put("pbr", "PBR");
		REGISTER_NAMES.put("p_n", "NF");
		REGISTER_NAMES.put("p_v", "VF");
		REGISTER_NAMES.put("p_d", "DF");
		REGISTER_NAMES.put("p_i", "IF");
		REGISTER_NAMES.put("p_z", "ZF");
		REGISTER_NAMES.put("p_c", "CF");
	}

	/**
	 * The full 8-bit layout of the corpus's {@code p} field, for documentation and bit
	 * extraction (via {@link FlagLayout.FlagBit#valueIn}) -- see the class doc, point 3.
	 * {@code M} and {@code X} are listed here for completeness but are NEVER compared; only the
	 * names in {@link #VERIFIED_P_FLAG_NAMES} are turned into synthetic comparable fields by
	 * {@link #adapt}.
	 */
	static final FlagLayout P_FLAGS = new FlagLayout(List.of(
		new FlagLayout.FlagBit("N", 7, 1),
		new FlagLayout.FlagBit("V", 6, 1),
		new FlagLayout.FlagBit("M", 5, 1), // UNVERIFIED -- no program register; see class doc
		new FlagLayout.FlagBit("X", 4, 1), // UNVERIFIED -- mode-dependent (X native / B emulation)
		new FlagLayout.FlagBit("D", 3, 1),
		new FlagLayout.FlagBit("I", 2, 1),
		new FlagLayout.FlagBit("Z", 1, 1),
		new FlagLayout.FlagBit("C", 0, 1)));

	private static final List<String> VERIFIED_P_FLAG_NAMES = List.of("N", "V", "D", "I", "Z", "C");

	private static final List<FlagLayout.FlagBit> VERIFIED_P_BITS = P_FLAGS.fields().stream()
			.filter(b -> VERIFIED_P_FLAG_NAMES.contains(b.name()))
			.toList();

	private W65816VectorHarnessSupport() {
	}

	/** Resolves the 65816 language via a {@link ProgramBuilder}, throwing if unavailable. */
	static Language resolveLanguage() throws Exception {
		return new ProgramBuilder("Test", LANGUAGE_ID).getProgram().getLanguage();
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
	 * classified as a decode-boundary harness artifact -- see
	 * {@link VectorRunner#isDecodeBoundaryCase}. Same 8-byte value as SPC700's (a decoder
	 * lookahead concern, not something specific to either language's encoding).
	 */
	private static final int DECODE_BOUNDARY_WINDOW_BYTES = 8;

	/**
	 * Hard cap on the TOTAL number of decode-boundary cases across a whole run. UNLIKE SPC700's
	 * {@code DECODE_BOUNDARY_CAP} (measured directly against a real 256,000-case run), this value
	 * is an ESTIMATE: no full {@code SingleStepTests/65816} clone was available while writing this
	 * harness (bead grm-9nxj.3), so the true count has never been measured. The estimate: the
	 * address space is 24-bit (16,777,216 bytes) vs. SPC700's 16-bit, so for the same 8-byte
	 * window the per-case probability of landing there is ~256x smaller; scaled up to the full
	 * suite's 5.12M cases (20x SPC700's case count), the expected count is on the order of
	 * 5,120,000 * 8 / 16,777,216 =~ 2.4 -- i.e. a small number, similarly to SPC700's measured 30.
	 * 200 is generous headroom over that estimate. <b>Revisit this comment with a measured value
	 * once a real exhaustive run has actually been executed</b> -- see
	 * {@code W65816VectorExhaustiveTest}.
	 */
	static final int DECODE_BOUNDARY_CAP = 200;

	static VectorRunner newRunner(Language language) {
		Register ctxMf = language.getRegister("ctx_MF");
		Register ctxXf = language.getRegister("ctx_XF");
		Register ctxEf = language.getRegister("ctx_EF");
		if (ctxMf == null || ctxXf == null || ctxEf == null) {
			throw new IllegalStateException("language " + language.getLanguageID() +
				" is missing one of ctx_MF/ctx_XF/ctx_EF");
		}
		AddressSpace space = language.getAddressFactory().getDefaultAddressSpace();

		VectorRunner runner = new VectorRunner(language, registerMap(language), "pc", Map.of(),
			VectorRunner.DEFAULT_REBUILD_INTERVAL, DECODE_BOUNDARY_WINDOW_BYTES);

		// The context provider is (re)installed PER CASE by runOpcodeFile(), because the ADAPTED
		// VectorCase passed to run() has had 'p'/'e' stripped out (they are not registers -- see
		// the class doc, point 3), so the provider cannot recover them from its own argument the
		// way the counter provider below recovers 'pbr'/'pc' (which DO survive adaptation). A
		// lambda capturing that case's raw p/e keeps the per-case state on the stack instead of
		// in static fields; see installContextFor().
		runner.withCounterAddressProvider(c -> {
			int pc = requireInt(c, "pc");
			int pbr = requireInt(c, "pbr");
			return space.getAddress((((long) pbr) << 16) | (pc & 0xFFFFL));
		});
		installContextFor(runner, language, 0, 0);
		return runner;
	}

	/**
	 * Installs a context provider carrying THIS case's mode bits. Called once per case rather
	 * than once per runner: the alternative is static per-case fields, which is state shared
	 * between the loop and the lambda for no benefit -- a captured argument says the same thing
	 * and cannot be read stale or out of order.
	 */
	private static void installContextFor(VectorRunner runner, Language language, int p, int e) {
		Register ctxMf = language.getRegister("ctx_MF");
		Register ctxXf = language.getRegister("ctx_XF");
		Register ctxEf = language.getRegister("ctx_EF");
		runner.withContextProvider(c -> contextFor(ctxMf, ctxXf, ctxEf, p, e));
	}

	/** Derives the per-case decode context from {@link #currentCaseP}/{@link #currentCaseE} --
	 *  see the class doc's CONTEXT section for the emulation-mode forcing decision. */
	private static RegisterValue contextFor(Register ctxMf, Register ctxXf, Register ctxEf,
			int p, int e) {
		int mf;
		int xf;
		if (e != 0) {
			mf = 1;
			xf = 1;
		}
		else {
			mf = (p >> 5) & 1;
			xf = (p >> 4) & 1;
		}
		RegisterValue rv = new RegisterValue(ctxMf, BigInteger.valueOf(mf));
		rv = rv.combineValues(new RegisterValue(ctxXf, BigInteger.valueOf(xf)));
		rv = rv.combineValues(new RegisterValue(ctxEf, BigInteger.valueOf(e)));
		return rv;
	}

	private static int requireInt(VectorCase c, String field) {
		Integer v = c.initialRegs().get(field);
		if (v == null) {
			throw new IllegalArgumentException(
				"case '" + c.name() + "' initial state has no '" + field + "' field");
		}
		return v;
	}

	/**
	 * Fails loudly (not a quiet skip) if the total decode-boundary case count across every row in
	 * {@code rows} exceeds {@link #DECODE_BOUNDARY_CAP}. See
	 * {@code Spc700VectorHarnessSupport#assertDecodeBoundaryCapNotExceeded} for the identical
	 * rationale.
	 */
	static void assertDecodeBoundaryCapNotExceeded(List<OpcodeBaseline> rows) {
		int total = rows.stream().mapToInt(OpcodeBaseline::decodeBoundaryCount).sum();
		if (total > DECODE_BOUNDARY_CAP) {
			throw new AssertionError("decode-boundary case count (" + total + ") exceeds the " +
				"ESTIMATED cap (" + DECODE_BOUNDARY_CAP + ", see that constant's doc) -- " +
				"investigate what started throwing DecodePcodeExecutionException before raising " +
				"this cap");
		}
	}

	/**
	 * Opcodes with NO correct single-step post-state to check against, because the instruction
	 * legitimately halts the processor pending an interrupt or reset -- the 65816 analogue of
	 * SPC700's {@code SLEEP}/{@code STOP} (see {@code Spc700VectorHarnessSupport}'s identical
	 * allowlist and its class doc for why this must stay narrow and named, never a blanket
	 * "exceptions don't count"). Opcode bytes confirmed by reading {@code 658xx.sinc}: {@code WAI}
	 * is {@code op=0xcb}, {@code STP} (the 65816's mnemonic for this opcode; upstream's own
	 * comment spells it "STP", not "STOP") is {@code op=0xdb}.
	 */
	private static final Map<String, String> NOT_APPLICABLE_OPCODES = Map.of(
		"CB", "WAI halts the processor pending an interrupt; no post-single-step state exists",
		"DB", "STP halts the processor pending a hardware reset; no post-single-step state exists");

	/**
	 * Runs every case in one upstream-shaped opcode+mode file ({@code <hex>.<n|e>.json}) and
	 * summarizes the result as one {@link OpcodeBaseline} row keyed {@code <HEX>.<N|E>} -- ONE
	 * ROW PER (OPCODE, MODE), not one row per opcode, since the corpus partitions native and
	 * emulation mode into separate files with genuinely different case populations (grm-wrmf's
	 * point 2, left to this bead). E.g. {@code a9.n.json} and {@code a9.e.json} both produce rows
	 * for opcode {@code A9}, named {@code A9.N} and {@code A9.E} respectively.
	 */
	static OpcodeBaseline runOpcodeFile(VectorRunner runner, File jsonFile) throws IOException {
		String base = jsonFile.getName().replaceFirst("\\.json$", "");
		String[] parts = base.split("\\.");
		String opcodeHex = parts[0].toUpperCase(Locale.ROOT);
		String modeLabel = parts.length > 1 && parts[1].equalsIgnoreCase("e") ? "E" : "N";
		String rowKey = opcodeHex + "." + modeLabel;

		List<VectorCase> rawCases;
		try (FileInputStream in = new FileInputStream(jsonFile)) {
			rawCases = VectorParser.parse(in);
		}
		String mnemonic = rawCases.isEmpty() ? "-" : mnemonicOf(rawCases.get(0));

		String naReason = NOT_APPLICABLE_OPCODES.get(opcodeHex);
		if (naReason != null) {
			return new OpcodeBaseline(rowKey, mnemonic, OpcodeBaseline.Status.NOT_APPLICABLE, 0,
				rawCases.size(), List.of(naReason), 0);
		}

		int passed = 0;
		int decodeBoundary = 0;
		TreeSet<String> mismatchedFields = new TreeSet<>();
		for (VectorCase raw : rawCases) {
			installContextFor(runner, runner.language(),
				raw.initialRegs().getOrDefault("p", 0), raw.initialRegs().getOrDefault("e", 0));
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
					mismatchedFields.add(fieldNameOf(mismatch));
				}
			}
		}
		int total = rawCases.size() - decodeBoundary;
		OpcodeBaseline.Status status =
			passed == total ? OpcodeBaseline.Status.PASS : OpcodeBaseline.Status.FAIL;
		return new OpcodeBaseline(rowKey, mnemonic, status, passed, total,
			List.copyOf(mismatchedFields), decodeBoundary);
	}

	/**
	 * Adapts one raw corpus {@link VectorCase} into the shape {@link VectorRunner} can compare
	 * generically: {@code p}/{@code e} (which have no corresponding {@link Register}) are
	 * dropped and replaced with the six synthetic, register-backed fields
	 * {@code p_n/p_v/p_d/p_i/p_z/p_c} -- see the class doc, point 3. Every other field
	 * ({@code pc/s/a/x/y/dbr/d/pbr}) passes through unchanged.
	 */
	private static VectorCase adapt(VectorCase c) {
		return new VectorCase(c.name(), adaptRegs(c.initialRegs()), c.initialRam(),
			adaptRegs(c.finalRegs()), c.finalRam());
	}

	private static Map<String, Integer> adaptRegs(Map<String, Integer> raw) {
		Map<String, Integer> out = new LinkedHashMap<>();
		for (Map.Entry<String, Integer> e : raw.entrySet()) {
			String key = e.getKey();
			if (key.equals("p") || key.equals("e")) {
				continue; // no Register backs either field -- see class doc, point 3
			}
			out.put(key, e.getValue());
		}
		Integer p = raw.get("p");
		if (p != null) {
			for (FlagLayout.FlagBit bit : VERIFIED_P_BITS) {
				out.put("p_" + bit.name().toLowerCase(Locale.ROOT), bit.valueIn(p));
			}
		}
		return out;
	}

	// ------------------------------------------------------------------
	// Mnemonic-column disassembly (readability only; never allowed to fail a run)
	// ------------------------------------------------------------------

	// Lazily built, reused across every opcode file in one test run -- see
	// Spc700VectorHarnessSupport's identical fields for the rationale.
	private static ProgramBuilder mnemonicBuilder;
	private static ProgramDB mnemonicProgram;
	private static Language mnemonicLanguage;
	// Each opcode+mode file gets its own scratch address, well clear of any previous
	// instruction's bytes -- 512 files x 16 bytes is 8 KiB, trivial against the 64 KiB scratch
	// block.
	private static long nextMnemonicAddr = 0x0200;

	/**
	 * The mnemonic + full operand text for {@code c}'s own instruction encoding, decoded under
	 * {@code c}'s OWN M/X/E context (not the language's static default) so that, e.g., a 16-bit
	 * {@code LDA #imm} case renders as a 3-byte instruction rather than misleadingly as an 8-bit
	 * 2-byte one. Falls back to {@code "-"} on any failure -- see
	 * {@code Spc700VectorHarnessSupport#mnemonicOf}'s identical contract and rationale.
	 */
	private static synchronized String mnemonicOf(VectorCase c) {
		try {
			byte[] bytes = instructionBytes(c);
			if (bytes.length == 0) {
				return "-";
			}
			if (mnemonicBuilder == null) {
				mnemonicBuilder = new ProgramBuilder("W65816MnemonicScratch", LANGUAGE_ID);
				mnemonicBuilder.createMemory(".ram", "0x0", 0x10000);
				mnemonicProgram = mnemonicBuilder.getProgram();
				mnemonicLanguage = mnemonicProgram.getLanguage();
			}
			long addr = nextMnemonicAddr;
			nextMnemonicAddr += 16;
			if (addr + 16 > 0x10000) {
				return "-"; // ran out of scratch space; should not happen for this sample's size
			}
			String addrStr = "0x" + Long.toHexString(addr);
			Address scratchAddr = mnemonicBuilder.addr(addrStr);
			Integer p = c.initialRegs().get("p");
			Integer e = c.initialRegs().get("e");
			if (p != null && e != null) {
				setMnemonicContext(scratchAddr, bytes.length, p, e);
			}
			mnemonicBuilder.setBytes(addrStr, toHexString(bytes), true);
			Instruction instr = mnemonicProgram.getListing().getInstructionAt(scratchAddr);
			return instr != null ? instr.toString() : "-";
		}
		catch (Exception e) {
			return "-";
		}
	}

	/** Stamps {@code addr}..{@code addr+lengthBytes-1} with the ctx_MF/ctx_XF/ctx_EF that
	 *  {@code p}/{@code e} imply, using the same forcing rule as {@link #contextFor}. */
	private static void setMnemonicContext(Address addr, int lengthBytes, int p, int e) {
		int mf;
		int xf;
		if (e != 0) {
			mf = 1;
			xf = 1;
		}
		else {
			mf = (p >> 5) & 1;
			xf = (p >> 4) & 1;
		}
		Register ctxMf = mnemonicLanguage.getRegister("ctx_MF");
		Register ctxXf = mnemonicLanguage.getRegister("ctx_XF");
		Register ctxEf = mnemonicLanguage.getRegister("ctx_EF");
		Address end = addr.add(Math.max(lengthBytes, 1) - 1);
		ProgramContext ctx = mnemonicProgram.getProgramContext();
		int tx = mnemonicProgram.startTransaction("set 65816 mnemonic context");
		boolean commit = false;
		try {
			ctx.setValue(ctxMf, addr, end, BigInteger.valueOf(mf));
			ctx.setValue(ctxXf, addr, end, BigInteger.valueOf(xf));
			ctx.setValue(ctxEf, addr, end, BigInteger.valueOf(e));
			commit = true;
		}
		catch (Exception ex) {
			// Never let a context-stamping hiccup take down the run -- mnemonicOf() falls back to
			// decoding under whatever context is already there (likely the language default).
		}
		finally {
			mnemonicProgram.endTransaction(tx, commit);
		}
	}

	/**
	 * The contiguous run of bytes in {@code c.initialRam()} starting at {@code c}'s initial
	 * counter address ({@code (pbr<<16)|pc} -- see the class doc, point 2; NOT {@code pc} alone),
	 * up to the longest possible 65816 encoding (4 bytes: opcode + up to 3 operand bytes, e.g.
	 * {@code JSL long} or {@code LDA long}). Stops at the first gap.
	 */
	private static byte[] instructionBytes(VectorCase c) {
		Integer pc = c.initialRegs().get("pc");
		Integer pbr = c.initialRegs().get("pbr");
		if (pc == null || pbr == null) {
			return new byte[0];
		}
		long start = (((long) pbr) << 16) | (pc & 0xFFFFL);
		Map<Long, Integer> byAddress = new HashMap<>();
		for (VectorCase.RamByte rb : c.initialRam()) {
			byAddress.put(Integer.toUnsignedLong(rb.address()), rb.value());
		}
		List<Byte> out = new ArrayList<>();
		long addr = start;
		int maxInstructionLength = 4; // the 65816's longest encoding (opcode + 3 operand bytes)
		while (out.size() < maxInstructionLength && byAddress.containsKey(addr)) {
			out.add((byte) (int) byAddress.get(addr));
			addr++;
		}
		byte[] result = new byte[out.size()];
		for (int i = 0; i < result.length; i++) {
			result[i] = out.get(i);
		}
		return result;
	}

	private static String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	/** Same convention as {@code Spc700VectorHarnessSupport#fieldNameOf}. */
	private static String fieldNameOf(String mismatch) {
		String head = mismatch.split(" ", 2)[0];
		int dot = head.indexOf('.');
		return dot < 0 ? head : head.substring(0, dot);
	}

	/** Every {@code <hex>.<n|e>.json} file directly under {@code dir}, sorted by name. Reuses
	 *  {@code Spc700VectorHarnessSupport}'s identical implementation (both just list
	 *  {@code *.json} files; nothing SPC700-specific about it). */
	static List<File> opcodeFilesIn(File dir) {
		return Spc700VectorHarnessSupport.opcodeFilesIn(dir);
	}
}
