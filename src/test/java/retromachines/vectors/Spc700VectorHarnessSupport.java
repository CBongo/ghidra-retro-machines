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
import java.util.ArrayList;
import java.util.HashMap;
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
 * Shared plumbing for the two SPC700 vector JUnit tests (bead grm-c9d.2):
 * {@code Spc700VectorSampleTest} (the vendored 8192-case sample, `unit` chunk) and
 * {@code Spc700VectorExhaustiveTest} (the full 256,000-case suite against
 * {@code GRM_SPC700_VECTORS}, `spc700-vectors` chunk). Neither test class depends on this
 * repository actually shipping the SPC700 language yet (bead grm-c9d.1, landing in parallel) --
 * both resolve it defensively and let the caller decide how to react when it is absent.
 *
 * <p>Language id and register names: {@code SPC700:LE:16:retro} (bead grm-c9d.1's vendored
 * SPCdra decode table -- deliberately not upstream SPCdra's own {@code spc700:LE:16:default}
 * id, so both can be installed side by side; see {@code Spc700LanguageTest}), registers
 * {@code PC/A/X/Y/SP/PSW}.
 */
final class Spc700VectorHarnessSupport {

	static final String LANGUAGE_ID = "SPC700:LE:16:retro";

	/** Vector JSON field name -> guessed Ghidra register name; see class doc. */
	private static final Map<String, String> REGISTER_NAMES = Map.of(
		"pc", "PC",
		"a", "A",
		"x", "X",
		"y", "Y",
		"sp", "SP",
		"psw", "PSW");

	private Spc700VectorHarnessSupport() {
	}

	/** Resolves the SPC700 language via a {@link ProgramBuilder}, throwing if unavailable. */
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

	static VectorRunner newRunner(Language language) {
		return new VectorRunner(language, registerMap(language), "pc",
			Map.of("psw", FlagLayout.SPC700_PSW));
	}

	/**
	 * Runs every case in one upstream-shaped opcode file ({@code <hex>.json}) and summarizes the
	 * result as one {@link OpcodeBaseline} row. The mnemonic column comes from disassembling the
	 * FIRST case's own instruction bytes (see {@link #mnemonicOf}) -- deliberately NOT pushed
	 * into {@link VectorRunner} itself, which stays language-agnostic and has no decoded-
	 * instruction access by design (bead grm-o9k depends on that staying true); this class is
	 * already the SPC700-specific layer, so the disassembly lives here instead.
	 */
	static OpcodeBaseline runOpcodeFile(VectorRunner runner, File jsonFile) throws IOException {
		String opcodeHex = jsonFile.getName().replaceFirst("\\.json$", "").toUpperCase(Locale.ROOT);
		List<VectorCase> cases;
		try (FileInputStream in = new FileInputStream(jsonFile)) {
			cases = VectorParser.parse(in);
		}
		int passed = 0;
		TreeSet<String> mismatchedFields = new TreeSet<>();
		for (VectorCase c : cases) {
			CaseResult result = runner.run(c);
			if (result.pass()) {
				passed++;
			}
			else {
				for (String mismatch : result.mismatches()) {
					mismatchedFields.add(fieldNameOf(mismatch));
				}
			}
		}
		String mnemonic = cases.isEmpty() ? "-" : mnemonicOf(cases.get(0));
		return new OpcodeBaseline(opcodeHex, mnemonic, passed == cases.size(), passed,
			cases.size(), List.copyOf(mismatchedFields));
	}

	// ------------------------------------------------------------------
	// Mnemonic-column disassembly (readability only; never allowed to fail a run)
	// ------------------------------------------------------------------

	// Lazily built, reused across every opcode file in one test run: constructing a
	// ProgramBuilder/Program is not free, and this class already reuses one Language-derived
	// VectorRunner the same way for the actual semantic measurement.
	private static ProgramBuilder mnemonicBuilder;
	private static ProgramDB mnemonicProgram;
	// Each opcode gets its own address, well clear of any previous instruction's bytes/operands,
	// so the Listing never needs undefining between opcodes. 256 opcodes x 16 bytes is 4 KiB --
	// trivial against the 64K scratch block.
	private static long nextMnemonicAddr = 0x0200;

	/**
	 * The mnemonic + full operand text (via {@link Instruction#toString()}) for {@code c}'s own
	 * instruction encoding, or {@code "-"} if that cannot be produced for any reason. Bytes come
	 * from {@code c.initialRam()} at {@code c.initialRegs().get("pc")} -- the contiguous run
	 * starting there, which is guaranteed to be a valid encoding of the opcode this case tests
	 * (unlike synthesizing operand bytes by hand, which would need to know each opcode's operand
	 * shape up front).
	 *
	 * <p><b>Never lets disassembly take down the run</b>: any exception, or a null/failed decode,
	 * falls back to {@code "-"} for just this row. The mnemonic is a readability aid; a decode
	 * hiccup on one opcode must not cost the 256-opcode semantic measurement.
	 */
	private static synchronized String mnemonicOf(VectorCase c) {
		try {
			byte[] bytes = instructionBytes(c);
			if (bytes.length == 0) {
				return "-";
			}
			if (mnemonicBuilder == null) {
				mnemonicBuilder = new ProgramBuilder("Spc700MnemonicScratch", LANGUAGE_ID);
				mnemonicBuilder.createMemory(".ram", "0x0", 0x10000);
				mnemonicProgram = mnemonicBuilder.getProgram();
			}
			long addr = nextMnemonicAddr;
			nextMnemonicAddr += 16;
			if (addr + 16 > 0x10000) {
				return "-"; // ran out of scratch space; should not happen for 256 opcodes
			}
			String addrStr = "0x" + Long.toHexString(addr);
			mnemonicBuilder.setBytes(addrStr, toHexString(bytes), true);
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
	 * {@code pc}, up to a generous safety cap -- i.e. just the instruction's own encoding, not
	 * any unrelated address {@code initial.ram} happens to also carry (e.g. an indirect
	 * addressing mode's target byte, which need not be adjacent to {@code pc} at all). Stops at
	 * the first gap. Empty if {@code c} has no {@code pc} field or nothing at it.
	 */
	private static byte[] instructionBytes(VectorCase c) {
		Integer pc = c.initialRegs().get("pc");
		if (pc == null) {
			return new byte[0];
		}
		Map<Integer, Integer> byAddress = new HashMap<>();
		for (VectorCase.RamByte rb : c.initialRam()) {
			byAddress.put(rb.address(), rb.value());
		}
		List<Byte> out = new ArrayList<>();
		int addr = pc;
		int maxInstructionLength = 8; // generously above any real SPC700 encoding
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

	/** The register/address token a {@link VectorRunner} mismatch message leads with, e.g.
	 *  {@code "PSW.C 1 != 0"} -> {@code "PSW"}, {@code "$10 0x99 != 0x42"} -> {@code "$10"}. */
	private static String fieldNameOf(String mismatch) {
		String head = mismatch.split(" ", 2)[0];
		int dot = head.indexOf('.');
		return dot < 0 ? head : head.substring(0, dot);
	}

	/** Every {@code <hex>.json} file directly under {@code dir}, sorted by name. */
	static List<File> opcodeFilesIn(File dir) {
		File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
		if (files == null) {
			return List.of();
		}
		List<File> list = new ArrayList<>(List.of(files));
		list.sort((a, b) -> a.getName().compareTo(b.getName()));
		return list;
	}
}
