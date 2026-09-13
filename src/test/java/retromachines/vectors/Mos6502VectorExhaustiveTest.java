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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.lang.Language;

import retromachines.AbstractBundledLanguageTest;

/**
 * The exhaustive, opt-in NMOS 6502 vector regression: all 256 opcodes x their full upstream case
 * count (10,000 cases/opcode, 2,560,000 cases total) against a full local clone of
 * {@code https://github.com/SingleStepTests/65x02}, named by {@code GRM_6502_VECTORS} (bead
 * grm-hzv8). Rides in its own {@code 6502-vectors} chunk -- the NMOS 6502 analogue of
 * {@code Spc700VectorExhaustiveTest} and {@code W65816VectorExhaustiveTest}, whose class docs
 * this one mirrors closely; see those classes for the general design.
 *
 * <p>Uses the corpus's {@code 6502/v1/} directory specifically: NMOS 6502 WITH decimal mode and
 * illegal/undocumented opcodes, matching this module's {@code 6502:LE:16:undoc} language. The
 * sibling {@code nes6502/} directory (no decimal mode -- the NES's 2A03) and the 65c02 variants
 * are out of scope; the NES corpus in this repo already uses stock Ghidra's
 * {@code 6502:LE:16:default}, which this bead does not touch.
 *
 * <p><b>When {@code GRM_6502_VECTORS} is unset, this refuses loudly and fails (not skips) --
 * exit nonzero</b>, identically to {@code Spc700VectorExhaustiveTest}'s and
 * {@code W65816VectorExhaustiveTest}'s rule: a green {@code 6502-vectors} chunk must mean the
 * exhaustive suite actually ran.
 *
 * <p>Since {@code 6502:LE:16:undoc} is bundled by this module and has shipped since before this
 * bead, this does NOT Assume-skip on a missing language (mirroring
 * {@code Mos6502VectorSampleTest}) -- a resolution failure here is a real problem.
 *
 * <p><b>Its own baseline, not the sampled one</b> -- see {@link OpcodeBaseline} and
 * {@code Spc700VectorExhaustiveTest}'s doc for why the sample and exhaustive tiers cannot share
 * one baseline file (different case-count fidelity moves every ratio).
 *
 * <p><b>Regenerating this baseline:</b> run with {@code -Dgrm.mos6502.regenerateExhaustiveBaseline
 * =true} against the {@code mos6502VectorTest} Gradle task specifically, with
 * {@code GRM_6502_VECTORS} set -- a DIFFERENT system property from
 * {@link Mos6502VectorSampleTest}'s, for the identical forwarding reason documented on
 * {@code spc700VectorTest} in {@code build.gradle}.
 */
public class Mos6502VectorExhaustiveTest extends AbstractBundledLanguageTest {

	static final String VECTORS_DIR_ENV = "GRM_6502_VECTORS";
	private static final String REGENERATE_PROPERTY = "grm.mos6502.regenerateExhaustiveBaseline";
	private static final String BASELINE_FILENAME = "mos6502-vector-baseline-exhaustive.txt";

	@Test
	public void exhaustiveRunAgainstFullVectorClone() throws Exception {
		String dir = System.getenv(VECTORS_DIR_ENV);
		if (dir == null || dir.isBlank()) {
			fail("6502VECTORS: SKIPPED -- " + VECTORS_DIR_ENV + " is unset. This tier was NOT " +
				"run; nothing about the full 2,560,000-case NMOS 6502 suite was checked. Set " +
				VECTORS_DIR_ENV + " to a full clone of " +
				"https://github.com/SingleStepTests/65x02 (git clone --depth 1 " +
				"https://github.com/SingleStepTests/65x02 <dir>) and rerun: " +
				"GRM_6502_VECTORS=<dir> bash tools/banktest/build-and-test.sh check " +
				"6502-vectors");
		}
		File v1Dir = new File(new File(dir, "6502"), "v1");
		assertTrue(VECTORS_DIR_ENV + "=" + dir + " does not look like a 65x02 clone (no " +
			"6502/v1/ directory)", v1Dir.isDirectory());

		Language language = Mos6502VectorHarnessSupport.resolveLanguage();
		List<File> opcodeFiles = Mos6502VectorHarnessSupport.opcodeFilesIn(v1Dir);
		assertTrue("expected 256 opcode files under " + v1Dir + ", found " + opcodeFiles.size(),
			opcodeFiles.size() == 256);

		VectorRunner runner = Mos6502VectorHarnessSupport.newRunner(language);
		List<OpcodeBaseline> actual = new ArrayList<>();
		for (File f : opcodeFiles) {
			actual.add(Mos6502VectorHarnessSupport.runOpcodeFile(runner, f));
		}
		Mos6502VectorHarnessSupport.assertDecodeBoundaryCapNotExceeded(actual);

		File moduleRoot = new File(System.getProperty(MODULE_DIR_PROPERTY));
		File baselineFile = new File(moduleRoot, "src/test/resources/" + BASELINE_FILENAME);

		if (Boolean.getBoolean(REGENERATE_PROPERTY)) {
			writeBaseline(baselineFile, actual);
			System.out.println("regenerated " + baselineFile + " (" + actual.size() +
				" opcodes) -- review the diff and commit deliberately");
			return;
		}

		assertTrue("no committed baseline at " + baselineFile + " -- run with -D" +
			REGENERATE_PROPERTY + "=true against the mos6502VectorTest task first",
			baselineFile.isFile());
		List<String> lines = Files.readAllLines(baselineFile.toPath(), StandardCharsets.UTF_8);
		List<OpcodeBaseline> baseline = OpcodeBaseline.parse(lines);

		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertTrue("baseline mismatch:\n" + String.join("\n", problems), problems.isEmpty());
	}

	private static void writeBaseline(File file, List<OpcodeBaseline> rows) throws IOException {
		List<String> lines = new ArrayList<>();
		lines.add("# " + BASELINE_FILENAME + " -- generated by Mos6502VectorExhaustiveTest with");
		lines.add("# -D" + REGENERATE_PROPERTY + "=true against the mos6502VectorTest Gradle task");
		lines.add("# (GRM_6502_VECTORS set). Review the diff, do not hand-edit casually. See");
		lines.add("# retromachines.vectors.OpcodeBaseline for the file format and");
		lines.add("# retromachines.vectors.Mos6502VectorHarnessSupport for the harness that");
		lines.add("# produced it (full upstream suite: 10,000 cases/opcode, 2,560,000 cases");
		lines.add("# total -- NOT the vendored 32-case/opcode sample in");
		lines.add("# src/test/resources/mos6502-vectors/, which keeps its own");
		lines.add("# mos6502-vector-baseline.txt at a different ratio).");
		lines.add("#");
		lines.add("# Mnemonic column: disassembly of the FIRST vector case's own instruction");
		lines.add("# bytes for that opcode. Operand VALUES are therefore whatever that first");
		lines.add("# case happened to hold -- expected, not a semantic change.");
		lines.addAll(OpcodeBaseline.formatAll(rows));
		Files.write(file.toPath(), lines, StandardCharsets.UTF_8);
	}
}
