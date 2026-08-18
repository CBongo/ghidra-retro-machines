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
 * The exhaustive, opt-in SPC700 vector regression: all 256 opcodes x their full upstream case
 * count (1000 cases/opcode, 256,000 cases total -- measured directly across all 256 upstream
 * files, bead grm-c9d.3 increment 6) against a full local clone of
 * {@code https://github.com/SingleStepTests/spc700}, named by {@code GRM_SPC700_VECTORS} (bead
 * grm-c9d.2). Rides in its own `spc700-vectors` chunk -- a JUnit-family chunk like `unit`, NOT a
 * headless one.
 *
 * <p><b>Routine, not ceremonial (grm-c9d.3 increment 6).</b> Now that a full vector clone is
 * available locally and the run is cheap (~256,000 cases at ~58 microseconds/case measured on
 * this project's hardware is on the order of 15 seconds, not a multi-minute affair), the project
 * owner has ruled this tier belongs in routine local verification alongside the real-ROM tier
 * (`tools/banktest/realrom-test.sh`) -- reach for it whenever `GRM_SPC700_VECTORS` is configured,
 * not only as a final ceremonial check before closing out grm-c9d.3. It stays excluded from the
 * default `all` gate for the same reason the real-ROM tier is: it needs a large, user-supplied
 * clone this repo cannot ship, so it cannot be a hard CI gate.
 *
 * <p><b>When {@code GRM_SPC700_VECTORS} is unset, this refuses loudly and fails (not skips) --
 * exit nonzero.</b> This matches {@code realrom-test.sh}'s rule stated in the project
 * {@code CLAUDE.md}: "never report a clean gate for a tier that did not execute." A green
 * `spc700-vectors` chunk must mean the exhaustive suite actually ran, not that nobody configured
 * it. Run it as: {@code GRM_SPC700_VECTORS=<full-clone-dir> bash
 * tools/banktest/build-and-test.sh check spc700-vectors}.
 *
 * <p>Unlike {@link Spc700VectorSampleTest}, this does NOT Assume-skip when the SPC700 language
 * itself is unavailable: once a caller has explicitly opted into this expensive tier by setting
 * {@code GRM_SPC700_VECTORS}, a missing language is a real problem they asked to hear about, not
 * a quiet skip.
 *
 * <p><b>Its own baseline, not the sampled one.</b> {@link Spc700VectorSampleTest} and this class
 * check the same semantic claim about the same 256 opcodes, but at different case-count fidelity
 * (32/opcode vs 1000/opcode) -- so their per-opcode PASS/FAIL ratios differ (e.g. {@code 32/32}
 * vs {@code 1000/1000}) even when both agree an opcode is fully correct, and a single shared file
 * cannot render both truthfully. Each keeps its own committed
 * {@code spc700-vector-baseline*.txt}; see {@link OpcodeBaseline} for the shared format and
 * {@code compare()} rules both files are checked against.
 *
 * <p><b>Regenerating this baseline:</b> run with {@code -Dgrm.spc700.regenerateExhaustiveBaseline
 * =true} against the {@code spc700VectorTest} Gradle task specifically (e.g. {@code gradle
 * spc700VectorTest -Dgrm.spc700.regenerateExhaustiveBaseline=true}), with
 * {@code GRM_SPC700_VECTORS} set. This is a DIFFERENT system property from
 * {@link Spc700VectorSampleTest}'s {@code grm.spc700.regenerateBaseline} deliberately -- see
 * {@code build.gradle}'s {@code spc700VectorTest} task for why the `test` task's forwarding of
 * the sample property does not, and must not, also flip this one.
 */
public class Spc700VectorExhaustiveTest extends AbstractBundledLanguageTest {

	static final String VECTORS_DIR_ENV = "GRM_SPC700_VECTORS";
	private static final String REGENERATE_PROPERTY = "grm.spc700.regenerateExhaustiveBaseline";
	private static final String BASELINE_FILENAME = "spc700-vector-baseline-exhaustive.txt";

	@Test
	public void exhaustiveRunAgainstFullVectorClone() throws Exception {
		String dir = System.getenv(VECTORS_DIR_ENV);
		if (dir == null || dir.isBlank()) {
			fail("SPC700VECTORS: SKIPPED -- " + VECTORS_DIR_ENV + " is unset. This tier was NOT " +
				"run; nothing about the full 256,000-case SPC700 suite was checked. Set " +
				VECTORS_DIR_ENV + " to a full clone of " +
				"https://github.com/SingleStepTests/spc700 (git clone --depth 1 " +
				"https://github.com/SingleStepTests/spc700 <dir>) and rerun: " +
				"GRM_SPC700_VECTORS=<dir> bash tools/banktest/build-and-test.sh check " +
				"spc700-vectors");
		}
		File v1Dir = new File(dir, "v1");
		assertTrue(VECTORS_DIR_ENV + "=" + dir + " does not look like a spc700 clone (no v1/ " +
			"directory)", v1Dir.isDirectory());

		Language language = Spc700VectorHarnessSupport.resolveLanguage();
		List<File> opcodeFiles = Spc700VectorHarnessSupport.opcodeFilesIn(v1Dir);
		assertTrue("expected 256 opcode files under " + v1Dir + ", found " + opcodeFiles.size(),
			opcodeFiles.size() == 256);

		VectorRunner runner = Spc700VectorHarnessSupport.newRunner(language);
		List<OpcodeBaseline> actual = new ArrayList<>();
		for (File f : opcodeFiles) {
			actual.add(Spc700VectorHarnessSupport.runOpcodeFile(runner, f));
		}

		File moduleRoot = new File(System.getProperty(MODULE_DIR_PROPERTY));
		File baselineFile = new File(moduleRoot, "src/test/resources/" + BASELINE_FILENAME);

		if (Boolean.getBoolean(REGENERATE_PROPERTY)) {
			writeBaseline(baselineFile, actual);
			System.out.println("regenerated " + baselineFile + " (" + actual.size() +
				" opcodes) -- review the diff and commit deliberately");
			return;
		}

		assertTrue("no committed baseline at " + baselineFile + " -- run with -D" +
			REGENERATE_PROPERTY + "=true against the spc700VectorTest task first",
			baselineFile.isFile());
		List<String> lines = Files.readAllLines(baselineFile.toPath(), StandardCharsets.UTF_8);
		List<OpcodeBaseline> baseline = OpcodeBaseline.parse(lines);

		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertTrue("baseline mismatch:\n" + String.join("\n", problems), problems.isEmpty());
	}

	private static void writeBaseline(File file, List<OpcodeBaseline> rows) throws IOException {
		List<String> lines = new ArrayList<>();
		lines.add("# " + BASELINE_FILENAME + " -- generated by Spc700VectorExhaustiveTest with");
		lines.add("# -D" + REGENERATE_PROPERTY + "=true against the spc700VectorTest Gradle task");
		lines.add("# (GRM_SPC700_VECTORS set). Review the diff, do not hand-edit casually. See");
		lines.add("# retromachines.vectors.OpcodeBaseline for the file format and");
		lines.add("# retromachines.vectors.Spc700VectorHarnessSupport for the harness that");
		lines.add("# produced it (full upstream suite: 1000 cases/opcode, 256,000 cases total,");
		lines.add("# SingleStepTests/spc700 commit 67d15f492b2740964abd4efd1229e0ec9c342228 --");
		lines.add("# NOT the vendored 32-case/opcode sample in src/test/resources/spc700-vectors/,");
		lines.add("# which keeps its own spc700-vector-baseline.txt at a different ratio).");
		lines.add("#");
		lines.add("# Mnemonic column: disassembly of the FIRST vector case's own instruction");
		lines.add("# bytes for that opcode. Operand VALUES are therefore whatever that first");
		lines.add("# case happened to hold (e.g. 'MOV A,0x10' vs 'MOV A,0x7f' on a re-run) --");
		lines.add("# expected and not a semantic change. Only a changed MNEMONIC or a row that");
		lines.add("# newly falls back to '-' is worth a second look.");
		lines.addAll(OpcodeBaseline.formatAll(rows));
		Files.write(file.toPath(), lines, StandardCharsets.UTF_8);
	}
}
