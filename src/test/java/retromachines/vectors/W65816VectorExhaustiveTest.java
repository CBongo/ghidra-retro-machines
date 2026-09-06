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
 * The exhaustive, opt-in W65816 vector regression: all 256 opcodes x both native/emulation
 * modes x their full upstream case count (10,000 cases/opcode/mode, 5,120,000 cases total)
 * against a full local clone of {@code https://github.com/SingleStepTests/65816}, named by
 * {@code GRM_W65816_VECTORS} (bead grm-9nxj.3). Rides in its own {@code w65816-vectors} chunk --
 * the W65816 analogue of {@code Spc700VectorExhaustiveTest}, whose class doc this one mirrors
 * closely; see that class for the general design.
 *
 * <p><b>Do NOT extrapolate SPC700's ~15s/256,000-case timing to this tier.</b> This suite is 20x
 * the case count with larger per-case payloads (24-bit flat RAM addressing vs. SPC700's 16-bit);
 * heap and wall-clock need remeasuring from scratch once a full clone is available to run
 * against -- see {@code docs/testing.md}'s row for whatever was actually measured (or, if this
 * comment is being read before that has happened, the absence of a measurement there is itself
 * the current state: nobody has run this tier yet).
 *
 * <p><b>When {@code GRM_W65816_VECTORS} is unset, this refuses loudly and fails (not skips) --
 * exit nonzero</b>, identically to {@code Spc700VectorExhaustiveTest}'s rule: a green
 * {@code w65816-vectors} chunk must mean the exhaustive suite actually ran.
 *
 * <p>Unlike {@link W65816VectorSampleTest}, this does NOT Assume-skip when the 65816 language
 * itself is unavailable -- once a caller has opted into this expensive tier, a missing language
 * is a real problem they asked to hear about.
 *
 * <p><b>Its own baseline, not the sampled one</b> -- see {@link OpcodeBaseline} and
 * {@code Spc700VectorExhaustiveTest}'s doc for why the sample and exhaustive tiers cannot share
 * one baseline file (different case-count fidelity moves every ratio).
 *
 * <p><b>Regenerating this baseline:</b> run with {@code -Dgrm.w65816.regenerateExhaustiveBaseline
 * =true} against the {@code w65816VectorTest} Gradle task specifically, with
 * {@code GRM_W65816_VECTORS} set -- a DIFFERENT system property from
 * {@link W65816VectorSampleTest}'s, for the identical forwarding reason documented on
 * {@code spc700VectorTest} in {@code build.gradle}.
 */
public class W65816VectorExhaustiveTest extends AbstractBundledLanguageTest {

	static final String VECTORS_DIR_ENV = "GRM_W65816_VECTORS";
	private static final String REGENERATE_PROPERTY = "grm.w65816.regenerateExhaustiveBaseline";
	private static final String BASELINE_FILENAME = "w65816-vector-baseline-exhaustive.txt";

	@Test
	public void exhaustiveRunAgainstFullVectorClone() throws Exception {
		String dir = System.getenv(VECTORS_DIR_ENV);
		if (dir == null || dir.isBlank()) {
			fail("W65816VECTORS: SKIPPED -- " + VECTORS_DIR_ENV + " is unset. This tier was NOT " +
				"run; nothing about the full 5,120,000-case W65816 suite was checked. Set " +
				VECTORS_DIR_ENV + " to a full clone of " +
				"https://github.com/SingleStepTests/65816 (git clone --depth 1 " +
				"https://github.com/SingleStepTests/65816 <dir>) and rerun: " +
				"GRM_W65816_VECTORS=<dir> bash tools/banktest/build-and-test.sh check " +
				"w65816-vectors");
		}
		File v1Dir = new File(dir, "v1");
		assertTrue(VECTORS_DIR_ENV + "=" + dir + " does not look like a 65816 clone (no v1/ " +
			"directory)", v1Dir.isDirectory());

		Language language = W65816VectorHarnessSupport.resolveLanguage();
		List<File> opcodeFiles = W65816VectorHarnessSupport.opcodeFilesIn(v1Dir);
		assertTrue("expected 512 opcode files (256 opcodes x native/emulation) under " + v1Dir +
			", found " + opcodeFiles.size(), opcodeFiles.size() == 512);

		VectorRunner runner = W65816VectorHarnessSupport.newRunner(language);
		List<OpcodeBaseline> actual = new ArrayList<>();
		for (File f : opcodeFiles) {
			actual.add(W65816VectorHarnessSupport.runOpcodeFile(runner, f));
		}
		W65816VectorHarnessSupport.assertDecodeBoundaryCapNotExceeded(actual);
		W65816VectorHarnessSupport.assertBankWrapCapNotExceeded(actual);

		File moduleRoot = new File(System.getProperty(MODULE_DIR_PROPERTY));
		File baselineFile = new File(moduleRoot, "src/test/resources/" + BASELINE_FILENAME);

		if (Boolean.getBoolean(REGENERATE_PROPERTY)) {
			writeBaseline(baselineFile, actual);
			System.out.println("regenerated " + baselineFile + " (" + actual.size() +
				" rows) -- review the diff and commit deliberately");
			return;
		}

		assertTrue("no committed baseline at " + baselineFile + " -- run with -D" +
			REGENERATE_PROPERTY + "=true against the w65816VectorTest task first",
			baselineFile.isFile());
		List<String> lines = Files.readAllLines(baselineFile.toPath(), StandardCharsets.UTF_8);
		List<OpcodeBaseline> baseline = OpcodeBaseline.parse(lines);

		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertTrue("baseline mismatch:\n" + String.join("\n", problems), problems.isEmpty());
	}

	private static void writeBaseline(File file, List<OpcodeBaseline> rows) throws IOException {
		List<String> lines = new ArrayList<>();
		lines.add("# " + BASELINE_FILENAME + " -- generated by W65816VectorExhaustiveTest with");
		lines.add("# -D" + REGENERATE_PROPERTY + "=true against the w65816VectorTest Gradle task");
		lines.add("# (GRM_W65816_VECTORS set). Review the diff, do not hand-edit casually. See");
		lines.add("# retromachines.vectors.OpcodeBaseline for the file format and");
		lines.add("# retromachines.vectors.W65816VectorHarnessSupport for the harness that");
		lines.add("# produced it (full upstream suite: 10,000 cases/opcode/mode, 5,120,000 cases");
		lines.add("# total -- NOT the vendored 16-opcode/32-case sample in");
		lines.add("# src/test/resources/w65816-vectors/, which keeps its own");
		lines.add("# w65816-vector-baseline.txt at a different ratio and coverage).");
		lines.add("#");
		lines.add("# Row key is <OPCODE-HEX>.<N|E> (native/emulation) -- see");
		lines.add("# W65816VectorHarnessSupport#runOpcodeFile.");
		lines.add("#");
		lines.add("# EXPECT FAILURES: see W65816VectorSampleTest's baseline header for why a FAIL");
		lines.add("# row is not a test bug, and W65816VectorHarnessSupport's class doc for the");
		lines.add("# bits of 'p' this harness cannot verify at all.");
		lines.addAll(OpcodeBaseline.formatAll(rows));
		Files.write(file.toPath(), lines, StandardCharsets.UTF_8);
	}
}
