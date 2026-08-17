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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.lang.Language;

import retromachines.AbstractBundledLanguageTest;

/**
 * The exhaustive, opt-in SPC700 vector regression: all 256 opcodes x their full upstream case
 * count (~131,072 cases total) against a full local clone of
 * {@code https://github.com/SingleStepTests/spc700}, named by {@code GRM_SPC700_VECTORS} (bead
 * grm-c9d.2). Rides in its own `spc700-vectors` chunk -- a JUnit-family chunk like `unit`, NOT a
 * headless one -- and is deliberately excluded from the default `all` gate, exactly like the
 * real-ROM tier (`tools/banktest/realrom-test.sh`): it needs a large, user-supplied clone this
 * repo cannot ship, so it stays manual/opt-in rather than a CI gate.
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
 * <p>Compares against the same committed {@code spc700-vector-baseline.txt} that
 * {@link Spc700VectorSampleTest} uses -- the sample and the exhaustive run are checking the same
 * claim about the same opcodes, just at different case-count fidelity, so they share one
 * baseline rather than each maintaining its own.
 */
public class Spc700VectorExhaustiveTest extends AbstractBundledLanguageTest {

	static final String VECTORS_DIR_ENV = "GRM_SPC700_VECTORS";

	@Test
	public void exhaustiveRunAgainstFullVectorClone() throws Exception {
		String dir = System.getenv(VECTORS_DIR_ENV);
		if (dir == null || dir.isBlank()) {
			fail("SPC700VECTORS: SKIPPED -- " + VECTORS_DIR_ENV + " is unset. This tier was NOT " +
				"run; nothing about the full ~131,072-case SPC700 suite was checked. Set " +
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
		File baselineFile = new File(moduleRoot, "src/test/resources/spc700-vector-baseline.txt");
		assertTrue("no committed baseline at " + baselineFile + " -- run " +
			"Spc700VectorSampleTest with -Dgrm.spc700.regenerateBaseline=true first",
			baselineFile.isFile());
		List<String> lines = Files.readAllLines(baselineFile.toPath(), StandardCharsets.UTF_8);
		List<OpcodeBaseline> baseline = OpcodeBaseline.parse(lines);

		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertTrue("baseline mismatch:\n" + String.join("\n", problems), problems.isEmpty());
	}
}
