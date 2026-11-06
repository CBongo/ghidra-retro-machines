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

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

/**
 * Drift check (beads grm-arbi.1, grm-arbi.3) for {@code machines/games/acs.yaml}: regenerates it
 * from the {@code external/game-music-extraction} submodule with
 * {@code tools/forth/forthhex2desc.py --check} and fails when the committed file is stale.
 * Assume-skips (green) when the submodule is not checked out or no Python interpreter runs.
 */
public class AcsForthYamlDriftTest {

	private static final Path ROOT = Paths.get("").toAbsolutePath();
	private static final Path SOURCE =
		ROOT.resolve("external/game-music-extraction/c64/acs/forthhex.pl");
	private static final Path SCRIPT = ROOT.resolve("tools/forth/forthhex2desc.py");

	private static Process start(String python) throws IOException {
		return new ProcessBuilder(python, "-I", SCRIPT.toString(), "--check")
				.directory(ROOT.toFile())
				.redirectErrorStream(true)
				.start();
	}

	@Test
	public void committedYamlMatchesRegeneration() throws Exception {
		assumeTrue("submodule external/game-music-extraction not checked out",
			Files.isRegularFile(SOURCE));
		Process p = null;
		for (String python : new String[] { "python", "python3" }) {
			try {
				p = start(python);
				break;
			}
			catch (IOException e) {
				// try the next interpreter name
			}
		}
		assumeTrue("no python interpreter on PATH", p != null);
		String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertEquals("machines/games/acs.yaml is stale; rerun tools/forth/forthhex2desc.py:\n" + out, 0,
			p.waitFor());
	}
}
