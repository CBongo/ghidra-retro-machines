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
package gdtbuilder;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/**
 * Shared scaffolding for the standalone {@code gdtbuilder} Verify* tools
 * ({@link DescriptorCompositionVerify}, {@link MapCompilerVerify}): the temp-dir
 * lifecycle, fixture {@link #write}, {@link #check}, and the throws-and-contains
 * assertion tail ({@link #expectThrows}). Keeping these here means a harness fix (temp-dir
 * cleanup, richer failure reporting) lands once instead of being copied per tool.
 */
final class VerifyHarness {

	private VerifyHarness() {
	}

	@FunctionalInterface
	interface TempDirTest {
		void run(Path temp) throws Exception;
	}

	@FunctionalInterface
	interface ThrowingAction {
		void run() throws Exception;
	}

	/**
	 * Runs {@code body} against a fresh temp directory, prints {@code passMessage} to stderr
	 * on success, and always reverse-order deletes the tree afterward.
	 */
	static void run(String tempPrefix, String passMessage, TempDirTest body) throws Exception {
		Path temp = Files.createTempDirectory(tempPrefix);
		try {
			body.run(temp);
			System.err.println(passMessage);
		}
		finally {
			try (var paths = Files.walk(temp)) {
				paths.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
			}
		}
	}

	static void write(Path file, String text) throws Exception {
		Files.writeString(file, text);
	}

	static void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}

	/**
	 * Asserts {@code action} throws an {@link IllegalArgumentException} whose message
	 * contains {@code part}; fails if it throws nothing or the message does not match.
	 */
	static void expectThrows(String part, ThrowingAction action) throws Exception {
		try {
			action.run();
			throw new AssertionError("expected error containing '" + part + "'");
		}
		catch (IllegalArgumentException e) {
			check(e.getMessage().contains(part),
				"expected error containing '" + part + "', got: " + e.getMessage());
		}
	}
}
