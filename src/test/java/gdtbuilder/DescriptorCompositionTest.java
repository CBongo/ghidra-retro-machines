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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * JUnit migration of
 * {@code tools/gdtbuilder/src/main/java/gdtbuilder/DescriptorCompositionVerify.java} (bead
 * grm-32f.4): machine-descriptor include composition checks.
 */
public class DescriptorCompositionTest {

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	@SuppressWarnings("unchecked")
	@Test
	public void composition() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path nested = Files.createDirectories(temp.resolve("nested"));
		Files.writeString(temp.resolve("base.yaml"), """
			nested: { base: yes, winner: base }
			numeric_keys: { 0: zero }
			items: [base]
			scalar: base
			changes_type: { from: base }
			""");
		Files.writeString(temp.resolve("third.yaml"), """
			nested: { third: yes, winner: third }
			items: [third]
			scalar: third
			""");
		Files.writeString(nested.resolve("second.yaml"), """
			include: ../third.yaml
			nested: { second: yes, winner: second }
			items: [second]
			""");
		Path root = temp.resolve("root.yaml");
		Files.writeString(root, """
			include: [base.yaml, nested/second.yaml]
			schema: 2
			nested: { local: yes, winner: local }
			items: [local]
			scalar: local
			changes_type: local-scalar
			""");

		Map<String, Object> composed = YamlSupport.loadComposed(root.toFile());
		assertTrue("include key leaked into composed document", !composed.containsKey("include"));
		Map<String, Object> merged = (Map<String, Object>) composed.get("nested");
		assertTrue("nested maps were not recursively merged: " + merged,
			merged.keySet().containsAll(List.of("base", "third", "second", "local")));
		assertTrue("local nested scalar did not win", "local".equals(merged.get("winner")));
		assertTrue("lists were not appended in include/local order: " + composed.get("items"),
			List.of("base", "third", "second", "local").equals(composed.get("items")));
		assertTrue("local scalar did not win", "local".equals(composed.get("scalar")));
		assertTrue("local type replacement did not win",
			"local-scalar".equals(composed.get("changes_type")));
		Map<Object, Object> numericKeys = (Map<Object, Object>) composed.get("numeric_keys");
		assertTrue("valid nested numeric mapping key was not preserved: " + numericKeys,
			"zero".equals(numericKeys.get(0)));

		// Mutating one result must not mutate data retained by a subsequent load.
		((List<Object>) composed.get("items")).add("mutation");
		Map<String, Object> reloaded = YamlSupport.loadComposed(root.toFile());
		assertTrue("composed values were not deep-copied",
			!((List<Object>) reloaded.get("items")).contains("mutation"));
	}

	@Test
	public void errors() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path errors = Files.createDirectories(temp.resolve("errors"));
		Files.writeString(errors.resolve("non-map.yaml"), "- not\n- a\n- map\n");
		expectError(errors.resolve("non-map.yaml"), "top-level mapping");

		Files.writeString(errors.resolve("non-string.yaml"), "include: [7]\n");
		expectError(errors.resolve("non-string.yaml"), "non-string");
		Files.writeString(errors.resolve("null.yaml"), "include: null\n");
		expectError(errors.resolve("null.yaml"), "string or list");

		Files.writeString(errors.resolve("wrong-shape.yaml"), "include: {bad: shape}\n");
		expectError(errors.resolve("wrong-shape.yaml"), "string or list");

		Files.writeString(errors.resolve("cyclic-alias.yaml"), "node: &node {self: *node}\n");
		expectError(errors.resolve("cyclic-alias.yaml"), "cyclic YAML anchor/alias");

		Files.writeString(errors.resolve("missing.yaml"), "include: absent.yaml\n");
		expectError(errors.resolve("missing.yaml"), "does not exist");

		String absolute = temp.resolve("base.yaml").toAbsolutePath().toString().replace("'", "''");
		Files.writeString(errors.resolve("absolute.yaml"), "include: '" + absolute + "'\n");
		expectError(errors.resolve("absolute.yaml"), "must be relative");

		Files.createDirectories(errors.resolve("sub"));
		Files.writeString(errors.resolve("a.yaml"), "include: sub/../b.yaml\n");
		Files.writeString(errors.resolve("b.yaml"), "include: a.yaml\n");
		expectError(errors.resolve("a.yaml"), "include cycle");

		IllegalArgumentException cycleError = assertThrows(IllegalArgumentException.class,
			() -> YamlSupport.loadComposed(errors.resolve("a.yaml").toFile()));
		assertTrue("cycle error lacks canonical chain: " + cycleError,
			cycleError.getMessage().contains("a.yaml") && cycleError.getMessage().contains("b.yaml") &&
				cycleError.getMessage().contains(" -> "));

		GdtBuilder.validateUniqueTypeNames(List.of(Map.of("name", "ONE")));
		IllegalArgumentException dupError = assertThrows(IllegalArgumentException.class,
			() -> GdtBuilder.validateUniqueTypeNames(
				List.of(Map.of("name", "DUP"), Map.of("name", "DUP"))));
		assertTrue("duplicate type-name error was unclear: " + dupError.getMessage(),
			dupError.getMessage().contains("declared twice"));
	}

	private static void expectError(Path file, String messagePart) {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> YamlSupport.loadComposed(file.toFile()));
		assertTrue("expected error containing '" + messagePart + "', got: " + e.getMessage(),
			e.getMessage().contains(messagePart));
	}
}
