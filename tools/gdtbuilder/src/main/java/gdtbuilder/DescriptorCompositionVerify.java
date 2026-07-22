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

import static gdtbuilder.VerifyHarness.check;
import static gdtbuilder.VerifyHarness.expectThrows;
import static gdtbuilder.VerifyHarness.write;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Standalone build check for machine-descriptor include composition. */
public class DescriptorCompositionVerify {

	public static void main(String[] args) throws Exception {
		VerifyHarness.run("descriptor-composition-", "Descriptor composition verification passed",
			temp -> {
				verifyComposition(temp);
				verifyErrors(temp);
			});
	}

	@SuppressWarnings("unchecked")
	private static void verifyComposition(Path temp) throws Exception {
		Path nested = Files.createDirectories(temp.resolve("nested"));
		write(temp.resolve("base.yaml"), """
			nested: { base: yes, winner: base }
			numeric_keys: { 0: zero }
			items: [base]
			scalar: base
			changes_type: { from: base }
			""");
		write(temp.resolve("third.yaml"), """
			nested: { third: yes, winner: third }
			items: [third]
			scalar: third
			""");
		write(nested.resolve("second.yaml"), """
			include: ../third.yaml
			nested: { second: yes, winner: second }
			items: [second]
			""");
		Path root = temp.resolve("root.yaml");
		write(root, """
			include: [base.yaml, nested/second.yaml]
			schema: 2
			nested: { local: yes, winner: local }
			items: [local]
			scalar: local
			changes_type: local-scalar
			""");

		Map<String, Object> composed = YamlSupport.loadComposed(root.toFile());
		check(!composed.containsKey("include"), "include key leaked into composed document");
		Map<String, Object> merged = (Map<String, Object>) composed.get("nested");
		check(merged.keySet().containsAll(List.of("base", "third", "second", "local")),
			"nested maps were not recursively merged: " + merged);
		check("local".equals(merged.get("winner")), "local nested scalar did not win");
		check(List.of("base", "third", "second", "local").equals(composed.get("items")),
			"lists were not appended in include/local order: " + composed.get("items"));
		check("local".equals(composed.get("scalar")), "local scalar did not win");
		check("local-scalar".equals(composed.get("changes_type")),
			"local type replacement did not win");
		Map<Object, Object> numericKeys = (Map<Object, Object>) composed.get("numeric_keys");
		check("zero".equals(numericKeys.get(0)),
			"valid nested numeric mapping key was not preserved: " + numericKeys);

		// Mutating one result must not mutate data retained by a subsequent load.
		((List<Object>) composed.get("items")).add("mutation");
		Map<String, Object> reloaded = YamlSupport.loadComposed(root.toFile());
		check(!((List<Object>) reloaded.get("items")).contains("mutation"),
			"composed values were not deep-copied");
	}

	private static void verifyErrors(Path temp) throws Exception {
		Path errors = Files.createDirectories(temp.resolve("errors"));
		write(errors.resolve("non-map.yaml"), "- not\n- a\n- map\n");
		expectError(errors.resolve("non-map.yaml"), "top-level mapping");

		write(errors.resolve("non-string.yaml"), "include: [7]\n");
		expectError(errors.resolve("non-string.yaml"), "non-string");
		write(errors.resolve("null.yaml"), "include: null\n");
		expectError(errors.resolve("null.yaml"), "string or list");

		write(errors.resolve("wrong-shape.yaml"), "include: {bad: shape}\n");
		expectError(errors.resolve("wrong-shape.yaml"), "string or list");

		write(errors.resolve("cyclic-alias.yaml"), "node: &node {self: *node}\n");
		expectError(errors.resolve("cyclic-alias.yaml"), "cyclic YAML anchor/alias");

		write(errors.resolve("missing.yaml"), "include: absent.yaml\n");
		expectError(errors.resolve("missing.yaml"), "does not exist");

		String absolute = temp.resolve("base.yaml").toAbsolutePath().toString().replace("'", "''");
		write(errors.resolve("absolute.yaml"), "include: '" + absolute + "'\n");
		expectError(errors.resolve("absolute.yaml"), "must be relative");

		Files.createDirectories(errors.resolve("sub"));
		write(errors.resolve("a.yaml"), "include: sub/../b.yaml\n");
		write(errors.resolve("b.yaml"), "include: a.yaml\n");
		expectError(errors.resolve("a.yaml"), "include cycle");
		try {
			YamlSupport.loadComposed(errors.resolve("a.yaml").toFile());
			throw new AssertionError("expected cycle error");
		}
		catch (IllegalArgumentException e) {
			check(e.getMessage().contains("a.yaml") && e.getMessage().contains("b.yaml") &&
				e.getMessage().contains(" -> "), "cycle error lacks canonical chain: " + e);
		}

		GdtBuilder.validateUniqueTypeNames(List.of(Map.of("name", "ONE")));
		try {
			GdtBuilder.validateUniqueTypeNames(
				List.of(Map.of("name", "DUP"), Map.of("name", "DUP")));
			throw new AssertionError("expected duplicate composed type-name error");
		}
		catch (IllegalArgumentException e) {
			check(e.getMessage().contains("declared twice"),
				"duplicate type-name error was unclear: " + e.getMessage());
		}
	}

	private static void expectError(Path file, String messagePart) throws Exception {
		expectThrows(messagePart, () -> YamlSupport.loadComposed(file.toFile()));
	}
}
