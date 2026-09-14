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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

/**
 * Shared build-time helpers for the {@code gdtBuilder} source set. Neither this class nor
 * its callers ({@link GdtBuilder}, {@link MapCompiler}) is shipped with the extension --
 * they run only during the Gradle build, so the snakeyaml dependency stays build-only.
 */
final class YamlSupport {

	private YamlSupport() {
	}

	/**
	 * Parses a machine-descriptor YAML file into its top-level map, treating an empty
	 * document as an empty map (snakeyaml returns {@code null} for one).
	 */
	@SuppressWarnings("unchecked")
	static Map<String, Object> load(File file) throws IOException {
		try (InputStream in = new FileInputStream(file)) {
			Yaml yaml = new Yaml();
			Object loaded = yaml.load(in);
			if (loaded == null) {
				return new LinkedHashMap<>();
			}
			if (!(loaded instanceof Map)) {
				throw new IllegalArgumentException(
					"YAML document is not a top-level mapping: " + file);
			}
			return (Map<String, Object>) loaded;
		}
	}

	/**
	 * Loads a schema-2 machine descriptor after expanding its build-time
	 * {@code include:} directives. This is deliberately separate from {@link #load}:
	 * external symbol/type source files and the schema-1 PETSCII compiler consume their
	 * YAML literally and must not acquire descriptor-composition semantics.
	 */
	static Map<String, Object> loadComposed(File file) throws IOException {
		return loadComposed(file.getCanonicalFile(), new ArrayList<>());
	}

	private static Map<String, Object> loadComposed(File file, List<File> stack)
			throws IOException {
		File canonical = file.getCanonicalFile();
		int cycleAt = stack.indexOf(canonical);
		if (cycleAt >= 0) {
			List<String> chain = new ArrayList<>();
			for (int i = cycleAt; i < stack.size(); i++) {
				chain.add(stack.get(i).getPath());
			}
			chain.add(canonical.getPath());
			throw new IllegalArgumentException("descriptor include cycle: " +
				String.join(" -> ", chain));
		}
		if (!canonical.isFile()) {
			throw new IllegalArgumentException(
				"descriptor include does not exist or is not a file: " + canonical);
		}

		stack.add(canonical);
		try {
			Map<String, Object> document = load(canonical);
			Map<String, Object> result = new LinkedHashMap<>();
			List<String> includes = document.containsKey("include")
				? includePaths(document.get("include"), canonical)
				: new ArrayList<>();
			for (String include : includes) {
				File includePath = new File(include);
				if (includePath.isAbsolute()) {
					throw new IllegalArgumentException(
						"descriptor include path must be relative in " + canonical + ": " + include);
				}
				File target = new File(canonical.getParentFile(), include).getCanonicalFile();
				result = mergeMaps(result, loadComposed(target, stack));
			}

			Map<String, Object> local = new LinkedHashMap<>();
			for (Map.Entry<?, ?> entry : document.entrySet()) {
				if (!(entry.getKey() instanceof String)) {
					throw new IllegalArgumentException(
						"descriptor mapping key is not a string in " + canonical + ": " +
							entry.getKey());
				}
				String key = (String) entry.getKey();
				if (!"include".equals(key)) {
					local.put(key, deepCopy(entry.getValue()));
				}
			}
			return mergeMaps(result, local);
		}
		finally {
			stack.remove(stack.size() - 1);
		}
	}

	private static List<String> includePaths(Object value, File source) {
		List<String> paths = new ArrayList<>();
		if (value instanceof String) {
			paths.add((String) value);
			return paths;
		}
		if (!(value instanceof List)) {
			throw new IllegalArgumentException(
				"descriptor include must be a string or list of strings in " + source);
		}
		for (Object item : (List<?>) value) {
			if (!(item instanceof String)) {
				throw new IllegalArgumentException(
					"descriptor include list contains a non-string value in " + source + ": " +
						item);
			}
			paths.add((String) item);
		}
		return paths;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> mergeMaps(Map<String, Object> earlier,
			Map<String, Object> later) {
		// Nested strategy params may intentionally have numeric YAML keys (MapCompiler
		// normalizes them to strings later), so only the document's top-level keys are
		// constrained above. Preserve arbitrary scalar keys while recursively merging.
		Map<Object, Object> merged = (Map<Object, Object>) deepCopy(earlier);
		for (Map.Entry<?, ?> entry : later.entrySet()) {
			Object key = entry.getKey();
			Object oldValue = merged.get(key);
			Object newValue = entry.getValue();
			if (oldValue instanceof Map && newValue instanceof Map) {
				merged.put(key, mergeMaps((Map<String, Object>) oldValue,
					(Map<String, Object>) newValue));
			}
			else if (oldValue instanceof List && newValue instanceof List) {
				List<Object> combined = (List<Object>) deepCopy(oldValue);
				for (Object item : (List<?>) newValue) {
					combined.add(deepCopy(item));
				}
				merged.put(key, combined);
			}
			else {
				merged.put(key, deepCopy(newValue));
			}
		}
		return (Map<String, Object>) (Map<?, ?>) merged;
	}

	private static Object deepCopy(Object value) {
		return deepCopy(value, new IdentityHashMap<>());
	}

	private static Object deepCopy(Object value, IdentityHashMap<Object, Boolean> visiting) {
		if (value instanceof Map) {
			if (visiting.put(value, Boolean.TRUE) != null) {
				throw new IllegalArgumentException(
					"cyclic YAML anchor/alias structures are not supported");
			}
			Map<Object, Object> copy = new LinkedHashMap<>();
			try {
				for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
					copy.put(entry.getKey(), deepCopy(entry.getValue(), visiting));
				}
				return copy;
			}
			finally {
				visiting.remove(value);
			}
		}
		if (value instanceof List) {
			if (visiting.put(value, Boolean.TRUE) != null) {
				throw new IllegalArgumentException(
					"cyclic YAML anchor/alias structures are not supported");
			}
			List<Object> copy = new ArrayList<>();
			try {
				for (Object item : (List<?>) value) {
					copy.add(deepCopy(item, visiting));
				}
				return copy;
			}
			finally {
				visiting.remove(value);
			}
		}
		return value;
	}
}
