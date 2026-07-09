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
import java.util.LinkedHashMap;
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
			return (Map<String, Object>) loaded;
		}
	}
}
