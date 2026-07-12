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
import java.io.FileWriter;
import java.io.Writer;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Standalone build-time tool (bead grm-1.4.1): reads {@code machines/generated/petscii.yaml}
 * (see that file's header for the frozen VICE-petcat-verbatim convention and provenance) and
 * emits {@code data/petscii.map} -- a JSON document holding two fully-resolved 256-entry
 * display-string tables, one per {@link retromachines.PetsciiMapper.Variant} -- for the
 * shipped extension's {@code PetsciiMapper} to load directly, with no YAML parser in the
 * runtime (mirrors {@link MapCompiler}'s split for the same reason).
 * <p>
 * Unlike the machine-descriptor YAML (whose {@code named_controls}/{@code literals}/
 * {@code identity_ranges}/{@code letter_range} sections are deliberately compact to avoid
 * hand-authoring 256 x 2 entries -- see petscii.yaml's header), the COMPILED output fully
 * expands both variants to 256 entries each: that duplication belongs in the generated
 * artifact, not the hand-maintained source, and it keeps {@code PetsciiMapper} a trivial
 * array-index lookup at runtime with no rule evaluation.
 * <p>
 * This class is NEVER shipped with the extension -- it runs only as part of the Gradle
 * build ({@code buildPetsciiMap} task in build.gradle). Never touches Ghidra runtime
 * classes (no {@code Application.initializeApplication}), same as {@link MapCompiler}.
 * <p>
 * Usage: {@code PetsciiCompiler <petscii.yaml> <output.map>}
 */
public class PetsciiCompiler {

	private static final int TABLE_SIZE = 256;

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: PetsciiCompiler <petscii.yaml> <output.map>");
			System.exit(1);
		}
		File descriptorFile = new File(args[0]).getCanonicalFile();
		File outputMap = new File(args[1]).getCanonicalFile();

		Map<String, Object> doc = YamlSupport.load(descriptorFile);

		int schemaVersion = ((Number) doc.get("schema")).intValue();
		if (schemaVersion != 1) {
			throw new IllegalArgumentException(
				"unsupported petscii.yaml 'schema: " + schemaVersion + "' -- this " +
					"PetsciiCompiler builds schema 1");
		}

		String[] unshifted = new String[TABLE_SIZE];
		String[] shifted = new String[TABLE_SIZE];

		// Baseline: petcat's own "{$xx}" lowercase-2-hex-digit fallback for every byte,
		// overwritten below by the more specific rules. (petscii.yaml's `default_fallback:
		// hex` field is documentation of this baseline, not a switch -- hex is the only
		// fallback this compiler implements.)
		for (int b = 0; b < TABLE_SIZE; b++) {
			String hex = String.format("{$%02x}", b);
			unshifted[b] = hex;
			shifted[b] = hex;
		}

		applyNamedControls(doc, unshifted, shifted);
		applyLiterals(doc, unshifted, shifted);
		applyIdentityRanges(doc, unshifted, shifted);
		applyLetterRange(doc, unshifted, shifted);

		for (int b = 0; b < TABLE_SIZE; b++) {
			if (unshifted[b] == null || unshifted[b].isEmpty() ||
				shifted[b] == null || shifted[b].isEmpty()) {
				throw new IllegalStateException(
					"byte 0x" + Integer.toHexString(b) + " resolved to an empty display " +
						"string -- every byte must produce a non-empty string in both variants");
			}
		}

		JsonObject mapDoc = new JsonObject();
		mapDoc.addProperty("schema", 1);

		JsonObject provenance = new JsonObject();
		@SuppressWarnings("unchecked")
		Map<String, Object> prov = (Map<String, Object>) doc.get("provenance");
		if (prov != null) {
			for (Map.Entry<String, Object> e : prov.entrySet()) {
				provenance.addProperty(e.getKey(), String.valueOf(e.getValue()));
			}
		}
		mapDoc.add("provenance", provenance);

		JsonObject variants = new JsonObject();
		variants.add("unshifted_graphics", toJsonArray(unshifted));
		variants.add("shifted_lowercase", toJsonArray(shifted));
		mapDoc.add("variants", variants);

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new FileWriter(outputMap)) {
			gson.toJson(mapDoc, w);
		}

		System.out.println("Wrote " + outputMap + " (256 bytes x 2 variants)");
	}

	private static JsonArray toJsonArray(String[] table) {
		JsonArray arr = new JsonArray();
		for (String s : table) {
			arr.add(s);
		}
		return arr;
	}

	@SuppressWarnings("unchecked")
	private static void applyNamedControls(Map<String, Object> doc, String[] unshifted,
			String[] shifted) {
		List<Map<String, Object>> entries =
			(List<Map<String, Object>>) doc.get("named_controls");
		if (entries == null) {
			return;
		}
		for (Map<String, Object> entry : entries) {
			int b = ((Number) entry.get("byte")).intValue();
			String name = (String) entry.get("name");
			String escaped = "{" + name + "}";
			unshifted[b] = escaped;
			shifted[b] = escaped;
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyLiterals(Map<String, Object> doc, String[] unshifted,
			String[] shifted) {
		List<Map<String, Object>> entries = (List<Map<String, Object>>) doc.get("literals");
		if (entries == null) {
			return;
		}
		for (Map<String, Object> entry : entries) {
			int b = ((Number) entry.get("byte")).intValue();
			String ch = (String) entry.get("char");
			unshifted[b] = ch;
			shifted[b] = ch;
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyIdentityRanges(Map<String, Object> doc, String[] unshifted,
			String[] shifted) {
		List<Map<String, Object>> ranges = (List<Map<String, Object>>) doc.get("identity_ranges");
		if (ranges == null) {
			return;
		}
		for (Map<String, Object> range : ranges) {
			int start = ((Number) range.get("start")).intValue();
			int end = ((Number) range.get("end")).intValue();
			for (int b = start; b <= end; b++) {
				String s = String.valueOf((char) b);
				unshifted[b] = s;
				shifted[b] = s;
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyLetterRange(Map<String, Object> doc, String[] unshifted,
			String[] shifted) {
		Map<String, Object> range = (Map<String, Object>) doc.get("letter_range");
		if (range == null) {
			return;
		}
		int start = ((Number) range.get("start")).intValue();
		int end = ((Number) range.get("end")).intValue();
		String unshiftedCase = (String) range.get("unshifted_graphics_case");
		String shiftedCase = (String) range.get("shifted_lowercase_case");
		for (int b = start; b <= end; b++) {
			char c = (char) b;
			unshifted[b] = String.valueOf(applyCase(c, unshiftedCase));
			shifted[b] = String.valueOf(applyCase(c, shiftedCase));
		}
	}

	private static char applyCase(char c, String caseSpec) {
		switch (caseSpec) {
			case "upper":
				return Character.toUpperCase(c);
			case "lower":
				return Character.toLowerCase(c);
			default:
				throw new IllegalArgumentException("unknown letter_range case '" + caseSpec + "'");
		}
	}
}
