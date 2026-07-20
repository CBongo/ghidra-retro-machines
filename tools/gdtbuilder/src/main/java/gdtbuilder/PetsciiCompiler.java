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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Standalone build-time tool (bead grm-1.4.1; unicode layer added grm-1.4.2): reads
 * {@code machines/generated/petscii.yaml} (see that file's header for the frozen
 * VICE-petcat-verbatim convention and provenance, and the {@code unicode:} section header for
 * the unicode-layer provenance) and emits {@code data/petscii.map} -- a JSON document holding
 * TWO independent 256-entry tables per {@link retromachines.PetsciiMapper.Variant}: the
 * frozen escaped-display strings ({@code variants}, byte-identical to schema 1 -- golden test
 * dumps depend on this) and the new unicode codepoints ({@code unicode_variants} + their
 * derived {@code encode} maps) -- for the shipped extension's {@code PetsciiMapper} to load
 * directly, with no YAML parser in the runtime (mirrors {@link MapCompiler}'s split for the
 * same reason).
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
		if (schemaVersion != 2) {
			throw new IllegalArgumentException(
				"unsupported petscii.yaml 'schema: " + schemaVersion + "' -- this " +
					"PetsciiCompiler builds schema 2");
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

		// Unicode layer (grm-1.4.2): a second, independent 256-entry codepoint table per
		// variant, built from petscii.yaml's `unicode:` section. Kept entirely separate from
		// the `unshifted`/`shifted` escaped-display arrays above -- neither reads nor writes
		// them -- so the frozen `variants` output above cannot be perturbed by this addition.
		int[] unshiftedUnicode = new int[TABLE_SIZE];
		int[] shiftedUnicode = new int[TABLE_SIZE];
		buildUnicodeLayer(doc, unshiftedUnicode, shiftedUnicode);

		Map<Integer, Integer> unshiftedEncode = buildEncodeMap(unshiftedUnicode);
		Map<Integer, Integer> shiftedEncode = buildEncodeMap(shiftedUnicode);

		JsonObject mapDoc = new JsonObject();
		mapDoc.addProperty("schema", 2);

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

		JsonObject unicodeVariants = new JsonObject();
		unicodeVariants.add("unshifted_graphics", toJsonArray(unshiftedUnicode));
		unicodeVariants.add("shifted_lowercase", toJsonArray(shiftedUnicode));
		mapDoc.add("unicode_variants", unicodeVariants);

		// Encode maps: codepoint -> canonical byte, keyed by DECIMAL codepoint string (JSON
		// object keys are always strings; decimal chosen over hex so PetsciiMapper can parse
		// with plain Integer.parseInt(key), no radix handling).
		JsonObject encode = new JsonObject();
		encode.add("unshifted_graphics", toEncodeJsonObject(unshiftedEncode));
		encode.add("shifted_lowercase", toEncodeJsonObject(shiftedEncode));
		mapDoc.add("encode", encode);

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new FileWriter(outputMap)) {
			gson.toJson(mapDoc, w);
		}

		System.out.println("Wrote " + outputMap + " (256 bytes x 2 variants, escaped + unicode layers)");
	}

	private static JsonArray toJsonArray(String[] table) {
		JsonArray arr = new JsonArray();
		for (String s : table) {
			arr.add(s);
		}
		return arr;
	}

	static JsonArray toJsonArray(int[] table) {
		JsonArray arr = new JsonArray();
		for (int cp : table) {
			arr.add(cp);
		}
		return arr;
	}

	/** Builds the {@code encode} map for one variant: codepoint -&gt; canonical byte, where
	 *  "canonical" means the LOWEST byte value that decodes to that codepoint (first-write-wins
	 *  iterating bytes in ascending order). */
	static Map<Integer, Integer> buildEncodeMap(int[] unicodeTable) {
		Map<Integer, Integer> encode = new LinkedHashMap<>();
		for (int b = 0; b < TABLE_SIZE; b++) {
			encode.putIfAbsent(unicodeTable[b], b);
		}
		return encode;
	}

	/** Serializes an encode map as a JSON object keyed by DECIMAL codepoint string (see the
	 *  {@code encode} comment at the call site for why decimal, not hex). */
	static JsonObject toEncodeJsonObject(Map<Integer, Integer> encode) {
		JsonObject obj = new JsonObject();
		for (Map.Entry<Integer, Integer> e : encode.entrySet()) {
			obj.addProperty(String.valueOf(e.getKey()), e.getValue());
		}
		return obj;
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

	// -------------------------------------------------------------------------------------
	// Unicode layer (grm-1.4.2). See petscii.yaml's `unicode:` section header for the full
	// provenance/discrepancy writeup this code implements. Entirely independent of the
	// escaped-display arrays above (different local variables, never touches them).
	// -------------------------------------------------------------------------------------

	/** Coverage marker for the "every byte covered exactly once" validation: which primary
	 *  unicode-layer rule category last touched a given byte, per variant. {@code null} means
	 *  "not yet touched by any primary category" -- expected only for the 0xC0-0xFF mirror
	 *  range, which primary categories deliberately never touch (mirror_ranges fills it last). */
	private enum Category {
		CONTROL, IDENTITY, LITERAL, DIVERGENCE, LETTER, GRAPHICS_LETTER, GRAPHICS
	}

	/** Package-visible (not private) so {@link ScreencodeCompiler} can reuse it to obtain
	 *  the PETSCII unicode-layer tables its own permutation rules reference -- see that
	 *  class's javadoc. */
	@SuppressWarnings("unchecked")
	static void buildUnicodeLayer(Map<String, Object> doc, int[] unshiftedUnicode,
			int[] shiftedUnicode) {
		Map<String, Object> unicode = (Map<String, Object>) doc.get("unicode");
		if (unicode == null) {
			throw new IllegalArgumentException(
				"petscii.yaml schema 2 requires a top-level 'unicode:' section");
		}

		int fallback = hexInt(unicode.get("default_fallback_codepoint"));
		java.util.Arrays.fill(unshiftedUnicode, fallback);
		java.util.Arrays.fill(shiftedUnicode, fallback);

		Category[] unshiftedCoverage = new Category[TABLE_SIZE];
		Category[] shiftedCoverage = new Category[TABLE_SIZE];

		applyControlPassthrough(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);
		applyUnicodeIdentityRanges(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);
		applyLiteralCodepoints(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);
		applyAsciiDivergences(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);
		applyUnicodeLetterRange(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);
		applyGraphicsLetterRange(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);
		applyGraphicsCodepoints(unicode, unshiftedUnicode, shiftedUnicode, unshiftedCoverage,
			shiftedCoverage);

		// Validation: every byte 0x00-0xBF covered exactly once by a primary category; every
		// byte 0xC0-0xFF NOT yet covered (reserved for mirror_ranges below).
		for (int b = 0; b < TABLE_SIZE; b++) {
			boolean shouldBeCovered = b < 0xC0;
			if (shouldBeCovered) {
				if (unshiftedCoverage[b] == null || shiftedCoverage[b] == null) {
					throw new IllegalStateException(String.format(
						"unicode layer: byte 0x%02x not covered by any primary rule category", b));
				}
			}
			else if (unshiftedCoverage[b] != null || shiftedCoverage[b] != null) {
				throw new IllegalStateException(String.format(
					"unicode layer: byte 0x%02x (mirror range) unexpectedly touched by a " +
						"primary rule category (%s/%s) before mirror_ranges ran",
					b, unshiftedCoverage[b], shiftedCoverage[b]));
			}
		}

		applyShiftedOverrides(unicode, shiftedUnicode);
		applyMirrorRanges(unicode, unshiftedUnicode, shiftedUnicode);

		// Mirror consistency re-check: every mirror byte must equal its (fully-resolved,
		// post-override) canonical partner, in both variants.
		for (Map<String, Object> rule : mirrorRuleList(unicode)) {
			for (int[] pair : mirrorPairs(rule)) {
				int target = pair[0];
				int source = pair[1];
				if (unshiftedUnicode[target] != unshiftedUnicode[source] ||
					shiftedUnicode[target] != shiftedUnicode[source]) {
					throw new IllegalStateException(String.format(
						"unicode layer: mirror byte 0x%02x does not match canonical 0x%02x",
						target, source));
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyControlPassthrough(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		List<Map<String, Object>> ranges =
			(List<Map<String, Object>>) unicode.get("control_passthrough_ranges");
		for (Map<String, Object> range : ranges) {
			int start = hexInt(range.get("start"));
			int end = hexInt(range.get("end"));
			for (int b = start; b <= end; b++) {
				unshifted[b] = b;
				shifted[b] = b;
				mark(unshiftedCoverage, shiftedCoverage, b, Category.CONTROL);
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyUnicodeIdentityRanges(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		List<Map<String, Object>> ranges = (List<Map<String, Object>>) unicode.get("identity_ranges");
		for (Map<String, Object> range : ranges) {
			int start = hexInt(range.get("start"));
			int end = hexInt(range.get("end"));
			for (int b = start; b <= end; b++) {
				unshifted[b] = b;
				shifted[b] = b;
				mark(unshiftedCoverage, shiftedCoverage, b, Category.IDENTITY);
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyLiteralCodepoints(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		List<Map<String, Object>> entries =
			(List<Map<String, Object>>) unicode.get("literal_codepoints");
		for (Map<String, Object> entry : entries) {
			int b = hexInt(entry.get("byte"));
			int cp = hexInt(entry.get("codepoint"));
			unshifted[b] = cp;
			shifted[b] = cp;
			mark(unshiftedCoverage, shiftedCoverage, b, Category.LITERAL);
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyAsciiDivergences(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		List<Map<String, Object>> entries =
			(List<Map<String, Object>>) unicode.get("ascii_divergences");
		for (Map<String, Object> entry : entries) {
			int b = hexInt(entry.get("byte"));
			int cp = hexInt(entry.get("codepoint"));
			unshifted[b] = cp;
			shifted[b] = cp;
			mark(unshiftedCoverage, shiftedCoverage, b, Category.DIVERGENCE);
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyUnicodeLetterRange(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		Map<String, Object> range = (Map<String, Object>) unicode.get("letter_range");
		int start = hexInt(range.get("start"));
		int end = hexInt(range.get("end"));
		String unshiftedCase = (String) range.get("unshifted_graphics_case");
		String shiftedCase = (String) range.get("shifted_lowercase_case");
		for (int b = start; b <= end; b++) {
			unshifted[b] = applyCase((char) b, unshiftedCase);
			shifted[b] = applyCase((char) b, shiftedCase);
			mark(unshiftedCoverage, shiftedCoverage, b, Category.LETTER);
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyGraphicsLetterRange(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		Map<String, Object> range = (Map<String, Object>) unicode.get("graphics_letter_range");
		int start = hexInt(range.get("start"));
		int end = hexInt(range.get("end"));
		String shiftedCase = (String) range.get("shifted_lowercase_case");
		Map<?, ?> codepoints = (Map<?, ?>) range.get("unshifted_graphics_codepoints");
		for (int b = start; b <= end; b++) {
			Integer cp = lookupIntKey(codepoints, b);
			if (cp != null) {
				unshifted[b] = cp;
			}
			// else: byte keeps the default_fallback_codepoint already filled in -- see
			// petscii.yaml DISCREPANCIES #2.
			shifted[b] = applyCase((char) b, shiftedCase);
			mark(unshiftedCoverage, shiftedCoverage, b, Category.GRAPHICS_LETTER);
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyGraphicsCodepoints(Map<String, Object> unicode, int[] unshifted,
			int[] shifted, Category[] unshiftedCoverage, Category[] shiftedCoverage) {
		Map<?, ?> codepoints = (Map<?, ?>) unicode.get("graphics_codepoints");
		for (Map.Entry<?, ?> e : codepoints.entrySet()) {
			int b = ((Number) e.getKey()).intValue();
			int cp = ((Number) e.getValue()).intValue();
			unshifted[b] = cp;
			shifted[b] = cp;
			mark(unshiftedCoverage, shiftedCoverage, b, Category.GRAPHICS);
		}
	}

	/** shifted_overrides: shifted_lowercase-only reassignment on top of the primary
	 *  categories above; {@code null} means "no assigned codepoint in this variant" -- falls
	 *  back to {@code default_fallback_codepoint} (already what the byte holds unless a
	 *  primary category set something else, so we must re-apply the fallback explicitly). */
	@SuppressWarnings("unchecked")
	private static void applyShiftedOverrides(Map<String, Object> unicode, int[] shifted) {
		Map<?, ?> overrides = (Map<?, ?>) unicode.get("shifted_overrides");
		if (overrides == null) {
			return;
		}
		int fallback = hexInt(unicode.get("default_fallback_codepoint"));
		for (Map.Entry<?, ?> e : overrides.entrySet()) {
			int b = ((Number) e.getKey()).intValue();
			Object value = e.getValue();
			shifted[b] = value == null ? fallback : ((Number) value).intValue();
		}
	}

	@SuppressWarnings("unchecked")
	private static void applyMirrorRanges(Map<String, Object> unicode, int[] unshifted,
			int[] shifted) {
		for (Map<String, Object> rule : mirrorRuleList(unicode)) {
			for (int[] pair : mirrorPairs(rule)) {
				int target = pair[0];
				int source = pair[1];
				unshifted[target] = unshifted[source];
				shifted[target] = shifted[source];
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> mirrorRuleList(Map<String, Object> unicode) {
		return (List<Map<String, Object>>) unicode.get("mirror_ranges");
	}

	/** Expands one {@code mirror_ranges} entry (either a {@code start/end/mirrors_start} range
	 *  or a single {@code byte/mirrors} pair) into explicit {@code {target, source}} byte
	 *  pairs. */
	private static List<int[]> mirrorPairs(Map<String, Object> rule) {
		List<int[]> pairs = new java.util.ArrayList<>();
		if (rule.containsKey("start")) {
			int start = hexInt(rule.get("start"));
			int end = hexInt(rule.get("end"));
			int mirrorsStart = hexInt(rule.get("mirrors_start"));
			for (int b = start; b <= end; b++) {
				pairs.add(new int[] { b, mirrorsStart + (b - start) });
			}
		}
		else {
			int b = hexInt(rule.get("byte"));
			int mirrors = hexInt(rule.get("mirrors"));
			pairs.add(new int[] { b, mirrors });
		}
		return pairs;
	}

	private static void mark(Category[] unshiftedCoverage, Category[] shiftedCoverage, int b,
			Category category) {
		if (unshiftedCoverage[b] != null || shiftedCoverage[b] != null) {
			throw new IllegalStateException(String.format(
				"unicode layer: byte 0x%02x covered twice (already %s/%s, now %s)", b,
				unshiftedCoverage[b], shiftedCoverage[b], category));
		}
		unshiftedCoverage[b] = category;
		shiftedCoverage[b] = category;
	}

	/** snakeyaml parses YAML mapping-key integers (including {@code 0x..} literals) as
	 *  {@code Integer}/{@code Long}; this looks one up by numeric value regardless of the
	 *  exact boxed type snakeyaml chose. */
	private static Integer lookupIntKey(Map<?, ?> map, int key) {
		for (Map.Entry<?, ?> e : map.entrySet()) {
			if (((Number) e.getKey()).intValue() == key) {
				return ((Number) e.getValue()).intValue();
			}
		}
		return null;
	}

	/** Reads a YAML-parsed scalar (already a {@code Number} -- snakeyaml resolves {@code 0x..}
	 *  hex literals to {@code Integer}/{@code Long} directly, no string parsing needed here)
	 *  as an {@code int}. */
	static int hexInt(Object value) {
		return ((Number) value).intValue();
	}
}
