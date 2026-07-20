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
import com.google.gson.JsonObject;

/**
 * Standalone build-time tool (bead grm-1.4.5): reads BOTH {@code
 * machines/generated/petscii.yaml} (for its already-verified {@code unicode:} layer -- see
 * that file's header) and {@code machines/generated/screencode.yaml} (for the screen-code
 * permutation rules -- see that file's header for the full "PERMUTATION MODEL" writeup this
 * class implements) and emits {@code data/screencode.map}: a JSON document holding the two
 * 256-entry codepoint tables (per {@link retromachines.PetsciiMapper.Variant}) plus their
 * derived encode maps, in EXACTLY the shape
 * {@code retromachines.charset.RetroCharsetProvider#tableCharsetFromScreencodeJson} expects
 * (top-level {@code unicode_variants}/{@code encode}, each keyed
 * {@code unshifted_graphics}/{@code shifted_lowercase}) -- the same shape
 * {@link PetsciiCompiler} writes for those two keys in {@code petscii.map}, so that class's
 * small serialization helpers ({@link PetsciiCompiler#toJsonArray(int[])},
 * {@link PetsciiCompiler#toEncodeJsonObject(Map)}, {@link PetsciiCompiler#buildEncodeMap(int[])},
 * {@link PetsciiCompiler#hexInt(Object)}) are reused verbatim rather than duplicated.
 * <p>
 * Screen-code glyph knowledge is NOT duplicated here: every screen byte's codepoint is
 * resolved by looking up the PETSCII byte screencode.yaml's permutation rules say it shares a
 * glyph with, in the SAME unicode-layer table {@link PetsciiCompiler#buildUnicodeLayer} builds
 * for {@code petscii.map} -- reused directly (also made package-visible for this purpose), not
 * re-derived. This keeps petscii.yaml the single source of truth for actual glyph shapes; this
 * class only ever adds screen-code <-> PETSCII-byte NUMBERING information.
 * <p>
 * This class is NEVER shipped with the extension -- it runs only as part of the Gradle build
 * ({@code buildScreencodeMap} task in build.gradle), same as {@link PetsciiCompiler}.
 * <p>
 * Usage: {@code ScreencodeCompiler <petscii.yaml> <screencode.yaml> <output.map>}
 */
public class ScreencodeCompiler {

	private static final int TABLE_SIZE = 256;

	public static void main(String[] args) throws Exception {
		if (args.length != 3) {
			System.err.println(
				"Usage: ScreencodeCompiler <petscii.yaml> <screencode.yaml> <output.map>");
			System.exit(1);
		}
		File petsciiFile = new File(args[0]).getCanonicalFile();
		File screencodeFile = new File(args[1]).getCanonicalFile();
		File outputMap = new File(args[2]).getCanonicalFile();

		Map<String, Object> petsciiDoc = YamlSupport.load(petsciiFile);
		int petsciiSchema = ((Number) petsciiDoc.get("schema")).intValue();
		if (petsciiSchema != 2) {
			throw new IllegalArgumentException(
				"unsupported petscii.yaml 'schema: " + petsciiSchema + "' -- ScreencodeCompiler " +
					"requires the schema-2 unicode layer petscii.yaml carries");
		}

		Map<String, Object> screencodeDoc = YamlSupport.load(screencodeFile);
		int screencodeSchema = ((Number) screencodeDoc.get("schema")).intValue();
		if (screencodeSchema != 1) {
			throw new IllegalArgumentException(
				"unsupported screencode.yaml 'schema: " + screencodeSchema + "' -- this " +
					"ScreencodeCompiler builds schema 1");
		}

		// Reuse PetsciiCompiler's unicode-layer builder verbatim: this is the SAME table
		// (per byte, per variant) petscii.map's unicode_variants section is built from, so
		// referencing it here can never drift from what PetsciiMapper/RetroCharsetProvider's
		// PETSCII charsets already serve.
		int[] petsciiUnshifted = new int[TABLE_SIZE];
		int[] petsciiShifted = new int[TABLE_SIZE];
		PetsciiCompiler.buildUnicodeLayer(petsciiDoc, petsciiUnshifted, petsciiShifted);

		int[] screenUnshifted = new int[TABLE_SIZE];
		int[] screenShifted = new int[TABLE_SIZE];
		boolean[] covered = new boolean[TABLE_SIZE];

		applyRangeRules(screencodeDoc, petsciiUnshifted, petsciiShifted, screenUnshifted,
			screenShifted, covered);
		applyReverseVideo(screencodeDoc, screenUnshifted, screenShifted, covered);

		// Full-coverage validation: every one of the 256 screen codes must have been
		// resolved exactly once by either a range_rule or reverse_video above.
		for (int b = 0; b < TABLE_SIZE; b++) {
			if (!covered[b]) {
				throw new IllegalStateException(String.format(
					"screencode.yaml: screen code 0x%02x not covered by any range_rule or " +
						"reverse_video rule", b));
			}
		}

		Map<Integer, Integer> unshiftedEncode = PetsciiCompiler.buildEncodeMap(screenUnshifted);
		Map<Integer, Integer> shiftedEncode = PetsciiCompiler.buildEncodeMap(screenShifted);

		// Reverse-video consistency check: the canonical (encode-map) byte for every
		// codepoint that a 0x80-0xFF screen code decodes to must be a LOW (0x00-0x7F) byte,
		// i.e. reverse-video screen codes must never win the "lowest byte wins" canonicalization
		// -- see screencode.yaml's header "PERMUTATION MODEL" note on lossy-by-design encode.
		checkReverseVideoNeverCanonical(unshiftedEncode, screenUnshifted, "unshifted_graphics");
		checkReverseVideoNeverCanonical(shiftedEncode, screenShifted, "shifted_lowercase");

		JsonObject mapDoc = new JsonObject();
		mapDoc.addProperty("schema", 1);

		JsonObject provenance = new JsonObject();
		@SuppressWarnings("unchecked")
		Map<String, Object> prov = (Map<String, Object>) screencodeDoc.get("provenance");
		if (prov != null) {
			for (Map.Entry<String, Object> e : prov.entrySet()) {
				provenance.addProperty(e.getKey(), String.valueOf(e.getValue()));
			}
		}
		mapDoc.add("provenance", provenance);

		JsonObject unicodeVariants = new JsonObject();
		unicodeVariants.add("unshifted_graphics", PetsciiCompiler.toJsonArray(screenUnshifted));
		unicodeVariants.add("shifted_lowercase", PetsciiCompiler.toJsonArray(screenShifted));
		mapDoc.add("unicode_variants", unicodeVariants);

		JsonObject encode = new JsonObject();
		encode.add("unshifted_graphics", PetsciiCompiler.toEncodeJsonObject(unshiftedEncode));
		encode.add("shifted_lowercase", PetsciiCompiler.toEncodeJsonObject(shiftedEncode));
		mapDoc.add("encode", encode);

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new FileWriter(outputMap)) {
			gson.toJson(mapDoc, w);
		}

		System.out.println(
			"Wrote " + outputMap + " (256 screen codes x 2 variants, permutation of petscii.map)");
	}

	/** Expands {@code screencode.yaml}'s {@code range_rules}: each rule maps a same-length
	 *  screen-code range onto a PETSCII byte range, resolving each screen code's codepoint (per
	 *  variant) from the already-built PETSCII unicode-layer tables. Validates that every
	 *  referenced PETSCII byte is in range (0-255) and that no screen code is covered twice. */
	@SuppressWarnings("unchecked")
	private static void applyRangeRules(Map<String, Object> screencodeDoc, int[] petsciiUnshifted,
			int[] petsciiShifted, int[] screenUnshifted, int[] screenShifted, boolean[] covered) {
		List<Map<String, Object>> rules =
			(List<Map<String, Object>>) screencodeDoc.get("range_rules");
		if (rules == null) {
			throw new IllegalArgumentException(
				"screencode.yaml requires a top-level 'range_rules' list");
		}
		for (Map<String, Object> rule : rules) {
			int screenStart = PetsciiCompiler.hexInt(rule.get("screen_start"));
			int screenEnd = PetsciiCompiler.hexInt(rule.get("screen_end"));
			int petsciiStart = PetsciiCompiler.hexInt(rule.get("petscii_start"));
			for (int screenByte = screenStart; screenByte <= screenEnd; screenByte++) {
				int petsciiByte = petsciiStart + (screenByte - screenStart);
				if (petsciiByte < 0 || petsciiByte >= TABLE_SIZE) {
					throw new IllegalStateException(String.format(
						"screencode.yaml range_rule screen 0x%02x-0x%02x <- petscii 0x%02x: " +
							"referenced petscii byte 0x%02x is out of range for screen code 0x%02x",
						screenStart, screenEnd, petsciiStart, petsciiByte, screenByte));
				}
				if (covered[screenByte]) {
					throw new IllegalStateException(String.format(
						"screencode.yaml: screen code 0x%02x covered twice by range_rules",
						screenByte));
				}
				screenUnshifted[screenByte] = petsciiUnshifted[petsciiByte];
				screenShifted[screenByte] = petsciiShifted[petsciiByte];
				covered[screenByte] = true;
			}
		}
	}

	/** Expands {@code screencode.yaml}'s {@code reverse_video} rule: every screen code in
	 *  {@code screen_start..screen_end} (0x80-0xFF) shows the SAME glyph as its already-resolved
	 *  {@code mirrors_start}-relative partner (0x00-0x7F) -- see screencode.yaml's header for
	 *  why this is a same-glyph mirror, not an independent codepoint source. Requires the
	 *  primary {@code range_rules} pass to have already covered every mirror-target byte. */
	@SuppressWarnings("unchecked")
	private static void applyReverseVideo(Map<String, Object> screencodeDoc, int[] screenUnshifted,
			int[] screenShifted, boolean[] covered) {
		Map<String, Object> rule = (Map<String, Object>) screencodeDoc.get("reverse_video");
		if (rule == null) {
			throw new IllegalArgumentException(
				"screencode.yaml requires a top-level 'reverse_video' rule");
		}
		int screenStart = PetsciiCompiler.hexInt(rule.get("screen_start"));
		int screenEnd = PetsciiCompiler.hexInt(rule.get("screen_end"));
		int mirrorsStart = PetsciiCompiler.hexInt(rule.get("mirrors_start"));
		for (int screenByte = screenStart; screenByte <= screenEnd; screenByte++) {
			int source = mirrorsStart + (screenByte - screenStart);
			if (source < 0 || source >= TABLE_SIZE || !covered[source]) {
				throw new IllegalStateException(String.format(
					"screencode.yaml reverse_video: mirror source 0x%02x for screen code 0x%02x " +
						"was not resolved by range_rules before reverse_video ran", source,
					screenByte));
			}
			if (covered[screenByte]) {
				throw new IllegalStateException(String.format(
					"screencode.yaml: screen code 0x%02x covered twice (reverse_video vs a " +
						"range_rule)", screenByte));
			}
			screenUnshifted[screenByte] = screenUnshifted[source];
			screenShifted[screenByte] = screenShifted[source];
			covered[screenByte] = true;
		}
	}

	/** Validates that reverse-video (0x80-0xFF) screen codes never win the encode map's
	 *  "lowest byte wins" canonicalization ({@link PetsciiCompiler#buildEncodeMap} iterates bytes
	 *  ascending, so this holds automatically as long as every reverse-video byte's glyph is
	 *  ALSO produced by some byte below 0x80 -- true by construction here, since reverse_video
	 *  always mirrors a 0x00-0x7F byte's already-resolved codepoint -- but checked explicitly
	 *  since it is exactly the "reverse-video consistency" invariant this bead's task calls
	 *  out.). */
	private static void checkReverseVideoNeverCanonical(Map<Integer, Integer> encode,
			int[] screenTable, String variantName) {
		for (Map.Entry<Integer, Integer> e : encode.entrySet()) {
			int canonicalByte = e.getValue();
			if (canonicalByte >= 0x80) {
				throw new IllegalStateException(String.format(
					"screencode.map variant %s: codepoint U+%04X canonicalized to reverse-video " +
						"byte 0x%02x -- expected a 0x00-0x7F byte to always exist for the same glyph",
					variantName, e.getKey(), canonicalByte));
			}
		}
		// Additionally: every reverse-video byte's own codepoint must be encodable at all
		// (i.e. present in the encode map with SOME canonical byte) -- sanity that
		// buildEncodeMap actually saw every codepoint this table produces.
		for (int b = 0x80; b < TABLE_SIZE; b++) {
			int codepoint = screenTable[b];
			if (!encode.containsKey(codepoint)) {
				throw new IllegalStateException(String.format(
					"screencode.map variant %s: reverse-video byte 0x%02x's codepoint U+%04X " +
						"missing from its own encode map", variantName, b, codepoint));
			}
		}
	}
}
