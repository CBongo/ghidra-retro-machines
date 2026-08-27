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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Data-driven PETSCII byte -&gt; display-string lookup (bead grm-1.4.1), for the future C64
 * BASIC detokenizing analyzer (grm-odt.1) and PETSCII charset registration (parent bead
 * grm-1.4). Backed entirely by the compiled {@code data/petscii.map} artifact (built from
 * {@code machines/generated/petscii.yaml} by {@code gdtbuilder.PetsciiCompiler} -- see that
 * YAML file's header for the frozen VICE-petcat-verbatim escape convention and full
 * provenance): this class contains no PETSCII knowledge of its own, only lookup logic.
 * <p>
 * <b>v1 scope (schema 1):</b> {@link #toDisplayEscaped(int, Variant)} -- ASCII-only bracket
 * escapes (e.g. {@code "{clr}"}, {@code "{$a3}"}).
 * <p>
 * <b>Unicode layer (schema 2, bead grm-1.4.2):</b> {@link #toDisplayUnicode(int, Variant)} --
 * every byte resolves to a real Unicode codepoint: C0/C1 controls pass through as their own
 * byte value, graphics render as true glyphs (box drawing, block elements, card suits, and
 * "Symbols for Legacy Computing" U+1FB00-U+1FBFF for glyphs with no older codepoint), and the
 * three PETSCII/ASCII divergences (0x5C/0x5E/0x5F) render as £/↑/← instead of the escaped
 * layer's ASCII transliteration. See {@code machines/generated/petscii.yaml}'s {@code unicode:}
 * section header for the full policy/provenance writeup. Entirely independent of
 * {@code toDisplayEscaped} -- neither layer influences the other's output.
 * <p>
 * Screen codes (what is POKEd into screen RAM -- a different numbering from PETSCII) are
 * explicitly out of scope; every byte this class accepts is a PETSCII code (memory / keyboard
 * value).
 */
public final class PetsciiMapper {

	/**
	 * The two PETSCII character-set halves; identical for every byte except $41-$5A (see
	 * petscii.yaml's {@code letter_range}), where {@link #UNSHIFTED_GRAPHICS} shows
	 * uppercase letters (with lowercase-ish graphics living at $61-$7A, hex-escaped in v1 --
	 * see docs/petscii.md) and {@link #SHIFTED_LOWERCASE} shows lowercase letters (with
	 * uppercase letters at $61-$7A, also hex-escaped in v1).
	 */
	public enum Variant {
		UNSHIFTED_GRAPHICS,
		SHIFTED_LOWERCASE
	}

	private static volatile PetsciiMapper instance;

	private final String[] unshiftedGraphics;
	private final String[] shiftedLowercase;

	/** Unicode-layer decode tables (schema 2); {@code null} if the loaded map predates the
	 *  unicode layer (schema 1) -- {@link #toDisplayUnicode} then throws rather than silently
	 *  returning garbage. */
	private final int[] unshiftedGraphicsUnicode;
	private final int[] shiftedLowercaseUnicode;

	/** Unicode-layer encode maps (codepoint -&gt; canonical byte), same nullability as the
	 *  decode tables above. */
	private final Map<Integer, Integer> unshiftedGraphicsEncode;
	private final Map<Integer, Integer> shiftedLowercaseEncode;

	private PetsciiMapper(JsonObject mapJson) {
		JsonObject variants = mapJson.getAsJsonObject("variants");
		this.unshiftedGraphics = toTable(variants.getAsJsonArray("unshifted_graphics"));
		this.shiftedLowercase = toTable(variants.getAsJsonArray("shifted_lowercase"));

		JsonObject unicodeVariants = mapJson.getAsJsonObject("unicode_variants");
		JsonObject encode = mapJson.getAsJsonObject("encode");
		if (unicodeVariants != null && encode != null) {
			this.unshiftedGraphicsUnicode = toUnicodeTable(
				unicodeVariants.getAsJsonArray("unshifted_graphics"));
			this.shiftedLowercaseUnicode = toUnicodeTable(
				unicodeVariants.getAsJsonArray("shifted_lowercase"));
			this.unshiftedGraphicsEncode = toEncodeMap(encode.getAsJsonObject("unshifted_graphics"));
			this.shiftedLowercaseEncode = toEncodeMap(encode.getAsJsonObject("shifted_lowercase"));
		}
		else {
			this.unshiftedGraphicsUnicode = null;
			this.shiftedLowercaseUnicode = null;
			this.unshiftedGraphicsEncode = null;
			this.shiftedLowercaseEncode = null;
		}
	}

	private static String[] toTable(JsonArray array) {
		if (array.size() != 256) {
			throw new IllegalArgumentException(
				"petscii.map variant table has " + array.size() + " entries, expected 256");
		}
		String[] table = new String[256];
		for (int i = 0; i < 256; i++) {
			String s = array.get(i).getAsString();
			if (s == null || s.isEmpty()) {
				throw new IllegalArgumentException(
					"petscii.map byte 0x" + Integer.toHexString(i) + " is empty");
			}
			table[i] = s;
		}
		return table;
	}

	private static int[] toUnicodeTable(JsonArray array) {
		if (array.size() != 256) {
			throw new IllegalArgumentException(
				"petscii.map unicode_variants table has " + array.size() +
					" entries, expected 256");
		}
		int[] table = new int[256];
		for (int i = 0; i < 256; i++) {
			table[i] = array.get(i).getAsInt();
		}
		return table;
	}

	/** Parses an {@code encode} object (decimal-codepoint-string keys, see
	 *  {@code gdtbuilder.PetsciiCompiler}'s output comment for why decimal) into a codepoint
	 *  -&gt; canonical-byte map. */
	private static Map<Integer, Integer> toEncodeMap(JsonObject encodeObj) {
		Map<Integer, Integer> map = new HashMap<>();
		for (Map.Entry<String, JsonElement> e : encodeObj.entrySet()) {
			map.put(Integer.parseInt(e.getKey()), e.getValue().getAsInt());
		}
		return map;
	}

	/**
	 * Loads (and caches) the bundled {@code petscii.map} through Ghidra's data-file
	 * resolution ({@link DescriptorSupport#loadMap}, the same helper every machine
	 * descriptor loader uses -- already generic over any bundled JSON path, so no new
	 * shared helper was needed for this bead). Requires a running Ghidra application
	 * ({@code Application.findDataFileInAnyModule}); tools that run outside a Ghidra
	 * runtime (e.g. {@code tools/petscii/PetsciiMapperVerify.java}) use
	 * {@link #loadFromMapFile(File)} instead.
	 */
	public static PetsciiMapper load() throws IOException {
		PetsciiMapper result = instance;
		if (result == null) {
			synchronized (PetsciiMapper.class) {
				result = instance;
				if (result == null) {
					result = new PetsciiMapper(DescriptorResources.loadMap("petscii.map"));
					instance = result;
				}
			}
		}
		return result;
	}

	/**
	 * Loads a {@code petscii.map} file directly, bypassing Ghidra's
	 * {@code Application.findDataFileInAnyModule} resolution entirely. This is the seam
	 * {@code tools/petscii/PetsciiMapperVerify.java} uses to exhaustively check this class
	 * without a Ghidra runtime available: that verifier lives in its own Gradle source set
	 * (mirroring {@code tools/bitalgebra/BitAlgebraEquivalence.java}) and calls this method
	 * on the freshly-built {@code data/petscii.map}, never {@link #load()}.
	 */
	public static PetsciiMapper loadFromMapFile(File mapFile) throws IOException {
		try (InputStream in = new FileInputStream(mapFile)) {
			return loadFromStream(in);
		}
	}

	/** Parses a {@code petscii.map} document from an already-open stream (UTF-8). This is the
	 *  seam {@link #loadFromMapFile(File)} delegates to; also usable directly by callers that
	 *  already have the map as a classpath resource or other {@link InputStream} rather than
	 *  a {@link File} (e.g. a future charset SPI provider -- see grm-1.4 Phase C). Closes
	 *  {@code in} (via the wrapping reader) before returning. */
	public static PetsciiMapper loadFromStream(InputStream in) throws IOException {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			return new PetsciiMapper(JsonParser.parseReader(reader).getAsJsonObject());
		}
	}

	/** The display string for one PETSCII byte in the given variant (e.g. {@code "{clr}"},
	 *  {@code "{$a3}"}, {@code "A"}). {@code byteValue} is masked to 8 bits. */
	public String toDisplayEscaped(int byteValue, Variant variant) {
		String[] table = variant == Variant.SHIFTED_LOWERCASE ? shiftedLowercase : unshiftedGraphics;
		return table[byteValue & 0xFF];
	}

	/** The concatenated display string for a run of PETSCII bytes in the given variant. */
	public String toDisplayEscaped(byte[] bytes, Variant variant) {
		StringBuilder sb = new StringBuilder(bytes.length);
		for (byte b : bytes) {
			sb.append(toDisplayEscaped(b, variant));
		}
		return sb.toString();
	}

	/** The Unicode display string for one PETSCII byte in the given variant -- the codepoint
	 *  as a {@link String} (a surrogate pair if the codepoint is above the Basic Multilingual
	 *  Plane, via {@link Character#toChars(int)}; see class javadoc for the full policy).
	 *  {@code byteValue} is masked to 8 bits.
	 *
	 * @throws IllegalStateException if the loaded {@code petscii.map} predates the unicode
	 *     layer (schema 1, no {@code unicode_variants}/{@code encode} keys)
	 */
	public String toDisplayUnicode(int byteValue, Variant variant) {
		int[] table = variant == Variant.SHIFTED_LOWERCASE ? shiftedLowercaseUnicode : unshiftedGraphicsUnicode;
		if (table == null) {
			throw new IllegalStateException(
				"toDisplayUnicode requires a schema-2 petscii.map (unicode layer) -- " +
					"the loaded map has no 'unicode_variants' section");
		}
		return new String(Character.toChars(table[byteValue & 0xFF]));
	}

	/** The concatenated Unicode display string for a run of PETSCII bytes in the given
	 *  variant. */
	public String toDisplayUnicode(byte[] bytes, Variant variant) {
		StringBuilder sb = new StringBuilder(bytes.length);
		for (byte b : bytes) {
			sb.append(toDisplayUnicode(b, variant));
		}
		return sb.toString();
	}

	/** The Unicode codepoint -&gt; canonical-byte encode lookup for the given variant, or
	 *  {@code null} if {@code codepoint} is not produced by any byte in this variant.
	 *  "Canonical" means the LOWEST byte value that decodes to that codepoint (see
	 *  {@code gdtbuilder.PetsciiCompiler#buildEncodeMap}). Primarily for
	 *  {@code tools/petscii/PetsciiMapperVerify.java}'s round-trip checks and the future
	 *  charset SPI encoder (grm-1.4 Phase C), not commonly needed by ordinary callers. */
	public Integer encodeUnicode(int codepoint, Variant variant) {
		Map<Integer, Integer> encode =
			variant == Variant.SHIFTED_LOWERCASE ? shiftedLowercaseEncode : unshiftedGraphicsEncode;
		if (encode == null) {
			throw new IllegalStateException(
				"encodeUnicode requires a schema-2 petscii.map (unicode layer) -- " +
					"the loaded map has no 'encode' section");
		}
		return encode.get(codepoint);
	}
}
