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
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;

import com.google.gson.JsonArray;
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
 * <b>v1 scope:</b> output is ASCII-only bracket escapes (e.g. {@code "{clr}"},
 * {@code "{$a3}"}) -- no Unicode glyphs. A future {@code toDisplayUnicode()} that renders
 * control codes and graphics characters as real Unicode glyphs (PETSCII box-drawing lives in
 * the "Symbols for Legacy Computing" block) is anticipated but not implemented here.
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

	private PetsciiMapper(JsonObject mapJson) {
		JsonObject variants = mapJson.getAsJsonObject("variants");
		this.unshiftedGraphics = toTable(variants.getAsJsonArray("unshifted_graphics"));
		this.shiftedLowercase = toTable(variants.getAsJsonArray("shifted_lowercase"));
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
					result = new PetsciiMapper(DescriptorSupport.loadMap("petscii.map"));
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
		try (Reader reader = new FileReader(mapFile)) {
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
}
