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
// Proves retromachines.charset.RetroCharsetProvider is discovered via the REAL
// java.util.ServiceLoader SPI path (bead grm-1.4 Phase C/F), in a plain JVM with no Ghidra
// runtime at all -- structured after tools/petscii/PetsciiMapperVerify.java: same PASS-line
// convention, same "exercise the real production class" philosophy.
//
// Run via `gradle verifyCharsets`. That task's classpath (see build.gradle) is exactly what
// makes this meaningful: a JavaExec classpath IS the forked JVM's system classpath, so
// Charset.forName("x-petscii-unshifted") below resolves through the SAME
// META-INF/services/java.nio.charset.spi.CharsetProvider + ServiceLoader mechanism Ghidra
// itself relies on at launch (GhidraClassLoader as the JVM system loader) -- not a shortcut
// that calls RetroCharsetProvider's methods directly.
//
// Exits non-zero (throws) on the first mismatch; prints "CHARSETS PASS (<n> cases)" when
// every case agrees.

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;

import retromachines.PetsciiMapper;
import retromachines.PetsciiMapper.Variant;

public final class CharsetProviderVerify {

	private CharsetProviderVerify() {
	}

	private static final String PETSCII_RESOURCE = "/retromachines/charset/petscii.map";

	public static void main(String[] args) throws Exception {
		long cases = 0;

		PetsciiMapper mapper = loadReferenceMapper();

		// -----------------------------------------------------------------------------
		// 1. Canonical names + aliases resolve via Charset.forName (case-insensitive),
		// and both petscii charsets are enumerated by Charset.availableCharsets().
		// -----------------------------------------------------------------------------
		cases += checkNamesResolve("x-petscii-unshifted", "petscii", "x-petscii", "X-PETSCII-Unshifted");
		cases += checkNamesResolve("x-petscii-shifted", "petscii-shifted", "PETSCII-SHIFTED");

		Charset unshifted = Charset.forName("x-petscii-unshifted");
		Charset shifted = Charset.forName("x-petscii-shifted");

		java.util.Map<String, Charset> available = Charset.availableCharsets();
		if (!available.containsKey(unshifted.name())) {
			throw new AssertionError(
				"x-petscii-unshifted missing from Charset.availableCharsets()");
		}
		if (!available.containsKey(shifted.name())) {
			throw new AssertionError("x-petscii-shifted missing from Charset.availableCharsets()");
		}
		cases += 2;

		// -----------------------------------------------------------------------------
		// 2 + 3. Decode agreement with PetsciiMapper.toDisplayUnicode, and encoder
		// canonical round-trip (encode(decode(b)) == canonical(b)) for every byte, both
		// variants.
		// -----------------------------------------------------------------------------
		cases += checkVariant(unshifted, mapper, Variant.UNSHIFTED_GRAPHICS);
		cases += checkVariant(shifted, mapper, Variant.SHIFTED_LOWERCASE);

		// -----------------------------------------------------------------------------
		// 4. Unmappable input triggers the encoder's unmappable path.
		// -----------------------------------------------------------------------------
		cases += checkUnmappable(unshifted);
		cases += checkUnmappable(shifted);

		// -----------------------------------------------------------------------------
		// 5. Screen-code charsets (bead grm-1.4.5): full check, same shape as the PETSCII
		// checks above -- names resolve, decode matches the independently re-derived
		// screen-code<->PETSCII permutation (composed with PetsciiMapper.toDisplayUnicode),
		// canonical encode round-trip, and the unmappable encoder path.
		// -----------------------------------------------------------------------------
		cases += checkNamesResolve("x-c64-screencode-unshifted", "c64-screencode",
			"X-C64-Screencode-Unshifted");
		cases += checkNamesResolve("x-c64-screencode-shifted");

		Charset screenUnshifted = Charset.forName("x-c64-screencode-unshifted");
		Charset screenShifted = Charset.forName("x-c64-screencode-shifted");

		if (!available.containsKey(screenUnshifted.name())) {
			throw new AssertionError(
				"x-c64-screencode-unshifted missing from Charset.availableCharsets()");
		}
		if (!available.containsKey(screenShifted.name())) {
			throw new AssertionError(
				"x-c64-screencode-shifted missing from Charset.availableCharsets()");
		}
		cases += 2;

		cases += checkScreencodeVariant(screenUnshifted, mapper, Variant.UNSHIFTED_GRAPHICS);
		cases += checkScreencodeVariant(screenShifted, mapper, Variant.SHIFTED_LOWERCASE);

		cases += checkUnmappable(screenUnshifted);
		cases += checkUnmappable(screenShifted);

		System.out.println("CHARSETS PASS (" + cases + " cases)");
	}

	private static PetsciiMapper loadReferenceMapper() throws IOException {
		try (InputStream in = CharsetProviderVerify.class.getResourceAsStream(PETSCII_RESOURCE)) {
			if (in == null) {
				throw new AssertionError(
					"classpath resource " + PETSCII_RESOURCE + " not found -- is " +
						"stageCharsetResources/processResources wired into this task's classpath?");
			}
			return PetsciiMapper.loadFromStream(in);
		}
	}

	/** Resolves {@code canonicalName} and every alias in {@code namesToTry} (already
	 *  case-varied by the caller as desired) via {@link Charset#forName(String)}, asserting
	 *  they all resolve to the SAME {@link Charset} instance (Charset.forName caches/returns
	 *  a shared instance per name it resolves to -- same underlying charset either way). */
	private static long checkNamesResolve(String canonicalName, String... namesToTry) {
		long cases = 0;
		Charset canonical = Charset.forName(canonicalName);
		if (!canonical.name().equalsIgnoreCase(canonicalName)) {
			throw new AssertionError("Charset.forName(\"" + canonicalName + "\") returned charset named \"" +
				canonical.name() + "\"");
		}
		cases++;
		for (String alias : namesToTry) {
			Charset resolved = Charset.forName(alias);
			if (!resolved.equals(canonical)) {
				throw new AssertionError("Charset.forName(\"" + alias + "\") did not resolve to " +
					canonicalName + " (got \"" + resolved.name() + "\")");
			}
			cases++;
		}
		return cases;
	}

	private static long checkVariant(Charset cs, PetsciiMapper mapper, Variant variant)
			throws CharacterCodingException {
		long cases = 0;
		for (int b = 0; b < 256; b++) {
			byte[] bytes = { (byte) b };

			// 2. Decode agreement with PetsciiMapper.toDisplayUnicode.
			String decoded = new String(bytes, cs);
			String expected = mapper.toDisplayUnicode(b, variant);
			if (!decoded.equals(expected)) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: decoded '%s' (U+%s) != PetsciiMapper '%s'",
					cs.name(), b, decoded, Integer.toHexString(decoded.codePointAt(0)), expected));
			}
			cases++;

			// 3. Encoder canonical round-trip: encode(decode(b)) == canonical(b), where
			// canonical(b) is PetsciiMapper.encodeUnicode's answer for the decoded
			// codepoint (the lowest byte that decodes to it -- may differ from b itself
			// for mirror-range bytes; that's the point of using encodeUnicode as the
			// reference rather than asserting round-trip-to-self).
			int codepoint = decoded.codePointAt(0);
			Integer canonicalByte = mapper.encodeUnicode(codepoint, variant);
			if (canonicalByte == null) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: PetsciiMapper.encodeUnicode(U+%04X) returned null " +
						"for a codepoint this charset itself just decoded",
					cs.name(), b, codepoint));
			}
			ByteBuffer encoded = cs.newEncoder().encode(CharBuffer.wrap(decoded));
			if (encoded.remaining() != 1) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: encoding decoded string produced %d bytes, expected 1",
					cs.name(), b, encoded.remaining()));
			}
			int encodedByte = encoded.get() & 0xFF;
			if (encodedByte != canonicalByte) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: encode(decode(byte))=0x%02x, expected canonical 0x%02x",
					cs.name(), b, encodedByte, canonicalByte));
			}
			cases++;
		}
		return cases;
	}

	private static long checkUnmappable(Charset cs) {
		CharsetEncoder encoder = cs.newEncoder()
			.onMalformedInput(CodingErrorAction.REPORT)
			.onUnmappableCharacter(CodingErrorAction.REPORT);
		try {
			encoder.encode(CharBuffer.wrap("€")); // EUR SIGN -- not a PETSCII codepoint.
			throw new AssertionError(
				"charset " + cs.name() + ": encoding U+20AC did not throw (expected unmappable)");
		}
		catch (CharacterCodingException expected) {
			// expected: the encoder's unmappable path was exercised.
		}
		return 1;
	}

	// -----------------------------------------------------------------------------------
	// Screen-code reference permutation (bead grm-1.4.5), independently re-derived here from
	// machines/generated/screencode.yaml's header rather than trusted from the built table --
	// same "catch a transcription/logic error in EITHER copy" spirit as
	// tools/petscii/PetsciiMapperVerify.java's reference tables.
	//
	//   screen 0x00-0x1F <- petscii 0x40-0x5F
	//   screen 0x20-0x3F <- petscii 0x20-0x3F (identity)
	//   screen 0x40-0x5F <- petscii 0x60-0x7F
	//   screen 0x60-0x7F <- petscii 0xA0-0xBF
	//   screen 0x80-0xFF: same glyph as screen (b & 0x7F) (reverse video, lossy on decode)
	// -----------------------------------------------------------------------------------

	/** The PETSCII byte whose glyph screen code {@code b} (0x00-0x7F only) shares, per
	 *  screencode.yaml's range_rules. */
	private static int screenToPetsciiByte(int b) {
		if (b >= 0x00 && b <= 0x1F) {
			return 0x40 + b;
		}
		if (b >= 0x20 && b <= 0x3F) {
			return b;
		}
		if (b >= 0x40 && b <= 0x5F) {
			return 0x60 + (b - 0x40);
		}
		if (b >= 0x60 && b <= 0x7F) {
			return 0xA0 + (b - 0x60);
		}
		throw new AssertionError(String.format("screen byte 0x%02x not in the 0x00-0x7F " +
			"primary-range domain", b));
	}

	/** The expected Unicode codepoint for screen code {@code b} in the given variant: resolved
	 *  through the permutation above onto the SAME {@code PetsciiMapper.toDisplayUnicode}
	 *  reference the PETSCII checks above use, folding 0x80-0xFF onto {@code b & 0x7F} first
	 *  (reverse video -- see screencode.yaml's header). */
	private static int expectedScreencodeCodepoint(int b, PetsciiMapper mapper, Variant variant) {
		int low = b & 0x7F;
		int petsciiByte = screenToPetsciiByte(low);
		return mapper.toDisplayUnicode(petsciiByte, variant).codePointAt(0);
	}

	/** The lowest screen-code byte (0-255) whose expected codepoint equals {@code codepoint} in
	 *  the given variant -- derived by brute-force scan of the reference permutation above
	 *  (never assumed to be exactly {@code b & 0x7F}, per this bead's task instructions), used
	 *  as the reference "canonical(b)" for the encode round-trip check below. */
	private static int lowestScreenByteForCodepoint(int codepoint, PetsciiMapper mapper,
			Variant variant) {
		for (int b = 0; b < 256; b++) {
			if (expectedScreencodeCodepoint(b, mapper, variant) == codepoint) {
				return b;
			}
		}
		throw new AssertionError(String.format(
			"no screen byte decodes to U+%04X in variant %s", codepoint, variant));
	}

	/** Full screen-code charset check, mirroring {@link #checkVariant}: decode agreement with
	 *  the independently re-derived reference permutation, and canonical encode round-trip
	 *  (encode(decode(b)) == canonical(b), canonical derived from the table itself via
	 *  {@link #lowestScreenByteForCodepoint}, not assumed to be {@code b & 0x7F}). */
	private static long checkScreencodeVariant(Charset cs, PetsciiMapper mapper, Variant variant)
			throws CharacterCodingException {
		long cases = 0;
		for (int b = 0; b < 256; b++) {
			byte[] bytes = { (byte) b };

			String decoded = new String(bytes, cs);
			int expected = expectedScreencodeCodepoint(b, mapper, variant);
			int decodedCp = decoded.codePointAt(0);
			if (decodedCp != expected) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: decoded U+%04X != expected screen-code " +
						"permutation U+%04X", cs.name(), b, decodedCp, expected));
			}
			cases++;

			int canonicalByte = lowestScreenByteForCodepoint(expected, mapper, variant);
			ByteBuffer encoded = cs.newEncoder().encode(CharBuffer.wrap(decoded));
			if (encoded.remaining() != 1) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: encoding decoded string produced %d bytes, expected 1",
					cs.name(), b, encoded.remaining()));
			}
			int encodedByte = encoded.get() & 0xFF;
			if (encodedByte != canonicalByte) {
				throw new AssertionError(String.format(
					"charset %s byte 0x%02x: encode(decode(byte))=0x%02x, expected canonical 0x%02x",
					cs.name(), b, encodedByte, canonicalByte));
			}
			cases++;
		}
		return cases;
	}
}
