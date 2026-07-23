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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import retromachines.PetsciiMapper.Variant;

/**
 * JUnit migration of {@code tools/charset/CharsetProviderVerify.java} (bead grm-32f.4): proves
 * {@code retromachines.charset.RetroCharsetProvider} is discovered via the real
 * {@link java.util.ServiceLoader} SPI path and that its charsets agree with
 * {@link PetsciiMapper} (bead grm-1.4 Phase C/F).
 * <p>
 * NOTE: whether {@link Charset#forName} discovers {@code RetroCharsetProvider} via
 * {@code ServiceLoader} when this test runs inside a Gradle {@code Test}-worker fork (as
 * opposed to the original standalone {@code JavaExec} task, whose classpath directly becomes
 * the forked JVM's system classpath) is being verified by the orchestrator running the actual
 * build; this test is written to faithfully preserve the original's checks regardless.
 */
public class RetroCharsetProviderTest {

	private static final String PETSCII_RESOURCE = "/retromachines/charset/petscii.map";

	private PetsciiMapper mapper;

	@Before
	public void setUp() throws Exception {
		try (InputStream in = getClass().getResourceAsStream(PETSCII_RESOURCE)) {
			assertNotNull("classpath resource " + PETSCII_RESOURCE + " not found -- is " +
				"stageCharsetResources/processResources wired into this task's classpath?", in);
			mapper = PetsciiMapper.loadFromStream(in);
		}
	}

	/** Resolves {@code canonicalName} and every alias in {@code namesToTry} (already
	 *  case-varied by the caller as desired) via {@link Charset#forName(String)}, asserting
	 *  they all resolve to the SAME {@link Charset} instance (Charset.forName caches/returns
	 *  a shared instance per name it resolves to -- same underlying charset either way). */
	private static void checkNamesResolve(String canonicalName, String... namesToTry) {
		Charset canonical = Charset.forName(canonicalName);
		assertTrue("Charset.forName(\"" + canonicalName + "\") returned charset named \"" +
			canonical.name() + "\"", canonical.name().equalsIgnoreCase(canonicalName));
		for (String alias : namesToTry) {
			Charset resolved = Charset.forName(alias);
			assertTrue("Charset.forName(\"" + alias + "\") did not resolve to " +
				canonicalName + " (got \"" + resolved.name() + "\")", resolved.equals(canonical));
		}
	}

	private static void checkVariant(Charset cs, PetsciiMapper mapper, Variant variant)
			throws CharacterCodingException {
		for (int b = 0; b < 256; b++) {
			byte[] bytes = { (byte) b };

			// Decode agreement with PetsciiMapper.toDisplayUnicode.
			String decoded = new String(bytes, cs);
			String expected = mapper.toDisplayUnicode(b, variant);
			if (!decoded.equals(expected)) {
				fail(String.format(
					"charset %s byte 0x%02x: decoded '%s' (U+%s) != PetsciiMapper '%s'",
					cs.name(), b, decoded, Integer.toHexString(decoded.codePointAt(0)), expected));
			}

			// Encoder canonical round-trip: encode(decode(b)) == canonical(b), where
			// canonical(b) is PetsciiMapper.encodeUnicode's answer for the decoded
			// codepoint (the lowest byte that decodes to it -- may differ from b itself
			// for mirror-range bytes; that's the point of using encodeUnicode as the
			// reference rather than asserting round-trip-to-self).
			int codepoint = decoded.codePointAt(0);
			Integer canonicalByte = mapper.encodeUnicode(codepoint, variant);
			if (canonicalByte == null) {
				fail(String.format(
					"charset %s byte 0x%02x: PetsciiMapper.encodeUnicode(U+%04X) returned null " +
						"for a codepoint this charset itself just decoded",
					cs.name(), b, codepoint));
			}
			ByteBuffer encoded = cs.newEncoder().encode(CharBuffer.wrap(decoded));
			if (encoded.remaining() != 1) {
				fail(String.format(
					"charset %s byte 0x%02x: encoding decoded string produced %d bytes, expected 1",
					cs.name(), b, encoded.remaining()));
			}
			int encodedByte = encoded.get() & 0xFF;
			if (encodedByte != canonicalByte) {
				fail(String.format(
					"charset %s byte 0x%02x: encode(decode(byte))=0x%02x, expected canonical 0x%02x",
					cs.name(), b, encodedByte, canonicalByte));
			}
		}
	}

	private static void checkUnmappable(Charset cs) {
		CharsetEncoder encoder = cs.newEncoder()
			.onMalformedInput(CodingErrorAction.REPORT)
			.onUnmappableCharacter(CodingErrorAction.REPORT);
		try {
			encoder.encode(CharBuffer.wrap("€")); // EUR SIGN -- not a PETSCII codepoint.
			fail("charset " + cs.name() + ": encoding U+20AC did not throw (expected unmappable)");
		}
		catch (CharacterCodingException expected) {
			// expected: the encoder's unmappable path was exercised.
		}
	}

	// -----------------------------------------------------------------------------------
	// Screen-code reference permutation (bead grm-1.4.5), independently re-derived here from
	// machines/generated/screencode.yaml's header rather than trusted from the built table --
	// same "catch a transcription/logic error in EITHER copy" spirit as
	// PetsciiMapperTest's reference tables.
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
	private static void checkScreencodeVariant(Charset cs, PetsciiMapper mapper, Variant variant)
			throws CharacterCodingException {
		for (int b = 0; b < 256; b++) {
			byte[] bytes = { (byte) b };

			String decoded = new String(bytes, cs);
			int expected = expectedScreencodeCodepoint(b, mapper, variant);
			int decodedCp = decoded.codePointAt(0);
			if (decodedCp != expected) {
				fail(String.format(
					"charset %s byte 0x%02x: decoded U+%04X != expected screen-code " +
						"permutation U+%04X", cs.name(), b, decodedCp, expected));
			}

			int canonicalByte = lowestScreenByteForCodepoint(expected, mapper, variant);
			ByteBuffer encoded = cs.newEncoder().encode(CharBuffer.wrap(decoded));
			if (encoded.remaining() != 1) {
				fail(String.format(
					"charset %s byte 0x%02x: encoding decoded string produced %d bytes, expected 1",
					cs.name(), b, encoded.remaining()));
			}
			int encodedByte = encoded.get() & 0xFF;
			if (encodedByte != canonicalByte) {
				fail(String.format(
					"charset %s byte 0x%02x: encode(decode(byte))=0x%02x, expected canonical 0x%02x",
					cs.name(), b, encodedByte, canonicalByte));
			}
		}
	}

	/** Canonical names + aliases resolve via Charset.forName (case-insensitive), and both
	 *  petscii/screencode charsets are enumerated by Charset.availableCharsets(). */
	@Test
	public void petsciiNamesResolveAndEnumerated() {
		checkNamesResolve("x-petscii-unshifted", "petscii", "x-petscii", "X-PETSCII-Unshifted");
		checkNamesResolve("x-petscii-shifted", "petscii-shifted", "PETSCII-SHIFTED");

		Charset unshifted = Charset.forName("x-petscii-unshifted");
		Charset shifted = Charset.forName("x-petscii-shifted");

		Map<String, Charset> available = Charset.availableCharsets();
		assertTrue("x-petscii-unshifted missing from Charset.availableCharsets()",
			available.containsKey(unshifted.name()));
		assertTrue("x-petscii-shifted missing from Charset.availableCharsets()",
			available.containsKey(shifted.name()));
	}

	/** Decode agreement with PetsciiMapper.toDisplayUnicode, and encoder canonical round-trip
	 *  (encode(decode(b)) == canonical(b)) for every byte, both variants. */
	@Test
	public void petsciiDecodeAndEncodeRoundTrip() throws CharacterCodingException {
		Charset unshifted = Charset.forName("x-petscii-unshifted");
		Charset shifted = Charset.forName("x-petscii-shifted");
		checkVariant(unshifted, mapper, Variant.UNSHIFTED_GRAPHICS);
		checkVariant(shifted, mapper, Variant.SHIFTED_LOWERCASE);
	}

	/** Unmappable input triggers the encoder's unmappable path. */
	@Test
	public void petsciiUnmappable() {
		Charset unshifted = Charset.forName("x-petscii-unshifted");
		Charset shifted = Charset.forName("x-petscii-shifted");
		checkUnmappable(unshifted);
		checkUnmappable(shifted);
	}

	/** Screen-code charsets (bead grm-1.4.5): names resolve, and both are enumerated by
	 *  Charset.availableCharsets(). */
	@Test
	public void screencodeNamesResolveAndEnumerated() {
		checkNamesResolve("x-c64-screencode-unshifted", "c64-screencode",
			"X-C64-Screencode-Unshifted");
		checkNamesResolve("x-c64-screencode-shifted");

		Charset screenUnshifted = Charset.forName("x-c64-screencode-unshifted");
		Charset screenShifted = Charset.forName("x-c64-screencode-shifted");

		Map<String, Charset> available = Charset.availableCharsets();
		assertTrue("x-c64-screencode-unshifted missing from Charset.availableCharsets()",
			available.containsKey(screenUnshifted.name()));
		assertTrue("x-c64-screencode-shifted missing from Charset.availableCharsets()",
			available.containsKey(screenShifted.name()));
	}

	/** Decode matches the independently re-derived screen-code<->PETSCII permutation
	 *  (composed with PetsciiMapper.toDisplayUnicode), and canonical encode round-trip. */
	@Test
	public void screencodeDecodeAndEncodeRoundTrip() throws CharacterCodingException {
		Charset screenUnshifted = Charset.forName("x-c64-screencode-unshifted");
		Charset screenShifted = Charset.forName("x-c64-screencode-shifted");
		checkScreencodeVariant(screenUnshifted, mapper, Variant.UNSHIFTED_GRAPHICS);
		checkScreencodeVariant(screenShifted, mapper, Variant.SHIFTED_LOWERCASE);
	}

	/** Unmappable input triggers the encoder's unmappable path, for both screen-code
	 *  variants. */
	@Test
	public void screencodeUnmappable() {
		Charset screenUnshifted = Charset.forName("x-c64-screencode-unshifted");
		Charset screenShifted = Charset.forName("x-c64-screencode-shifted");
		checkUnmappable(screenUnshifted);
		checkUnmappable(screenShifted);
	}
}
