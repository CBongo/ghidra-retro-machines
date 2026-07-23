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
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;

import retromachines.PetsciiMapper.Variant;

/**
 * JUnit migration of {@code tools/petscii/PetsciiMapperVerify.java} (bead grm-32f.4):
 * exhaustive check that {@link PetsciiMapper} resolves every byte correctly against the
 * compiled {@code petscii.map} (bead grm-1.4.1; unicode-layer checks added grm-1.4.2).
 * <p>
 * The mapper is loaded once in {@link #setUp()} from the classpath resource
 * {@code /retromachines/charset/petscii.map} that the build stages, rather than from a CLI
 * argument pointing at {@code data/petscii.map} directly.
 */
public class PetsciiMapperTest {

	// Verbatim VICE petcat ctrl1[]/ctrl2[] short-name tables (see
	// machines/generated/petscii.yaml's header for full provenance/verification details).
	// Transcribed here independently of petscii.yaml so this check catches a transcription
	// error in EITHER copy, not just internal self-consistency of one file. index 0 is byte
	// 0x00 (ctrl1) / 0x80 (ctrl2); "\n" marks the two petcat entries that are literal-newline
	// placeholders rather than bracket-escape names (0x0A, 0x0D) -- handled specially below.
	private static final String[] CTRL1 = {
		"", "CTRL-A", "CTRL-B", "stop", "CTRL-D", "wht", "CTRL-F", "CTRL-G",
		"dish", "ensh", "\n", "CTRL-K", "CTRL-L", "\n", "swlc", "CTRL-O",
		"CTRL-P", "down", "rvon", "home", "del", "CTRL-U", "CTRL-V", "CTRL-W",
		"CTRL-X", "CTRL-Y", "CTRL-Z", "esc", "red", "rght", "grn", "blu"
	};

	private static final String[] CTRL2 = {
		"", "orng", "", "", "", "f1", "f3", "f5",
		"f7", "f2", "f4", "f6", "f8", "sret", "swuc", "",
		"blk", "up", "rvof", "clr", "inst", "brn", "lred", "gry1",
		"gry2", "lgrn", "lblu", "gry3", "pur", "left", "yel", "cyn"
	};

	private static final Pattern HEX_ESCAPE = Pattern.compile("^\\{\\$[0-9a-f]{2}\\}$");

	// -------------------------------------------------------------------------------------
	// Unicode-layer reference data (bead grm-1.4.2), transcribed independently from
	// machines/generated/petscii.yaml's `unicode:` section (see that file's header for full
	// provenance) so this check can catch a transcription/logic error in EITHER copy, not
	// just internal self-consistency of the compiled map.
	// -------------------------------------------------------------------------------------

	private static final int UNICODE_FALLBACK = 0xFFFD;

	// unshifted_graphics true-glyph codepoints for the 0x61-0x7A "graphics_letter_range";
	// bytes absent here have no assigned Unicode codepoint (fall back to UNICODE_FALLBACK).
	private static final Map<Integer, Integer> UNSHIFTED_LETTER_RANGE_GRAPHICS = Map.ofEntries(
		Map.entry(0x61, 0x2660), Map.entry(0x62, 0x2502), Map.entry(0x63, 0x2500),
		Map.entry(0x69, 0x256E), Map.entry(0x6A, 0x2570), Map.entry(0x6B, 0x256F),
		Map.entry(0x6D, 0x2572), Map.entry(0x6E, 0x2571), Map.entry(0x71, 0x25CF),
		Map.entry(0x73, 0x2665), Map.entry(0x75, 0x256D), Map.entry(0x76, 0x2573),
		Map.entry(0x77, 0x25CB), Map.entry(0x78, 0x2663), Map.entry(0x7A, 0x2666));

	// Graphics codepoints shared by both variants (0x60, 0x7B-0x7F, 0xA0-0xBF); bytes absent
	// here fall back to UNICODE_FALLBACK.
	private static final Map<Integer, Integer> GRAPHICS_CODEPOINTS = Map.ofEntries(
		Map.entry(0x60, 0x2500), Map.entry(0x7B, 0x253C), Map.entry(0x7C, 0x1FB8C),
		Map.entry(0x7D, 0x2502), Map.entry(0x7E, 0x03C0), Map.entry(0x7F, 0x25E5),
		Map.entry(0xA0, 0x00A0), Map.entry(0xA1, 0x258C), Map.entry(0xA2, 0x2584),
		Map.entry(0xA3, 0x2594), Map.entry(0xA4, 0x2581), Map.entry(0xA5, 0x258F),
		Map.entry(0xA6, 0x2592), Map.entry(0xA7, 0x2595), Map.entry(0xA8, 0x1FB8F),
		Map.entry(0xA9, 0x25E4), Map.entry(0xAA, 0x1FB87), Map.entry(0xAB, 0x251C),
		Map.entry(0xAC, 0x2597), Map.entry(0xAD, 0x2514), Map.entry(0xAE, 0x2510),
		Map.entry(0xAF, 0x2582), Map.entry(0xB0, 0x250C), Map.entry(0xB1, 0x2534),
		Map.entry(0xB2, 0x252C), Map.entry(0xB3, 0x2524), Map.entry(0xB4, 0x258E),
		Map.entry(0xB5, 0x258D), Map.entry(0xB6, 0x1FB88), Map.entry(0xB7, 0x1FB82),
		Map.entry(0xB8, 0x1FB83), Map.entry(0xB9, 0x2583), Map.entry(0xBB, 0x2596),
		Map.entry(0xBC, 0x259D), Map.entry(0xBD, 0x2518), Map.entry(0xBE, 0x2598),
		Map.entry(0xBF, 0x259A));
	// 0xBA absent above -> unshifted falls back to UNICODE_FALLBACK (see yaml DISCREPANCIES #1).

	// shifted_lowercase-only reassignments on top of GRAPHICS_CODEPOINTS; a null value means
	// "no assigned codepoint in shifted mode" (falls back to UNICODE_FALLBACK).
	private static final Map<Integer, Integer> SHIFTED_OVERRIDES = new java.util.HashMap<>();
	static {
		SHIFTED_OVERRIDES.put(0x7E, 0x2592);
		SHIFTED_OVERRIDES.put(0x7F, null);
		SHIFTED_OVERRIDES.put(0xA7, null);
		SHIFTED_OVERRIDES.put(0xA9, null);
		SHIFTED_OVERRIDES.put(0xAA, 0x2595);
		SHIFTED_OVERRIDES.put(0xBA, 0x2713);
	}

	private PetsciiMapper mapper;

	@Before
	public void setUp() throws Exception {
		try (InputStream in = getClass().getResourceAsStream("/retromachines/charset/petscii.map")) {
			assertNotNull("classpath resource /retromachines/charset/petscii.map not found", in);
			mapper = PetsciiMapper.loadFromStream(in);
		}
	}

	/** Independently re-derives the expected unicode-layer codepoint for one byte/variant,
	 *  per the policy documented in petscii.yaml's {@code unicode:} section header. */
	private static int expectedUnicodeCodepoint(int b, Variant variant) {
		boolean shifted = variant == Variant.SHIFTED_LOWERCASE;

		// C0/C1 controls: pass-through.
		if ((b >= 0x00 && b <= 0x1F) || (b >= 0x80 && b <= 0x9F)) {
			return b;
		}
		// Identity range.
		if (b >= 0x20 && b <= 0x3F) {
			return b;
		}
		// Literals + ASCII divergences.
		switch (b) {
			case 0x40: return 0x0040;
			case 0x5B: return 0x005B;
			case 0x5C: return 0x00A3;
			case 0x5D: return 0x005D;
			case 0x5E: return 0x2191;
			case 0x5F: return 0x2190;
			default: break;
		}
		// Variant-divergent letter range.
		if (b >= 0x41 && b <= 0x5A) {
			return shifted ? b + 0x20 : b;
		}
		// The other variant-divergent range: graphics (unshifted) / uppercase letters (shifted).
		if (b >= 0x61 && b <= 0x7A) {
			return shifted ? b - 0x20 : UNSHIFTED_LETTER_RANGE_GRAPHICS.getOrDefault(b, UNICODE_FALLBACK);
		}
		// Shared graphics range (0x60, 0x7B-0x7F, 0xA0-0xBF), with shifted-only overrides.
		if (b == 0x60 || (b >= 0x7B && b <= 0x7F) || (b >= 0xA0 && b <= 0xBF)) {
			if (shifted && SHIFTED_OVERRIDES.containsKey(b)) {
				Integer override = SHIFTED_OVERRIDES.get(b);
				return override == null ? UNICODE_FALLBACK : override;
			}
			return GRAPHICS_CODEPOINTS.getOrDefault(b, UNICODE_FALLBACK);
		}
		// Mirror ranges.
		if (b >= 0xC0 && b <= 0xDF) {
			return expectedUnicodeCodepoint(b - 0x60, variant);
		}
		if (b >= 0xE0 && b <= 0xFE) {
			return expectedUnicodeCodepoint(b - 0x40, variant);
		}
		if (b == 0xFF) {
			return expectedUnicodeCodepoint(0x7E, variant);
		}
		throw new AssertionError("byte 0x" + Integer.toHexString(b) + " not covered by reference logic");
	}

	/** Extracts the single codepoint from a {@code toDisplayUnicode} result (handling
	 *  surrogate pairs). */
	private static int codepointOf(String s) {
		return s.codePointAt(0);
	}

	/** The lowest byte value (0-255) whose {@code toDisplayUnicode} decodes to
	 *  {@code codepoint} in the given variant -- an independent re-implementation of
	 *  {@code gdtbuilder.PetsciiCompiler#buildEncodeMap}'s canonicalization rule, used to
	 *  cross-check {@link PetsciiMapper#encodeUnicode}. */
	private int lowestByteDecodingTo(int codepoint, Variant variant) {
		for (int b = 0; b < 256; b++) {
			if (codepointOf(mapper.toDisplayUnicode(b, variant)) == codepoint) {
				return b;
			}
		}
		throw new AssertionError("no byte decodes to U+" + Integer.toHexString(codepoint));
	}

	private void assertMirrorsMatch(int mirrorByte, int canonicalByte, Variant variant) {
		int mirrorCp = codepointOf(mapper.toDisplayUnicode(mirrorByte, variant));
		int canonicalCp = codepointOf(mapper.toDisplayUnicode(canonicalByte, variant));
		if (mirrorCp != canonicalCp) {
			fail(String.format(
				"byte 0x%02x variant %s: mirror codepoint U+%04X != canonical 0x%02x's U+%04X",
				mirrorByte, variant, mirrorCp, canonicalByte, canonicalCp));
		}
	}

	/** Bytes this verifier independently expects to render as a single known ASCII
	 *  character: the $20-$3F identity range, the six ASCII-divergence/identity literals
	 *  ($40,$5B,$5C,$5D,$5E,$5F), and the variant-dependent $41-$5A letter range. */
	private static boolean isKnownPrintable(int b, Variant variant) {
		if (b >= 0x20 && b <= 0x3F) {
			return true;
		}
		if (b == 0x40 || b == 0x5B || b == 0x5C || b == 0x5D || b == 0x5E || b == 0x5F) {
			return true;
		}
		return b >= 0x41 && b <= 0x5A;
	}

	private static char expectedPrintableChar(int b, Variant variant) {
		if (b >= 0x41 && b <= 0x5A) {
			boolean upper = variant == Variant.UNSHIFTED_GRAPHICS;
			return upper ? (char) b : Character.toLowerCase((char) b);
		}
		switch (b) {
			case 0x5C:
				return '\\';
			case 0x5E:
				return '^';
			case 0x5F:
				return '_';
			default:
				return (char) b;
		}
	}

	/** Checks 1-6: per-byte, per-variant display-escaped rendering (naming, hex fallback,
	 *  printable-char sanity, and the special-cased 0x0D literal newline). */
	@Test
	public void displayEscapedEveryByteBothVariants() {
		for (Variant variant : Variant.values()) {
			for (int b = 0; b < 256; b++) {
				String s = mapper.toDisplayEscaped(b, variant);

				// 1. Every byte, every variant: non-null, non-empty.
				if (s == null || s.isEmpty()) {
					fail(String.format(
						"byte 0x%02x variant %s: display string is null/empty", b, variant));
				}

				// 2. Multi-byte overload agrees with the single-byte overload.
				String viaArray = mapper.toDisplayEscaped(new byte[] { (byte) b }, variant);
				if (!viaArray.equals(s)) {
					fail(String.format(
						"byte 0x%02x variant %s: byte[] overload '%s' != int overload '%s'",
						b, variant, viaArray, s));
				}

				// 3. Every petcat-named control byte matches the verified table exactly,
				// in both variants (control-code names are variant-invariant).
				String expectedName = null;
				if (b < 0x20 && !CTRL1[b].isEmpty() && !CTRL1[b].equals("\n")) {
					expectedName = CTRL1[b];
				}
				else if (b >= 0x80 && b < 0xA0 && !CTRL2[b - 0x80].isEmpty()) {
					expectedName = CTRL2[b - 0x80];
				}
				if (expectedName != null) {
					String expected = "{" + expectedName + "}";
					if (!expected.equals(s)) {
						fail(String.format(
							"byte 0x%02x variant %s: expected named escape '%s', got '%s'",
							b, variant, expected, s));
					}
				}

				// 4. 0x0D (CBM RETURN) is always a literal newline, both variants -- the one
				// petcat control code that is never escaped.
				if (b == 0x0D) {
					if (!"\n".equals(s)) {
						fail(String.format(
							"byte 0x0d variant %s: expected literal newline, got '%s'", variant, s));
					}
				}

				// 5. Every byte that is neither a named control code, the 0x0D literal, nor
				// a printable char, renders exactly "{$xx}" (lowercase 2-hex-digit).
				boolean isNamedControl = expectedName != null;
				boolean isPrintableAscii = b >= 0x20 && b < 0x7F && isKnownPrintable(b, variant);
				if (!isNamedControl && b != 0x0D && !isPrintableAscii) {
					Matcher m = HEX_ESCAPE.matcher(s);
					if (!m.matches()) {
						fail(String.format(
							"byte 0x%02x variant %s: expected hex fallback '{$%02x}', got '%s'",
							b, variant, b, s));
					}
					int parsed = Integer.parseInt(s.substring(2, 4), 16);
					if (parsed != b) {
						fail(String.format(
							"byte 0x%02x variant %s: hex fallback encodes wrong byte: '%s'",
							b, variant, s));
					}
				}

				// 6. Printable-range sanity: identity-range and letter-range bytes render as
				// a single expected ASCII character.
				if (isPrintableAscii) {
					char expectedChar = expectedPrintableChar(b, variant);
					if (s.length() != 1 || s.charAt(0) != expectedChar) {
						fail(String.format(
							"byte 0x%02x variant %s: expected printable char '%c', got '%s'",
							b, variant, expectedChar, s));
					}
				}
			}
		}
	}

	/** Check 7: the one variant-dependent range: 0x41-0x5A must differ in case between
	 *  variants; everything else must be IDENTICAL across variants (petcat has no shift-state
	 *  parameter, and petscii.yaml's letter_range is the only per-variant override). */
	@Test
	public void letterRangeVariantDivergence() {
		for (int b = 0; b < 256; b++) {
			String unshifted = mapper.toDisplayEscaped(b, Variant.UNSHIFTED_GRAPHICS);
			String shifted = mapper.toDisplayEscaped(b, Variant.SHIFTED_LOWERCASE);
			boolean inLetterRange = b >= 0x41 && b <= 0x5A;
			if (inLetterRange) {
				if (unshifted.equals(shifted)) {
					fail(String.format(
						"byte 0x%02x: expected variants to differ (letter range), both gave '%s'",
						b, unshifted));
				}
				if (!unshifted.equalsIgnoreCase(shifted)) {
					fail(String.format(
						"byte 0x%02x: variants differ by more than case: '%s' vs '%s'",
						b, unshifted, shifted));
				}
			}
			else if (!unshifted.equals(shifted)) {
				fail(String.format(
					"byte 0x%02x: expected identical variants outside the letter range, " +
						"got '%s' vs '%s'", b, unshifted, shifted));
			}
		}
	}

	/** Checks 8-12 (bead grm-1.4.2): independent re-derivation cross-check, encode/decode
	 *  round-trip, and toDisplayUnicode agreement. */
	@Test
	public void unicodeLayer() {
		for (Variant variant : Variant.values()) {
			for (int b = 0; b < 256; b++) {
				int cp = codepointOf(mapper.toDisplayUnicode(b, variant));

				// 8. Every codepoint is a valid Unicode scalar value: non-negative, within
				// range, and not a lone surrogate.
				if (cp < 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
					fail(String.format(
						"byte 0x%02x variant %s: invalid unicode codepoint U+%X", b, variant, cp));
				}

				// 9. Matches the independently re-derived reference codepoint.
				int expected = expectedUnicodeCodepoint(b, variant);
				if (cp != expected) {
					fail(String.format(
						"byte 0x%02x variant %s: expected unicode codepoint U+%04X, got U+%04X",
						b, variant, expected, cp));
				}

				// 10. byte[] overload agrees with the int overload.
				String viaArray = mapper.toDisplayUnicode(new byte[] { (byte) b }, variant);
				if (!viaArray.equals(mapper.toDisplayUnicode(b, variant))) {
					fail(String.format(
						"byte 0x%02x variant %s: unicode byte[] overload disagrees with int overload",
						b, variant));
				}

				// 11. encode(decode(b)) == canonical(b): the encode map, applied to this
				// byte's own decoded codepoint, must return the LOWEST byte that decodes to
				// that same codepoint.
				int canonical = lowestByteDecodingTo(cp, variant);
				Integer encoded = mapper.encodeUnicode(cp, variant);
				if (encoded == null || encoded != canonical) {
					fail(String.format(
						"byte 0x%02x variant %s: encode(decode(byte))=%s, expected canonical 0x%02x",
						b, variant, encoded, canonical));
				}

				// 12. toDisplayUnicode's string round-trips through the encode map: decoding
				// the encoded codepoint back out of the string yields the same codepoint.
				String rendered = mapper.toDisplayUnicode(b, variant);
				int roundTripCp = rendered.codePointAt(0);
				if (roundTripCp != cp) {
					fail(String.format(
						"byte 0x%02x variant %s: rendered string does not round-trip to U+%04X",
						b, variant, cp));
				}
			}
		}
	}

	/** Check 13: mirror-range consistency: every mirror byte decodes to the SAME codepoint as
	 *  its canonical (low) partner, in both variants. */
	@Test
	public void mirrorRangeConsistency() {
		for (Variant variant : Variant.values()) {
			for (int b = 0xC0; b <= 0xDF; b++) {
				assertMirrorsMatch(b, b - 0x60, variant);
			}
			for (int b = 0xE0; b <= 0xFE; b++) {
				assertMirrorsMatch(b, b - 0x40, variant);
			}
			assertMirrorsMatch(0xFF, 0x7E, variant);
		}
	}
}
