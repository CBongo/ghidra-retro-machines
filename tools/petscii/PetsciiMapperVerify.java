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
// Exhaustive check that retromachines.PetsciiMapper resolves every byte correctly against
// the compiled data/petscii.map (bead grm-1.4.1).
//
// Structured after tools/bitalgebra/BitAlgebraEquivalence.java: its own Gradle source set
// (petsciiCheck), its own task (verifyPetsciiMapper), same PASS-line convention. The key
// difference from BitAlgebraEquivalence is that this tool exercises the REAL production
// class rather than a transcribed reference implementation -- PetsciiMapper.loadFromMapFile
// is the seam that makes that possible without a live Ghidra runtime (no
// Application.initializeApplication(), no headless analyzer): it parses data/petscii.map
// directly from disk with plain gson, the same code path PetsciiMapper.load() uses
// internally once the JSON is in hand, just reached without Application.findDataFileInAnyModule.
//
// Run via `gradle verifyPetsciiMapper` (classpath = main's compiled retromachines classes +
// gson only -- no Ghidra jars; see build.gradle's petsciiCheckImplementation comment for why
// that is safe even though PetsciiMapper.java itself imports Ghidra types for load()) or
// plainly: javac -cp <main classes>:<gson.jar> + java -cp ... PetsciiMapperVerify <petscii.map>
//
// Exits non-zero (throws) on the first mismatch; prints "PETSCIIMAPPER PASS (<n> cases)" when
// every case agrees.

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import retromachines.PetsciiMapper;
import retromachines.PetsciiMapper.Variant;

public final class PetsciiMapperVerify {

	private PetsciiMapperVerify() {
	}

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

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			System.err.println("Usage: PetsciiMapperVerify <petscii.map>");
			System.exit(1);
		}
		PetsciiMapper mapper = PetsciiMapper.loadFromMapFile(new File(args[0]));

		long cases = 0;

		for (Variant variant : Variant.values()) {
			for (int b = 0; b < 256; b++) {
				String s = mapper.toDisplayEscaped(b, variant);
				cases++;

				// 1. Every byte, every variant: non-null, non-empty.
				if (s == null || s.isEmpty()) {
					throw new AssertionError(String.format(
						"byte 0x%02x variant %s: display string is null/empty", b, variant));
				}

				// 2. Multi-byte overload agrees with the single-byte overload.
				String viaArray = mapper.toDisplayEscaped(new byte[] { (byte) b }, variant);
				if (!viaArray.equals(s)) {
					throw new AssertionError(String.format(
						"byte 0x%02x variant %s: byte[] overload '%s' != int overload '%s'",
						b, variant, viaArray, s));
				}
				cases++;

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
						throw new AssertionError(String.format(
							"byte 0x%02x variant %s: expected named escape '%s', got '%s'",
							b, variant, expected, s));
					}
					cases++;
				}

				// 4. 0x0D (CBM RETURN) is always a literal newline, both variants -- the one
				// petcat control code that is never escaped.
				if (b == 0x0D) {
					if (!"\n".equals(s)) {
						throw new AssertionError(String.format(
							"byte 0x0d variant %s: expected literal newline, got '%s'", variant, s));
					}
					cases++;
				}

				// 5. Every byte that is neither a named control code, the 0x0D literal, nor
				// a printable char, renders exactly "{$xx}" (lowercase 2-hex-digit).
				boolean isNamedControl = expectedName != null;
				boolean isPrintableAscii = b >= 0x20 && b < 0x7F && isKnownPrintable(b, variant);
				if (!isNamedControl && b != 0x0D && !isPrintableAscii) {
					Matcher m = HEX_ESCAPE.matcher(s);
					if (!m.matches()) {
						throw new AssertionError(String.format(
							"byte 0x%02x variant %s: expected hex fallback '{$%02x}', got '%s'",
							b, variant, b, s));
					}
					int parsed = Integer.parseInt(s.substring(2, 4), 16);
					if (parsed != b) {
						throw new AssertionError(String.format(
							"byte 0x%02x variant %s: hex fallback encodes wrong byte: '%s'",
							b, variant, s));
					}
					cases++;
				}

				// 6. Printable-range sanity: identity-range and letter-range bytes render as
				// a single expected ASCII character.
				if (isPrintableAscii) {
					char expectedChar = expectedPrintableChar(b, variant);
					if (s.length() != 1 || s.charAt(0) != expectedChar) {
						throw new AssertionError(String.format(
							"byte 0x%02x variant %s: expected printable char '%c', got '%s'",
							b, variant, expectedChar, s));
					}
					cases++;
				}
			}
		}

		// 7. The one variant-dependent range: 0x41-0x5A must differ in case between variants;
		// everything else must be IDENTICAL across variants (petcat has no shift-state
		// parameter, and petscii.yaml's letter_range is the only per-variant override).
		for (int b = 0; b < 256; b++) {
			String unshifted = mapper.toDisplayEscaped(b, Variant.UNSHIFTED_GRAPHICS);
			String shifted = mapper.toDisplayEscaped(b, Variant.SHIFTED_LOWERCASE);
			boolean inLetterRange = b >= 0x41 && b <= 0x5A;
			if (inLetterRange) {
				if (unshifted.equals(shifted)) {
					throw new AssertionError(String.format(
						"byte 0x%02x: expected variants to differ (letter range), both gave '%s'",
						b, unshifted));
				}
				if (!unshifted.equalsIgnoreCase(shifted)) {
					throw new AssertionError(String.format(
						"byte 0x%02x: variants differ by more than case: '%s' vs '%s'",
						b, unshifted, shifted));
				}
			}
			else if (!unshifted.equals(shifted)) {
				throw new AssertionError(String.format(
					"byte 0x%02x: expected identical variants outside the letter range, " +
						"got '%s' vs '%s'", b, unshifted, shifted));
			}
			cases++;
		}

		System.out.println("PETSCIIMAPPER PASS (" + cases + " cases)");
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
}
