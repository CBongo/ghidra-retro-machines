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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

/**
 * Pure-JUnit coverage of the per-game identity grammar and digest (bead grm-hb6.1):
 * {@link DescriptorSupport.GameIdentity}, {@link DescriptorSupport#parseGameIdentity} and
 * {@link DescriptorSupport#sha256Hex}. Imports nothing from {@code ghidra.*} -- the property
 * value is plain string logic and the digest is plain {@code MessageDigest}, so no Ghidra
 * runtime bootstrap is needed (same discipline as {@link PlacementOverrideParseTest} and
 * {@link BankStateTest}). That is also the reason the identity path uses {@code MessageDigest}
 * directly instead of {@code generic.hash.HashUtilities}: it keeps this tier reachable.
 * <p>
 * As with the placement grammar, the colon separator is not decorative -- cmd.exe's
 * analyzeHeadless.bat splits argument values on '=', so a '='-shaped identity must not parse.
 */
public class GameIdentityParseTest {

	/** A well-formed 64-hex digest standing in for a PRG hash. */
	private static final String PRG_HEX =
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

	/** A different well-formed 64-hex digest standing in for a whole-file hash. */
	private static final String FILE_HEX =
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

	/** SHA-256 of the empty input -- the canonical NIST test vector. */
	private static final String SHA256_EMPTY =
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/** SHA-256 of the three ASCII bytes "abc" -- the other canonical NIST test vector. */
	private static final String SHA256_ABC =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

	@Test
	public void propertyValueUsesColonSeparatedPrgAndFileTokens() {
		String value = new DescriptorSupport.GameIdentity(PRG_HEX, FILE_HEX).toPropertyValue();
		assertTrue("unexpected property shape: " + value,
			value.matches("^prg:[0-9a-f]{64} file:[0-9a-f]{64}$"));
		// '=' anywhere in the value would be mangled by the headless batch arg parser.
		assertFalse("property value must not contain '='", value.contains("="));
	}

	@Test
	public void propertyValueRoundTripsThroughParse() {
		DescriptorSupport.GameIdentity id =
			new DescriptorSupport.GameIdentity(PRG_HEX, FILE_HEX);
		assertEquals(id, DescriptorSupport.parseGameIdentity(id.toPropertyValue()));
	}

	@Test
	public void tokenOrderDoesNotMatter() {
		DescriptorSupport.GameIdentity parsed =
			DescriptorSupport.parseGameIdentity("file:" + FILE_HEX + " prg:" + PRG_HEX);
		assertNotNull(parsed);
		assertEquals(PRG_HEX, parsed.prgSha256());
		assertEquals(FILE_HEX, parsed.fileSha256());
	}

	@Test
	public void uppercaseHexNormalizesToLowercase() {
		// ROM managers print digests in uppercase, and a hand-authored overlay descriptor
		// pastes whatever casing the user happened to have. Two identities naming the same
		// bytes must compare equal regardless, or a descriptor silently fails to match.
		DescriptorSupport.GameIdentity upper = DescriptorSupport.parseGameIdentity(
			"prg:" + PRG_HEX.toUpperCase() + " file:" + FILE_HEX.toUpperCase());
		DescriptorSupport.GameIdentity lower = DescriptorSupport.parseGameIdentity(
			"prg:" + PRG_HEX + " file:" + FILE_HEX);
		assertEquals(lower, upper);
		assertEquals(PRG_HEX, upper.prgSha256());
		assertEquals(FILE_HEX, upper.fileSha256());
	}

	@Test
	public void nullAndBlankYieldNoIdentity() {
		// Deliberately NOT parsePlacementOverride's empty-collection-on-blank: "this program
		// has no identity" is a distinct state from "an identity with empty halves", and only
		// the former can occur -- a loader writes both halves or writes nothing.
		assertNull(DescriptorSupport.parseGameIdentity(null));
		assertNull(DescriptorSupport.parseGameIdentity(""));
		assertNull(DescriptorSupport.parseGameIdentity("   "));
	}

	@Test
	public void equalsSeparatorIsRejected() {
		// The '='-based shape must not parse -- it is exactly what the headless batch arg
		// parser mangles, and every grammar in this extension uses colons because of it.
		assertThrows(IllegalArgumentException.class, () -> DescriptorSupport
				.parseGameIdentity("prg=" + PRG_HEX + " file=" + FILE_HEX));
	}

	@Test
	public void missingHalfIsRejected() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parseGameIdentity("prg:" + PRG_HEX));
		assertTrue(e.getMessage().contains("both"));
		assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parseGameIdentity("file:" + FILE_HEX));
	}

	@Test
	public void malformedDigestIsRejected() {
		// 63 hex digits: one short, which a truncated copy/paste produces.
		String shortHex = PRG_HEX.substring(1);
		assertEquals(63, shortHex.length());
		assertThrows(IllegalArgumentException.class, () -> DescriptorSupport
				.parseGameIdentity("prg:" + shortHex + " file:" + FILE_HEX));

		// Right length, wrong alphabet -- 'g' is not a hex digit.
		String notHex = "g" + PRG_HEX.substring(1);
		assertEquals(64, notHex.length());
		assertThrows(IllegalArgumentException.class, () -> DescriptorSupport
				.parseGameIdentity("prg:" + notHex + " file:" + FILE_HEX));
	}

	@Test
	public void unknownKeyIsRejected() {
		assertThrows(IllegalArgumentException.class, () -> DescriptorSupport.parseGameIdentity(
			"chr:" + FILE_HEX + " prg:" + PRG_HEX + " file:" + FILE_HEX));
	}

	@Test
	public void repeatedKeyIsRejected() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parseGameIdentity("prg:" + PRG_HEX + " prg:" + FILE_HEX));
		assertTrue(e.getMessage().contains("more than once"));
	}

	@Test
	public void sha256HexMatchesTheCanonicalTestVectors() throws IOException {
		String empty = DescriptorSupport.sha256Hex(new ByteArrayInputStream(new byte[0]), -1);
		assertEquals(SHA256_EMPTY, empty);

		String abc = DescriptorSupport.sha256Hex(
			new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)), -1);
		assertEquals(SHA256_ABC, abc);

		// The casing is ours to state, not inherited from a Ghidra internal -- assert it.
		assertEquals(64, abc.length());
		assertEquals(abc.toLowerCase(), abc);
	}

	@Test
	public void explicitLengthHashesOnlyThatManyBytes() throws IOException {
		byte[] all = new byte[32];
		for (int i = 0; i < all.length; i++) {
			all[i] = (byte) (i * 7 + 3);
		}
		byte[] head = new byte[16];
		System.arraycopy(all, 0, head, 0, head.length);

		String prefixOfAll = DescriptorSupport.sha256Hex(new ByteArrayInputStream(all), 16);
		String headAlone = DescriptorSupport.sha256Hex(new ByteArrayInputStream(head), -1);
		assertEquals(headAlone, prefixOfAll);

		// The trailing bytes really were excluded, not merely hashed identically.
		String allBytes = DescriptorSupport.sha256Hex(new ByteArrayInputStream(all), -1);
		assertFalse(allBytes.equals(prefixOfAll));
	}

	@Test
	public void lengthPastEndOfDataIsAnIoException() {
		// A short read means the caller's slice bounds were wrong; hashing whatever arrived
		// would mint a well-formed but wrong key, so it has to fail loudly.
		assertThrows(IOException.class,
			() -> DescriptorSupport.sha256Hex(new ByteArrayInputStream(new byte[4]), 8));
	}
}
