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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;

/**
 * Per-game identity (bead grm-hb6.1): the {@link GameIdentity} record, its property-value
 * grammar, and the SHA-256 helper the loaders compute it with. Split out of the former
 * {@code DescriptorSupport} (bead grm-rx1i.12).
 */
final class GameIdentities {

	private GameIdentities() {
	}

	/** One {@code prg:}/{@code file:} token of the identity grammar: capture group 1 = key,
	 *  2 = the 64 hex digits. Colon, not '=', for the reason recorded at
	 *  {@link DescriptorHints#PLACEMENT_PAIR} -- every grammar in this tier inherits that rule. */
	private static final Pattern IDENTITY_PAIR = Pattern.compile("(prg|file):([0-9a-fA-F]{64})");

	// ------------------------------------------------------------------
	// Per-game identity (bead grm-hb6.1)
	// ------------------------------------------------------------------

	/**
	 * A program's per-game identity: the program-ROM digest (the primary key, computed over
	 * cartridge content with container headers excluded) and the whole-file digest (the alias
	 * key), each 64 hex characters. Both are normalized to lowercase on construction, so two
	 * identities parsed from differently-cased text compare equal -- ROM managers print
	 * uppercase and a hand-authored descriptor will paste whatever the user had.
	 */
	record GameIdentity(String prgSha256, String fileSha256) {

		GameIdentity {
			prgSha256 = requireSha256(prgSha256, "prg");
			fileSha256 = requireSha256(fileSha256, "file");
		}

		private static String requireSha256(String digest, String key) {
			if (digest == null || !digest.matches("[0-9a-fA-F]{64}")) {
				throw new IllegalArgumentException(
					"game identity '" + key + "' must be 64 hex digits, got: " + digest);
			}
			return digest.toLowerCase();
		}

		/** The {@link DescriptorHints#GAME_IDENTITY_PROPERTY} value: {@code prg:<hex> file:<hex>}. */
		String toPropertyValue() {
			return "prg:" + prgSha256 + " file:" + fileSha256;
		}
	}

	/**
	 * Parses a {@link DescriptorHints#GAME_IDENTITY_PROPERTY} value -- whitespace-separated
	 * {@code prg:<64 hex>} and {@code file:<64 hex>} tokens, order-independent, both required.
	 * <p>
	 * Returns {@code null} for null/blank input, deliberately NOT mirroring
	 * {@link DescriptorHints#parsePlacementOverride}'s empty-collection-on-blank: "this program has no
	 * identity" is a distinct state from "an identity whose halves are empty", and only the
	 * former can occur (a loader either writes both halves or writes nothing). Throws
	 * {@link IllegalArgumentException} on anything else malformed -- an unknown key, a repeated
	 * key, a missing half, or a value that is not exactly 64 hex digits.
	 */
	static GameIdentity parseGameIdentity(String spec) {
		if (spec == null || spec.isBlank()) {
			return null;
		}
		String prg = null;
		String file = null;
		for (String token : spec.trim().split("\\s+")) {
			Matcher m = IDENTITY_PAIR.matcher(token);
			if (!m.matches()) {
				throw new IllegalArgumentException("malformed game identity '" + token +
					"'; expected prg:<64 hex> or file:<64 hex>");
			}
			boolean isPrg = "prg".equals(m.group(1));
			if ((isPrg ? prg : file) != null) {
				throw new IllegalArgumentException(
					"game identity names '" + m.group(1) + "' more than once");
			}
			if (isPrg) {
				prg = m.group(2);
			}
			else {
				file = m.group(2);
			}
		}
		if (prg == null || file == null) {
			throw new IllegalArgumentException(
				"game identity needs both prg: and file: digests, got: " + spec.trim());
		}
		return new GameIdentity(prg, file);
	}

	/**
	 * SHA-256 of {@code length} bytes read from {@code in} ({@code length < 0} reads to EOF), as
	 * 64 lowercase hex characters. Does not close {@code in}; throws {@link IOException} if EOF
	 * arrives before {@code length} bytes were read.
	 * <p>
	 * Plain {@link MessageDigest} rather than {@code generic.hash.HashUtilities} (which is on
	 * the classpath and is what Ghidra's own {@code setExecutableSHA256} goes through): this is
	 * the one piece of the identity path a pure-JUnit test must exercise with no Ghidra class on
	 * the stack, and the hex casing is then ours to state rather than to inherit from a Ghidra
	 * internal. Agreement with {@code Program.getExecutableSHA256()} -- and so with
	 * {@code tools/banktest/realrom/manifest.tsv} -- is asserted by a banktest criterion rather
	 * than assumed from a shared implementation.
	 */
	static String sha256Hex(InputStream in, long length) throws IOException {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			// SHA-256 is a required algorithm on every conformant JRE
			throw new AssertException("SHA-256 unavailable", e);
		}
		byte[] buf = new byte[8192];
		long remaining = length;
		while (remaining != 0) {
			int want = remaining < 0 ? buf.length : (int) Math.min(buf.length, remaining);
			int got = in.read(buf, 0, want);
			if (got < 0) {
				if (remaining > 0) {
					throw new IOException(
						"unexpected end of data: " + remaining + " bytes short of " + length);
				}
				break;
			}
			digest.update(buf, 0, got);
			if (remaining > 0) {
				remaining -= got;
			}
		}
		StringBuilder hex = new StringBuilder(64);
		for (byte b : digest.digest()) {
			hex.append(Character.forDigit((b >> 4) & 0xF, 16));
			hex.append(Character.forDigit(b & 0xF, 16));
		}
		return hex.toString();
	}
}
