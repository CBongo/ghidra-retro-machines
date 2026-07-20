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
package retromachines.charset;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.util.Map;

/**
 * A JVM {@link Charset} backed by a flat 256-entry byte-&gt;codepoint decode table and a
 * codepoint-&gt;canonical-byte encode map (bead grm-1.4 Phase C). No Ghidra imports: this
 * class is a pure {@code java.nio.charset} implementation, usable both inside Ghidra (via
 * {@link RetroCharsetProvider}'s {@code ServiceLoader} registration) and by
 * {@code tools/charset/CharsetProviderVerify.java} in a plain JVM.
 * <p>
 * The decode table is total -- every one of the 256 possible byte values maps to some
 * codepoint by construction (see {@code retromachines.PetsciiMapper}/{@code petscii.yaml}'s
 * control-pass-through and fallback policy) -- so {@link Decoder} never reports a decoding
 * error. The encode map is necessarily partial (many codepoints in the Unicode image, e.g.
 * arbitrary Latin text, have no PETSCII byte); {@link Encoder} reports
 * {@link CoderResult#unmappableForLength(int)} for those, which is ordinary
 * {@link CharsetEncoder} behavior (surfaces as {@link java.nio.charset.CharacterCodingException}
 * or a caller-supplied replacement, per the usual {@code java.nio.charset} contract).
 */
public final class TableCharset extends Charset {

	private final int[] toUnicode;
	private final Map<Integer, Integer> fromUnicode;

	/**
	 * @param canonicalName this charset's canonical name (e.g. {@code "x-petscii-unshifted"})
	 * @param aliases additional names this charset is also known by (may be empty)
	 * @param codepointTable 256-entry byte value -&gt; Unicode codepoint decode table; NOT
	 *     retained by reference (defensively copied)
	 * @param encodeMap Unicode codepoint -&gt; canonical byte value encode map; NOT retained
	 *     by reference (defensively copied)
	 */
	public TableCharset(String canonicalName, String[] aliases, int[] codepointTable,
			Map<Integer, Integer> encodeMap) {
		super(canonicalName, aliases);
		if (codepointTable.length != 256) {
			throw new IllegalArgumentException(
				"codepointTable must have exactly 256 entries, got " + codepointTable.length);
		}
		this.toUnicode = codepointTable.clone();
		this.fromUnicode = Map.copyOf(encodeMap);
	}

	@Override
	public boolean contains(Charset cs) {
		return cs.equals(this);
	}

	@Override
	public CharsetDecoder newDecoder() {
		return new Decoder(this);
	}

	@Override
	public CharsetEncoder newEncoder() {
		return new Encoder(this);
	}

	private final class Decoder extends CharsetDecoder {

		Decoder(Charset cs) {
			// averageCharsPerByte=1 (the common case), maxCharsPerByte=2 (Symbols-for-
			// Legacy-Computing codepoints above the BMP decode as a surrogate pair).
			super(cs, 1.0f, 2.0f);
		}

		@Override
		protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
			while (in.hasRemaining()) {
				int mark = in.position();
				int b = in.get() & 0xFF;
				int codepoint = toUnicode[b];
				char[] chars = Character.toChars(codepoint);
				if (out.remaining() < chars.length) {
					in.position(mark);
					return CoderResult.OVERFLOW;
				}
				out.put(chars);
			}
			return CoderResult.UNDERFLOW;
		}
	}

	private final class Encoder extends CharsetEncoder {

		Encoder(Charset cs) {
			// averageBytesPerChar=1, maxBytesPerChar=1: every mappable codepoint (whether
			// from a single char or a surrogate pair) encodes to exactly one canonical byte.
			super(cs, 1.0f, 1.0f);
		}

		@Override
		protected CoderResult encodeLoop(CharBuffer in, ByteBuffer out) {
			while (in.hasRemaining()) {
				int mark = in.position();
				char c = in.get();
				int codepoint;
				int charLen;
				if (Character.isHighSurrogate(c)) {
					if (!in.hasRemaining()) {
						in.position(mark);
						return CoderResult.UNDERFLOW;
					}
					char low = in.get();
					if (!Character.isLowSurrogate(low)) {
						in.position(mark);
						return CoderResult.malformedForLength(1);
					}
					codepoint = Character.toCodePoint(c, low);
					charLen = 2;
				}
				else if (Character.isLowSurrogate(c)) {
					in.position(mark);
					return CoderResult.malformedForLength(1);
				}
				else {
					codepoint = c;
					charLen = 1;
				}

				Integer canonicalByte = fromUnicode.get(codepoint);
				if (canonicalByte == null) {
					in.position(mark);
					return CoderResult.unmappableForLength(charLen);
				}
				if (!out.hasRemaining()) {
					in.position(mark);
					return CoderResult.OVERFLOW;
				}
				out.put((byte) (int) canonicalByte);
			}
			return CoderResult.UNDERFLOW;
		}
	}
}
