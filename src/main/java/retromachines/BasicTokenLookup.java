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

/**
 * Dialect-agnostic BASIC token lookup (bead grm-odt.1). Shaped as
 * (bytes consumed, keyword name) rather than a plain byte-&gt;name map so a future BASIC 7
 * (C128) implementation can recognize its two-byte {@code $CE}/{@code $FE} prefix tokens
 * (see {@code machines/generated/basic-tokens.yaml}'s header) through the same interface:
 * a BASIC 2 lookup always returns a 1-byte match, a BASIC 7 prefix lookup would return a
 * 2-byte match consuming the prefix and its second byte together. Not implemented for
 * BASIC 7 here -- see docs/basic-analyzer.md's dialect-expansion note (grm-1.6.1).
 */
interface BasicTokenLookup {

	/** A recognized token: how many bytes it occupied in the stream, and its keyword
	 *  text (e.g. {@code "FOR"}, {@code "="}, {@code "PRINT#"}). */
	record Match(int bytesConsumed, String name) {
	}

	/**
	 * Attempts to match a token starting at {@code data[offset]}. Returns {@code null}
	 * if the byte(s) at {@code offset} do not start a recognized token (either because
	 * the byte is below the dialect's token range, or because it falls in a gap the
	 * dialect does not assign -- e.g. BASIC 2 leaves {@code $CC}-{@code $FF} unassigned).
	 */
	Match lookup(byte[] data, int offset);
}
