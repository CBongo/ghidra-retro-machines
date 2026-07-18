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
 * Dialect-agnostic BASIC token lookup. The result shape supports both ordinary one-byte
 * tokens and configured two-byte prefix pages (for example BASIC 7 {@code $CE}/{@code $FE}
 * tokens), while preserving unrecognized complete prefix pairs as one raw two-byte unit.
 */
interface BasicTokenLookup {

	/** A token or raw multi-byte unit. {@code name} is null for a complete but unrecognized
	 *  configured prefix pair; callers render all {@code bytesConsumed} bytes literally. */
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
