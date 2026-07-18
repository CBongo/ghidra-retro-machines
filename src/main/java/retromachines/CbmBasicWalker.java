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

import java.util.ArrayList;
import java.util.List;

/**
 * Walks a tokenized Commodore BASIC program's line-link chain (bead grm-odt.1).
 * <p>
 * Each line is: 2-byte LE link to the next line's address, 2-byte LE line number,
 * tokenized text bytes, then a {@code $00} terminator. The chain ends when a line's
 * link is {@code $0000}.
 * <p>
 * Shared by {@link AbstractCbmPrgLoader} (a cheap structural sniff decides whether a freshly
 * loaded PRG is BASIC-start at all -- see {@link #isBasicStart}, which deliberately
 * does <em>not</em> compare the load address against any hardcoded value such as
 * {@code $0801}: a well-formed line chain is itself the signal, at whatever address
 * the PRG happens to load) and {@link C64BasicAnalyzer} (the full walk that types and
 * detokenizes every line).
 * <p>
 * <b>Malformed-link policy</b> (bead requirement): a line whose link does not land
 * exactly at the address the walk reached by scanning to that line's own {@code $00}
 * terminator is a STOP-and-bookmark condition, not a crash. The line already parsed
 * (up to and including its own terminator) is kept in the result; the walk does not
 * follow that line's link further. {@link WalkResult#malformedAt} records the
 * address of the offending line so the caller can bookmark it.
 */
final class CbmBasicWalker {

	private CbmBasicWalker() {
	}

	/** Byte source abstraction so the same walker runs over raw PRG bytes (loader,
	 *  pre-import) and over a live {@code Program}'s memory (analyzer, post-import). */
	interface ByteSource {
		/** Unsigned byte at {@code addr}, or -1 if {@code addr} is out of range. */
		int byteAt(long addr);
	}

	/** One parsed BASIC line. {@code textStart}..{@code terminatorAddr} (exclusive of the
	 *  terminator) is the tokenized text; {@code terminatorAddr} holds the {@code $00}. */
	record BasicLine(long lineAddr, long link, int lineNumber, long textStart,
			long terminatorAddr) {
	}

	/** Outcome of a walk: the lines successfully parsed, plus (if the walk stopped early
	 *  because of a malformed link) the address of the offending line and what its link
	 *  actually pointed to vs. where the walk had reached. A clean end-of-program
	 *  ({@code link == 0} on some line) leaves {@code malformedAt == null}. */
	record WalkResult(List<BasicLine> lines, Long malformedAt, Long malformedLink,
			Long expectedNextAddr) {
		boolean isMalformed() {
			return malformedAt != null;
		}
	}

	/**
	 * Cheap structural sniff: does {@code loadAddr} look like the start of a tokenized
	 * BASIC program? Used by the loader to decide whether to skip its usual
	 * mark-a-function-at-load-address behavior (those bytes are the first line-link, not
	 * code, for a BASIC-start PRG).
	 * <p>
	 * True when either (a) the program is a trivially empty BASIC program (link ==
	 * {@code $0000} right at {@code loadAddr}), or (b) at least one well-formed line was
	 * parsed <em>and the first line itself was not the malformed one</em>. Machine code
	 * happening to contain a {@code $00} byte early on can otherwise produce a spurious
	 * one-line "chain" purely by coincidence (its bogus link almost never lands exactly
	 * on the address the walk reached scanning for that "line"'s terminator); requiring
	 * the first line to be clean is what tells real BASIC apart from that coincidence.
	 * A real BASIC program that happens to be corrupt starting at its second or later
	 * line is still recognized as BASIC-start (the malformed condition there stops the
	 * walk, but the clean first line already parsed is enough signal).
	 */
	static boolean isBasicStart(ByteSource src, long loadAddr, long limitAddr) {
		int lo = src.byteAt(loadAddr);
		int hi = src.byteAt(loadAddr + 1);
		if (lo < 0 || hi < 0) {
			return false;
		}
		long firstLink = (hi << 8) | lo;
		if (firstLink == 0) {
			return true; // trivially empty BASIC program
		}
		WalkResult result = walk(src, loadAddr, limitAddr);
		if (result.lines().isEmpty()) {
			return false;
		}
		return result.malformedAt() == null || result.malformedAt() != loadAddr;
	}

	/** Full walk from {@code loadAddr}, stopping at end-of-chain, the malformed-link
	 *  condition, or {@code limitAddr} (exclusive upper bound on any byte read). */
	static WalkResult walk(ByteSource src, long loadAddr, long limitAddr) {
		List<BasicLine> lines = new ArrayList<>();
		long lineAddr = loadAddr;

		while (true) {
			int linkLo = src.byteAt(lineAddr);
			int linkHi = src.byteAt(lineAddr + 1);
			if (linkLo < 0 || linkHi < 0 || lineAddr + 1 >= limitAddr) {
				break; // out of range; nothing more to do
			}
			long link = (linkHi << 8) | linkLo;
			if (link == 0) {
				break; // clean end of program
			}
			if (link <= lineAddr) {
				// Not monotonically increasing -- can't be a real BASIC chain.
				return new WalkResult(lines, lineAddr, link, null);
			}

			int lnLo = src.byteAt(lineAddr + 2);
			int lnHi = src.byteAt(lineAddr + 3);
			if (lnLo < 0 || lnHi < 0) {
				return new WalkResult(lines, lineAddr, link, null);
			}
			int lineNumber = (lnHi << 8) | lnLo;

			long textStart = lineAddr + 4;
			long scan = textStart;
			int b;
			while ((b = src.byteAt(scan)) > 0) {
				scan++;
				if (scan >= limitAddr) {
					// Ran off the end of the PRG image without finding a terminator.
					return new WalkResult(lines, lineAddr, link, null);
				}
			}
			if (b != 0) {
				// Ran out of readable bytes before a terminator.
				return new WalkResult(lines, lineAddr, link, null);
			}
			long terminatorAddr = scan;
			long expectedNext = terminatorAddr + 1;

			lines.add(new BasicLine(lineAddr, link, lineNumber, textStart, terminatorAddr));

			if (link != expectedNext) {
				return new WalkResult(lines, lineAddr, link, expectedNext);
			}
			lineAddr = link;
		}
		return new WalkResult(lines, null, null, null);
	}
}
