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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * {@link CbmBasicWalker#isBasicStart} -- the sniff the CBM PRG loaders use to decide whether the
 * bytes at the load address are a BASIC line-link chain (do not mark a function there; a BASIC
 * analyzer will find the real ML entry from a {@code SYS} line) or machine code (mark a function,
 * which is what gets the program disassembled at all).
 * <p>
 * Tier 1: {@code ByteSource} is a one-method interface over raw bytes, so none of this needs a
 * {@code Program} or a {@code ProgramBuilder}.
 * <p>
 * <b>The load-bearing case is {@link #machineCodeStartingWithTwoZeroBytesIsNotBasic()}</b>, which
 * is a regression test for a measured, silent, total failure: a real non-packed SID player
 * ({@code sid.obj.64.prg}, 3153 bytes of 6502 at {@code $C000}) begins {@code 00 00}. The sniff
 * read that as "trivially empty BASIC program", the loader skipped marking a function, no
 * {@code SYS} line existed to redirect to, and the whole program ended up with ZERO instructions
 * in the listing. Nothing reported an error -- the import "succeeded".
 */
public class CbmBasicStartSniffTest {

	/** A {@code ByteSource} over a byte array based at {@code loadAddr}, bounded like the
	 *  loader's own (out of range reads answer -1, never throw). */
	private static CbmBasicWalker.ByteSource source(long loadAddr, int... payload) {
		return addr -> {
			long index = addr - loadAddr;
			if (index < 0 || index >= payload.length) {
				return -1;
			}
			return payload[(int) index] & 0xFF;
		};
	}

	private static boolean sniff(long loadAddr, int... payload) {
		return CbmBasicWalker.isBasicStart(source(loadAddr, payload), loadAddr,
			loadAddr + payload.length);
	}

	/**
	 * THE REGRESSION CASE. Machine code that happens to begin with two zero bytes is not a
	 * BASIC program, and calling it one costs the entire program. The payload here is the
	 * shape the SID player has: two zero bytes followed by real code.
	 */
	@Test
	public void machineCodeStartingWithTwoZeroBytesIsNotBasic() {
		// 00 00 then LDA #$00 / STA $D020 / RTS -- ordinary 6502, no BASIC anywhere.
		assertFalse("machine code beginning 00 00 must not be sniffed as BASIC",
			sniff(0xC000, 0x00, 0x00, 0xA9, 0x00, 0x8D, 0x20, 0xD0, 0x60));
	}

	/**
	 * The case (a) that IS real, and the reason the zero-link branch exists at all: a genuinely
	 * empty BASIC program is EXACTLY its two-byte terminator and nothing else. {@code SAVE}
	 * with no program in memory writes a 4-byte file (2 bytes of load address + these 2).
	 */
	@Test
	public void emptyBasicProgramIsExactlyItsTerminator() {
		assertTrue("a 2-byte all-zero payload is the empty BASIC program",
			sniff(0x0801, 0x00, 0x00));
	}

	/**
	 * A real one-line BASIC program still sniffs as BASIC -- the fix must not cost the case the
	 * sniff exists for. {@code 10 SYS 2062} at $0801, terminated by the end-of-program link.
	 */
	@Test
	public void realBasicProgramIsBasic() {
		assertTrue("a well-formed one-line chain is BASIC-start", sniff(0x0801,
			0x0B, 0x08,             // link -> $080B (this line's terminator + 1)
			0x0A, 0x00,             // line number 10
			0x9E,                   // SYS token
			0x32, 0x30, 0x36, 0x32, // "2062"
			0x00,                   // line terminator
			0x00, 0x00));           // end of program
	}

	/**
	 * Machine code carrying a {@code $00} byte early on must not produce a spurious one-line
	 * chain. This is the coincidence the "first line must be clean" rule already guarded, kept
	 * here so the zero-link fix is not mistaken for the whole of the sniff's defence.
	 */
	@Test
	public void machineCodeWithAnEarlyZeroByteIsNotBasic() {
		// A9 00 -> link $00A9 lands nowhere near where the walk reaches, so the first line is
		// the malformed one.
		assertFalse("a coincidental early $00 must not read as a BASIC line",
			sniff(0xC000, 0xA9, 0x00, 0x8D, 0x20, 0xD0, 0x60, 0x00, 0x00));
	}

	/** A payload too short to hold even a link answers false rather than reading out of range. */
	@Test
	public void truncatedPayloadIsNotBasic() {
		assertFalse("one byte cannot be a line link", sniff(0xC000, 0x00));
	}
}
