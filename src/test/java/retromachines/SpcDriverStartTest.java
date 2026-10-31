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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;

import org.junit.Test;

/** Pure-JUnit coverage of {@link SpcDriverStart} (bead grm-1.7.7, rule 1); lengths are checked
 *  against SLEIGH in {@code Spc700LanguageTest}. */
public class SpcDriverStartTest {

	/** One block of {@code code} at {@code addr}, entry {@code addr}. */
	private static SpcDriverStart.Outcome walk(int addr, int... code) {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		o.write(code.length);
		o.write(code.length >> 8);
		o.write(addr);
		o.write(addr >> 8);
		for (int b : code) {
			o.write(b);
		}
		SpcIplFormatTest.terminator(o, addr);
		SpcIplFormat.Result r = SpcIplFormat.parse(o.toByteArray(), 0);
		assertTrue(r.ok());
		return SpcDriverStart.walk(r.stream());
	}

	@Test
	public void akaoStyleStartReachesDspWrite() {
		// CLRP; MOV X,#$FF; MOV SP,X; MOV $F2,#$6C
		assertEquals(SpcDriverStart.Outcome.DSP_WRITE,
			walk(0x0200, 0x20, 0xCD, 0xFF, 0xBD, 0x8F, 0x6C, 0xF2));
	}

	@Test
	public void writeInsideCalleeCounts() {
		// CALL $0206; STOP; NOP; NOP; MOV A,#$00; MOV $F3,A; RET
		assertEquals(SpcDriverStart.Outcome.DSP_WRITE,
			walk(0x0200, 0x3F, 0x06, 0x02, 0xFF, 0x00, 0x00, 0xE8, 0x00, 0xC4, 0xF3, 0x6F));
	}

	@Test
	public void conditionalBranchFallsThroughAndJmpIsFollowed() {
		// BNE +$10; JMP $0207; STOP; MOV !$00F1,A
		assertEquals(SpcDriverStart.Outcome.DSP_WRITE,
			walk(0x0200, 0xD0, 0x10, 0x5F, 0x06, 0x02, 0xFF, 0xC5, 0xF1, 0x00));
	}

	@Test
	public void directPageWriteWithPSetIsNotThePort() {
		// SETP; MOV $F2,A (that is $01F2); STOP
		assertEquals(SpcDriverStart.Outcome.HALTED, walk(0x0200, 0x40, 0xC4, 0xF2, 0xFF));
	}

	@Test
	public void failsClosed() {
		// JMP $4000 (not uploaded)
		assertEquals(SpcDriverStart.Outcome.LEFT_IMAGE, walk(0x0200, 0x5F, 0x00, 0x40, 0x00));
		// RET with nothing called
		assertEquals(SpcDriverStart.Outcome.INDIRECT, walk(0x0200, 0x6F, 0x00));
		// TCALL 0
		assertEquals(SpcDriverStart.Outcome.INDIRECT, walk(0x0200, 0x01, 0x00));
		// BRA to self
		assertEquals(SpcDriverStart.Outcome.BUDGET, walk(0x0200, 0x2F, 0xFE));
	}
}
