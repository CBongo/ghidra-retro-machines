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

import org.junit.Test;

/** Pure-JUnit coverage of {@link SpcStackChain} (bead grm-c9d.9). */
public class SpcStackChainTest {

	private static byte[] ram() {
		return new byte[0x10000];
	}

	private static void put(byte[] ram, int at, int... bytes) {
		for (int i = 0; i < bytes.length; i++) {
			ram[at + i] = (byte) bytes[i];
		}
	}

	/** Pushes a 16-bit return address exactly as the language's push16 does; returns new SP. */
	private static int push16(byte[] ram, int sp, int value) {
		ram[0x100 + sp] = (byte) (value >> 8);
		ram[0x100 + sp - 1] = (byte) value;
		return sp - 2;
	}

	@Test
	public void callPushOrderIsHighThenLowSoLowByteIsAtSpPlusOne() {
		byte[] ram = ram();
		put(ram, 0x0500, 0x3F, 0x40, 0x05);   // CALL !$0540, returns to $0503
		int sp = push16(ram, 0xCF, 0x0503);
		assertEquals(0xCD, sp);
		assertEquals(0x03, ram[0x100 + sp + 1] & 0xFF);
		assertEquals(0x05, ram[0x100 + sp + 2] & 0xFF);
		SpcStackChain.Result r = SpcStackChain.recover(ram, 0x0541, sp, false);
		assertEquals(1, r.frames().size());
		SpcStackChain.Frame f = r.frames().get(0);
		assertEquals(0x0503, f.ret());
		assertEquals(0x0500, f.callAt());
		assertEquals(0x0540, f.target());
		assertEquals(SpcStackChain.Kind.CALL, f.kind());
		assertEquals(0xCE, f.slot());
	}

	@Test
	public void mixedCallPcallTcallChainWalksInnermostFirstAndRejectsDecoy() {
		byte[] ram = ram();
		put(ram, 0x0403, 0x3F, 0x40, 0x04);       // main: CALL !$0440 -> ret $0406
		put(ram, 0x0442, 0x31);                    // A: TCALL 3 (table at $FFD8) -> ret $0443
		put(ram, 0xFFD8, 0x60, 0x04);              // TCALL 3 -> $0460
		put(ram, 0x0461, 0x4F, 0x20);              // B: PCALL $20 -> $FF20, ret $0463
		put(ram, 0x0412, 0x3F, 0x00, 0x90);        // decoy call to $9000, ret $0415
		int sp = 0xCF;
		sp = push16(ram, sp, 0x0415);              // decoy: outermost, rejected (target > inner)
		sp = push16(ram, sp, 0x0406);
		sp = push16(ram, sp, 0x0443);
		sp = push16(ram, sp, 0x0463);
		SpcStackChain.Result r = SpcStackChain.recover(ram, 0xFF21, sp, false);
		assertEquals(3, r.frames().size());
		assertEquals(0x0463, r.frames().get(0).ret());
		assertEquals(SpcStackChain.Kind.PCALL, r.frames().get(0).kind());
		assertEquals(0xFF20, r.frames().get(0).target());
		assertEquals(0x0443, r.frames().get(1).ret());
		assertEquals(SpcStackChain.Kind.TCALL, r.frames().get(1).kind());
		assertEquals(0x0460, r.frames().get(1).target());
		assertEquals(0x0406, r.frames().get(2).ret());
		assertEquals(0x0440, r.frames().get(2).target());
		assertEquals(0xCC, r.frames().get(2).slot());
		assertEquals(0xCE, r.endSlot());
		assertTrue(r.stop(), r.stop().startsWith("no valid return address"));
	}

	@Test
	public void returnAddressNotPrecededByACallIsRejected() {
		byte[] ram = ram();
		put(ram, 0x0500, 0xE8, 0x01, 0x00);   // MOV A,#1; NOP -- no call before $0503
		int sp = push16(ram, 0xCF, 0x0503);
		assertTrue(SpcStackChain.recover(ram, 0x0510, sp, false).frames().isEmpty());
	}

	@Test
	public void targetThatCannotContainTheInnerFrameIsRejected() {
		byte[] ram = ram();
		put(ram, 0x0500, 0x3F, 0x00, 0x30);   // CALL !$3000, but PC is at $0510
		int sp = push16(ram, 0xCF, 0x0503);
		assertTrue(SpcStackChain.recover(ram, 0x0510, sp, false).frames().isEmpty());
		// Too far below the PC (beyond MAX_SPAN) is rejected too.
		put(ram, 0x0500, 0x3F, 0x00, 0x02);   // CALL !$0200
		assertTrue(SpcStackChain.recover(ram, 0x0200 + SpcStackChain.MAX_SPAN + 1, sp, false)
				.frames().isEmpty());
		assertEquals(1, SpcStackChain.recover(ram, 0x0200 + SpcStackChain.MAX_SPAN, sp, false)
				.frames().size());
	}

	@Test
	public void returnAddressesInHolesAreRejected() {
		byte[] ram = ram();
		// Inside the I/O page.
		put(ram, 0x00F0, 0x3F, 0x00, 0x00);
		int sp = push16(ram, 0xCF, 0x00F3);
		assertTrue(SpcStackChain.recover(ram, 0x00F8, sp, false).frames().isEmpty());
		// In the stack page.
		put(ram, 0x0140, 0x3F, 0x00, 0x01);
		sp = push16(ram, 0xCF, 0x0143);
		assertTrue(SpcStackChain.recover(ram, 0x0150, sp, false).frames().isEmpty());
	}

	@Test
	public void iplWindowIsOffLimitsOnlyWhenMappedIn() {
		byte[] ram = ram();
		put(ram, 0xFFC0, 0x3F, 0xC0, 0xFF);   // CALL !$FFC0 -> ret $FFC3
		int sp = push16(ram, 0xCF, 0xFFC3);
		assertTrue(SpcStackChain.recover(ram, 0xFFC8, sp, true).frames().isEmpty());
		assertEquals(1, SpcStackChain.recover(ram, 0xFFC8, sp, false).frames().size());
	}

	@Test
	public void tcallIsNotTrustedWhileTheIplIsMappedIn() {
		byte[] ram = ram();
		put(ram, 0x0500, 0x01);               // TCALL 0 -> table word at $FFDE
		put(ram, 0xFFDE, 0x00, 0x05);
		int sp = push16(ram, 0xCF, 0x0501);
		assertEquals(1, SpcStackChain.recover(ram, 0x0505, sp, false).frames().size());
		assertTrue(SpcStackChain.recover(ram, 0x0505, sp, true).frames().isEmpty());
	}

	@Test
	public void pushedRegistersBetweenFramesAreSkippedUpToTheLimit() {
		byte[] ram = ram();
		put(ram, 0x0500, 0x3F, 0x40, 0x05);   // outer: CALL !$0540 -> ret $0503
		put(ram, 0x0540, 0x3F, 0x80, 0x05);   // inner: CALL !$0580 -> ret $0543
		int sp = push16(ram, 0xCF, 0x0503);
		// The callee PUSHed two registers (A, X) before its own call.
		ram[0x100 + sp] = 0x11;
		ram[0x100 + sp - 1] = 0x22;
		sp -= 2;
		sp = push16(ram, sp, 0x0543);
		SpcStackChain.Result r = SpcStackChain.recover(ram, 0x0581, sp, false);
		assertEquals(2, r.frames().size());
		assertEquals(0, r.frames().get(0).skipped());
		assertEquals(2, r.frames().get(1).skipped());
		// Four junk bytes is past the limit.
		ram = ram();
		put(ram, 0x0500, 0x3F, 0x40, 0x05);
		put(ram, 0x0540, 0x3F, 0x80, 0x05);
		sp = push16(ram, 0xCF, 0x0503);
		sp -= SpcStackChain.MAX_SKIP + 1;
		sp = push16(ram, sp, 0x0543);
		assertEquals(1, SpcStackChain.recover(ram, 0x0581, sp, false).frames().size());
	}

	@Test
	public void emptyStackAndTopOfPageStop() {
		byte[] ram = ram();
		SpcStackChain.Result r = SpcStackChain.recover(ram, 0x0400, 0xFF, false);
		assertTrue(r.frames().isEmpty());
		assertEquals("reached the top of the stack page", r.stop());
		r = SpcStackChain.recover(ram, 0x0400, 0xCF, false);
		assertTrue(r.frames().isEmpty());
		assertTrue(r.stop().startsWith("no valid return address"));
	}

	@Test
	public void ff2TownShapePcOnBareRetStillYieldsTheCaller() {
		byte[] ram = ram();
		put(ram, 0x08A7, 0x3F, 0xE9, 0x10);   // CALL !$10E9 -> ret $08AA
		put(ram, 0x10ED, 0x6F);               // PC sits on a bare RET inside the callee
		int sp = push16(ram, 0xCF, 0x08AA);
		SpcStackChain.Result r = SpcStackChain.recover(ram, 0x10ED, sp, false);
		assertEquals(1, r.frames().size());
		assertEquals(0x08AA, r.frames().get(0).ret());
		assertEquals(0x10E9, r.frames().get(0).target());
	}
}
