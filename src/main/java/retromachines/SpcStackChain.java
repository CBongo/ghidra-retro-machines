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
 * Recovers the live call chain of an SPC700 sound-state snapshot from its stack page, bead
 * grm-c9d.9. Pure: it reads a 64 KiB RAM image and the captured {@code PC}/{@code SP}, nothing else.
 *
 * <p>A snapshot's header PC is wherever the CPU happened to be (often a bare {@code RET} deep in a
 * routine), but the stack page is captured whole, and the bytes above {@code SP} are the return
 * addresses of every call in flight. Verified against the vendored language
 * ({@code spc700ops.sinc}, {@code spc700core.sinc}), not assumed:
 * <ul>
 * <li>{@code CALL}, {@code PCALL}, {@code TCALL} and {@code BRK} all {@code push16(inst_next)}, and
 * {@code push16} writes the HIGH byte first at the current SP, then the LOW byte one below, with
 * SP walking down. So after a call, {@code [$0100+SP+1]} is the return address's low byte and
 * {@code [$0100+SP+2]} its high byte: frames are little-endian words, innermost first, walking
 * UP the stack page. The return address is {@code inst_next}: the byte after the call
 * instruction, i.e. {@code callAt+3} for {@code CALL !abs} ({@code 3F}), {@code callAt+2} for
 * {@code PCALL u} ({@code 4F}), {@code callAt+1} for {@code TCALL n} ({@code n1}).</li>
 * <li>The call targets are: {@code CALL} the operand; {@code PCALL} {@code $FF00+operand} (the
 * language's {@code call [ptr]} with {@code ptr=0xFF00+imm} is the address itself, not a
 * dereference); {@code TCALL n} the WORD at {@code $FFE0-2*(n+1)} (a dereference).</li>
 * <li>{@code BRK} pushes PSW after the return address and is not walked (a sound driver does not
 * use it; the language models a vector at {@code $FFDE}, shared with {@code TCALL 0}).</li>
 * </ul>
 *
 * <p>A candidate return address is accepted only if (a) it and the call instruction before it are
 * ordinary RAM: not the zero-page/stack/I-O holes and not {@code $FFC0+} when the IPL is mapped in;
 * (b) the bytes before it decode as one of the three call forms; and (c) that call's target lies
 * at or below the next-inner frame's call site (or the PC for the innermost) within
 * {@link #MAX_SPAN}, i.e. the callee plausibly contains the inner frame. The walk stops at the
 * first slot where no candidate passes, or at the top of the stack page. A driver's
 * {@code PUSH A/X/Y/PSW} between frames shifts the next word up; up to {@link #MAX_SKIP} bytes of
 * such pushes are skipped, and counted, before giving up.
 *
 * <p>Not recoverable here, by design: a frame whose callee dispatches by an indirect jump to far
 * away code breaks rule (c) and ends the chain early (reported, not guessed), and a {@code TCALL}
 * while the IPL is mapped in (the table then lives in ROM the snapshot does not carry).
 */
public final class SpcStackChain {
	private SpcStackChain() {
	}

	/** The three call forms that push a return address. */
	public enum Kind {
		/** {@code CALL !abs}. */
		CALL,
		/** {@code PCALL u}. */
		PCALL,
		/** {@code TCALL n}. */
		TCALL
	}

	/**
	 * One recovered stack frame.
	 *
	 * @param slot stack-page offset (0-$FF) of the return address's low byte
	 * @param ret the return address
	 * @param callAt address of the call instruction
	 * @param kind which call form it is
	 * @param target the call's target address
	 * @param skipped bytes of pushed registers skipped to reach this frame
	 */
	public record Frame(int slot, int ret, int callAt, Kind kind, int target, int skipped) {
	}

	/**
	 * The walk's outcome.
	 *
	 * @param frames the frames, innermost first (empty when the stack holds none)
	 * @param endSlot the stack-page offset where the walk stopped
	 * @param stop why it stopped
	 */
	public record Result(List<Frame> frames, int endSlot, String stop) {
	}

	/** Most bytes of pushed registers tolerated between two frames. */
	public static final int MAX_SKIP = 3;

	/** Largest distance from a call's target to the inner frame's call site. */
	public static final int MAX_SPAN = 0x1000;

	private static final int STACK = 0x0100;

	/**
	 * Walks the stack.
	 *
	 * @param ram the 64 KiB RAM image
	 * @param pc the captured program counter
	 * @param sp the captured stack pointer (the next FREE slot)
	 * @param iplMapped whether CONTROL bit 7 maps the IPL ROM over {@code $FFC0-$FFFF}
	 * @return the recovered chain
	 */
	public static Result recover(byte[] ram, int pc, int sp, boolean iplMapped) {
		List<Frame> frames = new ArrayList<>();
		int slot = (sp & 0xFF) + 1;
		int inner = pc;
		while (true) {
			Frame found = null;
			boolean room = false;
			for (int skip = 0; skip <= MAX_SKIP && found == null; skip++) {
				int s = slot + skip;
				if (s + 1 > 0xFF) {
					break;
				}
				room = true;
				int ret = u8(ram, STACK + s) | (u8(ram, STACK + s + 1) << 8);
				found = classify(ram, s, ret, inner, skip, iplMapped);
			}
			if (found == null) {
				String why = room ? String.format("no valid return address at $01%02X", slot)
						: "reached the top of the stack page";
				return new Result(frames, slot, why);
			}
			frames.add(found);
			slot = found.slot() + 2;
			inner = found.callAt();
		}
	}

	private static Frame classify(byte[] ram, int slot, int ret, int inner, int skip,
			boolean ipl) {
		if (!ok(ret, ipl) || !ok(ret - 1, ipl)) {
			return null;
		}
		int at = ret - 3;
		if (at >= 0 && ok(at, ipl) && u8(ram, at) == 0x3F) {
			int target = u8(ram, at + 1) | (u8(ram, at + 2) << 8);
			if (consistent(target, inner, ipl)) {
				return new Frame(slot, ret, at, Kind.CALL, target, skip);
			}
		}
		at = ret - 2;
		if (at >= 0 && ok(at, ipl) && u8(ram, at) == 0x4F) {
			int target = 0xFF00 + u8(ram, at + 1);
			if (consistent(target, inner, ipl)) {
				return new Frame(slot, ret, at, Kind.PCALL, target, skip);
			}
		}
		at = ret - 1;
		if (!ipl && ok(at, ipl) && (u8(ram, at) & 0x0F) == 0x01) {
			int ptr = 0xFFE0 - 2 * ((u8(ram, at) >> 4) + 1);
			int target = u8(ram, ptr) | (u8(ram, ptr + 1) << 8);
			if (consistent(target, inner, ipl)) {
				return new Frame(slot, ret, at, Kind.TCALL, target, skip);
			}
		}
		return null;
	}

	private static boolean consistent(int target, int inner, boolean ipl) {
		return ok(target, ipl) && target <= inner && inner - target <= MAX_SPAN;
	}

	/** Ordinary RAM a driver's code can live in: not the I/O page, the stack page, or IPL ROM. */
	private static boolean ok(int a, boolean ipl) {
		if (a < 0x0002 || a > 0xFFFF) {
			return false;
		}
		if (a < 0x00F0) {
			return true;
		}
		return a >= 0x0200 && (!ipl || a < 0xFFC0);
	}

	private static int u8(byte[] ram, int a) {
		return ram[a] & 0xFF;
	}
}
