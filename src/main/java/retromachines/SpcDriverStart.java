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
 * Does an IPL stream's entry look like the start of a sound driver? (bead grm-1.7.7, rule 1.)
 *
 * <p>Every driver must program the DSP, so straight-line flow from the entry should reach a write
 * to the DSP address/data ports ({@code $F2}/{@code $F3}) or the control register ({@code $F1})
 * within a short budget. The walk is pure Java over the uploaded image: an SPC700 length table,
 * conditional branches fall through, {@code BRA}/{@code JMP !abs} are followed, {@code CALL}
 * enters the callee and {@code RET} comes back. {@code CLRP}/{@code SETP} are tracked so a
 * direct-page write only counts with P clear (P is clear at IPL hand-off). A write through an
 * index register ({@code dp+X}, {@code (X)}, {@code !abs+Y}...) is not resolved and does not count.
 *
 * <p>Fail closed: flow that leaves the uploaded bytes, halts ({@code BRK}/{@code STOP}/
 * {@code SLEEP}), or goes indirect ({@code TCALL}/{@code PCALL}/{@code JMP [!abs+X]}/
 * {@code RETI}/{@code RET} with nothing called) ends the walk without a hit.
 */
public final class SpcDriverStart {

	/** How a walk from the entry ended. */
	public enum Outcome {
		/** Reached a write to $F1-$F3. */
		DSP_WRITE,
		/** Ran out of instruction budget without one. */
		BUDGET,
		/** Flow reached a byte that was not uploaded. */
		LEFT_IMAGE,
		/** BRK, STOP or SLEEP. */
		HALTED,
		/** An indirect or table transfer the walk cannot follow. */
		INDIRECT
	}

	/** Instructions walked before giving up; see class doc. */
	public static final int BUDGET = 256;

	private static final int MAX_CALL_DEPTH = 8;

	/** Instruction length by opcode, one row of 16 per high nibble. */
	private static final String LENGTHS =
		"1123231223323131" + "2123233231221133" + "1123231223323132" + "2123233231221123" +
		"1123231223323132" + "2123233231221133" + "1123231223323131" + "2123233231221121" +
		"1123231223323213" + "2123233231221111" + "1123231223323211" + "2123233231221111" +
		"1123231223323211" + "2123233222221131" + "1123231223323111" + "2123233222321121";

	private SpcDriverStart() {
	}

	/**
	 * The instruction length of an opcode (checked against SLEIGH by Spc700LanguageTest).
	 *
	 * @param opcode an SPC700 opcode byte
	 * @return its instruction length in bytes
	 */
	public static int length(int opcode) {
		return LENGTHS.charAt(opcode & 0xFF) - '0';
	}

	/**
	 * Walks straight-line flow from the stream's entry over its uploaded bytes.
	 *
	 * @param s a parsed stream
	 * @return how the walk ended
	 */
	public static Outcome walk(SpcIplFormat.Stream s) {
		byte[] ram = new byte[SpcIplFormat.APU_RAM_SIZE];
		boolean[] up = new boolean[SpcIplFormat.APU_RAM_SIZE];
		for (SpcIplFormat.Block b : s.blocks()) {
			byte[] d = b.data();
			for (int i = 0; i < d.length; i++) {
				int a = (b.addr() + i) & 0xFFFF;
				ram[a] = d[i];
				up[a] = true;
			}
		}
		int[] stack = new int[MAX_CALL_DEPTH];
		int depth = 0;
		boolean p = false;
		int pc = s.entry();
		for (int n = 0; n < BUDGET; n++) {
			int op = ram[pc] & 0xFF;
			int len = length(op);
			for (int i = 0; i < len; i++) {
				if (!up[(pc + i) & 0xFFFF]) {
					return Outcome.LEFT_IMAGE;
				}
			}
			int b1 = ram[(pc + 1) & 0xFFFF] & 0xFF;
			int b2 = ram[(pc + 2) & 0xFFFF] & 0xFF;
			if (writesDsp(op, b1, b2, p)) {
				return Outcome.DSP_WRITE;
			}
			int next = (pc + len) & 0xFFFF;
			switch (op) {
				case 0x0F, 0xEF, 0xFF -> {
					return Outcome.HALTED;
				}
				case 0x1F, 0x4F, 0x7F -> {
					return Outcome.INDIRECT;
				}
				case 0x20 -> p = false;
				case 0x40 -> p = true;
				case 0x2F -> next = (next + (byte) b1) & 0xFFFF;
				case 0x5F -> next = b1 | b2 << 8;
				case 0x3F -> {
					if (depth == MAX_CALL_DEPTH) {
						return Outcome.INDIRECT;
					}
					stack[depth++] = next;
					next = b1 | b2 << 8;
				}
				case 0x6F -> {
					if (depth == 0) {
						return Outcome.INDIRECT;
					}
					next = stack[--depth];
				}
				default -> {
					if ((op & 0x0F) == 0x01) {
						return Outcome.INDIRECT; // TCALL n
					}
				}
			}
			pc = next;
		}
		return Outcome.BUDGET;
	}

	/** Whether this instruction writes $F1-$F3 through a direct or absolute operand. */
	static boolean writesDsp(int op, int b1, int b2, boolean p) {
		switch (op) {
			// dp destination in the first operand byte
			case 0xC4, 0xD8, 0xCB, 0x0B, 0x2B, 0x4B, 0x6B, 0x8B, 0xAB:
				return !p && port(b1);
			// word writes of dp and dp+1
			case 0xDA, 0x1A, 0x3A:
				return !p && (port(b1) || port(b1 + 1));
			// dp destination in the second operand byte (op #imm,dp / op src,dst)
			case 0x8F, 0xFA, 0x18, 0x38, 0x58, 0x98, 0xB8, 0x09, 0x29, 0x49, 0x89, 0xA9:
				return !p && port(b2);
			// absolute destination
			case 0xC5, 0xC9, 0xCC, 0x0C, 0x2C, 0x4C, 0x6C, 0x8C, 0xAC, 0x0E, 0x4E:
				return port(b1 | b2 << 8);
			default:
				// SET1/CLR1 dp.bit
				return (op & 0x0F) == 0x02 && !p && port(b1);
		}
	}

	private static boolean port(int a) {
		return a >= 0xF1 && a <= 0xF3;
	}
}
