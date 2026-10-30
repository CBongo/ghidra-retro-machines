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

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Recognizer for grm-gipk.11: the 65816 "RTS trick". A routine loads a 16-bit word from a table,
 * pushes it as ONE word with {@code PHA} (accumulator 16-bit) and {@code RTS}es into it. The 65816
 * {@code RTS} pops a 16-bit word and resumes at word + 1 in its own program bank, so the table
 * normally holds target - 1 ({@code DEC A} before the push makes it exact). Stock Ghidra treats
 * {@code RTS} as a return, so the targets are never disassembled. This is the 65816 counterpart of
 * {@link RtsTrickDispatch}, which cannot run here (its analyzer is gated to 8-bit address spaces).
 *
 * <p><b>The shape.</b> An {@code RTS} whose straight-line predecessors (at most {@link #MAX_WINDOW})
 * are
 * <pre>
 *   LDA table,R / DEC A * k / PHA / noise / RTS      (R is X or Y; abs or long operand)
 * </pre>
 * The target is {@code word + 1 - k}. Real instances (a 776-ROM SNES sweep): Wolf3D c020d6 (inline
 * table right after the {@code RTS}), Super Widget, Urban Strike ({@code DEC A}, exact targets),
 * Madden 96 and Timecop (noise such as {@code LDX} after the {@code PHA}), TMNT ({@code abs,Y}),
 * Madden 97 c191d7, Road Riot ({@code REP/SEP} noise), and the call-like family where an earlier
 * {@code PEA} pushed a return address, which is irrelevant to where this {@code RTS} goes.
 *
 * <p>After the {@code PHA}, any straight-line instruction that leaves the stack alone is noise; the
 * first stack instruction found walking back must be the {@code PHA}, and anything that pushes,
 * pulls, moves the stack pointer or calls declines the site. The {@code PHA} must be 16-bit
 * ({@code ctx_MF == 0}, {@code ctx_EF == 0}). The load must be at M=0 as well. Nothing but
 * {@code DEC A} may sit between load and push.
 *
 * <p><b>Joins.</b> A non-fallthrough flow into any instruction after the load up to and including
 * the {@code PHA} declines the site (a different {@code A} would arrive). A join on the load itself
 * or after the push, the {@code RTS} included, does not, for the reason given on
 * {@link RtsTrickDispatch}.
 *
 * <p><b>The table.</b> A long operand names its 24-bit address; an abs operand is taken in the
 * {@code RTS}'s bank (DBR is assumed equal to PBR, as in
 * {@link W65816JumpTableAnalyzer}'s load handling). RAM tables are declined: abs operands below
 * {@code $8000}, long operands whose low 16 bits are below {@code $8000} or whose bank is
 * {@code $7E}/{@code $7F}. Targets are in the {@code RTS}'s bank. The bound is
 * {@link W65816JumpTables#bound}, fed the biased word.
 *
 * <p>Out of scope: {@code RTL} forms, M=1 two-byte pushes, dynamic loads ({@code (dp),Y},
 * {@code [dp],Y}).
 *
 * @see W65816RtsTrickAnalyzer
 */
final class W65816RtsTrick {

	/** How many instructions before the {@code RTS} the straight-line window may span. */
	static final int MAX_WINDOW = 12;

	/** Stack-touching (or stack-moving, or calling) mnemonics: never noise after the push. */
	private static final Set<String> NOT_NOISE = Set.of("PHA", "PHX", "PHY", "PHB", "PHD", "PHK",
		"PHP", "PEA", "PEI", "PER", "PLA", "PLX", "PLY", "PLB", "PLD", "PLP", "TCS", "TXS", "JSR",
		"JSL", "RTI", "BRK", "COP");

	private static final int PHA = 0x48;
	private static final int DEC_A = 0x3a;
	private static final int LDA_ABS_X = 0xbd;
	private static final int LDA_ABS_Y = 0xb9;
	private static final int LDA_LONG_X = 0xbf;

	private W65816RtsTrick() {
	}

	/**
	 * A recognized dispatch: the table's first byte (24-bit), the bias added to each word, and the
	 * most entries the index reaches.
	 */
	record Shape(Address rts, Address table, int bias, int cap) {
	}

	/** The shape ending at {@code rts}, or null when it is not conclusively this idiom. */
	static Shape recognize(Program program, Instruction rts) {
		if (!"RTS".equals(rts.getMnemonicString()) || opcode(rts) != 0x60) {
			return null;
		}
		Listing listing = program.getListing();
		ArrayDeque<Instruction> seq = new ArrayDeque<>();
		seq.add(rts);
		Instruction cur = rts;
		for (int n = 0; n < MAX_WINDOW; n++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough()) ||
				!RtsTrickDispatch.isStraight(prev)) {
				break;
			}
			seq.addFirst(prev);
			cur = prev;
		}
		Instruction[] w = seq.toArray(new Instruction[0]);

		int i = w.length - 2;
		while (i >= 0 && opcode(w[i]) != PHA) {
			if (NOT_NOISE.contains(w[i].getMnemonicString())) {
				return null;
			}
			i--;
		}
		if (i < 1 || w[i].getLength() != 1 || !flagIsZero(w[i], "ctx_EF") ||
			!flagIsZero(w[i], "ctx_MF")) {
			return null;
		}
		int pha = i;
		int k = 0;
		i--;
		while (i >= 1 && opcode(w[i]) == DEC_A && w[i].getLength() == 1) {
			k++;
			i--;
		}
		if (i < 0) {
			return null;
		}
		Instruction load = w[i];
		int op = opcode(load);
		boolean isLong = op == LDA_LONG_X;
		if (!(op == LDA_ABS_X || op == LDA_ABS_Y || isLong) ||
			load.getLength() != (isLong ? 4 : 3) || !flagIsZero(load, "ctx_MF")) {
			return null;
		}
		long operand;
		try {
			operand = (load.getByte(1) & 0xff) | ((load.getByte(2) & 0xff) << 8) |
				(isLong ? (long) (load.getByte(3) & 0xff) << 16 : 0);
		}
		catch (MemoryAccessException e) {
			return null;
		}
		if ((operand & 0xffff) < 0x8000) {
			return null;   // RAM or I/O table
		}
		long bank = isLong ? operand & 0xff0000L : rts.getMinAddress().getOffset() & 0xff0000L;
		if (isLong && (bank == 0x7e0000L || bank == 0x7f0000L)) {
			return null;
		}
		for (int j = i + 1; j <= pha; j++) {
			if (RtsTrickDispatch.hasNonFallThroughFlowInto(program, w[j].getMinAddress())) {
				return null;
			}
		}
		Address table = rts.getMinAddress().getNewAddress(bank | (operand & 0xffff));
		int cap;
		if (op == LDA_LONG_X || op == LDA_ABS_X) {
			cap = W65816JumpTableAnalyzer.indexCap(listing, load);
		}
		else {
			BigInteger xf = load.getValue(program.getRegister("ctx_XF"), false);
			cap = xf != null && xf.intValue() == 1 ? 128 : W65816JumpTables.MAX_ENTRIES;
		}
		return new Shape(rts.getMinAddress(), table, 1 - k, cap);
	}

	private static boolean flagIsZero(Instruction in, String reg) {
		Register r = in.getProgram().getRegister(reg);
		BigInteger v = r == null ? null : in.getValue(r, false);
		return v != null && v.intValue() == 0;
	}

	private static int opcode(Instruction instr) {
		try {
			return instr.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}
}
