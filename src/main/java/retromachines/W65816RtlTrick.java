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
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Recognizer for grm-gipk.14: the 65816 "RTL trick", the three-byte sibling of
 * {@link W65816RtsTrick}. A routine pushes a bank byte (8-bit {@code PHA}), then a 16-bit word
 * (16-bit {@code PHA}) and {@code RTL}s: RTL pops the word, adds one, and takes the pushed bank, so
 * the target is {@code bank:(word + 1 - k)} ({@code DEC A} k times before the word push makes it
 * exact). The bank comes from the table too, so each record names a full 24-bit target.
 *
 * <p><b>The shape.</b> An {@code RTL} whose straight-line predecessors (at most
 * {@link #MAX_WINDOW}) are
 * <pre>
 *   LDA bank,R / PHA / [REP|SEP]* / LDA word,R / DEC A * k / PHA / noise / RTL
 * </pre>
 * with the same index register and operand form for both loads (abs,X abs,Y or long,X). The bank
 * load and its push run at M=1, the word load and its push at M=0, E=0. The two operands are one
 * record apart: word = bank + 1 is a bank-first record {@code [bank, lo, hi]}, word = bank - 2 a
 * word-first one {@code [lo, hi, bank]} (real sites: Faceball 2000 is bank-first; ABC Monday Night
 * Football, Tetris 2, Yoshi's Cookie, Casper, Home Improvement and Urban Strike are word-first). The
 * record stride (3 or 4) is not in the code; the analyzer ranks both.
 *
 * <p>Between the bank push and the word load only {@code REP}/{@code SEP} may sit; after the word
 * push, anything that leaves the stack alone is noise. Joins and RAM tables are declined exactly as
 * {@link W65816RtsTrick} does: a non-fallthrough flow into anything after the bank load up to and
 * including the word push; abs operands below {@code $8000}, long operands below {@code $8000} or
 * in bank {@code $7E}/{@code $7F}. An abs operand is taken in the {@code RTL}'s bank.
 *
 * <p>Out of scope: a 16-bit load before the {@code SEP} (the bank is a word's low byte), a
 * {@code PHA/PLB} bank, RAM tables and the call-like {@code PHK/PEA} forms.
 *
 * @see W65816RtlTrickAnalyzer
 */
final class W65816RtlTrick {

	/** How many instructions before the {@code RTL} the straight-line window may span. */
	static final int MAX_WINDOW = 14;

	/** Stack-touching (or stack-moving, or calling) mnemonics: never noise after the push. */
	private static final Set<String> NOT_NOISE = Set.of("PHA", "PHX", "PHY", "PHB", "PHD", "PHK",
		"PHP", "PEA", "PEI", "PER", "PLA", "PLX", "PLY", "PLB", "PLD", "PLP", "TCS", "TXS", "JSR",
		"JSL", "RTI", "BRK", "COP");

	private static final int PHA = 0x48;
	private static final int DEC_A = 0x3a;
	private static final int LDA_ABS_X = 0xbd;
	private static final int LDA_ABS_Y = 0xb9;
	private static final int LDA_LONG_X = 0xbf;

	private W65816RtlTrick() {
	}

	/**
	 * A recognized dispatch.
	 *
	 * @param rtl the return
	 * @param table record 0's first byte (24-bit)
	 * @param bankFirst records are {@code [bank, lo, hi]}, else {@code [lo, hi, bank]}
	 * @param bias added to each word to get the target offset ({@code 1 - k})
	 * @param indexMax the largest index value the index register can hold
	 * @param own the dispatch's own instructions (loads and the return), for reference tests
	 */
	record Shape(Address rtl, Address table, boolean bankFirst, int bias, int indexMax,
			List<Address> own) {
	}

	/** The shape ending at {@code rtl}, or null when it is not conclusively this idiom. */
	static Shape recognize(Program program, Instruction rtl) {
		if (!"RTL".equals(rtl.getMnemonicString()) || opcode(rtl) != 0x6b) {
			return null;
		}
		Listing listing = program.getListing();
		ArrayDeque<Instruction> seq = new ArrayDeque<>();
		seq.add(rtl);
		Instruction cur = rtl;
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
		if (i < 3 || w[i].getLength() != 1 || flag(w[i], "ctx_EF") != 0 ||
			flag(w[i], "ctx_MF") != 0) {
			return null;
		}
		int wordPha = i;
		int k = 0;
		int j = i - 1;
		while (j >= 0 && opcode(w[j]) == DEC_A && w[j].getLength() == 1) {
			k++;
			j--;
		}
		if (j < 0) {
			return null;
		}
		Instruction wordLoad = w[j];
		int op = opcode(wordLoad);
		boolean isLong = op == LDA_LONG_X;
		if (!(op == LDA_ABS_X || op == LDA_ABS_Y || isLong) ||
			wordLoad.getLength() != (isLong ? 4 : 3) || flag(wordLoad, "ctx_MF") != 0) {
			return null;
		}
		j--;
		while (j >= 0 && (w[j].getMnemonicString().equalsIgnoreCase("REP") ||
			w[j].getMnemonicString().equalsIgnoreCase("SEP"))) {
			j--;
		}
		if (j < 1 || opcode(w[j]) != PHA || w[j].getLength() != 1 || flag(w[j], "ctx_MF") != 1 ||
			flag(w[j], "ctx_EF") != 0) {
			return null;
		}
		int bankLoadIdx = j - 1;
		Instruction bankLoad = w[bankLoadIdx];
		if (opcode(bankLoad) != op || bankLoad.getLength() != wordLoad.getLength() ||
			flag(bankLoad, "ctx_MF") != 1) {
			return null;
		}
		long bankOperand = operand(bankLoad, isLong);
		long wordOperand = operand(wordLoad, isLong);
		if (bankOperand < 0 || wordOperand < 0 ||
			(isLong && (bankOperand & 0xff0000L) != (wordOperand & 0xff0000L))) {
			return null;
		}
		long lowB = bankOperand & 0xffff;
		long lowW = wordOperand & 0xffff;
		if (lowB < 0x8000 || lowW < 0x8000) {
			return null;   // RAM or I/O table
		}
		long bank = isLong ? bankOperand & 0xff0000L : rtl.getMinAddress().getOffset() & 0xff0000L;
		if (isLong && (bank == 0x7e0000L || bank == 0x7f0000L)) {
			return null;
		}
		boolean bankFirst;
		if (lowW - lowB == 1) {
			bankFirst = true;
		}
		else if (lowW - lowB == -2) {
			bankFirst = false;
		}
		else {
			return null;
		}
		for (int m = bankLoadIdx + 1; m <= wordPha; m++) {
			if (RtsTrickDispatch.hasNonFallThroughFlowInto(program, w[m].getMinAddress())) {
				return null;
			}
		}
		Address table = rtl.getMinAddress().getNewAddress(bank | Math.min(lowB, lowW));
		int indexMax = flag(wordLoad, "ctx_XF") == 1 ? 0xff : 0xffff;   // X and Y share the flag
		return new Shape(rtl.getMinAddress(), table, bankFirst, 1 - k, indexMax,
			List.of(rtl.getMinAddress(), bankLoad.getMinAddress(), wordLoad.getMinAddress()));
	}

	/** The flag's value at {@code in}, or -1 when unknown. */
	private static int flag(Instruction in, String reg) {
		Register r = in.getProgram().getRegister(reg);
		BigInteger v = r == null ? null : in.getValue(r, false);
		return v == null ? -1 : v.intValue();
	}

	private static long operand(Instruction load, boolean isLong) {
		try {
			return (load.getByte(1) & 0xff) | ((load.getByte(2) & 0xff) << 8) |
				(isLong ? (long) (load.getByte(3) & 0xff) << 16 : 0);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
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
