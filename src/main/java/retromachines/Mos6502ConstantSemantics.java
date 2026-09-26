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

import java.util.Set;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

/**
 * {@link ConstantSemantics} for the NMOS 6502 family, as a table of OPERATIONS rather than of
 * (operation, addressing mode, register) triples (bead grm-as0m, design (a)).
 * <p>
 * Evaluated, each exactly and only when every input is exact:
 * <ul>
 * <li>{@code LDA/LDX/LDY} -- immediate, or a memory operand the scanner resolves;</li>
 * <li>{@code TAX/TAY/TXA/TYA}; {@code INX/INY/DEX/DEY};</li>
 * <li>{@code ASL/LSR/ROL/ROR} in accumulator form -- both A and the carry they shift out;</li>
 * <li>{@code AND/ORA/EOR} into A; {@code ADC/SBC} into A and carry;
 * {@code CMP/CPX/CPY} into carry -- each over an immediate or a resolvable memory operand;</li>
 * <li>{@code CLC/SEC}.</li>
 * </ul>
 * Everything else that writes a location declines. Before grm-as0m carry was modeled in one
 * place only, as the constant a {@code CLC}/{@code SEC} leaves, by a second backward walk that
 * duplicated every guard of the first; it is now just another location, so a shift or a
 * comparison between the {@code CLC} and the {@code ADC} yields the carry it computes instead
 * of ending the query.
 * <p>
 * <b>Binary mode is assumed for {@code ADC}/{@code SBC}</b>, exactly as the pre-grm-as0m
 * {@code ADC} branch assumed it. On NES (2A03, no decimal mode) that is the hardware; on the
 * C64 languages it is an assumption the D flag could violate, and it is the reason this table,
 * not the bundled language's p-code, is the default: that p-code branches on D, which is almost
 * never provably clear inside the walk's window, so a p-code evaluator would decline every
 * {@code ADC} there. The memory forms of the shifts and rotates decline for carry: they read a
 * byte that is, in practice, writable RAM this evaluator cannot pin.
 * <p>
 * <b>Why {@link #writes} is a UNION.</b> For A/X/Y it is the scanner's own modifier table
 * ({@link StoredValueScanner#modifiesRegister}) OR the instruction's p-code result objects; for
 * carry, anything outside {@link #CARRY_PRESERVING} OR p-code that writes {@code C}. Each half
 * alone has a hole: the modifier tables do not list the undocumented opcodes ({@code LAX}
 * writes A and X), and p-code is only as good as the language. Either one saying "writes" is
 * enough to make the walk stop, which can only turn an answer into a decline.
 */
final class Mos6502ConstantSemantics implements ConstantSemantics {

	static final Mos6502ConstantSemantics INSTANCE = new Mos6502ConstantSemantics();

	/**
	 * 6502 mnemonics that leave the carry flag exactly as they found it (bead grm-4bgh.2). An
	 * ALLOWLIST rather than a denylist of carry-writers: an unrecognized mnemonic -- an
	 * undocumented opcode, a spelling this table does not know -- must stop the walk, not be
	 * assumed inert. Absent on purpose, because they write carry: {@code ADC}/{@code SBC}, the
	 * comparisons, the shifts and rotates, {@code CLC}/{@code SEC} and {@code PLP} ({@code RTI}
	 * likewise, and it ends the walk as a flow break anyway). {@code PHP} and {@code PLA} ARE
	 * here -- they read the flags or write only N/Z.
	 */
	static final Set<String> CARRY_PRESERVING = Set.of("LDA", "LDX", "LDY", "STA", "STX", "STY",
		"TAX", "TAY", "TXA", "TYA", "TSX", "TXS", "PHA", "PHP", "PLA", "AND", "ORA", "EOR", "BIT",
		"INC", "DEC", "INX", "INY", "DEX", "DEY", "NOP", "CLD", "SED", "CLI", "SEI", "CLV");

	private Mos6502ConstantSemantics() {
	}

	@Override
	public boolean writes(Instruction instr, Loc loc) {
		if (loc == Loc.C) {
			return !CARRY_PRESERVING.contains(mnemonic(instr)) || pcodeWrites(instr, "C");
		}
		return StoredValueScanner.modifiesRegister(instr, loc.register()) ||
			pcodeWrites(instr, loc.name());
	}

	@Override
	public Integer after(Instruction instr, Loc loc, Inputs in) {
		String mnem = mnemonic(instr);
		switch (mnem) {
			case "CLC":
				return loc == Loc.C ? 0 : null;
			case "SEC":
				return loc == Loc.C ? 1 : null;
			case "LDA":
			case "LDX":
			case "LDY":
				return loc.register() == mnem.charAt(2) ? operand(instr, in) : null;
			case "TAX":
				return loc == Loc.X ? in.before(Loc.A) : null;
			case "TAY":
				return loc == Loc.Y ? in.before(Loc.A) : null;
			case "TXA":
				return loc == Loc.A ? in.before(Loc.X) : null;
			case "TYA":
				return loc == Loc.A ? in.before(Loc.Y) : null;
			case "INX":
				return loc == Loc.X ? plus(in.before(Loc.X), 1) : null;
			case "DEX":
				return loc == Loc.X ? plus(in.before(Loc.X), -1) : null;
			case "INY":
				return loc == Loc.Y ? plus(in.before(Loc.Y), 1) : null;
			case "DEY":
				return loc == Loc.Y ? plus(in.before(Loc.Y), -1) : null;
			case "ASL":
			case "LSR":
			case "ROL":
			case "ROR":
				return StoredValueScanner.isAccumulatorForm(instr) ? shift(mnem, loc, in) : null;
			case "AND":
			case "ORA":
			case "EOR":
				return loc == Loc.A ? logical(mnem, instr, in) : null;
			case "ADC":
			case "SBC":
				return arithmetic(mnem, instr, loc, in);
			case "CMP":
				return loc == Loc.C ? compare(instr, Loc.A, in) : null;
			case "CPX":
				return loc == Loc.C ? compare(instr, Loc.X, in) : null;
			case "CPY":
				return loc == Loc.C ? compare(instr, Loc.Y, in) : null;
			default:
				return null;
		}
	}

	/** The byte an immediate-or-memory operand supplies. */
	private static Integer operand(Instruction instr, Inputs in) {
		if (StoredValueScanner.isImmediate(instr)) {
			Integer imm = StoredValueScanner.immediateOperandValue(instr);
			return imm == null ? null : imm & 0xFF;
		}
		return in.memoryOperand();
	}

	private static Integer plus(Integer before, int delta) {
		return before == null ? null : (before + delta) & 0xFF;
	}

	/** Accumulator-form shift or rotate: the new A, or the bit shifted out into carry. */
	private static Integer shift(String mnem, Loc loc, Inputs in) {
		if (loc != Loc.A && loc != Loc.C) {
			return null;
		}
		Integer a = in.before(Loc.A);
		if (a == null) {
			return null;
		}
		boolean left = mnem.equals("ASL") || mnem.equals("ROL");
		if (loc == Loc.C) {
			return left ? (a >> 7) & 1 : a & 1;
		}
		int carryIn = 0;
		if (mnem.equals("ROL") || mnem.equals("ROR")) {
			Integer c = in.before(Loc.C);
			if (c == null) {
				return null;
			}
			carryIn = c;
		}
		return left ? ((a << 1) | carryIn) & 0xFF : ((a >> 1) | (carryIn << 7)) & 0xFF;
	}

	private static Integer logical(String mnem, Instruction instr, Inputs in) {
		Integer m = operand(instr, in);
		if (m == null) {
			return null;
		}
		Integer a = in.before(Loc.A);
		if (a == null) {
			return null;
		}
		return switch (mnem) {
			case "AND" -> a & m;
			case "ORA" -> (a | m) & 0xFF;
			default -> (a ^ m) & 0xFF;
		};
	}

	/**
	 * Binary-mode {@code ADC}/{@code SBC}: A is the byte sum, carry the carry-out -- for
	 * {@code SBC}, NOT-borrow. Inputs are asked in the pre-grm-as0m {@code ADC} order (operand,
	 * carry, A), which decides which query exhausts a shared budget first.
	 */
	private static Integer arithmetic(String mnem, Instruction instr, Loc loc, Inputs in) {
		if (loc != Loc.A && loc != Loc.C) {
			return null;
		}
		Integer m = operand(instr, in);
		if (m == null) {
			return null;
		}
		Integer c = in.before(Loc.C);
		if (c == null) {
			return null; // carry not established -- decline rather than guess a bit
		}
		Integer a = in.before(Loc.A);
		if (a == null) {
			return null;
		}
		int result = mnem.equals("ADC") ? a + m + c : a - m - (1 - c);
		if (loc == Loc.A) {
			return result & 0xFF;
		}
		return mnem.equals("ADC") ? (result > 0xFF ? 1 : 0) : (result >= 0 ? 1 : 0);
	}

	/** {@code CMP}/{@code CPX}/{@code CPY}: carry is set exactly when {@code reg >= operand}. */
	private static Integer compare(Instruction instr, Loc reg, Inputs in) {
		Integer m = operand(instr, in);
		if (m == null) {
			return null;
		}
		Integer r = in.before(reg);
		return r == null ? null : (r >= m ? 1 : 0);
	}

	private static String mnemonic(Instruction instr) {
		return instr.getMnemonicString().toUpperCase();
	}

	/**
	 * Whether the instruction's p-code writes any part of the register named {@code name} (or a
	 * register containing it). The 6502 languages define each flag as its own byte register, so
	 * {@code C} is not a slice of {@code P} there, but containment either way is the safe test.
	 */
	private static boolean pcodeWrites(Instruction instr, String name) {
		Register target = instr.getProgram().getRegister(name);
		if (target == null) {
			return false;
		}
		for (Object result : instr.getResultObjects()) {
			if (result instanceof Register r && (r.contains(target) || target.contains(r))) {
				return true;
			}
		}
		return false;
	}
}
