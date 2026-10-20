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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

/**
 * Stateless 6502 operand and register-effect helpers: which register a store targets, whether an
 * operand is immediate or a plain absolute address, and which mnemonics write or read a register.
 * Extracted from {@link StoredValueScanner} (bead grm-rx1i.9) because every bank-switch strategy
 * and the recovery passes use them; they carry no scanner state.
 */
final class MosOperands {

	private MosOperands() {
	}

	private static final Set<String> A_MODIFIERS = Set.of("LDA", "TXA", "TYA", "PLA", "ADC", "SBC",
		"AND", "ORA", "EOR", "ASL", "LSR", "ROL", "ROR");
	private static final Set<String> X_MODIFIERS = Set.of("LDX", "TAX", "TSX", "INX", "DEX");
	private static final Set<String> Y_MODIFIERS = Set.of("LDY", "TAY", "INY", "DEY");

	/**
	 * Whether {@code instr} uses the accumulator addressing mode ({@code ASL A} and friends)
	 * rather than a memory operand -- the {@code bbb = 2}, {@code cc = 2} column, i.e.
	 * {@code (op & 0x1f) == 0x0A}. Callers gate on the mnemonic first, so the other
	 * instructions in that column (e.g. {@code TAX}, {@code NOP}) never reach here.
	 */
	static boolean isAccumulatorForm(Instruction instr) {
		try {
			return (instr.getByte(0) & 0x1F) == 0x0A;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	// ------------------------------------------------------------------
	// Operand helpers shared by store-recognizing strategies
	// ------------------------------------------------------------------

	/**
	 * The register a 6502 store targets -- {@code 'A'}, {@code 'X'}, or {@code 'Y'} for
	 * {@code STA}/{@code STX}/{@code STY} -- or {@code null} for any other mnemonic. In
	 * particular the read-modify-write stores ({@code INC}/{@code DEC}/{@code ASL}/
	 * {@code LSR}/{@code ROL}/{@code ROR}) return {@code null}: they mutate the target in
	 * place and this scanner does not model the resulting value.
	 */
	static Character storeRegister(Instruction instr) {
		String mnem = instr.getMnemonicString().toUpperCase();
		if (mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY")) {
			return mnem.charAt(2); // 'A' | 'X' | 'Y'
		}
		return null;
	}

	static boolean writesAddress(Instruction instr, Address addr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(addr) && ref.getReferenceType().isWrite()) {
				return true;
			}
		}
		return false;
	}

	static boolean readsAddress(Instruction instr, Address addr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(addr) && ref.getReferenceType().isRead()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether {@code instr} writes {@code reg} (e.g. {@code STA PORT} on the bundled 6510
	 * language, where the on-die $01 port is a register, not a memory address). Used
	 * alongside {@link #writesAddress} so a mechanism modeled as a CPU register is detected
	 * the same way as one modeled as a memory-mapped address.
	 */
	static boolean writesRegister(Instruction instr, Register reg) {
		for (Object o : instr.getResultObjects()) {
			if (o instanceof Register r && r.equals(reg)) {
				return true;
			}
		}
		return false;
	}

	/** Whether {@code instr} reads {@code reg} (e.g. {@code LDA PORT}); see {@link #writesRegister}. */
	static boolean readsRegister(Instruction instr, Register reg) {
		for (Object o : instr.getInputObjects()) {
			if (o instanceof Register r && r.equals(reg)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether {@code instr} writes {@code reg}, by the same mnemonic sets this scanner's own
	 * backward walks stop on. Exposed for {@link BankMirrors}' discovery walks (grm-mej.2), which
	 * are structurally the same walk asking a different question and must agree with these on
	 * what clobbers a register -- a discovery pass that walked past a modifier this scanner stops
	 * at would nominate a cell the scanner can then never resolve through.
	 * <p>
	 * A call is deliberately NOT covered: {@code JSR} modifies every register but is not in any
	 * modifier set, so every walk tests {@code getFlowType().isCall()} separately.
	 */
	static boolean modifiesRegister(Instruction instr, char reg) {
		return modifiesRegister(registerModifiers(reg), instr.getMnemonicString().toUpperCase(),
			instr);
	}

	/**
	 * Whether {@code mnem} (already upper-cased, from {@code instr}) is in {@code modifiers}
	 * AND actually writes the register. ASL/LSR/ROL/ROR are in {@link #A_MODIFIERS} by
	 * mnemonic but only write A in accumulator form; {@code ROR $F0} rotates memory and leaves A
	 * alone (grm-jmsm: tmnt's {@code STA $21 / SEC / ROR $F0 / STA $FFFF} helper bodies).
	 */
	static boolean modifiesRegister(Set<String> modifiers, String mnem,
			Instruction instr) {
		if (!modifiers.contains(mnem)) {
			return false;
		}
		return !SHIFT_MNEMONICS.contains(mnem) || isAccumulatorForm(instr);
	}

	private static final Set<String> SHIFT_MNEMONICS = Set.of("ASL", "LSR", "ROL", "ROR");

	static Set<String> registerModifiers(char reg) {
		return switch (reg) {
			case 'A' -> A_MODIFIERS;
			case 'X' -> X_MODIFIERS;
			case 'Y' -> Y_MODIFIERS;
			default -> Set.of();
		};
	}

	static boolean isImmediate(Instruction instr) {
		String rep = instr.getDefaultOperandRepresentation(0);
		return rep != null && rep.startsWith("#");
	}

	/**
	 * Extracts the constant value of an immediate operand (e.g. the {@code $35} in
	 * {@code LDA #$35}). {@link ghidra.program.model.listing.CodeUnit#getScalar} only
	 * resolves scalars used as addressing components, not bare immediate operands, so we
	 * pull the {@link Scalar} directly out of the operand's object list instead.
	 */
	static Integer immediateOperandValue(Instruction instr) {
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Scalar s) {
				return (int) s.getUnsignedValue();
			}
		}
		return null;
	}

	/**
	 * The single constant memory address an operand names, or {@code null} when the
	 * operand is indexed/indirect (any register participates) or names no address --
	 * i.e. non-null exactly for plain absolute/zero-page addressing, where the target
	 * is statically certain.
	 * <p>
	 * Still the right predicate wherever "is this operand unindexed?" is the actual question
	 * (the {@code addr_mask} decode ruling, {@code JMP} target extraction). Where the question
	 * is "which address does this access reach?", prefer {@link StoredValueScanner#effectiveOperandTarget}, which
	 * answers this and additionally resolves an absolute-indexed operand with a constant index.
	 */
	static Address plainAbsoluteTarget(Instruction instr) {
		Address addr = null;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof ghidra.program.model.lang.Register) {
				return null; // indexed -- runtime-dependent target
			}
			if (obj instanceof Address a) {
				if (addr != null) {
					return null;
				}
				addr = a;
			}
		}
		return addr;
	}
}
