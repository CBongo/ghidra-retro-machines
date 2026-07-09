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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

/**
 * The 6502-family backward "mask algebra" scan shared by the store-recognizing
 * {@link BankSwitchStrategy} implementations: given a {@code ST<reg>} instruction,
 * determine (with per-bit confidence) the value it stores.
 * <p>
 * Walking backward from the store within its straight-line basic block, we maintain
 * {@code (aAcc, oAcc)} such that the stored value equals {@code (x & aAcc) | oAcc},
 * where {@code x} is the register's value before the earliest instruction examined so
 * far. Stepping back over:
 * <ul>
 * <li>{@code AND #imm} (register A only) composes {@code aAcc = imm & aAcc}.</li>
 * <li>{@code ORA #imm} (register A only) composes {@code oAcc = (imm & aAcc) | oAcc}.</li>
 * <li>{@code LDA/LDX/LDY #imm} into the matching register fully resolves {@code x}, so
 * the scan folds it through the accumulator and stops.</li>
 * <li>A non-immediate {@code LD<reg>} is offered to the strategy's
 * {@link Hooks#resolveLoad} (register-write resolves a read-back of its own mechanism
 * register to the tracked in-state; memory-latch resolves a plain absolute load of a
 * bank-invariant ROM byte to that byte); an unresolved load leaves {@code x} wholly
 * unknown.</li>
 * <li>Any other instruction that modifies the register (transfers, ADC/SBC, shifts,
 * INC/DEC, EOR#imm -- deliberately not modeled bit-wise) leaves {@code x} wholly
 * unknown from that point backward.</li>
 * <li>A mechanism write encountered mid-scan ({@link Hooks#isMechanismWrite}) means the
 * mechanism changed mid-chain: a base value read further back would predate that write,
 * so falling back to the in-state (which reflects state <em>after</em> it) would be
 * unsound. The scan aborts to a wholly-unknown base.</li>
 * <li>A subroutine call may clobber any register; its fall-through satisfies the
 * block-linkage check, so it is treated as a clobber explicitly.</li>
 * </ul>
 * The mnemonic tables are 6502-family, which covers every board strategy currently
 * shipped (C64 register-write, NES memory-latch); other CPU families will parameterize
 * the tables when they arrive rather than speculatively now.
 */
final class StoredValueScanner {

	/** Strategy-specific behavior injected into the shared scan. */
	interface Hooks {

		/** Whether this instruction writes the strategy's mechanism (mid-scan abort). */
		boolean isMechanismWrite(Instruction instr);

		/**
		 * Resolves the base value loaded by a non-immediate {@code LD<reg>} the strategy
		 * understands, or {@code null} to treat the load as an opaque register clobber.
		 */
		BankState resolveLoad(Instruction loadInstr, BankState inStateAtStore);
	}

	private static final int MAX_BACKWARD_SCAN = 16;

	private static final Set<String> A_MODIFIERS = Set.of("LDA", "TXA", "TYA", "PLA", "ADC", "SBC",
		"AND", "ORA", "EOR", "ASL", "LSR", "ROL", "ROR");
	private static final Set<String> X_MODIFIERS = Set.of("LDX", "TAX", "TSX", "INX", "DEX");
	private static final Set<String> Y_MODIFIERS = Set.of("LDY", "TAY", "INY", "DEY");

	private StoredValueScanner() {
	}

	/**
	 * Scans backward from {@code storeInstr} to determine the {@link BankState} it
	 * stores, reduced to {@code mask} (full algorithm in the class javadoc). After every
	 * composition step the base can be folded in via {@link #combine}; as an
	 * optimization, {@link #fullyDeterminedByAccumulator} lets the scan return without
	 * ever inspecting the base when the mask algebra alone already pins down every
	 * tracked bit.
	 * <p>
	 * 6502 has no immediate AND/ORA addressing the X or Y registers, so the mask-algebra
	 * composition only ever applies when {@code reg == 'A'}; the X/Y paths retain the
	 * simpler "resolved load or wholly unknown" behavior.
	 */
	static BankState resolveStoredValue(Program program, Instruction storeInstr, char reg,
			BankState inStateAtStore, int mask, Hooks hooks) {
		Listing listing = program.getListing();
		Set<String> modifiers = registerModifiers(reg);
		String loadMnemonic = "LD" + reg;

		int aAcc = 0xFF;
		int oAcc = 0x00;

		Instruction cur = storeInstr;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null) {
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			Address prevFallThrough = prev.getFallThrough();
			if (prevFallThrough == null || !prevFallThrough.equals(cur.getMinAddress())) {
				// not a straight-line predecessor of cur -- left the basic block
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}

			if (hooks.isMechanismWrite(prev)) {
				// the mechanism was written mid-chain; a base value read further back
				// would predate that write, so it's unsound to fall back to the in-state.
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}

			String mnem = prev.getMnemonicString().toUpperCase();

			if (reg == 'A' && mnem.equals("AND")) {
				Integer imm = isImmediate(prev) ? immediateOperandValue(prev) : null;
				if (imm == null) {
					// non-immediate AND (or an operand we couldn't pull a scalar out of)
					// is an opaque modifier of A.
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				aAcc = imm & aAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				cur = prev;
				continue;
			}

			if (reg == 'A' && mnem.equals("ORA")) {
				Integer imm = isImmediate(prev) ? immediateOperandValue(prev) : null;
				if (imm == null) {
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				oAcc = (imm & aAcc) | oAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				cur = prev;
				continue;
			}

			if (mnem.equals(loadMnemonic) && isImmediate(prev)) {
				Integer imm = immediateOperandValue(prev);
				if (imm != null) {
					// x is now fully known -- fold it through the accumulated transform.
					return combine(aAcc, oAcc, mask, BankState.fullyKnown(0xFF, imm));
				}
				// Scalar extraction failed; fall through and treat like any other modifier.
			}

			if (mnem.equals(loadMnemonic)) {
				BankState base = hooks.resolveLoad(prev, inStateAtStore);
				if (base != null) {
					return combine(aAcc, oAcc, mask, base);
				}
			}

			if (modifiers.contains(mnem)) {
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			if (prev.getFlowType().isCall()) {
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			cur = prev;
		}
		return combine(aAcc, oAcc, mask, BankState.unknown());
	}

	/**
	 * Checks whether every bit of {@code mask} is already determined by the accumulator
	 * alone, independent of whatever base register value {@code x} the scan eventually
	 * finds, given {@code result = (x & aAcc) | oAcc}: bit {@code b} is so determined
	 * iff {@code aAcc} clears it or {@code oAcc} sets it.
	 */
	private static boolean fullyDeterminedByAccumulator(int aAcc, int oAcc, int mask) {
		for (int bit = 0; bit < 8; bit++) {
			int bitMask = 1 << bit;
			if ((mask & bitMask) == 0) {
				continue; // not part of the tracked bank-state bits
			}
			boolean aClearsIt = (aAcc & bitMask) == 0;
			boolean oSetsIt = (oAcc & bitMask) != 0;
			if (!aClearsIt && !oSetsIt) {
				return false; // this mask bit still depends on the base value
			}
		}
		return true;
	}

	/**
	 * Folds the accumulated transform {@code result = (x & aAcc) | oAcc} against a
	 * (possibly partially known) base {@link BankState} for {@code x}, reduced to
	 * {@code mask}: {@code oAcc} setting a bit forces a known 1; otherwise {@code aAcc}
	 * clearing it forces a known 0; otherwise the bit passes {@code x} through, so it is
	 * known in the result iff it is known in {@code base}.
	 */
	private static BankState combine(int aAcc, int oAcc, int mask, BankState base) {
		int knownMask = 0;
		int bits = 0;
		for (int bit = 0; bit < 8; bit++) {
			int bitMask = 1 << bit;
			if ((mask & bitMask) == 0) {
				continue;
			}
			if ((oAcc & bitMask) != 0) {
				knownMask |= bitMask;
				bits |= bitMask;
			}
			else if ((aAcc & bitMask) == 0) {
				knownMask |= bitMask;
			}
			else if ((base.knownMask() & bitMask) != 0) {
				knownMask |= bitMask;
				if ((base.bits() & bitMask) != 0) {
					bits |= bitMask;
				}
			}
		}
		return new BankState(knownMask, bits);
	}

	// ------------------------------------------------------------------
	// Operand helpers shared by store-recognizing strategies
	// ------------------------------------------------------------------

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

	private static Set<String> registerModifiers(char reg) {
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
