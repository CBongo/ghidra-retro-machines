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


import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
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
	 * {@code STA}/{@code STX}/{@code STY} -- or {@code null} when the instruction stores no
	 * register's value to non-stack memory ({@link PcodeShapes#storeSource}). The read-modify-write
	 * opcodes ({@code INC}/{@code DEC}/{@code ASL}/...) and the stack pushes return {@code null}:
	 * they mutate the target in place and this scanner does not model the resulting value.
	 */
	static Character storeRegister(Instruction instr) {
		CpuRegs regs = CpuRegs.of(instr.getProgram().getLanguage());
		Register stored = PcodeShapes.storeSource(instr);
		if (stored == null) {
			return null;
		}
		if (stored.equals(regs.acc())) {
			return 'A';
		}
		if (stored.equals(regs.x())) {
			return 'X';
		}
		return stored.equals(regs.y()) ? 'Y' : null;
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
	 * Whether {@code instr} writes the accumulator/index register {@code reg} ({@code 'A'},
	 * {@code 'X'}, {@code 'Y'}), read off its p-code ({@link PcodeShapes#writesRegister}) rather than
	 * a mnemonic set (grm-jjuc W0). Exposed for {@link BankMirrors}' discovery walks (grm-mej.2),
	 * which are structurally the same walk as this scanner's own backward walks and must agree
	 * with them on what clobbers a register. Undocumented read-modify-write opcodes that also write
	 * A ({@code SLO}, {@code ISC}, {@code LAX}...) now count; the mnemonic sets never listed them.
	 * <p>
	 * A call is deliberately NOT covered: {@code JSR} modifies every register but its p-code writes
	 * none of them, so every walk tests {@code getFlowType().isCall()} separately.
	 */
	static boolean modifiesRegister(Instruction instr, char reg) {
		CpuRegs regs = CpuRegs.of(instr.getProgram().getLanguage());
		return PcodeShapes.writesRegister(instr, switch (reg) {
			case 'A' -> regs.acc();
			case 'X' -> regs.x();
			case 'Y' -> regs.y();
			default -> null;
		});
	}

	// ------------------------------------------------------------------
	// p-code-backed replacements for the 6502 mnemonic tests (grm-jjuc W1)
	// ------------------------------------------------------------------

	private static Register regOf(Instruction instr, char reg) {
		CpuRegs regs = CpuRegs.of(instr.getProgram().getLanguage());
		return switch (reg) {
			case 'A' -> regs.acc();
			case 'X' -> regs.x();
			case 'Y' -> regs.y();
			default -> null;
		};
	}

	/**
	 * Whether {@code instr} loads {@code reg} ({@code 'A'}/{@code 'X'}/{@code 'Y'}) from memory or a
	 * constant ({@code LDA}/{@code LDX}/{@code LDY}, any addressing mode).
	 */
	static boolean loadsInto(Instruction instr, char reg) {
		return loadsFromMemoryInto(instr, reg) || isImmediateLoadInto(instr, reg);
	}

	/** Whether {@code instr} loads {@code reg} from a memory operand (not an immediate). */
	static boolean loadsFromMemoryInto(Instruction instr, char reg) {
		Register r = regOf(instr, reg);
		return r != null && r.equals(PcodeShapes.loadDestination(instr));
	}

	/** Whether {@code instr} loads a constant into {@code reg} ({@code LDA #imm}). */
	static boolean isImmediateLoadInto(Instruction instr, char reg) {
		Register r = regOf(instr, reg);
		return r != null && PcodeShapes.constantInto(instr, r) != null;
	}

	/** The register ({@code 'A'}/{@code 'X'}/{@code 'Y'}) {@code instr} loads from memory or a constant, or 0. */
	static char loadedRegister(Instruction instr) {
		Register dst = PcodeShapes.loadDestination(instr);
		for (char c : new char[] { 'A', 'X', 'Y' }) {
			Register r = regOf(instr, c);
			if (r != null && (r.equals(dst) || PcodeShapes.constantInto(instr, r) != null)) {
				return c;
			}
		}
		return 0;
	}

	/** Whether {@code instr} is a plain store of {@code reg} ({@code STA}/{@code STX}/{@code STY}). */
	static boolean storesRegister(Instruction instr, char reg) {
		Character stored = storeRegister(instr);
		return stored != null && stored == reg;
	}

	/** The constant {@code instr} loads into {@code reg} ({@code LDX #imm}), or null. */
	static Long constantLoadedInto(Instruction instr, char reg) {
		Register r = regOf(instr, reg);
		return r == null ? null : PcodeShapes.constantInto(instr, r);
	}

	/** Whether {@code instr} loads any of A, X, Y from memory or a constant. */
	static boolean loadsAnyRegister(Instruction instr) {
		return loadsInto(instr, 'A') || loadsInto(instr, 'X') || loadsInto(instr, 'Y');
	}

	/**
	 * The register ({@code 'A'}/{@code 'X'}/{@code 'Y'}) {@code reg} is plainly copied from by a
	 * register transfer ({@code TAX}, {@code TAY}, {@code TXA}, {@code TYA}), or null.
	 */
	static Character transferSource(Instruction instr, char reg) {
		Register dst = regOf(instr, reg);
		if (dst == null) {
			return null;
		}
		Register src = PcodeShapes.copySource(instr, dst);
		for (char c : new char[] { 'A', 'X', 'Y' }) {
			if (c != reg && src != null && src.equals(regOf(instr, c))) {
				return c;
			}
		}
		return null;
	}

	/** Net stack-pointer change in bytes (0 when it is not a constant). */
	private static int stackDelta(Instruction instr) {
		return PcodeShapes.netStackDelta(instr, CpuRegs.of(instr.getProgram().getLanguage()))
			.orElse(0);
	}

	/** Whether {@code instr} sets {@code reg} to {@code reg + k} ({@code INX} = +1, {@code DEY} = -1). */
	static boolean incrementsBy(Instruction instr, char reg, int k) {
		Register r = regOf(instr, reg);
		Integer got = r == null ? null : PcodeShapes.incrementOf(instr, r);
		return got != null && got == k;
	}

	/** Whether {@code instr} copies the stack pointer into {@code reg} ({@code TSX}). */
	static boolean copiesStackPointerInto(Instruction instr, char reg) {
		Register dst = regOf(instr, reg);
		Register src = dst == null ? null : PcodeShapes.copySource(instr, dst);
		return src != null &&
			CpuRegs.of(instr.getProgram().getLanguage()).spViews().contains(src);
	}

	/** The one-byte stack operations the bank-switch walks model, read off the p-code's stack effect. */
	enum StackOp {
		/** {@code PHA}: pushes the accumulator. */
		PUSH_A,
		/** {@code PLA}: pops into the accumulator. */
		PULL_A,
		/** {@code PHP}: pushes a computed status byte. */
		PUSH_STATUS,
		/** {@code PLP}: pops the status byte into the flags. */
		PULL_STATUS,
		/** Anything else (including {@code PHX}/{@code PLX}, which the walks never modelled). */
		NONE
	}

	/** Classifies {@code instr} as one of the {@link StackOp}s by its measured stack effect. */
	static StackOp stackOp(Instruction instr) {
		int delta = stackDelta(instr);
		if (delta == -1) {
			Register pushed = PcodeShapes.pushedRegister(instr);
			if (pushed == null) {
				return StackOp.PUSH_STATUS;
			}
			return pushed.equals(regOf(instr, 'A')) ? StackOp.PUSH_A : StackOp.NONE;
		}
		if (delta == 1) {
			Register pulled = PcodeShapes.pulledRegister(instr);
			if (pulled == null) {
				return StackOp.PULL_STATUS;
			}
			return pulled.equals(regOf(instr, 'A')) ? StackOp.PULL_A : StackOp.NONE;
		}
		return StackOp.NONE;
	}

	/** Whether {@code instr} pushes exactly one byte ({@code PHA}, {@code PHP}). */
	static boolean pushesByte(Instruction instr) {
		return stackDelta(instr) == -1;
	}

	/** Whether {@code instr} pops exactly one byte ({@code PLA}, {@code PLP}). */
	static boolean popsByte(Instruction instr) {
		return stackDelta(instr) == 1;
	}

	/** Whether {@code instr} pushes the accumulator ({@code PHA}). */
	static boolean pushesAccumulator(Instruction instr) {
		return pushesByte(instr) && CpuRegs.of(instr.getProgram().getLanguage()).acc()
			.equals(PcodeShapes.pushedRegister(instr));
	}

	/** Whether {@code instr} pops into the accumulator ({@code PLA}). */
	static boolean popsAccumulator(Instruction instr) {
		return popsByte(instr) && CpuRegs.of(instr.getProgram().getLanguage()).acc()
			.equals(PcodeShapes.pulledRegister(instr));
	}

	/** Whether {@code instr} is an interrupt return that pops status and a 2-byte address ({@code RTI}). */
	static boolean isInterruptReturn(Instruction instr) {
		return PcodeShapes.isReturnOp(instr) && restoresStatus(instr);
	}

	/** Whether {@code instr} pulls the status register (writes the carry flag's register / PSW). */
	private static boolean restoresStatus(Instruction instr) {
		CpuRegs regs = CpuRegs.of(instr.getProgram().getLanguage());
		return PcodeShapes.writesRegister(instr, regs.carry().reg()) &&
			stackDelta(instr) > 0;
	}

	/** Whether {@code instr} returns popping a 2-byte address ({@code RTS}, not {@code RTI}). */
	static boolean isSubroutineReturn(Instruction instr) {
		return PcodeShapes.isReturnOp(instr) && !restoresStatus(instr) && stackDelta(instr) == 2;
	}

	/** Whether {@code instr} is {@code RTS} or {@code RTI} on the 6502 family (SPC700 {@code RET}/{@code RETI} are left out: W4 candidate). */
	static boolean isRtsOrRti(Instruction instr) {
		return CpuRegs.of(instr.getProgram().getLanguage()).psw() == null &&
			(isSubroutineReturn(instr) || isInterruptReturn(instr));
	}

	/** Whether {@code instr} pushes, pulls or rebases the stack ({@code PHA}, {@code PLP}, {@code TXS}). */
	static boolean touchesStack(Instruction instr) {
		return rebasesStackPointer(instr) || stackDelta(instr) != 0;
	}

	/** Whether {@code instr} sets the stack pointer to a non-constant offset ({@code TXS}). */
	static boolean rebasesStackPointer(Instruction instr) {
		return PcodeShapes.netStackDelta(instr, CpuRegs.of(instr.getProgram().getLanguage()))
			.isEmpty();
	}

	/**
	 * Whether {@code instr} is the 6502 {@code RTS} (a plain 2-byte return); the SPC700 {@code RET}
	 * is left out to keep the old mnemonic reach (W4 candidate).
	 */
	static boolean isRts(Instruction instr) {
		return CpuRegs.of(instr.getProgram().getLanguage()).psw() == null &&
			isSubroutineReturn(instr);
	}

	/** Whether {@code instr} ends in an interrupt vector jump with no operand ({@code BRK}). */
	static boolean isSoftwareInterrupt(Instruction instr) {
		ghidra.program.model.symbol.FlowType ft = instr.getFlowType();
		return ft.isComputed() && ft.isJump() && instr.getNumOperands() == 0;
	}

	/**
	 * Whether {@code instr}'s ENCODED flow (before any flow override) is a call: {@code JSR}, never a
	 * {@code JMP} that shared-return analysis re-typed as a call (grm-jjuc R3).
	 */
	static boolean isNativeCall(Instruction instr) {
		return instr.getPrototype().getFlowType(instr.getInstructionContext()).isCall();
	}

	/**
	 * Whether {@code instr} is a plain subroutine call ({@code JSR}; on the 65816 also {@code JSL}, but no caller reaches it there).
	 * Control-flow kind comes from the flow types (R3: a {@code JMP} retyped to a call by
	 * shared-return analysis has no push, so the stack effect excludes it). The SPC700 {@code CALL}
	 * is left out to keep the old mnemonic-{@code JSR} reach (W4 candidate).
	 */
	static boolean isJsr(Instruction instr) {
		return instr.getFlowType().isCall() && instr.getPrototype().getFlowType(instr.getInstructionContext()).isCall() &&
			CpuRegs.of(instr.getProgram().getLanguage()).psw() == null;
	}

	/** Whether {@code instr} is a branch on the Z or N flag ({@code BEQ}/{@code BNE}/{@code BMI}/{@code BPL}). */
	static boolean isZnBranch(Instruction instr) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(instr);
		return fb != null && (fb.kind() == CpuRegs.FlagKind.ZERO ||
			fb.kind() == CpuRegs.FlagKind.NEGATIVE);
	}

	/** Whether Z-or-N branch {@code branch} is taken when Z is {@code z} and N is {@code n}. */
	static boolean znBranchTaken(Instruction branch, boolean z, boolean n) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(branch);
		boolean flag = fb.kind() == CpuRegs.FlagKind.ZERO ? z : n;
		return flag == fb.takenWhenSet();
	}

	/** Whether {@code instr} branches on N, taken when it is clear ({@code BPL}). */
	static boolean isBpl(Instruction instr) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(instr);
		return fb != null && fb.kind() == CpuRegs.FlagKind.NEGATIVE && !fb.takenWhenSet();
	}

	/**
	 * Whether {@code instr} compares {@code reg} ({@code 'A'}/{@code 'X'}/{@code 'Y'}) with an
	 * operand and keeps nothing but flags ({@code CMP}/{@code CPX}/{@code CPY}): it reads the
	 * register, writes the carry flag and writes neither the register nor memory.
	 */
	static boolean comparesRegister(Instruction instr, char reg) {
		Register r = regOf(instr, reg);
		CpuRegs regs = CpuRegs.of(instr.getProgram().getLanguage());
		return r != null && PcodeShapes.readsRegister(instr, r) &&
			PcodeShapes.writesRegister(instr, regs.carry().reg()) &&
			!PcodeShapes.writesRegister(instr, r) && !PcodeShapes.writesMemory(instr);
	}

	/** Whether {@code instr}'s operand is an immediate ({@code #imm}): its only operand object is a scalar. */
	static boolean isImmediateOperand(Instruction instr) {
		if (instr.getNumOperands() < 1) {
			return false;
		}
		Object[] objs = instr.getOpObjects(0);
		return objs.length == 1 && objs[0] instanceof Scalar;
	}

	/** Whether {@code instr} branches on Z, taken when it is clear ({@code BNE}). */
	static boolean isBne(Instruction instr) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(instr);
		return fb != null && fb.kind() == CpuRegs.FlagKind.ZERO && !fb.takenWhenSet();
	}

	/** Whether {@code instr} branches on Z, taken when it is set ({@code BEQ}). */
	static boolean isBeq(Instruction instr) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(instr);
		return fb != null && fb.kind() == CpuRegs.FlagKind.ZERO && fb.takenWhenSet();
	}

	/** 0 or 1 when {@code instr} sets the carry flag to a constant ({@code CLC}/{@code SEC}), else null. */
	static Integer constantCarry(Instruction instr) {
		Long v = PcodeShapes.constantInto(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).carry().reg());
		return v == null ? null : (int) (long) v;
	}

	/** Whether {@code instr} computes {@code A := A & x} ({@code AND}, any operand mode). */
	static boolean isAndOnAccumulator(Instruction instr) {
		return PcodeShapes.bitOpOn(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc()) == PcodeOp.INT_AND;
	}

	/** Whether {@code instr} computes {@code A := A | x} ({@code ORA}, any operand mode). */
	static boolean isOrOnAccumulator(Instruction instr) {
		return PcodeShapes.bitOpOn(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc()) == PcodeOp.INT_OR;
	}

	/** Whether {@code instr} computes {@code A := A ^ x} ({@code EOR}, any operand mode). */
	static boolean isEorOnAccumulator(Instruction instr) {
		return PcodeShapes.bitOpOn(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc()) == PcodeOp.INT_XOR;
	}

	/** Whether {@code instr} is the accumulator form of {@code LSR} ({@code A := A >> 1}). */
	static boolean isLsrAccumulator(Instruction instr) {
		return PcodeShapes.shiftRightBy1(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc());
	}

	/** Whether {@code instr} is the accumulator form of {@code ASL} ({@code A := A << 1}). */
	static boolean isAslAccumulator(Instruction instr) {
		return PcodeShapes.shiftLeftBy1(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc());
	}

	/**
	 * Whether {@code instr} writes any non-stack memory ({@code STA}/{@code STX}/{@code STY}/
	 * {@code STZ}, a memory read-modify-write, {@code TSB}/{@code TRB}).
	 */
	static boolean writesMemory(Instruction instr) {
		return PcodeShapes.writesMemory(instr);
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
