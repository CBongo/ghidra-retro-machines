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

import java.util.OptionalInt;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/**
 * The 65816 effects the analyzers interpret instruction by instruction (bead grm-jjuc, wave 3),
 * read off the instruction's p-code through {@link PcodeShapes} so no analyzer matches a mnemonic
 * for them: which register a push or pull moves and how many bytes, constant loads, register
 * transfers, direct-page writes, returns and dispatch jumps.
 * <p>
 * What p-code CANNOT see stays out of here and stays mnemonic in the callers (design rulings R2,
 * R4): the M/X/E width and mode changes ({@code REP}, {@code SEP}, {@code XCE}, the status pull of
 * {@code PLP}) are context actions invisible in p-code, and {@code RTI} is a {@code RETURN} that
 * is told apart from {@code RTS}/{@code RTL} by {@link MosOperands#isInterruptReturn}. Push and pull
 * sizes already reflect the width the instruction was DECODED at; a caller that must bail when the
 * width is unknown keeps its own width source.
 */
final class W65816Shapes {

	private W65816Shapes() {}

	/** The registers a 65816 stack or transfer effect names; {@code OTHER} is any other register. */
	enum Role {
		A, X, Y, DBR, DP, OTHER, NONE
	}

	/**
	 * A push: {@code bytes} stacked, {@code role} the register pushed ({@code NONE} for a computed
	 * value such as {@code PHP}, {@code PEI}, {@code PER}), {@code constant} the stacked value when
	 * it folds to a constant ({@code PEA}, {@code PHK}, {@code PER}).
	 */
	record Push(Role role, int bytes, Long constant) {}

	/** A pull: {@code bytes} unstacked into {@code role} ({@code NONE} for {@code PLP}). */
	record Pull(Role role, int bytes) {}

	/** A plain register-to-register copy ({@code TAX}, {@code TXA}, {@code TCD}, {@code TDC}...). */
	record Transfer(Role src, Role dst) {}

	/** A constant loaded into a register ({@code LDA #imm}): the register, its width, the value. */
	record ConstLoad(Role role, int bytes, long value) {}

	private static Role roleOf(Language lang, Register r) {
		if (r == null) {
			return Role.NONE;
		}
		CpuRegs regs = CpuRegs.of(lang);
		if (r.equals(regs.acc()) || r.equals(regs.accWide())) {
			return Role.A;
		}
		if (r.equals(regs.x()) || r.equals(regs.xLow())) {
			return Role.X;
		}
		if (r.equals(regs.y()) || r.equals(regs.yLow())) {
			return Role.Y;
		}
		if (r.equals(lang.getRegister("DBR"))) {
			return Role.DBR;
		}
		if (r.equals(lang.getRegister("DP"))) {
			return Role.DP;
		}
		return Role.OTHER;
	}

	private static OptionalInt delta(Instruction ins) {
		return PcodeShapes.netStackDelta(ins, CpuRegs.of(ins.getProgram().getLanguage()));
	}

	/** The push this instruction is ({@code PHA PHX PHY PHB PHK PHD PHP PEA PEI PER}), or null. */
	static Push push(Instruction ins) {
		if (PcodeShapes.hasFlowOp(ins)) {
			return null;
		}
		OptionalInt d = delta(ins);
		if (d.isEmpty() || d.getAsInt() >= 0) {
			return null;
		}
		Language lang = ins.getProgram().getLanguage();
		return new Push(roleOf(lang, PcodeShapes.pushedRegister(ins)), -d.getAsInt(),
			PcodeShapes.pushedConstant(ins));
	}

	/** The pull this instruction is ({@code PLA PLX PLY PLB PLD PLP}), or null. */
	static Pull pull(Instruction ins) {
		if (PcodeShapes.hasFlowOp(ins)) {
			return null;
		}
		OptionalInt d = delta(ins);
		if (d.isEmpty() || d.getAsInt() <= 0) {
			return null;
		}
		Language lang = ins.getProgram().getLanguage();
		return new Pull(roleOf(lang, PcodeShapes.pulledRegister(ins)), d.getAsInt());
	}

	/** The constant load into A, X or Y ({@code LDA/LDX/LDY #imm}), or null. */
	static ConstLoad constLoad(Instruction ins) {
		Language lang = ins.getProgram().getLanguage();
		CpuRegs regs = CpuRegs.of(lang);
		Register[] candidates = { regs.acc(), regs.accWide(), regs.x(), regs.xLow(), regs.y(),
			regs.yLow() };
		for (Register r : candidates) {
			Long v = r == null ? null : PcodeShapes.constantInto(ins, r);
			if (v != null) {
				return new ConstLoad(roleOf(lang, r), r.getMinimumByteSize(), v);
			}
		}
		return null;
	}

	/** The value the instruction copies into {@code DBR} as a constant ({@code MVN}/{@code MVP}), or null. */
	static Long constIntoDbr(Instruction ins) {
		Register dbr = ins.getProgram().getLanguage().getRegister("DBR");
		return dbr == null ? null : PcodeShapes.constantInto(ins, dbr);
	}

	/**
	 * The register-to-register copy this instruction is, between A, X, Y, DP (and other registers
	 * as {@code OTHER}), or null. 8-bit {@code TAX} copies {@code A} to {@code XLow} only.
	 */
	static Transfer transfer(Instruction ins) {
		Language lang = ins.getProgram().getLanguage();
		CpuRegs regs = CpuRegs.of(lang);
		Register[] dsts = { regs.acc(), regs.accWide(), regs.x(), regs.xLow(), regs.y(),
			regs.yLow(), lang.getRegister("DP") };
		for (Register dst : dsts) {
			Register src = dst == null ? null : PcodeShapes.copySource(ins, dst);
			if (src != null) {
				return new Transfer(roleOf(lang, src), roleOf(lang, dst));
			}
		}
		return null;
	}

	/** Whether this instruction swaps the two halves of the accumulator ({@code XBA}). */
	static boolean swapsAccumulatorHalves(Instruction ins) {
		Language lang = ins.getProgram().getLanguage();
		Register a = CpuRegs.of(lang).acc();
		Register b = lang.getRegister("B");
		if (a == null || b == null) {
			return false;
		}
		return b.equals(PcodeShapes.copySource(ins, a)) && a.equals(PcodeShapes.copySource(ins, b));
	}

	/** Whether the instruction writes the direct-page register ({@code TCD}, {@code PLD}). */
	static boolean writesDp(Instruction ins) {
		Register dp = ins.getProgram().getLanguage().getRegister("DP");
		return dp != null && PcodeShapes.writesRegister(ins, dp);
	}

	/** Whether the instruction writes the stack pointer other than by a push or pull ({@code TXS}, {@code TCS}). */
	static boolean rebasesStack(Instruction ins) {
		return !PcodeShapes.hasFlowOp(ins) && delta(ins).isEmpty() &&
			PcodeShapes.writesRegister(ins,
				CpuRegs.of(ins.getProgram().getLanguage()).sp());
	}

	/**
	 * Whether this is a subroutine return ({@code RTS}, {@code RTL}): a plain terminator. {@code RTI}
	 * is a RETURN op too but NOT one of these (design ruling R4); ask {@link MosOperands#isInterruptReturn}.
	 */
	static boolean isReturn(Instruction ins) {
		FlowType ft = ins.getFlowType();
		return ft.isTerminal() && !ft.isCall() && !ft.isJump() && !ft.isComputed() &&
			!MosOperands.isInterruptReturn(ins);
	}

	/** The bytes a subroutine return pulls: 2 for {@code RTS}, 3 for {@code RTL}; 0 when not a return. */
	static int returnPopBytes(Instruction ins) {
		return isReturn(ins) ? delta(ins).orElse(0) : 0;
	}

	/** The kind label of a subroutine return: {@code "RTS"}, {@code "RTL"}, or null. */
	static String returnKind(Instruction ins) {
		switch (returnPopBytes(ins)) {
			case 2:
				return "RTS";
			case 3:
				return "RTL";
			default:
				return null;
		}
	}

	/** A real call: a call flow that is not made terminal by a CALL_RETURN override. */
	static boolean isCall(Instruction ins) {
		FlowType ft = ins.getFlowType();
		return ft.isCall() && !ft.isTerminal();
	}

	/**
	 * An unconditional indirect {@code JMP}/{@code JML}: a computed jump that does not touch the
	 * stack or call out, which tells it from {@code RTI}, {@code BRK}, {@code COP} and {@code STP}
	 * (all computed jumps in this sleigh too).
	 */
	static boolean isDispatchJump(Instruction ins) {
		FlowType ft = ins.getFlowType();
		if (!ft.isComputed() || !ft.isJump() || ft.isCall() || ft.isConditional()) {
			return false;
		}
		OptionalInt d = delta(ins);
		if (d.isEmpty() || d.getAsInt() != 0) {
			return false;
		}
		for (PcodeOp op : ins.getPcode()) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				return false;
			}
		}
		return true;
	}

	/** The bytes a call instruction pushes for its return address: 2 for {@code JSR}, 3 for {@code JSL}. */
	static int callPushBytes(Instruction ins) {
		return isCall(ins) ? -delta(ins).orElse(0) : 0;
	}

	/**
	 * Whether {@code ins} leaves the stack pointer as it found it, by its p-code: true for a
	 * {@code JMP} a CALL_RETURN override made a terminal call, which is still a jump, and false
	 * for a {@code JSR} so overridden, which still pushed its return address (grm-9nxj.53/.54).
	 */
	static boolean pushesNothing(Instruction ins) {
		OptionalInt d = delta(ins);
		return d.isPresent() && d.getAsInt() == 0;
	}

	/**
	 * The data-reference type of an instruction's memory operand, from its memory traffic: both a
	 * load and a store is {@code READ_WRITE} ({@code INC}, {@code ASL}, {@code TSB}...), a store
	 * alone {@code WRITE} ({@code STA}, {@code STZ}...), anything else {@code READ}.
	 */
	static RefType memAccessKind(Instruction ins) {
		int bits = PcodeShapes.dataAccess(ins);
		if (bits == (PcodeShapes.DATA_READ | PcodeShapes.DATA_WRITE)) {
			return RefType.READ_WRITE;
		}
		return bits == PcodeShapes.DATA_WRITE ? RefType.WRITE : RefType.READ;
	}

	/** Whether the instruction is a conditional branch on {@code flag}, taken when it is {@code taken}. */
	static boolean branchesOn(Instruction ins, CpuRegs.FlagKind flag, boolean taken) {
		// XCE and PLP branch inside their own p-code; only a conditional jump is a branch here.
		if (!ins.getFlowType().isConditional()) {
			return false;
		}
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(ins);
		return fb != null && fb.kind() == flag && fb.takenWhenSet() == taken;
	}

	/** Whether the instruction is a {@code TAX}-shaped copy of the accumulator into X. */
	static boolean copiesAccumulatorToX(Instruction ins) {
		Transfer t = transfer(ins);
		return t != null && t.src() == Role.A && t.dst() == Role.X;
	}

	/** Whether the instruction doubles the accumulator in place ({@code ASL A}). */
	static boolean shiftsAccumulatorLeft(Instruction ins) {
		CpuRegs regs = CpuRegs.of(ins.getProgram().getLanguage());
		return PcodeShapes.shiftLeftBy1(ins, regs.acc()) ||
			(regs.accWide() != null && PcodeShapes.shiftLeftBy1(ins, regs.accWide()));
	}

	/** Whether the instruction pushes the accumulator ({@code PHA}), at whatever width it decoded. */
	static boolean pushesAccumulator(Instruction ins) {
		Push p = push(ins);
		return p != null && p.role() == Role.A;
	}

	/** Whether the instruction decrements the accumulator in place ({@code DEC A}). */
	static boolean decrementsAccumulator(Instruction ins) {
		if (constIntoDbr(ins) != null) {
			return false;   // MVN/MVP count the 16-bit accumulator down too
		}
		CpuRegs regs = CpuRegs.of(ins.getProgram().getLanguage());
		Integer k = PcodeShapes.incrementOf(ins, regs.acc());
		Integer w = regs.accWide() == null ? null : PcodeShapes.incrementOf(ins, regs.accWide());
		return (k != null && k == -1) || (w != null && w == -1);
	}

	/**
	 * Whether the instruction moves or rewrites the stack pointer or calls out through it: a push,
	 * a pull, {@code TXS}/{@code TCS}, a call, {@code RTI}, {@code BRK}, {@code COP}. A subroutine
	 * return is not counted (the idiom recognizers end at one).
	 */
	static boolean touchesStack(Instruction ins) {
		if (isReturn(ins)) {
			return false;
		}
		OptionalInt d = delta(ins);
		return d.isEmpty() ? PcodeShapes.writesRegister(ins,
			CpuRegs.of(ins.getProgram().getLanguage()).sp()) : d.getAsInt() != 0;
	}

	/** Whether the instruction pushes the one-byte program bank ({@code PHK}): a constant byte. */
	static boolean pushesProgramBank(Instruction ins) {
		Push p = push(ins);
		return p != null && p.role() == Role.NONE && p.bytes() == 1 && p.constant() != null;
	}

	/** The constant word a 2-byte push stacks ({@code PEA}, {@code PER}: folded), or -1. */
	static int pushedConstantWord(Instruction ins) {
		Push p = push(ins);
		return p != null && p.role() == Role.NONE && p.bytes() == 2 && p.constant() != null
			? (int) (p.constant() & 0xffff) : -1;
	}
}
