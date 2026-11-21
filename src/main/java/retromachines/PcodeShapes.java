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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Stateless questions about the SEMANTICS of ONE instruction, answered from its
 * {@link Instruction#getPcode() p-code} instead of its mnemonic (bead grm-jjuc, wave 0). It is
 * the shared layer the recognizers migrate onto: "does this write A", "is this a register-to-
 * register copy", "what does this push" read the same on every CPU the extension carries (6502,
 * 6510, 65816, SPC700) because they are read off the decoded effect.
 * <p>
 * <b>Method.</b> Each call walks the instruction's op list once, straight-line (internal
 * branches inside one instruction are not followed; none of the shapes asked about here sit behind
 * one). A tiny within-instruction definition lookup lets unique-space temporaries be looked
 * through: {@code COPY}, {@code INT_ZEXT} and {@code SUBPIECE} (a byte sub-range) count as "the same
 * value", so {@code STA (zp),Y}'s {@code unique := A; STORE unique} still reads as "A is stored".
 * A value is traced to one of: a constant, a LIVE-IN varnode (its value on instruction entry), or
 * the (non-copy) op that computed it.
 * <p>
 * <b>Rulings honoured</b> (grm-jjuc design): fixed-address memory is a ram-space varnode
 * {@code COPY}/input with NO {@code LOAD}/{@code STORE} ({@code STA $12} is {@code (ram,$12) :=
 * A}); a register-space destination that is not a CPU register (the 6510 {@code $01} port) is
 * treated as memory-mapped I/O by the memory helpers and as a register write by
 * {@link #writesRegister}; the stack pointer is measured symbolically from the SP varnode(s)
 * ({@link #netStackDelta}), never assumed.
 * <p>
 * <b>Not covered.</b> Control-flow KIND stays {@link Instruction#getFlowType()} (it honours flow
 * overrides); width/mode context changes ({@code REP}/{@code SEP}/{@code XCE}) are invisible in
 * p-code and stay mnemonic; an instruction with no p-code (undefined bytes) answers "nothing".
 */
final class PcodeShapes {

	private PcodeShapes() {
	}

	/** A conditional branch's controlling flag and the polarity under which the branch is taken. */
	record FlagBranch(CpuRegs.FlagKind kind, boolean takenWhenSet) {}

	// ------------------------------------------------------------------
	// Public questions
	// ------------------------------------------------------------------

	/**
	 * Whether any op of {@code instr} writes a register-space location overlapping {@code reg}'s
	 * bytes (so a 16-bit write to the 65816's {@code C} writes {@code A}, and {@code TXS} writes
	 * {@code S}). Flag side effects count only when {@code reg} IS a flag register. A call
	 * ({@code JSR}) is not a write: its p-code does not touch A/X/Y even though the callee may.
	 */
	static boolean writesRegister(Instruction instr, Register reg) {
		if (reg == null) {
			return false;
		}
		Varnode rv = varnodeOf(reg);
		for (PcodeOp op : ops(instr)) {
			Varnode out = op.getOutput();
			if (out != null && out.isRegister() && overlaps(out, rv)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether {@code instr} reads a byte of {@code reg} that it has not itself written earlier in
	 * the same instruction (i.e. depends on the register's entry value). {@code INX} reads X;
	 * {@code LDX #imm} does not; {@code TAX} reads A and not X.
	 */
	static boolean readsRegister(Instruction instr, Register reg) {
		if (reg == null) {
			return false;
		}
		Varnode rv = varnodeOf(reg);
		long base = rv.getOffset();
		boolean[] written = new boolean[rv.getSize()];
		for (PcodeOp op : ops(instr)) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in.isRegister() && overlaps(in, rv)) {
					for (long b = Math.max(in.getOffset(), base); b < Math.min(
						in.getOffset() + in.getSize(), base + rv.getSize()); b++) {
						if (!written[(int) (b - base)]) {
							return true;
						}
					}
				}
			}
			Varnode out = op.getOutput();
			if (out != null && out.isRegister() && overlaps(out, rv)) {
				for (long b = Math.max(out.getOffset(), base); b < Math.min(
					out.getOffset() + out.getSize(), base + rv.getSize()); b++) {
					written[(int) (b - base)] = true;
				}
			}
		}
		return false;
	}

	/**
	 * The register {@code dst} receives a plain copy of ({@code TAX}, {@code TXA}, {@code TSX},
	 * {@code TXS}, SPC700 {@code MOV A,X}), or null. Looks through temporaries and zero-extension;
	 * the value is the register's value at the point it was read, so {@code XBA}'s swap answers
	 * correctly. Known limit: a sub-range of a register that has no exact register name is mapped
	 * to the smallest containing register.
	 */
	static Register copySource(Instruction instr, Register dst) {
		if (dst == null) {
			return null;
		}
		Walk w = new Walk(instr);
		int j = w.lastWrite(w.ops.length, varnodeOf(dst));
		if (j < 0 || !sameStorage(w.ops[j].getOutput(), varnodeOf(dst))) {
			return null;
		}
		Val v = w.eval(j);
		if (v.kind == Val.LIVE && v.vn.isRegister() && !sameStorage(v.vn, varnodeOf(dst))) {
			return w.registerFor(v.vn);
		}
		return null;
	}

	/**
	 * The constant {@code reg} ends up holding when the instruction assigns it a constant
	 * ({@code LDA #imm}, {@code CLC}-style flag sets are flags so ask with the flag register), or
	 * null. The write must be exactly {@code reg}'s width.
	 */
	static Long constantInto(Instruction instr, Register reg) {
		if (reg == null) {
			return null;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		int j = w.lastWrite(w.ops.length, rv);
		if (j < 0 || !sameStorage(w.ops[j].getOutput(), rv)) {
			return null;
		}
		Val v = w.eval(j);
		return v.kind == Val.CONST ? Long.valueOf(v.c) : null;
	}

	/**
	 * The register this instruction loads from NON-STACK memory ({@code LDA abs}, {@code LDA
	 * (zp),Y}, SPC700 {@code MOV A,dp}), or null. "Memory" is a {@code LOAD}, a ram-space varnode
	 * read directly (fixed address), or the 6510 port registers. Stack pulls are
	 * {@link #pulledRegister}. Arithmetic with a memory operand ({@code ADC abs}) is not a load: the
	 * value is computed, not copied.
	 */
	static Register loadDestination(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		for (int j = 0; j < w.ops.length; j++) {
			Varnode out = w.ops[j].getOutput();
			if (out == null || !out.isRegister() || w.regs.isFlagStorage(w.registerFor(out)) ||
				w.overlapsSp(out)) {
				continue;
			}
			Val v = w.eval(j);
			boolean fromMemory = (v.kind == Val.OPAQUE && !v.partial &&
				w.ops[v.op].getOpcode() == PcodeOp.LOAD && !w.stackAccess[v.op]) ||
				(v.kind == Val.LIVE && w.isMemoryLike(v.vn));
			if (fromMemory) {
				return w.registerFor(out);
			}
		}
		return null;
	}

	/**
	 * The register whose entry value is stored to NON-STACK memory ({@code STA abs}, {@code STA
	 * (zp),Y}, {@code STX}, SPC700 {@code MOV dp,A}, {@code STA PORT} on the 6510), or null. The
	 * store may be a {@code STORE} op, a copy into a ram-space varnode (fixed address) or a copy into
	 * a 6510 port register. Read-modify-write ({@code INC abs}) is not a store of a register.
	 * Stack pushes are {@link #pushedRegister}.
	 */
	static Register storeSource(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		for (int j = 0; j < w.ops.length; j++) {
			PcodeOp op = w.ops[j];
			Val v = null;
			if (op.getOpcode() == PcodeOp.STORE) {
				if (!w.stackAccess[j]) {
					v = w.trace(j, op.getInput(2));
				}
			}
			else if (op.getOutput() != null && w.isMemoryLike(op.getOutput()) && w.isCopyLike(op)) {
				v = w.eval(j);
			}
			if (v != null && v.kind == Val.LIVE && v.vn.isRegister() && !w.isMemoryLike(v.vn)) {
				Register r = w.registerFor(v.vn);
				if (r != null) {
					return r;
				}
			}
		}
		return null;
	}

	/**
	 * The fixed memory addresses {@code instr} writes (ram-space output varnodes; including
	 * read-modify-write like {@code INC $12} and the 6510 port registers, which are returned as
	 * their register-space address). Stack pushes and computed {@code STORE}s are not listed
	 * ({@link #hasComputedStore}).
	 */
	static List<Address> memoryWrites(Instruction instr) {
		Walk w = new Walk(instr);
		List<Address> out = new ArrayList<>();
		for (PcodeOp op : w.ops) {
			Varnode o = op.getOutput();
			if (o != null && w.isMemoryLike(o)) {
				out.add(o.getAddress());
			}
		}
		return out;
	}

	/** Whether {@code instr} has a {@code STORE} through a computed (non-stack) address. */
	static boolean hasComputedStore(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		for (int j = 0; j < w.ops.length; j++) {
			if (w.ops[j].getOpcode() == PcodeOp.STORE && !w.stackAccess[j]) {
				return true;
			}
		}
		return false;
	}

	/** Whether {@code instr} writes non-stack memory by any means ({@link #memoryWrites} or {@link #hasComputedStore}). */
	static boolean writesMemory(Instruction instr) {
		return !memoryWrites(instr).isEmpty() || hasComputedStore(instr);
	}

	/**
	 * Whether {@code reg} ends up as {@code reg << 1} computed from its own entry value ({@code ASL A},
	 * SPC700 {@code ASL A}; also {@code reg * 2} and {@code reg + reg}). {@code ASL $12} (memory form)
	 * does not write the register and answers false. {@code ROL} (shift OR carry) is not a plain
	 * shift and answers false.
	 */
	static boolean shiftLeftBy1(Instruction instr, Register reg) {
		if (reg == null) {
			return false;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		Val v = w.finalValue(rv);
		if (v == null || v.kind != Val.OPAQUE || v.partial) {
			return false;
		}
		PcodeOp op = w.ops[v.op];
		switch (op.getOpcode()) {
			case PcodeOp.INT_LEFT:
				return w.isEntry(v.op, op.getInput(0), rv) && op.getInput(1).isConstant() &&
					op.getInput(1).getOffset() == 1;
			case PcodeOp.INT_MULT:
				return (w.isEntry(v.op, op.getInput(0), rv) && isConst(op.getInput(1), 2)) ||
					(w.isEntry(v.op, op.getInput(1), rv) && isConst(op.getInput(0), 2));
			case PcodeOp.INT_ADD:
				return w.isEntry(v.op, op.getInput(0), rv) && w.isEntry(v.op, op.getInput(1), rv);
			default:
				return false;
		}
	}

	/**
	 * {@code k} when {@code reg} ends up as {@code reg + k} (INX = +1, DEY = -1, {@code INC A}),
	 * else null. The register must be written at exactly its own width.
	 */
	static Integer incrementOf(Instruction instr, Register reg) {
		if (reg == null) {
			return null;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		Val v = w.finalValue(rv);
		if (v == null || v.kind != Val.OPAQUE || v.partial) {
			return null;
		}
		PcodeOp op = w.ops[v.op];
		int opc = op.getOpcode();
		if (opc != PcodeOp.INT_ADD && opc != PcodeOp.INT_SUB) {
			return null;
		}
		Varnode a = op.getInput(0);
		Varnode b = op.getInput(1);
		if (w.isEntry(v.op, a, rv) && b.isConstant()) {
			long k = signed(b.getOffset(), b.getSize());
			return (int) (opc == PcodeOp.INT_ADD ? k : -k);
		}
		if (opc == PcodeOp.INT_ADD && w.isEntry(v.op, b, rv) && a.isConstant()) {
			return (int) signed(a.getOffset(), a.getSize());
		}
		return null;
	}

	/**
	 * SP after minus SP before, in bytes, measured symbolically from the SP varnode(s):
	 * PHA = -1, PLA = +1, JSR = -2, RTS = +2, RTI = +3, 65816 emulation PHA = -1 through
	 * {@code SPLow}, SPC700 push through {@code 0x0100|zext(SP:1)}. Empty when SP is written with a
	 * value that is not {@code SP+k} ({@code TXS}, {@code TCS}, SPC700 {@code MOV SP,X}). Writes to
	 * the high part of SP alone (65816 {@code SPHigh}) are ignored. The page wrap of an 8-bit SP is
	 * not modelled (the language itself does not: grm-m9nu).
	 */
	static OptionalInt netStackDelta(Instruction instr, CpuRegs regs) {
		Walk w = new Walk(instr, regs);
		w.stackWalk();
		return w.delta;
	}

	/**
	 * The register (or contiguous register pair, as the 65816 16-bit {@code PHA} pushes {@code C})
	 * whose entry value is stored to the stack by this instruction, or null. A push of a computed
	 * value (status byte of {@code PHP}, a return address, a constant) answers null.
	 */
	static Register pushedRegister(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		List<Varnode> pieces = new ArrayList<>();
		for (int j = 0; j < w.ops.length; j++) {
			if (w.ops[j].getOpcode() == PcodeOp.STORE && w.stackAccess[j]) {
				Val v = w.trace(j, w.ops[j].getInput(2));
				if (v.kind != Val.LIVE || !v.vn.isRegister()) {
					return null;
				}
				pieces.add(v.vn);
			}
		}
		if (pieces.isEmpty()) {
			return null;
		}
		pieces.sort((p, q) -> Long.compare(p.getOffset(), q.getOffset()));
		long lo = pieces.get(0).getOffset();
		long end = lo;
		for (Varnode p : pieces) {
			if (p.getOffset() != end) {
				return null;
			}
			end += p.getSize();
		}
		return w.registerFor(new Varnode(pieces.get(0).getAddress(), (int) (end - lo)));
	}

	/**
	 * The constant a push stores to the stack, folded through unique temporaries ({@code PEA},
	 * 65816 {@code PHK}, {@code PER}: {@code inst_next + disp} is built from integer ops), or null
	 * when any stacked byte is not a constant. A multi-byte push stores the HIGH byte first, so the
	 * stores combine most-significant first. Null for an instruction with no stack store.
	 */
	static Long pushedConstant(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		long value = 0;
		int n = 0;
		for (int j = 0; j < w.ops.length; j++) {
			if (w.ops[j].getOpcode() == PcodeOp.STORE && w.stackAccess[j]) {
				Long b = w.fold(j, w.ops[j].getInput(2));
				if (b == null || w.ops[j].getInput(2).getSize() != 1) {
					return null;
				}
				value = (value << 8) | (b & 0xff);
				n++;
			}
		}
		return n == 0 ? null : Long.valueOf(value);
	}

	/** {@link #dataAccess} bit: a non-stack {@code LOAD}. */
	static final int DATA_READ = 1;
	/** {@link #dataAccess} bit: a non-stack {@code STORE}. */
	static final int DATA_WRITE = 2;

	/**
	 * Which kinds of computed (non-stack) memory access the instruction makes: a bit set of
	 * {@link #DATA_READ} and {@link #DATA_WRITE}. {@code LDA abs} reads, {@code STA abs} writes,
	 * {@code INC abs}/{@code TSB} do both; pushes and pulls are stack traffic and count as neither.
	 */
	static int dataAccess(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		int bits = 0;
		for (int j = 0; j < w.ops.length; j++) {
			if (w.stackAccess[j]) {
				continue;
			}
			if (w.ops[j].getOpcode() == PcodeOp.LOAD) {
				bits |= DATA_READ;
			}
			else if (w.ops[j].getOpcode() == PcodeOp.STORE) {
				bits |= DATA_WRITE;
			}
		}
		return bits;
	}

	/**
	 * Whether the instruction leaves through a call, return or indirect jump ({@code CALL},
	 * {@code CALLIND}, {@code RETURN}, {@code BRANCHIND}): the calls, returns, interrupts and
	 * indirect jumps, which also touch the stack but are not stack transfers. Direct branches are
	 * not counted: a p-code-relative {@code CBRANCH} (65816 {@code PLP}) sits inside plain pulls.
	 */
	static boolean hasFlowOp(Instruction instr) {
		for (PcodeOp op : ops(instr)) {
			switch (op.getOpcode()) {
				case PcodeOp.BRANCHIND, PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN:
					return true;
				default:
					break;
			}
		}
		return false;
	}

	/**
	 * The (single) non-flag, non-SP register an instruction that loads from the stack writes
	 * ({@code PLA}, {@code PLX}, 65816 {@code PLB}/{@code PLD}), or null. A status pull
	 * ({@code PLP}, SPC700 {@code POP PSW}) and returns ({@code RTS}/{@code RTI}) write no such
	 * register and answer null.
	 */
	static Register pulledRegister(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		boolean pulls = false;
		for (int j = 0; j < w.ops.length; j++) {
			if (w.ops[j].getOpcode() == PcodeOp.LOAD && w.stackAccess[j]) {
				pulls = true;
			}
		}
		if (!pulls) {
			return null;
		}
		Register found = null;
		for (PcodeOp op : w.ops) {
			Varnode out = op.getOutput();
			if (out == null || !out.isRegister() || w.overlapsSp(out)) {
				continue;
			}
			Register r = w.registerFor(out);
			if (r == null || w.regs.isFlagStorage(r)) {
				continue;
			}
			if (found != null && !found.equals(r)) {
				return null;
			}
			found = r;
		}
		return found;
	}

	/**
	 * For a conditional branch on a single named flag, which flag and whether the branch is taken
	 * when it is SET ({@code BEQ}/{@code BCS}/{@code BMI}/{@code BVS}: true; {@code BNE}/{@code BCC}
	 * /{@code BPL}/{@code BVC}: false). Null when the condition is not one named flag (the 65816
	 * {@code BRA}, {@code BRL}, {@code JMP}, or an unrecognised flag such as the interrupt flag).
	 * The SPC700's flags are bits of {@code PSW} and are recognised through the usual
	 * {@code (PSW >> n) & 1} shapes.
	 */
	static FlagBranch branchOnFlag(Instruction instr) {
		Walk w = new Walk(instr);
		for (int j = 0; j < w.ops.length; j++) {
			if (w.ops[j].getOpcode() == PcodeOp.CBRANCH) {
				FlagBranch fb = w.condition(j, w.ops[j].getInput(1), 0);
				if (fb != null) {
					return fb;
				}
			}
		}
		return null;
	}

	/**
	 * Whether {@code instr} has a {@code RETURN} op: {@code RTS}, {@code RTL}, SPC700 {@code RET}.
	 * {@code RTI} is NOT uniformly a RETURN op (the 65816 sleigh ends it in an indirect goto, as it
	 * does {@code BRK}/{@code COP}/{@code STP}); callers that mean "RTS or RTI" keep an explicit
	 * RTI test. Use {@link Instruction#getFlowType()} for control-flow classification.
	 */
	static boolean isReturnOp(Instruction instr) {
		for (PcodeOp op : ops(instr)) {
			if (op.getOpcode() == PcodeOp.RETURN) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether {@code reg} ends up as {@code reg >> 1} (logical) computed from its own entry value
	 * ({@code LSR A}); the memory form writes no register and answers false, and {@code ROR}
	 * (shift OR carry) is not a plain shift.
	 */
	static boolean shiftRightBy1(Instruction instr, Register reg) {
		if (reg == null) {
			return false;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		Val v = w.finalValue(rv);
		if (v == null || v.kind != Val.OPAQUE || v.partial) {
			return false;
		}
		PcodeOp op = w.ops[v.op];
		return op.getOpcode() == PcodeOp.INT_RIGHT && w.isEntry(v.op, op.getInput(0), rv) &&
			isConst(op.getInput(1), 1);
	}

	/**
	 * The p-code opcode ({@link PcodeOp#INT_AND}, {@link PcodeOp#INT_OR} or {@link PcodeOp#INT_XOR})
	 * when {@code reg} ends up as {@code reg <op> x} computed from its own entry value ({@code AND},
	 * {@code ORA}, {@code EOR}), else -1. The other operand is not inspected: immediate or memory.
	 */
	static int bitOpOn(Instruction instr, Register reg) {
		if (reg == null) {
			return -1;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		Val v = w.finalValue(rv);
		if (v == null || v.kind != Val.OPAQUE || v.partial) {
			return -1;
		}
		PcodeOp op = w.ops[v.op];
		int opc = op.getOpcode();
		if (opc != PcodeOp.INT_AND && opc != PcodeOp.INT_OR && opc != PcodeOp.INT_XOR) {
			return -1;
		}
		return w.isEntry(v.op, op.getInput(0), rv) || w.isEntry(v.op, op.getInput(1), rv) ? opc
			: -1;
	}

	/**
	 * The constant {@code k} when {@code reg} ends up as {@code reg <opcode> k} with {@code k} an
	 * immediate ({@code AND #imm}, SPC700 {@code AND A,#imm}), where {@code opcode} is the p-code
	 * {@link PcodeOp#INT_AND}/{@code INT_OR}/{@code INT_XOR}; null for a memory operand or any
	 * other shape.
	 */
	static Long bitOpConstant(Instruction instr, Register reg, int opcode) {
		if (reg == null || bitOpOn(instr, reg) != opcode) {
			return null;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		Val v = w.finalValue(rv);
		PcodeOp op = w.ops[v.op];
		for (int i = 0; i < 2; i++) {
			if (w.isEntry(v.op, op.getInput(i), rv)) {
				Val other = w.trace(v.op, op.getInput(1 - i));
				return other.kind == Val.CONST ? Long.valueOf(other.c) : null;
			}
		}
		return null;
	}

	/**
	 * The constant {@code reg} is compared with when the instruction subtracts/compares {@code reg}'s
	 * entry value against an immediate ({@code CMP #imm}, {@code CPX #imm}, SPC700 {@code CMP A,#imm}),
	 * else null: read off the {@code INT_SUB}/{@code INT_LESS}/{@code INT_LESSEQUAL} the compare
	 * emits, whichever operand order, so a memory operand answers null.
	 */
	static Long compareImmediate(Instruction instr, Register reg) {
		if (reg == null) {
			return null;
		}
		Walk w = new Walk(instr);
		Varnode rv = varnodeOf(reg);
		for (int j = 0; j < w.ops.length; j++) {
			PcodeOp op = w.ops[j];
			int opc = op.getOpcode();
			if (opc != PcodeOp.INT_SUB && opc != PcodeOp.INT_LESS && opc != PcodeOp.INT_LESSEQUAL) {
				continue;
			}
			for (int i = 0; i < 2; i++) {
				if (w.isEntry(j, op.getInput(i), rv)) {
					Val other = w.trace(j, op.getInput(1 - i));
					if (other.kind == Val.CONST) {
						return other.c;
					}
				}
			}
		}
		return null;
	}

	/** An absolute-indexed load: {@code dst := *[base + index]} ({@code LDA abs,X}, SPC700 {@code MOV A,!abs+X}). */
	record IndexedLoad(Register dst, Register index, long base) {}

	/**
	 * The {@link IndexedLoad} the instruction performs (a non-stack {@code LOAD} whose address is a
	 * constant plus the entry value of one register, zero-extension looked through), or null.
	 */
	static IndexedLoad indexedLoad(Instruction instr) {
		Register dst = loadDestination(instr);
		if (dst == null) {
			return null;
		}
		Walk w = new Walk(instr);
		w.stackWalk();
		for (int j = 0; j < w.ops.length; j++) {
			PcodeOp op = w.ops[j];
			if (op.getOpcode() != PcodeOp.LOAD || w.stackAccess[j]) {
				continue;
			}
			Val addr = w.trace(j, op.getInput(1));
			if (addr.kind != Val.OPAQUE || addr.partial || addr.op < 0 ||
				w.ops[addr.op].getOpcode() != PcodeOp.INT_ADD) {
				continue;
			}
			PcodeOp add = w.ops[addr.op];
			for (int i = 0; i < 2; i++) {
				Val k = w.trace(addr.op, add.getInput(i));
				Val r = w.trace(addr.op, add.getInput(1 - i));
				if (k.kind == Val.CONST && r.kind == Val.LIVE && r.vn.isRegister()) {
					Register idx = w.registerFor(r.vn);
					if (idx != null) {
						return new IndexedLoad(dst, idx, k.c);
					}
				}
			}
		}
		return null;
	}

	/**
	 * {@code k} when the instruction read-modify-writes one memory cell as {@code cell + k}
	 * ({@code INC abs} = +1, {@code DEC zp,X} = -1), else null. The cell is either a fixed address
	 * (ram-space input and output) or a computed {@code LOAD}/{@code STORE} pair. Registers
	 * ({@code INX}) and plain stores answer null.
	 */
	static Integer rmwIncrement(Instruction instr) {
		Walk w = new Walk(instr);
		w.stackWalk();
		for (int j = 0; j < w.ops.length; j++) {
			PcodeOp op = w.ops[j];
			Varnode dst = null;
			Val v = null;
			if (op.getOpcode() == PcodeOp.STORE && !w.stackAccess[j]) {
				v = w.trace(j, op.getInput(2));
			}
			else if (op.getOutput() != null && w.isMemoryLike(op.getOutput()) && w.isCopyLike(op)) {
				dst = op.getOutput();
				v = w.eval(j);
			}
			if (v == null || v.kind != Val.OPAQUE || v.partial || v.op < 0) {
				continue;
			}
			PcodeOp add = w.ops[v.op];
			int opc = add.getOpcode();
			if (opc != PcodeOp.INT_ADD && opc != PcodeOp.INT_SUB) {
				continue;
			}
			Varnode a = add.getInput(0);
			Varnode b = add.getInput(1);
			if (a.isConstant() && opc == PcodeOp.INT_ADD) {
				Varnode t = a;
				a = b;
				b = t;
			}
			if (!b.isConstant()) {
				continue;
			}
			Val cell = w.trace(v.op, a);
			boolean fromCell = cell.kind == Val.LIVE && w.isMemoryLike(cell.vn) &&
				(dst == null || sameStorage(cell.vn, dst));
			if (cell.kind == Val.OPAQUE && !cell.partial && cell.op >= 0 &&
				w.ops[cell.op].getOpcode() == PcodeOp.LOAD && !w.stackAccess[cell.op]) {
				fromCell = dst == null;
			}
			if (fromCell) {
				long k = signed(b.getOffset(), b.getSize());
				return (int) (opc == PcodeOp.INT_ADD ? k : -k);
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Plumbing
	// ------------------------------------------------------------------

	private static PcodeOp[] ops(Instruction instr) {
		try {
			PcodeOp[] ops = instr.getPcode();
			return ops == null ? new PcodeOp[0] : ops;
		}
		catch (RuntimeException e) {
			return new PcodeOp[0];
		}
	}

	private static Varnode varnodeOf(Register reg) {
		return new Varnode(reg.getAddress(), reg.getMinimumByteSize());
	}

	private static boolean sameStorage(Varnode a, Varnode b) {
		return a != null && b != null && a.getAddress().equals(b.getAddress()) &&
			a.getSize() == b.getSize();
	}

	private static boolean overlaps(Varnode a, Varnode b) {
		if (!a.getAddress().getAddressSpace().equals(b.getAddress().getAddressSpace())) {
			return false;
		}
		long a0 = a.getOffset();
		long b0 = b.getOffset();
		return a0 < b0 + b.getSize() && b0 < a0 + a.getSize();
	}

	private static boolean contains(Varnode outer, Varnode inner) {
		return outer.getAddress().getAddressSpace().equals(inner.getAddress().getAddressSpace()) &&
			outer.getOffset() <= inner.getOffset() &&
			inner.getOffset() + inner.getSize() <= outer.getOffset() + outer.getSize();
	}

	private static boolean isConst(Varnode vn, long value) {
		return vn.isConstant() && vn.getOffset() == value;
	}

	private static long mask(int size) {
		return size >= 8 ? -1L : (1L << (8 * size)) - 1;
	}

	private static long signed(long v, int size) {
		int bits = 8 * Math.min(size, 8);
		if (bits >= 64) {
			return v;
		}
		v &= (1L << bits) - 1;
		return (v & (1L << (bits - 1))) != 0 ? v - (1L << bits) : v;
	}

	/** What a varnode holds at some point of the instruction. */
	private static final class Val {
		static final int CONST = 0;
		static final int LIVE = 1;
		static final int OPAQUE = 2;

		final int kind;
		/** LIVE: the entry-value varnode. OPAQUE: the defining op's output. */
		final Varnode vn;
		final long c;
		/** OPAQUE: index of the (non-copy) defining op. */
		final int op;
		/** OPAQUE: only a sub-range of the op's result. */
		final boolean partial;

		Val(int kind, Varnode vn, long c, int op, boolean partial) {
			this.kind = kind;
			this.vn = vn;
			this.c = c;
			this.op = op;
			this.partial = partial;
		}

		static Val konst(long c) {
			return new Val(CONST, null, c, -1, false);
		}

		static Val live(Varnode vn) {
			return new Val(LIVE, vn, 0, -1, false);
		}

		static Val opaque(int op, Varnode out, boolean partial) {
			return new Val(OPAQUE, out, 0, op, partial);
		}
	}

	/** Bit {@code bit} of register {@code reg}. */
	private record BitRef(Register reg, int bit) {}

	/** Symbolic stack-pointer value: not tracked / a constant / SP-at-entry plus an offset. */
	private record Sym(int k, long v) {
		static final int OTHER = 0;
		static final int CONST = 1;
		static final int SP = 2;
		static final Sym NONE = new Sym(OTHER, 0);
	}

	/** One instruction's op list plus the lookups the questions share. */
	private static final class Walk {
		final PcodeOp[] ops;
		final CpuRegs regs;
		final Language language;
		boolean[] stackAccess;
		OptionalInt delta = OptionalInt.empty();
		private boolean stackDone;

		Walk(Instruction instr) {
			this(instr, null);
		}

		Walk(Instruction instr, CpuRegs forced) {
			ops = PcodeShapes.ops(instr);
			language = instr.getProgram().getLanguage();
			regs = forced != null ? forced : CpuRegs.of(language);
			stackAccess = new boolean[ops.length];
		}

		// ---- value tracing ----

		int lastWrite(int before, Varnode vn) {
			for (int j = before - 1; j >= 0; j--) {
				Varnode out = ops[j].getOutput();
				if (out != null && overlaps(out, vn)) {
					return j;
				}
			}
			return -1;
		}

		/** The value of {@code vn} as read by op {@code idx}. */
		Val trace(int idx, Varnode vn) {
			if (vn.isConstant()) {
				return Val.konst(vn.getOffset() & mask(vn.getSize()));
			}
			int j = lastWrite(idx, vn);
			if (j < 0) {
				return Val.live(vn);
			}
			Varnode out = ops[j].getOutput();
			if (!contains(out, vn)) {
				return Val.opaque(j, out, true);
			}
			return piece(eval(j), (int) (vn.getOffset() - out.getOffset()), vn.getSize());
		}

		/** The constant {@code vn} holds as read by op {@code idx}, folded through integer ops; null if not constant. */
		Long fold(int idx, Varnode vn) {
			if (vn.isConstant()) {
				return vn.getOffset() & mask(vn.getSize());
			}
			int j = lastWrite(idx, vn);
			if (j < 0) {
				return null;
			}
			Varnode out = ops[j].getOutput();
			if (!contains(out, vn)) {
				return null;
			}
			Long v = foldOp(j);
			if (v == null) {
				return null;
			}
			return (v >>> (8 * (vn.getOffset() - out.getOffset()))) & mask(vn.getSize());
		}

		private Long foldOp(int j) {
			PcodeOp op = ops[j];
			int opc = op.getOpcode();
			long m = mask(op.getOutput().getSize());
			switch (opc) {
				case PcodeOp.COPY:
				case PcodeOp.INT_ZEXT: {
					Long a = fold(j, op.getInput(0));
					return a == null ? null : a & m;
				}
				case PcodeOp.SUBPIECE: {
					Long a = fold(j, op.getInput(0));
					return a == null || !op.getInput(1).isConstant() ? null
						: (a >>> (8 * op.getInput(1).getOffset())) & m;
				}
				case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_AND, PcodeOp.INT_OR,
						PcodeOp.INT_XOR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT: {
					Long a = fold(j, op.getInput(0));
					Long b = fold(j, op.getInput(1));
					if (a == null || b == null) {
						return null;
					}
					long r;
					switch (opc) {
						case PcodeOp.INT_ADD -> r = a + b;
						case PcodeOp.INT_SUB -> r = a - b;
						case PcodeOp.INT_AND -> r = a & b;
						case PcodeOp.INT_OR -> r = a | b;
						case PcodeOp.INT_XOR -> r = a ^ b;
						case PcodeOp.INT_LEFT -> r = b >= 64 ? 0 : a << b;
						default -> r = b >= 64 ? 0 : a >>> b;
					}
					return r & m;
				}
				default:
					return null;
			}
		}

		/** The value op {@code j} leaves in its output, looking through copy-like ops. */
		Val eval(int j) {
			PcodeOp op = ops[j];
			switch (op.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.INT_ZEXT:
					return trace(j, op.getInput(0));
				case PcodeOp.SUBPIECE:
					if (op.getInput(1).isConstant()) {
						return piece(trace(j, op.getInput(0)), (int) op.getInput(1).getOffset(),
							op.getOutput().getSize());
					}
					return Val.opaque(j, op.getOutput(), false);
				default:
					return Val.opaque(j, op.getOutput(), false);
			}
		}

		boolean isCopyLike(PcodeOp op) {
			int c = op.getOpcode();
			return c == PcodeOp.COPY || c == PcodeOp.INT_ZEXT ||
				(c == PcodeOp.SUBPIECE && op.getInput(1).isConstant());
		}

		private Val piece(Val v, int d, int size) {
			switch (v.kind) {
				case Val.CONST:
					return Val.konst((v.c >>> (8 * d)) & mask(size));
				case Val.LIVE:
					if (d == 0 && size >= v.vn.getSize()) {
						return v; // also the zero-extension case: the narrower source stands
					}
					if (d + size <= v.vn.getSize()) {
						return Val.live(new Varnode(v.vn.getAddress().add(d), size));
					}
					return Val.opaque(-1, v.vn, true);
				default:
					return d == 0 && size >= v.vn.getSize() ? v
						: new Val(Val.OPAQUE, v.vn, 0, v.op, true);
			}
		}

		/** The value {@code vn} holds at the end of the instruction when it is written at exactly
		 * its own width; null otherwise. */
		Val finalValue(Varnode vn) {
			int j = lastWrite(ops.length, vn);
			if (j < 0 || !sameStorage(ops[j].getOutput(), vn)) {
				return null;
			}
			return eval(j);
		}

		/** Whether {@code in}, read by op {@code idx}, is {@code reg}'s entry value. */
		boolean isEntry(int idx, Varnode in, Varnode reg) {
			Val v = trace(idx, in);
			return v.kind == Val.LIVE && sameStorage(v.vn, reg);
		}

		// ---- classification ----

		Register registerFor(Varnode vn) {
			Register r = language.getRegister(vn.getAddress(), vn.getSize());
			if (r != null) {
				return r;
			}
			Register best = null;
			for (Register c : language.getRegisters(vn.getAddress())) {
				if (c.getMinimumByteSize() >= vn.getSize() &&
					(best == null || c.getMinimumByteSize() < best.getMinimumByteSize())) {
					best = c;
				}
			}
			return best;
		}

		/** A ram-space location or a memory-mapped register (the 6510 port). */
		boolean isMemoryLike(Varnode vn) {
			if (vn.getAddress().isMemoryAddress()) {
				return true;
			}
			if (vn.isRegister()) {
				for (Register p : regs.ioPorts()) {
					if (overlaps(vn, varnodeOf(p))) {
						return true;
					}
				}
			}
			return false;
		}

		boolean overlapsSp(Varnode vn) {
			Register sp = regs.sp();
			return sp != null && vn.isRegister() && overlaps(vn, varnodeOf(sp));
		}

		private boolean atSpBase(Varnode vn) {
			Register sp = regs.sp();
			return sp != null && vn.getAddress().equals(sp.getAddress());
		}

		// ---- symbolic stack pointer ----

		void stackWalk() {
			if (stackDone) {
				return;
			}
			stackDone = true;
			Register sp = regs.sp();
			if (sp == null) {
				return;
			}
			Map<String, Sym> tmp = new HashMap<>();
			long cur = 0;
			boolean lost = false;
			for (int j = 0; j < ops.length; j++) {
				PcodeOp op = ops[j];
				int opc = op.getOpcode();
				if (opc == PcodeOp.LOAD || opc == PcodeOp.STORE) {
					stackAccess[j] = sym(op.getInput(1), tmp, cur).k() == Sym.SP;
				}
				Varnode out = op.getOutput();
				if (out == null) {
					continue;
				}
				Sym s = opc == PcodeOp.LOAD ? Sym.NONE : compute(op, tmp, cur);
				if (out.isUnique()) {
					tmp.put(out.getOffset() + ":" + out.getSize(), s);
				}
				else if (overlapsSp(out) && atSpBase(out)) {
					if (s.k() == Sym.SP) {
						cur = s.v();
					}
					else {
						lost = true;
					}
				}
			}
			delta = lost ? OptionalInt.empty() : OptionalInt.of((int) cur);
		}

		private Sym sym(Varnode vn, Map<String, Sym> tmp, long cur) {
			if (vn.isConstant()) {
				return new Sym(Sym.CONST, vn.getOffset());
			}
			if (vn.isUnique()) {
				return tmp.getOrDefault(vn.getOffset() + ":" + vn.getSize(), Sym.NONE);
			}
			if (overlapsSp(vn) && atSpBase(vn)) {
				return new Sym(Sym.SP, cur);
			}
			return Sym.NONE;
		}

		private Sym compute(PcodeOp op, Map<String, Sym> tmp, long cur) {
			switch (op.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.INT_ZEXT:
					return sym(op.getInput(0), tmp, cur);
				case PcodeOp.SUBPIECE:
					return isConst(op.getInput(1), 0) ? sym(op.getInput(0), tmp, cur) : Sym.NONE;
				case PcodeOp.INT_ADD:
				case PcodeOp.INT_SUB: {
					Sym a = sym(op.getInput(0), tmp, cur);
					Sym b = sym(op.getInput(1), tmp, cur);
					boolean add = op.getOpcode() == PcodeOp.INT_ADD;
					if (a.k() == Sym.SP && b.k() == Sym.CONST) {
						long c = signed(b.v(), op.getInput(1).getSize());
						return new Sym(Sym.SP, add ? a.v() + c : a.v() - c);
					}
					if (add && a.k() == Sym.CONST && b.k() == Sym.SP) {
						return new Sym(Sym.SP, b.v() + signed(a.v(), op.getInput(0).getSize()));
					}
					return Sym.NONE;
				}
				case PcodeOp.INT_OR: {
					// the SPC700 page form 0x0100 | zext(SP:1): same stack slot
					Sym a = sym(op.getInput(0), tmp, cur);
					Sym b = sym(op.getInput(1), tmp, cur);
					if (a.k() == Sym.SP && b.k() == Sym.CONST) {
						return a;
					}
					if (b.k() == Sym.SP && a.k() == Sym.CONST) {
						return b;
					}
					return Sym.NONE;
				}
				default:
					return Sym.NONE;
			}
		}

		// ---- branch conditions ----

		FlagBranch condition(int idx, Varnode cond, int depth) {
			if (depth > 4) {
				return null;
			}
			Val v = trace(idx, cond);
			BitRef ref = bitRef(v, false);
			if (ref != null) {
				return flagBranch(ref, true);
			}
			if (v.kind != Val.OPAQUE || v.partial || v.op < 0) {
				return null;
			}
			PcodeOp op = ops[v.op];
			switch (op.getOpcode()) {
				case PcodeOp.INT_EQUAL:
				case PcodeOp.INT_NOTEQUAL: {
					Varnode a = op.getInput(0);
					Varnode k = op.getInput(1);
					if (a.isConstant()) {
						Varnode t = a;
						a = k;
						k = t;
					}
					if (!k.isConstant() || k.getOffset() > 1) {
						return null;
					}
					Val av = trace(v.op, a);
					BitRef r = bitRef(av, false);
					if (r == null) {
						return null;
					}
					boolean eq = op.getOpcode() == PcodeOp.INT_EQUAL;
					return flagBranch(r, (k.getOffset() == 1) == eq);
				}
				case PcodeOp.BOOL_NEGATE: {
					FlagBranch inner = condition(v.op, op.getInput(0), depth + 1);
					return inner == null ? null
						: new FlagBranch(inner.kind(), !inner.takenWhenSet());
				}
				default:
					return null;
			}
		}

		private FlagBranch flagBranch(BitRef ref, boolean set) {
			CpuRegs.FlagKind kind = regs.kindOf(ref.reg(), ref.bit());
			return kind == null ? null : new FlagBranch(kind, set);
		}

		/**
		 * Resolves {@code v} to "bit b of register r" through {@code (x >> c) & 1} and plain 0/1
		 * flag registers, or null. A raw read of the SPC700 {@code PSW} counts only once masked or
		 * shifted to a single bit.
		 */
		private BitRef bitRef(Val v, boolean masked) {
			if (v.kind == Val.LIVE) {
				if (!v.vn.isRegister()) {
					return null;
				}
				Register r = registerFor(v.vn);
				if (r == null || (!masked && regs.psw() != null && regs.psw().equals(r))) {
					return null;
				}
				return new BitRef(r, 0);
			}
			if (v.kind != Val.OPAQUE || v.partial || v.op < 0) {
				return null;
			}
			PcodeOp op = ops[v.op];
			if (op.getOpcode() == PcodeOp.INT_AND) {
				Varnode x = op.getInput(0);
				Varnode m = op.getInput(1);
				if (x.isConstant()) {
					Varnode t = x;
					x = m;
					m = t;
				}
				return isConst(m, 1) ? bitRef(trace(v.op, x), true) : null;
			}
			if (op.getOpcode() == PcodeOp.INT_RIGHT && op.getInput(1).isConstant()) {
				int c = (int) op.getInput(1).getOffset();
				Varnode x = op.getInput(0);
				BitRef inner = bitRef(trace(v.op, x), masked || c == 8 * x.getSize() - 1);
				return inner == null ? null : new BitRef(inner.reg(), inner.bit() + c);
			}
			return null;
		}
	}
}
