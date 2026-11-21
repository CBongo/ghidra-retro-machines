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

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

/**
 * Measures how a 6502 subroutine returns (grm-ed6h, grm-0fzb, grm-tysk): through WHICH caller's
 * return address (its unwind {@link Unwind#level level}), advanced by how many bytes (its
 * {@link Unwind#skip skip}), and whether it also advances its CALLER'S return address
 * ({@link Unwind#callerSkip callerSkip}).
 *
 * <ul>
 * <li>Level 0, skip 0: a normal subroutine.</li>
 * <li>Level 1: discards the return address its {@code JSR} pushed and continues to its CALLER'S
 * caller, so the {@code JSR} never falls through. {@code PLA / PLA / RTS} (Metroid {@code c376}),
 * the inline-table JumpEngine ({@code ... PLA / PLA ... JMP (ind)}, smb {@code 8e04}) and the
 * inline-argument far-call trampoline (dbz_saiyan {@code c9c2}) are all level 1; {@code PLA} x4
 * is level 2.</li>
 * <li>Level 0, skip n: reads n INLINE argument bytes after its {@code JSR} and returns past
 * them, to {@code JSR+3+n}. db3 {@code db4c} pops its return address, reads the target word,
 * pushes the address back plus 2 and returns through it.</li>
 * <li>callerSkip n: rewrites its caller's return address in place ({@code TSX / LDA $0103,X /
 * ... / STA $0103,X}): drmario {@code b74b}, so its caller {@code b6c2} returns past ITS inline
 * word.</li>
 * </ul>
 *
 * <p>The walk follows every path from the entry through the listing's existing instructions,
 * keeping a small SYMBOLIC state: the stack as slots relative to the entry stack pointer (slot 0
 * and -1 are the entry's own return address, -2 and -3 its caller's, and so on), A, X, Y, the
 * carry, and the RAM cells the routine stores to. Return-address bytes are tracked as values
 * ({@code LO(frame)+k}, {@code HI(frame)}) through {@code PLA/PHA}, {@code STA/LDA},
 * {@code TAY/TYA}, {@code CLC/SEC} + {@code ADC #n}, and {@code TSX}-relative {@code $01xx,X}
 * reads and writes. An {@code RTS} at depth {@code d} returns through slots {@code d} (low) and
 * {@code d-1} (high): if they hold {@code LO(f)+k} and {@code HI(f)}, that exit is level f,
 * skip k. Other exits:
 * <ul>
 * <li>an indirect {@code JMP} through a cell holding a return address the routine popped (and
 * stepped with {@code INC}): a return to that address. If it also popped its caller's return
 * address first (Seven Cities of Gold ea2 {@code c4e8}: {@code PLA/STA $22/PLA/STA $23}, two
 * more {@code PLA}s, {@code INC $22}, {@code JMP ($0022)}), it is level 0 with
 * {@link Unwind#delta} -2: its {@code JSR} falls through, and the CALLER, now short of its own
 * return address, measures one level up;</li>
 * <li>any other indirect {@code JMP} at a negative depth: a tail call into code that returns
 * normally, so the same as {@code RTS} there (at depth 0 it is declined: nothing says the code
 * returns);</li>
 * <li>a {@code JSR} to a callee of level {@code k >= 1}: the callee returns through OUR slots,
 * the same as {@code RTS} at {@code d - 2(k-1)}. A {@code JSR} to a level-0 callee continues at
 * {@code JSR+3+skip} after applying the callee's callerSkip to our return slot, so a far-call stub
 * ({@code JSR helper} + inline bytes) is level 0;</li>
 * <li>ASSUMED (owner ruling, grm-tysk): a {@code JMP abs} taken AFTER the routine advanced its own
 * return address, into code the walk cannot measure, is taken to return normally. That is
 * drmario {@code b6c2}'s tail into its PPU script interpreter {@code b71c}, which keeps a script
 * call stack on the 6502 stack (script {@code $4C} pushes, {@code $60} pops) that pairs up only
 * at run time. {@link Unwind#assumed} records it, so a wrong assumption is visible in the log;
 * add a per-game hint only if one turns out wrong.</li>
 * </ul>
 * Every exit must agree. Anything else on any path is a decline: exits that disagree (Metroid
 * {@code c36b}'s {@code BCC} to the shared RTS), an {@code RTS} through bytes that are not a
 * return address (the RTS dispatch trick), an {@code RTI}/{@code BRK}, a {@code TXS} from an
 * untracked X (a stack reset such as {@code LDX #$FF / TXS}: a genuinely non-returning routine
 * stays declined), a {@code JSR} that does not fall through to a callee not known to unwind, a
 * depth outside a small window, or no exit at all (an infinite loop). A {@code JSR} to any other
 * callee is assumed stack-neutral and to clobber A, X, Y and the carry.
 *
 * <p>A path through a NON-overlay block that overlay banks overlap is also a decline: that block
 * is the base-space copy of a switchable window, holding whichever bank the loader laid there,
 * not necessarily the one live at the call (dodge {@code 800c} and smb3 {@code b44a} were
 * recognized on those bytes and cost each row hundreds of real instructions). Overlay blocks
 * (bank already resolved) and fixed blocks (Metroid {@code c376}) are trusted.
 *
 * @see <a href="urn:bead:grm-ed6h">grm-ed6h</a>
 * @see <a href="urn:bead:grm-0fzb">grm-0fzb</a>
 * @see <a href="urn:bead:grm-tysk">grm-tysk</a>
 */
final class PopReturnHelper {

	/** Return-address bytes a 6502 JSR pushes. */
	static final int RETURN_BYTES = 2;
	static final int MAX_LEVEL = 3;
	/** Largest inline-argument count accepted. */
	static final int MAX_SKIP = 8;
	private static final int MIN_DEPTH = -RETURN_BYTES * MAX_LEVEL;
	private static final int MAX_DEPTH = 16;
	private static final int MAX_STATES = 1024;
	private static final int MAX_CELLS = 16;

	/**
	 * How a subroutine returns.
	 *
	 * @param level caller frames discarded (0 = returns to its caller), or -1 for a decline
	 * @param skip inline bytes skipped past {@code JSR+3} (level 0 only)
	 * @param callerSkip bytes its caller's return address is advanced in place (level 0 only)
	 * @param delta stack bytes the continuation has LOST compared with a plain return (level 0
	 *     only; 0 or negative): ea2 {@code c4e8} pops its caller's return address too, then jumps
	 *     back to its own {@code JSR+3}, so it is level 0 with delta -2
	 * @param assumed true if the measurement rests on an assumed stack-neutral tail jump
	 */
	record Unwind(int level, int skip, int callerSkip, int delta, boolean assumed) {

		static final Unwind DECLINE = new Unwind(-1, 0, 0, 0, false);
		static final Unwind NORMAL = new Unwind(0, 0, 0, 0, false);

		boolean declined() {
			return level < 0;
		}

		/** Level 1 or more: a {@code JSR} to it never falls through. */
		boolean discards() {
			return level >= 1;
		}

		/** Returns to its caller, possibly past inline bytes. */
		boolean returns() {
			return level == 0;
		}

		boolean sameShape(Unwind o) {
			return level == o.level && skip == o.skip && callerSkip == o.callerSkip &&
				delta == o.delta;
		}
	}

	private PopReturnHelper() {
	}

	/**
	 * Per-program memo, resolving callees recursively. Conclusive answers are cached; an
	 * inconclusive one is asked again next time. A call cycle reads as a decline.
	 */
	static final class Levels {
		private final Program program;
		private final Map<Address, Unwind> cache = new HashMap<>();
		private final Set<Address> inProgress = new HashSet<>();

		Levels(Program program) {
			this.program = program;
		}

		/** Returns how the subroutine at {@code entry} returns, or null if inconclusive. */
		Unwind of(Address entry) {
			Unwind cached = cache.get(entry);
			if (cached != null) {
				return cached;
			}
			if (!inProgress.add(entry)) {
				return Unwind.DECLINE;
			}
			Unwind result;
			try {
				result = measure(program, entry, this::of);
			}
			finally {
				inProgress.remove(entry);
			}
			if (result != null) {
				cache.put(entry, result);
			}
			return result;
		}
	}

	/** Level 1 or more: a {@code JSR} to {@code entry} never falls through. */
	static Boolean recognize(Program program, Address entry) {
		Unwind u = new Levels(program).of(entry);
		return u == null ? null : u.discards();
	}

	// ---- symbolic values -------------------------------------------------------------------

	private static final int UNK = 0;
	private static final int CONST = 1;
	private static final int LO = 2;
	private static final int HI = 3;
	/** The carry out of {@code LO(frame)+k}: what makes {@code HI(frame) + 0 + C} a 16-bit add. */
	private static final int CARRY = 4;

	/** A tracked byte: unknown, a constant, or one byte of some frame's return address. */
	private record Val(int kind, int frame, int k) {
		static final Val UNKNOWN = new Val(UNK, 0, 0);

		static Val constant(int v) {
			return new Val(CONST, 0, v & 0xff);
		}

		static Val lo(int frame, int k) {
			return new Val(LO, frame, k);
		}

		static Val hi(int frame) {
			return new Val(HI, frame, 0);
		}
	}

	/** The original content of an unwritten slot: entry's own and its callers' return bytes. */
	private static Val original(int slot) {
		if (slot > 0) {
			return Val.UNKNOWN;
		}
		return (slot & 1) == 0 ? Val.lo(-slot / 2, 0) : Val.hi((-slot - 1) / 2);
	}

	/** Walk state; maps are immutable copies so states compare by content. */
	private record State(Address addr, int depth, Integer xRel, Val a, Val x, Val y, Val carry,
			Map<Integer, Val> slots, Map<Long, Val> cells) {
	}

	/** Mutable working copy of a {@link State}. */
	private static final class Regs {
		int depth;
		Integer xRel;
		Val a;
		Val x;
		Val y;
		Val carry;
		final Map<Integer, Val> slots;
		final Map<Long, Val> cells;

		Regs(State s) {
			depth = s.depth();
			xRel = s.xRel();
			a = s.a();
			x = s.x();
			y = s.y();
			carry = s.carry();
			slots = new HashMap<>(s.slots());
			cells = new HashMap<>(s.cells());
		}

		Val slot(int i) {
			Val v = slots.get(i);
			return v != null ? v : original(i);
		}

		State at(Address addr) {
			return new State(addr, depth, xRel, a, x, y, carry, Map.copyOf(slots),
				Map.copyOf(cells));
		}

		void clobber() {
			a = Val.UNKNOWN;
			x = Val.UNKNOWN;
			y = Val.UNKNOWN;
			carry = Val.UNKNOWN;
			xRel = null;
		}
	}

	/** A decoded operand: immediate, a RAM cell, a stack slot, the accumulator, or untracked. */
	private record Operand(int kind, long value) {
		static final int NONE = 0;
		static final int IMM = 1;
		static final int CELL = 2;
		static final int SLOT = 3;
		static final int ACC = 4;
		static final Operand UNTRACKED = new Operand(NONE, 0);
	}

	private static Operand operand(Instruction instr, Integer xRel) {
		if (instr.getNumOperands() < 1) {
			return Operand.UNTRACKED;
		}
		Long base = null;
		boolean address = false;
		boolean indexedByX = false;
		for (Object o : instr.getOpObjects(0)) {
			if (o instanceof Register reg) {
				if (!reg.getName().equals("X") || indexedByX) {
					return Operand.UNTRACKED;
				}
				indexedByX = true;
			}
			else if (base == null && (o instanceof Address || o instanceof Scalar)) {
				address = o instanceof Address;
				base = o instanceof Address ad ? ad.getOffset() : ((Scalar) o).getUnsignedValue();
			}
			else {
				return Operand.UNTRACKED;
			}
		}
		if (base == null) {
			return Operand.UNTRACKED;
		}
		if (indexedByX) {
			if (base >= 0x100 && base < 0x200 && xRel != null) {
				// $0101+S0 is slot 0 and X = S0 + xRel
				return new Operand(Operand.SLOT, 0x101 - base - xRel);
			}
			return Operand.UNTRACKED;
		}
		return address ? new Operand(Operand.CELL, base) : new Operand(Operand.IMM, base);
	}

	/** What an instruction does to the tracked machine, read off its p-code (grm-jjuc W2). */
	private enum Effect {
		PHA, PHP, PLA, PLP, TSX, INX, DEX, TXS, LDX, TAX, TXA, LDY, TAY, TYA, WRITES_Y, LDA, STA,
		STX, STY, CLC, SEC, ADC, SBC, WRITES_A, WRITES_CARRY, INC_DEC, SHIFT, RTS, INTERRUPT, OTHER
	}

	private static Effect effect(Instruction instr) {
		switch (MosOperands.stackOp(instr)) {
			case PUSH_A:
				return Effect.PHA;
			case PUSH_STATUS:
				return Effect.PHP;
			case PULL_A:
				return Effect.PLA;
			case PULL_STATUS:
				return Effect.PLP;
			default:
				break;
		}
		if (CpuRegs.of(instr.getProgram().getLanguage()).psw() == null &&
			MosOperands.isSubroutineReturn(instr)) {
			return Effect.RTS;
		}
		if (MosOperands.isInterruptReturn(instr)) {
			return Effect.INTERRUPT;
		}
		FlowType flow = instr.getFlowType();
		if (flow.isComputed() && flow.isJump() && instr.getNumOperands() == 0) {
			return Effect.INTERRUPT; // BRK: a jump through the interrupt vector
		}
		CpuRegs regs = CpuRegs.of(instr.getProgram().getLanguage());
		if (MosOperands.copiesStackPointerInto(instr, 'X')) {
			return Effect.TSX;
		}
		if (!flow.isCall() && PcodeShapes.netStackDelta(instr, regs).isEmpty() &&
			PcodeShapes.readsRegister(instr, regs.x())) {
			return Effect.TXS;
		}
		switch (MosOperands.loadedRegister(instr)) {
			case 'X':
				return Effect.LDX;
			case 'Y':
				return Effect.LDY;
			case 'A':
				return Effect.LDA;
			default:
				break;
		}
		Character from = MosOperands.transferSource(instr, 'X');
		if (from != null && from == 'A') {
			return Effect.TAX;
		}
		from = MosOperands.transferSource(instr, 'Y');
		if (from != null && from == 'A') {
			return Effect.TAY;
		}
		from = MosOperands.transferSource(instr, 'A');
		if (from != null) {
			return from == 'X' ? Effect.TXA : Effect.TYA;
		}
		if (MosOperands.storesRegister(instr, 'A')) {
			return Effect.STA;
		}
		if (MosOperands.storesRegister(instr, 'X')) {
			return Effect.STX;
		}
		if (MosOperands.storesRegister(instr, 'Y')) {
			return Effect.STY;
		}
		Integer carry = MosOperands.constantCarry(instr);
		if (carry != null) {
			return carry == 0 ? Effect.CLC : Effect.SEC;
		}
		// ADC/SBC stay mnemonic (decimal-flag branch, stock carry bugs: grm-jjuc design R1/W4)
		String mn = instr.getMnemonicString();
		if (mn.equals("ADC")) {
			return Effect.ADC;
		}
		if (mn.equals("SBC")) {
			return Effect.SBC;
		}
		if (MosOperands.incrementsBy(instr, 'X', 1)) {
			return Effect.INX;
		}
		if (MosOperands.incrementsBy(instr, 'X', -1)) {
			return Effect.DEX;
		}
		if (MosOperands.modifiesRegister(instr, 'Y') &&
			!MosOperands.modifiesRegister(instr, 'A')) {
			return Effect.WRITES_Y;
		}
		if (PcodeShapes.incrementOf(instr, regs.acc()) != null ||
			PcodeShapes.rmwIncrement(instr) != null) {
			return Effect.INC_DEC;
		}
		boolean writesCarry = PcodeShapes.writesRegister(instr, regs.carry().reg());
		if (writesCarry && (PcodeShapes.writesRegister(instr, regs.acc()) ||
			PcodeShapes.writesMemory(instr))) {
			return Effect.SHIFT;
		}
		if (PcodeShapes.writesRegister(instr, regs.acc())) {
			return Effect.WRITES_A;
		}
		return writesCarry ? Effect.WRITES_CARRY : Effect.OTHER;
	}

	private static Val read(Regs r, Operand o) {
		return switch (o.kind()) {
			case Operand.IMM -> Val.constant((int) o.value());
			case Operand.CELL -> r.cells.getOrDefault(o.value(), Val.UNKNOWN);
			case Operand.SLOT -> r.slot((int) o.value());
			case Operand.ACC -> r.a;
			default -> Val.UNKNOWN;
		};
	}

	private static void write(Regs r, Operand o, Val v) {
		switch (o.kind()) {
			case Operand.CELL -> {
				if (r.cells.size() < MAX_CELLS || r.cells.containsKey(o.value())) {
					r.cells.put(o.value(), v);
				}
			}
			case Operand.SLOT -> r.slots.put((int) o.value(), v);
			case Operand.ACC -> r.a = v;
			default -> {
				// untracked store: an index we cannot follow
			}
		}
	}

	/** {@code a + b + carry}, kept symbolic for a return address plus a constant. */
	private static void adc(Regs r, Val b) {
		Val a = r.a;
		Val c = r.carry;
		boolean loIsA = a.kind() == LO;
		Val lo = loIsA ? a : b.kind() == LO ? b : null;
		Val other = loIsA ? b : a;
		if (lo != null && other.kind() == CONST && c.kind() == CONST) {
			r.a = Val.lo(lo.frame(), lo.k() + other.k() + c.k());
			r.carry = new Val(CARRY, lo.frame(), 0);
			return;
		}
		boolean hiIsA = a.kind() == HI;
		Val hi = hiIsA ? a : b.kind() == HI ? b : null;
		Val rest = hiIsA ? b : a;
		if (hi != null && rest.kind() == CONST && rest.k() == 0 &&
			((c.kind() == CARRY && c.frame() == hi.frame()) ||
				(c.kind() == CONST && c.k() == 0))) {
			r.a = hi;
			r.carry = Val.UNKNOWN;
			return;
		}
		r.a = Val.UNKNOWN;
		r.carry = Val.UNKNOWN;
	}

	/** The exit an RTS at {@code depth} takes, plus {@code extraSkip}; DECLINE if not a return. */
	private static Unwind exitAt(Regs r, int depth, int extraSkip, boolean assumed) {
		Val lo = r.slot(depth);
		return lo.kind() != LO ? Unwind.DECLINE
				: exitThrough(r, lo, r.slot(depth - 1), depth - RETURN_BYTES, lo.k() + extraSkip,
					assumed);
	}

	/**
	 * The exit through return address {@code lo}/{@code hi} landing {@code skip} bytes past
	 * {@code JSR+3}, with the stack at {@code after} (relative to entry) when the continuation
	 * runs; DECLINE if they are not one frame's return address or the stack is off.
	 */
	private static Unwind exitThrough(Regs r, Val lo, Val hi, int after, int skip,
			boolean assumed) {
		if (lo.kind() != LO || hi.kind() != HI || lo.frame() != hi.frame()) {
			return Unwind.DECLINE;
		}
		int level = lo.frame();
		// a plain return through frame f leaves the stack at -2f-2; the continuation may have
		// LOST bytes (ea2 c4e8 popped its caller's frame first), but never gains stray ones (an
		// RTS through a COPY of the return address pushed higher)
		int delta = after + RETURN_BYTES * (level + 1);
		if (delta > 0 || delta % RETURN_BYTES != 0 || delta < -RETURN_BYTES * MAX_LEVEL ||
			level > MAX_LEVEL || skip < 0 || skip > MAX_SKIP ||
			(level > 0 && (skip != 0 || delta != 0))) {
			return Unwind.DECLINE;
		}
		int callerSkip = 0;
		if (level == 0) {
			Val clo = r.slot(-2);
			Val chi = r.slot(-1 - 2);
			if (clo.kind() != LO || clo.frame() != 1 || chi.kind() != HI || chi.frame() != 1) {
				return Unwind.DECLINE;
			}
			callerSkip = clo.k();
			if (callerSkip < 0 || callerSkip > MAX_SKIP) {
				return Unwind.DECLINE;
			}
		}
		return new Unwind(level, skip, callerSkip, delta, assumed);
	}

	/** {@code INC}/{@code DEC} of a tracked byte: a return address's low byte moves by one. */
	private static Val step(Val v, int by) {
		return switch (v.kind()) {
			case LO -> Val.lo(v.frame(), v.k() + by);
			// the high byte only absorbs the low byte's carry (INC lo / BNE / INC hi)
			case HI -> v;
			case CONST -> Val.constant(v.k() + by);
			default -> Val.UNKNOWN;
		};
	}

	/** Advances the return address in our slots {@code d}/{@code d-1} by {@code n}. */
	private static boolean advance(Regs r, int d, int n) {
		if (n == 0) {
			return true;
		}
		Val lo = r.slot(d);
		if (lo.kind() != LO) {
			return false;
		}
		r.slots.put(d, Val.lo(lo.frame(), lo.k() + n));
		r.slots.put(d - 1, r.slot(d - 1));
		return true;
	}

	/**
	 * Measures the subroutine at {@code entry}.
	 *
	 * @param callee how a called subroutine returns, or null if not yet known
	 * @return the measurement ({@link Unwind#DECLINE} for a decline), or null if a path runs into
	 *     an address that has no instruction yet
	 */
	static Unwind measure(Program program, Address entry, Function<Address, Unwind> callee) {
		Listing listing = program.getListing();
		ArrayDeque<State> work = new ArrayDeque<>();
		Set<State> seen = new HashSet<>();
		Map<MemoryBlock, Boolean> ambiguous = new HashMap<>();
		work.add(new State(entry, 0, null, Val.UNKNOWN, Val.UNKNOWN, Val.UNKNOWN, Val.UNKNOWN,
			Map.of(), Map.of()));
		Unwind result = null;
		while (!work.isEmpty()) {
			State s = work.poll();
			if (!seen.add(s)) {
				continue;
			}
			if (seen.size() > MAX_STATES) {
				return Unwind.DECLINE;
			}
			Instruction instr = listing.getInstructionAt(s.addr());
			if (instr == null) {
				return null;
			}
			MemoryBlock block = program.getMemory().getBlock(s.addr());
			if (block == null || ambiguous.computeIfAbsent(block,
				b -> !b.isOverlay() && SplitDispatchTableAnalyzer.isBanked(program, b))) {
				return Unwind.DECLINE;
			}
			Regs r = new Regs(s);
			Unwind exit = null;
			switch (effect(instr)) {
				case PHA -> {
					r.depth++;
					r.slots.put(r.depth, r.a);
				}
				case PHP -> {
					r.depth++;
					r.slots.put(r.depth, Val.UNKNOWN);
				}
				case PLA -> {
					r.a = r.slot(r.depth);
					r.depth--;
				}
				case PLP -> {
					r.carry = Val.UNKNOWN;
					r.depth--;
				}
				// S = S0 - depth, so TSX leaves X = S0 - depth: track X relative to S0
				case TSX -> {
					r.xRel = -r.depth;
					r.x = Val.UNKNOWN;
				}
				case INX -> {
					r.xRel = r.xRel == null ? null : r.xRel + 1;
					r.x = Val.UNKNOWN;
				}
				case DEX -> {
					r.xRel = r.xRel == null ? null : r.xRel - 1;
					r.x = Val.UNKNOWN;
				}
				case TXS -> {
					if (r.xRel == null) {
						return Unwind.DECLINE;
					}
					r.depth = -r.xRel;
				}
				case LDX -> {
					r.x = read(r, operand(instr, r.xRel));
					r.xRel = null;
				}
				case TAX -> {
					r.x = r.a;
					r.xRel = null;
				}
				case TXA -> r.a = r.xRel == null ? r.x : Val.UNKNOWN;
				case LDY -> r.y = read(r, operand(instr, r.xRel));
				case TAY -> r.y = r.a;
				case TYA -> r.a = r.y;
				case WRITES_Y -> r.y = Val.UNKNOWN;
				case LDA -> r.a = read(r, operand(instr, r.xRel));
				case STA -> write(r, operand(instr, r.xRel), r.a);
				case STX -> write(r, operand(instr, r.xRel), r.x);
				case STY -> write(r, operand(instr, r.xRel), r.y);
				case CLC -> r.carry = Val.constant(0);
				case SEC -> r.carry = Val.constant(1);
				case ADC -> adc(r, read(r, operand(instr, r.xRel)));
				case WRITES_A -> r.a = Val.UNKNOWN;
				case SBC -> {
					r.a = Val.UNKNOWN;
					r.carry = Val.UNKNOWN;
				}
				case WRITES_CARRY -> r.carry = Val.UNKNOWN;
				case INC_DEC -> {
					Operand o = incDecOperand(instr, r.xRel);
					write(r, o, step(read(r, o), incDecStep(instr)));
				}
				case SHIFT -> {
					write(r, shiftOperand(instr, r.xRel), Val.UNKNOWN);
					r.carry = Val.UNKNOWN;
				}
				case RTS -> exit = exitAt(r, r.depth, 0, false);
				case INTERRUPT -> {
					return Unwind.DECLINE;
				}
				default -> {
					// flags, branches, jumps, calls, NOP: handled below or no tracked effect
				}
			}
			if (r.depth < MIN_DEPTH || r.depth > MAX_DEPTH) {
				return Unwind.DECLINE;
			}
			FlowType flow = instr.getFlowType();
			if (exit == null && flow.isCall()) {
				Address[] targets = instr.getFlows();
				Unwind u = targets.length == 1 ? callee.apply(targets[0]) : null;
				Address next = instr.getMaxAddress().next();
				if (u != null && u.discards()) {
					exit = exitAt(r, r.depth - RETURN_BYTES * (u.level() - 1), 0,
						u.assumed());
				}
				else if (u != null && u.returns() &&
					(u.skip() > 0 || u.callerSkip() > 0 || u.delta() != 0)) {
					if (!advance(r, r.depth, u.callerSkip()) || next == null) {
						return Unwind.DECLINE;
					}
					// a negative delta consumed OUR bytes too (ea2 c4e8 drops our return address)
					r.depth += u.delta();
					r.clobber();
					work.add(r.at(next.add(u.skip())));
					continue;
				}
				else if (instr.getFallThrough() != null) {
					r.clobber();
					work.add(r.at(instr.getFallThrough()));
					continue;
				}
				else {
					return u == null ? null : Unwind.DECLINE;
				}
			}
			if (exit == null && flow.isComputed() && flow.isJump()) {
				Long cell = indirectCell(instr);
				Val lo = cell == null ? Val.UNKNOWN : r.cells.getOrDefault(cell, Val.UNKNOWN);
				if (lo.kind() == LO) {
					// JMP (ptr) through a return address the routine popped and fixed up itself
					// (ea2 c4e8: pop, INC, JMP ($0022)): a return to that address, which is one
					// short of where RTS would land
					exit = exitThrough(r, lo, r.cells.getOrDefault(cell + 1, Val.UNKNOWN),
						r.depth, lo.k() - 1, false);
				}
				else if (r.depth >= 0) {
					return Unwind.DECLINE;
				}
				else {
					exit = exitAt(r, r.depth, 0, false);
				}
			}
			if (exit == null && flow.isJump() && !flow.isConditional() && !flow.isComputed() &&
				rewritten(r)) {
				Address[] targets = instr.getFlows();
				if (targets.length != 1) {
					return Unwind.DECLINE;
				}
				Unwind u = callee.apply(targets[0]);
				if (u == null) {
					return null;
				}
				if (u.declined()) {
					exit = exitAt(r, r.depth, 0, true);
				}
				else if (u.delta() != 0) {
					return Unwind.DECLINE;
				}
				else if (u.discards()) {
					exit = exitAt(r, r.depth - RETURN_BYTES * u.level(), 0, u.assumed());
				}
				else {
					exit = advance(r, r.depth - RETURN_BYTES, u.callerSkip())
							? exitAt(r, r.depth, u.skip(), u.assumed())
							: Unwind.DECLINE;
				}
			}
			if (exit != null) {
				if (exit.declined() || (result != null && !result.sameShape(exit))) {
					return Unwind.DECLINE;
				}
				result = result == null || exit.assumed() ? exit : result;
				continue;
			}
			if (flow.isComputed() || (flow.isTerminal() && !flow.isJump())) {
				return Unwind.DECLINE;
			}
			if (flow.isJump()) {
				Address[] targets = instr.getFlows();
				if (targets.length != 1) {
					return Unwind.DECLINE;
				}
				work.add(r.at(targets[0]));
			}
			Address ft = instr.getFallThrough();
			if (ft != null) {
				work.add(r.at(ft));
			}
			else if (!flow.isJump()) {
				return Unwind.DECLINE;
			}
		}
		return result == null ? Unwind.DECLINE : result;
	}

	/** The {@code +1}/{@code -1} an {@code INC}/{@code DEC} applies, accumulator or memory form. */
	private static int incDecStep(Instruction instr) {
		Integer k = PcodeShapes.incrementOf(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc());
		return k != null ? k : PcodeShapes.rmwIncrement(instr);
	}

	private static Operand incDecOperand(Instruction instr, Integer xRel) {
		return PcodeShapes.incrementOf(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc()) != null
					? new Operand(Operand.ACC, 0)
					: operand(instr, xRel);
	}

	/** The accumulator when the shift writes A, else its memory operand. */
	private static Operand shiftOperand(Instruction instr, Integer xRel) {
		return PcodeShapes.writesRegister(instr,
			CpuRegs.of(instr.getProgram().getLanguage()).acc()) ? new Operand(Operand.ACC, 0)
					: operand(instr, xRel);
	}

	/** The pointer cell of {@code JMP (abs)}, or null for any other computed jump. */
	private static Long indirectCell(Instruction instr) {
		if (instr.getNumOperands() != 1) {
			return null;
		}
		Long cell = null;
		for (Object o : instr.getOpObjects(0)) {
			if (cell != null || !(o instanceof Address || o instanceof Scalar)) {
				return null;
			}
			cell = o instanceof Address a ? a.getOffset() : ((Scalar) o).getUnsignedValue();
		}
		return cell;
	}

	/** The routine has advanced its own return address (slot 0 holds {@code LO(0)+k}, k != 0). */
	private static boolean rewritten(Regs r) {
		Val lo = r.slots.get(r.depth);
		return r.depth == 0 && lo != null && lo.kind() == LO && lo.frame() == 0 && lo.k() != 0;
	}
}
