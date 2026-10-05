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
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Per-callee register-preservation summary over raw instruction p-code (bead grm-mej.11, "Part C"
 * of the grm-mej.11 design): which of {@code A}, {@code X}, {@code Y} a routine hands back to its
 * caller UNCHANGED, i.e. at every reachable return the register holds the value it held on entry.
 * The canonical shape is a bank-switch helper that does {@code TXA / PHA / TYA / PHA ... PLA / TAY
 * / PLA / TAX / RTS}: X and Y are preserved, A is not.
 * <p>
 * <b>No consumer yet.</b> Nothing outside this class and its tests calls it; grm-mej.13 is the
 * payoff consumer. It is a standalone, state-free analysis: it reads only the listing.
 * <p>
 * <b>Method.</b> A forward fixpoint over INSTRUCTIONS (not Ghidra function bodies), each
 * instruction interpreted through its own {@link Instruction#getPcode() p-code} (the op-walking
 * conventions of {@link PcodeConstantSemantics}: internal relative branches, exact
 * {@link OpBehaviorFactory} folding of all-constant ops). A tail {@code JMP} is walked inline in the
 * same frame. The lattice, per instruction entry:
 * <ul>
 * <li>{@code A}/{@code X}/{@code Y}: {@code Entry(R)} (still the value on entry), a constant, or
 * {@code TOP}. Joins are pointwise (equal, else TOP).</li>
 * <li>{@code SP}: {@code EntrySP + k} for an integer {@code k}. A join of two different {@code k}
 * ABANDONS the summary (the same rule the X1 stack-depth walk uses). SP is identified by the
 * compiler spec's stack pointer register; the 6502 languages declare a 2-byte {@code SP} and a
 * 1-byte {@code S} over the same bytes, and {@code TXS} writes {@code S}, so ANY write that overlaps
 * the SP bytes without being exactly the SP register ABANDONS.</li>
 * <li>stack slots: {@code k -> value}, byte granular. A slot present in the map has been WRITTEN
 * by this routine.</li>
 * </ul>
 * <p>
 * <b>Returns.</b> At each {@code RETURN} the SP must equal {@code Entry+2} (the {@code RTS} pop of
 * the return address) and the return-address slots ({@code +1}, {@code +2}) must never have been
 * written; any violation ABANDONS the whole summary. That subsumes "push an address then RTS" dispatch
 * routines (SP is short at the RTS). As a deliberate tightening of the design, a store to ANY slot
 * {@code k >= 1} (the return address or the caller's frame above it) abandons.
 * Also ABANDONED: {@code BRANCHIND} ({@code JMP (ind)}), {@code CALLIND}, {@code RTI}, {@code BRK},
 * a {@code CALLOTHER} with no output, an undisassembled instruction on any path, a transfer into a
 * banked window from outside its own block, a routine with no reachable return, and exceeding
 * {@link #MAX_INSTRUCTIONS} distinct instructions.
 * <p>
 * <b>Named assumptions</b> (each recorded in the returned {@link Summary} when it was relied on):
 * <ul>
 * <li>{@link StackDiscipline#CROSSED_CALL_IS_STACK_NEUTRAL} -- owner ruling O4.</li>
 * <li>{@link StackAssumption#INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME} -- owner ruling O3.</li>
 * </ul>
 * <p>
 * <b>Bank awareness.</b> Summaries are keyed by entry {@link Address} INCLUDING its address space,
 * so an overlay address is the summary of one specific bank image. A callee (or tail-jump target)
 * in a banked window ({@link SplitDispatchTableAnalyzer#isBanked}) reached from a different block
 * is not looked into: a nested call there is "unknown callee" (all registers TOP, stack neutral),
 * a tail jump there abandons.
 */
final class CalleeRegisterSummary {

	/** Most nested callee summaries in flight; one deeper is abandoned (and not memoized). */
	static final int MAX_NESTING = 8;

	/** Most distinct instructions one entry's fixpoint may visit before it abandons. */
	static final int MAX_INSTRUCTIONS = 2048;

	/** Most instruction evaluations (loop revisits included) one entry may spend. */
	private static final int MAX_STEPS = 16 * MAX_INSTRUCTIONS;

	/**
	 * A stack-discipline fact this analysis ASSUMES rather than proves.
	 */
	enum StackDiscipline {
		/**
		 * Owner ruling O4 (2026-10-05): a call that is crossed returns to its fall-through with the
		 * stack pointer where it was before the {@code JSR}, and leaves the caller's stack slots
		 * as they were. This is the existing "reaching the fall-through is the witness" argument
		 * used by {@code StoredValueScanner}'s push/pull pairing walk (the {@code stepOverCall}
		 * branch, grm-mej.3 increment 3), by its cross-block variant, and by
		 * {@code SaveRestoreTrampolines.restoresEntryBank}: a callee with a non-zero net stack
		 * delta at its RTS returns somewhere other than the fall-through. Accepted residual: a
		 * callee that BOTH returns normally AND rewrote the slot beneath its own return address.
		 * Relied on whenever the routine contains a nested {@code JSR}, resolved or not.
		 */
		CROSSED_CALL_IS_STACK_NEUTRAL
	}

	/** A memory-aliasing fact this analysis ASSUMES rather than proves. */
	enum StackAssumption {
		/**
		 * Owner ruling O3 (2026-10-05): a true indirect store ({@code STA (zp),Y} /
		 * {@code STA (zp,X)}) is assumed NOT to write the callers' stack slots. This extends to
		 * the stack frame the Q2 indirect-store assumption the bank-state walks already make about
		 * indirect stores and bank-state shadow cells. Without it any callee containing an
		 * indirect store would have to abandon.
		 */
		INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME
	}

	/** Why a summary was abandoned. */
	enum AbandonReason {
		UNSUPPORTED_LANGUAGE,
		UNDISASSEMBLED,
		BRANCH_INDIRECT,
		CALL_INDIRECT,
		RTI,
		BRK,
		CALLOTHER_NO_OUTPUT,
		SP_PARTIAL_WRITE,
		SP_LOST,
		JOIN_STACK_MISMATCH,
		STORE_ALIASES_STACK,
		STORE_UNRESOLVED_ADDRESS,
		WRITES_CALLER_FRAME,
		BAD_RETURN_STACK,
		NO_RETURN,
		BANKED_TRANSFER,
		UNSUPPORTED_PCODE,
		INSTRUCTION_CAP,
		NESTING_CAP
	}

	private static final String[] REG_NAMES = { "A", "X", "Y" };

	private CalleeRegisterSummary() {
	}

	/** The result of summarizing one entry. */
	static final class Summary {
		private final AbandonReason reason;
		private final String detail;
		private final boolean[] preserved;
		private final Set<StackAssumption> assumptions;
		private final Set<StackDiscipline> disciplines;

		private Summary(AbandonReason reason, String detail, boolean[] preserved,
				Set<StackAssumption> assumptions, Set<StackDiscipline> disciplines) {
			this.reason = reason;
			this.detail = detail;
			this.preserved = preserved;
			this.assumptions = Collections.unmodifiableSet(assumptions);
			this.disciplines = Collections.unmodifiableSet(disciplines);
		}

		static Summary abandoned(AbandonReason reason, String detail) {
			return new Summary(reason, detail, new boolean[3],
				EnumSet.noneOf(StackAssumption.class), EnumSet.noneOf(StackDiscipline.class));
		}

		boolean isAbandoned() {
			return reason != null;
		}

		AbandonReason reason() {
			return reason;
		}

		String detail() {
			return detail;
		}

		/** Whether {@code reg} ({@code 'A'}, {@code 'X'} or {@code 'Y'}) is preserved at every
		 * reachable return. Always false for an abandoned summary. */
		boolean preserves(char reg) {
			if (reason != null) {
				return false;
			}
			int i = "AXY".indexOf(Character.toUpperCase(reg));
			return i >= 0 && preserved[i];
		}

		/** The assumptions this summary (transitively, through composed callees) relied on. */
		Set<StackAssumption> assumptions() {
			return assumptions;
		}

		/** The stack-discipline facts this summary (transitively) relied on. */
		Set<StackDiscipline> disciplines() {
			return disciplines;
		}

		@Override
		public String toString() {
			return reason != null ? "ABANDONED(" + reason + (detail == null ? "" : ": " + detail) +
				")"
					: "preserves[A=" + preserved[0] + ",X=" + preserved[1] + ",Y=" + preserved[2] +
						"] assumptions=" + assumptions + " disciplines=" + disciplines;
		}
	}

	/**
	 * Per-run holder of finished summaries and the in-flight recursion stack. State-free: it keys
	 * only on entry address (space included), never on bank state. One per analysis run; do not
	 * share across programs.
	 */
	static final class Memo {
		private final Map<Address, Summary> done = new HashMap<>();
		private final Set<Address> inProgress = new HashSet<>();
		private int depth;

		int size() {
			return done.size();
		}
	}

	/** Summarizes the routine entered at {@code entry}. Never throws on odd input; abandons. */
	static Summary summarize(Program program, Address entry, Memo memo) {
		return new Runner(program, memo).summarizeEntry(entry).summary;
	}

	// ------------------------------------------------------------------
	// Lattice
	// ------------------------------------------------------------------

	private enum K {
		/** The value this register held on routine entry; {@code a} = register index. */
		ENTRY,
		/** Unknown. */
		TOP,
		/** Constant {@code a}. */
		CONST,
		/** EntrySP + {@code a}. */
		SP,
		/** Some value in the unsigned range [a, b] (an address with an index added); the full
		 * range [0, $FFFF] is an address nothing narrowed. */
		RANGE,
		/** Data read from memory (or computed only from such): the shape of a true indirect
		 * pointer, as opposed to an index or the stack pointer. */
		LOADED
	}

	private record Val(K k, long a, long b) {
		static final Val TOP = new Val(K.TOP, 0, 0);
		static final Val LOADED = new Val(K.LOADED, 0, 0);
		static final Val BYTE_RANGE = new Val(K.RANGE, 0, 255);
		static final Val FULL_RANGE = new Val(K.RANGE, 0, 0xFFFF);

		static Val entry(int reg) {
			return new Val(K.ENTRY, reg, 0);
		}

		static Val konst(long v) {
			return new Val(K.CONST, v, 0);
		}

		static Val sp(long k) {
			return new Val(K.SP, k, 0);
		}
	}

	private static final class St {
		final Val[] regs = new Val[3];
		int sp;
		TreeMap<Integer, Val> slots = new TreeMap<>();
		/** Unique-space temporaries of the instruction being executed only. */
		HashMap<Varnode, Val> tmps = new HashMap<>();

		St copy() {
			St s = new St();
			System.arraycopy(regs, 0, s.regs, 0, 3);
			s.sp = sp;
			s.slots = new TreeMap<>(slots);
			s.tmps = new HashMap<>(tmps);
			return s;
		}

		/** Join (least upper bound); null when the SP offsets differ. */
		St join(St o) {
			if (sp != o.sp) {
				return null;
			}
			St r = new St();
			r.sp = sp;
			for (int i = 0; i < 3; i++) {
				r.regs[i] = regs[i].equals(o.regs[i]) ? regs[i] : Val.TOP;
			}
			Set<Integer> keys = new HashSet<>(slots.keySet());
			keys.addAll(o.slots.keySet());
			for (Integer k : keys) {
				Val x = slots.get(k);
				Val y = o.slots.get(k);
				r.slots.put(k, x != null && x.equals(y) ? x : Val.TOP);
			}
			Set<Varnode> tk = new HashSet<>(tmps.keySet());
			tk.addAll(o.tmps.keySet());
			for (Varnode k : tk) {
				Val x = tmps.get(k);
				Val y = o.tmps.get(k);
				r.tmps.put(k, x != null && x.equals(y) ? x : Val.TOP);
			}
			return r;
		}

		/** Equality of the persistent (cross-instruction) part. */
		boolean sameAs(St o) {
			return sp == o.sp && java.util.Arrays.equals(regs, o.regs) && slots.equals(o.slots);
		}
	}

	private static final class Abandon extends RuntimeException {
		private static final long serialVersionUID = 1L;
		final AbandonReason reason;

		Abandon(AbandonReason reason, String detail) {
			super(detail, null, false, false);
			this.reason = reason;
		}
	}

	/** A finished summary plus what the cache needs to know about how it was derived. */
	private record Outcome(Summary summary, Set<Address> cutOn, boolean capHit) {}

	// ------------------------------------------------------------------
	// Interpreter
	// ------------------------------------------------------------------

	private static final class Runner {
		private final Program program;
		private final Memo memo;
		private final Listing listing;
		private final Memory memory;

		Runner(Program program, Memo memo) {
			this.program = program;
			this.memo = memo;
			this.listing = program.getListing();
			this.memory = program.getMemory();
		}

		// --- per-entry state ---
		private Varnode[] regVn = new Varnode[3];
		private Register spReg;
		private final Map<Address, St> in = new HashMap<>();
		private final ArrayDeque<Address> work = new ArrayDeque<>();
		private final Set<Address> visited = new HashSet<>();
		private boolean[] preserved;
		private boolean anyReturn;
		private final Set<StackAssumption> assumptions = EnumSet.noneOf(StackAssumption.class);
		private final Set<StackDiscipline> disciplines = EnumSet.noneOf(StackDiscipline.class);
		private final Set<Address> cutOn = new HashSet<>();
		private boolean capHit;

		Outcome summarizeEntry(Address entry) {
			Summary cached = memo.done.get(entry);
			if (cached != null) {
				return new Outcome(cached, Set.of(), false);
			}
			if (memo.depth > MAX_NESTING) {
				return new Outcome(Summary.abandoned(AbandonReason.NESTING_CAP,
					"nesting deeper than " + MAX_NESTING), Set.of(), true);
			}
			if (!memo.inProgress.add(entry)) {
				throw new IllegalStateException("in-progress entry must be handled by the caller");
			}
			memo.depth++;
			Summary result;
			try {
				result = run(entry);
			}
			catch (Abandon a) {
				result = Summary.abandoned(a.reason, a.getMessage());
			}
			finally {
				memo.depth--;
				memo.inProgress.remove(entry);
			}
			cutOn.remove(entry);
			// Cache only a result that does not depend on the order it was reached in: no cut on
			// an in-flight caller (recursion) and no nesting-cap truncation below it.
			if (cutOn.isEmpty() && !capHit && result.reason != AbandonReason.NESTING_CAP) {
				memo.done.put(entry, result);
			}
			return new Outcome(result, cutOn, capHit);
		}

		private Summary run(Address entry) {
			for (int i = 0; i < 3; i++) {
				Register r = program.getLanguage().getRegister(REG_NAMES[i]);
				if (r == null) {
					throw new Abandon(AbandonReason.UNSUPPORTED_LANGUAGE, "no register " +
						REG_NAMES[i]);
				}
				regVn[i] = new Varnode(r.getAddress(), r.getMinimumByteSize());
			}
			spReg = program.getCompilerSpec().getStackPointer();
			if (spReg == null) {
				throw new Abandon(AbandonReason.UNSUPPORTED_LANGUAGE, "no stack pointer");
			}
			preserved = new boolean[] { true, true, true };

			St init = new St();
			for (int i = 0; i < 3; i++) {
				init.regs[i] = Val.entry(i);
			}
			in.put(entry, init);
			work.add(entry);
			int steps = 0;
			while (!work.isEmpty()) {
				Address at = work.poll();
				if (++steps > MAX_STEPS) {
					throw new Abandon(AbandonReason.INSTRUCTION_CAP, "step budget");
				}
				Instruction instr = listing.getInstructionAt(at);
				if (instr == null) {
					throw new Abandon(AbandonReason.UNDISASSEMBLED, "nothing at " + at);
				}
				visited.add(at);
				if (visited.size() > MAX_INSTRUCTIONS) {
					throw new Abandon(AbandonReason.INSTRUCTION_CAP,
						"more than " + MAX_INSTRUCTIONS + " instructions");
				}
				execute(instr, in.get(at));
			}
			if (!anyReturn) {
				throw new Abandon(AbandonReason.NO_RETURN, "no reachable return");
			}
			return new Summary(null, null, preserved, assumptions, disciplines);
		}

		private void flowTo(Address target, St s) {
			St clean = s.copy();
			clean.tmps.clear();
			St old = in.get(target);
			if (old == null) {
				in.put(target, clean);
				work.add(target);
				return;
			}
			St joined = old.join(clean);
			if (joined == null) {
				throw new Abandon(AbandonReason.JOIN_STACK_MISMATCH,
					"SP " + old.sp + " vs " + clean.sp + " at " + target);
			}
			if (!joined.sameAs(old)) {
				in.put(target, joined);
				if (!work.contains(target)) {
					work.add(target);
				}
			}
		}

		// ---------------- one instruction ----------------

		private void execute(Instruction instr, St start) {
			String mnemonic = instr.getMnemonicString();
			if ("RTI".equalsIgnoreCase(mnemonic)) {
				throw new Abandon(AbandonReason.RTI, "RTI at " + instr.getAddress());
			}
			if ("BRK".equalsIgnoreCase(mnemonic)) {
				throw new Abandon(AbandonReason.BRK, "BRK at " + instr.getAddress());
			}
			PcodeOp[] ops;
			try {
				ops = instr.getPcode();
			}
			catch (RuntimeException e) {
				ops = null;
			}
			if (ops == null) {
				throw new Abandon(AbandonReason.UNSUPPORTED_PCODE, "no p-code at " +
					instr.getAddress());
			}
			// an empty op list (NOP) is a plain fall-through
			St[] pend = new St[ops.length + 1];
			pend[0] = start.copy();
			for (int i = 0; i < ops.length; i++) {
				St cur = pend[i];
				if (cur == null) {
					continue;
				}
				PcodeOp op = ops[i];
				switch (op.getOpcode()) {
					case PcodeOp.BRANCH: {
						Varnode dest = op.getInput(0);
						if (dest.getAddress().getAddressSpace().isConstantSpace()) {
							mergeOp(pend, internalTarget(dest, i, ops.length), cur);
						}
						else {
							transfer(instr, dest, cur);
						}
						continue;
					}
					case PcodeOp.CBRANCH: {
						Varnode dest = op.getInput(0);
						if (dest.getAddress().getAddressSpace().isConstantSpace()) {
							mergeOp(pend, internalTarget(dest, i, ops.length), cur);
						}
						else {
							transfer(instr, dest, cur);
						}
						mergeOp(pend, i + 1, cur);
						continue;
					}
					case PcodeOp.BRANCHIND:
						throw new Abandon(AbandonReason.BRANCH_INDIRECT, "indirect jump at " +
							instr.getAddress());
					case PcodeOp.CALLIND:
						throw new Abandon(AbandonReason.CALL_INDIRECT, "indirect call at " +
							instr.getAddress());
					case PcodeOp.RETURN:
						doReturn(cur);
						continue;
					case PcodeOp.CALL: {
						St after = cur.copy();
						doCall(instr, op.getInput(0), after);
						mergeOp(pend, i + 1, after);
						continue;
					}
					default:
						break;
				}
				doOp(instr, op, cur);
				mergeOp(pend, i + 1, cur);
			}
			St end = pend[ops.length];
			if (end != null) {
				Address ft = instr.getFallThrough();
				if (ft == null) {
					throw new Abandon(AbandonReason.UNSUPPORTED_PCODE,
						"falls off the end with no fall-through at " + instr.getAddress());
				}
				if (listing.getInstructionAt(ft) == null) {
					throw new Abandon(AbandonReason.UNDISASSEMBLED, "nothing at " + ft);
				}
				flowTo(ft, end);
			}
		}

		private static int internalTarget(Varnode dest, int opIndex, int n) {
			int t = (int) dest.getOffset() + opIndex;
			if (t <= opIndex || t > n) {
				throw new Abandon(AbandonReason.UNSUPPORTED_PCODE, "internal branch to " + t);
			}
			return t;
		}

		private void mergeOp(St[] pend, int idx, St s) {
			if (pend[idx] == null) {
				pend[idx] = s.copy();
				return;
			}
			St j = pend[idx].join(s);
			if (j == null) {
				throw new Abandon(AbandonReason.JOIN_STACK_MISMATCH, "SP differs inside one instruction");
			}
			pend[idx] = j;
		}

		/** Resolve a p-code branch/call target to a program address, in the instruction's own
		 * overlay image when it names one. */
		private Address resolveTarget(Instruction instr, Varnode dest) {
			Address a = dest.getAddress();
			AddressSpace home = instr.getAddress().getAddressSpace();
			if (home.isOverlaySpace() && !a.getAddressSpace().equals(home)) {
				Address o = home.getAddress(a.getOffset());
				if (memory.contains(o)) {
					return o;
				}
			}
			return a;
		}

		private boolean bankedFromOutside(Instruction instr, Address target) {
			MemoryBlock to = memory.getBlock(target);
			if (to == null) {
				return false;
			}
			MemoryBlock from = memory.getBlock(instr.getAddress());
			return !to.equals(from) && SplitDispatchTableAnalyzer.isBanked(program, to);
		}

		private void transfer(Instruction instr, Varnode dest, St s) {
			Address target = resolveTarget(instr, dest);
			if (bankedFromOutside(instr, target)) {
				throw new Abandon(AbandonReason.BANKED_TRANSFER, "jump into banked window " + target);
			}
			if (listing.getInstructionAt(target) == null) {
				throw new Abandon(AbandonReason.UNDISASSEMBLED, "nothing at " + target);
			}
			flowTo(target, s);
		}

		private void doReturn(St s) {
			if (s.sp != 2) {
				throw new Abandon(AbandonReason.BAD_RETURN_STACK, "SP = Entry+" + s.sp +
					" at return, expected Entry+2");
			}
			if (s.slots.containsKey(1) || s.slots.containsKey(2)) {
				throw new Abandon(AbandonReason.BAD_RETURN_STACK, "return-address slot written");
			}
			anyReturn = true;
			for (int i = 0; i < 3; i++) {
				if (!s.regs[i].equals(Val.entry(i))) {
					preserved[i] = false;
				}
			}
		}

		private void doCall(Instruction instr, Varnode dest, St s) {
			disciplines.add(StackDiscipline.CROSSED_CALL_IS_STACK_NEUTRAL);
			// the JSR's own pushed return address is popped by the callee's RTS (O4)
			s.sp += 2;
			Summary callee = calleeSummary(instr, resolveTarget(instr, dest));
			for (int i = 0; i < 3; i++) {
				if (callee == null || !callee.preserved[i]) {
					s.regs[i] = Val.TOP;
				}
			}
			if (callee != null) {
				assumptions.addAll(callee.assumptions);
				disciplines.addAll(callee.disciplines);
			}
		}

		/** The callee's summary, or null when it is unknown (unresolved, banked, recursive,
		 * abandoned): all registers then clobbered, stack still neutral. */
		private Summary calleeSummary(Instruction caller, Address target) {
			if (listing.getInstructionAt(target) == null || bankedFromOutside(caller, target)) {
				return null;
			}
			if (memo.inProgress.contains(target)) {
				cutOn.add(target);
				return null;
			}
			Summary cached = memo.done.get(target);
			if (cached != null) {
				return cached.isAbandoned() ? null : cached;
			}
			Runner sub = new Runner(program, memo);
			Outcome o = sub.summarizeEntry(target);
			cutOn.addAll(o.cutOn);
			capHit |= o.capHit;
			return o.summary.isAbandoned() ? null : o.summary;
		}

		// ---------------- one p-code op ----------------

		private Val read(St s, Varnode vn) {
			if (vn.isConstant()) {
				return Val.konst(vn.getOffset() & mask(vn.getSize()));
			}
			if (vn.isUnique()) {
				Val v = s.tmps.get(vn);
				return v != null ? v : Val.TOP;
			}
			if (vn.isRegister()) {
				for (int i = 0; i < 3; i++) {
					if (sameStorage(vn, regVn[i])) {
						return s.regs[i];
					}
				}
				if (sameStorage(vn, spVarnode())) {
					return Val.sp(s.sp);
				}
				return Val.TOP;
			}
			return Val.LOADED; // direct address-space read
		}

		private Varnode spVarnode() {
			return new Varnode(spReg.getAddress(), spReg.getMinimumByteSize());
		}

		private static boolean sameStorage(Varnode a, Varnode b) {
			return a.getAddress().equals(b.getAddress()) && a.getSize() == b.getSize();
		}

		private static boolean overlaps(Varnode a, Varnode b) {
			if (!a.getAddress().getAddressSpace().equals(b.getAddress().getAddressSpace())) {
				return false;
			}
			long a0 = a.getOffset();
			long b0 = b.getOffset();
			return a0 < b0 + b.getSize() && b0 < a0 + a.getSize();
		}

		private void write(St s, Varnode vn, Val v) {
			if (vn.isUnique()) {
				s.tmps.put(vn, v);
				return;
			}
			if (vn.isRegister()) {
				for (int i = 0; i < 3; i++) {
					if (sameStorage(vn, regVn[i])) {
						s.regs[i] = v;
						return;
					}
				}
				Varnode sp = spVarnode();
				if (sameStorage(vn, sp)) {
					if (v.k() != K.SP) {
						throw new Abandon(AbandonReason.SP_LOST, "SP written with a non-offset value");
					}
					s.sp = (int) v.a();
					return;
				}
				if (overlaps(vn, sp)) {
					throw new Abandon(AbandonReason.SP_PARTIAL_WRITE,
						"write to " + vn + " overlaps SP (TXS)");
				}
				return; // flags, scratch registers: untracked
			}
			if (vn.isAddress()) {
				store(s, Val.konst(vn.getOffset()), vn.getSize(), v);
			}
		}

		private void store(St s, Val addr, int size, Val v) {
			switch (addr.k()) {
				case SP: {
					for (int i = 0; i < size; i++) {
						int slot = (int) addr.a() + i;
						if (slot >= 1) {
							throw new Abandon(AbandonReason.WRITES_CALLER_FRAME,
								"store to Entry+" + slot);
						}
						s.slots.put(slot, size == 1 ? v : Val.TOP);
					}
					return;
				}
				case CONST: {
					AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
					for (int i = 0; i < size; i++) {
						Address cell = space.getAddress((addr.a() + i) & 0xFFFFFFFFL);
						if (StackFloor.mayAliasStack(program, cell)) {
							throw new Abandon(AbandonReason.STORE_ALIASES_STACK, "store to " + cell);
						}
					}
					return;
				}
				case RANGE: {
					if (addr.a() == 0 && addr.b() >= 0xFFFF) {
						// An address the analysis could not narrow at all -- two memory bytes
						// assembled into a pointer (the undoc language's (zp),Y expansion): a
						// true indirect store, owner ruling O3.
						assumptions.add(StackAssumption.INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME);
						return;
					}
					long lo = addr.a();
					long hi = Math.min(addr.b() + size - 1, 0xFFFF);
					long floorLo = StackFloor.STACK_PAGE + StackFloor.floor(program);
					long floorHi = StackFloor.STACK_PAGE + 0xFF;
					boolean hits = lo <= floorHi && hi >= floorLo;
					if (hits) {
						throw new Abandon(AbandonReason.STORE_ALIASES_STACK,
							"indexed store window " + Long.toHexString(lo) + ".." +
								Long.toHexString(hi) + " covers the stack");
					}
					return;
				}
				case LOADED:
					// A true indirect store: owner ruling O3.
					assumptions.add(StackAssumption.INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME);
					return;
				default:
					throw new Abandon(AbandonReason.STORE_UNRESOLVED_ADDRESS,
						"store through an unresolved address");
			}
		}

		private void doOp(Instruction instr, PcodeOp op, St s) {
			int opc = op.getOpcode();
			Varnode out = op.getOutput();
			switch (opc) {
				case PcodeOp.STORE: {
					Val addr = read(s, op.getInput(1));
					Val v = read(s, op.getInput(2));
					store(s, addr, op.getInput(2).getSize(), v);
					return;
				}
				case PcodeOp.LOAD: {
					Val addr = read(s, op.getInput(1));
					Val v = Val.LOADED;
					if (addr.k() == K.SP && out.getSize() == 1) {
						Val slot = s.slots.get((int) addr.a());
						if (slot != null) {
							v = slot;
						}
					}
					write(s, out, v);
					return;
				}
				case PcodeOp.CALLOTHER: {
					if (out == null) {
						throw new Abandon(AbandonReason.CALLOTHER_NO_OUTPUT, "CALLOTHER at " +
							instr.getAddress());
					}
					write(s, out, Val.TOP);
					return;
				}
				case PcodeOp.COPY: {
					write(s, out, read(s, op.getInput(0)));
					return;
				}
				default:
					break;
			}
			if (out == null) {
				return;
			}
			write(s, out, evaluate(s, op, out));
		}

		private Val evaluate(St s, PcodeOp op, Varnode out) {
			int opc = op.getOpcode();
			int n = op.getNumInputs();
			Val[] v = new Val[n];
			boolean allConst = true;
			boolean anyLoaded = false;
			boolean anySp = false;
			for (int i = 0; i < n; i++) {
				v[i] = read(s, op.getInput(i));
				allConst &= v[i].k() == K.CONST;
				anyLoaded |= v[i].k() == K.LOADED;
				anySp |= v[i].k() == K.SP;
			}
			if (allConst && n >= 1 && n <= 2) {
				OpBehavior b = OpBehaviorFactory.getOpBehavior(opc);
				Varnode in0 = op.getInput(0);
				if (out.getSize() <= 8 && in0.getSize() <= 8) {
					if (b instanceof UnaryOpBehavior u && n == 1) {
						return Val.konst(u.evaluateUnary(out.getSize(), in0.getSize(), v[0].a()) &
							mask(out.getSize()));
					}
					if (b instanceof BinaryOpBehavior bb && n == 2 &&
						op.getInput(1).getSize() <= 8) {
						return Val.konst(bb.evaluateBinary(out.getSize(), in0.getSize(), v[0].a(),
							v[1].a()) & mask(out.getSize()));
					}
				}
			}
			if ((opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_SUB) && n == 2) {
				boolean add = opc == PcodeOp.INT_ADD;
				if (v[0].k() == K.SP && v[1].k() == K.CONST) {
					long c = signed(v[1].a(), op.getInput(1).getSize());
					return Val.sp(add ? v[0].a() + c : v[0].a() - c);
				}
				if (add && v[0].k() == K.CONST && v[1].k() == K.SP) {
					return Val.sp(v[1].a() + signed(v[0].a(), op.getInput(0).getSize()));
				}
				if (anySp) {
					return Val.TOP;
				}
				if (out.getSize() == 2 && add && v[0].k() == K.RANGE && v[1].k() == K.RANGE) {
					long hi = v[0].b() + v[1].b();
					return hi > 0xFFFF ? Val.FULL_RANGE : new Val(K.RANGE, v[0].a() + v[1].a(), hi);
				}
				if (out.getSize() == 2 && add) {
					Val r = rangeAdd(v[0], v[1]);
					if (r == null) {
						r = rangeAdd(v[1], v[0]);
					}
					if (r != null) {
						return r;
					}
				}
			}
			if (out.getSize() == 2 && n == 2 && v[0].k() == K.RANGE) {
				if (opc == PcodeOp.INT_LEFT && v[1].k() == K.CONST && v[1].a() < 16) {
					long hi = v[0].b() << v[1].a();
					return hi > 0xFFFF ? Val.FULL_RANGE : new Val(K.RANGE, v[0].a() << v[1].a(), hi);
				}
				if ((opc == PcodeOp.INT_OR || opc == PcodeOp.INT_XOR) && v[1].k() == K.RANGE) {
					long m = Math.max(v[0].b(), v[1].b());
					return new Val(K.RANGE, 0, Long.highestOneBit(m) * 2 - 1 > 0xFFFF ? 0xFFFF
						: Long.highestOneBit(m) * 2 - 1);
				}
			}
			if (opc == PcodeOp.INT_ZEXT && n == 1 && !allConst && out.getSize() >= 2 &&
				op.getInput(0).getSize() == 1) {
				return v[0].k() == K.SP ? Val.TOP
					: v[0].k() == K.RANGE ? v[0] : Val.BYTE_RANGE;
			}
			return anyLoaded && !anySp ? Val.LOADED : Val.TOP;
		}

		/** {@code x + c} where {@code x} is a RANGE and {@code c} a CONST, else null. */
		private static Val rangeAdd(Val x, Val c) {
			if (x.k() == K.RANGE && c.k() == K.CONST) {
				long hi = x.b() + c.a();
				if (hi > 0xFFFF) {
					if (x.b() > 0xFF) {
						return Val.FULL_RANGE; // a wide window wraps anywhere
					}
					// a byte index past the top wraps into zero page only: the stack is not hit
					return new Val(K.RANGE, Math.min(x.a() + c.a(), 0xFFFF), 0xFFFF);
				}
				return new Val(K.RANGE, x.a() + c.a(), hi);
			}
			return null;
		}

		private static long signed(long v, int size) {
			int bits = 8 * Math.min(size, 8);
			if (bits >= 64) {
				return v;
			}
			long m = (1L << bits) - 1;
			v &= m;
			return (v & (1L << (bits - 1))) != 0 ? v - (1L << bits) : v;
		}

		private static long mask(int size) {
			return size >= 8 ? -1L : (1L << (8 * size)) - 1;
		}
	}
}
