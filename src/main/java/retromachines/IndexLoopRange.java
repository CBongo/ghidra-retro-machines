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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

/**
 * grm-9nxj.41.3: the STRONG loop proof of the index range of a register-indexed absolute read,
 * ported from the survey probe {@code IndexedDataRangeProbe} (grm-9nxj.41.1/.2, class L) whose
 * rules were checked against ROM bytes. Only proofs that pin BOTH ends survive here; the probe's
 * weak ones (a lock-step second counter, a non-immediate init, a memory limit) are declined.
 *
 * <p>The read must sit in a loop closed by a backward conditional branch. The loop body is run
 * through a small forward dataflow whose state tracks A/X/Y as {@code (token, scale, offset)}, a
 * stack and plain zero-page/absolute memory cells, starting from a symbolic iteration-start value
 * {@code I} of the index register. The index may be saved and restored inside the body
 * ({@code TXA/PHA..PLA/TAX}, {@code STX cell..LDX cell}, {@code PHX/PLX}); inner loops are black
 * boxes; a {@code JSR} is transparent when the callee (three levels deep) provably never writes
 * the register. The read is proven when, at the read, the index register is still {@code I+d1},
 * and at the back edge it is {@code I+de} with {@code |de| <= 8}. The closing branch's flag
 * source ({@code DEX/DEY/INX/INY} or {@code CPX/CPY #imm}) and the register's IMMEDIATE init
 * before the loop head then pin the values the loop body executes with, and a read after the step
 * is shifted by {@code d1}.
 *
 * <p>Where the probe matched by mnemonic this class reads the p-code instead (the way
 * {@link IndexGuardRecovery} does): register copies, increments, shifts, loads, stores, pushes
 * and pulls are modelled from their p-code effect, and any OTHER p-code write of A/X/Y makes the
 * register unknown. The result is a lower bound on what the probe proved, never more.
 */
final class IndexLoopRange {

	/** The values the index register takes at the read, {@code lo..hi} in steps of {@code step}. */
	record Proof(int lo, int hi, int step, boolean viaCall) {}

	/** A proof, or why there is none ({@code declined}; both null: the read is in no loop). */
	record Outcome(Proof proof, String declined) {}

	private static final int MAX_SCAN = 64;
	private static final int MAX_STEP = 8;

	private record V(int tok, int scale, int off) {}

	private static final V OPAQUE = new V(-1, 1, 0);

	/** Loop-body dataflow state. */
	private static final class LS {
		V a;
		V x;
		V y;
		boolean stackBad;
		List<V> stack = new ArrayList<>();
		Map<Long, V> cells = new HashMap<>();

		LS copy() {
			LS c = new LS();
			c.a = a;
			c.x = x;
			c.y = y;
			c.stackBad = stackBad;
			c.stack = new ArrayList<>(stack);
			c.cells = new HashMap<>(cells);
			return c;
		}
	}

	/** What a callee (and what it calls) may disturb. */
	private static final class Summ {
		boolean wX;
		boolean wY;
		boolean unknown;
		boolean unknownWrite;
		Set<Long> cells = new HashSet<>();
	}

	private final Listing listing;
	private final Program program;
	private final CpuRegs regs;
	private final Map<Address, Summ> summCache = new HashMap<>();
	private int tokenCounter = 1;
	private boolean callRelied;

	private IndexLoopRange(Program program) {
		this.program = program;
		this.listing = program.getListing();
		this.regs = CpuRegs.of(program.getLanguage());
	}

	/**
	 * The proven range of {@code index} (the X or Y register) at {@code read}, an instruction
	 * with one {@code abs,X}/{@code abs,Y} operand, or the reason there is none.
	 */
	static Outcome prove(Program program, Instruction read, Register index) {
		return new IndexLoopRange(program).loop(read, index.getName().charAt(0));
	}

	// ---------------------------------------------------------------- helpers

	private Register reg(char c) {
		return c == 'A' ? regs.acc() : c == 'X' ? regs.x() : regs.y();
	}

	private V fresh() {
		return new V(tokenCounter++, 1, 0);
	}

	private static V get(LS s, char c) {
		return c == 'X' ? s.x : c == 'Y' ? s.y : s.a;
	}

	private static Outcome unk(String why) {
		return new Outcome(null, why);
	}

	private Instruction fallingInto(Instruction i) {
		Instruction p = i == null ? null : listing.getInstructionBefore(i.getMinAddress());
		return p != null && i.getMinAddress().equals(p.getFallThrough()) ? p : null;
	}

	private static boolean condBranch(Instruction i) {
		return i.getFlowType().isConditional() && i.getFlowType().isJump();
	}

	private List<Reference> otherFlowsInto(Instruction i) {
		List<Reference> out = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesTo(i.getMinAddress())) {
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
				out.add(r);
			}
		}
		return out;
	}

	/** The unique instruction that falls into {@code i} with no other way in, else null. */
	private Instruction soleFallPredecessor(Instruction i) {
		Instruction f = fallingInto(i);
		return f != null && otherFlowsInto(i).isEmpty() ? f : null;
	}

	private static boolean isIndirect(Instruction i) {
		if (i.getNumOperands() == 0) {
			return false;
		}
		String r = i.getDefaultOperandRepresentation(0);
		return r.contains("(") || r.contains("[");
	}

	private static boolean hasIndexReg(Instruction i) {
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof Register) {
				return true;
			}
		}
		return false;
	}

	/** First address/scalar operand value, or -1. */
	private static long operandBase(Instruction i) {
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof Address a) {
				return a.getOffset();
			}
			if (o instanceof Scalar sc) {
				return sc.getUnsignedValue();
			}
		}
		return -1;
	}

	/** The fixed zero-page/absolute cell {@code i} names, or null (immediate, indexed, indirect). */
	private static Long plainCell(Instruction i) {
		if (isIndirect(i) || hasIndexReg(i) || i.getLength() < 2 || i.getNumOperands() == 0 ||
			MosOperands.isImmediateOperand(i)) {
			return null;
		}
		long b = operandBase(i);
		return b < 0 ? null : Long.valueOf(b);
	}

	/** Forgets the cells an indexed/indirect store may reach. */
	private static void clearRange(LS s, Instruction i) {
		if (isIndirect(i)) {
			s.cells.clear();
			return;
		}
		long b = operandBase(i);
		if (b < 0) {
			s.cells.clear();
			return;
		}
		long lo = i.getLength() == 2 ? 0 : b;
		long hi = i.getLength() == 2 ? 255 : b + 255;
		s.cells.keySet().removeIf(k -> k >= lo && k <= hi);
	}

	private boolean writes(Instruction i, char c) {
		return PcodeShapes.writesRegister(i, reg(c));
	}

	// ---------------------------------------------------------------- merge

	private V mv(V u, V v) {
		return u.equals(v) ? u : fresh();
	}

	private LS merge(LS p, LS q) {
		LS m = new LS();
		m.a = mv(p.a, q.a);
		m.x = mv(p.x, q.x);
		m.y = mv(p.y, q.y);
		m.stackBad = p.stackBad || q.stackBad;
		if (p.stack.size() == q.stack.size()) {
			for (int k = 0; k < p.stack.size(); k++) {
				m.stack.add(mv(p.stack.get(k), q.stack.get(k)));
			}
		}
		for (Map.Entry<Long, V> e : p.cells.entrySet()) {
			if (e.getValue().equals(q.cells.get(e.getKey()))) {
				m.cells.put(e.getKey(), e.getValue());
			}
		}
		return m;
	}

	private void push(LS[] in, int t, LS st, int n) {
		if (t >= n) {
			return;
		}
		in[t] = in[t] == null ? st.copy() : merge(in[t], st);
	}

	// ---------------------------------------------------------------- callee summary

	private Summ summarize(Address entry, int depth) {
		Summ c = summCache.get(entry);
		if (c != null) {
			return c;
		}
		Summ s = new Summ();
		s.unknown = true; // a recursive re-entry sees the conservative answer
		summCache.put(entry, s);
		boolean unk = false;
		Set<Address> seen = new HashSet<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		work.add(entry);
		int net = 0;
		while (!work.isEmpty() && !unk) {
			Address a = work.poll();
			if (!seen.add(a)) {
				continue;
			}
			if (seen.size() > 400) {
				unk = true;
				break;
			}
			Instruction i = listing.getInstructionAt(a);
			if (i == null) {
				unk = true;
				break;
			}
			FlowType ft = i.getFlowType();
			if (writes(i, 'X')) {
				s.wX = true;
			}
			if (writes(i, 'Y')) {
				s.wY = true;
			}
			if (MosOperands.isInterruptReturn(i) || MosOperands.isSoftwareInterrupt(i)) {
				unk = true;
				break;
			}
			if (!ft.isCall() && !ft.isTerminal()) {
				OptionalInt d = PcodeShapes.netStackDelta(i, regs);
				if (d.isEmpty()) {
					unk = true; // TXS and friends
					break;
				}
				net += d.getAsInt();
			}
			if (PcodeShapes.writesMemory(i)) {
				if (PcodeShapes.hasComputedStore(i)) {
					s.unknownWrite = true;
				}
				for (Address w : PcodeShapes.memoryWrites(i)) {
					s.cells.add(w.getOffset());
				}
			}
			if (ft.isComputed()) {
				unk = true;
				break;
			}
			if (ft.isCall()) {
				Address[] fl = i.getFlows();
				if (fl.length != 1 || depth >= 2) {
					unk = true;
					break;
				}
				Summ cs = summarize(fl[0], depth + 1);
				if (cs.unknown) {
					unk = true;
					break;
				}
				s.wX |= cs.wX;
				s.wY |= cs.wY;
				s.unknownWrite |= cs.unknownWrite;
				s.cells.addAll(cs.cells);
			}
			else {
				for (Address f : i.getFlows()) {
					work.add(f);
				}
			}
			Address ft2 = i.getFallThrough();
			if (ft2 != null) {
				work.add(ft2);
			}
		}
		s.unknown = unk || net != 0;
		return s;
	}

	// ---------------------------------------------------------------- transfer function

	private V popV(LS s) {
		if (s.stackBad || s.stack.isEmpty()) {
			return fresh();
		}
		V v = s.stack.remove(s.stack.size() - 1);
		return v.tok() == -1 ? fresh() : v;
	}

	private char regChar(Register r) {
		if (r == null) {
			return 0;
		}
		for (char c : new char[] { 'A', 'X', 'Y' }) {
			if (r.equals(reg(c))) {
				return c;
			}
		}
		return 0;
	}

	private void call(LS s, Instruction i) {
		Address[] fl = i.getFlows();
		Summ sm = fl.length == 1 && !i.getFlowType().isComputed() ? summarize(fl[0], 0) : null;
		s.a = fresh();
		if (sm == null || sm.unknown) {
			s.x = fresh();
			s.y = fresh();
			s.cells.clear();
			return;
		}
		if (sm.wX) {
			s.x = fresh();
		}
		else {
			callRelied = true;
		}
		if (sm.wY) {
			s.y = fresh();
		}
		if (sm.unknownWrite) {
			s.cells.clear();
		}
		else {
			s.cells.keySet().removeAll(sm.cells);
		}
	}

	private void step(LS s, Instruction i) {
		if (i.getFlowType().isCall()) {
			call(s, i);
			return;
		}
		V a0 = s.a;
		V x0 = s.x;
		V y0 = s.y;
		Long cell = plainCell(i);
		// memory: a plain register store records the register's value in its cell, any other
		// write (read-modify-write, STZ) leaves the cell untracked, a computed one clears a range
		if (PcodeShapes.writesMemory(i)) {
			Character st = MosOperands.storeRegister(i);
			if (cell != null) {
				if (st != null) {
					s.cells.put(cell, st == 'A' ? a0 : st == 'X' ? x0 : y0);
				}
				else {
					s.cells.remove(cell);
				}
			}
			else {
				clearRange(s, i);
			}
		}
		// the stack
		Register pulled = null;
		V popped = null;
		if (!i.getFlowType().isTerminal()) {
			OptionalInt d = PcodeShapes.netStackDelta(i, regs);
			if (d.isEmpty() || d.getAsInt() < -1 || d.getAsInt() > 1) {
				s.stackBad = true;
				s.stack.clear();
			}
			else if (d.getAsInt() == -1) {
				char pc = regChar(PcodeShapes.pushedRegister(i));
				s.stack.add(pc == 0 ? OPAQUE : get(s, pc));
			}
			else if (d.getAsInt() == 1) {
				pulled = PcodeShapes.pulledRegister(i);
				popped = popV(s);
			}
		}
		// registers, each from the ENTRY values
		V na = s.a;
		V nx = s.x;
		V ny = s.y;
		for (char c : new char[] { 'A', 'X', 'Y' }) {
			Register r = reg(c);
			if (!PcodeShapes.writesRegister(i, r)) {
				continue;
			}
			V nv;
			char src = regChar(PcodeShapes.copySource(i, r));
			Integer inc = PcodeShapes.incrementOf(i, r);
			if (src != 0 && src != c) {
				nv = src == 'A' ? a0 : src == 'X' ? x0 : y0;
			}
			else if (inc != null) {
				V o = c == 'A' ? a0 : c == 'X' ? x0 : y0;
				nv = new V(o.tok(), o.scale(), o.off() + inc);
			}
			else if (c == 'A' && PcodeShapes.shiftLeftBy1(i, r)) {
				nv = new V(a0.tok(), a0.scale() * 2, a0.off() * 2);
			}
			else if (pulled != null && pulled.equals(r)) {
				nv = popped;
			}
			else if (r.equals(PcodeShapes.loadDestination(i)) && cell != null) {
				V v = s.cells.get(cell);
				if (v == null) {
					v = fresh();
					s.cells.put(cell, v);
				}
				nv = v;
			}
			else {
				nv = fresh();
			}
			if (c == 'A') {
				na = nv;
			}
			else if (c == 'X') {
				nx = nv;
			}
			else {
				ny = nv;
			}
		}
		s.a = na;
		s.x = nx;
		s.y = ny;
	}

	/** Effect of an inner-loop region (body indices {@code k..end}) that does not hold the read. */
	private LS blackBox(LS m, List<Instruction> body, int k, int end) {
		LS o = m.copy();
		o.a = fresh();
		int net = 0;
		for (int j = k; j <= end; j++) {
			Instruction i = body.get(j);
			if (writes(i, 'X')) {
				o.x = fresh();
			}
			if (writes(i, 'Y')) {
				o.y = fresh();
			}
			FlowType ft = i.getFlowType();
			if (!ft.isCall() && !ft.isTerminal()) {
				OptionalInt d = PcodeShapes.netStackDelta(i, regs);
				if (d.isEmpty()) {
					o.stackBad = true;
				}
				else {
					net += d.getAsInt();
				}
			}
			if (PcodeShapes.writesMemory(i)) {
				Long cell = plainCell(i);
				if (cell != null) {
					o.cells.remove(cell);
				}
				else {
					clearRange(o, i);
				}
			}
			if (ft.isCall()) {
				Address[] fl = i.getFlows();
				Summ sm = fl.length == 1 && !ft.isComputed() ? summarize(fl[0], 0) : null;
				if (sm == null || sm.unknown) {
					o.x = fresh();
					o.y = fresh();
					o.cells.clear();
				}
				else {
					if (sm.wX) {
						o.x = fresh();
					}
					if (sm.wY) {
						o.y = fresh();
					}
					if (sm.unknownWrite) {
						o.cells.clear();
					}
					else {
						o.cells.keySet().removeAll(sm.cells);
					}
				}
			}
		}
		if (net != 0) {
			o.stackBad = true;
			o.stack.clear();
		}
		return o;
	}

	// ---------------------------------------------------------------- the loop proof

	private Outcome loop(Instruction rd, char r) {
		callRelied = false;
		Instruction cur = rd;
		Instruction closing = null;
		for (int n = 0; n < MAX_SCAN; n++) {
			Address ft = cur.getFallThrough();
			if (ft == null) {
				break;
			}
			cur = listing.getInstructionAt(ft);
			if (cur == null) {
				break;
			}
			if (condBranch(cur)) {
				Address[] fl = cur.getFlows();
				if (fl.length == 1 &&
					fl[0].getAddressSpace().equals(rd.getMinAddress().getAddressSpace()) &&
					fl[0].compareTo(rd.getMinAddress()) <= 0) {
					closing = cur;
					break;
				}
			}
		}
		if (closing == null) {
			return new Outcome(null, null);
		}
		Instruction head = listing.getInstructionAt(closing.getFlows()[0]);
		if (head == null) {
			return unk("headNotInsn");
		}
		if (head.getFlowType().isTerminal()) {
			return new Outcome(null, null); // a conditional return, not a loop
		}
		List<Instruction> body = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(head.getMinAddress(), true);
		Instruction prev = null;
		while (it.hasNext()) {
			Instruction i = it.next();
			if (prev != null && !prev.getMaxAddress().next().equals(i.getMinAddress())) {
				return unk("gap");
			}
			body.add(i);
			prev = i;
			if (i.equals(closing)) {
				break;
			}
		}
		if (prev == null || !prev.equals(closing)) {
			return unk("bodyScan");
		}
		int n = body.size();
		Map<Address, Integer> idxOf = new HashMap<>();
		for (int k = 0; k < n; k++) {
			idxOf.put(body.get(k).getMinAddress(), k);
		}
		Integer readIdxBox = idxOf.get(rd.getMinAddress());
		if (readIdxBox == null) {
			return unk("readOutsideBody");
		}
		int readIdx = readIdxBox;
		// every way in comes from inside the loop (the one outside entry is falling into the head)
		boolean multi = false;
		for (int k = 0; k < n; k++) {
			Instruction bi = body.get(k);
			if (bi.getFlowType().isComputed() && !bi.getFlowType().isCall()) {
				return unk("indirectFlow");
			}
			for (Reference ref : otherFlowsInto(bi)) {
				if (!idxOf.containsKey(ref.getFromAddress())) {
					multi = true;
				}
			}
		}
		// inner loops (back edges other than the closing one) become black-box regions
		List<int[]> regions = new ArrayList<>();
		for (int k = 0; k < n - 1; k++) {
			Instruction bi = body.get(k);
			if (bi.getFlowType().isCall()) {
				continue;
			}
			for (Address f : bi.getFlows()) {
				Integer t = idxOf.get(f);
				if (t != null && t <= k) {
					regions.add(new int[] { t, k });
				}
			}
		}
		regions.sort((p, q) -> Integer.compare(p[0], q[0]));
		List<int[]> union = new ArrayList<>();
		for (int[] rg : regions) {
			if (!union.isEmpty() && rg[0] <= union.get(union.size() - 1)[1]) {
				int[] last = union.get(union.size() - 1);
				last[1] = Math.max(last[1], rg[1]);
			}
			else {
				union.add(new int[] { rg[0], rg[1] });
			}
		}
		int[] regEnd = new int[n];
		Arrays.fill(regEnd, -1);
		for (int[] rg : union) {
			if (readIdx >= rg[0] && readIdx <= rg[1]) {
				return unk("nested.containsRead");
			}
			regEnd[rg[0]] = rg[1];
		}
		// dataflow from a symbolic iteration-start value of the index register
		V tokI = fresh();
		LS entry = new LS();
		entry.a = fresh();
		entry.x = r == 'X' ? tokI : fresh();
		entry.y = r == 'Y' ? tokI : fresh();
		LS[] in = new LS[n];
		in[0] = entry;
		LS readState = null;
		LS closeState = null;
		int k = 0;
		while (k < n) {
			if (regEnd[k] >= 0) {
				int end = regEnd[k];
				LS m = null;
				for (int j = k; j <= end; j++) {
					if (in[j] != null) {
						m = m == null ? in[j] : merge(m, in[j]);
					}
				}
				if (m != null) {
					LS out = blackBox(m, body, k, end);
					push(in, end + 1, out, n);
					for (int j = k; j <= end; j++) {
						for (Address f : body.get(j).getFlows()) {
							Integer t = idxOf.get(f);
							if (t != null && t > end && !body.get(j).getFlowType().isCall()) {
								push(in, t, out, n);
							}
						}
					}
				}
				k = end + 1;
				continue;
			}
			LS s0 = in[k];
			if (s0 == null) {
				k++;
				continue;
			}
			if (k == readIdx) {
				readState = s0;
			}
			if (k == n - 1) {
				closeState = s0;
				break;
			}
			Instruction bi = body.get(k);
			LS c = s0.copy();
			step(c, bi);
			if (bi.getFallThrough() != null) {
				push(in, k + 1, c, n);
			}
			if (!bi.getFlowType().isCall()) {
				for (Address f : bi.getFlows()) {
					Integer t = idxOf.get(f);
					if (t != null && t > k) {
						push(in, t, c, n);
					}
				}
			}
			k++;
		}
		String pfx = union.isEmpty() ? "" : "nested.";
		if (readState == null) {
			return unk(pfx + "readUnreached");
		}
		if (closeState == null) {
			return unk(pfx + "noBackEdge");
		}
		V rx = get(readState, r);
		if (rx.tok() != tokI.tok() || rx.scale() != 1) {
			return unk(pfx + "regWrite");
		}
		V cx = get(closeState, r);
		if (cx.tok() != tokI.tok() || cx.scale() != 1) {
			return unk(pfx + "regWrite.backedge");
		}
		int d1 = rx.off();
		int de = cx.off();
		if (de == 0) {
			return unk(pfx + "noStep");
		}
		if (Math.abs(de) > MAX_STEP) {
			return unk(pfx + "stepN");
		}
		// closing branch + flag source
		if (!otherFlowsInto(closing).isEmpty()) {
			return unk(pfx + "closeJoin");
		}
		Instruction pi = n >= 2 ? body.get(n - 2) : null;
		if (pi == null) {
			return unk(pfx + "closeNoFlag");
		}
		String cb = branchName(closing);
		boolean flagReg = false;
		boolean cmpImm = false;
		Long mm = null;
		char tested = 0;
		for (char c : new char[] { 'X', 'Y' }) {
			Integer inc = PcodeShapes.incrementOf(pi, reg(c));
			if (inc != null && Math.abs(inc) == 1) {
				flagReg = true;
				tested = c;
			}
			else if (MosOperands.comparesRegister(pi, c)) {
				mm = PcodeShapes.compareImmediate(pi, reg(c));
				if (mm == null) {
					return unk(pfx + "weak.memoryLimit"); // CPX zp: lower bound only
				}
				cmpImm = true;
				tested = c;
			}
		}
		if (tested == 0) {
			return unk(pfx + "flagSrc");
		}
		if (tested != r) {
			return unk(pfx + "weak.lockstep"); // the other counter pins it: not proved here
		}
		Long init = initValue(head, r);
		if (init == null) {
			return unk(pfx + "weak.init"); // lower bound only
		}
		int sk = Math.abs(de);
		long[] tr = testedRange(cb, flagReg, cmpImm, mm, de, sk, init);
		if (tr == null) {
			return unk(pfx + "closeBranch." + cb);
		}
		if (tr.length == 1) {
			return unk(pfx + "unprovable");
		}
		long rlo = tr[0] + d1;
		long rhi = tr[1] + d1;
		if (rhi < rlo || rlo < 0 || rhi > 255) {
			return unk(pfx + "emptyRange");
		}
		if (multi) {
			return unk("multiEntry");
		}
		return new Outcome(new Proof((int) rlo, (int) rhi, sk, callRelied), null);
	}

	/** {@code BNE}/{@code BPL}/{@code BCC}/{@code BCS} read off the branch's flag test, else "?". */
	private static String branchName(Instruction branch) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(branch);
		if (fb == null) {
			return "?";
		}
		return switch (fb.kind()) {
			case ZERO -> fb.takenWhenSet() ? "BEQ" : "BNE";
			case NEGATIVE -> fb.takenWhenSet() ? "BMI" : "BPL";
			case CARRY -> fb.takenWhenSet() ? "BCS" : "BCC";
			default -> "?";
		};
	}

	/**
	 * The values the tested register takes at the loop body's executed iterations, as
	 * {lo, hi}; null when the branch/flag pair is not a modelled loop test; {0} for a modelled
	 * test whose arithmetic does not close (wraps). The init is known.
	 */
	private static long[] testedRange(String cb, boolean flagReg, boolean cmpImm, Long m, int dT,
			int k, long init) {
		if (flagReg) {
			if (dT < 0 && cb.equals("BNE")) {
				if (init < k || init % k != 0) {
					return new long[] { 0 };
				}
				return new long[] { k, init };
			}
			if (dT < 0 && cb.equals("BPL")) {
				if (init < 0) {
					return new long[] { 0 };
				}
				return new long[] { init % k, init };
			}
			if (dT > 0 && cb.equals("BNE")) {
				if ((256 - init) % k != 0) {
					return new long[] { 0 };
				}
				return new long[] { init, 256 - k };
			}
			return null;
		}
		if (cmpImm) {
			if (dT > 0 && (cb.equals("BNE") || cb.equals("BCC"))) {
				if (init >= m) {
					return new long[] { 0 };
				}
				if (cb.equals("BNE")) {
					if ((m - init) % k != 0) {
						return new long[] { 0 };
					}
					return new long[] { init, m - k };
				}
				return new long[] { init, init + ((m - 1 - init) / k) * k };
			}
			if (dT < 0 && cb.equals("BNE")) {
				if (init <= m || (init - m) % k != 0) {
					return new long[] { 0 };
				}
				return new long[] { m + k, init };
			}
			if (dT < 0 && cb.equals("BCS")) {
				if (init < m) {
					return new long[] { 0 };
				}
				return new long[] { init - ((init - m) / k) * k, init };
			}
		}
		return null;
	}

	/** Immediate loaded into reg just before the loop head ({@code LDX #n}, or {@code TAX} after {@code LDA #n}). */
	private Long initValue(Instruction head, char r) {
		Instruction p = fallingInto(head);
		for (int n = 0; n < 12 && p != null; n++) {
			Long k = MosOperands.constantLoadedInto(p, r);
			if (k != null) {
				return k;
			}
			Character src = MosOperands.transferSource(p, r);
			if (src != null && src == 'A') {
				Instruction q = soleFallPredecessor(p);
				for (int j = 0; j < 6 && q != null; j++) {
					Long a = MosOperands.constantLoadedInto(q, 'A');
					if (a != null) {
						return a;
					}
					if (MosOperands.modifiesRegister(q, 'A') || q.getFlowType().isCall()) {
						return null;
					}
					q = soleFallPredecessor(q);
				}
				return null;
			}
			if (MosOperands.modifiesRegister(p, r) || p.getFlowType().isCall()) {
				return null;
			}
			p = soleFallPredecessor(p);
		}
		return null;
	}
}
