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
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Per-function PARAMETER / RETURN-VALUE evidence for the 6502-family CPUs (6502, 6510, 65816;
 * bead grm-etbh, stage E1). The engine only OBSERVES: it commits nothing to the program. A later
 * stage turns a {@link Proposal} into a function signature.
 * <p>
 * Everything is derived from instruction p-code through {@link PcodeShapes} and {@link CpuRegs}
 * (no mnemonic strings): which of A/X/Y a function reads before writing (inputs), which it leaves
 * different from entry at a return (outputs), the carry flag's value at the returns (constant or
 * computed), the zero-page cells it loads before storing, and whether the analysis was COMPLETE
 * (no computed jump or call, no unknown callee, no odd stack discipline, every path returns).
 * <p>
 * <b>Register model.</b> Each of A/X/Y holds, per instruction entry, a SET of symbolic values:
 * {@code ENTRY(A)}, {@code ENTRY(X)}, {@code ENTRY(Y)} or {@code CHANGED}. A plain register copy
 * ({@code TAX}) moves the symbol without counting as a use; a push stores the symbol on a modelled
 * stack and the matching pull restores it, so a saved-and-restored register is neither an input
 * nor an output (a push alone is not a use of the register). A non-copy read of a register that may
 * still hold {@code ENTRY(S)} makes {@code S} an input. A register is an OUTPUT iff its value set at
 * some return is anything other than exactly {@code {ENTRY(R)}} (liveness-correct, not "written on
 * some path"). A register that leaves holding another register's entry value is an output AND makes
 * that other register an input (the value flows through).
 * <p>
 * <b>Interprocedural.</b> Summaries are computed callee-first with a bounded worklist fixpoint
 * (monotone from a bottom summary, so recursion and cycles settle). A direct call applies the
 * callee's summary: its inputs are reads at the call site, its outputs are writes, registers it
 * preserves pass through, its carry result composes with the current carry. A jump (or branch) out
 * of the body into another function's entry inherits that function's summary as this function's
 * return. A call to an unknown target clobbers everything and makes the caller incomplete; an
 * incomplete callee makes its callers incomplete.
 * <p>
 * <b>Caller side.</b> For every direct call site the engine records, over a bounded path search
 * from the call's return point, whether any path reads A/X/Y or branches on C/Z/N before the
 * resource is written, and (linear look-back of eight instructions) which resources and
 * zero-page cells are written just before the call.
 * <p>
 * <b>65816 width.</b> An input's width comes from the size of the register varnode the reading
 * instruction's decoded p-code touches (which already reflects the M/X context the disassembler
 * used, the same facts {@code W65816WidthEffects} reads); a register read both wide and narrow, or
 * only through a pass-through, has unknown width and the {@link Proposal} is marked incomplete.
 * Direct-page cells are not modelled on the 65816.
 */
public final class ParamReturnEvidence {

	/** Resource indexes: A, X, Y, carry, zero, negative. */
	public static final int RA = 0, RX = 1, RY = 2, RC = 3, RZ = 4, RN = 5;
	/** Carry value lattice bits at a return. */
	public static final int C_ENTRY = 1, C_ZERO = 2, C_ONE = 4, C_UNK = 8;

	private static final int CHG = 8;
	private static final int MAX_INSNS = 3000;
	private static final int MAX_PASSES = 12;
	private static final int LOOK = 8;
	private static final int PATH_STEPS = 400;

	private ParamReturnEvidence() {
	}

	// ------------------------------------------------------------------
	// Public data
	// ------------------------------------------------------------------

	/** Everything the engine knows about one function. Fields are read-only to consumers. */
	public static final class FnEvidence {
		public final Address entry;
		/** False for a function that was skipped (no body, over the size cap, thunk). */
		public boolean analyzed;
		public boolean complete = true;
		/** Masks over A=1, X=2, Y=4. */
		public int inMask;
		public int inWide;
		public int inNarrow;
		public int outMask;
		public boolean carryIn;
		/** Union of {@code C_*} bits over the returns. */
		public int carry = C_ENTRY;
		public int returns;
		public int indirect;
		public boolean tail;
		/** Zero-page cells loaded before stored on some path. */
		public final Set<Integer> zpIn = new TreeSet<>();
		/** Candidate cells stored on EVERY path to a return. */
		public final Set<Integer> zpWritten = new TreeSet<>();
		// caller side
		public int sites;
		public int jumpRefs;
		/** A/X/Y bits: some caller reads it after the call before writing it. */
		public int afterRead;
		/** A/X/Y bits: it reaches a caller's own return unwritten (value passed up). */
		public int afterPass;
		/** Bits over RC/RZ/RN: some caller branches on the flag before writing it. */
		public int afterBranch;
		/** Bits over all six resources: some caller writes it within {@value #LOOK} instructions before. */
		public int beforeWrite;
		/** Some caller stores a cell of {@link #zpIn} just before the call. */
		public boolean zpSetBefore;

		FnEvidence(Address entry) {
			this.entry = entry;
		}

		boolean sameSummary(FnEvidence o) {
			return inMask == o.inMask && inWide == o.inWide && inNarrow == o.inNarrow &&
				outMask == o.outMask && carryIn == o.carryIn && carry == o.carry &&
				returns == o.returns && complete == o.complete && zpIn.equals(o.zpIn) &&
				zpWritten.equals(o.zpWritten);
		}

		void copySummaryFrom(FnEvidence o) {
			analyzed = o.analyzed;
			complete = o.complete;
			inMask = o.inMask;
			inWide = o.inWide;
			inNarrow = o.inNarrow;
			outMask = o.outMask;
			carryIn = o.carryIn;
			carry = o.carry;
			returns = o.returns;
			indirect = o.indirect;
			tail = o.tail;
			zpIn.clear();
			zpIn.addAll(o.zpIn);
			zpWritten.clear();
			zpWritten.addAll(o.zpWritten);
		}

		/** Whether the carry is written on every path to a return (never the entry value). */
		public boolean carryWritten() {
			return returns > 0 && (carry & C_ENTRY) == 0;
		}

		@Override
		public String toString() {
			return "Fn@" + entry + " in=" + inMask + " out=" + outMask + " carry=" + carry +
				" ret=" + returns + " complete=" + complete + " zp=" + zpIn;
		}
	}

	/** The result of {@link #analyze}. */
	public static final class Result {
		private final Map<Address, FnEvidence> byEntry = new HashMap<>();
		private boolean supported;
		private boolean is65816;
		private boolean zpModel;
		private int skippedCap;

		public boolean supported() {
			return supported;
		}

		public boolean is65816() {
			return is65816;
		}

		public boolean zpModel() {
			return zpModel;
		}

		public int skippedCap() {
			return skippedCap;
		}

		public FnEvidence get(Address entry) {
			return byEntry.get(entry);
		}

		public Map<Address, FnEvidence> all() {
			return Collections.unmodifiableMap(byEntry);
		}
	}

	/**
	 * The signature the evidence supports. {@code params} are register names ({@code "A"}, with a
	 * {@code ":16"}/{@code ":8"} suffix on the 65816); {@code ret} is {@code "A"}, {@code "X"},
	 * {@code "Y"}, {@code "carry"} or null (no confirmed result); {@code comments} are plate
	 * comment lines naming everything not committed as a parameter or return.
	 */
	public record Proposal(List<String> params, String ret, List<String> comments,
			boolean complete) {}

	// ------------------------------------------------------------------
	// Pure combination rules
	// ------------------------------------------------------------------

	/**
	 * Combines the evidence of one function into a proposal. INPUTS: callee evidence suffices.
	 * RETURN: only caller-confirmed results count (a register that is an output AND read by some
	 * caller; the carry when it is written on every path AND some caller branches on it). With
	 * several confirmed results the value register wins (A, then X, then Y) and the others, carry
	 * included, are named in comments; carry is the return only when it is the sole confirmed
	 * result (owner ruling, grm-etbh). Zero-page inputs are comment-only.
	 */
	public static Proposal propose(FnEvidence e, boolean is65816) {
		boolean complete = e.complete && e.analyzed;
		List<String> params = new ArrayList<>();
		String[] names = { "A", "X", "Y" };
		for (int r = 0; r < 3; r++) {
			if ((e.inMask & (1 << r)) == 0) {
				continue;
			}
			String n = names[r];
			if (is65816) {
				boolean wide = (e.inWide & (1 << r)) != 0;
				boolean narrow = (e.inNarrow & (1 << r)) != 0;
				if (wide == narrow) {
					complete = false;
					n += ":?";
				}
				else {
					n += wide ? ":16" : ":8";
				}
			}
			params.add(n);
		}
		List<String> confirmed = new ArrayList<>();
		for (int r = 0; r < 3; r++) {
			if ((e.outMask & (1 << r)) != 0 && (e.afterRead & (1 << r)) != 0) {
				confirmed.add(names[r]);
			}
		}
		boolean carryConfirmed = e.carryWritten() && (e.afterBranch & (1 << RC)) != 0;
		List<String> comments = new ArrayList<>();
		String ret = null;
		if (!confirmed.isEmpty()) {
			ret = confirmed.get(0);
			for (int i = 1; i < confirmed.size(); i++) {
				comments.add("Also returns " + confirmed.get(i) + " (read by callers)");
			}
			if (carryConfirmed) {
				comments.add("Carry status on return: " + describeCarry(e.carry));
			}
		}
		else if (carryConfirmed) {
			ret = "carry";
		}
		if ((e.afterBranch & (1 << RZ)) != 0) {
			comments.add("Callers branch on Z after the call");
		}
		if ((e.afterBranch & (1 << RN)) != 0) {
			comments.add("Callers branch on N after the call");
		}
		if (!e.zpIn.isEmpty() && e.zpSetBefore) {
			StringBuilder sb = new StringBuilder("Zero-page inputs:");
			for (int c : e.zpIn) {
				sb.append(String.format(" $%02X", c));
			}
			comments.add(sb.toString());
		}
		return new Proposal(params, ret, comments, complete);
	}

	private static String describeCarry(int c) {
		int v = c & (C_ZERO | C_ONE | C_UNK | C_ENTRY);
		if (v == C_ZERO) {
			return "always clear";
		}
		if (v == C_ONE) {
			return "always set";
		}
		if (v == (C_ZERO | C_ONE)) {
			return "set or clear (constants)";
		}
		return "computed";
	}

	// ------------------------------------------------------------------
	// Engine
	// ------------------------------------------------------------------

	/** Analyses every function of {@code program}. Never throws on odd input. */
	public static Result analyze(Program program) {
		return new Engine(program).run();
	}

	/** Per-instruction p-code facts. */
	private static final class Ia {
		FlowType ft;
		boolean bad;
		boolean ret;
		boolean terminal;
		boolean call;
		int readMask;
		int writeMask;
		int wide;
		final int[] copy = { -1, -1, -1 };
		int pushSym = -1;
		int pulledSym = -1;
		OptionalInt delta = OptionalInt.of(0);
		int carryWrite = -1;
		int branchBit = -1;
		int[] zpLoads = new int[0];
		int[] zpStores = new int[0];
	}

	/** Dataflow state at an instruction entry. */
	private static final class St {
		final int[] r = new int[3];
		int c;
		BitSet unw = new BitSet();
		/** Modelled stack, entries are (bytes << 4) | valueSet; null = unknown. */
		int[] stack = new int[0];

		St copy() {
			St o = new St();
			System.arraycopy(r, 0, o.r, 0, 3);
			o.c = c;
			o.unw = (BitSet) unw.clone();
			o.stack = stack;
			return o;
		}
	}

	private static final class Engine {
		private final Program program;
		private final Listing listing;
		private final FunctionManager fm;
		private final CpuRegs regs;
		private final Register[] rr = new Register[3];
		private final Register carryReg;
		private final Register zeroReg;
		private final Register negReg;
		private final boolean is65816;
		private final boolean zp;
		private final AddressSpace defaultSpace;
		private final Map<Address, Ia> iaCache = new HashMap<>();
		private final Result result = new Result();
		private boolean stackConflict;

		Engine(Program p) {
			program = p;
			listing = p.getListing();
			fm = p.getFunctionManager();
			regs = CpuRegs.of(p.getLanguage());
			rr[RA] = regs.acc();
			rr[RX] = regs.x();
			rr[RY] = regs.y();
			carryReg = regs.carry() == null ? null : regs.carry().reg();
			zeroReg = regs.zero() == null ? null : regs.zero().reg();
			negReg = regs.negative() == null ? null : regs.negative().reg();
			is65816 = regs.accWide() != null;
			zp = !is65816;
			defaultSpace = p.getLanguage().getDefaultSpace();
		}

		Result run() {
			result.is65816 = is65816;
			result.zpModel = zp;
			if (rr[RA] == null || rr[RX] == null || rr[RY] == null || carryReg == null ||
				regs.psw() != null) {
				return result;
			}
			result.supported = true;
			List<Function> fns = new ArrayList<>();
			for (Function f : fm.getFunctions(true)) {
				if (!f.isThunk() && !f.isExternal()) {
					fns.add(f);
				}
			}
			Map<Address, List<Instruction>> bodies = new HashMap<>();
			Map<Address, Set<Address>> callees = new HashMap<>();
			for (Function f : fns) {
				FnEvidence e = new FnEvidence(f.getEntryPoint());
				result.byEntry.put(f.getEntryPoint(), e);
				List<Instruction> body = new ArrayList<>();
				for (Instruction i : listing.getInstructions(f.getBody(), true)) {
					body.add(i);
					if (body.size() > MAX_INSNS) {
						break;
					}
				}
				if (body.isEmpty() || body.size() > MAX_INSNS) {
					if (body.size() > MAX_INSNS) {
						result.skippedCap++;
					}
					// unknown function: clobbers everything, never trusted
					e.complete = false;
					e.outMask = 7;
					e.carry = C_UNK;
					e.returns = 1;
					continue;
				}
				e.analyzed = true;
				bodies.put(f.getEntryPoint(), body);
			}
			// call graph (direct calls and out-of-body jumps)
			Map<Address, Set<Address>> callers = new HashMap<>();
			for (Map.Entry<Address, List<Instruction>> en : bodies.entrySet()) {
				Set<Address> cs = new LinkedHashSet<>();
				for (Instruction i : en.getValue()) {
					Ia a = ia(i);
					if (a.call && !a.ft.isComputed()) {
						Address t = singleFlow(i);
						if (t != null && bodies.containsKey(t)) {
							cs.add(t);
						}
					}
					else if (a.ft.isJump()) {
						for (Address t : i.getFlows()) {
							if (bodies.containsKey(t) && !t.equals(en.getKey())) {
								cs.add(t);
							}
						}
					}
				}
				callees.put(en.getKey(), cs);
				for (Address t : cs) {
					callers.computeIfAbsent(t, k -> new HashSet<>()).add(en.getKey());
				}
			}
			ArrayDeque<Address> work = new ArrayDeque<>(postOrder(bodies.keySet(), callees));
			Set<Address> queued = new HashSet<>(work);
			Map<Address, Integer> passes = new HashMap<>();
			while (!work.isEmpty()) {
				Address f = work.poll();
				queued.remove(f);
				int n = passes.merge(f, 1, Integer::sum);
				FnEvidence old = result.byEntry.get(f);
				FnEvidence fresh = analyzeFunction(f, bodies.get(f));
				if (n >= MAX_PASSES && !fresh.sameSummary(old)) {
					fresh.complete = false;
				}
				if (!fresh.sameSummary(old)) {
					old.copySummaryFrom(fresh);
					if (n < MAX_PASSES) {
						for (Address c : callers.getOrDefault(f, Set.of())) {
							if (queued.add(c)) {
								work.add(c);
							}
						}
					}
				}
			}
			callerSide(bodies);
			return result;
		}

		private List<Address> postOrder(Set<Address> nodes, Map<Address, Set<Address>> callees) {
			List<Address> order = new ArrayList<>();
			Set<Address> seen = new HashSet<>();
			List<Address> sorted = new ArrayList<>(nodes);
			Collections.sort(sorted);
			for (Address root : sorted) {
				if (!seen.add(root)) {
					continue;
				}
				ArrayDeque<Object[]> st = new ArrayDeque<>();
				st.push(new Object[] { root,
					callees.getOrDefault(root, Set.of()).iterator() });
				while (!st.isEmpty()) {
					Object[] top = st.peek();
					@SuppressWarnings("unchecked")
					java.util.Iterator<Address> it = (java.util.Iterator<Address>) top[1];
					if (it.hasNext()) {
						Address c = it.next();
						if (seen.add(c)) {
							st.push(new Object[] { c,
								callees.getOrDefault(c, Set.of()).iterator() });
						}
					}
					else {
						order.add((Address) top[0]);
						st.pop();
					}
				}
			}
			return order;
		}

		private Address singleFlow(Instruction i) {
			Address[] fl = i.getFlows();
			return fl != null && fl.length == 1 ? fl[0] : null;
		}

		// -------------------------------------------------------------- instruction facts

		private int symOf(Register r) {
			if (r == null) {
				return -1;
			}
			for (int s = 0; s < 3; s++) {
				if (overlapsReg(r, rr[s])) {
					return s;
				}
			}
			return -1;
		}

		private static boolean overlapsReg(Register a, Register b) {
			return a.getOffset() < b.getOffset() + b.getMinimumByteSize() &&
				b.getOffset() < a.getOffset() + a.getMinimumByteSize();
		}

		private Ia ia(Instruction ins) {
			Ia r = iaCache.get(ins.getAddress());
			if (r == null) {
				r = buildIa(ins);
				iaCache.put(ins.getAddress(), r);
			}
			return r;
		}

		private Ia buildIa(Instruction ins) {
			Ia a = new Ia();
			a.ft = ins.getFlowType();
			a.call = a.ft.isCall();
			PcodeOp[] ops;
			try {
				ops = ins.getPcode();
			}
			catch (RuntimeException e) {
				a.bad = true;
				return a;
			}
			try {
				a.ret = PcodeShapes.isReturnOp(ins);
				a.terminal = a.ft.isTerminal() && !a.ft.isJump() && !a.call && !a.ret;
				for (int s = 0; s < 3; s++) {
					if (PcodeShapes.readsRegister(ins, rr[s])) {
						a.readMask |= 1 << s;
					}
					if (PcodeShapes.writesRegister(ins, rr[s])) {
						a.writeMask |= 1 << s;
					}
					Register src = PcodeShapes.copySource(ins, rr[s]);
					a.copy[s] = symOf(src);
					if (a.copy[s] == s) {
						a.copy[s] = -1;
					}
				}
				if (PcodeShapes.readsRegister(ins, carryReg)) {
					a.readMask |= 1 << RC;
				}
				if (PcodeShapes.writesRegister(ins, carryReg)) {
					a.writeMask |= 1 << RC;
					Long k = PcodeShapes.constantInto(ins, carryReg);
					a.carryWrite = (k != null && (k == 0 || k == 1)) ? (int) (long) k : 2;
				}
				if (PcodeShapes.writesRegister(ins, zeroReg)) {
					a.writeMask |= 1 << RZ;
				}
				if (PcodeShapes.writesRegister(ins, negReg)) {
					a.writeMask |= 1 << RN;
				}
				PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(ins);
				if (fb != null) {
					switch (fb.kind()) {
						case CARRY:
							a.branchBit = RC;
							break;
						case ZERO:
							a.branchBit = RZ;
							break;
						case NEGATIVE:
							a.branchBit = RN;
							break;
						default:
							break;
					}
				}
				if (!a.call && !a.ret) {
					a.delta = PcodeShapes.netStackDelta(ins, regs);
					a.pushSym = symOf(PcodeShapes.pushedRegister(ins));
					a.pulledSym = symOf(PcodeShapes.pulledRegister(ins));
				}
			}
			catch (RuntimeException e) {
				a.bad = true;
				return a;
			}
			scanOps(ops, a);
			return a;
		}

		/** Wide register reads and constant zero-page loads/stores. */
		private void scanOps(PcodeOp[] ops, Ia a) {
			Map<Long, Long> uniq = new HashMap<>();
			Set<Integer> loads = new TreeSet<>();
			Set<Integer> stores = new TreeSet<>();
			for (PcodeOp op : ops) {
				int oc = op.getOpcode();
				int first = (oc == PcodeOp.LOAD || oc == PcodeOp.STORE) ? 1 : 0;
				for (int k = first; k < op.getNumInputs(); k++) {
					if (oc == PcodeOp.BRANCH || oc == PcodeOp.CALL ||
						(oc == PcodeOp.CBRANCH && k == 0)) {
						continue;
					}
					Varnode v = op.getInput(k);
					if (v == null) {
						continue;
					}
					if (isDirectMem(v)) {
						int cell = zpCell(v);
						if (cell >= 0) {
							loads.add(cell);
						}
					}
					else if (v.isRegister() && v.getSize() > 1) {
						for (int s = 0; s < 3; s++) {
							Register rg = s == RA && regs.accWide() != null ? regs.accWide() : rr[s];
							if (v.getOffset() < rg.getOffset() + rg.getMinimumByteSize() &&
								rg.getOffset() < v.getOffset() + v.getSize() &&
								v.getSize() >= 2 && is65816) {
								a.wide |= 1 << s;
							}
						}
					}
				}
				if (oc == PcodeOp.LOAD || oc == PcodeOp.STORE) {
					Long addr = value(op.getInput(1), uniq);
					Varnode sp = op.getInput(0);
					if (addr != null && zp && addr >= 0 && addr < 0x100 && sp != null &&
						spaceIsDefault(sp)) {
						(oc == PcodeOp.LOAD ? loads : stores).add((int) (long) addr);
					}
				}
				Varnode out = op.getOutput();
				if (out != null && isDirectMem(out)) {
					int cell = zpCell(out);
					if (cell >= 0) {
						stores.add(cell);
					}
				}
				else if (out != null && out.isUnique()) {
					Long cv = evalConst(op, uniq);
					if (cv != null) {
						uniq.put(out.getOffset(), cv);
					}
					else {
						uniq.remove(out.getOffset());
					}
				}
			}
			a.zpLoads = loads.stream().mapToInt(Integer::intValue).toArray();
			a.zpStores = stores.stream().mapToInt(Integer::intValue).toArray();
		}

		private boolean isDirectMem(Varnode v) {
			return v.isAddress() && v.getAddress().getAddressSpace().equals(defaultSpace);
		}

		private int zpCell(Varnode v) {
			long a = v.getOffset();
			return (zp && a >= 0 && a < 0x100) ? (int) a : -1;
		}

		private boolean spaceIsDefault(Varnode spaceId) {
			try {
				AddressSpace s =
					program.getAddressFactory().getAddressSpace((int) spaceId.getOffset());
				return s != null && s.equals(defaultSpace);
			}
			catch (RuntimeException e) {
				return false;
			}
		}

		private static Long value(Varnode v, Map<Long, Long> uniq) {
			if (v == null) {
				return null;
			}
			if (v.isConstant()) {
				return v.getOffset();
			}
			return v.isUnique() ? uniq.get(v.getOffset()) : null;
		}

		private static Long evalConst(PcodeOp op, Map<Long, Long> uniq) {
			Long a = op.getNumInputs() > 0 ? value(op.getInput(0), uniq) : null;
			Long b = op.getNumInputs() > 1 ? value(op.getInput(1), uniq) : null;
			int sz = op.getOutput().getSize();
			long mask = sz >= 8 ? -1L : (1L << (8 * sz)) - 1;
			switch (op.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT:
					return a == null ? null : (a & mask);
				case PcodeOp.INT_ADD:
					return (a == null || b == null) ? null : ((a + b) & mask);
				case PcodeOp.INT_SUB:
					return (a == null || b == null) ? null : ((a - b) & mask);
				case PcodeOp.INT_AND:
					return (a == null || b == null) ? null : ((a & b) & mask);
				case PcodeOp.INT_OR:
					return (a == null || b == null) ? null : ((a | b) & mask);
				default:
					return null;
			}
		}

		// -------------------------------------------------------------- callee side

		private FnEvidence analyzeFunction(Address entry, List<Instruction> body) {
			FnEvidence ce = new FnEvidence(entry);
			ce.analyzed = true;
			ce.carry = 0;
			Map<Address, Integer> idx = new HashMap<>();
			for (int i = 0; i < body.size(); i++) {
				idx.put(body.get(i).getAddress(), i);
			}
			Map<Integer, Integer> cellBit = new HashMap<>();
			for (Instruction ins : body) {
				Ia a = ia(ins);
				for (int cell : a.zpLoads) {
					cellBit.computeIfAbsent(cell, k -> cellBit.size());
				}
				if (a.call && !a.ft.isComputed()) {
					FnEvidence s = result.byEntry.get(singleFlow(ins));
					if (s != null) {
						for (int cell : s.zpIn) {
							cellBit.computeIfAbsent(cell, k -> cellBit.size());
						}
					}
				}
			}
			int n = body.size();
			St[] in = new St[n];
			Integer entryIdx = idx.get(entry);
			if (entryIdx == null) {
				entryIdx = 0;
			}
			St s0 = new St();
			for (int i = 0; i < 3; i++) {
				s0.r[i] = 1 << i;
			}
			s0.c = C_ENTRY;
			s0.unw.set(0, cellBit.size());
			in[entryIdx] = s0;
			BitSet unwUnion = new BitSet();
			stackConflict = false;
			ArrayDeque<Integer> work = new ArrayDeque<>();
			work.add(entryIdx);
			boolean[] queued = new boolean[n];
			queued[entryIdx] = true;
			while (!work.isEmpty()) {
				int i = work.poll();
				queued[i] = false;
				Instruction ins = body.get(i);
				Ia a = ia(ins);
				St t = in[i].copy();
				List<Address> succ = new ArrayList<>();
				if (a.bad) {
					ce.complete = false;
					continue;
				}
				if (a.call) {
					if (a.ft.isComputed()) {
						ce.complete = false;
						clobberAll(t);
					}
					else {
						FnEvidence s = result.byEntry.get(singleFlow(ins));
						if (s == null) {
							ce.complete = false;
							clobberAll(t);
						}
						else {
							applyCall(t, s, ce, cellBit);
						}
					}
					Address ft2 = ins.getFallThrough();
					if (ft2 != null) {
						succ.add(ft2);
					}
					else {
						ce.tail = true;
					}
				}
				else {
					semantics(t, a, ce, cellBit);
					if (a.ret) {
						recordReturn(t, ce, unwUnion);
					}
					else if (a.terminal) {
						ce.complete = false;
					}
					else {
						Address ft2 = ins.getFallThrough();
						if (ft2 != null) {
							succ.add(ft2);
						}
						if (a.ft.isComputed()) {
							ce.indirect++;
							ce.complete = false;
						}
						for (Address tg : ins.getFlows()) {
							if (idx.containsKey(tg)) {
								succ.add(tg);
							}
							else {
								ce.tail = true;
								FnEvidence s = result.byEntry.get(tg);
								if (s == null) {
									ce.complete = false;
								}
								else {
									St u = t.copy();
									applyCall(u, s, ce, cellBit);
									recordReturn(u, ce, unwUnion);
								}
							}
						}
					}
				}
				for (Address sa : succ) {
					Integer j = idx.get(sa);
					if (j == null) {
						continue;
					}
					if (join(in, j, t) && !queued[j]) {
						queued[j] = true;
						work.add(j);
					}
				}
			}
			if (stackConflict) {
				ce.complete = false;
			}
			if (ce.returns > 0) {
				for (Map.Entry<Integer, Integer> cb : cellBit.entrySet()) {
					if (!unwUnion.get(cb.getValue())) {
						ce.zpWritten.add(cb.getKey());
					}
				}
			}
			else {
				ce.carry = C_ENTRY;
			}
			return ce;
		}

		private boolean join(St[] in, int j, St t) {
			if (in[j] == null) {
				in[j] = t.copy();
				return true;
			}
			St o = in[j];
			boolean changed = false;
			for (int i = 0; i < 3; i++) {
				int m = o.r[i] | t.r[i];
				changed |= m != o.r[i];
				o.r[i] = m;
			}
			int c = o.c | t.c;
			changed |= c != o.c;
			o.c = c;
			BitSet u = (BitSet) o.unw.clone();
			u.or(t.unw);
			if (!u.equals(o.unw)) {
				o.unw = u;
				changed = true;
			}
			if (o.stack != null) {
				if (t.stack == null || o.stack.length != t.stack.length) {
					o.stack = null;
					stackConflict = true;
					changed = true;
				}
				else {
					int[] ns = o.stack.clone();
					boolean ok = true;
					for (int k = 0; k < ns.length && ok; k++) {
						if ((ns[k] >> 4) != (t.stack[k] >> 4)) {
							ok = false;
						}
						ns[k] |= t.stack[k];
					}
					if (!ok) {
						o.stack = null;
						stackConflict = true;
						changed = true;
					}
					else if (!java.util.Arrays.equals(ns, o.stack)) {
						o.stack = ns;
						changed = true;
					}
				}
			}
			return changed;
		}

		private void clobberAll(St t) {
			for (int i = 0; i < 3; i++) {
				t.r[i] = CHG;
			}
			t.c = C_UNK;
			t.unw.clear();
		}

		private void use(St t, int reg, boolean wide, boolean narrow, FnEvidence ce) {
			int m = t.r[reg];
			for (int s = 0; s < 3; s++) {
				if ((m & (1 << s)) != 0) {
					ce.inMask |= 1 << s;
					if (wide) {
						ce.inWide |= 1 << s;
					}
					if (narrow) {
						ce.inNarrow |= 1 << s;
					}
				}
			}
		}

		private void semantics(St t, Ia a, FnEvidence ce, Map<Integer, Integer> cellBit) {
			int copySrc = 0;
			for (int d = 0; d < 3; d++) {
				if (a.copy[d] >= 0) {
					copySrc |= 1 << a.copy[d];
				}
			}
			for (int r = 0; r < 3; r++) {
				if ((a.readMask & (1 << r)) != 0 && (copySrc & (1 << r)) == 0 && a.pushSym != r) {
					boolean wide = (a.wide & (1 << r)) != 0;
					use(t, r, wide, !wide, ce);
				}
			}
			if ((a.readMask & (1 << RC)) != 0 && (t.c & C_ENTRY) != 0) {
				ce.carryIn = true;
			}
			for (int cell : a.zpLoads) {
				Integer b = cellBit.get(cell);
				if (b != null && t.unw.get(b)) {
					ce.zpIn.add(cell);
				}
			}
			int[] nr = t.r.clone();
			for (int d = 0; d < 3; d++) {
				if (a.copy[d] >= 0) {
					nr[d] = t.r[a.copy[d]];
				}
				else if ((a.writeMask & (1 << d)) != 0) {
					nr[d] = CHG;
				}
			}
			if ((a.writeMask & (1 << RC)) != 0) {
				t.c = a.carryWrite == 0 ? C_ZERO : a.carryWrite == 1 ? C_ONE : C_UNK;
			}
			if (!a.delta.isPresent()) {
				t.stack = null;
				ce.complete = false;
			}
			else if (t.stack != null && a.delta.getAsInt() < 0) {
				int size = -a.delta.getAsInt();
				int mask = a.pushSym >= 0 ? t.r[a.pushSym] : CHG;
				int[] ns = java.util.Arrays.copyOf(t.stack, t.stack.length + 1);
				ns[t.stack.length] = (size << 4) | mask;
				t.stack = ns;
			}
			else if (t.stack != null && a.delta.getAsInt() > 0) {
				int need = a.delta.getAsInt();
				int popMask = CHG;
				int popped = 0;
				int len = t.stack.length;
				while (need > 0 && len > 0) {
					int e = t.stack[--len];
					int sz = e >> 4;
					if (sz > need) {
						t.stack = null;
						ce.complete = false;
						break;
					}
					need -= sz;
					popped++;
					popMask = e & 15;
				}
				if (t.stack != null) {
					if (need > 0) {
						ce.complete = false; // pulls the caller's data: not a plain frame
					}
					t.stack = java.util.Arrays.copyOf(t.stack, len);
					if (popped != 1 || need > 0) {
						popMask = CHG;
					}
					if (a.pulledSym >= 0) {
						nr[a.pulledSym] = popMask;
					}
				}
			}
			System.arraycopy(nr, 0, t.r, 0, 3);
			for (int cell : a.zpStores) {
				Integer b = cellBit.get(cell);
				if (b != null) {
					t.unw.clear(b);
				}
			}
		}

		private void applyCall(St t, FnEvidence s, FnEvidence ce, Map<Integer, Integer> cellBit) {
			for (int r = 0; r < 3; r++) {
				if ((s.inMask & (1 << r)) != 0) {
					use(t, r, (s.inWide & (1 << r)) != 0, (s.inNarrow & (1 << r)) != 0, ce);
				}
			}
			if (s.carryIn && (t.c & C_ENTRY) != 0) {
				ce.carryIn = true;
			}
			for (int cell : s.zpIn) {
				Integer b = cellBit.get(cell);
				if (b != null && t.unw.get(b)) {
					ce.zpIn.add(cell);
				}
			}
			for (int cell : s.zpWritten) {
				Integer b = cellBit.get(cell);
				if (b != null) {
					t.unw.clear(b);
				}
			}
			for (int r = 0; r < 3; r++) {
				if ((s.outMask & (1 << r)) != 0) {
					t.r[r] = CHG;
				}
			}
			if (s.returns > 0) {
				t.c = ((s.carry & C_ENTRY) != 0 ? t.c : 0) | (s.carry & ~C_ENTRY);
			}
			if (!s.complete) {
				ce.complete = false;
			}
		}

		private void recordReturn(St t, FnEvidence ce, BitSet unwUnion) {
			if (t.stack == null || t.stack.length != 0) {
				ce.complete = false;
			}
			ce.returns++;
			for (int r = 0; r < 3; r++) {
				int m = t.r[r];
				if (m != (1 << r)) {
					ce.outMask |= 1 << r;
					for (int s = 0; s < 3; s++) {
						if (s != r && (m & (1 << s)) != 0) {
							ce.inMask |= 1 << s;
						}
					}
				}
			}
			ce.carry |= t.c;
			unwUnion.or(t.unw);
		}

		// -------------------------------------------------------------- caller side

		/**
		 * Callers come from the ReferenceManager, not from scanning call instructions: every
		 * reference TO the entry whose type is a call (computed-call and far-call references our
		 * analyzers add included), plus the callers of any thunk of the function.
		 */
		private void callerSide(Map<Address, List<Instruction>> bodies) {
			ReferenceManager rm = program.getReferenceManager();
			for (Address entry : bodies.keySet()) {
				FnEvidence g = result.byEntry.get(entry);
				Function f = fm.getFunctionAt(entry);
				if (g == null || f == null) {
					continue;
				}
				List<Address> targets = new ArrayList<>();
				targets.add(entry);
				for (Address t : f.getFunctionThunkAddresses(true) == null ? new Address[0]
						: f.getFunctionThunkAddresses(true)) {
					targets.add(t);
				}
				Set<Address> seen = new HashSet<>();
				for (Address target : targets) {
					for (Reference ref : rm.getReferencesTo(target)) {
						if (ref.getReferenceType().isCall()) {
							Instruction ci = listing.getInstructionAt(ref.getFromAddress());
							if (ci == null || ia(ci).bad || !seen.add(ci.getAddress())) {
								continue;
							}
							g.sites++;
							lookAhead(ci, g);
							lookBack(ci, g);
						}
						else if (ref.getReferenceType().isJump()) {
							Function from = listing.getFunctionContaining(ref.getFromAddress());
							if (from == null || !from.equals(f)) {
								g.jumpRefs++;
							}
						}
					}
				}
			}
		}

		private void lookAhead(Instruction ci, FnEvidence g) {
			Address ft = ci.getFallThrough();
			if (ft == null) {
				return;
			}
			ArrayDeque<Object[]> st = new ArrayDeque<>();
			st.push(new Object[] { ft, 0 });
			Map<Address, Integer> seen = new HashMap<>();
			int steps = 0;
			while (!st.isEmpty() && steps < PATH_STEPS) {
				Object[] top = st.pop();
				Address ad = (Address) top[0];
				int w = (Integer) top[1];
				Instruction cur = listing.getInstructionAt(ad);
				if (cur == null) {
					continue;
				}
				Integer prev = seen.get(ad);
				if (prev != null && (w & prev) == prev) {
					continue;
				}
				seen.put(ad, prev == null ? w : (prev & w));
				steps++;
				Ia a = ia(cur);
				if (a.bad) {
					continue;
				}
				int reads;
				int writes;
				if (a.call) {
					FnEvidence s = a.ft.isComputed() ? null : result.byEntry.get(singleFlow(cur));
					if (s == null) {
						reads = 0;
						writes = 63;
					}
					else {
						reads = s.inMask | (s.carryIn ? 1 << RC : 0);
						writes = s.outMask | (1 << RZ) | (1 << RN) |
							(s.carryWritten() ? 1 << RC : 0);
					}
				}
				else {
					reads = a.readMask;
					writes = a.writeMask;
					if (a.branchBit >= 0 && (w & (1 << a.branchBit)) == 0) {
						g.afterBranch |= 1 << a.branchBit;
					}
				}
				g.afterRead |= reads & ~w & 7;
				w |= writes;
				if ((w & 63) == 63) {
					continue;
				}
				if (a.ret) {
					g.afterPass |= ~w & 7;
					continue;
				}
				if (a.terminal || (!a.call && a.ft.isComputed())) {
					continue;
				}
				Address nx = cur.getFallThrough();
				if (nx != null) {
					st.push(new Object[] { nx, w });
				}
				if (!a.call) {
					for (Address tg : cur.getFlows()) {
						st.push(new Object[] { tg, w });
					}
				}
			}
		}

		private void lookBack(Instruction ci, FnEvidence g) {
			Instruction cur = ci;
			for (int i = 0; i < LOOK; i++) {
				Instruction prev = cur.getPrevious();
				if (prev == null || prev.getFallThrough() == null ||
					!prev.getFallThrough().equals(cur.getAddress()) ||
					!prev.getFlowType().equals(RefType.FALL_THROUGH)) {
					break;
				}
				Ia a = ia(prev);
				g.beforeWrite |= a.writeMask;
				for (int cell : a.zpStores) {
					if (g.zpIn.contains(cell)) {
						g.zpSetBefore = true;
					}
				}
				cur = prev;
			}
		}
	}
}
