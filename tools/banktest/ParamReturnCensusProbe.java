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
// Parameter / return-value census (bead grm-etbh, step 1). For every function, per CPU: which
// of A/X/Y (and the carry flag, Z, N, and zero-page cells on 6502-family CPUs) the CALLEE reads
// before writing (inputs) or leaves written at a return (outputs), and what CALLERS do with
// them around each direct call (read the register / branch on the flag after the call, write
// the register / cell before it). Everything is derived from instruction P-CODE (register-space
// varnodes, LOAD/STORE with constant addresses, CBRANCH, RETURN), never from mnemonics.
//
// Output (also appended to <GRM_PRC_OUT>/<program>.prc when that env var names a directory,
// because a passing row deletes its log):
//   PRC <row> SUMMARY lang=.. fns=.. analyzed=.. skippedCap=.. noCallers=.. callSites=.. ...
//   PRC <row> CASE case=<name> callee=<n> caller=<n> both=<n>
//   PRC <row> SAMPLE case=<name> kind=<both|callee|caller> fn=<addr> callers=<k>
// Callee evidence of a case is independent of callers and vice versa; both = intersection.
// Limits (also in the bead notes): calls are opaque (they clobber everything for the walk);
// the register-restored test is a heuristic (a push of the register anywhere in the function
// counts as "saved"); 65816 direct-page cells are NOT modelled (no ZP cases there); SPC700
// flags live as bit slices of PSW so they are lumped into one "flag" resource without
// constant-carry detection. Run as REALROM_EXTRA_POSTSCRIPT. Read-only.
//@category RetroMachines.Test

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

public class ParamReturnCensusProbe extends GhidraScript {

	private static final int MAX_INSNS = 3000;
	private static final int LOOK = 8;
	private static final int A = 0, X = 1, Y = 2, C = 3, Z = 4, N = 5, NRES = 6;
	private static final String[] RNAME = { "A", "X", "Y", "C", "Z", "N" };
	private static final int CELL0 = 6;
	// carry value lattice bits
	private static final int C_ENTRY = 1, C_ZERO = 2, C_ONE = 4, C_UNK = 8;

	private final long[] lo = new long[NRES];
	private final long[] hi = new long[NRES];
	private boolean carryConst = true;
	private boolean zpEnabled = true;
	private long spLo = -1;
	private long spHi = -1;
	private String defaultSpace;
	private Listing listing;
	private final Map<Address, Ia> iaCache = new HashMap<>();

	/** Per-instruction p-code facts. */
	private static final class Ia {
		int readMask;      // resources read before written inside the instruction
		int writeMask;
		int branchMask;    // flag resources read by an instruction containing a CBRANCH
		int readWide;      // resources read at a size > 1
		int carryWrite = -1; // -1 none, 0, 1, 2 unknown
		boolean isReturn;
		boolean push;
		boolean badPcode;
		final Set<Integer> zpLoads = new HashSet<>();
		final Set<Integer> zpStores = new HashSet<>();
	}

	private static final class Counter {
		int callee;
		int caller;
		int both;
		final Map<String, List<String>> samples = new TreeMap<>();
	}

	@Override
	protected void run() throws Exception {
		listing = currentProgram.getListing();
		String lang = currentProgram.getLanguageID().getIdAsString();
		String row = currentProgram.getName();
		setupRegisters(lang);
		Register sp = currentProgram.getCompilerSpec().getStackPointer();
		if (sp != null) {
			spLo = sp.getOffset();
			spHi = spLo + sp.getMinimumByteSize();
		}
		defaultSpace = currentProgram.getLanguage().getDefaultSpace().getName();
		int samples = Integer.getInteger("grm.prc.samples", 3);
		String sEnv = System.getenv("GRM_PRC_SAMPLES");
		if (sEnv != null) {
			samples = Integer.parseInt(sEnv.trim());
		}

		Map<String, Counter> cases = new TreeMap<>();
		int fns = 0, analyzed = 0, skippedCap = 0, noCallers = 0, callSites = 0;
		int indirect = 0, tails = 0, noReturns = 0, tailInRefs = 0, calleeUnresolved = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			fns++;
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			List<Instruction> body = new ArrayList<>();
			for (Instruction i : listing.getInstructions(f.getBody(), true)) {
				body.add(i);
				if (body.size() > MAX_INSNS) {
					break;
				}
			}
			if (body.isEmpty()) {
				continue;
			}
			if (body.size() > MAX_INSNS) {
				skippedCap++;
				continue;
			}
			Callee ce = analyzeCallee(f, body);
			analyzed++;
			indirect += ce.indirect;
			tails += ce.tail ? 1 : 0;
			if (ce.returns == 0) {
				noReturns++;
			}
			Callers cs = analyzeCallers(f, ce);
			callSites += cs.sites;
			tailInRefs += cs.jumpRefs;
			if (cs.sites == 0) {
				noCallers++;
			}
			record(cases, f, ce, cs, samples);
		}
		StringBuilder sb = new StringBuilder();
		sb.append("PRC ").append(row).append(" SUMMARY lang=").append(lang).append(" fns=")
			.append(fns).append(" analyzed=").append(analyzed).append(" skippedCap=")
			.append(skippedCap).append(" noCallers=").append(noCallers).append(" callSites=")
			.append(callSites).append(" indirectJumps=").append(indirect).append(" tailExit=")
			.append(tails).append(" noReturnPath=").append(noReturns).append(" jumpRefsIn=")
			.append(tailInRefs).append(" carryConstModel=").append(carryConst).append(" zpModel=")
			.append(zpEnabled);
		List<String> out = new ArrayList<>();
		out.add(sb.toString());
		for (Map.Entry<String, Counter> e : cases.entrySet()) {
			Counter c = e.getValue();
			out.add("PRC " + row + " CASE case=" + e.getKey() + " callee=" + c.callee +
				" caller=" + c.caller + " both=" + c.both);
			for (Map.Entry<String, List<String>> s : c.samples.entrySet()) {
				for (String line : s.getValue()) {
					out.add("PRC " + row + " SAMPLE case=" + e.getKey() + " kind=" + s.getKey() +
						" " + line);
				}
			}
		}
		for (String l : out) {
			println(l);
		}
		String dir = System.getenv("GRM_PRC_OUT");
		if (dir != null && !dir.isBlank()) {
			try {
				Path p = Paths.get(dir);
				Files.createDirectories(p);
				try (PrintWriter w =
					new PrintWriter(new FileWriter(p.resolve(row + ".prc").toFile()))) {
					for (String l : out) {
						w.println(l);
					}
				}
			}
			catch (IOException e) {
				println("PRC " + row + " WARN cannot write GRM_PRC_OUT: " + e);
			}
		}
	}

	// ------------------------------------------------------------------ register setup

	private void setupRegisters(String lang) {
		boolean is816 = lang.contains("65816");
		zpEnabled = !is816;
		Register c = currentProgram.getRegister("C");
		String aName = (c != null && c.getMinimumByteSize() >= 2) ? "C" : "A";
		setRange(A, currentProgram.getRegister(aName));
		setRange(X, currentProgram.getRegister("X"));
		setRange(Y, currentProgram.getRegister("Y"));
		Register cf = currentProgram.getRegister("CF");
		if (cf == null && c != null && c.getMinimumByteSize() == 1) {
			cf = c;
		}
		if (cf != null) {
			setRange(C, cf);
			setRange(Z, firstOf("ZF", "Z"));
			setRange(N, firstOf("NF", "N"));
		}
		else {
			Register psw = currentProgram.getRegister("PSW");
			if (psw != null) {
				carryConst = false;
				setRange(C, psw);
				lo[Z] = hi[Z] = -1;
				lo[N] = hi[N] = -1;
			}
		}
	}

	private Register firstOf(String a, String b) {
		Register r = currentProgram.getRegister(a);
		return r != null ? r : currentProgram.getRegister(b);
	}

	private void setRange(int res, Register r) {
		if (r == null) {
			lo[res] = hi[res] = -1;
			return;
		}
		lo[res] = r.getOffset();
		hi[res] = r.getOffset() + r.getMinimumByteSize();
	}

	private int resOf(Varnode v) {
		long a = v.getOffset();
		long b = a + v.getSize();
		for (int r = 0; r < NRES; r++) {
			if (lo[r] >= 0 && a < hi[r] && b > lo[r]) {
				return r;
			}
		}
		return -1;
	}

	// ------------------------------------------------------------------ per-instruction p-code

	private Ia ia(Instruction ins) {
		Ia r = iaCache.get(ins.getAddress());
		if (r != null) {
			return r;
		}
		r = new Ia();
		Map<Long, Long> uniq = new HashMap<>();
		int written = 0;
		boolean hasCbranch = false;
		boolean readsSp = false;
		boolean storeNonConst = false;
		PcodeOp[] ops;
		try {
			ops = ins.getPcode();
		}
		catch (RuntimeException e) {
			r.badPcode = true;
			iaCache.put(ins.getAddress(), r);
			return r;
		}
		for (PcodeOp op : ops) {
			int oc = op.getOpcode();
			int first = (oc == PcodeOp.LOAD || oc == PcodeOp.STORE) ? 1 : 0;
			if (oc == PcodeOp.CBRANCH) {
				hasCbranch = true;
			}
			if (oc == PcodeOp.RETURN) {
				r.isReturn = true;
			}
			for (int k = first; k < op.getNumInputs(); k++) {
				if (oc == PcodeOp.BRANCH || oc == PcodeOp.CALL || (oc == PcodeOp.CBRANCH && k == 0)) {
					continue;
				}
				Varnode v = op.getInput(k);
				if (v != null && isDirectMem(v)) {
					int cell = zpCell(v);
					if (cell >= 0) {
						r.zpLoads.add(cell);
					}
					continue;
				}
				if (v == null || !v.isRegister()) {
					continue;
				}
				if (spLo >= 0 && v.getOffset() < spHi && v.getOffset() + v.getSize() > spLo) {
					readsSp = true;
				}
				int res = resOf(v);
				if (res >= 0 && (written & (1 << res)) == 0) {
					r.readMask |= 1 << res;
					if (v.getSize() > 1) {
						r.readWide |= 1 << res;
					}
				}
			}
			if (oc == PcodeOp.LOAD || oc == PcodeOp.STORE) {
				Long addr = value(op.getInput(1), uniq);
				boolean dflt = op.getInput(0) != null && spaceIsDefault(op.getInput(0));
				if (addr != null && dflt && zpEnabled && addr >= 0 && addr < 0x100) {
					(oc == PcodeOp.LOAD ? r.zpLoads : r.zpStores).add((int) (long) addr);
				}
				else if (oc == PcodeOp.STORE && addr == null) {
					storeNonConst = true;
				}
			}
			Varnode out = op.getOutput();
			if (out != null && isDirectMem(out)) {
				int cell = zpCell(out);
				if (cell >= 0) {
					r.zpStores.add(cell);
				}
			}
			else if (out != null) {
				if (out.isUnique()) {
					Long cv = evalConst(op, uniq);
					if (cv != null) {
						uniq.put(out.getOffset(), cv);
					}
					else {
						uniq.remove(out.getOffset());
					}
				}
				else if (out.isRegister()) {
					int res = resOf(out);
					if (res >= 0) {
						written |= 1 << res;
						r.writeMask |= 1 << res;
						if (res == C) {
							Long cv = oc == PcodeOp.COPY ? value(op.getInput(0), uniq) : null;
							r.carryWrite = (carryConst && cv != null && (cv == 0 || cv == 1))
									? (int) (long) cv : 2;
						}
					}
				}
			}
		}
		if (hasCbranch) {
			r.branchMask = r.readMask & ((1 << C) | (1 << Z) | (1 << N));
		}
		r.push = readsSp && storeNonConst;
		iaCache.put(ins.getAddress(), r);
		return r;
	}

	/** A varnode directly in the default data space (an exported *[ram]:1 operand). */
	private boolean isDirectMem(Varnode v) {
		return v.isAddress() && v.getAddress().getAddressSpace().getName().equals(defaultSpace);
	}

	private int zpCell(Varnode v) {
		long a = v.getOffset();
		return (zpEnabled && a >= 0 && a < 0x100) ? (int) a : -1;
	}

	private boolean spaceIsDefault(Varnode spaceId) {
		try {
			ghidra.program.model.address.AddressSpace s =
				currentProgram.getAddressFactory().getAddressSpace((int) spaceId.getOffset());
			return s != null && s.getName().equals(defaultSpace);
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	private Long value(Varnode v, Map<Long, Long> uniq) {
		if (v == null) {
			return null;
		}
		if (v.isConstant()) {
			return v.getOffset();
		}
		if (v.isUnique()) {
			return uniq.get(v.getOffset());
		}
		return null;
	}

	private Long evalConst(PcodeOp op, Map<Long, Long> uniq) {
		Long a = op.getNumInputs() > 0 ? value(op.getInput(0), uniq) : null;
		Long b = op.getNumInputs() > 1 ? value(op.getInput(1), uniq) : null;
		long mask = op.getOutput().getSize() >= 8 ? -1L : (1L << (8 * op.getOutput().getSize())) - 1;
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

	// ------------------------------------------------------------------ callee side

	private static final class Callee {
		int readMask;      // may be read before written (A,X,Y,C,Z,N)
		int readWide;
		int outMask;       // written on some path to a return
		int savedMask;     // register pushed somewhere in the body (heuristic restore)
		int cUnion;        // carry lattice at returns
		int returns;
		int indirect;
		boolean tail;
		final Set<Integer> zpIn = new HashSet<>();
		boolean strictCarryConst() {
			return returns > 0 && (cUnion & (C_ENTRY | C_UNK)) == 0;
		}
		boolean someCarryConst() {
			return (cUnion & (C_ZERO | C_ONE)) != 0;
		}
		boolean bothCarryVals() {
			return (cUnion & C_ZERO) != 0 && (cUnion & C_ONE) != 0;
		}
	}

	private Callee analyzeCallee(Function f, List<Instruction> body) {
		Callee ce = new Callee();
		AddressSet bodySet = new AddressSet();
		Map<Address, Integer> idx = new HashMap<>();
		for (int i = 0; i < body.size(); i++) {
			idx.put(body.get(i).getAddress(), i);
			bodySet.add(body.get(i).getAddress());
		}
		// candidate zp cells: those loaded anywhere in the body
		Map<Integer, Integer> cellBit = new HashMap<>();
		for (Instruction ins : body) {
			Ia a = ia(ins);
			for (int cell : a.zpLoads) {
				cellBit.computeIfAbsent(cell, k -> CELL0 + cellBit.size());
			}
			if (a.push) {
				ce.savedMask |= a.readMask & 7;
			}
		}
		int n = body.size();
		BitSet[] unw = new BitSet[n];
		int[] wr = new int[n];
		int[] cm = new int[n];
		BitSet all = new BitSet();
		all.set(0, NRES);
		for (int b : cellBit.values()) {
			all.set(b);
		}
		Integer entryIdx = idx.get(f.getEntryPoint());
		if (entryIdx == null) {
			entryIdx = 0;
		}
		unw[entryIdx] = (BitSet) all.clone();
		cm[entryIdx] = C_ENTRY;
		ArrayDeque<Integer> work = new ArrayDeque<>();
		work.add(entryIdx);
		while (!work.isEmpty()) {
			int i = work.poll();
			Instruction ins = body.get(i);
			Ia a = ia(ins);
			BitSet u = (BitSet) unw[i].clone();
			int w = wr[i];
			int c = cm[i];
			FlowType ft = ins.getFlowType();
			boolean call = ft.isCall();
			if (call) {
				u.clear(0, NRES);
				for (int b : cellBit.values()) {
					u.clear(b);
				}
				w |= 7;
				c = C_UNK;
			}
			else {
				for (int r = 0; r < NRES; r++) {
					if ((a.writeMask & (1 << r)) != 0) {
						u.clear(r);
					}
				}
				w |= a.writeMask & 7;
				if (a.carryWrite >= 0) {
					c = a.carryWrite == 0 ? C_ZERO : a.carryWrite == 1 ? C_ONE : C_UNK;
				}
				else if ((a.writeMask & (1 << C)) != 0) {
					c = C_UNK;
				}
				for (int cell : a.zpStores) {
					Integer b = cellBit.get(cell);
					if (b != null) {
						u.clear(b);
					}
				}
			}
			List<Address> succ = new ArrayList<>();
			if (a.isReturn) {
				ce.outMask |= w;
				ce.cUnion |= c;
				ce.returns++;
			}
			else {
				Address ft2 = ins.getFallThrough();
				if (ft2 != null) {
					succ.add(ft2);
				}
				if (call) {
					if (ft2 == null) {
						ce.tail = true;
					}
				}
				else {
					if (ft.isComputed()) {
						ce.indirect++;
					}
					for (Address t : ins.getFlows()) {
						if (bodySet.contains(t)) {
							succ.add(t);
						}
						else {
							ce.tail = true;
						}
					}
				}
			}
			for (Address s : succ) {
				Integer j = idx.get(s);
				if (j == null) {
					continue;
				}
				boolean changed = false;
				if (unw[j] == null) {
					unw[j] = (BitSet) u.clone();
					wr[j] = w;
					cm[j] = c;
					changed = true;
				}
				else {
					BitSet m = (BitSet) unw[j].clone();
					m.or(u);
					int w2 = wr[j] | w;
					int c2 = cm[j] | c;
					if (!m.equals(unw[j]) || w2 != wr[j] || c2 != cm[j]) {
						unw[j] = m;
						wr[j] = w2;
						cm[j] = c2;
						changed = true;
					}
				}
				if (changed) {
					work.add(j);
				}
			}
		}
		for (int i = 0; i < n; i++) {
			if (unw[i] == null) {
				continue;
			}
			Ia a = ia(body.get(i));
			if (body.get(i).getFlowType().isCall()) {
				continue; // reads inside a call instruction are the callee's, not ours
			}
			for (int r = 0; r < NRES; r++) {
				if ((a.readMask & (1 << r)) != 0 && unw[i].get(r)) {
					ce.readMask |= 1 << r;
					if ((a.readWide & (1 << r)) != 0) {
						ce.readWide |= 1 << r;
					}
				}
			}
			for (int cell : a.zpLoads) {
				Integer b = cellBit.get(cell);
				if (b != null && unw[i].get(b)) {
					ce.zpIn.add(cell);
				}
			}
		}
		return ce;
	}

	// ------------------------------------------------------------------ caller side

	private static final class Callers {
		int sites;
		int jumpRefs;
		int afterRead;     // mask A/X/Y/C(unused)/Z/N: some caller reads before write
		int afterBranch;   // mask of C/Z/N: some caller branches on it before write
		int beforeWrite;   // mask: some caller writes this resource within LOOK insns before
		boolean zpSet;     // some caller stores a cell in callee zpIn before the call
	}

	private Callers analyzeCallers(Function f, Callee ce) {
		Callers cs = new Callers();
		for (Reference ref : currentProgram.getReferenceManager()
			.getReferencesTo(f.getEntryPoint())) {
			if (ref.getReferenceType().isCall()) {
				Instruction ci = listing.getInstructionAt(ref.getFromAddress());
				if (ci == null || !ci.getFlowType().isCall()) {
					continue;
				}
				cs.sites++;
				lookAhead(ci, cs);
				lookBack(ci, cs, ce);
			}
			else if (ref.getReferenceType().isJump()) {
				Function from = listing.getFunctionContaining(ref.getFromAddress());
				if (from == null || !from.equals(f)) {
					cs.jumpRefs++;
				}
			}
		}
		return cs;
	}

	private void lookAhead(Instruction ci, Callers cs) {
		Address ft = ci.getFallThrough();
		Instruction cur = ft == null ? null : listing.getInstructionAt(ft);
		int written = 0;
		for (int i = 0; i < LOOK && cur != null; i++) {
			Ia a = ia(cur);
			if (a.badPcode) {
				return;
			}
			int fresh = a.readMask & ~written;
			cs.afterRead |= fresh & 0x3f;
			cs.afterBranch |= a.branchMask & ~written;
			if (cur.getFlowType().isCall() || a.isReturn) {
				return;
			}
			written |= a.writeMask;
			Address nx = cur.getFallThrough();
			cur = nx == null ? null : listing.getInstructionAt(nx);
		}
	}

	private void lookBack(Instruction ci, Callers cs, Callee ce) {
		Instruction cur = ci;
		boolean zp = false;
		for (int i = 0; i < LOOK; i++) {
			Instruction prev = cur.getPrevious();
			if (prev == null || prev.getFallThrough() == null ||
				!prev.getFallThrough().equals(cur.getAddress()) ||
				!prev.getFlowType().equals(ghidra.program.model.symbol.RefType.FALL_THROUGH)) {
				break;
			}
			Ia a = ia(prev);
			cs.beforeWrite |= a.writeMask;
			for (int cell : a.zpStores) {
				if (ce.zpIn.contains(cell)) {
					zp = true;
				}
			}
			cur = prev;
		}
		cs.zpSet |= zp;
	}

	// ------------------------------------------------------------------ classification

	private void record(Map<String, Counter> cases, Function f, Callee ce, Callers cs,
			int samples) {
		for (int r : new int[] { A, X, Y }) {
			String n = RNAME[r].toLowerCase();
			boolean calleeOut = (ce.outMask & (1 << r)) != 0 && (ce.savedMask & (1 << r)) == 0;
			boolean callerRead = (cs.afterRead & (1 << r)) != 0;
			add(cases, n + "_ret", calleeOut, callerRead, f, cs, samples);
			boolean in = (ce.readMask & (1 << r)) != 0;
			boolean wr = (cs.beforeWrite & (1 << r)) != 0;
			add(cases, n + "_in", in, wr, f, cs, samples);
			if (in && (ce.readWide & (1 << r)) != 0) {
				add(cases, n + "_in_wide", true, wr, f, cs, samples);
			}
			// output that is also an input (pass-through / modify-in-place)
			add(cases, n + "_inout", in && calleeOut, callerRead && wr, f, cs, samples);
		}
		boolean cBranch = (cs.afterBranch & (1 << C)) != 0;
		add(cases, "carry_ret_some_const", ce.someCarryConst(), cBranch, f, cs, samples);
		add(cases, "carry_ret_all_const", ce.strictCarryConst(), cBranch, f, cs, samples);
		add(cases, "carry_ret_both_values", ce.bothCarryVals(), cBranch, f, cs, samples);
		add(cases, "carry_ret_any_written", ce.returns > 0 && (ce.cUnion & C_ENTRY) == 0, cBranch,
			f, cs, samples);
		add(cases, "carry_in", (ce.readMask & (1 << C)) != 0,
			(cs.beforeWrite & (1 << C)) != 0, f, cs, samples);
		if (lo[Z] >= 0) {
			// callee evidence for Z/N would be "the last op before RETURN set it", true of
			// nearly every routine, so only the caller side is meaningful here (callee=0).
			add(cases, "z_ret_callerOnly", false, (cs.afterBranch & (1 << Z)) != 0, f, cs,
				samples);
			add(cases, "n_ret_callerOnly", false, (cs.afterBranch & (1 << N)) != 0, f, cs,
				samples);
		}
		else if (lo[C] >= 0) {
			// SPC700: one lumped PSW resource, no per-flag split.
			add(cases, "psw_branch_callerOnly", false, cBranch, f, cs, samples);
		}
		if (zpEnabled) {
			add(cases, "zp_in", !ce.zpIn.isEmpty(), cs.zpSet, f, cs, samples);
		}
	}

	private void add(Map<String, Counter> cases, String name, boolean callee, boolean caller,
			Function f, Callers cs, int samples) {
		Counter c = cases.computeIfAbsent(name, k -> new Counter());
		String kind = null;
		if (callee) {
			c.callee++;
		}
		if (caller) {
			c.caller++;
		}
		if (callee && caller) {
			c.both++;
			kind = "both";
		}
		else if (callee) {
			kind = "callee";
		}
		else if (caller) {
			kind = "caller";
		}
		if (kind != null) {
			List<String> l = c.samples.computeIfAbsent(kind, k -> new ArrayList<>());
			if (l.size() < ("both".equals(kind) ? samples : 1)) {
				l.add("fn=" + f.getEntryPoint() + " callers=" + cs.sites);
			}
		}
	}
}
