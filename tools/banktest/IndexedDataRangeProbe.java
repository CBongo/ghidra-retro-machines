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
// Indexed DATA read range survey (bead grm-9nxj.41.1; parent grm-9nxj.41). Run as
// REALROM_EXTRA_POSTSCRIPT=IndexedDataRangeProbe.java REALROM_WORK_DIR=<dir>. Read-only.
//
// For every register-indexed absolute access (6502/65816 abs,X / abs,Y; 65816 long,X) whose base
// lies in an initialized non-volatile block it emits one `IDR` line, with the evidence that
// proves a live index range at that site:
//   G  guard:  CMP/CPX/CPY #imm + BCC/BCS bounding the index register (or a register it copies /
//              doubles) on the path to the read. Fall-through of BCS / taken BCC => reg < imm
//              (range [.., imm-1]); fall-through of BCC / taken BCS => reg >= imm (lower bound only,
//              upper open, printed `*`). The path back from the read must be entered only by
//              fall-through or by the guard branch itself.
//   L  loop:   the read sits in a loop closed by a backward conditional branch (round 2,
//              grm-9nxj.41.2: a forward dataflow over the loop body). The index register is a
//              symbolic iteration-start value I; it may be saved and restored inside the body
//              (TXA/PHA..PLA/TAX, STX cell..LDX cell, PHX/PLX), inner loops are black boxes, and a
//              JSR is transparent when the callee (3 levels deep) provably never writes the
//              register (`Lcall=1`). The closing branch's flag source gives the range:
//              DEX/DEY+BNE ([k,n]) / +BPL ([0,n]), INX/INY+BNE ([n,256-k]) or +CPX/CPY #m with
//              BNE/BCC ([n,m-k]) and the countdown BNE/BCS forms, step k up to 8; a read after the
//              step shifts the range; a different counter register stepping in lock-step is used
//              when both inits are immediates (`Lw=lockstep`). `Lw=init` marks a countdown whose
//              init is not an immediate (lower bound only, hi `*`), `Lw=limit` a count-up to a
//              memory limit (lo only). Entries into the loop other than falling into the head, and
//              every other shape, are `Lunk=<reason>`, never guessed.
//   F  family: other reads in the straight-line window carrying the SAME index token (ASL-doubled
//              = stride 2), with TableFamilyProbe's tiling/disjointness equations: candidate
//              [lo,H) is disjoint, in initialized memory, over no instruction; an equation is
//              member end == another member start, or member end == a decoded instruction. Two
//              agreeing equations pin (lo,H) (only evaluated with >= 2 members).
//   T  target shape only: what is at base, and at base+1 (INSN / INSIDE / DATA_START / DATA_MID /
//              DATA_TAIL / UNDEF). `sym=1` when base lands on an instruction or inside other data,
//              the grm-9nxj.41 symptom. No range is claimed from T.
// Every proven class prints its start/end(exclusive) addresses (`Gstart=`, `Gend=`; `*` when
// open) and what lies at its start (`Gat=`). 65816 abs,X has no static bank, so its base is the
// existing data reference whose low 16 bits match the operand (sites with none are skipped and
// counted); long,X uses the operand bank.
//
// Independent of production (does not call retromachines.*), per ProbeSupport's rule.
// Aggregated by tools/recon/indexed_data_range_census.py.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

public class IndexedDataRangeProbe extends GhidraScript {

	private static final int BACK = 24;
	private static final int FWD = 24;
	private static final int MAX_LO = 6;
	private static final int MAX_H = 256;

	private static final Set<Integer> ABS_X_R =
		Set.of(0xbd, 0xbc, 0x7d, 0xfd, 0xdd, 0x3d, 0x1d, 0x5d);
	private static final Set<Integer> ABS_Y_R =
		Set.of(0xb9, 0xbe, 0x79, 0xf9, 0xd9, 0x39, 0x19, 0x59);
	private static final Set<Integer> ABS_X_S = Set.of(0x9d, 0x1e, 0x3e, 0x5e, 0x7e, 0xde, 0xfe);
	private static final Set<Integer> ABS_Y_S = Set.of(0x99);
	private static final Set<Integer> LONG_X_R = Set.of(0xbf, 0x7f, 0xff, 0xdf, 0x3f, 0x1f, 0x5f);
	private static final Set<Integer> LONG_X_S = Set.of(0x9f);

	private Listing listing;
	private Memory mem;
	private boolean is816;
	private int tokenCounter = 1;

	private record V(int tok, int scale, int off) {}

	private static final class St {
		V a;
		V x;
		V y;
	}

	/** Index register range in register units; hi == Long.MIN_VALUE means open. lo may be unset. */
	private record Rng(long lo, long hi) {
		boolean openHi() {
			return hi == Long.MIN_VALUE;
		}

		String txt() {
			return lo + ".." + (openHi() ? "*" : Long.toString(hi));
		}
	}

	/** One decoded site. */
	private static final class Site {
		Instruction insn;
		boolean store;
		boolean longMode;
		String reg;
		long operand;
		Address base;
		int opcode;
	}

	private final Map<String, Integer> counts = new TreeMap<>();

	private void bump(String k) {
		counts.merge(k, 1, Integer::sum);
	}

	@Override
	protected void run() throws Exception {
		listing = currentProgram.getListing();
		mem = currentProgram.getMemory();
		is816 = currentProgram.getLanguageID().toString().contains("65816");
		String prog = currentProgram.getName();
		StringBuilder blocks = new StringBuilder();
		for (MemoryBlock b : mem.getBlocks()) {
			blocks.append(b.getName()).append(b.isInitialized() ? "+" : "-").append(' ');
		}
		println("IDR blocks " + prog + " " + blocks.toString().trim());
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction i = it.next();
			Site s = decode(i);
			if (s == null) {
				continue;
			}
			bump(s.store ? "stores.seen" : "reads.seen");
			if (s.base == null) {
				bump("skip.noBase");
				continue;
			}
			MemoryBlock b = mem.getBlock(s.base);
			if (b == null || !b.isInitialized() || b.isVolatile()) {
				bump("skip.notInitializedBlock");
				continue;
			}
			bump(s.store ? "stores" : "reads");
			try {
				evaluate(prog, s, b);
			}
			catch (Exception e) {
				bump("error");
				println("IDR error " + prog + " " + i.getMinAddress() + " " + e);
			}
		}
		StringBuilder sb = new StringBuilder("IDR summary " + prog);
		for (Map.Entry<String, Integer> e : counts.entrySet()) {
			sb.append(' ').append(e.getKey()).append('=').append(e.getValue());
		}
		println(sb.toString());
	}

	// ---------------------------------------------------------------- decoding

	private static int op(Instruction i) {
		try {
			return i.getByte(0) & 0xff;
		}
		catch (Exception e) {
			return -1;
		}
	}

	private static String mn(Instruction i) {
		return i.getMnemonicString().toUpperCase();
	}

	private Site decode(Instruction i) {
		int o = op(i);
		Site s = new Site();
		s.insn = i;
		s.opcode = o;
		try {
			if (i.getLength() == 3 && ABS_X_R.contains(o)) {
				s.reg = "X";
			}
			else if (i.getLength() == 3 && ABS_Y_R.contains(o)) {
				s.reg = "Y";
			}
			else if (i.getLength() == 3 && ABS_X_S.contains(o)) {
				s.reg = "X";
				s.store = true;
			}
			else if (i.getLength() == 3 && ABS_Y_S.contains(o)) {
				s.reg = "Y";
				s.store = true;
			}
			else if (is816 && i.getLength() == 4 && LONG_X_R.contains(o)) {
				s.reg = "X";
				s.longMode = true;
			}
			else if (is816 && i.getLength() == 4 && LONG_X_S.contains(o)) {
				s.reg = "X";
				s.longMode = true;
				s.store = true;
			}
			else {
				return null;
			}
			s.operand = (i.getByte(1) & 0xff) | (i.getByte(2) & 0xff) << 8;
			if (s.longMode) {
				s.operand |= (long) (i.getByte(3) & 0xff) << 16;
			}
		}
		catch (Exception e) {
			return null;
		}
		if (!is816) {
			s.base = addr(i.getMinAddress().getAddressSpace(), s.operand);
		}
		else if (s.longMode) {
			s.base = addr(currentProgram.getAddressFactory().getDefaultAddressSpace(), s.operand);
		}
		else {
			for (Reference r : i.getReferencesFrom()) {
				if (r.getReferenceType().isData() &&
					(r.getToAddress().getOffset() & 0xffff) == s.operand) {
					s.base = r.getToAddress();
					break;
				}
			}
		}
		return s;
	}

	private static Address addr(AddressSpace space, long off) {
		try {
			return space.getAddress(off);
		}
		catch (Exception e) {
			return null;
		}
	}

	private Address plus(Address a, long d) {
		try {
			return a.addNoWrap(d);
		}
		catch (Exception e) {
			return null;
		}
	}

	/** INSN / INSIDE / DATA_START / DATA_MID / DATA_TAIL / UNDEF / NONE, plus length for INSN. */
	private String kind(Address a) {
		if (a == null) {
			return "NONE";
		}
		Instruction in = listing.getInstructionContaining(a);
		if (in != null) {
			return in.getMinAddress().equals(a) ? "INSN" : "INSIDE";
		}
		Data d = listing.getDataContaining(a);
		if (d == null || !d.isDefined()) {
			return "UNDEF";
		}
		if (d.getMinAddress().equals(a)) {
			return "DATA_START";
		}
		return d.getMaxAddress().equals(a) ? "DATA_TAIL" : "DATA_MID";
	}

	private static boolean symptom(String k) {
		return k.equals("INSN") || k.equals("INSIDE") || k.equals("DATA_MID") ||
			k.equals("DATA_TAIL");
	}

	// ---------------------------------------------------------------- window

	private Instruction fallingInto(Instruction i) {
		if (i == null) {
			return null;
		}
		Instruction p = listing.getInstructionBefore(i.getMinAddress());
		if (p != null && i.getMinAddress().equals(p.getFallThrough())) {
			return p;
		}
		return null;
	}

	private static boolean condBranch(Instruction i) {
		return i.getFlowType().isConditional() && i.getFlowType().isJump();
	}

	private List<Reference> otherFlowsInto(Instruction i) {
		List<Reference> out = new ArrayList<>();
		for (Reference r : currentProgram.getReferenceManager()
				.getReferencesTo(i.getMinAddress())) {
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
				out.add(r);
			}
		}
		return out;
	}

	/** The unique way into i: {pred, taken?} or null (several ways, or none). */
	private Object[] pred(Instruction i, boolean ignoreOthers) {
		Instruction f = fallingInto(i);
		List<Reference> others = otherFlowsInto(i);
		if (f != null) {
			return (others.isEmpty() || ignoreOthers) ? new Object[] { f, false } : null;
		}
		if (others.size() == 1) {
			Instruction from = listing.getInstructionAt(others.get(0).getFromAddress());
			if (from != null && condBranch(from)) {
				return new Object[] { from, true };
			}
		}
		return null;
	}

	// ---------------------------------------------------------------- evaluation

	private String flat(String s) {
		return s.replace(' ', '_');
	}

	private void evaluate(String prog, Site s, MemoryBlock blk) {
		Instruction site = s.insn;
		// back window
		List<Instruction> win = new ArrayList<>();
		List<Boolean> via = new ArrayList<>();
		win.add(site);
		via.add(false);
		Instruction cur = site;
		for (int n = 0; n < BACK; n++) {
			Object[] p = pred(cur, false);
			if (p == null) {
				break;
			}
			win.add(0, (Instruction) p[0]);
			via.set(0, (Boolean) p[1]);
			via.add(0, false);
			cur = (Instruction) p[0];
		}
		// via.get(k) == edge INTO win[k] was the taken edge
		int siteIdx = win.size() - 1;
		cur = site;
		for (int n = 0; n < FWD; n++) {
			Address ft = cur.getFallThrough();
			Instruction nx = ft == null ? null : listing.getInstructionAt(ft);
			if (nx == null || !otherFlowsInto(nx).isEmpty()) {
				break;
			}
			win.add(nx);
			via.add(false);
			cur = nx;
		}
		St[] st = simulate(win);
		V idx = reg(st[siteIdx], s.reg);

		Rng g = guard(win, via, st, siteIdx, idx);
		String[] lres = loop(s);
		Rng l = lres[0] == null ? null : parseRng(lres[0]);
		Object[] f = null;
		if (!s.store) {
			f = family(s, win, st, siteIdx, idx);
		}

		String bk = kind(s.base);
		Address b1 = plus(s.base, 1);
		String b1k = kind(b1);
		String baseMn = "-";
		int baseLen = 0;
		Instruction atBase = listing.getInstructionContaining(s.base);
		if (atBase != null) {
			baseMn = mn(atBase);
			baseLen = atBase.getLength();
		}
		int stride = idx.scale();
		StringBuilder sb = new StringBuilder();
		sb.append("IDR ").append(prog).append(" at=").append(site.getMinAddress());
		sb.append(" rw=").append(s.store ? "S" : "R").append(" reg=").append(s.reg);
		sb.append(" insn=").append(flat(site.toString()));
		sb.append(" base=").append(Long.toHexString(s.base.getOffset()));
		sb.append(" stride=").append(stride).append(" tokoff=").append(idx.off());
		sb.append(" blk=").append(blk.getName());
		StringBuilder rs = new StringBuilder();
		for (Reference r : site.getReferencesFrom()) {
			if (r.getReferenceType().isData()) {
				if (rs.length() > 0) {
					rs.append(',');
				}
				rs.append(Long.toHexString(r.getToAddress().getOffset()));
			}
		}
		sb.append(" refs=").append(rs.length() == 0 ? "-" : rs.toString());
		sb.append(" bkind=").append(bk).append(" b1kind=").append(b1k);
		sb.append(" baseMn=").append(baseMn).append(" baseLen=").append(baseLen);
		boolean sym = symptom(bk);
		sb.append(" sym=").append(sym ? 1 : 0);
		sb.append(" tshape=").append(sym && !b1k.equals("INSN") && !b1k.equals("INSIDE") ? 1 : 0);
		StringBuilder cls = new StringBuilder();
		if (g != null) {
			cls.append('G');
			bump("class.G");
			rangeFields(sb, "G", g, s, null, 0);
		}
		if (l != null) {
			cls.append('L');
			bump("class.L");
			rangeFields(sb, "L", l, s, null, 0);
		}
		if (lres[1] != null) {
			sb.append(" Lunk=").append(lres[1]);
			bump("loopUnknown");
			bump("loopUnknown." + lres[1]);
		}
		if (lres[2] != null) {
			sb.append(" Lcall=1");
		}
		if (lres[3] != null && l != null) {
			sb.append(" Lw=").append(lres[3]);
			bump("class.Lweak");
		}
		if (f != null) {
			sb.append(" Fn=").append(f[0]);
			if (f[1] != null) {
				cls.append('F');
				bump("class.F");
				long[] se = (long[]) f[1];
				Address fs = plus(s.base, se[0] - s.base.getOffset());
				Address fe = plus(s.base, se[1] - s.base.getOffset());
				sb.append(" Flohi=").append(f[2]);
				sb.append(" Fstart=").append(Long.toHexString(se[0])).append(" Fend=")
					.append(Long.toHexString(se[1])).append(" Fat=").append(kind(fs));
				sb.append(" Feq=").append(f[3]);
				if (fe == null) {
					sb.append(" Fwarn=end");
				}
			}
			else if (f[3] != null) {
				sb.append(" Funsolved=").append(f[3]);
			}
		}
		sb.append(" cls=").append(cls.length() == 0 ? "-" : cls.toString());
		if (sym) {
			bump(s.store ? "sym.stores" : "sym.reads");
		}
		println(sb.toString());
	}

	private Rng parseRng(String t) {
		String[] p = t.split("\\.\\.");
		return new Rng(Long.parseLong(p[0]),
			p[1].equals("*") ? Long.MIN_VALUE : Long.parseLong(p[1]));
	}

	/** Adds Xstart/Xend/Xat fields for an R-unit range. */
	private void rangeFields(StringBuilder sb, String c, Rng r, Site s, Object unused, int u) {
		long start = s.base.getOffset() + r.lo();
		sb.append(' ').append(c).append('=').append(r.txt());
		sb.append(' ').append(c).append("start=").append(Long.toHexString(start));
		sb.append(' ').append(c).append("end=")
			.append(r.openHi() ? "*" : Long.toHexString(s.base.getOffset() + r.hi() + 1));
		sb.append(' ').append(c).append("at=").append(kind(plus(s.base, r.lo())));
	}

	// ---------------------------------------------------------------- token simulation

	private V fresh() {
		return new V(tokenCounter++, 1, 0);
	}

	private static V reg(St s, String r) {
		return r.equals("X") ? s.x : r.equals("Y") ? s.y : s.a;
	}

	private static Long immediate(Instruction i) {
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof Scalar sc) {
				return sc.getUnsignedValue();
			}
		}
		return null;
	}

	private St[] simulate(List<Instruction> win) {
		St[] out = new St[win.size()];
		V a = fresh();
		V x = fresh();
		V y = fresh();
		int carry = -1;
		for (int k = 0; k < win.size(); k++) {
			Instruction i = win.get(k);
			St s = new St();
			s.a = a;
			s.x = x;
			s.y = y;
			out[k] = s;
			String m = mn(i);
			boolean acc = i.getLength() == 1;
			int newCarry = -1;
			switch (m) {
				case "CLC" -> newCarry = 0;
				case "SEC" -> newCarry = 1;
				default -> {
				}
			}
			switch (m) {
				case "TAX" -> x = a;
				case "TAY" -> y = a;
				case "TXA" -> a = x;
				case "TYA" -> a = y;
				case "TXY" -> y = x;
				case "TYX" -> x = y;
				case "TSX", "PLX" -> x = fresh();
				case "PLY" -> y = fresh();
				case "ASL" -> {
					if (acc) {
						a = new V(a.tok, a.scale * 2, a.off * 2);
					}
				}
				case "LSR", "ROL", "ROR" -> {
					if (acc) {
						a = fresh();
					}
				}
				case "INX" -> x = new V(x.tok, x.scale, x.off + 1);
				case "DEX" -> x = new V(x.tok, x.scale, x.off - 1);
				case "INY" -> y = new V(y.tok, y.scale, y.off + 1);
				case "DEY" -> y = new V(y.tok, y.scale, y.off - 1);
				case "INC" -> {
					if (acc) {
						a = new V(a.tok, a.scale, a.off + 1);
					}
				}
				case "DEC" -> {
					if (acc) {
						a = new V(a.tok, a.scale, a.off - 1);
					}
				}
				case "ADC", "SBC" -> {
					Long imm = immediate(i);
					if (imm != null && ((m.equals("ADC") && carry == 0) ||
						(m.equals("SBC") && carry == 1))) {
						a = new V(a.tok, a.scale, a.off + (int) (m.equals("ADC") ? imm : -imm));
					}
					else {
						a = fresh();
					}
				}
				case "LDA", "AND", "ORA", "EOR", "PLA" -> a = fresh();
				case "LDX" -> x = fresh();
				case "LDY" -> y = fresh();
				case "JSR", "JSL" -> {
					a = fresh();
					x = fresh();
					y = fresh();
				}
				case "MVN", "MVP" -> {
					x = fresh();
					y = fresh();
					a = fresh();
				}
				default -> {
				}
			}
			carry = newCarry;
		}
		return out;
	}

	// ---------------------------------------------------------------- G: guards

	private Rng guard(List<Instruction> win, List<Boolean> via, St[] st, int siteIdx, V idx) {
		long tlo = 0;
		long thi = 255;
		boolean any = false;
		boolean hiSet = false;
		for (int j = siteIdx - 1; j >= 1; j--) {
			Instruction br = win.get(j);
			String bm = mn(br);
			if (!bm.equals("BCC") && !bm.equals("BCS")) {
				continue;
			}
			Instruction cmp = win.get(j - 1);
			int co = op(cmp);
			String creg = co == 0xc9 ? "A" : co == 0xe0 ? "X" : co == 0xc0 ? "Y" : null;
			if (creg == null) {
				continue;
			}
			Long imm = immediate(cmp);
			if (imm == null) {
				continue;
			}
			V cv = reg(st[j - 1], creg);
			if (cv.tok != idx.tok || cv.scale < 1) {
				continue;
			}
			boolean taken = via.get(j + 1);
			boolean less = bm.equals("BCC") ? taken : !taken; // reg < imm on this path
			if (less) {
				long hi = Math.floorDiv(imm - 1 - cv.off, (long) cv.scale);
				thi = Math.min(thi, hi);
				hiSet = true;
			}
			else {
				long lo = -Math.floorDiv(-(imm - cv.off), (long) cv.scale);
				tlo = Math.max(tlo, lo);
			}
			any = true;
		}
		if (!any) {
			return null;
		}
		long rlo = (long) idx.scale * tlo + idx.off;
		long rhi = hiSet ? (long) idx.scale * thi + idx.off : Long.MIN_VALUE;
		if (hiSet && rhi < rlo) {
			return null;
		}
		return new Rng(rlo, rhi);
	}

	// ---------------------------------------------------------------- L: loops
	//
	// Round 2 (grm-9nxj.41.2). The loop body is run through a small forward dataflow whose state
	// tracks A/X/Y as (token, scale, offset), a stack, and plain memory cells, starting from a
	// symbolic iteration-start value I of the index register. The read is proven when, at the
	// read, the index register is still I+d1 (restored through TXA/PHA..PLA/TAX, STX cell..LDX
	// cell, PHX/PLX, a callee that never writes it, ...) and at the back edge it is I+d_e with
	// d_e = +-1; the closing branch's flag source then pins the range. Anything else is an Lunk
	// with a reason (regWrite.<cause>, nested..., flagSrc.<mnemonic>, ...), never a guess.

	private static boolean writesReg(Instruction i, String r) {
		String m = mn(i);
		if (m.equals("MVN") || m.equals("MVP")) {
			return true;
		}
		if (r.equals("X")) {
			return m.equals("LDX") || m.equals("TAX") || m.equals("TSX") || m.equals("PLX") ||
				m.equals("TYX") || m.equals("INX") || m.equals("DEX");
		}
		return m.equals("LDY") || m.equals("TAY") || m.equals("PLY") || m.equals("TXY") ||
			m.equals("INY") || m.equals("DEY");
	}

	private static final V OPAQUE = new V(-1, 1, 0);

	private final Map<Integer, String> why = new HashMap<>();

	private V freshW(String cause) {
		V v = fresh();
		why.put(v.tok(), cause);
		return v;
	}

	/** Loop-body dataflow state. */
	private static final class LS {
		V a;
		V x;
		V y;
		int carry = -1;
		boolean stackBad;
		List<V> stack = new ArrayList<>();
		Map<Long, V> cells = new HashMap<>();

		LS copy() {
			LS c = new LS();
			c.a = a;
			c.x = x;
			c.y = y;
			c.carry = carry;
			c.stackBad = stackBad;
			c.stack = new ArrayList<>(stack);
			c.cells = new HashMap<>(cells);
			return c;
		}
	}

	private V mv(V u, V v) {
		return u.equals(v) ? u : freshW("merge");
	}

	private LS merge(LS p, LS q) {
		LS m = new LS();
		m.a = mv(p.a, q.a);
		m.x = mv(p.x, q.x);
		m.y = mv(p.y, q.y);
		m.carry = p.carry == q.carry ? p.carry : -1;
		m.stackBad = p.stackBad || q.stackBad || p.stack.size() != q.stack.size();
		if (!m.stackBad) {
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

	private static boolean indirect(Instruction i) {
		if (i.getNumOperands() == 0) {
			return false;
		}
		String r = i.getDefaultOperandRepresentation(0);
		return r.contains("(") || r.contains("[");
	}

	private static boolean hasIndexReg(Instruction i) {
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof ghidra.program.model.lang.Register) {
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

	private static final Set<String> MEM_WRITE =
		Set.of("STA", "STX", "STY", "STZ", "INC", "DEC", "ASL", "LSR", "ROL", "ROR", "TSB",
			"TRB");

	/** Whether i writes memory (accumulator-form RMW excluded). */
	private static boolean writesMem(Instruction i) {
		String m = mn(i);
		if (!MEM_WRITE.contains(m)) {
			return false;
		}
		return !(i.getLength() == 1);
	}

	private void clearRange(LS s, Instruction i) {
		if (is816 || indirect(i)) {
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

	/** Result of what a callee (and what it calls) may disturb. */
	private static final class Summ {
		boolean wX;
		boolean wY;
		boolean unknown;
		boolean unknownWrite;
		boolean unbalanced;
		int net;
		Set<Long> cells = new java.util.HashSet<>();
	}

	private final Map<Address, Summ> summCache = new HashMap<>();
	private boolean callRelied;

	private Summ summarize(Address entry, int depth) {
		Summ c = summCache.get(entry);
		if (c != null) {
			return c;
		}
		Summ s = new Summ();
		s.unknown = true; // a recursive re-entry sees the conservative answer
		summCache.put(entry, s);
		boolean unk = false;
		java.util.Set<Address> seen = new java.util.HashSet<>();
		java.util.ArrayDeque<Address> work = new java.util.ArrayDeque<>();
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
			String m = mn(i);
			if (writesReg(i, "X")) {
				s.wX = true;
			}
			if (writesReg(i, "Y")) {
				s.wY = true;
			}
			switch (m) {
				case "PHA", "PHX", "PHY", "PHP", "PEA", "PEI", "PER", "PHB", "PHD", "PHK" -> net++;
				case "PLA", "PLX", "PLY", "PLP", "PLB", "PLD" -> net--;
				case "TXS", "TCS" -> unk = true;
				case "RTI", "BRK" -> unk = true;
				default -> {
				}
			}
			if (writesMem(i)) {
				if (indirect(i) || hasIndexReg(i) || is816) {
					s.unknownWrite = true;
				}
				else {
					s.cells.add(operandBase(i));
				}
			}
			if (m.equals("MVN") || m.equals("MVP")) {
				s.unknownWrite = true;
			}
			if (i.getFlowType().isComputed()) {
				unk = true;
				break;
			}
			if (i.getFlowType().isCall()) {
				Address[] fl = i.getFlows();
				if (fl.length != 1 || depth >= 2) {
					unk = true;
					break;
				}
				Summ cs = summarize(fl[0], depth + 1);
				if (cs.unknown || cs.unbalanced) {
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
			Address ft = i.getFallThrough();
			if (ft != null) {
				work.add(ft);
			}
		}
		s.net = net;
		s.unbalanced = net != 0;
		s.unknown = unk || s.unbalanced;
		return s;
	}

	private V popV(LS s, String cause) {
		if (s.stack.isEmpty()) {
			return freshW(cause);
		}
		V v = s.stack.remove(s.stack.size() - 1);
		return v.tok() == -1 ? freshW(cause) : v;
	}

	private void step(LS s, Instruction i) {
		String m = mn(i);
		boolean acc = i.getLength() == 1;
		int newCarry = -1;
		switch (m) {
			case "CLC" -> newCarry = 0;
			case "SEC" -> newCarry = 1;
			default -> {
			}
		}
		Long cell = null;
		if (!is816 && !indirect(i) && !hasIndexReg(i) && i.getLength() >= 2 &&
			!(i.getNumOperands() > 0 && i.getDefaultOperandRepresentation(0).startsWith("#"))) {
			long b = operandBase(i);
			cell = b < 0 ? null : b;
		}
		if (writesMem(i) && !m.startsWith("ST")) {
			// read-modify-write: the cell no longer holds a tracked value
			if (cell != null) {
				s.cells.remove(cell);
			}
			else {
				clearRange(s, i);
			}
		}
		switch (m) {
			case "TAX" -> s.x = s.a;
			case "TAY" -> s.y = s.a;
			case "TXA" -> s.a = s.x;
			case "TYA" -> s.a = s.y;
			case "TXY" -> s.y = s.x;
			case "TYX" -> s.x = s.y;
			case "TSX" -> s.x = freshW("tsx");
			case "TXS", "TCS" -> s.stackBad = true;
			case "TSC", "XBA", "TDC" -> s.a = freshW("arith");
			case "ASL" -> {
				if (acc) {
					s.a = new V(s.a.tok(), s.a.scale() * 2, s.a.off() * 2);
				}
			}
			case "LSR", "ROL", "ROR" -> {
				if (acc) {
					s.a = freshW("arith");
				}
			}
			case "INX" -> s.x = new V(s.x.tok(), s.x.scale(), s.x.off() + 1);
			case "DEX" -> s.x = new V(s.x.tok(), s.x.scale(), s.x.off() - 1);
			case "INY" -> s.y = new V(s.y.tok(), s.y.scale(), s.y.off() + 1);
			case "DEY" -> s.y = new V(s.y.tok(), s.y.scale(), s.y.off() - 1);
			case "INC" -> {
				if (acc) {
					s.a = new V(s.a.tok(), s.a.scale(), s.a.off() + 1);
				}
			}
			case "DEC" -> {
				if (acc) {
					s.a = new V(s.a.tok(), s.a.scale(), s.a.off() - 1);
				}
			}
			case "ADC", "SBC" -> {
				Long imm = immediate(i);
				if (imm != null && ((m.equals("ADC") && s.carry == 0) ||
					(m.equals("SBC") && s.carry == 1))) {
					s.a = new V(s.a.tok(), s.a.scale(), s.a.off() + (int) (m.equals("ADC") ? imm : -imm));
				}
				else {
					s.a = freshW("arith");
				}
			}
			case "AND", "ORA", "EOR" -> s.a = freshW("arith");
			case "LDA" -> s.a = load(s, i, cell, "lda");
			case "LDX" -> s.x = load(s, i, cell, "ldx");
			case "LDY" -> s.y = load(s, i, cell, "ldy");
			case "STA" -> store(s, i, cell, s.a);
			case "STX" -> store(s, i, cell, s.x);
			case "STY" -> store(s, i, cell, s.y);
			case "STZ" -> store(s, i, cell, OPAQUE);
			case "PHA" -> s.stack.add(s.a);
			case "PHX" -> s.stack.add(s.x);
			case "PHY" -> s.stack.add(s.y);
			case "PHP", "PEA", "PEI", "PER", "PHB", "PHD", "PHK" -> s.stack.add(OPAQUE);
			case "PLA" -> s.a = popV(s, "pla");
			case "PLX" -> s.x = popV(s, "plx");
			case "PLY" -> s.y = popV(s, "ply");
			case "PLP", "PLB", "PLD" -> popV(s, "pl");
			case "MVN", "MVP" -> {
				s.a = freshW("block");
				s.x = freshW("block");
				s.y = freshW("block");
				s.cells.clear();
			}
			case "JSR", "JSL" -> {
				Address[] fl = i.getFlows();
				Summ sm = (fl.length == 1 && !i.getFlowType().isComputed())
						? summarize(fl[0], 0) : null;
				s.a = freshW("call");
				if (sm == null || sm.unknown) {
					s.x = freshW("call");
					s.y = freshW("call");
					s.cells.clear();
				}
				else {
					if (sm.wX) {
						s.x = freshW("call");
					}
					else {
						callRelied = true;
					}
					if (sm.wY) {
						s.y = freshW("call");
					}
					if (sm.unknownWrite) {
						s.cells.clear();
					}
					else {
						s.cells.keySet().removeAll(sm.cells);
					}
				}
			}
			default -> {
			}
		}
		if (writesMem(i) && m.startsWith("ST") && cell == null) {
			clearRange(s, i);
		}
		s.carry = newCarry;
	}

	private V load(LS s, Instruction i, Long cell, String cause) {
		if (cell != null) {
			V v = s.cells.get(cell);
			if (v == null) {
				v = freshW(cause + "Cell");
				s.cells.put(cell, v);
			}
			return v;
		}
		return freshW(cause);
	}

	private void store(LS s, Instruction i, Long cell, V v) {
		if (cell != null) {
			s.cells.put(cell, v);
		}
	}

	/** {range or null, unknown-reason or null, call-flag or null, weak-reason or null}. */
	private String[] loop(Site s) {
		why.clear();
		callRelied = false;
		Instruction rd = s.insn;
		Instruction cur = rd;
		Instruction closing = null;
		for (int n = 0; n < 64; n++) {
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
				if (fl.length == 1 && fl[0].getAddressSpace().equals(rd.getMinAddress().getAddressSpace()) &&
					fl[0].compareTo(rd.getMinAddress()) <= 0) {
					closing = cur;
					break;
				}
			}
		}
		if (closing == null) {
			return new String[] { null, null, null, null };
		}
		Instruction head = listing.getInstructionAt(closing.getFlows()[0]);
		if (head == null) {
			return unk("headNotInsn");
		}
		if (head.getFlowType().isTerminal()) {
			// a backward branch to a nearby RTS is a conditional return, not a loop
			return new String[] { null, null, null, null };
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
		int readIdx = idxOf.get(rd.getMinAddress());
		// every way in comes from inside the loop (the one outside entry is falling into the head);
		// a violation is reported only for loops that would otherwise have been proven
		boolean multi = false;
		for (int k = 0; k < n; k++) {
			Instruction bi = body.get(k);
			if (bi.getFlowType().isComputed() && !bi.getFlowType().isCall()) {
				return unk("indirectFlow");
			}
			for (Reference r : otherFlowsInto(bi)) {
				if (!idxOf.containsKey(r.getFromAddress())) {
					multi = true;
				}
			}
		}
		// inner loops (back edges other than the closing one) become black-box regions
		List<int[]> regs = new ArrayList<>();
		for (int k = 0; k < n - 1; k++) {
			Instruction bi = body.get(k);
			if (bi.getFlowType().isCall()) {
				continue;
			}
			for (Address f : bi.getFlows()) {
				Integer t = idxOf.get(f);
				if (t != null && t <= k) {
					regs.add(new int[] { t, k });
				}
			}
		}
		regs.sort((p, q) -> Integer.compare(p[0], q[0]));
		List<int[]> union = new ArrayList<>();
		for (int[] r : regs) {
			if (!union.isEmpty() && r[0] <= union.get(union.size() - 1)[1]) {
				int[] last = union.get(union.size() - 1);
				last[1] = Math.max(last[1], r[1]);
			}
			else {
				union.add(new int[] { r[0], r[1] });
			}
		}
		int[] regEnd = new int[n];
		java.util.Arrays.fill(regEnd, -1);
		for (int[] r : union) {
			if (readIdx >= r[0] && readIdx <= r[1]) {
				return unk("nested.containsRead");
			}
			regEnd[r[0]] = r[1];
		}
		boolean hasInner = !union.isEmpty();
		// dataflow
		String r = s.reg;
		V tokI = freshW("iter");
		LS entry = new LS();
		entry.a = freshW("entry");
		V tokJ = freshW("iter2");
		entry.x = r.equals("X") ? tokI : tokJ;
		entry.y = r.equals("Y") ? tokI : tokJ;
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
		String pfx = hasInner ? "nested." : "";
		if (readState == null) {
			return unk(pfx + "readUnreached");
		}
		if (closeState == null) {
			return unk(pfx + "noBackEdge");
		}
		V rx = r.equals("X") ? readState.x : readState.y;
		if (rx.tok() != tokI.tok()) {
			return unk(pfx + "regWrite." + why.getOrDefault(rx.tok(), "?"));
		}
		if (rx.scale() != 1) {
			return unk(pfx + "regWrite.scaled");
		}
		V cx = r.equals("X") ? closeState.x : closeState.y;
		if (cx.tok() != tokI.tok()) {
			return unk(pfx + "regWrite.backedge." + why.getOrDefault(cx.tok(), "?"));
		}
		if (cx.scale() != 1) {
			return unk(pfx + "regWrite.scaled");
		}
		int d1 = rx.off();
		int de = cx.off();
		if (de == 0) {
			return unk(pfx + "noStep");
		}
		if (Math.abs(de) > 8) {
			return unk(pfx + "stepN");
		}
		// closing branch + flag source
		if (!otherFlowsInto(closing).isEmpty()) {
			return unk(pfx + "closeJoin");
		}
		String cb = mn(closing);
		Instruction pi = n >= 2 ? body.get(n - 2) : null;
		if (pi == null) {
			return unk(pfx + "closeNoFlag");
		}
		String pm = mn(pi);
		String tested;
		boolean flagReg = pm.equals("INX") || pm.equals("DEX") || pm.equals("INY") ||
			pm.equals("DEY");
		boolean cmp = pm.equals("CPX") || pm.equals("CPY");
		if (flagReg) {
			tested = pm.endsWith("X") ? "X" : "Y";
		}
		else if (cmp) {
			tested = pm.endsWith("X") ? "X" : "Y";
		}
		else {
			return unk(pfx + "flagSrc." + pm);
		}
		boolean cmpImm = cmp && immediateForm(pi);
		Long mm = cmpImm ? immediate(pi) : null;
		if (cmpImm && mm == null) {
			return unk(pfx + "cmpNoImm");
		}
		boolean lock = !tested.equals(r);
		int dT = de;
		if (lock) {
			String other = tested;
			V ox = other.equals("X") ? closeState.x : closeState.y;
			if (ox.tok() != tokJ.tok() || ox.scale() != 1) {
				return unk(pfx + "lockstep.otherRegWrite");
			}
			dT = ox.off();
			if (dT == 0) {
				return unk(pfx + "lockstep.noStep");
			}
		}
		int sk = Math.abs(dT);
		if (sk > 8) {
			return unk(pfx + "stepN");
		}
		Long initT = initValue(head, tested);
		Long init = lock ? initValue(head, r) : initT;
		if (lock && (init == null || initT == null)) {
			return unk(pfx + "lockstep.initUnknown");
		}
		if (!lock && (de != 1 && de != -1) && init == null) {
			return unk(pfx + "stepN");
		}
		long[] tr = testedRange(cb, flagReg, cmpImm, cmp, mm, dT, sk, initT);
		if (tr == null || tr.length == 1) {
			return unk(pfx + (tr == null ? "closeBranch." + cb + "." + pm : "unprovable"));
		}
		String weak = tr[2] == 1 ? "limit" : null;
		long lo = tr[0];
		long hi = tr[1];
		if (initT == null && weak == null) {
			weak = "init";
		}
		if (lock) {
			if (hi == Long.MIN_VALUE || (cb.equals("BPL")) || weak != null) {
				return unk(pfx + "lockstep.inexact");
			}
			long cnt = (hi - lo) / sk + 1;
			long a = init;
			long b = init + (cnt - 1) * de;
			lo = Math.min(a, b);
			hi = Math.max(a, b);
		}
		long rlo = lo + d1;
		long rhi = hi == Long.MIN_VALUE ? Long.MIN_VALUE : hi + d1;
		if (rhi != Long.MIN_VALUE && rhi < rlo) {
			return unk(pfx + "emptyRange");
		}
		if (multi) {
			return unk("multiEntry");
		}
		return new String[] { new Rng(rlo, rhi).txt(), null, callRelied ? "1" : null,
			weak == null ? (lock ? "lockstep" : null) : weak };
	}

	/**
	 * The values the tested register takes at the loop body's executed iterations, as
	 * {lo, hi, weak}; hi == Long.MIN_VALUE when open. null when the branch/flag pair is not a
	 * modelled loop test; {0} for a modelled test whose arithmetic does not close (wraps).
	 */
	private long[] testedRange(String cb, boolean flagReg, boolean cmpImm, boolean cmpMem, Long m,
			int dT, int k, Long init) {
		long open = Long.MIN_VALUE;
		if (flagReg) {
			if (dT < 0 && cb.equals("BNE")) {
				if (init != null && (init < k || init % k != 0)) {
					return new long[] { 0 };
				}
				return new long[] { k, init == null ? open : init, 0 };
			}
			if (dT < 0 && cb.equals("BPL")) {
				if (init != null && init < 0) {
					return new long[] { 0 };
				}
				return new long[] { init == null ? 0 : init % k, init == null ? open : init, 0 };
			}
			if (dT > 0 && cb.equals("BNE")) {
				if (init == null || (256 - init) % k != 0) {
					return new long[] { 0 };
				}
				return new long[] { init, 256 - k, 0 };
			}
			return null;
		}
		if (cmpImm) {
			if (dT > 0 && (cb.equals("BNE") || cb.equals("BCC"))) {
				if (init == null || init >= m) {
					return new long[] { 0 };
				}
				if (cb.equals("BNE")) {
					if ((m - init) % k != 0) {
						return new long[] { 0 };
					}
					return new long[] { init, m - k, 0 };
				}
				return new long[] { init, init + ((m - 1 - init) / k) * k, 0 };
			}
			if (dT < 0 && cb.equals("BNE")) {
				if (init != null && (init <= m || (init - m) % k != 0)) {
					return new long[] { 0 };
				}
				return new long[] { m + k, init == null ? open : init, 0 };
			}
			if (dT < 0 && cb.equals("BCS")) {
				if (init != null && init < m) {
					return new long[] { 0 };
				}
				return new long[] { init == null ? m : init - ((init - m) / k) * k,
					init == null ? open : init, 0 };
			}
			return null;
		}
		if (cmpMem && dT > 0 && (cb.equals("BNE") || cb.equals("BCC"))) {
			if (init == null) {
				return new long[] { 0 };
			}
			return new long[] { init, open, 1 };
		}
		return null;
	}

	private static boolean immediateForm(Instruction cmp) {
		int o = op(cmp);
		return o == 0xe0 || o == 0xc0;
	}

	private void push(LS[] in, int t, LS st, int n) {
		if (t >= n) {
			return;
		}
		in[t] = in[t] == null ? st.copy() : merge(in[t], st);
	}

	/** Effect of an inner-loop region (indices k..end) that does not contain the read. */
	private LS blackBox(LS m, List<Instruction> body, int k, int end) {
		LS o = m.copy();
		o.a = freshW("innerLoop");
		o.carry = -1;
		int net = 0;
		for (int j = k; j <= end; j++) {
			Instruction i = body.get(j);
			String mm = mn(i);
			if (writesReg(i, "X")) {
				o.x = freshW("innerLoop");
			}
			if (writesReg(i, "Y")) {
				o.y = freshW("innerLoop");
			}
			switch (mm) {
				case "PHA", "PHX", "PHY", "PHP", "PEA", "PEI", "PER", "PHB", "PHD", "PHK" -> net++;
				case "PLA", "PLX", "PLY", "PLP", "PLB", "PLD" -> net--;
				case "TXS", "TCS" -> o.stackBad = true;
				default -> {
				}
			}
			if (writesMem(i)) {
				if (!is816 && !indirect(i) && !hasIndexReg(i) && operandBase(i) >= 0) {
					o.cells.remove(operandBase(i));
				}
				else {
					clearRange(o, i);
				}
			}
			if (i.getFlowType().isCall()) {
				Address[] fl = i.getFlows();
				Summ sm = (fl.length == 1 && !i.getFlowType().isComputed())
						? summarize(fl[0], 0) : null;
				if (sm == null || sm.unknown) {
					o.x = freshW("innerLoop");
					o.y = freshW("innerLoop");
					o.cells.clear();
				}
				else {
					if (sm.wX) {
						o.x = freshW("innerLoop");
					}
					if (sm.wY) {
						o.y = freshW("innerLoop");
					}
					if (sm.unknownWrite) {
						o.cells.clear();
					}
					else {
						o.cells.keySet().removeAll(sm.cells);
					}
				}
			}
			if (mm.equals("MVN") || mm.equals("MVP")) {
				o.cells.clear();
			}
		}
		if (net != 0) {
			o.stackBad = true;
		}
		return o;
	}

	private String[] unk(String why2) {
		return new String[] { null, why2, null, null };
	}

	/** Immediate loaded into reg just before the loop head (LDX #n, or TAX after LDA #n). */
	private Long initValue(Instruction head, String r) {
		Instruction p = fallingInto(head);
		for (int n = 0; n < 12 && p != null; n++) {
			String m = mn(p);
			int o = op(p);
			if ((r.equals("X") && o == 0xa2) || (r.equals("Y") && o == 0xa0)) {
				return immediate(p);
			}
			if ((r.equals("X") && m.equals("TAX")) || (r.equals("Y") && m.equals("TAY"))) {
				Instruction q = fallingInto(p);
				for (int k = 0; k < 6 && q != null; k++) {
					if (op(q) == 0xa9) {
						return immediate(q);
					}
					String qm = mn(q);
					if (qm.equals("LDA") || qm.equals("PLA") || qm.equals("TXA") ||
						qm.equals("TYA") || qm.equals("JSR") || qm.equals("JSL") ||
						qm.equals("ADC") || qm.equals("SBC") || qm.equals("AND") ||
						qm.equals("ORA") || qm.equals("EOR")) {
						return null;
					}
					q = pred2(q);
				}
				return null;
			}
			if (writesReg(p, r) || mn(p).equals("JSR") || mn(p).equals("JSL")) {
				return null;
			}
			p = pred2(p);
		}
		return null;
	}

	private Instruction pred2(Instruction i) {
		Object[] p = pred(i, false);
		return (p == null || (Boolean) p[1]) ? null : (Instruction) p[0];
	}

	// ---------------------------------------------------------------- F: family

	private static final class Member {
		long base;
		int stride;
		boolean site;
		long space;
	}

	private static final Set<String> READ_M =
		Set.of("LDA", "LDX", "LDY", "ADC", "SBC", "CMP", "AND", "ORA", "EOR");

	/** {memberCount, long[]{start,end} or null, "lo..hi" or null, eq text or unsolved text}. */
	private Object[] family(Site s, List<Instruction> win, St[] st, int siteIdx, V idx) {
		AddressSpace space = s.base.getAddressSpace();
		List<Member> raw = new ArrayList<>();
		for (int k = 0; k < win.size(); k++) {
			Instruction i = win.get(k);
			Site o = i == s.insn ? s : decode(i);
			if (o == null || o.store || o.base == null || !READ_M.contains(mn(i)) ||
				!o.base.getAddressSpace().equals(space)) {
				continue;
			}
			V v = reg(st[k], o.reg);
			if (v.tok != idx.tok || v.scale < 1) {
				continue;
			}
			Member mb = new Member();
			mb.base = o.base.getOffset() + v.off;
			mb.stride = v.scale;
			mb.site = k == siteIdx;
			raw.add(mb);
		}
		raw.sort((p, r) -> p.stride != r.stride ? Integer.compare(p.stride, r.stride)
				: Long.compare(p.base, r.base));
		List<Member> mems = new ArrayList<>();
		for (Member mb : raw) {
			Member last = mems.isEmpty() ? null : mems.get(mems.size() - 1);
			if (last != null && last.stride == mb.stride && mb.base - last.base < mb.stride) {
				last.site |= mb.site;
				continue;
			}
			mems.add(mb);
		}
		if (mems.size() < 2) {
			return new Object[] { mems.size(), null, null, null };
		}
		int[] maxH = new int[mems.size() * (MAX_LO + 1)];
		for (int mi = 0; mi < mems.size(); mi++) {
			Member m = mems.get(mi);
			for (int lo = 0; lo <= MAX_LO; lo++) {
				int h = lo;
				while (h < MAX_H) {
					boolean ok = true;
					for (int b = 0; b < m.stride && ok; b++) {
						long off = m.base + (long) m.stride * h + b;
						ok = okByte(space, off);
					}
					if (!ok) {
						break;
					}
					h++;
				}
				maxH[mi * (MAX_LO + 1) + lo] = h;
			}
		}
		record Cand(int lo, int h, List<String> kinds) {}
		List<Cand> cands = new ArrayList<>();
		for (int lo = 0; lo <= MAX_LO; lo++) {
			int hmax = MAX_H;
			for (int mi = 0; mi < mems.size(); mi++) {
				hmax = Math.min(hmax, maxH[mi * (MAX_LO + 1) + lo]);
			}
			for (int h = lo + 1; h <= hmax; h++) {
				if (overlap(mems, lo, h)) {
					break;
				}
				List<String> kinds = new ArrayList<>();
				for (int ai = 0; ai < mems.size(); ai++) {
					Member ma = mems.get(ai);
					long ea = ma.base + (long) ma.stride * h;
					for (int bi = 0; bi < mems.size(); bi++) {
						if (bi != ai && ea == mems.get(bi).base + (long) mems.get(bi).stride * lo) {
							kinds.add(String.format("%04x>%04x", ma.base, mems.get(bi).base));
						}
					}
					Address ad = addr(space, ea);
					if (ad != null && listing.getInstructionAt(ad) != null) {
						kinds.add(String.format("%04x>code", ma.base));
					}
				}
				if (!kinds.isEmpty()) {
					cands.add(new Cand(lo, h, kinds));
				}
			}
		}
		int best = 0;
		for (Cand c : cands) {
			best = Math.max(best, c.kinds.size());
		}
		List<Cand> top = new ArrayList<>();
		for (Cand c : cands) {
			if (c.kinds.size() == best) {
				top.add(c);
			}
		}
		if (best >= 2 && top.size() == 1) {
			Cand c = top.get(0);
			Member sm = null;
			for (Member m : mems) {
				if (m.site) {
					sm = m;
				}
			}
			if (sm == null) {
				return new Object[] { mems.size(), null, null, "nosite" };
			}
			long start = sm.base + (long) sm.stride * c.lo;
			long end = sm.base + (long) sm.stride * c.h;
			return new Object[] { mems.size(), new long[] { start, end }, c.lo + ".." + (c.h - 1),
				String.join("+", c.kinds) };
		}
		String why = best >= 2 ? "conflict" : best == 1 ? "1eq" : "none";
		return new Object[] { mems.size(), null, null, why };
	}

	private boolean okByte(AddressSpace space, long off) {
		Address ad = addr(space, off);
		if (ad == null) {
			return false;
		}
		MemoryBlock b = mem.getBlock(ad);
		return b != null && b.isInitialized() && !b.isVolatile() &&
			listing.getInstructionContaining(ad) == null;
	}

	private boolean overlap(List<Member> mems, int lo, int h) {
		for (int i = 0; i < mems.size(); i++) {
			Member a = mems.get(i);
			long s = a.base + (long) a.stride * lo;
			long e = a.base + (long) a.stride * h;
			for (int j = i + 1; j < mems.size(); j++) {
				Member b = mems.get(j);
				long s2 = b.base + (long) b.stride * lo;
				long e2 = b.base + (long) b.stride * h;
				if (s < e2 && s2 < e) {
					return true;
				}
			}
		}
		return false;
	}
}
