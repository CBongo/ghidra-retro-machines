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
//   L  loop:   the read sits in a loop closed by a backward conditional branch; the index register
//              is set by LDX/LDY #n (or TAX/TAY after LDA #n) just before the loop head and stepped
//              once per iteration by DEX/DEY+BNE ([1,n]) / +BPL ([0,n]), or INX/INY+CPX/CPY #m
//              +BNE|BCC ([n,m-1]) / INX|INY+BNE ([n,255]); the read precedes the step. Any other
//              loop shape is counted as `Lunk=<reason>`, never guessed.
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

	private static boolean writesReg(Instruction i, String r) {
		String m = mn(i);
		if (r.equals("X")) {
			return m.equals("LDX") || m.equals("TAX") || m.equals("TSX") || m.equals("PLX") ||
				m.equals("TYX") || m.equals("INX") || m.equals("DEX");
		}
		return m.equals("LDY") || m.equals("TAY") || m.equals("PLY") || m.equals("TXY") ||
			m.equals("INY") || m.equals("DEY");
	}

	/** {range or null, unknown-reason or null, call-flag or null}. */
	private String[] loop(Site s) {
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
			return new String[] { null, null, null };
		}
		Instruction head = listing.getInstructionAt(closing.getFlows()[0]);
		if (head == null) {
			return unk("headNotInsn");
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
		boolean call = false;
		int stepAt = -1;
		int readAt = -1;
		for (int k = 0; k < body.size(); k++) {
			Instruction i = body.get(k);
			String m = mn(i);
			if (i.equals(rd)) {
				readAt = k;
			}
			if (m.equals("JSR") || m.equals("JSL")) {
				call = true;
			}
			if (i != closing && condBranch(i)) {
				Address[] fl = i.getFlows();
				if (fl.length == 1 && fl[0].compareTo(i.getMinAddress()) <= 0) {
					return unk("nested");
				}
			}
			if (writesReg(i, s.reg)) {
				if ((m.equals("INX") || m.equals("DEX") || m.equals("INY") || m.equals("DEY")) &&
					stepAt < 0) {
					stepAt = k;
				}
				else {
					return unk("regWrite");
				}
			}
		}
		if (call) {
			return unkCall("callInBody");
		}
		if (stepAt < 0) {
			return unk("noStep");
		}
		if (readAt < 0 || readAt > stepAt) {
			return unk("readAfterStep");
		}
		String stepM = mn(body.get(stepAt));
		String cb = mn(closing);
		boolean down = stepM.startsWith("DE");
		Long m = null;
		int branchAt = body.size() - 1;
		if (down) {
			if (branchAt != stepAt + 1) {
				return unk("downNotAdjacent");
			}
		}
		else if (branchAt == stepAt + 2) {
			Instruction cmp = body.get(stepAt + 1);
			int co = op(cmp);
			if (co != (s.reg.equals("X") ? 0xe0 : 0xc0)) {
				return unk("upCmpShape");
			}
			m = immediate(cmp);
			if (m == null) {
				return unk("upCmpShape");
			}
		}
		else if (branchAt != stepAt + 1) {
			return unk("upNotAdjacent");
		}
		// initialisation before the head
		Long n = initValue(head, s.reg);
		if (n == null) {
			return unk("initUnknown");
		}
		Rng r;
		if (down) {
			if (n < 1) {
				return unk("initZero");
			}
			if (cb.equals("BNE")) {
				r = new Rng(1, n);
			}
			else if (cb.equals("BPL")) {
				r = new Rng(0, n);
			}
			else {
				return unk("downBranch" + cb);
			}
		}
		else if (m != null) {
			if (!(cb.equals("BNE") || cb.equals("BCC")) || n >= m) {
				return unk("upBranch" + cb);
			}
			r = new Rng(n, m - 1);
		}
		else {
			if (!cb.equals("BNE")) {
				return unk("upBranch" + cb);
			}
			r = new Rng(n, 255);
		}
		return new String[] { r.txt(), null, null };
	}

	private String[] unk(String why) {
		return new String[] { null, why, null };
	}

	private String[] unkCall(String why) {
		return new String[] { null, why, "1" };
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
