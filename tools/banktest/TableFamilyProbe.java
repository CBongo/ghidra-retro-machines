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
// Same-index table-family survey (bead grm-gipk.41.1, answers grm-gipk.39). Run as
// REALROM_EXTRA_POSTSCRIPT=TableFamilyProbe.java. Read-only.
//
// For every pointer quad (LDA lo,r / STA P / LDA hi,r / STA P+1, either order, interleaved or
// planar) that leads to a JMP (P) (inline within 16 fall-through/JMP steps, or the stub form: the
// instruction after the quad is a JSR/JMP to a JMP (P) stub), it walks back up to 24
// fall-through predecessors, tracks each of A/X/Y as (token, scale, offset) -- scale doubles on
// ASL A, offset moves on INX/DEX/INY/DEY and CLC+ADC# / SEC+SBC# -- and collects every non-store
// abs,X / abs,Y read whose index register carries the SAME token as the quad's index register:
// the "same-index family". A member is base+offset at stride = scale. Members of equal stride
// whose bases are closer than the stride are fields of one record array and are merged.
//
// Then, for candidate live ranges [lo, H=hi+1) it tests DISJOINTNESS (no member extent
// [B+s*lo, B+s*H) overlaps another or any decoded instruction, all inside initialized memory) and
// counts TILING equations (member end == another member's start; member end == a decoded
// instruction's start). Two equations that agree pin (lo, H). Prints one TFAM line per site and a
// TFAMBANK line per per-entry bank/byte table (LDX/LDY abs,idx member, strict grm-gipk.36 shape
// flagged) saying where it sits relative to the pointer table.
//
// Independent of production (does not call retromachines.*), per ProbeSupport's rule.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class TableFamilyProbe extends GhidraScript {

	private static final int BACK_LIMIT = 24;
	private static final int FORWARD_LIMIT = 16;
	private static final int MAX_LO = 6;
	private static final int MAX_H = 256;

	private Listing listing;
	private Memory mem;
	private int tokenCounter = 1;

	private record V(int tok, int scale, int off) {}

	/** An indexed read: instruction, mnemonic, base operand, index reg, state before it. */
	private static final class Member {
		long base; // operand + offset
		long operand;
		int stride;
		int width = 1;
		boolean ptr;
		boolean fromLdxy;
		boolean strictBank;
		StringBuilder srcs = new StringBuilder();
	}

	private record Cand(int lo, int h, int eqs, String kinds) {}

	@Override
	protected void run() throws Exception {
		listing = currentProgram.getListing();
		mem = currentProgram.getMemory();
		String prog = currentProgram.getName();
		InstructionIterator it = listing.getInstructions(true);
		int sites = 0;
		while (it.hasNext()) {
			Instruction st2 = it.next();
			if (!isStoreCell(st2)) {
				continue;
			}
			Quad q = parseQuad(st2);
			if (q == null) {
				continue;
			}
			Instruction jmp = findJmp(st2, q.cell);
			if (jmp == null) {
				continue;
			}
			sites++;
			evaluate(prog, st2, q, jmp);
		}
		println("TFAMSUM " + prog + " sites=" + sites);
	}

	// ---------------------------------------------------------------- quad / site

	private record Quad(long cell, long lo, long hi, Instruction loLoad, Instruction first,
			Instruction second, boolean xIndex) {}

	private static int op(Instruction i) {
		if (i == null) {
			return -1;
		}
		try {
			return i.getByte(0) & 0xff;
		}
		catch (Exception e) {
			return -1;
		}
	}

	private Long operand16(Instruction i) {
		if (i == null || i.getLength() != 3) {
			return null;
		}
		try {
			return (long) ((i.getByte(1) & 0xff) | (i.getByte(2) & 0xff) << 8);
		}
		catch (Exception e) {
			return null;
		}
	}

	private Long storeCell(Instruction i) {
		int o = op(i);
		try {
			if (o == 0x85) {
				return (long) (i.getByte(1) & 0xff);
			}
			if (o == 0x8d) {
				return operand16(i);
			}
		}
		catch (Exception e) {
			return null;
		}
		return null;
	}

	private boolean isStoreCell(Instruction i) {
		return storeCell(i) != null;
	}

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

	private Instruction next(Instruction i) {
		Address ft = i.getFallThrough();
		return ft == null ? null : listing.getInstructionAt(ft);
	}

	private Quad parseQuad(Instruction st2) {
		Instruction ld2 = fallingInto(st2);
		Instruction st1 = fallingInto(ld2);
		Instruction ld1 = fallingInto(st1);
		if (ld1 == null) {
			return null;
		}
		int lop = op(ld1);
		if ((lop != 0xb9 && lop != 0xbd) || op(ld2) != lop) {
			return null;
		}
		Long c1 = storeCell(st1);
		Long c2 = storeCell(st2);
		Long t1 = operand16(ld1);
		Long t2 = operand16(ld2);
		if (c1 == null || c2 == null || t1 == null || t2 == null) {
			return null;
		}
		boolean x = lop == 0xbd;
		if (c1 + 1 == c2) {
			return t1.equals(t2) ? null : new Quad(c1, t1, t2, ld1, ld1, ld2, x);
		}
		if (c2 + 1 == c1) {
			return t1.equals(t2) ? null : new Quad(c2, t2, t1, ld2, ld1, ld2, x);
		}
		return null;
	}

	private boolean isJmpInd(Instruction i, long cell) {
		if (op(i) != 0x6c) {
			return false;
		}
		Long c = operand16(i);
		return c != null && c == cell;
	}

	/** The JMP (P) this quad feeds (inline within the forward limit, or via a stub call), or null. */
	private Instruction findJmp(Instruction st2, long cell) {
		Instruction cur = next(st2);
		for (int walked = 0; cur != null && walked <= FORWARD_LIMIT; walked++) {
			if (isJmpInd(cur, cell)) {
				return cur;
			}
			int o = op(cur);
			if (o == 0x4c || o == 0x20) {
				Address[] flows = cur.getFlows();
				if (flows.length != 1) {
					return null;
				}
				Instruction tgt = listing.getInstructionAt(flows[0]);
				if (tgt != null && isJmpInd(tgt, cell)) {
					return cur; // stub form: call/jump to the JMP (P) stub
				}
				if (o == 0x4c) {
					cur = tgt;
					continue;
				}
			}
			else if (o == 0x60 || o == 0x40 || o == 0x00) {
				return null;
			}
			cur = next(cur);
		}
		return null;
	}

	// ---------------------------------------------------------------- state tracking

	private V fresh() {
		return new V(tokenCounter++, 1, 0);
	}

	private static String mn(Instruction i) {
		return i.getMnemonicString().toUpperCase();
	}

	private String idxRegister(Instruction i) {
		if (i.getLength() != 3) {
			return null;
		}
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof Register r) {
				String n = r.getName().toUpperCase();
				if (n.equals("X") || n.equals("Y")) {
					return n;
				}
			}
		}
		return null;
	}

	private static Long plainCell(Instruction i) {
		Long cell = null;
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof Register) {
				return null;
			}
			if (o instanceof Address a) {
				if (cell != null) {
					return null;
				}
				cell = a.getOffset();
			}
		}
		return cell;
	}

	private long indexedOperand(Instruction i) {
		Long v = operand16(i);
		return v == null ? -1 : v;
	}

	private static final java.util.Set<String> READS = java.util.Set.of("LDA", "LDX", "LDY", "ADC",
		"SBC", "CMP", "AND", "ORA", "EOR");

	// ---------------------------------------------------------------- evaluation

	private void evaluate(String prog, Instruction st2, Quad q, Instruction jmp) throws Exception {
		curSpace = st2.getMinAddress().getAddressSpace();
		List<Instruction> win = new ArrayList<>();
		Instruction cur = q.first;
		win.add(cur);
		for (int n = 0; n < BACK_LIMIT; n++) {
			Instruction p = fallingInto(cur);
			if (p == null) {
				break;
			}
			win.add(0, p);
			cur = p;
		}
		// extend forward from the quad's first load through the second store
		Instruction fwd = q.first;
		while (!fwd.equals(st2)) {
			fwd = next(fwd);
			if (fwd == null) {
				return;
			}
			win.add(fwd);
		}
		// forward simulate to st2
		V a = fresh();
		V x = fresh();
		V y = fresh();
		List<V> stack = new ArrayList<>();
		Map<Long, V> cellTok = new HashMap<>();
		int carry = -1; // 0 clear, 1 set, -1 unknown
		V quadIdx = null;
		List<Object[]> reads = new ArrayList<>(); // {Instruction, V, String reg}
		for (Instruction i : win) {
			String m = mn(i);
			String reg = idxRegister(i);
			if (i.equals(q.first)) {
				quadIdx = q.xIndex ? x : y;
			}
			if (reg != null && READS.contains(m)) {
				reads.add(new Object[] { i, reg.equals("X") ? x : y, reg });
			}
			if (i.equals(st2)) {
				break;
			}
			int newCarry = -1;
			switch (m) {
				case "CLC" -> newCarry = 0;
				case "SEC" -> newCarry = 1;
				default -> {
				}
			}
			boolean idxd = reg != null;
			boolean acc = i.getLength() == 1;
			switch (m) {
				case "TAX" -> x = a;
				case "TAY" -> y = a;
				case "TXA" -> a = x;
				case "TYA" -> a = y;
				case "TSX" -> x = fresh();
				case "ASL" -> {
					if (acc) {
						a = new V(a.tok, a.scale * 2, a.off * 2);
					}
					else {
						clearCell(cellTok, i);
					}
				}
				case "LSR", "ROL", "ROR" -> {
					if (acc) {
						a = fresh();
					}
					else {
						clearCell(cellTok, i);
					}
				}
				case "INX" -> x = new V(x.tok, x.scale, x.off + 1);
				case "DEX" -> x = new V(x.tok, x.scale, x.off - 1);
				case "INY" -> y = new V(y.tok, y.scale, y.off + 1);
				case "DEY" -> y = new V(y.tok, y.scale, y.off - 1);
				case "ADC", "SBC" -> {
					Long imm = immediate(i);
					if (imm != null && ((m.equals("ADC") && carry == 0) ||
						(m.equals("SBC") && carry == 1))) {
						int d = (int) (m.equals("ADC") ? imm : -imm);
						a = new V(a.tok, a.scale, a.off + d);
					}
					else {
						a = fresh();
					}
				}
				case "LDA", "LDX", "LDY" -> {
					V v;
					Long cell = idxd ? null : plainCell(i);
					if (cell != null) {
						v = cellTok.computeIfAbsent(cell, k -> fresh());
					}
					else {
						v = fresh();
					}
					if (m.equals("LDA")) {
						a = v;
					}
					else if (m.equals("LDX")) {
						x = v;
					}
					else {
						y = v;
					}
				}
				case "AND", "ORA", "EOR" -> a = fresh();
				case "PLA" -> a = stack.isEmpty() ? fresh() : stack.remove(stack.size() - 1);
				case "PHA" -> stack.add(a);
				case "JSR" -> {
					a = fresh();
					x = fresh();
					y = fresh();
				}
				case "STA", "STX", "STY", "INC", "DEC" -> clearCell(cellTok, i);
				default -> {
				}
			}
			carry = newCarry;
		}
		if (quadIdx == null) {
			return;
		}
		// members
		List<Member> raw = new ArrayList<>();
		for (Object[] r : reads) {
			Instruction i = (Instruction) r[0];
			V v = (V) r[1];
			if (v.tok != quadIdx.tok || v.scale < 1) {
				continue;
			}
			Member mb = new Member();
			mb.operand = indexedOperand(i);
			mb.base = mb.operand + v.off;
			mb.stride = v.scale;
			mb.ptr = i.equals(q.first) || i.equals(q.second);
			String m = mn(i);
			mb.fromLdxy = m.equals("LDX") || m.equals("LDY");
			mb.srcs.append(m).append('@').append(i.getMinAddress());
			raw.add(mb);
		}
		boolean strict = strictBankShape(q);
		boolean interleaved = q.hi == q.lo + 1;
		// merge
		raw.sort((p, r) -> p.stride != r.stride ? Integer.compare(p.stride, r.stride)
				: Long.compare(p.base, r.base));
		List<Member> mems = new ArrayList<>();
		for (Member mb : raw) {
			Member last = mems.isEmpty() ? null : mems.get(mems.size() - 1);
			if (last != null && last.stride == mb.stride && (mb.base - last.base < mb.stride ||
				(interleaved && last.ptr && mb.ptr && mb.base - last.base == 1))) {
				last.width = (int) Math.max(last.width, mb.base - last.base + 1);
				last.ptr |= mb.ptr;
				last.fromLdxy |= mb.fromLdxy;
				if (mb.base != last.base || last.srcs.indexOf(mb.srcs.toString()) < 0) {
					last.srcs.append(',').append(mb.srcs);
				}
				continue;
			}
			mems.add(mb);
		}
		// pointer member: the one containing quad lo
		Member ptrM = null;
		for (Member mb : mems) {
			if (mb.ptr && (ptrM == null || mb.operand <= q.lo)) {
				if (q.lo >= mb.operand && q.lo < mb.operand + 4 || ptrM == null) {
					ptrM = mb;
				}
			}
		}
		// find member that contains lo operand: choose the one whose srcs include q.loLoad addr
		for (Member mb : mems) {
			if (mb.srcs.indexOf("@" + q.loLoad.getMinAddress()) >= 0) {
				ptrM = mb;
			}
		}
		// solve
		List<Cand> cands = new ArrayList<>();
		for (int lo = 0; lo <= MAX_LO; lo++) {
			for (int h = lo + 1; h <= MAX_H; h++) {
				String bad = invalid(mems, lo, h);
				if (bad != null) {
					break;
				}
				List<String> kinds = new ArrayList<>();
				for (int ai = 0; ai < mems.size(); ai++) {
					Member ma = mems.get(ai);
					long ea = ma.base + (long) ma.stride * h;
					for (int bi = 0; bi < mems.size(); bi++) {
						if (bi == ai) {
							continue;
						}
						Member mb = mems.get(bi);
						if (ea == mb.base + (long) mb.stride * lo) {
							kinds.add(label(ma) + ">" + label(mb));
						}
					}
					if (codeStart(ea)) {
						kinds.add(label(ma) + ">code");
					}
					else if (xrefTarget(ea)) {
						kinds.add(label(ma) + ">xref");
					}
				}
				if (!kinds.isEmpty()) {
					cands.add(new Cand(lo, h, kinds.size(), String.join("+", kinds)));
				}
			}
		}
		int best = 0;
		for (Cand c : cands) {
			best = Math.max(best, c.eqs);
		}
		List<Cand> top = new ArrayList<>();
		for (Cand c : cands) {
			if (c.eqs == best) {
				top.add(c);
			}
		}
		String solved;
		String agree;
		Cand sol = null;
		String eqText;
		if (best >= 2 && top.size() == 1) {
			sol = top.get(0);
			solved = "lo=" + sol.lo + ",hi=" + (sol.h - 1);
			agree = "yes";
			eqText = sol.kinds;
		}
		else if (best >= 2) {
			StringBuilder sb = new StringBuilder("CONFLICT");
			for (int n = 0; n < Math.min(4, top.size()); n++) {
				sb.append(" (").append(top.get(n).lo).append(',').append(top.get(n).h - 1).append(')');
			}
			solved = sb.toString();
			agree = "no";
			eqText = top.get(0).kinds;
		}
		else if (best == 1) {
			StringBuilder sb = new StringBuilder("unsolved(1eq:");
			int shown = 0;
			for (Cand c : cands) {
				if (shown++ < 3) {
					sb.append(" lo").append(c.lo).append("/hi").append(c.h - 1).append('[')
						.append(c.kinds).append(']');
				}
			}
			if (cands.size() > 3) {
				sb.append(" +").append(cands.size() - 3);
			}
			solved = sb.append(')').toString();
			agree = "no";
			eqText = "1";
		}
		else {
			solved = "unsolved";
			agree = "no";
			eqText = "none";
		}
		// today's extent
		AddressSpace space = jmp.getMinAddress().getAddressSpace();
		String today = "none";
		long tN = -1;
		Address loAddr = addr(space, q.lo);
		String eol = listing.getComment(CommentType.EOL, jmp.getMinAddress());
		Instruction siteCall = jmp;
		String eolCall = eol;
		if (eolCall == null || !eolCall.contains("split dispatch")) {
			// the comment is on the call (stub form) -- jmp may be the call already
			eolCall = null;
		}
		if (eolCall != null && loAddr != null) {
			Matcher mt = Pattern.compile("split dispatch: (\\d+)-entry table at (\\S+)")
					.matcher(eolCall);
			while (mt.find()) {
				if (mt.group(2).equals(loAddr.toString())) {
					tN = Long.parseLong(mt.group(1));
				}
			}
		}
		if (tN >= 0) {
			today = tN + "-entries";
		}
		else {
			int refs = 0;
			for (Reference rf : siteCall.getReferencesFrom()) {
				if (rf.getReferenceType().isComputed()) {
					refs++;
				}
			}
			Instruction stubJmp = jmp;
			if (op(jmp) != 0x6c) {
				Address[] fl = jmp.getFlows();
				stubJmp = fl.length == 1 ? listing.getInstructionAt(fl[0]) : null;
			}
			int stubRefs = 0;
			if (stubJmp != null) {
				for (Reference rf : stubJmp.getReferencesFrom()) {
					if (rf.getReferenceType().isComputed()) {
						stubRefs++;
					}
				}
			}
			today = (refs + stubRefs > 0) ? "refs-only(" + Math.max(refs, stubRefs) + ")" : "none";
		}
		String verdict = verdict(sol, ptrM, q, tN, best, today);
		// pointer plausibility at solved range
		String ptrChk = "";
		if (sol != null && ptrM != null) {
			ptrChk = " ptrBad=" + badPointers(q, interleaved, ptrM, sol, space);
		}
		StringBuilder ms = new StringBuilder();
		for (Member mb : mems) {
			ms.append(String.format("$%04x:s%dw%d%s ", mb.base, mb.stride, mb.width,
				mb.ptr ? "(ptr)" : ""));
		}
		String form = op(jmp) == 0x6c ? "inline" : "stub";
		println("TFAM " + prog + " site=" + jmp.getMinAddress() + " quad=" + st2.getMinAddress() +
			" form=" + form + " idx=" + (q.xIndex ? "X" : "Y") + (interleaved ? " interleaved" : " planar") +
			" members=[" + ms.toString().trim() + "] eqs=" + eqText + " solved=" + solved +
			" agree=" + agree + " today=" + today + ptrChk + " verdict=" + verdict);
		// bank tables
		for (Member mb : mems) {
			if (!mb.fromLdxy) {
				continue;
			}
			String place = placement(mb, ptrM, sol, tN, q);
			println("TFAMBANK " + prog + " site=" + jmp.getMinAddress() + " bank=$" +
				String.format("%04x", mb.base) + " stride=" + mb.stride +
				" shape=" + (strict ? "grm36" : "ldxy-member") + " ptr=$" +
				(ptrM == null ? "?" : String.format("%04x", ptrM.base)) + " placement=" + place);
		}
	}

	private String label(Member m) {
		return String.format("%04x", m.base);
	}

	private boolean strictBankShape(Quad q) {
		Instruction tay = fallingInto(q.first);
		Instruction asl = fallingInto(tay);
		Instruction tya = fallingInto(asl);
		Instruction ldx = fallingInto(tya);
		return op(tay) == 0xa8 && op(asl) == 0x0a && op(tya) == 0x98 && op(ldx) == 0xbe &&
			op(q.first) == 0xb9;
	}

	private Address addr(AddressSpace space, long off) {
		try {
			return space.getAddress(off);
		}
		catch (Exception e) {
			return null;
		}
	}

	private AddressSpace curSpace;

	/** An address in the space the site under evaluation executes in (overlay banks differ). */
	private Address defAddr(long off) {
		return addr(curSpace, off);
	}

	private boolean codeStart(long off) {
		Address a = defAddr(off);
		return a != null && listing.getInstructionAt(a) != null;
	}

	/** Undecoded address that something references (a handler Ghidra has not reached yet). */
	private boolean xrefTarget(long off) {
		Address a = defAddr(off);
		if (a == null || listing.getInstructionContaining(a) != null) {
			return false;
		}
		for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
			if (r.getReferenceType().isFlow()) {
				return true; // a jump/call/computed-flow target, not a data read
			}
		}
		return false;
	}

	/** Null when [lo,h) is a valid disjoint range for every member, else the reason. */
	private String invalid(List<Member> mems, int lo, int h) {
		for (int i = 0; i < mems.size(); i++) {
			Member a = mems.get(i);
			long s = a.base + (long) a.stride * lo;
			long e = a.base + (long) a.stride * h; // exclusive
			if (s < 0 || e > 0x10000) {
				return "range";
			}
			for (long o = s; o < e; o++) {
				Address ad = defAddr(o);
				if (ad == null) {
					return "addr";
				}
				MemoryBlock b = mem.getBlock(ad);
				if (b == null || !b.isInitialized() || b.isVolatile()) {
					return "mem";
				}
				if (listing.getInstructionContaining(ad) != null) {
					return "code";
				}
			}
			for (int j = i + 1; j < mems.size(); j++) {
				Member b = mems.get(j);
				long s2 = b.base + (long) b.stride * lo;
				long e2 = b.base + (long) b.stride * h;
				if (s < e2 && s2 < e) {
					return "overlap";
				}
			}
		}
		return null;
	}

	private String verdict(Cand sol, Member ptrM, Quad q, long tN, int best, String today) {
		if (best >= 2 && sol == null) {
			return "conflict";
		}
		if (sol == null) {
			return best == 1 ? "unsolved-1eq" : "unsolved";
		}
		if (ptrM == null) {
			return "solved-noptr";
		}
		if (tN < 0) {
			return "today-none";
		}
		long sp = ptrM.base + (long) ptrM.stride * sol.lo;
		long ep = ptrM.base + (long) ptrM.stride * sol.h;
		long ts = q.lo; // today's table base = quad lo operand
		long te = ts + tN * (q.hi == q.lo + 1 ? 2 : 1);
		List<String> v = new ArrayList<>();
		if (sp > ts) {
			v.add("would-skip-head");
		}
		if (sp < ts) {
			v.add("would-extend-head");
		}
		if (ep > te) {
			v.add("would-extend");
		}
		if (ep < te) {
			v.add("would-shorten");
		}
		return v.isEmpty() ? "agrees-with-today" : String.join("+", v);
	}

	private String badPointers(Quad q, boolean interleaved, Member ptrM, Cand sol,
			AddressSpace space) {
		List<String> bad = new ArrayList<>();
		long loBase = q.lo + (ptrM.base - ptrM.operand);
		long hiBase = q.hi + (ptrM.base - ptrM.operand);
		// recompute using the quad operands with the same offset as the lo member
		int step = interleaved && ptrM.stride == 1 ? 2 : 1;
		for (int i = sol.lo; i < sol.h; i += step) {
			try {
				long l = loBase + (long) ptrM.stride * i;
				long h = hiBase + (long) ptrM.stride * i;
				int lv = mem.getByte(addr(space, l)) & 0xff;
				int hv = mem.getByte(addr(space, h)) & 0xff;
				int v = lv | hv << 8;
				Address t = addr(space, v);
				MemoryBlock b = t == null ? null : mem.getBlock(t);
				boolean ok = b != null && b.isInitialized() && !b.isVolatile();
				if (ok) {
					Instruction in = listing.getInstructionContaining(t);
					if (in != null && !in.getMinAddress().equals(t)) {
						ok = false;
					}
				}
				if (!ok) {
					bad.add(i + ":$" + String.format("%04x", v));
				}
			}
			catch (Exception e) {
				bad.add(i + ":?");
			}
		}
		return bad.isEmpty() ? "0" : bad.size() + bad.toString().replace(" ", "");
	}

	private String placement(Member bank, Member ptrM, Cand sol, long tN, Quad q) {
		if (ptrM == null) {
			return "no-ptr-member";
		}
		long ps;
		long pe;
		String basis;
		if (sol != null) {
			ps = ptrM.base + (long) ptrM.stride * sol.lo;
			pe = ptrM.base + (long) ptrM.stride * sol.h;
			basis = "solved";
		}
		else if (tN >= 0) {
			ps = q.lo;
			pe = q.lo + tN * (q.hi == q.lo + 1 ? 2 : 1);
			basis = "today";
		}
		else {
			return "unknown-extent";
		}
		long n = (pe - ps) / ptrM.stride; // entries
		long bs = bank.base + (long) bank.stride * (sol != null ? sol.lo : 0);
		long be = bank.base + (long) bank.stride * (sol != null ? sol.h : n);
		String kind;
		if (be <= ps) {
			kind = "before gap=" + (ps - be);
		}
		else if (bs >= pe) {
			kind = "after gap=" + (bs - pe);
		}
		else {
			kind = "interleaved/overlap";
		}
		if (!kind.startsWith("interleaved") && Math.abs(be <= ps ? ps - be : bs - pe) > 256) {
			kind = "elsewhere(" + kind + ")";
		}
		return kind + " (" + basis + ")";
	}

	private static void clearCell(Map<Long, V> cellTok, Instruction i) {
		Long c = plainCell(i);
		if (c != null) {
			cellTok.remove(c);
		}
	}

	private static Long immediate(Instruction i) {
		for (Object o : i.getOpObjects(0)) {
			if (o instanceof ghidra.program.model.scalar.Scalar s) {
				return s.getUnsignedValue();
			}
		}
		return null;
	}
}
