// Narrow probe (grm-9nxj.32 survey): 65816 data-bank-register census.
//   Q1 DBR-setting idioms: every PLB classified by the source of the popped byte (PHK, LDA/LDX/LDY #imm
//      or PEA constant, PHB bracket, other register, stack underflow), plus MVN/MVP and any other writer.
//   Q2 absolute data operands (abs, abs,X, abs,Y; NOT long, NOT JMP/JSR/PEA) by the bank of their
//      existing memory reference (bank 0, own PBR, other, none), and (dp),Y / (dp,X) counts.
//   Q3 per-function: sets DBR before first absolute access vs relies on caller; callee classes
//      (no write / preserving / returns const / changes); call sites per class; and a measurement of what
//      an intraprocedural tracker (+ callee summaries) and an interprocedural entry seeding would resolve.
//   Q4 GRM_DBR_FUNCS=00ade4,00bb94,... dumps those functions: per instruction the DBR context value the
//      analyzer stamped (ctxDBR), the probe's own linear state (dbr), outgoing refs, every caller, and the
//      analyzer's call summary (W65816DataBankAnalyzer.CallSummaries) for the function and its callees.
//   Q5 abs operands under an analyzer-stamped DBR: how many carry a reference, how many to the DBR's
//      bank, where the targets land (instruction / defined data / undefined), samples, and every
//      reference whose target is an instruction ("DBR refToInstruction").
//   Q6 (grm-9nxj.42) "DBR loss": why abs operands still have no known DBR, by cause, with the root
//      causes behind unseeded entries traced upstream (W65816DataBankAnalyzer.Diagnostics); Q4's
//      dump adds the analyzer's own walk state per instruction ("DBR   walk") and takes any address.
// Run on snes-analysis with REALROM_EXTRA_POSTSCRIPT=DbrCensusProbe.java REALROM_WORK_DIR=<dir> (no
// dot-leading path element); output is the "DBR " lines of <dir>/<id>.log. Read-only.
// The scan is linear (address order) per function, not flow-sensitive: an estimate, not the analyzer.
//@category RetroMachines.Test

import java.util.*;
import java.util.regex.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

public class DbrCensusProbe extends GhidraScript {
	static final String ENTRY = "E", UNK = "?";
	static final Pattern ABS4 = Pattern.compile("(^|[^0-9a-fA-F#$])\\$[0-9a-fA-F]{4}($|[^0-9a-fA-F])");
	static final Set<String> NOT_DATA = new HashSet<>(Arrays.asList("JMP", "JML", "JSR", "JSL", "PEA", "PEI",
		"PER", "BRA", "BRL", "BEQ", "BNE", "BCC", "BCS", "BMI", "BPL", "BVC", "BVS", "MVN", "MVP"));

	static class Tag {
		String kind; Object val; String src;
		Tag(String k, Object v, String s) { kind = k; val = v; src = s; }
	}

	static class Fn {
		Function f; List<Instruction> ins = new ArrayList<>();
		Map<Address, Object> state = new HashMap<>();   // DBR state before each instruction
		Object exit = null;                              // summary: ENTRY / Integer / UNK / null (no return seen)
		boolean writes; int firstWrite = -1, firstAbs = -1;
		Set<Object> exits = new HashSet<>();
		Object seed = UNK;
	}

	/** One decoded width flag as stamped in the context: 0, 1, or - when unset (grm-9nxj.46). */
	static String flagOf(Instruction in, Register r) {
		java.math.BigInteger v = r == null ? null : in.getValue(r, false);
		return v == null ? "-" : v.toString();
	}

	Map<Address, Fn> fns = new LinkedHashMap<>();
	Map<String, Integer> plb = new TreeMap<>(), plbConst = new TreeMap<>(), other = new TreeMap<>();
	Map<String, List<String>> samples = new TreeMap<>();
	Register mf, xf, dbr;
	retromachines.W65816DataBankAnalyzer.CallSummaries sums;
	retromachines.W65816DataBankAnalyzer.Diagnostics diag;

	@Override
	protected void run() throws Exception {
		mf = currentProgram.getRegister("ctx_MF"); xf = currentProgram.getRegister("ctx_XF");
		dbr = currentProgram.getRegister("DBR");
		Listing l = currentProgram.getListing();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			Fn fn = new Fn(); fn.f = f;
			InstructionIterator it = l.getInstructions(f.getBody(), true);
			while (it.hasNext()) fn.ins.add(it.next());
			fns.put(f.getEntryPoint(), fn);
		}
		for (int round = 0; round < 3; round++) {
			plb.clear(); plbConst.clear(); other.clear(); samples.clear();
			for (Fn fn : fns.values()) simulate(fn);
		}
		println("DBR plbSources=" + plb);
		println("DBR plbConstBanks=" + plbConst);
		println("DBR otherDbrWriters=" + other);
		for (Map.Entry<String, List<String>> e : samples.entrySet())
			for (String s : e.getValue()) println("DBR sample " + e.getKey() + " " + s);
		operandCensus();
		functionCensus();
		// Q6 (grm-9nxj.42): why abs operands still have no known DBR, by cause, top callees, top
		// unseeded functions (the analyzer's own walk, W65816DataBankAnalyzer.Diagnostics).
		diag = new retromachines.W65816DataBankAnalyzer.Diagnostics(currentProgram);
		for (String line : diag.lossReport(25))
			println("DBR loss " + line);
		String sites = System.getenv("GRM_DBR_FUNCS");
		if (sites != null && !sites.isBlank()) for (String s : sites.split(",")) dumpFunc(s.trim());
	}

	Integer bankOf(Address a) { return (int) ((a.getOffset() >> 16) & 0xff); }

	boolean flag(Register r, Address a, boolean dflt) {
		RegisterValue v = currentProgram.getProgramContext().getRegisterValue(r, a);
		return v != null && v.hasValue() ? v.getUnsignedValue().intValue() != 0 : dflt;
	}

	boolean writesReg(Instruction in, int lo, int hi) {
		for (PcodeOp op : in.getPcode()) {
			Varnode o = op.getOutput();
			if (o != null && o.isRegister() && o.getAddress().getOffset() <= hi &&
				o.getAddress().getOffset() + o.getSize() > lo) return true;
		}
		return false;
	}

	/** Source of the value in the register occupying offsets lo..hi, scanning back from in. */
	Tag sourceOf(Instruction in, int lo, int hi, boolean wide, String kind) {
		Instruction p = in.getPrevious();
		for (int i = 0; i < 10 && p != null; i++, p = p.getPrevious()) {
			if (!writesReg(p, lo, hi)) continue;
			String m = p.getMnemonicString().toUpperCase();
			if ((m.equals("LDA") || m.equals("LDX") || m.equals("LDY")) &&
				p.getDefaultOperandRepresentation(0).startsWith("#")) {
				Scalar s = p.getScalar(0);
				if (s != null) return new Tag("C", (int) s.getUnsignedValue(), "imm:" + m + (wide ? "16" : "8"));
			}
			return new Tag(kind, null, m);
		}
		return new Tag(kind, null, "?far");
	}

	void simulate(Fn fn) {
		Object cur = ENTRY;
		Deque<Tag> st = new ArrayDeque<>();
		fn.exits.clear(); fn.writes = false; fn.firstWrite = -1; fn.firstAbs = -1;
		int idx = 0;
		for (Instruction in : fn.ins) {
			fn.state.put(in.getAddress(), cur);
			String m = in.getMnemonicString().toUpperCase();
			boolean M = flag(mf, in.getAddress(), true), X = flag(xf, in.getAddress(), true);
			if (isAbs(in) != null && fn.firstAbs < 0) fn.firstAbs = idx;
			switch (m) {
				case "PHK": st.push(new Tag("K", bankOf(in.getAddress()), null)); break;
				case "PHB": st.push(new Tag("B", cur, null)); break;
				case "PHA": pushReg(st, in, 0x10, 0x11, M, "A"); break;
				case "PHX": pushReg(st, in, 0x12, 0x13, X, "X"); break;
				case "PHY": pushReg(st, in, 0x14, 0x15, X, "Y"); break;
				case "PHD": st.push(new Tag("D", null, null)); st.push(new Tag("D", null, null)); break;
				case "PHP": st.push(new Tag("P", null, null)); break;
				case "PEI": case "PER": st.push(new Tag("?", null, m)); st.push(new Tag("?", null, m)); break;
				case "PEA": {
					Object[] oo = in.getOpObjects(0);
					int v = -1;
					if (oo.length > 0 && oo[0] instanceof Scalar) v = (int) ((Scalar) oo[0]).getUnsignedValue();
					else if (oo.length > 0 && oo[0] instanceof Address) v = (int) ((Address) oo[0]).getOffset();
					st.push(new Tag(v < 0 ? "?" : "C", v < 0 ? null : (v >> 8) & 0xff, "PEA"));
					st.push(new Tag(v < 0 ? "?" : "C", v < 0 ? null : v & 0xff, "PEA"));
					break;
				}
				case "PLA": pop(st, M ? 1 : 2); break;
				case "PLX": case "PLY": pop(st, X ? 1 : 2); break;
				case "PLD": pop(st, 2); break;
				case "PLP": pop(st, 1); break;
				case "TXS": case "TCS": st.clear(); break;
				case "PLB": {
					Tag t = st.isEmpty() ? new Tag("U", null, null) : st.pop();
					String cls; Object nv;
					if (t.kind.equals("B")) { cls = "PHB-bracket"; nv = t.val; }
					else if (t.kind.equals("K")) { cls = "PHK"; nv = t.val; }
					else if (t.kind.equals("C")) {
						cls = t.src.startsWith("imm") ? "imm-reg(LDA/LDX/LDY #)" : "PEA-const"; nv = t.val;
						bump(plbConst, String.format("%02x", (Integer) t.val));
					} else { cls = "unclassified:" + t.kind + (t.src != null ? "(" + t.src + ")" : ""); nv = UNK; }
					bump(plb, cls);
					if (cls.startsWith("unclassified")) sample(cls, in, fn);
					cur = nv; fn.writes = true; if (fn.firstWrite < 0) fn.firstWrite = idx;
					break;
				}
				case "MVN": case "MVP": {
					bump(plb, m); cur = UNK;
					try { cur = (int) (in.getByte(1) & 0xff); } catch (Exception e) { /* keep unknown */ }
					fn.writes = true; if (fn.firstWrite < 0) fn.firstWrite = idx; break;
				}
				case "JSR": case "JSL": {
					for (Reference r : in.getReferencesFrom()) {
						if (!r.getReferenceType().isCall()) continue;
						Fn cf = fns.get(r.getToAddress());
						if (cf == null || cf.exit == null || cf.exit.equals(ENTRY)) continue;
						cur = cf.exit;
						fn.writes = true; if (fn.firstWrite < 0) fn.firstWrite = idx;
					}
					break;
				}
				case "RTS": case "RTL": case "RTI":
					fn.exits.add(cur); st.clear(); break;
				default:
					if (dbr != null && writesReg(in, 0x20, 0x20)) {
						bump(other, m); cur = UNK; fn.writes = true; if (fn.firstWrite < 0) fn.firstWrite = idx;
					}
			}
			idx++;
		}
		fn.exit = fn.exits.isEmpty() ? null : fn.exits.size() == 1 ? fn.exits.iterator().next() : UNK;
	}

	void pushReg(Deque<Tag> st, Instruction in, int lo, int hi, boolean narrow, String kind) {
		Tag t = sourceOf(in, lo, hi, !narrow, kind);
		if (t.kind.equals("C") && !narrow) {
			int v = (Integer) t.val;
			st.push(new Tag("C", (v >> 8) & 0xff, t.src)); st.push(new Tag("C", v & 0xff, t.src));
		} else if (t.kind.equals("C")) st.push(new Tag("C", ((Integer) t.val) & 0xff, t.src));
		else { st.push(t); if (!narrow) st.push(t); }
	}

	void pop(Deque<Tag> st, int n) { for (int i = 0; i < n && !st.isEmpty(); i++) st.pop(); }

	void sample(String cls, Instruction in, Fn fn) {
		List<String> l = samples.computeIfAbsent(cls, k -> new ArrayList<>());
		if (l.size() < 4) l.add(in.getAddress() + " in " + fn.f.getName());
	}

	void bump(Map<String, Integer> m, String k) { m.merge(k, 1, Integer::sum); }

	/** returns a mode label if the instruction has an absolute data operand, else null. */
	String isAbs(Instruction in) {
		String m = in.getMnemonicString().toUpperCase();
		if (NOT_DATA.contains(m)) return null;
		for (int i = 0; i < in.getNumOperands(); i++) {
			String r = in.getDefaultOperandRepresentation(i);
			if (r.startsWith("#") || r.startsWith("[") || r.contains(",S")) continue;
			if (r.contains("!$")) return r.contains(",X") ? "abs,X" : r.contains(",Y") ? "abs,Y" : "abs";
		}
		return null;
	}

	int refBankValue(Instruction in) {
		for (Reference r : in.getReferencesFrom())
			if (!r.getReferenceType().isFlow() && r.isMemoryReference()) return bankOf(r.getToAddress());
		return -1;
	}

	String refBank(Instruction in) {
		int b = refBankValue(in);
		if (b < 0) return "none";
		if (b == 0) return "bank0";
		if (b == bankOf(in.getAddress())) return "ownPBR";
		return "other";
	}

	void operandCensus() throws Exception {
		Map<String, Integer> byRef = new TreeMap<>(), byMode = new TreeMap<>(), otherBanks = new TreeMap<>();
		int dpInd = 0;
		Pattern dpi = Pattern.compile("^\\(<");
		int shown = 0;
		for (Fn fn : fns.values()) for (Instruction in : fn.ins) {
			String mode = isAbs(in);
			if (mode != null) {
				String rb = refBank(in);
				bump(byRef, rb); bump(byMode, mode);
				if (shown++ < 4) println("DBR sample absop " + in.getAddress() + " " + in + " refBank=" + rb);
				if (rb.equals("other")) bump(otherBanks, String.format("%02x", refBankValue(in)));
				continue;
			}
			if (!NOT_DATA.contains(in.getMnemonicString().toUpperCase()))
				for (int i = 0; i < in.getNumOperands(); i++)
					if (dpi.matcher(in.getDefaultOperandRepresentation(i)).find()) { dpInd++; break; }
		}
		// Analyzer-stamped DBR context (grm-9nxj.32): abs operands where DBR has a context value,
		// and how many of those have a data reference at the (DBR<<16)|offset address.
		int stamped = 0, stampedRef = 0, stampedRefOk = 0;
		for (Fn fn : fns.values()) for (Instruction in : fn.ins) {
			if (isAbs(in) == null) continue;
			RegisterValue rv = currentProgram.getProgramContext().getRegisterValue(dbr, in.getAddress());
			if (rv == null || !rv.hasValue()) continue;
			stamped++;
			int rb = refBankValue(in);
			if (rb >= 0) { stampedRef++; if (rb == rv.getUnsignedValue().intValue()) stampedRefOk++; }
		}
		// Plausibility of the references on abs operands under a stamped DBR: where the target lands.
		int toCode = 0, toData = 0, toUndef = 0, samples = 0;
		for (Fn fn : fns.values()) for (Instruction in : fn.ins) {
			if (isAbs(in) == null) continue;
			RegisterValue rv = currentProgram.getProgramContext().getRegisterValue(dbr, in.getAddress());
			if (rv == null || !rv.hasValue()) continue;
			for (Reference r : in.getReferencesFrom()) {
				if (r.getReferenceType().isFlow() || !r.isMemoryReference()) continue;
				CodeUnit cu = currentProgram.getListing().getCodeUnitContaining(r.getToAddress());
				boolean code = cu instanceof Instruction;
				if (code) println("DBR refToInstruction " + in.getAddress() + " " + in + " DBR=" +
					String.format("%02x", rv.getUnsignedValue().intValue()) + " -> " + r.getToAddress() +
					" " + cu + " (fn " + currentProgram.getFunctionManager().getFunctionContaining(r.getToAddress()) + ")");
				if (code) toCode++; else if (cu instanceof Data && ((Data) cu).isDefined()) toData++; else toUndef++;
				if (samples < 8 && (samples % 1 == 0) && (in.getAddress().getOffset() % 97 == 0)) {
					samples++;
					println("DBR sample newref " + in.getAddress() + " " + in + " -> " + r.getToAddress() +
						" " + (code ? "CODE " + cu : cu == null ? "nothing" : cu.toString()));
				}
			}
		}
		println("DBR refTargets onInstruction=" + toCode + " onDefinedData=" + toData + " onUndefined=" + toUndef);
		println("DBR absOperandsWithStampedDbr=" + stamped + " withRef=" + stampedRef + " refBankEqualsDbr=" + stampedRefOk);
		println("DBR absOperands byRefBank=" + byRef + " byMode=" + byMode);
		println("DBR absOperands otherRefBanks=" + otherBanks);
		println("DBR dpIndirectData instrs=" + dpInd + " (no static final address)");
		rtsTrickCensus();
	}

	/** grm-9nxj.43: RTS windows (LDA abs,X/Y ... PHA ... RTS) by tracked DBR vs the PBR assumption. */
	void rtsTrickCensus() throws Exception {
		Listing l = currentProgram.getListing();
		int windows = 0, unknown = 0, agree = 0, disagree = 0, resolved = 0, resolvedDisagree = 0;
		for (Instruction rts : l.getInstructions(true)) {
			if (!"RTS".equals(rts.getMnemonicString())) continue;
			Instruction cur = rts, load = null; boolean pha = false;
			for (int n = 0; n < 12 && cur != null; n++) {
				Instruction prev = l.getInstructionBefore(cur.getMinAddress());
				if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough())) break;
				int op = prev.getByte(0) & 0xff;
				if (op == 0x48) pha = true;
				if (pha && (op == 0xbd || op == 0xb9)) { load = prev; break; }
				cur = prev;
			}
			if (load == null) continue;
			windows++;
			boolean res = rts.getComment(CommentType.EOL) != null && rts.getComment(CommentType.EOL).contains("65816 RTS trick");
			if (res) resolved++;
			RegisterValue v = currentProgram.getProgramContext().getRegisterValue(dbr, load.getMinAddress());
			if (v == null || !v.hasValue()) { unknown++; continue; }
			long bank = (rts.getMinAddress().getOffset() >> 16) & 0xff;
			if (v.getUnsignedValue().longValue() == bank) agree++;
			else { disagree++; if (res) resolvedDisagree++;
				println("DBR rtsTrick disagree " + rts.getMinAddress() + " load " + load.getMinAddress() + " DBR=" + v.getUnsignedValue()); }
		}
		println("DBR rtsTrickWindows=" + windows + " resolved=" + resolved + " dbrUnknown=" + unknown + " dbrAgreesPbr=" + agree + " dbrDiffersPbr=" + disagree + " (resolved&differs=" + resolvedDisagree + ")");
	}

	Object resolve(Fn fn, Object s) {
		if (s instanceof Integer) return s;
		if (ENTRY.equals(s)) return fn.seed;
		return UNK;
	}

	void functionCensus() {
		Map<String, Integer> cls = new TreeMap<>(), own = new TreeMap<>(), sites = new TreeMap<>();
		int withAbs = 0;
		for (Fn fn : fns.values()) {
			String c;
			if (!fn.writes) c = "noWrite";
			else if (fn.exit == null) c = "writes,noReturn";
			else if (ENTRY.equals(fn.exit)) c = "bracketed(preserving)";
			else if (fn.exit instanceof Integer) c = "returnsConst";
			else c = "changesUnknown";
			bump(cls, c);
			if (fn.firstAbs >= 0) {
				withAbs++;
				if (fn.firstWrite >= 0 && fn.firstWrite < fn.firstAbs) bump(own, "setsBeforeFirstAbs");
				else if (fn.firstWrite >= 0) bump(own, "writesOnlyAfterFirstAbs");
				else bump(own, "noWrite(relyOnCaller)");
			}
		}
		for (Fn fn : fns.values()) for (Instruction in : fn.ins) {
			String m = in.getMnemonicString().toUpperCase();
			if (!m.equals("JSR") && !m.equals("JSL")) continue;
			for (Reference r : in.getReferencesFrom()) {
				if (!r.getReferenceType().isCall()) continue;
				Fn cf = fns.get(r.getToAddress());
				if (cf == null) { bump(sites, "calleeNotFunction"); continue; }
				bump(sites, !cf.writes ? "noWrite" : ENTRY.equals(cf.exit) ? "bracketed" :
					cf.exit instanceof Integer ? "returnsConst" : "changes");
			}
		}
		println("DBR functions=" + fns.size() + " withAbsOperand=" + withAbs);
		println("DBR funcClass=" + cls);
		println("DBR absFuncOwnSetting=" + own);
		println("DBR callSitesByCalleeClass=" + sites);

		for (int round = 0; round < 8; round++) {
			boolean changed = false;
			for (Fn fn : fns.values()) {
				Object s = seedOf(fn);
				if (!s.equals(fn.seed)) { fn.seed = s; changed = true; }
			}
			if (!changed) break;
		}
		Map<String, Integer> res = new TreeMap<>(), agree = new TreeMap<>(), seedHist = new TreeMap<>();
		int seeded = 0;
		for (Fn fn : fns.values()) if (fn.seed instanceof Integer) {
			seeded++; bump(seedHist, String.format("%02x", (Integer) fn.seed));
		}
		println("DBR entrySeeded=" + seeded + " of " + fns.size() + " hist=" + seedHist);
		for (Fn fn : fns.values()) for (Instruction in : fn.ins) {
			if (isAbs(in) == null) continue;
			Object s = fn.state.get(in.getAddress());
			String k;
			if (s instanceof Integer) k = "A.localConst";
			else if (ENTRY.equals(s)) k = fn.seed instanceof Integer ? "B.entrySeeded" : "C.entryUnseeded";
			else k = "D.unknown";
			bump(res, k);
			Object v = resolve(fn, s);
			if (v instanceof Integer) {
				int dv = (Integer) v, rv = refBankValue(in);
				String rel = rv < 0 ? "noRef" : rv == dv ? "refMatchesDBR" :
					((rv & 0x7f) == (dv & 0x7f) && (dv & 0x7f) < 0x40) ? "refMirrorOfDBR" : "refDiffersFromDBR";
				bump(agree, k.substring(0, 1) + ":" + rel);
			}
		}
		println("DBR absResolution=" + res);
		println("DBR resolvedVsExistingRef=" + agree);
	}

	Object seedOf(Fn fn) {
		Object agreed = null;
		for (Reference r : currentProgram.getReferenceManager().getReferencesTo(fn.f.getEntryPoint())) {
			if (!r.getReferenceType().isCall()) return UNK;
			Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
			Fn caller = cf == null ? null : fns.get(cf.getEntryPoint());
			if (caller == null) return UNK;
			Object s = caller.state.get(r.getFromAddress());
			Object v = s == null ? UNK : resolve(caller, s);
			if (!(v instanceof Integer)) return UNK;
			if (agreed != null && !agreed.equals(v)) return UNK;
			agreed = v;
		}
		return agreed == null ? UNK : agreed;
	}

	void dumpFunc(String s) {
		Address a = currentProgram.getAddressFactory().getAddress(s);
		if (a != null && !fns.containsKey(a)) {   // any address: its containing function
			Function cf = currentProgram.getFunctionManager().getFunctionContaining(a);
			if (cf != null) a = cf.getEntryPoint();
		}
		Fn fn = a == null ? null : fns.get(a);
		if (fn == null) { println("DBR func " + s + ": not a function entry"); return; }
		if (sums == null) sums = new retromachines.W65816DataBankAnalyzer.CallSummaries(currentProgram);
		Set<Address> shown = new LinkedHashSet<>();
		shown.add(a);
		for (Instruction in : fn.ins) {
			String m = in.getMnemonicString().toUpperCase();
			if (m.equals("JSR") || m.equals("JSL") || (in.getFlowType().isJump() && !in.getFlowType().isComputed()))
				for (Address t : in.getFlows()) if (fns.containsKey(t)) shown.add(t);
		}
		for (Address t : shown)
			println("DBR sum " + t + " analyzer=" + sums.verdict(t) + " why=" + sums.why(t));
		println("DBR func " + s + " " + fn.f.getName() + " seed=" + show(fn.seed) + " exit=" + show(fn.exit) +
			" writes=" + fn.writes + " instrs=" + fn.ins.size());
		for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
			Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
			Fn caller = cf == null ? null : fns.get(cf.getEntryPoint());
			Object st = caller == null ? null : caller.state.get(r.getFromAddress());
			println("DBR   caller " + r.getReferenceType() + " " + r.getFromAddress() + " in " +
				(cf == null ? "<none>" : cf.getName()) + " state=" + show(st) + " resolved=" +
				(caller == null || st == null ? "?" : show(resolve(caller, st))) + " callerSeed=" +
				(caller == null ? "?" : show(caller.seed)));
			Instruction p = currentProgram.getListing().getInstructionAt(r.getFromAddress());
			List<String> back = new ArrayList<>();
			for (int i = 0; i < 8 && p != null; i++, p = p.getPrevious()) back.add(0, p.getAddress() + " " + p);
			for (String b : back) println("DBR       " + b);
		}
		for (String line : diag.states(a)) println("DBR   walk " + line);   // the analyzer's own states
		int n = 0;
		for (Instruction in : fn.ins) {
			if (n++ >= 2000) break;
			RegisterValue cv = currentProgram.getProgramContext().getRegisterValue(dbr, in.getAddress());
			StringBuilder sb = new StringBuilder("DBR   " + in.getAddress() + " " + in + " ctxDBR=" + (cv != null && cv.hasValue() ? String.format("%02x", cv.getUnsignedValue().intValue()) : "-") + " mx=" + flagOf(in, mf) + flagOf(in, xf) + " dbr=" +
				show(fn.state.get(in.getAddress())));
			for (Reference r : in.getReferencesFrom())
				if (!r.getReferenceType().isFlow()) sb.append(" [ref->").append(r.getToAddress()).append("]");
			println(sb.toString());
		}
	}

	String show(Object o) {
		return o == null ? "null" : o instanceof Integer ? String.format("%02x", (Integer) o) : o.toString();
	}
}
