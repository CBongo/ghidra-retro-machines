// Narrow probe (grm-9nxj.22): 65816 direct-page census. Classifies every DP writer (TCD/PLD) as
// constant / PHD-bracket / unknown by a local backward scan, histograms the constant values, and
// buckets dp-operand references by target page and type, and (grm-9nxj.26) counts functions whose
// every entry carries one known DP. With GRM_DP_SITES=<addr>,... it also lists, per site, the
// containing function's entry refs with the DP at each source, then the next 24 instructions with
// the DP context value and every outgoing reference (GRM_DP_SITE_WINDOW instructions, default 24).
// grm-hf5h.23: a callee census ("DPC callee") of which call targets really change the caller's DP,
// judged by the analyzer's own call summary.
// Read-only; every line is prefixed "DPC ". The deterministic counts live in W65816WidthDump's
// "REALROM dp" section; this adds the per-site detail the golden deliberately leaves out.
//@category RetroMachines.Test

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import retromachines.W65816DirectPageAnalyzer;

public class DpCensusProbe extends GhidraScript {
	private static final Set<String> SKIP = new HashSet<>(Arrays.asList("STA", "STX", "STY", "STZ", "TAX",
		"TAY", "PHA", "PHX", "PHY", "PHP", "PHB", "PHD", "PHK", "CLC", "SEC", "CLI", "SEI", "NOP", "CLD",
		"SED", "CLV"));

	@Override
	protected void run() throws Exception {
		Listing l = currentProgram.getListing();
		int total = 0, tcd = 0, pld = 0, dpOps = 0, dpOpsWithRef = 0, dpOpsNoRef = 0;
		Map<String, Integer> cls = new TreeMap<>();
		Map<String, Integer> hist = new TreeMap<>();
		Map<String, Integer> refKinds = new TreeMap<>();
		Map<String, Integer> sampleCount = new HashMap<>();
		Set<String> otherWriters = new TreeSet<>();
		Register dp = currentProgram.getRegister("DP");
		InstructionIterator it = l.getInstructions(true);
		while (it.hasNext()) {
			Instruction in = it.next();
			total++;
			String m = in.getMnemonicString().toUpperCase();
			PcodeOp[] ops = in.getPcode();
			boolean readsDp = false, writesDp = false;
			for (PcodeOp op : ops) {
				Varnode out = op.getOutput();
				if (out != null && isDp(out, dp)) writesDp = true;
				for (Varnode v : op.getInputs()) if (isDp(v, dp)) readsDp = true;
			}
			if (writesDp && !m.equals("TCD") && !m.equals("PLD")) otherWriters.add(m);
			if (m.equals("TCD")) {
				tcd++;
				String c = classifyTcd(in);
				bump(cls, "TCD:" + c.split(" ")[0]);
				if (c.startsWith("const")) bump(hist, c.substring(6));
				sample("TCD:" + c.split(" ")[0], in, c, sampleCount);
			} else if (m.equals("PLD")) {
				pld++;
				String c = classifyPld(in);
				bump(cls, "PLD:" + c.split(" ")[0]);
				if (c.startsWith("const")) bump(hist, c.substring(6));
				sample("PLD:" + c.split(" ")[0], in, c, sampleCount);
			} else if (readsDp && !m.equals("TDC") && !m.equals("PHD")) {
				dpOps++;
				Reference[] refs = in.getReferencesFrom();
				List<String> mem = new ArrayList<>();
				for (Reference r : refs) {
					if (r.getReferenceType().isFlow()) continue;
					if (!r.isMemoryReference()) continue;
					mem.add(r.getReferenceType() + (r.getToAddress().isStackAddress() ? "stack" : ""));
					long off = r.getToAddress().getOffset();
					bump(refKinds, r.getToAddress().getAddressSpace().getName() + ":" +
						((off >> 8) == 0 ? "page0" : "other") + " " + r.getReferenceType());
					if (sampleCount.merge("dpref", 1, Integer::sum) <= 3)
						println("DPC sample dp-ref " + in.getAddress() + " " + in + " -> " + r.getToAddress());
				}
				if (mem.isEmpty()) { dpOpsNoRef++; }
				else dpOpsWithRef++;
			}
		}
		println("DPC total=" + total + " TCD=" + tcd + " PLD=" + pld + " otherDpWriters=" + otherWriters);
		println("DPC classes=" + cls);
		println("DPC dpValueHistogram=" + hist);
		println("DPC dpOperandInstrs=" + dpOps + " withMemRef=" + dpOpsWithRef + " noMemRef=" + dpOpsNoRef);
		println("DPC dpOperandRefTargets=" + refKinds);
		entryCensus(dp);
		calleeCensus(dp);
		String sites = System.getenv("GRM_DP_SITES");
		if (sites == null || sites.isBlank()) return;
		for (String s : sites.split(",")) {
			s = s.trim();
			Address a;
			try { a = currentProgram.getAddressFactory().getAddress(s); } catch (Exception e) { a = null; }
			if (a == null) { println("DPC site " + s + ": not an address"); continue; }
			Instruction in = l.getInstructionContaining(a);
			if (in == null && (in = l.getInstructionAfter(a)) == null) continue;
			println("DPC site " + s + " (" + a + "): next " + SITE_WINDOW + " instructions");
			Function sf = currentProgram.getFunctionManager().getFunctionContaining(a);
			if (sf == null) println("DPC   in no function");
			else {
				println("DPC   in " + sf.getName() + " @" + sf.getEntryPoint() + (currentProgram
					.getSymbolTable().isExternalEntryPoint(sf.getEntryPoint()) ? " (external entry)" : ""));
				for (Reference r : currentProgram.getReferenceManager().getReferencesTo(sf.getEntryPoint())) {
					RegisterValue v = currentProgram.getProgramContext().getRegisterValue(dp, r.getFromAddress());
					Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
					println("DPC     entry ref " + r.getReferenceType() + " from " + r.getFromAddress() + " in " +
						(cf == null ? "<none>" : cf.getName() + "@" + cf.getEntryPoint()) + " DP=" +
						(v != null && v.hasValue() ? String.format("%04x", v.getUnsignedValue()) : "?"));
				}
			}
			for (int i = 0; i < SITE_WINDOW && in != null; i++, in = in.getNext()) {
				RegisterValue v = currentProgram.getProgramContext().getRegisterValue(dp, in.getAddress());
				StringBuilder sb = new StringBuilder("DPC   " + in.getAddress() + " " + in + " DP=" +
					(v != null && v.hasValue() ? String.format("%04x", v.getUnsignedValue()) : "?"));
				for (Reference r : in.getReferencesFrom())
					sb.append(" [ref ").append(r.getReferenceType()).append("->").append(r.getToAddress())
						.append(" op").append(r.getOperandIndex()).append("]");
				println(sb.toString());
			}
		}
	}

	private static final int SITE_WINDOW = Integer.parseInt(System.getenv().getOrDefault("GRM_DP_SITE_WINDOW", "24"));

	/**
	 * grm-9nxj.26 measurement: classifies each function by the DP its entries see, read from the
	 * stamps already laid at the source instruction of every flow reference into its entry point.
	 * strict = a data reference (pointer table, vector) also counts as an unknown entry; lenient =
	 * data references are ignored. "unlock" = dp operands in an agreeing function with DP unknown.
	 */
	private void entryCensus(Register dp) {
		Map<String, Integer> strict = new TreeMap<>(), lenient = new TreeMap<>();
		int unlockStrict = 0, unlockLenient = 0;
		ReferenceManager rm = currentProgram.getReferenceManager();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			Set<Integer> vals = new HashSet<>();
			boolean unknownFlow = false, data = false;
			int flows = 0;
			for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
				if (!r.getReferenceType().isFlow()) { data = true; continue; }
				flows++;
				RegisterValue v = currentProgram.getProgramContext().getRegisterValue(dp, r.getFromAddress());
				if (v == null || !v.hasValue()) unknownFlow = true;
				else vals.add(v.getUnsignedValue().intValue());
			}
			String le = flows == 0 ? "noFlowEntry" : unknownFlow ? "unknownCaller" :
				vals.size() > 1 ? "disagree" : "agree";
			String st = data && le.equals("agree") ? "dataRef" : le;
			bump(lenient, le);
			bump(strict, st);
			if (le.equals("agree")) {
				int n = unknownDpOperands(f, dp);
				unlockLenient += n;
				if (st.equals("agree")) unlockStrict += n;
			}
		}
		println("DPC entry strict=" + strict + " unlockOperands=" + unlockStrict);
		println("DPC entry lenient=" + lenient + " unlockOperands=" + unlockLenient);
	}

	/**
	 * grm-hf5h.23 measurement, for the owner's ruling on listing DP as unaffected in
	 * w65816.cspec: which callees really change their caller's DP? Each function is judged by the
	 * analyzer's own call summary (W65816DirectPageAnalyzer.CallSummaries), then split by whether
	 * its own body writes DP. Call sites (CALL refs to the entry) are counted per class, and for
	 * a callee that returns a constant, against the caller's stamped DP at the call: same (the
	 * call leaves DP as it was), diff (DP really changes), or unknown.
	 */
	private void calleeCensus(Register dp) throws Exception {
		W65816DirectPageAnalyzer.CallSummaries cs = new W65816DirectPageAnalyzer.CallSummaries(currentProgram);
		ReferenceManager rm = currentProgram.getReferenceManager();
		Map<String, Integer> fns = new TreeMap<>(), calls = new TreeMap<>(), constCalls = new TreeMap<>();
		Map<String, Integer> whyHist = new TreeMap<>();
		Map<String, Integer> hubs = new HashMap<>();
		Map<String, List<String>> ex = new TreeMap<>();
		FunctionManager fm = currentProgram.getFunctionManager();
		Map<Function, String> verdict = new HashMap<>(), writers = new HashMap<>();
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			verdict.put(f, cs.verdict(f.getEntryPoint()));
			String w = directWriter(f, dp);
			if (w != null) writers.put(f, w);
		}
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			Address e = f.getEntryPoint();
			String v = verdict.get(f);
			String writer = writers.get(f);
			String cls = v.equals("preserves") || v.equals("restores") ? v :
				v.equals("UNKNOWN") ? (writer != null ? "unknown-writes" : "unknown-nowrite") : "const";
			if (cls.equals("unknown-nowrite")) {
				String rr = reach(f, verdict, writers);
				if (rr.startsWith("reachesWriter ")) {
					int calls0 = 0;
					for (Reference r : rm.getReferencesTo(e)) if (r.getReferenceType().isCall()) calls0++;
					hubs.merge(rr.substring(14), calls0, Integer::sum);
					rr = "reachesWriter";
				}
				cls += "/" + rr;
			}
			bump(fns, cls);
			int n = 0, diff = 0;
			Set<String> callerDps = new TreeSet<>();
			for (Reference r : rm.getReferencesTo(e)) {
				if (!r.getReferenceType().isCall()) continue;
				n++;
				bump(calls, cls);
				if (!cls.equals("const")) continue;
				RegisterValue rv = currentProgram.getProgramContext().getRegisterValue(dp, r.getFromAddress());
				String c = rv == null || !rv.hasValue() ? "?" : String.format("$%04X", rv.getUnsignedValue());
				callerDps.add(c);
				String k = c.equals("?") ? "callerUnknown" : c.equals(v) ? "same" : "diff";
				if (k.equals("diff")) diff++;
				bump(constCalls, k);
			}
			String why = cs.why(e);
			if (cls.startsWith("unknown"))
				bump(whyHist, cls + ": " + (why == null ? "?" : why.replaceAll(" at .*", "")
					.replaceAll("\\[.*\\]", "[..]").replaceAll("\\$[0-9A-F]{4}", "\\$x")));
			String line = f.getName() + "@" + e + " calls=" + n + (writer == null ? "" : " writer=" + writer) +
				(cls.equals("const") ? " returns=" + v + " callerDPs=" + callerDps + " diff=" + diff : "") +
				(cls.startsWith("unknown") ? " why=" + why : "");
			if (cls.equals("restores") || n > 0 || writer != null)
				ex.computeIfAbsent(cls, k -> new ArrayList<>()).add(line);
		}
		// grm-hf5h.28: which calling convention each verdict class ended up with. A proven class
		// (preserves/restores) without __dp_preserved means the analyzer did not reach it or
		// something reset it; any other class WITH it is a wrong promise to the decompiler.
		Map<String, Integer> cc = new TreeMap<>();
		List<String> ccBad = new ArrayList<>();
		for (Function f : fm.getFunctions(true)) {
			// A thunk reports its target's convention (FunctionDB), so judge it by the target.
			Function judged = f.isThunk() ? f.getThunkedFunction(true) : f;
			String v = verdict.getOrDefault(judged, "UNKNOWN");
			boolean proven = v.equals("preserves") || v.equals("restores");
			String conv = f.getCallingConventionName();
			bump(cc, (proven ? v : v.equals("UNKNOWN") ? "unknown" : "const") + " -> " + conv);
			boolean has = "__dp_preserved".equals(conv);
			if (has != proven && (has || conv == null || conv.equals("unknown") || conv.equals("default") ||
				conv.equals("__unknowncall")))
				ccBad.add(f.getName() + "@" + f.getEntryPoint() + " verdict=" + v + " cc=" + conv);
		}
		println("DPC cc verdict -> convention: " + cc);
		println("DPC cc mismatches=" + ccBad.size());
		for (int i = 0; i < Math.min(25, ccBad.size()); i++) println("DPC cc mismatch " + ccBad.get(i));
		println("DPC callee functions=" + fns);
		println("DPC callee callSites=" + calls);
		println("DPC callee constCallSites=" + constCalls);
		println("DPC callee unknownWhy=" + whyHist);
		List<Map.Entry<String, Integer>> hl = new ArrayList<>(hubs.entrySet());
		hl.sort((a, b) -> b.getValue() - a.getValue());
		println("DPC callee reachesWriter first-writer hubs (call sites behind each): " +
			hl.subList(0, Math.min(15, hl.size())));
		for (Map.Entry<String, List<String>> en : ex.entrySet()) {
			if (en.getKey().equals("preserves")) continue;
			List<String> l = en.getValue();
			l.sort(Comparator.comparingInt(s -> -Integer.parseInt(s.replaceAll(".* calls=(\\d+).*", "$1"))));
			int cap = en.getKey().startsWith("unknown-nowrite") ? 8 : 25;
			for (int i = 0; i < Math.min(cap, l.size()); i++)
				println("DPC callee " + en.getKey() + " " + l.get(i));
			if (l.size() > cap) println("DPC callee " + en.getKey() + " ... " + (l.size() - cap) + " more");
		}
	}

	/**
	 * For a function with no DP writer of its own and an UNKNOWN summary: what its flow out of
	 * the body (calls, jumps, branches into other functions, followed transitively) can reach.
	 * "reachesWriter" = some reachable function writes DP and is not judged preserves/restores;
	 * else "unresolved" = a computed flow without targets, or a target in no function; else
	 * "noWriter" = nothing reachable can change DP, so the UNKNOWN is a summary limitation.
	 */
	private String reach(Function start, Map<Function, String> verdict, Map<Function, String> writers) {
		FunctionManager fm = currentProgram.getFunctionManager();
		Set<Function> seen = new HashSet<>(List.of(start));
		ArrayDeque<Function> work = new ArrayDeque<>(seen);
		boolean unresolved = false;
		while (!work.isEmpty()) {
			Function f = work.poll();
			if (f != start && writers.containsKey(f)) {
				String v = verdict.get(f);
				if (!v.equals("preserves") && !v.equals("restores"))
					return "reachesWriter " + f.getName() + "@" + f.getEntryPoint() + "=" + v;
			}
			for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				var ft = in.getFlowType();
				if (!ft.isCall() && !ft.isJump() && !ft.isComputed()) continue;
				Address[] fl = in.getFlows();
				if (ft.isComputed() && fl.length == 0) unresolved = true;
				for (Address t : fl) {
					if (f.getBody().contains(t) && !ft.isCall()) continue;
					Function g = fm.getFunctionAt(t);
					if (g == null) g = fm.getFunctionContaining(t);
					if (g == null) { unresolved = true; continue; }
					if (seen.add(g)) work.add(g);
				}
			}
		}
		return unresolved ? "unresolved" : "noWriter";
	}

	/** The first instruction in {@code f}'s body whose p-code writes DP, or null. */
	private String directWriter(Function f, Register dp) {
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true))
			for (PcodeOp op : in.getPcode())
				if (op.getOutput() != null && isDp(op.getOutput(), dp))
					return in.getMnemonicString() + "@" + in.getAddress();
		return null;
	}

	private int unknownDpOperands(Function f, Register dp) {
		int n = 0;
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			String m = in.getMnemonicString().toUpperCase();
			if (m.equals("TDC") || m.equals("PHD")) continue;
			boolean reads = false;
			for (PcodeOp op : in.getPcode())
				for (Varnode v : op.getInputs()) if (isDp(v, dp)) reads = true;
			if (!reads) continue;
			RegisterValue v = currentProgram.getProgramContext().getRegisterValue(dp, in.getAddress());
			if (v == null || !v.hasValue()) n++;
		}
		return n;
	}

	private boolean isDp(Varnode v, Register dp) {
		if (v == null || !v.isRegister()) return false;
		Register r = currentProgram.getRegister(v.getAddress(), v.getSize());
		return r != null && (r.equals(dp) || r.getBaseRegister().equals(dp) ||
			r.getName().equals("DPLow"));
	}

	private void bump(Map<String, Integer> m, String k) { m.merge(k, 1, Integer::sum); }

	private void sample(String k, Instruction in, String c, Map<String, Integer> cnt) {
		if (cnt.merge(k, 1, Integer::sum) > 3) return;
		StringBuilder sb = new StringBuilder("DPC sample " + k + " @" + in.getAddress() + " (" + c + ") prev:");
		Instruction p = in;
		List<String> back = new ArrayList<>();
		for (int i = 0; i < 4; i++) {
			p = p.getPrevious();
			if (p == null) break;
			back.add(0, p.getAddress() + " " + p);
		}
		println(sb.append(' ').append(String.join(" | ", back)).toString());
	}

	private Scalar imm(Instruction i) {
		if (i.getNumOperands() < 1) return null;
		for (Object o : i.getOpObjects(0)) if (o instanceof Scalar) return (Scalar) o;
		return null;
	}

	private Instruction prevFall(Instruction in) {
		Instruction p = in.getPrevious();
		if (p == null || p.getFallThrough() == null || !p.getFallThrough().equals(in.getAddress())) return null;
		return p;
	}

	private String classifyTcd(Instruction tcd) {
		Instruction p = prevFall(tcd);
		for (int i = 0; i < 12 && p != null; i++, p = prevFall(p)) {
			String m = p.getMnemonicString().toUpperCase();
			if (m.equals("LDA")) {
				Scalar s = imm(p);
				if (s != null && p.getLength() == 3)
					return "const " + String.format("%04x", s.getUnsignedValue());
				return "unknown (LDA non-imm16 @" + p.getAddress() + ")";
			}
			if (m.equals("TDC")) return "unknown (TDC-relative)";
			if (SKIP.contains(m)) continue;
			if (m.equals("REP") || m.equals("SEP")) continue;
			return "unknown (" + m + ")";
		}
		return "unknown (no def in block)";
	}

	private String classifyPld(Instruction pld) {
		Instruction p = prevFall(pld);
		if (p != null && p.getMnemonicString().equalsIgnoreCase("PEA")) {
			Scalar s = imm(p);
			if (s != null) return "const " + String.format("%04x", s.getUnsignedValue());
		}
		if (p != null && (p.getMnemonicString().equalsIgnoreCase("PHX") || p.getMnemonicString().equalsIgnoreCase("PHA")
			|| p.getMnemonicString().equalsIgnoreCase("PHY"))) {
			String ld = p.getMnemonicString().equalsIgnoreCase("PHX") ? "LDX" : p.getMnemonicString().equalsIgnoreCase("PHY") ? "LDY" : "LDA";
			Instruction q = prevFall(p);
			if (q != null && q.getMnemonicString().equalsIgnoreCase(ld) && q.getLength() == 3) {
				Scalar s = imm(q);
				if (s != null) return "const " + String.format("%04x", s.getUnsignedValue());
			}
		}
		Function f = currentProgram.getFunctionManager().getFunctionContaining(pld.getAddress());
		if (f != null) {
			InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
			while (it.hasNext()) {
				Instruction i = it.next();
				if (i.getAddress().compareTo(pld.getAddress()) >= 0) break;
				if (i.getMnemonicString().equalsIgnoreCase("PHD")) return "bracket";
			}
		}
		return "unknown" + (f == null ? " (no function)" : "");
	}
}
