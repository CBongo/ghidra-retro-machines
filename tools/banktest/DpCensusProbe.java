// Narrow probe (grm-9nxj.22): 65816 direct-page census. Classifies every DP writer (TCD/PLD) as
// constant / PHD-bracket / unknown by a local backward scan, histograms the constant values, and
// buckets dp-operand references by target page and type, and (grm-9nxj.26) counts functions whose
// every entry carries one known DP. With GRM_DP_SITES=<addr>,... it also lists, per site, the
// containing function's entry refs with the DP at each source, then the next 24 instructions with
// the DP context value and every outgoing reference.
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

	private static final int SITE_WINDOW = 24;

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
