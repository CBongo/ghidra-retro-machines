// Narrow probe (grm-9nxj.27): where does the 65816 direct page get lost? Reads only the DP stamps
// W65816DirectPageAnalyzer laid in the ProgramContext (the same values the listing's "assume DP"
// lines show) and reports every "loss edge": a stamped instruction flowing, inside its function,
// to an unstamped one. Each edge is classified by its source:
//   CALL   -- the call's return point is unstamped: the callee's DP summary failed;
//   WRITER -- PLD/TCD/PLP/RTI or any instruction whose p-code writes DP produced an unknown DP;
//   MERGE  -- an ordinary instruction: another path into the successor disagrees.
// Census (always): edge counts by kind, and the callees behind the most CALL losses.
// Chain (GRM_DP_LOSS_FROM=<addr>[,...]): that function's loss edges, then recursively each CALL
// loss's callee (entry DP, returns with their DP, its own loss edges), so one run follows the whole
// chain of lost DP down to where it really goes. Depth GRM_DP_LOSS_DEPTH (default 8).
// Read-only; every line is prefixed "DPL ".
//@category RetroMachines.Test

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class DpLossProbe extends GhidraScript {

	private Register dp;
	private final Set<Address> shown = new HashSet<>();

	private record Loss(Instruction from, Address to, String kind, Address callee) {}

	@Override
	protected void run() throws Exception {
		dp = currentProgram.getRegister("DP");
		FunctionManager fm = currentProgram.getFunctionManager();
		Map<String, Integer> kinds = new TreeMap<>();
		Map<Address, Integer> byCallee = new HashMap<>();
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			for (Loss l : losses(f)) {
				kinds.merge(l.kind, 1, Integer::sum);
				if (l.callee != null) byCallee.merge(l.callee, 1, Integer::sum);
			}
		}
		println("DPL lossEdges=" + kinds);
		// grm-9nxj.28: every entry whose known ways in disagree, with each way in and its DP.
		var bi = currentProgram.getBookmarkManager().getBookmarksIterator("Warning");
		while (bi.hasNext()) {
			Bookmark b = bi.next();
			if (b.getCategory().equals("65816 DP") && b.getComment().startsWith("DP conflict")) {
				Function cf = fm.getFunctionAt(b.getAddress());
				println("DPL conflict " + b.getAddress() + " " +
					(cf == null ? "<no function>" : cf.getName()) + ": " + b.getComment());
				if (cf != null) {
					entryWays(cf, "DPL   ");
				}
			}
		}
		List<Map.Entry<Address, Integer>> top = new ArrayList<>(byCallee.entrySet());
		top.sort((a, b) -> b.getValue() != a.getValue().intValue() ? b.getValue() - a.getValue()
			: a.getKey().compareTo(b.getKey()));
		for (int i = 0; i < Math.min(15, top.size()); i++) {
			Address c = top.get(i).getKey();
			Function cf = fm.getFunctionAt(c);
			println("DPL topCallee " + c + " " + (cf == null ? "<no function>" : cf.getName()) +
				" callLosses=" + top.get(i).getValue() + " " + returnsSummary(cf));
		}
		String dump = System.getenv("GRM_DP_STAMP_DUMP");
		if (dump != null && !dump.isBlank()) {
			// Every stamped instruction as "<addr> <dp> <function>", for diffing two builds.
			try (var w = new java.io.PrintWriter(dump + "." + currentProgram.getName() + ".txt")) {
				for (Instruction in : currentProgram.getListing().getInstructions(true)) {
					String v = dpAt(in.getAddress());
					if (v.equals("?")) continue;
					Function cf = fm.getFunctionContaining(in.getAddress());
					w.println(in.getAddress() + " " + v + " " + (cf == null ? "-" : cf.getEntryPoint()));
				}
			}
		}
		String from = System.getenv("GRM_DP_LOSS_FROM");
		if (from == null || from.isBlank()) return;
		String d = System.getenv("GRM_DP_LOSS_DEPTH");
		int depth = d == null || d.isBlank() ? 8 : Integer.parseInt(d.trim());
		for (String s : from.split(",")) {
			Address a = currentProgram.getAddressFactory().getAddress(s.trim());
			Function f = a == null ? null : fm.getFunctionContaining(a);
			if (f == null) { println("DPL chain " + s + ": no function"); continue; }
			chain(f, 0, depth);
		}
	}

	private void chain(Function f, int level, int depth) throws Exception {
		String ind = "DPL " + "  ".repeat(level);
		if (!shown.add(f.getEntryPoint())) {
			println(ind + f.getName() + " @" + f.getEntryPoint() + " (shown above)");
			return;
		}
		println(ind + f.getName() + " @" + f.getEntryPoint() + " entryDP=" + dpAt(f.getEntryPoint()) +
			" " + returnsSummary(f) + (f.isThunk() ? " THUNK->" + f.getThunkedFunction(false) : "") +
			" body=" + f.getBody());
		List<Loss> ls = losses(f);
		if (ls.isEmpty()) {
			println(ind + "  no loss edges" + (dpAt(f.getEntryPoint()).equals("?")
				? " (entry unseeded: nothing stamped to lose)" : ""));
		}
		// A tail jump out of the body returns whatever its target returns: follow it. A flow
		// override (CALL_RETURN turns a JMP into a terminal call) is listed, since it changes how
		// the analyzer's summary sees that instruction.
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			var ft = in.getFlowType();
			if (in.getFlowOverride() != FlowOverride.NONE) {
				println(ind + "  OVERRIDE " + in.getFlowOverride() + " " + in.getAddress() + " " + in +
					" flow=" + ft + " DP=" + dpAt(in.getAddress()));
				Address[] fl = in.getFlows();
				Function tf = fl.length == 1 ? currentProgram.getFunctionManager().getFunctionAt(fl[0]) : null;
				if (tf != null && ft.isCall() && level + 1 < depth) chain(tf, level + 2, depth);
			}
			if (ft.isCall() || !ft.isJump() || ft.isComputed()) continue;
			for (Address t : in.getFlows()) {
				if (f.getBody().contains(t)) continue;
				println(ind + "  TAIL " + in.getAddress() + " " + in + " DP=" + dpAt(in.getAddress()));
				Function tf = currentProgram.getFunctionManager().getFunctionAt(t);
				if (tf == null) println(ind + "    target " + t + ": no function");
				else if (level + 1 < depth) chain(tf, level + 2, depth);
			}
		}
		if (dpAt(f.getEntryPoint()).equals("?")) {
			entryWays(f, ind + "  ");
			// Unstamped body: no loss edges to see, but the call summary is context-free, so the
			// failure may be in any callee. List every call and keep following.
			for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				if (!in.getFlowType().isCall()) continue;
				Address[] fl = in.getFlows();
				println(ind + "  CALL? (unstamped) " + in.getAddress() + " " + in);
				Function cf = fl.length == 1 ? currentProgram.getFunctionManager().getFunctionAt(fl[0]) : null;
				if (cf == null) println(ind + "    callee: " + (fl.length == 1 ? "no function" : "indirect"));
				else if (level + 1 < depth) chain(cf, level + 2, depth);
			}
		}
		for (Loss l : ls) {
			println(ind + "  " + l.kind + " " + l.from.getAddress() + " " + l.from + " DP=" +
				dpAt(l.from.getAddress()) + " -> " + l.to + " DP=?");
			if (l.callee != null && level + 1 < depth) {
				Function cf = currentProgram.getFunctionManager().getFunctionAt(l.callee);
				if (cf == null) println(ind + "    callee " + l.callee + ": no function");
				else chain(cf, level + 2, depth);
			}
		}
	}

	/**
	 * Why an entry stayed unseeded: every way in (the analyzer's entrySources) with the DP stamped
	 * at its source -- references to the entry, and a fall-through from the instruction before it.
	 */
	private void entryWays(Function f, String ind) {
		Address e = f.getEntryPoint();
		if (currentProgram.getSymbolTable().isExternalEntryPoint(e)) println(ind + "way in: external entry");
		for (var r : currentProgram.getReferenceManager().getReferencesTo(e)) {
			Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
			println(ind + "way in: " + r.getReferenceType() + " from " + r.getFromAddress() + " in " +
				(cf == null ? "<none>" : cf.getName()) + " DP=" + dpAt(r.getFromAddress()));
		}
		Instruction before = currentProgram.getListing().getInstructionBefore(e);
		if (before != null && e.equals(before.getFallThrough())) {
			println(ind + "way in: FALL-THROUGH from " + before.getAddress() + " " + before + " DP=" +
				dpAt(before.getAddress()));
		}
	}

	/** Every RTS/RTL/RTI in f's body with its stamped DP, plus whether a jump leaves the body. */
	private String returnsSummary(Function f) {
		if (f == null) return "";
		StringBuilder sb = new StringBuilder("returns[");
		boolean leaves = false;
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			String m = in.getMnemonicString().toUpperCase(Locale.ROOT);
			if (m.equals("RTS") || m.equals("RTL") || m.equals("RTI")) {
				sb.append(' ').append(m).append('@').append(in.getAddress()).append('=')
					.append(dpAt(in.getAddress()));
			}
			var ft = in.getFlowType();
			if (!ft.isCall() && (ft.isJump() || ft.isComputed())) {
				for (Address t : in.getFlows()) leaves |= !f.getBody().contains(t);
				leaves |= ft.isComputed() && in.getFlows().length == 0;
			}
		}
		return sb.append(" ]").append(leaves ? " leavesBody" : "").toString();
	}

	private List<Loss> losses(Function f) {
		List<Loss> out = new ArrayList<>();
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			if (dpAt(in.getAddress()).equals("?")) continue;
			var ft = in.getFlowType();
			List<Address> succ = new ArrayList<>();
			if (ft.isCall()) {
				if (in.getFallThrough() != null) succ.add(in.getFallThrough());
			}
			else if (!ft.isTerminal()) {
				succ.addAll(Arrays.asList(in.getFlows()));
				if (in.hasFallthrough()) succ.add(in.getFallThrough());
			}
			for (Address s : succ) {
				if (!f.getBody().contains(s) || currentProgram.getListing().getInstructionAt(s) == null ||
					!dpAt(s).equals("?")) continue;
				if (ft.isCall()) {
					Address[] fl = in.getFlows();
					out.add(new Loss(in, s, "CALL", fl.length == 1 ? fl[0] : null));
				}
				else out.add(new Loss(in, s, writesDp(in) ? "WRITER" : "MERGE", null));
			}
		}
		return out;
	}

	private boolean writesDp(Instruction in) {
		for (PcodeOp op : in.getPcode()) {
			Varnode o = op.getOutput();
			if (o != null && o.isRegister() && o.getOffset() <= dp.getOffset() &&
				dp.getOffset() < o.getOffset() + o.getSize()) return true;
		}
		String m = in.getMnemonicString().toUpperCase(Locale.ROOT);
		return m.equals("PLD") || m.equals("TCD");
	}

	private String dpAt(Address a) {
		RegisterValue v = currentProgram.getProgramContext().getRegisterValue(dp, a);
		return v != null && v.hasValue() ? String.format("%04x", v.getUnsignedValue()) : "?";
	}
}
