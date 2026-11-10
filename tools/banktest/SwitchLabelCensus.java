// Narrow probe (grm-hf5h stage 1): the switch-label census. For EVERY computed jump (and every
// jump-table override) in the program, decompile the owning function and report what the
// decompiler made of the switch: how many dests, what its case LABELS are, and how those labels
// relate to the dispatch index. Read-only. Run as a postScript through the real-ROM tier, once
// per decompiler (stock/baseline and candidate) and diff the SLC lines:
//   REALROM_EXTRA_POSTSCRIPT=SwitchLabelCensus.java REALROM_WORK_DIR=<dir outside the repo> \
//     bash tools/banktest/realrom-test.sh check all --no-build
// (for a candidate decompile.exe use a junction-shadow install, see the
// decompiler-ab-via-junction-shadow-install bd memory and tools/banktest/mkshadow.ps1).
// Output lines start "SLC " in <dir>/<id>.log; tools/banktest/slc-summary.py tabulates them.
//
// One line per site:
//   SLC <lang> <program> <space::site> fn=<name> override=<y|n> analyzer=<guess> cases=<n dests, default
//       excluded> labels=<n distinct labels> kind=<...> min=<..> max=<..> default=<y|n> [ex=<first labels>]
// kind:
//   address       labels equal the dest offsets (the setupTrivial fallback: switch on the loaded pointer)
//   offset        labels are a constant multiple (2,3,..) of a contiguous index run (pre-multiplied
//                 index NOT recovered: case 0,2,4 for a word table)
//   index         labels are a contiguous integer run (normally 0..n-1) = the index was recovered
//   composite     anything else (sparse / combined labels, e.g. grm-gipk.25's (type<<4)|state)
//   none          a computed jump with no recovered JumpTable in the decompile (msg= carries the
//                 decompiler's warning text when it printed one)
//   unreached     a computed jump inside a function body that the decompile never reached (dead
//                 or bad-data flow; no BRANCHIND for it, no warning)
//   no-branchind  RTS-trick / push-return dispatch: a return the extension gave computed-jump
//                 refs to; there is no BRANCHIND to switch on (targets= counts the refs)
// analyzer= is a best guess from the EOL comment, the override namespace and the instruction;
// "?" when none applies. Per-program summary: "SLC-SUM <lang> <program> sites=<n> kind.<k>=<n> ...".
// Env: GRM_SLC_MAX=<n> caps functions decompiled (default unlimited); GRM_SLC_TIMEOUT=<s> per
// function (default 60).
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class SwitchLabelCensus extends GhidraScript {
	private static final long DEFAULT_CASE_VALUE = 0xbad1abe1L;

	private final Map<String, Integer> kindCounts = new TreeMap<>();
	private int sites;
	private String lang;
	private String prog;

	@Override
	protected void run() throws Exception {
		lang = currentProgram.getLanguageID().getIdAsString();
		prog = currentProgram.getName().replace(' ', '_');
		int max = envInt("GRM_SLC_MAX", Integer.MAX_VALUE);
		int timeout = envInt("GRM_SLC_TIMEOUT", 60);
		SymbolTable symtab = currentProgram.getSymbolTable();

		// Candidate sites per function: instruction-level computed jumps, and override sites.
		Map<Function, Set<Address>> bySite = new LinkedHashMap<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction in = it.next();
			FlowType ft = in.getFlowType();
			if (ft.isTerminal() && hasComputedRef(in)) {
				Function f = currentProgram.getFunctionManager().getFunctionContaining(in.getMinAddress());
				emitNoBranchind(in, f);
				continue;
			}
			if (!ft.isJump() || !ft.isComputed()) {
				continue;
			}
			Function f = currentProgram.getFunctionManager().getFunctionContaining(in.getMinAddress());
			if (f == null) {
				emit(in.getMinAddress(), "none", null, false, "?", 0, 0, "none", "-", "-", false,
					" msg=no-function");
				continue;
			}
			bySite.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(in.getMinAddress());
		}
		Map<Function, Set<Address>> overrides = new LinkedHashMap<>();
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		while (fi.hasNext()) {
			Function f = fi.next();
			Namespace ov = HighFunction.findOverrideSpace(f);
			if (ov == null) {
				continue;
			}
			for (Symbol s : symtab.getChildren(ov.getSymbol())) {
				String n = s.getName();
				if (n.startsWith("jmp_")) {
					Address a = currentProgram.getAddressFactory().getAddress(n.substring(4));
					if (a != null) {
						overrides.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(a);
						bySite.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(a);
					}
				}
			}
		}

		DecompInterface ifc = new DecompInterface();
		ifc.toggleJumpLoads(true);
		ifc.openProgram(currentProgram);
		int done = 0;
		try {
			for (Map.Entry<Function, Set<Address>> e : bySite.entrySet()) {
				if (done++ >= max) {
					println("SLC " + lang + " " + prog + " capped at GRM_SLC_MAX=" + max);
					break;
				}
				Function f = e.getKey();
				Set<Address> ovSites = overrides.getOrDefault(f, Set.of());
				DecompileResults res = ifc.decompileFunction(f, timeout, monitor);
				if (!res.decompileCompleted()) {
					String msg = String.valueOf(res.getErrorMessage()).trim().replace('\n', ' ');
					for (Address a : e.getValue()) {
						emit(a, f.getName(), f, ovSites.contains(a), guess(f, a, ovSites.contains(a)),
							0, 0, "none", "-", "-", false, " msg=decompile-failed: " + msg);
					}
					continue;
				}
				HighFunction hf = res.getHighFunction();
				String c = res.getDecompiledFunction().getC();
				Set<Address> seen = new LinkedHashSet<>();
				for (JumpTable jt : hf.getJumpTables()) {
					Address a = jt.getSwitchAddress();
					seen.add(a);
					classify(f, a, ovSites.contains(a), jt);
				}
				Set<Address> bi = new LinkedHashSet<>();
				Iterator<PcodeOpAST> ops = hf.getPcodeOps();
				while (ops.hasNext()) {
					PcodeOpAST op = ops.next();
					if (op.getOpcode() == PcodeOp.BRANCHIND) {
						bi.add(op.getSeqnum().getTarget());
					}
				}
				Set<Address> rest = new LinkedHashSet<>(e.getValue());
				rest.addAll(bi);
				for (Address a : rest) {
					if (seen.contains(a)) {
						continue;
					}
					String warn = jumpWarning(c, a);
					String kind = bi.contains(a) || !warn.isEmpty() ? "none" : "unreached";
					String why = bi.contains(a) ? "branchind-without-table"
						: warn.isEmpty() ? "not-in-decompile" : "branchind-dropped";
					emit(a, f.getName(), f, ovSites.contains(a), guess(f, a, ovSites.contains(a)), 0, 0,
						kind, "-", "-", false, " msg=" + why + (warn.isEmpty() ? "" : " | " + warn));
				}
			}
		}
		finally {
			ifc.dispose();
		}
		StringBuilder sb = new StringBuilder("SLC-SUM " + lang + " " + prog + " sites=" + sites);
		for (Map.Entry<String, Integer> k : kindCounts.entrySet()) {
			sb.append(" kind.").append(k.getKey()).append('=').append(k.getValue());
		}
		println(sb.toString());
	}

	private void classify(Function f, Address site, boolean override, JumpTable jt) {
		Address[] cases = jt.getCases();
		Integer[] labels = jt.getLabelValues();
		boolean def = false;
		int nCases = 0;
		boolean allAddr = true;
		TreeSet<Long> distinct = new TreeSet<>();
		List<Long> ordered = new ArrayList<>();
		for (int i = 0; i < cases.length; i++) {
			long l = i < labels.length ? labels[i].longValue() & 0xffffffffL : -1;
			if (l == DEFAULT_CASE_VALUE) {
				def = true;
				continue;
			}
			nCases++;
			distinct.add(l);
			ordered.add(l);
			if (l != (cases[i].getOffset() & 0xffffffffL)) {
				allAddr = false;
			}
		}
		String kind;
		String min = "-";
		String max = "-";
		if (distinct.isEmpty()) {
			kind = "none";
		}
		else {
			long lo = distinct.first();
			long hi = distinct.last();
			min = Long.toHexString(lo);
			max = Long.toHexString(hi);
			long g = 0;
			for (long d : distinct) {
				g = gcd(g, d);
			}
			if (allAddr && !(distinct.size() <= 2 && lo < 16 && hi < 16 && contiguous(distinct, 1))) {
				kind = "address";
			}
			else if (contiguous(distinct, 1)) {
				kind = "index";
			}
			else if (g > 1 && lo % g == 0 && contiguous(distinct, g)) {
				kind = "offset";
			}
			else {
				kind = "composite";
			}
		}
		StringBuilder ex = new StringBuilder(" ex=");
		for (int i = 0; i < Math.min(8, ordered.size()); i++) {
			ex.append(i == 0 ? "" : ",").append(Long.toHexString(ordered.get(i)));
		}
		emit(site, f.getName(), f, override, guess(f, site, override), nCases, distinct.size(), kind,
			min, max, def, ex.toString());
	}

	private static boolean contiguous(TreeSet<Long> d, long step) {
		return (d.last() - d.first()) / step + 1 == d.size() && (d.last() - d.first()) % step == 0;
	}

	private static long gcd(long a, long b) {
		return b == 0 ? a : gcd(b, a % b);
	}

	private void emit(Address site, String fn, Function f, boolean override, String analyzer, int cases,
			int labels, String kind, String min, String max, boolean def, String tail) {
		sites++;
		kindCounts.merge(kind, 1, Integer::sum);
		println("SLC " + lang + " " + prog + " " + site.getAddressSpace().getName() + "::" +
			Long.toHexString(site.getOffset()) + " fn=" + (f == null ? "-" : f.getName()) +
			" override=" + (override ? "y" : "n") + " analyzer=" + analyzer + " cases=" + cases +
			" labels=" + labels + " kind=" + kind + " min=" + min + " max=" + max +
			" default=" + (def ? "y" : "n") + tail);
	}

	private void emitNoBranchind(Instruction in, Function f) {
		int n = 0;
		for (Reference r : in.getReferencesFrom()) {
			if (r.getReferenceType().isComputed()) {
				n++;
			}
		}
		String eol = currentProgram.getListing().getComment(CommentType.EOL, in.getMinAddress());
		String an = eol != null && eol.startsWith("65816 RTS trick") ? "W65816RtsTrick"
			: eol != null && eol.startsWith("65816 RTL trick") ? "W65816RtlTrick" : "RtsTrickDispatch?";
		emit(in.getMinAddress(), f == null ? "-" : f.getName(), f, false, an, n, n, "no-branchind", "-", "-",
			false, " targets=" + n);
	}

	private static boolean hasComputedRef(Instruction in) {
		for (Reference r : in.getReferencesFrom()) {
			if (r.getReferenceType().isComputed() && r.getReferenceType().isJump()) {
				return true;
			}
		}
		return false;
	}

	private String guess(Function f, Address site, boolean override) {
		String eol = currentProgram.getListing().getComment(CommentType.EOL, site);
		if (eol != null) {
			if (eol.contains("[JumpTableBound]")) {
				return "JumpTableBound";
			}
			if (eol.startsWith("65816 jump table")) {
				return "W65816JumpTable";
			}
			if (eol.contains("split dispatch")) {
				return "SplitDispatchTable";
			}
		}
		if (override) {
			return "TwoLevelPointerDispatch?";
		}
		return "stock/BadDataCap?";
	}

	private static String jumpWarning(String c, Address site) {
		String hex = "0x" + Long.toHexString(site.getOffset());
		for (String line : c.split("\n")) {
			String l = line.toLowerCase();
			if ((l.contains("jumptable") || l.contains("jump table")) && l.contains(hex)) {
				return line.trim().replace('\n', ' ');
			}
		}
		return "";
	}

	private static int envInt(String name, int dflt) {
		String v = System.getenv(name);
		try {
			return v == null || v.isBlank() ? dflt : Integer.parseInt(v.trim());
		}
		catch (NumberFormatException e) {
			return dflt;
		}
	}
}
