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

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NoValueException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Tracks the 65816 data-bank register DBR (bead grm-9nxj.32, first increment) and stamps it as a
 * program-context register value, the way {@link W65816DirectPageAnalyzer} does for DP.
 *
 * <p><b>Why.</b> Every absolute data operand is built by the language as
 * {@code (zext(DBR) << 16) + offset} ({@code ref_data_bank}), but nothing gave DBR a value, so the
 * decompiler read {@code *(unknown_bank:offset)} and a table read {@code LDA abs,X} kept its
 * switch labels as ADDRESS. The decompiler seeds a register's context value at a function's
 * ENTRY as a constant (grm-9nxj.37, option (c)), which is all the channel there is.
 *
 * <p><b>Design: one symbolic walk per function.</b> DBR is never computed on, only copied, set
 * from the stack ({@code PLB}) or set by {@code MVN/MVP}. So each function is walked ONCE from a
 * symbolic entry value ({@link #ENTRY}); a walk yields the symbolic DBR before every instruction
 * and the function's EXIT SUMMARY (the DBR a return carries: a constant, the entry value, or
 * unknown), and the entry seed is substituted afterwards. Summaries are solved as a program-wide
 * fixpoint (optimistic start: every function preserves; a function whose summary changes
 * re-walks its callers; at most {@link #MAX_CHANGES} changes each, then UNKNOWN).
 * The walk tracks the stack byte by byte, so {@code PHK / PLB}, {@code PEA #$7E7E / PLB},
 * {@code LDA #$7E / PHA / PLB} (M=1; M=0 pushes two bytes), {@code PHB ... PLB} and a DBR carried
 * through the stack all resolve without special cases. Widths are read from the M/X context.
 *
 * <p><b>Entry seeds.</b> As for DP: a function's entry DBR is d when at least one way into it
 * (call, jump, branch, fall-through) carries a known DBR and every known one carries d; unknown
 * ways in are ignored; disagreeing ways in leave it unknown. RESET is entered with DBR = 0 (the
 * hardware reset state); the other vectors (NMI, IRQ, ...) are entered with whatever the
 * interrupted code had, so are never seeded from the vector. A function reached from somewhere
 * unknowable (another external entry, a pointer) is left unseeded.
 *
 * <p><b>Summaries, thunks, dispatches</b> mirror the DP analyzer: a jump or branch into ANOTHER
 * function's entry is a tail exit judged by that function's summary (so a {@code JMP} thunk
 * returns what its target returns); an unconditional indirect {@code JMP}/{@code JML} is a
 * dispatch exit that hands its handler the DBR it has (rule A, optimistic); a computed
 * {@code JSR/JSL (abs,X)} with several targets returns the DBR it was given; an exit that has
 * pulled below its entry stack is ignored (it returns to an outer frame); an exit with anything
 * of its own left on the stack is UNKNOWN. A {@code JSR} to a routine that only returns by
 * {@code RTL} consumes the bank byte the caller pushed.
 *
 * <p><b>grm-9nxj.42 additions.</b> A shared epilogue ({@code ... PLB / RTL} entered by a jump
 * after the jumper's {@code PHB}, the DP analyzer's structural scan) is walked on with the
 * jumper's stack instead of judged as a tail exit, and so are the handlers of a dispatch JMP
 * that are all such epilogues (CT's sound driver). A jump or branch carrying Ghidra's
 * CALL_RETURN override is a tail exit like a plain one; a tail jump over a return address of
 * the routine's own ({@code PHK / PER / JML}) is a call that comes back. An RTL that pulls
 * below the entry does not make the routine an RTL routine. {@code TDC} reads the DP
 * analyzer's stamped DP, and {@code TAX/TAY/TXA/TYA} copy known bytes, so FF3's
 * {@code TDC / PHA / PLB} resolves. Unresolved indirect calls still leave DBR unknown: no
 * evidence says their targets preserve it.
 *
 * <p><b>Output.</b> Where DBR is known at an instruction inside a function's body it is stamped
 * as an assumed register value over that instruction (the decompiler reads only the entry
 * address; the reference analyzers read every one). Optionally ({@link #OPT_REFS}) each absolute
 * data operand under a known DBR gets a memory reference to {@code (DBR << 16) | offset} when
 * that address is in memory and the instruction has no data reference yet.
 * Calling conventions: functions whose summary is "preserves" get {@code __dbr_preserved}
 * ({@code __dp_dbr_preserved} when the DP analyzer already proved DP too); see
 * {@link #compose}.
 *
 * <p>Priority: just after {@link W65816DirectPageAnalyzer}, before the stock constant propagator.
 */
public class W65816DataBankAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 Data Bank";
	private static final String DESCRIPTION =
		"Tracks the 65816 data-bank register (PHK/PLB, PEA/PLB, LDA #/PHA/PLB, PHB...PLB, " +
			"MVN/MVP, callee exit summaries, entry seeds from callers), stamps it as an assumed " +
			"register value and assigns the DBR-preserving calling conventions (grm-9nxj.32).";

	/** User property map recording the stamps this analyzer wrote (address -> DBR stamped). */
	static final String STAMP_MAP = "W65816 DBR stamps";

	static final String OPT_REFS = "Reference absolute operands under a known DBR";
	/** GRM_DBR_NOREFS=1 turns the references off by default (census A/B for grm-9nxj.32 (c)). */
	private boolean addRefs = !"1".equals(System.getenv("GRM_DBR_NOREFS"));

	/** Unknown value. */
	static final int UNKNOWN = -1;
	/** Symbolic DBR: "whatever DBR this function was entered with". */
	static final int ENTRY = -2;
	/** Seed state: known ways in disagree. */
	private static final int CONFLICT = -3;
	/** Stack element: unknown contents below (a poisoned or restarted stack). */
	private static final int FLOOR = -3;
	private static final int STACK_LIMIT = 32;
	private static final int STEP_LIMIT = 50_000;
	private static final int MAX_CHANGES = 6;

	/** The w65816.cspec prototypes (grm-9nxj.32; forks of the vendored file, see its header). */
	static final String DBR_PRESERVED = "__dbr_preserved";
	static final String DP_DBR_PRESERVED = "__dp_dbr_preserved";

	public W65816DataBankAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before().before().before().before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program) && program.getRegister("DBR") != null;
	}

	@Override
	public void registerOptions(ghidra.framework.options.Options options, Program program) {
		options.registerOption(OPT_REFS, addRefs, null,
			"Add a data reference for each absolute operand under a known DBR (bank << 16 | offset)");
	}

	@Override
	public void optionsChanged(ghidra.framework.options.Options options, Program program) {
		addRefs = options.getBoolean(OPT_REFS, addRefs);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Engine en = new Engine(program);
		en.solveSummaries(monitor);
		en.solveSeeds(monitor);
		int stamped = 0;
		int refs = 0;
		int[] absByHow = new int[3];    // seeded, summary, local
		int[] refsByHow = new int[3];
		for (Map.Entry<Address, Map<Address, State>> e : en.states.entrySet()) {
			monitor.checkCancelled();
			Function f = program.getFunctionManager().getFunctionAt(e.getKey());
			if (f == null) {
				continue;
			}
			int seed = en.seedOf(e.getKey());
			for (Map.Entry<Address, State> s : e.getValue().entrySet()) {
				int dbr = en.resolve(s.getValue().dbr, seed);
				if (!f.getBody().contains(s.getKey())) {
					continue;
				}
				Instruction in = program.getListing().getInstructionAt(s.getKey());
				if (in == null) {
					continue;
				}
				if (dbr == UNKNOWN) {
					en.clear(in);   // an earlier, less informed run may have stamped it
					continue;
				}
				stamped += en.stamp(in, dbr) ? 1 : 0;
				boolean abs = Engine.absOperand(in) != UNKNOWN;
				// How DBR was known here: from the entry seed, through a callee's summary, or
				// locally (PLB / MVN on the way).
				int how = expand(s.getValue().dbr).contains(ENTRY) ? 0 :
					s.getValue().viaCall ? 1 : 2;
				if (abs) {
					absByHow[how]++;
				}
				if (addRefs) {
					boolean added = en.reference(in, dbr);
					refs += added ? 1 : 0;
					if (added && abs) {
						refsByHow[how]++;
					}
				}
			}
		}
		int[] cc = assignConventions(program, en, monitor);
		if (stamped > 0 || refs > 0 || cc[0] > 0 || cc[1] > 0) {
			AnalyzerLog.info(this, "DBR stamped over " + stamped + " instructions, " + refs +
				" absolute operand references added; " + en.seeded() + " function entries " +
				"seeded; " + cc[0] + " functions given a DBR-preserving convention, " + cc[1] +
				" taken off one");
			AnalyzerLog.info(this, "DBR absolute operands under a known DBR (seeded/summary/" +
				"local): " + absByHow[0] + "/" + absByHow[1] + "/" + absByHow[2] + "; new " +
				"references: " + refsByHow[0] + "/" + refsByHow[1] + "/" + refsByHow[2] +
				"; " + en.replaced + " wrong-bank references replaced");
		}
		return true;
	}

	/** Read-only census hook (like {@code W65816DirectPageAnalyzer.CallSummaries}). */
	public static final class CallSummaries {
		private final Engine en;

		public CallSummaries(Program program) {
			en = new Engine(program);
			try {
				en.solveSummaries(TaskMonitor.DUMMY);
			}
			catch (CancelledException e) {
				// cannot happen with the dummy monitor
			}
		}

		/** {@code "preserves"}, {@code "$XX"} (returns that bank) or {@code "UNKNOWN"}. */
		public String verdict(Address target) {
			return en.verdict(target);
		}

		/** Why the summary is UNKNOWN, or null. */
		public String why(Address target) {
			return en.why.get(target);
		}
	}

	/**
	 * Read-only census hook (grm-9nxj.42): why absolute operands still have no known DBR, and
	 * the analyzer's own per-instruction state for named functions. Solves summaries and seeds
	 * once, afresh; changes nothing.
	 */
	public static final class Diagnostics {
		private final Engine en;

		public Diagnostics(Program program) {
			en = new Engine(program);
			try {
				en.solveSummaries(TaskMonitor.DUMMY);
				en.solveSeeds(TaskMonitor.DUMMY);
			}
			catch (CancelledException e) {
				// cannot happen with the dummy monitor
			}
		}

		/** Lost operands by cause, root causes behind unseeded entries, top callees. */
		public List<String> lossReport(int top) {
			return en.lossReport(top);
		}

		/** The walk's state before each instruction of the function at {@code entry}. */
		public List<String> states(Address entry) {
			List<String> out = new ArrayList<>();
			Map<Address, State> m = en.states.get(entry);
			out.add("seed=" + en.seedOf(entry) + " summary=" + en.verdict(entry) + " why=" +
				en.why.get(entry) + " walked=" + (m == null ? "none" : m.size()));
			if (m == null) {
				return out;
			}
			List<Address> keys = new ArrayList<>(m.keySet());
			java.util.Collections.sort(keys);
			for (Address a : keys) {
				State s = m.get(a);
				out.add(a + " dbr=" + show(s.dbr) + " stack=" + s.stack + (s.under ? " under" : ""));
			}
			return out;
		}

		private static String show(int v) {
			StringBuilder sb = new StringBuilder();
			for (int x : expand(v)) {
				sb.append(sb.length() == 0 ? "" : "|").append(x == ENTRY ? "E" :
					x == UNKNOWN ? "?" : String.format("%02x", x));
			}
			return sb.toString();
		}
	}

	// ---- calling conventions -------------------------------------------------------------

	static boolean hasDp(String cur) {
		return W65816DirectPageAnalyzer.DP_PRESERVED.equals(cur) || DP_DBR_PRESERVED.equals(cur);
	}

	static boolean hasDbr(String cur) {
		return DBR_PRESERVED.equals(cur) || DP_DBR_PRESERVED.equals(cur);
	}

	/** One of our prototypes (any of the three preserving ones). */
	static boolean isOurs(String cur) {
		return hasDp(cur) || hasDbr(cur);
	}

	/** The prototype for a pair of verdicts, or the unknown convention string for neither. */
	static String compose(boolean dp, boolean dbr) {
		if (dp && dbr) {
			return DP_DBR_PRESERVED;
		}
		return dp ? W65816DirectPageAnalyzer.DP_PRESERVED :
			dbr ? DBR_PRESERVED : Function.UNKNOWN_CALLING_CONVENTION_STRING;
	}

	/**
	 * Sets the DBR half of each function's prototype from the summary, keeping the DP half the
	 * DP analyzer set (it runs first and owns it). Only a function with no convention of its own
	 * or one of ours is touched; thunks are skipped.
	 *
	 * @return {changed to a prototype with DBR, taken off DBR} counts
	 */
	private static int[] assignConventions(Program program, Engine en, TaskMonitor monitor)
			throws CancelledException {
		int[] n = new int[2];
		var fm = program.getFunctionManager();
		if (fm.getCallingConvention(DBR_PRESERVED) == null ||
			fm.getCallingConvention(DP_DBR_PRESERVED) == null) {
			return n;
		}
		var dfltModel = fm.getDefaultCallingConvention();
		String dflt = dfltModel == null ? null : dfltModel.getName();
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			String cur = f.getCallingConventionName();
			boolean unset = cur == null || cur.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) ||
				cur.equals(Function.DEFAULT_CALLING_CONVENTION_STRING) || cur.equals(dflt);
			if (!unset && !isOurs(cur)) {
				continue;   // a convention someone chose: never override it
			}
			boolean keeps = en.preserves(f.getEntryPoint());
			String want = compose(hasDp(cur), keeps);
			if (want.equals(cur) || (unset && Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(want))) {
				continue;
			}
			try {
				f.setCallingConvention(want);
				if (keeps && !hasDbr(cur)) {
					n[0]++;
				}
				else if (!keeps && hasDbr(cur)) {
					n[1]++;
				}
			}
			catch (InvalidInputException e) {
				return n;
			}
		}
		return n;
	}

	// ---- values --------------------------------------------------------------------------

	/**
	 * A DBR value is a byte, {@link #ENTRY}, {@link #UNKNOWN}, or an id at or above
	 * {@link #SET_BASE} naming a small set of the others (at most {@link #SET_MAX}, none UNKNOWN):
	 * the DBR on one of several paths that merged. The merge keeps the alternatives, so a routine
	 * that exits with its entry DBR on one path and bank 0 on another stays exact for a caller
	 * whose DBR is 0 (a flat merge would lose both).
	 */
	private static final int SET_BASE = 1000;
	private static final int SET_MAX = 4;
	private static final List<List<Integer>> SET_TABLE = new ArrayList<>();
	private static final Map<List<Integer>, Integer> SET_IDS = new HashMap<>();

	/** The members of a value. */
	static synchronized Set<Integer> expand(int v) {
		return v >= SET_BASE ? new java.util.LinkedHashSet<>(SET_TABLE.get(v - SET_BASE)) :
			new java.util.LinkedHashSet<>(List.of(v));
	}

	/** The value for a set of members: UNKNOWN if any is, the member if one, else an id. */
	static synchronized int fromSet(Set<Integer> members) {
		if (members.isEmpty() || members.contains(UNKNOWN) || members.size() > SET_MAX) {
			return UNKNOWN;
		}
		if (members.size() == 1) {
			return members.iterator().next();
		}
		List<Integer> key = new ArrayList<>(new java.util.TreeSet<>(members));
		Integer id = SET_IDS.get(key);
		if (id == null) {
			id = SET_BASE + SET_TABLE.size();
			SET_TABLE.add(key);
			SET_IDS.put(key, id);
		}
		return id;
	}

	/** The value of a path that is either of two. */
	static int join(int a, int b) {
		if (a == b) {
			return a;
		}
		if (a == UNKNOWN || b == UNKNOWN) {
			return UNKNOWN;
		}
		Set<Integer> m = expand(a);
		m.addAll(expand(b));
		return fromSet(m);
	}

	// ---- state ---------------------------------------------------------------------------

	/**
	 * Dataflow state before an instruction. The register halves are bytes or UNKNOWN; the stack
	 * is bottom to top, bytes, ENTRY (a pushed entry DBR) or UNKNOWN, with {@link #FLOOR} at the
	 * bottom of a restarted stack; {@code under} means the path pulled below its entry stack.
	 */
	record State(int dbr, int aLo, int aHi, int xLo, int xHi, int yLo, int yHi,
			List<Integer> stack, boolean under, boolean viaCall) {

		State withDbr(int d) {
			return new State(d, aLo, aHi, xLo, xHi, yLo, yHi, stack, under, false);
		}

		State withStack(List<Integer> st, boolean u) {
			return new State(dbr, aLo, aHi, xLo, xHi, yLo, yHi, st, u, viaCall);
		}

		State withA(int lo, int hi) {
			return new State(dbr, lo, hi, xLo, xHi, yLo, yHi, stack, under, viaCall);
		}

		State withX(int lo, int hi) {
			return new State(dbr, aLo, aHi, lo, hi, yLo, yHi, stack, under, viaCall);
		}

		State withY(int lo, int hi) {
			return new State(dbr, aLo, aHi, xLo, xHi, lo, hi, stack, under, viaCall);
		}

		State meet(State o) {
			return new State(join(dbr, o.dbr), aLo == o.aLo ? aLo : UNKNOWN,
				aHi == o.aHi ? aHi : UNKNOWN, xLo == o.xLo ? xLo : UNKNOWN,
				xHi == o.xHi ? xHi : UNKNOWN, yLo == o.yLo ? yLo : UNKNOWN,
				yHi == o.yHi ? yHi : UNKNOWN, meetStack(stack, o.stack),
				// AND, not OR: a path that pulls "below the entry" only because an unrolled loop's
				// earlier pass pushed less must not hide the exit the other paths reach; an
				// ignored exit is the unsound direction, an included one only costs precision.
				under && o.under, viaCall || o.viaCall);
		}

		private static List<Integer> meetStack(List<Integer> p, List<Integer> q) {
			if (p.equals(q)) {
				return p;
			}
			if (p.size() == q.size()) {
				// Same depth: keep each slot's alternatives (a PHB'd DBR that is itself a set).
				List<Integer> j = new ArrayList<>(p.size());
				for (int i = 0; i < p.size(); i++) {
					int a = p.get(i);
					int b = q.get(i);
					if (a != b && (a == FLOOR || b == FLOOR)) {
						j = null;
						break;
					}
					j.add(join(a, b));
				}
				if (j != null) {
					return List.copyOf(j);
				}
			}
			int k = 0;
			while (k < p.size() && k < q.size() &&
				p.get(p.size() - 1 - k).equals(q.get(q.size() - 1 - k))) {
				k++;
			}
			if (k == 0) {
				return POISONED;
			}
			List<Integer> top = p.subList(p.size() - k, p.size());
			if (top.get(0) == FLOOR) {
				return List.copyOf(top);
			}
			List<Integer> out = new ArrayList<>(k + 1);
			out.add(FLOOR);
			out.addAll(top);
			return List.copyOf(out);
		}
	}

	private static final List<Integer> POISONED = List.of(FLOOR);

	private static final State ENTRY_STATE =
		new State(ENTRY, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, List.of(), false, false);

	/** A function's exit summary: the DBR its returns carry, and how it returns. */
	record Summary(Set<Integer> outs, Set<String> kinds) {

		/**
		 * The DBR after a call from a caller holding {@code caller} (a constant, {@link #ENTRY}
		 * for the caller's own entry value, or UNKNOWN): the one value every exit agrees on once
		 * the callee's ENTRY is read as the caller's DBR, else UNKNOWN. So a routine that exits
		 * with its entry DBR on one path and bank 0 on another is exact for a caller in bank 0.
		 */
		int apply(int caller) {
			return fromSet(mapped(caller));
		}

		/** Each exit's value in the caller's terms (a caller value that is a set contributes all). */
		Set<Integer> mapped(int caller) {
			Set<Integer> out = new java.util.LinkedHashSet<>();
			for (int v : outs) {
				if (v == ENTRY) {
					out.addAll(expand(caller));
				}
				else {
					out.add(v);
				}
			}
			return out;
		}

		boolean preserves() {
			return outs.equals(Set.of(ENTRY));
		}
	}

	private static final Summary OPTIMISTIC = new Summary(Set.of(ENTRY), Set.of());

	// ---- the engine ----------------------------------------------------------------------

	/** The walks, summaries and seeds for one program. Package-private for tests and probes. */
	static final class Engine {
		private final Program program;
		private final Register ctxM;
		private final Register ctxX;
		private final Register dbrReg;
		private final Register dpReg;
		private final Register[] tracked;   // C, X, Y, SP, DBR

		final Map<Address, Map<Address, State>> states = new LinkedHashMap<>();
		private final Map<Address, Summary> summaries = new HashMap<>();
		private final Map<Address, Integer> changes = new HashMap<>();
		private final Set<Address> frozen = new HashSet<>();
		private final Map<Address, Set<Address>> dependents = new HashMap<>();
		private final ArrayDeque<Address> work = new ArrayDeque<>();
		private final Set<Address> queued = new HashSet<>();
		private final Map<Address, Boolean> noReturn = new HashMap<>();
		private final Map<Address, Integer> seeds = new HashMap<>();
		private Address current;
		/** Wrong-bank operand references replaced by {@link #reference}. */
		int replaced;
		/** Why a summary is UNKNOWN (probes only; the last judgement wins unless first-recorded). */
		private final Map<Address, String> why = new HashMap<>();

		Engine(Program program) {
			this.program = program;
			ctxM = program.getRegister("ctx_MF");
			ctxX = program.getRegister("ctx_XF");
			dbrReg = program.getRegister("DBR");
			dpReg = program.getRegister("DP");
			tracked = new Register[] { program.getRegister("C"), program.getRegister("X"),
				program.getRegister("Y"), program.getRegister("SP"), dbrReg };
			scanUserValues();
		}

		/** DBR values set by the user (Set Register Values) or another analyzer, by instruction. */
		private final Map<Address, Integer> userVals = new HashMap<>();

		// -- summaries --

		void solveSummaries(TaskMonitor monitor) throws CancelledException {
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				enqueue(f.getEntryPoint());
			}
			while (!work.isEmpty()) {
				monitor.checkCancelled();
				Address root = work.poll();
				queued.remove(root);
				current = root;
				Map<Address, State> in = walk(root, false);
				if (program.getFunctionManager().getFunctionAt(root) != null) {
					// The stamp/seed walk also follows dispatch JMPs into handlers of the body.
					states.put(root, walk(root, true));
				}
				Summary now = summarize(root, in);
				Summary was = summaries.get(root);
				if (frozen.contains(root) || now.equals(was)) {
					continue;
				}
				int c = changes.merge(root, 1, Integer::sum);
				if (c > MAX_CHANGES) {
					now = new Summary(Set.of(UNKNOWN), now.kinds());
					frozen.add(root);
				}
				summaries.put(root, now);
				for (Address d : dependents.getOrDefault(root, Set.of())) {
					enqueue(d);
				}
			}
			current = null;
		}

		private void enqueue(Address root) {
			summaries.putIfAbsent(root, OPTIMISTIC);
			if (queued.add(root)) {
				work.add(root);
			}
		}

		/** The summary of a call/tail target; records the dependency of the walk in progress. */
		private Summary summaryOf(Address target) {
			if (current != null) {
				dependents.computeIfAbsent(target, k -> new LinkedHashSet<>()).add(current);
			}
			Summary s = summaries.get(target);
			if (s == null) {
				enqueue(target);
				s = OPTIMISTIC;
			}
			return s;
		}

		/** Whether a call to {@code target} provably leaves DBR as it was. */
		boolean preserves(Address target) {
			Summary s = summaries.get(target);
			return s != null && s.preserves();
		}

		/** The summary verdict for probes: "preserves", "$XX" or "UNKNOWN". */
		String verdict(Address target) {
			Summary s = summaries.get(target);
			if (s == null || s.outs.contains(UNKNOWN)) {
				return "UNKNOWN";
			}
			if (s.preserves()) {
				return "preserves";
			}
			StringBuilder sb = new StringBuilder();
			for (int v : s.outs) {
				sb.append(sb.length() == 0 ? "" : "|").append(
					v == ENTRY ? "entry" : String.format("$%02X", v));
			}
			return sb.toString();
		}

		// -- the walk --

		private boolean otherEntry(Address root, Address a) {
			return !a.equals(root) && program.getFunctionManager().getFunctionAt(a) != null;
		}

		private final Map<Address, Boolean> epilogues = new HashMap<>();

		/**
		 * Whether flow from {@code root}'s walk into {@code a} leaves it as a tail exit judged by
		 * {@code a}'s summary: {@code a} is another function's entry that is not a shared epilogue.
		 * A shared epilogue ({@code ... PLB / RTL} entered by a jump after the jumper's
		 * {@code PHB}; grm-9nxj.42, the DP analyzer's structural {@code scanEpilogue}) is walked
		 * on with the jumper's stack instead, so its {@code PLB} pulls the jumper's {@code PHB}.
		 * Judged alone it pulls below its entry and has no exit of its own.
		 */
		private boolean tailExit(Address root, Address a) {
			return otherEntry(root, a) && !isEpilogue(a);
		}

		private boolean isEpilogue(Address a) {
			return epilogues.computeIfAbsent(a,
				t -> W65816DirectPageAnalyzer.isSharedEpilogue(program, t));
		}

		/**
		 * A dispatch JMP whose resolved handlers are all shared epilogues (grm-9nxj.42): CT's
		 * sound driver {@code $C7:0140} ({@code PHB / PHD / ... / PLB / JMP ($0AD9,X)}, every
		 * handler leaving through the code that pulls that frame, as FF3's {@code $C5:0160} does
		 * for DP, grm-hf5h.26). A summary walk follows it instead of taking it as a rule-A exit,
		 * so the handlers' {@code PLB} pulls the dispatcher's {@code PHB} and the routine's
		 * exits are its RTLs.
		 */
		private boolean intoEpilogues(Instruction ins) {
			Address[] fl = ins.getFlows();
			if (fl.length == 0) {
				return false;
			}
			for (Address a : fl) {
				if (!isEpilogue(a)) {
					return false;
				}
			}
			return true;
		}

		/** A jump that is a call through a pushed return address: where it returns, and how. */
		record PushedCall(Address cont, State after) {
		}

		/**
		 * A tail jump into another routine reached with a known return address of this
		 * routine's own on top of the stack: F-Zero's far call {@code PHK / PER ret-1 / JML f}
		 * ({@code $00:8EAA}), or {@code PEA ret-1 / JMP f} for an RTS routine. When every exit
		 * of {@code f} is one RTL (three bytes: bank, high, low) or one RTS (two), control comes
		 * back to {@code ret} in this routine with those bytes pulled and {@code f}'s summary
		 * applied: the jump is a call, not an exit (grm-9nxj.42). Without it such a jump was a
		 * tail exit with bytes of its own on the stack, an UNKNOWN summary. Null otherwise.
		 */
		private PushedCall pushedCall(Address root, Instruction ins, State st) {
			if (st == null || !isTailJump(ins) || !tailExit(root, ins.getFlows()[0])) {
				return null;
			}
			Summary sm = summaryOf(ins.getFlows()[0]);
			int n = sm.kinds.equals(Set.of("RTL")) ? 3 : sm.kinds.equals(Set.of("RTS")) ? 2 : 0;
			List<Integer> stk = st.stack;
			int size = stk.size();
			if (n == 0 || size < n) {
				return null;
			}
			int lo = stk.get(size - 1);
			int hi = stk.get(size - 2);
			// An RTS returns in the bank it runs in: the target's (a JML into an RTS routine).
			int bank = n == 3 ? stk.get(size - 3) :
				(int) ((ins.getFlows()[0].getOffset() >> 16) & 0xff);
			if (lo < 0 || hi < 0 || bank < 0 || lo >= SET_BASE || hi >= SET_BASE ||
				bank >= SET_BASE) {
				return null;
			}
			long ret = (long) bank << 16 | (((hi << 8 | lo) + 1) & 0xffff);
			Address cont = ins.getAddress().getAddressSpace().getAddress(ret);
			if (program.getListing().getInstructionAt(cont) == null || tailExit(root, cont)) {
				return null;   // no code there, or another routine's entry: not followed
			}
			int dbr = sm.apply(st.dbr);
			State after = new State(dbr, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN,
				List.copyOf(stk.subList(0, size - n)), st.under, st.viaCall || dbr != st.dbr);
			return new PushedCall(cont, after);
		}

		/**
		 * @param dispatch follow an indirect JMP/JML's resolved targets inside the body (for
		 *     stamping and seeding); a summary walk does not, rule A treats the jump as an exit
		 */
		private Map<Address, State> walk(Address root, boolean dispatch) {
			Map<Address, State> in = new LinkedHashMap<>();
			ArrayDeque<Address> q = new ArrayDeque<>();
			in.put(root, ENTRY_STATE);
			q.add(root);
			int steps = 0;
			while (!q.isEmpty() && steps++ < STEP_LIMIT) {
				Address at = q.poll();
				Instruction ins = program.getListing().getInstructionAt(at);
				if (ins == null) {
					continue;
				}
				PushedCall pc = pushedCall(root, ins, in.get(at));
				State out = pc != null ? pc.after() : transfer(ins, in.get(at));
				for (Address next : pc != null ? List.of(pc.cont()) :
					successors(root, ins, dispatch)) {
					State old = in.get(next);
					State merged = old == null ? out : old.meet(out);
					Integer user = userVals.get(next);
					if (user != null && !next.equals(root)) {
						merged = merged.withDbr(user);   // the user's claim is authoritative here
					}
					if (!merged.equals(old)) {
						in.put(next, merged);
						q.add(next);
					}
				}
			}
			if (!q.isEmpty()) {
				return new LinkedHashMap<>();   // gave up: claim nothing
			}
			return in;
		}

		private static boolean isCallInstr(Instruction ins) {
			String mn = ins.getMnemonicString();
			return mn.equalsIgnoreCase("JSR") || mn.equalsIgnoreCase("JSL");
		}

		private static boolean isReturn(Instruction ins) {
			String mn = ins.getMnemonicString();
			return mn.equalsIgnoreCase("RTS") || mn.equalsIgnoreCase("RTL");
		}

		/**
		 * A direct jump or branch with one target that may be a tail exit: a plain jump, or one
		 * carrying Ghidra's CALL_RETURN override (FF3 {@code $C1:191D BRA}: a terminal call
		 * flow). Missing the override left such routines with no exit
		 * at all and an UNKNOWN summary (grm-9nxj.42).
		 */
		private static boolean isTailJump(Instruction ins) {
			var ft = ins.getFlowType();
			return !isCallInstr(ins) && !ft.isComputed() && ins.getFlows().length == 1 &&
				(ft.isJump() || (ft.isCall() && ft.isTerminal()));
		}

		/** Unconditional indirect JMP/JML: rule A, a dispatch exit (as the DP analyzer). */
		private static boolean isDispatchJmp(Instruction ins) {
			var ft = ins.getFlowType();
			String mn = ins.getMnemonicString();
			return ft.isComputed() && !ft.isConditional() && !isCallInstr(ins) &&
				(mn.equalsIgnoreCase("JMP") || mn.equalsIgnoreCase("JML"));
		}

		private List<Address> successors(Address root, Instruction ins, boolean dispatch) {
			List<Address> out = new ArrayList<>();
			var ft = ins.getFlowType();
			if (isDispatchJmp(ins) && (dispatch || intoEpilogues(ins))) {
				for (Address a : ins.getFlows()) {
					if (!tailExit(root, a)) {
						out.add(a);
					}
				}
				return out;
			}
			if (isReturn(ins) || isDispatchJmp(ins)) {
				return out;
			}
			if (isCallInstr(ins)) {
				if (!ft.isTerminal() && ins.getFallThrough() != null) {
					out.add(ins.getFallThrough());
				}
				return out;
			}
			if (ft.isComputed()) {
				return out;
			}
			for (Address a : ins.getFlows()) {
				if (!tailExit(root, a)) {
					out.add(a);
				}
			}
			if (ins.hasFallthrough() && ins.getFallThrough() != null) {
				out.add(ins.getFallThrough());
			}
			return out;
		}

		/** The summary of a walk: its exits, combined. */
		private Summary summarize(Address root, Map<Address, State> in) {
			why.remove(root);
			Set<Integer> outs = new java.util.LinkedHashSet<>();
			Set<String> kinds = new HashSet<>();
			int unders = 0;
			int noRetTails = 0;
			String underAt = null;
			for (Map.Entry<Address, State> e : in.entrySet()) {
				Instruction ins = program.getListing().getInstructionAt(e.getKey());
				if (ins == null) {
					continue;
				}
				State st = e.getValue();
				Set<Integer> out;
				Set<String> k;
				if (isReturn(ins)) {
					out = expand(st.dbr);
					k = Set.of(ins.getMnemonicString().toUpperCase(Locale.ROOT));
				}
				else if (isDispatchJmp(ins) && !intoEpilogues(ins)) {
					out = expand(st.dbr);
					k = Set.of("?");
				}
				else if (isTailJump(ins) && tailExit(root, ins.getFlows()[0])) {
					if (pushedCall(root, ins, st) != null) {
						continue;   // a call: it comes back into this routine
					}
					Address t = ins.getFlows()[0];
					if (neverReturns(t)) {
						noRetTails++;
						continue;
					}
					Summary ts = summaryOf(t);
					out = ts.mapped(st.dbr);
					k = (ts.kinds.isEmpty() ? Set.of("?") : ts.kinds);
				}
				else {
					continue;
				}
				if (st.under) {
					unders++;
					if (underAt == null) {
						underAt = e.getKey() + " " + ins;
					}
					continue;   // returns to an outer frame, not to the caller
				}
				// Only counted exits say how the routine returns: an RTL that pulls below the
				// entry (a JSR'd helper jumping into its caller's PLB / RTL epilogue, CT
				// $C7:0A39) returns for an outer frame, and must not make a JSR caller pop
				// a bank byte or poison its stack (grm-9nxj.42).
				kinds.addAll(k);
				String why = null;
				if (!st.stack.isEmpty() && !st.stack.equals(POISONED)) {
					out = Set.of(UNKNOWN);
					why = "non-empty stack " + st.stack;
				}
				else if (out.contains(UNKNOWN)) {
					why = "exit with unknown DBR";
				}
				if (why != null) {
					this.why.putIfAbsent(root, why + " at " + e.getKey() + " " + ins);
				}
				outs.addAll(out);
			}
			if (outs.isEmpty()) {
				why.putIfAbsent(root, in.isEmpty() ? "walk empty/gave up" : "no exit reached" +
					" (under=" + unders + (underAt == null ? "" : " first " + underAt) +
					", noReturnTails=" + noRetTails + ")");
				outs.add(UNKNOWN);
			}
			if (outs.contains(UNKNOWN)) {
				outs.clear();   // one canonical form
				outs.add(UNKNOWN);
			}
			return new Summary(Set.copyOf(outs), Set.copyOf(kinds));
		}

		private boolean neverReturns(Address a) {
			return noReturn.computeIfAbsent(a, t -> {
				Boolean scanned = W65816NoReturnProof.neverReturns(program, t);
				if (scanned != null) {
					return scanned;
				}
				Function fn = program.getFunctionManager().getFunctionAt(t);
				if (fn != null && fn.isThunk()) {
					fn = fn.getThunkedFunction(true);
				}
				return fn != null && fn.hasNoReturn();
			});
		}

		// -- transfer --

		private int width(Instruction ins, Register flag) {
			BigInteger v = flag == null ? null : ins.getValue(flag, false);
			return v == null ? UNKNOWN : (v.signum() == 0 ? 2 : 1);
		}

		private static int scalarOf(Instruction ins) {
			if (ins.getNumOperands() < 1) {
				return UNKNOWN;
			}
			for (Object o : ins.getOpObjects(0)) {
				if (o instanceof Scalar s) {
					return (int) (s.getUnsignedValue() & 0xffff);
				}
			}
			return UNKNOWN;
		}

		private static boolean isImmediate(Instruction ins) {
			return ins.getNumOperands() >= 1 &&
				ins.getDefaultOperandRepresentation(0).startsWith("#");
		}

		private static State push(State s, int b) {
			if (s.stack.size() >= STACK_LIMIT) {
				return s.withStack(POISONED, s.under);
			}
			List<Integer> l = new ArrayList<>(s.stack);
			l.add(b);
			return s.withStack(List.copyOf(l), s.under);
		}

		/** Pops one byte; the byte is the first element of the result. */
		private static Object[] pop(State s) {
			if (s.stack.isEmpty()) {
				return new Object[] { UNKNOWN, s.withStack(s.stack, true) };
			}
			int top = s.stack.get(s.stack.size() - 1);
			if (top == FLOOR) {
				return new Object[] { UNKNOWN, s };
			}
			return new Object[] { top, s.withStack(List.copyOf(s.stack.subList(0, s.stack.size() - 1)),
				s.under) };
		}

		private static State pushReg(State s, int w, int lo, int hi) {
			if (w == UNKNOWN) {
				return s.withStack(POISONED, s.under);
			}
			if (w == 2) {
				s = push(s, hi);
			}
			return push(s, lo);
		}

		/** Pulls a register's bytes; the result is {lo, hi, state}. */
		private static Object[] pull(State s, int w) {
			if (w == UNKNOWN) {
				return new Object[] { UNKNOWN, UNKNOWN, s.withStack(POISONED, s.under) };
			}
			Object[] r = pop(s);
			int lo = (Integer) r[0];
			s = (State) r[1];
			int hi = UNKNOWN;
			if (w == 2) {
				r = pop(s);
				hi = (Integer) r[0];
				s = (State) r[1];
			}
			return new Object[] { lo, hi, s };
		}

		State transfer(Instruction ins, State s) {
			String mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
			switch (mn) {
				case "LDA": {
					if (!isImmediate(ins)) {
						return s.withA(UNKNOWN, UNKNOWN);
					}
					int v = scalarOf(ins);
					if (v == UNKNOWN) {
						return s.withA(UNKNOWN, UNKNOWN);
					}
					return ins.getLength() == 3 ? s.withA(v & 0xff, v >> 8) :
						s.withA(v & 0xff, s.aHi);
				}
				case "LDX", "LDY": {
					boolean x = mn.equals("LDX");
					int v = isImmediate(ins) ? scalarOf(ins) : UNKNOWN;
					int lo = v == UNKNOWN ? UNKNOWN : v & 0xff;
					int hi = v == UNKNOWN ? UNKNOWN : ins.getLength() == 3 ? v >> 8 : 0;
					return x ? s.withX(lo, hi) : s.withY(lo, hi);
				}
				case "TDC": {
					// A = DP, from the DP analyzer's (or the user's) stamped value: FF3's
					// TDC / PHA / PLB sets DBR to DP's low byte (grm-9nxj.42).
					BigInteger d = dpReg == null ? null : ins.getValue(dpReg, false);
					if (d == null) {
						return s.withA(UNKNOWN, UNKNOWN);
					}
					int v = d.intValue() & 0xffff;
					return s.withA(v & 0xff, v >> 8);
				}
				case "TAX", "TAY": {
					int w = width(ins, ctxX);
					int lo = w == UNKNOWN ? UNKNOWN : s.aLo;
					int hi = w == 2 ? s.aHi : w == 1 ? 0 : UNKNOWN;
					return mn.equals("TAX") ? s.withX(lo, hi) : s.withY(lo, hi);
				}
				case "TXA", "TYA": {
					int w = width(ins, ctxM);
					int lo = mn.equals("TXA") ? s.xLo : s.yLo;
					int hi = mn.equals("TXA") ? s.xHi : s.yHi;
					return w == 2 ? s.withA(lo, hi) : w == 1 ? s.withA(lo, s.aHi) :
						s.withA(UNKNOWN, UNKNOWN);
				}
				case "XBA":
					return s.withA(s.aHi, s.aLo);
				case "PHA":
					return pushReg(s, width(ins, ctxM), s.aLo, s.aHi);
				case "PHX":
					return pushReg(s, width(ins, ctxX), s.xLo, s.xHi);
				case "PHY":
					return pushReg(s, width(ins, ctxX), s.yLo, s.yHi);
				case "PHB":
					return push(s, s.dbr);
				case "PHK":
					return push(s, (int) ((ins.getAddress().getOffset() >> 16) & 0xff));
				case "PHD", "PEI":
					return push(push(s, UNKNOWN), UNKNOWN);
				case "PER": {
					// Pushes the address of the next instruction plus the displacement (a return
					// address for F-Zero's PHK / PER / JML far call).
					int v = UNKNOWN;
					try {
						int disp = (short) ((ins.getByte(1) & 0xff) | (ins.getByte(2) & 0xff) << 8);
						v = (int) ((ins.getAddress().getOffset() + 3 + disp) & 0xffff);
					}
					catch (ghidra.program.model.mem.MemoryAccessException e) {
						// leave unknown
					}
					return push(push(s, v == UNKNOWN ? UNKNOWN : v >> 8),
						v == UNKNOWN ? UNKNOWN : v & 0xff);
				}
				case "PHP":
					return push(s, UNKNOWN);
				case "PEA": {
					int v = scalarOf(ins);
					return push(push(s, v == UNKNOWN ? UNKNOWN : v >> 8),
						v == UNKNOWN ? UNKNOWN : v & 0xff);
				}
				case "PLA": {
					int w = width(ins, ctxM);
					Object[] r = pull(s, w);
					State n = (State) r[2];
					return w == 2 ? n.withA((Integer) r[0], (Integer) r[1]) :
						n.withA((Integer) r[0], w == 1 ? n.aHi : UNKNOWN);
				}
				case "PLX", "PLY": {
					int w = width(ins, ctxX);
					Object[] r = pull(s, w);
					State n = (State) r[2];
					int hi = w == 2 ? (Integer) r[1] : w == 1 ? 0 : UNKNOWN;
					return mn.equals("PLX") ? n.withX((Integer) r[0], hi) :
						n.withY((Integer) r[0], hi);
				}
				case "PLB": {
					Object[] r = pop(s);
					return ((State) r[1]).withDbr((Integer) r[0]);
				}
				case "PLD": {
					return (State) pull(s, 2)[2];
				}
				case "PLP", "SEP", "REP", "XCE": {
					State n = mn.equals("PLP") ? (State) pull(s, 1)[2] : s;
					// A change of X width zeroes or exposes the index registers' high bytes.
					return n.withX(n.xLo, UNKNOWN).withY(n.yLo, UNKNOWN);
				}
				case "MVN", "MVP": {
					int dest = UNKNOWN;
					try {
						dest = ins.getByte(1) & 0xff;
					}
					catch (ghidra.program.model.mem.MemoryAccessException e) {
						// leave unknown
					}
					return generic(ins, s).withDbr(dest);
				}
				case "JSR", "JSL":
					return afterCall(ins, s);
				default:
					return generic(ins, s);
			}
		}

		private State afterCall(Instruction ins, State s) {
			Address[] flows = ins.getFlows();
			int dbr = UNKNOWN;
			List<Integer> stack = s.stack;
			if (flows.length == 1) {
				Summary sm = summaryOf(flows[0]);
				dbr = sm.apply(s.dbr);
				if (ins.getMnemonicString().equalsIgnoreCase("JSR") && sm.kinds.contains("RTL")) {
					if (sm.kinds.size() == 1) {
						// A JSR into a routine that returns by RTL also pulls the bank the caller
						// pushed (FZero's PHK / JSR thunk), as the DP analyzer models.
						stack = ((State) pop(s)[1]).stack;
					}
					else if (!sm.kinds.contains("?")) {
						stack = POISONED;   // returns both ways: the stack depth is not known
					}
				}
			}
			else if (flows.length > 1 && ins.getFlowType().isComputed()) {
				dbr = s.dbr;   // rule A for computed calls, as the DP analyzer
			}
			return new State(dbr, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, stack,
				s.under, s.viaCall || (flows.length >= 1 && dbr != s.dbr));
		}

		/** Anything unrecognized: forget what its p-code writes. */
		private State generic(Instruction ins, State s) {
			State r = s;
			for (PcodeOp op : ins.getPcode()) {
				Varnode out = op.getOutput();
				if (out == null || !out.isRegister()) {
					continue;
				}
				for (int i = 0; i < tracked.length; i++) {
					Register reg = tracked[i];
					if (reg == null || !overlaps(out, reg)) {
						continue;
					}
					switch (i) {
						case 0 -> r = r.withA(UNKNOWN, UNKNOWN);
						case 1 -> r = r.withX(UNKNOWN, UNKNOWN);
						case 2 -> r = r.withY(UNKNOWN, UNKNOWN);
						case 3 -> r = r.withStack(POISONED, r.under);
						default -> r = r.withDbr(UNKNOWN);
					}
				}
			}
			return r;
		}

		private static boolean overlaps(Varnode v, Register r) {
			long lo = v.getOffset();
			long hi = lo + v.getSize();
			long rlo = r.getAddress().getOffset();
			long rhi = rlo + r.getMinimumByteSize();
			return lo < rhi && rlo < hi;
		}

		// -- entry seeds --

		int seedOf(Address root) {
			Integer s = seeds.get(root);
			return s == null || s == CONFLICT ? UNKNOWN : s;
		}

		int seeded() {
			int n = 0;
			for (int v : seeds.values()) {
				n += v >= 0 ? 1 : 0;
			}
			return n;
		}

		int resolve(int v, int seed) {
			Set<Integer> m = new java.util.LinkedHashSet<>();
			for (int x : expand(v)) {
				m.add(x == ENTRY ? seed : x);
			}
			int r = fromSet(m);
			return r >= 0 && r < SET_BASE ? r : UNKNOWN;   // one known bank, or nothing
		}

		private boolean isReset(Address entry) {
			for (Symbol sym : program.getSymbolTable().getSymbols(entry)) {
				if (sym.getName().equals("RESET")) {
					return true;
				}
			}
			return false;
		}

		private List<Function> functionsAt(Address a) {
			List<Function> out = new ArrayList<>();
			program.getFunctionManager().getFunctionsOverlapping(new AddressSet(a))
					.forEachRemaining(out::add);
			return out;
		}

		/** Ways into {@code g}'s entry; null when one is unknowable. */
		private List<Address> entrySources(Function g, boolean reset) {
			Address entry = g.getEntryPoint();
			if (!reset && program.getSymbolTable().isExternalEntryPoint(entry)) {
				return null;
			}
			List<Address> out = new ArrayList<>();
			boolean data = false;
			boolean computed = false;
			for (Reference r : program.getReferenceManager().getReferencesTo(entry)) {
				RefType t = r.getReferenceType();
				if (!t.isFlow()) {
					data = true;
				}
				else {
					computed |= t.isComputed();
					out.add(r.getFromAddress());
				}
			}
			if (data && !computed && !reset) {
				return null;
			}
			Instruction before = program.getListing().getInstructionBefore(entry);
			if (before != null && entry.equals(before.getFallThrough())) {
				out.add(before.getMinAddress());
			}
			return out.isEmpty() && !reset ? null : out;
		}

		/** The DBR each way in carries under the seeds known so far, by source. */
		private Set<Integer> knownWaysIn(List<Address> src) {
			Set<Integer> out = new LinkedHashSet<>();
			for (Address s : src) {
				Instruction ins = program.getListing().getInstructionAt(s);
				if (ins == null) {
					continue;
				}
				for (Function f : functionsAt(s)) {
					Map<Address, State> m = states.get(f.getEntryPoint());
					State st = m == null ? null : m.get(s);
					if (st == null) {
						continue;
					}
					int v = ins.getFlowType().isCall() ? st.dbr : transfer(ins, st).dbr;
					v = resolve(v, seedOf(f.getEntryPoint()));
					if (v != UNKNOWN) {
						out.add(v);
					}
				}
			}
			return out;
		}

		void solveSeeds(TaskMonitor monitor) throws CancelledException {
			Map<Address, List<Address>> sources = new LinkedHashMap<>();
			Map<Address, Set<Address>> deps = new HashMap<>();
			Map<Address, Set<Integer>> seen = new HashMap<>();
			for (Function g : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				Integer user = userVals.get(g.getEntryPoint());
				if (user != null) {
					seeds.put(g.getEntryPoint(), user);   // beats caller agreement
					continue;
				}
				boolean reset = isReset(g.getEntryPoint());
				List<Address> src = entrySources(g, reset);
				if (src == null) {
					continue;
				}
				Address ge = g.getEntryPoint();
				sources.put(ge, src);
				if (reset) {
					seen.computeIfAbsent(ge, k -> new LinkedHashSet<>()).add(0);
				}
				for (Address s : src) {
					for (Function f : functionsAt(s)) {
						deps.computeIfAbsent(f.getEntryPoint(), k -> new LinkedHashSet<>()).add(ge);
					}
				}
			}
			ArrayDeque<Address> q = new ArrayDeque<>(sources.keySet());
			Set<Address> inQ = new HashSet<>(q);
			while (!q.isEmpty()) {
				monitor.checkCancelled();
				Address g = q.poll();
				inQ.remove(g);
				Integer was = seeds.get(g);
				if (was != null && was == CONFLICT) {
					continue;
				}
				Set<Integer> s = seen.computeIfAbsent(g, k -> new LinkedHashSet<>());
				s.addAll(knownWaysIn(sources.get(g)));
				if (s.isEmpty()) {
					continue;
				}
				int now = s.size() == 1 ? s.iterator().next() : CONFLICT;
				if (was != null && was == now) {
					continue;
				}
				seeds.put(g, now);
				for (Address c : deps.getOrDefault(g, Set.of())) {
					if (inQ.add(c)) {
						q.add(c);
					}
				}
			}
		}

		// -- loss census (probes only) --

		/** Why a function's entry seed is unknown. */
		private String seedLoss(Function g) {
			Integer s = seeds.get(g.getEntryPoint());
			if (s != null && s == CONFLICT) {
				return "conflict";
			}
			List<Address> src = entrySources(g, isReset(g.getEntryPoint()));
			if (src == null) {
				return program.getSymbolTable().isExternalEntryPoint(g.getEntryPoint()) ?
					"external" : "dataref/noref";
			}
			return "noKnownWayIn";
		}

		/** Why an instruction turns a known DBR into UNKNOWN, or null when it does not. */
		private String lossAt(Instruction ins, State st) {
			if (st.dbr == UNKNOWN) {
				return null;
			}
			String mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
			State out = transfer(ins, st);
			if (out.dbr != UNKNOWN) {
				return null;
			}
			if (mn.equals("JSR") || mn.equals("JSL")) {
				Address[] fl = ins.getFlows();
				if (fl.length == 0) {
					return "call:unresolvedIndirect";
				}
				if (fl.length > 1) {
					return "call:multi";
				}
				String w = why.getOrDefault(fl[0], "?");
				int cut = w.indexOf(" at ");
				w = cut > 0 ? w.substring(0, cut) : w;
				cut = w.indexOf(" (");
				w = cut > 0 ? w.substring(0, cut) : w;
				if (w.startsWith("non-empty stack")) {
					w = "non-empty stack";
				}
				return "call:" + w;
			}
			if (mn.equals("PLB")) {
				if (st.stack.isEmpty()) {
					return "plb:underflow";
				}
				int top = st.stack.get(st.stack.size() - 1);
				return top == FLOOR ? "plb:floor" : "plb:unknownByte";
			}
			return "op:" + mn;
		}

		private final Map<Address, Map<Address, String>> causeMaps = new HashMap<>();

		/**
		 * Per instruction of {@code root}'s walk whose DBR is UNKNOWN, the loss point it came
		 * from: a cause label propagated forward from each instruction that turns a known DBR
		 * into UNKNOWN (call labels carry {@code @callee}).
		 */
		private Map<Address, String> causeMap(Address root) {
			Map<Address, String> got = causeMaps.get(root);
			if (got != null) {
				return got;
			}
			Map<Address, State> m = states.getOrDefault(root, Map.of());
			Map<Address, String> cause = new HashMap<>();
			ArrayDeque<Address> q = new ArrayDeque<>();
			for (Map.Entry<Address, State> s : m.entrySet()) {
				Instruction ins = program.getListing().getInstructionAt(s.getKey());
				String c = ins == null ? null : lossAt(ins, s.getValue());
				if (c == null) {
					continue;
				}
				if (c.startsWith("call:") && ins.getFlows().length == 1) {
					c = c + "@" + ins.getFlows()[0];
				}
				for (Address n : successors(root, ins, true)) {
					if (!cause.containsKey(n)) {
						cause.put(n, c);
						q.add(n);
					}
				}
			}
			while (!q.isEmpty()) {
				Address a = q.poll();
				State st = m.get(a);
				Instruction ins = program.getListing().getInstructionAt(a);
				if (st == null || ins == null || st.dbr != UNKNOWN) {
					continue;
				}
				for (Address n : successors(root, ins, true)) {
					if (!cause.containsKey(n)) {
						cause.put(n, cause.get(a));
						q.add(n);
					}
				}
			}
			causeMaps.put(root, cause);
			return cause;
		}

		private final Map<Address, Set<String>> rootMemo = new HashMap<>();

		/**
		 * The root causes behind an unseeded function's entry: following each way in upstream
		 * through callers that are themselves unseeded, to a local loss point, an unknowable
		 * entry (vector / data ref), a source with no walk state, or a cycle of unseeded
		 * functions with no known way in at all.
		 */
		private Set<String> roots(Address g, Set<Address> onPath) {
			Set<String> memo = rootMemo.get(g);
			if (memo != null) {
				return memo;
			}
			Set<String> out = new java.util.TreeSet<>();
			if (!onPath.add(g) || onPath.size() > 200) {
				out.add("cycle/deep");
				return out;
			}
			Function fg = program.getFunctionManager().getFunctionAt(g);
			Integer sd = seeds.get(g);
			List<Address> src = fg == null ? null : entrySources(fg, isReset(g));
			if (sd != null && sd == CONFLICT) {
				out.add("conflict@" + g);
			}
			else if (src == null) {
				out.add((program.getSymbolTable().isExternalEntryPoint(g) ? "external@" :
					"dataref@") + g);
			}
			else {
				for (Address s : src) {
					Instruction ins = program.getListing().getInstructionAt(s);
					List<Function> fs = functionsAt(s);
					if (ins == null || fs.isEmpty()) {
						out.add("noFunction");
						continue;
					}
					for (Function f : fs) {
						Address fe = f.getEntryPoint();
						Map<Address, State> m = states.get(fe);
						State st = m == null ? null : m.get(s);
						if (st == null) {
							out.add(m == null || m.isEmpty() ? "walkEmpty" : "notReached");
							continue;
						}
						int v = ins.getFlowType().isCall() ? st.dbr : transfer(ins, st).dbr;
						if (resolve(v, seedOf(fe)) != UNKNOWN) {
							continue;   // a known way in: cannot be what blocks the seed
						}
						if (v == UNKNOWN) {
							String c = causeMap(fe).getOrDefault(s, "merge/userOrRoot");
							if (!ins.getFlowType().isCall() && lossAt(ins, st) != null) {
								c = lossAt(ins, st);
							}
							out.add(c.indexOf('@') > 0 ? c : c + "@" + s);
						}
						else if (!expand(v).contains(ENTRY)) {
							out.add("set");
						}
						else {
							out.addAll(roots(fe, onPath));
						}
					}
				}
				if (out.isEmpty()) {
					out.add("noWaysInAtAll");
				}
			}
			onPath.remove(g);
			rootMemo.put(g, out);
			return out;
		}

		/** Report lines: lost abs operands by cause, top callees and top unseeded functions. */
		List<String> lossReport(int top) {
			Map<String, Integer> byCause = new java.util.TreeMap<>();
			Map<String, Integer> byCallee = new HashMap<>();
			Map<String, Integer> byUnseeded = new HashMap<>();
			Map<String, Integer> byRootClass = new java.util.TreeMap<>();
			Map<String, Integer> byRoot = new HashMap<>();
			int known = 0;
			int lost = 0;
			for (Map.Entry<Address, Map<Address, State>> e : states.entrySet()) {
				Function f = program.getFunctionManager().getFunctionAt(e.getKey());
				if (f == null) {
					continue;
				}
				Address root = e.getKey();
				Map<Address, State> m = e.getValue();
				int seed = seedOf(root);
				Map<Address, String> cause = causeMap(root);
				int fnLost = 0;
				for (Map.Entry<Address, State> s : m.entrySet()) {
					if (!f.getBody().contains(s.getKey())) {
						continue;
					}
					Instruction ins = program.getListing().getInstructionAt(s.getKey());
					if (ins == null || absOperand(ins) == UNKNOWN) {
						continue;
					}
					int v = s.getValue().dbr;
					if (resolve(v, seed) != UNKNOWN) {
						known++;
						continue;
					}
					lost++;
					String c;
					if (v != UNKNOWN) {
						Set<Integer> mem = expand(v);
						c = mem.contains(ENTRY) && seed == UNKNOWN ? "unseeded:" + seedLoss(f) :
							"set(" + mem.size() + ")";
						if (c.startsWith("unseeded")) {
							byUnseeded.merge(root + " " + c, 1, Integer::sum);
							fnLost++;
						}
					}
					else {
						c = cause.getOrDefault(s.getKey(), "merge/userOrRoot");
						int at = c.indexOf('@');
						if (at > 0) {
							byCallee.merge(c.substring(at + 1) + " " + c.substring(0, at), 1,
								Integer::sum);
							c = c.substring(0, at);
						}
					}
					byCause.merge(c, 1, Integer::sum);
				}
				if (fnLost > 0) {
					// Unseeded operands, by the root causes upstream (an operand counts once per
					// distinct root class; a function with several classes adds to each).
					Set<String> rs = roots(root, new HashSet<>());
					Set<String> classes = new java.util.TreeSet<>();
					for (String r : rs) {
						int at = r.indexOf('@');
						classes.add(at > 0 ? r.substring(0, at) : r);
						if (at > 0) {
							byRoot.merge(r, fnLost, Integer::sum);
						}
					}
					byRootClass.merge(rs.size() == 1 ? "only " + classes.iterator().next() :
						"mixed " + classes, fnLost, Integer::sum);
				}
			}
			List<String> out = new ArrayList<>();
			out.add("knownAbs=" + known + " lostAbs=" + lost);
			for (Map.Entry<String, Integer> c : byCause.entrySet()) {
				out.add("cause " + c.getKey() + " " + c.getValue());
			}
			for (Map.Entry<String, Integer> c : byRootClass.entrySet()) {
				out.add("unseededRoot " + c.getKey() + " ops=" + c.getValue());
			}
			for (var e : topOf(byRoot, top)) {
				String k = e.getKey();
				String w = k.startsWith("call:") ? why.get(program.getAddressFactory()
						.getAddress(k.substring(k.indexOf('@') + 1))) : null;
				out.add("rootFn " + k + " opsBehind=" + e.getValue() +
					(w == null ? "" : " why=" + w.replace('\n', ' ')));
			}
			for (var e : topOf(byCallee, top)) {
				String w = why.get(program.getAddressFactory().getAddress(e.getKey().split(" ")[0]));
				out.add("callee " + e.getKey() + " ops=" + e.getValue() + " why=" +
					(w == null ? null : w.replace('\n', ' ')));
			}
			for (var e : topOf(byUnseeded, top)) {
				out.add("unseededFn " + e.getKey() + " ops=" + e.getValue());
			}
			return out;
		}

		private static List<Map.Entry<String, Integer>> topOf(Map<String, Integer> m, int n) {
			List<Map.Entry<String, Integer>> l = new ArrayList<>(m.entrySet());
			l.sort((a, b) -> b.getValue() - a.getValue());
			return l.subList(0, Math.min(n, l.size()));
		}

		// -- output --

		/** The DBR value in the program context at {@code a}, or UNKNOWN. */
		private int contextValue(Address a) {
			RegisterValue v = program.getProgramContext().getRegisterValue(dbrReg, a);
			return v != null && v.hasValue() ? v.getUnsignedValue().intValue() : UNKNOWN;
		}

		/** The marks of the stamps this analyzer wrote (address -> value stamped), or null. */
		private IntPropertyMap marks(boolean create) {
			PropertyMapManager pm = program.getUsrPropertyManager();
			IntPropertyMap m = pm.getIntPropertyMap(STAMP_MAP);
			if (m == null && create) {
				try {
					m = pm.createIntPropertyMap(STAMP_MAP);
				}
				catch (DuplicateNameException e) {
					m = pm.getIntPropertyMap(STAMP_MAP);
				}
			}
			return m;
		}

		/**
		 * Whether the DBR value at {@code a} is one this analyzer stamped: marked, and still the
		 * value it stamped. Anything else, set by the user or another analyzer, is theirs.
		 */
		boolean ours(Address a) {
			IntPropertyMap m = marks(false);
			if (m == null || !m.hasProperty(a)) {
				return false;
			}
			try {
				return m.getInt(a) == contextValue(a);
			}
			catch (NoValueException e) {
				return false;
			}
		}

		/** Every instruction carrying a DBR value that is not ours: the user's claims. */
		private void scanUserValues() {
			var pc = program.getProgramContext();
			AddressRangeIterator it = pc.getRegisterValueAddressRanges(dbrReg);
			while (it.hasNext()) {
				AddressRange r = it.next();
				for (Instruction i : program.getListing().getInstructions(new AddressSet(r), true)) {
					Address a = i.getMinAddress();
					int v = contextValue(a);
					if (v != UNKNOWN && !ours(a)) {
						userVals.put(a, v);
					}
				}
			}
		}

		/** Removes a DBR stamp of ours from an instruction whose DBR is now unknown. */
		void clear(Instruction ins) {
			Address at = ins.getMinAddress();
			if (!ours(at)) {
				return;   // the user's (or no) value: never removed
			}
			try {
				program.getProgramContext().remove(at, ins.getMaxAddress(), dbrReg);
				marks(false).remove(at);
			}
			catch (ContextChangeException e) {
				// leave the stamp: the context is locked
			}
		}

		boolean stamp(Instruction ins, int dbr) {
			Address at = ins.getMinAddress();
			int existing = contextValue(at);
			if (existing != UNKNOWN && !ours(at)) {
				return false;   // a value the user set stands
			}
			if (existing == dbr) {
				return false;
			}
			try {
				program.getProgramContext().setValue(dbrReg, at, ins.getMaxAddress(),
					BigInteger.valueOf(dbr));
				marks(true).add(at, dbr);
				return true;
			}
			catch (ContextChangeException e) {
				return false;
			}
		}

		/**
		 * The 16-bit offset of an absolute data operand ({@code abs}, {@code abs,X}, {@code abs,Y}:
		 * a 3-byte instruction whose operand prints as {@code $hhhh}, not an immediate, a branch,
		 * jump, call, PEA/PER or block move), or UNKNOWN.
		 */
		static int absOperand(Instruction ins) {
			if (ins.getLength() != 3 || ins.getNumOperands() < 1 || ins.getFlowType().isJump() || ins.getFlowType().isCall() || ins.getFlowType().isTerminal()) {
				return UNKNOWN;
			}
			String mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
			if (mn.equals("PEA") || mn.equals("PER") || mn.equals("PEI") || mn.equals("MVN") ||
				mn.equals("MVP")) {
				return UNKNOWN;
			}
			String r = ins.getDefaultOperandRepresentation(0);
			if (!r.startsWith("!") || r.contains("(") || r.contains("[") || r.contains(",S")) {
				return UNKNOWN;
			}
			try {
				return (ins.getByte(1) & 0xff) | (ins.getByte(2) & 0xff) << 8;
			}
			catch (ghidra.program.model.mem.MemoryAccessException e) {
				return UNKNOWN;
			}
		}

		boolean reference(Instruction ins, int dbr) {
			int off = absOperand(ins);
			if (off == UNKNOWN) {
				return false;
			}
			Address to = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(((long) dbr << 16) | off);
			if (!program.getMemory().contains(to)) {
				return false;
			}
			boolean present = false;
			for (Reference r : ins.getReferencesFrom()) {
				if (!r.isMemoryReference() || r.getReferenceType().isFlow()) {
					continue;
				}
				if (r.getToAddress().equals(to)) {
					present = true;
				}
				else if (r.getSource() != SourceType.USER_DEFINED &&
					(r.getToAddress().getOffset() & 0xffff) == off) {
					// A reference to the same offset in another bank, derived without this
					// DBR (an assumed bank): replaced. A user's own reference is kept.
					program.getReferenceManager().delete(r);
					replaced++;
				}
			}
			if (present) {
				return false;
			}
			program.getReferenceManager().addMemoryReference(ins.getMinAddress(), to,
				W65816DirectPageAnalyzer.typeOf(ins.getMnemonicString().toUpperCase(Locale.ROOT)),
				SourceType.ANALYSIS, 0);
			return true;
		}
	}
}
