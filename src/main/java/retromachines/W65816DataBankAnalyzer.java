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
 * {@code RTL} consumes the bank byte the caller pushed. NOT yet handled: shared epilogues
 * ({@code ... PLB / RTL} entered by a jump after the jumper's {@code PHB}), and unresolved
 * indirect calls (DBR unknown after them).
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
				State out = transfer(ins, in.get(at));
				for (Address next : successors(root, ins, dispatch)) {
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
			if (isDispatchJmp(ins) && dispatch) {
				for (Address a : ins.getFlows()) {
					if (!otherEntry(root, a)) {
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
				if (!otherEntry(root, a)) {
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
			for (Map.Entry<Address, State> e : in.entrySet()) {
				Instruction ins = program.getListing().getInstructionAt(e.getKey());
				if (ins == null) {
					continue;
				}
				State st = e.getValue();
				Set<Integer> out;
				if (isReturn(ins)) {
					out = expand(st.dbr);
					kinds.add(ins.getMnemonicString().toUpperCase(Locale.ROOT));
				}
				else if (isDispatchJmp(ins)) {
					out = expand(st.dbr);
					kinds.add("?");
				}
				else if (!isCallInstr(ins) && !ins.getFlowType().isComputed() &&
					ins.getFlows().length == 1 && ins.getFlowType().isJump() &&
					otherEntry(root, ins.getFlows()[0])) {
					Address t = ins.getFlows()[0];
					if (neverReturns(t)) {
						continue;
					}
					Summary ts = summaryOf(t);
					out = ts.mapped(st.dbr);
					kinds.addAll(ts.kinds.isEmpty() ? Set.of("?") : ts.kinds);
				}
				else {
					continue;
				}
				if (st.under) {
					continue;   // returns to an outer frame, not to the caller
				}
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
				why.putIfAbsent(root, in.isEmpty() ? "walk empty/gave up" : "no exit reached");
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
				case "PHD", "PEI", "PER":
					return push(push(s, UNKNOWN), UNKNOWN);
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
