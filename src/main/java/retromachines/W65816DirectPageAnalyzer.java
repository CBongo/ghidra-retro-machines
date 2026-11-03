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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Tracks the 65816 direct-page register DP through a function (bead grm-9nxj.22, slice 1) and
 * makes direct-page operands resolve to {@code DP + dp} in bank 0.
 *
 * <p><b>Why.</b> The stock constant propagator resolves {@code LDA #imm / TCD} in one flow but
 * does not model a value that comes back off the stack, so a game whose only DP-setting form is
 * {@code LDX #$0600 / PHX / PLD} (FF2) gets no reference for any dp operand. It also only seeds a
 * program-context register value at a function's entry, so a stamp laid mid-function never
 * reaches it. This analyzer therefore does both halves itself.
 *
 * <p><b>The walk.</b> For every function overlapping the analyzed set, a forward dataflow over
 * the body (fall-through, jumps and conditional branches that stay inside it) tracks DP, the
 * 16-bit constants A/X/Y hold, and a stack of pushed values with their widths. It recognizes
 * <ul>
 * <li>{@code LDA/LDX/LDY #imm16} (the instruction must be decoded 16-bit, so 3 bytes; an 8-bit
 * immediate leaves the register unknown), {@code PEA #imm};</li>
 * <li>{@code PHA/PHX/PHY/PEA/PHD/PHP/PHB/PHK/PEI/PER} and the matching pulls, widths read from
 * the M/X context at the instruction -- a width mismatch between push and pull, or an unknown
 * width, poisons the stack;</li>
 * <li>{@code PLD} (DP = the pulled value if it is a known 16-bit push; so
 * {@code PHD ... PLD} restores the DP at the PHD), {@code TCD}.</li>
 * </ul>
 * Anything else that writes A, X, Y, SP or DP (by its p-code) makes that state unknown. Unknown
 * stays unknown: DP is never defaulted, and at a merge DP survives only if every incoming path
 * agrees. A call ({@code JSR/JSL}) keeps DP only when its target is a function whose body (and the
 * direct callees' bodies, transitively) contains no {@code TCD} and no more {@code PLD} than
 * {@code PHD}, or when the callee's exit summary (walked from a symbolic entry DP) is a constant
 * or "the DP it was entered with" ({@code PHD ... TCD ... PLD}, grm-9nxj.27); an indirect call or
 * a target with no function makes DP unknown. A/X/Y are unknown after any call.
 *
 * <p><b>The output.</b> Where DP is known at an instruction, (1) DP is stamped as an assumed
 * register value over that instruction ({@code ProgramContext.setValue}; downstream consumers
 * such as the pointer-dispatch matcher can read it), and (2) every dp operand ({@code <$nn},
 * {@code <$nn,X/Y}, and the pointer of the indirect forms) gets a memory reference to
 * {@code (DP + nn) & $FFFF} in bank 0, typed WRITE for stores, READ_WRITE for read-modify-write
 * and READ otherwise (indirect pointers are always READ), unless the instruction already has a
 * memory reference to that address. The index register is not applied: indexed forms reference
 * the base.
 *
 * <p><b>Entry DP (slice 2, grm-9nxj.26).</b> A function's walk starts with DP unknown unless every
 * way into its entry is known to carry the same DP (see {@code Walker.solve}); each run solves
 * the whole program, since an entry's DP depends on callers outside the analyzed set.
 *
 * <p><b>Limits.</b> A function reached from anywhere unknown -- an unresolved computed jump, a
 * vector, a pointer table no dispatch resolved, a recursive self-call -- keeps an unknown
 * entry; a {@code PHD} whose {@code PLD} is in another
 * function is not paired; transfers ({@code TAX}, {@code TXA}...) and arithmetic forget the
 * constant; calls forget A/X/Y; a callee is assumed to preserve DP unless its body visibly
 * changes it. Stamps from an earlier run are not cleared where DP later becomes unknown.
 *
 * <p>Priority: just before the stock constant propagator, after functions exist.
 */
public class W65816DirectPageAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 Direct Page";
	private static final String DESCRIPTION =
		"Tracks the 65816 direct-page register through a function (LDX #imm / PHX / PLD, PEA / " +
			"PLD, PHD ... PLD, TCD), stamps it as an assumed register value, and references " +
			"direct-page operands at DP + dp in bank 0 (grm-9nxj.22).";
	private static final int UNKNOWN = -1;
	/**
	 * Symbolic DP: "whatever DP this function was entered with". Used only by a callee's
	 * exit-DP summary walk (never stamped), so that {@code PHD ... TCD ... PLD} returns as
	 * "the caller's DP" rather than unknown (grm-9nxj.27, FF2 {@code $04:8008}).
	 */
	private static final int ENTRY_DP = -2;
	private static final int STACK_LIMIT = 16;
	private static final int STEP_LIMIT = 50_000;

	/** One pushed item: its width in bytes and its value, or {@link #UNKNOWN}. */
	private record Pushed(int width, int value) {}

	/**
	 * The bottom of a stack restarted after poisoning: what lies beneath is unknown and is not
	 * the entry's, so a pop into it poisons (no pull has width 0) and a stack holding it is never
	 * the empty stack a plain RTS needs.
	 */
	private static final Pushed FLOOR = new Pushed(0, UNKNOWN);

	/** Dataflow state before an instruction. {@code stack == null} means poisoned. */
	private record State(int dp, int a, int x, int y, List<Pushed> stack) {

		State meet(State o) {
			return new State(dp == o.dp ? dp : UNKNOWN, a == o.a ? a : UNKNOWN,
				x == o.x ? x : UNKNOWN, y == o.y ? y : UNKNOWN, meetStack(stack, o.stack));
		}

		/**
		 * The items both stacks agree on, counted from the top, over a {@link #FLOOR} when they
		 * differ beneath that; poisoned when not even the top agrees.
		 */
		private static List<Pushed> meetStack(List<Pushed> p, List<Pushed> q) {
			if (p == null || q == null) {
				return null;
			}
			if (p.equals(q)) {
				return p;
			}
			int k = 0;
			while (k < p.size() && k < q.size() &&
				p.get(p.size() - 1 - k).equals(q.get(q.size() - 1 - k))) {
				k++;
			}
			if (k == 0) {
				return null;
			}
			List<Pushed> top = p.subList(p.size() - k, p.size());
			if (top.get(0).equals(FLOOR)) {
				return List.copyOf(top);
			}
			List<Pushed> out = new ArrayList<>(k + 1);
			out.add(FLOOR);
			out.addAll(top);
			return List.copyOf(out);
		}
	}

	private static final State ENTRY = new State(UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, List.of());

	public W65816DirectPageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before().before().before().before().before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program) && program.getRegister("DP") != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Walker w = new Walker(program);
		int stamped = 0;
		int refs = 0;
		// Program-wide, not just `set`: a function's entry DP depends on its callers anywhere.
		Map<Function, Map<Address, State>> all = w.solve(monitor);
		for (Map<Address, State> states : all.values()) {
			monitor.checkCancelled();
			for (Map.Entry<Address, State> e : states.entrySet()) {
				int dp = e.getValue().dp;
				if (dp == UNKNOWN) {
					continue;
				}
				Instruction in = program.getListing().getInstructionAt(e.getKey());
				if (in == null) {
					continue;
				}
				stamped += w.stamp(in, dp) ? 1 : 0;
				refs += w.reference(in, dp) ? 1 : 0;
			}
		}
		if (stamped > 0 || refs > 0) {
			AnalyzerLog.info(this, "DP stamped over " + stamped + " instructions, " + refs +
				" dp operand references added");
		}
		return true;
	}

	/** The walk, with per-program register handles. */
	private static final class Walker {
		private final Program program;
		private final Register dpReg;
		private final Register[] tracked;   // C, X, Y, SP, DP
		private final Register ctxM;
		private final Register ctxX;
		private final Map<Address, Boolean> preserves = new HashMap<>();
		private final Map<Address, Integer> exitDp = new HashMap<>();
		private final Set<Address> exitInProgress = new HashSet<>();

		Walker(Program program) {
			this.program = program;
			dpReg = program.getRegister("DP");
			tracked = new Register[] { program.getRegister("C"), program.getRegister("X"),
				program.getRegister("Y"), program.getRegister("SP"), dpReg };
			ctxM = program.getRegister("ctx_MF");
			ctxX = program.getRegister("ctx_XF");
		}

		/**
		 * Slice 2 (grm-9nxj.26): every function's walk, with its entry DP seeded from its
		 * entries. A function is seeded once, with DP d, when every way in is known to carry d:
		 * each flow reference to its entry (call, jump, branch, computed jump) and a fall-through
		 * from the instruction before it, judged at the source in the source function's walk (a
		 * call carries the DP before it; anything else the DP after it). An external entry point,
		 * a source outside every function or not reached by its walk, a data reference to the
		 * entry (a pointer or vector) unless a computed jump also resolved to it, and disagreeing
		 * or unknown sources all leave it UNKNOWN. Seeding only ever turns UNKNOWN into a value,
		 * and a source's value can only gain from it, so the worklist terminates.
		 */
		Map<Function, Map<Address, State>> solve(TaskMonitor monitor) throws CancelledException {
			var fm = program.getFunctionManager();
			Map<Function, Map<Address, State>> states = new LinkedHashMap<>();
			for (Function f : fm.getFunctions(true)) {
				monitor.checkCancelled();
				states.put(f, walk(f, ENTRY));
			}
			// Sources into each entry, and which functions' seeds read each function's states.
			Map<Function, List<Address>> sources = new HashMap<>();
			Map<Function, Set<Function>> dependents = new HashMap<>();
			Set<Function> blocked = new HashSet<>();
			for (Function g : states.keySet()) {
				monitor.checkCancelled();
				List<Address> src = entrySources(g);
				if (src == null) {
					blocked.add(g);
					continue;
				}
				sources.put(g, src);
				for (Address s : src) {
					for (Function f : functionsAt(s)) {
						dependents.computeIfAbsent(f, k -> new LinkedHashSet<>()).add(g);
					}
				}
			}
			ArrayDeque<Function> work = new ArrayDeque<>(sources.keySet());
			Set<Function> queued = new HashSet<>(work);
			Set<Function> seeded = new HashSet<>();   // each at most once: what bounds the loop
			while (!work.isEmpty()) {
				monitor.checkCancelled();
				Function g = work.poll();
				queued.remove(g);
				if (seeded.contains(g)) {
					continue;
				}
				int d = entryDp(sources.get(g), states);
				if (d == UNKNOWN) {
					continue;
				}
				seeded.add(g);
				states.put(g, walk(g, new State(d, UNKNOWN, UNKNOWN, UNKNOWN, List.of())));
				for (Function c : dependents.getOrDefault(g, Set.of())) {
					if (!blocked.contains(c) && queued.add(c)) {
						work.add(c);
					}
				}
			}
			return states;
		}

		/** Every function whose body holds {@code a} (bodies may overlap). */
		private List<Function> functionsAt(Address a) {
			List<Function> out = new ArrayList<>();
			program.getFunctionManager().getFunctionsOverlapping(new AddressSet(a))
					.forEachRemaining(out::add);
			return out;
		}

		/** The addresses control enters {@code g}'s entry from, or null if one is unknowable. */
		private List<Address> entrySources(Function g) {
			Address entry = g.getEntryPoint();
			if (program.getSymbolTable().isExternalEntryPoint(entry)) {
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
			if (data && !computed) {
				return null;
			}
			Instruction before = program.getListing().getInstructionBefore(entry);
			if (before != null && entry.equals(before.getFallThrough())) {
				out.add(before.getMinAddress());
			}
			return out.isEmpty() ? null : out;
		}

		private int entryDp(List<Address> src, Map<Function, Map<Address, State>> states) {
			int d = UNKNOWN;
			for (Address s : src) {
				Instruction ins = program.getListing().getInstructionAt(s);
				if (ins == null) {
					return UNKNOWN;
				}
				boolean any = false;
				for (Function f : functionsAt(s)) {
					State st = states.get(f) == null ? null : states.get(f).get(s);
					if (st == null) {
						return UNKNOWN;
					}
					int v = ins.getFlowType().isCall() ? st.dp : transfer(ins, st).dp;
					if (v == UNKNOWN || (d != UNKNOWN && v != d)) {
						return UNKNOWN;
					}
					d = v;
					any = true;
				}
				if (!any) {
					return UNKNOWN;
				}
			}
			return d;
		}

		Map<Address, State> walk(Function f, State entry) {
			Map<Address, State> in = new LinkedHashMap<>();
			ArrayDeque<Address> work = new ArrayDeque<>();
			in.put(f.getEntryPoint(), entry);
			work.add(f.getEntryPoint());
			int steps = 0;
			while (!work.isEmpty() && steps++ < STEP_LIMIT) {
				Address at = work.poll();
				Instruction ins = program.getListing().getInstructionAt(at);
				if (ins == null) {
					continue;
				}
				State out = transfer(ins, in.get(at));
				for (Address next : successors(f, ins)) {
					State old = in.get(next);
					State merged = old == null ? out : old.meet(out);
					if (!merged.equals(old)) {
						in.put(next, merged);
						work.add(next);
					}
				}
			}
			if (!work.isEmpty()) {
				return new LinkedHashMap<>();   // gave up: claim nothing
			}
			return in;
		}

		private List<Address> successors(Function f, Instruction ins) {
			List<Address> out = new ArrayList<>();
			var ft = ins.getFlowType();
			if (ft.isCall()) {
				addIfBody(f, out, ins.getFallThrough());
				return out;
			}
			if (ft.isTerminal()) {
				return out;
			}
			for (Address a : ins.getFlows()) {
				addIfBody(f, out, a);
			}
			if (ins.hasFallthrough()) {
				addIfBody(f, out, ins.getFallThrough());
			}
			return out;
		}

		private static void addIfBody(Function f, List<Address> out, Address a) {
			if (a != null && f.getBody().contains(a)) {
				out.add(a);
			}
		}

		private int width(Instruction ins, Register flag) {
			BigInteger v = ins.getValue(flag, false);
			return v == null ? UNKNOWN : (v.signum() == 0 ? 2 : 1);
		}

		/**
		 * A push onto a poisoned stack starts a fresh one: whatever lies beneath is unknown either
		 * way (a pop past the bottom yields UNKNOWN), but this item pulls back exactly. Without
		 * it, a merge with one poisoned path (FF2's RESET loops back to its entry after TXS)
		 * would lose every later PHX/PLD pair too.
		 */
		private static State push(State s, Pushed p) {
			if (s.stack != null && s.stack.size() >= STACK_LIMIT) {
				return new State(s.dp, s.a, s.x, s.y, null);
			}
			List<Pushed> l = new ArrayList<>(s.stack == null ? List.of(FLOOR) : s.stack);
			l.add(p);
			return new State(s.dp, s.a, s.x, s.y, List.copyOf(l));
		}

		/** Pops {@code width} bytes; the popped value, or UNKNOWN; second element is the new state. */
		private static Object[] pop(State s, int width) {
			if (s.stack == null || width == UNKNOWN) {
				return new Object[] { UNKNOWN, new State(s.dp, s.a, s.x, s.y, null) };
			}
			if (s.stack.isEmpty()) {
				// The caller's data (its return address, say): unknown, and the stack below is
				// no longer the entry's, so an RTS after this is not a plain return.
				return new Object[] { UNKNOWN, new State(s.dp, s.a, s.x, s.y, null) };
			}
			Pushed top = s.stack.get(s.stack.size() - 1);
			if (top.width != width) {
				return new Object[] { UNKNOWN, new State(s.dp, s.a, s.x, s.y, null) };
			}
			return new Object[] { top.value,
				new State(s.dp, s.a, s.x, s.y, List.copyOf(s.stack.subList(0, s.stack.size() - 1))) };
		}

		private static State with(State s, int dp, int a, int x, int y) {
			return new State(dp, a, x, y, s.stack);
		}

		/** The 16-bit constant of a {@code #imm} operand decoded as 16-bit, or UNKNOWN. */
		private static int imm16(Instruction ins) {
			if (ins.getLength() != 3 || ins.getNumOperands() < 1 ||
				!ins.getDefaultOperandRepresentation(0).startsWith("#")) {
				return UNKNOWN;
			}
			return scalar(ins);
		}

		private static int scalar(Instruction ins) {
			for (Object o : ins.getOpObjects(0)) {
				if (o instanceof Scalar s) {
					return (int) (s.getUnsignedValue() & 0xffff);
				}
			}
			return UNKNOWN;
		}

		State transfer(Instruction ins, State s) {
			String mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
			switch (mn) {
				case "LDA":
					return with(s, s.dp, imm16(ins), s.x, s.y);
				case "LDX":
					return with(s, s.dp, s.a, imm16(ins), s.y);
				case "LDY":
					return with(s, s.dp, s.a, s.x, imm16(ins));
				case "TCD":
					return with(s, s.a, s.a, s.x, s.y);
				case "PHA":
					return pushReg(s, width(ins, ctxM), s.a);
				case "PHX":
					return pushReg(s, width(ins, ctxX), s.x);
				case "PHY":
					return pushReg(s, width(ins, ctxX), s.y);
				case "PHD":
					return push(s, new Pushed(2, s.dp));
				case "PEA":
					return push(s, new Pushed(2, scalar(ins)));
				case "PEI", "PER":
					return push(s, new Pushed(2, UNKNOWN));
				case "PHP", "PHB", "PHK":
					return push(s, new Pushed(1, UNKNOWN));
				case "PLA": {
					Object[] r = pop(s, width(ins, ctxM));
					return with((State) r[1], s.dp, UNKNOWN, s.x, s.y);
				}
				case "PLX": {
					Object[] r = pop(s, width(ins, ctxX));
					return with((State) r[1], s.dp, s.a, UNKNOWN, s.y);
				}
				case "PLY": {
					Object[] r = pop(s, width(ins, ctxX));
					return with((State) r[1], s.dp, s.a, s.x, UNKNOWN);
				}
				case "PLP", "PLB": {
					Object[] r = pop(s, 1);
					return (State) r[1];
				}
				case "PLD": {
					Object[] r = pop(s, 2);
					State n = (State) r[1];
					return with(n, (Integer) r[0], s.a, s.x, s.y);
				}
				case "JSR", "JSL":
					return afterCall(ins, s);
				default:
					return generic(ins, s);
			}
		}

		private State pushReg(State s, int w, int value) {
			if (w == UNKNOWN) {
				return new State(s.dp, s.a, s.x, s.y, null);
			}
			return push(s, new Pushed(w, w == 2 ? value : UNKNOWN));
		}

		private State afterCall(Instruction ins, State s) {
			Address[] flows = ins.getFlows();
			int dp = UNKNOWN;
			if (flows.length == 1) {
				if (preserves(flows[0])) {
					dp = s.dp;
				}
				else {
					int e = exitDp(flows[0]);
					dp = e == ENTRY_DP ? s.dp : e;
				}
			}
			return new State(dp, UNKNOWN, UNKNOWN, UNKNOWN, s.stack);
		}

		/**
		 * The DP a call to {@code target} returns with, whatever DP it was entered with: a
		 * constant, {@link #ENTRY_DP} (it hands back the DP it was given), or UNKNOWN. The
		 * function is walked from a symbolic entry DP; it must reach at least one RTS/RTL, every
		 * one with the same known-or-entry DP and an empty, unpoisoned stack (so it returns to the
		 * caller); and it must have no other way out -- no RTI, no jump leaving its body, no jump
		 * without a target. A callee that sets DP itself ({@code LDX #$0600 / PHX / PLD ... RTS})
		 * so passes its constant back, and one that brackets its own DP change
		 * ({@code PHD ... TCD ... PLD ... RTS}, FF2 {@code $04:8008}) returns the caller's DP.
		 * Recursion is judged UNKNOWN.
		 */
		private int exitDp(Address target) {
			Integer known = exitDp.get(target);
			if (known != null) {
				return known;
			}
			Function callee = program.getFunctionManager().getFunctionAt(target);
			if (callee == null || !exitInProgress.add(target)) {
				return UNKNOWN;
			}
			int d = UNKNOWN;
			boolean ok = true;
			Map<Address, State> states =
				walk(callee, new State(ENTRY_DP, UNKNOWN, UNKNOWN, UNKNOWN, List.of()));
			if (states.isEmpty()) {
				ok = false;
			}
			for (Map.Entry<Address, State> e : states.entrySet()) {
				Instruction i = program.getListing().getInstructionAt(e.getKey());
				if (i == null) {
					continue;
				}
				String mn = i.getMnemonicString().toUpperCase(Locale.ROOT);
				var ft = i.getFlowType();
				State st = e.getValue();
				if (mn.equals("RTS") || mn.equals("RTL")) {
					if (st.dp == UNKNOWN || st.stack == null || !st.stack.isEmpty() ||
						(d != UNKNOWN && d != st.dp)) {
						ok = false;
					}
					d = st.dp;
				}
				else if (mn.equals("RTI")) {
					ok = false;
				}
				else if (!ft.isCall() && (ft.isJump() || ft.isComputed())) {
					Address[] fl = i.getFlows();
					if (fl.length == 0 && !ft.isConditional()) {
						ok = false;
					}
					for (Address t : fl) {
						ok &= callee.getBody().contains(t);
					}
				}
				if (!ok) {
					break;
				}
			}
			exitInProgress.remove(target);
			int result = ok ? d : UNKNOWN;
			exitDp.put(target, result);
			return result;
		}

		/** Whether a call to {@code target} leaves DP alone, as far as its code visibly shows. */
		private boolean preserves(Address target) {
			return preserves(target, new HashSet<>(), new HashSet<>());
		}

		/**
		 * @param path functions whose judgement is in progress (a cycle is optimistically assumed
		 *     to preserve)
		 * @param assumed receives each on-path function this judgement leaned on; a TRUE result
		 *     that leaned on an assumption still open is not cached, since that assumption may
		 *     yet fail
		 */
		private boolean preserves(Address target, Set<Address> path, Set<Address> assumed) {
			Function callee = program.getFunctionManager().getFunctionAt(target);
			if (callee == null) {
				return false;
			}
			Boolean known = preserves.get(target);
			if (known != null) {
				return known;
			}
			if (!path.add(target)) {
				assumed.add(target);
				return true;   // recursion: judged by the rest of the cycle
			}
			int phd = 0;
			int pld = 0;
			boolean ok = true;
			List<Address> next = new ArrayList<>();
			for (Instruction i : program.getListing().getInstructions(callee.getBody(), true)) {
				String mn = i.getMnemonicString().toUpperCase(Locale.ROOT);
				var ft = i.getFlowType();
				if (mn.equals("TCD")) {
					ok = false;
				}
				else if (mn.equals("PHD")) {
					phd++;
				}
				else if (mn.equals("PLD")) {
					pld++;
				}
				else if (ft.isCall()) {
					Address[] fl = i.getFlows();
					if (fl.length != 1) {
						ok = false;
					}
					else {
						next.add(fl[0]);
					}
				}
				else if (!ft.isTerminal() && (ft.isJump() || ft.isComputed())) {
					// A jump out of the body is a tail call: judged like a call to its target.
					Address[] fl = i.getFlows();
					boolean outside = false;
					for (Address t : fl) {
						if (!callee.getBody().contains(t)) {
							outside = true;
							if (ft.isComputed()) {
								ok = false;
							}
							else {
								next.add(t);
							}
						}
					}
					if (ft.isComputed() && fl.length == 0) {
						ok = false;
					}
					if (!outside && fl.length == 0 && !ft.isConditional()) {
						ok = false;   // a jump with no known target
					}
				}
			}
			ok &= pld <= phd;
			Set<Address> mine = new HashSet<>();
			for (Address c : next) {
				if (!ok) {
					break;
				}
				ok = preserves(c, path, mine);
			}
			path.remove(target);
			mine.remove(target);
			if (!ok || mine.isEmpty()) {
				preserves.put(target, ok);
			}
			assumed.addAll(mine);
			return ok;
		}

		/** Anything unrecognized: forget what its p-code writes. */
		private State generic(Instruction ins, State s) {
			int dp = s.dp;
			int a = s.a;
			int x = s.x;
			int y = s.y;
			List<Pushed> stack = s.stack;
			for (PcodeOp op : ins.getPcode()) {
				Varnode out = op.getOutput();
				if (out == null || !out.isRegister()) {
					continue;
				}
				for (int i = 0; i < tracked.length; i++) {
					Register r = tracked[i];
					if (r == null || !overlaps(out, r)) {
						continue;
					}
					switch (i) {
						case 0 -> a = UNKNOWN;
						case 1 -> x = UNKNOWN;
						case 2 -> y = UNKNOWN;
						case 3 -> stack = null;
						default -> dp = UNKNOWN;
					}
				}
			}
			return new State(dp, a, x, y, stack);
		}

		private static boolean overlaps(Varnode v, Register r) {
			long lo = v.getOffset();
			long hi = lo + v.getSize();
			long rlo = r.getAddress().getOffset();
			long rhi = rlo + r.getMinimumByteSize();
			return lo < rhi && rlo < hi;
		}

		boolean stamp(Instruction ins, int dp) {
			Address at = ins.getMinAddress();
			var pc = program.getProgramContext();
			var existing = pc.getRegisterValue(dpReg, at);
			if (existing != null && existing.hasValue() &&
				existing.getUnsignedValue().intValue() == dp) {
				return false;
			}
			try {
				pc.setValue(dpReg, at, ins.getMaxAddress(), BigInteger.valueOf(dp));
				return true;
			}
			catch (ContextChangeException e) {
				return false;
			}
		}

		boolean reference(Instruction ins, int dp) {
			if (ins.getNumOperands() < 1) {
				return false;
			}
			String repr = ins.getDefaultOperandRepresentation(0);
			boolean indirect = repr.startsWith("(<") || repr.startsWith("[<");
			if (!repr.startsWith("<") && !indirect) {
				return false;
			}
			int off = scalar(ins);
			if (off == UNKNOWN) {
				return false;
			}
			Address to = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress((dp + (off & 0xff)) & 0xffff);
			for (Reference r : ins.getReferencesFrom()) {
				if (r.isMemoryReference() && !r.getReferenceType().isFlow() &&
					r.getToAddress().equals(to)) {
					return false;
				}
			}
			program.getReferenceManager().addMemoryReference(ins.getMinAddress(), to,
				indirect ? RefType.READ : typeOf(ins.getMnemonicString().toUpperCase(Locale.ROOT)),
				SourceType.ANALYSIS, 0);
			return true;
		}

		private static RefType typeOf(String mn) {
			return switch (mn) {
				case "STA", "STX", "STY", "STZ" -> RefType.WRITE;
				case "INC", "DEC", "ASL", "LSR", "ROL", "ROR", "TSB", "TRB" -> RefType.READ_WRITE;
				default -> RefType.READ;
			};
		}
	}
}
