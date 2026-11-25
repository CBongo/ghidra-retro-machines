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
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
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
 * <p><b>Entry DP (slice 2, grm-9nxj.26; loosened by grm-9nxj.28).</b> A function's walk starts
 * with DP d when at least one way into its entry carries a known DP and every known one carries
 * d; ways in with an unknown DP are ignored, and each entry seeded past one gets a Warning
 * bookmark ({@value #BOOKMARK_CATEGORY}, "DP assumed ..."), as does an entry whose known ways in
 * disagree ("DP conflict ...", left unknown). See {@code Walker.solve}. Each run solves the whole
 * program, since an entry's DP depends on callers outside the analyzed set.
 *
 * <p><b>Limits.</b> A function reached only from somewhere unknown -- an unresolved computed jump,
 * a vector, a pointer table no dispatch resolved -- keeps an unknown entry, and a vector target
 * or pointer-table entry never seeds; a routine that really is entered with several DPs is
 * seeded wrongly if only one of them is known (hence the bookmark); a {@code PHD} whose {@code PLD} is in another
 * function is not paired; transfers ({@code TAX}, {@code TXA}...) and arithmetic forget the
 * constant; calls forget A/X/Y; a callee is assumed to preserve DP unless its body visibly
 * changes it. Stamps from an earlier run are not cleared where DP later becomes unknown.
 *
 * <p>Priority: just before the stock constant propagator, after functions exist.
 *
 * <p><b>Diagnostic (grm-9nxj.30).</b> Set the environment variable {@code GRM_DP_SUMMARY_TRACE}
 * to {@code all} or a comma-separated list of hex addresses (e.g. {@code e01a,b0d1}; a value up
 * to $FFFF matches that offset in any bank) and every call-summary judgement for a matching
 * target prints one stdout line prefixed {@code DPS }: {@code exitDp} gives the result, the
 * first failing instruction and why (UNKNOWN exit DP, non-empty or poisoned stack, disagreeing
 * exits, RTI, jump out of body or without target, walk gave up at STEP_LIMIT), where DP turned
 * UNKNOWN along the walk (a call whose summary failed, or a merge of disagreeing paths), and a
 * recursion-in-progress UNKNOWN naming the in-progress chain; {@code recHits} counts those
 * recursion hits during a judgement (a failure with recHits&gt;0 may be cycle poisoning). The
 * top-level {@link Walker#preserves} verdict is logged as {@code DPS preserves}. Unset, it costs one
 * boolean test per judgement.
 */
public class W65816DirectPageAnalyzer extends AbstractAnalyzer {

	/** {@code GRM_DP_SUMMARY_TRACE}: null (off), or the hex offsets to trace; empty set = all. */
	private static final Set<Long> TRACE = parseTrace(System.getenv("GRM_DP_SUMMARY_TRACE"));

	private static Set<Long> parseTrace(String v) {
		if (v == null || v.isBlank()) {
			return null;
		}
		Set<Long> out = new HashSet<>();
		if (v.trim().equalsIgnoreCase("all")) {
			return out;
		}
		for (String p : v.split(",")) {
			try {
				out.add(Long.parseLong(p.trim().replace("$", "").replace("0x", ""), 16));
			}
			catch (NumberFormatException e) {
				// ignore a malformed item
			}
		}
		return out;
	}

	private static boolean traced(Address a) {
		if (TRACE == null) {
			return false;
		}
		if (TRACE.isEmpty()) {
			return true;
		}
		long o = a.getOffset();
		return TRACE.contains(o) || TRACE.contains(o & 0xffff);
	}

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
	/** An entry whose known ways in carry different DPs (grm-9nxj.28); never a walk's DP. */
	private static final int CONFLICT = -3;
	/** Bookmark category for the entry-seeding warnings (grm-9nxj.28). */
	static final String BOOKMARK_CATEGORY = "65816 DP";
	private static final int STACK_LIMIT = 16;
	private static final int STEP_LIMIT = 50_000;

	/** One pushed item: its width in bytes and its value, or {@link #UNKNOWN}. */
	private record Pushed(int width, int value, boolean phd) {
		Pushed(int width, int value) {
			this(width, value, false);
		}
	}

	/**
	 * The bottom of a stack restarted after poisoning: what lies beneath is unknown and is not
	 * the entry's, so a pop into it poisons (no pull has width 0) and a stack holding it is never
	 * the empty stack a plain RTS needs.
	 */
	private static final Pushed FLOOR = new Pushed(0, UNKNOWN);

	/**
	 * The sole item of an "unwound" stack: the path has pulled below the stack it was entered
	 * with (its own return address, and maybe more) and pushed nothing since. An RTS/RTL or
	 * tail call from such a state cannot come back to the call's fall-through, so a call summary
	 * ignores that exit (CT {@code $c7:0a8c}: {@code PLA PLA PLA / JMP} into an outer routine's
	 * shared {@code ... PLD / PLB / RTL} epilogue). A push onto it restarts over {@link #FLOOR}
	 * like a poisoned stack, so pull-adjust-push-return (inline arguments) is still no plain
	 * return; a meet with any other stack poisons.
	 */
	private static final Pushed UNDER = new Pushed(-1, UNKNOWN);

	private static final List<Pushed> UNWOUND = List.of(UNDER);

	/** Dataflow state before an instruction. {@code stack == null} means poisoned. */
	private record State(int dp, int a, int x, int y, List<Pushed> stack) {

		/**
		 * {@link #meet} for the page-alignment proof's carried walks (grm-9nxj.55): pushed items of
		 * equal width and kind that differ in value merge to an unknown value instead of
		 * poisoning the stack (FF3's {@code $C5:0211} loop {@code PHX ... PLX}, X known on the
		 * first pass only). Only the proof reads these walks; the stamps and call summaries use
		 * the strict meet.
		 */
		State meetLoose(State o) {
			return new State(dp == o.dp ? dp : UNKNOWN, a == o.a ? a : UNKNOWN,
				x == o.x ? x : UNKNOWN, y == o.y ? y : UNKNOWN, meetStackLoose(stack, o.stack));
		}

		private static List<Pushed> meetStackLoose(List<Pushed> p, List<Pushed> q) {
			if (p == null || q == null) {
				return null;
			}
			if (p.equals(q)) {
				return p;
			}
			int k = 0;
			List<Pushed> rev = new ArrayList<>();   // top first
			while (k < p.size() && k < q.size()) {
				Pushed u = p.get(p.size() - 1 - k);
				Pushed v = q.get(q.size() - 1 - k);
				if (u.equals(v)) {
					rev.add(u);
				}
				else if (u.width > 0 && u.width == v.width && u.phd == v.phd) {
					rev.add(new Pushed(u.width, UNKNOWN, u.phd));
				}
				else {
					break;
				}
				k++;
			}
			if (k == 0) {
				return null;
			}
			List<Pushed> out = new ArrayList<>(k + 1);
			if (!rev.get(k - 1).equals(FLOOR) && (k < p.size() || k < q.size())) {
				out.add(FLOOR);
			}
			for (int i = k - 1; i >= 0; i--) {
				out.add(rev.get(i));
			}
			return List.copyOf(out);
		}

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
		int[] aligned = markPageAlignedWriters(program, w, all, monitor);
		AnalyzerLog.info(this, "DP writers proven page-aligned: " + aligned[0] + " of " +
			aligned[1] + (aligned[0] == aligned[1] ? " (D's low byte is $00 program-wide: proven)"
					: hinted(program) ? " (D's low byte is $00 program-wide: hinted by the " +
						"game descriptor)" : ""));
		int[] warned = bookmarkSeeds(program, w.seeds, monitor);
		int[] cc = assignDpPreserved(program, w, monitor);
		if (stamped > 0 || refs > 0 || cc[0] > 0 || cc[1] > 0) {
			AnalyzerLog.info(this, "DP stamped over " + stamped + " instructions, " + refs +
				" dp operand references added; " + warned[0] + " entries seeded past unknown " +
				"ways in, " + warned[1] + " with disagreeing ways in; " + cc[0] + " functions " +
				"given " + DP_PRESERVED + ", " + cc[1] + " taken off it");
		}
		return true;
	}

	/**
	 * User property map of the DP writers ({@code TCD}, {@code PLD}) proven to set a page-aligned
	 * DP (low byte $00) in every walk that reaches them (grm-9nxj.49). The map's existence means
	 * this analyzer ran; see {@link #lowByteZero}.
	 */
	static final String ALIGNED_MAP = "W65816 DP page-aligned writers";

	/** {@code GRM_DP_ALIGN_TRACE=1} prints each DP writer the page-alignment proof fails at. */
	private static final boolean ALIGN_TRACE = System.getenv("GRM_DP_ALIGN_TRACE") != null;

	/**
	 * Whether D's low byte is $00 everywhere in {@code program}, interrupt handlers included
	 * (grm-9nxj.49, owner ruling 2026-11-23): this analyzer ran and proved every {@code TCD} and
	 * {@code PLD} in the listing page-aligned. By induction from RESET (D = $0000) every D ever
	 * held is then page-aligned, whatever code was interrupted. FF3's NMI prologue
	 * {@code TDC / PHA / PLB} (M=1) reads it. Fails closed: a writer nobody proved (or one added
	 * since the analyzer ran) breaks it. Code that was never disassembled is not seen, and a
	 * stack-relative store into a PHD-pushed word before its PLD is not modelled (the walk's
	 * own {@code PHD ... PLD} restore assumes the same).
	 */
	static boolean lowByteZero(Program program) {
		return hinted(program) || proven(program);
	}

	/** True when the resolved game descriptor asserts D's low byte is $00 (grm-hb6.31). */
	static boolean hinted(Program program) {
		return "true".equals(program.getOptions(Program.PROGRAM_INFO)
				.getString(DescriptorHints.W65816_DP_PAGE_ALIGNED_PROPERTY, null));
	}

	/** True when the analyzer's own proof covers every DP writer in the listing. */
	static boolean proven(Program program) {
		IntPropertyMap m = program.getUsrPropertyManager().getIntPropertyMap(ALIGNED_MAP);
		if (m == null) {
			return false;
		}
		for (Instruction i : program.getListing().getInstructions(true)) {
			if (isDpWriter(i) && !m.hasProperty(i.getAddress())) {
				return false;
			}
		}
		return true;
	}

	private static boolean isDpWriter(Instruction i) {
		W65816Shapes.Transfer tr = W65816Shapes.transfer(i);
		if (tr != null && tr.dst() == W65816Shapes.Role.DP) {
			return true;
		}
		W65816Shapes.Pull pl = W65816Shapes.pull(i);
		return pl != null && pl.role() == W65816Shapes.Role.DP;
	}

	/**
	 * Rewrites {@link #ALIGNED_MAP}: a DP writer is marked when at least one walk reaches it and
	 * in every walk state there, a {@code TCD} copies a known A with low byte $00, and a
	 * {@code PLD} pulls a word pushed by {@code PHD} (the D of the moment, page-aligned by
	 * induction) or a known word with low byte $00.
	 *
	 * <p>The states come from three places (grm-9nxj.55; FF3 proved 51 of 54 before, 54 of 54
	 * now). The ordinary function walks, except those of functions entered only by jumps
	 * ({@link Walker#jumpEntered}): such a function runs on its jumper's stack, so FF3's shared
	 * epilogue {@code $C5:0171 ... PLD / PLB / RTL}, whose walk from an empty stack pulls below its
	 * entry, is judged by {@link Walker#carriedWalks} instead, walked with the stack of each jump
	 * into it (through the dispatch handlers that tail-jump to it, transitively). And, for a
	 * writer nothing else reaches, the walks from dispatch JMP targets that are no function's entry
	 * ({@link Walker#dispatchRootWalks}: FF3's event-command handlers inside {@code $C0:9C44}).
	 * Every state at a writer must prove it, as before.
	 *
	 * @return {marked, writers}
	 */
	private static int[] markPageAlignedWriters(Program program, Walker w,
			Map<Function, Map<Address, State>> all, TaskMonitor monitor) throws CancelledException {
		Map<Address, List<State>> at = new HashMap<>();
		for (Instruction i : program.getListing().getInstructions(true)) {
			monitor.checkCancelled();
			if (isDpWriter(i)) {
				at.put(i.getAddress(), new ArrayList<>());
			}
		}
		List<Map<Address, State>> roots = w.dispatchRootWalks(monitor);
		Set<Function> carried = w.jumpEntered(all.keySet(), monitor);
		for (Map.Entry<Function, Map<Address, State>> fe : all.entrySet()) {
			if (!carried.contains(fe.getKey())) {
				collectWriters(fe.getValue(), at);
			}
		}
		// Jump-entered functions are judged with the stacks their jumpers hand them (grm-9nxj.55).
		for (Map<Address, State> states : w.carriedWalks(carried, all, roots, monitor)) {
			collectWriters(states, at);
		}
		// A writer no walk reaches may sit in a dispatch handler that no function's walk follows:
		// the roots' walks (see dispatchRootWalks) stand in, and only for such a writer.
		Set<Address> unreached = new HashSet<>();
		at.forEach((a, l) -> {
			if (l.isEmpty()) {
				unreached.add(a);
			}
		});
		if (!unreached.isEmpty()) {
			for (Map<Address, State> states : roots) {
				for (Map.Entry<Address, State> e : states.entrySet()) {
					if (unreached.contains(e.getKey())) {
						at.get(e.getKey()).add(e.getValue());
					}
				}
			}
		}
		PropertyMapManager pm = program.getUsrPropertyManager();
		pm.removePropertyMap(ALIGNED_MAP);
		IntPropertyMap m;
		try {
			m = pm.createIntPropertyMap(ALIGNED_MAP);
		}
		catch (DuplicateNameException e) {
			return new int[] { 0, at.size() };   // cannot happen: removed just above
		}
		int marked = 0;
		for (Map.Entry<Address, List<State>> e : at.entrySet()) {
			Instruction i = program.getListing().getInstructionAt(e.getKey());
			String why = e.getValue().isEmpty() ? "no walk reaches it" : null;
			for (State s : e.getValue()) {
				why = why != null ? why : alignFailure(i, s);
			}
			if (why == null) {
				m.add(e.getKey(), 1);
				marked++;
			}
			else if (ALIGN_TRACE) {
				System.out.println("DP-ALIGN fails at " + e.getKey() + " " + i + ": " + why);
			}
		}
		return new int[] { marked, at.size() };
	}

	private static void collectWriters(Map<Address, State> states, Map<Address, List<State>> at) {
		for (Map.Entry<Address, State> e : states.entrySet()) {
			List<State> l = at.get(e.getKey());
			if (l != null) {
				l.add(e.getValue());
			}
		}
	}

	/** Why {@code s} does not prove writer {@code i} page-aligned; null when it does. */
	private static String alignFailure(Instruction i, State s) {
		W65816Shapes.Transfer tr = W65816Shapes.transfer(i);
		if (tr != null) {
			return s.a >= 0 && (s.a & 0xff) == 0 ? null :
				"TCD with A " + (s.a >= 0 ? String.format("$%04X", s.a) : "unknown");
		}
		if (s.stack == null) {
			return "PLD on a poisoned stack";
		}
		if (s.stack.isEmpty() || s.stack.equals(UNWOUND)) {
			return "PLD pulls below the walk's entry";
		}
		Pushed top = s.stack.get(s.stack.size() - 1);
		if (top.width != 2) {
			return "PLD pulls a " + top.width + "-byte item";
		}
		if (top.phd || (top.value >= 0 && (top.value & 0xff) == 0)) {
			return null;
		}
		return "PLD pulls " + (top.value >= 0 ? String.format("$%04X", top.value) : "an unknown word");
	}

	/** The w65816.cspec prototype that declares DP unaffected by a call (grm-hf5h.28). */
	static final String DP_PRESERVED = "__dp_preserved";

	/**
	 * Gives {@link #DP_PRESERVED} to every function whose call summary proves the caller's DP
	 * survives the call (verdict "preserves" or "restores", exactly as {@code afterCall} judges
	 * it), so the decompiler stops treating DP as clobbered after the call (grm-hf5h.28). Only a
	 * function with no convention of its own (unknown/default/the default prototype's name) is
	 * changed; one carrying {@link #DP_PRESERVED} that no longer qualifies goes back to unknown.
	 * Program-wide, like the solve. Thunks are skipped (setting one would set its target).
	 *
	 * @return {given, removed} counts
	 */
	private static int[] assignDpPreserved(Program program, Walker w, TaskMonitor monitor)
			throws CancelledException {
		int[] n = new int[2];
		var fm = program.getFunctionManager();
		if (fm.getCallingConvention(DP_PRESERVED) == null) {
			return n;   // a cspec without the prototype (should not happen for w65816)
		}
		var dfltModel = fm.getDefaultCallingConvention();
		String dflt = dfltModel == null ? null : dfltModel.getName();
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			String cur = f.getCallingConventionName();
			// Ours: any of the preserving prototypes (grm-9nxj.32 added the DBR pair; the DBR
			// analyzer owns that half of the verdict, this one the DP half).
			boolean ours = W65816DataBankAnalyzer.isOurs(cur);
			boolean hadDp = W65816DataBankAnalyzer.hasDp(cur);
			boolean unset = cur == null || cur.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) ||
				cur.equals(Function.DEFAULT_CALLING_CONVENTION_STRING) || cur.equals(dflt);
			if (!ours && !unset) {
				continue;   // a convention someone chose: never override it
			}
			Address at = f.getEntryPoint();
			boolean keeps = w.preserves(at) || w.exitDp(at) == ENTRY_DP;
			try {
				if (keeps != hadDp) {
					f.setCallingConvention(
						W65816DataBankAnalyzer.compose(keeps, W65816DataBankAnalyzer.hasDbr(cur)));
					if (keeps) {
						n[0]++;
					}
					else {
						n[1]++;
					}
				}
			}
			catch (InvalidInputException e) {
				return n;   // the prototype is not registered after all
			}
		}
		return n;
	}

	/**
	 * Warning bookmarks at each function entry seeded while ignoring ways in with unknown DP, and
	 * at each entry whose known ways in disagree (grm-9nxj.28). Program-wide like the solve, so
	 * the previous run's are cleared first. The message prefixes {@code "DP assumed"} and
	 * {@code "DP conflict"} are what W65816WidthDump counts.
	 *
	 * @return {assumed, conflict} counts
	 */
	private static int[] bookmarkSeeds(Program program, Map<Function, Walker.Seed> seeds,
			TaskMonitor monitor) throws CancelledException {
		BookmarkManager bm = program.getBookmarkManager();
		bm.removeBookmarks(program.getMemory(), BookmarkType.WARNING, BOOKMARK_CATEGORY, monitor);
		int[] n = new int[2];
		for (Map.Entry<Function, Walker.Seed> e : seeds.entrySet()) {
			Walker.Seed s = e.getValue();
			Address at = e.getKey().getEntryPoint();
			if (s.dp() == CONFLICT) {
				StringBuilder vs = new StringBuilder();
				s.seen().stream().sorted().forEach(v ->
					vs.append(vs.length() == 0 ? "" : ", ").append(String.format("$%04X", v)));
				bm.setBookmark(at, BookmarkType.WARNING, BOOKMARK_CATEGORY,
					"DP conflict at entry: ways in carry " + vs + "; entry DP left unknown");
				n[1]++;
			}
			else if (s.unknown() > 0) {
				bm.setBookmark(at, BookmarkType.WARNING, BOOKMARK_CATEGORY,
					String.format("DP assumed $%04X at entry: %d of %d ways in carry it, %d with " +
						"unknown DP ignored", s.dp(), s.known(), s.known() + s.unknown(),
						s.unknown()));
				n[0]++;
			}
		}
		return n;
	}

	/**
	 * Whether {@code a} is a shared epilogue (pulls what its jumper pushed and never returns on its
	 * own frame); structural, uncached. Shared with {@link W65816DataBankAnalyzer} (grm-9nxj.42).
	 */
	static boolean isSharedEpilogue(Program program, Address a) {
		return Walker.scanEpilogue(program, a);
	}

	/**
	 * Read-only census hook (grm-hf5h.23): the analyzer's own call-summary verdict for a call
	 * target, exactly as {@code afterCall} judges it, for probes that ask which callees really
	 * change the caller's DP. One instance caches across targets, like one analysis run.
	 */
	public static final class CallSummaries {
		private final Walker w;

		public CallSummaries(Program program) {
			w = new Walker(program);
		}

		/**
		 * Returns {@code "preserves"} (no visible DP change), {@code "restores"} (changes DP but
		 * returns the DP it was entered with), {@code "$XXXX"} (returns that constant), or
		 * {@code "UNKNOWN"}.
		 */
		public String verdict(Address target) {
			if (w.preserves(target)) {
				return "preserves";
			}
			int e = w.exitDp(target);
			return e == ENTRY_DP ? "restores" : Walker.dpName(e);
		}

		/** Why the last exit-DP judgement of {@code target} failed, or null. */
		public String why(Address target) {
			return w.exitWhy.get(target);
		}
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
		private final Set<Address> exitInProgress = new LinkedHashSet<>();
		/** exitDp's current assumption for each in-progress target (grm-9nxj.30). */
		private final Map<Address, Integer> exitAssume = new HashMap<>();
		/** The in-progress targets the current exitDp judgement has leaned on. */
		private Set<Address> exitLeaned = new HashSet<>();
		/** Results awaiting confirmation of the assumptions they leaned on. */
		private final List<Provisional> exitProvisional = new ArrayList<>();
		/** Why each failed exit-DP judgement failed (CallSummaries only; never read by analysis). */
		private final Map<Address, String> exitWhy = new HashMap<>();
		/**
		 * How each judged target returns to its caller: the RTS/RTL mnemonics of its accepted
		 * exits, through tail calls; "?" for an exit whose kind is not known (a dispatch JMP, a
		 * tail target still in progress). Recorded only for a walk that judged every exit.
		 */
		private final Map<Address, Set<String>> exitKinds = new HashMap<>();
		/**
		 * Bytes of its caller's stack a summarized routine drops ({@link W65816CalleePop},
		 * grm-9nxj.50): 0 or more when its walk succeeded, absent when it did not.
		 */
		private final Map<Address, Integer> exitPurge = new HashMap<>();
		/** Whether a function's body has an argument-dropping tail ({@link W65816CalleePop}). */
		private final Map<Address, Boolean> popTail = new HashMap<>();
		/** {@link #isEpilogue} decisions: a shared epilogue pulls what its jumper pushed. */
		private final Map<Address, Boolean> epilogues = new HashMap<>();
		/** Trace only (GRM_DP_SUMMARY_TRACE): where DP turned UNKNOWN in the walk in progress. */
		private Set<String> notes;
		private Set<String> lastNotes;
		private int recHits;
		private final List<String> recLog = new ArrayList<>();

		Walker(Program program) {
			this.program = program;
			dpReg = program.getRegister("DP");
			tracked = new Register[] { program.getRegister("C"), program.getRegister("X"),
				program.getRegister("Y"), program.getRegister("SP"), dpReg };
			ctxM = program.getRegister("ctx_MF");
			ctxX = program.getRegister("ctx_XF");
		}

		/** How each seeded or conflicted entry was judged, for the bookmarks (grm-9nxj.28). */
		record Seed(int dp, Set<Integer> seen, int known, int unknown) {}

		final Map<Function, Seed> seeds = new LinkedHashMap<>();

		/**
		 * Slice 2 (grm-9nxj.26), loosened by grm-9nxj.28: every function's walk, with its entry DP
		 * seeded from its ways in -- each flow reference to its entry (call, jump, branch,
		 * computed jump) and a fall-through from the instruction before it, judged at the source
		 * in the source function's walk (a call carries the DP before it; anything else the DP
		 * after it). A way in whose DP is unknown (or that lies outside every function, or that
		 * its walk does not reach) is IGNORED; the entry is seeded with d once at least one way in
		 * carries a known DP and every known one carries d (owner ruling 2026-11-03: a routine
		 * entered with arbitrary DPs is judged unlikely; {@link #seeds} records how many were
		 * ignored, for a warning). Known ways in that disagree make the entry a CONFLICT, which is
		 * sticky. An external entry point, and a data reference to the entry (a pointer or vector)
		 * unless a computed jump also resolved to it, still leave it UNKNOWN.
		 *
		 * <p>A seeded function's ways out are judged in one walk per entry DP it has seen, and
		 * carry the union (grm-9nxj.38). A CONFLICT entry's own walk runs with UNKNOWN, so reading
		 * that one instead would drop what it passes on: a callee seeded from the first value to
		 * arrive kept it, and one reached only after the conflict stayed unseeded, so the answer
		 * depended on solve order (w_ff2 thunk 048004 -> 048107). Now a DP that passes through a
		 * conflict entry reaches the callee as both values, a conflict there too.
		 *
		 * <p>Termination and order-independence: the values each entry has seen only accumulate,
		 * and the set a way out carries is monotone in its function's seen set (a walk is a pure
		 * function of its entry DP; call summaries do not read the solve), so this is a least
		 * fixpoint over finite sets of DP constants. Each entry is re-walked only when its set
		 * grows, once per new value plus once with UNKNOWN on becoming a CONFLICT.
		 */
		Map<Function, Map<Address, State>> solve(TaskMonitor monitor) throws CancelledException {
			var fm = program.getFunctionManager();
			Map<Function, Map<Address, State>> states = new LinkedHashMap<>();
			for (Function f : fm.getFunctions(true)) {
				monitor.checkCancelled();
				states.put(f, walk(f, ENTRY));
			}
			// Sources into each entry, and which functions' seeds read each function's states.
			Map<Function, List<Address>> sources = new LinkedHashMap<>();
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
			Map<Function, Set<Integer>> seen = new HashMap<>();
			Map<Function, Integer> entry = new LinkedHashMap<>();   // absent: unseeded
			// The walks a seeded function's ways out are read from: one per entry DP it has seen
			// (grm-9nxj.38). A CONFLICT entry's own walk (states) runs with UNKNOWN, which would
			// hide every DP it passes on; reading its per-value walks instead makes a conflict
			// reach its callees as a conflict, whatever order the entries were solved in.
			Map<Function, Map<Integer, Map<Address, State>>> byValue = new HashMap<>();
			while (!work.isEmpty()) {
				monitor.checkCancelled();
				Function g = work.poll();
				queued.remove(g);
				Set<Integer> s = seen.computeIfAbsent(g, k -> new LinkedHashSet<>());
				int before = s.size();
				knownEntryDpsBySource(sources.get(g), states, byValue).values()
						.forEach(s::addAll);
				if (s.size() == before) {
					continue;
				}
				int now = s.size() == 1 ? s.iterator().next() : CONFLICT;
				entry.put(g, now);
				Map<Integer, Map<Address, State>> walks =
					byValue.computeIfAbsent(g, k -> new LinkedHashMap<>());
				for (int v : s) {
					walks.computeIfAbsent(v,
						k -> walk(g, new State(k, UNKNOWN, UNKNOWN, UNKNOWN, List.of())));
				}
				states.put(g, now == CONFLICT ? walk(g, ENTRY) : walks.get(now));
				for (Function c : dependents.getOrDefault(g, Set.of())) {
					if (!blocked.contains(c) && queued.add(c)) {
						work.add(c);
					}
				}
			}
			// The final count of known and ignored ways in, against the final walks.
			for (Map.Entry<Function, Integer> e : entry.entrySet()) {
				List<Address> src = sources.get(e.getKey());
				int known = knownEntryDpsBySource(src, states, byValue).size();
				seeds.put(e.getKey(), new Seed(e.getValue(), Set.copyOf(seen.get(e.getKey())),
					known, src.size() - known));
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
			if (before != null && entry.equals(W65816FarCall.fallThrough(before))) {
				out.add(before.getMinAddress());
			}
			return out.isEmpty() ? null : out;
		}

		/**
		 * The known DPs each way in carries, keyed by source; a source with no known DP (no
		 * instruction, outside every function, not reached by its walk, or DP unknown there) is
		 * absent. A source inside overlapping bodies may carry more than one.
		 */
		private Map<Address, Set<Integer>> knownEntryDpsBySource(List<Address> src,
				Map<Function, Map<Address, State>> states,
				Map<Function, Map<Integer, Map<Address, State>>> byValue) {
			Map<Address, Set<Integer>> out = new LinkedHashMap<>();
			for (Address s : src) {
				Instruction ins = program.getListing().getInstructionAt(s);
				if (ins == null) {
					continue;
				}
				for (Function f : functionsAt(s)) {
					Map<Integer, Map<Address, State>> walks = byValue.get(f);
					Collection<Map<Address, State>> from = walks != null ? walks.values()
							: states.get(f) == null ? List.of() : List.of(states.get(f));
					for (Map<Address, State> w : from) {
						State st = w.get(s);
						if (st == null) {
							continue;
						}
						int v = W65816FarCall.flow(ins).isCall() ? st.dp : transfer(ins, st).dp;
						if (v != UNKNOWN) {
							out.computeIfAbsent(s, k -> new LinkedHashSet<>()).add(v);
						}
					}
				}
			}
			return out;
		}

		/** A walk whose jumps are yet to be scanned; {@code owner} null for a dispatch root. */
		private record Pending(Function owner, Map<Address, State> states) {}

		/** Distinct jumper stacks a jump-entered function is walked with before giving up (poisoned). */
		private static final int CARRY_LIMIT = 8;

		/**
		 * The targets control can jump to from {@code ins} without a return: a plain or
		 * conditional jump, a CALL_RETURN-overridden tail jump, or an unconditional dispatch JMP.
		 * A real call, a return and any other computed transfer have none.
		 */
		private static List<Address> jumpTargets(Instruction ins) {
			var ft = W65816FarCall.flow(ins);
			boolean jump = ft.isCall() ? isTailCall(ft) :
				ft.isJump() && (!ft.isComputed() || isDispatchJmp(ins));
			return jump ? List.of(ins.getFlows()) : List.of();
		}

		/**
		 * Functions entered only by jumps (grm-9nxj.55): every way into the entry is a jump, branch,
		 * tail jump or dispatch JMP; a data reference counts only when a dispatch JMP resolved to
		 * the entry too (a table slot of that dispatcher; optimistic, as rule A); no external
		 * entry point and no fall-through from the instruction before. Such a function runs on its
		 * jumper's stack, so a walk from an empty stack is not a way it is ever entered.
		 */
		Set<Function> jumpEntered(Collection<Function> fns, TaskMonitor monitor)
				throws CancelledException {
			Set<Function> out = new LinkedHashSet<>();
			for (Function g : fns) {
				monitor.checkCancelled();
				if (isJumpEntered(g)) {
					out.add(g);
				}
			}
			return out;
		}

		private boolean isJumpEntered(Function g) {
			Address entry = g.getEntryPoint();
			if (program.getSymbolTable().isExternalEntryPoint(entry)) {
				return false;
			}
			Instruction before = program.getListing().getInstructionBefore(entry);
			if (before != null && entry.equals(W65816FarCall.fallThrough(before))) {
				return false;
			}
			boolean flow = false;
			boolean data = false;
			boolean computed = false;
			for (Reference r : program.getReferenceManager().getReferencesTo(entry)) {
				if (!r.getReferenceType().isFlow()) {
					data = true;
					continue;
				}
				Instruction src = program.getListing().getInstructionAt(r.getFromAddress());
				if (src == null || !jumpTargets(src).contains(entry)) {
					return false;
				}
				flow = true;
				computed |= r.getReferenceType().isComputed();
			}
			return flow && (!data || computed);
		}

		/**
		 * Walks each jump-entered function with the stack its jumpers carry (grm-9nxj.55), the DP
		 * twin of the DBR analyzer's {@code intoEpilogues}/{@code intoBody} (grm-9nxj.42/.49)
		 * for the page-alignment proof: FF3's sound driver leaves {@code PHB / PHD / PHP ...}
		 * pushed through {@code JMP (tbl,X)} into handlers that tail-jump to the shared epilogue
		 * {@code $C5:0171 ... PLD / PLB / RTL}, so that epilogue's {@code PLD} pulls the
		 * dispatcher's {@code PHD}. The entry states are the in-states of the jumps into each,
		 * from the ordinary walks of every function that is not itself jump-entered and,
		 * transitively, from these walks; one walk per distinct stack. Registers are forgotten.
		 */
		List<Map<Address, State>> carriedWalks(Set<Function> carried,
				Map<Function, Map<Address, State>> all, List<Map<Address, State>> roots,
				TaskMonitor monitor)
				throws CancelledException {
			List<Map<Address, State>> out = new ArrayList<>();
			if (carried.isEmpty()) {
				return out;
			}
			Map<Address, Function> byEntry = new HashMap<>();
			for (Function g : carried) {
				byEntry.put(g.getEntryPoint(), g);
			}
			Map<Function, Set<List<Pushed>>> seen = new HashMap<>();
			ArrayDeque<Pending> pending = new ArrayDeque<>();
			for (Map.Entry<Function, Map<Address, State>> e : all.entrySet()) {
				if (!carried.contains(e.getKey())) {
					pending.add(new Pending(e.getKey(), e.getValue()));
				}
			}
			for (Map<Address, State> r : roots) {
				pending.add(new Pending(null, r));
			}
			while (!pending.isEmpty()) {
				monitor.checkCancelled();
				Pending p = pending.poll();
				for (Map.Entry<Address, State> e : p.states().entrySet()) {
					Instruction ins = program.getListing().getInstructionAt(e.getKey());
					if (ins == null) {
						continue;
					}
					for (Address t : jumpTargets(ins)) {
						Function h = byEntry.get(t);
						if (h == null || h.equals(p.owner())) {
							continue;
						}
						Set<List<Pushed>> stacks = seen.computeIfAbsent(h, k -> new HashSet<>());
						List<Pushed> stack = e.getValue().stack;
						if (stacks.size() >= CARRY_LIMIT) {
							stack = null;   // too many distinct frames: fail closed
						}
						if (stacks.add(stack)) {
							Map<Address, State> ws =
								walk(h.getEntryPoint(), h,
									new State(UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, stack), false, true);
							out.add(ws);
							pending.add(new Pending(h, ws));
						}
					}
				}
			}
			return out;
		}

		/**
		 * Walks from each resolved target of a dispatch JMP that is no function's entry, over an
		 * empty stack and bounded by the function body holding it (grm-9nxj.55: FF3's
		 * event-command handlers inside {@code $C0:9C44}'s body are reached only through the
		 * command table, so no function walk follows them). Sound for a handler's own
		 * {@code PHD ... PLD}: whatever frame the dispatcher left, the pair nests above it; a pull
		 * below the handler's entry fails the proof. The walks stand in for an unreached writer
		 * only, and their jumps feed {@link #carriedWalks}.
		 */
		List<Map<Address, State>> dispatchRootWalks(TaskMonitor monitor)
				throws CancelledException {
			Set<Address> roots = new LinkedHashSet<>();
			for (Instruction i : program.getListing().getInstructions(true)) {
				monitor.checkCancelled();
				if (isDispatchJmp(i)) {
					roots.addAll(List.of(i.getFlows()));
				}
			}
			List<Map<Address, State>> out = new ArrayList<>();
			for (Address t : roots) {
				if (program.getFunctionManager().getFunctionAt(t) != null) {
					continue;   // its own walk covers it
				}
				for (Function f : functionsAt(t)) {
					out.add(walk(t, f, ENTRY, false, true));
				}
			}
			return out;
		}

		Map<Address, State> walk(Function f, State entry) {
			return walk(f, entry, false);
		}

		/** @param summary a call-summary walk: dispatch JMPs end the path (see isDispatchJmp) */
		Map<Address, State> walk(Function f, State entry, boolean summary) {
			return walk(f.getEntryPoint(), f, entry, summary);
		}

		/**
		 * @param start where the walk begins (a function's entry, or for a summary any address)
		 * @param f the body bounding a non-summary walk; for a summary walk, null means "no body"
		 *     (see {@link #inline})
		 */
		private Map<Address, State> walk(Address start, Function f, State entry, boolean summary) {
			return walk(start, f, entry, summary, false);
		}

		private Map<Address, State> walk(Address start, Function f, State entry, boolean summary,
				boolean loose) {
			Set<String> outerNotes = notes;
			notes = TRACE == null ? null : new LinkedHashSet<>();
			try {
				return walkBody(start, f, entry, summary, loose);
			}
			finally {
				lastNotes = notes;
				notes = outerNotes;
			}
		}

		private Map<Address, State> walkBody(Address start, Function f, State entry,
				boolean summary, boolean loose) {
			Map<Address, State> in = new LinkedHashMap<>();
			ArrayDeque<Address> work = new ArrayDeque<>();
			in.put(start, entry);
			work.add(start);
			int steps = 0;
			while (!work.isEmpty() && steps++ < STEP_LIMIT) {
				Address at = work.poll();
				Instruction ins = program.getListing().getInstructionAt(at);
				if (ins == null) {
					continue;
				}
				PushedCall pc = pushedCall(start, f, ins, in.get(at));
				State out = pc != null ? pc.after() : transfer(ins, in.get(at));
				if (out == null) {
					continue;   // a call that does not come back to its fall-through
				}
				if (notes != null && in.get(at).dp != UNKNOWN && out.dp == UNKNOWN &&
					!W65816FarCall.flow(ins).isCall()) {
					notes.add("DP written UNKNOWN at " + at + ": " + ins);
				}
				List<Address> nexts = new ArrayList<>();
				if (pc != null) {
					add(start, f, summary, nexts, pc.cont());
				}
				else {
					nexts = successors(start, f, ins, summary);
				}
				for (Address next : nexts) {
					State old = in.get(next);
					State merged = old == null ? out : loose ? old.meetLoose(out) : old.meet(out);
					if (notes != null && old != null && old.dp != UNKNOWN && out.dp != UNKNOWN &&
						merged.dp == UNKNOWN) {
						notes.add("merge at " + next + " of DP " + dpName(old.dp) + " and " +
							dpName(out.dp) + " (from " + at + ")");
					}
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

		private List<Address> successors(Function f, Instruction ins, boolean summary) {
			return successors(f.getEntryPoint(), f, ins, summary);
		}

		private List<Address> successors(Address start, Function f, Instruction ins,
				boolean summary) {
			List<Address> out = new ArrayList<>();
			var ft = W65816FarCall.flow(ins);
			if (summary && isDispatchJmp(ins)) {
				return out;
			}
			if (ft.isCall()) {
				Address[] fl = ins.getFlows();
				if (summary && isTailCall(ft) && fl.length == 1) {
					add(start, f, true, out, fl[0]);   // walked on when inline (see inline)
				}
				add(start, f, summary, out, ins.getFallThrough());
				return out;
			}
			if (ft.isTerminal()) {
				return out;
			}
			for (Address a : ins.getFlows()) {
				add(start, f, summary, out, a);
			}
			if (W65816FarCall.hasFallthrough(ins)) {
				add(start, f, summary, out, ins.getFallThrough());
			}
			return out;
		}

		private void add(Address start, Function f, boolean summary, List<Address> out,
				Address a) {
			if (a != null && (summary ? inline(start, f, a) : f.getBody().contains(a))) {
				out.add(a);
			}
		}

		/** A jump that is a call through a pushed return address: where it returns, and how. */
		private record PushedCall(Address cont, State after) {
		}

		/**
		 * A tail jump into another function reached with a known return address of this routine's
		 * own on top of the stack, ported from the DBR analyzer (grm-9nxj.52): F-Zero's far call
		 * {@code $00:D0AA PHK / PER $D0B1 / JML $03:99C5}, or {@code PEA ret-1 / JMP f} for an RTS
		 * routine. When every exit of {@code f} is one RTL (bank byte under the return word) or
		 * one RTS (the return word; the bank is {@code f}'s), control comes back to {@code ret}
		 * with those items pulled and {@code f}'s summary applied: the jump is a call, not an
		 * exit. Before this d0aa's exits read {@code {RTL}} (the JML's target's), so
		 * {@code JSR $D0AA} looked like a hand-rolled JSL. Null otherwise.
		 */
		private PushedCall pushedCall(Address start, Function f, Instruction ins, State s) {
			var ft = W65816FarCall.flow(ins);
			Address[] fl = ins.getFlows();
			if (s == null || s.stack == null || s.stack.isEmpty() || ft.isComputed() ||
				ft.isConditional() || fl.length != 1 ||
				!((!ft.isCall() && ft.isJump()) || isTailCall(ft))) {
				return null;
			}
			List<Pushed> stk = s.stack;
			int n = stk.size();
			Pushed top = stk.get(n - 1);
			// Cheap shape test first: the summary questions below are costly at every jump.
			if (top.width != 2 || top.value == UNKNOWN || inline(start, f, fl[0]) ||
				neverReturns(fl[0]) || hasPopTail(fl[0])) {
				return null;
			}
			int te = exitDp(fl[0]);
			Set<String> kinds = exitKinds.get(fl[0]);
			if (traced(ins.getAddress())) {
				System.out.println("DPS   pushedCall? " + ins.getAddress() + " to " + fl[0] +
					" kinds=" + kinds + " stack=" + stk);
			}
			boolean rtl = Set.of("RTL").equals(kinds);
			if (!rtl && !Set.of("RTS").equals(kinds)) {
				return null;
			}
			int items = rtl ? 2 : 1;
			if (n < items) {
				return null;
			}
			Pushed word = stk.get(n - 1);
			Pushed bank = rtl ? stk.get(n - 2) : null;
			if (word.width != 2 || word.value == UNKNOWN ||
				(rtl && (bank.width != 1 || bank.value == UNKNOWN))) {
				return null;
			}
			int b = rtl ? bank.value : (int) ((fl[0].getOffset() >> 16) & 0xff);
			long ret = (long) b << 16 | ((word.value + 1) & 0xffff);
			Address cont = ins.getAddress().getAddressSpace().getAddress(ret);
			if (traced(ins.getAddress())) {
				System.out.println("DPS   pushedCall " + ins.getAddress() + " cont=" + cont +
					" ins=" + program.getListing().getInstructionAt(cont));
			}
			if (program.getListing().getInstructionAt(cont) == null) {
				return null;
			}
			int dp = preserves(fl[0]) ? s.dp : te == ENTRY_DP ? s.dp : te;
			return new PushedCall(cont, new State(dp, UNKNOWN, UNKNOWN, UNKNOWN,
				List.copyOf(stk.subList(0, n - items))));
		}

		/**
		 * Whether a summary walk from {@code start} follows flow into {@code a} (grm-9nxj.30/.31):
		 * yes inside {@code f}'s body, and yes outside it too unless {@code a} is another
		 * function's entry -- that is a tail exit judged by its own (cached) summary instead. Ghidra's
		 * body is an artifact of its function creation, not of the code: FF2's shared-tail stubs
		 * ({@code $01:8D2F}: {@code LDX #imm / BRA common}) and tail calls into code that is no
		 * function ({@code $00:B288}, {@code $15:B4B7}) leave every body without entering another.
		 * The empty-stack rule at each return still decides which RTS/RTL is the call's.
		 *
		 * <p>Also yes into another function's entry that is a shared epilogue (grm-hf5h.26):
		 * judged alone, from an empty stack, a shared epilogue ({@code PLY / PLX / PLA / PLP / PLD /
		 * PLB / RTL}, FF3's {@code $C5:0171}, entered by {@code BRA} from both sound-driver entries
		 * after their {@code PHB / PHD / PHP} prologues) pulls nothing it knows; walked on with the
		 * jumper's stack, its {@code PLD} pulls the jumper's {@code PHD}. A target that judges to
		 * a value, or fails for any other reason, stays a tail exit, as before. Only the epilogue
		 * case is followed: inlining every failing target timed out on FF2, FF3 and CT.
		 */
		private boolean inline(Address start, Function f, Address a) {
			return a.equals(start) || (f != null && f.getBody().contains(a)) ||
				program.getFunctionManager().getFunctionAt(a) == null || isEpilogue(a);
		}

		/**
		 * Whether {@code a} is a shared epilogue: code that pulls what its jumper pushed and never
		 * returns on its own frame (see {@link #scanEpilogue}). Structural and cached, deliberately
		 * NOT derived from {@link #exitDp}: asking the
		 * summary machinery from {@link #inline}, at every successor of a summary walk, multiplied
		 * the recursion retries on FF2's ring of mutually tail-jumping routines ($00:B2DC-B3FE,
		 * ~150,000 judgements each) and the row timed out.
		 */
		private boolean isEpilogue(Address a) {
			return epilogues.computeIfAbsent(a, t -> scanEpilogue(program, t));
		}

		private static final int EPILOGUE_SCAN = 4096;   // FF3 $C5:0180 handler is several hundred

		/**
		 * Every path from {@code a} (calls stepped over, flows of a computed jump not followed),
		 * counting its own pushes and pulls: an epilogue when some path pulls with nothing of its
		 * own pushed, and no path reaches an RTS/RTL or RTI with its own pushes balanced (a
		 * routine that can also return normally is not one). FF3's sound handlers ($C5:05A6)
		 * do their work and then tail-jump into the shared epilogue. Gives up (false) past
		 * {@link #EPILOGUE_SCAN} instructions or on a depth that differs between two paths.
		 */
		static boolean scanEpilogue(Program program, Address a) {
			Map<Address, Integer> seen = new HashMap<>();
			ArrayDeque<Address> work = new ArrayDeque<>();
			seen.put(a, 0);
			work.add(a);
			boolean pullsBelow = false;
			while (!work.isEmpty()) {
				if (seen.size() > EPILOGUE_SCAN) {
					return false;
				}
				Address at = work.poll();
				int depth = seen.get(at);
				Instruction i = program.getListing().getInstructionAt(at);
				if (i == null) {
					return false;
				}
				// Counts push and pull INSTRUCTIONS, not bytes (a W4 candidate: bytes).
				if (W65816Shapes.push(i) != null) {
					depth++;
				}
				else if (W65816Shapes.pull(i) != null) {
					if (depth == 0) {
						pullsBelow = true;
						continue;   // this path now belongs to the jumper's frame
					}
					depth--;
				}
				else if (W65816Shapes.isReturn(i) || MosOperands.isInterruptReturn(i)) {
					return false;   // returns with its own pushes balanced: a routine
				}
				var ft = W65816FarCall.flow(i);
				List<Address> next = new ArrayList<>();
				if (ft.isCall() || ft.isComputed()) {
					if (!ft.isTerminal() && i.getFallThrough() != null) {
						next.add(i.getFallThrough());
					}
					if (ft.isCall() && ft.isTerminal() && i.getFlows().length == 1) {
						next.add(i.getFlows()[0]);   // a tail call (CALL_RETURN override)
					}
				}
				else {
					next.addAll(List.of(i.getFlows()));
					if (W65816FarCall.fallThrough(i) != null) {
						next.add(W65816FarCall.fallThrough(i));
					}
				}
				for (Address n : next) {
					Integer d = seen.putIfAbsent(n, depth);
					if (d == null) {
						work.add(n);
					}
					else if (d != depth) {
						return false;
					}
				}
			}
			return pullsBelow;
		}

		/**
		 * A call-flow instruction that never returns here: a JMP or branch carrying Ghidra's
		 * CALL_RETURN override (FF2 {@code $00:e660}, FF3 {@code $C5:012F} {@code BRA}), a tail call.
		 */
		private static boolean isTailCall(FlowType ft) {
			return ft.isCall() && ft.isTerminal() && !ft.isConditional();
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
			List<Pushed> l = new ArrayList<>(
				s.stack == null || s.stack.equals(UNWOUND) ? List.of(FLOOR) : s.stack);
			l.add(p);
			return new State(s.dp, s.a, s.x, s.y, List.copyOf(l));
		}

		/** Pops {@code width} bytes; the popped value, or UNKNOWN; second element is the new state. */
		private static Object[] pop(State s, int width) {
			if (s.stack == null || width == UNKNOWN) {
				return new Object[] { UNKNOWN, new State(s.dp, s.a, s.x, s.y, null) };
			}
			if (s.stack.isEmpty() || s.stack.equals(UNWOUND)) {
				// The caller's data (its return address, say): unknown, and the stack below is
				// no longer the entry's, so an RTS after this is not a plain return to the call.
				return new Object[] { UNKNOWN, new State(s.dp, s.a, s.x, s.y, UNWOUND) };
			}
			Pushed top = s.stack.get(s.stack.size() - 1);
			int n = s.stack.size();
			if (width == 2 && top.width == 1 && n >= 2 && s.stack.get(n - 2).width == 1) {
				// Two byte pushes pulled as one word (FF3 $C5:015C: PHA / XBA / PHA / PLX with A
				// 8-bit and X 16-bit; grm-hf5h.26): the stack is bytes, so consume both; value unknown.
				return new Object[] { UNKNOWN,
					new State(s.dp, s.a, s.x, s.y, List.copyOf(s.stack.subList(0, n - 2))) };
			}
			if (top.width != width) {
				return new Object[] { UNKNOWN, new State(s.dp, s.a, s.x, s.y, null) };
			}
			return new Object[] { top.value,
				new State(s.dp, s.a, s.x, s.y, List.copyOf(s.stack.subList(0, s.stack.size() - 1))) };
		}

		private static State with(State s, int dp, int a, int x, int y) {
			return new State(dp, a, x, y, s.stack);
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
			if (W65816Shapes.isCall(ins)) {
				return afterCall(ins, s);
			}
			W65816Shapes.ConstLoad cl = W65816Shapes.constLoad(ins);
			if (cl != null) {
				// Only a 16-bit immediate is a known value; an 8-bit one forgets the register.
				int v = cl.bytes() == 2 ? (int) (cl.value() & 0xffff) : UNKNOWN;
				switch (cl.role()) {
					case A:
						return with(s, s.dp, v, s.x, s.y);
					case X:
						return with(s, s.dp, s.a, v, s.y);
					default:
						return with(s, s.dp, s.a, s.x, v);
				}
			}
			W65816Shapes.Transfer tr = W65816Shapes.transfer(ins);
			if (tr != null && tr.src() == W65816Shapes.Role.A &&
				tr.dst() == W65816Shapes.Role.DP) {
				return with(s, s.a, s.a, s.x, s.y);   // TCD
			}
			W65816Shapes.Push push = W65816Shapes.push(ins);
			if (push != null) {
				switch (push.role()) {
					case A:
						return pushReg(s, width(ins, ctxM), s.a);
					case X:
						return pushReg(s, width(ins, ctxX), s.x);
					case Y:
						return pushReg(s, width(ins, ctxX), s.y);
					case DP:
						return push(s, new Pushed(2, s.dp, true));   // tagged: see unwoundFrameDp
					default:
						// A push that folds to a constant keeps its value: PEA's word, PER's
						// return address, PHK's bank (grm-9nxj.52: a far-call thunk's
						// PHK / PER / JML is recognised from them, see pushedCall). Every other
						// push (PEI, PHP, PHB) is unknown bytes.
						Long c = push.constant();
						return push(s, new Pushed(push.bytes(), c == null ? UNKNOWN :
							(int) (c & (push.bytes() == 2 ? 0xffff : 0xff))));
				}
			}
			W65816Shapes.Pull pl = W65816Shapes.pull(ins);
			if (pl != null) {
				switch (pl.role()) {
					case A: {
						Object[] r = pop(s, width(ins, ctxM));
						return with((State) r[1], s.dp, UNKNOWN, s.x, s.y);
					}
					case X: {
						Object[] r = pop(s, width(ins, ctxX));
						return with((State) r[1], s.dp, s.a, UNKNOWN, s.y);
					}
					case Y: {
						Object[] r = pop(s, width(ins, ctxX));
						return with((State) r[1], s.dp, s.a, s.x, UNKNOWN);
					}
					case DP: {
						Object[] r = pop(s, 2);
						State n = (State) r[1];
						return with(n, (Integer) r[0], s.a, s.x, s.y);
					}
					default: {
						Object[] r = pop(s, 1);   // PLP, PLB
						return (State) r[1];
					}
				}
			}
			return generic(ins, s);
		}

		private State pushReg(State s, int w, int value) {
			if (w == UNKNOWN) {
				return new State(s.dp, s.a, s.x, s.y, null);
			}
			return push(s, new Pushed(w, w == 2 ? value : UNKNOWN));
		}

		private static String dpName(int dp) {
			return dp == UNKNOWN ? "UNKNOWN" : dp == ENTRY_DP ? "ENTRY" :
				dp == CONFLICT ? "CONFLICT" : String.format("$%04X", dp);
		}

		private State afterCall(Instruction ins, State s) {
			Address[] flows = ins.getFlows();
			int dp = UNKNOWN;
			if (notes != null && s.dp != UNKNOWN && flows.length != 1) {
				notes.add("call at " + ins.getAddress() + " has " + flows.length + " flow targets");
			}
			if (flows.length == 1) {
				if (preserves(flows[0])) {
					dp = s.dp;
				}
				else {
					int e = exitDp(flows[0]);
					dp = e == ENTRY_DP ? s.dp : e;
				}
			}
			else if (flows.length > 1 && W65816FarCall.flow(ins).isComputed()) {
				// Rule A for computed calls (owner ruling 2026-11-17, grm-hf5h.26): a JSR/JSL
				// (abs,X) dispatcher with several resolved targets -- FZero RESET's main loop,
				// JSR ($8050,X) at $00:8046 -- returns with the DP it was given. Optimistic, like
				// Rule A for JMP (see isDispatchJmp): unsound if a dispatched routine changes DP.
				dp = s.dp;
			}
			if (notes != null && s.dp != UNKNOWN && dp == UNKNOWN && flows.length == 1) {
				notes.add("call at " + ins.getAddress() + " to " + flows[0] +
					" lost DP (callee summary UNKNOWN)");
			}
			if (flows.length == 1 && hasPopTail(flows[0])) {
				return new State(dp, UNKNOWN, UNKNOWN, UNKNOWN, droppedArguments(ins, s));
			}
			State back = rtlConsumesPushedBank(ins, s);
			return back == null ? null : new State(dp, UNKNOWN, UNKNOWN, UNKNOWN, back.stack);
		}

		/**
		 * The caller's stack after a call to a routine that drops its caller's arguments
		 * ({@link W65816CalleePop}, grm-9nxj.50; FF3 {@code PEA / PEA / JSR $C2:5864}): the
		 * pushed bytes are gone. Poisoned when the callee has such a tail but its summary walk
		 * could not confirm how many bytes it drops, or when the drop splits a pushed item or
		 * reaches below this routine's own pushes. Other calls leave the stack alone.
		 */
		private List<Pushed> droppedArguments(Instruction ins, State s) {
			Address[] flows = ins.getFlows();
			if (flows.length != 1 || !hasPopTail(flows[0])) {
				return s.stack;
			}
			exitDp(flows[0]);
			Integer n = exitPurge.get(flows[0]);
			if (n == null) {
				return null;
			}
			Object[] r = dropBytes(s, n);
			return (Integer) r[1] == 0 ? ((State) r[0]).stack : null;
		}

		private boolean hasPopTail(Address target) {
			return popTail.computeIfAbsent(target, t -> {
				Function f = program.getFunctionManager().getFunctionAt(t);
				if (f == null) {
					return false;
				}
				for (Instruction i : program.getListing().getInstructions(f.getBody(), true)) {
					if (W65816CalleePop.tailAt(program, i) != null) {
						return true;
					}
				}
				return false;
			});
		}

		/**
		 * Drops {@code n} bytes of pushed items off the top: the new state, and the bytes still to
		 * drop past the bottom of this routine's own pushes. The stack is poisoned when an item
		 * would be split or the top is a {@link #FLOOR}/{@link #UNDER}.
		 */
		private static Object[] dropBytes(State s, int n) {
			List<Pushed> st = s.stack;
			while (n > 0 && st != null && !st.isEmpty()) {
				Pushed top = st.get(st.size() - 1);
				if (top.width <= 0 || top.width > n) {
					st = null;
					break;
				}
				n -= top.width;
				st = List.copyOf(st.subList(0, st.size() - 1));
			}
			return new Object[] { new State(s.dp, s.a, s.x, s.y, st), st == null ? 0 : n };
		}

		/**
		 * The caller's stack after a call returns (grm-hf5h.26). A {@code JSR} into a routine that
		 * leaves only by {@code RTL} -- FZero's {@code PHK / JSR thunk} with the thunk a
		 * {@code JML} to a far routine, a hand-rolled {@code JSL} -- returns having pulled one
		 * byte more than the JSR pushed: the bank the caller pushed before it. Only a known
		 * {@code PHK} of the caller's own bank brings that RTL back here, and then the 1-byte item
		 * is dropped; any other byte sends it elsewhere, so the call has no fall-through and this
		 * returns null (grm-9nxj.49's rule, as the DBR analyzer; sound only since
		 * {@link #pushedCall} keeps {@code PHK / PER / JML} thunks such as F-Zero's d0aa out of
		 * "RTL-only", grm-9nxj.52). A routine that returns both ways leaves the depth unknown
		 * (poisoned). Otherwise the stack is as it was.
		 */
		private State rtlConsumesPushedBank(Instruction ins, State s) {
			Address[] flows = ins.getFlows();
			if (flows.length != 1 || W65816Shapes.callPushBytes(ins) != 2) {
				return s;
			}
			exitDp(flows[0]);
			Set<String> kinds = exitKinds.get(flows[0]);
			if (kinds == null || !kinds.contains("RTL")) {
				return s;
			}
			if (kinds.size() > 1) {
				return kinds.contains("?") ? s : new State(s.dp, s.a, s.x, s.y, null);
			}
			if (s.stack == null || s.stack.isEmpty() ||
				!s.stack.get(s.stack.size() - 1).equals(
					new Pushed(1, (int) ((ins.getAddress().getOffset() >> 16) & 0xff)))) {
				return null;
			}
			return (State) pop(s, 1)[1];
		}

		/**
		 * The DP a call to {@code target} returns with, whatever DP it was entered with: a
		 * constant, {@link #ENTRY_DP} (it hands back the DP it was given), or UNKNOWN. The
		 * function is walked from a symbolic entry DP; it must reach at least one RTS/RTL, every
		 * one with the same known-or-entry DP and an empty, unpoisoned stack (so it returns to the
		 * caller); and it must have no other way out -- no RTI, no computed jump leaving it, no
		 * jump without a target. Flow is followed past Ghidra's body into code that is no function
		 * (and {@code target} itself need not be one); a branch or jump into another function's
		 * entry, conditional or not, is a tail call judged by that target's summary (see
		 * {@link #inline}, grm-9nxj.30/.31). An exit taken after
		 * pulling below the entry stack with nothing pushed since ({@link #UNDER}) is ignored: it
		 * cannot return to the call. A callee that sets DP itself ({@code LDX #$0600 / PHX / PLD ... RTS})
		 * so passes its constant back, and one that brackets its own DP change
		 * ({@code PHD ... TCD ... PLD ... RTS}, FF2 {@code $04:8008}) returns the caller's DP.
		 *
		 * <p>Recursion (grm-9nxj.30, FF2 {@code df63 -> e01a -> e221 -> a966 -> 9c1d -> a5c4 ->
		 * efa5 -> df63}) is assumed, then verified: a call to a target whose summary is in progress
		 * returns that target's current assumption ({@link #ENTRY_DP} first, as {@link #preserves}
		 * assumes a cycle preserves). When the target's walk ends with the value it assumed, the
		 * assumption is a consistent fixpoint and stands; otherwise it is retried once assuming
		 * the value it did produce, and then judged with recursion UNKNOWN (the old, sound rule).
		 * A result that leaned on an assumption still open is held provisionally and cached only
		 * once every assumption it leaned on has been confirmed, so a refuted guess never sticks.
		 */
		private int exitDp(Address target) {
			Integer known = exitDp.get(target);
			if (known != null) {
				return known;
			}
			if (exitInProgress.contains(target)) {
				int v = exitAssume.getOrDefault(target, ENTRY_DP);
				exitLeaned.add(target);
				recHits++;
				if (TRACE != null) {
					String m = "recursion: " + target + " in progress, assumed " + dpName(v) +
						", chain=" + exitInProgress;
					recLog.add(m);
					if (traced(target)) {
						System.out.println("DPS exitDp " + target + " = " + dpName(v) + ": " + m);
					}
				}
				return v;
			}
			Set<Address> outerLeaned = exitLeaned;
			int result = UNKNOWN;
			Set<Address> leaned = Set.of();
			int assume = ENTRY_DP;
			for (int attempt = 0; attempt < 3; attempt++) {
				exitAssume.put(target, assume);
				exitLeaned = new HashSet<>();
				exitInProgress.add(target);
				result = exitDpOnce(target);
				exitInProgress.remove(target);
				leaned = exitLeaned;
				boolean self = leaned.remove(target);
				if (!self || result == assume || assume == UNKNOWN) {
					break;
				}
				// The assumption was refuted: forget every result that leaned on it, and retry.
				exitProvisional.removeIf(p -> p.leaned().contains(target));
				assume = attempt == 0 && result != UNKNOWN ? result : UNKNOWN;
			}
			exitAssume.remove(target);
			// The assumption about target stands: results that leaned only on it are now final.
			Iterator<Provisional> it = exitProvisional.iterator();
			while (it.hasNext()) {
				Provisional p = it.next();
				if (p.leaned().remove(target) && p.leaned().isEmpty()) {
					exitDp.putIfAbsent(p.target(), p.dp());
					it.remove();
				}
			}
			exitLeaned = outerLeaned;
			if (leaned.isEmpty()) {
				exitDp.put(target, result);
			}
			else {
				exitProvisional.add(new Provisional(target, result, leaned));
				exitLeaned.addAll(leaned);
			}
			return result;
		}

		/**
		 * How a summary walk's paths leave for the caller, whatever their DP or stack judgement:
		 * each RTS/RTL reached (not unwound), and for a tail exit its target's recorded kinds, "?"
		 * when the target has none yet or the exit is a dispatch JMP. Reads only cached kinds, so it
		 * starts no walk of its own.
		 */
		private Set<String> exitKindsOf(Address target, Function callee, Map<Address, State> states) {
			Set<String> kinds = new HashSet<>();
			for (Map.Entry<Address, State> e : states.entrySet()) {
				Instruction i = program.getListing().getInstructionAt(e.getKey());
				if (i == null || UNWOUND.equals(e.getValue().stack)) {
					continue;
				}
				var ft = W65816FarCall.flow(i);
				Address[] fl = i.getFlows();
				if (W65816Shapes.isReturn(i)) {
					kinds.add(W65816Shapes.returnKind(i));
				}
				else if (isDispatchJmp(i)) {
					kinds.add("?");
				}
				else if (!ft.isComputed() && fl.length == 1 &&
					((!ft.isCall() && ft.isJump() && !inline(target, callee, fl[0])) ||
						(isTailCall(ft) && !inline(target, callee, fl[0])))) {
					if (neverReturns(fl[0]) || pushedCall(target, callee, i, e.getValue()) != null) {
						continue;
					}
					Set<String> t = exitKinds.get(fl[0]);
					kinds.addAll(t == null ? Set.of("?") : t);
				}
			}
			return Set.copyOf(kinds);
		}

		/**
		 * Rule A extended to a dispatcher's own frame (owner ruling 2026-11-17, grm-hf5h.26): a
		 * dispatch JMP reached with the dispatcher's prologue still pushed, whose resolved handlers
		 * are all shared epilogues (see {@link #scanEpilogue}) -- they leave through the code that
		 * pulls that frame, as FF3's sound driver {@code $C5:0160 JMP ($06FE,X)} does after
		 * {@code PHB / PHD / PHP / PHA / PHX / PHY} -- exits with the DP its {@code PHD} saved.
		 * Applies only when the frame holds exactly one PHD item and nothing beneath the entry
		 * stack; returns that DP, or null when the rule does not apply.
		 */
		private Integer unwoundFrameDp(Instruction jmp, State st) {
			if (st.stack == null || st.stack.isEmpty()) {
				return null;
			}
			Integer saved = null;
			for (Pushed p : st.stack) {
				if (p.width() <= 0) {
					return null;   // FLOOR / UNDER: not the dispatcher's own frame
				}
				if (p.phd()) {
					if (saved != null) {
						return null;
					}
					saved = p.value();
				}
			}
			Address[] fl = jmp.getFlows();
			if (saved == null || saved == UNKNOWN || fl.length == 0) {
				return null;
			}
			for (Address t : fl) {
				if (!isEpilogue(t)) {
					return null;
				}
			}
			return saved;
		}

		/** {@link #neverReturns} decisions. */
		private final Map<Address, Boolean> noReturn = new HashMap<>();

		/**
		 * Whether control entering {@code a} can never come back by RTS/RTL/RTI (owner ruling
		 * 2026-11-17, grm-hf5h.26): a tail jump into such code is not an exit of a call summary,
		 * as an unwound exit is not (FF3 {@code FUN_c0c4b3}'s soft reset {@code JMP $C0FF00}, a thunk
		 * to the boot routine {@code FUN_c00019} and its endless main loop). True when Ghidra has
		 * already flagged the function (or the function a thunk reaches) no-return, or when a
		 * structural scan of every path from {@code a} -- calls stepped over, jumps, branches, tail
		 * calls and resolved computed jumps followed -- reaches no return. A computed jump with no
		 * resolved target, a missing instruction, or more than {@link W65816NoReturnProof#MAX_SCAN} instructions
		 * proves nothing either way.
		 *
		 * <p>The scan goes first and Ghidra's flag only breaks a tie (grm-hf5h.30): a scan that
		 * reaches an RTS/RTL/RTI refutes the flag. Ghidra's "Non-Returning Functions - Discovered"
		 * is a heuristic and is wrong on FF3 {@code FUN_c3072d}, which returns by RTS with its
		 * caller's DP; the flag turns every {@code JSR} to it into a CALL_TERMINATOR, and the
		 * one-JSR "thunks" Ghidra then makes of them ({@code thunk_FUN_c3072d@c315aa}) were judged
		 * UNKNOWN while the decompiler gave them the target's {@code __dp_preserved}. Writes no
		 * flag: {@link W65816NoReturnFlagAnalyzer} does (grm-hf5h.27).
		 */
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

		/** A summary computed while leaning on assumptions about in-progress targets. */
		private record Provisional(Address target, int dp, Set<Address> leaned) {}

		/** One walk of {@link #exitDp}'s judgement; caching and recursion are the caller's. */
		private int exitDpOnce(Address target) {
			// No function at the target (a tail call into shared code Ghidra made no function of):
			// walk from the target with no body; see inline.
			Function callee = program.getFunctionManager().getFunctionAt(target);
			boolean tr = traced(target);
			int hits0 = recHits;
			int log0 = recLog.size();
			int d = UNKNOWN;
			boolean ok = true;
			String why = null;
			Address whyAt = null;
			Integer purge = null;
			Map<Address, State> states =
				walk(target, callee, new State(ENTRY_DP, UNKNOWN, UNKNOWN, UNKNOWN, List.of()), true);
			Set<String> wnotes = lastNotes;
			if (states.isEmpty()) {
				ok = false;
				why = "walk gave up at STEP_LIMIT";
				whyAt = target;
			}
			for (Map.Entry<Address, State> e : states.entrySet()) {
				Instruction i = program.getListing().getInstructionAt(e.getKey());
				if (i == null) {
					continue;
				}
				String mn = i.getMnemonicString().toUpperCase(Locale.ROOT);
				var ft = W65816FarCall.flow(i);
				State st = e.getValue();
				Address[] fl = i.getFlows();
				int out = UNKNOWN;
				boolean exit = false;
				int drops = 0;
				if (W65816Shapes.isReturn(i)) {
					exit = true;
					out = st.dp;
					// A tail that drops the caller's arguments pulls below the entry on purpose
					// and still returns to the caller (W65816CalleePop, grm-9nxj.50).
					W65816CalleePop.Tail tail = W65816CalleePop.tailAt(program, i);
					State at = tail == null ? null : states.get(tail.store());
					if (at != null && at.stack != null && at.stack.isEmpty()) {
						drops = tail.bytes();
						st = new State(st.dp, st.a, st.x, st.y, List.of());
					}
				}
				else if (!ft.isComputed() && fl.length == 1 &&
					((!ft.isCall() && ft.isJump() && !inline(target, callee, fl[0])) ||
						(isTailCall(ft) && !inline(target, callee, fl[0])))) {
					// A tail call (FF2's bank-$14 JMP thunks; or a JMP carrying Ghidra's CALL_RETURN
					// flow override, which reads as a terminal call, FF2 $00:e660): it returns what
					// its target returns, with the DP at the jump standing in for its entry DP. A
					// conditional branch to another function's entry is one too (grm-9nxj.31, FF2
					// $00:e66b BNE); its fall-through is walked as usual.
					if (pushedCall(target, callee, i, st) != null) {
						continue;   // a far call: it comes back into this routine (grm-9nxj.52)
					}
					if (neverReturns(fl[0])) {
						if (tr) {
							System.out.println("DPS   tail at " + i.getAddress() + " to " + fl[0] +
								" skipped: never returns");
						}
						continue;   // no-return tail (owner ruling 2026-11-17): never reaches the caller
					}
					exit = true;
					int te = exitDp(fl[0]);
					out = te == ENTRY_DP ? st.dp : te;
					Integer tp = hasPopTail(fl[0]) ? exitPurge.get(fl[0]) : Integer.valueOf(0);
					if (tp == null) {
						st = new State(st.dp, st.a, st.x, st.y, null);
					}
					else if (tp > 0 && !UNWOUND.equals(st.stack)) {
						// The target drops this routine's own pushes first, then its caller's.
						Object[] r = dropBytes(st, tp);
						st = (State) r[0];
						drops = (Integer) r[1];
					}
					if (tr && te == UNKNOWN) {
						System.out.println("DPS   tail call at " + i.getAddress() + " to " + fl[0] +
							" has summary UNKNOWN");
					}
				}
				else if (isDispatchJmp(i)) {
					// Rule A (owner ruling 2026-11-06, grm-9nxj.27): see isDispatchJmp.
					exit = true;
					out = st.dp;
					Integer saved = unwoundFrameDp(i, st);
					if (saved != null) {
						out = saved;
						st = new State(st.dp, st.a, st.x, st.y, List.of());
					}
				}
				// An unwound exit has pulled its return address: it leaves for an outer frame, never
				// the call's fall-through, so its DP is beside the point (see UNDER).
				if (exit && UNWOUND.equals(st.stack)) {
					continue;
				}
				if (exit) {
					if (purge != null && purge != drops && ok) {
						ok = false;
						why = "exits drop different numbers of caller bytes (" + purge + " vs " +
							drops + ")";
						whyAt = i.getAddress();
					}
					purge = drops;
				}
				if (exit) {
					if (ok) {
						if (out == UNKNOWN) {
							why = "exit (" + mn + ") with UNKNOWN dp";
						}
						else if (st.stack == null) {
							why = "exit (" + mn + ") with poisoned stack";
						}
						else if (!st.stack.isEmpty()) {
							why = "exit (" + mn + ") with non-empty stack " + st.stack;
						}
						else if (d != UNKNOWN && d != out) {
							why = "disagreeing exits: " + dpName(d) + " vs " + dpName(out) + " (" +
								mn + ")";
						}
						if (why != null) {
							whyAt = i.getAddress();
						}
					}
					if (out == UNKNOWN || st.stack == null || !st.stack.isEmpty() ||
						(d != UNKNOWN && d != out)) {
						ok = false;
					}
					d = out;
				}
				else if (MosOperands.isInterruptReturn(i)) {   // RTI stays explicit (R4)
					if (ok) {
						why = "RTI";
						whyAt = i.getAddress();
					}
					ok = false;
				}
				else if (!ft.isCall() && (ft.isJump() || ft.isComputed())) {
					boolean was = ok;
					if (fl.length == 0 && !ft.isConditional()) {
						ok = false;
						if (was && why == null) {
							why = "jump without a target (" + mn + ")";
						}
					}
					for (Address t : fl) {
						if (!inline(target, callee, t) && ft.isComputed()) {
							ok = false;
							if (was && why == null) {
								why = "jump out of body to " + t + " (" + mn + ")";
							}
						}
					}
					if (was && !ok) {
						whyAt = i.getAddress();
					}
				}
				if (!ok) {
					break;
				}
			}
			int result = ok ? d : UNKNOWN;
			if (ok) {
				exitPurge.put(target, purge == null ? 0 : purge);
			}
			else {
				exitPurge.remove(target);
			}
			if (!states.isEmpty()) {
				exitKinds.put(target, exitKindsOf(target, callee, states));
			}
			if (!ok) {
				exitWhy.put(target, why + " at " + whyAt);
			}
			else if (result == UNKNOWN) {
				exitWhy.put(target, "no RTS/RTL reached");
			}
			if (tr) {
				StringBuilder sb =
					new StringBuilder("DPS exitDp " + target + " = " + dpName(result));
				if (!ok) {
					sb.append(": ").append(why).append(" at ").append(whyAt);
					if (wnotes != null && !wnotes.isEmpty()) {
						sb.append("; DP lost: ").append(wnotes);
					}
				}
				sb.append("; exits=").append(exitKinds.get(target));
				if (ok && result == UNKNOWN) {
					// No exit found: say what the walk did visit, with each instruction's flow type.
					sb.append("; visited=");
					states.keySet().stream().limit(12).forEach(a -> {
						Instruction vi = program.getListing().getInstructionAt(a);
						sb.append(' ').append(a).append(vi == null ? ":none" : ":" + vi + "/" + vi.getFlowType());
					});
				}
				sb.append("; recHits=").append(recHits - hits0);
				if (recHits > hits0) {
					sb.append(" ").append(recLog.subList(log0, recLog.size()));
				}
				System.out.println(sb);
			}
			return result;
		}

		/**
		 * Rule A (owner ruling 2026-11-06, grm-9nxj.27; human TODO 1.13 answer: "safe to assume
		 * DP won't be changed en route since it's part of the main loop"). Inside a call summary,
		 * an indirect {@code JMP (abs)} / {@code JMP (abs,X)} / {@code JML [abs]} is ALWAYS a tail exit whose handler
		 * returns to our caller with the DP it was given at the jump, whatever its targets: none
		 * resolved, out of the body, or in the body (Ghidra pulls the handlers of FF2
		 * {@code $00:E0D0} into {@code FUN_00e01a}'s body). Its flows are NOT walked by the summary
		 * ({@link #successors} with {@code summary}), so handlers reached only through it do not
		 * count against the summary. For {@link #exitDp} the path exits with the DP live at the
		 * jump (a constant, or {@link #ENTRY_DP}), subject to the usual empty-stack rule; for
		 * {@link #preserves} the jump is neutral. Optimistic: unsound if a handler changes DP and
		 * does not restore it. Scope is {@code JMP} and {@code JML} (indirect {@code JML [abs]}, the
		 * long pointer FF2 {@code $03:xxxx} dispatchers use; owner ruling 2026-11-17, grm-hf5h.24,
		 * extending this rule), not JSR/JSL (abs,X).
		 */
		private static boolean isDispatchJmp(Instruction i) {
			return W65816Shapes.isDispatchJump(i);
		}

		/**
		 * For {@link #preserves}: the instructions of {@code f} reachable from its entry without
		 * going through a dispatch JMP (see {@link #isDispatchJmp}), or null when the body has no
		 * dispatch JMP (then every instruction counts, as before).
		 */
		private Set<Address> dispatchLiveSet(Function f) {
			boolean any = false;
			for (Instruction i : program.getListing().getInstructions(f.getBody(), true)) {
				if (isDispatchJmp(i)) {
					any = true;
					break;
				}
			}
			if (!any) {
				return null;
			}
			Set<Address> seen = new HashSet<>();
			ArrayDeque<Address> work = new ArrayDeque<>();
			work.add(f.getEntryPoint());
			while (!work.isEmpty()) {
				Address at = work.poll();
				Instruction ins = program.getListing().getInstructionAt(at);
				if (ins == null || !seen.add(at)) {
					continue;
				}
				for (Address a : successors(f, ins, true)) {
					if (f.getBody().contains(a)) {   // the live set is of f's body only
						work.add(a);
					}
				}
			}
			return seen;
		}

		/** Whether a call to {@code target} leaves DP alone, as far as its code visibly shows. */
		private boolean preserves(Address target) {
			boolean r = preserves(target, new HashSet<>(), new HashSet<>());
			if (traced(target)) {
				System.out.println("DPS preserves " + target + " = " + r);
			}
			return r;
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
			Set<Address> live = dispatchLiveSet(callee);
			for (Instruction i : program.getListing().getInstructions(callee.getBody(), true)) {
				if (live != null && !live.contains(i.getAddress())) {
					continue;   // a handler reached only through a dispatch JMP (rule A)
				}
				var ft = W65816FarCall.flow(i);
				W65816Shapes.Transfer tcd = W65816Shapes.transfer(i);
				W65816Shapes.Push push = W65816Shapes.push(i);
				W65816Shapes.Pull pull = W65816Shapes.pull(i);
				if (tcd != null && tcd.dst() == W65816Shapes.Role.DP) {
					ok = false;
				}
				else if (push != null && push.role() == W65816Shapes.Role.DP) {
					phd++;
				}
				else if (pull != null && pull.role() == W65816Shapes.Role.DP) {
					pld++;
				}
				else if (ft.isCall()) {
					Address[] fl = i.getFlows();
					if (fl.length > 1 && ft.isComputed()) {
						continue;   // Rule A for computed calls (grm-hf5h.26): see afterCall
					}
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
					if (isDispatchJmp(i)) {
						continue;   // rule A: hands the DP it was given to its handler
					}
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
				indirect ? RefType.READ : W65816Shapes.memAccessKind(ins),
				SourceType.ANALYSIS, 0);
			return true;
		}
	}
}
