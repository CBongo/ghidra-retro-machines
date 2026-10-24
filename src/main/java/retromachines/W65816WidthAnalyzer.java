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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Keeps 65816 code after a call decoded at the width the callee really leaves (bead
 * grm-9nxj.5.3).
 *
 * <p><b>The defect.</b> The language flows the CALLER's M/X context into the instruction after a
 * {@code JSR}/{@code JSL}, as if the callee preserved both. Many do not: a helper that ends
 * {@code SEP #$20 / RTS} returns with an 8-bit accumulator whatever it was given, and the code
 * after every call to it was decoded at the caller's old width -- wrong from its first
 * accumulator immediate on, which is mis-lengthed and desynchronizes everything after it.
 * Chrono Trigger's {@code $C1:0174} is one; nine call sites to it continue decoded 16-bit.
 *
 * <p><b>The repair.</b> {@link W65816WidthEffects} summarizes each callee. Where it SETS a flag to
 * {@code c} on every return, and the continuation was decoded at the other value, and the
 * continuation actually reaches a length-sensitive immediate before setting the flag itself (so
 * the stale width changes the decode, not merely the label on it), the continuation's flow is
 * cleared, the flag is stamped {@code c} at its first address -- after the clear, which would
 * otherwise wipe it -- and it is disassembled again from there. Ghidra's Clear Flow keeps any
 * block something outside the cleared flow still reaches, so no other path's code is lost. The
 * continuation carries an EOL note saying why. This is the ArmAnalyzer pattern (stamp the mode a
 * flow arrives in, let disassembly consume it), applied to a flow the language cannot see: a
 * return.
 *
 * <p>A continuation something else also enters is re-decoded only when every other flow into it
 * arrives at the corrected width too (grm-9nxj.5.7); one that arrives at the old width makes it
 * genuinely dual-width, which gets a warning bookmark instead, and an external entry point is
 * left alone.
 *
 * <p><b>The report.</b> A callee whose decode DEPENDS on an inherited flag (it reaches a
 * length-sensitive immediate before setting it) and is called at both widths cannot be
 * represented: one address carries one decode. Each call whose width differs from the one the
 * callee was decoded at gets a warning bookmark rather than a repair. On the real-ROM rows this
 * was measured at zero (grm-9nxj.5.3's census) -- every naive context mismatch there was a callee
 * that sets its own width first.
 *
 * <p><b>After a PLP</b> (grm-9nxj.5.5) the same applies to a flow the language cannot see because
 * the status comes off the stack: the fall-through is re-decoded at the width the matching
 * {@code PHP} saved, where that pairing is unambiguous.
 *
 * <p>Applies to any program whose language carries the 65816 {@code ctx_EF}/{@code ctx_MF}/
 * {@code ctx_XF} context: width is a CPU fact, not a SNES one.
 */
public class W65816WidthAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 Call Width";
	private static final String DESCRIPTION =
		"Re-decodes the code after a 65816 call at the M/X width the callee leaves on every " +
			"return, and warns where a callee whose decode depends on the inherited width is " +
			"called at two widths (grm-9nxj.5.3).";
	static final String BOOKMARK_CATEGORY = "65816 Width";

	/**
	 * Addresses re-decoded so far, per program. A later repair's Clear Flow can wipe an earlier
	 * one's stamp (CT {@code $C2:2CFF} lost its M=1 when the continuation above it was re-decoded
	 * once {@code $C2:2B61}'s PHP/PLP bracket summarized, grm-9nxj.5.7), so an address may be
	 * repaired again -- but at most {@link #MAX_REPAIRS} times, so two repairs that undo each
	 * other cannot loop.
	 */
	private static final Map<Program, Map<Address, Integer>> REPAIRED =
		Collections.synchronizedMap(new WeakHashMap<>());
	private static final int MAX_REPAIRS = 3;

	/** Per-program repair counts: {@link #spent} once an address used its last repair. */
	private static final class Ledger {
		private final Map<Address, Integer> counts;

		Ledger(Map<Address, Integer> counts) {
			this.counts = counts;
		}

		boolean spent(Address a) {
			return counts.getOrDefault(a, 0) >= MAX_REPAIRS;
		}

		void record(Address a) {
			counts.merge(a, 1, Integer::sum);
		}
	}

	public W65816WidthAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// After disassembly has laid the callees down, before functions are created over them.
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		W65816WidthEffects effects = new W65816WidthEffects(program);
		Listing listing = program.getListing();
		Ledger repaired = new Ledger(
			REPAIRED.computeIfAbsent(program, p -> Collections.synchronizedMap(new LinkedHashMap<>())));

		// Pass 1: every callee reached from the sites in view, judged against ALL its callers.
		Map<Address, List<Instruction>> callersOf = new LinkedHashMap<>();
		for (Instruction call : callSites(program, set)) {
			monitor.checkCancelled();
			for (Address target : call.getFlows()) {
				callersOf.computeIfAbsent(target, t -> allDirectCallers(program, effects, t));
			}
		}
		Map<Address, Map<Register, Integer>> entryRepairs = new LinkedHashMap<>();
		Set<Address> untrusted = new LinkedHashSet<>();
		int warned = 0;
		for (Map.Entry<Address, List<Instruction>> c : callersOf.entrySet()) {
			Address target = c.getKey();
			Instruction callee = listing.getInstructionAt(target);
			if (callee == null || c.getValue().isEmpty()) {
				continue;
			}
			W65816WidthEffects.Effect e = effects.effect(target);
			Map<Register, Integer> want = entryWant(effects, callee, c.getValue());
			if (want != null && want.isEmpty()) {
				for (Instruction call : c.getValue()) {
					warnEntryConflict(program, effects, call, callee, e);   // clears stale ones
				}
			}
			if (want == null) {
				// Genuinely called at two widths: not representable, so say so at each caller
				// whose width differs from the decode.
				untrusted.add(target);
				for (Instruction call : c.getValue()) {
					warned += warnEntryConflict(program, effects, call, callee, e) ? 1 : 0;
				}
			}
			else if (!want.isEmpty()) {
				untrusted.add(target);
				if (!repaired.spent(target) && reDecodable(program, target)) {
					entryRepairs.put(target, want);
				}
				else {
					for (Instruction call : c.getValue()) {
						warned += warnEntryConflict(program, effects, call, callee, e) ? 1 : 0;
					}
				}
			}
		}

		// Pass 2: continuations after calls to callees whose decode the callers agree with. A
		// callee decoded at the wrong width has no trustworthy exit summary (its REP/SEP may be
		// operand bytes), so it waits until its own entry repair has re-decoded it.
		Map<Address, Map<Register, Integer>> contRepairs = new LinkedHashMap<>();
		Map<Address, Address> contCaller = new LinkedHashMap<>();
		for (Map.Entry<Address, List<Instruction>> c : callersOf.entrySet()) {
			Address target = c.getKey();
			if (untrusted.contains(target) || listing.getInstructionAt(target) == null) {
				continue;
			}
			for (Instruction call : c.getValue()) {
				monitor.checkCancelled();
				Address cont = call.getFallThrough();
				if (cont == null || repaired.spent(cont)) {
					continue;
				}
				Map<Register, Integer> stamp = contStamp(listing, effects, call, target);
				if (!stamp.isEmpty()) {
					contRepairs.computeIfAbsent(cont, x -> new LinkedHashMap<>()).putAll(stamp);
					contCaller.put(cont, call.getMinAddress());
				}
			}
		}

		int entries = 0;
		for (Map.Entry<Address, Map<Register, Integer>> r : entryRepairs.entrySet()) {
			monitor.checkCancelled();
			Address target = r.getKey();
			// An earlier repair in this batch may have re-decoded a caller or the callee itself.
			effects.invalidate();
			List<Instruction> callers = allDirectCallers(program, effects, target);
			Instruction callee = listing.getInstructionAt(target);
			Map<Register, Integer> want =
				callee == null || callers.isEmpty() ? null : entryWant(effects, callee, callers);
			if (want == null || want.isEmpty()) {
				continue;
			}
			r.setValue(want);
			AnalyzerLog.info(this, "callee " + target + " re-decoded at " + describe(want) +
				", the width all " + callers.size() + " of its callers pass");
			Function f = program.getFunctionManager().getFunctionAt(target);
			if (f != null) {
				program.getFunctionManager().removeFunction(target);
			}
			reDecode(program, callers.get(0).getMinAddress(), target, r.getValue(), monitor);
			new CreateFunctionCmd(target).applyTo(program, monitor);
			AnalyzerCommentRecord.set(program, target, CommentType.EOL,
				"65816 width " + describe(r.getValue()) + " on entry: every caller passes it");
			repaired.record(target);
			entries++;
		}

		int conts = 0;
		for (Map.Entry<Address, Map<Register, Integer>> r : contRepairs.entrySet()) {
			monitor.checkCancelled();
			Address cont = r.getKey();
			Address caller = contCaller.get(cont);
			effects.invalidate();
			Instruction current = listing.getInstructionAt(caller);
			if (current == null || !isDirectCall(current) || !cont.equals(current.getFallThrough()) ||
				current.getFlows().length == 0) {
				continue;   // an earlier repair in this batch re-decoded the call itself
			}
			Map<Register, Integer> fresh =
				contStamp(listing, effects, current, current.getFlows()[0]);
			if (fresh.isEmpty()) {
				continue;
			}
			r.setValue(fresh);
			if (!mergeAgrees(program, effects, cont, caller, fresh, "the call at " + caller)) {
				continue;
			}
			Instruction call = listing.getInstructionAt(caller);
			String callee = call == null || call.getFlows().length == 0 ? "?"
					: call.getFlows()[0].toString();
			AnalyzerLog.info(this, "continuation " + cont + " re-decoded at " +
				describe(r.getValue()) + ": " + callee + " leaves it so on every return");
			reDecode(program, caller, cont, r.getValue(), monitor);
			AnalyzerCommentRecord.set(program, cont, CommentType.EOL,
				"65816 width " + describe(r.getValue()) + " after the call: " + callee +
					" leaves it so on every return");
			Function f = program.getFunctionManager().getFunctionContaining(caller);
			if (f != null) {
				CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
			}
			repaired.record(cont);
			conts++;
		}
		int plps = repairPlpContinuations(program, effects, set, repaired, monitor);
		int handlers = repairInterruptEntries(program, effects, set, repaired, monitor);
		if (entries + conts + plps + handlers > 0 || warned > 0) {
			AnalyzerLog.info(this, "re-decoded " + entries + " callee entr(ies), " + conts +
				" call continuation(s), " + plps + " PLP continuation(s) and " + handlers +
				" interrupt handler(s); " + warned + " dual-width call warning(s)");
		}
		return true;
	}

	/**
	 * Code after a {@code PLP} runs at the width the matching {@code PHP} saved, but the language
	 * cannot pull a status off the stack, so it decodes the fall-through at the width just BEFORE
	 * the PLP -- usually whatever the bracket's own REP/SEP set (bead grm-9nxj.5.5). Each PLP is
	 * paired by {@link #matchingPhps}; where every PHP that reaches it saved the same width, and
	 * the fall-through was decoded at another one that its decode depends on, the fall-through is
	 * re-decoded at the saved width. Ambiguous pairings (PHPs at different widths, or a path to
	 * the PLP with no PHP on it) are left alone.
	 */
	private int repairPlpContinuations(Program program, W65816WidthEffects effects,
			AddressSetView set, Ledger repaired, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Instruction> plps = new ArrayList<>();
		for (Instruction in : listing.getInstructions(set, true)) {
			if (in.getMnemonicString().equalsIgnoreCase("PLP") && !effects.emulation(in) &&
				in.getFallThrough() != null && !repaired.spent(in.getFallThrough())) {
				plps.add(in);
			}
		}
		int done = 0;
		for (Instruction seen : plps) {
			monitor.checkCancelled();
			effects.invalidate();
			Instruction plp = listing.getInstructionAt(seen.getMinAddress());
			if (plp == null || !plp.getMnemonicString().equalsIgnoreCase("PLP")) {
				continue;   // an earlier repair in this pass re-decoded it
			}
			Address cont = plp.getFallThrough();
			Instruction after = cont == null ? null : listing.getInstructionAt(cont);
			if (after == null || effects.emulation(after)) {
				continue;
			}
			Set<Instruction> phps = matchingPhps(program, plp);
			if (phps == null || phps.isEmpty()) {
				continue;
			}
			W65816WidthEffects.Effect k = effects.effect(cont);
			Map<Register, Integer> stamp = new LinkedHashMap<>();
			for (Register reg : new Register[] { effects.mRegister(), effects.xRegister() }) {
				boolean needs = reg == effects.mRegister() ? k.m().needs() : k.x().needs();
				Set<Integer> savedValues = new LinkedHashSet<>();
				for (Instruction php : phps) {
					savedValues.add(effects.flag(php, reg));
				}
				int v = savedValues.iterator().next();
				if (needs && savedValues.size() == 1 && (v == 0 || v == 1) &&
					v != effects.flag(after, reg)) {
					stamp.put(reg, v);
				}
			}
			if (stamp.isEmpty()) {
				continue;
			}
			if (!mergeAgrees(program, effects, cont, plp.getMinAddress(), stamp,
				"the PLP at " + plp.getMinAddress())) {
				continue;
			}
			Instruction php = phps.iterator().next();
			AnalyzerLog.info(this, "PLP continuation " + cont + " re-decoded at " +
				describe(stamp) + ", the width the PHP at " + php.getMinAddress() + " saved");
			reDecode(program, plp.getMinAddress(), cont, stamp, monitor);
			AnalyzerCommentRecord.set(program, cont, CommentType.EOL,
				"65816 width " + describe(stamp) + " after PLP: restored from the PHP at " +
					php.getMinAddress());
			Function f = program.getFunctionManager().getFunctionContaining(plp.getMinAddress());
			if (f != null) {
				CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
			}
			repaired.record(cont);
			done++;
		}
		return done;
	}

	/** Bound on (address, depth) pairs a backward PHP search visits. */
	private static final int PAIR_LIMIT = 2000;

	/**
	 * The PHPs whose saved status {@code plp} pulls: a backward walk over fall-through and jump
	 * predecessors, where each PLP passed opens a level and each PHP closes one, and a PHP met
	 * at level zero is a match. Null when some path reaches the PLP with no PHP on it -- through
	 * a routine entry, an unreached start, or past the walk bound -- since that path pulls a
	 * status pushed somewhere this walk cannot see.
	 */
	static Set<Instruction> matchingPhps(Program program, Instruction plp) {
		Listing listing = program.getListing();
		Set<Instruction> found = new LinkedHashSet<>();
		Set<Long> seen = new java.util.HashSet<>();
		java.util.ArrayDeque<Object[]> work = new java.util.ArrayDeque<>();
		work.push(new Object[] { plp, 0 });
		int steps = 0;
		while (!work.isEmpty()) {
			if (steps++ >= PAIR_LIMIT) {
				return null;
			}
			Object[] w = work.pop();
			Instruction at = (Instruction) w[0];
			int depth = (Integer) w[1];
			// Predecessors of `at`: the instruction falling into it, and every jump to it.
			List<Instruction> preds = new ArrayList<>();
			boolean entered = program.getSymbolTable().isExternalEntryPoint(at.getMinAddress());
			Instruction before = listing.getInstructionBefore(at.getMinAddress());
			if (before != null && at.getMinAddress().equals(before.getFallThrough())) {
				preds.add(before);
			}
			for (Reference ref : program.getReferenceManager().getReferencesTo(at.getMinAddress())) {
				if (!ref.getReferenceType().isFlow()) {
					continue;
				}
				if (ref.getReferenceType().isCall()) {
					entered = true;   // a routine entry: the PHP, if any, is in a caller
					continue;
				}
				Instruction from = listing.getInstructionAt(ref.getFromAddress());
				if (from != null) {
					preds.add(from);
				}
			}
			if (entered || preds.isEmpty()) {
				return null;
			}
			for (Instruction p : preds) {
				String mn = p.getMnemonicString().toUpperCase();
				int d = depth;
				if (mn.equals("PHP")) {
					if (d == 0) {
						found.add(p);
						continue;
					}
					d--;
				}
				else if (mn.equals("PLP") && ++d > 8) {
					return null;
				}
				if (seen.add(p.getMinAddress().getOffset() << 8 | d)) {
					work.push(new Object[] { p, d });
				}
			}
		}
		return found;
	}

	/**
	 * Interrupt handlers (the loader's and the trampoline analyzer's asynchronous entry points)
	 * start with whatever M/X the interrupted code had -- no caller says which. They are seeded
	 * 8-bit, which is wrong for a game that runs with 16-bit index registers throughout: FF2's
	 * NMI at {@code $9085} sets M but never X, so its {@code LDX #$0600} decoded as
	 * {@code LDX #$00} and desynchronized. For each flag a handler's decode depends on, it is
	 * re-decoded at the program's AMBIENT width -- the value most native-mode instructions hold,
	 * i.e. the width the code an interrupt lands in is most likely to have. An inference, stated
	 * as one in the EOL note; a flag the handler sets before using needs no inference at all.
	 */
	private int repairInterruptEntries(Program program, W65816WidthEffects effects,
			AddressSetView set, Ledger repaired, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Address> candidates = new ArrayList<>();
		for (Address entry : DescriptorHints.parseAsyncEntryPoints(program)) {
			Instruction in = listing.getInstructionAt(entry);
			if (in != null && set.contains(entry) && !repaired.spent(entry) &&
				!effects.emulation(in)) {
				candidates.add(entry);
			}
		}
		if (candidates.isEmpty()) {
			return 0;
		}
		Map<Register, Integer> ambient = ambientWidth(program, effects);
		int done = 0;
		for (Address entry : candidates) {
			monitor.checkCancelled();
			effects.invalidate();
			Instruction in = listing.getInstructionAt(entry);
			if (in == null) {
				continue;
			}
			W65816WidthEffects.Effect e = effects.effect(entry);
			Map<Register, Integer> want = new LinkedHashMap<>();
			if (e.m().needs() && ambient.containsKey(effects.mRegister()) &&
				effects.flag(in, effects.mRegister()) != ambient.get(effects.mRegister())) {
				want.put(effects.mRegister(), ambient.get(effects.mRegister()));
			}
			if (e.x().needs() && ambient.containsKey(effects.xRegister()) &&
				effects.flag(in, effects.xRegister()) != ambient.get(effects.xRegister())) {
				want.put(effects.xRegister(), ambient.get(effects.xRegister()));
			}
			repaired.record(entry);
			if (want.isEmpty()) {
				continue;
			}
			Function f = program.getFunctionManager().getFunctionAt(entry);
			String name = f == null ? null : f.getName();
			SourceType source = f == null ? null : f.getSymbol().getSource();
			if (f != null) {
				program.getFunctionManager().removeFunction(entry);
			}
			AnalyzerLog.info(this, "interrupt handler " + entry + " re-decoded at the ambient " +
				"width " + describe(want));
			reDecode(program, entry, entry, want, monitor);
			CreateFunctionCmd create = new CreateFunctionCmd(name, entry, null,
				source == null ? SourceType.ANALYSIS : source);
			create.applyTo(program, monitor);
			AnalyzerCommentRecord.set(program, entry, CommentType.EOL,
				"65816 width " + describe(want) + " on entry: inferred, the width most of the " +
					"program runs at (an interrupt keeps the interrupted code's M/X)");
			done++;
		}
		return done;
	}

	/** Per flag, the value held by the majority of decoded native-mode instructions. */
	private static Map<Register, Integer> ambientWidth(Program program,
			W65816WidthEffects effects) {
		int[] m = new int[2];
		int[] x = new int[2];
		for (Instruction in : program.getListing().getInstructions(true)) {
			if (effects.emulation(in)) {
				continue;
			}
			int mv = effects.flag(in, effects.mRegister());
			int xv = effects.flag(in, effects.xRegister());
			if (mv == 0 || mv == 1) {
				m[mv]++;
			}
			if (xv == 0 || xv == 1) {
				x[xv]++;
			}
		}
		Map<Register, Integer> ambient = new LinkedHashMap<>();
		if (m[0] != m[1]) {
			ambient.put(effects.mRegister(), m[0] > m[1] ? 0 : 1);
		}
		if (x[0] != x[1]) {
			ambient.put(effects.xRegister(), x[0] > x[1] ? 0 : 1);
		}
		return ambient;
	}

	/**
	 * The width a callee should be decoded at, judged against all its callers: for each flag its
	 * decode depends on, the one value every caller passes where that differs from the decode.
	 * Empty when the decode already agrees; null when callers disagree among themselves (a
	 * genuinely dual-width callee).
	 */
	private static Map<Register, Integer> entryWant(W65816WidthEffects effects,
			Instruction callee, List<Instruction> callers) {
		Map<Register, Integer> want = new LinkedHashMap<>();
		if (effects.emulation(callee)) {
			// Decoded in emulation mode though only native code calls it: an island disassembled
			// before any caller reached it, at the pspec default (FF3 $C2:E6E3, three M1X0 JSRs,
			// decoded E=1 into BRK). Re-decoded at the callers' E/M/X (grm-9nxj.5.7).
			want.put(effects.eRegister(), 0);
			return want;
		}
		W65816WidthEffects.Effect e = effects.effect(callee.getMinAddress());
		for (Register reg : new Register[] { effects.mRegister(), effects.xRegister() }) {
			boolean needs = reg == effects.mRegister() ? e.m().needs() : e.x().needs();
			if (!needs) {
				continue;
			}
			Set<Integer> passed = new LinkedHashSet<>();
			for (Instruction call : callers) {
				passed.add(effects.flag(call, reg));
			}
			if (passed.size() > 1) {
				return null;
			}
			int v = passed.iterator().next();
			if (v != effects.flag(callee, reg)) {
				want.put(reg, v);
			}
		}
		return want;
	}

	/**
	 * The flags to re-stamp on the continuation after {@code call} to {@code target}: each one
	 * the callee sets to a constant on every return, that the continuation was decoded at the
	 * other value, and that the continuation's decode depends on.
	 */
	private static Map<Register, Integer> contStamp(Listing listing, W65816WidthEffects effects,
			Instruction call, Address target) {
		Map<Register, Integer> stamp = new LinkedHashMap<>();
		Address cont = call.getFallThrough();
		Instruction after = cont == null ? null : listing.getInstructionAt(cont);
		if (after == null || effects.emulation(after) || listing.getInstructionAt(target) == null) {
			return stamp;
		}
		W65816WidthEffects.Effect e = effects.effect(target);
		W65816WidthEffects.Effect k = effects.effect(cont);
		if (e.m().setsConstant() && effects.flag(after, effects.mRegister()) != e.m().exit() &&
			k.m().needs()) {
			stamp.put(effects.mRegister(), e.m().exit());
		}
		if (e.x().setsConstant() && effects.flag(after, effects.xRegister()) != e.x().exit() &&
			k.x().needs()) {
			stamp.put(effects.xRegister(), e.x().exit());
		}
		return stamp;
	}

	/** Every direct, native-mode call whose flow reaches {@code target}. */
	private static List<Instruction> allDirectCallers(Program program,
			W65816WidthEffects effects, Address target) {
		List<Instruction> callers = new ArrayList<>();
		for (Reference ref : program.getReferenceManager().getReferencesTo(target)) {
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Instruction from = program.getListing().getInstructionAt(ref.getFromAddress());
			if (from != null && isDirectEntry(from) && !effects.emulation(from)) {
				callers.add(from);
			}
		}
		return callers;
	}

	/**
	 * Whether a callee may be cleared and decoded again: nothing but direct calls enters it (a
	 * jump or a vector could bring another width), and no one named its function.
	 */
	private static boolean reDecodable(Program program, Address target) {
		if (program.getSymbolTable().isExternalEntryPoint(target)) {
			return false;
		}
		Function f = program.getFunctionManager().getFunctionAt(target);
		if (f != null && f.getSymbol().getSource() != SourceType.DEFAULT &&
			f.getSymbol().getSource() != SourceType.ANALYSIS) {
			return false;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(target)) {
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isCall()) {
				return false;
			}
		}
		return true;
	}

	/** Direct calls in {@code set}, plus direct calls anywhere whose target lies in it. */
	private static Set<Instruction> callSites(Program program, AddressSetView set) {
		Listing listing = program.getListing();
		Set<Instruction> sites = new LinkedHashSet<>();
		for (Instruction instr : listing.getInstructions(set, true)) {
			if (isDirectEntry(instr)) {
				sites.add(instr);
			}
		}
		ReferenceManager refs = program.getReferenceManager();
		AddressIterator dests = refs.getReferenceDestinationIterator(set, true);
		while (dests.hasNext()) {
			for (Reference ref : refs.getReferencesTo(dests.next())) {
				if (ref.getReferenceType().isCall()) {
					Instruction from = listing.getInstructionAt(ref.getFromAddress());
					if (from != null && isDirectEntry(from)) {
						sites.add(from);
					}
				}
			}
		}
		return sites;
	}

	private static boolean isDirectCall(Instruction instr) {
		return isDirectEntry(instr) && instr.hasFallthrough();
	}

	/**
	 * A direct call, or a tail call -- a {@code JMP} Ghidra overrode into a call, with no
	 * fall-through. Both pass their width into the callee's entry: CT {@code $C2:7B9F} is entered
	 * only by four such {@code JMP}s at M=1 and was decoded M=0 (grm-9nxj.5.7).
	 */
	private static boolean isDirectEntry(Instruction instr) {
		FlowType ft = instr.getFlowType();
		return ft.isCall() && !ft.isComputed();
	}

	/**
	 * Whether {@code cont}, which {@code from} (a call or a PLP) reaches by fall-through at the
	 * widths in {@code stamp}, may be re-decoded at them: every OTHER flow into it must arrive at
	 * the same widths (grm-9nxj.5.7). Flows from code the stale decode itself reaches -- a loop
	 * back to {@code cont} -- do not count: they are stale for the same reason and are re-decoded
	 * with it. A flow at the other width makes {@code cont} genuinely dual-width, which one
	 * address cannot represent; that is reported with a warning bookmark and left alone, as is an
	 * external entry point (nothing says what width it is entered at).
	 */
	private boolean mergeAgrees(Program program, W65816WidthEffects effects, Address cont,
			Address from, Map<Register, Integer> stamp, String why) {
		if (program.getSymbolTable().isExternalEntryPoint(cont)) {
			AnalyzerLog.info(this, "continuation " + cont + " after " + why + " is decoded at a " +
				"stale width " + describe(stamp) + ", but it is also an entry point; left alone");
			return false;
		}
		Listing listing = program.getListing();
		Set<Address> downstream = null;
		for (Reference ref : program.getReferenceManager().getReferencesTo(cont)) {
			if (!ref.getReferenceType().isFlow() || ref.getFromAddress().equals(from)) {
				continue;
			}
			if (downstream == null) {
				downstream = forwardFlow(listing, cont);
			}
			if (downstream.contains(ref.getFromAddress())) {
				continue;
			}
			Instruction src = listing.getInstructionAt(ref.getFromAddress());
			String which = "";
			for (Map.Entry<Register, Integer> s : stamp.entrySet()) {
				if (src == null || effects.flag(src, s.getKey()) != s.getValue()) {
					which += s.getKey() == effects.mRegister() ? "M" : "X";
				}
			}
			if (!which.isEmpty()) {
				AnalyzerLog.info(this, "continuation " + cont + " after " + why + " wants " +
					describe(stamp) + ", but the flow from " + ref.getFromAddress() +
					" brings the other " + which + "; dual-width, left alone");
				program.getBookmarkManager().setBookmark(cont, BookmarkType.WARNING,
					BOOKMARK_CATEGORY, "entered at two " + which + " widths: " + why +
						" leaves " + describe(stamp) + ", the flow from " + ref.getFromAddress() +
						" does not; one address holds one decode, so one path's view is wrong");
				return false;
			}
		}
		return true;
	}

	/** Bound on the instructions {@link #forwardFlow} collects. */
	private static final int FLOW_LIMIT = 2000;

	/**
	 * Instructions reachable from {@code start} over fall-through and jumps, not into calls and
	 * not past a return -- the region a Clear Flow from {@code start} would cover.
	 */
	private static Set<Address> forwardFlow(Listing listing, Address start) {
		Set<Address> seen = new java.util.HashSet<>();
		java.util.ArrayDeque<Address> work = new java.util.ArrayDeque<>();
		work.push(start);
		while (!work.isEmpty() && seen.size() < FLOW_LIMIT) {
			Address a = work.pop();
			Instruction in = listing.getInstructionAt(a);
			if (in == null || !seen.add(a)) {
				continue;
			}
			FlowType ft = in.getFlowType();
			if (ft.isJump() && !ft.isComputed()) {
				for (Address t : in.getFlows()) {
					work.push(t);
				}
			}
			if (in.getFallThrough() != null) {
				work.push(in.getFallThrough());
			}
		}
		return seen;
	}

	/**
	 * Clears the flow from {@code start} and decodes it again with the context {@code from} (a
	 * call) passes, overridden by {@code stamp}.
	 */
	private void reDecode(Program program, Address from, Address start,
			Map<Register, Integer> stamp, TaskMonitor monitor) throws CancelledException {
		Address caller = from;
		Address cont = start;
		// The call passes its own E/M/X into the continuation; read them before anything is
		// cleared, then override only the flags being repaired.
		Instruction callInstr = program.getListing().getInstructionAt(caller);
		Map<Register, Integer> full = new LinkedHashMap<>();
		for (String name : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
			Register reg = program.getRegister(name);
			BigInteger v = callInstr == null ? null : callInstr.getValue(reg, false);
			if (v != null) {
				full.put(reg, v.intValue());
			}
		}
		full.putAll(stamp);
		// Clear first: ClearCmd clears register (context) values in the range too, so a stamp
		// written before it would be wiped -- and so would every flag NOT stamped, which then
		// reads as the pspec default (emulation mode, 8-bit index) and mis-decodes the index
		// immediates instead (measured on CT $C1:03B2). Hence all three flags are written. No
		// repair pass: it would re-parse the call and flow its stale context straight back in.
		new ClearFlowAndRepairCmd(cont, false, false, false).applyTo(program, monitor);
		for (Map.Entry<Register, Integer> s : full.entrySet()) {
			try {
				program.getProgramContext().setValue(s.getKey(), cont, cont,
					BigInteger.valueOf(s.getValue()));
			}
			catch (ContextChangeException e) {
				AnalyzerLog.info(this, "could not stamp " + s.getKey().getName() + " at " + cont +
					": " + e.getMessage());
				return;
			}
		}
		new DisassembleCommand(cont, null, true).applyTo(program, monitor);
	}

	private static String describe(Map<Register, Integer> stamp) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<Register, Integer> s : stamp.entrySet()) {
			sb.append(sb.length() == 0 ? "" : " ")
					.append(s.getKey().getName().substring(4, 5)).append("=")
					.append(s.getValue());
		}
		return sb.toString();
	}

	/**
	 * Warns at a call whose callee's decode depends on an inherited flag that this caller holds
	 * at the other value. Returns whether it warned.
	 */
	private static boolean warnEntryConflict(Program program, W65816WidthEffects effects,
			Instruction call, Instruction callee, W65816WidthEffects.Effect e) {
		String which = "";
		if (e.m().needs() &&
			effects.flag(call, effects.mRegister()) != effects.flag(callee, effects.mRegister())) {
			which += "M";
		}
		if (e.x().needs() &&
			effects.flag(call, effects.xRegister()) != effects.flag(callee, effects.xRegister())) {
			which += "X";
		}
		if (which.isEmpty()) {
			// Re-evaluated after a repair elsewhere and consistent now: drop a stale warning.
			var stale = program.getBookmarkManager().getBookmark(call.getMinAddress(),
				BookmarkType.WARNING, BOOKMARK_CATEGORY);
			if (stale != null) {
				program.getBookmarkManager().removeBookmark(stale);
			}
			return false;
		}
		program.getBookmarkManager().setBookmark(call.getMinAddress(), BookmarkType.WARNING,
			BOOKMARK_CATEGORY, "callee " + callee.getMinAddress() + " is decoded at a different " +
				which + " width than this call passes, and its decode depends on it; one " +
				"address holds one decode, so this caller's view of it is wrong");
		return true;
	}
}
