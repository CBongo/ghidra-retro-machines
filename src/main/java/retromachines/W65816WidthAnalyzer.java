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
 * <p>A continuation is left alone, and only the conflict is logged, when anything else enters it
 * -- a flow reference, an entry point or a function -- because another path may bring the old
 * width there legitimately.
 *
 * <p><b>The report.</b> A callee whose decode DEPENDS on an inherited flag (it reaches a
 * length-sensitive immediate before setting it) and is called at both widths cannot be
 * represented: one address carries one decode. Each call whose width differs from the one the
 * callee was decoded at gets a warning bookmark rather than a repair. On the real-ROM rows this
 * was measured at zero (grm-9nxj.5.3's census) -- every naive context mismatch there was a callee
 * that sets its own width first.
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

	/** Continuations already repaired, per program: each is repaired at most once. */
	private static final Map<Program, Set<Address>> REPAIRED =
		Collections.synchronizedMap(new WeakHashMap<>());

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
		Set<Address> repaired =
			REPAIRED.computeIfAbsent(program, p -> Collections.synchronizedSet(new LinkedHashSet<>()));

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
			if (callee == null || effects.emulation(callee) || c.getValue().isEmpty()) {
				continue;
			}
			W65816WidthEffects.Effect e = effects.effect(target);
			Map<Register, Integer> want = entryWant(effects, callee, c.getValue());
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
				if (!repaired.contains(target) && reDecodable(program, target)) {
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
				if (cont == null || repaired.contains(cont)) {
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
			repaired.add(target);
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
			if (!soleEntryIsFallThrough(program, cont)) {
				AnalyzerLog.info(this, "continuation " + cont + " after the call at " + caller +
					" is decoded at a stale width " + describe(r.getValue()) +
					", but something else also enters it; left alone");
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
			repaired.add(cont);
			conts++;
		}
		if (entries + conts > 0 || warned > 0) {
			AnalyzerLog.info(this, "re-decoded " + entries + " callee entr(ies) and " + conts +
				" call continuation(s); " + warned + " dual-width call warning(s)");
		}
		return true;
	}

	/**
	 * The width a callee should be decoded at, judged against all its callers: for each flag its
	 * decode depends on, the one value every caller passes where that differs from the decode.
	 * Empty when the decode already agrees; null when callers disagree among themselves (a
	 * genuinely dual-width callee).
	 */
	private static Map<Register, Integer> entryWant(W65816WidthEffects effects,
			Instruction callee, List<Instruction> callers) {
		W65816WidthEffects.Effect e = effects.effect(callee.getMinAddress());
		Map<Register, Integer> want = new LinkedHashMap<>();
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
			if (from != null && isDirectCall(from) && !effects.emulation(from)) {
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
			if (isDirectCall(instr)) {
				sites.add(instr);
			}
		}
		ReferenceManager refs = program.getReferenceManager();
		AddressIterator dests = refs.getReferenceDestinationIterator(set, true);
		while (dests.hasNext()) {
			for (Reference ref : refs.getReferencesTo(dests.next())) {
				if (ref.getReferenceType().isCall()) {
					Instruction from = listing.getInstructionAt(ref.getFromAddress());
					if (from != null && isDirectCall(from)) {
						sites.add(from);
					}
				}
			}
		}
		return sites;
	}

	private static boolean isDirectCall(Instruction instr) {
		FlowType ft = instr.getFlowType();
		return ft.isCall() && !ft.isComputed() && instr.hasFallthrough();
	}

	/** Whether nothing but the call's fall-through enters {@code cont}. */
	private static boolean soleEntryIsFallThrough(Program program, Address cont) {
		if (program.getSymbolTable().isExternalEntryPoint(cont) ||
			program.getFunctionManager().getFunctionAt(cont) != null) {
			return false;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(cont)) {
			if (ref.getReferenceType().isFlow()) {
				return false;
			}
		}
		return true;
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
					.append(s.getKey().getName().equals("ctx_MF") ? "M=" : "X=")
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
			return false;
		}
		program.getBookmarkManager().setBookmark(call.getMinAddress(), BookmarkType.WARNING,
			BOOKMARK_CATEGORY, "callee " + callee.getMinAddress() + " is decoded at a different " +
				which + " width than this call passes, and its decode depends on it; one " +
				"address holds one decode, so this caller's view of it is wrong");
		return true;
	}
}
