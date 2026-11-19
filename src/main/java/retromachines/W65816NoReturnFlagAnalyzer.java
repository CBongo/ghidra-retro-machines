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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sets Ghidra's no-return flag on a 65816 function that provably never returns (bead
 * grm-hf5h.27), and ends flow after every call to it, as stock "Non-Returning Functions -
 * Discovered" does for the functions it flags. Stock is off for SNES programs since grm-9nxj.39
 * (all three flags it set on the snes-analysis rows were wrong), so this is the only analyzer
 * that sets the flag on the 65816; scope is 65816-only by owner ruling (2026-11-18), 6502 is
 * grm-hf5h.32. <b>Disabled by default</b> until FF3 {@code ee0eab} settles whether the scan is
 * sound (see the constructor).
 * <p>
 * The test is {@link W65816NoReturnProof}'s structural scan, the one the DP summary already
 * trusts for tail jumps (grm-hf5h.26): every path from the entry is seen and none reaches
 * {@code RTS}/{@code RTL}/{@code RTI}. A path it cannot follow -- an unresolved computed jump,
 * which includes {@code BRK}/{@code COP}/{@code STP}, a missing instruction, the scan cap --
 * proves nothing, and nothing is flagged. Unlike stock, no "odd code after the call" evidence
 * is used: the decision is on the callee's own body. The worked example is FF3's boot routine
 * {@code FUN_c00019} and its endless main loop, reached from RESET and by the soft-reset
 * {@code JMP $C0FF00} thunk.
 * <p>
 * For each flagged function (and each of its thunks), every direct call to it that falls
 * through gets a {@code CALL_RETURN} flow override; the code after the call is cleared and
 * repaired when nothing else flows into it ({@link PopReturnHelperAnalyzer#clearable}, the same
 * guard and repair stock uses), and the callers' bodies are fixed. A call whose flows include a
 * target that returns (a computed call with several targets) is left alone. Flagging is
 * transitive: a caller whose only way out was such a call is proven on the next pass, which
 * now follows the overridden call into the callee instead of stepping over it.
 * <p>
 * It cannot flip-flop with the two analyzers that clear the flag:
 * {@link ProvablyReturningFlagAnalyzer} only clears a flag that carries stock's bookmark, and
 * {@link W65816ReturnProof} requires a reachable return, which a flagged body has none of;
 * {@link PopReturnHelperAnalyzer} does not run on the 65816. A function this analyzer flagged
 * once and that is no longer flagged (a user cleared it) is not flagged again.
 */
public class W65816NoReturnFlagAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 65816 Non-Returning Functions";
	private static final String DESCRIPTION =
		"Flags a 65816 function no-return when no path through its body reaches a return " +
			"(an endless main loop), and ends flow after the calls to it (grm-hf5h.27).";

	static final String BOOKMARK_CATEGORY = "Non-Returning Function (proven)";

	public W65816NoReturnFlagAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Late: after jump-table recovery, so a computed jump has all of its targets (one with
		// only some resolved would hide a return from the scan).
		setPriority(AnalysisPriority.CODE_ANALYSIS.after().after());
		// OFF until the scan's soundness is settled (grm-hf5h.27): on w_ff3 it flags ee0eab,
		// whose callers expect it to return (PHP/PHB/JSR/PLB/PLP), and how it gets back is open
		// (docs/human-research-todo.md 1.1). Enabled, the snes-analysis rows move w_ff3 (-4
		// instrs, the ee7576 cut) and w_ct (-14 instrs, Disassembler dispatch cuts).
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		// Judge every function, not only those in `set`: new code elsewhere (a resolved jump
		// table, a cut call) is what settles a scan.
		run(this, program, monitor);
		int repaired = repairDispatchCalls(program, set, monitor);
		if (repaired > 0) {
			AnalyzerLog.info(this, "gave back the fall-through of " + repaired + " dispatch " +
				"call(s) Ghidra stopped because their table's first slot is a flagged function " +
				"(grm-hf5h.27)");
		}
		return true;
	}

	/**
	 * Undoes Ghidra's Disassembler stopping a dispatch call because of this analyzer's flag
	 * (grm-hf5h.27). When it decodes a call through an indirect operand, the Disassembler
	 * ({@code Disassembler.java:1331} at 12.2) asks {@code getReferencedFunction} of the
	 * operand's address -- which reads only the table's FIRST slot -- and sets
	 * {@code CALL_RETURN} on the whole call if that one function is no-return. On w_ct that cut
	 * real code after six {@code JSR ($xxxx,X)} dispatches ({@code c05ab1}: a loop and an
	 * {@code RTS}). A computed call carrying {@code CALL_RETURN} whose referenced function is
	 * one this analyzer flagged, and one of whose resolved targets is not flagged, gets its
	 * fall-through back, decoded at the call's E/M/X. Another analyzer's override (no flagged
	 * first slot) is left alone.
	 * <p>
	 * UNPROVEN ON A REAL ROM: unit-tested, but on w_ct it repaired none of the six sites
	 * (grm-hf5h.33 has the open question of why).
	 */
	static int repairDispatchCalls(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		PopReturnHelperAnalyzer.Resume resume = new PopReturnHelperAnalyzer.Resume();
		int sites = 0;
		for (Instruction call : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			var ft = call.getFlowType();
			if (!ft.isCall() || !ft.isComputed() ||
				call.getFlowOverride() != FlowOverride.CALL_RETURN) {
				continue;
			}
			Function first = firstSlotFunction(program, call);
			if (first != null && first.isThunk()) {
				first = first.getThunkedFunction(true);   // a thunk reports its target's flag
			}
			if (first == null || !hasOwnBookmark(program, first.getEntryPoint())) {
				continue;
			}
			boolean returning = false;
			for (Address t : call.getFlows()) {
				Function callee = fm.getFunctionAt(t);
				if (callee == null || !callee.hasNoReturn()) {
					returning = true;
					break;
				}
			}
			if (returning) {
				resume.plan(program, call, 0);
				sites++;
			}
		}
		resume.apply(program, monitor);
		return sites;
	}

	/** The function the Disassembler's indirect-operand check sees: the table's first slot. */
	private static Function firstSlotFunction(Program program, Instruction call) {
		for (int op = 0; op < call.getNumOperands(); op++) {
			if (call.getOperandRefType(op).isIndirect()) {
				Address a = call.getAddress(op);
				if (a != null) {
					Function f = program.getFunctionManager().getReferencedFunction(a);
					if (f != null) {
						return f;
					}
				}
			}
		}
		return null;
	}

	/** Returns the functions flagged. */
	static Set<Function> run(AbstractAnalyzer analyzer, Program program, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		Set<Function> flagged = new LinkedHashSet<>();
		// Entries, re-looked-up each time: a clear-and-repair can delete a function.
		List<Address> candidates = new ArrayList<>();
		for (Function fn : fm.getFunctions(true)) {
			candidates.add(fn.getEntryPoint());
		}
		while (!candidates.isEmpty()) {
			List<Address> found = new ArrayList<>();
			for (Address entry : candidates) {
				monitor.checkCancelled();
				Function fn = fm.getFunctionAt(entry);
				if (fn == null || fn.isThunk() || fn.isExternal() || fn.hasNoReturn() ||
					hasOwnBookmark(program, entry)) {
					continue;
				}
				if (Boolean.TRUE.equals(W65816NoReturnProof.neverReturns(program, entry))) {
					found.add(entry);
				}
			}
			Set<Address> callers = new LinkedHashSet<>();
			for (Address entry : found) {
				monitor.checkCancelled();
				Function fn = fm.getFunctionAt(entry);
				if (fn != null && !fn.hasNoReturn()) {
					flag(analyzer, program, fn, callers, monitor);
					flagged.add(fn);
				}
			}
			Set<Function> bodies = new LinkedHashSet<>();
			for (Address c : callers) {
				Function fn = fm.getFunctionAt(c);
				if (fn != null) {
					bodies.add(fn);
				}
			}
			PopReturnHelperAnalyzer.fixBodies(program, bodies, monitor);
			// Only a function holding a call just cut can change its answer.
			candidates = new ArrayList<>(callers);
		}
		return flagged;
	}

	private static boolean hasOwnBookmark(Program program, Address entry) {
		return program.getBookmarkManager().getBookmark(entry, BookmarkType.ANALYSIS,
			BOOKMARK_CATEGORY) != null;
	}

	private static void flag(AbstractAnalyzer analyzer, Program program, Function fn,
			Set<Address> callers, TaskMonitor monitor) throws CancelledException {
		Address entry = fn.getEntryPoint();
		fn.setNoReturn(true);
		Set<Address> entries = new LinkedHashSet<>();
		entries.add(entry);
		Address[] thunks = fn.getFunctionThunkAddresses(true);
		if (thunks != null) {
			entries.addAll(List.of(thunks));
		}
		AddressSet clear = new AddressSet();
		int cut = 0;
		int calls = 0;
		for (Address e : entries) {
			for (Instruction call : PopReturnHelperAnalyzer.callsTo(program, e)) {
				calls++;
				if (!cuttable(program, call)) {
					continue;
				}
				Address after = call.getFallThrough();
				call.setFlowOverride(FlowOverride.CALL_RETURN);
				cut++;
				if (!entries.contains(after) && PopReturnHelperAnalyzer.clearable(program, after)) {
					clear.add(after);
				}
				Function caller =
					program.getFunctionManager().getFunctionContaining(call.getAddress());
				if (caller != null) {
					callers.add(caller.getEntryPoint());
				}
			}
		}
		PopReturnHelperAnalyzer.clearFlows(program, clear, monitor);
		program.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY,
			"no path returns; cut " + cut + " of " + calls + " call(s)");
		AnalyzerLog.info(analyzer, "flagged " + entry + " no-return: no path reaches a return; " +
			"ended flow at " + cut + " of " + calls + " call site(s), cleared the code after " +
			clear.getNumAddressRanges() + " (grm-hf5h.27)");
	}

	/**
	 * A call that falls through, carries no flow override, and whose every target is flagged
	 * no-return (a computed call with a returning target keeps its fall-through).
	 */
	private static boolean cuttable(Program program, Instruction call) {
		if (!call.getFlowType().isCall() || call.getFallThrough() == null ||
			call.getFlowOverride() != FlowOverride.NONE) {
			return false;
		}
		Address[] flows = call.getFlows();
		if (flows.length == 0) {
			return false;
		}
		for (Address t : flows) {
			Function callee = program.getFunctionManager().getFunctionAt(t);
			if (callee == null || !callee.hasNoReturn()) {
				return false;
			}
		}
		return true;
	}
}
