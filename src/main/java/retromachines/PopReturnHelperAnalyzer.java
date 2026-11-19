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
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Fixes the fall-through after each {@code JSR} to a 6502 subroutine that does not return to
 * {@code JSR+3}, as measured by {@link PopReturnHelper} (grm-ed6h, grm-0fzb, grm-tysk), WITHOUT
 * ever marking the subroutine no-return:
 * <ul>
 * <li>a subroutine that discards its caller's return address (unwind level 1+: pop-return
 * helper, inline-table JumpEngine, far-call trampoline) -- each {@code JSR} gets a
 * {@link FlowOverride#CALL_RETURN} override and the code decoded at its old fall-through is
 * cleared (unless something else flows into it);</li>
 * <li>a subroutine that reads n INLINE argument bytes and returns past them (level 0, skip n:
 * db3 {@code db4c}, drmario {@code b6c2}) -- each {@code JSR}'s fall-through is overridden to
 * {@code JSR+3+n} ({@link Instruction#setFallThrough}), the false decode over the inline bytes is
 * cleared, the bytes become data, and the code at the resume address is disassembled.</li>
 * </ul>
 *
 * <p><b>Why not no-return.</b> Ghidra's function-level no-return flag says "never comes back to
 * anyone", but these helpers come back to the caller's caller, or to the caller past its inline
 * bytes. The flag propagates: a far-call stub or a dispatch routine that starts with
 * {@code JSR helper} becomes a THUNK of the helper, a thunk shares the helper's flag, and every
 * caller of the stub loses its fall-through (zelda, smb2, tmnt, dbz2; dbz2 {@code ca9a} then
 * crashed the decompiler, grm-hf5h.13). Stock "calls only non-returning functions" does the same
 * to a routine that ends in such a call (Metroid {@code d4cb}).
 *
 * <p><b>Priority: before stock.</b> {@link AnalysisPriority#DISASSEMBLY}{@code .after()}, one
 * step ahead of stock {@code FindNoReturnFunctionsAnalyzer}. Stock counts evidence only at calls
 * that still fall through into something odd, so once every {@code JSR} to a helper is fixed it
 * has nothing to count and never flags the helper. Clearing stock's flag AFTER it ran instead fed
 * it the same evidence on the next pass, and an earlier attempt oscillated 583 times
 * (grm-hf5h.12).
 *
 * <p><b>Undoing a flag already set</b> (stock got there first, or an older analysis): a
 * recognized helper with the flag has it cleared, and so does every flagged function the
 * recognizer measures as returning to its caller that is a caller or a stub of a helper; each
 * such function's callers whose {@code JSR} was overridden to {@code CALL_RETURN} get their
 * fall-through back (to {@code JSR+3+skip}, disassembled). That repeats up the call graph for
 * callers that were flagged in turn.
 *
 * @see <a href="urn:bead:grm-ed6h">grm-ed6h</a>
 * @see <a href="urn:bead:grm-0fzb">grm-0fzb</a>
 * @see <a href="urn:bead:grm-tysk">grm-tysk</a>
 * @see PopReturnHelper
 */
public class PopReturnHelperAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 6502 Pop-Return Helpers";
	private static final String DESCRIPTION =
		"Fixes the fall-through after each JSR to a 6502 subroutine that discards its caller's " +
			"return address (PLA/PLA/RTS, JumpEngine, far-call trampoline) or returns past " +
			"inline argument bytes, without marking the subroutine non-returning (grm-ed6h, " +
			"grm-0fzb, grm-tysk).";

	private PopReturnHelper.Levels levels;

	public PopReturnHelperAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return AnalyzerGates.is8BitPcode(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (levels == null) {
			levels = new PopReturnHelper.Levels(program);
		}
		Set<Address> helpers = new LinkedHashSet<>();
		Map<Address, PopReturnHelper.Unwind> skippers = new LinkedHashMap<>();
		for (Instruction instr : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			if (!"JSR".equals(instr.getMnemonicString()) || !instr.getFlowType().isCall()) {
				continue;
			}
			Address[] flows = instr.getFlows();
			if (flows.length != 1) {
				continue;
			}
			PopReturnHelper.Unwind u = levels.of(flows[0]);
			if (u == null) {
				continue;
			}
			if (u.discards()) {
				helpers.add(flows[0]);
			}
			else if (u.returns() && u.skip() > 0) {
				skippers.put(flows[0], u);
			}
		}
		int sites = 0;
		int skipSites = 0;
		Set<Function> unflagged = new LinkedHashSet<>();
		for (Address helper : helpers) {
			monitor.checkCancelled();
			sites += applyHelper(program, helper, unflagged, monitor);
		}
		for (Map.Entry<Address, PopReturnHelper.Unwind> e : skippers.entrySet()) {
			monitor.checkCancelled();
			skipSites += applySkipper(program, e.getKey(), e.getValue(), unflagged, monitor);
			if (e.getValue().assumed()) {
				AnalyzerLog.info(this, "ASSUMED a stack-neutral tail jump in " + e.getKey() +
					" (returns past " + e.getValue().skip() + " inline byte(s)); add a " +
					"per-game hint if its callers' resume code is wrong (grm-tysk)");
			}
		}
		int restored =
			unflagged.isEmpty() ? 0 : restoreCallers(program, levels, unflagged, monitor);
		if (sites > 0 || skipSites > 0 || !unflagged.isEmpty()) {
			AnalyzerLog.info(this, "stopped fall-through at " + sites + " JSR site(s) to " +
				helpers.size() + " return-discarding helper(s) " + helpers + "; resumed " +
				skipSites + " JSR site(s) past inline bytes of " + skippers.keySet() +
				(unflagged.isEmpty() ? ""
						: "; cleared no-return on " + unflagged.size() + " function(s), " +
							"restored fall-through at " + restored + " call site(s)"));
		}
		return true;
	}

	private Function functionAt(Program program, Address entry, Set<Function> unflagged,
			TaskMonitor monitor) {
		Function function = program.getFunctionManager().getFunctionAt(entry);
		if (function == null) {
			new CreateFunctionCmd(entry).applyTo(program, monitor);
			function = program.getFunctionManager().getFunctionAt(entry);
		}
		if (function != null && !function.isThunk() && function.hasNoReturn()) {
			function.setNoReturn(false);
			unflagged.add(function);
		}
		return function;
	}

	/** @return the number of call sites whose fall-through was newly stopped */
	private int applyHelper(Program program, Address entry, Set<Function> unflagged,
			TaskMonitor monitor) throws CancelledException {
		functionAt(program, entry, unflagged, monitor);

		AddressSet clear = new AddressSet();
		Set<Function> callers = new LinkedHashSet<>();
		int sites = 0;
		for (Instruction call : callsTo(program, entry)) {
			noteCaller(program, call, callers, unflagged);
			Address fallthrough = call.getFallThrough();
			if (fallthrough == null) {
				continue; // already stopped (by us earlier, by stock, or by the disassembler)
			}
			call.setFlowOverride(FlowOverride.CALL_RETURN);
			sites++;
			if (!fallthrough.equals(entry) && clearable(program, fallthrough)) {
				clear.add(fallthrough);
			}
		}

		fixBodies(program, callers, monitor);
		clearFlows(program, clear, monitor);
		return sites;
	}

	/** @return the number of call sites newly resumed past their inline bytes */
	private int applySkipper(Program program, Address entry, PopReturnHelper.Unwind u,
			Set<Function> unflagged, TaskMonitor monitor) throws CancelledException {
		functionAt(program, entry, unflagged, monitor);
		Set<Function> callers = new LinkedHashSet<>();
		Resume resume = new Resume();
		for (Instruction call : callsTo(program, entry)) {
			noteCaller(program, call, callers, unflagged);
			resume.plan(program, call, u.skip());
		}
		int sites = resume.apply(program, monitor);
		fixBodies(program, callers, monitor);
		return sites;
	}

	/**
	 * Re-points JSRs to {@code JSR+3+skip}: override the fall-through, clear the false decode
	 * over the inline bytes, lay the bytes as data, and disassemble the resume address.
	 */
	static final class Resume {
		private final AddressSet clear = new AddressSet();
		private final AddressSet disassemble = new AddressSet();
		private final Map<Address, Integer> inline = new LinkedHashMap<>();
		/** 65816: the E/M/X each continuation inherits from its call, stamped before decode. */
		private final Map<Address, Map<Register, BigInteger>> context = new LinkedHashMap<>();
		private int sites;

		void plan(Program program, Instruction call, int skip) {
			Address after = call.getMaxAddress().next();
			if (after == null) {
				return;
			}
			Address target = after.add(skip);
			if (W65816WidthEffects.applies(program)) {
				Map<Register, BigInteger> flags = new LinkedHashMap<>();
				for (String name : new String[] { "ctx_EF", "ctx_MF", "ctx_XF", "ctx_DF" }) {
					Register reg = program.getRegister(name);
					BigInteger v = call.getValue(reg, false);
					if (v != null) {
						flags.put(reg, v);
					}
				}
				context.put(target, flags);
			}
			if (call.getFlowOverride() == FlowOverride.CALL_RETURN) {
				call.setFlowOverride(FlowOverride.NONE);
				disassemble.add(target);
			}
			if (target.equals(call.getFallThrough())) {
				return;
			}
			if (skip > 0 && clearable(program, after)) {
				clear.add(after);
			}
			call.setFallThrough(target);
			sites++;
			if (skip > 0) {
				inline.put(after, skip);
			}
			disassemble.add(target);
		}

		int apply(Program program, TaskMonitor monitor) throws CancelledException {
			clearFlows(program, clear, monitor);
			for (Map.Entry<Address, Integer> e : inline.entrySet()) {
				int n = e.getValue();
				DataType type = n == 2 ? WordDataType.dataType
						: new ArrayDataType(ByteDataType.dataType, n, 1);
				try {
					DataUtilities.createData(program, e.getKey(), type, n,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				}
				catch (CodeUnitInsertionException ex) {
					// an instruction something else flows into still covers the bytes: leave it
				}
			}
			AddressSet todo = new AddressSet();
			for (Address a : disassemble.getAddresses(true)) {
				if (program.getListing().getInstructionAt(a) == null &&
					program.getListing().getDefinedDataAt(a) == null) {
					todo.add(a);
					stamp(program, a);
				}
			}
			if (!todo.isEmpty()) {
				new DisassembleCommand(todo, null, true).applyTo(program, monitor);
			}
			return sites;
		}

		/**
		 * Writes the call's E/M/X at a 65816 continuation: the cleared bytes otherwise decode at
		 * the pspec default (emulation mode, 8-bit), as W65816WidthAnalyzer's reDecode found. A
		 * callee that leaves other widths is that analyzer's to repair afterwards.
		 */
		private void stamp(Program program, Address a) {
			Map<Register, BigInteger> flags = context.get(a);
			if (flags == null) {
				return;
			}
			for (Map.Entry<Register, BigInteger> f : flags.entrySet()) {
				try {
					program.getProgramContext().setValue(f.getKey(), a, a, f.getValue());
				}
				catch (ContextChangeException e) {
					return; // an instruction already covers it: nothing to decode there
				}
			}
		}
	}

	static Iterable<Instruction> callsTo(Program program, Address entry) {
		Set<Instruction> calls = new LinkedHashSet<>();
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(entry);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Instruction call = program.getListing().getInstructionAt(ref.getFromAddress());
			if (call != null) {
				calls.add(call);
			}
		}
		return calls;
	}

	private void noteCaller(Program program, Instruction call, Set<Function> callers,
			Set<Function> unflagged) {
		Function caller = program.getFunctionManager().getFunctionContaining(call.getAddress());
		if (caller != null) {
			callers.add(caller);
			unflagIfReturning(caller, unflagged);
		}
		Function stub = program.getFunctionManager().getFunctionAt(call.getAddress());
		if (stub != null) {
			unflagIfReturning(stub, unflagged);
		}
	}

	/** Code there that nothing else reaches: the false decode after a call. */
	static boolean clearable(Program program, Address addr) {
		return !hasFlowRefInto(program, addr) &&
			!program.getSymbolTable().isExternalEntryPoint(addr) &&
			program.getListing().getInstructionAt(addr) != null;
	}

	static void clearFlows(Program program, AddressSet clear, TaskMonitor monitor) {
		if (!clear.isEmpty()) {
			AddressSetView protectedSet =
				AutoAnalysisManager.getAnalysisManager(program).getProtectedLocations();
			new ClearFlowAndRepairCmd(clear, protectedSet, true, false, true)
					.applyTo(program, monitor);
		}
	}

	/**
	 * Clears a no-return flag the recognizer contradicts: {@code fn} provably returns to its
	 * caller. A thunk is skipped -- it shares its target's flag, cleared with the target.
	 */
	private void unflagIfReturning(Function fn, Set<Function> unflagged) {
		if (fn.isThunk() || !fn.hasNoReturn()) {
			return;
		}
		PopReturnHelper.Unwind u = levels.of(fn.getEntryPoint());
		if (u != null && u.returns()) {
			fn.setNoReturn(false);
			unflagged.add(fn);
		}
	}

	/**
	 * Gives back the fall-through at every {@code JSR} into a function whose no-return flag was
	 * just cleared, or into one of its thunks, when that callee measures as returning to its
	 * caller (a helper's own call sites stay stopped): to {@code JSR+3+skip}, disassembled. Then
	 * repeats for callers that were flagged only because of it.
	 *
	 * @return the number of call sites restored
	 */
	static int restoreCallers(Program program, PopReturnHelper.Levels levels,
			Set<Function> start, TaskMonitor monitor) throws CancelledException {
		return restoreCallers(program, levels, start, Set.of(), monitor);
	}

	/**
	 * As above, with {@code plain}: entries already proven to be plain returns by the caller (a
	 * local proof {@link PopReturnHelper.Levels} cannot make, e.g. in a banked block), taken as
	 * level 0, skip 0 without consulting {@code levels}.
	 */
	static int restoreCallers(Program program, PopReturnHelper.Levels levels,
			Set<Function> start, Set<Address> plain, TaskMonitor monitor)
			throws CancelledException {
		return restoreCallers(program,
			e -> plain.contains(e) ? PopReturnHelper.Unwind.NORMAL : levels.of(e), start, monitor);
	}

	/**
	 * As above, with {@code measure} judging how each entry returns (null: inconclusive). The
	 * 65816 passes {@link W65816ReturnProof}, since {@link PopReturnHelper} models the 6502
	 * stack. A {@code JSL} caller is restored like a {@code JSR}.
	 */
	static int restoreCallers(Program program,
			java.util.function.Function<Address, PopReturnHelper.Unwind> measure,
			Set<Function> start, TaskMonitor monitor) throws CancelledException {
		ArrayDeque<Function> work = new ArrayDeque<>(start);
		Set<Function> done = new HashSet<>();
		Set<Function> bodies = new LinkedHashSet<>();
		Resume resume = new Resume();
		int restored = 0;
		while (!work.isEmpty()) {
			monitor.checkCancelled();
			Function fn = work.poll();
			if (!done.add(fn)) {
				continue;
			}
			Set<Address> entries = new LinkedHashSet<>();
			entries.add(fn.getEntryPoint());
			Address[] thunks = fn.getFunctionThunkAddresses(true);
			if (thunks != null) {
				entries.addAll(Arrays.asList(thunks));
			}
			for (Address entry : entries) {
				PopReturnHelper.Unwind u = measure.apply(entry);
				if (u == null || !u.returns()) {
					continue; // a helper's own JSRs stay stopped; only returning callees resume
				}
				for (Instruction call : callsTo(program, entry)) {
					String mn = call.getMnemonicString();
					if (!("JSR".equals(mn) || "JSL".equals(mn)) ||
						call.getFlowOverride() != FlowOverride.CALL_RETURN) {
						continue;
					}
					resume.plan(program, call, u.skip());
					restored++;
					Function caller =
						program.getFunctionManager().getFunctionContaining(call.getAddress());
					if (caller != null) {
						bodies.add(caller);
						if (!caller.isThunk() && caller.hasNoReturn()) {
							PopReturnHelper.Unwind cu = measure.apply(caller.getEntryPoint());
							if (cu != null && cu.returns()) {
								caller.setNoReturn(false);
								work.add(caller);
							}
						}
					}
				}
			}
		}
		resume.apply(program, monitor);
		fixBodies(program, bodies, monitor);
		return restored;
	}

	static void fixBodies(Program program, Set<Function> functions, TaskMonitor monitor)
			throws CancelledException {
		for (Function fn : functions) {
			monitor.checkCancelled();
			if (!fn.getBody().equals(
				CreateFunctionCmd.getFunctionBody(program, fn.getEntryPoint()))) {
				CreateFunctionCmd.fixupFunctionBody(program, fn, monitor);
			}
		}
	}

	/** A flow (not data) reference into {@code addr}: someone else reaches it as code. */
	private static boolean hasFlowRefInto(Program program, Address addr) {
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(addr);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}
}
