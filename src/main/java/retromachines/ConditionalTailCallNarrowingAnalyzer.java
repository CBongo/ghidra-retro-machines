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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.WeakHashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Narrows Shared Return Calls' "Allow Conditional Jumps" (which {@link RetroAnalysisDefaults}
 * switches on) back to conditional branches into GENUINE routine entries (grm-6m24.1).
 *
 * <p>With that option on, the stock {@code SharedReturnAnalysisCmd} puts a {@code CALL_RETURN}
 * flow override on every conditional branch into any function entry. On a conditional branch
 * that override leaves the reference type and function bodies alone, but rewrites the branch's
 * p-code to "taken: return to the target", which every p-code reader (the decompiler, constant
 * propagation, our bank dataflow) then treats as leaving the routine. Owner ruling 2026-10-25
 * (docs/human-research-todo.md 1.6, retired): smb3 $E3EE-$E57A is ONE routine,
 * {@code SndMus_QueueCommon} in captainsouthbird's disassembly (PRG/prg031.asm line 338); $E401
 * and $E4CD, reached only by {@code BNE}/{@code BEQ} and {@code JMP}, are not entries. So a
 * conditional branch is a tail call only when its target is a GENUINE entry: referenced by an
 * instruction that is a call by its own encoding ({@code JSR}; not a {@code JMP} that Shared
 * Return Calls itself turned into a call), by a non-flow (pointer/data) reference, or marked as
 * an external entry. The case the option exists for keeps its override: smb3's borrowed-RTS stubs
 * b4c1/bb80/af23 are dispatch-table entries, i.e. pointer referenced, so {@code BEQ stub} stays a
 * conditional tail call. On smb3 this restores the golden exactly, including the
 * {@code LDA ($6B),Y} reads resolved into WA000_B28::a904 ({e4d3, e53b, e562}).
 *
 * <p><b>Mechanism: a no-op pin, not a post-hoc clear.</b> This runs one priority step BEFORE
 * Shared Return Calls and sets the {@code BRANCH} flow override on a conditional branch into a
 * non-genuine entry. On a conditional branch {@code BRANCH} changes nothing ({@code
 * FlowOverride.getModifiedFlowType} returns a jump's flow unchanged, and {@code PcodeEmit} only
 * rewrites CALL/CALLIND/RETURN ops under it), but the stock command skips any instruction whose
 * override is not {@code NONE}. Clearing the {@code CALL_RETURN} afterwards instead does not
 * work: each override change is a code change, the stock code-added twin re-applies it, and the
 * two analyzers ping-pong forever (measured: an smb3 import timed out). The cost is a visible
 * {@code BRANCH} override on those branches in the listing.
 *
 * <p>Every non-genuine entry seen is kept and re-checked on each run. Once a JSR or pointer turns
 * up it is dropped and its pins cleared, and the stock command's next pass gives its branches the
 * override back. Unconditional jumps are never touched.
 *
 * <p><b>Not covered: $E401/$E4CD are still functions.</b> Those splits come from the stock
 * "Assume Contiguous Functions Only" pass, which makes a function at any unconditional JMP target
 * that lies across another function ($E51B JMP $E401 and $E525 JMP $E4CD both cross FUN_e501).
 * That is pre-12.2 behaviour, present in the blessed goldens; only GP-6976's filter (option off)
 * happened to suppress it here. See grm-6m24.1.
 */
public class ConditionalTailCallNarrowingAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Conditional Tail-Call Narrowing";
	private static final String DESCRIPTION =
		"Keeps a conditional branch a tail call (Shared Return Calls' CALL_RETURN override) only " +
			"when its target is a genuine entry: reached by a JSR or a pointer, not only by " +
			"branches and jumps (grm-6m24.1).";

	/** The 6502-family ISAs we ship or load onto. */
	private static final Set<String> SUPPORTED_PROCESSORS = Set.of("6502", "6510", "65816");

	/**
	 * Function entries seen so far that were not genuine when last checked, per program. Static
	 * because the function-added and code-added halves are two analyzer instances.
	 */
	private static final Map<Program, Set<Address>> WATCHED =
		Collections.synchronizedMap(new WeakHashMap<>());

	public ConditionalTailCallNarrowingAnalyzer() {
		this(AnalyzerType.FUNCTION_ANALYZER);
		setSupportsOneTimeAnalysis();
	}

	/**
	 * Shared Return Calls is two stock analyzers under one name: a function analyzer (new
	 * function entries) and {@code SharedReturnJumpAnalyzer}, an instruction analyzer (new jumps
	 * into existing functions). Each half here runs one priority step ahead of the matching stock
	 * half, so the pin is in place before the stock command looks; the code-added half shares
	 * this name so the options dialog shows one entry, as the stock pair does.
	 */
	protected ConditionalTailCallNarrowingAnalyzer(AnalyzerType type) {
		super(NAME, DESCRIPTION, type);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return processor != null && SUPPORTED_PROCESSORS.contains(processor.toString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Set<Address> fresh = new TreeSet<>();
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			fresh.add(function.getEntryPoint());
		}
		return recheck(program, fresh, monitor);
	}

	/**
	 * Adds {@code fresh} to the program's watched entries and narrows every watched entry that is
	 * still not genuine. Shared Return Calls re-applies CALL_RETURN to an EXISTING function's
	 * incoming branches whenever a later pass lands a jump on it, so every entry seen so far is
	 * re-checked each time, not only the new ones.
	 */
	protected boolean recheck(Program program, Set<Address> fresh, TaskMonitor monitor)
			throws CancelledException {
		Set<Address> watched = WATCHED.computeIfAbsent(program, p -> new TreeSet<>());
		watched.addAll(fresh);
		int pinned = 0;
		for (Iterator<Address> it = watched.iterator(); it.hasNext();) {
			monitor.checkCancelled();
			Address entry = it.next();
			boolean isFunction = program.getFunctionManager().getFunctionAt(entry) != null;
			if (!isFunction || isGenuineEntry(program, entry)) {
				// Not (or no longer) a candidate: hand its branches back to the stock analyzer.
				// A JSR or pointer that turns up later is final.
				narrow(program, entry, false);
				it.remove();
				continue;
			}
			pinned += narrow(program, entry, true);
		}
		if (pinned > 0) {
			AnalyzerLog.info(this, "kept " + pinned + " conditional branch(es) out of Shared " +
				"Return Calls: their targets are reached by no JSR or pointer");
		}
		return true;
	}

	/**
	 * Pins ({@code pin}) or unpins every plain conditional branch into {@code entry}. Pinning
	 * sets the no-op {@code BRANCH} flow override (replacing a {@code CALL_RETURN} the stock
	 * analyzer already set); unpinning clears a {@code BRANCH} back to none. Returns how many
	 * branches changed. Package access for tests.
	 */
	static int narrow(Program program, Address entry, boolean pin) {
		FlowOverride from = pin ? null : FlowOverride.BRANCH;
		FlowOverride to = pin ? FlowOverride.BRANCH : FlowOverride.NONE;
		List<Instruction> branches = new ArrayList<>();
		for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
			if (!ref.getReferenceType().isFlow() || !ref.getReferenceType().isConditional()) {
				continue;
			}
			Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
			if (instr == null || !isPlainConditionalJump(encodedFlow(instr))) {
				continue;
			}
			FlowOverride current = instr.getFlowOverride();
			boolean applies = pin
					? current == FlowOverride.NONE || current == FlowOverride.CALL_RETURN
					: current == from;
			if (applies) {
				branches.add(instr);
			}
		}
		// Collected first: changing an override rewrites the instruction's references.
		for (Instruction instr : branches) {
			instr.setFlowOverride(to);
		}
		return branches.size();
	}

	/**
	 * True when something other than a branch or jump reaches {@code entry}: an instruction that
	 * is a call by its own encoding, a non-flow (pointer/data) reference, or an external-entry
	 * mark. Package access for tests.
	 */
	static boolean isGenuineEntry(Program program, Address entry) {
		if (program.getSymbolTable().isExternalEntryPoint(entry)) {
			return true;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
			RefType type = ref.getReferenceType();
			if (!type.isFlow()) {
				return true; // pointer, table word, operand reference
			}
			if (!type.isCall()) {
				continue;
			}
			Instruction from = program.getListing().getInstructionAt(ref.getFromAddress());
			// A call-typed ref from a JMP that Shared Return Calls overrode is still a jump.
			if (from == null || encodedFlow(from).isCall()) {
				return true;
			}
		}
		return false;
	}

	/** The instruction's flow type as encoded, before any flow override. */
	private static FlowType encodedFlow(Instruction instr) {
		return instr.getPrototype().getFlowType(instr.getInstructionContext());
	}

	private static boolean isPlainConditionalJump(FlowType flow) {
		return flow.isJump() && flow.isConditional() && !flow.isComputed() && !flow.isCall();
	}
}
