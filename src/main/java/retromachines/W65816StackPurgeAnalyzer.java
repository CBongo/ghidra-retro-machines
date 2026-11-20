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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * The 65816 call stack model (bead grm-9nxj.47): sets a function's stack purge to the bytes its
 * return instruction pulls, 2 for a proven {@code RTS} and 3 for a proven {@code RTL}
 * ({@link W65816ReturnProof}).
 * <p>
 * Every w65816 prototype has {@code extrapop="unknown"}, {@code stackshift="0"} and {@code SP}
 * in {@code <unaffected>}. With an unknown extrapop both consumers take the change in SP across
 * a call from the callee's purge: Ghidra's constant propagation adds {@code stackshift + purge}
 * to SP after the call ({@code SymbolicPropogator.getDefaultStackDepthChange}), and Java sends
 * the decompiler {@code extrapop = purge + stackshift} ({@code FunctionPrototype
 * .grabFromFunction}). The call instruction's own p-code already pushed the return address, so
 * the purge is what the callee's return pulls: SP after the call equals SP before the
 * {@code JSR}/{@code JSL}, and a value pushed before the call is read back by the pull after it.
 * <p>
 * A purge is the callee's property, not the call's: a routine reached by both {@code JSR} and
 * {@code JSL} gets its return's size, which is what the hardware pulls either way (a mismatched
 * pair is a stack trick, and the purge still describes it truthfully). A function whose return is
 * not proven -- an {@code RTS}/{@code RTL} trick, a pop-return helper, a computed jump, a tail
 * jump, an interrupt handler ending in {@code RTI}, an unknown width -- keeps an unknown purge,
 * which leaves SP unknown after a call to it: nothing folds across that call, and nothing is
 * forwarded wrongly. That is why the purge must exist before SP is unaffected (owner condition
 * on the cspec change): with extrapop 0 constant propagation kept SP at the post-push value, so
 * pulls after the call and an interrupt handler's {@code RTI} read the pushed return address
 * (grm-9nxj.44 BLOCKER: bogus RTI targets on w_ff2/w_ff3/w_ct).
 * <p>
 * The decompiler needs one more piece: with an unknown-extrapop default it would GUESS 4 bytes
 * for a callee with no purge ({@code ActionStackPtrFlow}, an x86 assumption) and fold a pull to
 * an older push. The cspec therefore names {@code __unknown_purge} (extrapop 0, SP not
 * unaffected) as its {@code eval_called_prototype}, which turns off that guess and replaces the
 * model of every unlocked callee -- so this analyzer names the default prototype on a function
 * it sets a purge on, locking it ({@code FunctionPrototype.grabFromFunction}), and the purge
 * reaches the decompiler. A function whose convention another analyzer later resets to
 * "unknown" loses its folding in the decompiler (SP unknown after calls to it), never its
 * correctness.
 * <p>
 * Ordering: a function analyzer at {@link AnalysisPriority#FUNCTION_ANALYSIS}, like stock's x86
 * purge analyzer -- after the width, no-return and stack-trick analyzers, before constant
 * propagation and the DP/DBR analyzers (all {@code REFERENCE_ANALYSIS} minus a few). A function
 * created later than its callers were propagated only costs those callers their folding (SP is
 * unknown after the call); it is never a wrong value. A purge someone else set (a user, an
 * import) is left alone unless it is one of ours (2 or 3) and the proof now says otherwise.
 */
public class W65816StackPurgeAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 65816 Stack Purge";
	private static final String DESCRIPTION =
		"Sets a 65816 function's stack purge to 2 when every path returns by RTS and 3 when " +
			"every path returns by RTL, so the stack pointer is known after a call to it " +
			"(grm-9nxj.47).";

	/** Bytes {@code RTS} pulls. */
	static final int RTS_PURGE = 2;
	/** Bytes {@code RTL} pulls. */
	static final int RTL_PURGE = 3;

	public W65816StackPurgeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS);
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
		int n = run(program, set, monitor);
		if (n > 0) {
			AnalyzerLog.info(this, "set the stack purge of " + n + " function(s) from a proven " +
				"RTS/RTL (grm-9nxj.47)");
		}
		return true;
	}

	/** Sets the purge of every function with its entry in {@code set}; returns how many changed. */
	static int run(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		int changed = 0;
		for (Function fn : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			if (apply(program, fn)) {
				changed++;
			}
		}
		return changed;
	}

	/** The purge {@code fn}'s proven return pulls, or null when its return is not proven. */
	static Integer provenPurge(Program program, Function fn) {
		String kind = W65816ReturnProof.provenReturn(program, fn.getEntryPoint());
		if ("RTS".equals(kind)) {
			return RTS_PURGE;
		}
		if ("RTL".equals(kind)) {
			return RTL_PURGE;
		}
		return null;
	}

	/** Sets {@code fn}'s purge from its proven return; true if it changed. */
	static boolean apply(Program program, Function fn) {
		if (fn.isThunk() || fn.isExternal()) {
			return false; // a thunk's purge is its target's
		}
		Integer purge = provenPurge(program, fn);
		if (purge == null) {
			return false;
		}
		int current = fn.getStackPurgeSize();
		if (current == purge) {
			lockDefaultConvention(program, fn); // a later analyzer may have unnamed it
			return false;
		}
		boolean ours = current == RTS_PURGE || current == RTL_PURGE;
		if (fn.isStackPurgeSizeValid() && !ours) {
			return false; // someone else's purge
		}
		fn.setStackPurgeSize(purge);
		lockDefaultConvention(program, fn);
		return true;
	}

	/**
	 * Names the default prototype on a function that has no convention of its own, so the
	 * decompiler keeps the extrapop Java sends for it: an unlocked callee's model is replaced by
	 * the cspec's {@code eval_called_prototype} ({@code __unknown_purge}, extrapop 0), which would
	 * drop the purge (ActionDefaultParams; Java locks any named convention).
	 */
	private static void lockDefaultConvention(Program program, Function fn) {
		String cur = fn.getCallingConventionName();
		PrototypeModel dflt = program.getFunctionManager().getDefaultCallingConvention();
		if (dflt == null || !(cur == null || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(cur) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(cur))) {
			return; // already named (ours, the DP/DBR analyzers', or a user's)
		}
		try {
			fn.setCallingConvention(dflt.getName());
		}
		catch (InvalidInputException e) {
			// the default is always registered; nothing to lock otherwise
		}
	}
}
