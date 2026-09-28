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

import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Removes the dead fall-through of the 6502 "branch always" pair (grm-78b): a conditional branch
 * followed directly by the branch on the opposite condition of the same flag, e.g.
 * <pre>
 *   f237  BNE $f21d
 *   f239  BEQ $f1cc   ; Z did not change since the BNE fell through, so this is always taken
 *   f23b  SEI         ; not reached from here -- blmaster's RESET body, entered by fff7 JMP $f23b
 * </pre>
 * Ghidra treats the second branch as an ordinary conditional one and follows its fall-through, so
 * the body of the function containing the pair runs on into whatever comes next. Function bodies
 * cannot overlap, so that function claims the next routine's code (blmaster's {@code FUN_f1ca}
 * absorbed RESET, and every mechanism write in it, which got a phantom bank-switch helper filed as
 * a bead). This analyzer sets a fall-through override of "none" on the second branch -- the same
 * record the GUI's fall-through actions keep -- so flow, function bodies and the decompiler all
 * stop there.
 *
 * <p><b>Why it is sound.</b> A branch changes no flag. When the first branch falls through, its
 * flag is in the state that makes the second branch taken. That holds only if the second branch
 * is reached by that fall-through ALONE: anything that branches, jumps or calls straight to it
 * brings its own flags, and then the fall-through is live. So the second branch must have no
 * reference to it at all. A reference that only appears later (code found by a later pass) is
 * not re-checked; that is the one way this can be wrong, and it would show as a body ending early.
 *
 * <p>Only the pair is handled, not branches whose flag is known from a preceding instruction
 * ({@code CLC / BCC}, {@code LDA #0 / BEQ}): those are the same idea, but touch many more sites.
 *
 * @see <a href="urn:bead:grm-78b">grm-78b</a>
 */
public class BranchAlwaysPairAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Branch-Always Pair";
	private static final String DESCRIPTION =
		"Removes the dead fall-through after a 6502 branch pair on opposite conditions of one " +
			"flag (BNE x / BEQ y), so function bodies stop there (grm-78b).";

	/** The 6502-family ISAs we ship or load onto, all with these eight flag branches. */
	private static final Set<String> SUPPORTED_PROCESSORS = Set.of("6502", "6510", "65816");

	/** Each flag branch and its complement. */
	private static final Map<String, String> COMPLEMENT = Map.of(
		"BPL", "BMI", "BMI", "BPL",
		"BVC", "BVS", "BVS", "BVC",
		"BCC", "BCS", "BCS", "BCC",
		"BNE", "BEQ", "BEQ", "BNE");

	public BranchAlwaysPairAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Straight after disassembly: before functions are laid down at FUNCTION_ANALYSIS, and
		// before anything reasons about which function contains a store.
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return processor != null && SUPPORTED_PROCESSORS.contains(processor.toString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		int removed = 0;
		for (Instruction first : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			Instruction second = alwaysTakenSecond(program, first);
			if (second == null) {
				continue;
			}
			second.setFallThrough(null);
			removed++;
			// A function laid down before this ran still has the old body; recompute it.
			Function function = program.getFunctionManager().getFunctionContaining(
				second.getMinAddress());
			if (function != null) {
				CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
			}
		}
		if (removed > 0) {
			AnalyzerLog.info(this, "removed " + removed + " dead fall-through(s) after a " +
				"branch-always pair");
		}
		return true;
	}

	/** The second branch of an always-taken pair starting at {@code first}, or null. Package
	 *  access for tests. */
	static Instruction alwaysTakenSecond(Program program, Instruction first) {
		String complement = COMPLEMENT.get(first.getMnemonicString().toUpperCase());
		if (complement == null || !first.hasFallthrough()) {
			return null;
		}
		Instruction second = program.getListing().getInstructionAt(first.getFallThrough());
		if (second == null ||
			!complement.equals(second.getMnemonicString().toUpperCase()) ||
			second.isFallThroughOverridden()) {
			return null;
		}
		Address at = second.getMinAddress();
		if (program.getReferenceManager().hasReferencesTo(at) ||
			program.getSymbolTable().isExternalEntryPoint(at)) {
			return null; // reachable other than by the first branch's fall-through
		}
		return second;
	}
}
