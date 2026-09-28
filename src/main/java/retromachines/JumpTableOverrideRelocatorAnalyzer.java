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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Keeps {@link JumpTableBoundAnalyzer}'s overrides attached to the function that contains each
 * switch NOW (grm-v60.1).
 * <p>
 * An override lives in {@code override/jmp_<addr>} under the function that contained the switch
 * when it was written, and the decompiler reads it only from the function that contains the
 * switch now. Creating a function can take a switch out of another function's body: dragonpower
 * 8655 is first bounded inside FUN_82ac's body, then becomes FUN_8645's once {@code 85bb JSR
 * $8645} makes that a function. The bound analyzer moves a stranded override if it happens to
 * revisit the switch, but whether it does depends on analysis order. The row flipped between 152
 * and 168 symbols over three runs. This analyzer hooks the event that causes the problem instead:
 * for each newly created function, it moves any stranded override for a computed jump in the new
 * body, via {@link JumpTableBoundAnalyzer#relocateStaleOverride}.
 */
public class JumpTableOverrideRelocatorAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Jump Table Override Relocator";
	private static final String DESCRIPTION =
		"Moves a Retro Jump Table Bound override onto the function that now contains its switch, " +
			"after function creation takes the switch out of the function it was written under.";

	public JumpTableOverrideRelocatorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		// Right after functions are created, and before later passes decompile them.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().supportsPcode()) {
			return false;
		}
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		return defaultSpace != null && defaultSpace.getSize() <= 16;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
		int moved = 0;
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function function = functions.next();
			InstructionIterator it = program.getListing().getInstructions(function.getBody(), true);
			while (it.hasNext()) {
				Instruction instr = it.next();
				if (!instr.getFlowType().isComputed() || !instr.getFlowType().isJump()) {
					continue;
				}
				if (JumpTableBoundAnalyzer.relocateStaleOverride(this, program, function,
					instr.getMinAddress(), log)) {
					moved++;
				}
			}
		}
		if (moved > 0) {
			AnalyzerLog.info(this, "moved " + moved + " stranded jump table override(s)");
		}
		return true;
	}
}
