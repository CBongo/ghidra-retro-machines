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

import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Removes the dead fall-through of a conditional branch whose flag is provably set by the
 * instruction before it, and clears the code that only that fall-through reached (grm-kdgv, the
 * listing half of grm-uurl):
 * <pre>
 *   ebef  LDA #$00
 *   ebf1  STA $2006
 *   ebf2  BEQ $EC34   ; Z is always set, so this is always taken
 *   ebf4  .byte ...   ; a palette table -- Ghidra decoded it as code, ending in BRK
 * </pre>
 * The decision is {@link StoredValueScanner#knownBranchOutcome}, the same state-free test the
 * Z2 writer census already uses to skip the impossible successor. For a branch it decides TAKEN,
 * this sets a fall-through override of "none" on the branch -- the record
 * {@link BranchAlwaysPairAnalyzer} keeps for the pair case -- so flow, function bodies and the
 * decompiler stop there. Then, when nothing else flows to the old fall-through address, it
 * clears the code reached only from it ({@link ClearFlowAndRepairCmd}, Ghidra's own "Clear Flow
 * and Repair", which keeps any block something outside the cleared flow still reaches).
 *
 * <p><b>Why it is sound.</b> knownBranchOutcome only decides a branch whose flag setter sits in
 * the same straight-line run with no join in between, so no other path can bring different
 * flags to it. The clear is guarded separately: a FLOW reference, an entry point, a function or
 * a non-default label at the fall-through address means something else runs it, and then only
 * the override is set.
 *
 * <p><b>Clearing is a reachability statement, not a data claim.</b> The cleared bytes are often
 * live code in the running game: tmnt's bank 4 {@code b786 LDA #$10 / BNE $b794 / b78a LDA #$11
 * / BNE $b794 / ...} is a chain of entries reached through the word table at {@code $B5A2}. They
 * are cleared anyway (owner ruling, 2026-10-13): the listing holds what the analysis has shown
 * reachable, and those entries were decoded only by a fall-through that cannot happen. Reaching
 * them through their table is a separate reachability job (grm-x51h).
 *
 * <p>Provably NOT-taken branches are left alone: Ghidra has no override that drops a
 * conditional branch's target flow. 6502/6510 only: knownBranchOutcome reads Z/N from the low
 * byte, which a 16-bit 65816 accumulator or index register does not honour.
 *
 * @see <a href="urn:bead:grm-kdgv">grm-kdgv</a>
 */
public class DecidedBranchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Decided Branch";
	private static final String DESCRIPTION =
		"Removes the dead fall-through after a 6502 conditional branch whose flag is provably " +
			"set by the preceding instruction (LDA #0 / BEQ), and clears code reached only " +
			"from it (grm-kdgv).";

	/** The 8-bit 6502-family ISAs; see the class comment for why the 65816 is excluded. */
	private static final Set<String> SUPPORTED_PROCESSORS = Set.of("6502", "6510");

	public DecidedBranchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Beside BranchAlwaysPairAnalyzer: straight after disassembly, before functions are laid
		// down and before anything reasons about which function contains a store.
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
		AddressSet clearStarts = new AddressSet();
		int removed = 0;
		for (Instruction branch : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			if (!isDecidedTaken(program, branch)) {
				continue;
			}
			Address dead = branch.getFallThrough();
			branch.setFallThrough(null);
			removed++;
			if (deadCodeStart(program, dead)) {
				clearStarts.add(dead);
				AnalyzerLog.info(this, branch.getMinAddress() + " " + branch +
					" is always taken; clearing flow from " + dead);
			}
			// A function laid down before this ran still has the old body; recompute it.
			Function function = program.getFunctionManager().getFunctionContaining(
				branch.getMinAddress());
			if (function != null) {
				CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
			}
		}
		if (!clearStarts.isEmpty()) {
			// Not clearing data: a defined table in the dead region is someone's claim, not ours.
			new ClearFlowAndRepairCmd(clearStarts, false, false, true).applyTo(program, monitor);
		}
		if (removed > 0) {
			AnalyzerLog.info(this, "removed " + removed + " dead fall-through(s) after a " +
				"decided branch; cleared flow from " + clearStarts.getNumAddresses() +
				" of them");
		}
		return true;
	}

	/** Whether {@code branch} is a conditional branch provably taken, with a live fall-through
	 *  still to remove. Package access for tests. */
	static boolean isDecidedTaken(Program program, Instruction branch) {
		if (!branch.getFlowType().isConditional() || !branch.hasFallthrough() ||
			branch.isFallThroughOverridden()) {
			return false;
		}
		return Boolean.TRUE.equals(StoredValueScanner.knownBranchOutcome(program, branch));
	}

	/**
	 * Whether the instruction at {@code dead} -- the old fall-through of a decided branch -- is
	 * reached by nothing else, so the code from there may be cleared. Any flow reference, an
	 * entry point, a function, or a label someone named keeps it.
	 */
	static boolean deadCodeStart(Program program, Address dead) {
		if (dead == null || program.getListing().getInstructionAt(dead) == null ||
			program.getSymbolTable().isExternalEntryPoint(dead) ||
			program.getFunctionManager().getFunctionAt(dead) != null) {
			return false;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(dead)) {
			if (ref.getReferenceType().isFlow()) {
				return false;
			}
		}
		for (Symbol symbol : program.getSymbolTable().getSymbols(dead)) {
			if (symbol.getSource() != SourceType.DEFAULT) {
				return false;
			}
		}
		return true;
	}
}
