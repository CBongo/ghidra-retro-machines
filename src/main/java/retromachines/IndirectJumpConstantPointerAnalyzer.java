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
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves a {@code JMP (P)} whose pointer cell {@code P} is proven constant on a straight-line
 * path reaching it, when Ghidra's own analysis leaves the jump uncomputed (grm-v60.1).
 *
 * <p><b>Motivating case.</b> Dragon Power and Shen Long (GxROM/mapper 66) enter their main
 * program from RESET through a far-call trampoline whose pointer cell (zero page {@code $17}/
 * {@code $18}) is written with constant bytes on the only path reaching the trailing
 * {@code JMP ($0017)}, with an inline {@code JSR} in between (see the bead for the full listing).
 * Today Ghidra cannot resolve this jump at all, so the entire main program downstream of it is
 * never disassembled. This analyzer adds only the targets a straight-line path actually proves --
 * other callers of the shared tail may reach it with different pointer values, and those are
 * simply not claimed here.
 *
 * <p><b>Mechanism</b> (see {@link IndirectJumpConstantPointer} for the actual logic, kept
 * separate so it is unit-testable on its own): for each qualifying site, find every direct
 * ({@code STA}/{@code STX}/{@code STY}, non-indexed) write to the pointer cell's two bytes in the
 * site's own address space, back each one up to the head of its straight-line run, and walk
 * forward from there as a static constant tracker. Any straight-line walk that reaches the site
 * with both pointer bytes known yields a resolved target. For each distinct resolved target, this
 * analyzer adds a {@link RefType#COMPUTED_CALL} mnemonic reference and disassembles the target
 * if it is not already code. The site is a far-call trampoline's exit, so CALL is the honest
 * type, and it is what keeps the trampoline's own function body from absorbing the whole
 * downstream program. The target's function is SCHEDULED through
 * {@code AutoAnalysisManager.createFunction}, so it is created at the normal function priority:
 * a CALL reference from a {@code JMP} does not get one from stock analysis on its own (measured:
 * dragonpower's 8008 was left inside the NMI function's body). Creating it immediately, at
 * {@code CODE_ANALYSIS.before()}, was measured to make
 * dragonpower's newly reachable 8655 switch recover twice in some runs (a second, non-primary
 * label set; symbols 207 vs 259), because {@code JumpTableBoundAnalyzer} shares this priority
 * and saw either a real function or a stand-in depending on which ran first.
 *
 * <p><b>Placement.</b> A resolved target is placed in the {@code JMP} instruction's OWN address
 * space -- exactly what a direct {@code JMP $xxxx} at the same address would get. Bank
 * retargeting into the correct overlay is the existing machinery's job (grm-v60), not this
 * analyzer's; see {@link IndirectJumpConstantPointer}'s class javadoc.
 *
 * @see <a href="urn:bead:grm-v60.1">grm-v60.1</a>
 */
public class IndirectJumpConstantPointerAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Indirect Jump Constant Pointer";
	private static final String DESCRIPTION =
		"Resolves a JMP (P) whose pointer cell P is proven constant on a straight-line path " +
			"reaching it, when nothing else in Ghidra's analysis can compute the target " +
			"(grm-v60.1).";

	public IndirectJumpConstantPointerAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
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
		Listing listing = program.getListing();
		List<Instruction> sites = findSites(listing, set, monitor);
		int resolvedSites = 0;
		int resolvedTargets = 0;
		for (Instruction site : sites) {
			monitor.checkCancelled();
			Address pointerAddr = IndirectJumpConstantPointer.pointerCell(site);
			Set<Address> targets = IndirectJumpConstantPointer.resolveTargets(program,
				site.getMinAddress(), pointerAddr, monitor);
			if (targets.isEmpty()) {
				continue;
			}
			resolvedSites++;
			for (Address target : targets) {
				applyTarget(program, listing, site, target, monitor);
				resolvedTargets++;
			}
		}
		if (resolvedSites > 0) {
			AnalyzerLog.info(this, "resolved " + resolvedTargets + " constant target(s) at " +
				resolvedSites + " indirect jump site(s)");
		}
		return true;
	}

	/** Sites in {@code set}: {@code JMP (P)} instructions with no existing computed reference. */
	private List<Instruction> findSites(Listing listing, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		List<Instruction> sites = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			if (!IndirectJumpConstantPointer.isIndirectJumpSite(instr)) {
				continue;
			}
			if (hasComputedReference(instr)) {
				continue; // already resolved by us or something else -- don't fight it
			}
			sites.add(instr);
		}
		return sites;
	}

	private boolean hasComputedReference(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Adds a {@link RefType#COMPUTED_CALL} mnemonic reference from {@code site} to {@code target}
	 * and disassembles {@code target} if it is not already code (flowing the site's context
	 * register, mirroring {@code DecompilerSwitchAnalysisCmd.setSwitchTargetContext}). Function
	 * creation is left to stock analysis; see the class javadoc for why.
	 */
	private void applyTarget(Program program, Listing listing, Instruction site, Address target,
			TaskMonitor monitor) throws CancelledException {
		site.addMnemonicReference(target, RefType.COMPUTED_CALL, SourceType.ANALYSIS);

		if (listing.getInstructionAt(target) == null) {
			ProgramContext programContext = program.getProgramContext();
			Register baseContextRegister = programContext.getBaseContextRegister();
			RegisterValue siteContext = null;
			if (baseContextRegister != null) {
				siteContext = programContext.getRegisterValue(baseContextRegister,
					site.getMinAddress());
				siteContext = programContext.getFlowValue(siteContext);
			}
			try {
				setTargetContext(program, programContext, target, siteContext);
			}
			catch (ContextChangeException e) {
				return; // another thread raced the same target; leave it alone, matches stock
			}
			DisassembleCommand cmd = new DisassembleCommand(new AddressSet(target), null, true);
			cmd.applyTo(program);
		}
		// Scheduled at the function priority, not created now -- see the class javadoc.
		AutoAnalysisManager.getAnalysisManager(program).createFunction(target, false);
	}

	/** Verbatim port of {@code DecompilerSwitchAnalysisCmd.setSwitchTargetContext} (see
	 *  {@code JumpTableBoundAnalyzer}'s copy). */
	private void setTargetContext(Program program, ProgramContext programContext, Address target,
			RegisterValue siteContext) throws ContextChangeException {
		if (siteContext == null) {
			return;
		}
		RegisterValue curContext =
			programContext.getNonDefaultValue(siteContext.getRegister(), target);
		if (curContext != null) {
			siteContext = curContext.combineValues(siteContext);
		}
		if (siteContext == null || !siteContext.hasAnyValue()) {
			return;
		}
		program.getProgramContext().setRegisterValue(target, target, siteContext);
	}
}
