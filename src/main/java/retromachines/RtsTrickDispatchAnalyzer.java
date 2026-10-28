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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves the 6502 RTS-trick dispatch (grm-gipk.7): {@code LDA t1,R / PHA / LDA t2,R / PHA / RTS}
 * through a table of target-minus-one entries (see {@link RtsTrickDispatch} for the shape and the
 * bound). On the 6502 {@code RTS} is a return, so stock builds no switch and the targets stay
 * undisassembled; the real instances are adventure_island's bd50 (planar, hi table first) and
 * 8dd1, c6c9, c95c (interleaved).
 *
 * <p>For every {@code RTS} in the newly-added set that is a recognized, bounded site this
 * <ol>
 * <li>lays the table with {@link JumpTableArrays} ({@code word[n]} interleaved, or {@code byte[n]}
 * lo and hi halves planar), with one DATA reference per entry to its real (word + 1) target;</li>
 * <li>adds a {@link RefType#COMPUTED_JUMP} reference from the {@code RTS} to each target;</li>
 * <li>disassembles each target with the site's flow context, following flow.</li>
 * </ol>
 * No function is created: the cases share the dispatcher's stack frame. A target in a different
 * banked window than the table gets the DATA reference only and is left undisassembled (grm-rnf0),
 * as {@link InlineJumpTableDispatchAnalyzer} does. Re-offers of the same {@code RTS} are
 * idempotent.
 *
 * <p><b>Priority</b> is that of {@link InlineJumpTableDispatchAnalyzer}
 * ({@code CODE_ANALYSIS.before().before()}); being an instruction analyzer, the code it
 * disassembles is offered back to it, so RTS-trick sites inside handlers converge.
 *
 * @see RtsTrickDispatch
 */
public class RtsTrickDispatchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro RTS Trick Dispatch";
	private static final String DESCRIPTION =
		"Resolves the 6502 RTS trick (LDA hi,X / PHA / LDA lo,X / PHA / RTS through a table of " +
			"target-minus-one entries): lays the table, references and disassembles the targets " +
			"(grm-gipk.7).";

	/** Table bases of every recognized site seen so far, across {@code added} calls. */
	private final Set<Address> knownBases = new HashSet<>();
	/**
	 * Every recognized shape, by RTS. A DECLINED one is re-scanned on each later call (a neighbour
	 * found since may bound it); a resolved one only when its RTS is in the call's set again.
	 */
	private final Map<Address, RtsTrickDispatch.Shape> shapes = new LinkedHashMap<>();
	private final Set<Address> resolved = new HashSet<>();

	public RtsTrickDispatchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
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
		Listing listing = program.getListing();
		List<Instruction> rtsSites = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			if ("RTS".equals(instr.getMnemonicString())) {
				rtsSites.add(instr);
			}
		}
		// First recognize every site in the set, so each is bounded against ALL the tables known.
		for (Instruction rts : rtsSites) {
			monitor.checkCancelled();
			RtsTrickDispatch.Shape shape = RtsTrickDispatch.recognize(program, rts);
			if (shape != null) {
				shapes.put(rts.getMinAddress(), shape);
				for (Address base : RtsTrickDispatch.tableBases(program, shape)) {
					if (base != null) {
						knownBases.add(base);
					}
				}
			}
		}
		for (Map.Entry<Address, RtsTrickDispatch.Shape> e : new ArrayList<>(shapes.entrySet())) {
			monitor.checkCancelled();
			Address rtsAddr = e.getKey();
			if (resolved.contains(rtsAddr) && !set.contains(rtsAddr)) {
				continue;
			}
			Instruction rts = listing.getInstructionAt(rtsAddr);
			if (rts == null) {
				continue;
			}
			RtsTrickDispatch.Shape shape = e.getValue();
			RtsTrickDispatch.Site site = RtsTrickDispatch.scan(program, shape, knownBases);
			if (site == null) {
				AnalyzerLog.debug(this, "RTS " + rtsAddr + ": push pair recognized, table declined");
				continue;
			}
			apply(program, listing, rts, site, monitor, log);
			if (resolved.add(rtsAddr)) {
				AnalyzerLog.info(this, "RTS " + rtsAddr + ": " +
					(shape.interleaved() ? "interleaved word table at " + site.loBase
							: "planar lo " + site.loBase + " hi " + site.loBase.add(shape.gap())) +
					", " + site.targets.size() + " entries (" + site.cut + ")");
			}
		}
		return true;
	}

	private void apply(Program program, Listing listing, Instruction rts, RtsTrickDispatch.Site site,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		List<Address> targets = site.targets;
		boolean laid;
		if (site.shape.interleaved()) {
			laid = JumpTableArrays.isLaid(program, site.loBase, targets) ||
				JumpTableArrays.layWords(program, site.loBase, targets);
		}
		else {
			int gap = site.shape.gap();
			laid = JumpTableArrays.isLaidPlanar(program, site.loBase, gap, targets) ||
				JumpTableArrays.layPlanar(program, site.loBase, gap, targets);
		}
		if (!laid) {
			AnalyzerLog.warn(this, log, "could not lay the table at " + site.loBase +
				" (RTS at " + rts.getMinAddress() + "): code or other data overlaps it");
		}

		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue siteContext = null;
		if (baseContextRegister != null) {
			siteContext = programContext.getRegisterValue(baseContextRegister, rts.getMinAddress());
			siteContext = programContext.getFlowValue(siteContext);
		}
		ReferenceManager refs = program.getReferenceManager();
		for (Address target : targets) {
			monitor.checkCancelled();
			if (InlineJumpTableDispatch.isCrossWindow(program, site.loBase, target)) {
				continue; // grm-rnf0: the wrong bank's bytes; leave it to the state-side pass
			}
			refs.addMemoryReference(rts.getMinAddress(), target, RefType.COMPUTED_JUMP,
				SourceType.ANALYSIS, 0);
			if (listing.getInstructionAt(target) == null) {
				try {
					InlineJumpTableDispatchAnalyzer.setTargetContext(program, programContext, target,
						siteContext);
				}
				catch (ContextChangeException e) {
					continue;
				}
				DisassembleCommand disCmd = new DisassembleCommand(new AddressSet(target), null, true);
				disCmd.applyTo(program);
				InlineJumpTableDispatchAnalyzer.followDroppedFlows(program, listing,
					disCmd.getDisassembledAddressSet(), monitor);
			}
		}
	}
}
