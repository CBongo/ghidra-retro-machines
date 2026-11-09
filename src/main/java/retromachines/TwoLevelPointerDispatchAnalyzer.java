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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
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
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves the two-level zero-page pointer dispatch (grm-gipk.23): an outer word table, indexed
 * by an object type, of pointers to per-type handler word tables, read into one zero-page pointer
 * and then through it into a second, which a {@code JMP (zp)} takes. cv3 bank 20's entity AI
 * ({@code 8505}..{@code 8524}) is the motivating case; see {@link TwoLevelPointerDispatch} for
 * the shape, the bounds and the declines.
 *
 * <p><b>Per site</b>, for a {@code JMP (zp)} in the added set that carries no computed
 * reference yet: lays the outer table and every inner table that yielded a handler as word
 * arrays ({@link JumpTableArrays#layWords}, which also places the entries' data references),
 * then adds a {@link RefType#COMPUTED_JUMP} mnemonic reference from the {@code JMP} to every
 * handler, disassembles each one not yet code (flowing the {@code JMP}'s context register, as
 * {@link InlineJumpTableDispatchAnalyzer} does) and schedules a function there: a handler's
 * {@code RTS} returns to the dispatch routine's caller, so each is entered like a tail-called
 * function, exactly as {@link InlineJumpTableDispatchAnalyzer}'s targets are. The tables are laid
 * before any handler is disassembled, so disassembly cannot run over them.
 *
 * <p><b>Priority</b> {@link AnalysisPriority#CODE_ANALYSIS}{@code .before()}, with
 * {@link IndirectJumpConstantPointerAnalyzer} and {@link JumpTableBoundAnalyzer}: neither claims
 * this site (its pointer is neither constant nor a slot-table reload, and stock switch recovery
 * cannot follow two levels), and newly disassembled handlers are re-offered to all three.
 *
 * @see <a href="urn:bead:grm-gipk.23">grm-gipk.23</a>
 */
public class TwoLevelPointerDispatchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Two-Level Pointer Dispatch";
	private static final String DESCRIPTION =
		"Resolves a JMP (zp) whose pointer is read through a second zero-page pointer taken from " +
			"an indexed table of handler-table addresses (object state machines; grm-gipk.23).";

	public TwoLevelPointerDispatchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
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
		List<TwoLevelPointerDispatch.Shape> shapes = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			if (!IndirectJumpConstantPointer.isIndirectJumpSite(instr) ||
				hasComputedReference(instr)) {
				continue;
			}
			TwoLevelPointerDispatch.Shape shape = TwoLevelPointerDispatch.match(program, instr);
			if (shape != null) {
				shapes.add(shape);
			}
		}
		for (TwoLevelPointerDispatch.Shape shape : shapes) {
			monitor.checkCancelled();
			TwoLevelPointerDispatch.Resolution r = TwoLevelPointerDispatch.resolve(program, shape);
			if (r.declined() != null) {
				AnalyzerLog.info(this, "site " + shape.jmp() + ": declined, " + r.declined());
				continue;
			}
			apply(program, listing, shape, r, monitor, log);
		}
		return true;
	}

	private static boolean hasComputedReference(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}

	private void apply(Program program, Listing listing, TwoLevelPointerDispatch.Shape shape,
			TwoLevelPointerDispatch.Resolution r, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Instruction jmp = listing.getInstructionAt(shape.jmp());
		if (jmp == null) {
			return;
		}
		TwoLevelPointerDispatch.Table outer = r.outer();
		int laidInner = 0;
		if (!JumpTableArrays.layWords(program, outer.start(), outer.entries())) {
			AnalyzerLog.warn(this, log, "site " + shape.jmp() + ": could not lay outer table " +
				outer.start() + "[" + outer.entries().size() + "]");
		}
		for (TwoLevelPointerDispatch.Table t : r.inner().values()) {
			if (!t.entries().isEmpty() && JumpTableArrays.layWords(program, t.start(), t.entries())) {
				laidInner++;
			}
		}

		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue siteContext = null;
		if (baseContextRegister != null) {
			siteContext = programContext.getFlowValue(
				programContext.getRegisterValue(baseContextRegister, jmp.getMinAddress()));
		}
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		int handlers = 0;
		for (Address h : r.handlers()) {
			monitor.checkCancelled();
			jmp.addMnemonicReference(h, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
			handlers++;
			if (listing.getInstructionAt(h) == null) {
				try {
					InlineJumpTableDispatchAnalyzer.setTargetContext(program, programContext, h,
						siteContext);
				}
				catch (ContextChangeException e) {
					continue; // another thread raced the same target; leave it alone
				}
				DisassembleCommand cmd = new DisassembleCommand(new AddressSet(h), null, true);
				cmd.applyTo(program);
				InlineJumpTableDispatchAnalyzer.followDroppedFlows(program, listing,
					cmd.getDisassembledAddressSet(), monitor);
			}
			analysisManager.createFunction(h, false);
		}
		AnalyzerLog.info(this, "site " + shape.jmp() + ": outer " + outer.start() + "[" +
			outer.entries().size() + ", " + outer.cut() + "], " + r.inner().size() +
			" inner table(s) (" + laidInner + " laid), " + handlers + " handler(s)");
	}
}
