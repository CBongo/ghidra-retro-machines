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
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
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
 * <p><b>Switch override</b> (grm-gipk.24). The handlers stay functions of their own, and the
 * dispatcher's function additionally gets a {@link JumpTable} override listing every handler, so
 * the decompiler shows the dispatch as a {@code switch} (case bodies inlined, keyed by handler
 * address) instead of {@code Could not recover jumptable ... Too many branches} and an opaque
 * indirect call. The override is NOT followed by a body fixup: the handlers do not join the
 * dispatcher's body, so they keep their own bodies, callers and call-graph edges. It needs a
 * function containing the {@code JMP}, and when this analyzer runs that function usually does
 * not exist yet (function creation comes later). If one already contains the {@code JMP} the
 * override is written here, from the resolved handlers; otherwise it is DEFERRED to
 * {@link JumpTableOverrideRelocatorAnalyzer}, which reacts to every newly created function and
 * calls {@link #writeDeferredOverride}. Nothing is remembered in memory between the two: the
 * program itself says what is owed, namely a {@code JMP (zp)} that {@link
 * TwoLevelPointerDispatch#match} still recognizes, that carries {@code ANALYSIS}
 * {@link RefType#COMPUTED_JUMP} references (only this analyzer adds them here, since stock switch
 * recovery cannot follow two levels and this analyzer skips a {@code JMP} that already has one),
 * and that has no override yet.
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
		// grm-gipk.24: the switch override, now if a function already holds the JMP, else the
		// relocator writes it when one is created (see the class javadoc).
		Function owner = program.getFunctionManager().getFunctionContaining(jmp.getMinAddress());
		if (owner != null) {
			writeOverride(this, program, owner, jmp.getMinAddress(), r.handlers(), log);
		}
		AnalyzerLog.info(this, "site " + shape.jmp() + ": outer " + outer.start() + "[" +
			outer.entries().size() + ", " + outer.cut() + "], " + r.inner().size() +
			" inner table(s) (" + laidInner + " laid), " + handlers + " handler(s)");
	}

	/**
	 * Writes the {@link JumpTable} override for {@code jmp} on {@code owner} with {@code handlers}
	 * as its destinations (grm-gipk.24). The one place both the immediate and the deferred path
	 * write it. Does not touch the function body.
	 *
	 * @return whether the override was written
	 */
	static boolean writeOverride(Analyzer analyzer, Program program, Function owner, Address jmp,
			Collection<Address> handlers, MessageLog log) {
		if (handlers.isEmpty()) {
			return false;
		}
		try {
			new JumpTable(jmp, new ArrayList<>(handlers), true, EquateSymbol.FORMAT_DEFAULT)
					.writeOverride(owner);
		}
		catch (InvalidInputException | RuntimeException e) {
			AnalyzerLog.warn(analyzer, log, "could not write the jump table override at " + jmp +
				": " + e.getMessage());
			return false;
		}
		AnalyzerLog.info(analyzer, "wrote switch override at " + jmp + " on " + owner.getName() +
			" (" + handlers.size() + " handler(s))");
		return true;
	}

	/**
	 * The deferred half of the switch override (grm-gipk.24): called by {@link
	 * JumpTableOverrideRelocatorAnalyzer} for each computed jump in a newly created function.
	 * Writes the override when {@code jmp} is a dispatch this analyzer resolved (see the class
	 * javadoc) and has none yet. The destinations are the {@code ANALYSIS} computed-jump
	 * references, which this analyzer added from exactly the handlers it resolved.
	 *
	 * @return whether an override was written
	 */
	static boolean writeDeferredOverride(Analyzer analyzer, Program program, Function function,
			Instruction jmp, MessageLog log) {
		Address at = jmp.getMinAddress();
		if (JumpTableBoundAnalyzer.alreadyOverridden(program, function, at)) {
			return false;
		}
		List<Address> handlers = new ArrayList<>();
		for (Reference ref : jmp.getReferencesFrom()) {
			if (RefType.COMPUTED_JUMP.equals(ref.getReferenceType()) &&
				ref.getSource() == SourceType.ANALYSIS) {
				handlers.add(ref.getToAddress());
			}
		}
		if (handlers.isEmpty() || TwoLevelPointerDispatch.match(program, jmp) == null) {
			return false;
		}
		return writeOverride(analyzer, program, function, at, handlers, log);
	}
}
