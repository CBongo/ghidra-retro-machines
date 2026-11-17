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

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Clears stock FindNoReturnFunctions' flag on a function whose body PROVABLY returns, and gives
 * its callers their fall-through back (bead grm-z0d7.2, step 3 of grm-z0d7's plan).
 * <p>
 * Stock flags a callee once three of its call sites "fall into something odd", and then clears
 * the code after every call. On smb3 the evidence for the negate routine {@code dd4e} was two
 * wrong-bank artifacts ({@link WrongBankArtifacts}) and one genuine shared tail, and 27 callers
 * lost their fall-through. A function is unflagged only if ALL of these hold:
 * <ul>
 * <li>it carries stock's "Non-Returning Function" ANALYSIS bookmark, is not a thunk, and has not
 * already been unflagged once here (so a flag stock sets again is left alone);</li>
 * <li>its body provably returns: either {@link #selfContainedReturn} (a local proof that needs
 * no bank knowledge, which is how smb3's {@code dd4e} in the banked base block qualifies), or
 * {@link PopReturnHelper} measures it as returning to its caller with skip 0, no caller skip, no
 * stack-delta and no assumption, and its body holds no {@code RTI}, {@code BRK}, {@code TXS},
 * indirect jump, or call that does not fall through;</li>
 * <li>stock's own indicators, replayed as if every call fell through ({@link #evidence}), find
 * fewer than stock's threshold sites. The replay decodes the bytes after each call without
 * writing, because stock's repair already cleared them, so the decision is on the code a
 * restore WOULD produce. This is the guard against the oscillation grm-hf5h.12 hit (583
 * re-flags): were the evidence still at the threshold, stock would flag it again.</li>
 * </ul>
 * Priority is after {@link BoardBankAnalyzer} (and so after its retargeting and
 * {@link WrongBankArtifacts}), so the artifacts that fed stock false evidence are gone first.
 * The restore itself is {@link PopReturnHelperAnalyzer#restoreCallers}, shared with the
 * pop-return pass.
 */
public class ProvablyReturningFlagAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro 6502 Provably-Returning Functions";
	private static final String DESCRIPTION =
		"Clears the stock no-return flag on a 6502 function whose body provably returns when " +
			"the evidence stock counted would no longer reach its threshold once the callers' " +
			"fall-through is restored (grm-z0d7.2).";

	static final String STOCK_BOOKMARK_CATEGORY = "Non-Returning Function";
	static final String BOOKMARK_CATEGORY = "No-return flag cleared: provably returns";
	private static final String STOCK_ANALYZER = "Non-Returning Functions - Discovered";
	private static final String STOCK_THRESHOLD = "Function Non-return Threshold";
	private static final int DEFAULT_THRESHOLD = 3;
	private static final int MAX_RUN = 256;

	/** Entries this analyzer has unflagged, per program: a function flips at most once. */
	private static final Map<Program, Set<Address>> UNFLAGGED = new WeakHashMap<>();

	public ProvablyReturningFlagAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after().after());
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
		// Judge every flagged function on every invocation, not only those in `set`: the evidence
		// changes when OTHER code (the wrong-bank artifacts) goes away.
		run(this, program, monitor);
		return true;
	}

	/** Returns the functions whose flag was cleared. */
	static Set<Function> run(AbstractAnalyzer analyzer, Program program, TaskMonitor monitor)
			throws CancelledException {
		Set<Function> cleared = new LinkedHashSet<>();
		PopReturnHelper.Levels levels = new PopReturnHelper.Levels(program);
		int threshold = threshold(program);
		for (boolean progress = true; progress;) {
			progress = false;
			for (Function fn : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				if (!fn.hasNoReturn() || fn.isThunk() || fn.isExternal() ||
					!hasStockBookmark(program, fn.getEntryPoint()) ||
					flipped(program).contains(fn.getEntryPoint())) {
					continue;
				}
				if (!provablyReturns(program, fn, levels)) {
					if (noted(program).add(fn.getEntryPoint())) {
						AnalyzerLog.info(analyzer, "no-return flag on " + fn.getEntryPoint() +
							" kept: not provably a plain return (measured " +
							levels.of(fn.getEntryPoint()) + ")");
					}
					continue;
				}
				int evidence = evidence(program, fn.getEntryPoint());
				if (evidence >= threshold) {
					AnalyzerLog.info(analyzer, "no-return flag on " + fn.getEntryPoint() +
						" kept: the body returns but stock's indicators still find " + evidence +
						" site(s) once its callers fall through (threshold " + threshold + ")");
					continue;
				}
				clear(analyzer, program, fn, evidence, monitor);
				cleared.add(fn);
				levels = new PopReturnHelper.Levels(program);
				progress = true;
				break; // the iterator is stale after the restore rewrote bodies
			}
		}
		return cleared;
	}

	private static void clear(AbstractAnalyzer analyzer, Program program, Function fn,
			int evidence, TaskMonitor monitor) throws CancelledException {
		Address entry = fn.getEntryPoint();
		int callers = 0;
		for (Instruction ignored : PopReturnHelperAnalyzer.callsTo(program, entry)) {
			callers++;
		}
		flipped(program).add(entry);
		fn.setNoReturn(false);
		Bookmark stock = program.getBookmarkManager().getBookmark(entry, BookmarkType.ANALYSIS,
			STOCK_BOOKMARK_CATEGORY);
		if (stock != null) {
			program.getBookmarkManager().removeBookmark(stock);
		}
		program.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY,
			"evidence=" + evidence + " callers=" + callers);
		Set<Function> start = new LinkedHashSet<>();
		start.add(fn);
		int restored = PopReturnHelperAnalyzer.restoreCallers(program,
			new PopReturnHelper.Levels(program), start, Set.of(entry), monitor);
		AnalyzerLog.info(analyzer, "cleared no-return on " + entry + ": the body provably " +
			"returns, replayed evidence " + evidence + ", restored fall-through at " + restored +
			" of " + callers + " call site(s) (grm-z0d7.2)");
	}

	private static final Map<Program, Set<Address>> NOTED = new WeakHashMap<>();

	private static synchronized Set<Address> noted(Program program) {
		return NOTED.computeIfAbsent(program, p -> new HashSet<>());
	}

	private static synchronized Set<Address> flipped(Program program) {
		return UNFLAGGED.computeIfAbsent(program, p -> new HashSet<>());
	}

	private static boolean hasStockBookmark(Program program, Address entry) {
		return program.getBookmarkManager().getBookmark(entry, BookmarkType.ANALYSIS,
			STOCK_BOOKMARK_CATEGORY) != null;
	}

	private static int threshold(Program program) {
		try {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			return options.getInt(STOCK_ANALYZER + Options.DELIMITER + STOCK_THRESHOLD,
				DEFAULT_THRESHOLD);
		}
		catch (RuntimeException e) {
			return DEFAULT_THRESHOLD;
		}
	}

	/** Measured level 0, skip 0, nothing else, over a plain body (see the class comment). */
	static boolean provablyReturns(Program program, Function fn, PopReturnHelper.Levels levels) {
		if (selfContainedReturn(program, fn)) {
			return true;
		}
		PopReturnHelper.Unwind u = levels.of(fn.getEntryPoint());
		if (u == null || !u.returns() || u.skip() != 0 || u.callerSkip() != 0 || u.delta() != 0 ||
			u.assumed()) {
			return false;
		}
		boolean rts = false;
		for (Instruction i : program.getListing().getInstructions(fn.getBody(), true)) {
			String m = i.getMnemonicString();
			if (m.equals("RTI") || m.equals("BRK") || m.equals("TXS")) {
				return false;
			}
			if (m.equals("RTS")) {
				rts = true;
			}
			if (m.equals("JMP") && i.getFlowType().isIndirect()) {
				return false;
			}
			if (i.getFlowType().isCall()) {
				if (!i.getFlowType().hasFallthrough()) {
					return false;
				}
				for (Address target : i.getFlows()) {
					Function callee = program.getFunctionManager().getFunctionAt(target);
					if (callee != null && callee.hasNoReturn()) {
						return false;
					}
				}
			}
		}
		return rts;
	}

	/**
	 * A LOCAL proof that the bytes of {@code fn} return, independent of which bank a caller
	 * reaches (owner ruling on grm-z0d7.2): the body is one memory block; it holds no stack,
	 * call or interrupt instruction at all (PHA PHP PLA PLP TXS JSR JSL RTI RTL BRK), so it is
	 * stack-neutral and calls nothing; every instruction is decoded; every flow target and every
	 * fall-through stays inside the body (no indirect jump, no fall off the end); and at least
	 * one RTS ends a path. This is how a body in a banked window's base block can be judged,
	 * where {@link PopReturnHelper} declines because it cannot know the live bank.
	 */
	static boolean selfContainedReturn(Program program, Function fn) {
		AddressSetView body = fn.getBody();
		MemoryBlock block = program.getMemory().getBlock(fn.getEntryPoint());
		if (block == null) {
			return false;
		}
		boolean rts = false;
		for (Instruction i : program.getListing().getInstructions(body, true)) {
			if (!block.contains(i.getMinAddress()) || !block.contains(i.getMaxAddress())) {
				return false;
			}
			switch (i.getMnemonicString()) {
				case "PHA", "PHP", "PLA", "PLP", "TXS", "JSR", "JSL", "RTI", "RTL", "BRK" -> {
					return false;
				}
				case "RTS" -> rts = true;
				default -> {
				}
			}
			if (i.getFlowType().isIndirect() || i.getFlowType().isCall()) {
				return false;
			}
			for (Address flow : i.getFlows()) {
				if (!body.contains(flow)) {
					return false;
				}
			}
			if (i.hasFallthrough()) {
				Address ft = i.getFallThrough();
				if (ft == null || !body.contains(ft) ||
					program.getListing().getInstructionAt(ft) == null) {
					return false;
				}
			}
		}
		return rts;
	}

	/**
	 * Stock's indicator sites at the calls into {@code entry}, judged as if every call fell
	 * through to {@code JSR+3}. Reads only: the bytes after a call that stock's repair cleared
	 * are decoded with a {@link PseudoDisassembler}.
	 */
	static int evidence(Program program, Address entry) {
		int sites = 0;
		for (Instruction call : PopReturnHelperAnalyzer.callsTo(program, entry)) {
			if (indicator(program, call)) {
				sites++;
			}
		}
		return sites;
	}

	private static boolean indicator(Program program, Instruction callInst) {
		FunctionManager fm = program.getFunctionManager();
		Listing listing = program.getListing();
		Function callingFunc = fm.getFunctionContaining(callInst.getMinAddress());
		Address at = callInst.getMaxAddress().next();
		if (at == null) {
			return false;
		}
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		for (int step = 0; at != null && step < MAX_RUN; step++) {
			FunctionIterator after = fm.getFunctions(at, true);
			Address nextFunc = after.hasNext() ? after.next().getEntryPoint() : null;
			if (nextFunc != null && nextFunc.equals(at)) {
				return true; // function defined after call
			}
			Instruction real = listing.getInstructionAt(at);
			CodeUnit cu = real;
			Instruction instr = real;
			int length;
			if (real == null) {
				if (listing.getCodeUnitAt(at) == null ||
					listing.getDefinedDataAt(at) != null || listing.getInstructionContaining(at) != null) {
					return true; // data, or the interior of an instruction
				}
				try {
					instr = pseudo.disassemble(at);
				}
				catch (Exception e) {
					return true; // undecodable: falls into data
				}
				if (instr == null) {
					return true;
				}
				length = instr.getLength();
				cu = null;
			}
			else {
				length = instr.getLength();
			}
			if (nextFunc != null && nextFunc.compareTo(at) > 0 &&
				nextFunc.compareTo(at.add(length)) < 0) {
				return true; // function defined in the instruction after the call
			}
			if (cu == null || cu instanceof Instruction) {
				if (inconsistentRefs(program, at, callingFunc)) {
					return true;
				}
			}
			if (listing.getDefinedDataAt(at) != null) {
				return true;
			}
			at = instr.getFlowType().isFallthrough() ? instr.getFallThrough() : null;
		}
		return false;
	}

	private static boolean inconsistentRefs(Program program, Address addr, Function callingFunc) {
		FunctionManager fm = program.getFunctionManager();
		for (Reference ref : program.getReferenceManager().getReferencesTo(addr)) {
			RefType t = ref.getReferenceType();
			if (t.isRead() || t.isWrite()) {
				if (callingFunc != null) {
					Address from = ref.getFromAddress();
					if (from.compareTo(addr) < 0 &&
						callingFunc.equals(fm.getFunctionContaining(from))) {
						return true;
					}
				}
				else {
					return true;
				}
			}
			if (t.isCall()) {
				return true;
			}
		}
		return false;
	}
}
