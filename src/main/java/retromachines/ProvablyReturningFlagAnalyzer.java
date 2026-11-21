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

import java.util.ArrayDeque;
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
 * <li>its body provably returns: either {@link #selfContainedReturn} (a local forward-only flow
 * walk from the entry in which every leaf is an RTS, targets may leave the body but not the
 * memory block, and no backward branch is admitted; it needs no bank knowledge, which is how
 * smb3's {@code dd4e} in the banked base block qualifies), or
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
		"Clears the stock no-return flag on a 6502 or 65816 function whose body provably " +
			"returns when the evidence stock counted would no longer reach its threshold once " +
			"the callers' fall-through is restored (grm-z0d7.2, grm-9nxj.39).";

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
		// The 65816 is judged by W65816ReturnProof (grm-9nxj.39); the name keeps "6502" so the
		// analyzer's option key, which project files and preScripts persist, is unchanged.
		return AnalyzerGates.is8BitPcode(program) || W65816WidthEffects.applies(program);
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
							(W65816WidthEffects.applies(program) ? "by W65816ReturnProof"
									: levels.of(fn.getEntryPoint())) + ")");
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
		int restored;
		if (W65816WidthEffects.applies(program)) {
			restored = PopReturnHelperAnalyzer.restoreCallers(program,
				e -> e.equals(entry) || w65816Returns(program, e) ? PopReturnHelper.Unwind.NORMAL
						: null,
				start, monitor);
		}
		else {
			restored = PopReturnHelperAnalyzer.restoreCallers(program,
				new PopReturnHelper.Levels(program), start, Set.of(entry), monitor);
		}
		int unthunked = unthunkCallSites(program, fn, monitor);
		AnalyzerLog.info(analyzer, "cleared no-return on " + entry + ": the body provably " +
			"returns, replayed evidence " + evidence + ", restored fall-through at " + restored +
			" of " + callers + " call site(s), un-thunked " + unthunked +
			" call-site thunk(s) (grm-z0d7.2, grm-9nxj.39)");
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

	/**
	 * Measured level 0, skip 0, nothing else, over a plain body (see the class comment). On the
	 * 65816, {@link W65816ReturnProof} instead, and every caller must use the matching call
	 * ({@code JSR} for an {@code RTS}, {@code JSL} for an {@code RTL}).
	 */
	static boolean provablyReturns(Program program, Function fn, PopReturnHelper.Levels levels) {
		if (W65816WidthEffects.applies(program)) {
			return w65816Returns(program, fn.getEntryPoint());
		}
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
			if (MosOperands.isInterruptReturn(i) || MosOperands.isSoftwareInterrupt(i) ||
				MosOperands.rebasesStackPointer(i)) {
				return false;
			}
			if (MosOperands.isRts(i)) {
				rts = true;
			}
			if (i.getFlowType().isJump() && i.getFlowType().isIndirect()) {
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

	/** {@link W65816ReturnProof} holds and every call into {@code entry} matches its return. */
	static boolean w65816Returns(Program program, Address entry) {
		String kind = W65816ReturnProof.provenReturn(program, entry);
		if (kind == null) {
			return false;
		}
		String call = kind.equals("RTL") ? "JSL" : "JSR";
		for (Instruction i : PopReturnHelperAnalyzer.callsTo(program, entry)) {
			if (!call.equalsIgnoreCase(i.getMnemonicString())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Un-thunks every one-call "thunk" of {@code fn} whose call falls through again: stock's
	 * flag made Ghidra take a lone {@code JSR fn} at a called address for a thunk
	 * ({@code thunk_FUN_c3072d@c315aa}, grm-9nxj.39), and with the fall-through restored it is
	 * an ordinary function that calls {@code fn} and goes on. A jump thunk is left alone.
	 */
	private static int unthunkCallSites(Program program, Function fn, TaskMonitor monitor)
			throws CancelledException {
		Address[] thunks = fn.getFunctionThunkAddresses(false);
		if (thunks == null) {
			return 0;
		}
		Set<Function> fixed = new LinkedHashSet<>();
		for (Address t : thunks) {
			Function thunk = program.getFunctionManager().getFunctionAt(t);
			Instruction i = program.getListing().getInstructionAt(t);
			if (thunk == null || i == null || !i.getFlowType().isCall() ||
				!i.getFlowType().hasFallthrough()) {
				continue;
			}
			thunk.setThunkedFunction(null);
			fixed.add(thunk);
		}
		PopReturnHelperAnalyzer.fixBodies(program, fixed, monitor);
		return fixed.size();
	}

	/** Cap on instructions visited by {@link #selfContainedReturn}'s walk. */
	private static final int MAX_WALK = 4096;

	/**
	 * A LOCAL proof that the bytes of {@code fn} return, independent of which bank a caller
	 * reaches (owner ruling on grm-z0d7.2, widened in grm-z0d7.3). It walks the flow graph from
	 * the entry, not the body. Every branch or jump target must be strictly greater than the
	 * branching instruction's address, so the walk is a DAG: it terminates and every path is
	 * examined. Targets may lie outside {@code fn.getBody()} (a shared RTS tail) but must stay in
	 * the entry's memory block and already be decoded instructions (a target that is not yet code
	 * declines; nothing is disassembled here). Every leaf must be an RTS; a fall-through into
	 * non-instruction bytes or off the block, any backward flow, indirect flow, call, or any of
	 * PHA PHP PLA PLP TXS JSR JSL RTI RTL BRK declines, as does exceeding a step cap. This is how a
	 * body in a banked window's base block can be judged, where {@link PopReturnHelper} declines
	 * because it cannot know the live bank.
	 */
	static boolean selfContainedReturn(Program program, Function fn) {
		Address entry = fn.getEntryPoint();
		MemoryBlock block = program.getMemory().getBlock(entry);
		if (block == null) {
			return false;
		}
		Listing listing = program.getListing();
		Set<Address> seen = new HashSet<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		work.add(entry);
		while (!work.isEmpty()) {
			Address at = work.poll();
			if (!seen.add(at)) {
				continue;
			}
			if (seen.size() > MAX_WALK || !block.contains(at)) {
				return false;
			}
			Instruction i = listing.getInstructionAt(at);
			if (i == null || !block.contains(i.getMaxAddress())) {
				return false;
			}
			if (MosOperands.isRts(i)) {
				continue; // a leaf
			}
			// anything that touches the stack, calls, or leaves by an interrupt/long return
			if (MosOperands.touchesStack(i) || i.getFlowType().isCall() ||
				MosOperands.isInterruptReturn(i) || MosOperands.isSoftwareInterrupt(i)) {
				return false;
			}
			if (i.getFlowType().isIndirect()) {
				return false;
			}
			for (Address flow : i.getFlows()) {
				if (flow.compareTo(at) <= 0) {
					return false;
				}
				work.add(flow);
			}
			if (i.hasFallthrough()) {
				Address ft = i.getFallThrough();
				if (ft == null) {
					return false;
				}
				work.add(ft);
			}
			else if (i.getFlows().length == 0) {
				return false; // terminates without RTS (e.g. a halt)
			}
		}
		return true;
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
