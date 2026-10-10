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
import java.util.LinkedHashSet;
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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Follows a SPLIT dispatch: a jump table whose load lives in the caller and whose
 * {@code JMP (P)} lives in a shared stub the caller calls (bead grm-3er5).
 *
 * <p><b>The shape</b>, rcproam's {@code FUN_bbb3} (NMI path) decoded from the pinned ROM:
 * <pre>
 *   bbc2: ASL A / TAY
 *   bbc4: LDA $bb89,Y / STA $1e     ; low byte of entry Y/2
 *   bbc9: LDA $bb8a,Y / STA $1f     ; high byte
 *   bbce: JSR $8068                 ; 8068: JMP ($001e) -- shared by every such caller
 * </pre>
 * At runtime this is an ordinary jump table, and each handler's {@code RTS} returns to the caller
 * through the stub. Neither Ghidra's switch recovery nor {@link JumpTableBoundAnalyzer} can see it,
 * because the decompiler recovers a switch only when the table load and the computed jump are in
 * ONE function, and factoring the {@code JMP (P)} into a stub separates them. So nothing reaches
 * the handlers: rcproam's {@code bd15} (entries 13 and 14 of {@code bb89}) and the {@code bd2e}
 * switch behind it went unreached once grm-eyn removed the over-read entry that used to reach
 * them by accident. Surveyed over the pinned NES corpus: 10 sites in 3 titles (rcproam 4, cv3 5,
 * dbz_datach 1).
 *
 * <p><b>The inline form</b> (grm-cqwn): the same four instructions falling straight into the
 * {@code JMP (P)} itself, with no stub. wizwarr's NMI state dispatch is the case:
 * <pre>
 *   b18c: LDX $03
 *   b18e: LDA $b19b,X / STA $66
 *   b193: LDA $b19c,X / STA $67
 *   b198: JMP ($0066)
 * </pre>
 * Here the load and the jump ARE in one function, but the decompiler still declines it ("Could
 * not recover jumptable ... Too many branches", then "Treating indirect jump as call"): the index
 * is a raw RAM byte with no guard in this function (the only one, {@code BMI} at {@code ff89}, is
 * in the NMI entry that reaches {@code b178} by {@code JMP}), and {@code
 * JumpBasic::findSmallestNormal} refuses a 1-byte switch variable's 256-value range unless a
 * {@code LOAD} lies on the path COMMON to every address byte. In a split pointer each byte has its
 * own {@code LOAD}, so neither is common, and no model is recovered at all -- leaving nothing for
 * {@link JumpTableBoundAnalyzer} to bound. The inline form is matched only when the {@code JMP (P)}
 * still carries no computed reference, i.e. when stock switch analysis (which runs before this
 * analyzer) recovered nothing there; the references and functions are the same as for a stub,
 * CALL-typed as the decompiler itself already treats the jump.
 *
 * <p><b>The table's extent</b> is not written anywhere in the code: the index is a doubled RAM
 * byte. Entries are therefore walked from the table start, interleaved low/high, and the walk
 * stops at the FIRST entry that:
 * <ul>
 * <li>overlaps an existing instruction -- the table ran into code (rcproam {@code bb89}'s 21
 *     entries end at {@code FUN_bbb3} itself);</li>
 * <li>starts another split-dispatch table found in the same pass -- tables laid end to end, the
 *     grm-2m07 signal (rcproam {@code bb5f} ends exactly where {@code bb89} begins);</li>
 * <li>points outside initialized, non-volatile memory (RAM, I/O, unmapped), or into a banked
 *     window other than the caller's own block;</li>
 * <li>points into the middle of an existing instruction;</li>
 * <li>would itself overlap the lowest target above the table seen so far -- a table cannot run
 *     into code it dispatches to, the {@link JumpTableBound#bound} rule (wizwarr {@code b19b}'s
 *     19 entries end at {@code b1c1}, entry 15's own handler, which nothing has disassembled yet
 *     when the walk runs);</li>
 * <li>or is past {@link #MAX_ENTRIES}.</li>
 * </ul>
 * Fewer than 2 surviving entries declines the site, and so does a table outside the block the
 * caller runs from: only that block's bytes are known to be mapped when the load executes
 * (dbz_datach's far-call reads a per-bank header at {@code $8001} straight after switching). Every rule only ever STOPS the walk earlier, so
 * a wrong answer is a table cut short, never one read past its end into invented targets -- the
 * failure grm-eyn spent a bead removing.
 *
 * <p><b>What is added</b>: a {@link RefType#COMPUTED_CALL} reference from the stub's
 * {@code JMP (P)} to each distinct target (CALL because the handler returns to the caller, the same
 * choice and placement as {@link IndirectJumpConstantPointerAnalyzer}), disassembly of the target,
 * a scheduled function, and an EOL comment at the call site naming the table. The stub is shared,
 * so its references are the union over its callers, exactly as a hand-written override would be.
 *
 * <p><b>Priority</b>: {@code CODE_ANALYSIS.after()}, deliberately after
 * {@link IndirectJumpConstantPointerAnalyzer}, which skips a {@code JMP (P)} that already carries a
 * computed reference; running first would hide that stub from it.
 */
public class SplitDispatchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Split Dispatch Table";
	private static final String DESCRIPTION =
		"Follows a jump table loaded in the caller (LDA tbl,Y / STA P / LDA tbl+1,Y / STA P+1) " +
			"and dispatched through a shared JMP (P) stub the caller calls (grm-3er5).";

	/** A doubled byte index (ASL A / TAY) addresses at most 128 two-byte entries. */
	static final int MAX_ENTRIES = 128;

	public SplitDispatchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
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

	/** One recognized call site: the call, the stub's {@code JMP (P)}, and the table's low byte
	 *  of entry 0 (the high byte follows it). In the inline form (grm-cqwn) {@code call} and
	 *  {@code stub} are the same {@code JMP (P)}. */
	record Site(Instruction call, Instruction stub, Address table) {

		boolean inline() {
			return call == stub;
		}
	}

	/**
	 * Whether {@code block} is a banked window: some overlay block (another bank's image) covers
	 * part of the same addresses. An address in such a block names bytes only for whichever bank
	 * is mapped, so a value read from it, or a target placed in it, is a claim about one bank.
	 */
	static boolean isBanked(Program program, MemoryBlock block) {
		if (block.isOverlay()) {
			return true;
		}
		for (MemoryBlock other : program.getMemory().getBlocks()) {
			if (other != block && other.isOverlay() &&
				other.getStart().getOffset() <= block.getEnd().getOffset() &&
				other.getEnd().getOffset() >= block.getStart().getOffset()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Site> sites = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Site site = match(listing, it.next());
			if (site != null) {
				sites.add(site);
			}
		}
		if (sites.isEmpty()) {
			return true;
		}
		Set<Address> tableStarts = new LinkedHashSet<>();
		for (Site s : sites) {
			tableStarts.add(s.table());
		}
		int resolvedSites = 0;
		int resolvedTargets = 0;
		for (Site site : sites) {
			monitor.checkCancelled();
			List<Address> targets = walkTable(program, site, tableStarts);
			if (targets.size() < 2) {
				continue;
			}
			resolvedSites++;
			Set<Address> distinct = new LinkedHashSet<>(targets);
			for (Address target : distinct) {
				if (applyTarget(program, listing, site.stub(), target)) {
					resolvedTargets++;
				}
			}
			String comment = "split dispatch: " + targets.size() + "-entry table at " +
				site.table() + " via JMP (" + IndirectJumpConstantPointer.pointerCell(site.stub()) +
				") at " + site.stub().getMinAddress() +
				(site.inline() ? " (grm-cqwn)" : " (grm-3er5)");
			AnnotationGuard.addComment(listing, site.call().getMinAddress(), CommentType.EOL,
				comment, "split dispatch:");
		}
		if (resolvedSites > 0) {
			AnalyzerLog.info(this, "followed " + resolvedSites + " split dispatch table(s), " +
				resolvedTargets + " new target reference(s)");
		}
		return true;
	}

	/**
	 * The site {@code call} completes, or null: {@code call} is a {@code JSR}/{@code JMP} to a
	 * {@code JMP (P)} stub, and the four instructions falling through into it are
	 * {@code LDA L,r / STA P / LDA L+1,r / STA P+1} in either load order, one index register.
	 * Or (grm-cqwn) {@code call} is itself a {@code JMP (P)} with no computed reference yet, and
	 * those four instructions fall through into it.
	 */
	static Site match(Listing listing, Instruction call) {
		Instruction stub;
		if (IndirectJumpConstantPointer.isIndirectJumpSite(call)) {
			if (hasComputedReference(call) || isDeclaredSwitch(call)) {
				// Switch analysis (or an earlier round) already resolved it, or a jump-table
				// override awaits stock switch analysis there (shenlong 8655, bounded by
				// JumpTableBoundAnalyzer): that switch has an owner.
				return null;
			}
			stub = call;
		}
		else {
			int op = opcode(call);
			if (op != 0x20 && op != 0x4c) {
				return null;
			}
			Address[] flows = call.getFlows();
			if (flows.length != 1) {
				return null;
			}
			stub = listing.getInstructionAt(flows[0]);
			if (stub == null || !IndirectJumpConstantPointer.isIndirectJumpSite(stub)) {
				return null;
			}
		}
		long cell = IndirectJumpConstantPointer.pointerCell(stub).getOffset();
		Instruction st2 = fallingInto(listing, call);
		Instruction ld2 = fallingInto(listing, st2);
		Instruction st1 = fallingInto(listing, ld2);
		Instruction ld1 = fallingInto(listing, st1);
		if (ld1 == null) {
			return null;
		}
		int loadOp = opcode(ld1);
		if ((loadOp != 0xb9 && loadOp != 0xbd) || opcode(ld2) != loadOp) {
			return null; // LDA abs,Y or LDA abs,X, the same index register for both bytes
		}
		Long c1 = storeCell(st1);
		Long c2 = storeCell(st2);
		Long t1 = operand16(ld1);
		Long t2 = operand16(ld2);
		if (c1 == null || c2 == null || t1 == null || t2 == null) {
			return null;
		}
		long lo;
		if (c1 == cell && c2 == cell + 1 && t2 == t1 + 1) {
			lo = t1;
		}
		else if (c2 == cell && c1 == cell + 1 && t1 == t2 + 1) {
			lo = t2;
		}
		else {
			return null;
		}
		return new Site(call, stub, call.getMinAddress().getAddressSpace().getAddress(lo));
	}

	/**
	 * The targets of {@code site}'s table, in order, cut at the first entry any stop rule rejects
	 * (see the class javadoc). Targets are placed in the stub's own space, as a direct
	 * {@code JMP} there would be.
	 */
	static List<Address> walkTable(Program program, Site site, Set<Address> tableStarts) {
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		AddressSpace targetSpace = site.stub().getMinAddress().getAddressSpace();
		List<Address> targets = new ArrayList<>();
		// The table must sit in the block the CALLER runs from: those bytes are mapped while the
		// caller executes, so the table read is the one the hardware sees. A table in another
		// banked window belongs to whichever bank is live there -- dbz_datach cc16 reads $8001,Y
		// right after its own far-call switch, i.e. a per-bank header -- and is declined.
		MemoryBlock home = memory.getBlock(site.call().getMinAddress());
		if (home == null || !home.equals(memory.getBlock(site.table()))) {
			return targets;
		}
		// Lowest target in the table's own block above the table, so far (grm-cqwn).
		long minTarget = Long.MAX_VALUE;
		for (int i = 0; i < MAX_ENTRIES; i++) {
			Address lo;
			Address hi;
			try {
				lo = site.table().addNoWrap(2L * i);
				hi = lo.addNoWrap(1);
			}
			catch (Exception e) {
				break;
			}
			if (i > 0 && tableStarts.contains(lo)) {
				break; // the next table begins here
			}
			if (hi.getOffset() >= minTarget) {
				break; // the table ran into one of its own handlers, disassembled or not
			}
			if (listing.getInstructionContaining(lo) != null ||
				listing.getInstructionContaining(hi) != null) {
				break; // the table ran into code
			}
			int value;
			try {
				value = (memory.getByte(lo) & 0xff) | (memory.getByte(hi) & 0xff) << 8;
			}
			catch (MemoryAccessException e) {
				break;
			}
			Address target = targetSpace.getAddress(value);
			MemoryBlock block = memory.getBlock(target);
			if (block == null || !block.isInitialized() || block.isVolatile()) {
				break; // RAM, I/O or unmapped: not a handler
			}
			if (!block.equals(home) && isBanked(program, block)) {
				break; // a handler in another banked window: which bank is not established here
			}
			Instruction at = listing.getInstructionContaining(target);
			if (at != null && !at.getMinAddress().equals(target)) {
				break; // mid-instruction
			}
			if (block.equals(home) && value > site.table().getOffset()) {
				minTarget = Math.min(minTarget, value);
			}
			targets.add(target);
		}
		return targets;
	}

	/** Whether a {@code switch} label sits on {@code instr}: what a {@link
	 *  ghidra.program.model.pcode.JumpTable} override (and stock switch labelling) leaves there. */
	private static boolean isDeclaredSwitch(Instruction instr) {
		for (Symbol sym : instr.getProgram().getSymbolTable().getSymbols(instr.getMinAddress())) {
			if ("switch".equals(sym.getName())) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasComputedReference(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}

	private static Instruction fallingInto(Listing listing, Instruction instr) {
		if (instr == null) {
			return null;
		}
		Instruction prev = listing.getInstructionBefore(instr.getMinAddress());
		if (prev == null || prev.getFallThrough() == null ||
			!prev.getFallThrough().equals(instr.getMinAddress())) {
			return null;
		}
		return prev;
	}

	private static int opcode(Instruction instr) {
		if (instr == null) {
			return -1;
		}
		try {
			return instr.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** The 16-bit operand of a 3-byte instruction, or null. */
	private static Long operand16(Instruction instr) {
		if (instr.getLength() != 3) {
			return null;
		}
		try {
			return (long) ((instr.getByte(1) & 0xff) | (instr.getByte(2) & 0xff) << 8);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	/** The cell a non-indexed {@code STA zp} / {@code STA abs} writes, or null. */
	private static Long storeCell(Instruction instr) {
		int op = opcode(instr);
		try {
			if (op == 0x85) {
				return (long) (instr.getByte(1) & 0xff);
			}
			if (op == 0x8d) {
				return operand16(instr);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return null;
	}

	/** Adds the COMPUTED_CALL reference (unless present), disassembles and schedules a function
	 *  at {@code target}, as {@link IndirectJumpConstantPointerAnalyzer} does. Returns whether a
	 *  new reference was added. */
	private boolean applyTarget(Program program, Listing listing, Instruction stub,
			Address target) {
		for (Reference ref : stub.getReferencesFrom()) {
			if (ref.getToAddress().equals(target) && ref.getReferenceType().isComputed()) {
				return false;
			}
		}
		stub.addMnemonicReference(target, RefType.COMPUTED_CALL, SourceType.ANALYSIS);
		if (listing.getInstructionAt(target) == null) {
			ProgramContext programContext = program.getProgramContext();
			Register base = programContext.getBaseContextRegister();
			if (base != null) {
				RegisterValue v = programContext.getFlowValue(
					programContext.getRegisterValue(base, stub.getMinAddress()));
				if (v != null && v.hasAnyValue() &&
					programContext.getNonDefaultValue(base, target) == null) {
					try {
						programContext.setRegisterValue(target, target, v);
					}
					catch (ContextChangeException e) {
						// another thread raced the same target; leave its context alone
					}
				}
			}
			new DisassembleCommand(new AddressSet(target), null, true).applyTo(program);
		}
		AutoAnalysisManager.getAnalysisManager(program).createFunction(target, false);
		return true;
	}
}
