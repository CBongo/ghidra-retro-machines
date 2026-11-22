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
import java.util.Objects;
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
 * <p><b>The gap and merged forms</b> (grm-gipk.34.1, grm-gipk.34.3): the inline form is found
 * from the load/store quad, walking FORWARD to the {@code JMP (P)} (see {@link #matchQuad}), so
 * instructions may sit between the second store and the jump, which the decompiler cannot see
 * through because a {@code JSR} there may write the pointer. ultimaav {@code 88f4}:
 * <pre>
 *   88e7: LDA $8903,Y / STA $02 / LDA $8904,Y / STA $03
 *   88f1: JSR $88f7                 ; a store-free helper
 *   88f4: JMP ($0002)
 * </pre>
 * and {@code 8a3f}, whose gap is {@code PLA / TAX / JSR $88f7}. dragonpower {@code f59a}/{@code
 * f5af}/{@code f5c8} are three quads, one per table, whose paths merge ({@code JMP $f5a6}) into
 * one {@code INY / STY $83 / INC $80 / JMP ($0000)}. Each quad is its own site and table; the
 * walk may pass loads, ALU ops, stores that cannot reach the pointer, calls that cannot write it,
 * and {@code JMP abs}. The quad's targets are reachable along its own path, and other paths
 * merging in can only add targets of other quads, so no other-entry check is needed.
 *
 * <p><b>Leading null slots</b> (grm-gipk.34.2): an interleaved table may begin with up to
 * {@link #MAX_LEADING_NULLS} {@code $0000} slots (dragonpower {@code a8a2}, dodge {@code 8571}),
 * an unused index. They are skipped, not stops, count toward the extent and add no target; a
 * {@code $0000} anywhere later still ends the walk.
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
 * <p><b>The planar form</b> (grm-gipk.33): the low and high bytes are two separate tables whose
 * bases are not adjacent ({@code LDA lo,Y / STA P / LDA hi,Y / STA P+1 / JMP (P)}, megaman2
 * {@code 82d5}: {@code $84dc} / {@code $84e5}), with the index a RAM variable no guard bounds. The
 * two tables cannot overlap, so the base distance (either order, at most
 * {@link #MAX_PLANAR_DISTANCE}) is the entry count. A recovered {@code CMP}/{@code BCC} index
 * guard ({@link IndexGuardRecovery#guardedIndexedLoad}) wins over the distance, setting both the
 * first and the last slot. The estimate is then trimmed at BOTH ends (owner ruling grm-c9d.8):
 * the usual stop rules end the walk at the first bad entry (the tail), and a bad entry before the
 * first good one (RAM, unmapped, mid-instruction, code, a table of this analyzer) is skipped
 * instead (the head). Each planar target must also decode as code
 * ({@link InlineJumpTableDispatch#decodesAsCode}), since the distance is only an estimate. The
 * head skip is not applied to the interleaved form, whose extent has never been an estimate of
 * this kind, nor to a guarded table, whose first slot is stated.
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

	/** The most a planar table's base distance may be to count as its extent (grm-gipk.33): a
	 *  byte index reaches 256 entries, so a wider gap means the two bases are not one table. */
	static final int MAX_PLANAR_DISTANCE = 256;

	public SplitDispatchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return AnalyzerGates.is8BitPcode(program);
	}

	/** One recognized call site: the call, the stub's {@code JMP (P)}, the table's low byte
	 *  of entry 0 (the high byte follows it, or, for a planar table, sits at {@code hiTable}) and
	 *  the {@code LDA} that loads the low bytes. In the inline form (grm-cqwn) {@code call} and
	 *  {@code stub} are the same {@code JMP (P)}. */
	record Site(Instruction call, Instruction stub, Address table, Address hiTable,
			Instruction loLoad, int gap, boolean viaJump) {

		/** Whether instructions were walked between the second store and the inline
		 *  {@code JMP (P)} (grm-gipk.34.1); {@code viaJump} says a {@code JMP abs} was followed
		 *  on the way (grm-gipk.34.3). */
		boolean gapped() {
			return gap > 0;
		}

		boolean inline() {
			return Objects.equals(call, stub);
		}

		/** Whether the high bytes are a separate table (grm-gipk.33), not interleaved at
		 *  {@code table + 1}: entry {@code i} is then {@code table[i]} / {@code hiTable[i]}. */
		boolean planar() {
			return hiTable.getOffset() != table.getOffset() + 1;
		}

		/** The table bases other tables must not start inside. */
		List<Address> bases() {
			return planar() ? List.of(table, hiTable) : List.of(table);
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
			if (!Objects.equals(other, block) && other.isOverlay() &&
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
			Instruction instr = it.next();
			Site site = match(listing, instr);
			if (site == null) {
				site = matchQuad(listing, instr);
			}
			if (site != null) {
				sites.add(site);
			}
		}
		if (sites.isEmpty()) {
			return true;
		}
		Set<Address> tableStarts = new LinkedHashSet<>();
		for (Site s : sites) {
			tableStarts.addAll(s.bases());
		}
		// decided up front: the first upgraded pin would otherwise make the rest look resolved
		Set<Address> orphanStubs = new LinkedHashSet<>();
		for (Site s : sites) {
			if (s.inline() && isOrphanPin(s.stub())) {
				orphanStubs.add(s.stub().getMinAddress());
			}
		}
		int resolvedSites = 0;
		int resolvedTargets = 0;
		for (Site site : sites) {
			monitor.checkCancelled();
			Walk walk = walkTable(program, site, tableStarts);
			List<Address> targets = walk.targets();
			if (targets.size() < 2) {
				continue;
			}
			resolvedSites++;
			Set<Address> distinct = new LinkedHashSet<>(targets);
			boolean orphanPin = orphanStubs.contains(site.stub().getMinAddress());
			for (Address target : distinct) {
				if (applyTarget(program, listing, site.stub(), target, orphanPin)) {
					resolvedTargets++;
				}
			}
			int nulls = walk.leadingNulls();
			String comment = "split dispatch: " + (targets.size() + nulls) + "-entry table at " +
				site.table() + (nulls > 0 ? " (" + nulls + " leading null" + (nulls > 1 ? "s" : "") + ")" : "") +
				(site.planar() ? " (high bytes at " + site.hiTable() + ")" : "") +
				" via JMP (" + IndirectJumpConstantPointer.pointerCell(site.stub()) +
				") at " + site.stub().getMinAddress() +
				(site.gapped() ? (site.viaJump() ? " (grm-gipk.34.3)" : " (grm-gipk.34.1)") : site.planar() ? " (grm-gipk.33)" :
					site.inline() ? " (grm-cqwn)" : " (grm-3er5)");
			AnalyzerCommentRecord.append(program, site.call().getMinAddress(), CommentType.EOL,
				comment, "table at " + site.table());
		}
		if (resolvedSites > 0) {
			AnalyzerLog.info(this, "followed " + resolvedSites + " split dispatch table(s), " +
				resolvedTargets + " new target reference(s)");
		}
		return true;
	}

	/**
	 * The stub-form site {@code call} completes, or null: {@code call} is a {@code JSR}/{@code JMP}
	 * to a {@code JMP (P)} stub, and the four instructions falling through into it are
	 * {@code LDA L,r / STA P / LDA L+1,r / STA P+1} in either load order, one index register. The
	 * inline form is found from the quad instead, by {@link #matchQuad}.
	 */
	static Site match(Listing listing, Instruction call) {
		int op = opcode(call);
		if (op != 0x20 && op != 0x4c) {
			return null;
		}
		Address[] flows = call.getFlows();
		if (flows.length != 1) {
			return null;
		}
		Instruction stub = listing.getInstructionAt(flows[0]);
		if (stub == null || !IndirectJumpConstantPointer.isIndirectJumpSite(stub)) {
			return null;
		}
		Quad quad = parseQuad(listing, fallingInto(listing, call));
		if (quad == null ||
			quad.cell() != IndirectJumpConstantPointer.pointerCell(stub).getOffset()) {
			return null;
		}
		AddressSpace space = call.getMinAddress().getAddressSpace();
		return new Site(call, stub, space.getAddress(quad.lo()), space.getAddress(quad.hi()),
			quad.loLoad(), 0, false);
	}

	/** A recognized {@code LDA lo,r / STA P / LDA hi,r / STA P+1} quad (either load order):
	 *  the pointer cell {@code P}, and the two table bases. */
	private record Quad(long cell, long lo, long hi, Instruction loLoad) {}

	/** The quad whose second store is {@code st2}, or null. */
	private static Quad parseQuad(Listing listing, Instruction st2) {
		if (st2 == null) {
			return null;
		}
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
		if (c1 + 1 == c2) {
			return t1.equals(t2) ? null : new Quad(c1, t1, t2, ld1);
		}
		if (c2 + 1 == c1) {
			return t1.equals(t2) ? null : new Quad(c2, t2, t1, ld2);
		}
		return null;
	}

	/**
	 * The inline-form site whose quad ends at {@code st2}, or null (grm-cqwn, grm-gipk.34.1,
	 * grm-gipk.34.3): walk FORWARD from the instruction after the second store, along fall-through
	 * and {@code JMP abs}, at most {@link #FORWARD_LIMIT} instructions, to a {@code JMP (P)} on the
	 * same {@code P}. Each walked instruction must be unable to change {@code P}: it writes no
	 * memory and is not control flow (loads, register/flag/stack ops, ALU, compares), or it stores
	 * or read-modify-writes a cell that provably is neither {@code P} nor {@code P+1}, or it is a
	 * {@code JSR} to a {@link #isPointerSafeCallee} routine, or a {@code JMP abs} (followed). A
	 * conditional branch, {@code RTS}/{@code RTI}/{@code BRK}, a {@code JMP (ind)} on another cell
	 * or an undecoded address ends the walk with no match.
	 *
	 * <p>Soundness: the quad's targets are reachable along its OWN walked path, because nothing on
	 * that path can change {@code P}; other paths merging into the walk (a shared tail, a branch
	 * into the gap) can only ADD targets of other quads, never invalidate these. So no check is
	 * made for other entries, and several quads may reach one {@code JMP (P)}, each contributing
	 * its own table. A {@code JMP (P)} that already carries computed references is left alone
	 * unless this analyzer wrote its comment there (an earlier quad or round).
	 */
	static Site matchQuad(Listing listing, Instruction st2) {
		Quad quad = parseQuad(listing, st2);
		if (quad == null) {
			return null;
		}
		long cell = quad.cell();
		Instruction cur = FlowEdges.nextFallThrough(listing, st2);
		boolean viaJump = false;
		for (int walked = 0; cur != null; walked++) {
			if (IndirectJumpConstantPointer.isIndirectJumpSite(cur)) {
				if (IndirectJumpConstantPointer.pointerCell(cur).getOffset() != cell) {
					return null;
				}
				if ((hasComputedReference(cur) && !isOrphanPin(cur) && !hasOwnComment(cur)) ||
					isDeclaredSwitch(cur)) {
					// Switch analysis (or an earlier round) already resolved it, or a jump-table
					// override awaits stock switch analysis there (shenlong 8655, bounded by
					// JumpTableBoundAnalyzer): that switch has an owner.
					return null;
				}
				AddressSpace space = cur.getMinAddress().getAddressSpace();
				return new Site(cur, cur, space.getAddress(quad.lo()), space.getAddress(quad.hi()),
					quad.loLoad(), walked, viaJump);
			}
			if (walked == FORWARD_LIMIT) {
				return null;
			}
			int op = opcode(cur);
			if (op == 0x4c) {
				Address[] flows = cur.getFlows();
				if (flows.length != 1) {
					return null;
				}
				Instruction target = listing.getInstructionAt(flows[0]);
				if (walked == 0 && target != null &&
					IndirectJumpConstantPointer.isIndirectJumpSite(target)) {
					return null; // a call to a stub: that is the stub form
				}
				viaJump = true;
				cur = target;
			}
			else if (op == 0x20) {
				Address[] flows = cur.getFlows();
				if (flows.length != 1 || !isPointerSafeCallee(listing, flows[0], cell)) {
					return null;
				}
				cur = FlowEdges.nextFallThrough(listing, cur);
			}
			else if (in(op, HARMLESS_OPS) || writeMissesPointer(cur, op, cell)) {
				cur = FlowEdges.nextFallThrough(listing, cur);
			}
			else {
				return null;
			}
		}
		return null;
	}

	/** Whether this analyzer already commented {@code instr} (an earlier quad or round). */
	private static boolean hasOwnComment(Instruction instr) {
		String eol = instr.getProgram().getListing().getComment(CommentType.EOL,
			instr.getMinAddress());
		return eol != null && eol.contains("split dispatch:");
	}

	/** Most instructions {@link #matchQuad} walks between the second store and the jump. */
	static final int FORWARD_LIMIT = 16;

	/** Deepest nesting of calls {@link #isPointerSafeCallee} follows. */
	static final int MAX_CALL_DEPTH = 3;

	/** Most instructions {@link #isPointerSafeCallee} visits before giving up. */
	static final int MAX_CALLEE_INSTRUCTIONS = 256;

	/** Longest leading run of {@code $0000} entries an interleaved table may skip (grm-gipk.34.2). */
	static final int MAX_LEADING_NULLS = 4;

	private static boolean in(int op, int[] set) {
		for (int o : set) {
			if (o == op) {
				return true;
			}
		}
		return false;
	}

	private static final int[] STORE_ZP = { 0x85, 0x86, 0x84, 0xe6, 0xc6, 0x06, 0x46, 0x26, 0x66 };
	private static final int[] STORE_ABS = { 0x8d, 0x8e, 0x8c, 0xee, 0xce, 0x0e, 0x4e, 0x2e, 0x6e };
	private static final int[] STORE_ZP_IDX = { 0x95, 0x94, 0x96, 0xf6, 0xd6, 0x16, 0x56, 0x36,
		0x76 };
	private static final int[] STORE_ABS_IDX = { 0x9d, 0x99, 0xfe, 0xde, 0x1e, 0x5e, 0x3e, 0x7e };

	/** Documented opcodes that write no memory and are not a flow break (loads, ALU, compares,
	 *  register/flag/stack ops, accumulator shifts); branches, JSR, JMP abs and RTS are handled
	 *  by the walk itself. */
	private static final int[] HARMLESS_OPS = { 0x69, 0x65, 0x75, 0x6d, 0x7d, 0x79, 0x61, 0x71,
		0x29, 0x25, 0x35, 0x2d, 0x3d, 0x39, 0x21, 0x31, 0xc9, 0xc5, 0xd5, 0xcd, 0xdd, 0xd9, 0xc1,
		0xd1, 0x49, 0x45, 0x55, 0x4d, 0x5d, 0x59, 0x41, 0x51, 0x09, 0x05, 0x15, 0x0d, 0x1d, 0x19,
		0x01, 0x11, 0xe9, 0xe5, 0xf5, 0xed, 0xfd, 0xf9, 0xe1, 0xf1, 0x24, 0x2c, 0xe0, 0xe4, 0xec,
		0xc0, 0xc4, 0xcc, 0x0a, 0x4a, 0x2a, 0x6a, 0xba, 0x9a, 0xe8, 0xc8, 0xca, 0x88, 0xa9, 0xa5,
		0xb5, 0xad, 0xbd, 0xb9, 0xa1, 0xb1, 0xa2, 0xa6, 0xb6, 0xae, 0xbe, 0xa0, 0xa4, 0xb4, 0xac,
		0xbc, 0xaa, 0xa8, 0x8a, 0x98, 0x68, 0x48, 0x08, 0x28, 0x18, 0x38, 0xd8, 0xf8, 0x58, 0x78,
		0xb8, 0xea };

	private static final int[] BRANCH_OPS = { 0x10, 0x30, 0x50, 0x70, 0x90, 0xb0, 0xd0, 0xf0 };

	/**
	 * Whether calling the routine at {@code entry} cannot change the pointer cells
	 * {@code pointer} and {@code pointer + 1} (grm-gipk.34.1). The callee is walked by flow:
	 * fall-through, both arms of a branch, {@code JMP abs}, and nested {@code JSR abs} up to
	 * {@link #MAX_CALL_DEPTH}; an {@code RTS} ends a path. Unsafe: a store or read-modify-write
	 * whose target could be either cell (an indexed zero-page store could be any zero-page cell, an
	 * absolute-indexed one any of 256 from its base, an indirect one anywhere), {@code JMP (ind)},
	 * {@code RTI}, {@code BRK}, any opcode not known to be harmless, bytes that are not decoded
	 * code, or more than {@link #MAX_CALLEE_INSTRUCTIONS} instructions.
	 */
	static boolean isPointerSafeCallee(Listing listing, Address entry, long pointer) {
		return walkCallee(listing, entry, pointer, 1, new java.util.HashSet<>(), new int[1]);
	}

	private static boolean walkCallee(Listing listing, Address entry, long pointer, int depth,
			Set<Address> visited, int[] budget) {
		java.util.ArrayDeque<Address> work = new java.util.ArrayDeque<>();
		work.add(entry);
		while (!work.isEmpty()) {
			Address at = work.poll();
			if (!visited.add(at)) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(at);
			if (instr == null || ++budget[0] > MAX_CALLEE_INSTRUCTIONS) {
				return false;
			}
			int op = opcode(instr);
			if (op == 0x60) {
				continue; // RTS ends the path
			}
			if (op == 0x4c) {
				Address[] flows = instr.getFlows();
				if (flows.length != 1) {
					return false;
				}
				work.add(flows[0]);
				continue;
			}
			if (op == 0x20) {
				Address[] flows = instr.getFlows();
				if (flows.length != 1 || depth >= MAX_CALL_DEPTH ||
					!walkCallee(listing, flows[0], pointer, depth + 1, visited, budget)) {
					return false;
				}
			}
			else if (in(op, BRANCH_OPS)) {
				for (Address f : instr.getFlows()) {
					work.add(f);
				}
			}
			else if (!in(op, HARMLESS_OPS) && !writeMissesPointer(instr, op, pointer)) {
				return false;
			}
			Address ft = instr.getFallThrough();
			if (ft != null) {
				work.add(ft);
			}
		}
		return true;
	}

	/** Whether {@code instr} is a store/RMW opcode whose target cannot be either pointer cell. */
	private static boolean writeMissesPointer(Instruction instr, int op, long pointer) {
		try {
			if (in(op, STORE_ZP)) {
				long t = instr.getByte(1) & 0xff;
				return t != pointer && t != pointer + 1;
			}
			if (in(op, STORE_ABS)) {
				Long t = operand16(instr);
				return t != null && t != pointer && t != pointer + 1;
			}
			if (in(op, STORE_ZP_IDX)) {
				return pointer > 0xff; // wraps within page zero: any cell there is possible
			}
			if (in(op, STORE_ABS_IDX)) {
				Long base = operand16(instr);
				return base != null && !(base <= pointer + 1 && pointer <= base + 255);
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		return false; // indirect stores, JMP (ind), RTI, BRK, unknown opcodes
	}

	/**
	 * The targets of {@code site}'s table, in order, cut at the first entry any stop rule rejects
	 * (see the class javadoc). Targets are placed in the stub's own space, as a direct
	 * {@code JMP} there would be.
	 */
	static Walk walkTable(Program program, Site site, Set<Address> tableStarts) {
		int[] nulls = new int[1];
		List<Address> targets = walkTargets(program, site, tableStarts, nulls);
		return new Walk(targets, nulls[0]);
	}

	/** A table walk's result: the targets, and how many leading {@code $0000} slots were skipped
	 *  (grm-gipk.34.2), which belong to the table's extent but contribute no target. */
	record Walk(List<Address> targets, int leadingNulls) {}

	private static List<Address> walkTargets(Program program, Site site,
			Set<Address> tableStarts, int[] leadingNulls) {
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
		boolean planar = site.planar();
		if (planar && !home.equals(memory.getBlock(site.hiTable()))) {
			return targets;
		}
		int first = 0;
		int end = MAX_ENTRIES;
		boolean guarded = false;
		if (planar) {
			// grm-gipk.33: a planar table's extent is the distance between its two bases (the
			// tables cannot overlap), unless an index guard in front of the load states it.
			IndexGuardRecovery.LoadGuard guard =
				IndexGuardRecovery.guardedIndexedLoad(program, site.loLoad());
			if (guard != null && guard.range().step() == 1) {
				guarded = true;
				first = guard.range().lo();
				end = guard.range().hi() + 1;
			}
			else {
				long distance = Math.abs(site.hiTable().getOffset() - site.table().getOffset());
				if (distance > MAX_PLANAR_DISTANCE) {
					return targets; // unrelated bases: no count to derive
				}
				end = (int) distance;
			}
		}
		long tableStart = Math.min(site.table().getOffset(), site.hiTable().getOffset());
		// Lowest target in the table's own block above the table, so far (grm-cqwn).
		long minTarget = Long.MAX_VALUE;
		for (int i = first; i < end; i++) {
			Address lo;
			Address hi;
			try {
				if (planar) {
					lo = site.table().addNoWrap(i);
					hi = site.hiTable().addNoWrap(i);
				}
				else {
					lo = site.table().addNoWrap(2L * i);
					hi = lo.addNoWrap(1);
				}
			}
			catch (Exception e) {
				break;
			}
			// Leading invalid entries of an unguarded planar table are skipped, not fatal: the
			// start end of every stop rule below (table trim rules apply to both ends, owner
			// ruling grm-c9d.8). Once an entry is taken, the first invalid one ends the walk.
			boolean skipLeading = planar && !guarded && targets.isEmpty();
			if (i > first && (tableStarts.contains(lo) || tableStarts.contains(hi))) {
				break; // the next table begins here
			}
			if (Math.max(lo.getOffset(), hi.getOffset()) >= minTarget) {
				break; // the table ran into one of its own handlers, disassembled or not
			}
			if (listing.getInstructionContaining(lo) != null ||
				listing.getInstructionContaining(hi) != null) {
				if (skipLeading) {
					continue;
				}
				break; // the table ran into code
			}
			int value;
			try {
				value = (memory.getByte(lo) & 0xff) | (memory.getByte(hi) & 0xff) << 8;
			}
			catch (MemoryAccessException e) {
				break;
			}
			if (value == 0 && !planar && targets.isEmpty() &&
				leadingNulls[0] < MAX_LEADING_NULLS) {
				leadingNulls[0]++; // a null slot ahead of the first handler (grm-gipk.34.2)
				continue;
			}
			Address target = targetSpace.getAddress(value);
			MemoryBlock block = memory.getBlock(target);
			if (block == null || !block.isInitialized() || block.isVolatile()) {
				if (skipLeading) {
					continue;
				}
				break; // RAM, I/O or unmapped: not a handler
			}
			if (!block.equals(home) && isBanked(program, block)) {
				if (skipLeading) {
					continue;
				}
				break; // a handler in another banked window: which bank is not established here
			}
			Instruction at = listing.getInstructionContaining(target);
			if (at != null && !at.getMinAddress().equals(target)) {
				if (skipLeading) {
					continue;
				}
				break; // mid-instruction
			}
			if (planar && !InlineJumpTableDispatch.decodesAsCode(program, target, true)) {
				// The extent is only an estimate, so each entry must also read as a handler
				// (megaman2 92d5's 128th slot is $ff filler).
				if (skipLeading) {
					continue;
				}
				break;
			}
			if (block.equals(home) && value > tableStart) {
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

	/**
	 * Whether {@code call}'s only computed references are {@link JumpTableBoundAnalyzer}'s
	 * reference pins and no function contains it (grm-gipk.28): the jump was bounded by
	 * references alone because no function owned it, so there is no switch for a decompile to
	 * recover and no override to await, and its pinned targets are COMPUTED_JUMP references that
	 * create no function. deadly_towers B1 {@code e738}: once grm-gipk.26's retraction kept the
	 * B1 cases and reached the dispatcher earlier, the bound pinned {@code e767} before this
	 * analyzer saw the site, and {@code e767} (with the {@code e775} switch inside it) was never
	 * made a function. Such a site is still ours to resolve as a call.
	 */
	static boolean isOrphanPin(Instruction call) {
		Program program = call.getProgram();
		if (program.getFunctionManager().getFunctionContaining(call.getMinAddress()) != null ||
			!JumpTableBoundAnalyzer.boundWithoutOverride(program, call.getMinAddress())) {
			return false;
		}
		for (Reference ref : call.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed() &&
				!RefType.COMPUTED_JUMP.equals(ref.getReferenceType())) {
				return false;
			}
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

	private static Instruction fallingInto(Listing listing, Instruction instr) {
		if (instr == null) {
			return null;
		}
		return FlowEdges.fallThroughPredecessor(listing, instr);
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
			Address target, boolean upgradeJumpPins) {
		for (Reference ref : stub.getReferencesFrom()) {
			if (ref.getToAddress().equals(target) && ref.getReferenceType().isComputed()) {
				if (upgradeJumpPins && RefType.COMPUTED_JUMP.equals(ref.getReferenceType())) {
					break; // a reference pin never made a function; retype it to a call below
				}
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
