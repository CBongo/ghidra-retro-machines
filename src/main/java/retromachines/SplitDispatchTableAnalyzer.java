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
 *     grm-2m07 signal (rcproam {@code bb5f} ends exactly where {@code bb89} begins); in family
 *     terms, a pointer member's extent is disjoint from every other site's table base;</li>
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
 * <p><b>The same-index family</b> (grm-gipk.41): a routine that indexes the pointer table
 * with a value often indexes companion tables with the SAME value, raw or doubled, and an
 * assembler lays such a family back to back. {@link #familyExtent} collects, from the
 * fall-through region before the quad, every {@code abs,X}/{@code abs,Y} read whose index
 * carries the quad's value as a member (stride 2 width 2 for an interleaved pointer table; two
 * stride-1 members, the low-byte and high-byte tables, for a planar one), and accepts a live
 * range {@code [lo, hi]} only when (a) no member's extent overlaps another's or a decoded
 * instruction, all lie in the caller's block, and no pointer member runs over another site's
 * table base, (b) at least two independent tiling equations hold (a member's end is another
 * member's start, or is a decoded instruction's start or one of the family's own targets), (c)
 * the ordinary walk accepts every slot in the range (so slots are never invented), and (d)
 * exactly one {@code (lo, hi)} qualifies. That evidence, and only that, permits skipping a
 * non-null bad head (ultimaav {@code 8a3f}: slot 0 is RAM, slots 1..8 are handlers); anything
 * less keeps the walk above, shorten-only. The older rules are instances of it:
 * <ul>
 * <li><b>Planar</b> (grm-gipk.33; the low and high bytes are two tables whose bases are not
 *     adjacent, megaman2 {@code 82d5}: {@code $84dc} / {@code $84e5}). When the family cannot pin
 *     a range, the member>member tiling equation with {@code lo = 0} is the ESTIMATE: the base
 *     distance ({@link #pairEstimate}, at most {@link #MAX_PLANAR_DISTANCE}) is the entry count.
 *     A recovered {@code CMP}/{@code BCC} index guard ({@link IndexGuardRecovery#guardedIndexedLoad})
 *     states {@code lo} and {@code hi} and wins over both. An estimate is trimmed at BOTH ends
 *     (owner ruling grm-c9d.8): a bad entry before the first good one is skipped (the head), the
 *     usual stop rules end the walk at the first bad one after (the tail), and each target must
 *     decode as code ({@link InlineJumpTableDispatch#decodesAsCode}). The head skip applies to
 *     neither the interleaved form nor a stated (guarded or family) range.</li>
 * <li><b>End to end</b> (grm-2m07): another site's table base is a boundary no pointer member
 *     may cover, in the walk and in the family's disjointness alike.</li>
 * <li><b>Bank table</b> (grm-gipk.36): the per-entry bank byte table of a switch helper is a
 *     stride-1 member; a slot's bank is trusted only if the bank table's extent over the
 *     walked slots is in the caller's block, disjoint from the pointer table and holds no
 *     code.</li>
 * </ul>
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
			Instruction loLoad, int gap, boolean viaJump, Address switchEntry,
				Address bankTable, Instruction quadFirst) {

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
				(walk.family() ? " (slots " + walk.familyLo() + ".." + walk.familyHi() +
					", family extent grm-gipk.41.2)" : "") +
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
			quad.loLoad(), 0, false, null, null, quad.first());
	}

	/** A recognized {@code LDA lo,r / STA P / LDA hi,r / STA P+1} quad (either load order):
	 *  the pointer cell {@code P}, and the two table bases. */
	private record Quad(long cell, long lo, long hi, Instruction loLoad, Instruction first) {}

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
			return t1.equals(t2) ? null : new Quad(c1, t1, t2, ld1, ld1);
		}
		if (c2 + 1 == c1) {
			return t1.equals(t2) ? null : new Quad(c2, t2, t1, ld2, ld1);
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
		Address helper = null; // the FIRST JSR walked, with no X write before it (grm-gipk.36)
		boolean xWritten = false;
		boolean sawJsr = false;
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
					quad.loLoad(), walked, viaJump, helper,
					helper == null ? null : bankTableOf(listing, quad), quad.first());
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
				if (!sawJsr && !xWritten) {
					helper = flows[0];
				}
				sawJsr = true;
				cur = FlowEdges.nextFallThrough(listing, cur);
			}
			else if (in(op, HARMLESS_OPS) || writeMissesPointer(cur, op, cell)) {
				if (in(op, WRITES_X)) {
					xWritten = true;
				}
				cur = FlowEdges.nextFallThrough(listing, cur);
			}
			else {
				return null;
			}
		}
		return null;
	}

	/** Opcodes that change X: LDX (four modes), INX, DEX, TAX, TSX. */
	private static final int[] WRITES_X = { 0xa2, 0xa6, 0xb6, 0xae, 0xbe, 0xe8, 0xca, 0xaa, 0xba };

	/**
	 * The byte table a switch helper's bank argument is read from (grm-gipk.36): the quad is
	 * preceded by {@code LDX tbl,Y / TYA / ASL A / TAY}, so X is {@code tbl[i]} for the entry whose
	 * (pre-doubling) index is Y, and a helper called before the {@code JMP (P)} switches to that
	 * bank. Returns {@code tbl}, or null when the quad does not follow that shape.
	 */
	private static Address bankTableOf(Listing listing, Quad quad) {
		Instruction tay = fallingInto(listing, quad.first());
		Instruction asl = fallingInto(listing, tay);
		Instruction tya = fallingInto(listing, asl);
		Instruction ldx = fallingInto(listing, tya);
		if (opcode(tay) != 0xa8 || opcode(asl) != 0x0a || opcode(tya) != 0x98 ||
			opcode(ldx) != 0xbe || opcode(quad.first()) != 0xb9) {
			return null;
		}
		Long tbl = operand16(ldx);
		return tbl == null ? null
				: ldx.getMinAddress().getAddressSpace().getAddress(tbl);
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
		// a recovered index guard states the first and last slot of a planar table (grm-gipk.33)
		int[] stated = null;
		if (site.planar()) {
			IndexGuardRecovery.LoadGuard guard =
				IndexGuardRecovery.guardedIndexedLoad(program, site.loLoad());
			if (guard != null && guard.range().step() == 1) {
				stated = new int[] { guard.range().lo(), guard.range().hi() };
			}
		}
		if (stated != null) {
			return new Walk(walkTargets(program, site, tableStarts, nulls, stated[0], stated[1] + 1),
				nulls[0]);
		}
		int[] family = familyExtent(program, site, tableStarts);
		if (family != null) {
			List<Address> targets =
				walkTargets(program, site, tableStarts, nulls, family[0], family[1] + 1);
			return new Walk(targets, nulls[0], family[0], family[1]);
		}
		List<Address> targets = walkTargets(program, site, tableStarts, nulls, -1, -1);
		return new Walk(targets, nulls[0]);
	}

	/** A table walk's result: the targets, and how many leading {@code $0000} slots were skipped
	 *  (grm-gipk.34.2), which belong to the table's extent but contribute no target. */
	record Walk(List<Address> targets, int leadingNulls, int familyLo, int familyHi) {
		Walk(List<Address> targets, int leadingNulls) {
			this(targets, leadingNulls, -1, -1);
		}
	
		/** Whether the extent is the same-index family's (grm-gipk.41.2), not the stop-rule walk's. */
		boolean family() {
			return familyLo >= 0;
		}
	}
	
	/** {@code forcedFirst}/{@code forcedEnd} (both -1 for none) fix the slot range to one the
	 *  family model or an index guard states; the stop rules still apply inside it. With none, the
	 *  range is an ESTIMATE: planar, the pair equation ({@link #pairEstimate}) trimmed at both ends;
	 *  interleaved, the whole {@link #MAX_ENTRIES} cut by the first stop rule. */
	private static List<Address> walkTargets(Program program, Site site,
			Set<Address> tableStarts, int[] leadingNulls, int forcedFirst, int forcedEnd) {
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
		boolean stated = forcedFirst >= 0;
		if (stated) {
			first = forcedFirst;
			end = forcedEnd;
		}
		else if (planar) {
			end = pairEstimate(site);
			if (end < 0) {
				return targets; // unrelated bases: no count to derive
			}
		}
		List<FamilyMember> ptrs = pointerMembers(site);
		AddressSpace space = site.table().getAddressSpace();
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
			boolean skipLeading = planar && !stated && targets.isEmpty();
			if (i > first && slotHitsBase(ptrs, i, space, tableStarts)) {
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
				// Which bank is not established by the walk itself; a switch helper fed a
				// per-entry bank byte can establish it (grm-gipk.36), else the entry is declined.
				Address placed =
					resolveSwitchedTarget(program, site, planar, first, i, target);
				MemoryBlock placedBlock = placed == null ? null : memory.getBlock(placed);
				if (placedBlock == null || !placedBlock.isInitialized() ||
					placedBlock.isVolatile()) {
					if (skipLeading) {
						continue;
					}
					break; // a handler in another banked window: which bank is not established
				}
				target = placed;
				block = placedBlock;
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

	/** Smallest first slot the family search tries (an index base of 0..{@value}). */
	static final int MAX_FAMILY_LO = 6;

	/** Most fall-through predecessors of the quad the family collection scans. */
	static final int FAMILY_BACK_LIMIT = 24;

	/** An index value as tracked backwards from the quad: {@code tok * scale + off}. */
	private record IdxVal(int tok, int scale, int off) {}

	/** One table read with the quad's index: bytes at {@code base + stride * i}, {@code width}
	 *  consecutive bytes per entry. */
	private static final class FamilyMember {
		long base;
		final int stride;
		int width = 1;
		boolean ptr;

		/** The offset of slot {@code k}'s first byte. */
		long start(int k) {
			return base + (long) stride * k;
		}

		FamilyMember(long base, int stride, boolean ptr) {
			this.base = base;
			this.stride = stride;
			this.ptr = ptr;
		}
	}

	private static final int[] FAMILY_X_READS = { 0xbd, 0xbc, 0x7d, 0xfd, 0xdd, 0x3d, 0x1d, 0x5d };
	private static final int[] FAMILY_Y_READS = { 0xb9, 0xbe, 0x79, 0xf9, 0xd9, 0x39, 0x19, 0x59 };
	/** ALU opcodes (other than the handled {@code ADC #}/{@code SBC #}) that replace A. */
	private static final int[] A_ALU = { 0x29, 0x25, 0x35, 0x2d, 0x3d, 0x39, 0x21, 0x31, 0x09, 0x05,
		0x15, 0x0d, 0x1d, 0x19, 0x01, 0x11, 0x49, 0x45, 0x55, 0x4d, 0x5d, 0x59, 0x41, 0x51, 0x65,
		0x75, 0x6d, 0x7d, 0x79, 0x61, 0x71, 0xe5, 0xf5, 0xed, 0xfd, 0xf9, 0xe1, 0xf1 };
	private static final int[] LOADS_A = { 0xa9, 0xb5, 0xbd, 0xb9, 0xa1, 0xb1 };
	private static final int[] LOADS_X = { 0xa2, 0xb6, 0xbe };
	private static final int[] LOADS_Y = { 0xa0, 0xb4, 0xbc };
	/** Stores and read-modify-writes of one fixed cell (zero page / absolute). */
	private static final int[] CELL_WRITES = { 0x85, 0x8d, 0x86, 0x8e, 0x84, 0x8c, 0x06, 0x0e, 0x46,
		0x4e, 0x26, 0x2e, 0x66, 0x6e, 0xe6, 0xee, 0xc6, 0xce };
	/** Stores and read-modify-writes whose cell is indexed or indirect: any cell may change. */
	private static final int[] ANY_WRITES = { 0x95, 0x9d, 0x99, 0x81, 0x91, 0x96, 0x94, 0x16, 0x1e,
		0x56, 0x5e, 0x36, 0x3e, 0x76, 0x7e, 0xf6, 0xfe, 0xd6, 0xde };
	/** Opcodes that change no register (compares, branches, flag ops, NOP, TXS). */
	private static final int[] NO_REG_CHANGE = { 0xc9, 0xc5, 0xd5, 0xcd, 0xdd, 0xd9, 0xc1, 0xd1,
		0xe0, 0xe4, 0xec, 0xc0, 0xc4, 0xcc, 0x24, 0x2c, 0x10, 0x30, 0x50, 0x70, 0x90, 0xb0, 0xd0,
		0xf0, 0xd8, 0xf8, 0x58, 0x78, 0xb8, 0xea, 0x9a };

	/**
	 * The slot range {@code [lo, hi]} the same-index family pins for {@code site}'s interleaved
	 * table, as {@code {lo, hi}}, or null when the evidence does not suffice (see the class
	 * javadoc, "The same-index family"). Never returns a range the ordinary walk would reject a
	 * slot of.
	 */
	static int[] familyExtent(Program program, Site site, Set<Address> tableStarts) {
		boolean planar = site.planar();
		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		MemoryBlock home = memory.getBlock(site.call().getMinAddress());
		if (home == null || site.quadFirst() == null ||
			!home.equals(memory.getBlock(site.table()))) {
			return null;
		}
		List<FamilyMember> members = collectFamily(listing, site, home);
		if (members == null || members.size() < 2) {
			return null;
		}
		AddressSpace space = site.table().getAddressSpace();
		long homeStart = home.getStart().getOffset();
		long homeEnd = home.getEnd().getOffset();
		// the value each pointer slot holds, -1 where unreadable
		int limit = planar ? MAX_PLANAR_DISTANCE : MAX_ENTRIES;
		int[] slotValue = new int[limit];
		for (int k = 0; k < limit; k++) {
			slotValue[k] = -1;
			try {
				Address lo = site.table().addNoWrap(planar ? k : 2L * k);
				Address hi = planar ? site.hiTable().addNoWrap(k) : lo.addNoWrap(1);
				slotValue[k] = (memory.getByte(lo) & 0xff) | (memory.getByte(hi) & 0xff) << 8;
			}
			catch (Exception e) {
				break;
			}
		}
		int[] found = null;
		for (int lo = 0; lo <= MAX_FAMILY_LO; lo++) {
			for (int hi = lo + 1; hi < limit; hi++) {
				long h = hi + 1;
				// extents only grow with hi, so the first disjointness failure ends this lo
				if (!familyDisjoint(listing, members, space, tableStarts, homeStart, homeEnd, lo, h)) {
					break;
				}
				if (familyEquations(listing, members, space, slotValue, lo, hi) < 2) {
					continue;
				}
				// the ordinary walk must accept every slot of the range
				int[] nulls = new int[1];
				List<Address> targets =
					walkTargets(program, site, tableStarts, nulls, lo, hi + 1);
				if (targets.size() < 2 || targets.size() + nulls[0] != hi - lo + 1) {
					continue;
				}
				if (found != null) {
					return null; // ambiguous: more than one range survives
				}
				found = new int[] { lo, hi };
			}
		}
		return found;
	}

	/** Whether no member's extent for slots {@code lo .. h-1} overlaps another's or an instruction,
	 *  all lie inside {@code home}, and no pointer member runs over another site's table base (tables
	 *  laid end to end, grm-2m07: a base is a boundary, and a tiling point). */
	private static boolean familyDisjoint(Listing listing, List<FamilyMember> members,
			AddressSpace space, Set<Address> tableStarts, long homeStart, long homeEnd, int lo,
			long h) {
		for (int i = 0; i < members.size(); i++) {
			FamilyMember a = members.get(i);
			long s = a.start(lo);
			long e = a.start((int) h); // exclusive
			if (s < homeStart || e - 1 > homeEnd || extentHitsCode(listing, space, s, e)) {
				return false;
			}
			for (int j = i + 1; j < members.size(); j++) {
				if (overlaps(a, members.get(j), lo, h)) {
					return false;
				}
			}
			if (a.ptr) {
				for (int k = lo + 1; k < h; k++) {
					if (slotHitsBase(List.of(a), k, space, tableStarts)) {
						return false;
					}
				}
			}
		}
		return true;
	}

	/** Whether members {@code a} and {@code b} overlap over slots {@code lo .. h-1}. */
	private static boolean overlaps(FamilyMember a, FamilyMember b, int lo, long h) {
		return a.start(lo) < b.start((int) h) && b.start(lo) < a.start((int) h);
	}

	/** Whether an instruction lies in {@code [s, e)}. */
	private static boolean extentHitsCode(Listing listing, AddressSpace space, long s, long e) {
		Address sa = space.getAddress(s);
		if (listing.getInstructionContaining(sa) != null) {
			return true;
		}
		Instruction after = listing.getInstructionAfter(sa);
		return after != null && after.getMinAddress().getOffset() < e;
	}

	/** Whether slot {@code k} of any member in {@code ptrs} covers a table base in {@code starts}. */
	private static boolean slotHitsBase(List<FamilyMember> ptrs, int k, AddressSpace space,
			Set<Address> starts) {
		for (FamilyMember m : ptrs) {
			for (int b = 0; b < m.width; b++) {
				long o = m.start(k) + b;
				if (o >= 0 && o <= 0xffff && starts.contains(space.getAddress(o))) {
					return true;
				}
			}
		}
		return false;
	}

	/** The site's pointer table(s) as members: one stride-2 width-2 table, or, for a planar site,
	 *  its low-byte and high-byte tables (two stride-1 members). */
	private static List<FamilyMember> pointerMembers(Site site) {
		if (site.planar()) {
			return List.of(new FamilyMember(site.table().getOffset(), 1, true),
				new FamilyMember(site.hiTable().getOffset(), 1, true));
		}
		FamilyMember m = new FamilyMember(site.table().getOffset(), 2, true);
		m.width = 2;
		return List.of(m);
	}

	/**
	 * A planar table's extent when the family cannot pin one: the member>member tiling equation
	 * with the first slot 0 (the two tables cannot overlap, so the base distance is the count), or
	 * -1 when the bases are further apart than {@link #MAX_PLANAR_DISTANCE} (grm-gipk.33). Only an
	 * estimate; the walk trims it at both ends.
	 */
	private static int pairEstimate(Site site) {
		long distance = Math.abs(site.hiTable().getOffset() - site.table().getOffset());
		return distance > MAX_PLANAR_DISTANCE ? -1 : (int) distance;
	}

	/** The number of independent tiling equations the range {@code lo..hi} satisfies: a member's
	 *  end equals another member's start, or equals a decoded instruction's start or one of the
	 *  range's own pointer targets (counted once per member, the two coincide on that address). */
	private static int familyEquations(Listing listing, List<FamilyMember> members,
			AddressSpace space, int[] slotValue, int lo, int hi) {
		long h = hi + 1;
		Set<Integer> own = new java.util.HashSet<>();
		for (int k = lo; k <= hi; k++) {
			if (slotValue[k] > 0) {
				own.add(slotValue[k]);
			}
		}
		int eqs = 0;
		for (int a = 0; a < members.size(); a++) {
			FamilyMember ma = members.get(a);
			long ea = ma.base + (long) ma.stride * h;
			for (int b = 0; b < members.size(); b++) {
				FamilyMember mb = members.get(b);
				if (a != b && ea == mb.base + (long) mb.stride * lo) {
					eqs++;
				}
			}
			if (ea >= 0 && ea <= 0xffff &&
				(own.contains((int) ea) || listing.getInstructionAt(space.getAddress(ea)) != null)) {
				eqs++;
			}
		}
		return eqs;
	}

	/**
	 * The family of {@code site}'s interleaved quad: its pointer table plus every non-store
	 * {@code abs,X}/{@code abs,Y} read in the {@link #FAMILY_BACK_LIMIT} fall-through predecessors
	 * whose index carries the quad's value, raw or doubled, with the base moved by any {@code INX}-
	 * style adjustment. Registers are tracked through transfers, {@code ASL A}, {@code PHA/PLA},
	 * constant {@code ADC}/{@code SBC} and cell loads; anything unknown makes a register fresh, so
	 * it never matches. Reads in another block than the caller's are not members. Returns null
	 * unless the quad's own index is an unadjusted value, doubled for an interleaved table (stride 2) or raw for a planar one (two stride-1 members).
	 */
	private static List<FamilyMember> collectFamily(Listing listing, Site site, MemoryBlock home) {
		Instruction first = site.quadFirst();
		int quadOp = opcode(first);
		if (quadOp != 0xbd && quadOp != 0xb9) {
			return null;
		}
		List<Instruction> window = new ArrayList<>();
		Instruction cur = first;
		for (int n = 0; n < FAMILY_BACK_LIMIT; n++) {
			Instruction p = fallingInto(listing, cur);
			if (p == null) {
				break;
			}
			window.add(0, p);
			cur = p;
		}
		int[] counter = { 1 };
		IdxVal a = new IdxVal(counter[0]++, 1, 0);
		IdxVal x = new IdxVal(counter[0]++, 1, 0);
		IdxVal y = new IdxVal(counter[0]++, 1, 0);
		java.util.ArrayDeque<IdxVal> stack = new java.util.ArrayDeque<>();
		java.util.Map<Long, IdxVal> cells = new java.util.HashMap<>();
		int carry = -1;
		List<long[]> reads = new ArrayList<>(); // {operand, token, scale, offset}
		for (Instruction instr : window) {
			int op = opcode(instr);
			Long operand = operand16(instr);
			boolean xRead = in(op, FAMILY_X_READS);
			if (operand != null && (xRead || in(op, FAMILY_Y_READS))) {
				IdxVal v = xRead ? x : y;
				reads.add(new long[] { operand, v.tok(), v.scale(), v.off() });
			}
			int newCarry = -1;
			try {
				if (op == 0xaa) {
					x = a;
				}
				else if (op == 0xa8) {
					y = a;
				}
				else if (op == 0x8a) {
					a = x;
				}
				else if (op == 0x98) {
					a = y;
				}
				else if (op == 0xba) {
					x = new IdxVal(counter[0]++, 1, 0);
				}
				else if (op == 0x0a) {
					a = new IdxVal(a.tok(), a.scale() * 2, a.off() * 2);
				}
				else if (op == 0x4a || op == 0x2a || op == 0x6a || in(op, A_ALU)) {
					a = new IdxVal(counter[0]++, 1, 0);
				}
				else if (op == 0xe8 || op == 0xca) {
					x = new IdxVal(x.tok(), x.scale(), x.off() + (op == 0xe8 ? 1 : -1));
				}
				else if (op == 0xc8 || op == 0x88) {
					y = new IdxVal(y.tok(), y.scale(), y.off() + (op == 0xc8 ? 1 : -1));
				}
				else if (op == 0x18 || op == 0x38) {
					newCarry = op == 0x18 ? 0 : 1;
				}
				else if (op == 0x69 || op == 0xe9) {
					int imm = instr.getByte(1) & 0xff;
					if ((op == 0x69 && carry == 0) || (op == 0xe9 && carry == 1)) {
						a = new IdxVal(a.tok(), a.scale(), a.off() + (op == 0x69 ? imm : -imm));
					}
					else {
						a = new IdxVal(counter[0]++, 1, 0);
					}
				}
				else if (op == 0xa5 || op == 0xad || op == 0xa6 || op == 0xae || op == 0xa4 ||
					op == 0xac) {
					long cell = op == 0xa5 || op == 0xa6 || op == 0xa4 ? instr.getByte(1) & 0xff
							: operand16(instr);
					IdxVal v = cells.computeIfAbsent(cell, k -> new IdxVal(counter[0]++, 1, 0));
					if (op == 0xa5 || op == 0xad) {
						a = v;
					}
					else if (op == 0xa6 || op == 0xae) {
						x = v;
					}
					else {
						y = v;
					}
				}
				else if (in(op, LOADS_A)) {
					a = new IdxVal(counter[0]++, 1, 0);
				}
				else if (in(op, LOADS_X)) {
					x = new IdxVal(counter[0]++, 1, 0);
				}
				else if (in(op, LOADS_Y)) {
					y = new IdxVal(counter[0]++, 1, 0);
				}
				else if (op == 0x48) {
					stack.push(a);
				}
				else if (op == 0x68) {
					a = stack.isEmpty() ? new IdxVal(counter[0]++, 1, 0) : stack.pop();
				}
				else if (op == 0x08) {
					stack.push(new IdxVal(counter[0]++, 1, 0));
				}
				else if (op == 0x28) {
					if (!stack.isEmpty()) {
						stack.pop();
					}
				}
				else if (op == 0x20) {
					a = new IdxVal(counter[0]++, 1, 0);
					x = new IdxVal(counter[0]++, 1, 0);
					y = new IdxVal(counter[0]++, 1, 0);
					cells.clear();
				}
				else if (in(op, CELL_WRITES)) {
					Long cell = in(op, STORE_ZP) ? (Long) (long) (instr.getByte(1) & 0xff)
							: operand16(instr);
					if (cell == null) {
						cells.clear();
					}
					else {
						cells.remove(cell);
					}
				}
				else if (in(op, ANY_WRITES)) {
					cells.clear();
				}
				else if (!in(op, NO_REG_CHANGE)) {
					a = new IdxVal(counter[0]++, 1, 0);
					x = new IdxVal(counter[0]++, 1, 0);
					y = new IdxVal(counter[0]++, 1, 0);
					cells.clear();
					stack.clear();
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			carry = newCarry;
		}
		IdxVal idx = quadOp == 0xbd ? x : y;
		if (idx.scale() != (site.planar() ? 1 : 2) || idx.off() != 0) {
			return null;
		}
		AddressSpace space = first.getMinAddress().getAddressSpace();
		List<FamilyMember> ptrs = pointerMembers(site);
		List<FamilyMember> raw = new ArrayList<>(ptrs);
		for (long[] r : reads) {
			if (r[1] != idx.tok() || (r[2] != 1 && r[2] != 2)) {
				continue;
			}
			long base = r[0] + r[3];
			if (base < 0 || base > 0xffff ||
				!home.equals(first.getProgram().getMemory().getBlock(space.getAddress(base)))) {
				continue; // not a table of the caller's block
			}
			raw.add(new FamilyMember(base, (int) r[2], false));
		}
		raw.sort((p, q) -> p.stride != q.stride ? Integer.compare(p.stride, q.stride)
				: Long.compare(p.base, q.base));
		List<FamilyMember> members = new ArrayList<>();
		for (FamilyMember m : raw) {
			FamilyMember last = members.isEmpty() ? null : members.get(members.size() - 1);
			if (last != null && last.stride == m.stride && m.base - last.base < m.stride) {
				last.width = (int) Math.max(last.width, m.base - last.base + m.width);
				last.ptr |= m.ptr;
				continue;
			}
			members.add(m);
		}
		for (FamilyMember m : members) {
			if (m.ptr && ptrs.stream().noneMatch(p -> p.base == m.base)) {
				return null; // a field read below the table base: the extent is not modelled
			}
		}
		return members;
	}

	/**
	 * The overlay address {@code target} reaches for entry {@code i}, when the site calls a switch
	 * helper fed by a per-entry bank byte ({@link #bankTableOf}), or null (grm-gipk.36). The bank
	 * table is a stride-1 family member read at {@code bankTable + slot}; its extent over the walked
	 * slots {@code first .. i} must lie in the caller's block, be disjoint from the pointer table
	 * (so it is not one of their bytes) and hold no code. {@link BankContext}
	 * evaluates what the helper switches in for that byte ({@link BankContext#switchedByEntry}) and
	 * where {@code target} then lands. The result is only ever a REFERENCE target, never a flow
	 * override (the decompiler cannot follow a branch into another address space).
	 */
	private static Address resolveSwitchedTarget(Program program, Site site, boolean planar,
			int first, int i, Address target) {
		BankContext ctx = BankContext.forProgram(program);
		if (ctx == null) {
			return null;
		}
		if (planar || site.switchEntry() == null || site.bankTable() == null) {
			// No per-entry bank: only a bank the local walk PROVES live at the dispatch applies
			// to every entry alike.
			return ctx.resolveUnder(ctx.stateBefore(site.call()), target);
		}
		Memory memory = program.getMemory();
		MemoryBlock home = memory.getBlock(site.call().getMinAddress());
		FamilyMember bank = new FamilyMember(site.bankTable().getOffset(), 1, false);
		long s = bank.start(first);
		long e = bank.start(i + 1);
		if (home == null || s < 0 || e - 1 > 0xffff || overlaps(bank, pointerMembers(site).get(0), first, i + 1L)) {
			return null;
		}
		AddressSpace space = site.table().getAddressSpace();
		try {
			Address bankAddr = site.bankTable().addNoWrap(i);
			if (!home.equals(memory.getBlock(space.getAddress(s))) ||
				!home.equals(memory.getBlock(bankAddr)) ||
				extentHitsCode(program.getListing(), space, s, e)) {
				return null;
			}
			int bank0 = memory.getByte(bankAddr) & 0xff;
			BankContext.EntrySwitch sw = ctx.switchedByEntry(site.switchEntry(),
				PartialByte.unknown(), PartialByte.fullyKnown(bank0), PartialByte.unknown());
			return sw == null ? null : ctx.resolveUnder(sw.state(), target);
		}
		catch (MemoryAccessException | ghidra.program.model.address.AddressOverflowException e2) {
			return null;
		}
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
