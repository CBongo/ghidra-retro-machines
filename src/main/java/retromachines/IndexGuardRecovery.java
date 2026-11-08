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
import java.util.Locale;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

/**
 * grm-c9d.8.2: recovers the index range of a register-indexed jump from a {@code CMP reg,#imm} /
 * {@code BCC|BCS} guard, and reads the table slots that range reaches. The Ghidra-facing half of
 * {@link IndexGuard}; a match is by mnemonic ({@code CMP/CPX/CPY}, {@code BCC/BCS}, {@code ASL/LSR},
 * the register moves), which is the same spelling on 6502, 65C02 and SPC700, so there is one
 * adapter and no per-CPU one. Super Mario World's SPC700 driver, whose decompiler table is wrong at
 * BOTH ends:
 * <pre>
 *   0c9b CALL $125E / CMP A,#$DA / BCC $0CA8 / 0ca3 CALL $0D40       ; only caller: A in da..ff
 *   0d40 ASL A / MOV X,A / MOV A,#0 / 0d44 JMP [!$0EDC+X]            ; X = 2A mod 256 = b4..fe
 * </pre>
 * Slots 90..127 of the table at $0EDC (so $0F90..$0FDA), where the decompiler read slots 0..92.
 *
 * <p><b>What must hold</b> for a range to be claimed (each failure declines, never guesses):
 * <ul>
 * <li>the switch instruction itself names the index register and the table base (the
 * {@code JMP [!base+X]} shape), the base being the decompiler's single moving load table;
 * <li>walking back from it, every instruction is entered only by falling through from the one
 * before, until either a guard or the routine's entry; each one either leaves the index register
 * alone (checked on its p-code, not by mnemonic), or is a modelled move: a register copy,
 * {@code ASL A}, {@code LSR A};
 * <li>a guard is {@code CMP reg,#imm} immediately followed by {@code BCC}/{@code BCS}, with the
 * path being analysed reaching the next instruction only by that branch NOT being taken (the
 * branch is entered from nowhere else), and {@code reg} being the register tracked at that point;
 * <li>at the routine's entry, EVERY reference to it is a call or unconditional jump from an
 * instruction that is itself guarded this way (no data reference, no computed or conditional
 * flow, no external entry point). The ranges are joined with {@link IndexGuard#hull}. A caller
 * discovered only later does not undo the claim (owner ruling, grm-c9d.8).
 * </ul>
 * Then the result must be a run of whole table entries ({@link IndexGuard#slotSpan}).
 */
final class IndexGuardRecovery {

	private IndexGuardRecovery() {}

	/** Straight-line instructions walked back before giving up; the chains are a handful long. */
	private static final int MAX_RUN = 32;

	/** {@code TAX}-style moves: mnemonic to {destination, source}. */
	private static final Map<String, String[]> TRANSFERS = Map.of("TAX", new String[] { "X", "A" },
		"TAY", new String[] { "Y", "A" }, "TXA", new String[] { "A", "X" }, "TYA",
		new String[] { "A", "Y" });

	/** The slots (relative to the table base, in entries) the guard says the dispatch reaches. */
	record Span(int first, int last, String evidence) {}

	/**
	 * The slot span the guards in front of {@code sw} allow, or null when none can be recovered.
	 * {@code tableBase} is the decompiler's moving load table start and {@code entryBytes} the
	 * width of one entry (2 for a word table).
	 */
	static Span recover(Program program, Instruction sw, Address tableBase, int entryBytes) {
		Register index = null;
		boolean baseMatches = false;
		for (int i = 0; i < sw.getNumOperands(); i++) {
			for (Object o : sw.getOpObjects(i)) {
				if (o instanceof Register r) {
					if (index != null) {
						return null; // two registers: not the simple [base+reg] shape
					}
					index = r;
				}
				else if (o instanceof Scalar s && s.getUnsignedValue() == tableBase.getOffset()) {
					baseMatches = true;
				}
			}
		}
		if (index == null || !baseMatches) {
			return null;
		}
		List<String> notes = new ArrayList<>();
		IndexGuard.Range r = walk(program, sw, index, new ArrayList<>(), true, notes);
		int[] span = IndexGuard.slotSpan(r, entryBytes);
		if (span == null) {
			return null;
		}
		return new Span(span[0], span[1], String.join("; ", notes) + " -> " + index.getName() +
			" " + r + " -> slots " + span[0] + ".." + span[1]);
	}

	/**
	 * grm-c9d.8.5: where another guarded reader of nearby bytes starts reading. {@code start} is
	 * {@code base + lo} for an instruction with one {@code base+reg} operand whose register range
	 * the same guards as {@link #recover} establish; {@code evidence} says how.
	 */
	record ReaderStart(Address reader, long start, String evidence) {}

	/**
	 * The lowest byte {@code instr} can read through its indexed operand ({@code !base+X/Y}: the
	 * instruction names exactly one scalar and exactly one {@code X}/{@code Y} register, which
	 * SPC700 puts in separate operands, {@code ADC A,!$0EE8+Y} being {@code [A] [0xee8] [Y]}),
	 * when a guard bounds the index
	 * ({@link #walk}, as for {@link #recover}); else null. SMW's {@code 10cb ADC A,!$0EE8+Y}, guarded
	 * by {@code 10c3 CMP A,#$DA / BCC} through {@code MOV Y,A}, starts at {@code $0FC2}: the vcmd
	 * operand-length table that follows the {@code $0D44} dispatch table.
	 */
	static ReaderStart readerStart(Program program, Instruction instr) {
		LoadGuard g = guardedIndexedLoad(program, instr);
		if (g == null) {
			return null;
		}
		long start = g.base() + g.range().lo();
		return new ReaderStart(instr.getMinAddress(), start, instr.getMinAddress() + " " + instr +
			": " + g.notes() + " -> " + g.index().getName() + " " + g.range() + " -> from " +
			Long.toHexString(start));
	}

	/** An indexed operand's {@code base}, its index register and the range the guards give it. */
	record LoadGuard(long base, Register index, IndexGuard.Range range, String notes) {}

	/**
	 * grm-gipk.18: the guarded range of the index register of {@code instr}, an instruction with
	 * one {@code !base+X/Y} operand (see {@link #readerStart} for the operand shape), or null when
	 * no guard bounds it.
	 */
	static LoadGuard guardedIndexedLoad(Program program, Instruction instr) {
		Register index = null;
		Long base = null;
		int indexes = 0;
		int scalars = 0;
		for (int i = 0; i < instr.getNumOperands(); i++) {
			for (Object o : instr.getOpObjects(i)) {
				if (o instanceof Register reg &&
					(reg.getName().equals("X") || reg.getName().equals("Y"))) {
					index = reg;
					indexes++;
				}
				else if (o instanceof Scalar sc) {
					base = sc.getUnsignedValue();
					scalars++;
				}
			}
		}
		if (indexes != 1 || scalars != 1) {
			return null; // e.g. MOV X,!abs+Y: which register indexes is not the simple shape
		}
		List<String> notes = new ArrayList<>();
		IndexGuard.Range r = walk(program, instr, index, new ArrayList<>(), true, notes);
		return r == null ? null : new LoadGuard(base, index, r, String.join("; ", notes));
	}

	/**
	 * The guarded readers ({@link #readerStart}) whose first byte lies at an entry position of the
	 * word table at {@code base}, between slot {@code first + 1} and {@code last}: offset of that
	 * position to the reader. Candidates are instructions in the table's address space with an
	 * indexed base in {@code [base - 255, base + 2*(last+1))} (an 8-bit index reaches at most 255
	 * past its base), outside the table's possible extent (bytes there are table read as code) and
	 * not {@code own}.
	 */
	static Map<Long, ReaderStart> readerStarts(Program program, Address base, int first, int last,
			Address own) {
		Map<Long, ReaderStart> out = new java.util.HashMap<>();
		long lo = base.getOffset() - 255;
		long extentEnd = base.getOffset() + 2L * (last + 1);
		var space = base.getAddressSpace();
		var set = new ghidra.program.model.address.AddressSet(space.getMinAddress(),
			space.getMaxAddress());
		for (Instruction in : program.getListing().getInstructions(set, true)) {
			long at = in.getMinAddress().getOffset();
			if (in.getMinAddress().equals(own) || (at >= base.getOffset() && at < extentEnd) ||
				!hasScalarIn(in, lo, extentEnd)) {
				continue;
			}
			ReaderStart rs = readerStart(program, in);
			if (rs == null) {
				continue;
			}
			long d = rs.start() - base.getOffset();
			if (d % 2 == 0 && d / 2 > first && d / 2 <= last) {
				out.merge(rs.start(), rs, (a, b) -> a.reader().compareTo(b.reader()) <= 0 ? a : b);
			}
		}
		return out;
	}

	private static boolean hasScalarIn(Instruction in, long lo, long hi) {
		for (int i = 0; i < in.getNumOperands(); i++) {
			for (Object o : in.getOpObjects(i)) {
				if (o instanceof Scalar s && s.getUnsignedValue() >= lo && s.getUnsignedValue() < hi) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * The range of the register that ends up as the switch index, given that the instruction
	 * {@code from} is reached with {@code reg} holding the value we track. {@code opsBackward}
	 * collects the modelled maps met so far, last first. Null on any failure.
	 */
	private static IndexGuard.Range walk(Program program, Instruction from, Register reg0,
			List<IndexGuard.Op> opsBackward, boolean allowEntry, List<String> notes) {
		Listing listing = program.getListing();
		Register reg = reg0;
		Instruction cur = from;
		for (int step = 0; step < MAX_RUN; step++) {
			List<Reference> incoming = new ArrayList<>();
			for (Reference ref : program.getReferenceManager()
					.getReferencesTo(cur.getMinAddress())) {
				if (!ref.getReferenceType().isFallthrough()) {
					incoming.add(ref);
				}
			}
			if (!incoming.isEmpty()) {
				if (cur.getFallFrom() != null || !allowEntry ||
					program.getSymbolTable().isExternalEntryPoint(cur.getMinAddress())) {
					return null; // also entered from elsewhere, or a second routine boundary
				}
				return fromCallers(program, incoming, reg, opsBackward, notes);
			}
			Address fallFrom = cur.getFallFrom();
			Instruction prev = fallFrom == null ? null : listing.getInstructionAt(fallFrom);
			if (prev == null) {
				return null;
			}
			if (prev.getFlowType().isConditional() && prev.getFlowType().isJump()) {
				return guardBefore(program, prev, reg, opsBackward, notes);
			}
			if (prev.getFlowType().isCall() || prev.getFlowType().isJump() ||
				prev.getFlowType().isTerminal()) {
				return null; // a call clobbers the register; a jump does not fall through
			}
			reg = effectOf(program, prev, reg, opsBackward);
			if (reg == null) {
				return null;
			}
			cur = prev;
		}
		return null;
	}

	/** The routine entry {@code incoming} lead to: join the guarded range of every caller. */
	private static IndexGuard.Range fromCallers(Program program, List<Reference> incoming,
			Register reg, List<IndexGuard.Op> opsBackward, List<String> notes) {
		IndexGuard.Range joined = null;
		for (Reference ref : incoming) {
			var type = ref.getReferenceType();
			boolean flow = type.isCall() || (type.isJump() && !type.isConditional());
			if (!flow || type.isComputed() || !type.isFlow()) {
				return null; // data reference, computed or conditional flow: not a plain caller
			}
			Instruction caller = program.getListing().getInstructionAt(ref.getFromAddress());
			if (caller == null) {
				return null;
			}
			notes.add("caller " + caller.getMinAddress());
			IndexGuard.Range r =
				walk(program, caller, reg, new ArrayList<>(opsBackward), false, notes);
			if (r == null) {
				return null;
			}
			joined = joined == null ? r : IndexGuard.hull(joined, r);
		}
		return joined;
	}

	/**
	 * {@code branch} is the BCC/BCS the tracked path fell out of; the instruction before it must
	 * be the CMP of the tracked register. Returns the register range after the maps in
	 * {@code opsBackward}, or null.
	 */
	private static IndexGuard.Range guardBefore(Program program, Instruction branch, Register reg,
			List<IndexGuard.Op> opsBackward, List<String> notes) {
		// grm-gipk.18: the CMP may be followed by a short chain of BEQ/BNE/BCC/BCS, each entered
		// only by falling through from the one before; the tracked path fell out of all of them.
		List<IndexGuard.Branch> chain = new ArrayList<>();
		Instruction cur = branch;
		Instruction cmp = null;
		while (cmp == null) {
			IndexGuard.Branch kind = branchKind(cur);
			if (kind == null || chain.size() >= IndexGuard.MAX_CHAIN || cur.getFallFrom() == null) {
				return null;
			}
			for (Reference ref : program.getReferenceManager()
					.getReferencesTo(cur.getMinAddress())) {
				if (!ref.getReferenceType().isFallthrough()) {
					return null; // the branch can be entered without running the CMP first
				}
			}
			chain.add(kind);
			Instruction before = program.getListing().getInstructionAt(cur.getFallFrom());
			if (before == null) {
				return null;
			}
			if (before.getFlowType().isConditional() && before.getFlowType().isJump()) {
				cur = before;
			}
			else {
				cmp = before;
			}
		}
		Register cmpReg = compareRegister(program, cmp);
		Integer imm = compareImmediate(cmp);
		if (cmpReg == null || imm == null || !sameRegister(cmpReg, reg)) {
			return null;
		}
		IndexGuard.Range g = IndexGuard.fallThrough(chain, imm);
		List<IndexGuard.Op> ops = new ArrayList<>(opsBackward);
		java.util.Collections.reverse(ops); // program order
		IndexGuard.Range out = g == null ? null : IndexGuard.apply(g, ops);
		if (out != null) {
			String mnem = branch.getMnemonicString().toUpperCase(Locale.ROOT);
			notes.add(cmp.getMinAddress() + " " + cmp + ", " + branch.getMinAddress() + " " + mnem +
				" not taken" + (chain.size() > 1 ? " (chain of " + chain.size() + ")" : "") + ": " +
				cmpReg.getName() + " " + g);
		}
		return out;
	}

	private static IndexGuard.Branch branchKind(Instruction in) {
		try {
			return IndexGuard.Branch.valueOf(in.getMnemonicString().toUpperCase(Locale.ROOT));
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	/**
	 * What straight-line instruction {@code prev} does to the tracked register {@code reg}, which
	 * it is run just before: returns the register to track instead (the same one, or the source of
	 * a copy), appending a modelled map to {@code opsBackward}; null if it writes {@code reg} in a
	 * way that is not modelled.
	 */
	private static Register effectOf(Program program, Instruction prev, Register reg,
			List<IndexGuard.Op> opsBackward) {
		String mnem = prev.getMnemonicString().toUpperCase(Locale.ROOT);
		Register dst = null;
		Register src = null;
		if (mnem.equals("MOV") && prev.getNumOperands() == 2) {
			dst = single(prev, 0);
			src = single(prev, 1);
		}
		else if (TRANSFERS.containsKey(mnem)) {
			String[] t = TRANSFERS.get(mnem);
			dst = program.getRegister(t[0]);
			src = program.getRegister(t[1]);
		}
		if (dst != null && src != null && sameRegister(dst, reg)) {
			return src; // reg was just copied from src: track src instead
		}
		if ((mnem.equals("ASL") || mnem.equals("LSR")) && prev.getNumOperands() <= 1) {
			Register acc = prev.getNumOperands() == 1 ? single(prev, 0) : program.getRegister("A");
			if (acc != null && sameRegister(acc, reg)) {
				opsBackward.add(mnem.equals("ASL") ? IndexGuard.Op.ASL1 : IndexGuard.Op.LSR1);
				return reg;
			}
		}
		return writes(prev, reg) ? null : reg;
	}

	/** Whether any p-code output of {@code instr} overlaps register {@code reg}. */
	private static boolean writes(Instruction instr, Register reg) {
		long lo = reg.getAddress().getOffset();
		long hi = lo + reg.getMinimumByteSize() - 1;
		for (PcodeOp op : instr.getPcode()) {
			Varnode out = op.getOutput();
			if (out == null || !out.isRegister()) {
				continue;
			}
			long o = out.getOffset();
			if (o <= hi && o + out.getSize() - 1 >= lo) {
				return true;
			}
		}
		return false;
	}

	private static boolean sameRegister(Register a, Register b) {
		return a.getBaseRegister().equals(b.getBaseRegister()) && a.getName().equals(b.getName());
	}

	/** The one register object operand {@code i} is, or null. */
	private static Register single(Instruction instr, int i) {
		Object[] objs = instr.getOpObjects(i);
		return objs.length == 1 && objs[0] instanceof Register r ? r : null;
	}

	/** The register a CMP/CPX/CPY compares: its register operand, else implied by the mnemonic. */
	private static Register compareRegister(Program program, Instruction cmp) {
		String mnem = cmp.getMnemonicString().toUpperCase(Locale.ROOT);
		switch (mnem) {
			case "CMP":
				Register explicit = cmp.getNumOperands() == 2 ? single(cmp, 0) : null;
				return explicit != null ? explicit
						: cmp.getNumOperands() == 1 ? program.getRegister("A") : null;
			case "CPX":
				return program.getRegister("X");
			case "CPY":
				return program.getRegister("Y");
			default:
				return null;
		}
	}

	/** The immediate of a CMP/CPX/CPY ({@code #n} operand), else null. */
	private static Integer compareImmediate(Instruction cmp) {
		int last = cmp.getNumOperands() - 1;
		if (last < 0) {
			return null;
		}
		// The "#" is part of the mnemonic line, not of the operand text, on SPC700; the listing text
		// is the one spelling that carries it on every language.
		Object[] objs = cmp.getOpObjects(last);
		if (!cmp.toString().contains("#") || objs.length != 1 || !(objs[0] instanceof Scalar s)) {
			return null;
		}
		return (int) (s.getUnsignedValue() & 0xff);
	}

	// ------------------------------------------------------------------------------------------
	// The slots a span names, with the hard per-entry checks (owner ruling, grm-c9d.8.2)
	// ------------------------------------------------------------------------------------------

	/**
	 * The table a guard span reads. {@code targets} holds one entry per slot from {@code first};
	 * a null entry is an UNUSED slot (a {@code $0000} placeholder). {@code clippedAt} is the slot
	 * index the span was cut at because its target failed a hard check, else -1; {@code why} says
	 * which.
	 */
	record GuardTable(int first, List<Address> targets, int clippedAt, String why) {}

	/**
	 * Reads slots {@code span.first() .. span.last()} of the word table at {@code base} and keeps
	 * them up to the first one that fails a hard check: its target must lie in an initialized,
	 * non-volatile memory block, unless the word is {@code $0000}, a placeholder. Trailing
	 * placeholders are not part of the table. Returns null when nothing remains.
	 *
	 * <p>grm-c9d.8.5: the read also ends at the first slot after {@code span.first()} that
	 * something else references ({@link EntryReferences}, strong hits only): another table's load
	 * or code reached from elsewhere starts there, the structural end of this one. The guard states
	 * which indices the CODE can reach, not where the table's bytes stop, so a guard over-wide for
	 * the table (SMW 0d44: slots 90..127 guarded, 25 real, then the vcmd length table at
	 * {@code $0FC2}, read from {@code $10CB}) is cut there. A bare label (weak hit) does not end
	 * the read: there is no scorer here to weigh it. The same holds for another GUARDED READER
	 * whose lowest byte is such a position ({@link #readerStarts}): SMW's real reader of
	 * {@code $0FC2} is {@code 10cb ADC A,!$0EE8+Y} with Y guarded to {@code $DA..$FF}, a biased base
	 * that makes no reference to {@code $0FC2} at all. References sourced in the table's possible
	 * extent (slot 0 of {@code base} through the span's end, covering our own laid words over any
	 * earlier over-read) or at {@code own} do not count.
	 *
	 * @param template an address in the space the targets live in
	 * @param own the dispatch instruction, whose operand reference points into the table
	 */
	static GuardTable readSlots(Program program, Address base, Span span, Address template,
			Address own) {
		List<Address> targets = new ArrayList<>();
		int clippedAt = -1;
		String why = null;
		List<EntryReferences.Extent> extents =
			List.of(new EntryReferences.Extent(base, 2L * (span.last() + 1)));
		List<Address> owns = own == null ? List.of() : List.of(own);
		Map<Long, ReaderStart> readers = readerStarts(program, base, span.first(), span.last(), own);
		for (int k = span.first(); k <= span.last(); k++) {
			long word;
			try {
				Address at = base.add(2L * k);
				if (k > span.first()) {
					EntryReferences.Hit hit = EntryReferences.find(program, at, extents, owns);
					if (hit != null && hit.strong()) {
						clippedAt = k;
						why = "slot " + k + " entry referenced " + hit.describe();
						break;
					}
					ReaderStart reader = readers.get(at.getOffset());
					if (reader != null) {
						clippedAt = k;
						why = "slot " + k + " is where a guarded reader starts (" +
							reader.evidence() + ")";
						break;
					}
				}
				word = (program.getMemory().getByte(at) & 0xffL) |
					(program.getMemory().getByte(at.add(1)) & 0xffL) << 8;
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
				clippedAt = k;
				why = "slot bytes unreadable";
				break;
			}
			if (word == 0) {
				targets.add(null); // unused placeholder
				continue;
			}
			Address target = template.getNewAddress(word);
			MemoryBlock block = program.getMemory().getBlock(target);
			if (block == null || !block.isInitialized() || block.isVolatile()) {
				clippedAt = k;
				why = "slot " + k + " target " + target + " is not in code memory";
				break;
			}
			targets.add(target);
		}
		while (!targets.isEmpty() && targets.get(targets.size() - 1) == null) {
			targets.remove(targets.size() - 1);
		}
		return targets.isEmpty() ? null : new GuardTable(span.first(), targets, clippedAt, why);
	}
}
