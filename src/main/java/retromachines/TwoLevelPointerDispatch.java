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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pure(ish) logic for grm-gipk.23: the two-level zero-page pointer dispatch, a "table of
 * pointers to handler tables" that NES games use for object/entity state machines. cv3 bank 20:
 *
 * <pre>
 *   8505  LDA $07c2,X / ASL / TAY / LDA $8527,Y / STA $00 / LDA $8528,Y / STA $01  ; outer
 *   8514  LDA $07c8,X / AND #$0f / ASL / TAY
 *         LDA ($00),Y / STA $02 / INY / LDA ($00),Y / STA $03                      ; inner
 *   8524  JMP ($0002)
 * </pre>
 *
 * The OUTER table {@code T} ($8527) holds one word per entity type, each the address of that
 * type's INNER word table ($8bab = 8bb1 8bf8 8c57), whose words are the handlers the
 * {@code JMP} reaches. Neither level is visible to Ghidra's own switch recovery.
 *
 * <p><b>Recognition</b> ({@link #match}): on the straight-line run ending at the {@code JMP
 * (zp2)} (backed up through fall-through, stopping at a call, whose callee could rewrite the
 * cells), the last writes of {@code zp2}/{@code zp2+1} must be {@code STA} of {@code LDA
 * (zp1),Y}, low byte first, with exactly one {@code INY} between the low store and the high
 * load; {@code Y} must come from {@code ASL A / TAY} (optionally {@code AND #imm} first, which
 * caps the inner table at {@code imm+1} entries); and the last writes of {@code zp1}/{@code
 * zp1+1} before the low load must be {@code STA} of {@code LDA T,R} / {@code LDA T+1,R} on one
 * index register {@code R} that does not change between them. Declined: {@code T} inside the
 * dispatch's own instructions (TMNT2/conflict-style hits, which read as one-level inline tables
 * through a zero-page copy), {@code T} in another banked window than the {@code JMP}, or {@code
 * T} not in ROM.
 *
 * <p><b>Bounds</b> ({@link #resolve}). The outer table is read like any word table: it ends at
 * the lowest inner-table address above it ({@link Cut#ABOVE_TABLE_TARGET}), at code ({@link
 * Cut#RAN_INTO_CODE}), at a position something else references ({@link Cut#ENTRY_REFERENCED}),
 * at a word that cannot be an inner table ({@link Cut#INVALID_WORD}: unreadable, into the table
 * itself, or {@link Cut#OUT_OF_BANK}, outside the outer table's own memory block -- the survey's
 * false positives were exactly out-of-bank words), or at the outer index cap when one was
 * recovered. Ended by nothing within 128 entries, the site is declined. When an invalid word
 * ended it, the tail is trimmed back while its inner table yields no handler. Each distinct inner
 * table is read the same way, plus: it ends where another inner table (or the outer table)
 * begins ({@link Cut#NEXT_TABLE}), every handler must be a plausible code entry in the same
 * bank ({@link InlineJumpTableDispatch#plausibleTarget}, not {@linkplain
 * InlineJumpTableDispatch#isCrossWindow cross-window}; else {@link Cut#IMPLAUSIBLE}), and the
 * recovered {@code AND #imm} cap ends it as a positive bound. An inner table that nothing ends
 * within 128 entries and that has no cap is dropped; one whose start is already code is
 * skipped.
 *
 * <p><b>Both ends</b> (table-trim-rules-apply-to-both-ends): each table's START is the address
 * the code itself names -- {@code T} from the {@code LDA T,R} operand, each inner start from an
 * outer word -- not a bound inferred from the bytes, so no rule trims a start. An entry the walk
 * cannot accept ends the table there rather than being skipped, which keeps a bad word from
 * hiding the bound.
 *
 * @see <a href="urn:bead:grm-gipk.23">grm-gipk.23</a>
 */
final class TwoLevelPointerDispatch {

	/** How far back from the {@code JMP} the straight-line run is collected. */
	static final int MAX_RUN = 32;

	/** An index doubled by {@code ASL A} reaches at most 128 words. */
	static final int MAX_ENTRIES = 128;

	private TwoLevelPointerDispatch() {
	}

	/** How a table walk ended. */
	enum Cut {
		/** The next entry starts at or past the lowest target above the table start. */
		ABOVE_TABLE_TARGET,
		/** The next entry position is (or is inside) an existing instruction. */
		RAN_INTO_CODE,
		/** The next entry position is referenced from outside the table. */
		ENTRY_REFERENCED,
		/** Inner tables only: another inner table, or the outer table, begins here. */
		NEXT_TABLE,
		/** The word is unreadable, points into the table itself, or lands outside ROM. */
		INVALID_WORD,
		/** Outer table only: the word points outside the outer table's own memory block. */
		OUT_OF_BANK,
		/** Inner tables only: the handler is not a plausible code entry in the same bank. */
		IMPLAUSIBLE,
		/** The recovered index cap ({@code AND #imm}) was reached: a positive bound. */
		INDEX_CAP,
		/** Nothing ended the table within {@link #MAX_ENTRIES} and no cap was recovered. */
		DECLINED
	}

	/**
	 * A recognized dispatch site.
	 *
	 * @param jmp the {@code JMP (zp2)}
	 * @param outer the outer table {@code T}, in the space its bytes live in
	 * @param outerCap the outer index cap in entries, or null when none was recovered
	 * @param innerCap the inner index cap in entries ({@code AND #imm} + 1), or null
	 * @param own the dispatch's own instructions, from the first outer load to the {@code JMP}
	 */
	record Shape(Address jmp, Address outer, Integer outerCap, Integer innerCap, Set<Address> own) {
	}

	/** One walked table: its start, the words kept, and how it ended. */
	record Table(Address start, List<Address> entries, Cut cut) {
	}

	/**
	 * A resolved site: the outer table (its kept words are inner-table starts), and the inner
	 * tables by start, each with its handlers (empty when the inner table was skipped or dropped).
	 * {@link #declined} is null when the site resolved, else why it did not.
	 */
	record Resolution(Table outer, Map<Address, Table> inner, String declined) {
		/** Every distinct handler, in outer then inner order. */
		Set<Address> handlers() {
			Set<Address> out = new LinkedHashSet<>();
			for (Table t : inner.values()) {
				out.addAll(t.entries());
			}
			return out;
		}
	}

	// ---------------------------------------------------------------------
	// Recognition
	// ---------------------------------------------------------------------

	/** The recognized shape ending at {@code jmp}, or null when it is not this dispatch. */
	static Shape match(Program program, Instruction jmp) {
		if (!IndirectJumpConstantPointer.isIndirectJumpSite(jmp)) {
			return null;
		}
		Address cell = IndirectJumpConstantPointer.pointerCell(jmp);
		if (cell == null || cell.getOffset() > 0xfe) {
			return null;
		}
		long zp2 = cell.getOffset();
		List<Instruction> run = run(program.getListing(), jmp);
		int n = run.size() - 1; // index of the JMP

		int hiSt = lastWriter(run, n, zp2 + 1);
		int loSt = lastWriter(run, n, zp2);
		if (hiSt < 1 || loSt < 1 || opcode(run.get(hiSt)) != 0x85 ||
			opcode(run.get(loSt)) != 0x85) {
			return null;
		}
		int hiLd = hiSt - 1;
		int loLd = loSt - 1;
		Long z1 = indirectY(run.get(loLd));
		if (z1 == null || !z1.equals(indirectY(run.get(hiLd))) || z1 > 0xfe || loSt >= hiLd) {
			return null;
		}
		// zp1's pair must survive the low store: the two pointer pairs are disjoint.
		if (zp2 == z1 || zp2 == z1 + 1 || zp2 + 1 == z1) {
			return null;
		}
		// Exactly one INY between the low store and the high load.
		if (hiLd - loSt != 2 || !"INY".equals(run.get(loSt + 1).getMnemonicString())) {
			return null;
		}

		// Y for the inner load: ASL A / TAY, optionally AND #imm first.
		int tay = lastRegisterWriter(run, loLd, "Y");
		if (tay < 1 || !"TAY".equals(run.get(tay).getMnemonicString()) ||
			opcode(run.get(tay - 1)) != 0x0a) {
			return null;
		}
		Integer innerCap = andCap(run, tay - 2);

		// The outer pair: zp1/zp1+1 last written from LDA T,R / LDA T+1,R.
		int z1LoSt = lastWriter(run, loLd, z1);
		int z1HiSt = lastWriter(run, loLd, z1 + 1);
		if (z1LoSt < 1 || z1HiSt < 1 || opcode(run.get(z1LoSt)) != 0x85 ||
			opcode(run.get(z1HiSt)) != 0x85) {
			return null;
		}
		Instruction loTab = run.get(z1LoSt - 1);
		Instruction hiTab = run.get(z1HiSt - 1);
		int op = opcode(loTab);
		if ((op != 0xb9 && op != 0xbd) || opcode(hiTab) != op) {
			return null;
		}
		Long t = absolute(loTab);
		Long t1 = absolute(hiTab);
		if (t == null || t1 == null || t1 != t + 1) {
			return null;
		}
		String reg = op == 0xb9 ? "Y" : "X";
		int first = Math.min(z1LoSt, z1HiSt) - 1;
		int second = Math.max(z1LoSt, z1HiSt) - 1;
		for (int i = first + 1; i < second; i++) {
			if (writesRegister(run.get(i), reg)) {
				return null; // the two halves would come from different slots
			}
		}
		Integer outerCap = null;
		int idx = lastRegisterWriter(run, first, reg);
		String transfer = "Y".equals(reg) ? "TAY" : "TAX";
		if (idx >= 1 && transfer.equals(run.get(idx).getMnemonicString()) &&
			opcode(run.get(idx - 1)) == 0x0a) {
			outerCap = andCap(run, idx - 2);
		}

		Address jmpAddr = jmp.getMinAddress();
		Memory memory = program.getMemory();
		Address outer = InlineJumpTableDispatch.resolveTarget(jmpAddr.getAddressSpace(), memory, t);
		if (outer == null) {
			return null;
		}
		Instruction firstInstr = run.get(first);
		// T inside the dispatch's own code: not this shape (TMNT2, conflict, ...).
		if (outer.getAddressSpace().equals(jmpAddr.getAddressSpace()) &&
			t >= firstInstr.getMinAddress().getOffset() && t <= jmp.getMaxAddress().getOffset()) {
			return null;
		}
		if (InlineJumpTableDispatch.isCrossWindow(program, jmpAddr, outer) || !isRom(program, outer)) {
			return null;
		}
		Set<Address> own = new LinkedHashSet<>();
		for (int i = first; i <= n; i++) {
			own.add(run.get(i).getMinAddress());
		}
		return new Shape(jmpAddr, outer, outerCap, innerCap, own);
	}

	/** The straight-line run ending at {@code jmp}, oldest first, {@code jmp} last. */
	private static List<Instruction> run(Listing listing, Instruction jmp) {
		List<Instruction> rev = new ArrayList<>();
		rev.add(jmp);
		Instruction cur = jmp;
		while (rev.size() < MAX_RUN) {
			Instruction prev;
			try {
				prev = listing.getInstructionContaining(cur.getMinAddress().subtract(1));
			}
			catch (RuntimeException e) {
				break;
			}
			if (prev == null || prev.getFlowType().isCall() ||
				!cur.getMinAddress().equals(prev.getFallThrough())) {
				break;
			}
			rev.add(prev);
			cur = prev;
		}
		List<Instruction> out = new ArrayList<>(rev.size());
		for (int i = rev.size() - 1; i >= 0; i--) {
			out.add(rev.get(i));
		}
		return out;
	}

	/**
	 * The index of the last instruction before {@code before} that may write zero-page byte
	 * {@code offset}, or -1. A direct write ({@link IndirectJumpConstantPointer#isDirectWriteTo})
	 * counts, and so does any zero-page indexed or indirect store, which could reach it; the
	 * caller then requires a plain {@code STA}, so such a store declines the site.
	 */
	private static int lastWriter(List<Instruction> run, int before, long offset) {
		for (int i = before - 1; i >= 0; i--) {
			Instruction in = run.get(i);
			if (IndirectJumpConstantPointer.isDirectWriteTo(in, offset)) {
				return i;
			}
			switch (opcode(in)) {
				case 0x95, 0x94, 0x96, 0x91, 0x81, 0xf6, 0xd6, 0x16, 0x56, 0x36, 0x76:
					return i;
				default:
					break;
			}
		}
		return -1;
	}

	/** The index of the last instruction before {@code before} writing {@code reg}, or -1. */
	private static int lastRegisterWriter(List<Instruction> run, int before, String reg) {
		for (int i = before - 1; i >= 0; i--) {
			if (writesRegister(run.get(i), reg)) {
				return i;
			}
		}
		return -1;
	}

	private static boolean writesRegister(Instruction in, String reg) {
		String mn = in.getMnemonicString();
		if ("Y".equals(reg)) {
			return switch (mn) {
				case "LDY", "INY", "DEY", "TAY", "PLY" -> true;
				default -> false;
			};
		}
		return switch (mn) {
			case "LDX", "INX", "DEX", "TAX", "TSX", "PLX" -> true;
			default -> false;
		};
	}

	/** {@code AND #imm} at {@code i}: {@code imm + 1} entries (at most 128); else null. */
	private static Integer andCap(List<Instruction> run, int i) {
		if (i < 0 || opcode(run.get(i)) != 0x29) {
			return null;
		}
		try {
			int imm = run.get(i).getByte(1) & 0xff;
			return Math.min(imm + 1, MAX_ENTRIES);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	// ---------------------------------------------------------------------
	// Bounds
	// ---------------------------------------------------------------------

	/** Resolves both levels of {@code shape}; see the class javadoc for the rules. */
	static Resolution resolve(Program program, Shape shape) {
		Address t = shape.outer();
		int outerCap = shape.outerCap() == null ? MAX_ENTRIES : shape.outerCap();
		List<EntryReferences.Extent> outerExtent =
			List.of(new EntryReferences.Extent(t, 2L * outerCap));
		Memory memory = program.getMemory();
		MemoryBlock outerBlock = memory.getBlock(t);

		Map<Address, Table> innerCache = new LinkedHashMap<>();
		TableScorer.Result<Address, Cut> walked = TableScorer.walk(outerCap, (i, before) -> {
			Address pos = t.add(2L * i);
			if (pos.getOffset() >= lowestAbove(t, before)) {
				return TableScorer.Entry.rejected(Cut.ABOVE_TABLE_TARGET);
			}
			if (inCode(program, pos)) {
				return TableScorer.Entry.rejected(Cut.RAN_INTO_CODE);
			}
			Long word = readWord(memory, pos);
			if (word == null || (word >= t.getOffset() && word <= pos.getOffset() + 1)) {
				return TableScorer.Entry.rejected(Cut.INVALID_WORD);
			}
			Address inner = InlineJumpTableDispatch.resolveTarget(t.getAddressSpace(), memory, word);
			if (inner == null || !outerBlock.equals(memory.getBlock(inner))) {
				return TableScorer.Entry.rejected(Cut.OUT_OF_BANK);
			}
			if (i >= 1) {
				EntryReferences.Hit hit = EntryReferences.find(program, pos, outerExtent, shape.own());
				if (hit != null && hit.strong()) {
					return TableScorer.Entry.rejected(Cut.ENTRY_REFERENCED);
				}
			}
			return TableScorer.Entry.accepted(inner, List.of());
		}, TableScorer.HARD_ONLY);

		List<Address> outerWords = new ArrayList<>(walked.targets());
		Cut outerCut = walked.endedBy();
		if (outerCut == null) {
			outerCut = shape.outerCap() != null ? Cut.INDEX_CAP : Cut.DECLINED;
		}
		if (outerCut == Cut.DECLINED || outerWords.isEmpty()) {
			return new Resolution(new Table(t, List.of(), outerCut), Map.of(),
				"outer table " + t + " not bounded (" + outerCut + ")");
		}

		// Inner tables, for the words the outer walk kept; the extents they may not run into are
		// every other inner start and the outer table itself.
		Set<Address> starts = new LinkedHashSet<>(outerWords);
		long outerEnd = t.getOffset() + 2L * outerWords.size();
		for (Address s : starts) {
			innerCache.put(s, walkInner(program, shape, s, starts, t, outerEnd));
		}
		if (outerCut == Cut.INVALID_WORD || outerCut == Cut.OUT_OF_BANK) {
			// Nothing positive ended the outer table: its tail may be the next bytes read as words.
			while (!outerWords.isEmpty() &&
				innerCache.get(outerWords.get(outerWords.size() - 1)).entries().isEmpty()) {
				outerWords.remove(outerWords.size() - 1);
			}
		}
		Map<Address, Table> inner = new LinkedHashMap<>();
		for (Address s : outerWords) {
			inner.putIfAbsent(s, innerCache.get(s));
		}
		Table outerTable = new Table(t, List.copyOf(outerWords), outerCut);
		boolean any = inner.values().stream().anyMatch(x -> !x.entries().isEmpty());
		return new Resolution(outerTable, inner, any ? null : "no inner table yielded a handler");
	}

	private static Table walkInner(Program program, Shape shape, Address s, Set<Address> starts,
			Address outer, long outerEnd) {
		Listing listing = program.getListing();
		if (listing.getInstructionContaining(s) != null) {
			return new Table(s, List.of(), Cut.RAN_INTO_CODE); // already code: not a table
		}
		if (s.getAddressSpace().equals(outer.getAddressSpace()) &&
			s.getOffset() >= outer.getOffset() && s.getOffset() < outerEnd) {
			return new Table(s, List.of(), Cut.NEXT_TABLE); // inside the outer table
		}
		Memory memory = program.getMemory();
		int cap = shape.innerCap() == null ? MAX_ENTRIES : shape.innerCap();
		List<EntryReferences.Extent> extent = List.of(new EntryReferences.Extent(s, 2L * cap));
		TableScorer.Result<Address, Cut> walked = TableScorer.walk(cap, (i, before) -> {
			Address pos = s.add(2L * i);
			if (pos.getOffset() >= lowestAbove(s, before)) {
				return TableScorer.Entry.rejected(Cut.ABOVE_TABLE_TARGET);
			}
			if (i >= 1 && (starts.contains(pos) || (sameSpace(pos, outer) &&
				pos.getOffset() + 1 >= outer.getOffset() && pos.getOffset() < outerEnd))) {
				return TableScorer.Entry.rejected(Cut.NEXT_TABLE);
			}
			if (inCode(program, pos)) {
				return TableScorer.Entry.rejected(Cut.RAN_INTO_CODE);
			}
			Long word = readWord(memory, pos);
			if (word == null || (word >= s.getOffset() && word <= pos.getOffset() + 1)) {
				return TableScorer.Entry.rejected(Cut.INVALID_WORD);
			}
			Address h = InlineJumpTableDispatch.resolveTarget(s.getAddressSpace(), memory, word);
			MemoryBlock block = h == null ? null : memory.getBlock(h);
			if (block == null || !block.isInitialized() || block.isVolatile()) {
				return TableScorer.Entry.rejected(Cut.INVALID_WORD);
			}
			if (InlineJumpTableDispatch.isCrossWindow(program, s, h) ||
				!InlineJumpTableDispatch.plausibleTarget(program, h)) {
				return TableScorer.Entry.rejected(Cut.IMPLAUSIBLE);
			}
			if (i >= 1) {
				EntryReferences.Hit hit = EntryReferences.find(program, pos, extent, shape.own());
				if (hit != null && hit.strong()) {
					return TableScorer.Entry.rejected(Cut.ENTRY_REFERENCED);
				}
			}
			return TableScorer.Entry.accepted(h, List.of());
		}, TableScorer.HARD_ONLY);
		Cut cut = walked.endedBy();
		if (cut == null) {
			cut = shape.innerCap() != null ? Cut.INDEX_CAP : Cut.DECLINED;
		}
		List<Address> kept = cut == Cut.DECLINED ? List.of() : List.copyOf(walked.targets());
		return new Table(s, kept, cut);
	}

	private static boolean sameSpace(Address a, Address b) {
		return a.getAddressSpace().equals(b.getAddressSpace());
	}

	/** Whether either byte of the word at {@code pos} is covered by an existing instruction. */
	private static boolean inCode(Program program, Address pos) {
		Listing listing = program.getListing();
		if (listing.getInstructionContaining(pos) != null) {
			return true;
		}
		try {
			return listing.getInstructionContaining(pos.add(1)) != null;
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	/** The lowest of {@code before} lying after {@code start} (same space), else MAX_VALUE. */
	private static long lowestAbove(Address start, List<Address> before) {
		long lowest = Long.MAX_VALUE;
		for (Address a : before) {
			if (sameSpace(a, start) && a.getOffset() > start.getOffset()) {
				lowest = Math.min(lowest, a.getOffset());
			}
		}
		return lowest;
	}

	private static Long readWord(Memory memory, Address pos) {
		try {
			int lo = memory.getByte(pos) & 0xff;
			int hi = memory.getByte(pos.add(1)) & 0xff;
			return (long) (lo | (hi << 8));
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	private static boolean isRom(Program program, Address addr) {
		MemoryBlock block = program.getMemory().getBlock(addr);
		return block != null && block.isInitialized() && !block.isWrite() && !block.isVolatile();
	}

	// ---------------------------------------------------------------------
	// Raw instruction helpers (by opcode byte, like the sibling classes).
	// ---------------------------------------------------------------------

	private static int opcode(Instruction in) {
		try {
			return in.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** {@code LDA ($nn),Y} (opcode {@code 0xb1}): {@code $nn}, else null. */
	private static Long indirectY(Instruction in) {
		if (opcode(in) != 0xb1 || in.getLength() != 2) {
			return null;
		}
		try {
			return (long) (in.getByte(1) & 0xff);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	/** The 16-bit operand of a 3-byte instruction, else null. */
	private static Long absolute(Instruction in) {
		if (in.getLength() != 3) {
			return null;
		}
		try {
			return (long) ((in.getByte(1) & 0xff) | ((in.getByte(2) & 0xff) << 8));
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}
}
