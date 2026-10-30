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
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

/**
 * Pure(ish) logic for grm-gipk.7: the 6502 "RTS trick". The dispatcher pushes a target MINUS ONE
 * as two bytes and {@code RTS}es into it, so the {@code RTS} is a computed jump. On the 6502 stock
 * Ghidra treats {@code RTS} as a return, so no switch is ever built, and the targets stay
 * undisassembled unless something else reaches them. Overriding the {@code RTS}'s flow to a branch
 * is not an option: Ghidra's 6502 {@code RTS} p-code does not add the 1 (and {@code JSR} pushes
 * {@code inst_next}, not {@code inst_next-1}, to match), so every recovered target would land one
 * byte early. The recognizer therefore reads the push pair directly, like
 * {@link InlineJumpTableDispatch} does for its inline-table shape.
 *
 * <p><b>The shape.</b> An {@code RTS} whose straight-line predecessors are
 * <pre>
 *   LDA t1,R / PHA / LDA t2,R / PHA / RTS        (R is X or Y)
 * </pre>
 * The first push is the HIGH byte. Branch-free, stack-neutral instructions may sit between the
 * parts (not between an {@code LDA} and its {@code PHA}, which would be free to clobber {@code A})
 * but R must not be written between the two loads. A {@code PLA}/{@code PHP}/{@code PLP}/
 * {@code TXS}/{@code JSR}/branch/jump in the window, or any flow INTO the sequence after its first
 * instruction and before the {@code RTS}, declines the site. Flow into the {@code RTS} itself does
 * not: a path sharing the return brings its own stack (grm-gipk.8).
 * <ul>
 * <li><b>Interleaved</b> when {@code t1 == t2+1}: a word table at {@code t2}, entry {@code i} at
 * {@code t2 + 2i} (the index was doubled upstream). Real instances: adventure_island 8dd1, c6c9,
 * c95c.</li>
 * <li><b>Planar</b> otherwise: low bytes at {@code t2}, high bytes at {@code t1}, entry {@code i} is
 * {@code lo[t2+i] | hi[t1+i] << 8}. The gap {@code t1 - t2} may be NEGATIVE: adventure_island bd50
 * pushes {@code LDA $bd65,X} first, so the hi table sits below the lo table at {@code $bd6d}.</li>
 * </ul>
 * Every target is the table word plus one.
 *
 * <p><b>Other CPUs</b> (grm-gipk.8): the SPC700 spells the same idiom
 * {@code MOV A,!t1+Y / PUSH A / MOV A,!t2+Y / PUSH A / RET}, and its {@code RET} pops the target
 * itself, so the bias is 0 (see {@link Dialect}). The AKAO sound drivers dispatch voice commands
 * this way, interleaved and hi first. The 65816 form (a 16-bit {@code PHA}, grm-gipk.11) is
 * recognized separately, by {@link W65816RtsTrick}.
 *
 * <p><b>The bound</b> ({@link #scan}). Entries are read in order from 0 until the first of
 * <ul>
 * <li>the entry's own table bytes would reach the lowest target seen so far that lies above the
 * table start ({@link Cut#ABOVE_TABLE_TARGET}; targets below the table are ignored, as in
 * {@link InlineJumpTableDispatch#scanTable});</li>
 * <li>the entry's own table bytes would reach ANOTHER dispatch site's table base that lies above
 * this table's start ({@link Cut#NEIGHBOUR_TABLE}, in the spirit of grm-2m07's
 * {@code JumpTableBound.boundByNeighbourTable}): adventure_island's 8efe table runs straight into
 * the plausible words of 8f8e's, and nothing else would end it. The caller supplies the bases;
 * the word-table start of an interleaved site, the lo and hi base of a planar one;</li>
 * <li>the planar halves would overlap: at most {@code |gap|} entries ({@link Cut#GAP}), capped at
 * 256 (the width of the index register);</li>
 * <li>the target is not usable: unmapped, uninitialized or volatile memory, inside the table's own
 * bytes, mid-instruction, on defined data, or bytes that do not decode as code
 * ({@link Cut#INVALID_TARGET}). A target in a DIFFERENT banked window than the table is kept
 * unjudged and never disassembled (grm-rnf0, as {@link InlineJumpTableDispatch#isCrossWindow});</li>
 * <li>an interleaved table that nothing ended within {@link #MAX_INTERLEAVED_ENTRIES}
 * ({@link Cut#DECLINED}: no length can be trusted, the site is declined).</li>
 * <li>every index an {@code AND #mask / ASL A* / TAX|TAY} directly before the first load allows was
 * read ({@link Cut#MASK}, grm-gipk.8: FF3 0a12 masks with {@code #$0f}, so 16 entries, where the
 * other rules read 49). A masked interleaved table is never {@link Cut#DECLINED}.</li>
 * </ul>
 * Fewer than two kept entries declines. No {@code CMP #n / BCS} guard is looked for.
 *
 * @see RtsTrickDispatchAnalyzer
 */
final class RtsTrickDispatch {

	/** How many instructions before the {@code RTS} the straight-line window may span. */
	static final int MAX_WINDOW = 10;

	/** Cap on interleaved entries (the index is a doubled byte, but nothing ends it for sure). */
	static final int MAX_INTERLEAVED_ENTRIES = 128;

	/** Cap on planar entries: the index register is a byte. */
	static final int MAX_PLANAR_ENTRIES = 256;

	/** 6502 mnemonics that are never "stack-neutral, branch-free noise" between the parts. */
	private static final Set<String> NOT_NOISE =
		Set.of("PHA", "PLA", "PHP", "PLP", "TXS", "JSR", "RTS", "RTI", "BRK", "JMP");
	private static final Set<String> X_WRITERS = Set.of("INX", "DEX", "LDX", "TAX", "TSX");
	private static final Set<String> Y_WRITERS = Set.of("INY", "DEY", "LDY", "TAY");

	private RtsTrickDispatch() {
	}

	/**
	 * The per-CPU spelling of the idiom (grm-gipk.8): the return, the one-byte accumulator push,
	 * the two absolute-indexed accumulator loads, and the BIAS, i.e. what the return adds to the
	 * popped word. The shape and the bound are otherwise the same.
	 */
	enum Dialect {
		/** 6502 family: {@code LDA abs,X/Y} / {@code PHA} / {@code RTS}, which pops target - 1. */
		MOS6502("RTS", 0x48, 0xbd, 0xb9, 1, 0xaa, 0xa8, 0x0a, 0x29) {
			@Override
			boolean writesIndex(Instruction instr, boolean x) {
				return (x ? X_WRITERS : Y_WRITERS).contains(instr.getMnemonicString());
			}

			@Override
			boolean isNoise(Instruction instr) {
				return isStraight(instr) && !NOT_NOISE.contains(instr.getMnemonicString());
			}
		},
		/**
		 * SPC700: {@code MOV A,!abs+X/Y} / {@code PUSH A} / {@code RET}, which pops the target
		 * itself ({@code pop16(PC)}, no +1). The AKAO drivers' command dispatch (FF3 0a12/0c69, CT
		 * 0e10, Lemmings 1175, Secret of Mana 100e; RtsTrickProbe survey on grm-gipk.8).
		 */
		SPC700("RET", 0x2d, 0xf5, 0xf6, 0, 0x5d, 0xfd, 0x1c, 0x28) {
			@Override
			boolean writesIndex(Instruction instr, boolean x) {
				return writesRegister(instr, instr.getProgram().getRegister(x ? "X" : "Y"));
			}

			@Override
			boolean isNoise(Instruction instr) {
				String m = instr.getMnemonicString();
				return isStraight(instr) && !"PUSH".equals(m) && !"POP".equals(m) &&
					!writesRegister(instr, instr.getProgram().getCompilerSpec().getStackPointer());
			}
		};

		final String returnMnemonic;
		final int pushOpcode;
		final int loadX;
		final int loadY;
		final int bias;
		/** {@code TAX}/{@code TAY} ({@code MOV X,A}/{@code MOV Y,A}), {@code ASL A}, {@code AND #imm}. */
		final int transferX;
		final int transferY;
		final int aslA;
		final int andImm;

		Dialect(String returnMnemonic, int pushOpcode, int loadX, int loadY, int bias,
				int transferX, int transferY, int aslA, int andImm) {
			this.returnMnemonic = returnMnemonic;
			this.pushOpcode = pushOpcode;
			this.loadX = loadX;
			this.loadY = loadY;
			this.bias = bias;
			this.transferX = transferX;
			this.transferY = transferY;
			this.aslA = aslA;
			this.andImm = andImm;
		}

		/** True when {@code instr} writes the X (or Y) index register. */
		abstract boolean writesIndex(Instruction instr, boolean x);

		/** Stack-neutral, branch-free filler allowed between the parts. */
		abstract boolean isNoise(Instruction instr);

		/** The SPC700 dialect for that processor; the 6502 one for every other 8-bit language. */
		static Dialect of(Program program) {
			return "SPC700".equals(program.getLanguage().getProcessor().toString()) ? SPC700
					: MOS6502;
		}

		private static boolean writesRegister(Instruction instr, Register reg) {
			if (reg == null) {
				return false;
			}
			for (Object o : instr.getResultObjects()) {
				if (o instanceof Register r && (r.equals(reg) || r.contains(reg))) {
					return true;
				}
			}
			return false;
		}
	}

	/** How a site's table was ended; see {@link #scan}. */
	enum Cut {
		ABOVE_TABLE_TARGET, GAP, INVALID_TARGET,
		/** The entry's bytes would reach ANOTHER site's table base lying above this table's start. */
		NEIGHBOUR_TABLE, DECLINED,
		/** Every index an {@code AND #mask} before the loads allows was read (grm-gipk.8). */
		MASK
	}

	/**
	 * A recognized push pair: the two table bases, before any bound, the dialect's bias, and the
	 * entry cap an {@code AND #mask} on the index allows (0 when there is none).
	 */
	record Shape(Address rts, int tHi, int tLo, int bias, int maskCap) {
		boolean interleaved() {
			return tHi == tLo + 1;
		}

		/** hi - lo: planar gap, possibly negative. Meaningless when interleaved. */
		int gap() {
			return tHi - tLo;
		}
	}

	/** A bounded site: the table's lo base, the kept targets (word + 1) and why it ended. */
	static final class Site {
		final Shape shape;
		/** The low byte of entry 0 (interleaved: the word table's start). */
		final Address loBase;
		final Cut cut;
		final List<Address> targets;

		private Site(Shape shape, Address loBase, Cut cut, List<Address> targets) {
			this.shape = shape;
			this.loBase = loBase;
			this.cut = cut;
			this.targets = targets;
		}
	}

	// ---------------------------------------------------------------------
	// Recognizer.
	// ---------------------------------------------------------------------

	/** The push-pair shape ending at {@code rts}, or null when it is not conclusively this idiom. */
	static Shape recognize(Program program, Instruction rts) {
		Dialect d = Dialect.of(program);
		if (!d.returnMnemonic.equals(rts.getMnemonicString())) {
			return null;
		}
		Listing listing = program.getListing();
		ArrayDeque<Instruction> seq = new ArrayDeque<>();
		seq.add(rts);
		Instruction cur = rts;
		for (int n = 0; n < MAX_WINDOW; n++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough()) ||
				!isStraight(prev)) {
				break;
			}
			seq.addFirst(prev);
			cur = prev;
		}
		Instruction[] w = seq.toArray(new Instruction[0]);

		int i = w.length - 2;
		while (i >= 0 && d.isNoise(w[i])) {
			i--;
		}
		if (i < 1 || !isPush(d, w[i])) {
			return null;
		}
		int push2 = i;
		int load2 = i - 1;
		int tLo = loadOperand(d, w[load2]);
		int reg = loadRegister(d, w[load2]);
		if (tLo < 0) {
			return null;
		}
		i = load2 - 1;
		while (i >= 0 && d.isNoise(w[i])) {
			if (d.writesIndex(w[i], reg == d.loadX)) {
				return null; // R changes between the loads
			}
			i--;
		}
		if (i < 1 || !isPush(d, w[i])) {
			return null;
		}
		int load1 = i - 1;
		int tHi = loadOperand(d, w[load1]);
		if (tHi < 0 || loadRegister(d, w[load1]) != reg || tHi == tLo) {
			return null;
		}
		// No flow into the sequence between the first load and the last push: a join there could
		// bring a different index or a half-built return address. Anything after the last push may
		// be a join, the return included: another path reaching it brings its own stack, and does
		// not change what this path pushed (CT 0e10, FF3 0c69, SoM 100e share their RET,
		// grm-gipk.8; radical 0c89 and Terranigma 0468 join between the last push and it,
		// grm-gipk.12).
		for (int k = load1 + 1; k <= push2; k++) {
			if (hasNonFallThroughFlowInto(program, w[k].getMinAddress())) {
				return null;
			}
		}
		return new Shape(rts.getMinAddress(), tHi, tLo, d.bias,
			maskCap(program, d, w, load1, reg == d.loadX, tHi == tLo + 1));
	}

	/**
	 * The entry cap of {@code AND #mask / ASL A* / TAX|TAY} directly before the first load, or 0
	 * when the index is not masked there (or flow joins after the {@code AND}, bypassing it).
	 */
	private static int maskCap(Program program, Dialect d, Instruction[] w, int load1, boolean x,
			boolean interleaved) {
		int j = load1 - 1;
		if (j < 0 || opcode(w[j]) != (x ? d.transferX : d.transferY) || w[j].getLength() != 1) {
			return 0;
		}
		int shifts = 0;
		j--;
		while (j >= 0 && opcode(w[j]) == d.aslA && w[j].getLength() == 1) {
			shifts++;
			j--;
		}
		if (j < 0 || opcode(w[j]) != d.andImm || w[j].getLength() != 2) {
			return 0;
		}
		for (int k = j + 1; k <= load1; k++) {
			if (hasNonFallThroughFlowInto(program, w[k].getMinAddress())) {
				return 0;
			}
		}
		int mask;
		try {
			mask = w[j].getByte(1) & 0xff;
		}
		catch (MemoryAccessException e) {
			return 0;
		}
		long maxIndex = ((long) mask) << shifts;
		return (int) (interleaved ? maxIndex / 2 + 1 : maxIndex + 1);
	}

	private static int opcode(Instruction instr) {
		try {
			return instr.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	static boolean isStraight(Instruction instr) {
		FlowType ft = instr.getFlowType();
		return !(ft.isConditional() || ft.isJump() || ft.isCall() || ft.isTerminal() ||
			ft.isComputed()) && instr.getFallThrough() != null;
	}

	/** The dialect's one-byte accumulator push ({@code PHA}, {@code PUSH A}). */
	private static boolean isPush(Dialect d, Instruction instr) {
		try {
			return instr.getLength() == 1 && (instr.getByte(0) & 0xff) == d.pushOpcode;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/** The absolute-indexed accumulator load's 16-bit operand, or -1. */
	private static int loadOperand(Dialect d, Instruction instr) {
		if (loadRegister(d, instr) < 0 || instr.getLength() != 3) {
			return -1;
		}
		try {
			return (instr.getByte(1) & 0xff) | ((instr.getByte(2) & 0xff) << 8);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** The opcode when {@code instr} is the dialect's {@code abs,X} or {@code abs,Y} load, else -1. */
	private static int loadRegister(Dialect d, Instruction instr) {
		try {
			int op = instr.getByte(0) & 0xff;
			return (op == d.loadX || op == d.loadY) ? op : -1;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	static boolean hasNonFallThroughFlowInto(Program program, Address at) {
		for (Reference ref : program.getReferenceManager().getReferencesTo(at)) {
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	// ---------------------------------------------------------------------
	// Bound.
	// ---------------------------------------------------------------------

	/**
	 * Reads and bounds the table of {@code shape}; see the class Javadoc. Never throws. Returns null
	 * when the site is declined (a table that is not in initialized memory, fewer than two entries,
	 * or {@link Cut#DECLINED}).
	 */
	static Site scan(Program program, Shape shape) {
		return scan(program, shape, List.of());
	}

	/**
	 * The table bases {@code shape} contributes as neighbour starts for OTHER sites' bounds (see
	 * {@link Cut#NEIGHBOUR_TABLE}), resolved in the RTS's space: the word-table start when
	 * interleaved, else the lo and hi base. Empty when unresolvable.
	 */
	static List<Address> tableBases(Program program, Shape shape) {
		AddressSpace space = shape.rts().getAddressSpace();
		Memory memory = program.getMemory();
		List<Address> out = new ArrayList<>();
		out.add(InlineJumpTableDispatch.resolveTarget(space, memory, shape.tLo()));
		if (!shape.interleaved()) {
			out.add(InlineJumpTableDispatch.resolveTarget(space, memory, shape.tHi()));
		}
		return out;
	}

	/** As {@link #scan(Program, Shape)}, also cut at any of {@code neighbourStarts}. */
	static Site scan(Program program, Shape shape, Collection<Address> neighbourStarts) {
		AddressSpace space = shape.rts().getAddressSpace();
		Memory memory = program.getMemory();
		boolean interleaved = shape.interleaved();
		Address loBase = InlineJumpTableDispatch.resolveTarget(space, memory, shape.tLo());
		Address hiBase = interleaved ? loBase.add(1)
				: InlineJumpTableDispatch.resolveTarget(space, memory, shape.tHi());
		if (!isReadable(memory, loBase) || !isReadable(memory, hiBase)) {
			return null;
		}
		int stride = interleaved ? 2 : 1;
		int cap = interleaved ? MAX_INTERLEAVED_ENTRIES
				: Math.min(MAX_PLANAR_ENTRIES, Math.abs(shape.gap()));
		boolean masked = shape.maskCap() > 0 && shape.maskCap() <= cap;
		if (masked) {
			cap = shape.maskCap();
		}
		long tableStart = Math.min(loBase.getOffset(), hiBase.getOffset());
		long nextNeighbour = Long.MAX_VALUE;
		for (Address n : neighbourStarts) {
			if (n.getAddressSpace().equals(loBase.getAddressSpace()) && n.getOffset() > tableStart &&
				!n.equals(loBase) && !n.equals(hiBase)) {
				nextNeighbour = Math.min(nextNeighbour, n.getOffset());
			}
		}

		List<Address> kept = new ArrayList<>();
		long lowestAbove = Long.MAX_VALUE;
		Cut cut = masked ? Cut.MASK : interleaved ? Cut.DECLINED : Cut.GAP;
		for (int i = 0; i < cap; i++) {
			long loOff = loBase.getOffset() + (long) stride * i;
			long hiOff = hiBase.getOffset() + (long) stride * i;
			if (Math.max(loOff, hiOff) >= lowestAbove) {
				cut = Cut.ABOVE_TABLE_TARGET;
				break;
			}
			if (Math.max(loOff, hiOff) >= nextNeighbour) {
				cut = Cut.NEIGHBOUR_TABLE;
				break;
			}
			int lo;
			int hi;
			try {
				lo = memory.getByte(loBase.add((long) stride * i)) & 0xff;
				hi = memory.getByte(hiBase.add((long) stride * i)) & 0xff;
			}
			catch (MemoryAccessException | RuntimeException e) {
				cut = Cut.INVALID_TARGET;
				break;
			}
			long target = (lo | (hi << 8)) + shape.bias() & 0xffff;
			Address targetAddr = usableTarget(program, space, loBase, target, loBase, hiBase, i,
				stride);
			if (targetAddr == null) {
				cut = Cut.INVALID_TARGET;
				break;
			}
			if (targetAddr.getOffset() > tableStart) {
				lowestAbove = Math.min(lowestAbove, targetAddr.getOffset());
			}
			kept.add(targetAddr);
		}
		if (cut == Cut.DECLINED || kept.size() < 2) {
			return null;
		}
		return new Site(shape, loBase, cut, List.copyOf(kept));
	}

	private static boolean isReadable(Memory memory, Address a) {
		MemoryBlock block = a == null ? null : memory.getBlock(a);
		return block != null && block.isInitialized() && !block.isVolatile();
	}

	/**
	 * The resolved target address, or null when it cannot be a handler entry: inside the table's own
	 * bytes (entries 0..i of either half), outside initialized non-volatile memory, or not plausible
	 * code. A cross-window target is returned without the plausibility judgement.
	 */
	private static Address usableTarget(Program program, AddressSpace space, Address tableAddr,
			long target, Address loBase, Address hiBase, int i, int stride) {
		long span = (long) stride * i + stride - 1;
		if (inRange(target, loBase.getOffset(), span) || inRange(target, hiBase.getOffset(), span)) {
			return null;
		}
		Memory memory = program.getMemory();
		Address t = InlineJumpTableDispatch.resolveTarget(space, memory, target);
		if (!isReadable(memory, t)) {
			return null;
		}
		if (InlineJumpTableDispatch.isCrossWindow(program, tableAddr, t)) {
			return t;
		}
		return InlineJumpTableDispatch.plausibleTarget(program, t) ? t : null;
	}

	private static boolean inRange(long v, long start, long span) {
		return v >= start && v <= start + span;
	}
}
