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
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Pure(ish) logic for grm-v60's RESTORING far-call trampoline (wizwarr {@code FUN_ff69}, Ironsword
 * {@code FUN_ffc0}): an entry that copies a register (Y) into the low byte of a pointer cell
 * {@code P}, writes the bank mechanism from a value derived from A, and reaches a
 * {@code JMP (P)}. Each caller sets Y (the low byte) and A (the bank, possibly through a
 * BIT-skip stub), so the routine the {@code JMP (P)} runs lives in the DESTINATION bank's
 * overlay -- which no single reference in the program says.
 *
 * <p>Per qualifying {@code JMP (P)} site this recovers, per call site: Y and A by a straight-line
 * constant walk from the call site into the trampoline entry ({@link IndirectJumpConstantPointer}'s
 * tracker); the bank by re-evaluating the trampoline's mechanism write under those registers
 * ({@link BankContext#switchedByEntry}); and the pointer's HIGH byte by the <b>write-once
 * constant rule</b>: the cell has exactly one direct (non-indexed) write in the whole program,
 * and it stores an immediate-derived constant. That rule is general and deliberately weak (an
 * indexed or indirect write, or a write in code not yet disassembled, would not be seen), so a
 * call site is accepted ONLY with corroboration: the resolved target, read in the destination
 * bank, must be a {@code JMP abs} or {@code JSR abs} entry (a vector-table slot). A site that
 * fails corroboration is declined, with a reason, and nothing is placed for it.
 *
 * <p>The pass does not model what the trampoline does AFTER the call (the restoring variant puts
 * the bank back; a GxROM return-address-popping variant, dragonpower's {@code ffdc}, resumes in
 * the destination bank) -- it only places the call's target.
 *
 * @see <a href="urn:bead:grm-v60">grm-v60</a>
 */
final class FarCallTrampoline {

	private static final int MAX_CHAIN_MEMBERS = 32;
	private static final int MAX_SHAPE_STEPS = 64;

	/** How far before a chain member a hidden (offcut) stub entry is looked for. */
	private static final int ENTRY_WINDOW = 0x20;


	private FarCallTrampoline() {
	}

	/** A call site whose target was resolved into a bank's overlay (or the home bank). */
	record Placement(Instruction callSite, Address target) {
	}

	/** A call site that had everything but was refused, and why. */
	record Declined(Instruction callSite, String reason) {
	}

	record Outcome(List<Placement> placed, List<Declined> declined) {
		static Outcome none() {
			return new Outcome(new ArrayList<>(), new ArrayList<>());
		}
	}

	/** Program-wide index: direct writers by 16-bit operand offset, and the indirect-jump sites. */
	static final class Index {
		private final Map<Long, List<Instruction>> writers = new HashMap<>();
		final List<Instruction> sites = new ArrayList<>();

		/**
		 * Collapses MIRROR COPIES of a writer into one: the same instruction bytes at the same
		 * offset in different spaces (the base window and its bank overlays, each carrying its
		 * own copy of fixed code, e.g. AxROM's per-bank trampoline). The canonical copy is the
		 * base-space one, else the lowest overlay space name, so the choice does not depend on
		 * disassembly order. Writers differing in offset or bytes stay separate.
		 */
		void collapseMirrorCopies() {
			for (Map.Entry<Long, List<Instruction>> e : writers.entrySet()) {
				Map<String, Instruction> canonical = new java.util.LinkedHashMap<>();
				for (Instruction i : e.getValue()) {
					String key;
					try {
						key = Long.toHexString(i.getMinAddress().getOffset()) + ":" +
							java.util.HexFormat.of().formatHex(i.getBytes());
					}
					catch (MemoryAccessException ex) {
						key = i.getMinAddress().toString(); // unreadable: never merged
					}
					Instruction prior = canonical.get(key);
					if (prior == null || rank(i) < rank(prior) ||
						(rank(i) == rank(prior) && i.getMinAddress().getAddressSpace().getName()
								.compareTo(prior.getMinAddress().getAddressSpace().getName()) < 0)) {
						canonical.put(key, i);
					}
				}
				e.setValue(new ArrayList<>(canonical.values()));
			}
		}

		private static int rank(Instruction i) {
			return i.getMinAddress().getAddressSpace().isOverlaySpace() ? 1 : 0;
		}

		List<Instruction> writersOf(long offset) {
			return writers.getOrDefault(offset & 0xffff, List.of());
		}
	}

	static Index buildIndex(Program program, TaskMonitor monitor) throws CancelledException {
		Index index = new Index();
		InstructionIterator it = program.getListing().getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			if (IndirectJumpConstantPointer.isIndirectJumpSite(instr)) {
				index.sites.add(instr);
				continue;
			}
			if (instr.getLength() < 2) {
				continue;
			}
			switch (instr.getMnemonicString()) {
				case "STA", "STX", "STY", "INC", "DEC", "ASL", "LSR", "ROL", "ROR":
					break;
				default:
					continue;
			}
			Address operand = operandOffsetAddress(instr);
			if (operand != null &&
				IndirectJumpConstantPointer.isDirectWriteTo(instr, operand.getOffset())) {
				index.writers.computeIfAbsent(operand.getOffset(), k -> new ArrayList<>())
						.add(instr);
			}
		}
		index.collapseMirrorCopies();
		return index;
	}

	private static Address operandOffsetAddress(Instruction instr) {
		try {
			AddressSpace space = instr.getMinAddress().getAddressSpace();
			if (instr.getLength() == 2) {
				return space.getAddress(instr.getByte(1) & 0xff);
			}
			if (instr.getLength() == 3) {
				return space.getAddress(
					((instr.getByte(2) & 0xff) << 8) | (instr.getByte(1) & 0xff));
			}
		}
		catch (MemoryAccessException e) {
			// fall through
		}
		return null;
	}

	/** Resolves one {@code JMP (P)} site, or returns an empty outcome when it is not a trampoline's. */
	static Outcome resolve(Program program, BankContext ctx, Index index, Instruction site,
			TaskMonitor monitor) throws CancelledException {
		Outcome out = Outcome.none();
		Listing listing = program.getListing();
		Address pointer = IndirectJumpConstantPointer.pointerCell(site);
		if (pointer == null) {
			return out;
		}
		long pLo = pointer.getOffset();
		long pHi = (pLo + 1) & 0xffff;
		List<Instruction> loWriters = index.writersOf(pLo);
		List<Instruction> hiWriters = index.writersOf(pHi);
		if (loWriters.size() != 1 || hiWriters.size() != 1) {
			return out; // not write-once on both bytes: not this idiom
		}
		Instruction loStore = loWriters.get(0);
		Character reg = MosOperands.storeRegister(loStore);
		if (reg == null) {
			return out;
		}
		Integer hi = IndirectJumpConstantPointer.storedConstant(program, hiWriters.get(0),
			monitor);
		if (hi == null) {
			return out;
		}

		// The trampoline entry: the head of the store's straight-line run, with the stored
		// register untouched between the entry and the store (so it IS the caller's value).
		Address entry = IndirectJumpConstantPointer.runHead(program, loStore.getMinAddress(),
			monitor);
		for (Instruction i = listing.getInstructionAt(entry); i != null &&
			!i.getMinAddress().equals(loStore.getMinAddress());
				i = listing.getInstructionAfter(i.getMinAddress())) {
			if (writesRegister(program, i, reg)) {
				return out;
			}
		}
		List<Instruction> run = straightLineToSite(program, entry, site);
		if (run == null) {
			return out;
		}

		for (Instruction caller : callSites(program, entry)) {
			monitor.checkCancelled();
			IndirectJumpConstantPointer.Regs regs = IndirectJumpConstantPointer.walkToAddress(
				program, IndirectJumpConstantPointer.runHead(program, caller.getMinAddress(),
					monitor),
				entry, monitor);
			if (regs == null || regs.a() == null) {
				continue;
			}
			Integer lo = switch (reg) {
				case 'A' -> regs.a();
				case 'X' -> regs.x();
				default -> regs.y();
			};
			if (lo == null) {
				continue; // an interior link of the entry chain, or a call with an unknown argument
			}
			BankContext.EntrySwitch sw = ctx.switchedByEntry(entry,
				PartialByte.fullyKnown(regs.a()),
				regs.x() == null ? PartialByte.unknown() : PartialByte.fullyKnown(regs.x()),
				regs.y() == null ? PartialByte.unknown() : PartialByte.fullyKnown(regs.y()));
			if (sw == null ||
				run.stream().noneMatch(i -> i.getMinAddress().equals(sw.writeSite()))) {
				out.declined().add(new Declined(caller,
					"far-call bank not recovered for A=$" + Integer.toHexString(regs.a())));
				continue;
			}
			AddressSpace home = program.getAddressFactory().getDefaultAddressSpace();
			Address homeTarget = home.getAddress(((hi & 0xff) << 8) | (lo & 0xff));
			Address target = ctx.resolveUnder(sw.state(), homeTarget);
			if (target == null) {
				out.declined().add(new Declined(caller, "far-call destination " + homeTarget +
					" is not determined by bank state " + sw.state()));
				continue;
			}
			if (!landsOnJumpEntry(program, target)) {
				out.declined().add(new Declined(caller, "write-once pointer high byte $" +
					Integer.toHexString(hi) + " not corroborated: " + target +
					" is not a JMP/JSR entry"));
				continue;
			}
			out.placed().add(new Placement(caller, target));
		}
		return out;
	}

	/** Corroboration: the destination bank's byte at {@code target} is {@code JMP abs} or {@code JSR abs}. */
	static boolean landsOnJumpEntry(Program program, Address target) {
		MemoryBlock block = program.getMemory().getBlock(target);
		if (block == null || !block.isInitialized()) {
			return false;
		}
		try {
			int op = program.getMemory().getByte(target) & 0xff;
			return op == 0x4c || op == 0x20;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * The instructions from {@code entry} along its unbroken fall-through run to the transfer
	 * that dereferences {@code site}: the site itself, or a {@code JSR} whose callee reaches the
	 * site through fall-through and unconditional {@code JMP}s. Null if the run ends first.
	 */
	private static List<Instruction> straightLineToSite(Program program, Address entry,
			Instruction site) {
		Listing listing = program.getListing();
		List<Instruction> run = new ArrayList<>();
		Instruction cur = listing.getInstructionAt(entry);
		for (int i = 0; cur != null && i < MAX_SHAPE_STEPS; i++) {
			run.add(cur);
			if (cur.getMinAddress().equals(site.getMinAddress())) {
				return run;
			}
			FlowType ft = cur.getFlowType();
			if ("JSR".equals(cur.getMnemonicString())) {
				if (reachesSite(program, singleTarget(cur), site)) {
					return run;
				}
			}
			else if (ft.isJump() || ft.isCall() || ft.isTerminal() || ft.isConditional()) {
				return null;
			}
			Address next = cur.getFallThrough();
			cur = next == null ? null : listing.getInstructionAt(next);
		}
		return null;
	}

	private static boolean reachesSite(Program program, Address start, Instruction site) {
		Listing listing = program.getListing();
		Address pc = start;
		for (int i = 0; pc != null && i < 8; i++) {
			if (pc.equals(site.getMinAddress())) {
				return true;
			}
			Instruction instr = listing.getInstructionAt(pc);
			if (instr == null) {
				return false;
			}
			FlowType ft = instr.getFlowType();
			if (IndirectJumpConstantPointer.isDirectJump(instr)) {
				pc = singleTarget(instr);
			}
			else if (ft.isJump() || ft.isCall() || ft.isTerminal() || ft.isConditional()) {
				return false;
			}
			else {
				pc = instr.getFallThrough();
			}
		}
		return false;
	}

	private static Address singleTarget(Instruction instr) {
		Address[] flows = instr.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	/**
	 * Every {@code JSR abs}/{@code JMP abs} that flows to {@code entry} or to a point from which
	 * straight-line control reaches it (an unconditional {@code JMP} to the entry, or a
	 * fall-through into it) -- wizwarr's BIT-skip stubs ({@code LDA #n / JMP ff69}). Candidates
	 * only: the constant walk decides which actually carry known arguments.
	 */
	private static List<Instruction> callSites(Program program, Address entry) {
		Listing listing = program.getListing();
		Set<Address> members = new LinkedHashSet<>();
		Set<Instruction> callers = new LinkedHashSet<>();
		Deque<Address> queue = new ArrayDeque<>();
		members.add(entry);
		queue.add(entry);
		while (!queue.isEmpty()) {
			Address m = queue.poll();
			Instruction prev = listing.getInstructionBefore(m);
			if (prev != null && FlowEdges.fallsInto(prev, m) &&
				members.size() < MAX_CHAIN_MEMBERS && members.add(prev.getMinAddress())) {
				queue.add(prev.getMinAddress());
			}
			ReferenceIterator refs = program.getReferenceManager().getReferencesTo(m);
			while (refs.hasNext()) {
				Reference ref = refs.next();
				if (!ref.getReferenceType().isFlow() ||
					ref.getReferenceType().isFallthrough()) {
					continue;
				}
				Instruction from = listing.getInstructionAt(ref.getFromAddress());
				if (from == null) {
					continue;
				}
				boolean jsr = "JSR".equals(from.getMnemonicString());
				boolean jmp = IndirectJumpConstantPointer.isDirectJump(from);
				if (!jsr && !jmp) {
					continue;
				}
				callers.add(from);
				if (jmp && members.size() < MAX_CHAIN_MEMBERS &&
					members.add(from.getMinAddress())) {
					queue.add(from.getMinAddress());
				}
			}
		}
		// A caller can also enter a few bytes BEFORE the chain, at an address no instruction
		// starts at (the skip idiom's hidden entry, bc08 inside bc07's BIT operand): nothing
		// falls into it, so the chain above cannot reach it. Any direct call or jump into that
		// window before ANY chain member is a candidate too; the constant walk decides whether it truly reaches the entry.
		for (Address member : members) {
			for (int back = 1; back <= ENTRY_WINDOW; back++) {
				Address a;
				try {
					a = member.subtractNoWrap(back);
				}
				catch (ghidra.program.model.address.AddressOverflowException e) {
					break;
				}
				ReferenceIterator refs = program.getReferenceManager().getReferencesTo(a);
				while (refs.hasNext()) {
					Reference ref = refs.next();
					if (!ref.getReferenceType().isFlow() ||
						ref.getReferenceType().isFallthrough()) {
						continue;
					}
					Instruction from = listing.getInstructionAt(ref.getFromAddress());
					if (from != null && ("JSR".equals(from.getMnemonicString()) ||
						IndirectJumpConstantPointer.isDirectJump(from))) {
						callers.add(from);
					}
				}
			}
		}
		return new ArrayList<>(callers);
	}

	/** Whether {@code instr}'s p-code writes register {@code reg} ('A', 'X' or 'Y'). */
	private static boolean writesRegister(Program program, Instruction instr, char reg) {
		PcodeOp[] ops;
		try {
			ops = instr.getPcode();
		}
		catch (RuntimeException e) {
			return true; // cannot tell: assume it does
		}
		for (PcodeOp op : ops) {
			Varnode out = op.getOutput();
			if (out == null) {
				continue;
			}
			Register r;
			try {
				r = program.getRegister(out);
			}
			catch (RuntimeException e) {
				continue;
			}
			if (r != null && r.getName().equalsIgnoreCase(String.valueOf(reg))) {
				return true;
			}
		}
		return false;
	}
}
