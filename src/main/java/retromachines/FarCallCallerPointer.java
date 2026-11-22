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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * grm-gipk.2: the CALLER-SET-POINTER far call (Dragon Power's GxROM {@code $FFE8}). The
 * counterpart of {@link FarCallTrampoline#resolve}'s write-once variant for a trampoline whose
 * pointer cell is written at EVERY call site:
 *
 * <pre>
 *   caller:  ... set pointer P/P+1 ... LDA #bank / JSR entry
 *   entry:   STA shadow / JSR leafHelper / JMP (P)          leafHelper: ... bank write ... RTS
 * </pre>
 *
 * <p>Per caller, a forward constant walk over the caller's straight-line run recovers A (the
 * bank) and the values stored into P and P+1: either two constants, or a lo/hi pair loaded from
 * an interleaved word table {@code tbl,Y} / {@code tbl+1,Y}. With a known Y exactly that entry is
 * used; otherwise entries are enumerated from the table base while each one corroborates (a
 * {@code JMP abs}/{@code JSR abs} in the destination bank), stopping at the first that does not
 * ({@link #MAX_TABLE_ENTRIES} at most). Every placed target must pass
 * {@link FarCallTrampoline#landsOnJumpEntry} in the destination bank.
 *
 * <p><b>The bank, and what it is NOT derived from.</b> {@link BankContext#switchedByEntry} cannot
 * recover it: it stops at the {@code JSR leafHelper}, and the write inside the helper is an
 * indexed store of a ROM-table value ({@code STA $FFCC,Y} with Y built from the shadow), whose
 * value no strategy pins. Instead the entry's first store (A into a shadow cell) names A as the
 * bank number, and the bank state is built from A as the value of the board's single bank field.
 * This is the FALLBACK path: {@code BankContext} exposes no query that turns "shadow cell = v"
 * into a bank state (BankMirrors models write-through shadows of the latch VALUE, which this
 * {@code $F2} is not: the latch value is a table-encoded function of it), so the shadow cell is
 * not verified to mirror the bank register. The helper is verified to contain a bank-mechanism
 * write, the board must have exactly one mechanism, and the corroboration rule backstops a wrong
 * bank. No emulation is done.
 */
final class FarCallCallerPointer {

	static final int MAX_TABLE_ENTRIES = 64;
	private static final int MAX_CALLER_RUN = 48;

	private FarCallCallerPointer() {
	}

	/** A value known to the caller walk: a constant, or one byte of a word table. */
	private record Val(Integer constant, Long tableByteAddr, Integer tableY) {
		static Val of(int v) {
			return new Val(v & 0xff, null, null);
		}

		static Val table(long addr, Integer y) {
			return new Val(null, addr, y);
		}
	}

	/** The pointer value(s) a caller leaves: one target offset, or a table of them. */
	private record Pointer(Integer constant, Long tableBase, Integer tableY) {
	}

	/**
	 * Resolves one {@code JMP (P)} site as a caller-set-pointer far call. Empty outcome when the
	 * site is not that shape (the write-once variant's sites, or anything else).
	 */
	static FarCallTrampoline.Outcome resolve(Program program, BankContext ctx,
			FarCallTrampoline.Index index, Instruction site, TaskMonitor monitor)
			throws CancelledException {
		FarCallTrampoline.Outcome out = FarCallTrampoline.Outcome.none();
		Address pointer = IndirectJumpConstantPointer.pointerCell(site);
		if (pointer == null) {
			return out;
		}
		long pLo = pointer.getOffset();
		long pHi = (pLo + 1) & 0xffff;
		if (index.writersOf(pLo).size() == 1 && index.writersOf(pHi).size() == 1) {
			return out; // the write-once variant's, resolved by FarCallTrampoline
		}
		Listing listing = program.getListing();
		// entry: STA shadow / JSR leaf-helper / JMP (P)
		Instruction jsr = FlowEdges.fallThroughPredecessor(listing, site);
		if (jsr == null || !jsr.getPrototype().getFlowType(jsr.getInstructionContext()).isCall()) {
			return out;
		}
		Instruction store = FlowEdges.fallThroughPredecessor(listing, jsr);
		if (store == null || !Character.valueOf('A').equals(MosOperands.storeRegister(store)) ||
			store.getLength() < 2) {
			return out;
		}
		Address[] flows = jsr.getFlows();
		if (flows.length != 1 || !ctx.isLeafBankSwitchHelper(flows[0])) {
			return out;
		}
		Address entry = store.getMinAddress();
		for (Instruction caller : FarCallTrampoline.callSites(program, entry)) {
			monitor.checkCancelled();
			resolveCaller(program, ctx, caller, pLo, pHi, out);
		}
		return out;
	}

	private static void resolveCaller(Program program, BankContext ctx, Instruction caller,
			long pLo, long pHi, FarCallTrampoline.Outcome out) {
		Listing listing = program.getListing();
		List<Instruction> run = new ArrayList<>();
		Instruction cur = FlowEdges.fallThroughPredecessor(listing, caller);
		while (cur != null && run.size() < MAX_CALLER_RUN) {
			run.add(0, cur);
			if (hasJoin(cur)) {
				break;
			}
			cur = FlowEdges.fallThroughPredecessor(listing, cur);
		}
		Val a = null;
		Val x = null;
		Val y = null;
		Map<Long, Val> cells = new HashMap<>();
		for (Instruction i : run) {
			int op = opcode(i);
			int imm = i.getLength() == 2 ? operandByte(i) : -1;
			int abs = i.getLength() == 3 ? operandWord(i) : -1;
			switch (op) {
				case 0xa9 -> a = imm < 0 ? null : Val.of(imm);
				case 0xa2 -> x = imm < 0 ? null : Val.of(imm);
				case 0xa0 -> y = imm < 0 ? null : Val.of(imm);
				case 0xb9 -> a = abs < 0 ? null
						: Val.table(abs, y == null ? null : y.constant());
				case 0x85, 0x8d -> store(cells, i, a);
				case 0x86, 0x8e -> store(cells, i, x);
				case 0x84, 0x8c -> store(cells, i, y);
				default -> {
					if (i.getPrototype().getFlowType(i.getInstructionContext()).isCall()) {
						// a callee may rewrite any register or pointer cell
						a = null;
						x = null;
						y = null;
						cells.clear();
						continue;
					}
					if (FarCallTrampoline.writesRegister(program, i, 'A')) {
						a = null;
					}
					if (FarCallTrampoline.writesRegister(program, i, 'X')) {
						x = null;
					}
					if (FarCallTrampoline.writesRegister(program, i, 'Y')) {
						y = null;
					}
					for (Address w : PcodeShapes.memoryWrites(i)) {
						cells.remove(w.getOffset());
					}
				}
			}
		}
		if (a == null || a.constant() == null) {
			return;
		}
		Pointer p = pointerOf(cells.get(pLo), cells.get(pHi));
		if (p == null) {
			return;
		}
		int bank = a.constant();
		BankState state = ctx.stateForBankValue(bank);
		if (state == null) {
			out.declined().add(new FarCallTrampoline.Declined(caller,
				"far-call bank $" + Integer.toHexString(bank) + " is not a bank of the board"));
			return;
		}
		AddressSpace home = program.getAddressFactory().getDefaultAddressSpace();
		List<Address> targets = new ArrayList<>();
		String failure = null;
		if (p.constant() != null) {
			Address t = ctx.resolveUnder(state, home.getAddress(p.constant()));
			if (t != null && FarCallTrampoline.landsOnJumpEntry(program, t)) {
				targets.add(t);
			}
			else {
				failure = "constant pointer $" + Integer.toHexString(p.constant()) +
					" is not a JMP/JSR entry in bank " + bank;
			}
		}
		else {
			AddressSpace readSpace = caller.getMinAddress().getAddressSpace();
			int first = p.tableY() == null ? 0 : p.tableY();
			int last = p.tableY() == null ? 2 * (MAX_TABLE_ENTRIES - 1) : p.tableY();
			for (int k = first; k <= last; k += 2) {
				Integer w = tableWord(program, readSpace, p.tableBase() + k);
				Address t = w == null ? null : ctx.resolveUnder(state, home.getAddress(w));
				if (t == null || !FarCallTrampoline.landsOnJumpEntry(program, t)) {
					if (targets.isEmpty()) {
						failure = "table entry at $" + Long.toHexString(p.tableBase() + k) +
							" is not a JMP/JSR entry in bank " + bank;
					}
					break; // the first entry that does not corroborate ends the table
				}
				targets.add(t);
			}
		}
		for (Address t : targets) {
			out.placed().add(new FarCallTrampoline.Placement(caller, t));
		}
		if (failure != null && targets.isEmpty()) {
			out.declined().add(new FarCallTrampoline.Declined(caller, failure));
		}
	}

	private static boolean hasJoin(Instruction i) {
		for (Reference ref : i.getProgram().getReferenceManager()
				.getReferencesTo(i.getMinAddress())) {
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	private static Pointer pointerOf(Val lo, Val hi) {
		if (lo == null || hi == null) {
			return null;
		}
		if (lo.constant() != null && hi.constant() != null) {
			return new Pointer((hi.constant() << 8) | lo.constant(), null, null);
		}
		if (lo.tableByteAddr() != null && hi.tableByteAddr() != null &&
			hi.tableByteAddr().equals(lo.tableByteAddr() + 1) &&
			Objects.equals(lo.tableY(), hi.tableY())) {
			return new Pointer(null, lo.tableByteAddr(), lo.tableY());
		}
		return null;
	}

	private static void store(Map<Long, Val> cells, Instruction i, Val v) {
		long cell = i.getLength() == 2 ? operandByte(i) : operandWord(i);
		if (v == null) {
			cells.remove(cell);
		}
		else {
			cells.put(cell, v);
		}
	}

	private static Integer tableWord(Program program, AddressSpace space, long off) {
		try {
			Address lo = space.getAddress(off & 0xffff);
			Address hi = space.getAddress((off + 1) & 0xffff);
			return ((program.getMemory().getByte(hi) & 0xff) << 8) |
				(program.getMemory().getByte(lo) & 0xff);
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	private static int opcode(Instruction i) {
		try {
			return i.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	private static int operandByte(Instruction i) {
		try {
			return i.getByte(1) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	private static int operandWord(Instruction i) {
		try {
			return ((i.getByte(2) & 0xff) << 8) | (i.getByte(1) & 0xff);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}
}
