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

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

/**
 * Pure(ish) logic for grm-j2kl: the "JSR inline jump table" / SMB "JumpEngine" idiom. A
 * subroutine ({@code JMP (P)} through a zero-page pointer {@code P}) pops its OWN return
 * address off the stack and indexes a word table laid out immediately after the {@code JSR}
 * that called it, rather than ever returning to the caller. Ghidra, not knowing this, disassembles
 * the table bytes as ordinary fall-through code and never reaches any of the real targets.
 *
 * <p><b>The dispatcher shape</b> (see the bead for the worked SMB and db3 examples): a bounded,
 * branch-free instruction run that
 * <ol>
 * <li>doubles the dispatch index in {@code A} with a single {@code ASL A} and captures it in
 * {@code Y} with {@code TAY} -- BEFORE it is clobbered by the {@code PLA}s below;</li>
 * <li>pops the just-pushed return address with {@code PLA / STA zp} (low byte) then
 * {@code PLA / STA zp+1} (high byte) -- the two bytes of a pointer {@code loAddr}/{@code loAddr+1}
 * that, at the call site, equals {@code JSR+2};</li>
 * <li>reads {@code LDA (loAddr),Y} at {@code Y = 2*index + 1} and stores it to a zero-page cell
 * {@code p} -- entry {@code index}'s low byte, which sits at {@code JSR+3 + 2*index} (the table
 * immediately after the {@code JSR});</li>
 * <li>increments {@code Y} and repeats the indirect load, storing to {@code p+1} -- the entry's
 * high byte;</li>
 * <li>terminates with {@code JMP (p)} -- the actual dispatch.</li>
 * </ol>
 * Harmless register-save/restore noise (a {@code STY}/{@code STX} before the index is captured,
 * a restoring {@code LDY} after both loads, as in the db3 shape) is tolerated; anything else --
 * in particular a conditional branch, or an inline-ARGUMENT routine that pops, modifies and
 * re-pushes its return address before an {@code RTS} -- is declined.
 *
 * <p><b>Per call site</b> ({@link #tableEntries}), the table right after the {@code JSR} is
 * bounded by the lowest target lying after it, or by the first word that cannot be a target;
 * see {@link #scanTable}.
 *
 * @see <a href="urn:bead:grm-j2kl">grm-j2kl</a>
 */
final class InlineJumpTableDispatch {

	/** "About 24 instructions" per the design: the dispatcher body's straight-line walk budget. */
	private static final int MAX_DISPATCHER_STEPS = 24;

	/** Hard cap on how many table entries a single call site may contribute (design: 128). */
	static final int MAX_TABLE_ENTRIES = 128;

	private InlineJumpTableDispatch() {
	}

	/**
	 * Whether the instructions starting at {@code entry} are conclusively recognized as (or
	 * conclusively NOT) a JSR-inline-jump-table dispatcher body. Returns {@code null} --
	 * inconclusive, do not cache -- if the walk runs off the end of currently disassembled code;
	 * the caller should retry later once more of the program is disassembled.
	 */
	static Boolean recognizeDispatcher(Program program, Address entry) {
		Listing listing = program.getListing();

		int aslCount = 0;
		boolean ySet = false;
		int yOffset = 0;
		int plaCount = 0;
		Address loAddr = null;
		Address hiAddr = null;
		int loadCount = 0;
		Address pAddr = null;
		Integer firstLoadYOffset = null;

		// What the NEXT instruction is required to be, set by PLA / the indirect-Y load.
		final int PENDING_NONE = 0;
		final int PENDING_PLA_STORE = 1;
		final int PENDING_LOAD_STORE = 2;
		int pending = PENDING_NONE;

		Address pc = entry;
		for (int step = 0; step < MAX_DISPATCHER_STEPS; step++) {
			Instruction instr = listing.getInstructionAt(pc);
			if (instr == null) {
				return null; // not (yet) disassembled -- inconclusive
			}
			String mn = instr.getMnemonicString();
			FlowType ft = instr.getFlowType();

			// The terminator: JMP (p), only valid once both bytes of the entry are loaded.
			if (loadCount == 2 && pending == PENDING_NONE && isIndirectJump(instr) &&
				zeroPageIndirectOperand(instr) != null &&
				zeroPageIndirectOperand(instr).equals(pAddr)) {
				return Boolean.TRUE;
			}

			if (ft.isConditional() || ft.isCall()) {
				return Boolean.FALSE;
			}
			if (ft.isJump() || ft.isTerminal()) {
				// Any other jump/return (including a plain JMP, or RTS/RTI as in the distinct
				// inline-ARGUMENT idiom) is not this shape.
				return Boolean.FALSE;
			}

			if (pending == PENDING_PLA_STORE) {
				Address zp = directZeroPageStoreAddress(instr);
				if (!"STA".equals(mn) || zp == null) {
					return Boolean.FALSE;
				}
				if (plaCount == 1) {
					loAddr = zp;
				}
				else { // plaCount == 2
					if (loAddr == null || !zp.equals(loAddr.add(1))) {
						return Boolean.FALSE;
					}
					hiAddr = zp;
				}
				pending = PENDING_NONE;
				pc = instr.getFallThrough();
				continue;
			}
			if (pending == PENDING_LOAD_STORE) {
				Address zp = directZeroPageStoreAddress(instr);
				if (!"STA".equals(mn) || zp == null) {
					return Boolean.FALSE;
				}
				if (loadCount == 0) {
					pAddr = zp;
				}
				else { // loadCount == 1, second (high) byte
					if (pAddr == null || !zp.equals(pAddr.add(1))) {
						return Boolean.FALSE;
					}
				}
				loadCount++;
				pending = PENDING_NONE;
				pc = instr.getFallThrough();
				continue;
			}

			switch (mn) {
				case "ASL":
					if (!isAccumulatorMode(instr) || ySet) {
						return Boolean.FALSE;
					}
					aslCount++;
					break;
				case "TAY":
					if (ySet || aslCount != 1) {
						return Boolean.FALSE;
					}
					ySet = true;
					yOffset = 0;
					break;
				case "INY":
					if (!ySet) {
						return Boolean.FALSE;
					}
					yOffset++;
					break;
				case "DEY":
					if (!ySet) {
						return Boolean.FALSE;
					}
					yOffset--;
					break;
				case "PLA":
					if (loAddr != null && hiAddr == null && plaCount != 1) {
						return Boolean.FALSE; // stray PLA between the pair and its use
					}
					if (plaCount >= 2) {
						return Boolean.FALSE;
					}
					plaCount++;
					pending = PENDING_PLA_STORE;
					break;
				case "LDA": {
					Address indirectBase = indirectIndexedYOperand(instr);
					if (indirectBase == null || hiAddr == null || !indirectBase.equals(loAddr) ||
						!ySet || loadCount >= 2) {
						return Boolean.FALSE;
					}
					if (loadCount == 0) {
						if (yOffset != 1) {
							return Boolean.FALSE;
						}
						firstLoadYOffset = yOffset;
					}
					else { // loadCount == 1
						if (firstLoadYOffset == null || yOffset != firstLoadYOffset + 1) {
							return Boolean.FALSE;
						}
					}
					pending = PENDING_LOAD_STORE;
					break;
				}
				case "STY":
				case "STX": {
					// Harmless register-save noise, only before the index is captured.
					if (ySet || directZeroPageStoreAddress(instr) == null) {
						return Boolean.FALSE;
					}
					break;
				}
				case "LDY": {
					// Harmless restore, only after both loads are done.
					if (loadCount != 2 || directZeroPageLoadAddress(instr) == null) {
						return Boolean.FALSE;
					}
					break;
				}
				default:
					return Boolean.FALSE;
			}

			Address fallThrough = instr.getFallThrough();
			if (fallThrough == null) {
				return Boolean.FALSE;
			}
			pc = fallThrough;
		}
		return Boolean.FALSE; // budget exhausted without reaching JMP (p)
	}

	// ---------------------------------------------------------------------
	// Per call site: bound and read the table right after the JSR.
	// ---------------------------------------------------------------------

	/**
	 * One call site's table scan: how the table was ended and the entries kept. Exposed so the
	 * analyzer can log a per-site line and tests can assert on the cut.
	 */
	static final class CallSiteScan {
		final Address tableStart;
		final Cut cut;
		final List<Address> kept;
		/** Tail entries dropped as implausible (only for {@link Cut#INVALID_WORD}). */
		final List<Address> trimmed;

		private CallSiteScan(Address tableStart, Cut cut, List<Address> kept,
				List<Address> trimmed) {
			this.tableStart = tableStart;
			this.cut = cut;
			this.trimmed = trimmed;
			this.kept = kept;
		}
	}

	/** How a call site's table was ended; see {@link #scanTable}. */
	enum Cut {
		/** The table ran into the lowest target seen so far that lies after the table start. */
		ABOVE_TABLE_TARGET,
		/** The next word is not a usable target (unmapped, RAM/IO, or into the table itself). */
		INVALID_WORD,
		/** Neither happened within {@link #MAX_TABLE_ENTRIES}; the site is declined. */
		DECLINED
	}

	/**
	 * The table entries a {@code JSR} to a recognized dispatcher carries, starting at
	 * {@code jsrAddr + jsr.getLength()} (normally {@code jsrAddr + 3} on 6502), in the JSR's own
	 * address space. Never throws; returns an empty list if nothing usable is found.
	 */
	static List<Address> tableEntries(Program program, Address jsrAddr) {
		Instruction jsr = program.getListing().getInstructionAt(jsrAddr);
		if (jsr == null) {
			return List.of();
		}
		Address tableStart = jsrAddr.add(jsr.getLength());
		return tableEntriesAt(program, tableStart);
	}

	/** As {@link #tableEntries}, but given the table's start address directly (test seam). */
	static List<Address> tableEntriesAt(Program program, Address tableStart) {
		return scanTable(program, tableStart).kept;
	}

	/**
	 * As {@link #tableEntriesAt}, but returns the full {@link CallSiteScan} diagnostics instead of
	 * just the kept entries.
	 *
	 * <p><b>The bound.</b> Words are read in order and the table ends at whichever comes first:
	 * <ul>
	 * <li>the next entry would start at or past the lowest target seen so far that lies after
	 * the table start ({@link Cut#ABOVE_TABLE_TARGET}). JumpEngine tables are laid out
	 * immediately before a handler, so the table ends where that handler begins. Targets BELOW
	 * the table are ignored for this purpose. Handlers routinely sit on both sides of their
	 * table, which is why {@link JumpTableBound#bound}'s {@code LOWEST_TARGET} rule (which
	 * declines as soon as any target is below the table) is not used here: measured on smb it
	 * declined 7 of 12 real tables, all of which this rule bounds exactly -- 921e 3, 92cb 8,
	 * aee2 4, b04f 13, bdc0 9, c282 55 (the enemy-ID table), c892 34;</li>
	 * <li>the next word is not a usable target: unmapped, uninitialized or volatile memory, or
	 * pointing into the table itself ({@link Cut#INVALID_WORD}). smb's 8218 ends this way, at
	 * {@code 00a0} (the {@code LDY #$00} of the next routine), not at a target. Nothing positive
	 * ended such a table, so the words before the invalid one may already be the next routine's
	 * bytes: the tail is trimmed back while its target is implausible ({@link
	 * #plausibleTarget});</li>
	 * <li>otherwise, after {@link #MAX_TABLE_ENTRIES} the site is declined outright ({@link
	 * Cut#DECLINED}, zero entries): nothing ended the table, so no length can be trusted.</li>
	 * </ul>
	 * An earlier draft also stopped at a target falling inside an existing instruction. That is
	 * wrong at this stage: until the call site is repaired, the table's own mis-decode can
	 * straddle a real handler (921e's first target 9224 sits right after the table).
	 */
	static CallSiteScan scanTable(Program program, Address tableStart) {
		AddressSpace space = tableStart.getAddressSpace();
		Memory memory = program.getMemory();

		List<Address> kept = new ArrayList<>();
		List<Address> trimmed = new ArrayList<>();
		long lowestAbove = Long.MAX_VALUE;
		Cut cut = Cut.DECLINED;
		for (int i = 0; i < MAX_TABLE_ENTRIES; i++) {
			long entryOffset = tableStart.getOffset() + 2L * i;
			if (entryOffset >= lowestAbove) {
				cut = Cut.ABOVE_TABLE_TARGET;
				break;
			}
			Address targetAddr = readTarget(memory, space, tableStart, i);
			if (targetAddr == null) {
				cut = Cut.INVALID_WORD;
				break;
			}
			if (targetAddr.getOffset() > tableStart.getOffset()) {
				lowestAbove = Math.min(lowestAbove, targetAddr.getOffset());
			}
			kept.add(targetAddr);
		}
		if (cut == Cut.DECLINED) {
			kept.clear();
		}
		else if (cut == Cut.INVALID_WORD) {
			// Nothing positive ended this table, so its tail may be the following routine's bytes
			// read as words. Over-read entries can only ever be at the tail: trim them from the
			// end. An entry with a plausible target stops the trim, so no entry before it is
			// ever judged.
			while (!kept.isEmpty() && !plausibleTarget(program, kept.get(kept.size() - 1))) {
				trimmed.add(0, kept.remove(kept.size() - 1));
			}
		}
		return new CallSiteScan(tableStart, cut, List.copyOf(kept), List.copyOf(trimmed));
	}

	/** How many instructions {@link #plausibleTarget} decodes before accepting a target. */
	private static final int PLAUSIBLE_DECODE_STEPS = 8;

	/**
	 * Whether {@code target} could be a handler entry: it does not fall strictly inside an
	 * existing instruction or on defined data, and the bytes there decode along fall-through for
	 * {@link #PLAUSIBLE_DECODE_STEPS} instructions (or up to a return/jump) with no undefined
	 * opcode and no {@code BRK}. An existing instruction starting exactly at {@code target} is
	 * accepted outright. Used only on the tail of a table that ended at an invalid word; see
	 * {@link #scanTable}.
	 */
	static boolean plausibleTarget(Program program, Address target) {
		Listing listing = program.getListing();
		if (listing.getInstructionAt(target) != null) {
			return true;
		}
		if (listing.getInstructionContaining(target) != null) {
			return false; // mid-instruction of existing code
		}
		if (listing.getDefinedDataContaining(target) != null) {
			return false;
		}
		PseudoDisassembler dis = new PseudoDisassembler(program);
		Address at = target;
		for (int i = 0; i < PLAUSIBLE_DECODE_STEPS; i++) {
			PseudoInstruction instr;
			try {
				instr = dis.disassemble(at);
			}
			catch (Exception e) {
				return false; // undefined opcode, or bytes run out mid-instruction
			}
			if (instr == null || "BRK".equals(instr.getMnemonicString())) {
				return false;
			}
			FlowType flow = instr.getFlowType();
			if (flow.isTerminal() || (flow.isJump() && !flow.isConditional())) {
				return true;
			}
			at = instr.getFallThrough();
			if (at == null) {
				return true;
			}
		}
		return true;
	}

	/**
	 * Entry {@code i}'s target, or null when that word cannot be a target: unreadable, pointing
	 * into the table itself (up to and including this entry), or landing outside initialized,
	 * non-volatile memory.
	 */
	private static Address readTarget(Memory memory, AddressSpace space, Address tableStart,
			int i) {
		Address entryAddr;
		int lo;
		int hi;
		try {
			entryAddr = tableStart.add(2L * i);
			lo = memory.getByte(entryAddr) & 0xff;
			hi = memory.getByte(entryAddr.add(1)) & 0xff;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
		long target = lo | (hi << 8);
		if (target >= tableStart.getOffset() && target <= entryAddr.getOffset() + 1) {
			return null;
		}
		Address targetAddr = resolveTarget(space, memory, target);
		if (targetAddr == null) {
			return null;
		}
		MemoryBlock block = memory.getBlock(targetAddr);
		if (block == null || !block.isInitialized() || block.isVolatile()) {
			return null;
		}
		return targetAddr;
	}

	/**
	 * Resolves a raw table-entry offset to an {@link Address}, preferring {@code space} (the
	 * table's own address space -- the site's overlay bank, for a table inside a banked window)
	 * but falling back to the underlying physical/base space when {@code space} is itself an
	 * overlay AND has no memory block at that offset. A banked window's overlay space only has a
	 * block over the SWITCHABLE range; an offset landing in the fixed (non-switchable) part of the
	 * address map -- always represented in the base space, exactly like a direct {@code JSR}/
	 * {@code JMP} from that overlay into the fixed bank resolves -- would otherwise look unmapped
	 * purely because it was looked up in the wrong space object, not because it is actually
	 * unreachable. An offset inside the switchable range that resolves to a DIFFERENT bank's copy
	 * is deliberately left alone: that is cross-bank retargeting, explicitly out of scope for this
	 * class (see the class javadoc) and left to the existing machinery (grm-v60).
	 */
	private static Address resolveTarget(AddressSpace space, Memory memory, long target) {
		Address inSpace;
		try {
			inSpace = space.getAddress(target);
		}
		catch (RuntimeException e) {
			return null;
		}
		if (memory.getBlock(inSpace) != null) {
			return inSpace;
		}
		AddressSpace physical = space.getPhysicalSpace();
		if (physical.equals(space)) {
			return inSpace; // not an overlay -- nothing else to try
		}
		try {
			Address inPhysical = physical.getAddress(target);
			return memory.getBlock(inPhysical) != null ? inPhysical : inSpace;
		}
		catch (RuntimeException e) {
			return inSpace;
		}
	}

	// ---------------------------------------------------------------------
	// Small instruction-shape helpers (raw opcode bytes, like IndirectJumpConstantPointer's).
	// ---------------------------------------------------------------------

	private static boolean isAccumulatorMode(Instruction instr) {
		return opcodeByte(instr) == 0x0a; // ASL A
	}

	/** {@code JMP} with the plain absolute-indirect operand (opcode {@code 0x6c}). */
	private static boolean isIndirectJump(Instruction instr) {
		return "JMP".equals(instr.getMnemonicString()) && opcodeByte(instr) == 0x6c;
	}

	/** The pointer cell of a {@code JMP ($nnnn)}, when that cell is a zero-page address
	 *  (high byte zero) -- null otherwise (not zero page, or not readable). */
	private static Address zeroPageIndirectOperand(Instruction instr) {
		Address a = absoluteOperand(instr);
		return (a != null && a.getOffset() <= 0xff) ? a : null;
	}

	/** {@code STA $nn} (direct zero-page, opcode {@code 0x85}) -- the store address, or null. */
	private static Address directZeroPageStoreAddress(Instruction instr) {
		if (!"STA".equals(instr.getMnemonicString()) || opcodeByte(instr) != 0x85) {
			// also allow STY $nn (0x84) / STX $nn (0x86) for the harmless-save case
			int op = opcodeByte(instr);
			String mn = instr.getMnemonicString();
			if (("STY".equals(mn) && op == 0x84) || ("STX".equals(mn) && op == 0x86)) {
				return zeroPageOperand(instr);
			}
			return null;
		}
		return zeroPageOperand(instr);
	}

	/** {@code LDY $nn} (direct zero-page, opcode {@code 0xa4}) -- the load address, or null. */
	private static Address directZeroPageLoadAddress(Instruction instr) {
		if (!"LDY".equals(instr.getMnemonicString()) || opcodeByte(instr) != 0xa4) {
			return null;
		}
		return zeroPageOperand(instr);
	}

	/** {@code LDA ($nn),Y} (indirect indexed, opcode {@code 0xb1}) -- the zero-page base address
	 *  (i.e. {@code $nn}), or null. */
	private static Address indirectIndexedYOperand(Instruction instr) {
		if (!"LDA".equals(instr.getMnemonicString()) || opcodeByte(instr) != 0xb1) {
			return null;
		}
		return zeroPageOperand(instr);
	}

	private static Address zeroPageOperand(Instruction instr) {
		try {
			if (instr.getLength() != 2) {
				return null;
			}
			int zp = instr.getByte(1) & 0xff;
			return instr.getMinAddress().getAddressSpace().getAddress(zp);
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/** The raw 16-bit absolute operand of a 3-byte instruction (e.g. {@code JMP ($nnnn)}). */
	private static Address absoluteOperand(Instruction instr) {
		try {
			if (instr.getLength() != 3) {
				return null;
			}
			int lo = instr.getByte(1) & 0xff;
			int hi = instr.getByte(2) & 0xff;
			return instr.getMinAddress().getAddressSpace().getAddress((hi << 8) | lo);
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	private static int opcodeByte(Instruction instr) {
		try {
			return instr.getByte(0) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}
}
