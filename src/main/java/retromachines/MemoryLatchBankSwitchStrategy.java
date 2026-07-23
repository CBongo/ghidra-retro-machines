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

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

/**
 * The {@code memory-latch} mechanism class (vision doc §5.2): a store <em>anywhere</em>
 * in a declared address range latches the bank -- the write goes to a mapper register,
 * not to the ROM that occupies those addresses (NES discrete mappers UxROM/AxROM/CNROM/
 * GxROM/BNROM; GB MBC coarse registers and the SMS Sega mapper are the same shape).
 * Params: {@code start}/{@code end} (the latch range), {@code mask} (field bits after
 * shifting), {@code shift} (bit position of the field within the written byte, e.g. 4
 * for GxROM's PRG bits 4-5), {@code bus_conflict} (see below).
 * <p>
 * <b>Address-decode predicate</b> (optional {@code addr_mask}/{@code addr_match}): a
 * register-file board mirrors several independent registers across one address range and
 * decodes <em>which</em> register a write hits from low address bits, not from the data
 * value. Bandai's FCG/LZ93D50 (iNES mappers 16/157/159) is the shipped example: the mapper
 * decodes only the write address's low nibble ({@code A & 0x0F}), where nibble {@code 0x8}
 * is the 16 KiB PRG bank register and nibbles {@code 0-7}/{@code 9-D} are CHR/mirroring/IRQ
 * registers that must NOT disturb the PRG bank. When {@code addr_mask} is present, a write
 * latches only if {@code (offset & addr_mask) == addr_match} -- so one mechanism can own the
 * PRG register while ignoring every sibling register sharing the same {@code [start,end]}
 * range (those sibling writes still get {@code on_write: mechanism} at the window level, so
 * they are not misread as ROM writes; they simply are not <em>this</em> latch). Absent (the
 * discrete-mapper default: UxROM/AxROM/CNROM/GxROM/BNROM), any write in range latches,
 * exactly as before. The predicate is purely address-based, so {@link #cacheable()} stays
 * true.
 * <p>
 * Differences from {@code register-write} injected via {@link StoredValueScanner.Hooks}:
 * <ul>
 * <li>The latch is write-only -- reading a latch-range address reads the underlying ROM
 * byte, never the bank state. So a non-immediate {@code LD<reg>} resolves not to the
 * tracked in-state but to the ROM byte itself, when the load target is a single constant
 * address inside a non-writable initialized block that is <em>bank-invariant</em> (no
 * overlay block shadows that offset -- i.e. a fixed window, not a switchable one whose
 * base-space content is just the home bank).</li>
 * <li>{@code bus_conflict: true} models boards without bus isolation, where the
 * effective latched value is the CPU-driven byte AND the ROM byte at the written
 * address. When the store target is constant and bank-invariant ROM, the recovered
 * value is ANDed with that byte -- each 0 bit in the ROM byte becomes a <em>known</em>
 * 0 regardless of what the CPU drove. Indexed stores (the classic
 * {@code STA banktable,X} idiom) have no static target, so no AND is applied; correct
 * games guarantee driven value == ROM byte there anyway, so the recovered driven value
 * is already the effective one.</li>
 * </ul>
 * Field positioning: this strategy always deposits the recovered field at bits
 * {@code [0, width)} of its own field-local coordinate space (via {@code shift}/
 * {@code mask} above, which describe the field's position within the <em>written
 * byte</em>, not the board's state int). {@link BoardBankAnalyzer} then repositions that
 * field-local result into the board's absolute state bits, using the mechanism's
 * {@code sets} field-name list in the descriptor to work out where the field(s) it
 * writes actually sit in {@code banking.state} (their union must form one contiguous bit
 * run). The mechanism no longer needs its {@code sets} field to be first in
 * {@code banking.state} -- a board with multiple latches (e.g. GB MBC's ROM+RAM bank
 * registers, or a bank latch plus a separate mode latch) is supported as long as each
 * mechanism's own fields are contiguous.
 */
public class MemoryLatchBankSwitchStrategy implements BankSwitchStrategy {

	private AddressSpace space;
	private long rangeStart;
	private long rangeEnd;
	private int mask;
	private int shift;
	private boolean busConflict;

	/**
	 * Optional address-decode predicate for register-file boards (see class javadoc): when
	 * {@code addrMask != 0}, a write latches only if {@code (offset & addrMask) == addrMatch}.
	 * {@code addrMask == 0} (the default when the descriptor omits {@code addr_mask}) means
	 * "no predicate" -- any write in {@code [rangeStart, rangeEnd]} latches, as before.
	 */
	private long addrMask;
	private long addrMatch;

	/**
	 * Base-space shadow of every overlay memory block, snapshotted at {@link #configure}
	 * time (an efficiency memoization for {@link #bankInvariantRomByte} -- see grm-5tl.13.1).
	 * Loader-placed memory blocks are fixed before analyzers run and phase 2 of the engine
	 * never adds blocks, so a snapshot taken here is valid for this strategy instance's
	 * entire lifetime on this program. Each overlay block {@code b} contributes the base-space
	 * range {@code [b.getStart().getOffset(), b.getEnd().getOffset()]} -- i.e. the same raw
	 * offset comparison the original per-call linear scan performed, just precomputed into an
	 * interval set instead of walking every block on every query.
	 */
	private AddressSet overlayCoveredRanges;

	@Override
	public String strategyName() {
		return "memory-latch";
	}

	/**
	 * {@code computeSwitch}'s {@code resolveLoad} hook resolves loads to a bank-invariant
	 * ROM byte (a property of the program alone), never to {@code inStateAtStore}; the only
	 * other place a base value can come from is {@link StoredValueScanner}'s own immediate-
	 * value folding, also state-independent. So the whole result is a pure function of
	 * {@code (program, instr)} -- safe to cache per address (grm-5tl.13.2).
	 */
	@Override
	public boolean cacheable() {
		return true;
	}

	@Override
	public void configure(Program program, JsonObject params, int stateMask) {
		space = program.getAddressFactory().getDefaultAddressSpace();
		rangeStart = params.get("start").getAsLong();
		rangeEnd = params.get("end").getAsLong();
		mask = params.has("mask") ? params.get("mask").getAsInt() : stateMask;
		shift = params.has("shift") ? params.get("shift").getAsInt() : 0;
		busConflict = params.has("bus_conflict") && params.get("bus_conflict").getAsBoolean();
		addrMask = params.has("addr_mask") ? params.get("addr_mask").getAsLong() : 0;
		addrMatch = params.has("addr_match") ? params.get("addr_match").getAsLong() : 0;

		overlayCoveredRanges = new AddressSet();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (b.getStart().getAddressSpace().isOverlaySpace()) {
				overlayCoveredRanges.addRange(space.getAddress(b.getStart().getOffset()),
					space.getAddress(b.getEnd().getOffset()));
			}
		}
	}

	private final StoredValueScanner.Hooks hooks = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return writesInRange(instr);
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, BankState inStateAtStore) {
			// The ROM byte a plain absolute load reads is a compile-time constant when
			// nothing can rebank it out from under us.
			Address target = StoredValueScanner.plainAbsoluteTarget(loadInstr);
			Integer romByte = target == null ? null
					: bankInvariantRomByte(loadInstr.getProgram(), target);
			return romByte == null ? null : BankState.fullyKnown(0xFF, romByte);
		}
	};

	@Override
	public BankState computeSwitch(Program program, Instruction instr, BankState inState) {
		if (!writesInRange(instr)) {
			return null;
		}

		Character reg = StoredValueScanner.storeRegister(instr);
		if (reg == null) {
			return BankState.unknown();
		}
		BankState stored =
			StoredValueScanner.resolveStoredValue(program, instr, reg, inState, 0xFF, hooks);

		if (busConflict) {
			Address target = StoredValueScanner.plainAbsoluteTarget(instr);
			Integer romByte = target == null ? null : bankInvariantRomByte(program, target);
			if (romByte != null) {
				// effective = driven AND rom: rom's 0 bits are known 0 whatever was driven
				stored = new BankState(stored.knownMask() | (~romByte & 0xFF),
					stored.bits() & romByte);
			}
		}

		// deposit the extracted field at state bits [0, width) -- see class javadoc
		return new BankState((stored.knownMask() >> shift) & mask,
			(stored.bits() >> shift) & mask);
	}

	private boolean writesInRange(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && to.getAddressSpace().equals(space) &&
				to.getOffset() >= rangeStart && to.getOffset() <= rangeEnd &&
				matchesDecode(to.getOffset())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The register-file address-decode predicate (class javadoc): true unless an
	 * {@code addr_mask} is configured and this write's low address bits do not select the
	 * register this mechanism owns. With no {@code addr_mask} (discrete mappers) every
	 * in-range write matches.
	 */
	private boolean matchesDecode(long offset) {
		return addrMask == 0 || (offset & addrMask) == addrMatch;
	}

	/**
	 * The byte at {@code addr} when it is guaranteed load-time constant: inside a
	 * non-writable initialized base-space block with no overlay block shadowing the same
	 * offset (an overlay there means the base content is merely the home bank of a
	 * switchable window). Returns {@code null} when any of that fails.
	 */
	private Integer bankInvariantRomByte(Program program, Address addr) {
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || block.isWrite() || !block.isInitialized()) {
			return null;
		}
		// Normalize to a base-space address first: the interval set holds base-space
		// shadows, but the pre-index code compared raw offsets, so an overlay-space addr
		// covered by any overlay block (its own included) must still be refused here.
		if (overlayCoveredRanges.contains(space.getAddress(addr.getOffset()))) {
			return null;
		}
		try {
			return program.getMemory().getByte(addr) & 0xFF;
		}
		catch (Exception e) {
			return null;
		}
	}
}
