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
 * true. It is also the one case where an <em>indexed</em> store cannot be judged from its
 * operand alone -- see the soundness ruling on {@link #operandStoresInRange}.
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

	/**
	 * Whether {@code instr} writes into this latch's range -- the mechanism-write predicate.
	 * Two tiers, tried in order (grm-3x1):
	 * <ol>
	 * <li><b>Write references.</b> Authoritative when present: a reference names the
	 * <em>resolved</em> target, so an indexed store whose base+index constant propagation
	 * pinned down is tested at its true address, decode predicate included. The range test
	 * accepts an overlay over the code space as well as the code space itself -- a latch store
	 * executing from inside a {@code PRG_LO_B<n>} window gets its write reference in that
	 * overlay's space, and used to be skipped for it.</li>
	 * <li><b>Operand decode</b> ({@link #operandStoresInRange}). References are not always
	 * there to be had: a 6502 indexed operand's base arrives as a {@code Scalar}, so
	 * {@code CodeManager} lays down no default operand reference at disassembly time, and
	 * const-prop -- the only thing that would supply one later -- covers function bodies
	 * only. The canonical UxROM bus-conflict switch is exactly that shape
	 * ({@code LDA #n / TAX / STA banktable,X}), and measurement (grm-2yx probe) found refless
	 * plain-absolute stores too, in code const-prop never reached. Tier 1 alone therefore
	 * misses live switch sites in real ROMs (contra, dragonpower, wizwarr, megaman).</li>
	 * </ol>
	 */
	private boolean writesInRange(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && inLatchRange(to) &&
				matchesDecode(to.getOffset())) {
				return true;
			}
		}
		return operandStoresInRange(instr);
	}

	/**
	 * Tier 2 of {@link #writesInRange}: read the store's target straight off its operand,
	 * for the stores that carry no write reference at all.
	 * <p>
	 * Gated on {@link StoredValueScanner#storeRegister} being non-null, i.e. a true
	 * {@code STA}/{@code STX}/{@code STY}. The read-modify-write stores ({@code INC $8000}
	 * and friends) keep tier-1-only behaviour deliberately: {@code computeSwitch} answers
	 * {@link BankState#unknown()} for them, so newly <em>seeing</em> one would poison bank
	 * state rather than recover it -- a reachability fix must not widen into that.
	 * <p>
	 * <b>Soundness: an indexed operand under an {@code addr_mask} declines.</b> Tier 2 knows
	 * only the base, and {@code base & 0x0F} says nothing whatever about
	 * {@code (base + X) & 0x0F}. On Bandai FCG that is the difference between the PRG bank
	 * register and an IRQ register sharing the same range -- claiming a match would latch
	 * {@code prg_bank} off an IRQ write, precisely what {@code addr_mask} exists to prevent.
	 * Declining under-reports, which is this predicate's pre-existing failure mode and is
	 * safe; answering {@link BankState#unknown()} instead would be a fresh source of WARNINGs
	 * across the Bandai titles as a side effect of a fix aimed elsewhere.
	 * <p>
	 * Only the base is range-tested, never {@code base + 0xFF}: the canonical bank table sits
	 * at the very top of the range (Contra's {@code STA $FFD0,X}), so requiring the whole
	 * indexed span to fit would reject the exact idiom this tier exists to catch.
	 */
	private boolean operandStoresInRange(Instruction instr) {
		if (StoredValueScanner.storeRegister(instr) == null) {
			return false;
		}
		Address target = StoredValueScanner.plainAbsoluteTarget(instr);
		if (target != null) {
			return inLatchRange(target) && matchesDecode(target.getOffset());
		}
		Address base = LoopIdioms.indexedBase(instr);
		if (base == null || addrMask != 0) {
			return false; // see the soundness ruling above
		}
		return inLatchRange(base);
	}

	/**
	 * Whether {@code addr} falls in {@code [rangeStart, rangeEnd]} of this program's code
	 * space. An overlay over the default space counts: on a banked machine a latch store
	 * executing from inside a {@code PRG_LO_B<n>} window names its target in that overlay's
	 * space, and it is the same physical bus address either way.
	 */
	private boolean inLatchRange(Address addr) {
		if (!addr.getAddressSpace().getPhysicalSpace().equals(space)) {
			return false;
		}
		long offset = addr.getOffset();
		return offset >= rangeStart && offset <= rangeEnd;
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
