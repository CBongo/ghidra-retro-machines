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
 * 0 regardless of what the CPU drove. An <em>indexed</em> store (the classic
 * {@code STA banktable,X} idiom) has a static target too whenever its index register
 * resolves to a constant ({@link StoredValueScanner#effectiveOperandTarget}, grm-hum), and
 * the AND applies there exactly as it does to an absolute store -- which is how Mega Man's
 * {@code STA $C000,Y} is pinned to bank 0 even though the driven value itself is
 * unrecoverable. Only a still-unresolvable index gets no AND; there the old justification
 * still holds, since correct games guarantee driven value == ROM byte at a bus-conflict
 * board, so the recovered driven value is already the effective one.</li>
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
	 * value folding, also state-independent. Effective-address resolution (grm-hum) reads only
	 * instructions, operands and bank-invariant ROM bytes, and is handed
	 * {@link RegisterEnv#NONE} plus a {@link BankState#unknown()} in-state by construction. So
	 * the whole result stays a pure function of {@code (program, instr)} -- safe to cache per
	 * address (grm-5tl.13.2).
	 * <p>
	 * <b>Tripwire.</b> If any future change routes a real {@link RegisterEnv} into
	 * {@link #computeSwitch}, or makes {@code resolveLoad} state-dependent (a bank-identifying
	 * read-back would), this <b>must</b> become {@code false}: {@code BoardBankAnalyzer}'s
	 * {@code matchCache} is keyed by address alone (:611-639), so it would hand back an
	 * env-free result for an env-bearing query. {@link RegisterWriteBankSwitchStrategy} is the
	 * precedent for how a state-dependent strategy behaves. Note the helper path of grm-hum
	 * increment 2 ({@link #depositHelperArgument}, which really does evaluate under a caller's
	 * {@link RegisterEnv}) does <em>not</em> trip it, and this was re-checked when it landed: it
	 * calls {@link #evaluateLatch} directly, never through {@link #computeSwitch} and never
	 * through {@code matchCache}, and its result is consumed only as that one call site's
	 * effect. {@link #computeSwitch} itself still passes {@link RegisterEnv#NONE}
	 * unconditionally.
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
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			// The ROM byte a load with a statically certain target reads is a compile-time
			// constant when nothing can rebank it out from under us. The target is whatever
			// the scanner resolved -- plain absolute, or absolute-indexed with a constant
			// index (grm-hum); this hook deliberately does not re-derive it.
			Integer romByte = resolvedTarget == null ? null
					: bankInvariantRomByte(loadInstr.getProgram(), resolvedTarget);
			return romByte == null ? null : BankState.fullyKnown(0xFF, romByte);
		}
	};

	@Override
	public BankState computeSwitch(Program program, Instruction instr, BankState inState) {
		if (!writesInRange(instr)) {
			return null;
		}
		// RegisterEnv.NONE, always -- see cacheable()'s tripwire.
		return evaluateLatch(program, instr, RegisterEnv.NONE);
	}

	/**
	 * The latch semantics themselves, given that {@code store} <em>is</em> a mechanism write:
	 * recover the stored byte, apply the bus-conflict AND, and deposit the field at state bits
	 * {@code [0, width)}.
	 * <p>
	 * Split out of {@link #computeSwitch} (everything but its {@link #writesInRange} gate) so
	 * that grm-hum increment 2's helper path -- which knows a call site's register values and
	 * must re-evaluate the helper's switch site under them -- reuses this verbatim instead of
	 * reimplementing "what does this store latch?" against
	 * {@code BoardBankAnalyzer.recoverCallArgument}'s weaker "the register holds the field
	 * value verbatim" convention. The direct path and the helper path therefore cannot drift.
	 * {@link #depositHelperArgument} is that helper path; {@code env} is
	 * {@link RegisterEnv#NONE} for every direct-path call.
	 * <p>
	 * {@link BankState#unknown()} is passed as the scanner's in-state rather than a caller's:
	 * this strategy's {@code resolveLoad} never consults it (the latch is write-only, so a load
	 * in range reads ROM, not bank state), so this is behavior-identical and makes the purity
	 * {@link #cacheable()} claims structural rather than incidental.
	 */
	private BankState evaluateLatch(Program program, Instruction store, RegisterEnv env) {
		Character reg = StoredValueScanner.storeRegister(store);
		if (reg == null) {
			return BankState.unknown();
		}
		BankState stored = StoredValueScanner.resolveStoredValue(program, store, reg,
			BankState.unknown(), 0xFF, hooks, env);

		if (busConflict) {
			Address target = StoredValueScanner.effectiveOperandTarget(program, store, hooks, env);
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
	 * <b>Mini-inlines the helper</b> (grm-hum increment 2): re-runs this latch's real switch
	 * semantics at {@code switchSite} under the calling site's registers, rather than accepting
	 * {@code argValue}'s convention that the helper's argument register already holds the
	 * field value verbatim.
	 * <p>
	 * {@code argValue} is deliberately <b>ignored</b>. That convention is wrong here in two
	 * ways this override fixes: it skips {@code shift}/{@code mask} extraction, so it
	 * misreports any board whose field is not at bit 0 of the written byte; and it skips the
	 * bus-conflict AND, so a bus-conflict board called with a variable argument reports the
	 * driven value rather than the effective one. It is also blind to the argument arriving in
	 * a register other than the one the mechanism write happens to store -- Contra's helper
	 * ({@code LDA $FFD0,Y / STA $FFD0,Y / RTS}) takes its bank in <b>Y</b>, but
	 * {@code findHelpers} necessarily records the {@code STA}'s register, {@code A}. Handing
	 * {@link #evaluateLatch} all three of A/X/Y and letting its demand-driven backward scan
	 * pull whichever it needs sidesteps the question entirely -- no input-register discovery
	 * is required.
	 * <p>
	 * {@code ownedMask} is the whole {@code stateMask}: memory-latch has exactly one switch
	 * site per helper committing one field spanning its entire field-local width, so a call
	 * really does replace all of it -- known or not, exactly as the inherited default does.
	 * <p>
	 * <b>Evaluation only. There is deliberately no convention fallback</b> -- grm-6pi removed the
	 * one grm-hum added, because the assumption underneath it is false on a real cartridge and was
	 * producing confident wrong answers.
	 * <p>
	 * The convention says "the argument register holds the field value verbatim". That is a claim
	 * about a <em>particular site</em> -- the one that commits the argument. But this method is
	 * handed {@code switchSite}, which {@code findHelpers} defines as the last recognized write on
	 * the path to the helper's RETURN. In a switch/call/restore trampoline those are two different
	 * instructions, and the convention then describes neither the right value nor the right point
	 * in time. Ironsword's {@code FUN_ffc0}, transcribed byte-exact from the
	 * pinned dump:
	 * <pre>
	 *   FFC0: STY $C1 / STA $C3   ; save the target-pointer low byte and the bank argument
	 *   FFC4: LDA $C5 / PHA       ; save the CURRENT bank shadow on the stack
	 *   FFC7: AND #$18            ; keep the untracked VRAM bits
	 *   FFC9: ORA $C3             ; splice the requested bank into bits 0-2
	 *   FFCB: STA $C5
	 *   FFCD: STA $8000           ; COMMIT -- switch to the requested bank
	 *   FFD0: JSR $FFDA           ; -> JMP ($00C1): run the target routine IN that bank
	 *   FFD3: PLA / STA $C5
	 *   FFD6: STA $8000           ; RESTORE -- the saved shadow goes back
	 *   FFD9: RTS
	 * </pre>
	 * The requested bank is live only for the inner {@code JSR $FFDA}. By the time the caller
	 * resumes, {@code $FFD6} has put the old bank back -- so a call site's effect on the caller's
	 * own state is <em>no change</em>, and {@code argValue} is the one answer that is definitely
	 * wrong. {@code switchSite} is {@code $FFD6}, correctly; it is unrecoverable only because its
	 * value arrives via {@code PLA}.
	 * <p>
	 * <b>Measured (grm-6pi), and it is not a close call.</b> Callers set the shadow explicitly
	 * before calling -- {@code $80AB LDA #$00 / STA $C5} then {@code LDA #$07 / JSR $FFC0}, and
	 * {@code $D680 LDA #$00 / STA $C5} then {@code LDA #$01 / JSR $FFC0} -- so the restore
	 * genuinely returns bank 0, not the requested bank. With the fallback in place the engine
	 * annotated "bank -&gt; 7" and retargeted the following calls into bank 7's overlay. The ROM
	 * bytes at those targets settle it:
	 * <pre>
	 *   $8C4B bank 0: a5 00 29 7f 8d 00 20 ...  LDA $00 / AND #$7F / STA $2000   -- code
	 *   $8C4B bank 7: 82 30 82 00 52 30 52 ...                                   -- graphics data
	 *   $E530 bank 0: ad 02 20 a9 10 8d 00 20   LDA $2002 / LDA #$10 / STA $2000 -- code
	 *   $E530 bank 3: aa 10 65 5a b5 02 33 ...                                   -- graphics data
	 * </pre>
	 * The engine's own output contradicted itself too: {@code $E91D JSR $E530} resolved in base
	 * space while {@code $D571 JSR $E530} was retargeted into bank 3 -- the same routine placed in
	 * two banks, one of them data. Removing the fallback dropped {@code instrs.inOverlay} from 55
	 * to 0: every one of those 55 instructions had been disassembled out of graphics data.
	 * <p>
	 * So when evaluation pins nothing down, <b>decline</b>: deposit unknown, which raises the
	 * ordinary "bank state becomes unknown here" warning and leaves references to resolve against
	 * {@code initial_state}. That is grm-hum's own prescription for this situation -- "losing 78
	 * refs beats shipping a wrong bank" -- applied to the case it did not recognize it was in.
	 * Nothing else measured depended on the fallback: Contra is recovered by evaluation (its
	 * argument is in {@code Y}, which the convention cannot see anyway), and Mega Man by tail-call
	 * composition; every other pinned title and every synthetic golden is byte-identical.
	 * <p>
	 * <b>Unknown is honest, not optimal.</b> The true post-call effect here is "unchanged", which
	 * {@link HelperDeposit} can already express as {@code ownedMask = 0}. Claiming it requires
	 * verifying the save/restore pair, i.e. pairing the {@code PHA} at {@code $FFC6} with the
	 * {@code PLA} at {@code $FFD3} -- grm-mej.3. Until then, declining is the sound answer and
	 * asserting no-op would be another guess.
	 * <p>
	 * <b>This is not a caching path.</b> It calls {@link #evaluateLatch} directly, never
	 * {@link #computeSwitch} and never {@code BoardBankAnalyzer}'s address-keyed
	 * {@code matchCache}, which is why {@link #cacheable()} can stay {@code true} while an
	 * env-bearing evaluation exists at all. The result is used for this one call site's
	 * {@code CallEffect} and is never attributed to {@code switchSite}.
	 */
	@Override
	public HelperDeposit depositHelperArgument(Program program, Instruction switchSite,
			BankState argValue, BankState inState, int stateMask, RegisterEnv callerRegs) {
		// argValue is unused on purpose -- see the javadoc. Evaluation is the only model here;
		// when it pins nothing down the deposit is unknown, which warns rather than guesses.
		BankState evaluated = evaluateLatch(program, switchSite, callerRegs);
		return new HelperDeposit(stateMask,
			new BankState(evaluated.knownMask() & stateMask, evaluated.bits() & stateMask));
	}

	/**
	 * {@code false}: the override above ignores {@code argValue} entirely, so this strategy is
	 * immune to the stale-argument hazard {@code BoardBankAnalyzer}'s prologue guard exists for
	 * -- and must be exempted from it, because the guard would otherwise forfeit the answers
	 * this mini-inline was built to produce (grm-mu7).
	 * <p>
	 * <b>Contra is the case that makes this load-bearing rather than a micro-optimization.</b>
	 * Its helper is {@code LDA $FFD0,Y / STA $FFD0,Y}, whose prologue writes A -- the exact
	 * shape the guard declines on. Here that write is not a hazard but the mechanism itself:
	 * {@link #evaluateLatch}'s backward scan starts at {@code switchSite} and walks straight
	 * through the {@code LDA}, resolving the ROM table read under the caller's own Y. A guard
	 * that fired here would turn a correct bank into no bank.
	 * <p>
	 * The general reason it is safe: this strategy never trusts a value recovered in the
	 * CALLER, so no assumption about what survives the prologue is being made. It re-derives
	 * the value INSIDE the helper, where a clobbering prologue is simply part of the code the
	 * scan reads -- and where a genuinely unresolvable one (Bionic Commando's
	 * {@code LDA $65}, reading RAM) comes back {@link BankState#unknown()} on its own merits.
	 * <p>
	 * Keep this in sync with {@link #depositHelperArgument} above: if that override ever grows
	 * a path that reads {@code argValue}, this must go back to the default {@code true}.
	 */
	@Override
	public boolean consumesHelperArgument() {
		return false;
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
	 * misses live switch sites in real ROMs (contra, dragonpower, ironsword, megaman).</li>
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
	 * <p>
	 * <b>Deliberately still {@link StoredValueScanner#plainAbsoluteTarget}, not
	 * {@link StoredValueScanner#effectiveOperandTarget}</b> (grm-hum increment 1). The ruling
	 * above does evaporate for an indexed store whose index resolves to a constant -- there
	 * {@code (base + X) & 0x0F} <em>is</em> statically known, so the decode predicate could be
	 * applied exactly. Acting on that would newly latch (or newly decline) Bandai FCG register
	 * writes and so puts the four Bandai real-ROM goldens in play, for no benefit to the UxROM
	 * titles this bead is about. Left as a follow-up (grm-hum bead F); the current behavior is
	 * the safe under-reporting direction either way.
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
