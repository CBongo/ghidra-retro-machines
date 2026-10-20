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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import retromachines.SaveSlotForwarding.IndexRegs;
import retromachines.SaveSlotForwarding.SlotWrite;

import static retromachines.SaveSlotForwarding.RETURN_DISPATCH_LOOKBACK;
import static retromachines.CrossBlockStackPairing.crossBlockMatchingPush;
import static retromachines.CrossBlockStackPairing.findMatchingPush;
import static retromachines.LocalStoreForwarding.forwardedStoreValue;
import static retromachines.LocalStoreForwarding.operandByte;
import static retromachines.CrossBlockStackPairing.pairedArms;
import static retromachines.SaveSlotForwarding.saveSlotForwarded;

/**
 * The 6502-family backward "mask algebra" scan shared by the store-recognizing
 * {@link BankSwitchStrategy} implementations: given a {@code ST<reg>} instruction,
 * determine (with per-bit confidence) the value it stores.
 * <p>
 * Walking backward from the store within its straight-line basic block, we maintain
 * {@code (aAcc, oAcc)} such that the stored value equals {@code (x & aAcc) | oAcc},
 * where {@code x} is the register's value before the earliest instruction examined so
 * far. Stepping back over:
 * <ul>
 * <li>{@code AND #imm} (register A only) composes {@code aAcc = imm & aAcc}.</li>
 * <li>{@code ORA #imm} (register A only) composes {@code oAcc = (imm & aAcc) | oAcc}.</li>
 * <li>{@code LDA/LDX/LDY #imm} into the matching register fully resolves {@code x}, so
 * the scan folds it through the accumulator and stops.</li>
 * <li>A non-immediate {@code LD<reg>} is offered to the strategy's
 * {@link Hooks#resolveLoad}, together with the single address it reads when that is
 * statically certain ({@link #effectiveOperandTarget}: plain absolute/zero-page, or
 * absolute-indexed with a constant-resolvable index). Register-write resolves a read-back
 * of its own mechanism register to the tracked in-state; memory-latch resolves a load of a
 * bank-invariant ROM byte to that byte. When no strategy claims the load,
 * {@link LocalStoreForwarding#forwardedStoreValue} tries local store-to-load forwarding (below), and only if
 * THAT comes back empty is the load offered to {@link Hooks#resolveMirrorLoad} (bead
 * grm-mej.2). An otherwise unresolved load leaves {@code x} wholly unknown.</li>
 * <li><b>Local store-to-load forwarding</b> (grm-mej.1): a load, or a non-immediate
 * {@code AND}/{@code ORA} operand, whose target is statically certain is answered from the
 * nearest preceding store to that same cell <em>within the same basic block</em>, by
 * recursing into this very scan on that store. This is what lets a helper that stashes its
 * register argument in memory and splices it back in be <em>derived</em> rather than assumed
 * -- Ironsword's {@code STA $C3 ... ORA $C3 / STA $8000}, quoted in
 * {@link MemoryLatchBankSwitchStrategy}'s {@code depositHelperArgument}. The forwarding is
 * deliberately <b>not</b> restricted to the zero page: the measured examples happen to live
 * there, but Contra's save slots are {@code $07EC}/{@code $07ED}, and
 * {@link MosOperands#plainAbsoluteTarget} already treats zero-page and absolute operands identically.
 * If anything the zero page is the <em>worse</em>-supported case, since zero-page indexed
 * wraps inside the page and {@link #effectiveOperandTarget} therefore declines it.</li>
 * <li>{@code PLA} (register A only) is paired to the {@code PHA} it pops, BY STACK DEPTH rather
 * than address, over an intra-block straight-line walk (grm-mej.3 increment 2, see
 * {@link CrossBlockStackPairing#findMatchingPush}). Once found, the scan continues from the instruction before that
 * {@code PHA} with the accumulators intact, so composition after the pop (e.g. {@code PLA / AND
 * #imm / STA}) still applies. A {@code PLA} paired to a {@code PHP} (a status byte, never a
 * value), one with no matching push in range, or one separated from its push by ANY control
 * flow all leave {@code x} wholly unknown, exactly like the fallback below.</li>
 * <li>A STACK-RELATIVE RELOAD -- {@code LD<reg> $01nn,X} following a {@code TSX} -- reads a byte
 * pushed earlier WITHOUT popping it, the idiom 6502 code uses when a stack-passed value is
 * needed MORE THAN ONCE (bead grm-4bgh.1; River City Ransom's {@code FUN_fed1}: {@code PHA / TXA
 * / PHA / ... / TSX / LDA $0102,X} reads the FIRST push again, having already consumed it once
 * via a pop-free reload rather than a {@code PLA}). See {@link #stackRelativePush} for the
 * address arithmetic and the soundness window it enforces between the {@code TSX} and the
 * load.</li>
 * <li>Any other instruction that modifies the register (transfers, ADC/SBC, shifts,
 * INC/DEC, EOR#imm -- deliberately not modeled bit-wise) is opaque to the mask algebra. Before
 * giving up on it, the scan asks {@link #constantRegisterValue} -- the separate ALL-OR-NOTHING
 * evaluator, which does model those forms exactly -- whether the register is nevertheless a
 * known constant at that point, and adopts a non-null answer as a fully known base (bead
 * grm-4bgh.6). The two evaluators stay apart: this is a fallback consulted only on the path
 * that was already returning wholly unknown, so it can turn a decline into an answer and
 * nothing else. Only when it too declines does {@code x} stay wholly unknown from that point
 * backward. This is the bridge that makes grm-4bgh.1's stack-relative reload and grm-4bgh.2's
 * {@code ADC #imm} reachable from a helper-argument deposit, which they were not when they
 * landed.</li>
 * <li>A mechanism write encountered mid-scan ({@link Hooks#isMechanismWrite}) means the
 * mechanism changed mid-chain: a base value read further back would predate that write, so
 * falling back to the in-state (which reflects state <em>after</em> it) would be unsound.
 * The scan therefore WITHDRAWS the in-state -- everything beyond that point is evaluated as
 * though the strategy's tracked state were unknown -- and keeps walking (bead grm-4bgh.7).
 * It used to abort outright. The distinction matters because most of what this scan can find
 * does not come from the in-state at all: an immediate is a constant in the image, a byte on
 * the stack is untouched by a store to the mechanism, an {@code env}'s caller-supplied
 * register describes the helper's entry, and a bank-invariant ROM byte is invariant by
 * construction. Only two sources actually consult it -- register-write's port read-back,
 * which returns the in-state verbatim, and every {@code resolveMirrorLoad} -- and both see
 * {@code unknown()} past the crossing and decline exactly as the old abort made them. The
 * same withdrawal is applied by the forwarding walk, and reported outward by the two stack
 * walks ({@link Span}) so that the walk which resumes from a push applies it too;
 * {@link #constantRegisterValue} (whose carry queries are the same walk) carries no such rule,
 * having no in-state to withdraw.</li>
 * <li>A subroutine call may clobber any register; its fall-through satisfies the
 * block-linkage check, so it is treated as a clobber explicitly.</li>
 * <li>A caller-supplied {@link RegisterEnv}'s entry address ends the walk and adopts that
 * environment's value for the register being asked about -- grm-hum increment 2's
 * mini-inlining of a bank-switch helper's own switch site under one call site's registers.
 * With {@link RegisterEnv#NONE} (every path but that one) it never fires and the scan
 * behaves exactly as it always has. See {@link RegisterEnv}'s javadoc for why stopping at
 * a function entry is an argued exception to the control-flow-join refusal rather than a
 * hole in it.</li>
 * <li>That same env may nominate ONE control-flow join the walk is allowed to cross
 * ({@link RegisterEnv#mayCrossJoinAt}, bead grm-k90), which is what lets a query asked on
 * behalf of a call into a PASS-THROUGH WRAPPER reach the wrapper's entry at all: the wrapped
 * helper's own entry lies between the two and is a join, so without this the walk dies there
 * and the env's stop is unreachable. It suppresses the join refusal and NOTHING else --
 * fall-through linkage, the mechanism-write abort and {@link #MAX_BACKWARD_SCAN} all still
 * apply at that instruction -- and it is honored identically by all three of this class's
 * backward walks, because the licence is a property of the env (a proved straight-line inert
 * fallthrough edge) and not of which question is being asked across it.</li>
 * </ul>
 * The mnemonic tables are 6502-family, which covers every board strategy currently
 * shipped (C64 register-write, NES memory-latch); other CPU families will parameterize
 * the tables when they arrive rather than speculatively now.
 */
final class StoredValueScanner {

	/** Strategy-specific behavior injected into the shared scan. */
	interface Hooks {

		/**
		 * Whether this instruction writes the strategy's mechanism. A backward walk that meets
		 * one WITHDRAWS its in-state from that point back rather than ending (bead grm-4bgh.7);
		 * see {@link #resolveStoredValue}'s handling for the argument.
		 */
		boolean isMechanismWrite(Instruction instr);

		/**
		 * Resolves the base value loaded by a non-immediate {@code LD<reg>} the strategy
		 * understands, or {@code null} to treat the load as an opaque register clobber.
		 *
		 * @param loadInstr       the load
		 * @param resolvedTarget  the single address the load actually reads, from
		 *                        {@link #effectiveOperandTarget} -- plain absolute/zero-page
		 *                        as before, plus absolute-indexed whose index register the
		 *                        scanner could pin to a constant (grm-hum). {@code null} when
		 *                        the target is not statically determinable. Supplied by the
		 *                        scanner rather than recomputed per hook so that the indexed
		 *                        case is resolved once, under one shared step budget.
		 * @param inStateAtStore  the strategy's tracked in-state at the store being scanned (mechanism
		 *                        state, field-local -- a {@link MechanismState}, not a byte)
		 * @return the loaded BYTE, partly known ({@link PartialByte}), or {@code null} to decline
		 */
		PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore);

		/**
		 * <b>Last resort</b> (bead grm-mej.2): resolves a load of an address that MIRRORS THE
		 * LIVE BANK -- a bank-identifying ROM offset, or a RAM cell the game writes the bank
		 * through -- from {@code inStateAtStore}. {@code null} (the default) means this strategy
		 * recovers nothing from a mirror, which is what every strategy did before mirrors existed.
		 * <p>
		 * <b>Why this is a second hook and not a branch inside {@link #resolveLoad}.</b> A
		 * write-through shadow is written BEFORE the value reaches the mechanism, so in the gap
		 * between the two the shadow holds the NEW bank while tracked in-state still holds the
		 * OLD one. Castlevania 2 is exactly that shape:
		 * <pre>
		 *   c183: STA $1C     ; shadow := the new bank, still only in A
		 *   c185: LDA $1C     ; &lt;-- reads the NEW bank
		 *   c187: 5x STA/LSR  ; commit
		 * </pre>
		 * {@link #resolveStoredValue}'s {@code LD<reg>} branch returns on ANY non-null
		 * {@link #resolveLoad} answer, short-circuiting {@link LocalStoreForwarding#forwardedStoreValue}. Answering
		 * mirrors there would therefore preempt grm-mej.1's correct forwarded value with the stale
		 * in-state -- a silently wrong bank on the easiest case in the bead. Ranking mirrors below
		 * forwarding makes the precedence explicit and unmissable.
		 * <p>
		 * {@link #resolveLoad} keeps its first-place slot for the opposite reason: it answers with
		 * a NON-writable ROM byte, and nothing can store to non-writable memory, so forwarding can
		 * never have a better answer to preempt it with.
		 * <p>
		 * <b>A non-null answer may be wholly unknown</b>, and that is meaningful rather than a
		 * degenerate null: it says "this site read the bank back and the bank was not known here",
		 * which is precisely what
		 * {@link BankSwitchStrategy#effectDependsOnPriorState(Program, Instruction, MechanismState)}
		 * reports as a bank-known-on-entry requirement. Callers must therefore treat non-null as
		 * authoritative, not test {@code knownMask() != 0}.
		 *
		 * @param loadInstr       the load
		 * @param resolvedTarget  the single address it reads, as for {@link #resolveLoad}
		 * @param inStateAtStore  the strategy's tracked in-state at the store being scanned, in
		 *                        that mechanism's field-local {@code [0, width)} coordinates
		 */
		default PartialByte resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore) {
			return null;
		}

		/**
		 * The strategy's tracked in-state at an ARBITRARY instruction -- in the same field-local
		 * coordinates as {@code inStateAtStore} -- or {@code null} (the default) when this query
		 * has no way to know it (bead grm-mej.3 increment 3, call-crossing PHA/PLA pairing).
		 * <p>
		 * <b>Why this exists.</b> Every other hook takes {@code inStateAtStore}, and the walk's
		 * founding invariant is that the value it recovers depends on the state at the store
		 * ALONE: within a straight-line span with no mechanism write, every instruction shares
		 * that state, and a mechanism write in the span WITHDRAWS it (grm-4bgh.7). Pairing a
		 * {@code PLA} to a {@code PHA} across a CALL breaks the invariant in a way withdrawal
		 * cannot repair usefully: in {@code LDA <mirror> / PHA / LDA #n / JSR helper / ... / PLA
		 * / JSR helper} the pushed byte was read BEFORE the intervening switch, so the state at
		 * the store would attribute it the bank the first call installed -- a confident WRONG
		 * value -- and withdrawing to unknown forfeits every customer, since all of them save
		 * via a mirror read. The right state is the one AT THE {@code PHA}, which only the
		 * dataflow engine knows.
		 * <p>
		 * The scanner consults this ONLY at a call-crossing resume (see the {@code PLA} branch of
		 * {@link #resolveStoredValue}); a {@code null} answer there ABANDONS the pairing, which is
		 * what every walk did at a call before this increment (see
		 * {@link #resumeStateAfterPairing} for why it must not withdraw and walk on instead). A
		 * hook that answers non-null has two obligations the engine discharges on the call-site
		 * path ({@code BankDataflowEngine.runDataflow}): the answer for {@code addr} must be
		 * re-asked when {@code addr}'s state changes (a dependency edge in the fixpoint, since
		 * the store's own in-state may not see the change -- both calls typically deposit the
		 * same fields), and nothing computed through it may be memoized on the store's in-state
		 * alone. Direct-site strategies keep the default and so keep {@code matchCache}'s
		 * state-independence claim intact.
		 */
		default MechanismState stateAt(Address addr) {
			return null;
		}

		/**
		 * Whether {@code target} MIRRORS THE LIVE BANK -- a {@link BankMirrors.Kind#WRITE_THROUGH}
		 * shadow or a {@link BankMirrors.Kind#ROM_IDENTIFYING} offset -- as a matter of KIND alone
		 * (bead grm-yflf). {@code false} (the default) means the hook cannot say.
		 * <p>
		 * <b>Deliberately separate from {@link #resolveMirrorLoad}, which is a VALUE channel.</b>
		 * That hook answers {@code null} for two different reasons the scanner cannot tell apart
		 * -- "not a mirror" and "a mirror this strategy will not resolve" (a stale write-through
		 * shadow under {@code MemoryLatchBankSwitchStrategy}'s coherence walk; every
		 * {@code WRITE_THROUGH} cell under {@code SerialShiftBankSwitchStrategy}'s bit-7 rule) --
		 * and the second reason is precisely the population this exists for. A walk that ends on
		 * an UNMODIFIED read-back of a live-bank mirror ({@code LDA $29 / ... / JSR switch}) is
		 * looking at a RESTORE of the bank live at that read, whatever the strategy could or
		 * could not say about its value; {@link #resolveStoredValue} reports that as
		 * {@link BankSwitchStrategy.ValueStop#RESTORED_BANK} with a {@link ReadBack} naming the
		 * read, instead of the generic {@code ANALYZER_LIMIT} that reads as our failure. Only the
		 * engine's call-site path answers this today ({@code HelperArgumentRecovery}'s
		 * {@code OracleHooks}); a strategy's own direct-site hooks keep the default, so direct
		 * sites -- including grm-p9y's NMI-tail restores -- are classified exactly as before.
		 */
		default boolean isLiveBankMirror(Address target) {
			return false;
		}

		/**
		 * Whether this env supplies a per-address state oracle at all (bead grm-mej.3 increment
		 * X1; default {@code false}). {@link CrossBlockStackPairing#crossBlockMatchingPush} runs ONLY when this is
		 * true, so direct-site hooks and {@code MemoryLatchBankSwitchStrategy
		 * .effectDependsOnPriorState}'s {@code MirrorProbe} -- which have no oracle to resume
		 * from and would otherwise see a blind cross-block resume report "consulted a mirror,
		 * came up unknown", the identical ironsword hazard {@link #resumeStateAfterPairing}'s
		 * javadoc records for the call-crossing case -- stay byte-identical to before this
		 * increment. {@code true} only in {@code HelperArgumentRecovery}'s {@code OracleHooks}.
		 */
		default boolean hasStateOracle() {
			return false;
		}

		/**
		 * The per-run memo of {@link CrossBlockStackPairing#crossBlockMatchingPush} proofs, keyed by the {@code PLA}'s
		 * address, or {@code null} (the default) to compute the proof fresh every time. The proof
		 * is STATE-FREE -- it depends only on the listing and control flow, never on tracked bank
		 * state -- so caching it across a whole analysis run is sound, exactly like
		 * {@code BankDataflowEngine}'s {@code armCache} (bead grm-mej.3 increment X1). Supplied
		 * only by {@code HelperArgumentRecovery.OracleHooks}, threaded in from the engine.
		 */
		default Map<Address, CrossBlockProof> crossBlockProofMemo() {
			return null;
		}

		/**
		 * The per-run memo of {@link SaveSlotForwarding#saveSlotForwarded} proofs and callee-closure writer censuses
		 * (bead grm-zsxz increment Z2), or {@code null} (the default) to compute fresh every time.
		 * Both are STATE-FREE -- functions of the listing, its references and the memory map --
		 * so a whole run may share them, for the same reason as {@link #crossBlockProofMemo}.
		 */
		default ProofMemo saveSlotMemo() {
			return null;
		}

		/**
		 * Whether the ABSOLUTE-INDEXED table {@code loadInstr} reads, based at {@code base}, is an
		 * IDENTITY TABLE over this strategy's tracked field -- {@code table[v] == v} for every
		 * {@code v} in {@code [0, fieldMask]}, after this mechanism's own shift/mask extraction and
		 * bus-conflict AND, where {@code idxReadBack} is where the caller-side scan proved the
		 * load's index register was itself read back from (bead grm-ld68).
		 * <p>
		 * {@code false} (the default) means this strategy makes no such claim -- every strategy but
		 * {@code MemoryLatchBankSwitchStrategy} keeps the default, and direct-site scanning (which
		 * never has an {@code idxReadBack} to offer, since {@link RegisterEnv#NONE} carries none)
		 * never reaches this hook at all -- see {@link #resolveStoredValue}'s caller.
		 * <p>
		 * <b>What this licenses.</b> When {@code idxReadBack}'s cell is itself provably the bank
		 * number (a {@code ROM_IDENTIFYING} mirror in plain identity encoding -- verified by the
		 * caller BEFORE this hook is asked, not by the strategy), an identity table read with that
		 * same index is a NO-OP: the byte {@code LDA base,idx} reads back is exactly the bank the
		 * caller already read, whatever bank that was. A store that re-commits it is therefore a
		 * RESTORE, not an unresolved argument -- contra's {@code FUN_c13f} (its two-instruction body
		 * {@code LDA $FFD0,Y / STA $FFD0,Y}, table {@code $FFD0..$FFD7 == 00..07}) is the worked
		 * case: Y arrives as a caller-side read-back of the {@code $8000} ROM_IDENTIFYING mirror
		 * (identity-encoded, verified), so this answers {@code true} and the scanner reports
		 * {@link BankSwitchStrategy.ValueStop#RESTORED_BANK} carrying {@code idxReadBack} itself --
		 * NOT a new {@link ReadBack} about this load, because the bank this site re-commits is the
		 * one the CALLER read, not one this site reads independently.
		 * <p>
		 * <b>Whether {@code idxReadBack}'s value is provably the bank number is NOT this hook's
		 * question</b> -- the scanner never calls it without having already confirmed that (bead
		 * grm-ld68 rule (c)); an implementation is free to re-check it (as
		 * {@code MemoryLatchBankSwitchStrategy} does, from its own {@code BankMirrors}) but must not
		 * assume the caller skipped it.
		 *
		 * @param loadInstr   the absolute-indexed load (e.g. {@code LDA base,Y})
		 * @param base        the table's base address -- the load's operand with the index
		 *                    subtracted out ({@link LoopIdioms#indexedBase})
		 * @param idxReadBack where the caller-side scan says the load's index register was itself
		 *                    read back from
		 */
		default boolean isIdentityTableLoad(Instruction loadInstr, Address base,
				ReadBack idxReadBack) {
			return false;
		}

		/**
		 * Hooks that resolve nothing and see no mechanism: {@link #isMechanismWrite} is always
		 * {@code false} and {@link #resolveLoad} always {@code null}. The state-free context
		 * {@link #constantIndex} evaluates in, so a census or slot proof stays memoizable; and the
		 * safe default for a caller-side scan, because it never looks at an in-state. One shared
		 * instance rather than one per call site. It overrides only those two methods, so every
		 * other hook keeps its interface default.
		 */
		Hooks INERT = new Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
					MechanismState inStateAtStore) {
				return null;
			}
		};
	}

	/**
	 * The state-free result of a {@link CrossBlockStackPairing#crossBlockMatchingPush} proof (bead grm-mej.3 increment
	 * X1): the {@code PHA}s it found, in address order (empty for a decline; more than one when
	 * the {@code PLA}'s arms each pushed their own byte, bead grm-mej.21), whether any explored
	 * path crossed a call, the sole call address every path agreed was the nearest one crossed
	 * ({@code null} when some path crossed none, or paths disagreed about which), and whether any
	 * path crossed a mechanism write. See {@link Hooks#crossBlockProofMemo}.
	 */
	record CrossBlockProof(List<Address> phas, boolean crossedCall, Address agreedLastCall,
			boolean crossedMechanismWrite) {

		static final CrossBlockProof DECLINED = new CrossBlockProof(List.of(), false, null, false);

		CrossBlockProof {
			phas = List.copyOf(phas);
		}

		/** The push when every path agreed on exactly one, else {@code null}. */
		Address pha() {
			return phas.size() == 1 ? phas.get(0) : null;
		}
	}

	/**
	 * The per-run memo of the scanner's STATE-FREE proofs (bead grm-zsxz increment Z2): X1's
	 * cross-block pairing proofs (keyed by {@code PLA}), and Z2's save-slot proofs and
	 * callee-closure writer censuses. One instance per dataflow run, created by the engine and
	 * threaded to {@code HelperArgumentRecovery}'s {@code OracleHooks}.
	 */
	static final class ProofMemo {

		final Map<Address, CrossBlockProof> crossBlock = new HashMap<>();

		final Map<SlotKey, SlotProof> slotProofs = new HashMap<>();

		final Map<CensusKey, CensusResult> censuses = new HashMap<>();
	}

	/** {@link ProofMemo} key for a save-slot proof: the load, the slot's physical offset, and the
	 *  env entry the search abandons at ({@code null} for none). */
	record SlotKey(Address load, long cellOffset, Address envEntry) {}

	/** A save-slot proof: the single store every path reaches ({@code null} = declined), the
	 *  calls through which the paths reach it when it sits inside a SAVE HELPER ({@code via},
	 *  sorted; empty for a store on the paths themselves -- bead grm-mej.23), and whether
	 *  {@link SlotAssumption#INDIRECT_STORES_DO_NOT_WRITE_SLOT} was relied on. */
	record SlotProof(Address store, List<Address> via, boolean indirectStoresAssumed) {

		static final SlotProof DECLINED = new SlotProof(null, List.of(), false);
	}

	/** {@link ProofMemo} key for a callee-closure census: the callee entry and the slot's
	 *  physical offset. */
	/** A census memo key. {@code x}/{@code y} are the index registers the CALL SITE proves on
	 *  entry ({@link SaveSlotForwarding#callCensus}, bead grm-mej.25), {@code null} when not a provable constant. */
	record CensusKey(Address entry, long cellOffset, Integer x, Integer y) {}

	/** A callee-closure census: {@code clean} when no instruction reachable from the entry may
	 *  write the slot (and the closure was fully resolved), plus whether an indirect store was
	 *  stepped over under the named assumption. */
	record CensusResult(boolean clean, boolean indirectStoresAssumed) {

		static final CensusResult DIRTY = new CensusResult(false, false);
	}

	/**
	 * Where a {@link BankSwitchStrategy.ValueStop#RESTORED_BANK} scan read the bank back from
	 * (bead grm-yflf): the mirror {@code cell}, the load instruction {@code readAt}, and -- when a
	 * PHA/PLA pairing or stack-relative reload carried the byte over a call between the read and
	 * the store -- the LAST such call, {@code carriedAcross} ({@code null} for a read that fed the
	 * store directly). Descriptive: the classification is decided by the read's shape alone, and
	 * this only lets the annotation say where the bank came from and what it was carried over.
	 */
	record ReadBack(Address cell, Address readAt, Address carriedAcross, Address crossBlockPush,
			Address crossBlockPull, SlotCarrier slot, List<ReadBack> arms) {

		/**
		 * {@code arms} is empty for an ordinary read-back. A JOINED read-back (bead grm-mej.21)
		 * lists one single-read ReadBack per pushing arm -- the {@code PLA} sits at a join each of
		 * whose arms pushed its OWN read of {@code cell} -- and its own {@code readAt}/push/pull
		 * fields repeat the first arm's, so a consumer that has not learned about joins still reads
		 * something true about one arm. Every claim about "the read" must hold for each of
		 * {@link #reads()}.
		 */
		ReadBack {
			arms = arms == null ? List.of() : List.copyOf(arms);
		}

		/** Pre-grm-mej.21 form: one read. */
		ReadBack(Address cell, Address readAt, Address carriedAcross, Address crossBlockPush,
				Address crossBlockPull, SlotCarrier slot) {
			this(cell, readAt, carriedAcross, crossBlockPush, crossBlockPull, slot, List.of());
		}

		/** Pre-grm-mej.3-increment-X1 form: no cross-block span. */
		ReadBack(Address cell, Address readAt, Address carriedAcross) {
			this(cell, readAt, carriedAcross, null, null, null);
		}

		/** Pre-grm-zsxz form: not carried through a RAM save slot. */
		ReadBack(Address cell, Address readAt, Address carriedAcross, Address crossBlockPush,
				Address crossBlockPull) {
			this(cell, readAt, carriedAcross, crossBlockPush, crossBlockPull, null);
		}

		/** This read-back, additionally carried to the site through {@code carrier}. */
		ReadBack withSlot(SlotCarrier carrier) {
			return new ReadBack(cell, readAt, carriedAcross, crossBlockPush, crossBlockPull,
				carrier, arms);
		}

		/** Every read this read-back stands for: its arms when joined, else itself alone. */
		List<ReadBack> reads() {
			return arms.isEmpty() ? List.of(this) : arms;
		}

		/**
		 * The tracked states at EVERY read, concatenated, for a claim that must hold at each of
		 * them ({@code BankMirrors.restoreMembership} requires it of every state it is given) --
		 * or an empty list as soon as any one read has no state, so a stateless arm can never be
		 * outvoted by the others.
		 */
		List<BankState> statesAtEveryRead(
				java.util.function.Function<Address, List<BankState>> statesAt) {
			List<BankState> all = new ArrayList<>();
			for (ReadBack read : reads()) {
				List<BankState> states = statesAt.apply(read.readAt());
				if (states == null || states.isEmpty()) {
					return List.of();
				}
				all.addAll(states);
			}
			return all;
		}

		/** The read-back joined from one per-arm read-back each (bead grm-mej.21); the arms must
		 *  share one {@code cell}. */
		static ReadBack joined(List<ReadBack> arms) {
			ReadBack first = arms.get(0);
			return new ReadBack(first.cell(), first.readAt(), first.carriedAcross(),
				first.crossBlockPush(), first.crossBlockPull(), first.slot(), arms);
		}
	}

	/**
	 * The CARRIER a {@link ReadBack} went through when the read byte reached the site via a RAM
	 * SAVE SLOT rather than directly or on the stack (bead grm-zsxz increment Z2): the byte was
	 * stored into {@code cell} at {@code store} and reloaded at {@code load}, with every path
	 * between the two proved free of other writers of {@code cell} by
	 * {@link SaveSlotForwarding#saveSlotForwarded}. {@code indirectStoresAssumed} records whether that proof stepped
	 * over at least one indirect store under {@link SlotAssumption#INDIRECT_STORES_DO_NOT_WRITE_SLOT}
	 * -- descriptive, so the annotation can say the assumption was actually relied on.
	 */
	record SlotCarrier(Address cell, Address store, Address load, boolean indirectStoresAssumed,
			Address storedVia) {

		/** {@code storedVia} is the call whose SAVE HELPER ran {@code store} on this read's path
		 *  (bead grm-mej.23; cv3's {@code JSR e2e0}, whose {@code e2e3 STA $22} is the save), or
		 *  {@code null} when the store sits on the path itself. */
		SlotCarrier(Address cell, Address store, Address load, boolean indirectStoresAssumed) {
			this(cell, store, load, indirectStoresAssumed, null);
		}
	}

	/**
	 * The NAMED, BOUNDED ASSUMPTIONS the RAM save-slot proof ({@link SaveSlotForwarding#saveSlotForwarded}, bead
	 * grm-zsxz increment Z2) rests on -- the memory-slot counterpart of {@link StackFloor} for the
	 * stack slot. Named here so every place that relies on one cites the same constant, and so the
	 * restore note can state it (owner ruling Q2, 2026-10-05).
	 */
	enum SlotAssumption {

		/**
		 * An INDIRECT store -- {@code STA ($zp),Y} or {@code STA ($zp,X)} -- whose target Ghidra
		 * did not resolve to a concrete address is assumed NOT to write the save slot being
		 * forwarded. Neither a pointer nor its contents is modelled, so such a store cannot be
		 * proved to miss the slot; counting every one as a possible writer would block nearly every
		 * proof (game code is full of pointer copies). The assumption is BOUNDED: it covers only
		 * the two true indirect modes, never an unplaceable store of any other shape, and never
		 * an indexed store whose reachable window covers the slot ({@code STA base,X} reaches
		 * {@code base..base+$FF}; a zero-page-indexed store reaches the whole zero page) -- those
		 * are counted as writers. An indirect store that Ghidra DID resolve (a write reference to
		 * the slot) is a writer too. The residual risk is a pointer genuinely aimed at the slot,
		 * which is the same class of risk {@link StackFloor} accepts for a deep push.
		 */
		INDIRECT_STORES_DO_NOT_WRITE_SLOT;

		/** The short form the restore note quotes. */
		static final String NOTE_WORDING = "assuming no indirect store (STA ($zp),Y / " +
			"STA ($zp,X)) writes the slot";
	}

	static final int MAX_BACKWARD_SCAN = 16;

	/**
	 * How deep {@link #constantRegisterValue} may recurse through register-to-register
	 * dependencies (a {@code TAX} asks about A, whose {@code LDA table,X} asks about X, ...).
	 */
	static final int MAX_RESOLVE_DEPTH = 4;

	/**
	 * Instructions one whole {@link #effectiveOperandTarget} query tree may inspect. The depth
	 * cap alone is not a bound worth relying on -- at {@link #MAX_BACKWARD_SCAN} steps per
	 * level it permits {@code 16^depth} instruction visits -- so every visit also spends from
	 * a single {@link Budget} shared across the entire tree. Mega Man's real chain
	 * ({@code LDA #$00 / STA $0C / ASL A / TAX / LDA $D81E,X}) uses depth 3 and about 10 steps.
	 */
	static final int MAX_RESOLVE_STEPS = 64;

	/**
	 * 6502 mnemonics that write memory, for {@link LocalStoreForwarding#writesMemory}'s third detector. The stores
	 * are here as well as in {@link MosOperands#storeRegister} because that method deliberately excludes the
	 * read-modify-write forms, which write memory just the same. The shift/rotate entries write
	 * memory only in their non-accumulator addressing modes, which {@link LocalStoreForwarding#writesMemory} tests.
	 * Stack pushes ({@code PHA}/{@code PHP}) are absent on purpose, and this is still true after
	 * grm-mej.3 increment 2 relaxed {@link LocalStoreForwarding#forwardedStoreValue}'s stack-page refusal: they write
	 * the stack without naming an address any detector here can see, so they are still stepped
	 * over as inert rather than recognized as writing whatever cell the walk is forwarding. A
	 * call -- the other way the stack is written -- ends the walk anyway. What keeps that sound
	 * is {@link StackFloor}, applied at the cell being forwarded rather than here: no
	 * per-instruction detector for a push's target is possible without tracking {@code S}, so
	 * the guard has to key on the address the walk cares about instead.
	 */
	static final Set<String> MEMORY_WRITERS =
		Set.of("STA", "STX", "STY", "INC", "DEC", "ASL", "LSR", "ROL", "ROR");

	private StoredValueScanner() {
	}

	/** Mutable step counter shared across one {@link #effectiveOperandTarget} query tree. */
	static final class Budget {

		private int steps;

		/** Cached by {@link #constantValue} the first time it is asked, within THIS one query
		 * tree -- {@link BoardBankAnalyzer#constantSemanticsMode} reads a program option via
		 * two {@link ghidra.framework.options.Options} lookups, and a single walk can call
		 * into {@link #constantValue} recursively many times over the SAME program, so caching
		 * it once per {@link Budget} instance (freshly created per top-level entry, see every
		 * {@code new Budget(...)} call site) avoids repeating that lookup without introducing
		 * any state that outlives one query or is shared across programs. */
		private ConstantSemantics semantics;

		Budget(int steps) {
			this.steps = steps;
		}

		/** Spends one step; false once the budget is exhausted. */
		boolean spend() {
			return steps-- > 0;
		}

		/** {@link #semanticsFor}, cached for the lifetime of this {@link Budget}. */
		private ConstantSemantics semanticsFor(Program program) {
			if (semantics == null) {
				semantics = StoredValueScanner.semanticsFor(program);
			}
			return semantics;
		}
	}

	/**
	 * A backward SUB-walk's report to the walk that called it (bead grm-4bgh.7): how many
	 * instructions it stepped over, and whether it CROSSED A MECHANISM WRITE doing so.
	 * <p>
	 * The step count was previously passed back through a single-element {@code int[]}, for the
	 * reason its callers document: a sub-walk spends from the caller's own
	 * {@link #MAX_BACKWARD_SCAN} budget, so the caller has to know how much was spent on every
	 * return path including a failed one. The crossing flag has exactly the same shape of
	 * requirement -- {@link CrossBlockStackPairing#findMatchingPush} and {@link #stackRelativePush} may now step OVER a
	 * mechanism write instead of stopping at one, and the walk that resumes from the instruction
	 * they found is the CALLER's, so only the caller can apply the consequence
	 * ({@link #resolveStoredValue} withdrawing its in-state). Two parallel out-params would have
	 * been two chances to update one and forget the other.
	 */
	static final class Span {

		int steps;

		boolean crossedMechanismWrite;

		/**
		 * Whether the search stepped over a CALL (grm-mej.3 increment 3). The consequence for the
		 * resumed walk is applied by the caller through {@link #resumeStateAfterPairing}: the
		 * in-state at the store no longer describes the instructions before the push, because
		 * the callee (or a helper among the crossed calls) may have switched banks in between.
		 */
		boolean crossedCall;

		/**
		 * The LAST call the search stepped over, when {@link #crossedCall} -- for the
		 * {@link ReadBack} a {@code RESTORED_BANK} scan reports, so the annotation can name the
		 * call the saved byte was carried across. Descriptive only; nothing decides on it.
		 */
		Address crossedCallAt;

		/**
		 * Whether the search that found this pairing was the CROSS-BLOCK ALL-PATHS proof (bead
		 * grm-mej.3 increment X1) rather than {@link CrossBlockStackPairing#findMatchingPush}'s straight-line walk.
		 * Handled by {@link #resumeStateAfterPairing} exactly like {@link #crossedCall}: crossing
		 * a control-flow join is one more crossing the resumed walk cannot assume is state-stable,
		 * whether or not a call happened to sit on any explored path. A block crossing with no
		 * state at the push therefore ABANDONS the same way a call crossing does -- never
		 * withdraw-and-continue (the ironsword rule).
		 */
		boolean crossedBlock;
	}

	/**
	 * The in-state the enclosing walk resumes with after a pairing search found {@code push}
	 * (grm-mej.3 increment 3), or {@code null} to ABANDON the pairing. Three cases, in order:
	 * <ul>
	 * <li>the span crossed a call: the store's state is not the push's. Ask
	 * {@link Hooks#stateAt} for the state AT the push. A {@code null} answer ABANDONS -- the
	 * caller treats the pairing as not found, exactly as every pre-increment-3 walk did at a
	 * call. It does NOT withdraw to unknown and walk on, and the distinction was measured, not
	 * guessed: withdrawing lets the resumed walk reach a mirror load under a state that is
	 * unknown because WE cannot see it, and
	 * {@code MemoryLatchBankSwitchStrategy.effectDependsOnPriorState}'s probe then records
	 * "consulted a mirror, came up unknown" -- the same signal a genuinely unknown bank leaves.
	 * That declared a bank-known-on-entry requirement for ironsword's {@code FUN_ffc0} (whose
	 * inner {@code JSR $FFDA} the pairing now crosses to reach {@code LDA $C5}) and pushed six
	 * violation warnings onto the very call sites {@code restoresEntryBank} had proved no-ops,
	 * and moved dodge, ff1 and lwings in the losing direction for the same reason. A withdrawn
	 * state after a mechanism write in the same span IS an honest "bank unknown here"; after a
	 * blind call crossing it is a statement about our own blindness, and must not be reported
	 * as the game's property. Direct-site strategies have no oracle, so on that path a
	 * call-crossing pairing is byte-identical to increment 2. When the answer is non-null it
	 * subsumes a mechanism write in the same span -- the state at the push already predates it,
	 * whichever order the two crossings happened in program order;</li>
	 * <li>the span crossed only a mechanism write: withdraw (grm-4bgh.7), unchanged;</li>
	 * <li>neither: the store's state still describes the push -- unchanged.</li>
	 * </ul>
	 */
	private static MechanismState resumeStateAfterPairing(Span span, Instruction push, Hooks hooks,
			MechanismState current) {
		if (span.crossedCall || span.crossedBlock) {
			return push == null ? null : hooks.stateAt(push.getMinAddress());
		}
		if (span.crossedMechanismWrite) {
			return MechanismState.unknown();
		}
		return current;
	}

	/**
	 * Scans backward from {@code storeInstr} to determine the {@link PartialByte} it
	 * stores, reduced to {@code mask} -- a BYTE mask: which bits of the stored byte the caller
	 * consumes (see {@link #CLASSIFY_ONLY}; bits beyond the eighth select nothing, as
	 * {@link PartialByte} clips) -- full algorithm in the class javadoc. After every
	 * composition step the base can be folded in via {@link #combine}; as an
	 * optimization, {@link #fullyDeterminedByAccumulator} lets the scan return without
	 * ever inspecting the base when the mask algebra alone already pins down every
	 * tracked bit.
	 * <p>
	 * 6502 has no immediate AND/ORA addressing the X or Y registers, so the mask-algebra
	 * composition only ever applies when {@code reg == 'A'}; the X/Y paths retain the
	 * simpler "resolved load or wholly unknown" behavior.
	 */
	static PartialByte resolveStoredValue(Program program, Instruction storeInstr, char reg,
			MechanismState inStateAtStore, int mask, Hooks hooks) {
		return resolveStoredValue(program, storeInstr, reg, inStateAtStore, mask, hooks,
			RegisterEnv.NONE);
	}

	/**
	 * {@link #resolveStoredValue} evaluated under a caller-supplied {@link RegisterEnv}: the
	 * backward walk additionally stops at {@code env}'s entry address and adopts what that
	 * environment says the register holds there, instead of walking into whatever code
	 * physically precedes the entry (which is some unrelated function, not a predecessor).
	 * <p>
	 * This is the mini-inlining entry point (grm-hum increment 2): a bank-switch helper's own
	 * switch site is re-evaluated with the A/X/Y a specific call site supplies, which is how a
	 * helper taking its bank argument in Y ({@code LDA $FFD0,Y / STA $FFD0,Y / RTS} -- Contra)
	 * is resolved at all. The 6-argument form above delegates here with {@link RegisterEnv#NONE},
	 * so every pre-existing caller is byte-identical.
	 * <p>
	 * <b>An env-derived result may only ever be used for the one call site whose registers
	 * {@code env} describes</b> -- see {@link RegisterEnv}'s class javadoc for the soundness
	 * argument and the structural enforcement.
	 */
	static PartialByte resolveStoredValue(Program program, Instruction storeInstr, char reg,
			MechanismState inStateAtStore, int mask, Hooks hooks, RegisterEnv env) {
		return resolveStoredValueScan(program, storeInstr, reg, inStateAtStore, mask, hooks, env)
				.value();
	}

	/**
	 * {@link #resolveStoredValue} keeping the {@link Scan#stop()} reason a caller needs to
	 * tell an HONEST unresolved value from one this scanner simply gave up on (bead
	 * {@code grm-3ou} part 1). Same walk, same answer -- only the classification survives
	 * the return, which the {@link PartialByte}-returning forms discard.
	 */
	static Scan resolveStoredValueScan(Program program, Instruction storeInstr, char reg,
			MechanismState inStateAtStore, int mask, Hooks hooks, RegisterEnv env) {
		return resolveStoredValue(program, storeInstr, reg, inStateAtStore, mask, hooks, env,
			new Budget(MAX_RESOLVE_STEPS), 0);
	}

	/**
	 * {@link #resolveStoredValue} within an ongoing store-to-load forwarding chain's depth and
	 * step budget. Only {@link LocalStoreForwarding#forwardedStoreValue} passes a non-fresh budget: every public
	 * entry point starts a new one, so a top-level scan is unaffected by this parameterization.
	 * <p>
	 * Note the {@link #effectiveOperandTarget} call in the {@code LD<reg>} branch below
	 * deliberately keeps starting a <em>fresh</em> budget rather than spending from this one.
	 * That is exactly what it did before forwarding existed, and preserving it keeps this change
	 * from silently withdrawing effective-address resolution that a long scan relies on today.
	 * The forwarding lookups are the only ones that share {@code budget}, which is what bounds
	 * the recursion this method can now enter.
	 */
	static Scan resolveStoredValue(Program program, Instruction storeInstr, char reg,
			MechanismState inStateAtStore, int mask, Hooks hooks, RegisterEnv env, Budget budget,
			int depth) {
		return resolveStoredValue(program, storeInstr, reg, inStateAtStore, mask, hooks, env,
			budget, depth, 0);
	}

	/**
	 * The walk itself, with {@code startStep} of its {@link #MAX_BACKWARD_SCAN} budget already
	 * spent -- nonzero only for an arm {@link CrossBlockStackPairing#pairedArms} resumes from a push, which continues
	 * the enclosing walk's budget rather than starting a fresh one.
	 */
	static Scan resolveStoredValue(Program program, Instruction storeInstr, char reg,
			MechanismState inStateAtStore, int mask, Hooks hooks, RegisterEnv env, Budget budget,
			int depth, int startStep) {
		Listing listing = program.getListing();
		Set<String> modifiers = MosOperands.registerModifiers(reg);
		String loadMnemonic = "LD" + reg;

		// The in-state is a LOCAL from here on, because crossing a mechanism write WITHDRAWS it
		// (bead grm-4bgh.7): everything reached beyond that point is evaluated as though the
		// strategy's tracked state were unknown, which it effectively is. The parameter itself
		// stays untouched so the withdrawal cannot leak back to a caller.
		MechanismState inState = inStateAtStore;
		// grm-mej.13: true once the walk has stepped back over a register-preserving call with no
		// state available at that call. The register's value still survives the call, but the
		// BANK may not have -- the callee can switch it -- so inState no longer describes anything
		// read before the call. A blind walk may still finish on a state-free definition (an
		// immediate, a transfer, an immediate AND/ORA); every read that would consult inState
		// stops with today's ANALYZER_LIMIT instead, WITHOUT asking the hook, so no strategy probe
		// records our blindness as a property of the game (the ironsword rule, see
		// resumeStateAfterPairing). Cleared only by a resume that obtains a real state.
		boolean stateBlind = false;
		// The last call a PHA/PLA pairing or stack-relative reload carried the tracked byte
		// across (bead grm-yflf) -- reported in a RESTORED_BANK stop's ReadBack, decided on by
		// nothing. Null until a resume crosses one.
		Address carriedAcross = null;
		// The push/pull span a CROSS-BLOCK pairing carried the tracked byte across (bead
		// grm-mej.3 increment X1) -- reported in a RESTORED_BANK stop's ReadBack with the new
		// "carried on the stack across control flow <push>..<pull>" wording, in place of
		// carriedAcross's "across the call at" (which still applies to a plain, non-cross-block
		// call crossing). Null unless a resume actually used the cross-block search.
		Address crossBlockPush = null;
		Address crossBlockPull = null;

		int aAcc = 0xFF;
		int oAcc = 0x00;

		Instruction cur = storeInstr;
		// A plain for(i...) can no longer express the budget: pairing a PLA to its PHA
		// (below) must spend from this SAME MAX_BACKWARD_SCAN budget rather than a fresh one,
		// and the amount it spends is not known until the pairing search returns. i is
		// therefore incremented by hand -- by exactly 1 for every ordinary step, matching the
		// for-loop's old semantics exactly, and by the pairing search's own step count on a
		// PLA. See findMatchingPush.
		int i = startStep;
		while (i < MAX_BACKWARD_SCAN) {
			if (env.stopsAt(cur.getMinAddress())) {
				// Reached the entry this query was asked on behalf of: the register's value
				// here is the caller's, not whatever code happens to sit at a lower address.
				// Deliberately BEFORE the linkage/join/mechanism-write checks -- an entry has
				// no fall-through predecessor to check, and its incoming flows are other call
				// sites, which is exactly what the env already answers for.
				return stopped(aAcc, oAcc, mask, env.get(reg), BankSwitchStrategy.ValueStop.HELPER_ARGUMENT);
			}
			// The block start, a predecessor that does not fall through into cur, or a
			// control-flow join: some other path reaches cur and may leave a different register
			// value, so prev's fall-through value can't be attributed to the store with
			// confidence. The exceptions are the join an env explicitly licenses (grm-k90) and
			// the arm an env names (grm-wul): there prev IS cur's predecessor on the path this
			// context-sensitive query is asked about. Only the linkage/join tests are skipped --
			// the mechanism-write abort below still runs. See pathPredecessor.
			Instruction prev = pathPredecessor(program, listing, cur, env);
			if (prev == null) {
				return stopped(aAcc, oAcc, mask, countedLoopValue(program, cur, reg),
					BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
			}

			if (hooks.isMechanismWrite(prev)) {
				// The mechanism was written mid-chain. A base value read further back predates
				// that write, so the in-state -- which describes the state AT THE STORE, i.e.
				// AFTER it -- may not be consulted beyond this point. That is the WHOLE of the
				// hazard, and until grm-4bgh.7 this returned rather than saying so: withdrawing
				// the in-state and walking on leaves every in-state-INDEPENDENT source (an
				// immediate in the image, a byte on the stack, the env's caller-supplied
				// registers, a bank-invariant ROM byte) free to answer, while the two hooks that
				// DO consult it (register-write's port read-back, which returns the in-state
				// verbatim, and every resolveMirrorLoad) now see unknown() and decline exactly as
				// this early return used to make them.
				//
				// STRICTLY ADDITIVE, by the same argument as grm-4bgh.6's: this path returned a
				// wholly unknown base, and combine() is monotone in the base's knownMask -- the
				// bits the accumulators already pinned are unchanged, and a later base can only
				// add more. See findMatchingPush's javadoc, which asked for exactly this
				// distinction and named the ASL modeling it was waiting on.
				inState = MechanismState.unknown();
			}

			// Every prev reached past this point is examined and stepped over -- exactly the
			// for-loop's old per-iteration i++, now explicit because the PLA branch below may
			// additionally consume several more steps from this same budget in one go.
			i++;

			String mnem = prev.getMnemonicString().toUpperCase();

			if (stateBlind && (mnem.equals("AND") || mnem.equals("ORA") || mnem.equals(loadMnemonic))
					&& !MosOperands.isImmediate(prev)) {
				return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
			}

			if (reg == 'A' && mnem.equals("AND")) {
				Integer imm = operandByte(program, prev, inState, hooks, env, budget, depth);
				if (imm == null) {
					// an operand we couldn't pull a scalar out of, and couldn't forward a store
					// to either, is an opaque modifier of A.
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				aAcc = imm & aAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				cur = prev;
				continue;
			}

			if (reg == 'A' && mnem.equals("ORA")) {
				Integer imm = operandByte(program, prev, inState, hooks, env, budget, depth);
				if (imm == null) {
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				oAcc = (imm & aAcc) | oAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				cur = prev;
				continue;
			}

			if (mnem.equals(loadMnemonic) && MosOperands.isImmediate(prev)) {
				Integer imm = MosOperands.immediateOperandValue(prev);
				if (imm != null) {
					// x is now fully known -- fold it through the accumulated transform.
					return stopped(aAcc, oAcc, mask, PartialByte.fullyKnown(imm), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				// Scalar extraction failed; fall through and treat like any other modifier.
			}

			if (mnem.equals(loadMnemonic)) {
				// The target is resolved here, not in the hook: an absolute-indexed load's
				// target needs the whole constant-index evaluator, and doing it once keeps
				// every strategy's hook a pure "do I understand this address" question.
				Address target = effectiveOperandTarget(program, prev, hooks, env);
				PartialByte base = hooks.resolveLoad(prev, target, inState);
				if (base != null) {
					// grm-mej.8: a read-back of a live-bank mirror stays a read-back when the strategy
					// can ALSO partly evaluate it (see restoredKeepingValue). Same shape test as the
					// mirror branch below; only the reason and the ReadBack change, never the value.
					if (aAcc == 0xFF && oAcc == 0x00 && MosOperands.plainAbsoluteTarget(prev) != null &&
						hooks.isLiveBankMirror(target)) {
						Scan restored = restoredKeepingValue(aAcc, oAcc, mask, base,
							new ReadBack(target, prev.getMinAddress(), carriedAcross,
								crossBlockPush, crossBlockPull));
						if (restored != null) {
							return restored;
						}
					}
					return stopped(aAcc, oAcc, mask, base, BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				// No strategy claims this address; try to forward a store to it from earlier in
				// this same block (grm-mej.1). A partial answer is fine here -- combine() folds
				// a partially known base per bit -- unlike the AND/ORA operand case, which needs
				// all eight bits to compose into the accumulator.
				PartialByte forwarded = forwardedStoreValue(program, prev, target, inState,
					hooks, env, budget, depth);
				if (forwarded.knownMask() != 0) {
					return stopped(aAcc, oAcc, mask, forwarded, BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				// Last resort (grm-mej.2): does this address MIRROR the live bank? Strictly below
				// forwarding -- see Hooks.resolveMirrorLoad for the cv2 case that ordering exists
				// for. A non-null answer is authoritative even when wholly unknown.
				PartialByte mirrored = hooks.resolveMirrorLoad(prev, target, inState);
				// A plain, UNMODIFIED read-back of a live-bank mirror is a RESTORE of the bank
				// live at that read, not an argument we failed to pin down (bead grm-yflf):
				// megaman2's `LDA $29 / PHA / JSR c96b / PLA / JSR c000` re-commits whatever the
				// write-through shadow held before the inner call. Classified on the read's
				// SHAPE -- fixed non-indexed address, identity accumulators (the stored byte IS
				// the read byte) -- independently of whether the strategy would resolve its
				// value: a mirror the hook answers null for (stale, or a kind it refuses) is
				// still a mirror, and Hooks.isLiveBankMirror is the kind query that says so.
				// The value stays whatever the hook said (unknown when it declined), so the
				// deposit is unchanged; only the reason and the ReadBack differ.
				boolean readBack = aAcc == 0xFF && oAcc == 0x00 &&
					MosOperands.plainAbsoluteTarget(prev) != null && hooks.isLiveBankMirror(target);
				if (mirrored != null || readBack) {
					if (readBack && mirrored != null) {
						// grm-mej.8: a partly known mirror value keeps its read-back too.
						Scan restored = restoredKeepingValue(aAcc, oAcc, mask, mirrored,
							new ReadBack(target, prev.getMinAddress(), carriedAcross,
								crossBlockPush, crossBlockPull));
						if (restored != null) {
							return restored;
						}
					}
					return stopped(aAcc, oAcc, mask, mirrored != null ? mirrored : PartialByte.unknown(),
						readBack ? BankSwitchStrategy.ValueStop.RESTORED_BANK
								: BankSwitchStrategy.ValueStop.ANALYZER_LIMIT,
						readBack ? new ReadBack(target, prev.getMinAddress(), carriedAcross,
								crossBlockPush, crossBlockPull) : null);
				}
				// IDENTITY-TABLE INDEX HELPER (bead grm-ld68): an ABSOLUTE-INDEXED load whose
				// index register is provably the SAME caller-supplied value `env` describes --
				// not just "some caller register", but the one env has a ReadBack for -- and
				// whose table is an identity over the field re-commits the bank that read-back
				// already named, whatever it was. Contra's FUN_c13f is the worked case: `LDA
				// $FFD0,Y / STA $FFD0,Y`, table $FFD0..$FFD7 == 00..07, Y arriving as a caller-
				// side read-back of the $8000 ROM_IDENTIFYING mirror. Guarded exactly like the
				// plain-mirror readBack above (aAcc/oAcc unmodified -- rule (a)) plus three more
				// conditions the hook and this scanner split between them:
				//  (b) idx is not redefined between env's entry and this load -- verified by
				//      scanning idx FROM THIS INSTRUCTION under the same env and requiring the
				//      independent walk to reach the SAME entry stop (HELPER_ARGUMENT), which is
				//      exactly what "not redefined in between" means;
				//  (c) the read-back cell idx came from is provably the bank number; and
				//  (d) the table itself is an identity over [0, fieldMask].
				// (c) and (d) are strategy/mirror knowledge this scanner has no business
				// evaluating, so they are asked of Hooks.isIdentityTableLoad, which defaults to
				// "no" -- nothing changes for a strategy that does not override it.
				if (mirrored == null && !readBack && aAcc == 0xFF && oAcc == 0x00
						&& isAbsoluteIndexed(prev)) {
					Address idxBase = LoopIdioms.indexedBase(prev);
					Register idxRegister = LoopIdioms.indexReg(prev);
					String idxName = idxRegister == null ? null : idxRegister.getName().toUpperCase();
					if (idxBase != null && ("X".equals(idxName) || "Y".equals(idxName))
							&& depth < MAX_RESOLVE_DEPTH) {
						char idxChar = idxName.charAt(0);
						ReadBack idxReadBack = env.readBack(idxChar);
						if (idxReadBack != null) {
							// rule (b): the independent scan of idx starting AT this very
							// instruction (i.e. idx's value on entry to it) must reach env's own
							// entry stop with nothing in between having redefined idx. Shares
							// this walk's budget, exactly like effectiveOperandTarget's own
							// constantRegisterValue consultation just above does.
							//
							// Run at mask 0: a CLASSIFICATION-ONLY scan. env's own value for idx
							// can be partially known (a ROM_IDENTIFYING mirror's upper bits are
							// proven zero -- IdentifyingEncoding#byteFor), and at any wider mask
							// stopped()'s "a value that knows something is a resolved value"
							// demotion would turn the entry stop's HELPER_ARGUMENT into RESOLVED.
							// At mask 0 combine() can know nothing, so the stop reason survives and
							// HELPER_ARGUMENT means exactly "reached env's entry stop with nothing
							// redefining idx". Value equality against env.get(idx) was rejected: a
							// helper that reloads idx from the same mirror yields an equal partial
							// value while committing the bank live at the CALL, not the read-back.
							Scan idxScan = resolveStoredValue(program, prev, idxChar,
								MechanismState.unknown(), CLASSIFY_ONLY, hooks, env, budget, depth + 1);
							boolean idxUnmodifiedFromEntry =
								idxScan.stop() == BankSwitchStrategy.ValueStop.HELPER_ARGUMENT;
							if (idxUnmodifiedFromEntry
									&& hooks.isIdentityTableLoad(prev, idxBase, idxReadBack)) {
								// The value stays unknown -- only WHERE the bank was last read
								// back is known, not what it was. See Hooks.isIdentityTableLoad's
								// javadoc for why idxReadBack itself (not a new ReadBack about
								// this load) is the right thing to report.
								return stopped(aAcc, oAcc, mask, PartialByte.unknown(),
									BankSwitchStrategy.ValueStop.RESTORED_BANK, idxReadBack);
							}
						}
					}
				}
				// A load from a VOLATILE block -- memory-mapped I/O -- IS genuinely runtime and can
				// never be pinned statically: PPU status, controller input, APU state. isVolatile()
				// is the established test for this (DescriptorMemory sets it for `kind: io` regions;
				// IoPolicy already keys off it), and it cannot overlap grm-hum, because nothing in
				// the image stores a determinable value to a hardware register.
				if (readsVolatileMemory(program, target)) {
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(),
						BankSwitchStrategy.ValueStop.RUNTIME_SOURCE);
				}
				// A load from writable memory that NOTHING in the image ever stores to (bead
				// grm-rr5p). "Loads from writable memory" is two opposite situations, and only
				// one is honest:
				//   untouched cell   no instruction writes it, so nothing could have determined
				//                    its content and no analysis could ever pin it down.
				//                    nesmirrortest's $30/$31/$33 (cells that fixture creates
				//                    precisely as having "no known content") and banktest2's
				//                    $0400 are this -- a NOTE is correct.
				//   parameter latch  written elsewhere and read here. nesmirrortest c102 reads
				//                    $59, stored at c02d; dbz_datach cc2a is `LDA $59 / STA $8008`
				//                    inside helper FUN_cc28 with ~300 `STA $59` sites in the PRG.
				//                    The value is recoverable in principle -- grm-hum's own
				//                    population -- so it stays ANALYZER_LIMIT, visible as work.
				// The first attempt (2026-09-02, grm-3ou) used "writable block" alone and could not
				// tell them apart; re-measured 2026-10-04 it flipped c102 and cc2a wrongly. The
				// test below is the narrower one: see neverStoredTo. A failed recovery where SOME
				// store exists -- even one we cannot follow -- remains ANALYZER_LIMIT.
				if (neverStoredTo(program, target)) {
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(),
						BankSwitchStrategy.ValueStop.RUNTIME_SOURCE);
				}
				//
				// Last resort (grm-4bgh.1): a STACK-RELATIVE RELOAD -- see stackRelativePush's
				// javadoc for the shape and soundness argument. Restricted to reg == 'A': the push
				// this finds is always a PHA (the only 6502 mnemonic that saves a value byte), so
				// resuming THIS SAME walk from it, under the accumulators built so far, is only
				// sound when the register already being tracked is A -- for X/Y the byte read came
				// from A, not the tracked register, and resuming the walk under the wrong register
				// name could attribute an unrelated earlier X/Y definition to this load.
				if (reg == 'A') {
					Span reload = new Span();
					Instruction pha = stackRelativePush(program, prev, hooks, env,
						MAX_BACKWARD_SCAN - i, reload);
					i += reload.steps;
					// The reload's search may have stepped over a mechanism write to reach its
					// push (rcransom's FUN_fed1 does exactly this -- see grm-4bgh.7), or a call
					// (grm-mej.3 increment 3). Same rules as the PLA case below, applied HERE
					// because the walk that resumes from the push is this one.
					MechanismState resumed = resumeStateAfterPairing(reload, pha, hooks, inState);
					stateBlind = stateBlind && !(reload.crossedCall || reload.crossedBlock);
					if (pha != null && resumed != null) {
						inState = resumed;
						if (reload.crossedCall) {
							carriedAcross = reload.crossedCallAt;
						}
						cur = pha;
						continue;
					}
					// pha == null, or the pairing crossed a call with no state available at the
					// push (abandon -- see resumeStateAfterPairing): fall through to the generic
					// modifier handling below exactly as an unpaired reload always has.
				}
			}

			if (reg == 'A' && mnem.equals("PLA")) {
				// grm-mej.3 increment 2: rather than surrender to the generic clobber below, find
				// the PHA this PLA pairs with (by stack DEPTH, not address -- see
				// findMatchingPush) and keep resolving from the value A held right before it. The
				// accumulators are intact and keep composing across the pop, which is what makes
				// "PLA / AND #imm / STA" resolve correctly and not just a bare "PLA / STA".
				Span pairing = new Span();
				Instruction pha = findMatchingPush(program, prev, MAX_BACKWARD_SCAN - i, hooks,
					env, pairing);
				i += pairing.steps;
				if (pha == null && hooks.hasStateOracle() && !env.hasArms()) {
					// FALLBACK (bead grm-mej.3 increment X1): the straight-line search gave up --
					// a flow break, an unbalanced pop, a budget exhaustion. Try the bounded
					// cross-block ALL-PATHS proof, which can only turn this decline into an
					// answer (residual failures are the SAME ones findMatchingPush already
					// reports). Its own node/join cap (CROSS_BLOCK_NODE_CAP/CROSS_BLOCK_JOIN_CAP,
					// raised 2026-10-03, grm-mej.7) is independent of MAX_BACKWARD_SCAN, so
					// it is charged exactly ONE step against this walk's budget regardless of what
					// it spent internally (OWNER RULING Q1, 2026-09-27) -- and env.hasArms() is
					// excluded outright rather than searched (grm-wul arm queries, out of scope
					// for this increment).
					Span crossBlock = new Span();
					List<Instruction> crossPhas = crossBlockMatchingPush(program, prev, hooks, env,
						crossBlock);
					i += 1;
					if (crossPhas.size() > 1) {
						// bead grm-mej.21: the pop's arms each pushed their own byte.
						return pairedArms(program, prev, crossPhas, reg, aAcc, oAcc, mask, hooks,
							env, budget, depth, i);
					}
					if (crossPhas.size() == 1) {
						pha = crossPhas.get(0);
						pairing = crossBlock;
					}
				}
				// This walk resumes from the push, so the consequence of what the search crossed
				// (a mechanism write, a call, a control-flow join) lands on THIS walk's in-state
				// -- see resumeStateAfterPairing.
				MechanismState resumed = resumeStateAfterPairing(pairing, pha, hooks, inState);
				stateBlind = stateBlind && !(pairing.crossedCall || pairing.crossedBlock);
				if (pha == null || resumed == null) {
					return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				inState = resumed;
				if (pairing.crossedCall) {
					carriedAcross = pairing.crossedCallAt;
				}
				if (pairing.crossedBlock) {
					crossBlockPush = pha.getMinAddress();
					crossBlockPull = prev.getMinAddress();
				}
				cur = pha;
				continue;
			}

			// TAX/TAY renaming (bead grm-ld68): when tracking Y and prev is TAY (or tracking X
			// and prev is TAX), the value carried past this point is A's, not an opaque Y/X
			// modifier -- switch what this walk tracks to A and keep resolving under the SAME
			// accumulators (contra's `PLA / TAY / JSR helper`, where the helper consumes Y but
			// the value was A's all along). transferSource(mnem, reg) also answers TXA/TYA
			// (source X/Y, writing A) when reg == 'A', but that direction never returns 'A' as
			// the source -- only TAX (reg == 'X') and TAY (reg == 'Y') do -- so the `== 'A'` test
			// below excludes TXA/TYA automatically without a second mnemonic check; renaming on
			// TXA/TYA would move a direct A-site scan onto X/Y, which is out of scope here.
			Character transferredFrom = transferSource(mnem, reg);
			if (transferredFrom != null && transferredFrom == 'A') {
				reg = transferredFrom;
				modifiers = MosOperands.registerModifiers(reg);
				loadMnemonic = "LD" + reg;
				cur = prev;
				continue;
			}

			if (MosOperands.modifiesRegister(modifiers, mnem, prev)) {
				// The mask algebra has met something it cannot decompose per bit -- an
				// ASL/LSR/ROL/ROR, an ADC/SBC, a transfer, or a load whose base nothing above
				// could resolve. Before declining, ask the OTHER evaluator whether the register
				// is nevertheless an exact constant here (bead grm-4bgh.6).
				//
				// WHY THIS IS ADDITIVE, NOT A MERGER OF THE TWO EVALUATORS. Reaching this line
				// already means the walk is returning `unknown` for the base; a non-null answer
				// can therefore only turn a decline into an answer, never change one answer into
				// a different one. The two evaluators stay apart -- the mask algebra is not
				// taught arithmetic (see constantRegisterValue's javadoc for why an effective
				// address wants all-or-nothing and a deposit wants per-bit), and
				// BitAlgebraEquivalenceTest keeps proving exactly what it proved before. An
				// all-or-nothing answer converts cleanly into a base here because it is fully
				// known: it enters combine() the same way the `LD<reg> #imm` branch's
				// fullyKnown(0xFF, imm) does, and the accumulators keep composing over it.
				//
				// A FRESH BUDGET, matching the LD<reg> branch's effectiveOperandTarget call
				// rather than the forwarding chain's shared one: this query is a leaf of the
				// walk (constantRegisterValue never re-enters resolveStoredValue, so the
				// recursion terminates), and spending a forwarding chain's remaining budget on
				// it would silently shorten the outer scan that is still running.
				//
				// Note this inherits constantRegisterValue's conservative in-state rule -- it
				// asks resolveLoad with MechanismState.unknown(), never inStateAtStore -- so nothing
				// resolved through here can make a cacheable strategy state-dependent.
				Integer exact = constantRegisterValue(program, cur, reg, hooks, env,
					new Budget(MAX_RESOLVE_STEPS));
				if (exact != null) {
					return stopped(aAcc, oAcc, mask, PartialByte.fullyKnown(exact),
						BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
				}
				// FALLBACK (bead grm-zsxz increment Z2): a load of a RAM cell that nothing above
				// could resolve -- forwarding stopped at a call or a block boundary -- is traced
				// backward over ALL paths, across calls and joins, to the one store that filled it.
				// Oracle path only (it resumes through Hooks.stateAt), never along a grm-wul arm,
				// and it returns null on every failure so this line's answer is exactly today's.
				// Its own node/join/census caps bound it; the enclosing walk ends here either way, so
				// (unlike X1's resumed pairing) there is no remaining step budget to charge.
				if (mnem.equals(loadMnemonic) && !MosOperands.isImmediate(prev) && hooks.hasStateOracle() &&
					!env.hasArms()) {
					Scan viaSlot = saveSlotForwarded(program, prev, aAcc, oAcc, mask, hooks, env,
						budget, depth);
					if (viaSlot != null) {
						return viaSlot;
					}
				}
				return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
			}
			if (prev.getFlowType().isCall() && calleePreserves(program, prev, reg)) {
				// grm-mej.13: the register survives the call; the bank state need not. Resume with
				// the state AT the call (before it ran), exactly as a call-crossing pairing does
				// (resumeStateAfterPairing); with none available, go blind (see stateBlind).
				MechanismState atCall = hooks.stateAt(prev.getMinAddress());
				if (atCall != null) {
					inState = atCall;
					stateBlind = false;
				}
				else {
					stateBlind = true;
				}
				cur = prev;
				continue;
			}
			if (prev.getFlowType().isCall()) {
				// (grm-mej.13: a call the callee provably leaves `reg` untouched across is
				// stepped over -- see calleePreserves. Everything below is the unchanged
				// clobber path.)
				//
				// NOT RUNTIME_SOURCE, though grm-3ou's description proposes it. banktest2's C5
				// fixture is the counter-example: LDA #$35 / JSR sub / STA $01 -- the value WAS
				// known and we lost it only because this scanner conservatively assumes any call
				// clobbers the register. If the callee never touches A, $35 survives on real
				// hardware. That is recoverable in principle by inter-procedural analysis, so it is
				// our limitation and must stay visible as such. See grm-rr5p.
				return stopped(aAcc, oAcc, mask, PartialByte.unknown(),
					BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
			}
			cur = prev;
		}
		return stopped(aAcc, oAcc, mask, PartialByte.unknown(), BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
	}


	/** Instructions that leave N and Z alone, which {@link #knownBranchOutcome} may walk back over
	 *  to the flag setter. Deliberately short: anything not listed ends the walk. */
	private static final Set<String> NZ_NEUTRAL = Set.of("STA", "STX", "STY", "STZ", "PHA",
		"PHX", "PHY", "PHP", "CLC", "SEC", "CLI", "SEI", "CLD", "SED", "CLV", "NOP", "TXS");

	/** Instructions that set N and Z from the register they write, keyed to that register. */
	private static final Map<String, Character> NZ_FROM_RESULT = Map.ofEntries(
		Map.entry("LDA", 'A'), Map.entry("LDX", 'X'), Map.entry("LDY", 'Y'),
		Map.entry("TAX", 'X'), Map.entry("TAY", 'Y'), Map.entry("TXA", 'A'),
		Map.entry("TYA", 'A'), Map.entry("TSX", 'X'), Map.entry("PLA", 'A'),
		Map.entry("INX", 'X'), Map.entry("DEX", 'X'), Map.entry("INY", 'Y'),
		Map.entry("DEY", 'Y'), Map.entry("AND", 'A'), Map.entry("ORA", 'A'),
		Map.entry("EOR", 'A'), Map.entry("ADC", 'A'), Map.entry("SBC", 'A'));

	/**
	 * Whether conditional branch {@code branch} is provably TAKEN ({@code TRUE}), provably NOT
	 * taken ({@code FALSE}), or either ({@code null}) -- bead grm-uurl. Modeled for {@code BEQ},
	 * {@code BNE}, {@code BMI} and {@code BPL}, whose Z/N come from the last instruction that set
	 * them: the walk goes back over {@link #NZ_NEUTRAL} instructions within one straight-line run
	 * ({@link FlowEdges#isControlFlowJoin} ends it) to a setter in {@link #NZ_FROM_RESULT}, and asks
	 * {@link #constantRegisterValue} -- state-free, as for {@link #constantIndex} -- for the
	 * register's value right after it. Z is "that value is 0", N its bit 7 ({@code ADC}/{@code SBC}
	 * only in binary mode -- {@link #binaryModeFlags}). Anything else, or an accumulator
	 * shift/rotate or a memory read-modify-write (which set flags from a result this does not
	 * evaluate), declines. Blaster Master's {@code ebf2}: {@code LDA #0 / STA $2006 /
	 * BEQ $EC34} is always taken.
	 */
	static Boolean knownBranchOutcome(Program program, Instruction branch) {
		String br = branch.getMnemonicString().toUpperCase();
		if (!br.equals("BEQ") && !br.equals("BNE") && !br.equals("BMI") && !br.equals("BPL")) {
			return null;
		}
		Listing listing = program.getListing();
		Instruction after = branch;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			Instruction prev = listing.getInstructionBefore(after.getMinAddress());
			if (prev == null || !FlowEdges.fallsInto(prev, after) ||
				FlowEdges.isControlFlowJoin(program, after, prev) || prev.getFlowType().isCall()) {
				return null;
			}
			String m = prev.getMnemonicString().toUpperCase();
			if (NZ_NEUTRAL.contains(m)) {
				after = prev;
				continue;
			}
			Character reg = NZ_FROM_RESULT.get(m);
			if (reg == null || !binaryModeFlags(program, prev, m)) {
				return null;
			}
			Integer v = constantRegisterValue(program, after, reg, Hooks.INERT, RegisterEnv.NONE,
				new Budget(MAX_RESOLVE_STEPS));
			if (v == null) {
				return null;
			}
			boolean z = (v & 0xFF) == 0;
			boolean n = (v & 0x80) != 0;
			return switch (br) {
				case "BEQ" -> z;
				case "BNE" -> !z;
				case "BMI" -> n;
				default -> !n; // BPL
			};
		}
		return null;
	}

	/**
	 * Whether {@code setter}'s N/Z are the flags of the value {@link #constantRegisterValue}
	 * evaluates for it. Always, except for {@code ADC}/{@code SBC}: in NMOS decimal mode they set
	 * N/Z from the BINARY result while A receives the BCD one. So they qualify when D is provably
	 * clear before {@code setter}, or -- D unknown -- under the TABLE evaluator, which computes A
	 * as the binary sum by its own named assumption ({@link Mos6502ConstantSemantics}' "binary
	 * mode is assumed", the hardware on NES's 2A03), so the flags and the value agree. A provably
	 * SET D, or an unknown D under the PCODE evaluator (whose {@code ADC} honours D), declines.
	 */
	private static boolean binaryModeFlags(Program program, Instruction setter, String mnem) {
		if (!mnem.equals("ADC") && !mnem.equals("SBC")) {
			return true;
		}
		Integer d = constantLocValue(program, setter, ConstantSemantics.Loc.D, Hooks.INERT,
			RegisterEnv.NONE, new Budget(MAX_RESOLVE_STEPS));
		if (d != null) {
			return d == 0;
		}
		return BoardBankAnalyzer.constantSemanticsMode(program) ==
			BoardBankAnalyzer.ConstantSemanticsMode.TABLE;
	}

	/**
	 * Whether control passing from {@code from} to {@code target} lands in a BANKED window
	 * ({@link SplitDispatchTableAnalyzer#isBanked}) other than the bank image {@code from} itself
	 * executes in -- i.e. the code that runs there depends on which bank is mapped, which a
	 * state-free census cannot know. Undefined memory counts as unknown too.
	 * <p>
	 * A target inside a realized OVERLAY block is a known bank, whoever jumps there (bead
	 * grm-mej.24): an overlay holds one bank image by construction, and a flow into it is the
	 * analysis's own claim of which bank runs -- cv3's trampolines {@code JSR} into
	 * {@code W8000_M2_B8::b1fb}. Only base-space banked targets (a window's home bytes, cv3's
	 * {@code $C000} window under {@code bank_5116}) entered from another block stay unknown.
	 */
	static boolean entersUnknownBank(Program program, Instruction from, Address target) {
		MemoryBlock targetBlock = program.getMemory().getBlock(target);
		if (targetBlock == null) {
			return true;
		}
		if (targetBlock.isOverlay()) {
			return false;
		}
		if (!SplitDispatchTableAnalyzer.isBanked(program, targetBlock)) {
			return false;
		}
		MemoryBlock fromBlock = program.getMemory().getBlock(from.getMinAddress());
		return !targetBlock.equals(fromBlock);
	}

	/**
	 * Whether {@code ret} ({@code RTS}/{@code RTI}) ends a PUSH-THEN-RETURN dispatch ({@code LDA
	 * hi,X / PHA / LDA lo,X / PHA / RTS}): walking back over straight-line code, pushes outnumber
	 * pops before anything else intervenes. Such a return jumps to an address the listing never
	 * records, so the census cannot see where it goes and must abandon. A heuristic over the
	 * last {@link SaveSlotForwarding#RETURN_DISPATCH_LOOKBACK} instructions -- an epilogue restoring saved registers
	 * ({@code PLA / TAY / PLA / RTS}) pops, and passes.
	 */
	static boolean looksLikeReturnDispatch(Listing listing, Instruction ret) {
		int balance = 0;
		Instruction cur = ret;
		for (int k = 0; k < RETURN_DISPATCH_LOOKBACK; k++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !FlowEdges.fallsInto(prev, cur) ||
				prev.getFlowType().isCall() || prev.getFlows().length > 0) {
				return false;
			}
			String m = prev.getMnemonicString().toUpperCase();
			if (m.equals("PHA") || m.equals("PHP")) {
				if (++balance > 0) {
					return true;
				}
			}
			else if (m.equals("PLA") || m.equals("PLP")) {
				balance--;
			}
			cur = prev;
		}
		return false;
	}

	/**
	 * How {@code instr} relates to the save slot {@code cell} (bead grm-zsxz increment Z2) -- the
	 * per-instruction writer test both the save-slot search and the callee census use. Compared by
	 * PHYSICAL offset, so an overlay-space operand naming the same RAM cell still matches.
	 * <ul>
	 * <li>a write reference to the slot, from anything: {@code STORES_SLOT} if the instruction is
	 * a plain {@code ST<r>} whose operand is the slot, else {@code WRITES_SLOT};</li>
	 * <li>otherwise only the memory-writing mnemonics ({@link #MEMORY_WRITERS}, plus the 65C02
	 * {@code STZ}/{@code TSB}/{@code TRB}) are considered -- stack pushes and calls write only the
	 * stack page, which {@link StackFloor} keeps out of scope;</li>
	 * <li>a plain operand: {@code STORES_SLOT}/{@code WRITES_SLOT} on the slot (by store vs.
	 * read-modify-write), {@code NONE} elsewhere;</li>
	 * <li>by 6502 addressing mode: {@code (zp,X)}/{@code (zp),Y} are {@code INDIRECT_ASSUMED}
	 * ({@link SlotAssumption#INDIRECT_STORES_DO_NOT_WRITE_SLOT}); an indexed store whose index is
	 * a provable constant ({@link #constantIndex}) writes exactly {@code base+idx} (mod {@code $100}
	 * for zero-page indexed); failing that, one inside a counted loop ({@link #loopIndexRange},
	 * grm-mej.15) writes exactly {@code base+lo..base+hi}; otherwise zero-page indexed wraps within
	 * the zero page, so it writes a zero-page slot and nothing else; absolute indexed reaches
	 * {@code base..base+$FF}; anything else is {@code UNPLACEABLE}.</li>
	 * </ul>
	 */
	static SlotWrite classifySlotWrite(Program program, Instruction instr, Address cell) {
		return classifySlotWrite(program, instr, cell, IndexRegs.UNKNOWN);
	}

	/** {@link #classifySlotWrite} with the index registers {@link SaveSlotForwarding#calleeClosureCensus}
	 *  propagated to {@code instr} (bead grm-mej.25); an unknown one falls back to the
	 *  state-free evaluators. */
	static SlotWrite classifySlotWrite(Program program, Instruction instr, Address cell,
			IndexRegs known) {
		Character storeReg = MosOperands.storeRegister(instr);
		Address plain = MosOperands.plainAbsoluteTarget(instr);
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isWrite() && sameCell(ref.getToAddress(), cell)) {
				return storeReg != null && plain != null && sameCell(plain, cell)
						? SlotWrite.STORES_SLOT : SlotWrite.WRITES_SLOT;
			}
		}
		String mnem = instr.getMnemonicString().toUpperCase();
		boolean writer = (MEMORY_WRITERS.contains(mnem) && !MosOperands.isAccumulatorForm(instr)) ||
			mnem.equals("STZ") || mnem.equals("TSB") || mnem.equals("TRB");
		if (!writer) {
			return SlotWrite.NONE;
		}
		if (plain != null) {
			if (!sameCell(plain, cell)) {
				return SlotWrite.NONE;
			}
			return storeReg != null ? SlotWrite.STORES_SLOT : SlotWrite.WRITES_SLOT;
		}
		int op;
		try {
			op = instr.getByte(0) & 0xFF;
		}
		catch (MemoryAccessException e) {
			return SlotWrite.UNPLACEABLE;
		}
		int mode = (op >> 2) & 7;
		int group = op & 3;
		if (group == 1 && (mode == 0 || mode == 4)) {
			return SlotWrite.INDIRECT_ASSUMED; // (zp,X) / (zp),Y -- the named assumption
		}
		if (mode == 5 || mode == 6 || mode == 7) {
			Address base = LoopIdioms.indexedBase(instr);
			Integer idx = knownIndex(instr, known);
			if (idx == null) {
				idx = constantIndex(program, instr);
			}
			boolean zeroPage = mode == 5;
			if (idx != null && base != null) {
				// A provably constant index pins the ONE cell written: base+idx, wrapping inside
				// page zero for the zero-page indexed modes ($FF,X with X=1 writes $00).
				long target = zeroPage ? (base.getOffset() + idx) & 0xFF : base.getOffset() + idx;
				if (target != cell.getOffset()) {
					return SlotWrite.NONE;
				}
				// it writes exactly the slot, but through an indexed form: not a source this
				// proof re-scans, so it counts as a writer
				return SlotWrite.WRITES_SLOT;
			}
			LoopIdioms.IndexRange range = base == null ? null : loopIndexRange(program, instr);
			if (range != null) {
				// A counted loop bounds the index (grm-mej.15): the store reaches exactly
				// base+lo..base+hi, wrapping inside page zero for the zero-page indexed modes.
				long delta = cell.getOffset() - base.getOffset();
				if (zeroPage) {
					delta &= 0xFF;
				}
				boolean reachable = (!zeroPage || cell.getOffset() < 0x100) && delta >= 0 &&
					delta <= 0xFF && range.contains((int) delta);
				return reachable ? SlotWrite.WRITES_SLOT : SlotWrite.NONE;
			}
			if (zeroPage) {
				// unknown index: the effective address may be any zero-page cell
				return cell.getOffset() < 0x100 ? SlotWrite.WRITES_SLOT : SlotWrite.NONE;
			}
			if (base == null) {
				return SlotWrite.UNPLACEABLE;
			}
			long lo = base.getOffset();
			long c = cell.getOffset();
			return c >= lo && c <= lo + 0xFF ? SlotWrite.WRITES_SLOT : SlotWrite.NONE;
		}
		return SlotWrite.UNPLACEABLE;
	}

	/**
	 * The index register's value on entry to an indexed store, when it is a PROVABLE constant
	 * (bead grm-zsxz Z2, owner ruling 2026-10-05): {@link #constantRegisterValue}'s
	 * all-or-nothing straight-line walk, so a redefinition it cannot evaluate ({@code INX} of an
	 * unknown, {@code TAX}, {@code PLA}-fed transfers, a call, a join, a block boundary) yields
	 * {@code null} and the caller keeps its conservative window rule. State-free: evaluated under
	 * {@link Hooks#INERT} and {@link RegisterEnv#NONE}, with a fresh budget. Blaster Master's
	 * {@code ea3a} ({@code LDX #$7A / ... / STA $00,X / STA $01,X}) is the measured case.
	 */
	/** The propagated value of {@code instr}'s index register, or {@code null}. */
	private static Integer knownIndex(Instruction instr, IndexRegs known) {
		Register idx = LoopIdioms.indexReg(instr);
		if (idx == null) {
			return null;
		}
		String name = idx.getName().toUpperCase();
		return name.equals("X") ? known.x() : name.equals("Y") ? known.y() : null;
	}

	private static Integer constantIndex(Program program, Instruction instr) {
		Register idx = LoopIdioms.indexReg(instr);
		if (idx == null) {
			return null;
		}
		String name = idx.getName().toUpperCase();
		if (!name.equals("X") && !name.equals("Y")) {
			return null;
		}
		Integer v = constantRegisterValue(program, instr, name.charAt(0), Hooks.INERT,
			RegisterEnv.NONE, new Budget(MAX_RESOLVE_STEPS));
		return v == null ? null : v & 0xFF;
	}

	/**
	 * The index range of an indexed store inside a counted loop
	 * ({@link LoopIdioms#countedLoopIndexRange}, bead grm-mej.15), with the counter's entry value
	 * proven by the same state-free evaluator as {@link #constantIndex}. Blaster Master's
	 * {@code e6fe}/{@code ce02} ({@code LDX #$1F / STA $58,X / DEX / BPL}: {@code $58..$77}) and
	 * {@code e8d8} ({@code LDX #1 / ... STA $F5,X / DEX / BPL}: {@code $F5..$F6}) are the cases
	 * that otherwise count as writing every zero-page cell.
	 */
	private static LoopIdioms.IndexRange loopIndexRange(Program program, Instruction instr) {
		Register idx = LoopIdioms.indexReg(instr);
		if (idx == null) {
			return null;
		}
		char reg = Character.toUpperCase(idx.getName().charAt(0));
		return LoopIdioms.countedLoopIndexRange(program, instr,
			p -> constantRegisterValue(program, p, reg, Hooks.INERT, RegisterEnv.NONE,
				new Budget(MAX_RESOLVE_STEPS)));
	}

	/**
	 * What a backward walk that reached a JOIN at {@code at} can still say about {@code reg}
	 * (bead grm-mej.29): when {@code reg} is the counter of a counted loop whose body contains
	 * {@code at} before the step ({@link LoopIdioms#countedLoopRange}), the bits every value in
	 * the range shares -- the bits above the highest one {@code lo} and {@code hi} differ in. A
	 * join is exactly where a loop head sits, so this is the walk's one chance to see the range.
	 * megaman3's {@code ff49} ({@code LDX #0 / L: STX $8000 / ... / INX / CPX #6 / BNE L}, X in
	 * 0..5) is the case: bits 3..7, prg_mode among them, are provably 0. Unknown otherwise.
	 */
	private static PartialByte countedLoopValue(Program program, Instruction at, char reg) {
		LoopIdioms.IndexRange range = LoopIdioms.countedLoopRange(program, at, reg,
			p -> constantRegisterValue(program, p, Character.toUpperCase(reg), Hooks.INERT,
				RegisterEnv.NONE, new Budget(MAX_RESOLVE_STEPS)));
		if (range == null) {
			return PartialByte.unknown();
		}
		int differ = range.lo() ^ range.hi();
		int varying = differ == 0 ? 0 : (Integer.highestOneBit(differ) << 1) - 1;
		int known = ~varying & 0xFF;
		return PartialByte.of(known, range.lo() & known);
	}

	/** Same physical RAM cell, whichever (overlay or base) space names it. */
	private static boolean sameCell(Address a, Address cell) {
		return a != null && a.getOffset() == cell.getOffset() &&
			a.getAddressSpace().getPhysicalSpace().equals(cell.getAddressSpace().getPhysicalSpace());
	}

	/**
	 * Finds the {@code PHA} whose pushed byte a STACK-RELATIVE RELOAD reads: a load shaped
	 * {@code LD<reg> $01nn,X} following a {@code TSX}, which reads a byte saved earlier on the
	 * stack <em>without popping it</em> -- the idiom 6502 code uses when a stack-passed value is
	 * needed more than once (bead grm-4bgh.1). River City Ransom's {@code FUN_fed1} is the
	 * motivating shape:
	 * <pre>
	 *   FED1  PHA            ; save the caller's bank argument
	 *   FED2  TXA
	 *   FED3  PHA            ; save X
	 *   ...
	 *   FEDB  TSX            ; X = S
	 *   FEDC  LDA $0102,X    ; &lt;- reads the byte pushed at FED1, without popping it
	 * </pre>
	 * <p>
	 * <b>Address arithmetic.</b> {@code TSX} copies {@code S} into {@code X}, so immediately
	 * afterward {@code $0100 + X} is the CURRENT top of stack and {@code $0100 + X + n} is the
	 * byte {@code n} pushes back from there, counting the most recent push as {@code n == 1}: a
	 * push writes {@code $0100 + S} and then decrements {@code S}, so the byte a {@code PHA}
	 * <em>just</em> wrote sits at {@code $0100 + (S - 1) + 1}, i.e. one more than the
	 * post-decrement {@code S} that a following {@code TSX} would load. An operand
	 * {@code $01nn,X} therefore names {@code n = nn}, and finding the push it reads is
	 * exactly {@link CrossBlockStackPairing#findMatchingPush}'s depth-{@code n} generalization, entered at the
	 * {@code TSX} rather than at a {@code PLA} (which always owes exactly {@code n == 1}).
	 * <p>
	 * This method's own job is upstream of that: given {@code load}, confirm its shape (absolute
	 * indexed by X, base in {@code $0101..$01FF}), walk backward to find the {@code TSX} that set
	 * X, and confirm nothing in between could have overwritten the slot -- then hand off to
	 * {@link CrossBlockStackPairing#findMatchingPush}.
	 * <p>
	 * <b>Returns {@code null} (decline) when:</b>
	 * <ul>
	 * <li>{@code load} is not absolute-indexed ({@link #isAbsoluteIndexed}, base from
	 * {@link LoopIdioms#indexedBase}, index register from {@link LoopIdioms#indexReg});</li>
	 * <li>the index register is not X -- nothing on 6502 copies {@code S} into Y, so a
	 * {@code $01nn,Y} operand can never be this idiom;</li>
	 * <li>the base does not lie in {@code $0101..$01FF} -- outside the stack page, or naming
	 * {@code $0100} itself ({@code n == 0}, which is not "{@code n} pushes back" from anything);</li>
	 * <li>walking backward from {@code load} to find the {@code TSX}, ANY of the guards
	 * {@link CrossBlockStackPairing#findMatchingPush} itself applies is violated first: {@code env.stopsAt}, the
	 * instruction before {@code cur} not existing, a broken fall-through, an unlicensed
	 * {@link FlowEdges#isControlFlowJoin}, a flow or a call, or {@link Hooks#isMechanismWrite} -- reused
	 * verbatim rather than reimplemented, for the identical soundness reasons {@code
	 * findMatchingPush}'s own javadoc gives for each;</li>
	 * <li><b>ANY of {@code PHA}/{@code PHP}/{@code PLA}/{@code PLP} occurs between the
	 * {@code TSX} and {@code load}.</b> The load's effective address is
	 * {@code $0100 + S(at the TSX) + n} -- a fixed cell -- and a {@code PLA} followed by a
	 * {@code PHA} in that window can overwrite EXACTLY that cell with an unrelated byte before
	 * {@code load} reads it. Attributing the read to the push {@link CrossBlockStackPairing#findMatchingPush} finds
	 * would then be a confident WRONG value, not a missing one, which is the failure direction
	 * this scanner exists to avoid;</li>
	 * <li><b>anything writes X</b> in that same window. Asked of the LANGUAGE
	 * ({@link MosOperands#writesRegister}) rather than a mnemonic list -- see
	 * {@code HelperArgumentRecovery.argumentSurvivesPrologue}'s javadoc for the same call and why
	 * it is preferred over enumerating mnemonics. {@code TSX} itself writes X and is this walk's
	 * own terminator, so it is tested FIRST and the generic "writes X" test is applied only to
	 * every OTHER instruction in the window -- checking the generic test before recognizing
	 * {@code TSX} would misread the terminator itself as an abandon.</li>
	 * </ul>
	 * On finding the {@code TSX}, this hands off to {@link CrossBlockStackPairing#findMatchingPush} with
	 * {@code initialDepth = n}, entered AT the {@code TSX} (which is exactly where that method's
	 * own backward walk starts examining from, by design -- it inspects the instruction BEFORE
	 * the instruction it is handed).
	 *
	 * @param budgetSteps    how many further instructions this search -- INCLUDING the further
	 *                       search {@link CrossBlockStackPairing#findMatchingPush} performs once the {@code TSX} is
	 *                       found -- may step over, spent from the caller's own
	 *                       {@link #MAX_BACKWARD_SCAN} budget rather than a fresh one
	 * @param span           out-param, valid on every return path: how many instructions this
	 *                       search stepped over IN TOTAL (its own plus
	 *                       {@link CrossBlockStackPairing#findMatchingPush}'s), and whether either of them crossed a
	 *                       mechanism write
	 */
	/**
	 * {@link #stackRelativePush} exposed for a walk INSIDE a helper (bead grm-mej.7):
	 * {@code HelperArgumentRecovery}'s read-back retention asks which {@code PHA} a
	 * {@code TSX} / {@code LDA $01nn,X} reload in the helper's own body reads, so it can
	 * check that push saved the caller's argument. Reused rather than re-implemented, so
	 * "which push does this reload read" has one answer across value recovery and the
	 * read-back proof.
	 * <p>
	 * The backward walk stops at {@code helperEntry} (the caller's stack is not modelled
	 * there, just as for every other env-bounded walk in this class). A pairing that stepped
	 * over a call returns {@code null}: the caller's walk already refuses any call in the
	 * span, so this only makes that refusal independent of the caller.
	 *
	 * @return the {@code PHA} whose byte {@code load} reads, or {@code null} when it is not a
	 *         provable stack-relative reload of a push inside {@code [helperEntry, load)}
	 */
	static Instruction stackRelativeReloadPush(Program program, Instruction load, Hooks hooks,
			Address helperEntry, int budgetSteps) {
		RegisterEnv env = new RegisterEnv(helperEntry, PartialByte.unknown(), PartialByte.unknown(),
			PartialByte.unknown());
		Span span = new Span();
		Instruction pha = stackRelativePush(program, load, hooks, env, budgetSteps, span);
		return pha == null || span.crossedCall ? null : pha;
	}

	private static Instruction stackRelativePush(Program program, Instruction load, Hooks hooks,
			RegisterEnv env, int budgetSteps, Span span) {
		if (!isAbsoluteIndexed(load)) {
			span.steps = 0;
			return null;
		}
		Address base = LoopIdioms.indexedBase(load);
		Register idx = LoopIdioms.indexReg(load);
		if (base == null || idx == null || !idx.getName().equalsIgnoreCase("X")) {
			span.steps = 0;
			return null;
		}
		long baseOffset = base.getOffset();
		if (baseOffset < 0x101 || baseOffset > 0x1FF) {
			span.steps = 0;
			return null;
		}
		int n = (int) (baseOffset - 0x100);

		Register xRegister = program.getLanguage().getRegister("X");
		if (xRegister == null) {
			span.steps = 0;
			return null; // cannot ask the question -- do not assume the favorable answer
		}

		Listing listing = program.getListing();
		Instruction cur = load;
		int steps = 0;
		while (steps < budgetSteps) {
			if (env.stopsAt(cur.getMinAddress())) {
				span.steps = steps;
				return null; // the caller's stack is not modeled -- mirrors findMatchingPush
			}
			Instruction prev = pathPredecessor(program, listing, cur, env);
			if (prev == null) {
				span.steps = steps;
				// block start, left the basic block, or another path could reach here with a
				// different X/stack state
				return null;
			}
			if (prev.getFlows().length > 0 || prev.getFlowType().isCall()) {
				span.steps = steps;
				return null; // not straight-line
			}
			if (hooks.isMechanismWrite(prev)) {
				// Stepped over, not aborted on (bead grm-4bgh.7), mirroring findMatchingPush's
				// identical relaxation. Nothing this walk establishes -- that X came from a TSX,
				// and that no push, pop or X-write intervened -- is affected by a store to the
				// mechanism. The consequence for the VALUE is the caller's to apply.
				span.crossedMechanismWrite = true;
			}
			steps++;
			String mnem = prev.getMnemonicString().toUpperCase();
			if (mnem.equals("TSX")) {
				// The terminator: hand off to findMatchingPush, entered AT the TSX, for the
				// n-th push back from the top of stack it establishes.
				Span pushSpan = new Span();
				Instruction pha = findMatchingPush(program, prev, budgetSteps - steps, hooks, env,
					pushSpan, n);
				span.steps = steps + pushSpan.steps;
				span.crossedMechanismWrite |= pushSpan.crossedMechanismWrite;
				return pha;
			}
			if (mnem.equals("PHA") || mnem.equals("PHP") || mnem.equals("PLA") || mnem.equals("PLP")) {
				span.steps = steps;
				return null; // could overwrite the reloaded slot -- see javadoc
			}
			if (MosOperands.writesRegister(prev, xRegister)) {
				span.steps = steps;
				return null; // X changed before we found the TSX that is supposed to set it
			}
			cur = prev;
		}
		span.steps = steps;
		return null; // budget exhausted before a TSX was found
	}

	/**
	 * The instruction a backward walk steps to from {@code cur} on the path {@code env}
	 * describes, or {@code null} when the walk must stop at {@code cur}: there is no instruction
	 * before it, the one before it does not fall through into it (a basic-block start), or
	 * {@code cur} is a {@link FlowEdges#isControlFlowJoin control-flow join} the env neither licenses
	 * ({@link RegisterEnv#mayCrossJoinAt}, grm-k90) nor names an arm for
	 * ({@link RegisterEnv#armPredecessorAt}, grm-wul).
	 * <p>
	 * <b>Every backward walk in this class takes its predecessor step through here</b>, so the
	 * three questions -- block linkage, the join refusal, and the env's two exceptions to it --
	 * are answered identically whether the walk is resolving a register, forwarding a store,
	 * pairing a push, or evaluating the carry. That uniformity is what grm-k90 already required of
	 * the licensed join ("the licence describes the EDGE, not the kind of value being carried
	 * across it") and grm-wul's arm map inherits it: a path-forking query that resolved its
	 * register across an arm but refused to forward a store across the same arm would describe
	 * two different executions of one instruction stream.
	 * <p>
	 * An arm named by the env is taken WITHOUT the linkage test -- the predecessor on a branch
	 * arm is the branch, whose fall-through is not {@code cur} -- and without the join test, which
	 * is the point. The engine that built the map proved the edge exists (it enumerated the
	 * join's incoming flows), so nothing here re-derives it. Everything else the walk checks at
	 * that instruction (the mechanism-write withdrawal, the step bound, a walk's own
	 * straight-line-only rule) still runs; a stack walk that meets a branch as its arm's
	 * predecessor stops there exactly as it stops at any other flow instruction.
	 */
	static Instruction pathPredecessor(Program program, Listing listing, Instruction cur,
			RegisterEnv env) {
		Address curAddr = cur.getMinAddress();
		Address arm = env.armPredecessorAt(curAddr);
		if (arm != null) {
			return listing.getInstructionAt(arm);
		}
		Instruction prev = listing.getInstructionBefore(curAddr);
		if (prev == null) {
			return null;
		}
		if (!FlowEdges.fallsInto(prev, cur)) {
			return null; // not a straight-line predecessor of cur -- left the basic block
		}
		if (FlowEdges.isControlFlowJoin(program, cur, prev) && !env.mayCrossJoinAt(curAddr)) {
			return null;
		}
		return prev;
	}

	/**
	 * Checks whether every bit of {@code mask} is already determined by the accumulator
	 * alone, independent of whatever base register value {@code x} the scan eventually
	 * finds, given {@code result = (x & aAcc) | oAcc}: bit {@code b} is so determined
	 * iff {@code aAcc} clears it or {@code oAcc} sets it -- i.e. iff {@code ~aAcc | oAcc}
	 * covers every masked bit. (The exhaustive equivalence of this bit-parallel form to the
	 * original per-bit loop is proved by
	 * {@code src/test/java/retromachines/BitAlgebraEquivalenceTest.java}, run by
	 * {@code gradle test}.)
	 */
	private static boolean fullyDeterminedByAccumulator(int aAcc, int oAcc, int mask) {
		return ((~aAcc | oAcc) & mask) == mask;
	}

	/**
	 * Folds the accumulated transform {@code result = (x & aAcc) | oAcc} against a
	 * (possibly partially known) base {@link MechanismState} for {@code x}, reduced to
	 * {@code mask}: {@code oAcc} setting a bit forces a known 1; otherwise {@code aAcc}
	 * clearing it forces a known 0; otherwise the bit passes {@code x} through, so it is
	 * known in the result iff it is known in {@code base}. A result bit is 1 exactly when
	 * {@code oAcc} sets it, or {@code aAcc} passes a known base 1 through -- the base's
	 * <em>known</em> gate on that second term is what keeps result bits 0 in still-unknown
	 * positions (so two states compare equal iff genuinely equal). Equivalence to the
	 * original per-bit loop is proved exhaustively by
	 * {@code src/test/java/retromachines/BitAlgebraEquivalenceTest.java} ({@code gradle test}).
	 */
	private static PartialByte combine(int aAcc, int oAcc, int mask, PartialByte base) {
		int knownMask = mask & (oAcc | ~aAcc | base.knownMask());
		int bits = mask & (oAcc | (aAcc & base.knownMask() & base.bits()));
		return new PartialByte(knownMask, bits); // the constructor clips to one byte
	}

	/**
	 * The scan mask meaning "CLASSIFY ONLY, the value is not wanted" (bead grm-ze06.1). Every
	 * scan's {@code mask} is a BYTE mask -- which bits of the stored byte the caller consumes. At
	 * mask 0 {@link #combine} can know nothing, so a scan reports only WHY it stopped (its
	 * {@link BankSwitchStrategy.ValueStop}): the identity-table index check and
	 * {@code HelperArgumentRecovery}'s read-back re-scan rely on exactly that, because at any
	 * wider mask {@link #stopped} would demote a partly known entry value to {@code RESOLVED}
	 * and lose the stop reason they are asking about.
	 */
	static final int CLASSIFY_ONLY = 0;

	/**
	 * A scan's answer plus, when it did not resolve, WHY (bead {@code grm-3ou} part 1).
	 * {@code stop} is only meaningful when {@code value.knownMask() == 0} -- with ONE exception, a
	 * {@code RESTORED_BANK} stop whose read-back the strategy could partly evaluate, which keeps
	 * both its partial value and its {@code readBack} (bead grm-mej.8; see
	 * {@code restoredKeepingValue}).
	 */
	record Scan(PartialByte value, BankSwitchStrategy.ValueStop stop, ReadBack readBack) {

		/** The pre-grm-yflf form: no read-back. */
		Scan(PartialByte value, BankSwitchStrategy.ValueStop stop) {
			this(value, stop, null);
		}
	}

	/**
	 * Whether {@code target} names MEMORY-MAPPED I/O -- a read whose value is produced by
	 * hardware at runtime and which no scan of static bytes could ever pin down. A null target
	 * is NOT runtime-sourced: failing to work out where a load reads from is our limitation.
	 */
	private static boolean readsVolatileMemory(Program program, Address target) {
		if (target == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(target);
		return block != null && block.isVolatile();
	}

	// ------------------------------------------------------------------
	// "No static store to this cell" (bead grm-rr5p)
	// ------------------------------------------------------------------

	/**
	 * Whether {@code target} is a WRITABLE, non-volatile RAM cell that no instruction in the
	 * program stores to -- the condition under which a load of it is genuinely
	 * {@link BankSwitchStrategy.ValueStop#RUNTIME_SOURCE}: nothing in the image could have
	 * determined what it holds, so no analysis could recover it. A null target is NOT
	 * qualifying (failing to work out where a load reads from is our limitation).
	 * <p>
	 * Three conditions, all required:
	 * <ol>
	 * <li>the block is writable and not volatile (a read-only block is a constant ROM byte,
	 * volatile is memory-mapped I/O -- both handled elsewhere);</li>
	 * <li>zero {@code isWrite()} references to the cell in the {@code ReferenceManager}
	 * <em>and</em> no disassembled instruction with a plain (non-indexed, non-indirect) operand
	 * that stores to it. The second leg exists because a reference is laid down only where
	 * something created one -- see {@link LocalStoreForwarding#writesMemory}'s refless-store note -- so references
	 * alone would call a plainly written cell untouched;</li>
	 * <li><b>for a ZERO-PAGE cell, additionally no store instruction anywhere in the program
	 * with an indexed or indirect operand.</b> Zero page is where 6502 parameter latches live
	 * and where {@code STA ($10),Y} / {@code STA $00,X} reach cells Ghidra never resolved to a
	 * concrete address, so absence of a write reference is much weaker evidence there. Outside
	 * zero page an indirect store is not assumed to reach the cell (the conservative variant
	 * the bead's measurement supported), but an ABSOLUTE-INDEXED store is: {@code STA base,X}
	 * can write any of {@code base..base+$FF}, so a cell in that window of any such store is
	 * treated as stored to. That range is exactly what the operand can address, so it costs
	 * nothing to honour and closes the obvious hole ({@code STA $03F0,X} reaching
	 * {@code $0400}).</li>
	 * </ol>
	 * Measured 2026-10-04 (bead grm-rr5p, Phase 1): the unqualified "writable block" rule flipped
	 * 5 fixture sites WARNING to NOTE plus dbz_datach cc2a on the real-ROM tier. This test keeps
	 * the untouched cells and refuses nesmirrortest c102 ($59) and dbz_datach cc2a, both of which
	 * have stores.
	 */
	static boolean neverStoredTo(Program program, Address target) {
		if (target == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(target);
		if (block == null || !block.isWrite() || block.isVolatile()) {
			return false;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(target)) {
			if (ref.getReferenceType().isWrite()) {
				return false;
			}
		}
		StoreCensus census = storeCensus(program);
		if (census.plainTargets().contains(target)) {
			return false;
		}
		if (target.getOffset() < 0x100 && census.anyUnresolvedStore()) {
			return false;
		}
		for (Address base : census.absIndexedBases()) {
			if (base.getAddressSpace().equals(target.getAddressSpace()) &&
				target.getOffset() >= base.getOffset() &&
				target.getOffset() <= base.getOffset() + 0xFF) {
				return false; // inside an absolute-indexed store's reachable window
			}
		}
		return true;
	}

	/**
	 * What one pass over the program's instructions found out about its stores: the set of
	 * addresses written by a plain operand or by a write reference, whether ANY store has
	 * an indexed/indirect operand, and the base of every absolute-indexed store.
	 */
	private record StoreCensus(long modNumber, Set<Address> plainTargets,
			boolean anyUnresolvedStore, List<Address> absIndexedBases) {
	}

	/**
	 * One census per program, recomputed only when {@link Program#getModificationNumber()} has
	 * moved -- so {@link #neverStoredTo} costs one listing pass per analysis state, not one per
	 * load.
	 */
	private static final Map<Program, StoreCensus> STORE_CENSUS =
		new java.util.WeakHashMap<>();

	private static StoreCensus storeCensus(Program program) {
		synchronized (STORE_CENSUS) {
			StoreCensus cached = STORE_CENSUS.get(program);
			if (cached != null && cached.modNumber() == program.getModificationNumber()) {
				return cached;
			}
			Set<Address> plain = new HashSet<>();
			boolean unresolved = false;
			List<Address> absIndexedBases = new ArrayList<>();
			for (Instruction instr : program.getListing().getInstructions(true)) {
				String mnem = instr.getMnemonicString().toUpperCase();
				if (!(MEMORY_WRITERS.contains(mnem) || mnem.equals("STZ") ||
					mnem.equals("TSB") || mnem.equals("TRB")) || MosOperands.isAccumulatorForm(instr)) {
					continue;
				}
				for (Reference ref : instr.getReferencesFrom()) {
					if (ref.getReferenceType().isWrite()) {
						plain.add(ref.getToAddress());
					}
				}
				Address t = MosOperands.plainAbsoluteTarget(instr);
				if (t != null) {
					plain.add(t);
				}
				else {
					unresolved = true;
					if (isAbsoluteIndexed(instr)) {
						Address base = LoopIdioms.indexedBase(instr);
						if (base != null) {
							absIndexedBases.add(base);
						}
					}
				}
			}
			StoreCensus census = new StoreCensus(program.getModificationNumber(), plain, unresolved,
				List.copyOf(absIndexedBases));
			STORE_CENSUS.put(program, census);
			return census;
		}
	}

	/**
	 * {@link #combine} carrying the reason the walk stopped. The reason is DISCARDED when the
	 * combined value turns out to know something: the mask algebra can pin bits down even
	 * where the base is unknown (that is what {@link #fullyDeterminedByAccumulator} exploits),
	 * so a call site's stated reason is a claim about the BASE, not about the result. Deciding
	 * that here, once, is what keeps every {@code return} in the walk free to name its own
	 * reason without also having to work out whether it still applies.
	 */
	static Scan stopped(int aAcc, int oAcc, int mask, PartialByte base,
			BankSwitchStrategy.ValueStop reason) {
		return stopped(aAcc, oAcc, mask, base, reason, null);
	}

	/**
	 * {@link #stopped(int, int, int, PartialByte, BankSwitchStrategy.ValueStop)} with the
	 * {@link ReadBack} a {@code RESTORED_BANK} stop names. Discarded with the reason when the
	 * combined value knows something: a read-back that resolved is just a resolved value.
	 */
	static Scan stopped(int aAcc, int oAcc, int mask, PartialByte base,
			BankSwitchStrategy.ValueStop reason, ReadBack readBack) {
		PartialByte value = combine(aAcc, oAcc, mask, base);
		return value.knownMask() != 0 ? new Scan(value, BankSwitchStrategy.ValueStop.RESOLVED)
				: new Scan(value, reason, readBack);
	}

	/**
	 * A {@code RESTORED_BANK} stop that KEEPS a partly known value (bead grm-mej.8), or {@code null}
	 * when the value is fully known over {@code mask} -- then the caller stops {@code RESOLVED} as
	 * before, since a concrete bank says strictly more than "restored".
	 * <p>
	 * {@link #stopped(int, int, int, PartialByte, BankSwitchStrategy.ValueStop, ReadBack)} turns ANY
	 * known bit into {@code RESOLVED} and drops the {@link ReadBack}. That is wrong for a read-back
	 * the strategy can only partly evaluate: rcransom's {@code LDA $bfff / PHA / ... / PLA / JSR
	 * fed1} at cd57/ef85 reaches the read with the bank partly pinned, so the ROM byte is partly
	 * known (A in {0,2,4,6}), and fed1's prologue then discards the caller's register value
	 * ({@code HelperArgumentRecovery.recoverCallArgument}), leaving neither a value nor the restore
	 * it really is. Keeping both is safe because every consumer of a call's read-back
	 * ({@code BoardBankAnalyzer}'s classification) gates on the argument NOT having resolved: where
	 * the partial value survives to the deposit, the read-back is simply unused.
	 * <p>
	 * Callers must establish the read-back's own shape first (identity accumulators, a live-bank
	 * mirror) -- this only decides between the two stop reasons.
	 */
	static Scan restoredKeepingValue(int aAcc, int oAcc, int mask, PartialByte base,
			ReadBack readBack) {
		PartialByte value = combine(aAcc, oAcc, mask, base);
		if (value.knowsAll(mask)) {
			return null;
		}
		return new Scan(value, BankSwitchStrategy.ValueStop.RESTORED_BANK, readBack);
	}


	// ------------------------------------------------------------------
	// Known effective address (grm-hum GAP 1)
	// ------------------------------------------------------------------

	/**
	 * The single address {@code instr}'s operand 0 actually accesses, when that is statically
	 * certain: {@link MosOperands#plainAbsoluteTarget} when the operand is unindexed (unchanged behavior),
	 * otherwise an <em>absolute</em>-indexed operand whose index register
	 * {@link #constantRegisterValue} pins to a fully known byte.
	 * <p>
	 * <b>Absolute-indexed only, deliberately.</b> Zero-page indexed wraps inside the zero page
	 * ({@code LDA $80,X} with {@code X == $FF} reads {@code $7F}, not {@code $17F} -- real 6502
	 * behavior, sleigh {@code tmp:2 = zext(imm8 + X)}), and both indirect modes read a pointer
	 * this scanner does not model. Absolute indexed does <em>not</em> wrap at a page boundary,
	 * so {@code base + idx} is exact -- and requiring a <em>fully</em> known index is what makes
	 * it exact rather than merely likely. Anything else declines.
	 *
	 * @param env register values to adopt at an entry stop -- {@link RegisterEnv#NONE} on every
	 *            path except a helper call site's mini-inline (grm-hum increment 2), which is
	 *            what lets Contra's {@code LDA $FFD0,Y} resolve from the caller's Y
	 */
	static Address effectiveOperandTarget(Program program, Instruction instr, Hooks hooks,
			RegisterEnv env) {
		return effectiveTarget(program, instr, hooks, env, new Budget(MAX_RESOLVE_STEPS), 0);
	}

	/** {@link #effectiveOperandTarget} within an ongoing query tree's depth and step budget. */
	static Address effectiveTarget(Program program, Instruction instr, Hooks hooks,
			RegisterEnv env, Budget budget, int depth) {
		Address plain = MosOperands.plainAbsoluteTarget(instr);
		if (plain != null) {
			return plain;
		}
		if (depth > MAX_RESOLVE_DEPTH || !isAbsoluteIndexed(instr)) {
			return null;
		}
		Address base = LoopIdioms.indexedBase(instr);
		Register idx = LoopIdioms.indexReg(instr);
		if (base == null || idx == null) {
			return null;
		}
		String idxName = idx.getName().toUpperCase();
		if (!idxName.equals("X") && !idxName.equals("Y")) {
			return null;
		}
		Integer value =
			constantRegisterValue(program, instr, idxName.charAt(0), hooks, env, budget, depth);
		if (value == null) {
			return null;
		}
		try {
			return base.add(value & 0xFF);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * The fully known byte {@code reg} holds immediately before {@code at}, or {@code null}
	 * when any step of the chain is not modeled.
	 * <p>
	 * <b>All-or-nothing on purpose.</b> This is a separate evaluator from
	 * {@link #resolveStoredValue}'s mask algebra and does <em>not</em> share its per-bit
	 * machinery: an effective address needs all eight index bits or it needs none, so a
	 * partially known register is simply a decline. Keeping the two apart is also what lets
	 * {@code BitAlgebraEquivalenceTest} stand as the untouched proof that grm-hum did not
	 * disturb the proven algebra.
	 * <p>
	 * {@link #resolveStoredValue} nevertheless CONSULTS this evaluator, as a last resort at the
	 * point its own walk meets an opaque register modifier and would otherwise return wholly
	 * unknown (bead grm-4bgh.6). That is a fallback, not a merger: an answer from here enters
	 * the mask algebra only as a fully known base, on a path that had no other answer to give.
	 * <p>
	 * <b>What is modeled lives in {@link ConstantSemantics}, not here</b> (bead grm-as0m). This
	 * method is the backward walk only: it queries a {@link ConstantSemantics.Loc location} --
	 * A, X, Y, or the carry -- finds the last instruction that writes it, and asks the
	 * semantics what that instruction leaves there, answering each input the instruction reads
	 * with another walk of this same method. So the carry an {@code ADC} adds in is an ordinary
	 * query (it used to be a second, guard-for-guard duplicate walk), and every operation folds
	 * exactly when all of its inputs do. See {@link Mos6502ConstantSemantics} for the table.
	 * <p>
	 * Every guard {@link #resolveStoredValue} applies is reused verbatim: fall-through block
	 * linkage, {@link FlowEdges#isControlFlowJoin}, and {@link #MAX_BACKWARD_SCAN}; a call ends the walk.
	 * The one guard NOT reused is the mechanism-write abort, and as of bead grm-4bgh.7 it is not
	 * merely relaxed here but ABSENT: that guard exists to stop an in-state-derived value being
	 * read across the write, and this evaluator never consults a caller's in-state at all.
	 * {@code env}'s entry stop is honored the same way it is there, and is likewise
	 * all-or-nothing: a partially known caller register declines, because an effective address
	 * needs all eight index bits. For the carry the entry stop always declines -- a
	 * {@link RegisterEnv} describes the caller's A/X/Y and says nothing about its flags. So is
	 * {@code env}'s licensed join ({@link RegisterEnv#mayCrossJoinAt}) honored -- and this walk
	 * is the one that actually needs it, since Contra's caller-supplied Y is consumed as the
	 * INDEX of the switch site's operand rather than as its stored value.
	 * <p>
	 * <b>{@link MechanismState#unknown()} is passed to {@link Hooks#resolveLoad}, never a caller's
	 * in-state.</b> That is load-bearing for {@link BankSwitchStrategy#cacheable()}: an
	 * effective address computed from the in-state would make {@code computeSwitch} a function
	 * of {@code (program, instr, inState)}, while {@code BoardBankAnalyzer}'s {@code matchCache}
	 * is keyed by address alone. A strategy whose {@code resolveLoad} is state-dependent
	 * (register-write's port read-back) therefore contributes nothing here -- which is correct,
	 * since it also declines to be cached.
	 */
	static Integer constantRegisterValue(Program program, Instruction at, char reg, Hooks hooks,
			RegisterEnv env, Budget budget) {
		return constantRegisterValue(program, at, reg, hooks, env, budget, 0);
	}

	static Integer constantRegisterValue(Program program, Instruction at, char reg,
			Hooks hooks, RegisterEnv env, Budget budget, int depth) {
		return constantValue(program, at, ConstantSemantics.Loc.ofRegister(reg), hooks, env,
			budget, depth);
	}

	/**
	 * {@link #constantRegisterValue}'s walk over any {@link ConstantSemantics.Loc}, including
	 * the flags {@link ConstantSemantics.Loc#C} and {@link ConstantSemantics.Loc#D} that
	 * {@link #constantRegisterValue}'s {@code char} parameter cannot name. Exposed (bead
	 * grm-4wqd) for tests that need to query a flag directly rather than through a register
	 * that happens to depend on it -- production callers all go through
	 * {@link #constantRegisterValue} or {@link WalkInputs#before}.
	 */
	static Integer constantLocValue(Program program, Instruction at, ConstantSemantics.Loc loc,
			Hooks hooks, RegisterEnv env, Budget budget) {
		return constantValue(program, at, loc, hooks, env, budget, 0);
	}

	/**
	 * The semantics {@link #constantValue} evaluates with, for {@code program} -- selected per
	 * program by the {@code Constant Evaluator} analyzer option
	 * ({@link BoardBankAnalyzer#constantSemanticsMode}, bead grm-4wqd), defaulting to
	 * {@link Mos6502ConstantSemantics}.
	 */
	private static ConstantSemantics semanticsFor(Program program) {
		return BoardBankAnalyzer.constantSemanticsMode(program) ==
			BoardBankAnalyzer.ConstantSemanticsMode.PCODE ? PcodeConstantSemantics.INSTANCE
					: Mos6502ConstantSemantics.INSTANCE;
	}

	/**
	 * Whether the routine {@code call} ({@code JSR}) invokes provably returns register {@code reg}
	 * unchanged (bead grm-mej.13), so a backward walk resolving {@code reg} may step over it
	 * instead of declaring it clobbered. Answers {@code false} -- today's behaviour -- for anything
	 * not a plain direct call to one resolved, disassembled, non-banked-from-outside target, for
	 * an abandoned summary, and for any register other than A/X/Y.
	 * <p>
	 * ASSUMPTIONS RELIED ON (named in {@link CalleeRegisterSummary}): a {@code true} answer rests on
	 * {@code StackDiscipline.CROSSED_CALL_IS_STACK_NEUTRAL} (owner ruling O4) whenever the callee
	 * itself contains a call, and on {@code StackAssumption.INDIRECT_STORES_DO_NOT_WRITE_STACK_FRAME}
	 * (O3) when it contains an indirect store; both are recorded on the {@code Summary} returned
	 * by {@link CalleeRegisterSummary#summarizeCallSite}. This concerns only the REGISTER VALUE;
	 * the bank STATE across the call is the engine's separate business. The summary memo is the
	 * per-program one ({@link CalleeRegisterSummary#memoFor}) because these walks run from hooks
	 * with no run-scoped holder.
	 */
	static boolean calleePreserves(Program program, Instruction call, char reg) {
		char r = Character.toUpperCase(reg);
		if (r != 'A' && r != 'X' && r != 'Y') {
			return false;
		}
		CalleeRegisterSummary.Summary sum = CalleeRegisterSummary.summarizeCallSite(program, call,
			CalleeRegisterSummary.memoFor(program));
		return sum != null && sum.preserves(r);
	}

	/** {@link #constantRegisterValue}'s walk, over any {@link ConstantSemantics.Loc}. */
	private static Integer constantValue(Program program, Instruction at,
			ConstantSemantics.Loc loc, Hooks hooks, RegisterEnv env, Budget budget, int depth) {
		if (depth > MAX_RESOLVE_DEPTH) {
			return null;
		}
		ConstantSemantics semantics = budget.semanticsFor(program);
		Listing listing = program.getListing();

		Instruction cur = at;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			if (env.stopsAt(cur.getMinAddress())) {
				// The entry stop, same rule as resolveStoredValue's: adopt the caller's value
				// rather than walking past the entry. All-or-nothing here too -- a partially
				// known caller register is not an index -- and the env carries no flags.
				if (!loc.isRegister()) {
					return null;
				}
				PartialByte entryValue = env.get(loc.register());
				return entryValue.exact();
			}
			if (!budget.spend()) {
				return null;
			}
			// Block start, left the basic block, or another path reaches cur and may leave a
			// different value -- except at the one join the env licenses (grm-k90) or the arm it
			// names (grm-wul). This evaluator is the one that actually carries Contra: the switch
			// site's own scan never sees the wrapper split, but resolving the index of its
			// `LDA $ffd0,Y` walks straight back into it. It is also the one that carries a
			// `TXA / STA mechanism` merge: the A walk asks it for X, and X is what the arms set.
			Instruction prev = pathPredecessor(program, listing, cur, env);
			if (prev == null) {
				return null;
			}
			// NO MECHANISM-WRITE ABORT HERE AT ALL (bead grm-4bgh.7), and note this is a
			// stronger statement than resolveStoredValue's withdrawal above. That abort exists
			// solely to stop an in-state-derived value being read across the write; THIS
			// evaluator never consults a caller's in-state in the first place -- it passes
			// MechanismState.unknown() to resolveLoad by construction, for the cacheability reason in
			// its javadoc -- so it has nothing to withdraw and never had a hazard to guard. The
			// abort it used to carry was copied from the walk that does.

			if (semantics.writes(prev, loc)) {
				return semantics.after(prev, loc,
					new WalkInputs(program, prev, hooks, env, budget, depth, MAX_BACKWARD_SCAN - i));
			}
			if (prev.getFlowType().isCall() &&
				!(loc.isRegister() && calleePreserves(program, prev, loc.register()))) {
				// a subroutine may clobber any register, and returns any carry -- unless
				// (grm-mej.13) a callee summary proves THIS register preserved; flags never are
				return null;
			}
			cur = prev;
		}
		return null;
	}

	/**
	 * {@link ConstantSemantics.Inputs} for one writer {@link #constantValue} found: each input is
	 * another walk from that writer, one level deeper, spending from the same {@link Budget}.
	 * <p>
	 * The effective target is computed at most ONCE per instance (bead grm-om3i). Both
	 * {@link #effectiveTarget} and {@link #memoryOperand} need it, and an implementation may ask
	 * for both -- {@link PcodeConstantSemantics} checks its own address against the target and
	 * then reads the operand -- so without the memo every such read walked for the index
	 * register twice, spending budget {@link Mos6502ConstantSemantics} never spent. Caching is
	 * sound because nothing the computation depends on (instruction, env, depth) varies within
	 * one instance; only the shared {@link Budget} does, and a repeat would merely spend more
	 * of it for the same answer or a budget-exhausted {@code null}.
	 */
	private static final class WalkInputs implements ConstantSemantics.Inputs {
		private final Program program;
		private final Instruction instr;
		private final Hooks hooks;
		private final RegisterEnv env;
		private final Budget budget;
		private final int depth;
		private final int remainingScan;
		private boolean targetComputed;
		private Address cachedTarget;

		WalkInputs(Program program, Instruction instr, Hooks hooks, RegisterEnv env,
				Budget budget, int depth, int remainingScan) {
			this.program = program;
			this.instr = instr;
			this.hooks = hooks;
			this.env = env;
			this.budget = budget;
			this.depth = depth;
			this.remainingScan = remainingScan;
		}

		@Override
		public Integer before(ConstantSemantics.Loc loc) {
			return constantValue(program, instr, loc, hooks, env, budget, depth + 1);
		}

		@Override
		public Address effectiveTarget() {
			if (!targetComputed) {
				cachedTarget = StoredValueScanner.effectiveTarget(program, instr, hooks, env, budget,
					depth + 1);
				targetComputed = true;
			}
			return cachedTarget;
		}

		@Override
		public Integer memoryOperand() {
			Address target = effectiveTarget();
			// unknown() in-state, never a caller's -- see constantRegisterValue's javadoc
			PartialByte base = hooks.resolveLoad(instr, target, MechanismState.unknown());
			if (base != null && base.isFullyKnown()) {
				return base.exact();
			}
			// Last resort (grm-4bgh.1): a stack-relative reload -- see stackRelativePush's
			// javadoc for the shape and soundness argument, which is about the ADDRESS read and
			// so holds whatever the instruction does with the byte. The recursive query is
			// always for 'A': the push stackRelativePush finds is always a PHA, which only ever
			// saves A. The Span's crossing flag is deliberately IGNORED here: this evaluator
			// holds no in-state to withdraw (see constantValue's comment where the abort used to
			// be), so a mechanism write between the reload and its push changes nothing it
			// computes.
			Instruction pha =
				stackRelativePush(program, instr, hooks, env, remainingScan, new Span());
			return pha == null ? null
					: constantValue(program, pha, ConstantSemantics.Loc.A, hooks, env, budget,
						depth + 1);
		}
	}

	/**
	 * The source register of a transfer that writes {@code reg} ({@code TAX}/{@code TAY} write
	 * X/Y from A; {@code TXA}/{@code TYA} write A from X/Y), or {@code null} when {@code mnem}
	 * is not such a transfer. {@code TSX} is deliberately absent: the stack pointer is not
	 * tracked.
	 */
	private static Character transferSource(String mnem, char reg) {
		return switch (mnem) {
			case "TAX" -> reg == 'X' ? 'A' : null;
			case "TAY" -> reg == 'Y' ? 'A' : null;
			case "TXA" -> reg == 'A' ? 'X' : null;
			case "TYA" -> reg == 'A' ? 'Y' : null;
			default -> null;
		};
	}

	/** {@code +1}/{@code -1} when {@code mnem} increments or decrements {@code reg}, else null. */
	private static Integer incDecDelta(String mnem, char reg) {
		return switch (mnem) {
			case "INX" -> reg == 'X' ? 1 : null;
			case "DEX" -> reg == 'X' ? -1 : null;
			case "INY" -> reg == 'Y' ? 1 : null;
			case "DEY" -> reg == 'Y' ? -1 : null;
			default -> null;
		};
	}

	/**
	 * Whether operand 0 uses an <em>absolute</em>-indexed addressing mode ({@code abs,X} /
	 * {@code abs,Y}), the only indexed mode with a statically exact effective address.
	 * <p>
	 * Classified from the raw opcode byte, reusing {@code MosConstantReferenceAnalyzer.classify}'s
	 * reasoning rather than inventing a second discriminator: 6502 opcodes encode as
	 * {@code aaabbbcc} with {@code bbb = (op >> 2) & 7} selecting the addressing-mode column, so
	 * {@code op & 0x1f} identifies the mode independently of which instruction occupies it.
	 * {@code bbb = 6} ({@code abs,Y}) and {@code bbb = 7} ({@code abs,X}, plus {@code abs,Y} for
	 * the {@code cc=2} column's {@code LDX}) are exactly {@code (op & 0x1f) >= 0x18}. That
	 * excludes zero-page indexed ({@code bbb = 5}, {@code 0x14-0x17}), {@code (zp,X)}
	 * ({@code 0x01}/{@code 0x03}) and {@code (zp),Y} ({@code 0x11}/{@code 0x13}).
	 * <p>
	 * Like {@code classify}, this narrows by opcode only -- the non-indexed instructions that
	 * share those columns (e.g. {@code TXS}, {@code CLC}) are rejected by
	 * {@link LoopIdioms#indexedBase}/{@link LoopIdioms#indexReg} returning null. And as that
	 * javadoc warns, {@code OperandType.INDIRECT} does not work for this: it tests for indirect
	 * <em>flow</em>, so both indirect data modes report false.
	 */
	private static boolean isAbsoluteIndexed(Instruction instr) {
		try {
			return (instr.getByte(0) & 0x1F) >= 0x18;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}
}
