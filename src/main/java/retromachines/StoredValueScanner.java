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

import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

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
 * {@link #forwardedStoreValue} tries local store-to-load forwarding (below). An
 * otherwise unresolved load leaves {@code x} wholly unknown.</li>
 * <li><b>Local store-to-load forwarding</b> (grm-mej.1): a load, or a non-immediate
 * {@code AND}/{@code ORA} operand, whose target is statically certain is answered from the
 * nearest preceding store to that same cell <em>within the same basic block</em>, by
 * recursing into this very scan on that store. This is what lets a helper that stashes its
 * register argument in memory and splices it back in be <em>derived</em> rather than assumed
 * -- Ironsword's {@code STA $C3 ... ORA $C3 / STA $8000}, quoted in
 * {@link MemoryLatchBankSwitchStrategy}'s {@code depositHelperArgument}. The forwarding is
 * deliberately <b>not</b> restricted to the zero page: the measured examples happen to live
 * there, but Contra's save slots are {@code $07EC}/{@code $07ED}, and
 * {@link #plainAbsoluteTarget} already treats zero-page and absolute operands identically.
 * If anything the zero page is the <em>worse</em>-supported case, since zero-page indexed
 * wraps inside the page and {@link #effectiveOperandTarget} therefore declines it.</li>
 * <li>Any other instruction that modifies the register (transfers, ADC/SBC, shifts,
 * INC/DEC, EOR#imm -- deliberately not modeled bit-wise) leaves {@code x} wholly
 * unknown from that point backward.</li>
 * <li>A mechanism write encountered mid-scan ({@link Hooks#isMechanismWrite}) means the
 * mechanism changed mid-chain: a base value read further back would predate that write,
 * so falling back to the in-state (which reflects state <em>after</em> it) would be
 * unsound. The scan aborts to a wholly-unknown base.</li>
 * <li>A subroutine call may clobber any register; its fall-through satisfies the
 * block-linkage check, so it is treated as a clobber explicitly.</li>
 * <li>A caller-supplied {@link RegisterEnv}'s entry address ends the walk and adopts that
 * environment's value for the register being asked about -- grm-hum increment 2's
 * mini-inlining of a bank-switch helper's own switch site under one call site's registers.
 * With {@link RegisterEnv#NONE} (every path but that one) it never fires and the scan
 * behaves exactly as it always has. See {@link RegisterEnv}'s javadoc for why stopping at
 * a function entry is an argued exception to the control-flow-join refusal rather than a
 * hole in it.</li>
 * </ul>
 * The mnemonic tables are 6502-family, which covers every board strategy currently
 * shipped (C64 register-write, NES memory-latch); other CPU families will parameterize
 * the tables when they arrive rather than speculatively now.
 */
final class StoredValueScanner {

	/** Strategy-specific behavior injected into the shared scan. */
	interface Hooks {

		/** Whether this instruction writes the strategy's mechanism (mid-scan abort). */
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
		 * @param inStateAtStore  the strategy's tracked in-state at the store being scanned
		 */
		BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore);
	}

	private static final int MAX_BACKWARD_SCAN = 16;

	/**
	 * How deep {@link #constantRegisterValue} may recurse through register-to-register
	 * dependencies (a {@code TAX} asks about A, whose {@code LDA table,X} asks about X, ...).
	 */
	private static final int MAX_RESOLVE_DEPTH = 4;

	/**
	 * Instructions one whole {@link #effectiveOperandTarget} query tree may inspect. The depth
	 * cap alone is not a bound worth relying on -- at {@link #MAX_BACKWARD_SCAN} steps per
	 * level it permits {@code 16^depth} instruction visits -- so every visit also spends from
	 * a single {@link Budget} shared across the entire tree. Mega Man's real chain
	 * ({@code LDA #$00 / STA $0C / ASL A / TAX / LDA $D81E,X}) uses depth 3 and about 10 steps.
	 */
	private static final int MAX_RESOLVE_STEPS = 64;

	private static final Set<String> A_MODIFIERS = Set.of("LDA", "TXA", "TYA", "PLA", "ADC", "SBC",
		"AND", "ORA", "EOR", "ASL", "LSR", "ROL", "ROR");
	private static final Set<String> X_MODIFIERS = Set.of("LDX", "TAX", "TSX", "INX", "DEX");
	private static final Set<String> Y_MODIFIERS = Set.of("LDY", "TAY", "INY", "DEY");

	/**
	 * 6502 mnemonics that write memory, for {@link #writesMemory}'s third detector. The stores
	 * are here as well as in {@link #storeRegister} because that method deliberately excludes the
	 * read-modify-write forms, which write memory just the same. The shift/rotate entries write
	 * memory only in their non-accumulator addressing modes, which {@link #writesMemory} tests.
	 * Stack pushes are absent on purpose: the stack page is not a cell this scanner ever forwards
	 * through, and a call -- the other way the stack is written -- ends the walk anyway.
	 */
	private static final Set<String> MEMORY_WRITERS =
		Set.of("STA", "STX", "STY", "INC", "DEC", "ASL", "LSR", "ROL", "ROR");

	private StoredValueScanner() {
	}

	/** Mutable step counter shared across one {@link #effectiveOperandTarget} query tree. */
	static final class Budget {

		private int steps;

		Budget(int steps) {
			this.steps = steps;
		}

		/** Spends one step; false once the budget is exhausted. */
		boolean spend() {
			return steps-- > 0;
		}
	}

	/**
	 * Scans backward from {@code storeInstr} to determine the {@link BankState} it
	 * stores, reduced to {@code mask} (full algorithm in the class javadoc). After every
	 * composition step the base can be folded in via {@link #combine}; as an
	 * optimization, {@link #fullyDeterminedByAccumulator} lets the scan return without
	 * ever inspecting the base when the mask algebra alone already pins down every
	 * tracked bit.
	 * <p>
	 * 6502 has no immediate AND/ORA addressing the X or Y registers, so the mask-algebra
	 * composition only ever applies when {@code reg == 'A'}; the X/Y paths retain the
	 * simpler "resolved load or wholly unknown" behavior.
	 */
	static BankState resolveStoredValue(Program program, Instruction storeInstr, char reg,
			BankState inStateAtStore, int mask, Hooks hooks) {
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
	static BankState resolveStoredValue(Program program, Instruction storeInstr, char reg,
			BankState inStateAtStore, int mask, Hooks hooks, RegisterEnv env) {
		return resolveStoredValue(program, storeInstr, reg, inStateAtStore, mask, hooks, env,
			new Budget(MAX_RESOLVE_STEPS), 0);
	}

	/**
	 * {@link #resolveStoredValue} within an ongoing store-to-load forwarding chain's depth and
	 * step budget. Only {@link #forwardedStoreValue} passes a non-fresh budget: every public
	 * entry point starts a new one, so a top-level scan is unaffected by this parameterization.
	 * <p>
	 * Note the {@link #effectiveOperandTarget} call in the {@code LD<reg>} branch below
	 * deliberately keeps starting a <em>fresh</em> budget rather than spending from this one.
	 * That is exactly what it did before forwarding existed, and preserving it keeps this change
	 * from silently withdrawing effective-address resolution that a long scan relies on today.
	 * The forwarding lookups are the only ones that share {@code budget}, which is what bounds
	 * the recursion this method can now enter.
	 */
	private static BankState resolveStoredValue(Program program, Instruction storeInstr, char reg,
			BankState inStateAtStore, int mask, Hooks hooks, RegisterEnv env, Budget budget,
			int depth) {
		Listing listing = program.getListing();
		Set<String> modifiers = registerModifiers(reg);
		String loadMnemonic = "LD" + reg;

		int aAcc = 0xFF;
		int oAcc = 0x00;

		Instruction cur = storeInstr;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			if (env.stopsAt(cur.getMinAddress())) {
				// Reached the entry this query was asked on behalf of: the register's value
				// here is the caller's, not whatever code happens to sit at a lower address.
				// Deliberately BEFORE the linkage/join/mechanism-write checks -- an entry has
				// no fall-through predecessor to check, and its incoming flows are other call
				// sites, which is exactly what the env already answers for.
				return combine(aAcc, oAcc, mask, env.get(reg));
			}
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null) {
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			Address prevFallThrough = prev.getFallThrough();
			if (prevFallThrough == null || !prevFallThrough.equals(cur.getMinAddress())) {
				// not a straight-line predecessor of cur -- left the basic block
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			if (isControlFlowJoin(program, cur, prev)) {
				// cur is also a branch target: some other path reaches it and may leave a
				// different register value, so prev's fall-through value can't be attributed
				// to the store with confidence.
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}

			if (hooks.isMechanismWrite(prev)) {
				// the mechanism was written mid-chain; a base value read further back
				// would predate that write, so it's unsound to fall back to the in-state.
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}

			String mnem = prev.getMnemonicString().toUpperCase();

			if (reg == 'A' && mnem.equals("AND")) {
				Integer imm = operandByte(program, prev, inStateAtStore, hooks, env, budget, depth);
				if (imm == null) {
					// an operand we couldn't pull a scalar out of, and couldn't forward a store
					// to either, is an opaque modifier of A.
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				aAcc = imm & aAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				cur = prev;
				continue;
			}

			if (reg == 'A' && mnem.equals("ORA")) {
				Integer imm = operandByte(program, prev, inStateAtStore, hooks, env, budget, depth);
				if (imm == null) {
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				oAcc = (imm & aAcc) | oAcc;
				if (fullyDeterminedByAccumulator(aAcc, oAcc, mask)) {
					return combine(aAcc, oAcc, mask, BankState.unknown());
				}
				cur = prev;
				continue;
			}

			if (mnem.equals(loadMnemonic) && isImmediate(prev)) {
				Integer imm = immediateOperandValue(prev);
				if (imm != null) {
					// x is now fully known -- fold it through the accumulated transform.
					return combine(aAcc, oAcc, mask, BankState.fullyKnown(0xFF, imm));
				}
				// Scalar extraction failed; fall through and treat like any other modifier.
			}

			if (mnem.equals(loadMnemonic)) {
				// The target is resolved here, not in the hook: an absolute-indexed load's
				// target needs the whole constant-index evaluator, and doing it once keeps
				// every strategy's hook a pure "do I understand this address" question.
				Address target = effectiveOperandTarget(program, prev, hooks, env);
				BankState base = hooks.resolveLoad(prev, target, inStateAtStore);
				if (base != null) {
					return combine(aAcc, oAcc, mask, base);
				}
				// No strategy claims this address; try to forward a store to it from earlier in
				// this same block (grm-mej.1). A partial answer is fine here -- combine() folds
				// a partially known base per bit -- unlike the AND/ORA operand case, which needs
				// all eight bits to compose into the accumulator.
				BankState forwarded = forwardedStoreValue(program, prev, target, inStateAtStore,
					hooks, env, budget, depth);
				if (forwarded.knownMask() != 0) {
					return combine(aAcc, oAcc, mask, forwarded);
				}
			}

			if (modifiers.contains(mnem)) {
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			if (prev.getFlowType().isCall()) {
				return combine(aAcc, oAcc, mask, BankState.unknown());
			}
			cur = prev;
		}
		return combine(aAcc, oAcc, mask, BankState.unknown());
	}

	/**
	 * Whether {@code cur} is reachable other than by falling through from {@code prev} --
	 * i.e. another instruction branches, jumps, or calls to it, making it a control-flow
	 * join. The backward scan follows only the {@code prev} fall-through path, so at a join
	 * it cannot soundly attribute that path's register value to the store: the other
	 * incoming path(s) may leave a different value.
	 * <p>
	 * A join is detected by an incoming <em>flow</em> reference from an address other than
	 * {@code prev} (a conditional or unconditional branch to {@code cur} records one; the
	 * implicit fall-through from {@code prev} is not a reference, and a branch from
	 * {@code prev} whose target is also its own fall-through is excluded). Unresolved
	 * computed jumps leave no reference and so are not detected -- conservative in the safe
	 * direction (a missed join only forfeits a fold the scan would otherwise have made).
	 */
	private static boolean isControlFlowJoin(Program program, Instruction cur, Instruction prev) {
		Address curAddr = cur.getMinAddress();
		Address prevAddr = prev.getMinAddress();
		for (Reference ref : program.getReferenceManager().getReferencesTo(curAddr)) {
			if (ref.getReferenceType().isFlow() && !ref.getFromAddress().equals(prevAddr)) {
				return true;
			}
		}
		return false;
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
		return (((~aAcc | oAcc) & mask) & 0xFF) == (mask & 0xFF);
	}

	/**
	 * Folds the accumulated transform {@code result = (x & aAcc) | oAcc} against a
	 * (possibly partially known) base {@link BankState} for {@code x}, reduced to
	 * {@code mask}: {@code oAcc} setting a bit forces a known 1; otherwise {@code aAcc}
	 * clearing it forces a known 0; otherwise the bit passes {@code x} through, so it is
	 * known in the result iff it is known in {@code base}. A result bit is 1 exactly when
	 * {@code oAcc} sets it, or {@code aAcc} passes a known base 1 through -- the base's
	 * <em>known</em> gate on that second term is what keeps result bits 0 in still-unknown
	 * positions (so two states compare equal iff genuinely equal). Equivalence to the
	 * original per-bit loop is proved exhaustively by
	 * {@code src/test/java/retromachines/BitAlgebraEquivalenceTest.java} ({@code gradle test}).
	 */
	private static BankState combine(int aAcc, int oAcc, int mask, BankState base) {
		int knownMask = mask & (oAcc | ~aAcc | base.knownMask()) & 0xFF;
		int bits = mask & (oAcc | (aAcc & base.knownMask() & base.bits())) & 0xFF;
		return new BankState(knownMask, bits);
	}

	// ------------------------------------------------------------------
	// Local store-to-load forwarding (grm-mej.1)
	// ------------------------------------------------------------------

	/**
	 * The fully known byte an {@code AND}/{@code ORA} operand contributes: its immediate value, or
	 * -- when the operand names memory whose address is statically certain -- the value forwarded
	 * from a store to that cell earlier in the same basic block. {@code null} when neither
	 * applies, which is the pre-grm-mej.1 behavior for every non-immediate operand.
	 * <p>
	 * <b>All-or-nothing, deliberately.</b> The mask algebra composes an operand into
	 * {@code (aAcc, oAcc)} as if it were an immediate, and that composition has no way to say
	 * "this bit of the operand was unknown" -- expressing it would need a third accumulator for
	 * bits forced unknown, perturbing the algebra that
	 * {@code src/test/java/retromachines/BitAlgebraEquivalenceTest.java} proves exhaustively.
	 * Requiring all eight bits keeps that proof untouched and costs nothing on the measured case
	 * (Ironsword's {@code $C3} holds either the caller's fully known {@code A} or nothing). This
	 * is the same reasoning {@link #constantRegisterValue} already records for itself.
	 * <p>
	 * <b>{@link Hooks#resolveLoad} is deliberately NOT consulted here</b>, only forwarding. A
	 * strategy resolving an {@code ORA} operand (a bank-invariant ROM byte, or a bank mirror) is
	 * a real further capability with its own blast radius, and belongs to grm-mej.2 where it can
	 * be measured on its own. Adding it is one line at the top of this method.
	 */
	private static Integer operandByte(Program program, Instruction instr, BankState inStateAtStore,
			Hooks hooks, RegisterEnv env, Budget budget, int depth) {
		if (isImmediate(instr)) {
			return immediateOperandValue(instr);
		}
		Address target = effectiveOperandTarget(program, instr, hooks, env);
		BankState forwarded =
			forwardedStoreValue(program, instr, target, inStateAtStore, hooks, env, budget, depth);
		return (forwarded.knownMask() & 0xFF) == 0xFF ? forwarded.bits() & 0xFF : null;
	}

	/**
	 * The value {@code cell} holds when {@code useInstr} executes, reduced to {@code mask} -- the
	 * MEMORY dual of {@link #resolveStoredValue}'s register query, asked at the same instruction
	 * (bead grm-67g).
	 * <p>
	 * A bank-switch helper does not always take its argument in a register. smb3's {@code FUN_ffc2}
	 * is handed the bank through RAM shadow {@code $0720}:
	 * <pre>
	 *   ca23  LDA #$1b / STA $0720 / JSR $ffc2     &lt;- useInstr is the JSR, cell is $0720
	 *   ffc2  ... LDA $0720 / STA $8001            &lt;- the helper consumes it here
	 * </pre>
	 * Once {@code BoardBankAnalyzer.inboundArgumentCell} has proved the helper reaches its switch
	 * site holding {@code $0720}'s value unmodified, this answers the other half: what the CALLER
	 * put there. Every guard that makes the answer trustworthy already exists in
	 * {@link #forwardedStoreValue} -- block linkage, {@link #isControlFlowJoin}, the
	 * {@link Hooks#isMechanismWrite} abort, the unplaceable-store and call aborts, the stack-page
	 * refusal -- so this is an entry point onto it, not a second scanner.
	 * <p>
	 * <b>A fresh {@link Budget}</b>, like every other public entry point: only the internal
	 * forwarding chain shares one (see {@link #resolveStoredValue}'s private overload). A caller's
	 * cell query must not be weakened by whatever some earlier query spent.
	 * <p>
	 * <b>{@link RegisterEnv#NONE} deliberately.</b> This scan runs in the CALLER, where there is no
	 * entry to stop at and nothing to adopt -- the mirror of the reason
	 * {@code valueSuppliedInsideHelper} needs an env and this does not.
	 * <p>
	 * <b>{@code inStateAtStore} is {@link BankState#unknown()} deliberately.</b> It is consulted
	 * only through {@code hooks.resolveLoad}, and the sole production caller passes
	 * {@code NO_HOOKS}; the only state it could otherwise supply describes the CALL, not the store
	 * this scans back to, and feeding a strategy a state that is off by the intervening
	 * instructions would be a fresh unsoundness for no measured gain.
	 */
	static BankState callerCellValue(Program program, Instruction useInstr, Address cell, int mask,
			Hooks hooks) {
		BankState value = forwardedStoreValue(program, useInstr, cell, BankState.unknown(), hooks,
			RegisterEnv.NONE, new Budget(MAX_RESOLVE_STEPS), 0);
		// Equivalent to combine(0xFF, 0x00, mask, value), spelled out because there is no
		// accumulated AND/ORA transform to fold here -- the cell's byte arrives verbatim.
		return new BankState(value.knownMask() & mask, value.bits() & mask);
	}

	/**
	 * The value {@code target} holds when {@code useInstr} reads it, forwarded from the nearest
	 * preceding store to that same cell <em>within {@code useInstr}'s own basic block</em>, by
	 * recursing into {@link #resolveStoredValue} on that store. {@link BankState#unknown()} when
	 * no such store is provably reached.
	 * <p>
	 * This is the piece grm-hum could only work around. Ironsword's {@code FUN_ffc0} launders the
	 * caller's bank argument through {@code $C3} ({@code STA $C3 ... ORA $C3 / STA $8000}), so the
	 * whole of AxROM's tracked field is derivable only if the scan can follow a value through a
	 * memory cell. A local forward within one block is much cheaper than general memory dataflow
	 * and covers the idiom, because a helper that stashes an argument and splices it back in does
	 * both in straight-line code.
	 * <p>
	 * <b>Not restricted to the zero page.</b> See the class javadoc: the measured cells happen to
	 * be zero-page, but Contra's save slots are {@code $07EC}/{@code $07ED}, and the scanner has
	 * no zero-page-specific path to restrict in the first place.
	 * <p>
	 * <b>Soundness.</b> Every guard {@link #resolveStoredValue} applies is reused verbatim rather
	 * than reimplemented -- block linkage, {@link #isControlFlowJoin}, the
	 * {@link Hooks#isMechanismWrite} mid-scan abort, {@link #MAX_BACKWARD_SCAN} -- and on top of
	 * them this walk declines on <em>any</em> intervening instruction that might write
	 * {@code target} without being a store this scanner can place: an indexed or indirect store,
	 * a read-modify-write, or a call. A store the walk can prove targets a <em>different</em>
	 * cell is stepped over; anything it cannot place at all ends the walk. Declining
	 * under-reports, which is this scanner's failure mode everywhere else.
	 * <p>
	 * The {@code env} entry stop ends the walk with {@link BankState#unknown()} rather than
	 * adopting anything: {@link RegisterEnv} describes a call site's <em>registers</em>, and says
	 * nothing whatever about memory. A caller's zero page is not modeled and must not be guessed.
	 */
	private static BankState forwardedStoreValue(Program program, Instruction useInstr,
			Address target, BankState inStateAtStore, Hooks hooks, RegisterEnv env, Budget budget,
			int depth) {
		if (target == null || depth >= MAX_RESOLVE_DEPTH || inStackPage(target)) {
			return BankState.unknown();
		}
		Listing listing = program.getListing();
		Instruction cur = useInstr;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			if (env.stopsAt(cur.getMinAddress())) {
				return BankState.unknown(); // the caller's memory is not modeled -- see javadoc
			}
			if (!budget.spend()) {
				return BankState.unknown();
			}
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null) {
				return BankState.unknown();
			}
			Address prevFallThrough = prev.getFallThrough();
			if (prevFallThrough == null || !prevFallThrough.equals(cur.getMinAddress())) {
				return BankState.unknown(); // left the basic block
			}
			if (isControlFlowJoin(program, cur, prev)) {
				return BankState.unknown(); // another path reaches cur with a different cell value
			}
			if (hooks.isMechanismWrite(prev)) {
				// Same rule as the register scan's: a value read further back would predate the
				// mechanism change, so nothing beyond this point may be attributed forward.
				return BankState.unknown();
			}

			if (writesMemory(prev)) {
				Character storeReg = storeRegister(prev);
				// The store's own target shares this query tree's budget, unlike the LD<reg>
				// branch's -- see resolveStoredValue's private overload for why only the
				// forwarding lookups do.
				Address storeTarget = storeReg == null ? null
						: effectiveTarget(program, prev, hooks, env, budget, depth + 1);
				if (storeTarget == null) {
					return BankState.unknown(); // a memory write this scanner cannot place
				}
				if (storeTarget.equals(target)) {
					return resolveStoredValue(program, prev, storeReg, inStateAtStore, 0xFF, hooks,
						env, budget, depth + 1);
				}
				// provably a different cell -- harmless, keep walking
			}
			if (prev.getFlowType().isCall()) {
				return BankState.unknown(); // a subroutine may write anywhere
			}
			cur = prev;
		}
		return BankState.unknown();
	}

	/**
	 * Whether {@code addr} is in the 6502 stack page, {@code $0100-$01FF}.
	 * <p>
	 * {@link #forwardedStoreValue} refuses to forward through a stack cell, and this guard is
	 * load-bearing rather than decorative. {@code PHA}/{@code PHP} write the stack without naming
	 * an address any of {@link #writesMemory}'s detectors can see, so without this a push between
	 * a store and a load of the same stack cell would be stepped over and the stale value
	 * attributed forward. Declining the whole page is the cheap sound answer; carrying values
	 * across a push/pull pair is a separate dataflow domain and belongs to grm-mej.3.
	 * <p>
	 * The alternative -- treating {@code PHA}/{@code PHP} as memory writes -- was rejected because
	 * it would end the walk for <em>every</em> target, and Ironsword's {@code FUN_ffc0} has a
	 * {@code PHA} at {@code $FFC6} sitting between the {@code STA $C3} this forwards from and the
	 * {@code ORA $C3} that consumes it. That is the motivating case, so the guard has to key on
	 * the cell being read, not on the instructions passed over.
	 */
	private static boolean inStackPage(Address addr) {
		long offset = addr.getOffset();
		return offset >= 0x0100 && offset <= 0x01FF;
	}

	/**
	 * Whether {@code instr} may write memory -- the predicate {@link #forwardedStoreValue} uses to
	 * decide that a cell's value can no longer be attributed past this instruction.
	 * <p>
	 * Three independent detectors, deliberately unioned rather than ranked, because each one
	 * alone has a blind spot: {@link Instruction#getResultObjects} reports a concrete destination
	 * address for {@code STA $C3} but not for a computed one like {@code STA ($10),Y}; a write
	 * reference exists only where something laid one down (the same refless-store gap
	 * {@code MemoryLatchBankSwitchStrategy.writesInRange} needs two tiers for); and the mnemonic
	 * test covers the read-modify-write stores, which {@link #storeRegister} deliberately does not
	 * recognize. Over-reporting merely forfeits a forward; under-reporting would be unsound.
	 * <p>
	 * <b>Package-private for a second consumer</b> (bead grm-67g):
	 * {@code BoardBankAnalyzer.inboundArgumentCell} asks the identical question -- "may this
	 * instruction have written the cell I am attributing a value to?" -- over a FORWARD walk
	 * through a helper body rather than this backward one, and the three-detector union is
	 * load-bearing for both. The reference-only {@link #writesAddress} is the tempting shortcut
	 * there and is not sound for it: a missed write costs that predicate a confident wrong bank,
	 * not merely a forfeited forward.
	 */
	static boolean writesMemory(Instruction instr) {
		for (Object o : instr.getResultObjects()) {
			if (!(o instanceof Register)) {
				return true;
			}
		}
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isWrite()) {
				return true;
			}
		}
		return MEMORY_WRITERS.contains(instr.getMnemonicString().toUpperCase()) &&
			!isAccumulatorForm(instr);
	}

	// ------------------------------------------------------------------
	// Known effective address (grm-hum GAP 1)
	// ------------------------------------------------------------------

	/**
	 * The single address {@code instr}'s operand 0 actually accesses, when that is statically
	 * certain: {@link #plainAbsoluteTarget} when the operand is unindexed (unchanged behavior),
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
	private static Address effectiveTarget(Program program, Instruction instr, Hooks hooks,
			RegisterEnv env, Budget budget, int depth) {
		Address plain = plainAbsoluteTarget(instr);
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
	 * Modeled: {@code LD<reg> #imm}; a {@code LD<reg> <mem>} whose target resolves and whose
	 * {@link Hooks#resolveLoad} answers with all eight bits known; {@code TAX/TAY/TXA/TYA};
	 * {@code INX/INY/DEX/DEY}; {@code ASL A}/{@code LSR A}; {@code AND/ORA/EOR #imm} on A.
	 * {@code ROL}/{@code ROR} <b>decline</b> -- the carry flag is not modeled anywhere in this
	 * scanner, and guessing it would be a wrong answer rather than a missing one. Any other
	 * instruction in the register's modifier set, and any call, declines.
	 * <p>
	 * Every guard {@link #resolveStoredValue} applies is reused verbatim: fall-through block
	 * linkage, {@link #isControlFlowJoin}, the {@link Hooks#isMechanismWrite} mid-scan abort,
	 * and {@link #MAX_BACKWARD_SCAN}. The mechanism-write abort in particular is <em>not</em>
	 * relaxed here: a base value read further back would predate that write. {@code env}'s
	 * entry stop is honored the same way it is there, and is likewise all-or-nothing: a
	 * partially known caller register declines, because an effective address needs all eight
	 * index bits.
	 * <p>
	 * <b>{@link BankState#unknown()} is passed to {@link Hooks#resolveLoad}, never a caller's
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

	private static Integer constantRegisterValue(Program program, Instruction at, char reg,
			Hooks hooks, RegisterEnv env, Budget budget, int depth) {
		if (depth > MAX_RESOLVE_DEPTH) {
			return null;
		}
		Listing listing = program.getListing();
		Set<String> modifiers = registerModifiers(reg);
		String loadMnemonic = "LD" + reg;

		Instruction cur = at;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			if (env.stopsAt(cur.getMinAddress())) {
				// The entry stop, same rule as resolveStoredValue's: adopt the caller's value
				// rather than walking past the entry. All-or-nothing here too -- a partially
				// known caller register is not an index.
				BankState entryValue = env.get(reg);
				return (entryValue.knownMask() & 0xFF) == 0xFF ? entryValue.bits() & 0xFF : null;
			}
			if (!budget.spend()) {
				return null;
			}
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null) {
				return null;
			}
			Address prevFallThrough = prev.getFallThrough();
			if (prevFallThrough == null || !prevFallThrough.equals(cur.getMinAddress())) {
				return null; // left the basic block
			}
			if (isControlFlowJoin(program, cur, prev)) {
				return null; // another path reaches cur and may leave a different value
			}
			if (hooks.isMechanismWrite(prev)) {
				// NOT relaxed for this evaluator: see the class javadoc's mid-scan rule.
				return null;
			}

			String mnem = prev.getMnemonicString().toUpperCase();

			if (mnem.equals(loadMnemonic)) {
				if (isImmediate(prev)) {
					Integer imm = immediateOperandValue(prev);
					return imm == null ? null : imm & 0xFF;
				}
				Address target = effectiveTarget(program, prev, hooks, env, budget, depth + 1);
				// unknown() in-state, never a caller's -- see this method's javadoc
				BankState base = hooks.resolveLoad(prev, target, BankState.unknown());
				if (base == null || (base.knownMask() & 0xFF) != 0xFF) {
					return null;
				}
				return base.bits() & 0xFF;
			}

			Character source = transferSource(mnem, reg);
			if (source != null) {
				return constantRegisterValue(program, prev, source, hooks, env, budget, depth + 1);
			}

			Integer delta = incDecDelta(mnem, reg);
			if (delta != null) {
				Integer before =
					constantRegisterValue(program, prev, reg, hooks, env, budget, depth + 1);
				return before == null ? null : (before + delta) & 0xFF;
			}

			if (reg == 'A' && (mnem.equals("ROL") || mnem.equals("ROR")) &&
				isAccumulatorForm(prev)) {
				return null; // carry is not modeled -- decline rather than guess a bit
			}

			if (reg == 'A' && (mnem.equals("ASL") || mnem.equals("LSR")) &&
				isAccumulatorForm(prev)) {
				Integer before =
					constantRegisterValue(program, prev, 'A', hooks, env, budget, depth + 1);
				if (before == null) {
					return null;
				}
				return mnem.equals("ASL") ? (before << 1) & 0xFF : (before >> 1) & 0xFF;
			}

			if (reg == 'A' && isImmediate(prev) &&
				(mnem.equals("AND") || mnem.equals("ORA") || mnem.equals("EOR"))) {
				Integer imm = immediateOperandValue(prev);
				if (imm == null) {
					return null;
				}
				Integer before =
					constantRegisterValue(program, prev, 'A', hooks, env, budget, depth + 1);
				if (before == null) {
					return null;
				}
				return switch (mnem) {
					case "AND" -> before & imm & 0xFF;
					case "ORA" -> (before | imm) & 0xFF;
					default -> (before ^ imm) & 0xFF;
				};
			}

			if (modifiers.contains(mnem)) {
				return null;
			}
			if (prev.getFlowType().isCall()) {
				return null; // a subroutine may clobber any register
			}
			cur = prev;
		}
		return null;
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

	/**
	 * Whether {@code instr} uses the accumulator addressing mode ({@code ASL A} and friends)
	 * rather than a memory operand -- the {@code bbb = 2}, {@code cc = 2} column, i.e.
	 * {@code (op & 0x1f) == 0x0A}. Callers gate on the mnemonic first, so the other
	 * instructions in that column (e.g. {@code TAX}, {@code NOP}) never reach here.
	 */
	private static boolean isAccumulatorForm(Instruction instr) {
		try {
			return (instr.getByte(0) & 0x1F) == 0x0A;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	// ------------------------------------------------------------------
	// Operand helpers shared by store-recognizing strategies
	// ------------------------------------------------------------------

	/**
	 * The register a 6502 store targets -- {@code 'A'}, {@code 'X'}, or {@code 'Y'} for
	 * {@code STA}/{@code STX}/{@code STY} -- or {@code null} for any other mnemonic. In
	 * particular the read-modify-write stores ({@code INC}/{@code DEC}/{@code ASL}/
	 * {@code LSR}/{@code ROL}/{@code ROR}) return {@code null}: they mutate the target in
	 * place and this scanner does not model the resulting value.
	 */
	static Character storeRegister(Instruction instr) {
		String mnem = instr.getMnemonicString().toUpperCase();
		if (mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY")) {
			return mnem.charAt(2); // 'A' | 'X' | 'Y'
		}
		return null;
	}

	static boolean writesAddress(Instruction instr, Address addr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(addr) && ref.getReferenceType().isWrite()) {
				return true;
			}
		}
		return false;
	}

	static boolean readsAddress(Instruction instr, Address addr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getToAddress().equals(addr) && ref.getReferenceType().isRead()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether {@code instr} writes {@code reg} (e.g. {@code STA PORT} on the bundled 6510
	 * language, where the on-die $01 port is a register, not a memory address). Used
	 * alongside {@link #writesAddress} so a mechanism modeled as a CPU register is detected
	 * the same way as one modeled as a memory-mapped address.
	 */
	static boolean writesRegister(Instruction instr, Register reg) {
		for (Object o : instr.getResultObjects()) {
			if (o instanceof Register r && r.equals(reg)) {
				return true;
			}
		}
		return false;
	}

	/** Whether {@code instr} reads {@code reg} (e.g. {@code LDA PORT}); see {@link #writesRegister}. */
	static boolean readsRegister(Instruction instr, Register reg) {
		for (Object o : instr.getInputObjects()) {
			if (o instanceof Register r && r.equals(reg)) {
				return true;
			}
		}
		return false;
	}

	private static Set<String> registerModifiers(char reg) {
		return switch (reg) {
			case 'A' -> A_MODIFIERS;
			case 'X' -> X_MODIFIERS;
			case 'Y' -> Y_MODIFIERS;
			default -> Set.of();
		};
	}

	static boolean isImmediate(Instruction instr) {
		String rep = instr.getDefaultOperandRepresentation(0);
		return rep != null && rep.startsWith("#");
	}

	/**
	 * Extracts the constant value of an immediate operand (e.g. the {@code $35} in
	 * {@code LDA #$35}). {@link ghidra.program.model.listing.CodeUnit#getScalar} only
	 * resolves scalars used as addressing components, not bare immediate operands, so we
	 * pull the {@link Scalar} directly out of the operand's object list instead.
	 */
	static Integer immediateOperandValue(Instruction instr) {
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Scalar s) {
				return (int) s.getUnsignedValue();
			}
		}
		return null;
	}

	/**
	 * The single constant memory address an operand names, or {@code null} when the
	 * operand is indexed/indirect (any register participates) or names no address --
	 * i.e. non-null exactly for plain absolute/zero-page addressing, where the target
	 * is statically certain.
	 * <p>
	 * Still the right predicate wherever "is this operand unindexed?" is the actual question
	 * (the {@code addr_mask} decode ruling, {@code JMP} target extraction). Where the question
	 * is "which address does this access reach?", prefer {@link #effectiveOperandTarget}, which
	 * answers this and additionally resolves an absolute-indexed operand with a constant index.
	 */
	static Address plainAbsoluteTarget(Instruction instr) {
		Address addr = null;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof ghidra.program.model.lang.Register) {
				return null; // indexed -- runtime-dependent target
			}
			if (obj instanceof Address a) {
				if (addr != null) {
					return null;
				}
				addr = a;
			}
		}
		return addr;
	}
}
