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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

import retromachines.StoredValueScanner.Budget;
import retromachines.StoredValueScanner.Hooks;
import java.util.Locale;

import static retromachines.StoredValueScanner.MAX_BACKWARD_SCAN;
import static retromachines.StoredValueScanner.MAX_RESOLVE_DEPTH;
import static retromachines.StoredValueScanner.MAX_RESOLVE_STEPS;
import static retromachines.StoredValueScanner.MEMORY_WRITERS;
import static retromachines.StoredValueScanner.effectiveOperandTarget;
import static retromachines.StoredValueScanner.effectiveTarget;
import static retromachines.StoredValueScanner.pathPredecessor;
import static retromachines.StoredValueScanner.resolveStoredValue;

/**
 * Local store-to-load forwarding within one basic block (bead grm-mej.1): operand bytes, caller
 * cell values, and the memory-write detector the forwarding walks stop on. Moved out of
 * {@link StoredValueScanner} (bead grm-rx1i.9); behaviour unchanged.
 */
final class LocalStoreForwarding {

	private LocalStoreForwarding() {
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
	 * is the same reasoning {@link StoredValueScanner#constantRegisterValue} already records for itself.
	 * <p>
	 * <b>{@link Hooks#resolveMirrorLoad} IS consulted, below forwarding</b> (grm-mej.2), in the
	 * same order and for the same reason as the {@code LD<reg>} branch of
	 * {@link StoredValueScanner#resolveStoredValue}: a bank spliced into an {@code ORA} operand is the same claim
	 * about the same cell, and letting the two branches disagree about precedence would be a bug
	 * waiting to be found by whichever board splices rather than loads. The all-or-nothing rule
	 * above still applies afterwards, so a mirror narrower than the whole byte -- every board
	 * whose latch field is not eight bits wide -- contributes nothing here and declines exactly as
	 * before.
	 * <p>
	 * <b>{@link Hooks#resolveLoad} is still deliberately NOT consulted here</b>, only forwarding
	 * and mirrors. A strategy resolving an {@code ORA} operand to a bank-invariant ROM byte is a
	 * separate further capability with its own blast radius across every pinned title, and unlike
	 * the mirror path it is not needed by anything measured. Adding it is one line at the top of
	 * this method.
	 */
	static Integer operandByte(Program program, Instruction instr, MechanismState inStateAtStore,
			Hooks hooks, RegisterEnv env, Budget budget, int depth) {
		if (MosOperands.isImmediate(instr)) {
			return MosOperands.immediateOperandValue(instr);
		}
		Address target = effectiveOperandTarget(program, instr, hooks, env);
		PartialByte forwarded =
			forwardedStoreValue(program, instr, target, inStateAtStore, hooks, env, budget, depth);
		if (forwarded.isFullyKnown()) {
			return forwarded.exact();
		}
		if (forwarded.knownMask() == 0) {
			PartialByte mirrored = hooks.resolveMirrorLoad(instr, target, inStateAtStore);
			if (mirrored != null && mirrored.isFullyKnown()) {
				return mirrored.exact();
			}
		}
		return null;
	}

	/**
	 * The value {@code cell} holds when {@code useInstr} executes, reduced to {@code mask} -- the
	 * MEMORY dual of {@link StoredValueScanner#resolveStoredValue}'s register query, asked at the same instruction
	 * (bead grm-67g).
	 * <p>
	 * A bank-switch helper does not always take its argument in a register. smb3's {@code FUN_ffc2}
	 * is handed the bank through RAM shadow {@code $0720}:
	 * <pre>
	 *   ca23  LDA #$1b / STA $0720 / JSR $ffc2     &lt;- useInstr is the JSR, cell is $0720
	 *   ffc2  ... LDA $0720 / STA $8001            &lt;- the helper consumes it here
	 * </pre>
	 * Once {@code HelperArgumentRecovery.inboundArgumentCell} has proved the helper reaches its switch
	 * site holding {@code $0720}'s value unmodified, this answers the other half: what the CALLER
	 * put there. Every guard that makes the answer trustworthy already exists in
	 * {@link #forwardedStoreValue} -- block linkage, {@link FlowEdges#isControlFlowJoin}, the
	 * {@link Hooks#isMechanismWrite} abort, and the unplaceable-store and call aborts -- so this
	 * is an entry point onto it, not a second scanner.
	 * <p>
	 * <b>A fresh {@link Budget}</b>, like every other public entry point: only the internal
	 * forwarding chain shares one (see {@link StoredValueScanner#resolveStoredValue}'s private overload). A caller's
	 * cell query must not be weakened by whatever some earlier query spent.
	 * <p>
	 * <b>{@link RegisterEnv#NONE} deliberately.</b> This scan runs in the CALLER, where there is no
	 * entry to stop at and nothing to adopt -- the mirror of the reason
	 * {@code valueSuppliedInsideHelper} needs an env and this does not.
	 * <p>
	 * <b>{@code inStateAtStore} is the CALLER's tracked in-state at {@code useInstr}, not
	 * {@link MechanismState#unknown()}</b> (bead grm-mej.3 item 4 -- this was {@code unknown()}
	 * hardcoded before, back when the sole production caller passed {@code NO_HOOKS} and no hook
	 * ever consulted it). It is consulted only through {@code hooks.resolveMirrorLoad} /
	 * {@code hooks.resolveLoad}, and {@link #forwardedStoreValue} WITHDRAWS it to
	 * {@link MechanismState#unknown()} the moment it crosses a {@link Hooks#isMechanismWrite} on the
	 * walk from {@code useInstr} back to the store that fills {@code cell} -- the identical
	 * grm-4bgh.7 machinery {@link StoredValueScanner#resolveStoredValue} itself relies on. That withdrawal is what
	 * makes passing the CALL's state here sound rather than "a state that is off by the
	 * intervening instructions": the state offered to a hook is never further from the truth than
	 * the nearest mechanism write between it and {@code useInstr}, and past that write it is
	 * honestly unknown instead of stale. A caller that still wants the pre-mirror behaviour (no
	 * hook ever sees a non-{@code unknown()} state) passes {@link MechanismState#unknown()} explicitly.
	 */
	static PartialByte callerCellValue(Program program, Instruction useInstr, Address cell,
			MechanismState inStateAtStore, int mask, Hooks hooks) {
		return callerCellValue(program, useInstr, cell, inStateAtStore, mask, hooks,
			RegisterEnv.NONE);
	}

	/** {@link #callerCellValue} along {@code env}'s arms (bead grm-wul); {@code NONE} crosses nothing. */
	static PartialByte callerCellValue(Program program, Instruction useInstr, Address cell,
			MechanismState inStateAtStore, int mask, Hooks hooks, RegisterEnv env) {
		PartialByte value = forwardedStoreValue(program, useInstr, cell, inStateAtStore, hooks,
			env, new Budget(MAX_RESOLVE_STEPS), 0);
		// Equivalent to combine(0xFF, 0x00, mask, value), spelled out because there is no
		// accumulated AND/ORA transform to fold here -- the cell's byte arrives verbatim.
		return value.restrict(mask);
	}

	/**
	 * The value {@code target} holds when {@code useInstr} reads it, forwarded from the nearest
	 * preceding store to that same cell <em>within {@code useInstr}'s own basic block</em>, by
	 * recursing into {@link StoredValueScanner#resolveStoredValue} on that store. {@link MechanismState#unknown()} when
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
	 * <b>Soundness.</b> Every guard {@link StoredValueScanner#resolveStoredValue} applies is reused verbatim rather
	 * than reimplemented -- block linkage, {@link FlowEdges#isControlFlowJoin}, the
	 * {@link Hooks#isMechanismWrite} in-state withdrawal, {@link StoredValueScanner#MAX_BACKWARD_SCAN} -- and on
	 * top of
	 * them this walk declines on <em>any</em> intervening instruction that might write
	 * {@code target} without being a store this scanner can place: an indexed or indirect store,
	 * a read-modify-write, or a call. A store the walk can prove targets a <em>different</em>
	 * cell is stepped over; anything it cannot place at all ends the walk. Declining
	 * under-reports, which is this scanner's failure mode everywhere else.
	 * <p>
	 * The {@code env} entry stop ends the walk with {@link MechanismState#unknown()} rather than
	 * adopting anything: {@link RegisterEnv} describes a call site's <em>registers</em>, and says
	 * nothing whatever about memory. A caller's zero page is not modeled and must not be guessed.
	 * <p>
	 * <b>Stack-page cells BELOW the assumed stack floor ARE forwarded through, deliberately</b>
	 * ({@link StackFloor}; grm-mej.3 increment 2, narrowed by the floor afterwards -- the ruling
	 * below is the project owner's, recorded here for the implementation
	 * that carries it out). Before this increment the whole page was refused outright: a blanket
	 * guard existed because {@code PHA}/{@code PHP} write the stack without naming an address any
	 * of {@link #writesMemory}'s detectors can see, so a push between a store and a load of the
	 * same stack cell would be stepped over and a stale value attributed forward -- and because
	 * treating {@code PHA}/{@code PHP} as memory writes to reject that case would have ended the
	 * walk for <em>every</em> target, Ironsword's {@code FUN_ffc0} has a {@code PHA} sitting
	 * between the {@code STA $C3} this forwards from and the {@code ORA $C3} that consumes it.
	 * <p>
	 * The guard is now accepted to be over-conservative for a low-in-the-page cell: dodge's
	 * {@code FUN_ff08} parks its argument at {@code $0103} and reloads it several instructions
	 * later, stepping over an intervening {@code PHA} that is unrelated to {@code $0103}
	 * entirely. Refusing the whole page declines that case even though nothing pushed onto the
	 * stack could plausibly alias {@code $0103} -- doing so would need the stack to run ~253
	 * bytes deep at the moment of the push, which does not happen in practice; games park scratch
	 * cells low in the stack page precisely because the stack never reaches them. This is the
	 * identical aliasing assumption {@code HelperArgumentRecovery.argumentSurvivesPrologue} already
	 * makes over this same dodge routine, so refusing here was internally inconsistent rather
	 * than conservative -- one code path trusted the low stack page and the other did not, over
	 * the same bytes of the same ROM.
	 * <p>
	 * <b>The residual risk</b> is exactly that deep-stack scenario: a push that genuinely does
	 * reach a cell this walk is willing to forward through would alias a value that was never
	 * really stored there, and nothing here detects it. It is now <em>bounded</em> rather than
	 * merely accepted: {@link StackFloor#mayAliasStack} refuses any cell at or above the assumed
	 * floor, so the risk is confined to a title whose stack runs deeper than that floor, and the
	 * remedy for such a title is to move the floor rather than to re-litigate this method.
	 * {@code argumentSurvivesPrologue} and {@code inboundArgumentCell} consult the same floor,
	 * which is what keeps the three walks agreeing about the same bytes of the same ROM -- the
	 * inconsistency that motivated increment 2 in the first place.
	 * <p>
	 * The motivating reason the guard had to key on the CELL being read rather than on the
	 * instructions passed over remains true and still shapes this method even though the refusal
	 * itself is gone: {@code PHA}/{@code PHP} are still invisible to {@link #writesMemory}, so a
	 * push that genuinely does write the forwarded cell (the accepted residual risk above) is
	 * still stepped over rather than caught -- there is no cheaper per-instruction detector for
	 * it, only the low-probability argument above.
	 */
	static PartialByte forwardedStoreValue(Program program, Instruction useInstr,
			Address target, MechanismState inStateAtStore, Hooks hooks, RegisterEnv env, Budget budget,
			int depth) {
		if (target == null || depth >= MAX_RESOLVE_DEPTH) {
			return PartialByte.unknown();
		}
		if (StackFloor.mayAliasStack(program, target)) {
			// A push between the store and the use would be stepped over silently -- see javadoc.
			return PartialByte.unknown();
		}
		Listing listing = program.getListing();
		// Withdrawn rather than aborted on, exactly as in resolveStoredValue -- see grm-4bgh.7.
		MechanismState inState = inStateAtStore;
		Instruction cur = useInstr;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			if (env.stopsAt(cur.getMinAddress())) {
				return PartialByte.unknown(); // the caller's memory is not modeled -- see javadoc
			}
			if (!budget.spend()) {
				return PartialByte.unknown();
			}
			// Block start, left the basic block, or another path reaches cur with a different
			// cell value -- unless the env licenses this exact join (grm-k90) or names the arm
			// (grm-wul), in which case prev is the real predecessor on the path asked about and
			// a store in that prefix genuinely did execute. Honored here as well as in the
			// register walks deliberately: the licence describes the EDGE, not the kind of value
			// being carried across it, and a forwarding walk that refused where a register walk
			// crossed would make the two disagree about what the same instruction stream did.
			Instruction prev = pathPredecessor(program, listing, cur, env);
			if (prev == null) {
				return PartialByte.unknown();
			}
			if (hooks.isMechanismWrite(prev)) {
				// Same rule as the register scan's, and now the same REMEDY (grm-4bgh.7): the
				// in-state is withdrawn for everything read past this point, and the walk goes
				// on. Note the ordering matters and is favorable -- the writesMemory test below
				// still runs on this very instruction, so a mechanism write that IS a store to
				// the cell being forwarded is forwarded from rather than skipped, which is the
				// right answer and was previously unreachable.
				inState = MechanismState.unknown();
			}

			if (writesMemory(prev)) {
				Character storeReg = MosOperands.storeRegister(prev);
				// The store's own target shares this query tree's budget, unlike the LD<reg>
				// branch's -- see resolveStoredValue's private overload for why only the
				// forwarding lookups do.
				Address storeTarget = storeReg == null ? null
						: effectiveTarget(program, prev, hooks, env, budget, depth + 1);
				if (storeTarget == null) {
					return PartialByte.unknown(); // a memory write this scanner cannot place
				}
				if (storeTarget.equals(target)) {
					return resolveStoredValue(program, prev, storeReg, inState, PartialByte.BYTE_MASK, hooks,
						env, budget, depth + 1).value();
				}
				// provably a different cell -- harmless, keep walking
			}
			if (prev.getFlowType().isCall()) {
				return PartialByte.unknown(); // a subroutine may write anywhere
			}
			cur = prev;
		}
		return PartialByte.unknown();
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
	 * test covers the read-modify-write stores, which {@link MosOperands#storeRegister} deliberately does not
	 * recognize. Over-reporting merely forfeits a forward; under-reporting would be unsound.
	 * <p>
	 * <b>Package-private for a second consumer</b> (bead grm-67g):
	 * {@code HelperArgumentRecovery.inboundArgumentCell} asks the identical question -- "may this
	 * instruction have written the cell I am attributing a value to?" -- over a FORWARD walk
	 * through a helper body rather than this backward one, and the three-detector union is
	 * load-bearing for both. The reference-only {@link MosOperands#writesAddress} is the tempting shortcut
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
		return MEMORY_WRITERS.contains(instr.getMnemonicString().toUpperCase(Locale.ROOT)) &&
			!MosOperands.isAccumulatorForm(instr);
	}
}
