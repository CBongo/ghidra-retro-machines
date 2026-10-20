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
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

import retromachines.StoredValueScanner.Budget;
import retromachines.StoredValueScanner.CrossBlockProof;
import retromachines.StoredValueScanner.Hooks;
import retromachines.StoredValueScanner.ReadBack;
import retromachines.StoredValueScanner.Scan;
import retromachines.StoredValueScanner.Span;

import static retromachines.StoredValueScanner.MAX_RESOLVE_DEPTH;
import static retromachines.StoredValueScanner.pathPredecessor;
import static retromachines.StoredValueScanner.resolveStoredValue;
import static retromachines.StoredValueScanner.restoredKeepingValue;
import static retromachines.StoredValueScanner.stopped;

/**
 * Cross-block PHA/PLA pairing: the bounded all-paths backward search that finds the push a
 * {@code PLA} pops when {@link StoredValueScanner}'s straight-line walk gives up, plus the
 * straight-line walk itself ({@link #findMatchingPush}) and the closed-world predecessor rule
 * both share. Moved out of {@link StoredValueScanner} (bead grm-rx1i.9); behaviour unchanged.
 */
final class CrossBlockStackPairing {

	private CrossBlockStackPairing() {
	}

	/**
	 * Finds the {@code PHA} that a {@code PLA} pairs with, walking backward from the
	 * instruction immediately preceding {@code pla} and matching by STACK DEPTH rather than
	 * address (grm-mej.3 increment 2). A counter starts at 1 (one push is owed); {@code PHA}/
	 * {@code PHP} decrement it and a nested {@code PLA}/{@code PLP} increment it, so an inner
	 * push/pull pair fully balances before an outer pairing is considered. The match is the
	 * push instruction seen when the counter reaches 0.
	 * <p>
	 * <b>A MECHANISM WRITE IN THE SPAN IS NO LONGER AN ABANDON</b> (bead grm-4bgh.7). It was one
	 * for a real reason: once a matching {@code PHA} is found, the ENCLOSING walk resumes
	 * resolving from before it, and a value that walk eventually reads from {@code inStateAtStore}
	 * (a write-through mirror load, say) would be attributed the state AFTER the final store --
	 * i.e. after a mechanism write this span skipped over, a confidently WRONG value. But the
	 * hazard is entirely about the in-state and says nothing about the pairing itself: a store to
	 * the mechanism does not move {@code S}, so the depth counter stays exact across it. The span
	 * is therefore stepped over and the crossing REPORTED to the caller through {@link Span},
	 * which withdraws its in-state and keeps walking -- so a value derived from an immediate,
	 * from the stack, or from the {@code env}'s caller-supplied registers survives the crossing,
	 * while an in-state-derived one still cannot be formed at all.
	 * <p>
	 * The previous version of this javadoc predicted this fix and named its blocker: telling the
	 * two kinds of value apart "also needs bit-wise {@code ASL} modeling to be of any use" on
	 * smb2's {@code ff88} shape ({@code ASL A / PHA / LDA #imm / STA <mechanism> / PLA / STA
	 * <chain>}), because {@code ASL A} was an opaque A-modifier everywhere. grm-4bgh.6 supplied
	 * that modeling, which is what made this relaxation worth making.
	 * <p>
	 * <b>Returns {@code null} (abandon) when:</b>
	 * <ul>
	 * <li>the matching push is a {@code PHP} -- a status byte pushed by {@code PHP} is never a
	 * value, so a {@code PLA} that pairs with one cannot be resolved as one either;</li>
	 * <li>the stack pointer moves by anything other than {@code PHA}/{@code PHP}/{@code PLA}/
	 * {@code PLP} -- compared by BASE register via {@link HelperArgumentRecovery#writesStackPointer},
	 * reused rather than reimplemented because the 6502 stack-pointer-by-two-names trap it
	 * guards against ({@code TXS}'s p-code writing the 1-byte {@code S} while
	 * {@code CompilerSpec.getStackPointer()} answers the 2-byte {@code SP}) applies here
	 * identically;</li>
	 * <li>any instruction in the span has {@code getFlows().length > 0} or a null fall-through,
	 * OTHER THAN A CALL -- this walk is intra-block and straight-line only, matching the
	 * increment's own name, and is what makes the pairing sound: if any control flow could enter
	 * between the {@code PHA} and the {@code PLA}, a different path could have pushed a different
	 * byte, and attributing the pop to THIS push would be a confident wrong value rather than a
	 * missing one (see the class javadoc's PLA bullet for the full soundness argument). A call
	 * IS stepped over as of grm-mej.3 increment 3, reported through {@link Span#crossedCall}; the
	 * inline comment at the crossing carries the fall-through-witness argument for why the depth
	 * counter stays exact across it;</li>
	 * <li>{@code cur} is a control-flow join not licensed by {@code env}
	 * ({@link FlowEdges#isControlFlowJoin}) -- the same reasoning as every other backward walk in this
	 * class: a join means some other path reaches this point in the span with a potentially
	 * different stack depth, which is exactly the hazard the bullet above describes for an
	 * outgoing branch, mirrored for an incoming one;</li>
	 * <li>{@code env} claims this address as its entry -- the caller's stack contents are not
	 * modeled, mirroring {@link LocalStoreForwarding#forwardedStoreValue}'s identical refusal for memory;</li>
	 * <li>the instruction before {@code cur} does not exist ({@code null}) -- the block's start
	 * was reached with the counter still nonzero, i.e. an unbalanced pop;</li>
	 * <li>{@code budgetSteps} is exhausted before a match is found.</li>
	 * </ul>
	 *
	 * @param budgetSteps    how many further instructions this search may step over -- SPENT
	 *                       FROM the caller's {@link StoredValueScanner#MAX_BACKWARD_SCAN} budget, not a fresh one,
	 *                       so a save/restore spanning more than the budget degrades to unknown
	 *                       rather than silently scanning further
	 * @param span           out-param, valid on every return path including a null one: how many
	 *                       instructions this search stepped over (so the caller's own counter
	 *                       stays accurate whether or not a match was found), and whether it
	 *                       crossed a mechanism write doing so
	 */
	static Instruction findMatchingPush(Program program, Instruction pla, int budgetSteps,
			Hooks hooks, RegisterEnv env, Span span) {
		return findMatchingPush(program, pla, budgetSteps, hooks, env, span, 1);
	}

	/**
	 * {@link #findMatchingPush} generalized to an arbitrary starting depth (bead grm-4bgh.1):
	 * a {@code PLA} always owes exactly one push, but a stack-relative reload's {@code $01nn,X}
	 * operand names depth {@code n = nn} counted from the top of stack AT THE {@code TSX}
	 * that set X ({@link StoredValueScanner#stackRelativePush}), which may be any {@code n >= 1}. {@code initialDepth}
	 * is that counter's starting value -- 1 for a {@code PLA} (the 4-arg overload above, kept so
	 * every pre-existing {@code PLA} caller is byte-identical), {@code n} for a stack-relative
	 * reload. Everything else -- the {@code PHP} abandon, the stack-pointer-write abandon, the
	 * join/linkage/call breaks, the mechanism-write step-over, the budget and {@link Span}
	 * accounting --
	 * is unchanged and applies identically regardless of where the counter started.
	 */
	static Instruction findMatchingPush(Program program, Instruction pla, int budgetSteps,
			Hooks hooks, RegisterEnv env, Span span, int initialDepth) {
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			span.steps = 0;
			return null; // cannot verify the depth model -- do not assume the favorable answer
		}
		Listing listing = program.getListing();
		int depth = initialDepth;
		Instruction cur = pla;
		int steps = 0;
		while (steps < budgetSteps) {
			if (env.stopsAt(cur.getMinAddress())) {
				break; // the caller's stack is not modeled -- mirrors forwardedStoreValue
			}
			Instruction prev = pathPredecessor(program, listing, cur, env);
			if (prev == null) {
				// block start reached with the counter still nonzero (unbalanced), left the
				// basic block, or another path could reach here with a different stack depth
				break;
			}
			boolean stepOverCall = prev.getFlowType().isCall();
			if (stepOverCall) {
				// A CALL IS STEPPED OVER (grm-mej.3 increment 3), and the depth counter stays
				// exact across it. pathPredecessor only handed us prev because its fall-through
				// is cur, so if the pop we are pairing executes at all, the callee returned to
				// that fall-through -- and JSR/RTS are balanced by construction: the pushed byte
				// sits BELOW the return address, RTS pops exactly the two bytes above it, and a
				// callee with a non-zero net stack delta at its RTS returns somewhere other than
				// the fall-through, so the pop never runs. REACHING THE FALL-THROUGH IS THE
				// WITNESS -- the same argument SaveRestoreTrampolines.restoresEntryBank crosses
				// its inner JSR on (increment 1), and it needs no look inside the callee, which
				// is what makes ironsword's JSR $FFDA -> JMP ($00C1) crossable at all. The
				// accepted residual is identical too: a callee that BOTH returns normally AND
				// rewrote the slot beneath its own return address -- constructed, not
				// incidental. What a crossed call does disturb is the in-state the resumed walk
				// may consult, and that consequence is the caller's (resumeStateAfterPairing).
				span.crossedCall = true;
				span.crossedCallAt = prev.getMinAddress();
			}
			else if (prev.getFlows().length > 0) {
				break; // not straight-line -- see this method's javadoc
			}
			if (hooks.isMechanismWrite(prev)) {
				// NO LONGER A BREAK (bead grm-4bgh.7). Stepping over a mechanism write cannot
				// disturb the stack DEPTH this walk tracks -- a store writes memory, not S -- so
				// the pairing itself stays exact. What it does disturb is any value the RESUMED
				// walk might read from the caller's in-state, and that consequence is applied
				// there, by the caller, on this flag. See this method's javadoc.
				span.crossedMechanismWrite = true;
			}
			steps++;
			String mnem = prev.getMnemonicString().toUpperCase();
			switch (mnem) {
				case "PHA" -> {
					if (--depth == 0) {
						span.steps = steps;
						return prev;
					}
				}
				case "PHP" -> {
					if (--depth == 0) {
						span.steps = steps;
						return null; // the matching push is a status byte, not a value
					}
				}
				case "PLA", "PLP" -> depth++;
				default -> {
					// BUG FIX (grm-mej.3 increment 3, found by CallCrossingPushPullProgramTest):
					// writesStackPointer must NOT fire on the call instruction itself. A JSR's
					// own p-code writes S (it pushes a two-byte return address), so this check --
					// meant to catch a TXS-style base-register move that desyncs the depth
					// counter -- fired on every crossed call and defeated the crossing entirely,
					// even though a call's own SP write is exactly the balanced push/pop this
					// method's own javadoc argues nets to zero (JSR pushes, RTS pops, before the
					// pairing's resumed walk ever sees the net effect). Excluded here rather than
					// weakening the check itself, so a genuine mid-span TXS/TSX still aborts.
					if (!stepOverCall
						&& HelperArgumentRecovery.writesStackPointer(prev, stackPointer)) {
						span.steps = steps;
						return null; // the stack pointer moved under us -- see javadoc
					}
				}
			}
			cur = prev;
		}
		span.steps = steps;
		return null; // budget exhausted before a match was found
	}

	/**
	 * A join instruction's predecessors, under the CLOSED-WORLD rules every backward walk in this
	 * class already assumes (bead grm-mej.3 increment X1): the physical fall-through predecessor
	 * (when its fall-through actually reaches {@code headAddr}) plus every incoming FLOW reference,
	 * deduplicated against it. Returns {@code null} -- meaning "cannot be soundly enumerated" -- when
	 * {@code headAddr} is itself a function entry (its predecessors are callers, not a control-flow
	 * edge in this function), when any incoming reference is a CALL (code enters here from outside
	 * this span, which no depth or state proof below can account for), or when an incoming edge
	 * comes from an undisassembled address or a different function (the walk could not soundly
	 * continue along it either way). An empty, non-null list means {@code headAddr} is reachable
	 * only by falling off the end of a disassembled predecessor that does not lead here -- a dead
	 * end.
	 * <p>
	 * Factored out of {@link BankDataflowEngine#joinArms} (bead grm-mej.3 increment X1) so both it
	 * and {@link #crossBlockMatchingPush} enumerate a join's incoming edges under the identical
	 * rule -- {@code joinArms} additionally requires at least two predecessors (a fork needs two
	 * arms; a single-predecessor boundary is the value scan's separate linkage refusal, not a join
	 * at all), which it still checks itself after calling this. Every production caller now uses
	 * the four-argument form with cross-function edges admitted ({@code joinArms} since bead
	 * grm-dos9.11); this strict form remains as the rule's reference definition.
	 */
	static List<Address> closedWorldPredecessors(Program program, Listing listing,
			Address headAddr) {
		return closedWorldPredecessors(program, listing, headAddr, false);
	}

	/**
	 * {@link #closedWorldPredecessors(Program, Listing, Address)}, optionally admitting a JUMP
	 * from another function (bead grm-mej.21). Two routines ending in one common epilogue are the
	 * case: cv3's {@code FUN_e61e} ends {@code e62a JMP e63d} into {@code FUN_e62f}'s own
	 * {@code e63d PLA / e63e JMP e2e6}. Ghidra cannot give both functions the tail (bodies may not
	 * overlap), so the edge always looks cross-function. Walking it backward is still one more
	 * enumerated edge: a jump moves no stack byte, and every rule the walk applies -- the
	 * function-entry and call-reference abandons, the per-address depth check -- is applied at
	 * each node it reaches, relative to that node's own function. {@link #crossBlockMatchingPush}
	 * and the save-slot proof ({@link SaveSlotForwarding#solveSlot}, bead grm-mej.22) opt in, and so does
	 * {@code joinArms} (bead grm-dos9.11: cv3's e2d6/e2da entries sharing the e2dc store tail).
	 */
	static List<Address> closedWorldPredecessors(Program program, Listing listing,
			Address headAddr, boolean admitCrossFunctionJumps) {
		FunctionManager fm = program.getFunctionManager();
		if (fm.getFunctionAt(headAddr) != null) {
			return null; // entered by callers, not a predecessor edge in this function
		}
		Function scope = fm.getFunctionContaining(headAddr);
		List<Address> preds = new ArrayList<>();
		Instruction physical = listing.getInstructionBefore(headAddr);
		if (physical != null && headAddr.equals(physical.getFallThrough())) {
			preds.add(physical.getMinAddress());
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(headAddr)) {
			RefType type = ref.getReferenceType();
			if (!type.isFlow()) {
				continue;
			}
			if (type.isCall()) {
				return null; // a call reference into the span -- not a closed world
			}
			Address fromAddr = ref.getFromAddress();
			if (preds.contains(fromAddr)) {
				continue; // a branch whose target is also its own fall-through
			}
			if (listing.getInstructionAt(fromAddr) == null) {
				return null; // undisassembled predecessor
			}
			if (fm.getFunctionContaining(fromAddr) != scope && !admitCrossFunctionJumps) {
				return null; // from a different function
			}
			preds.add(fromAddr);
		}
		return preds;
	}

	/** Sentinel cap for {@link #crossBlockMatchingPush}'s own bounded search, independent of
	 * {@link StoredValueScanner#MAX_BACKWARD_SCAN}. OWNER RULING Q1 set it at 64 on 2026-09-27; the owner approved
	 * raising it on 2026-10-03 (grm-mej.7) to cover River City Ransom's measured mainline
	 * {@code FUN_fed1} restores, whose proofs need (grm-3jzn's 2026-10-03 trace, caps lifted)
	 * c08e 45, c0f4 79, c7db 81, cd57 177 and ef85 317 nodes. 384 is that worst case plus ~20%
	 * headroom -- a sentinel against a pathological search, not a value tuned to one title. */
	static final int CROSS_BLOCK_NODE_CAP = 384;

	/** {@link #crossBlockMatchingPush}'s own join cap. OWNER RULING Q1 set it at 8 forks on
	 * 2026-09-27; raised with the node cap on the owner's 2026-10-03 approval (grm-mej.7) to cover
	 * the same rcransom sites' measured needs (grm-3jzn: c08e 1, c0f4 3, c7db 3, cd57 11, ef85 24
	 * joins) with ~33% headroom. */
	static final int CROSS_BLOCK_JOIN_CAP = 32;

	/** Thrown internally by {@link #crossBlockMatchingPush}'s search to abandon the WHOLE proof
	 * from arbitrary recursion depth; caught only at the top level. Stateless and carries no
	 * message or stack trace -- it is pure control flow within one bounded search. */
	private static final class CrossBlockAbandon extends RuntimeException {
		static final CrossBlockAbandon INSTANCE = new CrossBlockAbandon();

		private CrossBlockAbandon() {
			super(null, null, false, false);
		}
	}

	/**
	 * One backward search node's contribution once it resolves (bead grm-mej.3 increment X1):
	 * which {@code PHA}s the paths from here reach ({@code phas} -- one unless the paths' arms
	 * each pushed their own byte, bead grm-mej.21), whether any of those paths crossed a call
	 * ({@code crossedCall}), the nearest call address EVERY path agreed on ({@code lastCallOnPath},
	 * {@code null} when some path crossed none or they disagreed), and whether any path crossed a
	 * mechanism write ({@code sawMechanismWrite}).
	 */
	private record CrossBlockResult(Set<Address> phas, boolean crossedCall, Address lastCallOnPath,
			boolean sawMechanismWrite) {}

	/**
	 * How many DISTINCT pushes one {@code PLA}'s proof may name (bead grm-mej.21). Each is resumed
	 * as its own walk, and the answer is adopted only when every one of them ends on a read-back
	 * of the same cell, so this bounds work rather than soundness. cv3's {@code e63d} needs two.
	 */
	private static final int CROSS_BLOCK_PUSH_CAP = 4;

	/**
	 * Mutable search-wide state for one {@link #crossBlockMatchingPush} call.
	 * <p>
	 * <b>{@link #spend()} is called EXACTLY ONCE per node visited</b> (bead grm-mej.3 X1 follow-up
	 * fix): once when {@link #solveCrossBlock} is entered for a NEW address (covers every
	 * predecessor that gets recursed into -- a call crossing, a nested push/pop, an ordinary
	 * straight-line step), and once more, directly, for a TERMINAL {@code PHA} at depth 0, which
	 * is never itself passed to a recursive call (there is nothing further to walk from it) and so
	 * has no other entry point to charge it. Earlier code charged BOTH the parent's loop (for every
	 * {@code predAddr} examined) AND the recursive call's own entry, double-counting every
	 * non-terminal node and letting a real 64-node span exhaust the budget at ~32 -- caught by
	 * megaman2's {@code cb60} declining with "node cap exceeded" well under its true span. A node
	 * revisited via the loop-convergence path ({@code inProgress}) or the completed-memo path is
	 * NOT charged again, matching {@code depthSeen}'s existing once-per-address bookkeeping.
	 */
	private static final class CrossBlockSearch {

		int nodeBudget = CROSS_BLOCK_NODE_CAP;
		int joinBudget = CROSS_BLOCK_JOIN_CAP;
		int terminalCount;
		final Map<Address, Integer> depthSeen = new HashMap<>();
		final Map<Address, CrossBlockResult> memo = new HashMap<>();
		final Set<Address> inProgress = new HashSet<>();

		void spend() {
			if (--nodeBudget < 0) {
				throw CrossBlockAbandon.INSTANCE;
			}
		}
	}

	/**
	 * A bounded backward ALL-PATHS search for the {@code PHA} a {@code PLA} pairs with, used ONLY
	 * as a FALLBACK where {@link #findMatchingPush}'s straight-line walk gives up (bead grm-mej.3
	 * increment X1 -- the design's ROM examples are megaman2 {@code cb60} and a contra-{@code
	 * c0d3}-shaped diamond, both on register A). Unlike {@code findMatchingPush}, a control-flow
	 * join does not abandon the search: every incoming edge ({@link #closedWorldPredecessors}) is
	 * explored, and the pairing is trusted only when EVERY explored path agrees -- on the SAME
	 * {@code PHA} at depth 0, with every address visited at a SINGLE owed depth. A loop with zero
	 * net stack effect is stepped over regardless of trip count: its back-edge reconverges on an
	 * already-in-progress node at the same depth and contributes nothing new, rather than being
	 * walked again.
	 * <p>
	 * <b>Soundness rules, applied identically to every explored edge:</b> {@code env.stopsAt} and
	 * an exhausted budget abandon the whole search; a {@code PHP} found at depth 0 abandons (a
	 * status byte, never a value); a stack-pointer write other than a crossed call ({@code TSX}/
	 * {@code TXS}, or any other -- see {@link HelperArgumentRecovery#writesStackPointer}) abandons;
	 * a call is stepped over via the existing fall-through witness, exactly as
	 * {@link #findMatchingPush} already crosses one; a mechanism write is stepped over and merely
	 * recorded, per {@link Span#crossedMechanismWrite}'s existing rule; the same address reached
	 * at two different owed depths abandons (bead-tracked as "disagreeing joins"); a predecessor
	 * edge {@link #closedWorldPredecessors} cannot enumerate (a call reference into the span, an
	 * undisassembled predecessor, or the span reaching a function entry) abandons the whole
	 * search. A JUMP in from another function is walked like any other edge (bead grm-mej.21;
	 * X1 abandoned on it) -- see the four-argument {@link #closedWorldPredecessors}.
	 * <p>
	 * <b>Different push sites on different paths</b> (bead grm-mej.21; X1 abandoned on them) are
	 * returned together, up to {@link #CROSS_BLOCK_PUSH_CAP}: the pop then reads whichever arm's
	 * byte the execution pushed, so the CALLER resumes from each and adopts the answer only when
	 * every arm agrees -- see {@link #pairedArms}. cv3's shared epilogue {@code e63d PLA}, reached
	 * from {@code e621 PHA} and {@code e634 PHA}, is the case.
	 * <p>
	 * <b>Budget</b> is this method's OWN -- {@link #CROSS_BLOCK_NODE_CAP} nodes,
	 * {@link #CROSS_BLOCK_JOIN_CAP} joins -- independent of {@link StoredValueScanner#MAX_BACKWARD_SCAN}; the caller
	 * charges its own budget exactly ONE step regardless of outcome (OWNER RULING Q1, 2026-09-27).
	 * <p>
	 * <b>Runs only under a state oracle</b> ({@link Hooks#hasStateOracle}) and never along a
	 * {@code grm-wul} arm ({@link RegisterEnv#hasArms}, out of scope for this increment) --
	 * enforced by the caller, not here, so this method itself has no oracle-vs-direct-site branch
	 * to keep in sync.
	 * <p>
	 * <b>Memoized per PLA</b> across a whole analysis run via {@link Hooks#crossBlockProofMemo} --
	 * the proof is state-free, so nothing about it can go stale within one run.
	 *
	 * @param pla  the {@code PLA} instruction the search resolves, entered at depth 1 exactly like
	 *             {@link #findMatchingPush}'s 4-argument overload
	 * @param span out-param: {@link Span#crossedBlock} is set whenever this method returns
	 *             non-null (so the caller always resumes through {@link Hooks#stateAt}, never the
	 *             local in-state); {@link Span#crossedCall}/{@code crossedCallAt} name the sole
	 *             agreed nearest call, when every path crossed one and agreed on which; {@link
	 *             Span#crossedMechanismWrite} is set when any path crossed one
	 * @return the found {@code PHA}s in address order, or an empty list to decline (the caller
	 *         keeps today's {@code ANALYZER_LIMIT} answer unchanged)
	 */
	static List<Instruction> crossBlockMatchingPush(Program program, Instruction pla,
			Hooks hooks, RegisterEnv env, Span span) {
		if (env.hasArms()) {
			return List.of(); // grm-wul arm queries do not search (out of scope for this increment)
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			return List.of();
		}
		Listing listing = program.getListing();
		Address plaAddr = pla.getMinAddress();

		Map<Address, CrossBlockProof> memo = hooks.crossBlockProofMemo();
		CrossBlockProof cached = memo == null ? null : memo.get(plaAddr);
		if (cached != null) {
			return applyProof(listing, cached, span);
		}

		CrossBlockSearch ctx = new CrossBlockSearch();
		CrossBlockProof proof;
		try {
			// The top-level call is never itself in-progress, so an empty Optional here can only
			// mean the whole search resolved to nothing -- treat exactly like a decline.
			proof = solveCrossBlock(program, listing, hooks, env, stackPointer, ctx, plaAddr, 1)
				.map(result -> new CrossBlockProof(new ArrayList<>(new TreeSet<>(result.phas())),
					result.crossedCall(), result.lastCallOnPath(), result.sawMechanismWrite()))
				.orElse(CrossBlockProof.DECLINED);
		}
		catch (CrossBlockAbandon abandon) {
			proof = CrossBlockProof.DECLINED;
		}
		if (memo != null) {
			memo.put(plaAddr, proof);
		}
		List<Instruction> found = applyProof(listing, proof, span);
		if (!found.isEmpty()) {
			Msg.debug(StoredValueScanner.class, "cross-block PHA/PLA pairing: pull=" + plaAddr +
				" push=" + proof.phas() + " paths=" + ctx.terminalCount);
		}
		return found;
	}

	/** Applies a {@link CrossBlockProof} (fresh or memoized) to {@code span} and returns the
	 * found {@code PHA} instructions in address order, or an empty list for a declined proof. */
	private static List<Instruction> applyProof(Listing listing, CrossBlockProof proof,
			Span span) {
		List<Instruction> pushes = new ArrayList<>();
		for (Address pha : proof.phas()) {
			Instruction instr = listing.getInstructionAt(pha);
			if (instr == null) {
				return List.of();
			}
			pushes.add(instr);
		}
		if (pushes.isEmpty()) {
			return pushes;
		}
		span.crossedBlock = true;
		span.crossedCall = proof.crossedCall();
		span.crossedCallAt = proof.agreedLastCall();
		span.crossedMechanismWrite = proof.crossedMechanismWrite();
		return pushes;
	}

	/**
	 * The answer for a {@code PLA} whose cross-block proof found SEVERAL pushes -- one per arm of
	 * a join, each pushing its own byte (bead grm-mej.21; cv3's shared epilogue {@code e63d PLA /
	 * e63e JMP e2e6}, reached from {@code e61e LDA $8000 / PHA} and {@code e631 LDA $8000 / PHA}).
	 * The popped byte is whichever arm's push executed, so the walk resumes from EACH push under
	 * {@link Hooks#stateAt} there, exactly as a single cross-block pairing resumes, and the answer
	 * is adopted only when EVERY arm ends on a {@code RESTORED_BANK} read-back of the SAME cell:
	 * then the site re-commits the bank read back on whichever arm ran, and the value is the
	 * {@link PartialByte#merge} of the arms'. Anything else -- an arm with no state at its push,
	 * an arm that resolves or declines, arms reading different cells -- returns today's
	 * {@code ANALYZER_LIMIT} unknown. Merging resolved arm values would be sound too, but is not
	 * attempted: X1 ruled those disagreeing joins an abandon, and this lifts that only for the
	 * restore idiom the bead names.
	 * <p>
	 * Only for a bare pop: the accumulators must still be the identity (nothing composed onto the
	 * popped byte before the store), since each arm is resumed as a fresh walk.
	 */
	static Scan pairedArms(Program program, Instruction pla, List<Instruction> pushes,
			char reg, int aAcc, int oAcc, int mask, Hooks hooks, RegisterEnv env, Budget budget,
			int depth, int step) {
		Scan declined = stopped(aAcc, oAcc, mask, PartialByte.unknown(),
			BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
		if (reg != 'A' || aAcc != 0xFF || oAcc != 0x00 || depth >= MAX_RESOLVE_DEPTH) {
			return declined;
		}
		List<ReadBack> reads = new ArrayList<>();
		PartialByte merged = null;
		for (Instruction push : pushes) {
			MechanismState atPush = hooks.stateAt(push.getMinAddress());
			if (atPush == null) {
				return declined; // no state at this push -- abandon, never withdraw (ironsword)
			}
			Scan arm = resolveStoredValue(program, push, reg, atPush, mask, hooks, env, budget,
				depth + 1, step);
			ReadBack rb = arm.readBack();
			if (arm.stop() != BankSwitchStrategy.ValueStop.RESTORED_BANK || rb == null ||
				!rb.arms().isEmpty() || rb.crossBlockPush() != null || rb.slot() != null ||
				(!reads.isEmpty() && !rb.cell().equals(reads.get(0).cell()))) {
				return declined;
			}
			reads.add(new ReadBack(rb.cell(), rb.readAt(), rb.carriedAcross(),
				push.getMinAddress(), pla.getMinAddress()));
			merged = merged == null ? arm.value() : PartialByte.merge(merged, arm.value());
		}
		Msg.debug(StoredValueScanner.class, "cross-block PHA/PLA pairing over " + reads.size() +
			" arms: pull=" + pla.getMinAddress() + " cell=" + reads.get(0).cell());
		Scan restored = restoredKeepingValue(aAcc, oAcc, mask, merged, ReadBack.joined(reads));
		return restored != null ? restored
				: stopped(aAcc, oAcc, mask, merged, BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
	}

	/**
	 * The recursive heart of {@link #crossBlockMatchingPush}: what every path backward from
	 * {@code addr}, owing {@code depth} pushes, resolves to. Returns {@link Optional#empty()} --
	 * meaning "a cycle back to a node still being computed above this one on the call stack; no
	 * NEW contribution" -- rather than a result, so a loop's back-edge can reconverge without
	 * re-deriving what the loop's other arm(s) already establish. Throws {@link CrossBlockAbandon}
	 * to abandon the WHOLE search from any depth.
	 */
	private static Optional<CrossBlockResult> solveCrossBlock(Program program, Listing listing,
			Hooks hooks, RegisterEnv env, Register stackPointer, CrossBlockSearch ctx, Address addr,
			int depth) {
		Integer seenDepth = ctx.depthSeen.get(addr);
		if (seenDepth != null) {
			if (seenDepth != depth) {
				throw CrossBlockAbandon.INSTANCE; // same address, disagreeing owed depths
			}
			if (ctx.inProgress.contains(addr)) {
				return Optional.empty(); // a loop's back-edge -- no new contribution
			}
			// Already resolved -- possibly to "no contribution" (memo holds an explicit null for
			// a node whose every edge was itself a cycle), so ofNullable rather than of().
			return Optional.ofNullable(ctx.memo.get(addr));
		}
		ctx.depthSeen.put(addr, depth);
		ctx.spend();
		ctx.inProgress.add(addr);
		if (env.stopsAt(addr)) {
			throw CrossBlockAbandon.INSTANCE; // the caller's stack is not modeled
		}
		List<Address> preds = closedWorldPredecessors(program, listing, addr, true);
		if (preds == null || preds.isEmpty()) {
			throw CrossBlockAbandon.INSTANCE; // unsound edge, or a dead end
		}
		if (preds.size() > 1 && --ctx.joinBudget < 0) {
			throw CrossBlockAbandon.INSTANCE; // join cap exceeded
		}

		List<CrossBlockResult> contributions = new ArrayList<>();
		for (Address predAddr : preds) {
			Instruction predInstr = listing.getInstructionAt(predAddr);
			if (predInstr == null) {
				throw CrossBlockAbandon.INSTANCE;
			}
			boolean mech = hooks.isMechanismWrite(predInstr);
			if (predInstr.getFlowType().isCall()) {
				// Stepped over via the same fall-through witness findMatchingPush already relies
				// on: reaching the fall-through proves the callee returned, and JSR/RTS are
				// balanced by construction, so the depth counter stays exact across it.
				// No spend() here: predAddr is charged exactly once, by the recursive call's own
				// entry (bead grm-mej.3 X1 follow-up -- see solveCrossBlock's javadoc on the
				// double-charge this replaced).
				solveCrossBlock(program, listing, hooks, env, stackPointer, ctx, predAddr, depth)
					.ifPresent(child -> contributions.add(new CrossBlockResult(child.phas(), true,
						predAddr, child.sawMechanismWrite() || mech)));
				continue;
			}
			String mnem = predInstr.getMnemonicString().toUpperCase();
			switch (mnem) {
				case "PHA" -> {
					int next = depth - 1;
					if (next == 0) {
						// A TERMINAL node: unlike every other case below, this predAddr is never
						// passed to a recursive solveCrossBlock call (there is nothing further to
						// walk), so it has no other entry point to charge it. Charge it here,
						// exactly once, matching every other node's single charge.
						ctx.spend();
						contributions.add(new CrossBlockResult(Set.of(predAddr), false, null, mech));
						ctx.terminalCount++;
					}
					else {
						solveCrossBlock(program, listing, hooks, env, stackPointer, ctx, predAddr,
							next).ifPresent(child -> contributions
								.add(carryMechanism(child, mech)));
					}
				}
				case "PHP" -> {
					if (depth - 1 == 0) {
						throw CrossBlockAbandon.INSTANCE; // the matching push is a status byte
					}
					solveCrossBlock(program, listing, hooks, env, stackPointer, ctx, predAddr,
						depth - 1).ifPresent(child -> contributions
							.add(carryMechanism(child, mech)));
				}
				case "PLA", "PLP" -> solveCrossBlock(program, listing, hooks, env, stackPointer,
					ctx, predAddr, depth + 1)
						.ifPresent(child -> contributions.add(carryMechanism(child, mech)));
				default -> {
					if (HelperArgumentRecovery.writesStackPointer(predInstr, stackPointer)) {
						throw CrossBlockAbandon.INSTANCE; // the stack pointer moved under us
					}
					solveCrossBlock(program, listing, hooks, env, stackPointer, ctx, predAddr,
						depth).ifPresent(child -> contributions.add(carryMechanism(child, mech)));
				}
			}
		}
		ctx.inProgress.remove(addr);
		if (contributions.isEmpty()) {
			ctx.memo.put(addr, null); // record the resolution as "no contribution", not "unvisited"
			return Optional.empty(); // every edge was itself a cycle -- no new contribution here
		}
		// Different push sites on different paths no longer abandon (bead grm-mej.21): each is a
		// separate arm the caller resumes from, and the caller adopts the answer only when every
		// arm agrees on what it read back. Bounded by CROSS_BLOCK_PUSH_CAP.
		Set<Address> phas = new TreeSet<>();
		boolean crossedCall = false;
		boolean sawMechanismWrite = false;
		Address agreedLastCall = null;
		boolean firstCall = true;
		boolean lastCallAgrees = true;
		for (CrossBlockResult c : contributions) {
			phas.addAll(c.phas());
			if (phas.size() > CROSS_BLOCK_PUSH_CAP) {
				throw CrossBlockAbandon.INSTANCE;
			}
			crossedCall |= c.crossedCall();
			sawMechanismWrite |= c.sawMechanismWrite();
			if (!c.crossedCall() || c.lastCallOnPath() == null) {
				lastCallAgrees = false;
			}
			else if (firstCall) {
				agreedLastCall = c.lastCallOnPath();
				firstCall = false;
			}
			else if (!agreedLastCall.equals(c.lastCallOnPath())) {
				lastCallAgrees = false;
			}
		}
		CrossBlockResult combined = new CrossBlockResult(Set.copyOf(phas), crossedCall,
			lastCallAgrees ? agreedLastCall : null, sawMechanismWrite);
		ctx.memo.put(addr, combined);
		return Optional.of(combined);
	}

	/** {@code child}, with {@code mech} folded into its {@code sawMechanismWrite} flag. */
	private static CrossBlockResult carryMechanism(CrossBlockResult child, boolean mech) {
		return mech && !child.sawMechanismWrite()
				? new CrossBlockResult(child.phas(), child.crossedCall(), child.lastCallOnPath(),
					true)
				: child;
	}
}
