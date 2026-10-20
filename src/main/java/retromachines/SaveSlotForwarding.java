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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

import retromachines.StoredValueScanner.Budget;
import retromachines.StoredValueScanner.CensusKey;
import retromachines.StoredValueScanner.CensusResult;
import retromachines.StoredValueScanner.Hooks;
import retromachines.StoredValueScanner.ProofMemo;
import retromachines.StoredValueScanner.ReadBack;
import retromachines.StoredValueScanner.Scan;
import retromachines.StoredValueScanner.SlotCarrier;
import retromachines.StoredValueScanner.SlotKey;
import retromachines.StoredValueScanner.SlotProof;

import static retromachines.CrossBlockStackPairing.CROSS_BLOCK_JOIN_CAP;
import static retromachines.CrossBlockStackPairing.CROSS_BLOCK_NODE_CAP;
import static retromachines.StoredValueScanner.MAX_BACKWARD_SCAN;
import static retromachines.StoredValueScanner.MAX_RESOLVE_DEPTH;
import static retromachines.StoredValueScanner.MAX_RESOLVE_STEPS;
import static retromachines.StoredValueScanner.calleePreserves;
import static retromachines.StoredValueScanner.classifySlotWrite;
import static retromachines.CrossBlockStackPairing.closedWorldPredecessors;
import static retromachines.StoredValueScanner.constantRegisterValue;
import static retromachines.StoredValueScanner.entersUnknownBank;
import static retromachines.StoredValueScanner.knownBranchOutcome;
import static retromachines.StoredValueScanner.looksLikeReturnDispatch;
import static retromachines.StoredValueScanner.resolveStoredValue;
import static retromachines.StoredValueScanner.restoredKeepingValue;
import static retromachines.StoredValueScanner.stopped;

/**
 * RAM save-slot forwarding across calls and joins, and the callee-closure writer census it
 * rests on (bead grm-zsxz increment Z2). Moved out of {@link StoredValueScanner} (bead
 * grm-rx1i.9); behaviour unchanged.
 */
final class SaveSlotForwarding {

	private SaveSlotForwarding() {
	}

	// ------------------------------------------------------------------
	// RAM save-slot forwarding across calls and joins (bead grm-zsxz increment Z2)
	// ------------------------------------------------------------------

	/** {@link #saveSlotForwarded}'s own cap on the instructions ONE callee closure's writer
	 *  census may visit. A sentinel against a pathological closure (a game's whole main loop is
	 *  reachable from some calls), not a value tuned to one title; over it, the census abandons. */
	private static final int SLOT_CENSUS_INSTRUCTION_CAP = 4096;

	/** How far back from an {@code RTS}/{@code RTI} the census looks for the push-then-return
	 *  dispatch idiom ({@link StoredValueScanner#looksLikeReturnDispatch}). */
	static final int RETURN_DISPATCH_LOOKBACK = 8;

	/** Thrown internally by the save-slot search and census to abandon the WHOLE proof from any
	 *  recursion depth; caught only at the top. Stateless, no stack trace -- pure control flow. */
	private static final class SlotAbandon extends RuntimeException {
		static final SlotAbandon INSTANCE = new SlotAbandon();

		private SlotAbandon() {
			super(null, null, false, false);
		}
	}

	/** How one instruction relates to the save slot a proof is forwarding. */
	enum SlotWrite {
		/** Provably does not write the slot. */
		NONE,
		/** A plain {@code STA}/{@code STX}/{@code STY} to exactly the slot -- a usable source. */
		STORES_SLOT,
		/** Writes (or may write) the slot in a way that is not a usable source: a read-modify-
		 *  write, an indexed store whose reachable window covers the slot, a resolved write
		 *  reference from anything else. */
		WRITES_SLOT,
		/** A memory write this proof cannot place at all. */
		UNPLACEABLE,
		/** A true indirect store, stepped over under
		 *  {@link SlotAssumption#INDIRECT_STORES_DO_NOT_WRITE_SLOT}. */
		INDIRECT_ASSUMED
	}

	/** One save-slot search node's resolution: the store every path from it reaches, the calls
	 *  whose save helper ran it ({@code via}; empty when the store is on the paths themselves --
	 *  bead grm-mej.23), and whether any of those paths relied on the indirect-store assumption. */
	private record SlotResult(Address store, Set<Address> via, boolean indirectAssumed) {}

	/** Sentinel cap on the distinct calls ({@link SlotResult#via}) one save-slot proof may resolve
	 *  a save helper through (bead grm-mej.23). cv3's shared {@code e67f} epilogue measured 31 arms;
	 *  this is about twice that, a sentinel against a pathological fan-in, not a tuned value. */
	private static final int SLOT_HELPER_ARM_CAP = 64;

	/** Mutable search-wide state for one save-slot proof. Spending mirrors
	 *  {@link CrossBlockSearch}: once per node entered, once more per terminal store. */
	private static final class SlotSearch {

		int nodeBudget = CROSS_BLOCK_NODE_CAP;
		int joinBudget = CROSS_BLOCK_JOIN_CAP;
		final Set<Address> visited = new HashSet<>();
		final Map<Address, SlotResult> memo = new HashMap<>();
		final Set<Address> inProgress = new HashSet<>();

		void spend() {
			if (--nodeBudget < 0) {
				throw SlotAbandon.INSTANCE;
			}
		}
	}

	/**
	 * The value a load of a RAM SAVE SLOT reads, forwarded from the ONE store that filled it --
	 * across calls and control-flow joins within one function body (bead grm-zsxz increment Z2).
	 * The RAM-slot model in the same backward ALL-PATHS skeleton X1 built for stack slots
	 * ({@link CrossBlockStackPairing#crossBlockMatchingPush}): slot identity is an ADDRESS rather than a depth, a path
	 * ends at a placeable store to that address, and a call is crossed only on a WRITER CENSUS of
	 * its callee closure instead of the stack's fall-through witness. Blaster Master's
	 * {@code FUN_e9b8} is the shape ({@code e9bb LDA $DB / STA $D3}, three calls, {@code e9c9 LDA
	 * $D3 / JSR $E61B}).
	 * <p>
	 * <b>A FALLBACK ONLY</b>, called solely where {@link StoredValueScanner#resolveStoredValue} was about to return
	 * a wholly unknown {@code ANALYZER_LIMIT} for this load, and only under a state oracle
	 * ({@link Hooks#hasStateOracle}) off any grm-wul arm. Returns {@code null} on EVERY failure --
	 * a declined proof, no state at the store, or a resumed walk that ends anywhere other than a
	 * value or a restore -- so the caller keeps today's answer exactly; it can only turn a decline
	 * into an answer, never change a classification it did not improve (grm-mej.3's lesson:
	 * widening what a walk traverses changes stop classification, so a resumed walk ending in,
	 * say, {@code RUNTIME_SOURCE} is NOT adopted).
	 * <p>
	 * <b>Resolution.</b> The store is re-scanned for the register it stores, under the tracked
	 * state AT THE STORE ({@link Hooks#stateAt}; {@code null} abandons -- the ironsword rule,
	 * {@link StoredValueScanner#resumeStateAfterPairing}). That state predates every call and mechanism write
	 * between the store and the load, so a mirror read feeding the store is attributed the bank
	 * live at the read. A resolved value is folded through this walk's accumulators exactly as
	 * {@link LocalStoreForwarding#forwardedStoreValue} folds one; a {@code RESTORED_BANK} stop is kept, with the slot
	 * recorded as its {@link SlotCarrier}, when this walk's accumulators are still the identity
	 * (the stored byte reaches the site unmodified).
	 * <p>
	 * <b>The proof</b> (all paths backward from the load, under {@link CrossBlockStackPairing#closedWorldPredecessors}'
	 * closed-world rules): every path must reach the SAME plain store to the slot before reaching
	 * anything that may write it. Abandons on: different stores on different paths (stores whose
	 * values might agree are NOT reconciled -- that would need each resolved under its own state,
	 * and no measured customer needs it); a path reaching a function entry, a call reference, an
	 * undisassembled predecessor, or the env's entry (a JUMP in from another function is walked,
	 * bead grm-mej.22); any other writer of the slot on a path ({@link StoredValueScanner#classifySlotWrite}); a
	 * crossed call whose callee closure may write the slot ({@link #calleeClosureCensus}) --
	 * unless that callee is a SAVE HELPER ({@link #saveHelperStore}, bead grm-mej.23), when the
	 * call ends the path as its store, resolved per call by {@link #saveHelperArms}; the node/join
	 * caps (the same
	 * {@link CrossBlockStackPairing#CROSS_BLOCK_NODE_CAP}/{@link CrossBlockStackPairing#CROSS_BLOCK_JOIN_CAP} X1 uses). Slots that may alias
	 * the stack ({@link StackFloor}), non-writable and volatile cells, and indexed loads are
	 * refused up front. Interrupt handlers are not modelled as writers -- the same stance the
	 * within-block forwarding has always taken.
	 */
	static Scan saveSlotForwarded(Program program, Instruction load, int aAcc, int oAcc,
			int mask, Hooks hooks, RegisterEnv env, Budget budget, int depth) {
		if (depth >= MAX_RESOLVE_DEPTH) {
			return null;
		}
		Address cell = MosOperands.plainAbsoluteTarget(load);
		if (cell == null) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(cell);
		if (block == null || !block.isWrite() || block.isVolatile() ||
			StackFloor.mayAliasStack(program, cell)) {
			return null;
		}
		int innerMask = mask & aAcc & ~oAcc;
		if (innerMask == 0) {
			return null;
		}
		SlotProof proof = saveSlotProof(program, load, cell, hooks, env);
		if (proof.store() == null) {
			return null;
		}
		Listing listing = program.getListing();
		Instruction store = listing.getInstructionAt(proof.store());
		Character storeReg = store == null ? null : MosOperands.storeRegister(store);
		if (storeReg == null) {
			return null;
		}
		if (!proof.via().isEmpty()) {
			return saveHelperArms(program, load, store, storeReg, cell, proof, aAcc, oAcc, mask,
				innerMask, hooks, budget, depth);
		}
		MechanismState atStore = hooks.stateAt(store.getMinAddress());
		if (atStore == null) {
			return null; // no state at the store: abandon, never withdraw-and-continue
		}
		Scan inner = resolveStoredValue(program, store, storeReg, atStore, innerMask, hooks, env,
			budget, depth + 1);
		SlotCarrier carrier = new SlotCarrier(cell, store.getMinAddress(), load.getMinAddress(),
			proof.indirectStoresAssumed());
		Msg.debug(StoredValueScanner.class, "save-slot forwarding: load=" + load.getMinAddress() +
			" cell=" + cell + " store=" + store.getMinAddress() + " -> " + inner.stop());
		if (inner.stop() == BankSwitchStrategy.ValueStop.RESTORED_BANK && inner.readBack() != null &&
			aAcc == 0xFF && oAcc == 0x00) {
			// grm-mej.8: checked BEFORE the partly-known case below, so a restore whose byte the
			// strategy could partly evaluate keeps its read-back -- see restoredKeepingValue.
			Scan restored = restoredKeepingValue(aAcc, oAcc, mask, inner.value(),
				inner.readBack().withSlot(carrier));
			if (restored != null) {
				return restored;
			}
		}
		if (inner.value().knownMask() != 0) {
			return stopped(aAcc, oAcc, mask, inner.value(),
				BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
		}
		return null;
	}

	/**
	 * {@link #saveSlotForwarded}'s answer when the proof's store sits inside a SAVE HELPER the
	 * paths CALL (bead grm-mej.23; {@link #saveHelperStore}). Each call is an arm: the paths
	 * reach the same store through different calls (cv3's ~30 trampolines each {@code JSR e2e0}),
	 * and the store's state is the merge over every caller, so each arm is resolved under the
	 * state AT ITS OWN CALL ({@link Hooks#stateAt}) -- sound because the helper's line from its
	 * entry to the store switches nothing. The answer is adopted only as grm-mej.21's
	 * {@link CrossBlockStackPairing#pairedArms} adopts one: EVERY arm a {@code RESTORED_BANK} read-back of the SAME
	 * cell, read on that straight line (so the call-site state is the state at the read), with
	 * this walk's accumulators still the identity. Anything else -- an arm with no state at its
	 * call, an arm that resolves to a number or declines -- returns {@code null}, keeping today's
	 * answer: merging resolved arm values would be sound too, but no measured customer needs it.
	 */
	private static Scan saveHelperArms(Program program, Instruction load, Instruction store,
			char storeReg, Address cell, SlotProof proof, int aAcc, int oAcc, int mask,
			int innerMask, Hooks hooks, Budget budget, int depth) {
		if (aAcc != 0xFF || oAcc != 0x00) {
			return null;
		}
		Listing listing = program.getListing();
		List<ReadBack> reads = new ArrayList<>();
		PartialByte merged = null;
		for (Address callAt : proof.via()) {
			Instruction call = listing.getInstructionAt(callAt);
			Address[] flows = call == null ? null : call.getFlows();
			if (flows == null || flows.length != 1) {
				return null;
			}
			Address entry = flows[0];
			MechanismState atCall = hooks.stateAt(callAt);
			if (atCall == null) {
				return null; // no state at this call -- abandon, never withdraw (ironsword)
			}
			Scan arm = resolveStoredValue(program, store, storeReg, atCall, innerMask, hooks,
				RegisterEnv.NONE, budget, depth + 1);
			ReadBack rb = arm.readBack();
			if (arm.stop() != BankSwitchStrategy.ValueStop.RESTORED_BANK || rb == null ||
				!rb.arms().isEmpty() || rb.slot() != null || rb.crossBlockPush() != null ||
				rb.carriedAcross() != null || !sameSpace(rb.readAt(), entry) ||
				rb.readAt().compareTo(entry) < 0 ||
				rb.readAt().compareTo(store.getMinAddress()) >= 0 ||
				(!reads.isEmpty() && !rb.cell().equals(reads.get(0).cell()))) {
				return null;
			}
			reads.add(rb.withSlot(new SlotCarrier(cell, store.getMinAddress(),
				load.getMinAddress(), proof.indirectStoresAssumed(), callAt)));
			merged = merged == null ? arm.value() : PartialByte.merge(merged, arm.value());
		}
		Msg.debug(StoredValueScanner.class, "save-slot forwarding through a save helper: load=" +
			load.getMinAddress() + " cell=" + cell + " store=" + store.getMinAddress() + " over " +
			reads.size() + " call(s)");
		ReadBack readBack = reads.size() == 1 ? reads.get(0) : ReadBack.joined(reads);
		Scan restored = restoredKeepingValue(aAcc, oAcc, mask, merged, readBack);
		// Every arm's state pinned the read-back byte whole: the merged value, as the direct
		// route keeps one (saveSlotForwarded's partly-known branch).
		return restored != null ? restored
				: stopped(aAcc, oAcc, mask, merged, BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
	}

	private static boolean sameSpace(Address a, Address b) {
		return a.getAddressSpace().equals(b.getAddressSpace());
	}

	/** The (possibly memoized) save-slot proof for {@code load} reading {@code cell}. */
	private static SlotProof saveSlotProof(Program program, Instruction load, Address cell,
			Hooks hooks, RegisterEnv env) {
		ProofMemo memo = hooks.saveSlotMemo();
		SlotKey key = new SlotKey(load.getMinAddress(), cell.getOffset(), env.entryAddr());
		SlotProof cached = memo == null ? null : memo.slotProofs.get(key);
		if (cached != null) {
			return cached;
		}
		SlotSearch ctx = new SlotSearch();
		SlotProof proof;
		try {
			proof = solveSlot(program, program.getListing(), env, hooks, memo, ctx, cell,
				load.getMinAddress())
					.map(r -> new SlotProof(r.store(), new ArrayList<>(new TreeSet<>(r.via())),
						r.indirectAssumed()))
					.orElse(SlotProof.DECLINED);
		}
		catch (SlotAbandon abandon) {
			proof = SlotProof.DECLINED;
		}
		if (memo != null) {
			memo.slotProofs.put(key, proof);
		}
		return proof;
	}

	/**
	 * The recursive heart of {@link #saveSlotProof}: what every path backward from {@code addr}
	 * resolves to. {@link Optional#empty()} means a loop back-edge (or a node whose every edge
	 * was one) -- no new contribution -- exactly as in {@link CrossBlockStackPairing#solveCrossBlock}.
	 */
	private static Optional<SlotResult> solveSlot(Program program, Listing listing,
			RegisterEnv env, Hooks hooks, ProofMemo memo, SlotSearch ctx, Address cell,
			Address addr) {
		if (ctx.visited.contains(addr)) {
			if (ctx.inProgress.contains(addr)) {
				return Optional.empty();
			}
			return Optional.ofNullable(ctx.memo.get(addr));
		}
		ctx.visited.add(addr);
		ctx.spend();
		ctx.inProgress.add(addr);
		if (env.stopsAt(addr)) {
			throw SlotAbandon.INSTANCE; // the caller's memory is not modelled
		}
		// grm-mej.22: a JUMP in from another function is one more enumerated edge (cv3's e67f
		// LDA $22, the shared tail of ~30 trampolines that each JMP e67f) -- the same rule, and
		// the same per-node entry/call-reference abandons, crossBlockMatchingPush walks under.
		List<Address> preds = closedWorldPredecessors(program, listing, addr, true);
		if (preds == null || preds.isEmpty()) {
			throw SlotAbandon.INSTANCE; // a function entry, a call ref, an unsound edge, a dead end
		}
		if (preds.size() > 1 && --ctx.joinBudget < 0) {
			throw SlotAbandon.INSTANCE;
		}
		List<SlotResult> contributions = new ArrayList<>();
		for (Address predAddr : preds) {
			Instruction pred = listing.getInstructionAt(predAddr);
			if (pred == null) {
				throw SlotAbandon.INSTANCE;
			}
			boolean assumed = false;
			switch (classifySlotWrite(program, pred, cell)) {
				case STORES_SLOT -> {
					ctx.spend(); // a terminal node, charged once (see SlotSearch)
					contributions.add(new SlotResult(predAddr, Set.of(), false));
					continue;
				}
				case WRITES_SLOT, UNPLACEABLE -> throw SlotAbandon.INSTANCE;
				case INDIRECT_ASSUMED -> assumed = true;
				case NONE -> {
				}
			}
			if (pred.getFlowType().isCall()) {
				CensusResult census = callCensus(program, listing, memo, pred, cell);
				if (!census.clean()) {
					// grm-mej.23: a callee that may write the slot is still a usable SOURCE when it
					// is a save helper -- it stores the slot exactly once, last, on every path.
					SaveHelperStore helper = saveHelperStore(program, listing, hooks, memo, pred,
						cell);
					if (helper == null) {
						throw SlotAbandon.INSTANCE; // the callee closure may write the slot
					}
					ctx.spend(); // a terminal node, charged once (see SlotSearch)
					contributions.add(new SlotResult(helper.store(), Set.of(predAddr),
						assumed || helper.indirectStoresAssumed()));
					continue;
				}
				assumed |= census.indirectStoresAssumed();
			}
			boolean viaAssumption = assumed;
			solveSlot(program, listing, env, hooks, memo, ctx, cell, predAddr).ifPresent(child ->
				contributions.add(viaAssumption && !child.indirectAssumed()
						? new SlotResult(child.store(), child.via(), true) : child));
		}
		ctx.inProgress.remove(addr);
		if (contributions.isEmpty()) {
			ctx.memo.put(addr, null);
			return Optional.empty();
		}
		Address store = contributions.get(0).store();
		boolean direct = contributions.get(0).via().isEmpty();
		boolean anyAssumed = false;
		Set<Address> via = new HashSet<>();
		for (SlotResult c : contributions) {
			if (!c.store().equals(store)) {
				throw SlotAbandon.INSTANCE; // different stores on different paths
			}
			if (c.via().isEmpty() != direct) {
				throw SlotAbandon.INSTANCE; // the store reached both directly and through a call
			}
			anyAssumed |= c.indirectAssumed();
			via.addAll(c.via());
		}
		if (via.size() > SLOT_HELPER_ARM_CAP) {
			throw SlotAbandon.INSTANCE;
		}
		SlotResult combined = new SlotResult(store, via, anyAssumed);
		ctx.memo.put(addr, combined);
		return Optional.of(combined);
	}

	/**
	 * The writer census for one crossed {@code call}: whether NOTHING its callee closure may
	 * execute writes {@code cell}. The call must have exactly one resolved, disassembled target in
	 * a known bank; see {@link #calleeClosureCensus} for the closure itself.
	 */
	private static CensusResult callCensus(Program program, Listing listing, ProofMemo memo,
			Instruction call, Address cell) {
		Address[] flows = call.getFlows();
		if (call.getFlowType().isComputed() || flows == null || flows.length != 1) {
			return CensusResult.DIRTY; // an indirect or unresolved call
		}
		Address entry = flows[0];
		if (entersUnknownBank(program, call, entry)) {
			return CensusResult.DIRTY;
		}
		// grm-mej.25: the index registers this call site provably passes in, the census's seed
		// for propagating X/Y through the closure (see calleeClosureCensus).
		Integer x = constantRegisterValue(program, call, 'X', Hooks.INERT, RegisterEnv.NONE,
			new Budget(MAX_RESOLVE_STEPS));
		Integer y = constantRegisterValue(program, call, 'Y', Hooks.INERT, RegisterEnv.NONE,
			new Budget(MAX_RESOLVE_STEPS));
		return memoizedCensus(program, listing, memo, entry, cell, x, y);
	}

	/** {@link #calleeClosureCensus} from {@code entry}, through {@code memo} when there is one. */
	private static CensusResult memoizedCensus(Program program, Listing listing, ProofMemo memo,
			Address entry, Address cell) {
		return memoizedCensus(program, listing, memo, entry, cell, null, null);
	}

	/**
	 * {@link #memoizedCensus} with the index registers known on entry ({@code null} = unknown),
	 * keyed on them too (bead grm-mej.25): {@link #calleeClosureCensus} propagates them forward
	 * through the closure.
	 */
	private static CensusResult memoizedCensus(Program program, Listing listing, ProofMemo memo,
			Address entry, Address cell, Integer x, Integer y) {
		CensusKey key = new CensusKey(entry, cell.getOffset(), x, y);
		CensusResult cached = memo == null ? null : memo.censuses.get(key);
		if (cached != null) {
			return cached;
		}
		CensusResult result = calleeClosureCensus(program, listing, entry, cell, x, y);
		if (memo != null) {
			memo.censuses.put(key, result);
		}
		return result;
	}

	/** A save helper's slot store ({@link #saveHelperStore}): the store, the callee entry, and
	 *  whether the census after the store relied on the indirect-store assumption. */
	record SaveHelperStore(Address entry, Address store, boolean indirectStoresAssumed) {}

	/**
	 * Whether {@code call}'s callee is a SAVE HELPER for {@code cell} (bead grm-mej.23): every
	 * path from its entry stores the slot exactly once, with a plain store, and nothing after
	 * that store writes it again -- so after the call returns, the slot holds what that store
	 * wrote, and the call can end a save-slot path as if the store were on it. cv3's
	 * {@code FUN_e2e0} ({@code PHA / LDA $21 / STA $22 / PLA / STA $21 / STA $5115 / RTS}) is the
	 * shape.
	 * <p>
	 * Deliberately narrow: the entry must reach the store by a STRAIGHT fall-through line (no
	 * flow, no call, no other writer of the slot, no {@link Hooks#isMechanismWrite}, at most
	 * {@link StoredValueScanner#MAX_BACKWARD_SCAN} instructions), which makes "every path stores it once" and "no
	 * bank switches between the entry and the store" both hold by construction -- the second is
	 * what lets {@link #saveSlotForwarded} resolve the store under the state AT THE CALL. What
	 * follows the store must pass the same closure census a crossed call does
	 * ({@link #calleeClosureCensus}); a loop back to the store is caught there, as the store
	 * itself is a writer. The call needs one resolved target in a known bank, as
	 * {@link #callCensus} requires. {@code null} on any failure.
	 */
	private static SaveHelperStore saveHelperStore(Program program, Listing listing, Hooks hooks,
			ProofMemo memo, Instruction call, Address cell) {
		Address[] flows = call.getFlows();
		if (call.getFlowType().isComputed() || flows == null || flows.length != 1) {
			return null;
		}
		Address entry = flows[0];
		if (entersUnknownBank(program, call, entry)) {
			return null;
		}
		Address cursor = entry;
		for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || hooks.isMechanismWrite(instr)) {
				return null;
			}
			SlotWrite write = classifySlotWrite(program, instr, cell);
			if (write == SlotWrite.STORES_SLOT) {
				Address after = instr.getFallThrough();
				if (after == null) {
					return null;
				}
				CensusResult rest = memoizedCensus(program, listing, memo, after, cell);
				return rest.clean()
						? new SaveHelperStore(entry, instr.getMinAddress(),
							rest.indirectStoresAssumed())
						: null;
			}
			if (write != SlotWrite.NONE) {
				return null;
			}
			ghidra.program.model.symbol.FlowType ft = instr.getFlowType();
			Address next = instr.getFallThrough();
			if (!ft.isFallthrough() || ft.isCall() || instr.getFlows().length > 0 ||
				next == null) {
				return null;
			}
			cursor = next;
		}
		return null;
	}

	/**
	 * Every instruction reachable from {@code entry} -- following fall-through, branches, jumps
	 * and calls TRANSITIVELY, instruction by instruction rather than through Ghidra's function
	 * bodies (which can be wrong) -- is checked with {@link StoredValueScanner#classifySlotWrite}. DIRTY (abandon)
	 * when any of them may write {@code cell}, or the closure cannot be fully resolved: a computed
	 * jump or call ({@code JMP ($nnnn)}), a jump or call with no resolved target, an undisassembled
	 * target, a base-space target in a banked window entered from outside that bank's own image
	 * ({@link StoredValueScanner#entersUnknownBank} -- which bank runs there depends on state this census does not
	 * have; a realized overlay is one known image and is walked), a {@code BRK}, a return that looks like a push-then-return dispatch
	 * ({@link StoredValueScanner#looksLikeReturnDispatch}, whose real targets are invisible to the listing), or more
	 * than {@link #SLOT_CENSUS_INSTRUCTION_CAP} instructions. Indirect stores are stepped over
	 * under {@link SlotAssumption#INDIRECT_STORES_DO_NOT_WRITE_SLOT}, and reported.
	 * <p>
	 * <b>Index registers are propagated FORWARD through the closure</b> (bead grm-mej.25): each
	 * instruction carries the X and Y it may be reached with, starting from {@code entryX}/
	 * {@code entryY} (the crossed call's provable values, {@code null} = unknown) and merged at
	 * every join -- two different constants, or a constant and unknown, merge to unknown, and a
	 * merged address is re-visited, so a store is classified under every value that reaches it.
	 * Sound because only closure paths run between the crossed call and its return (interrupts
	 * are out of scope, as everywhere here). A callee is entered with the caller's registers; the
	 * fall-through after a call keeps a register only when {@link StoredValueScanner#calleePreserves} proves it.
	 * cv3's ec04 is the measured shape: {@code LDX #$00}, then a loop that calls the zero-page
	 * add helper e899 ({@code STA $00,X / INC $01,X}) from three sites behind loop joins, where
	 * no backward straight-line walk can see the {@code LDX}. An index the propagation does not
	 * know falls back to the state-free {@link StoredValueScanner#constantIndex}/{@link StoredValueScanner#loopIndexRange}.
	 */
	private static CensusResult calleeClosureCensus(Program program, Listing listing,
			Address entry, Address cell, Integer entryX, Integer entryY) {
		Map<Address, IndexRegs> regs = new HashMap<>();
		List<Address> work = new ArrayList<>();
		regs.put(entry, new IndexRegs(entryX, entryY));
		work.add(entry);
		boolean assumed = false;
		while (!work.isEmpty()) {
			Address at = work.remove(work.size() - 1);
			if (regs.size() > SLOT_CENSUS_INSTRUCTION_CAP) {
				return CensusResult.DIRTY;
			}
			Instruction instr = listing.getInstructionAt(at);
			if (instr == null) {
				return CensusResult.DIRTY; // undisassembled
			}
			IndexRegs in = regs.get(at);
			switch (classifySlotWrite(program, instr, cell, in)) {
				case STORES_SLOT, WRITES_SLOT, UNPLACEABLE -> {
					return CensusResult.DIRTY;
				}
				case INDIRECT_ASSUMED -> assumed = true;
				case NONE -> {
				}
			}
			String mnem = instr.getMnemonicString().toUpperCase();
			if (mnem.equals("BRK")) {
				return CensusResult.DIRTY;
			}
			if (mnem.equals("RTS") || mnem.equals("RTI")) {
				if (looksLikeReturnDispatch(listing, instr)) {
					return CensusResult.DIRTY;
				}
				continue;
			}
			ghidra.program.model.symbol.FlowType ft = instr.getFlowType();
			if (ft.isComputed()) {
				return CensusResult.DIRTY;
			}
			Address[] flows = instr.getFlows();
			if ((ft.isJump() || ft.isCall()) && (flows == null || flows.length == 0)) {
				return CensusResult.DIRTY;
			}
			// A call enters its callee with the registers it was reached with; everything else
			// passes on what it leaves behind.
			IndexRegs out = ft.isCall() ? in : in.after(instr);
			// A conditional branch whose flags are provable has one live successor (grm-uurl):
			// blmaster ebf2 BEQ after LDA #0 never falls into the palette table at ebf4.
			Boolean taken = ft.isConditional() ? knownBranchOutcome(program, instr) : null;
			if (Boolean.TRUE.equals(taken)) {
				for (Address target : flows) {
					if (entersUnknownBank(program, instr, target)) {
						return CensusResult.DIRTY;
					}
					reach(regs, work, target, out);
				}
				continue;
			}
			if (Boolean.FALSE.equals(taken)) {
				flows = null;
			}
			if (flows != null) {
				for (Address target : flows) {
					if (entersUnknownBank(program, instr, target)) {
						return CensusResult.DIRTY;
					}
					reach(regs, work, target, out);
				}
			}
			Address ft2 = instr.getFallThrough();
			if (ft2 != null) {
				reach(regs, work, ft2, ft.isCall()
						? in.afterCall(calleePreserves(program, instr, 'X'),
							calleePreserves(program, instr, 'Y'))
						: out);
			}
		}
		return new CensusResult(true, assumed);
	}

	/** Records that {@code target} is reached with {@code with}, (re)queueing it when that is new
	 *  or weakens what it was already reached with. */
	private static void reach(Map<Address, IndexRegs> regs, List<Address> work, Address target,
			IndexRegs with) {
		IndexRegs old = regs.get(target);
		IndexRegs merged = old == null ? with : old.merge(with);
		if (!merged.equals(old)) {
			regs.put(target, merged);
			work.add(target);
		}
	}

	/**
	 * The X and Y {@link #calleeClosureCensus} may reach an instruction with: a provable constant
	 * ({@code 0..255}) or {@code null} (unknown). Bead grm-mej.25.
	 */
	record IndexRegs(Integer x, Integer y) {

		static final IndexRegs UNKNOWN = new IndexRegs(null, null);

		/** Every path's value: a register both sides agree on stays, anything else is unknown. */
		IndexRegs merge(IndexRegs other) {
			return new IndexRegs(java.util.Objects.equals(x, other.x) ? x : null,
				java.util.Objects.equals(y, other.y) ? y : null);
		}

		/** After a call: a register survives only when the callee provably preserves it. */
		IndexRegs afterCall(boolean keepX, boolean keepY) {
			return new IndexRegs(keepX ? x : null, keepY ? y : null);
		}

		/** The registers after the non-call {@code instr} executes. */
		IndexRegs after(Instruction instr) {
			int op;
			try {
				op = instr.getByte(0) & 0xFF;
			}
			catch (MemoryAccessException e) {
				return UNKNOWN;
			}
			Integer nx = x;
			Integer ny = y;
			switch (op) {
				case 0xA2 -> nx = immediate(instr); // LDX #imm
				case 0xA0 -> ny = immediate(instr); // LDY #imm
				case 0xE8 -> nx = x == null ? null : (x + 1) & 0xFF; // INX
				case 0xCA -> nx = x == null ? null : (x - 1) & 0xFF; // DEX
				case 0xC8 -> ny = y == null ? null : (y + 1) & 0xFF; // INY
				case 0x88 -> ny = y == null ? null : (y - 1) & 0xFF; // DEY
				default -> {
					if (writesRegister(instr, 'X')) {
						nx = null;
					}
					if (writesRegister(instr, 'Y')) {
						ny = null;
					}
				}
			}
			return new IndexRegs(nx, ny);
		}

		private static Integer immediate(Instruction instr) {
			try {
				return instr.getByte(1) & 0xFF;
			}
			catch (MemoryAccessException e) {
				return null;
			}
		}

		/** By mnemonic (LDX/TAX/TSX/PLX, LAX and kin) and by Ghidra's own result objects, so an
		 *  instruction either one says writes the register makes it unknown. */
		private static boolean writesRegister(Instruction instr, char reg) {
			String m = instr.getMnemonicString().toUpperCase();
			boolean byName = reg == 'X'
					? Set.of("LDX", "TAX", "TSX", "PLX", "INX", "DEX", "LAX", "LAS", "SBX", "AXS")
							.contains(m)
					: Set.of("LDY", "TAY", "PLY", "INY", "DEY").contains(m);
			if (byName) {
				return true;
			}
			for (Object o : instr.getResultObjects()) {
				if (o instanceof Register r &&
					r.getName().equalsIgnoreCase(String.valueOf(reg))) {
					return true;
				}
			}
			return false;
		}
	}
}
