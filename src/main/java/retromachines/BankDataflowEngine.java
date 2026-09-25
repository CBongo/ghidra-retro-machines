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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static retromachines.HelperArgumentRecovery.recoverCallArgument;
import static retromachines.HelperDiscovery.calledHelper;
import static retromachines.HelperDiscovery.helperLabel;

import retromachines.BankStrategyRegistry.ConfiguredMechanism;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.ComputedWindowModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.ModeWindowModel;
import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.CallSiteRegKey;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * The forward bank-state dataflow engine: one fixpoint run over a program's instructions,
 * folding each recognized bank-switch site's effect and (when a helper map is supplied)
 * each helper call's effect, returning the per-address in-state plus the resolved switch
 * and call-switch sites as a {@link DataflowResult} for the annotation/mutation adapter to
 * consume.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Dataflow" section without behavior
 * change (bead grm-ft8 increment 3a, from QR-12's "dataflow engine returning facts" step, split
 * from the much larger "Helper-call propagation" section that was itself extracted, three ways,
 * by bead grm-shnf, QR-12 increment 3b). One holder, not several files, following
 * {@link BoardDescriptorModel}, {@link BankStrategyRegistry} and {@link BankAnnotationAdapter}'s
 * precedent in this package.
 *
 * <p>{@link #mergeAndEnqueue} and {@link #clampToResidence} needed no receiver at all: an
 * instance-state survey of the section found zero {@code this.} references and zero instance
 * fields on {@code BoardBankAnalyzer}, so both became {@code static} outright, staying
 * {@code private} since nothing outside this class calls them. {@link #runDataflow} calls
 * {@code calledHelper} and {@code recoverCallArgument}, which grm-shnf moved to
 * {@link HelperDiscovery} and {@link HelperArgumentRecovery} respectively -- both were already
 * {@code static} as of that bead's step 2, so {@code runDataflow} needed no threaded receiver to
 * reach them even before the move (the leading {@code BoardBankAnalyzer analyzer} parameter it
 * carried under increment 3a was already gone), and neither does {@link BankAnnotationAdapter}'s
 * {@code helperArgumentCallSites}, which calls {@code calledHelper} the same way.
 * {@code calledHelper} and {@code helperLabel} are referenced here via {@code import static} from
 * {@link HelperDiscovery}; {@code recoverCallArgument} the same way from
 * {@link HelperArgumentRecovery} -- none of the three needs a receiver.
 * {@link #position} and {@link #overwrite} are needed the OTHER way too: helper-propagation code
 * in both split-out classes ({@code composeWithCallee} in {@link HelperDiscovery},
 * {@code recoverCallArgument}'s own body in {@link HelperArgumentRecovery}) calls them, so both
 * were widened from {@code private} to package-private {@code static} here and are referenced
 * back from those classes via {@code import static} so those call sites stay byte-unchanged --
 * the mirror image of {@code toFieldLocal}/{@code reachableEntries} below. {@code CallEffect}, a
 * record {@code runDataflow} constructs and holds directly, moved to {@link HelperArgumentRecovery}
 * with the rest of grm-shnf's step 3 (helper-propagation code there also constructs it) and is
 * referenced here via {@code import retromachines.HelperArgumentRecovery.CallEffect}.
 * {@code CallSwitch}, {@code DataflowResult} and {@code SwitchResult} moved to this class outright
 * (bead grm-shnf step 1): all three were already package-private as of increment 4, so the move
 * needed no visibility change, and {@code BoardBankAnalyzer}'s own harness method now reaches them
 * via {@code import retromachines.BankDataflowEngine.<Name>} instead. {@code MatchInfo} moved here
 * unchanged (still {@code private}, nested in this
 * class instead) because {@code runDataflow} is its sole consumer. {@code toFieldLocal} is a
 * static helper referenced by {@link BankAnnotationAdapter} via {@code import static}; that
 * import now targets this class instead of {@code BoardBankAnalyzer}. {@code clampToResidence}
 * calls back into {@code BankAnnotationAdapter.findModeWindowInstance(...)} (already qualified,
 * already {@code static}) -- the one place this section is called INTO from the annotation side,
 * documented on {@link BankAnnotationAdapter} as well.
 * <p>
 * <b>Bead grm-wul (2026-09-19) made the state at an address a bounded set of whole states, one
 * per path, and added demand-driven PATH FORKING at merge sites</b> -- see the 8-argument
 * {@link #runDataflow}'s javadoc for the model, {@link #joinArms}/{@link #evaluateArms} for how
 * a site's arms are enumerated and evaluated, {@link #mergeAndEnqueue} for the live cap, and
 * {@link ForkBudget} for the two caps and the per-program ledger.
 */
final class BankDataflowEngine {

	private BankDataflowEngine() {
	}


	// ------------------------------------------------------------------
	// Path-fork budget (bead grm-wul)
	// ------------------------------------------------------------------

	/**
	 * Live forks one address may hold: the number of distinct {@link PathId}s in its state set.
	 * Exceeding it collapses that address to today's single field-wise merge, permanently (see
	 * {@link #mergeAndEnqueue}). Configurable constant for now; an analyzer option later if the
	 * real-ROM tally justifies one (the owner's ruling on grm-wul).
	 */
	static final int MAX_LIVE_FORKS_PER_BLOCK = 4;

	/**
	 * Forks one function may create in total -- arms summed over its forking sites. A site whose
	 * arms would push its function past this is denied and recorded
	 * {@link BankSwitchStrategy.ValueStop#MULTI_VALUED_AT_MERGE}, naming the arms it found.
	 */
	static final int MAX_FORKS_PER_FUNCTION = 16;

	/**
	 * The most arms one site's enumeration may inspect, nested joins included. A join wider than
	 * this is not enumerated at all -- no claim is made about it, so the site keeps the stop the
	 * strategy gave it rather than a {@code MULTI_VALUED_AT_MERGE} the engine never verified.
	 */
	private static final int MAX_ARMS_SCANNED = 8;

	/** How many nested joins an arm enumeration may descend through before declining. */
	private static final int MAX_ARM_DEPTH = 2;

	/**
	 * Instructions walked back from a site (or an arm's predecessor) looking for the join heading
	 * its block. Matches {@code StoredValueScanner.MAX_BACKWARD_SCAN}: a join the value scan could
	 * never have reached is not worth enumerating.
	 */
	private static final int MAX_HEAD_WALK = 16;

	// ------------------------------------------------------------------
	// Dataflow
	// ------------------------------------------------------------------

	/**
	 * One forward-dataflow run to fixpoint. When {@code helpers} is non-null, a call to
	 * a helper function is itself a switch site: the state on the call's fall-through is
	 * the helper's effect, not the flowed-through in-state (the call target's entry is
	 * still seeded with the in-state -- the switch happens inside the helper).
	 */
	static DataflowResult runDataflow(Program program, TaskMonitor monitor, Listing listing,
			List<ConfiguredMechanism> mechanisms, BoardModel board,
			Map<Function, HelperModel> helpers, Set<Function> restoringTrampolines)
			throws CancelledException {
		return runDataflow(program, monitor, listing, mechanisms, board, helpers,
			restoringTrampolines, Set.of());
	}

	/**
	 * As the 7-argument form, with {@code secondTierRelaySites} (bead grm-ylm6): the call-site
	 * addresses {@link HelperDiscovery#findSecondTierHelpers} proved are a second-tier helper's
	 * own relay call -- the register it reads is genuinely a live argument, but one supplied by
	 * THIS FUNCTION's caller, not resolvable at this address no matter how good value recovery
	 * gets. An unresolved call at one of these addresses is reclassified via
	 * {@link HelperArgumentRecovery.CallEffect#asSecondTierRelay} so
	 * {@code BoardBankAnalyzer} can report it as an honest gap
	 * ({@link BankSwitchStrategy.ValueStop#SECOND_TIER_ARGUMENT}) instead of our limitation --
	 * see that method's javadoc. Empty for every caller but {@code BoardBankAnalyzer}'s phase-2
	 * pass, which is the only one with a helper map (and therefore relay sites) to supply; the
	 * 7-argument form above is pass 1's and every existing caller's unchanged entry point.
	 * <p>
	 * <b>The state at an address is a SET OF WHOLE STATES, keyed by path</b> (bead grm-wul,
	 * option (b) path forking under the owner's 2026-09-19 ruling). Each element is one
	 * {@link PathId} -- the fork-site/arm choices that distinguish the path -- paired with the
	 * full {@link BankState} tuple that holds along it. Elements with the SAME path id merge
	 * field-wise exactly as the single-state engine always did; elements with different ids are
	 * never merged with each other, so a bank selected on one arm stays correlated with
	 * everything derived from it downstream (the 2026-08-09 comment's {@code $8006} vs
	 * {@code $8002} table base per bank). {@link PathId#ROOT} is the ordinary, unforked path,
	 * and an unforked program has exactly one element everywhere: this engine is then the old
	 * engine, byte for byte.
	 * <p>
	 * <b>Forks are created in exactly one place: a switch site (direct, or a helper call) whose
	 * value did not resolve, whose block is headed by a control-flow join, and every one of
	 * whose arms DOES resolve.</b> {@link #joinArms} enumerates the incoming edges of that join
	 * and {@link #evaluateArms} re-asks the strategy along each (descending through a nested
	 * join up to {@link #MAX_ARM_DEPTH}) via {@link RegisterEnv#onArms}. All arms resolving to
	 * one value resolves the site outright; to several values, the in-element is REPLACED by one
	 * out-element per value, each carrying that value's effect, if the budget allows. Nothing
	 * else forks: two ordinary in-states meeting at a join still merge field-wise (an entry seeded
	 * from {@code initial_state} meeting a caller's context must not become two paths -- that
	 * seed is a heuristic, and forking on it would fabricate a bank for every function in the
	 * program).
	 * <p>
	 * <b>Forks are intraprocedural.</b> An element flowing into a function ENTRY -- a call
	 * target, or any jump to an address that is a function's entry point -- arrives as
	 * {@code ROOT}, merged field-wise with whatever else reaches that entry, which is precisely
	 * what the single-state engine gave the callee. So a fork costs at most the forking
	 * function's own body, and the per-function cap {@link #MAX_FORKS_PER_FUNCTION} describes a
	 * real bound. The forked TAIL of the function (the merged dispatch after the switch, in
	 * blmaster's c9a4) is what the fork exists for and is what it covers.
	 * <p>
	 * <b>Termination.</b> Per address, the set only ever gains path ids (never loses one) until it
	 * collapses, and each id's state only ever loses known bits; a collapse happens at most once
	 * per address and is permanent ({@code collapsedAddrs}); a site's budget decision is
	 * permanent too (granted once, forked on every later dequeue; denied once, denied forever).
	 * A path id is a MAP from fork site to value, so a fork site inside a loop re-forks an
	 * element that already carries its own choice into the SAME id, not a longer one -- the set
	 * at the loop head reaches a fixpoint rather than growing a new element per iteration. Every
	 * quantity is finite and monotone, so the worklist drains.
	 * <p>
	 * <b>A collapsed state is never more precise than the single-state engine's.</b> The collapse
	 * value at an address is the field-wise merge of every element that ever reached it, which is
	 * exactly the single-state engine's merge of the same incoming states. A DENIED site is
	 * recorded unknown with {@code MULTI_VALUED_AT_MERGE}, which is what the strategy returned
	 * before the arms were consulted, reclassified -- the value itself is untouched.
	 * <p>
	 * <b>One honest caveat on order.</b> An arm's value may depend on the in-state (a mirror
	 * load along the arm), and the in-state at a site only weakens over the fixpoint. A fork
	 * element created from an earlier, stronger in-state is never withdrawn from the addresses
	 * it reached, even if a later dequeue of the same site no longer resolves that arm. Such an
	 * element is still MAY-sound -- a known value derived from a merge of real paths holds on at
	 * least one of them -- but it is a path this engine cannot re-derive from the final state.
	 * The arm values the shipped strategies actually recover are immediates, for which the
	 * question does not arise.
	 */
	static DataflowResult runDataflow(Program program, TaskMonitor monitor, Listing listing,
			List<ConfiguredMechanism> mechanisms, BoardModel board,
			Map<Function, HelperModel> helpers, Set<Function> restoringTrampolines,
			Set<Address> secondTierRelaySites)
			throws CancelledException {

		Map<Address, LinkedHashMap<PathId, BankState>> stateIn = new HashMap<>();
		Set<Address> collapsedAddrs = new HashSet<>();
		Map<Address, SwitchResult> switchResults = new HashMap<>();
		Map<Address, CallSwitch> callSwitches = new HashMap<>();
		Deque<Address> worklist = new ArrayDeque<>();
		Map<String, int[]> clampCache = new HashMap<>();
		// Scoped to this runDataflow call (not a field): phase 1/2 separation guarantees no
		// instruction appears mid-fixpoint, so per-call scoping sidesteps any staleness
		// question. See probeSite for the soundness invariant this relies on (grm-5tl.13.2).
		Map<Address, MatchInfo> matchCache = new HashMap<>();
		// Likewise scoped to this runDataflow call: the A/X/Y a helper call site supplies
		// (grm-hum increment 2). Purely an efficiency memo -- but a necessary one: without it,
		// three backward scans plus a strategy's mini-inline would rerun on EVERY dequeue of
		// every helper call address across the whole fixpoint. Mega Man (25 switch sites, a
		// large fixpoint) is where that bites.
		//
		// UPDATED INVARIANT (bead grm-mej.3 item 4, tripwire 2) -- the paragraph this replaces
		// argued the memoized value was a function of (program, call address, HELPER MODEL)
		// alone, because "the three scans themselves remain state-independent -- they use
		// NO_HOOKS and never consult tracked state". That is no longer true: a helper whose
		// strategy overrides BankSwitchStrategy.callerSideHooks() (MemoryLatchBankSwitchStrategy,
		// for contra's c0d3 LDA $8000 at a call site) now has its caller-side scans threaded with
		// the REAL tracked in-state at the call, narrowed to that helper's mechanism's
		// field-local space, so hooks.resolveMirrorLoad can resolve a bank-mirror load there. Two
		// dequeues of the same call address under different in-states can therefore produce
		// different RegisterEnv results, and memoizing by address alone would silently serve one
		// call site's answer to another's.
		//
		// The fix is to key on (call address, in-state) rather than address alone or to drop the
		// memo -- CallSiteRegKey (HelperArgumentRecovery), constructed by recoverCallArgument
		// from the SAME localIn it narrows callSiteIn to. Re-keying was preferred over dropping
		// the cache outright: the cache exists for a real, measured performance reason (Mega Man,
		// 25 switch sites, a large fixpoint) and the helper map is still FIXED before runDataflow
		// begins (phase 1/2 separation, same invariant matchCache above relies on), so one call
		// address still dispatches to exactly one HELPER MODEL -- only the in-state half of the
		// key can vary across dequeues of the same address now. argumentSurvivesPrologue remains
		// a pure function of the listing and needs no key at all. grm-wul added the arm map to
		// the key for the same reason: a caller-side scan along one arm answers for that arm.
		Map<CallSiteRegKey, RegisterEnv> callSiteRegCache = new HashMap<>();
		// STATE DEPENDENCIES (bead grm-mej.3 increment 3): P -> the helper call sites whose
		// argument recovery consulted the tracked state AT P through a StateOracle. A
		// call-crossing PHA/PLA pairing resumes its walk from the push and resolves against the
		// state at the push, not at the call -- and the fixpoint's own propagation cannot be
		// relied on to re-evaluate the call when that state changes: in the customer shape
		// (LDA <mirror> / PHA / LDA #n / JSR helper / ... / PLA / JSR helper) both calls deposit
		// the same fields, so a change at the push is MASKED before it reaches the second call's
		// in-state. mergeAndEnqueue therefore re-enqueues P's dependents whenever P's state
		// changes. Recording happens in the oracle itself (see applyHelperCall), so an address is
		// a dependency exactly when it was asked about -- including an ask that answered null
		// because P had no state yet, which is precisely the case that must be re-asked later.
		// Termination is unaffected: a dependent is enqueued only on a change at P, and changes
		// are bounded by the same lattice that bounds every other enqueue here.
		Map<Address, Set<Address>> stateDependents = new HashMap<>();
		// The arms heading each site's block are structural -- a function of the listing and its
		// flow references, both fixed for the duration of this run -- so they are enumerated once
		// per address. An empty Optional records "not forkable here" so the walk is not repeated.
		Map<Address, Optional<List<Arm>>> armCache = new HashMap<>();
		ForkBudget budget = new ForkBudget(program);

		Set<Address> seeds = new LinkedHashSet<>();
		AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
		while (eps.hasNext()) {
			seeds.add(eps.next());
		}
		FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
		for (Function f : funcs) {
			seeds.add(f.getEntryPoint());
		}

		// Two seed states, not one. banking.initial_state is what the board powers up holding,
		// so it is sound for an entry the machine reaches from reset -- and unsound for one it
		// reaches from an interrupt, which fires from arbitrary mainline context and leaves the
		// interrupted code's bank live on entry. The loader tells us which entries those are
		// (DescriptorSupport.ASYNC_ENTRY_POINTS_PROPERTY); this stays machine-independent and
		// merely consumes the list. Bead grm-913.
		BankState seedState = BankState.fullyKnown(board.mask(), board.initialState());
		Set<Address> asyncEntries = DescriptorSupport.parseAsyncEntryPoints(program);
		for (Address seed : seeds) {
			BankState entryState = asyncEntries.contains(seed) ? BankState.unknown() : seedState;
			mergeAndEnqueue(seed, PathId.ROOT, entryState, stateIn, collapsedAddrs, worklist,
				listing, board, clampCache, budget, stateDependents);
		}

		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Address addr = worklist.poll();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			// Every element at this address is re-processed on every dequeue: the set is small
			// (at most MAX_LIVE_FORKS_PER_BLOCK) and a per-element dirty flag would buy little
			// while adding a second thing that has to be right. Snapshot, because a self-loop's
			// mergeAndEnqueue may mutate the live map underneath.
			List<Map.Entry<PathId, BankState>> elements =
				new ArrayList<>(stateIn.get(addr).entrySet());
			SiteTally site = new SiteTally();
			CallTally call = new CallTally();
			List<OutElement> outs = new ArrayList<>();

			for (Map.Entry<PathId, BankState> element : elements) {
				PathId pathId = element.getKey();
				BankState inState = element.getValue();

				Probe probe = probeSite(program, instr, inState, mechanisms, matchCache,
					RegisterEnv.NONE);
				ConfiguredMechanism matchedMechanism = probe.mechanism();
				// The strategy's answer now carries WHY an unrecovered value did not resolve (bead
				// grm-3ou part 1). It rides the existing match cache unchanged: the stop reason is
				// a property of the very recovery that produced the value, so anything already
				// safe to cache as a value is safe to cache with its reason attached.
				BankSwitchStrategy.SwitchOutcome switchedLocal = probe.outcome();

				// Out-elements for THIS in-element: one, or one per arm value when the site forks.
				List<OutElement> mine = new ArrayList<>();
				if (switchedLocal != null) {
					int lsb = matchedMechanism.lsb();
					int effectMask = matchedMechanism.effectMask();
					List<BankState> forkValues = null;
					List<BankState> deniedValues = null;
					if (unresolvedOurs(switchedLocal)) {
						// grm-wul: the site did not resolve and blamed us. Ask along each arm of
						// the join heading its block, if there is one.
						List<Arm> arms = armsFor(program, listing, instr, armCache);
						List<BankState> perArm = arms == null ? null
								: evaluateArms(program, listing, arms, env -> {
									Probe along = probeSite(program, instr, inState, mechanisms,
										matchCache, env);
									return along.outcome() == null ? null : along.outcome().value();
								}, 1);
						if (perArm != null) {
							List<BankState> values = distinct(perArm);
							if (values.size() == 1) {
								// Every arm agrees: the site resolves to that one value outright.
								// Not a fork -- nothing to budget, nothing to carry separately.
								switchedLocal = new BankSwitchStrategy.SwitchOutcome(values.get(0),
									BankSwitchStrategy.ValueStop.RESOLVED);
								budget.resolvedThroughArms++;
							}
							else if (budget.grant(addr, values, lsb, effectMask)) {
								forkValues = values;
							}
							else {
								deniedValues = values;
								switchedLocal = new BankSwitchStrategy.SwitchOutcome(
									BankState.unknown(),
									BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE);
							}
						}
					}
					if (forkValues != null) {
						// FORK: this in-element becomes one out-element per distinct arm value,
						// each with that value's positioned effect folded in on the mechanism's
						// own bits, exactly as a resolved single value is below.
						List<BankState> positionedArms = new ArrayList<>();
						for (BankState armLocal : forkValues) {
							BankState positioned = position(armLocal, lsb, effectMask);
							positionedArms.add(positioned);
							site.add(positioned, BankSwitchStrategy.ValueStop.RESOLVED);
							BankState out = overwrite(inState, positioned, effectMask);
							mine.add(new OutElement(pathId.with(addr, positioned), out, out));
						}
						site.arms(positionedArms, false);
					}
					else {
						// Fold: this mechanism's switch REPLACES only the bits it owns
						// (effectMask), preserving whatever the rest of the tracked state already
						// knew about other mechanisms' fields. For a single-mechanism board
						// effectMask covers every tracked bit, so this reduces exactly to the old
						// whole-state replace.
						BankState positionedEffect = position(switchedLocal.value(), lsb, effectMask);
						BankSwitchStrategy.ValueStop stop = deniedValues != null
								? BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE
								: classifyGap(program, instr, inState, matchedMechanism,
									switchedLocal, helpers);
						// grm-rd6h: classifyGap only ever reclassifies an ANALYZER_LIMIT (see its
						// javadoc), so a RESTORED_BANK stop and its ReadBack always survive intact
						// -- the guard below is defensive, not load-bearing.
						site.add(positionedEffect, stop,
							stop == BankSwitchStrategy.ValueStop.RESTORED_BANK
									? switchedLocal.readBack() : null);
						if (deniedValues != null) {
							site.arms(deniedValues.stream()
									.map(v -> position(v, lsb, effectMask))
									.toList(), true);
						}
						BankState out = overwrite(inState, positionedEffect, effectMask);
						mine.add(new OutElement(pathId, out, out));
					}
					site.mechanism(matchedMechanism);
				}
				else {
					mine.add(new OutElement(pathId, inState, inState));
				}

				// isCall() is also what keeps a BRK-derived IRQ/vector reference out of this whole
				// mechanism (bead grm-htgl): BRK's p-code is "goto [*:2 target]", an indirect
				// JUMP, never a call, in both this repo's own 6510 sinc and Ghidra's own stock
				// 6502.slaspec (the language every NES board actually loads with) -- verified in
				// BrkIsNotACallSiteProgramTest. So a routine an IRQ/BRK vector reaches (megaman2's
				// RESET happens to be one, since its IRQ vector aliases its RESET vector) can
				// never pick up a spurious "call site" here no matter how much of the image is
				// misdisassembled data decoding as $00 (= BRK): FlowType is fixed at disassembly
				// from the instruction's own p-code template, and no later analysis pass promotes
				// a COMPUTED_JUMP to a CALL. No additional filtering (e.g. cross-referencing
				// DescriptorSupport.ASYNC_ENTRY_POINTS_PROPERTY) is needed on top of this gate.
				if (helpers != null && instr.getFlowType().isCall()) {
					HelperModel helper = calledHelper(program, instr, helpers);
					if (helper != null) {
						// A store is never a call, so `mine` holds exactly one element here, and
						// its out-state is the in-state.
						mine = applyHelperCall(program, instr, helper, pathId, mine.get(0).out(),
							callSiteRegCache, restoringTrampolines, secondTierRelaySites, listing,
							armCache, budget, call, stateIn, stateDependents);
					}
				}
				outs.addAll(mine);
			}

			if (site.seen()) {
				switchResults.put(addr, site.result());
			}
			if (call.seen()) {
				callSwitches.put(addr, call.result());
			}

			boolean isCall = instr.getFlowType().isCall();
			for (OutElement out : outs) {
				for (Address flowAddr : instr.getFlows()) {
					// A fork ends at a function entry: a call target, or a jump onto an entry
					// point (a tail call). The callee sees the merged ROOT state, exactly as
					// the single-state engine gave it.
					PathId to = isCall || budget.isFunctionEntry(flowAddr) ? PathId.ROOT
							: out.pathId();
					mergeAndEnqueue(flowAddr, to, out.out(), stateIn, collapsedAddrs, worklist,
						listing, board, clampCache, budget, stateDependents);
				}
				Address fallThrough = instr.getFallThrough();
				if (fallThrough != null) {
					PathId to = budget.isFunctionEntry(fallThrough) ? PathId.ROOT : out.pathId();
					mergeAndEnqueue(fallThrough, to, out.fall(), stateIn, collapsedAddrs,
						worklist, listing, board, clampCache, budget, stateDependents);
				}
			}
		}

		// The single-state view every existing consumer reads: per address, the field-wise
		// merge of its elements -- what the old engine would have held, or better where a fork
		// resolved something it could not. The per-element view rides alongside for the one
		// consumer that can use it (reference retargeting, which places one reference per
		// distinct state).
		Map<Address, BankState> merged = new HashMap<>();
		Map<Address, List<BankState>> forkedStates = new HashMap<>();
		for (Map.Entry<Address, LinkedHashMap<PathId, BankState>> e : stateIn.entrySet()) {
			BankState acc = null;
			for (BankState s : e.getValue().values()) {
				acc = acc == null ? s : BankState.merge(acc, s);
			}
			merged.put(e.getKey(), acc);
			if (e.getValue().size() > 1) {
				forkedStates.put(e.getKey(), distinct(new ArrayList<>(e.getValue().values())));
			}
		}
		return new DataflowResult(merged, switchResults, callSwitches, forkedStates,
			budget.stats());
	}

	/**
	 * The helper-call half of one element's transfer (grm-hum increment 2 and successors; split
	 * out of the main loop by grm-wul so the fork machinery reads the same for a call as for a
	 * direct site). {@code outState} is the state after the call instruction's own effect (the
	 * in-state: a call is never a store). Returns the out-element(s) for the call's fall-through:
	 * one, or one per distinct arm effect when the argument resolved only along the arms of the
	 * join heading this block.
	 */
	private static List<OutElement> applyHelperCall(Program program, Instruction instr,
			HelperModel helper, PathId pathId, BankState outState,
			Map<CallSiteRegKey, RegisterEnv> callSiteRegCache, Set<Function> restoringTrampolines,
			Set<Address> secondTierRelaySites, Listing listing,
			Map<Address, Optional<List<Arm>>> armCache, ForkBudget budget, CallTally call,
			Map<Address, LinkedHashMap<PathId, BankState>> stateIn,
			Map<Address, Set<Address>> stateDependents) {
		Address addr = instr.getMinAddress();
		// The recording StateOracle for THIS call (grm-mej.3 increment 3): answers the merged
		// state at any instruction and records the ask as a dependency edge P -> addr, so a later
		// change at P re-enqueues this call (see stateDependents' declaration). The MERGE over
		// P's path elements is deliberate -- the query is asked on behalf of one element at addr,
		// but attributing a single element at P to it would need the path identity to survive
		// the pairing walk, and a merge can only lose knowledge, never invent it.
		StateOracle oracle = p -> {
			stateDependents.computeIfAbsent(p, k -> new LinkedHashSet<>()).add(addr);
			LinkedHashMap<PathId, BankState> elements = stateIn.get(p);
			if (elements == null || elements.isEmpty()) {
				return null;
			}
			BankState acc = null;
			for (BankState st : elements.values()) {
				acc = acc == null ? st : BankState.merge(acc, st);
			}
			return acc;
		};
		CallEffect callEffect = helper.constState() != null
				? new CallEffect(helper.constState(), helper.effectMask())
				: recoverCallArgument(program, instr, helper, outState, callSiteRegCache,
					restoringTrampolines, RegisterEnv.NONE, oracle);
		List<CallEffect> forkEffects = null;
		boolean denied = false;
		// grm-wul, the call-site twin of the direct case: the caller's argument did not resolve
		// at this call and nothing says the failure is honest (a second-tier relay, a provably
		// argument-less helper, a restore entry). Ask along each arm of the join heading the
		// block. Every arm must resolve, and each arm's whole CallEffect is what the fork
		// carries -- the deposit is the strategy's, computed along that arm, never a value the
		// engine invented.
		if (helper.constState() == null && !callEffect.argumentResolved() &&
			callEffect.ownedMask() != 0 && !secondTierRelaySites.contains(addr) &&
			!callEffect.noInboundArgument() && callEffect.restoredFrom() == null) {
			List<Arm> arms = armsFor(program, listing, instr, armCache);
			if (arms != null) {
				List<CallEffect> perArm = new ArrayList<>();
				List<BankState> perArmValue = evaluateArms(program, listing, arms, env -> {
					CallEffect along = recoverCallArgument(program, instr, helper, outState,
						callSiteRegCache, restoringTrampolines, env, oracle);
					if (!along.argumentResolved()) {
						return null;
					}
					perArm.add(along);
					return along.state();
				}, 1);
				if (perArmValue != null) {
					List<CallEffect> values = new ArrayList<>();
					for (CallEffect ce : perArm) {
						if (values.stream().noneMatch(d -> d.state().equals(ce.state()) &&
							d.ownedMask() == ce.ownedMask())) {
							values.add(ce);
						}
					}
					values.sort((a, b) -> a.state().bits() != b.state().bits()
							? Integer.compare(a.state().bits(), b.state().bits())
							: Integer.compare(a.state().knownMask(), b.state().knownMask()));
					if (values.size() == 1) {
						callEffect = values.get(0);
						budget.resolvedThroughArms++;
					}
					else if (budget.grant(addr, values.stream().map(CallEffect::state).toList(),
						0, helper.effectMask())) {
						forkEffects = values;
					}
					else {
						denied = true;
						call.arms(values.stream().map(CallEffect::state).toList(), true);
					}
				}
			}
		}
		// bead grm-ylm6: an unresolved call at a known second-tier relay site is an
		// HONEST gap, not our limitation -- reclassified here, after recoverCallArgument
		// returns, rather than inside it: the relay-site set is a whole-program fact
		// HelperDiscovery derives once, and threading it into recoverCallArgument's own
		// several return points would duplicate what one check at this single call site
		// already covers. See CallEffect#asSecondTierRelay and ValueStop
		// #SECOND_TIER_ARGUMENT.
		if (!callEffect.argumentResolved() && secondTierRelaySites.contains(addr)) {
			callEffect = callEffect.asSecondTierRelay();
		}
		List<OutElement> outs = new ArrayList<>();
		// ownedMask == 0 means this call site is a verified no-op on every tracked
		// bit -- a serial-shift helper whose switch site targets an unconfigured CHR
		// register, or (grm-mej.3) a save/restore trampoline proved to put the entry
		// bank back before returning -- so skip both the fold (a no-op regardless, since
		// callEffect.state()'s knownMask is always a subset of ownedMask by
		// construction) and the annotation, so a provably-inert call gets neither a
		// misleading "bank -> ?" comment nor a spurious WARNING bookmark.
		if (callEffect.ownedMask() == 0) {
			outs.add(new OutElement(pathId, outState, outState));
			return outs;
		}
		// The annotation state echoes the in-state only within the helper's own
		// mechanism window -- see CallSwitch's javadoc.
		BankState mechIn = new BankState(outState.knownMask() & helper.effectMask(),
			outState.bits() & helper.effectMask());
		String label = helperLabel(program, helper);
		if (forkEffects != null) {
			List<BankState> afters = new ArrayList<>();
			for (CallEffect arm : forkEffects) {
				BankState fall = overwrite(outState, arm.state(), arm.ownedMask());
				BankState after = overwrite(mechIn, arm.state(), arm.ownedMask());
				afters.add(after);
				outs.add(new OutElement(pathId.with(addr, arm.state()), outState, fall));
				call.add(label, arm.state(), after, true, false, false, null, null);
			}
			call.arms(afters, false);
			return outs;
		}
		BankState fallState = overwrite(outState, callEffect.state(), callEffect.ownedMask());
		outs.add(new OutElement(pathId, outState, fallState));
		call.add(label, callEffect.state(),
			overwrite(mechIn, callEffect.state(), callEffect.ownedMask()),
			callEffect.argumentResolved(), callEffect.noInboundArgument(),
			callEffect.secondTierRelay(), callEffect.restoreCell(), callEffect.readBack());
		return outs;
	}

	/** A strategy's answer for one address: which mechanism matched (null: none) and what it said. */
	private record Probe(ConfiguredMechanism mechanism, BankSwitchStrategy.SwitchOutcome outcome) {}

	/**
	 * The strategy probe for one address under one in-state, memoized per address across
	 * dequeues (grm-5tl.13.2). Both shipped strategies gate computeSwitch on an
	 * instruction-only predicate (MemoryLatch's writesInRange, RegisterWrite's writesMechanism)
	 * that fully determines whether the result is null -- neither ever returns null for an
	 * instruction its predicate accepts, so "which mechanism matches this address" (if any) does
	 * not depend on inState, only the *value* a non-cacheable match produces does. That lets us
	 * cache the matched mechanism's identity per address across dequeues and, on a cache hit,
	 * either reuse a cacheable strategy's state-independent result outright or re-probe only the
	 * one non-cacheable strategy that matched -- never the others, and never re-run the whole
	 * ordered loop. A future strategy whose match/no-match outcome genuinely depends on inState
	 * would violate this; the fallback (treat an unexpected null from the cached strategy as
	 * no-match for this dequeue, rather than re-probing every strategy) stays conservative in
	 * that case instead of unsound.
	 * <p>
	 * Every strategy computes in its mechanism's field-local [0, width) coordinate space, never
	 * the board's absolute state bits: the in-state handed to computeSwitch is narrowed to that
	 * mechanism's effectMask/lsb, and a non-null result is positioned back into absolute bits
	 * before it touches stateIn.
	 * <p>
	 * An ARM query ({@code env.hasArms()}, grm-wul) never reads or writes the cached RESULT --
	 * it is a claim about one arm, not about the site -- but it does reuse the cached mechanism
	 * identity, since which mechanism matches is a property of the instruction alone. The plain
	 * probe always runs first at an address (the main loop asks it before any arm), so an arm
	 * query never finds the cache cold.
	 */
	private static Probe probeSite(Program program, Instruction instr, BankState inState,
			List<ConfiguredMechanism> mechanisms, Map<Address, MatchInfo> matchCache,
			RegisterEnv env) {
		Address addr = instr.getMinAddress();
		MatchInfo cached = matchCache.get(addr);
		if (cached == null) {
			ConfiguredMechanism matched = null;
			BankSwitchStrategy.SwitchOutcome result = null;
			for (ConfiguredMechanism cm : mechanisms) {
				BankState localIn = toFieldLocal(inState, cm.lsb(), cm.effectMask());
				result = cm.strategy().computeSwitchOutcome(program, instr, localIn, env);
				if (result != null) {
					matched = cm;
					break;
				}
			}
			if (env.hasArms()) {
				// never cache an arm's answer (see javadoc)
				return new Probe(matched, matched == null ? null : result);
			}
			matchCache.put(addr, new MatchInfo(matched,
				matched != null && matched.strategy().cacheable() ? result : null));
			return new Probe(matched, matched == null ? null : result);
		}
		if (cached.mechanism() == null) {
			// no strategy's instruction-level predicate matches this address at all
			return new Probe(null, null);
		}
		if (!env.hasArms() && cached.result() != null) {
			// cacheable strategy matched before; its result here is state-independent
			return new Probe(cached.mechanism(), cached.result());
		}
		// non-cacheable strategy matched before (or this is an arm query); only it can match
		// here, re-probe it alone with the current in-state along the requested path
		ConfiguredMechanism mech = cached.mechanism();
		BankState localIn = toFieldLocal(inState, mech.lsb(), mech.effectMask());
		return new Probe(mech, mech.strategy().computeSwitchOutcome(program, instr, localIn, env));
	}

	/** Whether a strategy's answer is a wholly unrecovered value that it called OUR limitation. */
	private static boolean unresolvedOurs(BankSwitchStrategy.SwitchOutcome outcome) {
		return outcome.value().knownMask() == 0 &&
			outcome.stop() == BankSwitchStrategy.ValueStop.ANALYZER_LIMIT;
	}

	/**
	 * {@code states} with duplicates removed, in CANONICAL order: by value bits, then by known
	 * mask. The arms arrive in edge order (fall-through first, then references), which is an
	 * accident of layout; a comment that reads {@code 1 | 2} and a primary reference that goes
	 * to the lower bank regardless of which arm happened to fall through are what a reader and
	 * a golden want.
	 */
	private static List<BankState> distinct(List<BankState> states) {
		List<BankState> out = new ArrayList<>();
		for (BankState s : states) {
			if (!out.contains(s)) {
				out.add(s);
			}
		}
		out.sort((a, b) -> a.bits() != b.bits() ? Integer.compare(a.bits(), b.bits())
				: Integer.compare(a.knownMask(), b.knownMask()));
		return out;
	}

	// ------------------------------------------------------------------
	// Arm enumeration (bead grm-wul)
	// ------------------------------------------------------------------

	/**
	 * One arm of a join: {@code preds} is the {@code join -> predecessor} map a scan along it
	 * follows ({@link RegisterEnv#onArms}); {@code tip} is the predecessor this arm was most
	 * recently extended with -- the instruction a nested enumeration walks back from.
	 */
	private record Arm(Map<Address, Address> preds, Address tip) {}

	/**
	 * The arms of the control-flow join heading {@code instr}'s block, memoized per address;
	 * {@code null} when the block is not headed by a forkable join (see {@link #joinArms}).
	 */
	private static List<Arm> armsFor(Program program, Listing listing, Instruction instr,
			Map<Address, Optional<List<Arm>>> armCache) {
		return armCache.computeIfAbsent(instr.getMinAddress(),
			a -> Optional.ofNullable(joinArms(program, listing, instr, Map.of()))).orElse(null);
	}

	/**
	 * Walks back from {@code from} along the path {@code base} describes to the instruction the
	 * value scan would have stopped at, and, if that instruction is a control-flow join with at
	 * least two enumerable predecessors, returns one arm per predecessor: {@code base} extended
	 * with {@code join -> predecessor}. {@code null} otherwise.
	 * <p>
	 * A join is FORKABLE only when every incoming edge is a known intraprocedural jump, branch or
	 * fall-through from a disassembled instruction in the same function as the join, and the join
	 * is not a function entry point. A CALL reference means the block is entered by callers, whose
	 * context is not an arm; an edge from another function, or from an undisassembled address,
	 * means the walk could not soundly continue along it. A block start with a SINGLE known
	 * predecessor is deliberately not enumerated: the value scan refuses such a boundary today
	 * for its linkage rule, not the join rule, and lifting that is a separate question from this
	 * bead's (a two-armed merge). Unresolved computed jumps leave no reference and are invisible
	 * here, exactly as they are to {@code StoredValueScanner.isControlFlowJoin} and to this
	 * engine's own forward flow -- the same closed-world assumption, applied consistently.
	 */
	private static List<Arm> joinArms(Program program, Listing listing, Instruction from,
			Map<Address, Address> base) {
		RegisterEnv env = RegisterEnv.onArms(base);
		Instruction cur = from;
		Instruction head = null;
		for (int i = 0; i < MAX_HEAD_WALK; i++) {
			Instruction prev = StoredValueScanner.pathPredecessor(program, listing, cur, env);
			if (prev == null) {
				head = cur;
				break;
			}
			cur = prev;
		}
		if (head == null || base.containsKey(head.getMinAddress())) {
			return null; // no block head within reach, or a join this path already chose at
		}
		Address headAddr = head.getMinAddress();
		FunctionManager fm = program.getFunctionManager();
		if (fm.getFunctionAt(headAddr) != null) {
			return null; // entered by callers, not arms
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
				return null;
			}
			Address fromAddr = ref.getFromAddress();
			if (preds.contains(fromAddr)) {
				continue; // a branch whose target is also its own fall-through
			}
			if (listing.getInstructionAt(fromAddr) == null ||
				fm.getFunctionContaining(fromAddr) != scope) {
				return null;
			}
			preds.add(fromAddr);
		}
		if (preds.size() < 2) {
			return null;
		}
		List<Arm> arms = new ArrayList<>();
		for (Address pred : preds) {
			Map<Address, Address> extended = new TreeMap<>(base);
			extended.put(headAddr, pred);
			arms.add(new Arm(extended, pred));
		}
		return arms;
	}

	/**
	 * Evaluates {@code eval} along every arm in {@code arms}, descending through a nested join
	 * (up to {@link #MAX_ARM_DEPTH}) when an arm does not resolve on its own, and returns one
	 * value per leaf arm -- or {@code null} the moment ANY arm fails to resolve, or the arm
	 * count exceeds {@link #MAX_ARMS_SCANNED}. All-or-nothing on purpose: a fork that carried
	 * three resolved arms and dropped a fourth would assert the site takes only those three
	 * values, which is the fabrication this whole mechanism must never commit.
	 */
	private static List<BankState> evaluateArms(Program program, Listing listing, List<Arm> arms,
			java.util.function.Function<RegisterEnv, BankState> eval, int depth) {
		if (arms.size() > MAX_ARMS_SCANNED) {
			return null;
		}
		List<BankState> values = new ArrayList<>();
		for (Arm arm : arms) {
			BankState value = eval.apply(RegisterEnv.onArms(arm.preds()));
			if (value != null && value.knownMask() != 0) {
				values.add(value);
				continue;
			}
			if (depth >= MAX_ARM_DEPTH) {
				return null;
			}
			// The arm's own block may be headed by another join: descend along it, from the
			// arm's tip (the last instruction on this arm before the join).
			Instruction tip = listing.getInstructionAt(arm.tip());
			List<Arm> nested = tip == null ? null : joinArms(program, listing, tip, arm.preds());
			if (nested == null) {
				return null;
			}
			List<BankState> below = evaluateArms(program, listing, nested, eval, depth + 1);
			if (below == null) {
				return null;
			}
			values.addAll(below);
			if (values.size() > MAX_ARMS_SCANNED) {
				return null;
			}
		}
		return values;
	}

	// ------------------------------------------------------------------
	// Fork state (bead grm-wul)
	// ------------------------------------------------------------------

	/**
	 * One element's identity in an address's state set: the fork sites this path has passed
	 * through and the value each selected there. {@link #ROOT} (no choices) is the ordinary,
	 * unforked path. A map, not a sequence: re-passing a fork site REPLACES that site's choice,
	 * which is what bounds the id space and lets a fork inside a loop converge.
	 */
	record PathId(List<Fork> forks) {

		/** One choice on a path: the value {@code site} selected. */
		record Fork(Address site, BankState value) {}

		static final PathId ROOT = new PathId(List.of());

		/** This path with {@code site}'s choice set to {@code value}, replacing any earlier one. */
		PathId with(Address site, BankState value) {
			List<Fork> next = new ArrayList<>();
			boolean placed = false;
			for (Fork f : forks) {
				if (f.site().equals(site)) {
					continue;
				}
				if (!placed && f.site().compareTo(site) > 0) {
					next.add(new Fork(site, value));
					placed = true;
				}
				next.add(f);
			}
			if (!placed) {
				next.add(new Fork(site, value));
			}
			return new PathId(List.copyOf(next));
		}

		@Override
		public String toString() {
			if (forks.isEmpty()) {
				return "root";
			}
			StringBuilder sb = new StringBuilder();
			for (Fork f : forks) {
				if (sb.length() > 0) {
					sb.append(',');
				}
				sb.append(f.site()).append("=0x").append(Integer.toHexString(f.value().bits()));
			}
			return sb.toString();
		}
	}

	/** One element leaving an instruction: its path, its state on every flow, and on the fall-through. */
	private record OutElement(PathId pathId, BankState out, BankState fall) {}

	/**
	 * The per-run fork ledger: the two caps, what each site was granted or denied, every collapse,
	 * and the counters the per-program summary line reports (bead grm-wul). Decisions are sticky
	 * -- see {@code runDataflow}'s termination argument.
	 */
	private static final class ForkBudget {

		private final FunctionManager fm;
		private final Map<Function, Integer> perFunction = new HashMap<>();
		private final Map<Address, Integer> granted = new HashMap<>();
		private final Set<Address> denied = new HashSet<>();
		private final Map<Address, Boolean> entryCache = new HashMap<>();
		private final List<String> log = new ArrayList<>();
		int forksCreated;
		int forksDenied;
		int addressCollapses;
		int maxLive = 1;
		Address maxLiveAt;
		int resolvedThroughArms;

		ForkBudget(Program program) {
			this.fm = program.getFunctionManager();
		}

		boolean isFunctionEntry(Address addr) {
			return entryCache.computeIfAbsent(addr, a -> fm.getFunctionAt(a) != null);
		}

		/**
		 * Whether {@code site} may fork into {@code values.size()} elements. Sticky: the first
		 * answer for a site is its answer forever. {@code lsb}/{@code effectMask} only render the
		 * values for the log.
		 */
		boolean grant(Address site, List<BankState> values, int lsb, int effectMask) {
			if (granted.containsKey(site)) {
				return true;
			}
			if (denied.contains(site)) {
				return false;
			}
			int k = values.size();
			Function f = fm.getFunctionContaining(site);
			int used = perFunction.getOrDefault(f, 0);
			String where = "site " + site + " in " + (f == null ? "(no function)" : f.getName());
			String what = k + " arm values " + render(values, lsb, effectMask);
			if (k > MAX_LIVE_FORKS_PER_BLOCK) {
				denied.add(site);
				forksDenied += k;
				log.add("path fork DENIED at " + where + ": " + what + " exceeds " +
					MAX_LIVE_FORKS_PER_BLOCK + " live forks per block; collapsed to unknown");
				return false;
			}
			if (used + k > MAX_FORKS_PER_FUNCTION) {
				denied.add(site);
				forksDenied += k;
				log.add("path fork DENIED at " + where + ": " + what + " would bring the function to " +
					(used + k) + " forks, over " + MAX_FORKS_PER_FUNCTION +
					" per function; collapsed to unknown");
				return false;
			}
			granted.put(site, k);
			perFunction.put(f, used + k);
			forksCreated += k;
			log.add("path fork at " + where + ": " + what + " (function total " + (used + k) + "/" +
				MAX_FORKS_PER_FUNCTION + ")");
			return true;
		}

		void observeLive(Address addr, int live) {
			if (live > maxLive) {
				maxLive = live;
				maxLiveAt = addr;
			}
		}

		void collapsed(Address addr, int had) {
			addressCollapses++;
			Function f = fm.getFunctionContaining(addr);
			log.add("path forks COLLAPSED at " + addr + " in " +
				(f == null ? "(no function)" : f.getName()) + ": " + (had) +
				" live elements exceeds " + MAX_LIVE_FORKS_PER_BLOCK +
				" per block; merged field-wise from here on");
		}

		private static String render(List<BankState> values, int lsb, int effectMask) {
			StringBuilder sb = new StringBuilder("{");
			for (BankState v : values) {
				if (sb.length() > 1) {
					sb.append(", ");
				}
				// field-local value, rendered as the number an analyst would recognize
				sb.append(v.knownMask() == 0 ? "?" : "0x" + Integer.toHexString(v.bits()));
			}
			return sb.append('}').toString();
		}

		ForkStats stats() {
			return new ForkStats(forksCreated, granted.size(), forksDenied, denied.size(),
				addressCollapses, maxLive, maxLiveAt, resolvedThroughArms, List.copyOf(log));
		}
	}

	/**
	 * Per-run path-forking counters (bead grm-wul). {@code forksCreated} is the number of arm
	 * values carried forward as separate elements, summed over the {@code sitesForked} sites
	 * that were granted; {@code forksDenied} likewise over the {@code sitesDenied} sites whose
	 * arms resolved but whose budget did not allow them ({@code MULTI_VALUED_AT_MERGE});
	 * {@code addressCollapses} counts addresses whose live set overflowed and was merged;
	 * {@code maxLive} is the largest live set seen anywhere, at {@code maxLiveAt};
	 * {@code resolvedThroughArms} counts sites whose every arm agreed on ONE value (resolved
	 * outright, no fork). {@code log} carries one line per decision, for the analyzer log.
	 */
	record ForkStats(int forksCreated, int sitesForked, int forksDenied, int sitesDenied,
			int addressCollapses, int maxLive, Address maxLiveAt, int resolvedThroughArms,
			List<String> log) {

		/** The one-line per-program summary the owner's ruling asks the analyzer log to print. */
		String summary() {
			return "path forking: forks created=" + forksCreated + " (sites " + sitesForked +
				") collapsed=" + forksDenied + " (sites " + sitesDenied + ", address collapses " +
				addressCollapses + ") max live at one block=" + maxLive +
				(maxLiveAt == null ? "" : " (" + maxLiveAt + ")") + " resolved-through-arms=" +
				resolvedThroughArms + " [caps: " + MAX_LIVE_FORKS_PER_BLOCK + "/block, " +
				MAX_FORKS_PER_FUNCTION + "/function]";
		}
	}

	/** Accumulates one address's direct-switch outcomes across its elements into one {@link SwitchResult}. */
	private static final class SiteTally {

		private ConfiguredMechanism mechanism;
		private BankState effect;
		private BankSwitchStrategy.ValueStop stop;
		// The RESTORED_BANK detail (bead grm-rd6h), carried alongside stop by the same rule --
		// set only when the winning element's stop is RESTORED_BANK, cleared whenever a later
		// element overwrites stop with something else (RESOLVED, MULTI_VALUED_AT_MERGE, ...).
		private StoredValueScanner.ReadBack readBack;
		private List<BankState> arms = List.of();
		private boolean armsDenied;

		boolean seen() {
			return mechanism != null;
		}

		void mechanism(ConfiguredMechanism m) {
			mechanism = m;
		}

		void add(BankState positioned, BankSwitchStrategy.ValueStop s) {
			add(positioned, s, null);
		}

		void add(BankState positioned, BankSwitchStrategy.ValueStop s,
				StoredValueScanner.ReadBack read) {
			effect = effect == null ? positioned : BankState.merge(effect, positioned);
			// RESOLVED (any element knowing anything) beats a denial beats the first reason.
			if (stop == null || s == BankSwitchStrategy.ValueStop.RESOLVED ||
				(s == BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE &&
					stop != BankSwitchStrategy.ValueStop.RESOLVED)) {
				stop = s;
				readBack = s == BankSwitchStrategy.ValueStop.RESTORED_BANK ? read : null;
			}
		}

		void arms(List<BankState> positionedArms, boolean deniedArms) {
			arms = positionedArms;
			armsDenied = deniedArms;
		}

		SwitchResult result() {
			return new SwitchResult(effect, mechanism.effectMask(), mechanism.lsb(),
				mechanism.strategy(), stop, readBack, arms, armsDenied);
		}
	}

	/** Accumulates one address's helper-call outcomes across its elements into one {@link CallSwitch}. */
	private static final class CallTally {

		private String helperName;
		private BankState effect;
		private BankState stateAfter;
		private boolean argumentResolved = true;
		private boolean noInboundArgument;
		private boolean secondTierRelay;
		private Address restoreCell;
		private StoredValueScanner.ReadBack readBack;
		private List<BankState> arms = List.of();
		private boolean armsDenied;

		boolean seen() {
			return helperName != null;
		}

		void add(String name, BankState e, BankState after, boolean resolved, boolean noInbound,
				boolean secondTier, Address restore, StoredValueScanner.ReadBack read) {
			helperName = name;
			effect = effect == null ? e : BankState.merge(effect, e);
			stateAfter = stateAfter == null ? after : BankState.merge(stateAfter, after);
			argumentResolved &= resolved;
			noInboundArgument |= noInbound;
			secondTierRelay |= secondTier;
			if (restoreCell == null) {
				restoreCell = restore;
			}
			if (readBack == null) {
				readBack = read;
			}
		}

		void arms(List<BankState> states, boolean deniedArms) {
			arms = states;
			armsDenied = deniedArms;
		}

		CallSwitch result() {
			return new CallSwitch(helperName, effect, stateAfter, argumentResolved,
				noInboundArgument, secondTierRelay, restoreCell, readBack, arms, armsDenied);
		}
	}

	/**
	 * The stop reason a direct switch site is finally recorded with: the strategy's own answer,
	 * except that an {@link BankSwitchStrategy.ValueStop#ANALYZER_LIMIT} at a site sitting inside
	 * a recognized bank-switch HELPER is offered to the strategy once more, to be reclassified
	 * {@link BankSwitchStrategy.ValueStop#HELPER_ARGUMENT} if the value is that helper's argument
	 * (bead {@code grm-3ou} part 1).
	 * <p>
	 * <b>This belongs to the engine, not to the strategy, because only the engine knows the helper
	 * set.</b> A strategy sees one instruction and its own mechanism; "is the function I am
	 * standing in a helper, and where do its callers enter it" is a whole-program fact that
	 * {@link HelperDiscovery} computes and {@code runDataflow} carries. Hence the two-phase shape:
	 * the strategy recovers the value with no notion of a helper (phase one, unchanged), and the
	 * engine, holding the helper set, asks the classification question afterward.
	 * <p>
	 * Asked ONLY for a wholly unresolved value that the strategy already called our limitation, so
	 * it can never overwrite a {@code RESOLVED} or a reason the strategy established positively --
	 * and the VALUE recorded is phase one's regardless, so nothing here can move a bank number.
	 * The default {@link BankSwitchStrategy#classifyHelperBodyGap} answers
	 * {@code ANALYZER_LIMIT}, so a strategy that has not opted in behaves exactly as before.
	 */
	private static BankSwitchStrategy.ValueStop classifyGap(Program program, Instruction instr,
			BankState inState, ConfiguredMechanism mech,
			BankSwitchStrategy.SwitchOutcome outcome, Map<Function, HelperModel> helpers) {
		if (helpers == null || outcome.value().knownMask() != 0 ||
			outcome.stop() != BankSwitchStrategy.ValueStop.ANALYZER_LIMIT) {
			return outcome.stop();
		}
		Function containing =
			program.getFunctionManager().getFunctionContaining(instr.getMinAddress());
		if (containing == null) {
			return outcome.stop();
		}
		// Keyed by the CONTAINING function, and its model's own entry() -- not the function's
		// entry point. For a mid-body or pass-through-wrapper model those differ, and entry() is
		// the one callers actually arrive at, which is where the argument register is live.
		HelperModel helper = helpers.get(containing);
		if (helper == null || helper.entry() == null) {
			return outcome.stop();
		}
		BankState localIn = toFieldLocal(inState, mech.lsb(), mech.effectMask());
		return mech.strategy().classifyHelperBodyGap(program, instr, localIn, helper.entry());
	}

	/**
	 * Narrows a board-absolute {@link BankState} to one mechanism's field-local
	 * {@code [0, width)} coordinate space: the bits outside {@code effectMask} are
	 * discarded and the surviving bits are shifted down by {@code lsb}. This is what a
	 * {@link BankSwitchStrategy} actually sees as its {@code inState} -- e.g. its own
	 * mechanism read back ({@code LDA} of a register-write's own address/register)
	 * resolves against only the field(s) that mechanism owns, not the whole board state.
	 * The inverse of {@link #position}.
	 */
	static BankState toFieldLocal(BankState state, int lsb, int effectMask) {
		return new BankState((state.knownMask() & effectMask) >>> lsb,
			(state.bits() & effectMask) >>> lsb);
	}

	/**
	 * Positions a mechanism's field-local {@code [0, width)} result back into the board's
	 * absolute state bits: shifted up by {@code lsb} and masked to {@code effectMask} (a
	 * defensive mask -- a well-behaved strategy result is already {@code <= width} bits,
	 * but this keeps a stray high bit from a strategy from ever leaking outside the
	 * mechanism's own field). The inverse of {@link #toFieldLocal}.
	 */
	static BankState position(BankState fieldLocal, int lsb, int effectMask) {
		return new BankState((fieldLocal.knownMask() << lsb) & effectMask,
			(fieldLocal.bits() << lsb) & effectMask);
	}

	/**
	 * Folds a mechanism's positioned effect into a base state: bits inside {@code mask}
	 * take the effect's knowledge (whether known or not), every other bit keeps whatever
	 * {@code base} already knew. {@code effect}'s known bits are always a subset of
	 * {@code mask} by construction ({@link #position} masks to it), so this is a clean
	 * per-bit replace, not a merge -- one mechanism's switch never has to agree with what
	 * was known before it fired. When {@code mask} covers every tracked bit (every shipped
	 * board today, since each has exactly one mechanism spanning the whole board mask),
	 * this reduces to replacing the state outright, matching the engine's original
	 * single-mechanism behavior exactly.
	 */
	static BankState overwrite(BankState base, BankState effect, int mask) {
		return new BankState((base.knownMask() & ~mask) | effect.knownMask(),
			(base.bits() & ~mask) | effect.bits());
	}


	/**
	 * Folds {@code incoming} into the element for {@code pathId} at {@code addr} and enqueues
	 * the address if anything changed (bead grm-wul generalizes the single-state version: same
	 * field-wise merge per element, plus the live cap).
	 * <p>
	 * <b>The live cap.</b> If adding a new path id would leave more than
	 * {@link #MAX_LIVE_FORKS_PER_BLOCK} elements at {@code addr}, every element there is merged
	 * field-wise into ONE {@link PathId#ROOT} element and the address is marked collapsed --
	 * permanently: every later arrival at a collapsed address merges into ROOT whatever path it
	 * came on. That is exactly what the single-state engine would have held (the merge of all
	 * incoming states), so a collapse can lose what forking gained but never invent anything, and
	 * it happens at most once per address, which the termination argument relies on.
	 */
	private static void mergeAndEnqueue(Address addr, PathId pathId, BankState incoming,
			Map<Address, LinkedHashMap<PathId, BankState>> stateIn, Set<Address> collapsedAddrs,
			Deque<Address> worklist, Listing listing, BoardModel board,
			Map<String, int[]> clampCache, ForkBudget budget,
			Map<Address, Set<Address>> stateDependents) {
		if (listing.getInstructionAt(addr) == null) {
			// not (yet) disassembled / not code -- nothing to track here
			return;
		}
		LinkedHashMap<PathId, BankState> elements =
			stateIn.computeIfAbsent(addr, a -> new LinkedHashMap<>());
		if (collapsedAddrs.contains(addr)) {
			pathId = PathId.ROOT;
		}
		BankState existing = elements.get(pathId);
		BankState merged = existing == null ? incoming : BankState.merge(existing, incoming);
		merged = clampToResidence(addr, merged, board, clampCache);
		boolean changed = existing == null || !merged.equals(existing);
		if (!changed) {
			return; // unchanged, already processed with this exact state -- nothing to do
		}
		elements.put(pathId, merged);
		if (elements.size() > MAX_LIVE_FORKS_PER_BLOCK) {
			BankState all = null;
			for (BankState s : elements.values()) {
				all = all == null ? s : BankState.merge(all, s);
			}
			budget.collapsed(addr, elements.size());
			elements.clear();
			elements.put(PathId.ROOT, all);
			collapsedAddrs.add(addr);
		}
		budget.observeLive(addr, elements.size());
		worklist.add(addr);
		// The state at addr changed, so every helper call whose recovery consulted it through a
		// StateOracle must be re-evaluated (grm-mej.3 increment 3) -- see stateDependents'
		// declaration for why the fixpoint's own propagation does not cover this.
		Set<Address> dependents = stateDependents.get(addr);
		if (dependents != null) {
			worklist.addAll(dependents);
		}
	}


	/**
	 * Execution implies mapping: an instruction physically inside a computed window's
	 * bank overlay {@code WINDOW_B<n>} can only be running while that window's field
	 * holds {@code n}, so those bits are forced known regardless of what flowed in.
	 * (Idempotent and deterministic per address, so the fixpoint still terminates.)
	 */
	private static BankState clampToResidence(Address addr, BankState state, BoardModel board,
			Map<String, int[]> clampCache) {
		AddressSpace space = addr.getAddressSpace();
		if (!space.isOverlaySpace()) {
			return state;
		}
		int[] clamp = clampCache.computeIfAbsent(space.getName(), name -> {
			for (ComputedWindowModel w : board.computedWindows().values()) {
				Integer v = DescriptorSupport.OverlayNaming.parseBankValue(w.name(), name);
				if (v != null) {
					FieldSpec f = w.field();
					return new int[] { f.positionedMask(), (v << f.lsb()) & f.positionedMask() };
				}
				// null: not one of ours (e.g. a C64 occupant overlay) -- keep looking
			}
			if (board.modeField() != null) {
				FieldSpec modeField = board.modeField();
				Set<String> windowNames = new LinkedHashSet<>();
				for (ModeWindowModel w : board.modeWindows()) {
					windowNames.add(w.name());
				}
				for (String windowName : windowNames) {
					DescriptorSupport.OverlayNaming.ModeBank mb =
						DescriptorSupport.OverlayNaming.parseModeBankValue(windowName, name);
					if (mb != null) {
						ModeWindowModel instance = BankAnnotationAdapter
							.findModeWindowInstance(board.modeWindows(), windowName, mb.mode());
						if (instance != null && instance.bankField() != null) {
							FieldSpec bankField = instance.bankField();
							int posMask = modeField.positionedMask() | bankField.positionedMask();
							int posBits =
								((mb.mode() << modeField.lsb()) & modeField.positionedMask()) |
									((mb.bank() << bankField.lsb()) & bankField.positionedMask());
							return new int[] { posMask, posBits };
						}
						continue;
					}
					Integer mv = DescriptorSupport.OverlayNaming.parseModeValue(windowName, name);
					if (mv != null) {
						return new int[] { modeField.positionedMask(),
							(mv << modeField.lsb()) & modeField.positionedMask() };
					}
				}
			}
			return new int[0];
		});
		if (clamp.length == 0) {
			return state;
		}
		return new BankState(state.knownMask() | clamp[0],
			(state.bits() & ~clamp[0]) | clamp[1]);
	}


	/**
	 * Per-address strategy-probe cache entry for {@link #runDataflow} (grm-5tl.13.2).
	 * {@code mechanism == null} records that no strategy's instruction-level predicate
	 * matched this address at all. Otherwise {@code mechanism} is the one mechanism whose
	 * strategy predicate matched; {@code result} holds its state-independent, field-local
	 * result when {@link BankSwitchStrategy#cacheable()} is true, or {@code null} when the
	 * match was found but the value must be recomputed from the current in-state on every
	 * dequeue.
	 */
	private record MatchInfo(ConfiguredMechanism mechanism,
			BankSwitchStrategy.SwitchOutcome result) {}


	/**
	 * A recognized direct switch at one address. {@code stop} says WHY {@code effect} did
	 * not resolve when it did not (bead {@code grm-3ou} part 1) -- it is
	 * {@link BankSwitchStrategy.ValueStop#RESOLVED} whenever any bit of {@code effect} is
	 * known, and is what lets an annotator tell a gap that is HONEST (the value really is
	 * runtime-determined, or is the caller's argument) from one that is OUR LIMITATION.
	 * <p>
	 * {@code arms} (bead grm-wul) is non-empty in exactly two cases. FORKED ({@code armsDenied}
	 * false): the site resolved to these several positioned effects, one per arm of the join
	 * above it, and the state was carried forward separately along each; {@code effect} is then
	 * their field-wise merge (typically wholly unknown) and {@code stop} is {@code RESOLVED} --
	 * an annotator must read {@code arms}, not {@code effect}, or it will call a resolved site
	 * undeterminable. DENIED ({@code armsDenied} true): the arms resolved to these values but the
	 * fork budget did not allow them, {@code effect} is unknown and {@code stop} is
	 * {@link BankSwitchStrategy.ValueStop#MULTI_VALUED_AT_MERGE}; {@code arms} is what the
	 * warning names.
	 */
	record SwitchResult(BankState effect, int effectMask, int lsb,
			BankSwitchStrategy strategy, BankSwitchStrategy.ValueStop stop,
			StoredValueScanner.ReadBack readBack, List<BankState> arms, boolean armsDenied) {

		/** The pre-grm-rd6h form: no read-back. */
		SwitchResult(BankState effect, int effectMask, int lsb, BankSwitchStrategy strategy,
				BankSwitchStrategy.ValueStop stop, List<BankState> arms, boolean armsDenied) {
			this(effect, effectMask, lsb, strategy, stop, null, arms, armsDenied);
		}

		/** The pre-grm-wul form: no arms. */
		SwitchResult(BankState effect, int effectMask, int lsb, BankSwitchStrategy strategy,
				BankSwitchStrategy.ValueStop stop) {
			this(effect, effectMask, lsb, strategy, stop, List.of(), false);
		}

		/** Whether this site was carried forward as several elements, one per arm. */
		boolean forked() {
			return !armsDenied && arms.size() >= 2;
		}
	}

	/**
	 * A resolved call-site switch (for annotation, distinct from direct switches).
	 * {@code effect} is the call's own recovered deposit (positioned, known bits limited to
	 * what the argument scan resolved of the bits this call site owns). {@code argumentResolved}
	 * -- not {@code effect} -- is what the WARN decision keys off since bead grm-4bgh.5: a
	 * multi-deposit helper can establish a field from its OWN body constant while the caller's
	 * argument stays unrecovered, and warning off "is anything known" would let the first fact
	 * hide the second. For every single-deposit helper the two questions are identical by
	 * construction ({@code CallEffect}'s 2-argument constructor), so this changed no existing
	 * answer. {@code stateAfter}
	 * is the post-call state of the helper's own MECHANISM WINDOW: the in-state narrowed to
	 * the helper's {@code effectMask}, overwritten by {@code effect} on the call's owned
	 * bits. The COMMENT is rendered from it, because a helper deposit, unlike a
	 * {@code computeSwitch} result, has no in-state echoed into it: without this, every
	 * sibling field the call doesn't own would render as "assumed from initial" even when
	 * the dataflow knows it perfectly well. Narrowing the echo to the mechanism window
	 * (rather than folding over the whole tracked state) keeps the comment's knowledge
	 * horizon identical to a direct switch's at the same spot -- a {@code computeSwitch}
	 * result echoes exactly its own mechanism's in-state bits, never another mechanism's,
	 * so a helper-call comment on a multi-mechanism board keeps showing other mechanisms'
	 * fields as assumed, exactly as it always did. For a single-field helper (owned == the
	 * whole mechanism window) {@code stateAfter == effect}, so the historical path is
	 * unchanged byte-for-byte.
	 * <p>
	 * {@code noInboundArgument} is carried straight through from
	 * {@link HelperArgumentRecovery.CallEffect#noInboundArgument} (bead grm-jqt0): a helper whose
	 * OWN prologue provably redefines the argument register before the caller's value could ever
	 * reach the mechanism, e.g. zelda2's {@code FUN_ffc9} ({@code LDA $0769}, falling into the
	 * real setter {@code FUN_ffcc}). {@code BoardBankAnalyzer} reads it only when
	 * {@code argumentResolved} is false, to tell that HONEST case apart from a call site whose
	 * argument plausibly was statically determinable and simply was not recovered.
	 * <p>
	 * {@code secondTierRelay} (bead grm-ylm6) is carried straight through from
	 * {@link HelperArgumentRecovery.CallEffect#secondTierRelay}: this call site is itself a
	 * second-tier helper's relay call, so an unresolved argument here is recoverable one frame
	 * out (at the WRAPPER's own call sites) rather than a gap in this analyzer. Read only when
	 * {@code argumentResolved} is false, exactly like {@code noInboundArgument}.
	 * <p>
	 * {@code restoreCell} (bead grm-yflf) is carried straight through from
	 * {@link HelperArgumentRecovery.CallEffect#restoreCell}: non-null only when this call's
	 * helper is a proven no-argument RESTORE entry, naming the cell the bank is restored from --
	 * zelda2's {@code FUN_ffc9} restores from {@code $0769}. Read only when
	 * {@code argumentResolved} is false, exactly like the two booleans above; classify such a
	 * site {@link BankSwitchStrategy.ValueStop#RESTORED_BANK} rather than
	 * {@code ANALYZER_LIMIT}.
	 * <p>
	 * {@code readBack} (bead grm-yflf, the caller-side half) is carried straight through from
	 * {@link HelperArgumentRecovery.CallEffect#readBack}: non-null when the CALLER's register
	 * scan ended on a plain read-back of a live-bank mirror (megaman2's {@code LDA $29 / PHA /
	 * JSR c96b / PLA / JSR c000}), naming the cell, the read and the call it was carried across.
	 * Read only when {@code argumentResolved} is false, and classified {@code RESTORED_BANK}
	 * exactly as {@code restoreCell} is.
	 * <p>
	 * {@code arms}/{@code armsDenied} (bead grm-wul) mirror {@link SwitchResult}'s: FORKED
	 * carries one post-call mechanism-window state per arm (render those, not
	 * {@code stateAfter}, which is their merge); DENIED carries the arm deposits the budget
	 * refused, and the site is classified {@code MULTI_VALUED_AT_MERGE}.
	 */
	record CallSwitch(String helperName, BankState effect, BankState stateAfter,
			boolean argumentResolved, boolean noInboundArgument, boolean secondTierRelay,
			Address restoreCell, StoredValueScanner.ReadBack readBack, List<BankState> arms,
			boolean armsDenied) {

		/** The pre-grm-wul form: no arms, no read-back. */
		CallSwitch(String helperName, BankState effect, BankState stateAfter,
				boolean argumentResolved, boolean noInboundArgument, boolean secondTierRelay,
				Address restoreCell) {
			this(helperName, effect, stateAfter, argumentResolved, noInboundArgument,
				secondTierRelay, restoreCell, null, List.of(), false);
		}

		/** Whether this call was carried forward as several elements, one per arm. */
		boolean forked() {
			return !armsDenied && arms.size() >= 2;
		}
	}

	/**
	 * The engine's output. {@code stateIn} is the single-state view -- per address, the
	 * field-wise merge of every element there -- which every consumer that wants ONE state reads
	 * unchanged. {@code forkedStates} (bead grm-wul) lists, for the addresses that hold more
	 * than one element, each distinct whole state; reference retargeting places one reference
	 * per state. {@code forkStats} is the per-run ledger the analyzer log summarizes.
	 */
	record DataflowResult(Map<Address, BankState> stateIn,
			Map<Address, SwitchResult> switchResults, Map<Address, CallSwitch> callSwitches,
			Map<Address, List<BankState>> forkedStates, ForkStats forkStats) {

		/** Every distinct whole state at {@code addr}: the forked set, or the single state. */
		List<BankState> statesAt(Address addr) {
			List<BankState> forked = forkedStates.get(addr);
			if (forked != null) {
				return forked;
			}
			BankState single = stateIn.get(addr);
			return single == null ? List.of() : List.of(single);
		}
	}
}
