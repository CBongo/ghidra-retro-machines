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
import java.util.Arrays;
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

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.FlowType;
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
 * <p>{@link Run#mergeAndEnqueue} and {@link #clampToResidence} needed no receiver at all: an
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
 * {@link #overwrite} is needed the OTHER way too: helper-propagation code
 * in {@link HelperDiscovery} ({@code composeWithCallee}) calls it, so it
 * was widened from {@code private} to package-private {@code static} here and is referenced
 * back from there via {@code import static}. (The coordinate conversions that used to sit beside
 * it, {@code toFieldLocal}/{@code position}, are now {@link MechanismPlacement}, bead grm-ze06.2.) {@code CallEffect}, a
 * record {@code runDataflow} constructs and holds directly, moved to {@link HelperArgumentRecovery}
 * with the rest of grm-shnf's step 3 (helper-propagation code there also constructs it) and is
 * referenced here via {@code import retromachines.HelperArgumentRecovery.CallEffect}.
 * {@code CallSwitch}, {@code DataflowResult} and {@code SwitchResult} moved to this class outright
 * (bead grm-shnf step 1): all three were already package-private as of increment 4, so the move
 * needed no visibility change, and {@code BoardBankAnalyzer}'s own harness method now reaches them
 * via {@code import retromachines.BankDataflowEngine.<Name>} instead. {@code MatchInfo} moved here
 * unchanged (still {@code private}, nested in this
 * class instead) because {@code runDataflow} is its sole consumer. {@code clampToResidence}
 * calls back into {@code BankAnnotationAdapter.findModeWindowInstance(...)} (already qualified,
 * already {@code static}) -- the one place this section is called INTO from the annotation side,
 * documented on {@link BankAnnotationAdapter} as well.
 * <p>
 * <b>Bead grm-wul (2026-09-19) made the state at an address a bounded set of whole states, one
 * per path, and added demand-driven PATH FORKING at merge sites</b> -- see
 * {@link #runDataflow}'s javadoc for the model, {@link #joinArms}/{@link #evaluateArms} for how
 * a site's arms are enumerated and evaluated, {@link Run#mergeAndEnqueue} for the live cap, and
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
	 * {@link Run#mergeAndEnqueue}). Configurable constant for now; an analyzer option later if the
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
	 * Everything a dataflow run takes besides the program, the monitor and the listing -- the one
	 * place a new per-run input is added (bead grm-rx1i.2), instead of a positional parameter in
	 * every signature the run threads it through. Build one with {@link #of} and the {@code with*}
	 * methods; every optional member defaults to the "none" a caller with no such input passed.
	 * <p>
	 * {@code helpers} is {@code null} for a run with no helper map (pass 1), which is not the same
	 * as empty; {@code bankResolution} is {@code null} for the stateless callee lookup.
	 */
	record DataflowInputs(List<ConfiguredMechanism> mechanisms, BoardModel board,
			Map<Function, HelperModel> helpers, Map<Function, Integer> restoringTrampolines,
			Set<Address> secondTierRelaySites, BankStackBrackets.Claims bracketClaims,
			HelperDiscovery.BankResolution bankResolution, ShadowCommits.Plan shadowCommits) {

		/** A run with no helpers, trampolines, relay sites, brackets, resolution or shadow hints. */
		static DataflowInputs of(List<ConfiguredMechanism> mechanisms, BoardModel board) {
			return new DataflowInputs(mechanisms, board, null, Map.of(), Set.of(),
				BankStackBrackets.Claims.NONE, null, ShadowCommits.Plan.NONE);
		}

		DataflowInputs withHelpers(Map<Function, HelperModel> h) {
			return new DataflowInputs(mechanisms, board, h, restoringTrampolines,
				secondTierRelaySites, bracketClaims, bankResolution, shadowCommits);
		}

		DataflowInputs withRestoringTrampolines(Map<Function, Integer> t) {
			return new DataflowInputs(mechanisms, board, helpers, t, secondTierRelaySites,
				bracketClaims, bankResolution, shadowCommits);
		}

		DataflowInputs withSecondTierRelaySites(Set<Address> sites) {
			return new DataflowInputs(mechanisms, board, helpers, restoringTrampolines, sites,
				bracketClaims, bankResolution, shadowCommits);
		}

		DataflowInputs withBracketClaims(BankStackBrackets.Claims claims) {
			return new DataflowInputs(mechanisms, board, helpers, restoringTrampolines,
				secondTierRelaySites, claims, bankResolution, shadowCommits);
		}

		DataflowInputs withBankResolution(HelperDiscovery.BankResolution resolution) {
			return new DataflowInputs(mechanisms, board, helpers, restoringTrampolines,
				secondTierRelaySites, bracketClaims, resolution, shadowCommits);
		}

		DataflowInputs withShadowCommits(ShadowCommits.Plan plan) {
			return new DataflowInputs(mechanisms, board, helpers, restoringTrampolines,
				secondTierRelaySites, bracketClaims, bankResolution, plan);
		}
	}

	/**
	 * One forward-dataflow run to fixpoint. When {@code helpers} is non-null, a call to
	 * a helper function is itself a switch site: the state on the call's fall-through is
	 * the helper's effect, not the flowed-through in-state (the call target's entry is
	 * still seeded with the in-state -- the switch happens inside the helper).
	 * <p>
	 * {@code secondTierRelaySites} (bead grm-ylm6): the call-site
	 * addresses {@link HelperDiscovery#findSecondTierHelpers} proved are a second-tier helper's
	 * own relay call -- the register it reads is genuinely a live argument, but one supplied by
	 * THIS FUNCTION's caller, not resolvable at this address no matter how good value recovery
	 * gets. An unresolved call at one of these addresses is reclassified via
	 * {@link HelperArgumentRecovery.CallEffect#asSecondTierRelay} so
	 * {@code BoardBankAnalyzer} can report it as an honest gap
	 * ({@link BankSwitchStrategy.ValueStop#SECOND_TIER_ARGUMENT}) instead of our limitation --
	 * see that method's javadoc. Empty for every caller but {@code BoardBankAnalyzer}'s phase-2
	 * pass, which is the only one with a helper map (and therefore relay sites) to supply.
	 * <p>
	 * {@code bracketClaims} (bead grm-mej.10): the verified RAM bank-stack brackets. At a
	 * claimed POP call site the restored fields are deposited from the tracked state at the
	 * matching PUSH, and a claimed push's own unrecoverable argument is private to its bracket.
	 * {@link BankStackBrackets.Claims#NONE} means no brackets.
	 * <p>
	 * {@code bankResolution} (bead grm-fj4m): when non-null,
	 * the helper branch resolves a call's callee through
	 * {@link HelperDiscovery#calledHelper(Program, Instruction, Map, BankState, HelperDiscovery.BankResolution)}
	 * against the in-state at the call, so a base-space call into a window whose bank that state
	 * pins reaches the overlay callee, not the home bank's function. Null is the stateless
	 * lookup (pass 1 has no helpers, and tests that predate the bead).
	 * <p>
	 * {@code shadowCommits} (bead grm-hb6.26): the validated {@code banking.shadow_commits}
	 * hints: at a call to a hinted helper the field is committed from the hinted RAM cell,
	 * or the call is a no-op on it. {@link ShadowCommits.Plan#NONE} means no hints.
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
			DataflowInputs inputs) throws CancelledException {
		DataflowResult locked = runDataflowOnce(program, monitor, listing, inputs, true);
		ModeLock lock = locked.modeLock();
		if (lock == null || !lock.rejected()) {
			return locked;
		}
		// The lock did not survive verification (grm-dos9.6): some write reached only after it
		// was formed writes another mode, or one the analyzer could not resolve. Nothing derived
		// under the lock may reach the output, so the whole run is redone without it; the
		// rejected lock rides along only as evidence for the warning the analyzer raises.
		DataflowResult plain = runDataflowOnce(program, monitor, listing, inputs, false);
		return new DataflowResult(plain.stateIn(), plain.switchResults(), plain.callSwitches(),
			plain.forkedStates(), plain.forkStats(), lock, null, plain.hintNotes());
	}

	/**
	 * One fixpoint run. {@code allowModeLock} (bead grm-dos9.6) lets the run lock the board's
	 * layout-mode field once the reset-reached code has written it -- see {@link ModeLock}.
	 */
	private static DataflowResult runDataflowOnce(Program program, TaskMonitor monitor,
			Listing listing, DataflowInputs inputs, boolean allowModeLock)
			throws CancelledException {
		return new Run(program, monitor, listing, inputs, allowModeLock).execute();
	}

	/**
	 * One fixpoint run's inputs and mutable state (bead grm-rx1i.2). A fresh instance per
	 * {@link #runDataflowOnce}: nothing here is shared between runs, so the mode-lock redo starts
	 * from empty maps exactly as the single-method form did. The methods that used to take this
	 * state as a dozen positional parameters read the fields instead.
	 */
	private static final class Run {

		private final Program program;
		private final TaskMonitor monitor;
		private final Listing listing;
		private final List<ConfiguredMechanism> mechanisms;
		private final BoardModel board;
		private final Map<Function, HelperModel> helpers;
		private final Map<Function, Integer> restoringTrampolines;
		private final Set<Address> secondTierRelaySites;
		private final BankStackBrackets.Claims bracketClaims;
		private final HelperDiscovery.BankResolution bankResolution;
		private final ShadowCommits.Plan shadowCommits;
		/** Bead grm-dos9.6: whether this run may lock the board layout-mode field. */
		private final boolean allowModeLock;

		private final Map<Address, LinkedHashMap<PathId, BankState>> stateIn = new HashMap<>();
		private final Set<Address> collapsedAddrs = new HashSet<>();
		private final Map<Address, SwitchResult> switchResults = new HashMap<>();
		private final Map<Address, CallSwitch> callSwitches = new HashMap<>();
		private final Deque<Address> worklist = new ArrayDeque<>();
		private final Map<String, int[]> clampCache = new HashMap<>();
		private final Map<String, int[]> residenceInvariantCache = new HashMap<>();
		// Scoped to this run (a field of the per-run object, never of the engine): phase 1/2
		// separation guarantees no instruction appears mid-fixpoint, so per-run scoping sidesteps
		// any staleness question. See probeSite for the soundness invariant this relies on (grm-5tl.13.2).
		private final Map<Address, MatchInfo> matchCache = new HashMap<>();
		// Likewise scoped to this run: the A/X/Y a helper call site supplies
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
		private final Map<CallSiteRegKey, RegisterEnv> callSiteRegCache = new HashMap<>();
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
		private final Map<Address, Set<Address>> stateDependents = new HashMap<>();
		// The arms heading each site's block are structural -- a function of the listing and its
		// flow references, both fixed for the duration of this run -- so they are enumerated once
		// per address. An empty Optional records "not forkable here" so the walk is not repeated.
		private final Map<Address, Optional<List<Arm>>> armCache = new HashMap<>();
		// The cross-block PHA/PLA pairing proof (bead grm-mej.3 increment X1) is STATE-FREE -- a
		// function of the listing and control flow alone, like armCache above -- so it too is
		// computed once per PLA address for the whole run and handed to every OracleHooks that
		// might walk through it. The same holder carries grm-zsxz Z2's save-slot proofs and
		// callee-closure writer censuses, which are state-free for the same reason.
		private final StoredValueScanner.ProofMemo crossBlockProofMemo = new StoredValueScanner.ProofMemo();
		private final ForkBudget budget;
		// Bead grm-hb6.20: the diagnoses of banking.switch_sites bank: VALUE hints. Per-RUN state
		// like switchResults: the last evaluation of a site wins, and the caller of runDataflow
		// only ever sees the final run's, so a re-run (the mode-lock redo) or an earlier analysis
		// pass cannot leave a duplicate or stale diagnosis behind.
		private final Map<Address, SwitchSiteHints.HintNote> hintNotes = new HashMap<>();

		Run(Program program, TaskMonitor monitor, Listing listing, DataflowInputs inputs,
				boolean allowModeLock) {
			this.program = program;
			this.monitor = monitor;
			this.listing = listing;
			this.mechanisms = inputs.mechanisms();
			this.board = inputs.board();
			this.helpers = inputs.helpers();
			this.restoringTrampolines = inputs.restoringTrampolines();
			this.secondTierRelaySites = inputs.secondTierRelaySites();
			this.bracketClaims = inputs.bracketClaims();
			this.bankResolution = inputs.bankResolution();
			this.shadowCommits = inputs.shadowCommits();
			this.allowModeLock = allowModeLock;
			this.budget = new ForkBudget(program);
		}

		DataflowResult execute() throws CancelledException {

			// Only the REAL entries are seeded up front: the external entry points (reset and the
			// vectors) and the loader's async entries. An ordinary function entry used to be seeded
			// too, with the power-on state marked fully KNOWN, and that seed then merged against the
			// state its callers carried in -- so wherever a caller had moved a field off its power-on
			// value (cv3's RESET sets MMC5 prg_mode 2; the board resets to 3), the two "known"
			// values disagreed and every callee lost the field. Bead grm-dos9.4. A function entry no
			// real entry reaches is still seeded, as a FALLBACK once the fixpoint runs dry (see
			// seedUnreachedFunctions), so the power-on state is what is assumed when no caller says
			// otherwise, never a claim competing with one.
			Set<Address> seeds = new LinkedHashSet<>();
			AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
			while (eps.hasNext()) {
				seeds.add(eps.next());
			}

			// Two seed states, not one. banking.initial_state is what the board powers up holding,
			// so it is sound for an entry the machine reaches from reset -- and unsound for one it
			// reaches from an interrupt, which fires from arbitrary mainline context and leaves the
			// interrupted code's bank live on entry. The loader tells us which entries those are
			// (DescriptorHints.ASYNC_ENTRY_POINTS_PROPERTY); this stays machine-independent and
			// merely consumes the list. Bead grm-913.
			BankState seedState = BankState.fullyKnown(board.mask(), board.initialState());
			// Bead grm-hb6.20: banking.switch_sites bank: VALUE hints. Empty (and every use below is
			// then skipped outright) for every program whose descriptor states none. hintNotes is
			// per-RUN state like switchResults: the last evaluation of a site wins, and the caller of
			// runDataflow only ever sees the final run's, so a re-run (the mode-lock redo) or an
			// earlier analysis pass cannot leave a duplicate or stale diagnosis behind.
			Map<Address, Integer> valueHints = SwitchSiteHints.valueHints(program);
			Set<Address> asyncEntries = DescriptorHints.parseAsyncEntryPoints(program);
			// Bead grm-mej.12: a per-game banking.fixed_after_init hint names fields that hold their
			// initial value at every instruction after init, so those bits (only) are known on an
			// async entry too. Mask 0 (no hint) leaves this exactly BankState.unknown().
			int fixedMask = DescriptorHints.readFixedAfterInitMask(program) & board.mask();
			BankState asyncSeed = fixedMask == 0 ? BankState.unknown()
					: new BankState(fixedMask, seedState.bits() & fixedMask);
			// Seeding runs in three phases (grm-dos9.6). The reset-side entries go first, alone, so
			// that when the worklist first runs dry every mode write the reset path reaches has
			// converged -- that census is what may lock the layout-mode field. The async entries
			// follow, seeded with the locked mode when there is one, and then the fallback seeds for
			// functions nothing reached (grm-dos9.4), again with the locked mode.
			for (Address seed : seeds) {
				if (!asyncEntries.contains(seed)) {
					mergeAndEnqueue(seed, PathId.ROOT, seedState);
				}
			}
			List<Address> functionEntries = new ArrayList<>();
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				functionEntries.add(f.getEntryPoint());
			}
			// Bead grm-hb6.4: banking.switch_sites -- a game descriptor's "there is a bank-switch store
			// here" hints join the fallback seed set, exactly like a function entry nothing reached.
			// A SEED, never an injected result: the site's own computeSwitch still decides.
			for (Address hinted : SwitchSiteHints.seedAddresses(program)) {
				if (!functionEntries.contains(hinted)) {
					functionEntries.add(hinted);
				}
			}
			// The board's layout-mode field (MapCompiler's single shared `when:` field), or 0.
			int layoutMask = board.modeField() == null ? 0
					: board.modeField().positionedMask() & board.mask();
			int modeMask = allowModeLock ? layoutMask : 0;
			Map<Address, ModeWrite> modeWrites = new HashMap<>();
			// grm-dos9.9: the direct sites whose every deposit was implicit (a shifter reset), and the
			// helper sites each mode-writing CALL reaches. A call is an implicit set when every site
			// of its helper is -- rcproam's ffea calls ff83, LDA #$80 / STA $8000 / RTS.
			Set<Address> implicitSites = new HashSet<>();
			Map<Address, List<Address>> callHelperSites = new HashMap<>();
			boolean asyncSeeded = false;
			ModeLock lock = null;
			String noLock = null;
			BankState fallbackSeed = seedState;

			while (true) {
				if (worklist.isEmpty()) {
					if (!asyncSeeded) {
						asyncSeeded = true;
						markImplicitCalls(modeWrites, callHelperSites, implicitSites);
						LockCensus census = censusModeLock(modeWrites, modeMask);
						lock = census.lock();
						noLock = census.noLock();
						BankState asyncEntryState = asyncSeed;
						if (lock != null) {
							asyncEntryState = overwrite(asyncSeed, lock.state(), modeMask);
							fallbackSeed = overwrite(seedState, lock.state(), modeMask);
						}
						for (Address seed : asyncEntries) {
							mergeAndEnqueue(seed, PathId.ROOT, asyncEntryState);
						}
					}
					if (worklist.isEmpty() && !seedUnreachedFunctions(functionEntries, fallbackSeed)) {
						break;
					}
				}
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
				Integer hint = valueHints.isEmpty() ? null : valueHints.get(addr);
				HintTally hintTally = hint == null ? null : new HintTally(hint);
				if (!shadowCommits.isEmpty() && hintTally == null) {
					// grm-hb6.26: the last evaluation of a call wins -- retract a note an earlier
					// dequeue left (ShadowCommits.apply re-records it if it still applies)
					hintNotes.remove(addr);
				}
				List<OutElement> outs = new ArrayList<>();
				List<Address> calledSites = null;

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
						MechanismPlacement placement = matchedMechanism.placement();
						int effectMask = matchedMechanism.effectMask();
						if (hintTally != null) {
							// grm-hb6.20: a VALID hint replaces the outcome with a fully known,
							// RESOLVED one BEFORE the arm logic below, so a hinted site never forks.
							switchedLocal = applyStoreHint(hintTally, switchedLocal, matchedMechanism,
								inState, instr);
						}
						List<MechanismState> forkValues = null;
						List<MechanismState> deniedValues = null;
						if (unresolvedOurs(switchedLocal)) {
							// grm-wul: the site did not resolve and blamed us. Ask along each arm of
							// the join heading its block, if there is one.
							List<Arm> arms = armsFor(instr);
							List<MechanismState> perArm = arms == null ? null
									: evaluateArms(program, listing, arms, env -> {
										Probe along = probeSite(program, instr, inState, mechanisms,
											matchCache, env);
										return along.outcome() == null ? null : along.outcome().value();
									}, 1);
							if (perArm != null) {
								List<MechanismState> values = distinct(perArm);
								if (values.size() == 1) {
									// Every arm agrees: the site resolves to that one value outright.
									// Not a fork -- nothing to budget, nothing to carry separately.
									switchedLocal = new BankSwitchStrategy.SwitchOutcome(values.get(0),
										BankSwitchStrategy.ValueStop.RESOLVED);
									budget.resolvedThroughArms++;
								}
								else if (budget.grant(addr, values.size(), ForkBudget.render(values))) {
									forkValues = values;
								}
								else {
									deniedValues = values;
									switchedLocal = new BankSwitchStrategy.SwitchOutcome(
										MechanismState.unknown(),
										BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE);
								}
							}
						}
						if (forkValues != null) {
							// FORK: this in-element becomes one out-element per distinct arm value,
							// each with that value's positioned effect folded in on the mechanism's
							// own bits, exactly as a resolved single value is below.
							List<BankState> positionedArms = new ArrayList<>();
							for (MechanismState armLocal : forkValues) {
								BankState positioned = placement.position(armLocal);
								positionedArms.add(positioned);
								site.add(positioned, BankSwitchStrategy.ValueStop.RESOLVED);
								BankState out = overwrite(inState,
									fillFromLock(positioned, effectMask & modeMask, lock), effectMask);
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
							BankState positionedEffect = placement.position(switchedLocal.value());
							BankSwitchStrategy.ValueStop stop = deniedValues != null
									? BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE
									: classifyGap(program, instr, inState, matchedMechanism,
										switchedLocal, helpers);
							// grm-rd6h: classifyGap only ever reclassifies an ANALYZER_LIMIT (see its
							// javadoc), so a RESTORED_BANK stop and its ReadBack always survive intact
							// -- the guard below is defensive, not load-bearing.
							site.add(positionedEffect, stop,
								stop == BankSwitchStrategy.ValueStop.RESTORED_BANK
										? switchedLocal.readBack() : null,
								switchedLocal.implicit());
							if (deniedValues != null) {
								site.arms(deniedValues.stream()
										.map(placement::position)
										.toList(), true);
							}
							BankState out = overwrite(inState,
								fillFromLock(positionedEffect, effectMask & modeMask, lock), effectMask);
							mine.add(new OutElement(pathId, out, out));
						}
						site.mechanism(matchedMechanism);
					}
					else {
						mine.add(new OutElement(pathId, inState, inState));
					}

					// isHelperCallSite, not bare isCall(), is what keeps a BRK-derived IRQ/vector
					// reference out of this whole mechanism (beads grm-htgl, grm-ktne).
					if (helpers != null && isHelperCallSite(instr)) {
						HelperModel helper = calledHelper(program, instr, helpers, mine.get(0).out(),
							bankResolution);
						if (helper != null) {
							calledSites = helper.sites();
							// A store is never a call, so `mine` holds exactly one element here, and
							// its out-state is the in-state.
							mine = applyHelperCall(instr, helper, pathId, mine.get(0).out(), call, lock,
								layoutMask, hintTally);
						}
					}
					outs.addAll(mine);
				}

				if (hintTally != null) {
					// grm-hb6.20: neither a recognized latch store nor a recognized helper call
					if (!hintTally.handled) {
						hintTally.reject("no latch store or bank-switch helper call at this address");
					}
					hintNotes.put(addr, hintTally.note());
				}
				if (site.seen()) {
					SwitchResult sr = site.result();
					switchResults.put(addr, sr);
					// Two kinds of direct site are not census entries (grm-dos9.7; together they made
					// every MMC1 row refuse the lock). A NO_DEPOSIT site writes nothing -- MMC1's shift
					// writes 1-4, a discarded CHR commit -- its "effect" is an echo of the in-state. A
					// HELPER_ARGUMENT site's value is its caller's: the census judges it once per CALL
					// SITE, under that caller's registers, so the body's merged non-answer is not a
					// second, unresolved vote. An ENTRY_SUPPLIED site (grm-dos9.14) is the same
					// argument made per entry.
					if (sr.stop() != BankSwitchStrategy.ValueStop.NO_DEPOSIT &&
						sr.stop() != BankSwitchStrategy.ValueStop.HELPER_ARGUMENT &&
						sr.stop() != BankSwitchStrategy.ValueStop.ENTRY_SUPPLIED) {
						recordModeWrite(modeWrites, addr, sr.effectMask() & modeMask, sr.effect(),
							sr.stop(), site.implicit());
					}
					if (site.implicit()) {
						implicitSites.add(addr);
					}
					else {
						implicitSites.remove(addr);
					}
				}
				if (call.seen()) {
					CallSwitch cs = call.result();
					callSwitches.put(addr, cs);
					recordModeWrite(modeWrites, addr, call.ownedMask() & modeMask, cs.effect(), null,
						false);
					if (calledSites != null) {
						callHelperSites.put(addr, calledSites);
					}
				}

				boolean isCall = instr.getFlowType().isCall();
				for (OutElement out : outs) {
					for (Address flowAddr : instr.getFlows()) {
						if (mapsElsewhere(program, flowAddr, addr, out.out(), bankResolution) ||
							contradictsResidence(program, flowAddr, addr, out.out(), bankResolution,
								residenceInvariantCache)) {
							continue;
						}
						// A fork ends at a function entry: a call target, or a jump onto an entry
						// point (a tail call). The callee sees the merged ROOT state, exactly as
						// the single-state engine gave it.
						PathId to = isCall || budget.isFunctionEntry(flowAddr) ? PathId.ROOT
								: out.pathId();
						mergeAndEnqueue(flowAddr, to, out.out());
					}
					Address fallThrough = instr.getFallThrough();
					// A return the state cannot explain still happens: forget the state, keep the edge
					// (grm-q4ga), so the code after the call is still visited.
					BankState fall = isCall && fallThrough != null &&
						returnsElsewhere(program, listing, fallThrough, out.fall(), bankResolution)
								? BankState.unknown()
								: out.fall();
					if (fallThrough != null &&
						!mapsElsewhere(program, fallThrough, addr, fall,
							bankResolution) &&
						!contradictsResidence(program, fallThrough, addr, fall,
							bankResolution, residenceInvariantCache)) {
						PathId to = budget.isFunctionEntry(fallThrough) ? PathId.ROOT : out.pathId();
						mergeAndEnqueue(fallThrough, to, fall);
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
			if (lock != null) {
				markImplicitCalls(modeWrites, callHelperSites, implicitSites);
				lock = lock.verified(modeWrites);
			}
			return new DataflowResult(merged, switchResults, callSwitches, forkedStates,
				budget.stats(), lock, noLock, hintNotes);
		}

		/**
		 * Recovers the argument a helper call site supplies, with this run's call-site memo, trampoline
		 * map and cross-block proof memo -- the context all three call sites that recover one share.
		 */
		private CallEffect recoverCall(Instruction instr, HelperModel helper, BankState outState,
				RegisterEnv env, StateOracle oracle) {
			return recoverCallArgument(program, instr, helper, outState, callSiteRegCache,
				restoringTrampolines, env, oracle, crossBlockProofMemo);
		}

		/**
		 * The helper-call half of one element's transfer (grm-hum increment 2 and successors; split
		 * out of the main loop by grm-wul so the fork machinery reads the same for a call as for a
		 * direct site). {@code outState} is the state after the call instruction's own effect (the
		 * in-state: a call is never a store). Returns the out-element(s) for the call's fall-through:
		 * one, or one per distinct arm effect when the argument resolved only along the arms of the
		 * join heading this block.
		 */
		private List<OutElement> applyHelperCall(Instruction instr, HelperModel helper,
				PathId pathId, BankState outState, CallTally call, ModeLock lock, int modeMask,
				HintTally hintTally) {
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
					: recoverCall(instr, helper, outState, RegisterEnv.NONE, oracle);
			callEffect = applyBracketClaim(callEffect, addr, bracketClaims, oracle);
			BankStackBrackets.Restore helperRestore =
				bracketClaims.helperRestores().get(helper.function());
			if (helperRestore != null) {
				// a self-contained restoring helper (grm-mej.10, FUN_9169): restore from the state
				// at the call itself, computing the paired field rather than copying it
				callEffect = BankStackBrackets.fold(callEffect, helperRestore, outState);
			}
			if (!shadowCommits.isEmpty()) {
				// bead grm-hb6.26: banking.shadow_commits. Before the bank: value hint, which wins.
				callEffect = ShadowCommits.apply(shadowCommits, hintNotes, callEffect, helper, outState,
					program, instr, oracle, crossBlockProofMemo);
			}
			if (hintTally != null) {
				callEffect = applyCallHint(hintTally, callEffect, helper, outState, instr, oracle);
			}
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
				List<Arm> arms = armsFor(instr);
				if (arms != null) {
					List<CallEffect> perArm = new ArrayList<>();
					List<BankState> perArmValue = evaluateArms(program, listing, arms, env -> {
						CallEffect along = recoverCall(instr, helper, outState, env, oracle);
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
						else if (budget.grant(addr, values.size(),
							ForkBudget.render(values.stream().map(CallEffect::state).toList()))) {
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
			// mechanism window, plus the board's layout-mode field -- see CallSwitch's javadoc.
			BankState mechIn = outState.restrictedTo(helper.effectMask() | modeMask);
			String label = helperLabel(program, helper);
			if (forkEffects != null) {
				List<BankState> afters = new ArrayList<>();
				for (CallEffect arm : forkEffects) {
					BankState fall = overwrite(outState,
						fillFromLock(arm.state(), arm.ownedMask() & modeMask, lock), arm.ownedMask());
					BankState after = overwrite(mechIn, arm.state(), arm.ownedMask());
					afters.add(after);
					outs.add(new OutElement(pathId.with(addr, arm.state()), outState, fall));
					call.add(label, arm.state(), after, true, false, false, null, null);
					call.owned(arm.ownedMask());
				}
				call.arms(afters, false);
				return outs;
			}
			BankState fallState = overwrite(outState,
				fillFromLock(callEffect.state(), callEffect.ownedMask() & modeMask, lock),
				callEffect.ownedMask());
			outs.add(new OutElement(pathId, outState, fallState));
			// grm-9z9t: an unresolved call must not be worded as a failed argument recovery when
			// no recovery was attempted -- see ArgumentSought.
			call.argumentSought(ArgumentSought.of(helper));
			call.add(label, callEffect.state(),
				overwrite(mechIn, callEffect.state(), callEffect.ownedMask()),
				callEffect.argumentResolved(), callEffect.noInboundArgument(),
				callEffect.secondTierRelay(), callEffect.restoreCell(), callEffect.readBack());
			call.owned(callEffect.ownedMask());
			return outs;
		}

		/**
		 * Applies a {@code bank:} hint at a DIRECT latch store (bead grm-hb6.20): when it passes
		 * {@link #fitHint}, the strategy's outcome is REPLACED by a fully known RESOLVED one, and the
		 * values dataflow would have recovered (the plain probe, or along each arm of the join heading
		 * the block when the plain probe blamed us) are noted if they disagree. The caller's arm/fork
		 * logic then sees a resolved site and does nothing. An invalid hint returns {@code plain}
		 * untouched.
		 */
		private BankSwitchStrategy.SwitchOutcome applyStoreHint(HintTally tally,
				BankSwitchStrategy.SwitchOutcome plain, ConfiguredMechanism cm, BankState inState,
				Instruction instr) {
			if (plain.implicit()) {
				tally.reject("the write's deposit is a hardware side effect (a shifter reset), " +
					"not a bank the game chose");
				return plain;
			}
			if (plain.stop() == BankSwitchStrategy.ValueStop.NO_DEPOSIT) {
				tally.reject("the write commits no tracked bank field (a serial-shift write " +
					"before the commit, or a select-data write to an untracked register)");
				return plain;
			}
			MechanismPlacement placement = cm.placement();
			// grm-hb6.22: judged on the bits THIS write deposits, so a multi-field mechanism's store
			// that commits exactly one field (MMC3 R6 after select 6, MMC1's PRG commit) qualifies.
			int deposited = plain.depositMask() == BankSwitchStrategy.SwitchOutcome.WHOLE_MECHANISM
					? cm.effectMask() : placement.positionMask(plain.depositMask());
			HintFit fit = fitHint(tally.bank, deposited, inState, board, bankResolution);
			if (fit.problem() != null) {
				tally.reject(fit.problem());
				return plain;
			}
			// The hinted field in the mechanism's local coordinates; the rest of the outcome is the
			// in-state echo the strategy already computed, and is kept as is.
			BitField local = new BitField(fit.field().lsb() - placement.lsb(), fit.field().width());
			int fieldMask = local.positionedMask();
			List<MechanismState> recovered = new ArrayList<>();
			if (plain.stop() == BankSwitchStrategy.ValueStop.RESOLVED) {
				recovered.add(plain.value());
			}
			else if (unresolvedOurs(plain)) {
				List<Arm> arms = armsFor(instr);
				List<MechanismState> perArm = arms == null ? null
						: evaluateArms(program, listing, arms, env -> {
							Probe along = probeSite(program, instr, inState, mechanisms, matchCache, env);
							return along.outcome() == null ? null : along.outcome().value();
						}, 1);
				if (perArm != null) {
					recovered.addAll(distinct(perArm));
				}
			}
			List<String> differing = new ArrayList<>();
			for (MechanismState r : recovered) {
				MechanismState f = local.extract(r);
				if (((f.bits() ^ tally.bank) & f.knownMask()) != 0) {
					differing.add(renderRecovered(f.knownMask(), f.bits(), local.widthMask()));
				}
			}
			tally.apply(differing);
			MechanismState echo = plain.value();
			return new BankSwitchStrategy.SwitchOutcome(new MechanismState(echo.knownMask() | fieldMask,
				(echo.bits() & ~fieldMask) | local.place(tally.bank)),
				BankSwitchStrategy.ValueStop.RESOLVED, null, false, plain.depositMask());
		}

		/**
		 * Applies a {@code bank:} hint at a CALL to a recognized bank-switch helper (bead grm-hb6.20,
		 * the owner's 2026-10-18 scope ruling): the hint REPLACES the call's argument-derived
		 * {@link CallEffect} with a fully known deposit on the helper's single owned field. The
		 * recovered effect (or, when the argument did not resolve, the per-arm effects) is noted if it
		 * disagrees. An invalid or ambiguous (multi-field) hint returns {@code recovered} untouched.
		 */
		private CallEffect applyCallHint(HintTally tally, CallEffect recovered, HelperModel helper,
				BankState outState, Instruction instr, StateOracle oracle) {
			int owned = recovered.ownedMask();
			HintFit fit = fitHint(tally.bank, owned, outState, board, bankResolution);
			if (fit.problem() != null) {
				tally.reject(owned == 0 ? "the call deposits nothing on a tracked bank field"
						: fit.problem());
				return recovered;
			}
			FieldSpec field = fit.field();
			List<BankState> recoveredStates = new ArrayList<>();
			if (recovered.argumentResolved()) {
				recoveredStates.add(recovered.state());
			}
			else if (helper.constState() == null &&
				!secondTierRelaySites.contains(instr.getMinAddress()) &&
				!recovered.noInboundArgument() && recovered.restoredFrom() == null) {
				List<Arm> arms = armsFor(instr);
				List<BankState> perArm = arms == null ? null
						: evaluateArms(program, listing, arms, env -> {
							CallEffect along = recoverCall(instr, helper, outState, env, oracle);
							return along.argumentResolved() ? along.state() : null;
						}, 1);
				if (perArm != null) {
					recoveredStates.addAll(distinct(perArm));
				}
			}
			List<String> differing = new ArrayList<>();
			for (BankState r : recoveredStates) {
				int known = r.knownMask() & owned;
				int hinted = tally.bank << field.lsb();
				if (((r.bits() ^ hinted) & known) != 0) {
					differing.add(renderRecovered(known >>> field.lsb(), r.bits() >>> field.lsb(),
						field.widthMask()));
				}
			}
			tally.apply(differing);
			return new CallEffect(new BankState(owned, tally.bank << field.lsb()), owned);
		}

		/**
		 * The arms of the control-flow join heading {@code instr}'s block, memoized per address;
		 * {@code null} when the block is not headed by a forkable join (see {@link #joinArms}).
		 */
		private List<Arm> armsFor(Instruction instr) {
			return armCache.computeIfAbsent(instr.getMinAddress(),
				a -> Optional.ofNullable(joinArms(program, listing, instr, Map.of()))).orElse(null);
		}

		/**
		 * The fallback half of the seeding policy (bead grm-dos9.4): called when the worklist has run
		 * dry, it seeds function entries the fixpoint never reached with the power-on state and
		 * reports whether it enqueued anything, so the caller's loop resumes.
		 * <p>
		 * Only entries with NO calling instruction are seeded in a round -- a function some code
		 * calls should get its state from that call, and its caller may simply be another unreached
		 * function that this same round is about to seed. Seeding the callee as well would recreate
		 * exactly the conflict this policy removes: a fully-known power-on seed merged against the
		 * caller's state. When every unreached entry has a caller (a cycle, or callers that are
		 * themselves dead code), the lowest-addressed one is seeded alone, which breaks the cycle
		 * deterministically and guarantees progress: each round gives at least one unreached entry
		 * a state, so the loop ends once every function entry has one -- the same coverage the old
		 * "seed every function up front" policy had.
		 * <p>
		 * A "calling instruction" is any instruction with a flow reference to the entry, or whose
		 * fall-through is the entry. Async entries are already seeded up front and never reach here.
		 */
		private boolean seedUnreachedFunctions(List<Address> functionEntries, BankState seedState) {
			List<Address> unreached = new ArrayList<>();
			for (Address entry : functionEntries) {
				// An entry the seed maps elsewhere is filtered here, not dropped at the merge: a
				// dropped root would leave stateIn without it, so it would be re-picked forever and
				// starve the entries behind it.
				if (!stateIn.containsKey(entry) && listing.getInstructionAt(entry) != null &&
					!mapsElsewhere(program, entry, null, seedState, bankResolution)) {
					unreached.add(entry);
				}
			}
			if (unreached.isEmpty()) {
				return false;
			}
			List<Address> roots = new ArrayList<>();
			for (Address entry : unreached) {
				if (!hasCallingInstruction(program, listing, entry)) {
					roots.add(entry);
				}
			}
			if (roots.isEmpty()) {
				roots.add(unreached.get(0));
			}
			for (Address entry : roots) {
				mergeAndEnqueue(entry, PathId.ROOT, seedState);
			}
			return !worklist.isEmpty();
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
		private void mergeAndEnqueue(Address addr, PathId pathId, BankState incoming) {
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
	}

	/**
	 * One converged write to the layout-mode field (grm-dos9.6): the mode bits the site OWNS,
	 * and the deposit it makes -- merged over its path elements and fork arms, so arms that
	 * disagree leave the bits unknown.
	 */
	record ModeWrite(int ownedMode, BankState effect, BankSwitchStrategy.ValueStop stop,
			boolean implicit) {

		ModeWrite(int ownedMode, BankState effect, BankSwitchStrategy.ValueStop stop) {
			this(ownedMode, effect, stop, false);
		}

		ModeWrite(int ownedMode, BankState effect) {
			this(ownedMode, effect, null);
		}

		boolean resolved() {
			return (effect.knownMask() & ownedMode) == ownedMode;
		}

		/** A KNOWN owned mode bit that differs from the lock: the premise is disproved. */
		boolean contradicts(BankState lock) {
			int known = effect.knownMask() & ownedMode;
			return (effect.bits() & known) != (lock.bits() & known);
		}
	}

	/**
	 * The board's layout-mode field, locked to the one value every reset-reached write gives it
	 * (bead grm-dos9.6; the general form of grm-mej.12's per-game {@code fixed_after_init}).
	 * Most games set the PRG mode once at reset, or rewrite it with every control-register write
	 * but always to the same value. Once the reset path has done that, the mode holds that value
	 * at every later instruction, so async entries and unreached functions are seeded with it
	 * instead of an unknown or power-on mode.
	 * <p>
	 * {@code source} is the lowest-addressed write the lock was formed from. After the whole
	 * fixpoint the lock is re-checked against EVERY mode write ({@link #verified});
	 * {@code contradictions} lists the writes with a KNOWN mode bit that differs from it; a
	 * non-empty list means the lock was wrong, so the engine reruns without it and the analyzer
	 * raises a WARNING at each. {@code assumed} lists the writes whose owned mode bits did not
	 * resolve: per the owner's ruling (2026-10-11) they keep the lock -- see
	 * {@link #fillFromLock} -- and the analyzer NOTEs each as assumed rather than verified.
	 * {@code writes} is the census both were judged against.
	 */
	record ModeLock(BankState state, Address source, List<Address> contradictions,
			List<Address> assumed, Map<Address, ModeWrite> writes) {

		boolean rejected() {
			return !contradictions.isEmpty();
		}

		/** The implicit writes (shifter resets) the explicit ones outvoted (grm-dos9.9). */
		List<Address> outvoted() {
			Map<Address, ModeWrite> voters = modeVoters(writes);
			return new TreeMap<>(writes).keySet().stream()
					.filter(a -> !voters.containsKey(a))
					.toList();
		}

		ModeLock verified(Map<Address, ModeWrite> all) {
			List<Address> bad = new ArrayList<>();
			List<Address> unverified = new ArrayList<>();
			for (Map.Entry<Address, ModeWrite> e : new TreeMap<>(modeVoters(all)).entrySet()) {
				ModeWrite w = e.getValue();
				if (w.contradicts(state)) {
					bad.add(e.getKey());
				}
				else if (!w.resolved()) {
					unverified.add(e.getKey());
				}
			}
			return new ModeLock(state, source, List.copyOf(bad), List.copyOf(unverified),
				Map.copyOf(all));
		}
	}

	/**
	 * Under a lock, a mode write whose owned mode bits did not resolve deposits the LOCKED value
	 * on them (owner ruling 2026-10-11, grm-dos9.6): the lock's premise is that the game never
	 * changes the mode, and a write the analyzer cannot read -- smb2's {@code ff73} loop,
	 * {@code TYA / ORA #$80 / STA $8000} with Y in 0..5, whose bit 6 is always 0 -- is exactly
	 * what the premise covers. Only bits the write owns and left unknown are filled; a known bit
	 * is never overridden, and a known bit that DISAGREES is a contradiction that rejects the
	 * lock instead. The site's own tally keeps the unfilled deposit, so its comment and the
	 * census still say what was actually resolved, and the analyzer NOTEs it as assumed.
	 */
	static BankState fillFromLock(BankState effect, int ownedMode, ModeLock lock) {
		if (lock == null || ownedMode == 0) {
			return effect;
		}
		int unknown = ownedMode & ~effect.knownMask();
		if (unknown == 0) {
			return effect;
		}
		return new BankState(effect.knownMask() | unknown,
			(effect.bits() & ~unknown) | (lock.state().bits() & unknown));
	}

	private static void recordModeWrite(Map<Address, ModeWrite> modeWrites, Address addr,
			int ownedMode, BankState effect, BankSwitchStrategy.ValueStop stop, boolean implicit) {
		if (ownedMode != 0) {
			modeWrites.put(addr, new ModeWrite(ownedMode, effect, stop, implicit));
		}
	}

	/**
	 * Marks a recorded CALL write implicit when every switch site of the helper it calls is an
	 * implicit set (grm-dos9.9): a call to a reset-only helper is a reset, not a mode the game
	 * chose. Re-run before each judgment, since the fixpoint re-records calls as explicit.
	 */
	private static void markImplicitCalls(Map<Address, ModeWrite> modeWrites,
			Map<Address, List<Address>> callHelperSites, Set<Address> implicitSites) {
		callHelperSites.forEach((callAddr, sites) -> {
			ModeWrite w = modeWrites.get(callAddr);
			if (w != null && !w.implicit() && !sites.isEmpty() &&
				implicitSites.containsAll(sites)) {
				modeWrites.put(callAddr, new ModeWrite(w.ownedMode(), w.effect(), w.stop(), true));
			}
		});
	}

	/**
	 * The writes that vote on the lock (owner ruling 2026-10-11, grm-dos9.9): an explicit mode
	 * set trumps an implicit one. When the game writes the field itself anywhere, the hardware's
	 * side-effect deposits (MMC1's shifter reset forcing prg_mode 3) are outvoted -- drmario and
	 * rcproam reset the shifter, then set prg_mode 0 at every control write, and run in mode 0.
	 * The premise is the lock's own: a game runs in one mode, because its ROM organization
	 * depends on it. With no explicit write at all, the implicit ones are all there is, and vote.
	 */
	static Map<Address, ModeWrite> modeVoters(Map<Address, ModeWrite> modeWrites) {
		if (modeWrites.values().stream().allMatch(ModeWrite::implicit)) {
			return modeWrites;
		}
		Map<Address, ModeWrite> explicit = new HashMap<>();
		modeWrites.forEach((a, w) -> {
			if (!w.implicit()) {
				explicit.put(a, w);
			}
		});
		return explicit;
	}

	/**
	 * The lock the converged reset-side census supports, or null: at least one write, every
	 * write's owned mode bits resolved, all of them agreeing, and together covering the whole
	 * field.
	 */
	static ModeLock formModeLock(Map<Address, ModeWrite> modeWrites, int modeMask) {
		return censusModeLock(modeWrites, modeMask).lock();
	}

	/**
	 * The phase-A census's verdict (grm-dos9.7): the lock, or -- when none formed -- WHY, for
	 * the analyzer log. {@code noLock} is null when a lock formed or the board has no
	 * layout-mode field, so there was nothing to explain.
	 */
	record LockCensus(ModeLock lock, String noLock) {}

	/** Reports at most this many unresolved writes by address in a no-lock reason. */
	private static final int NO_LOCK_SITE_LIMIT = 8;

	static LockCensus censusModeLock(Map<Address, ModeWrite> allWrites, int modeMask) {
		if (modeMask == 0) {
			return new LockCensus(null, null);
		}
		Map<Address, ModeWrite> modeWrites = modeVoters(allWrites);
		if (modeWrites.isEmpty()) {
			return new LockCensus(null, "no reset-reached write owns the field");
		}
		int known = 0;
		int bits = 0;
		Address source = null;
		Address firstAt = null;
		List<String> unresolved = new ArrayList<>();
		String disagreement = null;
		for (Map.Entry<Address, ModeWrite> e : new TreeMap<>(modeWrites).entrySet()) {
			ModeWrite w = e.getValue();
			if (!w.resolved()) {
				unresolved.add(e.getKey() + " (owns 0x" + Integer.toHexString(w.ownedMode()) +
					", known 0x" + Integer.toHexString(w.effect().knownMask() & w.ownedMode()) +
					(w.stop() == null ? ", call" : ", " + w.stop()) + ")");
				continue;
			}
			int value = w.effect().bits() & w.ownedMode();
			int overlap = known & w.ownedMode();
			if ((bits & overlap) != (value & overlap)) {
				if (disagreement == null) {
					disagreement = "disagreement: " + e.getKey() + " writes 0x" +
						Integer.toHexString(value & overlap) + " where " + firstAt +
						" and earlier writes gave 0x" + Integer.toHexString(bits & overlap);
				}
				continue;
			}
			known |= w.ownedMode();
			bits |= value;
			if (source == null) {
				source = e.getKey();
				firstAt = source;
			}
		}
		if (!unresolved.isEmpty()) {
			String more = unresolved.size() > NO_LOCK_SITE_LIMIT
					? ", ... (" + (unresolved.size() - NO_LOCK_SITE_LIMIT) + " more)" : "";
			return new LockCensus(null, unresolved.size() + " of " + modeWrites.size() +
				" write(s) leave owned mode bits unresolved: " +
				String.join(", ", unresolved.subList(0,
					Math.min(unresolved.size(), NO_LOCK_SITE_LIMIT))) + more +
				(disagreement == null ? "" : "; also " + disagreement));
		}
		if (disagreement != null) {
			return new LockCensus(null, disagreement);
		}
		if ((known & modeMask) != modeMask) {
			return new LockCensus(null, modeWrites.size() + " agreeing write(s) cover only 0x" +
				Integer.toHexString(known & modeMask) + " of field mask 0x" +
				Integer.toHexString(modeMask));
		}
		return new LockCensus(new ModeLock(new BankState(modeMask, bits & modeMask), source,
			List.of(), List.of(), Map.of()), null);
	}

	/**
	 * Folds a verified RAM bank-stack bracket (bead grm-mej.10, {@link BankStackBrackets}) into
	 * a helper call's effect.
	 * <p>
	 * At a verified POP the fields the pop restores take the tracked state AT THE MATCHING PUSH
	 * (the oracle's merged in-state there: a bracket whose entry bank was unknown deposits an
	 * unknown, never a made-up value), and the call keeps its ordinary effect on every other
	 * field. The deposit counts as resolved only when every OTHER owned bit was already known --
	 * a pop whose own select/mode writes were unrecoverable still warns.
	 * <p>
	 * At a PUSH belonging to a verified bracket, the bank argument it could not recover is the
	 * bracket's private business: the bank it installs lasts only until the pop. The deposit is
	 * kept (the in-bracket state really is unknown) but the call is not reported as a failed
	 * argument recovery, provided the only unknown owned bits are the fields the push helper's
	 * data commits write.
	 */
	static CallEffect applyBracketClaim(CallEffect effect, Address addr,
			BankStackBrackets.Claims claims, StateOracle oracle) {
		if (claims.isEmpty()) {
			return effect;
		}
		BankStackBrackets.Pop pop = claims.pops().get(addr);
		if (pop != null) {
			return BankStackBrackets.fold(effect, pop.restore(), oracle.stateAt(pop.pushSite()));
		}
		Integer pushFields = claims.privatePushes().get(addr);
		if (pushFields != null && !effect.argumentResolved() && effect.ownedMask() != 0 &&
			(effect.ownedMask() & ~effect.state().knownMask() & ~pushFields) == 0) {
			return effect.withResolved(true);
		}
		return effect;
	}

	/**
	 * One hinted site's evaluation within a single dequeue (bead grm-hb6.20), merged over the
	 * address's path elements: {@code handled} once the site was recognized as a latch store or a
	 * helper call (whether or not the hint then turned out valid), {@code applied} if ANY element
	 * took the hint, {@code differing} the renderings of recovered values the hint overrode.
	 */
	private static final class HintTally {

		private final int bank;
		private boolean handled;
		private boolean applied;
		private String problem;
		private final Set<String> differing = new LinkedHashSet<>();

		HintTally(int bank) {
			this.bank = bank;
		}

		void reject(String why) {
			handled = true;
			if (problem == null) {
				problem = why;
			}
		}

		void apply(List<String> overridden) {
			handled = true;
			applied = true;
			differing.addAll(overridden);
		}

		SwitchSiteHints.HintNote note() {
			return new SwitchSiteHints.HintNote(bank, applied, applied ? null : problem,
				applied && !differing.isEmpty() ? String.join(" | ", differing) : null);
		}
	}

	/** A hint checked against a deposit's field: the field it targets, or why it cannot. */
	private record HintFit(FieldSpec field, String problem) {}

	/**
	 * The cheap self-consistency checks a {@code bank:} hint must pass at a deposit owning
	 * {@code ownedMask} (bead grm-hb6.20; never a re-run of the analysis):
	 * <ol>
	 * <li>the deposit is a SINGLE bank field -- exactly one board field, and the deposit covers
	 * all of it. A deposit touching several fields (a field plus mode bits; MMC3's R6 and R7)
	 * cannot be attributed one bank number, so it is ambiguous and the hint is not applied;</li>
	 * <li>the bank number fits the field's width;</li>
	 * <li>the window can hold it: the state after the deposit is asked of
	 * {@link BankAnnotationAdapter#impossibleBank} against the realized-bank universe -- the very
	 * test that would reject the same bank were dataflow to recover it -- when the caller has that
	 * universe ({@code bankResolution} non-null).</li>
	 * </ol>
	 */
	private static HintFit fitHint(int bank, int ownedMask, BankState inState, BoardModel board,
			HelperDiscovery.BankResolution bankResolution) {
		FieldSpec field = null;
		for (FieldSpec f : board.fieldSpecs()) {
			if ((f.positionedMask() & ownedMask) == 0) {
				continue;
			}
			if (field != null) {
				return new HintFit(null, "the deposit spans more than one bank field (" +
					field.name() + ", " + f.name() + "), so one bank number is ambiguous");
			}
			field = f;
		}
		if (field == null) {
			return new HintFit(null, "the deposit owns no tracked bank field");
		}
		if (field.positionedMask() != ownedMask) {
			return new HintFit(null, "the deposit covers only part of field '" + field.name() +
				"', so one bank number is ambiguous");
		}
		if (!isBankField(board, field)) {
			return new HintFit(null, "field '" + field.name() + "' is not a bank any window maps " +
				"by (a select or mode field), so a bank number has no referent");
		}
		if (bank < 0 || bank > field.widthMask()) {
			return new HintFit(null, "bank " + bank + " does not fit field '" + field.name() +
				"' (" + field.width() + " bit(s), 0.." + field.widthMask() + ")");
		}
		if (bankResolution != null) {
			BankAnnotationAdapter.Impossible impossible = BankAnnotationAdapter.impossibleBank(
				board, overwrite(inState, new BankState(ownedMask, bank << field.lsb()), ownedMask),
				bankResolution.bankUniverse());
			if (impossible instanceof BankAnnotationAdapter.ImpossibleBank bad) {
				return new HintFit(null, "bank " + bank + " is not one this window can hold: " +
					"the image provides only " + bad.realized() + " bank(s) for " + bad.window());
			}
			if (impossible != null) {
				return new HintFit(null, "bank " + bank + " is not one this window can hold: " +
					"no layout reachable here provides a slice for it");
			}
		}
		return new HintFit(field, null);
	}

	/**
	 * Whether {@code field} is one a banked window maps by (bead grm-hb6.22): what keeps a
	 * {@code bank:} hint off a multi-field mechanism's select index (MMC3's {@code select}) or
	 * mode bits once a store may name a single field. A board declaring no banked window at all
	 * (CNROM's CHR-only latch, the unit tests' bare boards) has nothing to test against, so every
	 * field passes, exactly as before.
	 */
	private static boolean isBankField(BoardModel board, FieldSpec field) {
		boolean anyBanked = false;
		for (ComputedWindowModel w : board.computedWindows().values()) {
			if (w.field() != null) {
				anyBanked = true;
				if (w.field().name().equals(field.name())) {
					return true;
				}
			}
		}
		for (ModeWindowModel w : board.modeWindows()) {
			if (w.bankField() != null) {
				anyBanked = true;
				if (w.bankField().name().equals(field.name())) {
					return true;
				}
			}
		}
		return !anyBanked;
	}

	/** A recovered field value for a hint diagnostic: the bank number, or what little is known. */
	private static String renderRecovered(int knownMask, int bits, int fieldMask) {
		return (knownMask & fieldMask) == fieldMask ? Integer.toString(bits & fieldMask)
				: "partly known: bits 0x" + Integer.toHexString(bits & knownMask) +
					" of mask 0x" + Integer.toHexString(knownMask);
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
				MechanismState localIn = cm.placement().toLocal(inState);
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
		MechanismState localIn = mech.placement().toLocal(inState);
		return new Probe(mech, mech.strategy().computeSwitchOutcome(program, instr, localIn, env));
	}

	/**
	 * One straight-line step of the direct-switch transfer function, outside the fixpoint: the
	 * state after {@code instr} given the state before it, applying the first mechanism whose
	 * strategy recognizes the instruction exactly as the main loop does (probe in field-local
	 * coordinates, then {@code overwrite} the mechanism's own bits with the positioned result).
	 * An instruction no mechanism recognizes leaves the state as it was; a recognized switch
	 * whose value is unrecovered makes the mechanism's bits unknown. Calls (helper effects) are
	 * NOT modelled -- callers of this walk stop at a call. Used by {@link BankContext}.
	 */
	static BankState applyDirectSwitch(Program program, Instruction instr, BankState inState,
			List<ConfiguredMechanism> mechanisms) {
		Probe probe = probeSite(program, instr, inState, mechanisms, new HashMap<>(),
			RegisterEnv.NONE);
		if (probe.mechanism() == null || probe.outcome() == null) {
			return inState;
		}
		ConfiguredMechanism cm = probe.mechanism();
		return overwrite(inState, cm.placement().position(probe.outcome().value()),
			cm.effectMask());
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
	private static <T extends BitKnowledge> List<T> distinct(List<T> states) {
		List<T> out = new ArrayList<>();
		for (T s : states) {
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
	 * Walks back from {@code from} along the path {@code base} describes to the instruction the
	 * value scan would have stopped at, and, if that instruction is a control-flow join with at
	 * least two enumerable predecessors, returns one arm per predecessor: {@code base} extended
	 * with {@code join -> predecessor}. {@code null} otherwise.
	 * <p>
	 * A join is FORKABLE only when every incoming edge is a known jump, branch or fall-through
	 * from a disassembled instruction, and the join is not a function entry point. A CALL
	 * reference means the block is entered by callers, whose context is not an arm; an edge from
	 * an undisassembled address means the walk could not soundly continue along it. An edge from
	 * another function's body is an arm like any other (bead grm-dos9.11: a store tail shared by
	 * several entries). A block start with a SINGLE known
	 * predecessor is deliberately not enumerated: the value scan refuses such a boundary today
	 * for its linkage rule, not the join rule, and lifting that is a separate question from this
	 * bead's (a two-armed merge). Unresolved computed jumps leave no reference and are invisible
	 * here, exactly as they are to {@code FlowEdges.isControlFlowJoin} and to this
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
		// Predecessor enumeration under the closed-world rules is shared with
		// CrossBlockStackPairing.crossBlockMatchingPush (bead grm-mej.3 increment X1), which needs
		// the identical rule -- flow refs + fall-through only, no call references into the span,
		// every predecessor disassembled, never crossing a function entry -- for its own
		// ALL-PATHS backward search. This method's own extra requirement (at least two
		// predecessors -- a fork needs two arms; a single-predecessor boundary is the value
		// scan's separate linkage refusal) is checked here, after the shared call.
		//
		// A predecessor in ANOTHER function is admitted (bead grm-dos9.11), as the cross-block
		// search already does (grm-mej.21). The case is a store tail shared by several entries:
		// cv3's e2d6 LDA #$87 / BNE e2dc and e2da LDA #$9e both reach e2dc STA $5116, and Ghidra
		// gives the tail to one function only, so one edge always looks cross-function. An arm
		// is a claim about the path through that edge, never about a caller's context: every
		// rule a walk along it applies (refuse at a function entry, refuse at a call reference)
		// still holds at each node it reaches, so the arm resolves only when its own straight
		// line defines the value, exactly as a same-function arm does.
		List<Address> preds =
			CrossBlockStackPairing.closedWorldPredecessors(program, listing, headAddr, true);
		if (preds == null || preds.size() < 2) {
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
	private static <T extends BitKnowledge> List<T> evaluateArms(Program program, Listing listing,
			List<Arm> arms, java.util.function.Function<RegisterEnv, T> eval, int depth) {
		if (arms.size() > MAX_ARMS_SCANNED) {
			return null;
		}
		List<T> values = new ArrayList<>();
		for (Arm arm : arms) {
			T value = eval.apply(RegisterEnv.onArms(arm.preds()));
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
			List<T> below = evaluateArms(program, listing, nested, eval, depth + 1);
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
		 * answer for a site is its answer forever. {@code renderedValues} (from {@link #render})
		 * is only for the log, so the value type -- board or field-local -- never matters here.
		 */
		boolean grant(Address site, int k, String renderedValues) {
			if (granted.containsKey(site)) {
				return true;
			}
			if (denied.contains(site)) {
				return false;
			}
			Function f = fm.getFunctionContaining(site);
			int used = perFunction.getOrDefault(f, 0);
			String where = "site " + site + " in " + (f == null ? "(no function)" : f.getName());
			String what = k + " arm values " + renderedValues;
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

		static String render(List<? extends BitKnowledge> values) {
			StringBuilder sb = new StringBuilder("{");
			for (BitKnowledge v : values) {
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
		// grm-dos9.9: every element's deposit was a hardware side effect (an MMC1 shifter reset),
		// not a value the game wrote. One explicit element makes the site explicit.
		private boolean implicit = true;

		boolean seen() {
			return mechanism != null;
		}

		boolean implicit() {
			return effect != null && implicit;
		}

		void mechanism(ConfiguredMechanism m) {
			mechanism = m;
		}

		void add(BankState positioned, BankSwitchStrategy.ValueStop s) {
			add(positioned, s, null, false);
		}

		void add(BankState positioned, BankSwitchStrategy.ValueStop s,
				StoredValueScanner.ReadBack read, boolean implicitDeposit) {
			implicit &= implicitDeposit;
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

	/**
	 * Whether a helper call looked for a caller argument at all (bead grm-9z9t), so the analyzer
	 * can word an unresolved call honestly. Only {@link #SOUGHT} makes "the bank argument could
	 * not be recovered at this call site" true; the other two never attempted a recovery.
	 */
	enum ArgumentSought {
		/** Argument recovery ran (whatever it found). */
		SOUGHT,
		/**
		 * The helper model has no argument register: its switch sites do not agree on one
		 * mechanism and stored register (rtk2's {@code FUN_f55f} writes three different MMC5
		 * PRG registers), its site is not a plain register store (an INC/DEC read-modify-write),
		 * or it was composed through a tail call. {@code recoverCallArgument} short-circuits on
		 * that before consulting any caller state. The analyzer's wording names only the null
		 * register, never which of these caused it.
		 * <p>
		 * NOT reported for a per-site strategy whose sites merely store from different registers
		 * (grm-fekc, MMC3's {@code STY $8000 / STA $8001}): that model is recovered site by site
		 * under the caller's registers, so recovery does run -- see
		 * {@link HelperDiscovery.HelperModel#recoversPerSiteWithoutArgReg}.
		 */
		NO_ARGUMENT_REGISTER,
		/**
		 * The strategy does not consume a helper argument (memory-latch re-derives the value
		 * inside the helper under the caller's registers instead) -- see
		 * {@link BankSwitchStrategy#consumesHelperArgument()}.
		 */
		RE_DERIVED_IN_HELPER;

		static ArgumentSought of(HelperModel helper) {
			if (helper.argReg() == null && !helper.recoversPerSiteWithoutArgReg()) {
				return NO_ARGUMENT_REGISTER;
			}
			if (helper.strategy() != null && !helper.strategy().consumesHelperArgument()) {
				return RE_DERIVED_IN_HELPER;
			}
			return SOUGHT;
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
		private ArgumentSought argumentSought = ArgumentSought.SOUGHT;
		private StoredValueScanner.ReadBack readBack;
		private List<BankState> arms = List.of();
		private boolean armsDenied;
		private int ownedMask;

		boolean seen() {
			return helperName != null;
		}

		/**
		 * grm-dos9.6: the bits this call site OWNS, which its effect cannot tell apart from bits
		 * it merely failed to resolve -- the mode-lock census needs the difference.
		 */
		void owned(int mask) {
			ownedMask |= mask;
		}

		int ownedMask() {
			return ownedMask;
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

		/** grm-9z9t: why, if at all, this call never looked for a caller argument. */
		void argumentSought(ArgumentSought sought) {
			argumentSought = sought;
		}

		CallSwitch result() {
			return new CallSwitch(helperName, effect, stateAfter, argumentResolved,
				noInboundArgument, secondTierRelay, restoreCell, readBack, arms, armsDenied,
				argumentSought);
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
	 * Asked ONLY for a site whose own deposit recovered nothing and that the strategy already
	 * called our limitation (its value may still echo other in-state fields, grm-dos9.10), so
	 * it can never overwrite a {@code RESOLVED} or a reason the strategy established positively --
	 * and the VALUE recorded is phase one's regardless, so nothing here can move a bank number.
	 * The default {@link BankSwitchStrategy#classifyHelperBodyGap} answers
	 * {@code ANALYZER_LIMIT}, so a strategy that has not opted in behaves exactly as before.
	 */
	private static BankSwitchStrategy.ValueStop classifyGap(Program program, Instruction instr,
			BankState inState, ConfiguredMechanism mech,
			BankSwitchStrategy.SwitchOutcome outcome, Map<Function, HelperModel> helpers) {
		// The stop, not value.knownMask(), says whether the site recovered anything: a deposit
		// outcome's value can carry echoed in-state bits it did not recover (grm-dos9.10).
		if (helpers == null || outcome.stop() != BankSwitchStrategy.ValueStop.ANALYZER_LIMIT) {
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
		MechanismState localIn = mech.placement().toLocal(inState);
		BankSwitchStrategy.ValueStop stop =
			mech.strategy().classifyHelperBodyGap(program, instr, localIn, helper.entry());
		if (stop == BankSwitchStrategy.ValueStop.ANALYZER_LIMIT &&
			everyArmJudgedElsewhere(program, instr, localIn, mech, containing, helper, helpers)) {
			return BankSwitchStrategy.ValueStop.ENTRY_SUPPLIED;
		}
		return stop;
	}

	/**
	 * Whether a helper-body site's register scan stops at a JOIN of several helper entries, each
	 * of whose values is judged at that entry's own call sites (bead grm-dos9.14). The site is
	 * then {@code ENTRY_SUPPLIED}: like a single-entry helper's {@code HELPER_ARGUMENT}, the census
	 * judges its value once per call site, never as the body's merged non-answer.
	 * <p>
	 * Bionic Commando's PRG chain is the case. {@code dcaa STA $E000} heads a five-write chain
	 * and is reached three ways: by falling through from {@code FUN_dca8}'s {@code LDA $65} (a
	 * proven no-argument restore, reported RESTORED at its callers), by {@code FUN_dcbe}'s
	 * {@code STA $65 / JMP dcaa} (a call-edge wrapper), and by {@code FUN_d6e2}'s lone
	 * {@code JMP dcaa} (a relay thunk). One arm per incoming edge ({@link #joinArms}), and EVERY
	 * arm must qualify:
	 * <ul>
	 * <li>An arm from another function is the wrapper's relay or a one-instruction thunk; the
	 * strategy's scan along it, stopping at that function's entry, must reach the entry with the
	 * register undefined; and that entry must be judged ({@link #judgedEntry}).</li>
	 * <li>An arm from the helper's own body must be the helper's own entry instruction, the
	 * helper must be a proven restore ({@link HelperArgumentRecovery#restoreSourceCell}: that
	 * instruction reloads the register from a RAM cell and falls straight into the join), the
	 * strategy's scan must reach the join with the register undefined, and the entry must be
	 * judged.</li>
	 * </ul>
	 * Any other arm -- code that sets the register itself and jumps in -- is a value nobody
	 * judges, so the site keeps its warning.
	 */
	private static boolean everyArmJudgedElsewhere(Program program, Instruction instr,
			MechanismState localIn, ConfiguredMechanism mech, Function containing,
			HelperModel helper, Map<Function, HelperModel> helpers) {
		List<Arm> arms = joinArms(program, program.getListing(), instr, Map.of());
		if (arms == null) {
			return false;
		}
		FunctionManager fm = program.getFunctionManager();
		for (Arm arm : arms) {
			Address pred = arm.tip();
			Function from = fm.getFunctionContaining(pred);
			if (from == null) {
				return false;
			}
			BankSwitchStrategy strategy = mech.strategy();
			if (from.equals(containing)) {
				// The restore proof covers the entry's load reaching the join directly; the scan
				// stopping AT the join proves nothing redefines the register from the join to
				// where the strategy reads it. (The load itself scans ANALYZER_LIMIT by design --
				// a cell the image stores to is a parameter latch, grm-rr5p -- so its stop is
				// not the test.)
				Address join = arm.preds().keySet().iterator().next();
				if (!pred.equals(helper.entry()) || helper.argReg() == null ||
					HelperArgumentRecovery.restoreSourceCell(program, helper,
						helper.argReg()) == null ||
					!judgedEntry(program, helper.entry(), 0) ||
					strategy.classifyHelperBodyArm(program, instr, localIn, join,
						arm.preds()) != BankSwitchStrategy.ValueStop.HELPER_ARGUMENT) {
					return false;
				}
				continue;
			}
			Address entry = relayEntry(program, from, pred, helpers);
			if (entry == null || !judgedEntry(program, entry, 0) ||
				strategy.classifyHelperBodyArm(program, instr, localIn, entry,
					arm.preds()) != BankSwitchStrategy.ValueStop.HELPER_ARGUMENT) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The entry whose callers supply the register on an arm arriving from {@code pred} in
	 * function {@code from}, or null: a call-edge wrapper's entry when {@code pred} is its relay,
	 * or {@code pred} itself when {@code from} is nothing but that one jump (a relay thunk, which
	 * {@link HelperDiscovery#reachableEntries} follows from every call to it).
	 */
	private static Address relayEntry(Program program, Function from, Address pred,
			Map<Function, HelperModel> helpers) {
		HelperModel wrapper = helpers.get(from);
		if (wrapper != null && wrapper.relay() != null && wrapper.relay().callSite().equals(pred)) {
			return wrapper.entry();
		}
		Instruction jump = program.getListing().getInstructionAt(pred);
		if (from.getEntryPoint().equals(pred) && jump != null &&
			from.getBody().getMaxAddress().equals(jump.getMaxAddress()) &&
			HelperDiscovery.isTailJump(jump, from)) {
			return pred;
		}
		return null;
	}

	/** How many relay thunks {@link #judgedEntry} follows back from an entry. */
	private static final int MAX_JUDGED_RELAY_DEPTH = 4;

	/**
	 * Whether every way into {@code entry} is a call the analysis judges: each incoming flow is a
	 * CALL, or a jump from a relay thunk whose own entry is judged in turn; and no instruction
	 * falls through into it. A plain jump from other code, or a fall-through, is a path whose
	 * register value nothing judges.
	 */
	private static boolean judgedEntry(Program program, Address entry, int depth) {
		if (depth > MAX_JUDGED_RELAY_DEPTH) {
			return false;
		}
		Listing listing = program.getListing();
		Instruction before = listing.getInstructionBefore(entry);
		if (before != null && FlowEdges.fallsInto(before, entry)) {
			return false;
		}
		FunctionManager fm = program.getFunctionManager();
		boolean any = false;
		for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
			RefType type = ref.getReferenceType();
			if (!type.isFlow()) {
				continue;
			}
			any = true;
			if (type.isCall()) {
				continue;
			}
			Function thunk = fm.getFunctionContaining(ref.getFromAddress());
			Instruction jump = listing.getInstructionAt(ref.getFromAddress());
			if (thunk == null || jump == null ||
				!thunk.getEntryPoint().equals(ref.getFromAddress()) ||
				!HelperDiscovery.isTailJump(jump, thunk) ||
				!judgedEntry(program, thunk.getEntryPoint(), depth + 1)) {
				return false;
			}
		}
		return any;
	}

	/**
	 * Folds a mechanism's positioned effect into a base state: bits inside {@code mask}
	 * take the effect's knowledge (whether known or not), every other bit keeps whatever
	 * {@code base} already knew. {@code effect}'s known bits are always a subset of
	 * {@code mask} by construction ({@link MechanismPlacement#position} masks to it), so this is a clean
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
	 * Whether {@code instr} can be a call site of a bank-switch helper: its flow is a call,
	 * and not a COMPUTED jump that a flow override promoted to one (beads grm-htgl, grm-ktne).
	 * <p>
	 * BRK's p-code is {@code goto [*:2 0xfffe]} and {@code JMP (P)}'s is {@code goto [P]}:
	 * computed jumps, in both Ghidra's stock 6502.slaspec and this repo's 6510 sinc. But
	 * {@code getFlowType()} is not fixed at disassembly -- it applies the instruction's
	 * {@code FlowOverride}. On a read-only PRG image constant propagation resolves the vector
	 * read and adds a COMPUTED_JUMP reference to the IRQ or RESET handler, and when that
	 * handler is a function entry and the jump sits outside any function, Ghidra's
	 * SharedReturnAnalysisCmd sets CALL_RETURN on it, turning the flow into
	 * COMPUTED_CALL_TERMINATOR. deadly_towers (BNROM) showed the cost: IRQ = RESET = fcfa, which
	 * stores bank 0, so ~30 filler $00 bytes in bank 2's data each became "bank -> 0 via fcfa".
	 * <p>
	 * A computed target is a property of memory at run time, not of the instruction, so a
	 * promoted computed jump is never a helper call -- the same rule
	 * {@code HelperDiscovery}'s relay test applies. A DIRECT {@code JMP helper} that
	 * SharedReturn promoted is a real tail call and stays a call site.
	 */
	static boolean isHelperCallSite(Instruction instr) {
		FlowType flow = instr.getFlowType();
		if (!flow.isCall()) {
			return false;
		}
		return !(flow.isComputed() && instr.getFlowOverride() != FlowOverride.NONE);
	}

	/**
	 * Whether a base-space {@code target} is NOT the byte that runs under {@code state}
	 * (bead grm-dos9.5). Base space holds each banked window's HOME occupant only; when the
	 * state fully pins the window to another bank or mode, the CPU executes that occupant's
	 * overlay copy at this offset, and the base bytes there never run under it. Feeding them
	 * the state anyway let base-space filler (a $00 = BRK in bank 0 under a mode that maps the
	 * last bank) retarget its IRQ jump into phantom overlays (nesmodetest 8040 -> c010).
	 * <p>
	 * Mirrors {@code BankAnnotationAdapter.retargetForState}'s rule for retiring the base
	 * reference: only dataflow KNOWLEDGE counts (no placement override -- a guess must not
	 * starve code), and a flow from a base instruction into its OWN window stays, since a
	 * routine duplicated into every bank reaches its own bytes whatever bank is live.
	 * {@code from} is null for a seed. The overlay copy gets its state from the retargeted
	 * reference on the next analyzer round.
	 * <p>
	 * An occupant that is not the home one can still map the SAME image byte -- e.g. MMC1's 32K
	 * mode 0 with bank 0 selects exactly the slices a mode-3 home layout put in base space. The
	 * base byte is then the one that runs, so it keeps the state.
	 */
	static boolean mapsElsewhere(Program program, Address target, Address from,
			BankState state, HelperDiscovery.BankResolution ctx) {
		if (ctx == null || target.getAddressSpace().isOverlaySpace()) {
			return false;
		}
		BankAnnotationAdapter.OffsetResolution r = BankAnnotationAdapter.resolveOffsetOccupant(
			ctx.board(), ctx.bankUniverse(), state, target.getOffset(), Map.of());
		if (r == null || !r.fullyKnown() || r.home()) {
			return false;
		}
		if (from != null && !from.getAddressSpace().isOverlaySpace() &&
			BankAnnotationAdapter.sameWindow(ctx.board(), state, from.getOffset(),
				target.getOffset())) {
			return false;
		}
		// No realized overlay (a stated layout mode suppressed the others' blocks -- drmario's
		// gmap) leaves the state nowhere else to go: keep it, as retargeting keeps the base
		// reference when it cannot place an overlay one.
		AddressSpace overlay = program.getAddressFactory().getAddressSpace(r.space());
		return overlay != null &&
			!sameImageByte(program, target, overlay.getAddress(target.getOffset()));
	}

	/**
	 * Whether a CALL's base-space fall-through cannot be where the call returns under
	 * {@code state} (bead grm-q4ga). {@link #mapsElsewhere} exempts a flow within the caller's own
	 * window, because sequential code that switches its own window runs on into the live bank. A
	 * call's fall-through is not sequential: RTS lands on whatever the live bank holds at that
	 * offset. When the state pins the window to an occupant whose bytes there differ from the base
	 * instruction's, the base instruction never runs under that state. The state is then the
	 * engine's mistake (the callee restored the bank on a path it cannot see), so none of its bits
	 * can be trusted. The caller forgets it but keeps the edge: dropping the edge instead left
	 * everything after deadly_towers' far calls unvisited (instrs.inOverlay 4549 -> 1393).
	 * deadly_towers: {@code JSR $fc2a} switches to bank 2 and dispatches through a
	 * table, and each handler returns through {@code fc54}, which stores bank 0. Without this guard,
	 * bank 2 reached base {@code 8484 JMP $85a9}, which was retargeted onto bank 2's zero filler.
	 * <p>
	 * A routine duplicated byte for byte in every bank (as these trampolines are) still returns
	 * into its own bytes, so equal bytes keep the flow. The overlay side needs no twin: there
	 * {@link #clampToResidence} already forces the caller's own bank.
	 */
	static boolean returnsElsewhere(Program program, Listing listing, Address fallThrough,
			BankState state, HelperDiscovery.BankResolution ctx) {
		if (ctx == null || fallThrough.getAddressSpace().isOverlaySpace()) {
			return false;
		}
		BankAnnotationAdapter.OffsetResolution r = BankAnnotationAdapter.resolveOffsetOccupant(
			ctx.board(), ctx.bankUniverse(), state, fallThrough.getOffset(), Map.of());
		if (r == null || !r.fullyKnown() || r.home()) {
			return false;
		}
		AddressSpace overlay = program.getAddressFactory().getAddressSpace(r.space());
		Instruction landing = listing.getInstructionAt(fallThrough);
		if (overlay == null || landing == null) {
			return false;
		}
		Address copy = overlay.getAddress(fallThrough.getOffset());
		if (sameImageByte(program, fallThrough, copy)) {
			return false;
		}
		try {
			byte[] base = landing.getBytes();
			byte[] other = new byte[base.length];
			if (program.getMemory().getBytes(copy, other) != other.length) {
				return true;
			}
			return !Arrays.equals(base, other);
		}
		catch (MemoryAccessException e) {
			return true; // nothing readable there: the base instruction is not what runs
		}
	}

	/**
	 * Whether an OVERLAY {@code target} is NOT the byte that runs under {@code state} -- the
	 * overlay-side mirror of {@link #mapsElsewhere} (bead grm-dos9.12). Without it such a flow
	 * (a base reference kept beside its overlay sibling, an overlay reference placed for one fork
	 * arm and followed by every arm) reached {@link #clampToResidence}, which overwrote the
	 * window's bits and merged a path that cannot execute there in with the real ones.
	 * <p>
	 * Decided by occupant, not by raw bits, so a bank number the image wraps (MMC3's r7=44 on a
	 * 32-bank ROM selects bank 12) still reaches its overlay. Same exemptions as
	 * {@code mapsElsewhere}: a flow from the target's own window stays (code that switches its
	 * own window runs on into whatever bank is now live), and so does an occupant backed by the
	 * same image byte.
	 * <p>
	 * A PARTLY known state (grm-dos9.13) cannot name the occupant that runs, so it is tested
	 * against {@link #residenceInvariant} instead: only the bits wrap cannot alias. Since the
	 * occupant is unknown, the same-image-byte exemption is taken whenever ANY other space backs
	 * this offset with the target's byte.
	 */
	static boolean contradictsResidence(Program program, Address target, Address from,
			BankState state, HelperDiscovery.BankResolution ctx,
			Map<String, int[]> invariantCache) {
		AddressSpace space = target.getAddressSpace();
		if (ctx == null || !space.isOverlaySpace()) {
			return false;
		}
		if (from != null && BankAnnotationAdapter.sameWindow(ctx.board(), state,
			from.getOffset(), target.getOffset())) {
			return false;
		}
		BankAnnotationAdapter.OffsetResolution r = BankAnnotationAdapter.resolveOffsetOccupant(
			ctx.board(), ctx.bankUniverse(), state, target.getOffset(), Map.of());
		if (r != null && r.fullyKnown()) {
			AddressSpace runs = r.home() ? space.getPhysicalSpace()
					: program.getAddressFactory().getAddressSpace(r.space());
			if (runs == null || runs.equals(space)) {
				return false;
			}
			return !sameImageByte(program, target, runs.getAddress(target.getOffset()));
		}
		int[] inv = invariantCache.computeIfAbsent(space.getName(),
			name -> residenceInvariant(name, ctx));
		if (inv.length == 0 || (state.knownMask() & inv[0] & (state.bits() ^ inv[1])) == 0) {
			return false;
		}
		return !imageByteBackedElsewhere(program, target);
	}

	/**
	 * {@code {mask, bits}}: the part of {@code overlayName}'s residence that bank wrap cannot
	 * alias, or an empty array for an overlay that pins nothing. The mode field never wraps; of a
	 * bank field, only the decoded bits {@link BankAnnotationAdapter#canonicalBank} preserves --
	 * applied to an all-ones value, it returns exactly that mask (the truncation's {@code n-1},
	 * an explicit {@code bank_wrap}, or every bit where the guard declines), so the wrap rule
	 * lives in one place. {@link #clampToResidence}'s mask is the unwrapped superset.
	 */
	private static int[] residenceInvariant(String overlayName,
			HelperDiscovery.BankResolution ctx) {
		BoardModel board = ctx.board();
		for (ComputedWindowModel w : board.computedWindows().values()) {
			Integer v = OverlayNaming.parseBankValue(w.name(), overlayName);
			if (v != null) {
				int mask = wrapInvariantBits(board, ctx.bankUniverse().get(w.name()), w.field(),
					w.decodedMask());
				return new int[] { mask, w.field().pos().place(v) & mask };
			}
		}
		FieldSpec modeField = board.modeField();
		if (modeField == null) {
			return new int[0];
		}
		Set<String> windowNames = new LinkedHashSet<>();
		for (ModeWindowModel w : board.modeWindows()) {
			windowNames.add(w.name());
		}
		for (String windowName : windowNames) {
			OverlayNaming.ModeBank mb =
				OverlayNaming.parseModeBankValue(windowName, overlayName);
			if (mb != null) {
				ModeWindowModel instance = BankAnnotationAdapter
					.findModeWindowInstance(board.modeWindows(), windowName, mb.mode());
				if (instance == null || instance.bankField() == null) {
					continue;
				}
				int bankMask = wrapInvariantBits(board, ctx.bankUniverse().get(
					BankAnnotationAdapter.modeBankKey(windowName, mb.mode())),
					instance.bankField(), instance.decodedMask());
				return new int[] { modeField.positionedMask() | bankMask,
					modeField.pos().place(mb.mode()) |
						(instance.bankField().pos().place(mb.bank()) & bankMask) };
			}
			Integer mv = OverlayNaming.parseModeValue(windowName, overlayName);
			if (mv != null) {
				return new int[] { modeField.positionedMask(), modeField.pos().place(mv) };
			}
		}
		return new int[0];
	}

	/** Positioned bits of {@code field} that select the same image whatever wrap does. */
	private static int wrapInvariantBits(BoardModel board, Set<Integer> realized, FieldSpec field,
			long decodedMask) {
		int full = (int) BoardDescriptorModel.fullMask(field);
		int kept = BankAnnotationAdapter.canonicalBank(board.bankWrap(), realized, full);
		return field.pos().place(kept & (int) decodedMask);
	}

	/**
	 * Whether some OTHER space realizes {@code target}'s offset from the same image byte -- the
	 * occupant-agnostic form of the same-image-byte exemption, for a state too partly known to
	 * name its occupant.
	 */
	private static boolean imageByteBackedElsewhere(Program program, Address target) {
		FileByte fb = fileByte(program, target);
		if (fb == null) {
			return true; // cannot tell -- keep the flow
		}
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			AddressSpace s = block.getStart().getAddressSpace();
			if (s.equals(target.getAddressSpace())) {
				continue;
			}
			Address a;
			try {
				a = s.getAddress(target.getOffset());
			}
			catch (AddressOutOfBoundsException e) {
				continue;
			}
			if (block.contains(a) && fb.equals(fileByte(program, a))) {
				return true;
			}
		}
		return false;
	}

	/** Whether two addresses are backed by the same byte of the same loaded file. */
	private static boolean sameImageByte(Program program, Address a, Address b) {
		FileByte fa = fileByte(program, a);
		return fa != null && fa.equals(fileByte(program, b));
	}

	private record FileByte(FileBytes source, long offset) {}

	private static FileByte fileByte(Program program, Address addr) {
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null) {
			return null;
		}
		for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
			if (info.contains(addr) && info.getFileBytes().isPresent()) {
				long offset = info.getFileBytesOffset(addr);
				return offset < 0 ? null : new FileByte(info.getFileBytes().get(), offset);
			}
		}
		return null;
	}

	private static boolean hasCallingInstruction(Program program, Listing listing, Address entry) {
		for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
			if (ref.getReferenceType().isFlow() &&
				listing.getInstructionAt(ref.getFromAddress()) != null) {
				return true;
			}
		}
		Instruction before = listing.getInstructionBefore(entry);
		return before != null && FlowEdges.fallsInto(before, entry);
	}


	/**
	 * Execution implies mapping: an instruction physically inside a computed window's
	 * bank overlay {@code WINDOW_B<n>} can only be running while that window's field
	 * holds {@code n}, so those bits are forced known regardless of what flowed in.
	 * (Idempotent and deterministic per address, so the fixpoint still terminates.)
	 */
	static BankState clampToResidence(Address addr, BankState state, BoardModel board,
			Map<String, int[]> clampCache) {
		AddressSpace space = addr.getAddressSpace();
		if (!space.isOverlaySpace()) {
			return state;
		}
		int[] clamp = clampCache.computeIfAbsent(space.getName(), name -> {
			for (ComputedWindowModel w : board.computedWindows().values()) {
				Integer v = OverlayNaming.parseBankValue(w.name(), name);
				if (v != null) {
					// Pin only the bits the window decodes (grm-5dgx); ignored bits stay as
					// they arrived -- execution inside the overlay never constrains them.
					FieldSpec f = w.field();
					int decoded = (int) w.decodedMask() << f.lsb();
					return new int[] { decoded, f.pos().place(v) & decoded };
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
					OverlayNaming.ModeBank mb =
						OverlayNaming.parseModeBankValue(windowName, name);
					if (mb != null) {
						ModeWindowModel instance = BankAnnotationAdapter
							.findModeWindowInstance(board.modeWindows(), windowName, mb.mode());
						if (instance != null && instance.bankField() != null) {
							FieldSpec bankField = instance.bankField();
							int bankDecoded = (int) instance.decodedMask() << bankField.lsb();
							int posMask = modeField.positionedMask() | bankDecoded;
							int posBits = modeField.pos().place(mb.mode()) |
								(bankField.pos().place(mb.bank()) & bankDecoded);
							return new int[] { posMask, posBits };
						}
						continue;
					}
					Integer mv = OverlayNaming.parseModeValue(windowName, name);
					if (mv != null) {
						return new int[] { modeField.positionedMask(), modeField.pos().place(mv) };
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
	 * {@link BankSwitchStrategy.ValueStop#RESOLVED} whenever the site recovered a bit of its own
	 * deposit (any other known bit of {@code effect} is an in-state echo, grm-dos9.10, so the
	 * stop and not {@code effect.knownMask()} is the test), and is what lets an annotator tell
	 * a gap that is HONEST (the value really is
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

		/** Where the mechanism that produced this result sits in the board state. */
		MechanismPlacement placement() {
			return new MechanismPlacement(lsb, effectMask);
		}

		/** The pre-grm-wul form: no arms. */
		SwitchResult(BankState effect, int effectMask, int lsb, BankSwitchStrategy strategy,
				BankSwitchStrategy.ValueStop stop) {
			this(effect, effectMask, lsb, strategy, stop, null, List.of(), false);
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
	 * fields as assumed, exactly as it always did -- with ONE exception (bead grm-dos9.3): the
	 * board's layout-mode field is always echoed too. On a mode-varying board the mode decides
	 * WHICH window a bank field feeds, so it is part of the meaning of every bank write; cv3's
	 * {@code e03d} (MMC5, where {@code $5100} and {@code $5116} are separate mechanisms) rendered
	 * {@code prg_mode} as "assumed from initial" although the dataflow knew it was 2. The
	 * analyzer renders {@code stateAfter} only when the call's own effect knows something, so
	 * the echoed mode can never turn a call that resolved nothing into a comment.
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
			boolean armsDenied, ArgumentSought argumentSought) {

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
	 * {@code hintNotes} (bead grm-hb6.20) holds, per site a game descriptor's {@code bank:} value
	 * hint named, what the engine's FINAL evaluation of that site did with it; empty when the
	 * descriptor states no value hint.
	 */
	record DataflowResult(Map<Address, BankState> stateIn,
			Map<Address, SwitchResult> switchResults, Map<Address, CallSwitch> callSwitches,
			Map<Address, List<BankState>> forkedStates, ForkStats forkStats, ModeLock modeLock,
			String noModeLock, Map<Address, SwitchSiteHints.HintNote> hintNotes) {

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
