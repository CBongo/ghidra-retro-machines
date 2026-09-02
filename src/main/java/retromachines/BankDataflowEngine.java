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
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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
 */
final class BankDataflowEngine {

	private BankDataflowEngine() {
	}

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

		Map<Address, BankState> stateIn = new HashMap<>();
		Map<Address, SwitchResult> switchResults = new HashMap<>();
		Map<Address, CallSwitch> callSwitches = new HashMap<>();
		Deque<Address> worklist = new ArrayDeque<>();
		Map<String, int[]> clampCache = new HashMap<>();
		// Scoped to this runDataflow call (not a field): phase 1/2 separation guarantees no
		// instruction appears mid-fixpoint, so per-call scoping sidesteps any staleness
		// question. See the strategy-probe loop below for the soundness invariant this relies
		// on (grm-5tl.13.2).
		Map<Address, MatchInfo> matchCache = new HashMap<>();
		// Likewise scoped to this runDataflow call: the A/X/Y a helper call site supplies
		// (grm-hum increment 2). Purely an efficiency memo -- but a necessary one: without it,
		// three backward scans plus a strategy's mini-inline would rerun on EVERY dequeue of
		// every helper call address across the whole fixpoint. Mega Man (25 switch sites, a
		// large fixpoint) is where that bites.
		//
		// The memoized value is a function of (program, call address, HELPER MODEL) -- the model
		// entered the signature with grm-k90's prologue filter and crossable join, where it had
		// previously been (program, call address) alone. Keying on the address only is still
		// correct, and the reason is worth stating rather than assuming: one call instruction
		// dispatches to exactly one callee, and the helper map is FIXED before runDataflow begins
		// (phase 1/2 separation, same invariant matchCache above relies on), so within one
		// fixpoint a given call address resolves to one and only one model. The three scans
		// themselves remain state-independent -- they use NO_HOOKS and never consult tracked
		// state -- and argumentSurvivesPrologue is a pure function of the listing.

		Map<Address, RegisterEnv> callSiteRegCache = new HashMap<>();

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
			mergeAndEnqueue(seed, entryState, stateIn, worklist, listing, board, clampCache);
		}

		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Address addr = worklist.poll();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			BankState inState = stateIn.get(addr);
			BankState outState = inState;

			// Strategy-probe memoization (grm-5tl.13.2): both shipped strategies gate
			// computeSwitch on an instruction-only predicate (MemoryLatch's writesInRange,
			// RegisterWrite's writesMechanism) that fully determines whether the result is
			// null -- neither ever returns null for an instruction its predicate accepts, so
			// "which mechanism matches this address" (if any) does not depend on inState, only
			// the *value* a non-cacheable match produces does. That lets us cache the matched
			// mechanism's identity per address across dequeues and, on a cache hit, either reuse
			// a cacheable strategy's state-independent result outright or re-probe only the one
			// non-cacheable strategy that matched -- never the others, and never re-run the
			// whole ordered loop. A future strategy whose match/no-match outcome genuinely
			// depends on inState would violate this; the fallback below (treat an unexpected
			// null from the cached strategy as no-match for this dequeue, rather than
			// re-probing every strategy) stays conservative in that case instead of unsound.
			//
			// Every strategy computes in its mechanism's field-local [0, width) coordinate
			// space, never the board's absolute state bits: the in-state handed to
			// computeSwitch is narrowed to that mechanism's effectMask/lsb, and a non-null
			// result is positioned back into absolute bits before it touches stateIn.
			MatchInfo cached = matchCache.get(addr);
			ConfiguredMechanism matchedMechanism;
			// The strategy's answer now carries WHY an unrecovered value did not resolve (bead
			// grm-3ou part 1). It rides the existing match cache unchanged: the stop reason is a
			// property of the very recovery that produced the value, so anything already safe to
			// cache as a value is safe to cache with its reason attached.
			BankSwitchStrategy.SwitchOutcome switchedLocal;
			if (cached == null) {
				ConfiguredMechanism matched = null;
				BankSwitchStrategy.SwitchOutcome result = null;
				for (ConfiguredMechanism cm : mechanisms) {
					BankState localIn = toFieldLocal(inState, cm.lsb(), cm.effectMask());
					result = cm.strategy().computeSwitchOutcome(program, instr, localIn);
					if (result != null) {
						matched = cm;
						break;
					}
				}
				matchedMechanism = matched;
				switchedLocal = matched == null ? null : result;
				matchCache.put(addr, new MatchInfo(matched,
					matched != null && matched.strategy().cacheable() ? result : null));
			}
			else if (cached.mechanism() == null) {
				// no strategy's instruction-level predicate matches this address
				matchedMechanism = null;
				switchedLocal = null;
			}
			else if (cached.result() != null) {
				// cacheable strategy matched before; its result here is state-independent
				matchedMechanism = cached.mechanism();
				switchedLocal = cached.result();
			}
			else {
				// non-cacheable strategy matched before; only it can match here, re-probe it
				// alone with the current in-state
				matchedMechanism = cached.mechanism();
				BankState localIn =
					toFieldLocal(inState, matchedMechanism.lsb(), matchedMechanism.effectMask());
				switchedLocal =
					matchedMechanism.strategy().computeSwitchOutcome(program, instr, localIn);
			}
			if (switchedLocal != null) {
				// Fold: this mechanism's switch REPLACES only the bits it owns (effectMask),
				// preserving whatever the rest of the tracked state already knew about other
				// mechanisms' fields. For a single-mechanism board effectMask covers every
				// tracked bit, so this reduces exactly to the old whole-state replace.
				BankState positionedEffect =
					position(switchedLocal.value(), matchedMechanism.lsb(),
						matchedMechanism.effectMask());
				switchResults.put(addr, new SwitchResult(positionedEffect,
					matchedMechanism.effectMask(), matchedMechanism.lsb(),
					matchedMechanism.strategy(),
					classifyGap(program, instr, inState, matchedMechanism, switchedLocal,
						helpers)));
				outState = overwrite(inState, positionedEffect, matchedMechanism.effectMask());
			}

			BankState fallState = outState;
			if (helpers != null && instr.getFlowType().isCall()) {
				HelperModel helper = calledHelper(program, instr, helpers);
				if (helper != null) {
					CallEffect callEffect = helper.constState() != null
							? new CallEffect(helper.constState(), helper.effectMask())
							: recoverCallArgument(program, instr, helper, outState,
								callSiteRegCache, restoringTrampolines);
					// ownedMask == 0 means this call site is a verified no-op on every tracked
					// bit -- a serial-shift helper whose switch site targets an unconfigured CHR
					// register, or (grm-mej.3) a save/restore trampoline proved to put the entry
					// bank back before returning -- so skip both the fold (a no-op regardless, since
					// callEffect.state()'s knownMask is always a subset of ownedMask by
					// construction) and the annotation, so a provably-inert call gets neither a
					// misleading "bank -> ?" comment nor a spurious WARNING bookmark.
					if (callEffect.ownedMask() != 0) {
						fallState = overwrite(outState, callEffect.state(), callEffect.ownedMask());
						// The annotation state echoes the in-state only within the helper's own
						// mechanism window -- see CallSwitch's javadoc.
						BankState mechIn = new BankState(outState.knownMask() & helper.effectMask(),
							outState.bits() & helper.effectMask());
						callSwitches.put(addr, new CallSwitch(helperLabel(program, helper),
							callEffect.state(),
							overwrite(mechIn, callEffect.state(), callEffect.ownedMask())));
					}
				}
			}

			for (Address flowAddr : instr.getFlows()) {
				mergeAndEnqueue(flowAddr, outState, stateIn, worklist, listing, board, clampCache);
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough != null) {
				mergeAndEnqueue(fallThrough, fallState, stateIn, worklist, listing, board,
					clampCache);
			}
		}
		return new DataflowResult(stateIn, switchResults, callSwitches);
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

	private static void mergeAndEnqueue(Address addr, BankState incoming,
			Map<Address, BankState> stateIn, Deque<Address> worklist, Listing listing,
			BoardModel board, Map<String, int[]> clampCache) {
		if (listing.getInstructionAt(addr) == null) {
			// not (yet) disassembled / not code -- nothing to track here
			return;
		}
		BankState existing = stateIn.get(addr);
		BankState merged = existing == null ? incoming : BankState.merge(existing, incoming);
		merged = clampToResidence(addr, merged, board, clampCache);
		if (existing == null || !merged.equals(existing)) {
			stateIn.put(addr, merged);
			worklist.add(addr);
		}
		// else: unchanged, already processed with this exact state -- nothing to do
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
	 * One recognized switch site's positioned effect (grm-ezl): {@code effect} is the pure
	 * effect of the mechanism that matched here -- positioned into absolute state bits, but
	 * <em>not</em> folded against any in-state -- kept separately from the folded
	 * {@code stateIn} because annotation and helper-classification key off the pure effect,
	 * not the composite. {@code effectMask}/{@code lsb} identify which mechanism produced it
	 * (the same pair as the matching {@link ConfiguredMechanism}), so downstream consumers
	 * (helper classification, call-argument recovery) know which bits it's authoritative
	 * over without re-deriving it from the descriptor. {@code strategy} is the matched
	 * mechanism's own strategy instance, carried through so a helper call site can later
	 * ask it to position a recovered argument via
	 * {@link BankSwitchStrategy#depositHelperArgument} instead of the engine guessing.
	 */
	/**
	 * A recognized direct switch at one address. {@code stop} says WHY {@code effect} did
	 * not resolve when it did not (bead {@code grm-3ou} part 1) -- it is
	 * {@link BankSwitchStrategy.ValueStop#RESOLVED} whenever any bit of {@code effect} is
	 * known, and is what lets an annotator tell a gap that is HONEST (the value really is
	 * runtime-determined, or is the caller's argument) from one that is OUR LIMITATION.
	 */
	record SwitchResult(BankState effect, int effectMask, int lsb,
			BankSwitchStrategy strategy, BankSwitchStrategy.ValueStop stop) {}

	/**
	 * A resolved call-site switch (for annotation, distinct from direct switches).
	 * {@code effect} is the call's own recovered deposit (positioned, known bits limited to
	 * what the argument scan resolved of the bits this call site owns) -- the WARN decision
	 * keys off it, exactly as a direct switch warns off its pure effect. {@code stateAfter}
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
	 */
	record CallSwitch(String helperName, BankState effect, BankState stateAfter) {}

	record DataflowResult(Map<Address, BankState> stateIn,
			Map<Address, SwitchResult> switchResults, Map<Address, CallSwitch> callSwitches) {}
}
