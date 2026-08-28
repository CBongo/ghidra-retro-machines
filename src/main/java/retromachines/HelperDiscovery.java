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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import static retromachines.BankDataflowEngine.overwrite;
import static retromachines.HelperArgumentRecovery.argumentSurvivesPrologue;
import static retromachines.HelperArgumentRecovery.prologueSegments;

import retromachines.BankDataflowEngine.SwitchResult;

/**
 * Helper-function <em>discovery</em>: recognizing which functions are bank-switch helpers,
 * composing tail-call chains so a helper's modeled effect reflects its RETURN rather than only
 * its own body, admitting pass-through and call-edge wrapper functions into the helper map, and
 * resolving a call instruction's actual target through Ghidra thunks and relay trampolines.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Helper-call propagation" section (bead
 * grm-shnf, QR-12 increment 3b), split three ways along the section's natural fault lines --
 * {@link HelperArgumentRecovery} (per-call-site argument recovery and its prologue-preservation
 * machinery) and {@link SaveRestoreTrampolines} (save/restore no-op detection) are its siblings.
 * The three-way cut retains the compile-time verbatim argument the four prior QR-12 increments
 * established: an instance-state survey found zero {@code this.} references anywhere in the
 * section and zero non-static instance fields on {@code BoardBankAnalyzer} at all, and grm-shnf's
 * own step 2 had already made every method in it {@code static} -- so cutting the section into
 * three classes changes no behavior, only which file a given static member lives in.
 *
 * <p>This class holds {@link #findHelpers}, the {@link #composeTailCalls} cluster
 * ({@code exitEffect}/{@code composeWithCallee}/{@code agreeOrDecline}/{@code TailEffect} are one
 * recursive unit and were not split further), pass-through and call-edge wrapper recognition
 * ({@link #findPassThroughWrappers}/{@link #isPassThroughInto}/{@link #findCallEdgeWrappers}),
 * and relay walking ({@link #reachableEntries}/{@link #relayTarget}/{@link #helperLabel}/
 * {@link #calledHelper}/{@link #midBodyEntryHelper}) -- plus {@link HelperModel} itself (the
 * per-helper summary every one of those methods builds or re-keys) and its call-edge
 * {@link Relay}. {@code BoardBankAnalyzer.added()} reaches {@link #findHelpers},
 * {@link #composeTailCalls}, {@link #findPassThroughWrappers} and {@link #findCallEdgeWrappers}
 * via {@code import static}; {@link BankDataflowEngine} and {@code BankAnnotationAdapter} reach
 * {@link #calledHelper}/{@link #helperLabel}/{@link #reachableEntries} the same way, and
 * {@link HelperModel} via a nested-type import, mirroring the pattern increments 1-5 established
 * for {@code BoardBankAnalyzer}'s other split-out records.
 *
 * <p>One residual cross-class edge, costing an import and nothing more:
 * {@link #findCallEdgeWrappers} calls {@link HelperArgumentRecovery#argumentSurvivesPrologue} and
 * {@link HelperArgumentRecovery#prologueSegments}, both static package-private predicates in the
 * sibling class.
 */
final class HelperDiscovery {

	private HelperDiscovery() {
	}

	/**
	 * Every function containing a recognized mechanism write is a bank-switch helper. This
	 * deliberately misses a real shape: a pass-through wrapper that writes no mechanism of
	 * its own and simply falls through into the function that does (Castlevania 2's
	 * {@code FUN_c183 -> FUN_c185 -> FUN_c187}, TMNT's {@code FUN_cea5 -> FUN_cea7}, Wizards
	 * & Warriors' AxROM {@code $ce89 -> $ce8b}). {@link #findPassThroughWrappers} admits
	 * those into the map afterward, by re-keying rather than by relaxing this containment
	 * rule.
	 * <p>
	 * When all of a helper's switch results are fully known and agree, calling it
	 * unconditionally produces that state; otherwise the helper's effect depends on its
	 * caller (bank-argument convention) and is recovered per call site.
	 * <p>
	 * A helper's sites all belonging to the same mechanism (the common case, and the only
	 * case on every shipped board) merge exactly as before, keyed off that mechanism's
	 * {@code effectMask}/{@code lsb}. A helper whose sites belong to <em>different</em>
	 * mechanisms (e.g. one function that can be reached with either a bank-mechanism write
	 * or a mode-mechanism write on different call paths) degrades conservatively: the
	 * const/register agreement is dropped ({@code constState = argReg = null}, forcing
	 * per-call-site {@link HelperArgumentRecovery#recoverCallArgument} which itself returns unknown without an
	 * argument register) and {@code effectMask} becomes the union of every site's mask, so
	 * the caller-side unknown-effect fold in {@link BankDataflowEngine#runDataflow} wipes every field this
	 * helper might touch rather than under- or mis-covering it.
	 * <p>
	 * <b>Two of the rules below became load-bearing in new ways with grm-hum increment 2</b>,
	 * and neither needed a code change for it -- which is worth saying out loud, because both
	 * are now depended on by a path they were not written for:
	 * <ul>
	 * <li><b>{@code constState} disagreement -&gt; {@code null}</b> (just below) is what routes a
	 * multi-site helper into per-call recovery <em>at all</em>. Mega Man's {@code FUN_d846}
	 * switches to bank 6, then to a loop-carried unknown, then back to 6; those three disagree,
	 * so the helper has no constant effect and every call site is recovered individually. Had
	 * they agreed, the mini-inline would never run.</li>
	 * <li><b>The max-address {@code switchSite} rule</b> (see the comment on it below) now
	 * decides which site a <em>memory-latch</em> multi-site helper commits through, not just
	 * which sub-field a serial-shift chain selects: it is the site
	 * {@link BankSwitchStrategy#depositHelperArgument} mini-inlines. That picks the right site
	 * <em>inside the body</em> for {@code FUN_d846}, whose last site by address ({@code $D88D},
	 * the post-loop restore) is also the last one its body executes. <b>It is a heuristic, and
	 * address order is not execution order in general</b> -- a helper whose exit path branches
	 * backward to an earlier switch would be committed to the wrong site by it. Nothing shipped
	 * does that today; a helper that did would need real terminal-site analysis rather than a
	 * max(). And "inside the body" is a real qualifier, not a formality: {@code FUN_d846} then
	 * tail-jumps to {@code FUN_c3b3}, so the bank live at its RETURN is 5 rather than the 6
	 * {@code $D88D} deposits -- see {@link #composeTailCalls}, which is what makes the
	 * body-local answer safe to build here.</li>
	 * </ul>
	 * <p>
	 * The map this returns is post-processed by {@link #composeTailCalls} before anything sees
	 * it, because the body-local answer is not the whole answer: see that method for why a
	 * helper's effect is the state at its RETURN, not at the last write in its own body.
	 */
	// Package-private (not private): BoardBankAnalyzer.added() reaches this via
	// import static (grm-shnf step 3).
	static Map<Function, HelperModel> findHelpers(Program program,
			Map<Address, SwitchResult> switchResults) {
		Map<Function, HelperModel> helpers = new LinkedHashMap<>();
		for (Map.Entry<Address, SwitchResult> entry : switchResults.entrySet()) {
			Function f = program.getFunctionManager().getFunctionContaining(entry.getKey());
			if (f == null) {
				continue;
			}
			SwitchResult site = entry.getValue();
			BankState result = site.effect();
			Instruction store = program.getListing().getInstructionAt(entry.getKey());
			Character reg = store == null ? null : StoredValueScanner.storeRegister(store);

			HelperModel existing = helpers.get(f);
			if (existing == null) {
				helpers.put(f, new HelperModel(f, f.getEntryPoint(),
					result.knownMask() == site.effectMask() ? result : null, reg,
					site.effectMask(), site.lsb(), site.strategy(), entry.getKey(),
					entry.getKey(), null));
			}
			else if (existing.effectMask() == site.effectMask() && existing.lsb() == site.lsb()) {
				BankState constState = existing.constState() != null
						&& !existing.constState().equals(result) ? null : existing.constState();
				Character argReg = Objects.equals(existing.argReg(), reg) ? reg : null;
				// When several instructions in this helper share the same mechanism (e.g. a
				// serial-shift chain's 5 stores), the switch site that decides WHICH sub-field
				// a call-site argument commits through is the one whose own address encodes
				// that decision. What we actually want is THE LAST RECOGNIZED WRITE ON THE PATH
				// TO THIS HELPER'S RETURN; the highest-address one is a PROXY for that, and the
				// proxy is only valid while control cannot leave the function body -- see
				// HelperModel.switchSite's javadoc and composeTailCalls, which repairs the one
				// way control routinely does leave it (a tail call). Within the body the proxy
				// holds for every idiom this engine recognizes: the last write in program order
				// is an unrolled chain's write-5 STA, or a counted loop's closing BNE, both of
				// which sit after their chain's earlier writes. Keeping the max-address entry is
				// a no-op for every single-instruction mechanism (register-write, memory-latch:
				// exactly one site per helper) and picks the correct commit site for
				// serial-shift.
				Address switchSite = entry.getKey().compareTo(existing.switchSite()) > 0
						? entry.getKey() : existing.switchSite();
				// The mirror of the max above, and NOT a proxy for anything: the lowest-addressed
				// site is exactly what midBodyEntryHelper needs to decide whether entering
				// somewhere other than the top still runs every site this model summarizes.
				Address firstSite = entry.getKey().compareTo(existing.firstSite()) < 0
						? entry.getKey() : existing.firstSite();
				helpers.put(f, new HelperModel(f, f.getEntryPoint(), constState, argReg,
					site.effectMask(), site.lsb(), site.strategy(), switchSite, firstSite,
					null));
			}
			else {
				// Sites in this helper belong to different mechanisms -- degrade to the
				// conservative union (see javadoc above). argReg is forced null, so
				// recoverCallArgument short-circuits before ever consulting strategy/
				// switchSite -- both left null/unset is safe. firstSite goes with them: a null
				// there makes midBodyEntryHelper decline, which is the right answer for a model
				// that no longer describes one coherent mechanism.
				helpers.put(f, new HelperModel(f, f.getEntryPoint(), null, null,
					existing.effectMask() | site.effectMask(), 0, null, null, null, null));
			}
		}
		return helpers;
	}

	/**
	 * Depth cap for {@link #composeTailCalls}' fixpoint. Real chains are one or two links
	 * (Mega Man's {@code FUN_d846 -> FUN_c3b3} is one); the cap exists so a pathological
	 * chain declines instead of running away, alongside the visited-set cycle guard in
	 * {@link #exitEffect}.
	 * <p>
	 * <b>This javadoc used to cite Mega Man's {@code FUN_f105} (which tail-jumps to ITSELF at
	 * {@code $F10F}) as what made the cycle guard non-hypothetical. That was wrong</b>, measured
	 * while writing grm-432's coverage. Ghidra's {@code SharedReturnAnalysisCmd} explicitly
	 * SKIPS a jump whose containing function's entry is the jump target ("just an internal jump
	 * reference to the top of the function"), so a self-{@code JMP} never receives
	 * {@code CALL_RETURN}, never becomes {@code CALL_TERMINATOR}, and so is never terminal --
	 * which means {@link #exitInstructions} never yields it and the cycle guard is never reached
	 * by that route at all. {@code FUN_f105} does not exercise this guard.
	 * <p>
	 * The guard is still load-bearing and still correct: a cycle of TWO OR MORE functions is
	 * presented normally, each tail {@code JMP} landing on a different function's entry, and
	 * reaches {@code !onStack.add(f)} exactly as intended. That mutual shape is what
	 * {@code nesuxhelpertest}'s {@code PingA}/{@code PingB} pair and
	 * {@code TailCallCompositionProgramTest} pin. Note the depth cap BACKSTOPS the cycle guard
	 * -- deleting the cycle check alone still terminates, by running to depth 9 and declining
	 * there -- so the two must be covered by distinguishing which branch is taken, not by
	 * deleting one and watching for a hang.
	 */
	private static final int MAX_TAIL_CALL_DEPTH = 8;

	/**
	 * Round cap for {@link #findPassThroughWrappers}'s fixpoint. This is a POLICY bound, not
	 * a termination crutch -- termination is already STRUCTURAL: each round only admits a
	 * wrapper strictly BELOW, in address order, the model it wraps ({@code
	 * isPassThroughInto} requires the wrapper's body to fall straight through into
	 * {@code model.entry()}), and the result map's keys dedupe, so nothing can be
	 * re-admitted or looped on. Castlevania 2's three-function stack
	 * ({@code FUN_c183 -> FUN_c185 -> FUN_c187}) is the deepest chain measured on any
	 * shipped board.
	 */
	private static final int MAX_WRAPPER_CHAIN = 3;

	/**
	 * Re-summarizes every helper whose control flow LEAVES ITS BODY by a tail call, so its
	 * modeled effect is the bank state at its RETURN rather than at the last recognized write
	 * inside its own body (bead grm-hum increment 2b).
	 * <p>
	 * <b>The defect this repairs shipped wrong answers.</b> {@link #findHelpers} summarizes a
	 * helper by the max-address recognized write in its own body, which is a sound proxy for
	 * "the last write before the return" only while control cannot leave that body. A tail call
	 * is exactly when it can. On Mega Man, {@code FUN_d131}'s only own site is
	 * {@code $D135 STA $C006}, so it modeled as a constant bank 6 and every call to it folded
	 * bank 6 -- but it ends {@code $D159 JMP $C3B3}, and {@code FUN_c3b3} latches bank 5, so the
	 * live bank after the call is 5. {@code FUN_d846} and {@code FUN_c55d} tail-jump to the same
	 * routine with the same consequence.
	 * <p>
	 * <b>This is a SUMMARY fix, not a dataflow fix.</b> {@link BankDataflowEngine#runDataflow} already treats a
	 * {@code CALL_TERMINATOR} jump as a call ({@code getFlowType().isCall()} is true for it --
	 * Ghidra's shared-return analysis rewrites a jump to another function's entry that way) and
	 * already folds the callee helper's effect there, so the tracked state at the end of these
	 * functions was right all along. Only {@link HelperModel} discarded it.
	 * <p>
	 * <b>The rule is NARROWED, not replaced.</b> A helper with no tail call to a recognized
	 * helper is returned completely untouched, so the max-address summary keeps deciding
	 * every case it was already right about -- a serial-shift chain's commit site, and the
	 * restore-before-RTS trampolines in {@code nesbanktest2}, whose last write really is the
	 * last one executed. A tail call to a function this engine does not model as a helper is
	 * likewise a no-op, which is exactly what {@link BankDataflowEngine#runDataflow} folds for a call to one.
	 * <p>
	 * <b>Where it composes:</b> a tail-callee that is a recognized helper with a
	 * caller-independent effect (its own {@code constState}, or one it composes to) overwrites
	 * the bits it owns on top of the caller's own deposit -- callee wins on its own bits, which
	 * is just {@link BankDataflowEngine#overwrite}. When the callee owns every bit the caller's body could touch,
	 * the composite is caller-independent even if the caller's body alone was not; that is Mega
	 * Man's {@code FUN_d846}, whose own three sites disagree (6 / loop-carried unknown / 6) yet
	 * whose exit is unconditionally {@code FUN_c3b3}'s bank 5.
	 * <p>
	 * <b>Everywhere else it DECLINES</b> -- returns a helper owning the mechanism with no
	 * recovered value, which yields a WARNING bookmark at each call site instead of an
	 * annotation. That covers a caller-dependent tail-callee, several exits whose composed
	 * effects disagree, a cycle, and the depth cap. Losing an annotation beats shipping a wrong
	 * bank; that is the whole point of this pass.
	 */
	// Package-private (not private) so TailCallCompositionProgramTest (grm-432) can drive the
	// four DECLINE branches directly against a hand-built helper map -- the same precedent as
	// HelperModel and SaveRestoreTrampolines.restoresEntryBank, and the only reachable seam: everything above this in
	// added() needs a board descriptor and a real import, which is the Tier 3 tier. No behavior
	// change: every other member keeps its own visibility.
	static Map<Function, HelperModel> composeTailCalls(Program program,
			Map<Function, HelperModel> helpers) {
		Map<Function, HelperModel> composed = new LinkedHashMap<>(helpers);
		for (Function f : helpers.keySet()) {
			TailEffect effect = exitEffect(program, f, helpers, new LinkedHashSet<>(), 0);
			if (!effect.composed()) {
				continue; // no tail call out of this body -- the body-local summary stands
			}
			// argReg/strategy/switchSite are deliberately dropped: they describe the helper's
			// OWN body, which is no longer what this model asserts. A composed constant needs
			// none of them (runDataflow uses constState directly), and a decline needs none
			// either (recoverCallArgument short-circuits on the null argReg).
			composed.put(f, new HelperModel(f, f.getEntryPoint(), effect.constState(), null,
				effect.effectMask(), 0, null, null, null, null));
		}
		return composed;
	}

	/**
	 * One helper's composed exit effect. {@code declined} means "no value may be asserted for
	 * this helper" (the caller must warn); otherwise a null {@code constState} means the effect
	 * is caller-dependent and the body-local {@link HelperModel} still describes it.
	 * {@code composed} records whether a tail call to a recognized helper actually contributed
	 * -- when it is false the helper must be left exactly as {@link #findHelpers} built it.
	 */
	private record TailEffect(BankState constState, int effectMask, boolean declined,
			boolean composed) {}

	/**
	 * The effect {@code f} leaves behind when it returns to ITS caller, following tail calls.
	 * See {@link #composeTailCalls} for the rules; {@code onStack} is the cycle guard and
	 * {@code depth} the bound.
	 */
	private static TailEffect exitEffect(Program program, Function f, Map<Function, HelperModel> helpers,
			Set<Function> onStack, int depth) {
		HelperModel model = helpers.get(f);
		int ownMask = model.effectMask();
		if (depth > MAX_TAIL_CALL_DEPTH || !onStack.add(f)) {
			return new TailEffect(null, ownMask, true, true);
		}
		try {
			TailEffect merged = null;
			boolean sawHelperTailCall = false;
			for (Instruction exit : exitInstructions(program, f)) {
				HelperModel callee = exit.getFlowType().isCall()
						? calledHelper(program, exit, helpers)
						: null;
				TailEffect here;
				if (callee == null) {
					// RTS/RTI, or a tail call to a function this engine does not model as a
					// bank-switch helper -- the same no-op runDataflow folds for a call to one.
					here = new TailEffect(model.constState(), ownMask, false, false);
				}
				else {
					sawHelperTailCall = true;
					here = composeWithCallee(model,
						exitEffect(program, callee.function(), helpers, onStack, depth + 1));
				}
				merged = merged == null ? here : agreeOrDecline(merged, here, ownMask);
			}
			if (merged == null || !sawHelperTailCall) {
				return new TailEffect(model.constState(), ownMask, false, false);
			}
			return merged;
		}
		finally {
			onStack.remove(f);
		}
	}

	/** {@code model}'s own deposit with its tail-callee's laid over the bits the callee owns. */
	private static TailEffect composeWithCallee(HelperModel model, TailEffect callee) {
		int ownMask = model.effectMask();
		int union = ownMask | callee.effectMask();
		if (callee.declined() || callee.constState() == null) {
			// nothing assertable about the callee, so nothing assertable about this helper
			return new TailEffect(null, union, true, true);
		}
		if (model.constState() != null) {
			return new TailEffect(overwrite(model.constState(), callee.constState(),
				callee.effectMask()), union, false, true);
		}
		if ((callee.effectMask() & ownMask) == ownMask) {
			// The callee overwrites every bit this helper's own body could touch, so whatever
			// the body did with them is irrelevant and the composite is caller-independent even
			// though the body alone was not. Mega Man's FUN_d846 lands here.
			return new TailEffect(callee.constState(), union, false, true);
		}
		return new TailEffect(null, union, true, true);
	}

	/** Two exits' composed effects when they agree, a decline owning both masks when they don't. */
	private static TailEffect agreeOrDecline(TailEffect a, TailEffect b, int ownMask) {
		int union = a.effectMask() | b.effectMask() | ownMask;
		if (!a.declined() && !b.declined() && a.effectMask() == b.effectMask() &&
			Objects.equals(a.constState(), b.constState())) {
			return new TailEffect(a.constState(), a.effectMask(), false,
				a.composed() || b.composed());
		}
		return new TailEffect(null, union, true, true);
	}

	/**
	 * Admits pass-through wrapper functions into {@code helpers} by re-keying each helper's
	 * model onto the entry of a function that falls straight through into it without
	 * writing any mechanism of its own (bead grm-2dr increment 1).
	 * <p>
	 * <b>Why {@link #findHelpers} misses these.</b> {@link #findHelpers} admits a function
	 * as a helper only if it CONTAINS a recognized mechanism write. Real NES ROMs route
	 * bank switching through small trampolines that write nothing and simply fall through
	 * into the real helper -- Castlevania 2's {@code FUN_c183} ({@code STA $1C}) falls into
	 * {@code FUN_c185} ({@code LDA $1C}), which falls into {@code FUN_c187} (the MMC1
	 * serial-shift chain itself, {@code firstSite} {@code $c18e}); TMNT's {@code FUN_cea5}
	 * ({@code STA $21}) falls into {@code FUN_cea7} (whose own body starts {@code SEC / ROR
	 * $F0} before the chain at {@code $ceaa}); Wizards & Warriors' {@code $ce89} falls into
	 * {@code $ce8b}, an AxROM single-write latch -- named specifically because this rule is
	 * NOT scoped to serial-shift boards. Calls land on the wrapper's entry, which is not a
	 * key {@link #findHelpers} ever produces, so {@link #calledHelper} misses and the call
	 * site's argument is never recovered.
	 * <p>
	 * <b>Why re-keying alone is sound.</b> {@link HelperArgumentRecovery#argumentSurvivesPrologue} walks LINEARLY
	 * BY ADDRESS from {@code entry} to {@code firstSite} with NO REFERENCE TO FUNCTION
	 * BOUNDARIES. Because a wrapper is address-contiguous with the helper it falls into,
	 * re-keying the helper's model onto the wrapper's entry makes that ONE EXISTING WALK
	 * cover the wrapper's body and the helper's own prologue with no change to that method
	 * at all. On cv2: {@code STA $1C} records {@code $1C} in {@code argumentCells};
	 * {@code LDA $1C} is recognized as a restore via {@code HelperArgumentRecovery.argumentReloadSource} so
	 * {@code holdsArgument} stays true; then {@code FUN_c187}'s own {@code PHA} /
	 * {@code LDA #$01} / {@code STA $0103} / {@code PLA} save-restore pair resolves exactly
	 * as it already does today.
	 * <p>
	 * <b>NOT HANDLED HERE, deliberately:</b> blmaster's {@code FUN_e61b} reaches its helper by
	 * an internal {@code JSR}, so it is not address-contiguous with it. {@link
	 * #isPassThroughInto}'s {@code getFlows().length == 0} condition (a call's flows include
	 * its target) excludes that BY CONSTRUCTION -- there is no special case for it here, and
	 * there should not be one. That edge is {@link #findCallEdgeWrappers}' job (grm-2dr
	 * increment 2), which reuses this method's sibling predicate on the wrapper's PREFIX rather
	 * than widening this one.
	 * <p>
	 * {@code switchResults} is threaded through so "the wrapper writes no mechanism" is
	 * asserted LOCALLY, against the same map the rest of this analysis already trusts,
	 * rather than by assuming {@link #findHelpers} completely characterizes every function
	 * that is not a helper.
	 * <p>
	 * Runs in rounds, capped by {@link #MAX_WRAPPER_CHAIN}, so a stack of wrappers is
	 * admitted one link per round: on cv2, round 1 admits {@code FUN_c185} against
	 * {@code FUN_c187}'s model, and round 2 admits {@code FUN_c183} against the model NOW
	 * keyed on {@code FUN_c185}'s entry -- matched against {@link HelperModel#entry}, NOT
	 * {@code model.function().getEntryPoint()}, which is exactly what lets round 2 see round
	 * 1's work. Each round scans a SNAPSHOT of the map's keys ({@code List.copyOf}), never
	 * the live map, so a wrapper admitted mid-round cannot itself be re-wrapped in the same
	 * pass -- preserving the deterministic ordering the backing {@link LinkedHashMap} exists
	 * for. A round that admits nothing ends the fixpoint early.
	 * <p>
	 * A helper whose model {@link #composeTailCalls} already composed is NOT skipped here --
	 * both outcomes of wrapping one are already correct without a special case: a composed
	 * constant takes {@link BankDataflowEngine#runDataflow}'s {@code constState} branch directly and never
	 * touches the nulled {@code argReg}/{@code switchSite} fields a wrapper would also leave
	 * untouched, and a composed decline short-circuits in {@link HelperArgumentRecovery#recoverCallArgument} on
	 * the null {@code argReg}, producing a warning plus honest poison exactly as a direct
	 * call to it would.
	 */
	// Package-private (not private): BoardBankAnalyzer.added() reaches this via
	// import static (grm-shnf step 3).
	static Map<Function, HelperModel> findPassThroughWrappers(Program program,
			Map<Function, HelperModel> helpers, Map<Address, SwitchResult> switchResults) {
		Map<Function, HelperModel> result = new LinkedHashMap<>(helpers);
		FunctionManager fm = program.getFunctionManager();
		for (int round = 0; round < MAX_WRAPPER_CHAIN; round++) {
			boolean added = false;
			for (Function key : List.copyOf(result.keySet())) {
				HelperModel model = result.get(key);
				Address before = model.entry().previous();
				if (before == null) {
					continue;
				}
				Function wrapper = fm.getFunctionContaining(before);
				if (wrapper == null || result.containsKey(wrapper)) {
					continue;
				}
				if (isPassThroughInto(program, wrapper, model.entry(), switchResults)) {
					result.put(wrapper, model.atFallThroughWrapper(wrapper));
					added = true;
				}
			}
			if (!added) {
				break;
			}
		}
		return result;
	}

	/**
	 * Whether {@code wrapper} does nothing but fall straight through into {@code target}: no
	 * branch, no jump, no call, no fallthrough override, no gap in disassembly, and no
	 * recognized mechanism write anywhere in its body. Structured as one linear cursor walk
	 * from {@code wrapper.getEntryPoint()} to {@code target}, deliberately shaped like
	 * {@link HelperArgumentRecovery#argumentSurvivesPrologue} so the two read alike -- both exist to answer "does
	 * this straight-line stretch of code preserve something", the caller's byte there versus
	 * the fact that nothing has happened yet here.
	 * <p>
	 * EVERY condition below must hold for every instruction on the walk:
	 * <ul>
	 * <li>{@code wrapper.getBody()} is a single contiguous range starting at
	 * {@code wrapper.getEntryPoint()} -- a disjoint body would make "walk linearly to the
	 * end" meaningless.</li>
	 * <li>{@code getInstructionAt(cursor) != null} at every step -- disassembly
	 * completeness. This is LOAD-BEARING in a way it is not for
	 * {@code HelperArgumentRecovery.argumentSurvivesPrologue}: the {@code constState}-inherit path in
	 * {@link HelperModel#atFallThroughWrapper} bypasses {@code HelperArgumentRecovery.argumentSurvivesPrologue}
	 * entirely (a constant helper never calls it), so nothing else on that path ever checks
	 * for a disassembly gap in the wrapper's body -- this method is the only place that
	 * does.</li>
	 * <li>{@code instr.getFlows().length == 0} -- no branch, no jump, and no {@code JSR} (a
	 * call's flows include its target). This is what keeps blmaster's {@code FUN_e61b} out of
	 * {@link #findPassThroughWrappers} by construction, since it reaches its helper via an
	 * internal {@code JSR} rather than a fallthrough.</li>
	 * <li>{@code !instr.getFlowType().isTerminal()} -- NOT redundant with the flows check
	 * above: {@code RTS}/{@code RTI} have zero flows too, and neither falls through
	 * anywhere.</li>
	 * <li>{@code instr.getFallThrough()} equals {@code instr.getMaxAddress().next()} -- the
	 * fallthrough-OVERRIDE check. Ghidra allows an instruction's fallthrough to be
	 * overridden even when it has no flows and is not terminal, which would falsify both the
	 * pass-through claim and the linear-by-address walk this entire design -- here and in
	 * {@code HelperArgumentRecovery.argumentSurvivesPrologue} -- rests on.</li>
	 * <li>{@code !switchResults.containsKey(cursor)} -- writes no mechanism, asserted
	 * locally against the same map the rest of the analysis trusts rather than assuming
	 * {@link #findHelpers} completely characterizes every non-helper function.</li>
	 * </ul>
	 * The walk must land EXACTLY on {@code target}; overshooting or undershooting it is not
	 * a pass-through. Package-private static, not private, so a JUnit test can pin it
	 * directly, following the precedent of {@link #reachableEntries} and
	 * {@link HelperArgumentRecovery#argumentSurvivesPrologue}.
	 * <p>
	 * <b>{@code target} has TWO meanings, by two callers</b> (grm-2dr increment 2).
	 * {@link #findPassThroughWrappers} passes a wrapped HELPER'S ENTRY, asking "does this
	 * wrapper fall straight into that helper?". {@link #findCallEdgeWrappers} passes a CALL SITE
	 * INSIDE the wrapper's own body, asking "does control reach that call unconditionally, with
	 * nothing bank-relevant happening first?". The predicate is identical for both because the
	 * question is: every step from the entry to here is plain, disassembled, inert
	 * fallthrough. In the second use the body-max bound never binds -- the target lies inside
	 * the body, so the walk returns on reaching it.
	 * <p>
	 * <b>Why bounding the walk by {@code getBody()} is safe, and not merely convenient.</b>
	 * Ghidra function bodies CANNOT OVERLAP: both {@code FunctionManagerDB.createFunction}
	 * and {@code setFunctionBody} route through the namespace manager and convert an
	 * {@code OverlappingNamespaceException} into an {@code OverlappingFunctionException}
	 * (verified against the targeted Ghidra source). Body assignment is therefore
	 * first-come-claims-it: whichever function is created first owns the addresses, and a
	 * later one is clipped at that boundary. So a wrapper's body is GUARANTEED to stop at or
	 * before {@code target}, and the early return when the cursor reaches {@code target}
	 * cannot silently accept a body that overruns it.
	 * <p>
	 * The same rule explains, from the other side, why this shape exists at all -- and why
	 * bead grm-78b is its mirror image. Whether a fallthrough chain surfaces as ONE BIG
	 * FUNCTION or as WRAPPER PLUS HELPER is decided purely by what got created first. On cv2
	 * all three entries were created, so each body was clipped and the wrappers are visible
	 * here; on blmaster nothing created a function at {@code f23b}, so {@code FUN_f1ca}'s
	 * body swallowed the RESET routine whole and its register writes were misattributed.
	 * Same mechanism, opposite outcomes.
	 * <p>
	 * Note this bound is a property of the FUNCTION MODEL, not of the decompiler, which is
	 * not bounded by function bodies at all: {@code Funcdata::startProcessing} calls
	 * {@code followFlow} over the whole address space, so a decompiled listing happily
	 * continues past a body's end. Do not read decompiler output as evidence about where a
	 * function's body stops.
	 */
	static boolean isPassThroughInto(Program program, Function wrapper, Address target,
			Map<Address, SwitchResult> switchResults) {
		AddressSetView body = wrapper.getBody();
		if (body.getNumAddressRanges() != 1 ||
			!body.getMinAddress().equals(wrapper.getEntryPoint())) {
			return false;
		}
		Listing listing = program.getListing();
		Address end = body.getMaxAddress();
		Address cursor = wrapper.getEntryPoint();
		while (cursor != null && cursor.compareTo(end) <= 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return false;
			}
			if (instr.getFlows().length > 0 || instr.getFlowType().isTerminal()) {
				return false;
			}
			Address next = instr.getMaxAddress().next();
			Address fallThrough = instr.getFallThrough();
			if (next == null || fallThrough == null || !fallThrough.equals(next)) {
				return false;
			}
			if (switchResults.containsKey(cursor)) {
				return false;
			}
			if (next.equals(target)) {
				return true;
			}
			cursor = next;
		}
		return false;
	}

	/**
	 * {@code helpers}, plus every CALL-EDGE wrapper of one: a function that writes no mechanism
	 * itself and reaches a real helper by an interior {@code JSR} rather than by falling through
	 * into it (bead grm-2dr increment 2). The sibling of {@link #findPassThroughWrappers}, for
	 * the edge that one excludes by construction.
	 * <p>
	 * blmaster's {@code FUN_e61b} is the shape the increment exists for -- twelve call sites, and
	 * before this every one of them silently unrecovered:
	 * <pre>
	 *   e61b  STA $DB        ; stash the caller's requested PRG bank in the shadow
	 *         ...            ; straight-line, reloads A from $DB
	 *   e627  JSR $e63c      ; the relay -- FUN_e63c is the real MMC1 serial-shift helper
	 *         ...            ; calls FUN_eb98 in a loop
	 *         RTS
	 * </pre>
	 * Call RECOGNITION already worked: the golden warned at {@code e627} naming
	 * {@code FUN_e63c}. What failed was ARGUMENT recovery, because the caller's {@code LDA #imm}
	 * is two frames from the store and {@code e61b} was not a helper, so nothing looked.
	 * <p>
	 * <b>TWO gates, and the second does not subsume the first.</b>
	 * <ul>
	 * <li>STRUCTURAL: {@link #isPassThroughInto} with {@code target} = the relay call site. The
	 * reuse is exact rather than opportunistic -- <em>the prefix of a call-edge wrapper, up to
	 * its relay call, is precisely a pass-through into that call site</em> -- and it is what
	 * proves the relay is REACHED UNCONDITIONALLY. Its body-max bound is harmless because the
	 * call site is inside the body, so the walk lands on it and returns first.</li>
	 * <li>VALUE: {@link HelperArgumentRecovery#argumentSurvivesPrologue} over {@link HelperArgumentRecovery#prologueSegments}, which proves
	 * the caller's byte is still in {@code argReg} when the helper's first site reads it. On
	 * blmaster this is exactly the {@code argumentCells}/{@code HelperArgumentRecovery.argumentReloadSource}
	 * save-restore model (grm-mu7 increment 2) recognizing the {@code STA $DB} / {@code LDA $DB}
	 * pair -- the same machinery that made cv2's {@code STA $1C} / {@code LDA $1C} work in
	 * increment 1.</li>
	 * </ul>
	 * <b>The value gate alone would be unsound, which is not obvious.</b> A branch does NOT make
	 * {@link HelperArgumentRecovery#argumentSurvivesPrologue} decline: a nonzero {@code getFlows().length} only clears
	 * {@code straightLine} and {@code argumentCells}, and the walk CONTINUES. A prefix that
	 * branches around the relay call but never writes {@code argReg} would pass it -- and then
	 * every claim below about the wrapper's effect would rest on a call that might not run.
	 * <p>
	 * A tail {@code JMP} that Ghidra's shared-return analysis retyped {@code CALL_TERMINATOR}
	 * reports {@code isCall()} and counts as a relay. It is the SOUNDER case: control never
	 * returns to the wrapper, so there is no post-relay body to assume anything about.
	 * <p>
	 * <b>What is checked versus what is ASSUMED.</b> Checked: the prefix is inert and
	 * unconditional; no recognized mechanism write appears ANYWHERE in the wrapper's body (the
	 * whole body, not just the prefix -- a write after the relay would make the wrapper's effect
	 * not the helper's); no SECOND known-helper call appears there either. Assumed: that calls
	 * after the relay to functions this engine does not model as helpers are bank-neutral.
	 * <p>
	 * <b>{@code FUN_eb98} is the load-bearing instance of that assumption and it holds BY
	 * ACCIDENT, not by construction.</b> {@code e61b}'s loop calls it; {@code eb98} itself
	 * {@code JSR}s {@code e63c} twice -- {@code ec53} with a constant 5 for the duration of some
	 * work, then {@code ec5b} with the {@code $DB} value to put the requested bank back. The net
	 * effect at {@code e61b}'s return is the requested bank, so the model is right; it would not
	 * be if the restore were missing. {@code eb98} escapes admission here twice over: it
	 * contains no mechanism write, so {@link #findHelpers} never sees it, and it makes TWO
	 * known-helper calls, so the exactly-one rule rejects it as a wrapper. Both facts are
	 * load-bearing for {@code e61b} -- were {@code eb98} ever a helper, {@code e61b} would see
	 * two relay candidates and be rejected, which would then be the correct conservative answer.
	 * <p>
	 * This EXTENDS an existing standard rather than introducing a new unsoundness:
	 * {@link BankDataflowEngine#runDataflow} already folds a call to a non-helper as a no-op on bank state, and
	 * {@link #composeTailCalls} already writes that down for the tail-call case. But the
	 * extension is real and worth naming -- increment 1 CHECKED inertness per instruction over
	 * the whole wrapper body, while this checks it over the prefix and ASSUMES it over the tail.
	 * <p>
	 * {@link #exitEffect} is not reusable here, for a one-sentence reason: it composes effects at
	 * a function's EXIT instructions and deliberately nulls {@code argReg}/{@code strategy}/
	 * {@code switchSite} because they describe a body its result no longer summarizes -- while a
	 * relay is MID-BODY and exists precisely to PRESERVE {@code argReg} so the caller's value can
	 * be recovered. The two machineries want opposite things from the same fields.
	 * <p>
	 * <b>ONE ROUND, and the exactly-one count is taken against the IMMUTABLE INPUT map.</b> That
	 * is a correctness requirement, not a budget: the exactly-one rule is NON-MONOTONE in the
	 * helper set, so admitting X could flip Y's count from one to two and turn an admission into
	 * a rejection. With rounds, the answer would depend on candidate iteration order -- the same
	 * class of bug increment 1's snapshot guards against, but one a snapshot alone does NOT fix,
	 * since the snapshot would grow between rounds. Counting against the input makes this a
	 * PURE, ORDER-INDEPENDENT function of its arguments. Note the contrast with
	 * {@link #findPassThroughWrappers}, which looks similar but whose termination is STRUCTURAL
	 * with {@link #MAX_WRAPPER_CHAIN} merely a policy cap; here termination is trivially one
	 * pass.
	 * <p>
	 * Runs LAST in the helper-discovery chain, so it sees the richest helper set -- a relay
	 * landing on a pass-through wrapper admitted by increment 1 resolves through
	 * {@link #calledHelper} and counts toward the exactly-one tally. The converse, a pass-through
	 * wrapper OF a call-edge wrapper, is not reachable under this order; that is a documented gap
	 * with no measured instance, cheaply closed later by a second
	 * {@link #findPassThroughWrappers} call, which would stay deterministic because call-edge
	 * decisions are fixed by then. A wrapped model that ALREADY carries a relay is rejected: the
	 * prologue would need three segments, and {@link HelperArgumentRecovery#prologueSegments} expresses two.
	 */
	// Package-private (not private): BoardBankAnalyzer.added() reaches this via
	// import static (grm-shnf step 3).
	static Map<Function, HelperModel> findCallEdgeWrappers(Program program,
			Map<Function, HelperModel> helpers, Map<Address, SwitchResult> switchResults) {
		Map<Function, HelperModel> result = new LinkedHashMap<>(helpers);
		// Address-ordered and materialized before use, matching findPassThroughWrappers'
		// List.copyOf discipline: the enumeration must not depend on live map or iterator state.
		List<Function> candidates = new ArrayList<>();
		program.getFunctionManager().getFunctions(true).forEach(candidates::add);
		Listing listing = program.getListing();
		for (Function wrapper : candidates) {
			// helpers, never result: the count that decides admission is taken against the
			// immutable input, which is what makes this pass order-independent.
			if (helpers.containsKey(wrapper)) {
				continue;
			}
			if (wrapper.getBody().getNumAddressRanges() != 1) {
				continue;
			}
			Address relayCall = null;
			HelperModel wrapped = null;
			boolean rejected = false;
			for (Instruction instr : listing.getInstructions(wrapper.getBody(), true)) {
				if (switchResults.containsKey(instr.getMinAddress())) {
					rejected = true; // writes a mechanism -- a helper, not a wrapper
					break;
				}
				if (!instr.getFlowType().isCall()) {
					continue;
				}
				HelperModel target = calledHelper(program, instr, helpers);
				if (target == null) {
					continue; // a call to something this engine does not model -- assumed inert
				}
				if (relayCall != null) {
					rejected = true; // a second known-helper call
					break;
				}
				relayCall = instr.getMinAddress();
				wrapped = target;
			}
			if (rejected || relayCall == null || wrapped.relay() != null ||
				wrapped.argReg() == null || wrapped.firstSite() == null) {
				continue;
			}
			if (!isPassThroughInto(program, wrapper, relayCall, switchResults)) {
				continue;
			}
			HelperModel model = wrapped.atCallEdgeWrapper(wrapper, relayCall);
			if (!argumentSurvivesPrologue(program, prologueSegments(model), model.argReg())) {
				continue;
			}
			result.put(wrapper, model);
		}
		return result;
	}

	/**
	 * Every instruction in {@code f} that ends a path through it: {@code RTS}/{@code RTI}
	 * ({@code TERMINATOR}) and a tail call out of the body ({@code CALL_TERMINATOR} -- a jump
	 * to another function's entry, which Ghidra's shared-return analysis rewrites into a
	 * call-with-no-fall-through). Both report {@link ghidra.program.model.symbol.FlowType#isTerminal()};
	 * they are told apart by {@code isCall()}, the same test {@link BankDataflowEngine#runDataflow} already uses
	 * to route a {@code CALL_TERMINATOR} jump through the helper-call path.
	 * <p>
	 * A plain unconditional jump that leaves the body WITHOUT landing on a function entry is
	 * not terminal and so is not seen here. Ghidra normally absorbs such a target into this
	 * function's body instead, which makes it an internal branch the max-address rule already
	 * covers; a genuinely bodiless jump out would be a gap, not a wrong answer, since it can
	 * only leave the body-local summary in place.
	 */
	private static List<Instruction> exitInstructions(Program program, Function f) {
		List<Instruction> exits = new ArrayList<>();
		for (Instruction instr : program.getListing().getInstructions(f.getBody(), true)) {
			if (instr.getFlowType().isTerminal()) {
				exits.add(instr);
			}
		}
		return exits;
	}

	/**
	 * Hop cap for {@link #reachableEntries}. A real argument relay is one link -- a jump-table
	 * slot, or Ghidra's own thunk typing of the same. Three is slack, not a modeled depth.
	 */
	private static final int MAX_RELAY_HOPS = 3;

	/**
	 * The addresses control can actually arrive at from this call: its direct flow targets,
	 * then each one followed through Ghidra thunks and one-instruction unconditional-jump
	 * trampolines, in that order (nearest first, so a direct hit always wins over a hop).
	 * <p>
	 * <b>Why a call's flow target is not always where it lands.</b> Games route bank switches
	 * through a jump table of 3-byte slots, and Ghidra types those two different ways depending
	 * on nothing the game did. Bionic Commando's {@code $D751 JMP $DCC3} becomes
	 * {@code thunk_FUN_dcc3} because {@code $DCC3} happens to be a function entry; its
	 * {@code $D6E2 JMP $DCAA} stays an ordinary one-instruction function, because {@code $DCAA}
	 * is mid-body. Both are the same idiom and both were invisible: the thunk is a different
	 * {@code Function} than the helper, and the trampoline is not the helper at all, so the old
	 * {@code getFunctionAt} + map lookup missed both and returned null -- which
	 * {@link BankDataflowEngine#runDataflow} folds as a call that does nothing to bank state. A SILENT miss, and
	 * measurably the whole story on two real cartridges: every one of Bionic Commando's 5 bank
	 * call sites and all 59 of Final Fantasy's reach their helper only through a hop.
	 * <p>
	 * Package-private and static so it can be tested against a {@code ProgramBuilder} program
	 * on its own -- it is a function of {@code (program, callInstr)} and nothing else, with no
	 * analyzer state, no board, and no dependence on any helper having been found yet.
	 */
	static List<Address> reachableEntries(Program program, Instruction callInstr) {
		List<Address> entries = new ArrayList<>();
		for (Address flow : callInstr.getFlows()) {
			Set<Address> seen = new LinkedHashSet<>();
			Address cur = flow;
			for (int hop = 0; cur != null && seen.add(cur); hop++) {
				entries.add(cur);
				cur = hop < MAX_RELAY_HOPS ? relayTarget(program, cur) : null;
			}
		}
		return entries;
	}

	/**
	 * One hop from {@code at} through a thunk or a one-instruction unconditional-jump
	 * trampoline, or null if {@code at} is neither.
	 * <p>
	 * The one-instruction requirement is what keeps this from following ordinary tail jumps.
	 * A {@code JMP} at the end of a longer body is reached only after that body has run, so
	 * attributing the jump's target to a call that entered at the top would credit the caller
	 * with a helper it reaches only via other code -- and that case already has an owner:
	 * {@link #composeTailCalls}, which composes the two effects rather than substituting one
	 * for the other. Here the trampoline body IS the jump, so there is nothing to compose.
	 */
	private static Address relayTarget(Program program, Address at) {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(at);
		if (f != null && f.isThunk()) {
			Function thunked = f.getThunkedFunction(true);
			if (thunked != null) {
				return thunked.getEntryPoint();
			}
		}
		Instruction instr = program.getListing().getInstructionAt(at);
		// isCall() is deliberately NOT excluded: shared-return analysis retypes a tail JMP as
		// CALL_TERMINATOR, which reports both isCall() and isJump(). A one-instruction body
		// that does that is still a relay. A JSR is isCall() but not isJump(), so it is out.
		//
		// isComputed() IS excluded, and that exclusion is load-bearing rather than tidiness.
		// A relay's defining property is that its target is encoded in the instruction, so
		// "where this call lands" stays a static fact; a computed jump's target is read from
		// memory at run time and is not that instruction's property at all. Measured cost of
		// getting this wrong, on Mega Man 2: the 6502's BRK is specified as
		// `goto [*:2 0xFFFE]`, so every filler $00 byte Ghidra disassembles becomes a
		// one-instruction "relay" into the IRQ handler. Following those reached RESET from
		// unrelated call sites, poisoning bank state that nothing had written, and cost 285
		// resolved overlay instructions -- a silent miss traded for a loud wrong answer.
		if (instr == null || !instr.getFlowType().isJump() ||
			instr.getFlowType().isConditional() || instr.getFlowType().isComputed()) {
			return null;
		}
		Function owner = fm.getFunctionContaining(at);
		if (owner != null && (!owner.getEntryPoint().equals(at) ||
			owner.getBody().getNumAddresses() != instr.getLength())) {
			return null;
		}
		Address[] flows = instr.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	/**
	 * How a helper is named in a user-visible warning. The function's name, except for a
	 * mid-body entry, where naming the function would point the reader at {@code FUN_dca8}
	 * when the call actually went to {@code LAB_dcaa} -- an address whose whole significance
	 * is that it is NOT the function entry.
	 */
	static String helperLabel(Program program, HelperModel helper) {
		if (helper.entry().equals(helper.function().getEntryPoint())) {
			return helper.function().getName();
		}
		Symbol sym = program.getSymbolTable().getPrimarySymbol(helper.entry());
		return (sym == null ? helper.entry().toString() : sym.getName()) + " (mid-body entry in " +
			helper.function().getName() + ")";
	}

	/**
	 * The helper this call instruction targets, or null.
	 * <p>
	 * This relies on {@code helpers} already containing an entry keyed on the actual call
	 * target, which is why a call landing on a pass-through wrapper's entry (Castlevania
	 * 2's {@code FUN_c183}, TMNT's {@code FUN_cea5}, Wizards & Warriors' {@code $ce89}) does
	 * not silently miss here: {@link #findPassThroughWrappers} re-keys the wrapped helper's
	 * model onto the wrapper's own entry BEFORE this method ever runs, so the lookup below
	 * hits it the same way it would hit a direct call.
	 */
	static HelperModel calledHelper(Program program, Instruction callInstr,
			Map<Function, HelperModel> helpers) {
		FunctionManager fm = program.getFunctionManager();
		for (Address entry : reachableEntries(program, callInstr)) {
			Function f = fm.getFunctionAt(entry);
			if (f != null) {
				HelperModel helper = helpers.get(f);
				if (helper != null) {
					return helper;
				}
				continue; // a real function that is not a helper -- not a mid-body entry either
			}
			HelperModel midBody = midBodyEntryHelper(program, entry, helpers);
			if (midBody != null) {
				return midBody;
			}
		}
		return null;
	}

	/**
	 * A helper model for control arriving INSIDE a helper's body rather than at its entry, or
	 * null when this address is not an admissible mid-body entry.
	 * <p>
	 * <b>The admission test is "no recognized site strictly precedes {@code entry}".</b> That
	 * is what makes reusing the containing function's summary exact rather than a guess:
	 * entering here still runs the body's entire recognized site set, in the same order, so
	 * {@code effectMask}, {@code lsb}, {@code strategy} and {@code switchSite} all still
	 * describe this path -- no reachability over- or under-approximation is involved. Entering
	 * PAST a site (a {@code JSR} into the middle of a serial-shift chain) fails the test and is
	 * declined rather than guessed at: its real effect is a partial chain, which this model has
	 * no way to express. {@code constState} is dropped regardless; see
	 * {@link HelperModel#atMidBodyEntry}.
	 * <p>
	 * Resolution is demand-driven -- only an address some call actually reaches is ever tested
	 * -- rather than enumerating every branch target in every helper body. A mid-body entry
	 * that nothing calls cannot change any answer, and enumerating would mean inventing a rule
	 * for which of a loop's internal labels count as entry points.
	 * <p>
	 * <b>A CALL-EDGE wrapper is declined outright, and the admission test above cannot be
	 * trusted to do it</b> (bead grm-2dr increment 2). Such a model's {@code firstSite} lives in
	 * a DIFFERENT function and is therefore greater than every address in {@code owner}'s body,
	 * so {@code entry > firstSite} is false for every mid-body address in the wrapper --
	 * including ones PAST the relay call, where the {@code JSR} into the real helper has already
	 * been skipped and no bank switch happens on that path at all. The test's whole
	 * justification -- "entering here still runs the body's entire recognized site set" -- does
	 * not survive a relay, because the site set is not in this body and a branch inside the
	 * wrapper could route around the call that reaches it. The check is deliberately blunt
	 * ({@code relay != null}) rather than {@code entry <= relay.callSite()}: nothing measured
	 * needs the finer rule, and the coarse one cannot be wrong.
	 */
	private static HelperModel midBodyEntryHelper(Program program, Address entry,
			Map<Function, HelperModel> helpers) {
		FunctionManager fm = program.getFunctionManager();
		if (fm.getFunctionAt(entry) != null) {
			return null; // a function entry, not a mid-body one -- calledHelper handles it
		}
		Function owner = fm.getFunctionContaining(entry);
		if (owner == null) {
			return null;
		}
		HelperModel model = helpers.get(owner);
		if (model == null || model.relay() != null || model.firstSite() == null ||
			entry.compareTo(model.firstSite()) > 0) {
			return null;
		}
		return model.atMidBodyEntry(entry);
	}

	/**
	 * A helper function's modeled effect: a constant state, or null = caller-supplied. For
	 * caller-supplied helpers, {@code argReg} is the register (A/X/Y) the helper stores into
	 * its mechanism -- i.e. the register by which the caller passes the bank field -- or null
	 * when the helper's switch sites disagree on that register or use a non-{@code ST<reg>}
	 * write, in which case the argument convention is unknown. {@code effectMask}/{@code lsb}
	 * are the mechanism's positioning (or the conservative union of several, when the
	 * helper's sites span more than one mechanism -- see {@link #findHelpers}), used to fold
	 * this helper's effect into only the state bits it actually owns. {@code strategy} is the
	 * matched mechanism's strategy (null when the sites disagree, per {@code findHelpers}'s
	 * degrade case -- unused there since {@code argReg} is also forced null and
	 * {@link HelperArgumentRecovery#recoverCallArgument} short-circuits before ever consulting {@code strategy});
	 * {@code switchSite} is the recognized switch instruction that
	 * {@link BankSwitchStrategy#depositHelperArgument} is asked to interpret a call site's
	 * argument against.
	 * <p>
	 * <b>What {@code switchSite} MEANS is "the last recognized write on the path to this
	 * helper's RETURN".</b> {@link #findHelpers} implements that as the highest-address site
	 * when a helper's sites span several instructions of the same mechanism -- e.g. a
	 * serial-shift chain's 5 stores all resolve to the same target address here, but for an
	 * idiom where they could legitimately differ, the LAST write is the one whose address
	 * actually decides the target, per {@link SerialShiftBankSwitchStrategy}.
	 * <p>
	 * <b>Max-address is only a PROXY for that meaning, and it is valid only while control
	 * cannot leave the function body.</b> A tail call is exactly when it can: Mega Man's
	 * {@code FUN_d131} contains one site ({@code $D135 STA $C006}, bank 6) and then ends
	 * {@code $D159 JMP $C3B3}, so the bank live at its return is {@code FUN_c3b3}'s 5, not its
	 * own 6. {@link #composeTailCalls} post-processes {@link #findHelpers}' map to repair that
	 * -- composing the callee's effect in where it can, declining where it cannot -- so nothing
	 * downstream ever sees a body-local summary of a helper that tail-calls another one. The
	 * proxy is still a heuristic WITHIN the body (address order is not execution order in
	 * general: a helper whose exit path branches backward to an earlier switch would be
	 * committed to the wrong site by it); nothing shipped does that today, and a helper that
	 * did would need real terminal-site analysis rather than a max().
	 * <p>
	 * <b>{@code entry} is WHERE CONTROL ARRIVED, which is not always {@code function}'s entry
	 * point.</b> A game may jump directly into the middle of a switch routine, deliberately
	 * skipping a prologue that would clobber the argument register -- Bionic Commando's
	 * {@code $D6E2 JMP $DCAA} lands on the first {@code STA $E000} of a 5-write chain, past the
	 * {@code $DCA8 LDA $65} that would have overwritten A. Ghidra keeps {@code $DCAA} mid-body,
	 * so {@code getFunctionContaining} answers {@code FUN_dca8} and a model keyed on the
	 * function alone describes the argument at the WRONG entry. See
	 * {@link #midBodyEntryHelper} for how such an entry is admitted and what it costs.
	 * {@code entry} is also the {@link RegisterEnv} stop address {@link HelperArgumentRecovery#recoverCallArgument}
	 * hands the mini-inline scan, which must stop where control actually entered.
	 * <p>
	 * {@code firstSite} is the LOWEST-addressed recognized site in the body, the mirror of
	 * {@code switchSite}'s max, and is null in the same degraded cases {@code switchSite} is.
	 * It has two consumers, both of which want "the first thing this body does that matters":
	 * {@link #midBodyEntryHelper}'s admission test (does entering here still run every site?)
	 * and {@link HelperArgumentRecovery#argumentSurvivesPrologue}'s walk bound (does the caller's argument survive
	 * as far as the site that consumes it?). Together with {@code entry} it delimits exactly
	 * the prologue a given call runs before the mechanism reads its argument -- EXCEPT when
	 * {@code relay} is non-null, which is precisely the case where that stops being one span;
	 * see {@link Relay} and {@link HelperArgumentRecovery#prologueSegments}.
	 * <p>
	 * <b>{@code relay} is the one field that is not about this helper's own body</b> (bead
	 * grm-2dr increment 2). It is null for every model {@link #findHelpers},
	 * {@link #composeTailCalls} and {@link #findPassThroughWrappers} produce, and non-null only
	 * for a CALL-EDGE wrapper -- a function that writes no mechanism and reaches the real helper
	 * by an interior {@code JSR} rather than by falling through into it. Every other field is
	 * then inherited from the wrapped helper and describes ITS body, while {@code entry}
	 * describes the wrapper's; {@code relay} is what stitches the two together.
	 */
	// Package-private (not private) so BankSaveRestoreTrampolineProgramTest (grm-mej.3
	// increment 1) can construct a HelperModel directly to drive
	// SaveRestoreTrampolines.restoresEntryBank -- the
	// established pattern in this file for a helper that a same-package Tier 2 test needs to
	// reach but that has no other production caller outside HelperDiscovery. No behavior
	// change: every other member keeps its own visibility.
	record HelperModel(Function function, Address entry, BankState constState,
			Character argReg, int effectMask, int lsb, BankSwitchStrategy strategy,
			Address switchSite, Address firstSite, Relay relay) {

		/**
		 * This helper re-keyed to a mid-body {@code entry}, with {@code constState} dropped.
		 * <p>
		 * Dropping the constant is the one thing that cannot be reused. A constant is a claim
		 * about what the whole body does when entered at the top, and a mid-body entry is
		 * precisely a path that skipped part of that -- shipping it would ship a wrong bank,
		 * which this engine treats as strictly worse than shipping none. Nulling it routes the
		 * call through {@link HelperArgumentRecovery#recoverCallArgument}, which re-derives the value from the call
		 * site's own registers. Everything else survives because
		 * {@link #midBodyEntryHelper}'s admission test guarantees the entry still runs the
		 * body's entire recognized site set.
		 */
		HelperModel atMidBodyEntry(Address midBody) {
			return new HelperModel(function, midBody, null, argReg, effectMask, lsb, strategy,
				switchSite, firstSite, relay);
		}

		/**
		 * This helper re-keyed onto a pass-through wrapper that falls straight through into
		 * it, for {@link #findPassThroughWrappers} (bead grm-2dr increment 1).
		 * <p>
		 * {@code function} MUST become {@code wrapper}, not stay the wrapped helper's own
		 * function: {@link #helperLabel} compares {@code entry} against
		 * {@code function.getEntryPoint()} to decide whether to print a plain function name
		 * or a "mid-body entry in ..." qualifier, so leaving {@code function} pointed at the
		 * helper would print the misleading claim that the wrapper's entry is a mid-body
		 * entry INTO the helper's own function. It also keeps this record's {@code function}
		 * field equal to its own map key, which {@link #exitEffect}'s
		 * {@code helpers.get(callee.function())} lookup depends on to find a callee's model
		 * again by its own key.
		 * <p>
		 * {@code constState} is INHERITED, not dropped -- and that is an IDENTITY, not a
		 * guess, and the exact DUAL of {@link #atMidBodyEntry}: a mid-body entry runs a
		 * SUBSET of the body (it drops the constant because the skipped prefix might have
		 * been where the summarized effect came from), while a pass-through wrapper's caller
		 * runs a SUPERSET of the body -- an inert prefix (the wrapper itself) plus the
		 * ENTIRE wrapped body, unabridged. {@link #isPassThroughInto}'s admission predicate
		 * already guarantees the wrapper's body is fully disassembled, writes no mechanism,
		 * makes no call, and transfers control to nothing but {@code target} (this helper's
		 * own {@code entry}) -- so it changes no tracked bank bit, and whatever constant this
		 * helper asserts when entered at the top still holds when entered at the wrapper's
		 * top instead.
		 * <p>
		 * {@code relay} is carried through rather than nulled. Under the phase order at
		 * {@link BoardBankAnalyzer#added}'s helper-discovery chain, {@link #findCallEdgeWrappers} runs
		 * LAST, so this method can never actually see a non-null one today -- but a pass-through
		 * wrapper OF a call-edge wrapper is address-contiguous and inert, so the first prologue
		 * segment simply widens to start at the outer wrapper's entry and stays correct.
		 * Dropping it would be a latent bug the day that order changes.
		 */
		HelperModel atFallThroughWrapper(Function wrapper) {
			return new HelperModel(wrapper, wrapper.getEntryPoint(), constState, argReg,
				effectMask, lsb, strategy, switchSite, firstSite, relay);
		}

		/**
		 * This helper re-keyed onto a CALL-EDGE wrapper -- one that reaches it by an interior
		 * {@code JSR} (or a tail {@code JMP} retyped {@code CALL_TERMINATOR}) rather than by
		 * falling through into it, for {@link #findCallEdgeWrappers} (bead grm-2dr increment 2).
		 * blmaster's {@code FUN_e61b} is the shape: {@code STA $DB} on entry, the argument
		 * reloaded from that shadow, then {@code $e627 JSR $e63c} into the real MMC1 chain.
		 * <p>
		 * {@code function} MUST become {@code wrapper} for both reasons
		 * {@link #atFallThroughWrapper} documents -- {@link #helperLabel}'s "mid-body entry in
		 * ..." qualifier, and keeping this record's {@code function} equal to its own map key
		 * for {@link #exitEffect}'s lookup.
		 * <p>
		 * <b>The {@link Relay}'s callee entry is {@code entry}, NOT
		 * {@code function().getEntryPoint()}.</b> If the helper being wrapped is itself a
		 * pass-through wrapper, {@code entry} is where control actually arrives and is the
		 * correct start for the second prologue segment; the function's own entry point would
		 * be the same address only by coincidence.
		 * <p>
		 * <b>{@code constState} is INHERITED, and this is the WEAKEST of the three re-keyings.</b>
		 * Place it on the axis: {@link #atMidBodyEntry} inherits a SUBSET of the body and so must
		 * drop the constant; {@link #atFallThroughWrapper} inherits a strict SUPERSET (inert
		 * prefix plus the entire wrapped body) and so inherits it as an IDENTITY; a call-edge
		 * wrapper is NEITHER, because its body continues after the relay call. Inheriting rests
		 * on four conditions {@link #findCallEdgeWrappers} checks -- the prefix
		 * {@code [entry, callSite)} is inert and unconditional, no recognized mechanism write
		 * appears ANYWHERE in the wrapper's body, no second known-helper call appears there
		 * either, and the relay call is therefore guaranteed to execute -- plus one it ASSUMES:
		 * that calls after the relay to functions this engine does not model as helpers are
		 * bank-neutral. That last one is genuinely weaker than
		 * {@link #atFallThroughWrapper}'s, where inertness is CHECKED per instruction over the
		 * whole body rather than assumed over the tail. Inheriting rather than dropping is the
		 * consistent choice: the same assumption already underwrites the {@code argReg} path,
		 * so declining it only for the constant would buy nothing.
		 */
		HelperModel atCallEdgeWrapper(Function wrapper, Address callSite) {
			return new HelperModel(wrapper, wrapper.getEntryPoint(), constState, argReg,
				effectMask, lsb, strategy, switchSite, firstSite, new Relay(callSite, entry));
		}
	}

	/**
	 * A call-edge wrapper's relay: the call instruction inside the wrapper that reaches the real
	 * bank-switch helper, and the address that call lands on (bead grm-2dr increment 2).
	 * <p>
	 * Its whole job is to record that a {@link HelperModel}'s prologue is TWO DISJOINT SPANS
	 * rather than one. For an ordinary helper the caller's argument has to survive
	 * {@code [entry, firstSite)}, one linear-by-address stretch. For a call-edge wrapper it has
	 * to survive {@code [wrapper entry, callSite)} and then {@code [calleeEntry, firstSite)} --
	 * and the addresses BETWEEN those two spans are the wrapper's own tail, which the call never
	 * executes on its way in. Walking straight from the wrapper's entry to the helper's first
	 * site would walk over that tail and read it as prologue, which is why this cannot be
	 * expressed by re-keying {@code entry} alone the way {@link HelperModel#atFallThroughWrapper}
	 * does.
	 * <p>
	 * Three consumers, all of which would otherwise silently use the wrapper's entry where the
	 * WRAPPED HELPER's is meant: {@link HelperArgumentRecovery#prologueSegments}, {@link HelperArgumentRecovery#valueSuppliedInsideHelper}
	 * and {@link HelperArgumentRecovery#callSiteRegisters}'s stop address. A fourth, {@link #midBodyEntryHelper},
	 * declines outright on a non-null relay.
	 */
	// Package-private (not private): HelperArgumentRecovery's insideHelperEntry and
	// prologueSegments call Relay's accessors on a helper model built here (grm-shnf step 3).
	record Relay(Address callSite, Address calleeEntry) {}
}
