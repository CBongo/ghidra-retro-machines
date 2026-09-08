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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import static retromachines.BankDataflowEngine.overwrite;
import static retromachines.BankDataflowEngine.position;
import static retromachines.BankDataflowEngine.toFieldLocal;

import retromachines.HelperDiscovery.HelperModel;

/**
 * Per-call-site helper <em>argument recovery</em>: what value a caller actually passed a
 * bank-switch helper, and the prologue/save-restore machinery that proves whether the caller's
 * register (or a memory cell it wrote) still holds that value by the time the helper's mechanism
 * reads it.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Helper-call propagation" section (bead
 * grm-shnf, QR-12 increment 3b), one of three siblings split along the section's natural fault
 * lines -- see {@link HelperDiscovery}'s class javadoc for the shared move rationale (zero
 * {@code this.} references, zero non-static instance fields, every member already {@code static}
 * as of grm-shnf step 2, so the cut is compile-time verbatim rather than a behavior change).
 *
 * <p>This class holds {@link #recoverCallArgument}, {@link #valueSuppliedInsideHelper}, both
 * {@link #inboundArgumentCell} overloads, {@link #callSiteRegisters}, {@link #surviving} and
 * {@link #crossableWrapperJoin}; the prologue-preservation cluster (both
 * {@link #argumentSurvivesPrologue} overloads -- the {@link List}-of-{@link PrologueSegment} form
 * delegates to the three-address form, and the two were not split apart --
 * {@link #forgetCellsThePushMayHaveHit}, {@link #prologueSegments}, {@link #argumentReloadSource}
 * and {@link #writesStackPointer}); the shared {@link HelperModel} accessors
 * {@link #helperValueSite} and {@link #insideHelperEntry}; and {@link CallEffect}/{@code NO_HOOKS}.
 * {@code BoardBankAnalyzer.added()} never reaches this class directly (it calls only
 * {@link HelperDiscovery}'s and {@link SaveRestoreTrampolines}' entry points), but
 * {@code StoredValueScanner.findMatchingPush} reaches {@link #writesStackPointer} via a qualified
 * call, and {@link BankDataflowEngine} reaches {@link #recoverCallArgument} via
 * {@code import static} exactly as it did before this bead, since that method was already
 * {@code static} as of grm-shnf step 2.
 *
 * <p>Two residual cross-class edges, costing an import each and nothing more:
 * {@link HelperDiscovery#findCallEdgeWrappers} calls {@link #argumentSurvivesPrologue} and
 * {@link #prologueSegments} here, and {@link SaveRestoreTrampolines#restoresEntryBank} calls
 * {@link #insideHelperEntry} and {@link #argumentReloadSource} here -- both targets widened from
 * {@code private} to package-private {@code static} by this move (the same accepted category as
 * every prior QR-12 increment's visibility widenings), and {@link #writesStackPointer} was
 * already package-private since {@code StoredValueScanner} needed it.
 */
final class HelperArgumentRecovery {

	private HelperArgumentRecovery() {
	}

	/**
	 * Recovers the bank argument at a helper call site by running the shared backward scan
	 * for an immediate value in the register the helper actually reads ({@code LDA #bank /
	 * JSR SelectBank}, or the X/Y equivalent). The argument register is taken from the
	 * helper's own mechanism-write ({@link HelperDiscovery.HelperModel#argReg}) rather than guessed,
	 * so a caller that also loads an unrelated immediate into another register no longer misleads
	 * the scan. By the helper convention the register holds the <em>field value itself</em>,
	 * so no mechanism transform is applied beyond the field-local width mask -- the scan
	 * resolves in the helper's own mechanism's field-local {@code [0, width)} space (same
	 * convention as {@link BankSwitchStrategy#computeSwitch}). The recovered byte is then
	 * handed to the matched strategy's {@link BankSwitchStrategy#depositHelperArgument},
	 * which knows -- from the helper's own recognized {@link HelperDiscovery.HelperModel#switchSite}
	 * -- whether this mechanism's field-local space is one field (the recovered byte deposits
	 * verbatim, owning the whole field-local width, the historical behavior) or several
	 * disjoint sub-fields keyed by which switch site is in play (serial-shift) OR by the
	 * caller's own TRACKED STATE at the call site (select-data -- a bare data-write helper's
	 * routing depends on whichever register the caller's select last picked, which the
	 * switch site's address alone cannot tell us): only that call knows which sub-field the
	 * recovered value actually commits through, and therefore which bits this call site may
	 * claim ownership of ({@link CallEffect#ownedMask} -- see
	 * {@link BankSwitchStrategy.HelperDeposit}'s javadoc for why that is tracked separately
	 * from the value's own known bits). To support the state-routed case, {@code callSiteIn}
	 * (the caller's board-absolute state under which this call executes -- the same
	 * {@code outState} {@link BankDataflowEngine#runDataflow} folds the call's own effect into) is
	 * narrowed to this helper's mechanism's field-local space exactly like {@code argValue} before
	 * being handed to {@link BankSwitchStrategy#depositHelperArgument}; a strategy whose routing is
	 * address-keyed instead (serial-shift) simply ignores it. Both the value and the
	 * owned-bits mask are positioned back into the board's absolute state bits before
	 * returning, exactly as a direct dataflow switch's result is. Returns an unknown value
	 * owning the WHOLE mechanism when the argument register itself is unknown (the helper's
	 * sites disagreed on it) -- conservatively wiping everything this helper's mechanism
	 * could possibly touch, the historical behavior for that degrade case.
	 * <p>
	 * <b>The "register holds the field value" convention is a fallback, not the whole story</b>
	 * (grm-hum increment 2). It is blind in three ways: the argument may arrive in a register
	 * other than the one the helper's mechanism write stores (Contra's helper takes its bank in
	 * Y and stores A, and {@link HelperDiscovery#findHelpers} can only see the store); the value may
	 * need the mechanism's own {@code shift}/{@code mask} extraction; and on a bus-conflict board the
	 * driven value is not the latched one. So this also hands the strategy the CALL SITE'S WHOLE
	 * REGISTER ENVIRONMENT ({@link #callSiteRegisters}), letting a strategy that can do better --
	 * {@code memory-latch} does -- re-evaluate its own switch site under those registers instead.
	 * {@code argValue} keeps its exact prior meaning either way, because {@code select-data}
	 * decodes a byte field out of it.
	 * <p>
	 * <b>The convention also assumes the helper does not eat its own argument</b> (grm-mu7).
	 * {@code argReg} is whatever register the mechanism write STORES, which is the only
	 * evidence {@link HelperDiscovery#findHelpers} has -- but a helper whose prologue reloads the bank
	 * from RAM ({@code LDA $65 / STA $E000}) stores A without ever reading the caller's A, so the
	 * caller's value is not the argument and depositing it would ship a confident wrong bank.
	 * {@link #argumentSurvivesPrologue} tests that precondition over {@code entry..firstSite},
	 * and a failure falls through rather than short-circuiting, so the strategy still decides
	 * ownership and only the bits this call really writes are poisoned.
	 * <p>
	 * <b>That fallback has THREE outcomes, not two</b> (bead grm-67g), tried in this order once
	 * the caller's register is ruled out:
	 * <ol>
	 * <li>the caller's byte arriving through MEMORY -- {@link #inboundArgumentCell} proves the
	 * helper consumes a cell it never writes, and {@link StoredValueScanner#callerCellValue}
	 * reads what the caller stored there (smb3's {@code $0720});</li>
	 * <li>the helper's OWN value where its body supplies a constant --
	 * {@link #valueSuppliedInsideHelper} (grm-cxb), reading whichever site the strategy says
	 * consumes the byte ({@link #helperValueSite});</li>
	 * <li>unknown.</li>
	 * </ol>
	 * So a failed prologue test is not by itself a guarantee of silence. It is skipped for a strategy
	 * that re-derives the value inside the
	 * helper instead of consuming {@code argValue} -- see
	 * {@link BankSwitchStrategy#consumesHelperArgument}, and note that memory-latch's Contra
	 * helper is a prologue-clobber case that must keep resolving.
	 * <p>
	 * {@code envCache} memoizes that environment per call address for the duration of one
	 * {@link BankDataflowEngine#runDataflow}; see its declaration there for why it is not optional.
	 * <p>
	 * <b>The environment is PROLOGUE-FILTERED, per register</b> (bead grm-k90). What
	 * {@link #callSiteRegisters} scans is the caller's raw A/X/Y, and for a WRAPPER model the
	 * wrapper's body executes between the caller and the point the env claims to describe -- it
	 * may freely write X or Y, and {@link HelperDiscovery#isPassThroughInto} admits an
	 * {@code LDX #imm} without blinking. For a CALL-EDGE wrapper it is worse than theoretical: the
	 * scan stops at {@code relay.calleeEntry()} and never walks the wrapper's prefix at all, so an
	 * unfiltered env would hand a strategy a register value the wrapper had already overwritten. Each
	 * of A/X/Y is therefore passed through only where
	 * {@link #argumentSurvivesPrologue(Program, List, char)} holds for THAT register over
	 * {@link #prologueSegments}, and comes back {@link BankState#unknown()} otherwise. The test
	 * is per-register precisely because the answers differ: on Contra's {@code FUN_c139} wrapper
	 * ({@code LDA $8000 / STA $07ec}, falling into {@code FUN_c13f}) A does not survive and Y
	 * does, and it is Y the latch actually consumes.
	 * <p>
	 * This is uniform across ordinary helpers, pass-through wrappers and call-edge wrappers, and
	 * for an ordinary helper it is not a behavior change in any measured case -- the same
	 * predicate over the same span already gated {@code argValue} just above. Note the
	 * interaction with the crossable join below: for a PASS-THROUGH wrapper the scan now walks
	 * the wrapper's prefix itself, so a register the filter would have zeroed is one the scan
	 * clobbers on its own before ever reaching the stop. The filter is therefore
	 * redundant-but-harmless there, and load-bearing for the call-edge case where the prefix is
	 * never walked. It is kept for both because "the env describes the caller's registers as
	 * they are at the point the env stops" is the invariant, and an invariant that holds only on
	 * the paths that happen to re-derive it is not one.
	 * <p>
	 * <b>And it nominates the join the scan may cross</b> ({@link #crossableWrapperJoin}), which
	 * is what makes the stop reachable at all for a pass-through wrapper. The bead's own filed
	 * hypothesis -- that these call sites fail because {@code recoverCallArgument} gates the
	 * whole path on {@code argumentSurvivesPrologue} with {@code reg == argReg == 'A'} -- is
	 * WRONG for memory-latch, and worth recording so nobody re-derives it: that gate is skipped
	 * entirely, because {@link BankSwitchStrategy#consumesHelperArgument} is false for
	 * memory-latch. The real failure was the join refusal killing the walk two instructions
	 * short of the env's stop.
	 */
	static CallEffect recoverCallArgument(Program program, Instruction callInstr,
			HelperModel helper, BankState callSiteIn, Map<CallSiteRegKey, RegisterEnv> envCache,
			Set<Function> restoringTrampolines) {
		if (restoringTrampolines.contains(helper.function())) {
			// A VERIFIED no-op (grm-mej.3): this helper puts the entry bank back before returning,
			// so the call owns nothing. Answered before argReg is even consulted, because the
			// argument is genuinely irrelevant here -- it selects the bank the INNER call runs in,
			// and that is over by the time the caller resumes. See
			// SaveRestoreTrampolines.restoresEntryBank.
			return new CallEffect(BankState.unknown(), 0);
		}
		Character reg = helper.argReg();
		if (reg == null) {
			return new CallEffect(BankState.unknown(), helper.effectMask());
		}
		int stateMask = helper.effectMask() >>> helper.lsb();
		// The call's tracked in-state, narrowed to THIS helper's mechanism's field-local
		// [0, width) space -- computed once, up front, rather than where the pre-grm-mej.3 code
		// first needed it (just before the depositHelperArgument call below). Every caller-side
		// scan in this method now needs it too (grm-mej.3 item 4): a mirror-aware Hooks answers
		// hooks.resolveMirrorLoad from exactly this state, in exactly this coordinate space -- see
		// MemoryLatchBankSwitchStrategy.mirroredByte's "COORDINATE CONVERSION" javadoc for why
		// getting that space wrong is the easiest way to ship a wrong bank here.
		BankState localIn = toFieldLocal(callSiteIn, helper.lsb(), helper.effectMask());
		// The Hooks a scan running at THIS call site (i.e. outside helper's own instructions) may
		// use (bead grm-mej.3 item 4). NOT NO_HOOKS any more for a strategy that overrides
		// BankSwitchStrategy.callerSideHooks() (MemoryLatchBankSwitchStrategy does, for contra's
		// c0d3 LDA $8000 at a call site) -- but NO_HOOKS remains exactly right for
		// valueSuppliedInsideHelper and inboundArgumentCell's effectiveOperandTarget call below,
		// which run INSIDE the helper / do address computation rather than caller-side value
		// recovery, and are deliberately NOT converted.
		StoredValueScanner.Hooks callerHooks = callerHooksFor(helper);
		BankState local = StoredValueScanner.resolveStoredValue(program, callInstr, reg,
			localIn, stateMask, callerHooks);
		// grm-mu7: what the caller left in argReg is this helper's argument only if the helper
		// still has it when the first switch site reads it. Withholding the value (rather than
		// short-circuiting the whole call) is deliberate -- it routes the call down the exact
		// path an unresolvable caller-side scan already takes, so the strategy still decides
		// which bits this site owns and poisons only those. Strategies that re-derive the value
		// inside the helper are exempt; see BankSwitchStrategy.consumesHelperArgument.
		//
		// grm-67g: the caller's byte may still reach the site THROUGH MEMORY even when it does not
		// reach it in the register -- smb3's `LDA #$1b / STA $0720 / JSR $ffc2` against a helper
		// that reloads A from $0720. So this branch makes two attempts before giving up, in the
		// order caller's-cell then helper's-own-constant, and both are strictly additive: it only
		// ever runs where the register answer was already discarded.
		// grm-jqt0: computed alongside the existing survival test, on the same register, rather
		// than as a separate pass -- see PrologueOutcome's javadoc for why "does not survive" and
		// "provably clobbered" are different questions with the same evidence. Zero cost when the
		// argument DOES survive (short-circuits before the second call), and answers a question
		// BoardBankAnalyzer needs regardless of which of the three fallback attempts below (if
		// any) goes on to recover a value anyway -- this describes the REGISTER at the call site,
		// not whether some other channel happened to compensate.
		//
		// NOTE THE DIFFERENT SPANS, which is load-bearing and was a bug in this bead's second
		// increment (rcransom FUN_fed1/FUN_fe56 asserted "no inbound argument" about helpers that
		// demonstrably take one). The survival test keeps prologueSegments, ending at firstSite,
		// because that is the span its own callers' value recovery is defined over and widening it
		// would change RECOVERED VALUES. The clobber PROOF uses clobberSegments, ending at
		// helperValueSite -- the site where the value is actually CONSUMED, which for a
		// select-data helper is switchSite and not firstSite (grm-67g). rcransom's FUN_fed1 is
		// why: its firstSite is the MMC3 SELECT write STA $8000 at $fed8, while the caller's
		// argument is read back stack-relative at $fedc (TSX / LDA $0102,X) and committed at
		// $fee2. A span ending at firstSite stops BEFORE the reload and concludes, wrongly, that
		// the register was clobbered for good.
		//
		// Widening only the PROOF's span is sound in one direction and that is the direction that
		// matters: more walked instructions can only reveal a restore, clear straightLine, or trip
		// the stack-page tripwire -- every one of which turns DEFINITELY_CLOBBERED into
		// INDETERMINATE. It cannot manufacture a clobber proof that the shorter span did not
		// already support, because this expression is guarded by the survival test above and so is
		// only ever evaluated where the argument was already known not to survive to firstSite.
		boolean definitelyNoInboundArgument =
			(helper.strategy() == null || helper.strategy().consumesHelperArgument()) &&
				!argumentSurvivesPrologue(program, prologueSegments(helper), reg) &&
				argumentDefinitelyClobbered(program, clobberSegments(helper), reg);
		if ((helper.strategy() == null || helper.strategy().consumesHelperArgument()) &&
			!argumentSurvivesPrologue(program, prologueSegments(helper), reg)) {
			Address inbound = inboundArgumentCell(program, helper, reg);
			BankState viaCell = inbound == null ? BankState.unknown()
					: StoredValueScanner.callerCellValue(program, callInstr, inbound, localIn,
						stateMask, callerHooks);
			// Partial knowledge counts, matching how combine() and setFieldFromByte already treat
			// a per-bit answer. Mirror-aware as of grm-mej.3 item 4 for the same reason the
			// caller-side register scan above is: this scan runs in the CALLER, outside any
			// mechanism's interpretation, and callerHooks' isMechanismWrite (when the strategy
			// overrides it) is what keeps that sound -- see BankSwitchStrategy.callerSideHooks()'s
			// javadoc. A store to the mechanism is still stepped over on the strength of being a
			// provably different cell than `inbound`; what changed is only that a LOAD of a mirror
			// encountered on the way there can now resolve instead of declining outright.
			local = viaCell.knownMask() != 0 ? viaCell
					: valueSuppliedInsideHelper(program, helper, reg, stateMask);
		}
		Instruction switchSite = helper.switchSite() == null ? null
				: program.getListing().getInstructionAt(helper.switchSite());
		if (helper.strategy() == null || switchSite == null) {
			return new CallEffect(position(local, helper.lsb(), helper.effectMask()),
				helper.effectMask(), local.knownMask() != 0, definitelyNoInboundArgument);
		}
		// helper.entry(), not function().getEntryPoint(): the mini-inline scan must stop where
		// control actually arrived. For a mid-body entry those differ, and stopping at the
		// function entry would walk the scan back through the very prologue this call skipped.
		// For a CALL-EDGE wrapper it is the relay's callee entry instead: the scan runs inside
		// the WRAPPED helper, so stopping at the wrapper's entry would let it run off the
		// helper's own entry and back into the wrapper's tail (grm-2dr increment 2).
		Address scanStop = insideHelperEntry(helper);
		// Keyed on (call address, localIn), not address alone (bead grm-mej.3 item 4, tripwire 2)
		// -- see the memo's declaration at BankDataflowEngine.runDataflow for why the address-only
		// key this replaced is no longer sound. BankState is a record, so CallSiteRegKey gets
		// value equality on localIn for free.
		RegisterEnv callerRegs = envCache.computeIfAbsent(
			new CallSiteRegKey(callInstr.getMinAddress(), localIn),
			key -> callSiteRegisters(program, callInstr, scanStop,
				crossableWrapperJoin(program, helper.firstSite(), scanStop), helper, localIn));
		// The argument-bearing deposit, computed exactly as it was before grm-4bgh.5 -- this
		// is both the answer for a single-site helper and, for a folded one, the deposit whose
		// emptiness decides whether this CALL SITE gets a warning. See foldDeposits.
		BankSwitchStrategy.HelperDeposit primary = helper.strategy()
				.depositHelperArgument(program, switchSite, local, localIn, stateMask, callerRegs);
		BankSwitchStrategy.HelperDeposit deposit = foldDeposits(program, helper, primary, localIn,
			stateMask, callerRegs);
		BankState positionedValue = position(deposit.value(), helper.lsb(), helper.effectMask());
		int positionedOwnedMask = (deposit.ownedMask() << helper.lsb()) & helper.effectMask();
		return new CallEffect(positionedValue, positionedOwnedMask,
			primary.value().knownMask() != 0, definitelyNoInboundArgument);
	}

	/**
	 * The helper's deposit: one per RECOGNIZED SITE for a strategy that says its sites are
	 * independent, folded in address order; otherwise the single {@code switchSite} deposit this
	 * method has always produced (bead grm-4bgh.5).
	 * <p>
	 * <b>Why one site is not always enough.</b> {@code HelperModel.switchSite} is the
	 * max-address site, a PROXY for "the last recognized write on the path to the return", and
	 * that is exactly right for a serial-shift chain whose five writes commit one value. It has
	 * no correct answer for a helper that deposits into SEVERAL fields from one argument:
	 * rcransom's {@code FUN_fed1} sets R6 = A*2 at {@code $FEE2} and R7 = A*2+1 at {@code $FEF5},
	 * and the proxy picks {@code $FEF5}, so the R6 deposit -- the one that actually resolves --
	 * is never consulted. There is no single site that could be picked instead: both deposits
	 * are real and neither summarizes the other. Which shape a mechanism has is
	 * {@link BankSwitchStrategy#depositsPerSite}'s question, not something this method guesses
	 * from the site count.
	 * <p>
	 * <b>The fold's semantics are execution semantics.</b> Sites are visited in ascending
	 * address order and a later site OVERWRITES an earlier one on the bits it owns
	 * ({@link BankDataflowEngine#overwrite}, the same per-bit replace the engine already uses to
	 * fold a mechanism's effect into a state), while {@code ownedMask} accumulates as a union.
	 * fed1 relies on both halves of that: its two select writes deposit the same field with
	 * different values ({@code $06} then {@code $07}) and the later one must win, while its two
	 * data writes own disjoint fields and must both survive.
	 * <p>
	 * <b>EVERY FOLDED SITE OWNS WHAT IT WRITES, RESOLVED OR NOT -- unresolved ownership is
	 * HONEST POISON and is kept.</b> This was measured both ways, and the losing variant is
	 * instructive. Restricting a folded-in site to the bits it actually RESOLVED
	 * ({@code ownedMask & value.knownMask()}) preserves more prior knowledge and reads as the
	 * conservative choice, but it makes the annotation LIE: at rcransom's {@code $C08E} the
	 * comment then renders {@code r6=0} as known, echoing the dataflow's prior belief, at a
	 * call to {@code FUN_fed1} -- a helper that demonstrably WRITES r6 (as {@code A*2}) with a
	 * value this site could not recover. A bit a helper writes is not a bit the caller still
	 * knows. The apparent cost of poisoning -- rcransom's {@code $B80B} losing {@code select}
	 * and {@code r6}, both previously "known" -- is on inspection not a cost at all: an
	 * intervening {@code fed1} call really does clobber those fields with an unrecoverable
	 * value, so the knowledge being lost was already wrong. Precision that survives only
	 * because a write went unmodeled is not precision.
	 * <p>
	 * <b>{@code primary} decides the WARNING, not the folded result.</b> A call whose helper
	 * writes a select register from its own constant now KNOWS something even when the caller's
	 * argument was not recovered at all -- and {@code BankAnnotationAdapter.annotateOrWarn}
	 * warns on "nothing is known", which that would silently satisfy. Measured on rcransom, the
	 * first version of this bead dropped its warning count from 43 to 5 while every one of those
	 * sites' actual bank fields stayed unresolved, quietly shrinking the very census grm-nqxt is
	 * adjudicating. So {@link CallEffect#argumentResolved} reports whether {@code primary} --
	 * the deposit at the site that consumes the caller's argument -- resolved anything, and
	 * {@code BoardBankAnalyzer} warns off that. The comment still renders from the richer folded
	 * state, so such a site now carries BOTH a warning and a partial annotation: the warning
	 * says the argument was not recovered, and the comment says what the helper's own body
	 * established regardless.
	 * <p>
	 * <b>The fold requires the sites to RUN UNCONDITIONALLY, and that is a soundness condition
	 * rather than a tidiness one</b> -- see {@link #sitesRunUnconditionally}. Folding asserts
	 * that every site executed on this call; two mechanism writes on opposite arms of a branch
	 * would have exactly one of them execute, and depositing both would ship a value from a path
	 * that did not run. When the guard declines, this falls back to the single-site deposit,
	 * which is no worse than the behaviour before this bead.
	 * <p>
	 * <b>THE FACE-VALUE ARGUMENT IS OFFERED TO AT MOST ONE SITE, and this is a soundness rule,
	 * not a refinement.</b> {@code argValue} is a claim about ONE deposit: a
	 * {@code HelperModel} carries one {@code argReg} and the convention that the register holds
	 * the field value itself. Handing the same byte to several independent deposits asserts
	 * that every field this helper writes receives that same value, which is exactly the
	 * assumption bead grm-4bgh was filed to say is wrong. The amplification is real and was
	 * measured while writing this bead's tests: {@link #valueSuppliedInsideHelper} scans back
	 * from the helper's value site with {@link #NO_HOOKS}, which steps straight over an earlier
	 * mechanism write (a plain {@code STA} does not touch the register being resolved), so it
	 * can return a constant that belongs to a DIFFERENT site -- an earlier select write's own
	 * {@code LDA #imm}, say. Under an unrestricted fold that stray constant would be deposited
	 * verbatim into every field at once.
	 * <p>
	 * So only {@code switchSite} -- the site this model already summarized before grm-4bgh.5,
	 * and the only one with any prior claim to the recovered byte -- is offered {@code local},
	 * as {@code primary}, computed by {@link #recoverCallArgument} before this method is even
	 * called. Every other site is passed {@link BankState#unknown()} and must earn its value
	 * from its own body under the caller's registers, which is precisely what
	 * {@code SelectDataBankSwitchStrategy}'s {@code callerRegs} mini-inline (grm-4bgh.4) does
	 * and what makes rcransom's {@code $FEE2} resolve to {@code A*2} rather than to {@code A}.
	 * The rule also makes the fold a strict superset of the old behaviour at {@code switchSite}
	 * itself: that site's deposit is byte-identical to what it was.
	 * <p>
	 * {@code inState} ({@code localIn}) IS the same for every site: it is the state flowing into
	 * the CALL, which no site changes. Threading each site's accumulated result into the next as
	 * its {@code inState} was considered and not done -- the one thing it would buy for
	 * select-data (a data write routed by a select the same helper set) is already answered per
	 * site, and better, by {@code selectSuppliedInsideHelper} reading the helper's own body.
	 */
	private static BankSwitchStrategy.HelperDeposit foldDeposits(Program program,
			HelperModel helper, BankSwitchStrategy.HelperDeposit primary, BankState localIn,
			int stateMask, RegisterEnv callerRegs) {
		BankSwitchStrategy strategy = helper.strategy();
		List<Address> sites = helper.sites();
		if (!strategy.depositsPerSite() || sites.size() < 2
				|| !sitesRunUnconditionally(program, sites)) {
			return primary;
		}
		Listing listing = program.getListing();
		BankState value = primary.value();
		int owned = primary.ownedMask();
		for (Address siteAddr : sites) {
			if (siteAddr.equals(helper.switchSite())) {
				continue; // already folded in as primary, and the only site offered argValue
			}
			Instruction site = listing.getInstructionAt(siteAddr);
			if (site == null) {
				// No instruction to interpret. Cannot happen for a site findHelpers recorded,
				// but claiming a field on the strength of an address alone is exactly the kind
				// of guess this engine refuses: skip it, owning nothing.
				continue;
			}
			BankSwitchStrategy.HelperDeposit deposit = strategy.depositHelperArgument(program,
				site, BankState.unknown(), localIn, stateMask, callerRegs);
			int siteOwned = deposit.ownedMask();
			BankState scoped = new BankState(deposit.value().knownMask() & siteOwned,
				deposit.value().bits() & siteOwned);
			value = overwrite(value, scoped, siteOwned);
			owned |= siteOwned;
		}
		return new BankSwitchStrategy.HelperDeposit(owned, value);
	}

	/**
	 * Whether every one of {@code sites} runs on every call that reaches the first of them --
	 * the precondition {@link #foldDeposits} needs before it may attribute all their deposits to
	 * one call.
	 * <p>
	 * The test is deliberately blunt: walk the instructions from the lowest site to the highest
	 * and require a contiguous FALL-THROUGH chain containing no jump of any kind. A conditional
	 * branch in the span could skip a later site; an unconditional one could skip it or leave
	 * the body entirely; a gap in the disassembly is bytes whose control flow is unknown, which
	 * is not the same as harmless. A CALL is permitted -- it returns to the next instruction, so
	 * the later sites still run, and whatever it does to the registers is the per-site scan's
	 * problem, which that scan already declines on.
	 * <p>
	 * An incoming branch INTO the span (a control-flow join) is deliberately NOT disqualifying.
	 * It means some other path reaches the middle of this body, but it does not remove any site
	 * from the path THIS call takes, which is the only claim the fold makes. A call that enters
	 * mid-body is a different model entirely -- see {@code HelperDiscovery.midBodyEntryHelper},
	 * whose own admission test asks the corresponding question for that case.
	 * <p>
	 * Any missing instruction, any address-space mismatch, or any site outside the walked span
	 * declines, in keeping with this file's standing rule that a false decline costs one
	 * annotation while a false accept ships a wrong bank.
	 */
	private static boolean sitesRunUnconditionally(Program program, List<Address> sites) {
		Address first = sites.get(0);
		Address last = sites.get(sites.size() - 1);
		if (first == null || last == null
				|| !first.getAddressSpace().equals(last.getAddressSpace())) {
			return false;
		}
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(first);
		if (instr == null) {
			return false;
		}
		Set<Address> wanted = new LinkedHashSet<>(sites);
		wanted.remove(first);
		while (!instr.getMinAddress().equals(last)) {
			if (instr.getFlowType().isJump()) {
				return false; // a branch could route around a later site
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough == null) {
				return false; // no straight-line successor: the walk cannot continue
			}
			Instruction next = listing.getInstructionAt(fallThrough);
			if (next == null) {
				return false; // undisassembled bytes: unknown control flow, not harmless
			}
			wanted.remove(next.getMinAddress());
			instr = next;
		}
		return wanted.isEmpty();
	}

	/**
	 * Whether a value the CALLER left in {@code reg} is still there when the helper's first
	 * recognized switch site reads it -- the soundness precondition for
	 * {@link #recoverCallArgument} handing that value to a strategy that takes it at face
	 * value (grm-mu7).
	 * <p>
	 * <b>The bound is {@code firstSite}, emphatically not {@code switchSite}.</b> The argument
	 * has to survive as far as the FIRST site because that is where the mechanism consumes it;
	 * what happens after is the mechanism's own business, and a serial-shift chain's
	 * {@code STA/LSR A/STA/...} clobbers A four times between its first write and its last by
	 * design. Walking to {@code switchSite} would therefore decline every serial-shift helper
	 * on the planet -- it would "fix" this bug by disabling the feature.
	 * <p>
	 * <b>{@code entry}, not the function's entry point.</b> The prologue this must inspect is
	 * the part of it a given call actually runs. Bionic Commando's {@code FUN_dca8} is exactly
	 * why: entering at {@code $DCA8} runs {@code LDA $65} and the caller's A is irrelevant,
	 * while entering at {@code $DCAA} -- the mid-body entry its jump table really uses -- skips
	 * that load and takes the bank in A. One function, two answers, told apart by nothing but
	 * this address; a mid-body entry equal to {@code firstSite} walks an empty range and
	 * correctly keeps its argument.
	 * <p>
	 * Declining conditions, all conservative -- a false decline costs one annotation, a false
	 * accept ships a wrong bank:
	 * <ul>
	 * <li><b>Anything that writes {@code reg}</b>, asked of the language rather than a mnemonic
	 * list so an undocumented or synthetic opcode cannot slip past.</li>
	 * <li><b>Any call</b>: the callee's register effects are not modeled here at all.</li>
	 * <li><b>A gap in the disassembly</b>, i.e. the walk cannot reach {@code firstSite} through
	 * contiguous instructions. Undisassembled bytes in the middle of a helper body are bytes
	 * whose register effects are unknown, which is not the same as harmless.</li>
	 * <li><b>A missing {@code firstSite}</b> -- {@code HelperDiscovery.findHelpers}' multi-mechanism
	 * degrade case, where the model no longer describes one coherent mechanism and there is nothing
	 * meaningful to walk to.</li>
	 * </ul>
	 * <b>A CLOBBER IS NOT A LOSS WHEN THE PROLOGUE SAVED THE ARGUMENT FIRST.</b> This is not a
	 * refinement, it is the difference between working and not working, and it was measured the
	 * expensive way: the first version of this method tested only "does anything write
	 * {@code reg}", and that silently destroyed three real ROMs. Castlevania 2's {@code FUN_c187},
	 * byte-exact:
	 * <pre>
	 *   c187  PHA            ; save the caller's bank argument
	 *   c188  LDA #$01       ; the naive test declines HERE
	 *   c18a  STA $0103
	 *   c18d  PLA            ; ...but this puts the argument back
	 *   c18e  STA $FFFF      ; firstSite: the chain consumes A, correctly
	 * </pre>
	 * The argument survives perfectly well -- across the stack. Declining cost Kid Icarus all 215
	 * of its overlay instructions, Dodgeball all 10692 of its, and Castlevania 2 both of its bank
	 * comments; the synthetic goldens all passed, because none of them saves and restores.
	 * <p>
	 * So the walk carries an abstract state instead of a single flag: whether {@code reg} still
	 * holds the caller's value, a shadow stack of which pushed bytes ARE that value, and the set
	 * of memory cells it was stored to and not yet overwritten. {@code PHA} pushes the current
	 * answer, {@code PLA} pops it back, and {@code PHP}/{@code PLP} are modelled purely to keep
	 * the depth honest so an interleaved status push cannot make a later {@code PLA} pop the
	 * wrong byte. Anything else that moves the stack pointer abandons the model rather than guess
	 * at the new depth.
	 * <p>
	 * <b>The memory half is not optional either</b> -- the same three ROMs need both. Double
	 * Dribble's {@code FUN_ff08} restores from the stack and then immediately parks the argument
	 * in RAM, because it needs A again for an unrelated shadow:
	 * <pre>
	 *   ff11  PLA            ; the argument is back...
	 *   ff12  STA $0103      ; ...and immediately parked in memory
	 *   ff15  LDA $ff        ; A reused for the mirroring shadow
	 *   ff1a  STA $ff
	 *   ff1c  LDA $0103      ; the argument is reloaded HERE
	 *   ff1f  STA $FFFF      ; firstSite
	 * </pre>
	 * A load counts as a restore only when it reads a cell this walk watched the argument being
	 * written to and nothing has written since; every other write to {@code reg} loses it. An
	 * indexed store forgets every tracked cell, since its target is runtime-dependent and could
	 * have landed on any of them.
	 * <p>
	 * <b>This is a PRESERVATION model, not a value model.</b> It answers only "does the caller's
	 * byte still reach the first site", never "what is it" -- the value still comes from the
	 * caller-side scan. Teaching {@link StoredValueScanner} to carry values through the stack and
	 * across blocks is a different and much larger capability, tracked by {@code grm-mej.3} and
	 * blocked on {@code grm-mej.2}; nothing here anticipates it.
	 * <p>
	 * <b>Soundness of the save/restore half.</b> The clobber half of this walk is linear in
	 * address order, which is a proxy for execution order in the same way
	 * {@code HelperDiscovery.HelperModel.switchSite}'s max-address rule is, and it errs SAFE: a
	 * prologue that branches around a clobber is declined even though the argument survives the taken
	 * path. The save/restore half does not get that for free -- a branch that skipped a {@code PLA}
	 * would make "restored" a claim about a path that never runs, and that error points the
	 * unsafe way. It is therefore trusted only over genuinely straight-line code: any
	 * non-fall-through flow in the range abandons the shadow stack, after which a {@code PLA} is
	 * an ordinary clobber again. Clobber detection itself is unaffected and stays conservative.
	 * <p>
	 * <b>Where the memory half and the stack half collide</b>: a push writes memory too, at
	 * {@code $0100 + S}, so a tracked cell in the stack page could be clobbered by the very
	 * {@code PHA} this walk models as a pure save. {@link StackFloor} draws that line, applied
	 * by {@link #forgetCellsThePushMayHaveHit}; the same floor governs
	 * {@code StoredValueScanner.forwardedStoreValue} and {@link #inboundArgumentCell}, so all
	 * three walks now make one assumption instead of three tacit ones.
	 */
	/**
	 * Drops every tracked cell a {@code PHA}/{@code PHP} could have landed on, per
	 * {@link StackFloor}. The pushes are otherwise {@code modelled = true} and so skip the
	 * generic {@code argumentCells.removeIf} below -- which is right for the register half (a
	 * push does not clobber {@code reg}) and wrong for the memory half, since a push does write
	 * memory, at an address no detector in {@link StoredValueScanner} can name because it is
	 * {@code $0100 + S}. Below the floor this removes nothing, which is the whole point: the
	 * measured cell in Double Dribble and Castlevania 2 is {@code $0103}.
	 */
	private static void forgetCellsThePushMayHaveHit(Program program, Set<Address> argumentCells) {
		argumentCells.removeIf(cell -> StackFloor.mayAliasStack(program, cell));
	}

	/**
	 * The three-way outcome of the prologue walk {@link #argumentSurvivesPrologue} performs,
	 * exposing WHY a "does not survive" answer was reached (bead grm-jqt0). The plain boolean
	 * collapses {@code DEFINITELY_CLOBBERED} and {@code INDETERMINATE} into the same "false",
	 * which is exactly right for {@link #recoverCallArgument}'s own gating (either way, do not
	 * trust the caller's register) but wrong for {@code BoardBankAnalyzer}'s warning text: a
	 * call site whose helper genuinely never receives an argument in that register is not a gap
	 * in this analyzer, and must not be reported as one.
	 * <ul>
	 * <li>{@code SURVIVES} -- unchanged meaning, the caller's byte reaches {@code firstSite}.</li>
	 * <li>{@code DEFINITELY_CLOBBERED} -- the walk ran the WHOLE way to {@code firstSite} with
	 * {@code straightLine} true throughout (no branch, no unmodelled stack-pointer write, no
	 * unpaired {@code PLA}/{@code PLP} -- see below for why that flag is exactly the needed
	 * witness) and still ended with {@code holdsArgument} false. Every write to {@code reg} this
	 * walk saw was therefore evaluated under fully trustworthy save/restore accounting, so a
	 * "does not survive" here is a PROOF, not a guess: {@code reg} is provably redefined from
	 * something other than the caller's value on every path this prologue can take.</li>
	 * <li>{@code INDETERMINATE} -- everything else: a disassembly gap, a call, running off the
	 * end of the space, an unaskable register, a malformed span, OR a completed walk whose
	 * {@code straightLine} went false somewhere along the way. That last case matters: once
	 * {@code straightLine} is false, {@code holdsArgument}'s own formula
	 * ({@code straightLine && from != null && argumentCells.contains(from)}) forces every
	 * SUBSEQUENT write to read as a loss regardless of what it actually reloads, which is the
	 * correct SAFE answer for "does it survive" but would be a FALSE claim of "provably
	 * clobbered" -- the truth after a desync is "unknown", not "definitely something else".</li>
	 * </ul>
	 * <b>Why {@code straightLine}'s final value is exactly the needed witness, with no separate
	 * tracking added.</b> The field is monotonic in this method -- every assignment in the walk
	 * sets it to {@code false}; nothing ever sets it back to {@code true}. So "true at the end"
	 * already means "never went false", which is precisely "every write-detection this walk made
	 * ran under conditions the save/restore model fully trusted". Reusing it rather than adding a
	 * parallel {@code sawBranch}-style flag is deliberate: two variables tracking the same
	 * question could drift, and this bead's own instruction was to reuse the EXISTING
	 * distinction rather than invent a parallel one.
	 * <p>
	 * <b>Verified against this bead's three named cases.</b> zelda2's {@code FUN_ffc9}
	 * ({@code LDA $0769} as the very first instruction, reg {@code 'A'}): the load is a plain,
	 * unconditional write with an {@code argumentReloadSource} of {@code $0769}, a cell nothing
	 * upstream of this walk ever stored to, so {@code holdsArgument} goes false right there,
	 * {@code straightLine} never moves, and the walk (a short, branch-free LDA/STA chain) reaches
	 * {@code firstSite} cleanly -- {@code DEFINITELY_CLOBBERED}. Contra's {@code FUN_c139}
	 * (falls into {@code FUN_c13f}, which takes its argument in {@code Y}) touches only {@code A};
	 * asked with {@code reg == 'Y'}, {@code writesRegister(instr, Y)} is never true, so
	 * {@code holdsArgument} for Y stays true the entire way -- {@code SURVIVES}, unaffected by
	 * this refinement. Castlevania 2's {@code FUN_c183}/{@code c185}/{@code c187} chain
	 * ({@code STA $1C} then {@code LDA $1C}, evaluated together over the FULL composed prologue,
	 * exactly as {@link #recoverCallArgument} already does via {@link #prologueSegments}): the
	 * store records {@code $1C} in {@code argumentCells} and the later load recognizes it as a
	 * restore, so {@code holdsArgument} stays true and the outcome is {@code SURVIVES} -- never
	 * {@code DEFINITELY_CLOBBERED}, which is exactly why this predicate must be evaluated on the
	 * helper's OWN fully-resolved model (as {@link #recoverCallArgument} does) and never on one
	 * wrapper layer's isolated body in isolation from the layers around it.
	 */
	enum PrologueOutcome {
		SURVIVES, DEFINITELY_CLOBBERED, INDETERMINATE
	}

	static boolean argumentSurvivesPrologue(Program program, Address entry, Address firstSite,
			char reg) {
		return prologueOutcome(program, entry, firstSite, reg) == PrologueOutcome.SURVIVES;
	}

	/**
	 * Whether {@code reg}'s value at {@code firstSite} is PROVABLY not the caller's, over the
	 * single span {@code [entry, firstSite)} -- see {@link PrologueOutcome#DEFINITELY_CLOBBERED}
	 * for exactly what that proof requires.
	 */
	static boolean argumentDefinitelyClobbered(Program program, Address entry, Address firstSite,
			char reg) {
		return prologueOutcome(program, entry, firstSite, reg) == PrologueOutcome.DEFINITELY_CLOBBERED;
	}

	private static PrologueOutcome prologueOutcome(Program program, Address entry,
			Address firstSite, char reg) {
		if (entry == null || firstSite == null || entry.compareTo(firstSite) > 0) {
			return PrologueOutcome.INDETERMINATE;
		}
		Register register = program.getLanguage().getRegister(String.valueOf(reg));
		if (register == null) {
			return PrologueOutcome.INDETERMINATE; // cannot ask the question -> not a proof either way
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		Listing listing = program.getListing();
		// Does argReg still hold what the CALLER left in it?
		boolean holdsArgument = true;
		// The saved-value stack: one entry per byte this walk watched being pushed, true when
		// that byte IS the caller's argument. Only consulted while straightLine holds.
		Deque<Boolean> saved = new ArrayDeque<>();
		// The memory half of the same idea: cells this walk watched the argument being stored to
		// and which nothing has overwritten since, so a load from one is a restore.
		//
		// Note the DUAL of this set, inboundArgumentCell (grm-67g): a cell enters here only when
		// the HELPER stores argReg into it, and enters there only when the helper never does. A
		// helper cannot satisfy both, which is what lets recoverCallArgument try them in sequence
		// without the order mattering.
		Set<Address> argumentCells = new LinkedHashSet<>();
		// Whether the save/restore model is still trustworthy. Cleared by anything that moves
		// the stack pointer in a way this does not model, and by any non-fall-through flow --
		// see the javadoc's soundness note.
		boolean straightLine = true;
		// Whether this walk saw an absolute-indexed access whose base lies in the stack page
		// (bead grm-jqt0, third increment -- the M15/grm-mu7 hazard in a THIRD form, found on
		// rcransom's FUN_fed1/FUN_fe56). TSX + LDA $0100+n,X is a stack-relative reload: it reads
		// the caller's argument back off the stack WITHOUT a PLA, which is exactly the shape this
		// walk's save/restore model (PHA/PLA/PHP/PLP only) does not recognize. Left unguarded,
		// {@code holdsArgument} goes false at the {@code LDA} (a plain write to {@code reg} whose
		// {@code argumentReloadSource} is not a cell this walk tracked) with {@code straightLine}
		// still true -- exactly {@link PrologueOutcome#DEFINITELY_CLOBBERED}'s signature, and
		// WRONG: {@code FUN_fed1} demonstrably does take the argument, at {@code $fee2}
		// ({@code r6 = A*2}) and {@code $fef5} ({@code r7 = A*2+1}), both already documented at
		// {@link BankSwitchStrategy}'s {@code foldDeposits} javadoc.
		// <p>
		// Deliberately NOT an attempt to identify the matching {@code TSX} and recover the actual
		// value the way {@code StoredValueScanner.stackRelativePush} does for value recovery --
		// that is grm-mej.3/grm-4bgh's job. This is a much blunter, purely syntactic tripwire:
		// ANY absolute-indexed access (load or store, either register the walk is asked about or
		// not) whose base falls in {@code $0100-$01FF} anywhere in the walked span downgrades a
		// would-be {@code DEFINITELY_CLOBBERED} to {@code INDETERMINATE} -- costing only the OLD
		// wording ("could not be recovered"), never a wrong claim. Blunt is correct here: a false
		// trigger is free, a missed one ships a false "no argument" statement.
		boolean sawStackRelativeAccess = false;
		Address cursor = entry;
		while (cursor.compareTo(firstSite) < 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || instr.getFlowType().isCall()) {
				return PrologueOutcome.INDETERMINATE;
			}
			if (isStackPageIndexedAccess(instr)) {
				sawStackRelativeAccess = true;
			}
			boolean modelled = false;
			if (reg == 'A') {
				switch (instr.getMnemonicString()) {
					case "PHA" -> {
						if (straightLine) {
							saved.push(holdsArgument);
						}
						forgetCellsThePushMayHaveHit(program, argumentCells);
						modelled = true;
					}
					case "PLA" -> {
						if (straightLine && !saved.isEmpty()) {
							holdsArgument = saved.pop();
						}
						else {
							// Popping a byte this walk never watched being pushed: it belongs to
							// the caller's frame or to code we did not model, and the depth is out
							// of step from here on either way.
							holdsArgument = false;
							straightLine = false;
						}
						modelled = true;
					}
					case "PHP" -> {
						// Modelled only to keep the DEPTH right, so an interleaved status push
						// cannot make a later PLA pop the wrong byte. A status byte is never the
						// argument.
						if (straightLine) {
							saved.push(Boolean.FALSE);
						}
						forgetCellsThePushMayHaveHit(program, argumentCells);
						modelled = true;
					}
					case "PLP" -> {
						if (straightLine && !saved.isEmpty()) {
							saved.pop();
						}
						else {
							straightLine = false;
						}
						modelled = true;
					}
					default -> {
						// fall through to the generic tests below
					}
				}
			}
			if (!modelled) {
				// Any write to a cell we were relying on ends that reliance, whatever wrote it
				// (a plain store, or an INC/ASL-style read-modify-write).
				argumentCells.removeIf(cell -> StoredValueScanner.writesAddress(instr, cell));
				Character stored = StoredValueScanner.storeRegister(instr);
				if (stored != null && stored.charValue() == reg && holdsArgument && straightLine) {
					Address cell = StoredValueScanner.plainAbsoluteTarget(instr);
					if (cell != null) {
						argumentCells.add(cell);
					}
					else {
						// An indexed store's target is runtime-dependent, so it may have landed on
						// any tracked cell. Forget all of them rather than pick.
						argumentCells.clear();
					}
				}
				if (StoredValueScanner.writesRegister(instr, register)) {
					// A load is a RESTORE when it reads back a cell this walk watched the argument
					// being written to; every other write to argReg loses it.
					Address from = argumentReloadSource(instr, reg);
					holdsArgument = straightLine && from != null && argumentCells.contains(from);
				}
				// Anything else that touches the stack pointer (TXS, or a PHX/PLX-style push on a
				// variant that has one) desynchronises the depth, so stop believing the model
				// rather than let a later PLA pop the wrong entry.
				if (stackPointer == null || writesStackPointer(instr, stackPointer)) {
					straightLine = false;
				}
			}
			// A branch or jump means the walk's straight line is not necessarily a real path, so
			// a PLA after it cannot be trusted to pair with a PHA before it. Plain clobber
			// detection is unaffected and stays conservative.
			if (instr.getFlows().length > 0) {
				straightLine = false;
				argumentCells.clear();
			}
			cursor = instr.getMaxAddress().next();
			if (cursor == null) {
				return PrologueOutcome.INDETERMINATE; // ran off the end before reaching firstSite
			}
		}
		if (!cursor.equals(firstSite)) {
			return PrologueOutcome.INDETERMINATE; // defensive; the loop bound should prevent this
		}
		if (holdsArgument) {
			return PrologueOutcome.SURVIVES;
		}
		// holdsArgument is false. That is a PROOF of clobber only if straightLine held for the
		// WHOLE walk AND no stack-relative reload was seen anywhere in it -- see
		// PrologueOutcome's javadoc for the straightLine argument and sawStackRelativeAccess's
		// declaration above for the third hazard (rcransom's FUN_fed1/FUN_fe56).
		return straightLine && !sawStackRelativeAccess ? PrologueOutcome.DEFINITELY_CLOBBERED
				: PrologueOutcome.INDETERMINATE;
	}

	/**
	 * Whether {@code instr} is an absolute-indexed access (load or store, any register) whose
	 * base address lies in the stack page {@code $0100-$01FF} -- the syntactic shape of a
	 * {@code TSX} / {@code LDA $0100+n,X} stack-relative reload, without attempting to confirm
	 * the {@code TSX} or recover the value (that is {@code StoredValueScanner.stackRelativePush}
	 * and {@code findMatchingPush}'s job, deliberately not reused here -- see
	 * {@code sawStackRelativeAccess}'s declaration in {@link #prologueOutcome} for why blunt is
	 * the correct choice for THIS caller).
	 * <p>
	 * Reuses {@link LoopIdioms#indexedBase}, which already returns {@code null} for anything not
	 * indexed (a plain absolute operand, an accumulator-form instruction, immediate, etc.) --
	 * this method adds only the page-range test, the same {@code $0100-$01FF} bound
	 * {@code StoredValueScanner.stackRelativePush} and {@link StackFloor} use elsewhere in this
	 * area, so the "what counts as the stack page" answer is asked of one place, not three.
	 * Deliberately not narrowed to loads, or to X-indexing, or to {@code reg}: any indexed touch
	 * of that page is reason enough to distrust a clobber conclusion for this call, since the
	 * value question this exists to protect is "could the argument be reachable via the stack
	 * at all", not "is THIS particular instruction the reload".
	 */
	private static boolean isStackPageIndexedAccess(Instruction instr) {
		Address base = LoopIdioms.indexedBase(instr);
		if (base == null) {
			return false;
		}
		long offset = base.getOffset();
		return offset >= StackFloor.STACK_PAGE && offset <= StackFloor.STACK_PAGE + 0xFF;
	}

	/**
	 * The byte the helper puts into {@code reg} itself, for the case where
	 * {@link #argumentSurvivesPrologue} has just proved the CALLER's byte does not reach the
	 * first switch site (grm-cxb).
	 * <p>
	 * <b>Declining is not the only honest answer there.</b> Something reaches that site, and once
	 * the caller's value is ruled out it can only have come from inside the helper. Kid Icarus's
	 * {@code FUN_eb07} is the shape that makes this worth doing:
	 * <pre>
	 *   eb07  LDA #$0F       ; the helper supplies its OWN value
	 *   eb09  STA $9FFF      ; firstSite -- $9FFF decodes to MMC1 target 0, Control
	 *   eb0c  LSR A / STA $9FFF / ...
	 * </pre>
	 * It takes no argument at all, and {@code 0x0F} commits {@code mirroring=3, prg_mode=3}. But a
	 * chain helper never has a {@code constState} -- writes 1-4 of a chain echo the in-state and
	 * write 5 commits, so {@link HelperDiscovery#findHelpers}' multi-site disagreement rule nulls it,
	 * by design -- so every one of them is routed through per-call recovery, where the prologue guard
	 * sees that {@code LDA #$0F} clobber and declines. Scanning here recovers the answer the helper's
	 * own body already knows: {@code SerialShiftBankSwitchStrategy.computeSwitch} resolves exactly
	 * this byte, from exactly this instruction, when it evaluates the chain's commit.
	 * <p>
	 * <b>The caller's registers are passed as explicitly UNKNOWN</b>, not omitted. The scan must
	 * stop at {@code entry} -- otherwise it walks back into whatever code physically precedes the
	 * helper and reads it as a prologue -- but it must also not adopt the caller's values there,
	 * because the whole reason we are here is that those values provably do not survive.
	 * {@link RegisterEnv} carries both halves of that: the stop address, and what to believe at
	 * it.
	 * <p>
	 * Bionic Commando's {@code FUN_dca8} ({@code LDA $65}) still declines, on its own merits: the
	 * scan reaches a RAM load it cannot resolve and returns unknown. That is the difference this
	 * whole area turns on -- a helper that supplies a CONSTANT is knowable, one that supplies a
	 * RAM read is not, and neither has anything to do with the caller.
	 * <p>
	 * <b>This is now the LAST resort, not the only one</b> (bead grm-67g):
	 * {@link #recoverCallArgument} tries {@link #inboundArgumentCell} first, so a RAM load whose
	 * cell the CALLER wrote is answered there. The {@code FUN_dca8} decline therefore stands only
	 * where no caller stored to {@code $65} in the same basic block -- which is the honest
	 * refinement, since "the helper reads RAM" was never the real question. "Whose byte is in that
	 * RAM" is.
	 */
	private static BankState valueSuppliedInsideHelper(Program program, HelperModel helper,
			char reg, int stateMask) {
		Address readAt = helperValueSite(helper);
		Instruction site = readAt == null ? null : program.getListing().getInstructionAt(readAt);
		if (site == null) {
			return BankState.unknown();
		}
		RegisterEnv insideOnly = new RegisterEnv(insideHelperEntry(helper), BankState.unknown(),
			BankState.unknown(), BankState.unknown());
		return StoredValueScanner.resolveStoredValue(program, site, reg, BankState.unknown(),
			stateMask, NO_HOOKS, insideOnly);
	}

	/**
	 * The site at which this helper's mechanism CONSUMES the byte in {@code argReg} -- which of a
	 * multi-write helper's sites is the one whose value ends up in the tracked field (bead
	 * grm-67g).
	 * <p>
	 * WHICH site that is, is the strategy's call and not a constant. For every single-site
	 * mechanism {@code firstSite} and {@code switchSite} are the same instruction and the question
	 * does not arise; the two multi-site shapes want opposite answers, and select-data reading
	 * {@code firstSite} is what shipped smb3's confident wrong {@code r7=7} -- {@code firstSite}
	 * there holds the {@code $8000} register-SELECT byte, not the bank. See
	 * {@link BankSwitchStrategy#suppliesHelperValueAtFirstSite}.
	 * <p>
	 * <b>This is NOT the same bound as {@link #argumentSurvivesPrologue}'s</b>, which is
	 * emphatically {@code firstSite} for every strategy -- and the two are consistent rather than
	 * in tension. That predicate asks whether the CALLER's byte is still in the register when the
	 * mechanism starts, and a serial-shift chain clobbers A four times between its first write and
	 * its last BY DESIGN, so walking to {@code switchSite} there would decline every serial-shift
	 * helper on the planet. The clobbers that make that true all fall AFTER {@code firstSite}, so
	 * for serial-shift this method answers {@code firstSite} too and both walks stop short of
	 * them. One selector therefore serves both multi-site shapes without a special case.
	 * <p>
	 * Two consumers: {@link #valueSuppliedInsideHelper} (what the helper's own body puts in the
	 * register) and {@link #inboundArgumentCell} (what cell the caller's byte arrives in). Same
	 * question, different storage class.
	 */
	private static Address helperValueSite(HelperModel helper) {
		return helper.strategy() == null || helper.strategy().suppliesHelperValueAtFirstSite()
				? helper.firstSite()
				: helper.switchSite();
	}

	/**
	 * Where a backward scan that runs INSIDE the helper must stop -- the address control
	 * arrived at in the body that actually contains {@code firstSite}.
	 * <p>
	 * For every ordinary helper, and for a pass-through wrapper, that is {@code entry}: the
	 * wrapper is address-contiguous with the helper, so one body's worth of addresses runs from
	 * {@code entry} to {@code firstSite} and stopping at {@code entry} is right. For a CALL-EDGE
	 * wrapper it is emphatically not: {@code entry} is the WRAPPER's, while {@code firstSite}
	 * lives in the wrapped helper, and the addresses between them are the wrapper's own tail.
	 * A scan bounded by the wrapper's entry would run off the helper's entry, walk backwards
	 * through that tail, and read instructions the call never executed as the helper's prologue
	 * -- the precise hazard {@link #valueSuppliedInsideHelper}'s javadoc already warns about for
	 * the unbounded case.
	 * <p>
	 * Two consumers: {@link #valueSuppliedInsideHelper}'s {@link RegisterEnv} stop address, and
	 * the one {@link #recoverCallArgument} hands {@link #callSiteRegisters} for
	 * {@link BankSwitchStrategy#depositHelperArgument}'s mini-inlining.
	 * <p>
	 * <b>For a pass-through wrapper, contiguity makes the walk POSSIBLE but does not make this
	 * stop REACHABLE</b> (bead grm-k90) -- the gap in the paragraph above, and the whole of
	 * Contra's defect. The addresses do run linearly from {@code entry} to {@code firstSite}, so
	 * the answer here is right; what the argument omits is that the WRAPPED helper's own entry
	 * sits on that line and is a control-flow join, because the callers who bypass the wrapper
	 * jump straight to it. {@code StoredValueScanner}'s join refusal fires there and the scan
	 * returns unknown two instructions short of this stop. That is repaired by licensing exactly
	 * that one join rather than by moving the stop -- see {@link #crossableWrapperJoin}, which
	 * also records why moving it would have been the worse fix.
	 */
	// Package-private (not private): SaveRestoreTrampolines.restoresEntryBank also needs
	// this stop address (grm-shnf step 3).
	static Address insideHelperEntry(HelperModel helper) {
		return helper.relay() == null ? helper.entry() : helper.relay().calleeEntry();
	}

	/**
	 * One half-open, linear-by-address stretch {@code [from, to)} of the prologue a call runs
	 * before the helper's mechanism reads its argument (bead grm-2dr increment 2).
	 * <p>
	 * Package-private so a Tier 2 test can construct one; {@code HelperArgumentRecovery}'s own
	 * records are private, which is what kept increment 1's wrapper tests at the predicate
	 * level.
	 */
	record PrologueSegment(Address from, Address to) {}

	/**
	 * {@link #argumentSurvivesPrologue} over a prologue that is more than one contiguous span:
	 * a literal AND, evaluating each segment independently (bead grm-2dr increment 2).
	 * <p>
	 * <b>The single-segment case is byte-for-byte unchanged</b> -- same method, same body, same
	 * answer -- because a one-element list delegates once and returns exactly what the three-
	 * address form returns. Only a call-edge wrapper ever supplies two.
	 * <p>
	 * <b>Resetting the save/restore model between segments is deliberate, and it errs in the
	 * safe direction.</b> Each delegated call starts with fresh {@code holdsArgument},
	 * {@code saved}, {@code argumentCells} and {@code straightLine}, so a {@code PHA} in
	 * segment 1 cannot pair with a {@code PLA} in segment 2, and a cell the argument was stored
	 * to in segment 1 cannot make a segment-2 load read as a restore. Both refusals
	 * UNDER-approximate survival, so the cost is at most a missing annotation -- never a
	 * confidently wrong bank, which this engine treats as strictly worse. blmaster is
	 * unaffected either way: its {@code STA $DB} and {@code LDA $DB} both live in segment 1.
	 * <p>
	 * An EMPTY segment ({@code from.equals(to)}) is trivially true, and that is load-bearing
	 * rather than incidental: the loop's bound test is {@code cursor < to}, so it never
	 * executes and the method returns {@code cursor.equals(to) && holdsArgument}. That is
	 * exactly blmaster's second segment, since {@code FUN_e63c}'s {@code STA $FFFF} IS its entry
	 * instruction and so its {@code entry} and {@code firstSite} coincide.
	 * <p>
	 * An EMPTY LIST is false, not vacuously true -- there is no prologue to have proved
	 * anything about, and returning true there would hand a strategy a caller's byte on no
	 * evidence at all.
	 */
	static boolean argumentSurvivesPrologue(Program program, List<PrologueSegment> segments,
			char reg) {
		if (segments.isEmpty()) {
			return false;
		}
		for (PrologueSegment segment : segments) {
			if (!argumentSurvivesPrologue(program, segment.from(), segment.to(), reg)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether {@code reg}'s value is PROVABLY not the caller's by the end of ANY segment of
	 * {@code helper}'s prologue (bead grm-jqt0). Unlike {@link #argumentSurvivesPrologue(Program,
	 * List, char)}'s AND-of-segments, one segment reporting
	 * {@link PrologueOutcome#DEFINITELY_CLOBBERED} settles the WHOLE list on its own: each
	 * segment's walk starts by ASSUMING {@code holdsArgument} true at its own {@code from} (see
	 * {@link #prologueOutcome}), which is exactly "if the caller's value were still present
	 * entering this segment, does this segment's own code preserve it" -- an unconditional
	 * overwrite proven within one segment erases whatever was there before REGARDLESS of what an
	 * earlier or later segment's own answer is, so it needs no help from its neighbours to be a
	 * sound proof. An empty list, like the boolean form, proves nothing either way.
	 */
	static boolean argumentDefinitelyClobbered(Program program, List<PrologueSegment> segments,
			char reg) {
		for (PrologueSegment segment : segments) {
			if (argumentDefinitelyClobbered(program, segment.from(), segment.to(), reg)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The stretches of code a call into {@code helper} runs before its mechanism reads the
	 * argument: one span for an ordinary helper, two for a call-edge wrapper.
	 * <p>
	 * DERIVED, not stored on {@link HelperDiscovery.HelperModel}. It is a pure function of
	 * {@code entry}, {@code firstSite} and {@code relay}, all already on the record; storing it would
	 * duplicate state that {@link HelperDiscovery.HelperModel#atMidBodyEntry} and
	 * {@link HelperDiscovery.HelperModel#atFallThroughWrapper} re-key underneath, and would drag a
	 * list into the record's equality.
	 * <p>
	 * <b>Why passing the relay's call site as segment 1's END bound does not trip
	 * {@link #argumentSurvivesPrologue}'s own {@code isCall()} rejection.</b> That loop's bound
	 * test is {@code cursor.compareTo(to) < 0}, so it STOPS BEFORE INSPECTING the instruction at
	 * {@code to} -- the relay {@code JSR} is the boundary, never a walked instruction. This
	 * looks like an accident and is not: it is the whole reason segmenting works without
	 * touching the predicate.
	 */
	// Package-private (not private): HelperDiscovery.findCallEdgeWrappers also calls this
	// (grm-shnf step 3).
	static List<PrologueSegment> prologueSegments(HelperModel helper) {
		if (helper.relay() == null) {
			return List.of(new PrologueSegment(helper.entry(), helper.firstSite()));
		}
		return List.of(new PrologueSegment(helper.entry(), helper.relay().callSite()),
			new PrologueSegment(helper.relay().calleeEntry(), helper.firstSite()));
	}

	/**
	 * {@link #prologueSegments}, but bounded by {@link #helperValueSite} instead of
	 * {@code firstSite} -- the span a CLOBBER PROOF must cover, as opposed to the span value
	 * recovery is defined over (bead grm-jqt0, third increment).
	 * <p>
	 * <b>Why the two spans differ.</b> {@code firstSite} is where this helper's mechanism first
	 * WRITES; {@link #helperValueSite} is where it READS the value it commits, and for a
	 * select-data helper those are different instructions -- MMC3's {@code $8000} register-select
	 * write and its {@code $8001} bank write, the same distinction
	 * {@link BankSwitchStrategy#suppliesHelperValueAtFirstSite} exists to express (grm-67g). To
	 * prove the caller's byte never reaches the mechanism, the walk has to cover everything that
	 * runs before the mechanism READS -- otherwise a reload sitting between the two writes is
	 * invisible to it.
	 * <p>
	 * <b>The case that forced this.</b> rcransom's {@code FUN_fed1} pushes the caller's A, reuses
	 * the register as scratch for the select write at {@code $fed8} (its {@code firstSite}), then
	 * reads the argument back off the stack at {@code $fedc} ({@code TSX} / {@code LDA $0102,X})
	 * and commits it at {@code $fee2}. Bounded by {@code firstSite} the walk stops at {@code $fed8}
	 * and reports a clobber; bounded by {@code helperValueSite} it reaches {@code $fedc}, trips the
	 * stack-page tripwire, and correctly declines to claim there is no argument. {@code FUN_fe56}
	 * is the same shape for two stack-passed arguments. {@code BankSwitchStrategy}'s
	 * {@code foldDeposits} javadoc already documented that {@code FUN_fed1} takes an argument.
	 * <p>
	 * <b>Deliberately NOT used by {@link #argumentSurvivesPrologue}.</b> That predicate's span is
	 * part of the contract its callers' value recovery is built on, and
	 * {@link HelperDiscovery#findCallEdgeWrappers} admits wrappers with it; widening it would
	 * change recovered VALUES and counts, which this bead must not do. This span feeds only the
	 * clobber proof, whose sole consumer is the WORDING {@code BoardBankAnalyzer} selects.
	 * <p>
	 * Falls back to {@code firstSite} when {@link #helperValueSite} has nothing better to offer,
	 * so a helper whose model carries no {@code switchSite} behaves exactly as before.
	 */
	private static List<PrologueSegment> clobberSegments(HelperModel helper) {
		Address valueSite = helperValueSite(helper);
		if (valueSite == null || helper.firstSite() == null ||
			valueSite.compareTo(helper.firstSite()) < 0) {
			return prologueSegments(helper);
		}
		if (helper.relay() == null) {
			return List.of(new PrologueSegment(helper.entry(), valueSite));
		}
		return List.of(new PrologueSegment(helper.entry(), helper.relay().callSite()),
			new PrologueSegment(helper.relay().calleeEntry(), valueSite));
	}

	/**
	 * The address {@code instr} reloads {@code reg} from, when it is a plain load whose target is
	 * statically certain -- the memory half of {@link #argumentSurvivesPrologue}'s save/restore
	 * model, and the load-side predicate of {@link #inboundArgumentCell}. Null for anything else,
	 * including an immediate load (no address operand at all) and an indexed one
	 * ({@link StoredValueScanner#plainAbsoluteTarget} refuses those, since their target is
	 * runtime-dependent).
	 */
	// Package-private (not private): SaveRestoreTrampolines.restoresEntryBank also calls
	// this (grm-shnf step 3).
	static Address argumentReloadSource(Instruction instr, char reg) {
		if (!("LD" + reg).equals(instr.getMnemonicString())) {
			return null;
		}
		return StoredValueScanner.plainAbsoluteTarget(instr);
	}

	/**
	 * The memory cell a helper takes its argument IN, when the caller passes the bank through RAM
	 * rather than in a register (bead grm-67g) -- or null when no such cell is provable.
	 * <p>
	 * <b>The claim.</b> If the helper's LAST write to {@code reg} before its value-consuming site
	 * is a plain load from cell C, and nothing between the entry and that site could have written
	 * C, then C still holds what the CALLER put there. C is therefore an inbound argument, and its
	 * value must be resolved at the CALL SITE ({@link StoredValueScanner#callerCellValue}) rather
	 * than by scanning for {@code reg} there.
	 * <p>
	 * <b>This is the exact dual of {@link #argumentSurvivesPrologue}'s {@code argumentCells}
	 * set</b>, and the two are MUTUALLY EXCLUSIVE by construction. That set admits C only when the
	 * HELPER stores {@code reg} into it (a save/restore across the prologue); this admits C only
	 * when the helper NEVER stores to it. So a helper cannot satisfy both, which is why the order
	 * in which {@link #recoverCallArgument} tries them is not a judgement call -- hoisting this
	 * above the survives-prologue test could not change an answer, only cost a walk.
	 * <p>
	 * <b>Worked example</b>, smb3's {@code FUN_ffc2} with {@code reg == 'A'} and the value site at
	 * {@code $FFC7} (select-data consumes at {@code switchSite}, not {@code firstSite}):
	 * <pre>
	 *   ffc2  LDA #$47      ; clears cell -- an immediate is not a reload
	 *   ffc4  STA $0721     ; lands in `written`, and PROVES a different cell than $0720
	 *   ffc6  STA $8000     ; firstSite, walked THROUGH: the select byte is not the bank
	 *   ffc7  LDA $0720     ; sets cell = $0720   &lt;- the answer
	 *   ffc9  STA $8001     ; the value site; walk stops here
	 * </pre>
	 * The caller side then finishes it: {@code ca23 LDA #$1b / STA $0720 / JSR $ffc2} resolves
	 * {@code $0720} to {@code $1b = 27}. And the counter-example {@code written} exists for is one
	 * instruction away -- a helper whose {@code $FFC4} were {@code STA $0720} would be supplying
	 * its OWN byte, and without that set this would confidently ship {@code $47} as the bank,
	 * which is the very number the regression this bead tracks shipped.
	 * <p>
	 * <b>Not a restoration of anything.</b> smb3's correct {@code r7=27/26} predates the prologue
	 * guard, but it was never sourced from the shadow: {@code local} was simply the caller-side
	 * REGISTER scan, and {@code LDA #$1b / STA $0720 / JSR} happens to leave {@code $1b} still in
	 * A. That is luck the idiom happens to grant, not a mechanism. This rule reaches the same
	 * number for a sound reason, and keeps reaching it when the caller's A is clobbered.
	 * <p>
	 * <b>The bound is {@link #helperValueSite}, not {@code firstSite}</b> -- see that method for
	 * why the two predicates want opposite-looking bounds for the same underlying reason.
	 * <p>
	 * <b>{@link #insideHelperEntry}, not the function's entry point.</b> Bionic Commando's
	 * {@code FUN_dca8} ({@code LDA $65 / STA $E000}) is a real inbound-cell helper when entered at
	 * {@code $DCA8}; entered mid-body at {@code $DCAA} the walk starts past the load, finds no
	 * reload, and correctly returns null -- one function, two answers, exactly as
	 * {@link #argumentSurvivesPrologue} documents for its own walk. It also means a FALL-THROUGH
	 * wrapper's prefix IS walked, which matters more than it looks:
	 * {@code HelperDiscovery.isPassThroughInto} forbids a wrapper from writing the MECHANISM but not
	 * from writing ordinary RAM, so a wrapper containing {@code STA $0720} is admissible and only the
	 * walk starting at the wrapper's entry catches it.
	 * <p>
	 * <b>A CALL-EDGE wrapper declines outright.</b> There {@link #insideHelperEntry} is the
	 * relay's callee entry, so the walk would cover only the second prologue segment and never see
	 * the wrapper's own prefix. blmaster's shape is the counterexample: a wrapper doing
	 * {@code STA $22 / LDA $22 / JSR helper} in front of a helper whose body begins {@code LDA $22}
	 * would look like an inbound cell, and the value would be resolved at the JSR INTO THE WRAPPER
	 * -- i.e. the byte the wrapper was about to overwrite. Stale, confident, wrong. Today the
	 * branch that calls this is unreachable for a relay model at all ({@code
	 * HelperDiscovery.findCallEdgeWrappers} uses {@link #argumentSurvivesPrologue} as its ADMISSION
	 * gate, so every relay helper in the map already answers true there), so this guard is defensive
	 * -- but the invariant is one refactor away from moving. A generalization over
	 * {@link #prologueSegments} must NOT reset {@code written} per segment the way
	 * {@link #argumentSurvivesPrologue} resets its shadow stack: that reset under-approximates and
	 * errs safe, while forgetting the wrapper's {@code STA $22} errs the unsafe way. Same segment
	 * list, opposite discipline.
	 * <p>
	 * <b>Every flow declines here</b>, where {@link #argumentSurvivesPrologue} merely stops
	 * trusting its save/restore model. A branch costs that predicate a fold; here it would let a
	 * linear-by-address walk skip a write to C, or count one that never executes, and both point
	 * the unsafe way.
	 * <p>
	 * <b>{@link StoredValueScanner#writesMemory}, not {@code writesAddress}.</b> The reference-only
	 * test under-reports (an indirect store has no concrete result address, refless stores exist,
	 * and the read-modify-write mnemonics are invisible to {@code storeRegister}). In the
	 * save/restore model a missed write is bounded by {@code holdsArgument}; here it is directly a
	 * confident wrong bank.
	 *
	 * <b>A cell in the live part of the stack page is refused</b> ({@link StackFloor}). This walk
	 * is the one place where the hazard is not hypothetical: the caller reached {@code entry}
	 * through a {@code JSR}, which pushed two bytes, and neither that nor a {@code PHA} inside
	 * the range is visible to {@link StoredValueScanner#writesMemory}. Unlike the other two
	 * consumers of the floor, a wrong answer here is a confident wrong bank rather than a
	 * forfeited forward, so the guard matters most here even though the code is smallest.
	 *
	 * @param entry     where control actually arrives -- {@link #insideHelperEntry}
	 * @param valueSite where the mechanism consumes the byte -- {@link #helperValueSite}
	 */
	static Address inboundArgumentCell(Program program, Address entry, Address valueSite, char reg) {
		if (entry == null || valueSite == null || entry.compareTo(valueSite) > 0) {
			return null;
		}
		Register register = program.getLanguage().getRegister(String.valueOf(reg));
		if (register == null) {
			return null; // cannot ask the question -> do not assume the favorable answer
		}
		Listing listing = program.getListing();
		// The cell reg was LAST plainly loaded from, or null when reg's current value came from
		// anywhere else. Set and cleared by the same statement, which is the whole trick.
		Address cell = null;
		// Every address this walk saw written, accumulated over the WHOLE range rather than tested
		// as we go: in FUN_ffc2 the STA $0721 precedes the LDA $0720 that names the cell, so a
		// check applied only after the load would miss a store in the same position.
		Set<Address> written = new LinkedHashSet<>();
		Address cursor = entry;
		while (cursor.compareTo(valueSite) < 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || instr.getFlowType().isCall() || instr.getFlowType().isTerminal() ||
				instr.getFlows().length > 0) {
				return null;
			}
			Address fallThrough = instr.getFallThrough();
			Address next = instr.getMaxAddress().next();
			if (next == null || fallThrough == null || !fallThrough.equals(next)) {
				return null; // a gap, an override, or the end of the space -- not one linear path
			}
			if (StoredValueScanner.writesMemory(instr)) {
				Address target = StoredValueScanner.effectiveOperandTarget(program, instr, NO_HOOKS,
					RegisterEnv.NONE);
				if (target == null) {
					return null; // a write this scanner cannot place may have landed on the cell
				}
				written.add(target);
			}
			if (StoredValueScanner.writesRegister(instr, register)) {
				cell = argumentReloadSource(instr, reg);
			}
			cursor = next;
		}
		// StackFloor: the caller's own JSR pushed a return address, and any PHA in the range was
		// stepped over as inert, both at addresses writesMemory cannot name. A cell at or above
		// the floor may therefore have been clobbered between the caller's store and this load.
		// (The null-cell case reaches mayAliasStack's "unplaceable reads as unsafe" answer and
		// would be rejected by the cell != null test below regardless -- same verdict either way.)
		return cursor.equals(valueSite) && cell != null && !written.contains(cell) &&
			!StackFloor.mayAliasStack(program, cell) ? cell : null;
	}

	/** {@link #inboundArgumentCell} asked of a helper model; null for a call-edge wrapper. */
	private static Address inboundArgumentCell(Program program, HelperModel helper, char reg) {
		if (helper.relay() != null) {
			return null;
		}
		return inboundArgumentCell(program, insideHelperEntry(helper), helperValueSite(helper), reg);
	}

	/**
	 * Whether {@code instr} moves the stack pointer, for {@link #argumentSurvivesPrologue}'s
	 * shadow stack.
	 * <p>
	 * <b>Compared by BASE register, not by identity.</b> The 6502 declares the stack pointer
	 * twice over the same bytes -- a two-byte {@code SP} and a one-byte {@code S} -- and
	 * {@code CompilerSpec.getStackPointer()} answers one while {@code TXS}'s p-code writes the
	 * other. An {@code equals} test (which is what {@link StoredValueScanner#writesRegister}
	 * deliberately does, and must keep doing for A/X/Y) therefore reports that {@code TXS} does
	 * not touch the stack, and the shadow stack would go on trusting a depth that had just moved
	 * underneath it. Measured, not theorised: the {@code TXS} case was the one unit test that
	 * failed on the identity comparison.
	 * <p>
	 * Package-private for a second consumer (grm-mej.3 increment 2):
	 * {@code StoredValueScanner.findMatchingPush} needs the identical base-register-aware test
	 * for its own PHA/PLA depth pairing, over a BACKWARD walk rather than this method's forward
	 * one. Reused verbatim rather than reimplemented so the two walks cannot silently drift apart
	 * on what "moves the stack pointer" means.
	 */
	static boolean writesStackPointer(Instruction instr, Register stackPointer) {
		Register wanted = stackPointer.getBaseRegister();
		for (Object o : instr.getResultObjects()) {
			if (o instanceof Register r && wanted.equals(r.getBaseRegister())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * What A, X and Y hold at {@code callInstr}, packaged with {@code entryAddr} (the called
	 * helper's entry) as the address a backward scan started inside that helper must stop at.
	 * This is what makes {@link BankSwitchStrategy#depositHelperArgument}'s mini-inlining
	 * possible without any input-register discovery: the scan inside the helper is
	 * demand-driven, so supplying all three registers and letting it pull whichever it actually
	 * reads is both simpler and strictly more capable than deducing an argument convention
	 * (grm-hum increment 2 -- Contra's helper takes its bank in Y while
	 * {@link HelperDiscovery#findHelpers} can only see the {@code STA}'s A).
	 * <p>
	 * <b>Masked to {@code 0xFF}, deliberately not to the mechanism's {@code stateMask}.</b> An
	 * index register is not the mechanism's field: Contra's UxROM latch has {@code mask: 0x0F},
	 * and narrowing Y to four bits would truncate the very index used to read the bank table.
	 * {@code argValue}'s {@code stateMask} narrowing in {@link #recoverCallArgument} is a
	 * different question (the field value itself) and keeps it.
	 * <p>
	 * {@link #NO_HOOKS} is used because the scan runs in the CALLER, outside any mechanism's
	 * interpretation: the caller's mechanism writes are not this helper's, and no strategy's
	 * load resolution applies to a register the caller is merely setting up. A register the
	 * scan cannot pin down comes back {@link BankState#unknown()}, which is what keeps a
	 * RAM-sourced argument honestly unresolved instead of guessed.
	 * <p>
	 * <b>Each register is then filtered by whether it SURVIVES the UNWALKED part of the
	 * prologue</b> (bead grm-k90, narrowed by grm-4bgh increment 3). The three scans above run in
	 * the caller and answer "what did the caller leave here"; the env claims something stronger
	 * -- "what holds at {@code entryAddr}" -- and for a WRAPPER model those differ, because the
	 * wrapper's own body runs in between and nothing forbids it writing X or Y
	 * ({@link HelperDiscovery#isPassThroughInto} admits an {@code LDX #imm} without blinking).
	 * {@link #unwalkedPrologueSegments} answers exactly that question restricted to the segments
	 * {@link #recoverCallArgument}'s own mini-inline scan does not itself traverse (see its
	 * javadoc for why the traversed segments need no second check), and
	 * {@link #argumentSurvivesPrologue(Program, List, char)} is asked over that narrowed list
	 * ONCE PER REGISTER rather than once for {@link HelperDiscovery.HelperModel#argReg}, with a
	 * register that does not survive handed back as {@link BankState#unknown()} instead of the
	 * caller's stale value. Per-register is the whole point: on Contra's {@code FUN_c139} A does
	 * not survive ({@code LDA $8000}) while Y does, and Y is the one the latch consumes -- running
	 * the test on {@code argReg} alone would let a clobber of a register nobody reads suppress a
	 * correct recovery.
	 * <p>
	 * For an ordinary helper this filter is now a no-op by construction, not merely
	 * "redundant-but-harmless": its one prologue segment is entirely WALKED by the mini-inline
	 * scan, so {@link #unwalkedPrologueSegments} hands back an empty list and {@link #surviving}
	 * adopts the caller-side scan unfiltered. The scan meets any clobber of {@code reg} itself
	 * before it reaches {@code entryAddr}, so the env value is trusted only when the scan
	 * traversed the ENTIRE unwalked span without finding a definition of the register -- which is
	 * also the soundness argument for the wrapper case below. It remains LOAD-BEARING for a
	 * CALL-EDGE wrapper's PREFIX segment ({@code [entry, relay.callSite()]}), which lies strictly
	 * before the scan's stop ({@code relay.calleeEntry()}, per {@link #insideHelperEntry}) and so
	 * is never walked at all -- that is the soundness hole this bead was originally filed on, and
	 * it is closed here rather than by forcing X/Y to unknown for wrapper models wholesale
	 * (considered and rejected in grm-2dr increment 2 as strictly less precise).
	 * <p>
	 * {@code crossableJoin} is passed through untouched; see {@link #crossableWrapperJoin} for
	 * where it comes from and {@link RegisterEnv} for why crossing it is sound.
	 * <p>
	 * {@code localIn} (bead grm-mej.3 item 4) is {@code recoverCallArgument}'s own
	 * {@code localIn} -- the call's tracked in-state, already narrowed to {@code helper}'s
	 * mechanism's field-local space -- threaded down to {@link #surviving} so a mirror-aware
	 * {@link BankSwitchStrategy#callerSideHooks} can answer from real state instead of the
	 * historical {@link BankState#unknown()}. It is what makes {@link #CallSiteRegKey} need the
	 * in-state in its key: this method's result can now differ across two calls at the same
	 * address under different {@code localIn}.
	 */
	private static RegisterEnv callSiteRegisters(Program program, Instruction callInstr,
			Address entryAddr, Address crossableJoin, HelperModel helper, BankState localIn) {
		List<PrologueSegment> unwalked = unwalkedPrologueSegments(entryAddr, helper);
		return new RegisterEnv(entryAddr, crossableJoin,
			surviving(program, callInstr, 'A', unwalked, helper, localIn),
			surviving(program, callInstr, 'X', unwalked, helper, localIn),
			surviving(program, callInstr, 'Y', unwalked, helper, localIn));
	}

	/**
	 * The subset of {@link #prologueSegments} the mini-inline scan at
	 * {@link #recoverCallArgument} does NOT itself walk, i.e. the only segments over which
	 * {@link #callSiteRegisters}' grm-k90 filter is still doing real work (bead grm-4bgh
	 * increment 3).
	 * <p>
	 * <b>Why this narrowing is sound, not just an optimization.</b> The mini-inline scan runs
	 * backward from {@code helper.switchSite()} and stops at {@code entryAddr} (the same
	 * {@code scanStop} the caller of {@link #callSiteRegisters} already computed as
	 * {@link #insideHelperEntry}), so it walks exactly {@code [entryAddr, switchSite]}. Any
	 * clobber of a register inside that span is a clobber the scan meets and reports on its own;
	 * the env's answer for that register is adopted by a strategy ONLY when the scan traverses
	 * the whole span without finding a definition of the register, at which point the two
	 * questions -- "what does the scan see" and "what does the env claim" -- agree by
	 * construction. Filtering a WALKED segment through {@link #argumentSurvivesPrologue} a
	 * second time is therefore redundant-but-harmless, exactly as grm-k90's own javadoc concedes
	 * for the ordinary-helper case.
	 * <p>
	 * The filter stays LOAD-BEARING only for the call-edge wrapper's PREFIX segment
	 * ({@code [entry, relay.callSite()]}): that span lies strictly before {@code scanStop} (which
	 * is {@code relay.calleeEntry()} for a wrapper, per {@link #insideHelperEntry}), so the
	 * mini-inline scan never walks it at all, and a clobber inside it would otherwise slip
	 * through unseen.
	 * <p>
	 * An ORDINARY helper has one segment, {@code [entry, firstSite]}, which is entirely
	 * contained in {@code [entryAddr, switchSite]} because {@code entryAddr == entry} and
	 * {@code firstSite} precedes or equals {@code switchSite} (both are addresses within the
	 * same recognized body). It is therefore always WALKED and never appears in the result.
	 * <p>
	 * <b>Containment is tested conservatively.</b> A segment is WALKED iff {@code entryAddr},
	 * {@code helper.switchSite()}, and the segment's own bounds are all non-null, all share one
	 * address space, and the segment lies within {@code [entryAddr, switchSite]}. Any null, or
	 * any address-space mismatch, is treated as NOT walked -- kept in the filtered list -- rather
	 * than assumed favorable, matching this engine's standing rule that a false decline (one
	 * missing annotation) is acceptable where a false accept (a wrong bank) is not.
	 */
	private static List<PrologueSegment> unwalkedPrologueSegments(Address entryAddr,
			HelperModel helper) {
		Address switchSite = helper.switchSite();
		List<PrologueSegment> segments = prologueSegments(helper);
		List<PrologueSegment> unwalked = new ArrayList<>(segments.size());
		for (PrologueSegment segment : segments) {
			if (!isWalkedByMiniInlineScan(entryAddr, switchSite, segment)) {
				unwalked.add(segment);
			}
		}
		return unwalked;
	}

	/**
	 * Whether the mini-inline scan's span {@code [entryAddr, switchSite]} already covers
	 * {@code segment}, per {@link #unwalkedPrologueSegments}. Never assumes the favorable answer
	 * on missing or mismatched data -- see that method's javadoc.
	 */
	private static boolean isWalkedByMiniInlineScan(Address entryAddr, Address switchSite,
			PrologueSegment segment) {
		Address from = segment.from();
		Address to = segment.to();
		if (entryAddr == null || switchSite == null || from == null || to == null) {
			return false;
		}
		if (!entryAddr.getAddressSpace().equals(switchSite.getAddressSpace())
				|| !entryAddr.getAddressSpace().equals(from.getAddressSpace())
				|| !entryAddr.getAddressSpace().equals(to.getAddressSpace())) {
			return false;
		}
		return from.compareTo(entryAddr) >= 0 && to.compareTo(switchSite) <= 0;
	}

	/**
	 * What the caller left in {@code reg}, or {@link BankState#unknown()} when an UNWALKED
	 * segment of the helper's prologue (see {@link #unwalkedPrologueSegments}) does not preserve
	 * it as far as the site that reads it -- one register's worth of {@link #callSiteRegisters}'
	 * filter (bead grm-k90, narrowed by grm-4bgh increment 3).
	 * <p>
	 * The survival test is evaluated FIRST and the scan skipped when it fails, which is a small
	 * efficiency win but mostly a statement of intent: a value that cannot be attributed is not
	 * merely discarded afterwards, it is never derived.
	 * <p>
	 * <b>An empty {@code unwalked} list means there is nothing left to filter on</b> -- every
	 * segment of the prologue is already covered by the mini-inline scan -- so this returns the
	 * caller-side scan unfiltered rather than calling {@link #argumentSurvivesPrologue(Program,
	 * List, char)}, which treats an empty list as an unproven decline (see its own javadoc) and
	 * would wrongly force every ordinary helper's env to {@link BankState#unknown()}.
	 * <p>
	 * <b>Mirror-aware as of bead grm-mej.3 item 4.</b> {@code localIn} -- {@code helper}'s
	 * mechanism's field-local tracked state at the call, threaded down from
	 * {@link #callSiteRegisters} -- replaces the historical hardcoded
	 * {@link BankState#unknown()}, and {@link #callerHooksFor} replaces the historical
	 * {@code NO_HOOKS}. This is masked to {@code 0xFF} rather than the mechanism's own
	 * {@code stateMask} exactly as before (an index register is not the mechanism's field, see
	 * this method's original javadoc on {@link #callSiteRegisters}); the mask narrowing and the
	 * in-state's coordinate space are independent questions, and only the mask stayed {@code 0xFF}
	 * here. A strategy that does not override {@link BankSwitchStrategy#callerSideHooks} answers
	 * identically to before, since its hooks never consult {@code localIn} at all.
	 */
	private static BankState surviving(Program program, Instruction callInstr, char reg,
			List<PrologueSegment> unwalked, HelperModel helper, BankState localIn) {
		if (!unwalked.isEmpty() && !argumentSurvivesPrologue(program, unwalked, reg)) {
			return BankState.unknown();
		}
		return StoredValueScanner.resolveStoredValue(program, callInstr, reg, localIn, 0xFF,
			callerHooksFor(helper));
	}

	/**
	 * The one control-flow join a mini-inline scan for {@code helper} may walk through, or
	 * {@code null} for the overwhelmingly common "none" (bead grm-k90).
	 * <p>
	 * <b>The problem it solves.</b> For a PASS-THROUGH WRAPPER, {@link #insideHelperEntry}
	 * correctly reports the WRAPPER's entry as where control arrived -- but that stop is not
	 * REACHABLE. The scan starts at the switch site, inside the wrapped helper, and the wrapped
	 * helper's own entry lies between it and the stop. That entry is a genuine control-flow join,
	 * because the direct callers who bypass the wrapper jump straight to it, so
	 * {@code StoredValueScanner}'s join refusal fires and the walk dies short of the env. On
	 * Contra this is the entire defect: {@code c0cb LDY #1 / JSR $c13f} resolves because its stop
	 * IS the join and {@code stopsAt} is tested first, while the identical {@code c094 LDY #1 /
	 * JSR $c139} warns because its stop is two instructions further back and the join wins the
	 * race.
	 * <p>
	 * <b>What is nominated.</b> "The entry of the body that actually contains {@code firstSite}"
	 * -- which is what {@link #insideHelperEntry}'s javadoc already claims to compute and, for a
	 * pass-through wrapper, does not. It is taken from the function containing {@code firstSite}
	 * rather than stored on {@link HelperDiscovery.HelperModel} deliberately:
	 * {@link HelperDiscovery.HelperModel#atFallThroughWrapper} overwrites {@code entry} with the
	 * wrapper's, so recording the wrapped entry would mean a new field on a ten-field record, and one
	 * that would have to be threaded correctly through a CHAIN of wrappers. Deriving it gets the
	 * chained case right for free -- every outer wrapper is contiguous with the next and contributes
	 * no join of its own, so the function containing {@code firstSite} is the innermost helper however
	 * many wrappers are stacked on it.
	 * <p>
	 * <b>The window test is what keeps it honest</b>, and it is not a formality -- it is the only
	 * thing standing between this and licensing a join nobody proved anything about. The nominee
	 * must lie STRICTLY after {@code scanStop} and at or before {@code firstSite}. Walk the four
	 * model shapes:
	 * <ul>
	 * <li>ORDINARY HELPER: the nominee IS {@code scanStop}, not strictly after it, so
	 * {@code null}. Byte-for-byte no change, which is what lets this land without re-blessing
	 * every golden.</li>
	 * <li>MID-BODY ENTRY (Bionic Commando's {@code $DCAA} inside {@code FUN_dca8}): the nominee is
	 * {@code dca8}, BEFORE the stop, so {@code null}. That case must not regress and structurally
	 * cannot -- the whole point of a mid-body entry is that the prologue was skipped, and
	 * licensing a join behind the stop would walk the scan into exactly the code the call
	 * avoided.</li>
	 * <li>PASS-THROUGH WRAPPER (Contra): {@code c139 < c13f <= c142}. Nominated. This is the
	 * fix.</li>
	 * <li>CALL-EDGE WRAPPER: {@code scanStop} is {@code relay.calleeEntry()}. If the wrapped model
	 * is itself a pass-through wrapper the nominee is after it and crossing is licensed by THAT
	 * wrapper's own {@link HelperDiscovery#isPassThroughInto} proof; otherwise the nominee is the stop
	 * and this returns {@code null}.</li>
	 * </ul>
	 * In every nominated case the span between stop and nominee is a pass-through wrapper's body,
	 * which {@link HelperDiscovery#isPassThroughInto} has already proved is straight-line, fully
	 * disassembled, mechanism-inert and reached only by unconditional fallthrough. That proof is the
	 * licence; see {@link RegisterEnv}'s class javadoc for why it is sufficient.
	 * <p>
	 * <b>Why the join is crossed rather than the stop simply MOVED to the nominee.</b> Moving it
	 * would have been a smaller change and it is the wrong one. The scan would then stop at the
	 * wrapped helper's entry and adopt {@link #callSiteRegisters}' prologue-FILTERED values,
	 * throwing away whatever the wrapper's own body supplies -- a wrapper of the shape
	 * {@code LDY #3} / fall-through-into-helper would report Y unknown (the filter correctly says
	 * Y does not survive a prologue that writes it) where today's scan reads the {@code LDY #3}
	 * directly. Crossing keeps the walk going through the wrapper's prefix, so its writes and
	 * loads are read natively by the machinery that already knows how, and the filter is left to
	 * do its work only at the true outer stop.
	 * <p>
	 * Takes {@code firstSite} and {@code scanStop} loose rather than a
	 * {@link HelperDiscovery.HelperModel}, and is package-private static, for one reason:
	 * {@code HelperDiscovery.HelperModel} is private, so a test that wanted a model could not build
	 * one -- the constraint that kept grm-2dr increment 1's wrapper tests at the predicate level. Same
	 * precedent as {@link #argumentSurvivesPrologue} and {@link HelperDiscovery#isPassThroughInto},
	 * and the two parameters are the only two the window test reads anyway.
	 */
	static Address crossableWrapperJoin(Program program, Address firstSite, Address scanStop) {
		if (firstSite == null || scanStop == null) {
			return null;
		}
		Function body = program.getFunctionManager().getFunctionContaining(firstSite);
		if (body == null) {
			return null;
		}
		Address nominee = body.getEntryPoint();
		if (nominee.compareTo(scanStop) <= 0 || nominee.compareTo(firstSite) > 0) {
			return null;
		}
		return nominee;
	}

	/**
	 * A helper call site's positioned effect: {@code state} is the recovered value in the
	 * board's absolute state bits (like {@link SwitchResult#effect}); {@code ownedMask} is
	 * which of those absolute bits this call site is authoritative over -- the mask
	 * {@link BankDataflowEngine#runDataflow} folds {@code state} into via
	 * {@link BankDataflowEngine#overwrite}, distinct from {@code state.knownMask()} for exactly the
	 * reason {@link BankSwitchStrategy.HelperDeposit} documents (a touched-but-unresolved bit is owned
	 * and poisoned; an untouched bit is neither).
	 * <p>
	 * {@code noInboundArgument} (bead grm-jqt0) is true when {@link #recoverCallArgument} proved
	 * -- via {@link #argumentDefinitelyClobbered}, not merely a failed
	 * {@link #argumentSurvivesPrologue} -- that the register this helper reads is REDEFINED by
	 * the helper's own prologue on every path, independent of whatever the caller passed. It says
	 * nothing about whether {@code argumentResolved} ended up true anyway through one of the
	 * other two recovery channels (a caller-side memory cell, or a constant the helper's own body
	 * supplies): those are orthogonal questions, and a consumer of this field cares about it only
	 * when {@code argumentResolved} is false, which is exactly {@code BoardBankAnalyzer}'s use.
	 */
	record CallEffect(BankState state, int ownedMask, boolean argumentResolved,
			boolean noInboundArgument) {

		/**
		 * A call effect whose {@code argumentResolved} follows from {@code state} alone -- the
		 * pre-grm-4bgh.5 equivalence, for every path that produces a single undifferentiated
		 * deposit. Only {@link #foldDeposits}' multi-site path needs to say something different,
		 * because only there can a call know something (a helper-body constant) while still
		 * having failed to recover the caller's argument. {@code noInboundArgument} defaults
		 * false here: every caller of this short form is either a verified no-op
		 * ({@link #recoverCallArgument}'s {@code restoringTrampolines} branch), the
		 * multi-mechanism-disagreement degrade ({@code helper.argReg() == null}, which has no
		 * register to have proved a clobber of), or a direct dataflow switch that never runs the
		 * helper-argument machinery at all ({@code BankDataflowEngine}'s {@code constState}
		 * branch) -- none of which this bead's proof applies to.
		 */
		CallEffect(BankState state, int ownedMask) {
			this(state, ownedMask, state.knownMask() != 0, false);
		}
	}

	/**
	 * The {@link StoredValueScanner.Hooks} a caller-side scan for {@code helper} should use
	 * (bead grm-mej.3 item 4): the helper's own strategy's {@link BankSwitchStrategy#callerSideHooks},
	 * or plain {@link #NO_HOOKS} when the helper has no strategy at all (the same
	 * multi-mechanism-disagreement degrade {@link #recoverCallArgument} and
	 * {@link #foldDeposits} already handle by testing {@code helper.strategy() == null}
	 * elsewhere). One place for this so {@code recoverCallArgument} and
	 * {@link #callSiteRegisters} cannot answer the question differently for the same helper.
	 */
	private static StoredValueScanner.Hooks callerHooksFor(HelperModel helper) {
		return helper.strategy() == null ? NO_HOOKS : helper.strategy().callerSideHooks();
	}

	/**
	 * Memo key for {@code envCache} (a.k.a. {@code BankDataflowEngine.runDataflow}'s
	 * {@code callSiteRegCache}): a call address PLUS the tracked in-state flowing into it, in
	 * this helper's mechanism's field-local coordinates (bead grm-mej.3 item 4, tripwire 2).
	 * <p>
	 * Before this bead the memo was keyed on {@code address} alone, and
	 * {@code BankDataflowEngine.runDataflow}'s declaration comment argued that was sound because
	 * {@link #callSiteRegisters}' three backward scans "use NO_HOOKS and never consult tracked
	 * state". This bead makes that argument false for a strategy that overrides
	 * {@link BankSwitchStrategy#callerSideHooks()}: {@link #surviving} now threads a real
	 * {@code localIn} into those scans, so two dequeues of the same call address under different
	 * in-states can answer differently and a memo keyed on the address alone would silently
	 * serve one call site's answer to another. {@link BankState} is a {@code record}, so this
	 * gets value equality on {@code localIn} for free -- two keys with the same address and the
	 * same known/bits pair collide exactly when they should.
	 */
	record CallSiteRegKey(Address address, BankState localIn) {
	}

	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};
}
