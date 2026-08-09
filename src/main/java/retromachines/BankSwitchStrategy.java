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

import com.google.gson.JsonObject;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * One bank-switch <em>mechanism class</em> (vision doc §5.2): the L2 code that knows how
 * to recognize this mechanism's switch instructions and recover the written bank-state
 * value, parameterized entirely by a descriptor {@code banking.mechanisms[]} entry.
 * Implementations are discovered via ClassSearcher (class name must end in
 * {@code BankSwitchStrategy} -- see {@code data/ExtensionPoint.manifest}) and matched to
 * mechanism entries by {@link #strategyName()}; {@link BoardBankAnalyzer} instantiates a
 * fresh instance per configured mechanism.
 * <p>
 * The planned vocabulary is small and closed: {@code register-write} (implemented),
 * {@code memory-latch}, {@code select-data}, {@code serial-shift}, {@code io-port},
 * {@code mode-register}. A strategy owns candidate-write recognition and value recovery
 * (with per-bit confidence, {@link BankState}); the engine owns dataflow, merging,
 * annotation, and application.
 */
public interface BankSwitchStrategy extends ExtensionPoint {

	/** The {@code banking.mechanisms[].strategy} value this class implements. */
	String strategyName();

	/**
	 * Configures this instance from one descriptor mechanism entry.
	 *
	 * @param program   the program under analysis (for address-space resolution)
	 * @param params    the mechanism's strategy-specific {@code params} object
	 * @param stateMask the field-local width mask of this mechanism's own {@code sets}
	 *                  fields (bits {@code [0, width)}) -- <em>not</em> the whole board
	 *                  mask, unless this mechanism's fields happen to be the whole board
	 *                  mask (every shipped, single-mechanism board today). Every
	 *                  {@code computeSwitch} result is likewise expected in this same
	 *                  field-local space; {@link BoardBankAnalyzer} positions it into the
	 *                  board's absolute state bits afterward.
	 */
	void configure(Program program, JsonObject params, int stateMask);

	/**
	 * Examines one instruction under the tracked in-state.
	 *
	 * @return the bank state after this instruction if it is a switch this mechanism
	 *         recognizes ({@link BankState#unknown()} for a recognized switch whose
	 *         value could not be recovered), or {@code null} if the instruction is not
	 *         a mechanism write at all and the state flows through unchanged
	 */
	BankState computeSwitch(Program program, Instruction instr, BankState inState);

	/**
	 * The field-local result of {@link #depositHelperArgument}: {@code ownedMask} marks
	 * which bits of this mechanism's field-local space THIS call site is authoritative over
	 * -- i.e. the set of bits {@link BoardBankAnalyzer} should fold the recovered
	 * {@code value} into, replacing whatever those bits' prior knowledge was, while leaving
	 * every bit outside {@code ownedMask} completely untouched (not even poisoned). This is
	 * deliberately a SEPARATE concept from {@code value.knownMask()}: an owned bit whose
	 * value could not be resolved is still owned (honest poison -- the bit becomes unknown,
	 * because the call really did write it, just not to a value this scanner could pin
	 * down), whereas an unowned bit is not touched at all, known or not (e.g. a serial-shift
	 * helper site targeting a DIFFERENT field, or a CHR target this mechanism deliberately
	 * tracks nothing for) -- a single {@link BankState} cannot represent that
	 * touched-but-unresolved / untouched distinction, which is why this is a two-part
	 * result rather than a bare {@code BankState}. {@code value.knownMask()} is always a
	 * subset of {@code ownedMask} by construction.
	 */
	record HelperDeposit(int ownedMask, BankState value) {}

	/**
	 * Converts a helper call site's recovered argument byte into this mechanism's
	 * field-local state deposit, given the switch site inside the helper that the call
	 * ultimately reaches ({@link BoardBankAnalyzer}'s {@code HelperModel} carries this --
	 * the instruction whose recognized-switch identity classified the containing function
	 * as a helper in the first place). {@code argValue} is the register value recovered at
	 * the call site (same convention as a mechanism write's own stored byte -- masked to
	 * {@code stateMask}, this mechanism's field-local width), and {@code stateMask} is that
	 * same field-local width mask passed to {@link #configure}.
	 * <p>
	 * The default reproduces the historical, pre-multi-target behavior byte-for-byte: the
	 * recovered byte IS the field-local deposit, verbatim, and {@code ownedMask} is the
	 * WHOLE {@code stateMask} (correct for any mechanism whose one switch site commits
	 * exactly one field spanning the whole {@code stateMask}, i.e. every single-target
	 * strategy: {@code register-write}, {@code memory-latch} -- calling such a helper always
	 * replaces the mechanism's entire tracked state, known or not, exactly as before this
	 * method existed). A mechanism whose single switch instruction shape can commit to
	 * different DISJOINT sub-fields depending on the site itself (the {@code serial-shift}
	 * mechanism's per-target write, keyed by the write's own address) must override this to
	 * decode which sub-field {@code switchSite} commits to, return an {@code ownedMask}
	 * covering ONLY that sub-field (so sibling fields this call site never touches are left
	 * exactly as they were, not wiped to unknown -- there is no in-state to echo at a helper
	 * call site the way {@link #computeSwitch} can), and deposit only that sub-field's bits
	 * into {@code value} (0/unknown elsewhere). A target with no tracked fields at all (e.g.
	 * serial-shift's CHR targets) should return {@code ownedMask = 0}: this call site is a
	 * verified no-op on every tracked field, a stronger and more honest result than a
	 * conservative poison.
	 * <p>
	 * {@code value} is FIELD-LOCAL, exactly like a {@link #computeSwitch} result --
	 * {@link BoardBankAnalyzer} positions both it and {@code ownedMask} into the board's
	 * absolute state bits the same way afterward.
	 * <p>
	 * {@code inState} is the caller's tracked mechanism state AT THE CALL SITE (the state
	 * the call executes under, i.e. after any direct switch at the call instruction itself),
	 * already narrowed to this mechanism's FIELD-LOCAL {@code [0, width)} space -- the same
	 * coordinate space as {@code argValue} and the returned {@code value} -- by
	 * {@link BoardBankAnalyzer#recoverCallArgument}. It exists for mechanisms whose routing
	 * (which sub-field a call's argument ultimately commits to) is decided by tracked STATE
	 * rather than by the switch site's own address (contrast {@code serial-shift}, whose
	 * routing is address-keyed and therefore ignores this parameter -- see
	 * {@code SerialShiftBankSwitchStrategy}'s override). The default ignores it, since the
	 * default's single-field-spans-the-whole-mask behavior needs no routing decision at all.
	 */
	default HelperDeposit depositHelperArgument(Program program, Instruction switchSite,
			BankState argValue, BankState inState, int stateMask) {
		return new HelperDeposit(stateMask,
			new BankState(argValue.knownMask() & stateMask, argValue.bits() & stateMask));
	}

	/**
	 * {@link #depositHelperArgument} with the call site's whole register environment available,
	 * for a strategy that would rather <em>re-evaluate its own switch semantics</em> at
	 * {@code switchSite} under those registers than trust the "the argument register holds the
	 * field value verbatim" convention {@code argValue} encodes (grm-hum increment 2's
	 * mini-inlining). This is the form {@link BoardBankAnalyzer} actually calls; the default
	 * delegates to the 5-argument form above, so a strategy that has no use for the registers
	 * overrides that one and is unaffected.
	 * <p>
	 * <b>{@code argValue} keeps its exact meaning</b> in both forms -- the value recovered in
	 * the helper's {@link BoardBankAnalyzer}-chosen argument register at the call site, already
	 * masked to {@code stateMask}. It is emphatically <em>not</em> redefined as "the evaluated
	 * switch effect": {@code SelectDataBankSwitchStrategy} decodes a byte <em>field</em> out of
	 * it, and a strategy that wants the evaluated form must compute it itself here (as
	 * {@code MemoryLatchBankSwitchStrategy} does) rather than have it substituted underneath
	 * every existing override.
	 * <p>
	 * {@code callerRegs} carries the helper function's entry point as its stop address, so a
	 * backward scan started inside the helper adopts the caller's A/X/Y at the entry instead of
	 * walking into the unrelated code that physically precedes it. Any register the call site
	 * could not pin down arrives {@link BankState#unknown()}, so an unresolvable call site
	 * degrades to an unresolved deposit rather than to a guess.
	 * <p>
	 * <b>Soundness.</b> A result derived from {@code callerRegs} is valid for THIS call site
	 * only and must never be cached per switch-site address or attributed to the switch site --
	 * see {@link RegisterEnv}'s class javadoc.
	 */
	default HelperDeposit depositHelperArgument(Program program, Instruction switchSite,
			BankState argValue, BankState inState, int stateMask, RegisterEnv callerRegs) {
		return depositHelperArgument(program, switchSite, argValue, inState, stateMask);
	}

	/**
	 * Whether this strategy's {@link #depositHelperArgument} actually READS {@code argValue}
	 * -- i.e. whether a helper call site's answer depends on the caller's argument register
	 * still holding the bank when control reaches the helper's first switch site (grm-mu7).
	 * <p>
	 * <b>What this gates.</b> {@code BoardBankAnalyzer.findHelpers} necessarily takes a
	 * helper's argument register from the register its mechanism write STORES -- the
	 * {@code STA}/{@code STX}/{@code STY} at the switch site is the only evidence available
	 * there -- and {@code recoverCallArgument} then scans the CALLER for that register. That
	 * chain silently assumes the helper's own prologue leaves the register alone. A helper
	 * that reloads the bank from a RAM shadow breaks the assumption:
	 * <pre>
	 *   $DCA8  LDA $65      ; the bank really comes from RAM
	 *   $DCAA  STA $E000    ; ...but this is where argReg='A' is recorded
	 * </pre>
	 * Called as {@code LDA #$09 / JSR $DCA8}, the caller's 9 is not this helper's argument at
	 * all, and depositing it verbatim ships a confident WRONG bank -- strictly worse, in this
	 * engine, than shipping none. So {@code recoverCallArgument} walks entry..firstSite and
	 * withholds the recovered value when anything there clobbers the register.
	 * <p>
	 * <b>Why it is a per-strategy question rather than a blanket rule.</b> A blanket "decline
	 * when the prologue writes argReg" would break the very case grm-hum increment 2 was
	 * built for. Contra's helper is {@code LDA $FFD0,Y / STA $FFD0,Y} -- its prologue writes
	 * A, and {@code MemoryLatchBankSwitchStrategy} nonetheless answers it correctly, because
	 * it ignores {@code argValue} entirely and re-evaluates its own switch site under the
	 * caller's {@link RegisterEnv}: that mini-inline SEES the prologue, so a clobber there is
	 * not a hazard but an input. Declining for such a strategy would forfeit real answers to
	 * protect against a wrong one it cannot produce.
	 * <p>
	 * {@code true} (the default) is the SAFE answer and is correct for every strategy that
	 * takes {@code argValue} at face value -- the default deposit, {@code serial-shift}, and
	 * {@code select-data} (which decodes a byte field out of it). Only override to
	 * {@code false} when {@code depositHelperArgument} genuinely never consults
	 * {@code argValue}, and re-check this method when changing that override's body: the two
	 * must agree, or the guard protects the wrong strategy.
	 */
	default boolean consumesHelperArgument() {
		return true;
	}

	/**
	 * Where inside a multi-site helper the HELPER'S OWN supplied value lives, when the caller's
	 * argument has been ruled out and {@code BoardBankAnalyzer.valueSuppliedInsideHelper} goes
	 * looking for what the body itself puts there: {@code true} (the default) reads the argument
	 * register at the helper's {@code firstSite}, {@code false} reads it at {@code switchSite}.
	 * <p>
	 * <b>For every single-site mechanism the two are the same instruction</b> (register-write and
	 * memory-latch record exactly one site per helper), so this question only has teeth for the
	 * two multi-site shapes -- and they want OPPOSITE answers, which is why it cannot be a
	 * constant:
	 * <ul>
	 * <li>{@code serial-shift} wants {@code firstSite} (the default). Kid Icarus's
	 * {@code FUN_eb07} is the motivating case: {@code LDA #$0F / STA $9FFF / LSR A / STA $9FFF /
	 * ...} re-derives each successive write from the first by shifting, so the committed byte is
	 * the one live at the FIRST write. Reading the last write's register would see {@code $0F}
	 * already shifted away and report a wrong bank.</li>
	 * <li>{@code select-data} wants {@code switchSite} (bead grm-67g). It is the first shape
	 * where one helper carries two mechanism writes holding DIFFERENT values -- MMC3's
	 * {@code $8000} register-select byte and its {@code $8001} bank byte. smb3's {@code FUN_ffc2}
	 * is {@code LDA #$47 / STA $0721 / STA $8000 / LDA $0720 / STA $8001}: {@code firstSite}
	 * holds {@code $47}, the SELECT byte, which is not this deposit's operand at all. Depositing
	 * it truncated it into the 6-bit {@code r7} field and shipped a confident {@code r7=7} where
	 * the answer is {@code $1B}.</li>
	 * </ul>
	 * <p>
	 * The invariant to reason from: {@code depositHelperArgument} mini-inlines
	 * {@code switchSite}, so {@code switchSite} is where the value is CONSUMED. Returning
	 * {@code true} therefore asserts something extra about the body -- that the value at
	 * {@code firstSite} is the same one {@code switchSite} commits -- which is true of a
	 * re-derived chain and false in general. It stays the default only because it is what every
	 * shipped strategy but this one needs.
	 */
	default boolean suppliesHelperValueAtFirstSite() {
		return true;
	}

	/**
	 * Whether {@link #computeSwitch}'s result at a given {@code (program, instr)} pair is
	 * independent of {@code inState} -- i.e. a pure function of the program and instruction
	 * alone, safe for the dataflow engine to memoize per-address across worklist dequeues
	 * (grm-5tl.13.2). {@code false} (the default) is always safe; only override to
	 * {@code true} when {@code computeSwitch} genuinely never consults {@code inState} (or
	 * anything derived from it) to decide its return value.
	 */
	default boolean cacheable() {
		return false;
	}

	/**
	 * Whether this mechanism's switch RESULT can depend on the tracked bank state that flowed
	 * into the site -- i.e. whether an unknown outcome at the site is evidence the dispatch
	 * NEEDED a state bit it did not have on entry. {@code BoardBankAnalyzer
	 * .annotateBankRequirementViolations} gates its {@code ownRequires} contribution on this
	 * predicate, so it decides whether "the site's effect came out unknown" is allowed to be
	 * blamed on missing bank state.
	 * <p>
	 * {@code true} is the SAFE answer and is what a masked read-modify-write mechanism needs,
	 * since an RMW genuinely consumes its prior value to compute the new one. The default
	 * derives from {@link #cacheable()} so behavior is unchanged for every existing strategy
	 * except where explicitly overridden: a cacheable strategy is by definition a pure function
	 * of program and instruction alone and so cannot depend on prior state, while a
	 * non-cacheable one is assumed to depend on it until it says otherwise.
	 * <p>
	 * Merely ECHOING {@code inState} -- returning it unchanged for a no-op, a deferred-commit
	 * branch, or a poison branch -- is NOT a dependence; that is why this is a separate question
	 * from {@link #cacheable()} rather than a synonym for it. Only override to {@code false}
	 * when the mechanism's registers are genuinely write-only and never resolved back to tracked
	 * state, so an unknown outcome there reflects something else (an unresolved DATA value, for
	 * instance) rather than a missing state bit.
	 */
	default boolean effectDependsOnPriorState() {
		return !cacheable();
	}
}
