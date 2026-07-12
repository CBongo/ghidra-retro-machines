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
}
