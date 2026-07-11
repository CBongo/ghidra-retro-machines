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
