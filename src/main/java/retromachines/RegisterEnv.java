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

import ghidra.program.model.address.Address;

/**
 * Register values known to hold on entry to a specific address -- the caller-supplied
 * A/X/Y a backward scan may adopt instead of walking past {@code entryAddr}.
 * <p>
 * Exactly one thing populates a non-{@link #NONE} env: {@code BoardBankAnalyzer}'s
 * {@code callSiteRegisters}, at a bank-switch helper call site, with that helper's entry point
 * as {@code entryAddr}. {@link BankSwitchStrategy#depositHelperArgument} then hands it to a
 * strategy that re-evaluates the helper's own switch site under those registers -- grm-hum
 * increment 2's mini-inlining, which is how a helper taking its bank argument in a register
 * other than the one its mechanism write stores (Contra: argument in Y, {@code STA} of A) is
 * resolved without any input-register discovery. Every other path passes {@link #NONE}, for
 * which {@link #stopsAt} is always false and behavior is exactly as it was before.
 * <p>
 * <b>Soundness rule, recorded here because this record is what enables the exception.</b>
 * The backward scan normally refuses to attribute a value across a
 * control-flow join. The entry stop is an argued exception to that: at a function entry the
 * "other incoming paths" are other <em>call sites</em>, and an env-bearing query is asked on
 * behalf of one specific call site -- context-sensitive evaluation, not an ignored hazard.
 * What makes it safe is that <b>an env-derived result is only ever used for that one call
 * site's {@code CallEffect}</b> -- never written into {@code flow.switchResults()}, never into
 * {@code BoardBankAnalyzer}'s {@code matchCache}, never attributed to the switch site itself.
 * That is enforced structurally: {@link BankSwitchStrategy#computeSwitch} keeps its signature
 * and always passes {@link #NONE}, so nothing reachable from the cache can carry an env.
 *
 * @param entryAddr the address the scan stops at, or {@code null} for "never stop"
 * @param a         what A holds on entry
 * @param x         what X holds on entry
 * @param y         what Y holds on entry
 */
public record RegisterEnv(Address entryAddr, BankState a, BankState x, BankState y) {

	/** The empty environment: no entry stop, nothing known. */
	public static final RegisterEnv NONE =
		new RegisterEnv(null, BankState.unknown(), BankState.unknown(), BankState.unknown());

	/** What {@code reg} ({@code 'A'}/{@code 'X'}/{@code 'Y'}) holds on entry; unknown otherwise. */
	public BankState get(char reg) {
		return switch (reg) {
			case 'A' -> a;
			case 'X' -> x;
			case 'Y' -> y;
			default -> BankState.unknown();
		};
	}

	/** Whether a backward scan reaching {@code addr} should stop and adopt this environment. */
	public boolean stopsAt(Address addr) {
		return entryAddr != null && entryAddr.equals(addr);
	}
}
