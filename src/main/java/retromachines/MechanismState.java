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

/**
 * One mechanism's bank state in its own field-local coordinates: bit {@code b} of
 * {@code bits} is meaningful iff bit {@code b} of {@code knownMask} is set, and bit 0 is the
 * mechanism's lowest owned bit (a mechanism whose latch sits at {@code lsb 9} sees it at 0).
 * This is what a {@link BankSwitchStrategy}, a {@link StoredValueScanner.Hooks} callback and
 * the helper-argument recovery's {@code localIn} work in; {@link BankState} is the BOARD
 * state (every mechanism's bits at absolute positions). The two are deliberately distinct
 * types so a strategy can never be handed board coordinates by accident (bead grm-ze06.2);
 * {@link MechanismPlacement} holds the only conversions between them.
 * <p>
 * Thin by design: no {@code merge}/{@code effective} -- the dataflow lattice is a board
 * concept, and neither was ever applied to mechanism state. Record equality matters (this
 * is a map key in {@code HelperArgumentRecovery.CallSiteRegKey}).
 *
 * @param knownMask bits whose values are known
 * @param bits the known bit values; bits outside {@code knownMask} are insignificant
 */
public record MechanismState(int knownMask, int bits) implements BitKnowledge {

	private static final MechanismState BOTTOM = new MechanismState(0, 0);

	/** The state in which no bit of the mechanism's field is known. */
	public static MechanismState unknown() {
		return BOTTOM;
	}

	/** A state whose bits in {@code mask} are all known, with the values {@code value & mask}. */
	public static MechanismState fullyKnown(int mask, int value) {
		return new MechanismState(mask, value & mask);
	}

	/**
	 * Folds {@code effect} into {@code base}: bits inside {@code mask} take the effect's
	 * knowledge (known or not), every other bit keeps what {@code base} knew. The
	 * field-local twin of {@link BankDataflowEngine#overwrite} (board coordinates).
	 */
	public static MechanismState overwrite(MechanismState base, MechanismState effect, int mask) {
		return new MechanismState((base.knownMask() & ~mask) | effect.knownMask(),
			(base.bits() & ~mask) | effect.bits());
	}
}
