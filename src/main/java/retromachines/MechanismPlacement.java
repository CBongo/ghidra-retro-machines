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
 * Where one mechanism's field sits in the board state: {@code effectMask} is the set of
 * board-state bits it owns and {@code lsb} is the position of its lowest one. This is the
 * ONLY place board coordinates ({@link BankState}) and field-local coordinates
 * ({@link MechanismState}) convert into one another (bead grm-ze06.2); before it, the
 * engine's {@code toFieldLocal}/{@code position} plus several inline shifts did the same
 * job unchecked.
 *
 * @param lsb the shift between board bit positions and field-local ones
 * @param effectMask the board-state bits the mechanism owns
 */
public record MechanismPlacement(int lsb, int effectMask) {

	/**
	 * Narrows a board state to this mechanism's field-local {@code [0, width)} space: the
	 * bits outside {@code effectMask} are discarded and the survivors shifted down by
	 * {@code lsb}. This is what a {@link BankSwitchStrategy} sees as its {@code inState}.
	 * The inverse of {@link #position}.
	 */
	public MechanismState toLocal(BankState board) {
		return new MechanismState((board.knownMask() & effectMask) >>> lsb,
			(board.bits() & effectMask) >>> lsb);
	}

	/**
	 * Positions a mechanism's field-local result back into board bits: shifted up by
	 * {@code lsb} and masked to {@code effectMask} (a defensive mask -- it keeps a stray high
	 * bit from a strategy from ever leaking outside the mechanism's own field). The inverse
	 * of {@link #toLocal}.
	 */
	public BankState position(MechanismState local) {
		return new BankState((local.knownMask() << lsb) & effectMask,
			(local.bits() << lsb) & effectMask);
	}

	/**
	 * Board bits restricted to this mechanism's window, and NOT shifted: the result stays in
	 * BOARD coordinates, with every bit outside {@code effectMask} unknown (bead grm-ze06.3).
	 * This is not a coordinate conversion -- contrast {@link #toLocal}, which also shifts down
	 * to bit 0. The engine uses it for a helper call's annotation state, which echoes the
	 * in-state only within the helper's own mechanism (see {@code CallSwitch}).
	 */
	public BankState window(BankState board) {
		return new BankState(board.knownMask() & effectMask, board.bits() & effectMask);
	}

	/** Positions a field-local owned-bit mask into board bits, clipped to {@code effectMask}. */
	public int positionMask(int ownedMask) {
		return (ownedMask << lsb) & effectMask;
	}

	/** The mechanism's field width as a mask: {@code effectMask >>> lsb}. */
	public int widthMask() {
		return effectMask >>> lsb;
	}
}
