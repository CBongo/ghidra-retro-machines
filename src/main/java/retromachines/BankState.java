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
 * Per-bit knowledge of a board's bank state: bit {@code b} of {@code bits} is meaningful
 * iff bit {@code b} of {@code knownMask} is set. Only bits within the descriptor's state
 * mask are ever tracked (every {@code BankState} in the engine is constructed already
 * reduced to that mask). {@code knownMask == 0} is the bottom of the lattice ("nothing
 * known"); the dataflow merge at control-flow joins ({@link #merge}) only ever shrinks
 * {@code knownMask}, so the worklist fixpoint terminates.
 * <p>
 * This is the value+mask model of Ghidra's {@code RegisterValue}, reimplemented on ints.
 * Binding it to a real context register (so {@code ProgramContext} carries it natively)
 * needs an <em>application-layer</em> bank-state register to exist. The bundled 6510
 * language (grm-bk6) deliberately does <em>not</em> declare one: it is system-neutral and
 * models only the on-die {@code PORT} register, since the port bits' banking meaning is
 * C64 board wiring, not CPU architecture. So that channel awaits a per-system pspec alias
 * or the RFC #9349 resolution hook; until then the engine stamps a context register only
 * when the program's language actually declares one (today: none).
 */
public record BankState(int knownMask, int bits) {

	private static final BankState BOTTOM = new BankState(0, 0);

	public static BankState unknown() {
		return BOTTOM;
	}

	public static BankState fullyKnown(int mask, int value) {
		return new BankState(mask, value & mask);
	}

	/**
	 * Joins two states at a control-flow merge point: a bit is known in the result only
	 * if it is known -- and agrees -- in both inputs. Monotone ({@code knownMask} only
	 * ever shrinks as more predecessors are merged in).
	 */
	public static BankState merge(BankState a, BankState b) {
		int agree = ~(a.bits() ^ b.bits());
		int knownMask = a.knownMask() & b.knownMask() & agree;
		int bits = a.bits() & knownMask;
		return new BankState(knownMask, bits);
	}

	/**
	 * The effective bank state used for reference retargeting and switch comments: bits
	 * known here keep their tracked value; any bit left unknown is assumed to hold its
	 * {@code banking.initial_state} value. Degrades gracefully -- a fully known state is
	 * unaffected, and a wholly unknown state falls back entirely to the initial state.
	 */
	public int effective(int initialState, int mask) {
		return (bits & knownMask) | (initialState & ~knownMask & mask);
	}
}
