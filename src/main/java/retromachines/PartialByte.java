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
 * A PARTLY-KNOWN BYTE: the value of a register (A/X/Y) or a memory cell, one bit at a time.
 * Bit {@code b} of {@code bits} is meaningful iff bit {@code b} of {@code knownMask} is set;
 * {@code knownMask == 0} is "nothing known".
 * <p>
 * <b>Why this is not a {@link BankState}</b> (bead grm-ze06.1). Both are value+mask pairs, but a
 * {@code BankState} is bank state -- board state, or one mechanism's field-local state, whose
 * width is a property of the descriptor or the mechanism -- whereas this is a machine BYTE, always
 * exactly eight bits wide. Reusing the one record for both let a mechanism-width mask (MMC3's
 * {@code 0xFFFF}, MMC1's {@code 0x1FF}) flow into a byte scan and be clipped by an incidental
 * {@code & 0xFF}; the clip now lives HERE, in the constructor, and nowhere else. Crossing between
 * the two kinds of value is a named method on the owning strategy (deposit / extract), never a
 * reinterpretation of the same record.
 * <p>
 * The constructor clips both fields to a byte and deliberately does NOT normalise
 * {@code bits &= knownMask}: records compare by value, and not every producer guarantees bits are
 * zero outside the known mask, so normalising here would change equality.
 *
 * @param knownMask bits whose values are known (clipped to 8 bits)
 * @param bits the known bit values (clipped to 8 bits); bits outside {@code knownMask} are
 *             insignificant
 */
public record PartialByte(int knownMask, int bits) {

	/** All eight bits of a byte. */
	public static final int BYTE_MASK = 0xFF;

	private static final PartialByte UNKNOWN = new PartialByte(0, 0);

	public PartialByte {
		knownMask &= BYTE_MASK;
		bits &= BYTE_MASK;
	}

	/**
	 * The byte about which nothing is known.
	 *
	 * @return the bottom element
	 */
	public static PartialByte unknown() {
		return UNKNOWN;
	}

	/**
	 * A byte whose eight bits are all known.
	 *
	 * @param value the byte's value (only its low eight bits are kept)
	 * @return the fully known byte
	 */
	public static PartialByte fullyKnown(int value) {
		return new PartialByte(BYTE_MASK, value);
	}

	/**
	 * A byte with the given known bits.
	 *
	 * @param knownMask the bits whose values are known
	 * @param bits the values of those bits
	 * @return the partly known byte
	 */
	public static PartialByte of(int knownMask, int bits) {
		return new PartialByte(knownMask, bits);
	}

	/**
	 * Whether all eight bits are known.
	 *
	 * @return true if no bit is unknown
	 */
	public boolean isFullyKnown() {
		return knownMask == BYTE_MASK;
	}

	/**
	 * Whether anything at all is known.
	 *
	 * @return true if at least one bit is known
	 */
	public boolean knowsAnything() {
		return knownMask != 0;
	}

	/**
	 * Whether every bit selected by {@code byteMask} is known. Bits of {@code byteMask} beyond
	 * the eighth select nothing in a byte and are ignored -- so a mask wider than a byte is
	 * satisfied exactly when the whole byte is known over its low eight bits.
	 *
	 * @param byteMask the byte bits of interest
	 * @return true if all of them are known
	 */
	public boolean knowsAll(int byteMask) {
		int want = byteMask & BYTE_MASK;
		return (knownMask & want) == want;
	}

	/**
	 * Whether bit {@code bit} is known.
	 *
	 * @param bit the bit index, 0..7
	 * @return true if that bit's value is known
	 */
	public boolean isKnown(int bit) {
		return (knownMask & (1 << bit)) != 0;
	}

	/**
	 * The value of bit {@code bit}; meaningful only when {@link #isKnown} is true.
	 *
	 * @param bit the bit index, 0..7
	 * @return 1 if the bit is set in {@code bits}, else 0
	 */
	public int bit(int bit) {
		return (bits >> bit) & 1;
	}

	/**
	 * The exact value when every bit is known, else {@code null} -- the all-or-nothing view an
	 * effective-address or AND/ORA operand needs.
	 *
	 * @return the byte value 0..255, or {@code null}
	 */
	public Integer exact() {
		return isFullyKnown() ? Integer.valueOf(bits) : null;
	}

	/**
	 * This byte reduced to {@code byteMask}: bits outside it become unknown.
	 *
	 * @param byteMask the byte bits to keep
	 * @return the restricted byte
	 */
	public PartialByte restrict(int byteMask) {
		return new PartialByte(knownMask & byteMask, bits & byteMask);
	}

	/**
	 * Joins two bytes at a merge: a bit is known only if it is known -- and agrees -- in both.
	 *
	 * @param a one byte
	 * @param b the other
	 * @return the greatest byte whose known bits agree in both inputs
	 */
	public static PartialByte merge(PartialByte a, PartialByte b) {
		int known = a.knownMask & b.knownMask & ~(a.bits ^ b.bits);
		return new PartialByte(known, a.bits & known);
	}
}
