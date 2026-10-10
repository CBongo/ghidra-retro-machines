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
 * A bit-field's position: bits {@code [lsb, lsb+width)} of some containing word. One type for
 * both levels it occurs at -- a {@code banking.state} field inside the board state
 * ({@link BoardDescriptorModel.FieldSpec} wraps one with its name) and a tracked sub-field
 * inside one mechanism's field-local state (the select-data and serial-shift strategies).
 * <p>
 * Bead grm-ze06.4 replaced four position records with this one. Two of them spelled
 * {@code mask()} differently -- one meant the POSITIONED mask, its sibling the UNPOSITIONED
 * width mask -- so this type deliberately has no {@code mask()}: say {@link #positionedMask}
 * or {@link #widthMask}. Every extract/deposit shift belongs here rather than inline.
 * <p>
 * A field never reaches bit 31 ({@code MapCompiler} caps {@code banking.state} at 31 bits),
 * so the {@code long} overloads the loader's packed-state code uses agree with the {@code int}
 * ones bit for bit.
 *
 * @param lsb the field's lowest bit within the containing word
 * @param width the field's width in bits
 */
record BitField(int lsb, int width) {

	/** The field's width as a mask at bit 0: {@code (1 << width) - 1}. */
	int widthMask() {
		return (1 << width) - 1;
	}

	/** The field's bits in the containing word: {@code widthMask() << lsb}. */
	int positionedMask() {
		return widthMask() << lsb;
	}

	/** This field's value in {@code word}, shifted down to bit 0. */
	int extract(int word) {
		return (word >>> lsb) & widthMask();
	}

	/** This field's value in {@code word}, shifted down to bit 0. */
	long extract(long word) {
		return (word >>> lsb) & widthMask();
	}

	/** {@code value} shifted up into this field's bits, every other bit clear. */
	int place(int value) {
		return (value << lsb) & positionedMask();
	}

	/** {@code word} with this field's bits replaced by {@code value}. */
	int deposit(int word, int value) {
		return (word & ~positionedMask()) | place(value);
	}

	/** {@code word} with this field's bits replaced by {@code value}. */
	long deposit(long word, long value) {
		long mask = positionedMask();
		return (word & ~mask) | ((value << lsb) & mask);
	}

	/** The field's value in {@code state} (known bits and their values) shifted to bit 0. */
	MechanismState extract(MechanismState state) {
		return new MechanismState(extract(state.knownMask()), extract(state.bits()));
	}

	/**
	 * {@code base} with this field replaced by {@code value} -- a field value at bit 0,
	 * possibly only partially known (e.g. mask-algebra knowledge from
	 * {@link StoredValueScanner}) -- leaving every other bit of {@code base} exactly as it was.
	 */
	MechanismState deposit(MechanismState base, MechanismState value) {
		return new MechanismState(deposit(base.knownMask(), value.knownMask()),
			deposit(base.bits(), value.bits()));
	}

	/** {@code base} with this field's bits marked unknown, every other bit untouched. */
	MechanismState forget(MechanismState base) {
		int mask = positionedMask();
		return new MechanismState(base.knownMask() & ~mask, base.bits() & ~mask);
	}

	/**
	 * This field's value in {@code state} when EVERY bit of it is known, else null -- a
	 * dispatch decision (e.g. which register a data write targets) cannot be made from a
	 * partially known field.
	 */
	Integer valueIfFullyKnown(MechanismState state) {
		int mask = positionedMask();
		if ((state.knownMask() & mask) != mask) {
			return null;
		}
		return extract(state.bits());
	}
}
