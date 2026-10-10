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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link BitField} (bead grm-ze06.4), the one field-position type that
 * replaced four records. Pins the two mask meanings the old records disagreed on -- the
 * POSITIONED mask and the UNPOSITIONED width mask -- and the extract/deposit pair every
 * hand-written shift was converted to. Imports nothing from {@code ghidra.*}.
 */
public class BitFieldTest {

	/** A 4-bit field at bits 2..5. */
	private static final BitField F = new BitField(2, 4);

	@Test
	public void theTwoMasks() {
		assertEquals(0xF, F.widthMask());
		assertEquals(0x3C, F.positionedMask());
	}

	@Test
	public void extractShiftsDownAndClipsToWidth() {
		assertEquals(0x9, F.extract(0b1110_0111));
		assertEquals(0x9L, F.extract(0b1110_0111L));
		// Bits above the field never leak in, including the sign bit.
		assertEquals(0x0, F.extract(0xFFFF_FFC3));
	}

	@Test
	public void placeAndDepositLeaveOtherBitsAlone() {
		assertEquals(0x24, F.place(0x9));
		assertEquals(0x3C, F.place(0xFF)); // a too-wide value is clipped to the field
		assertEquals(0xC3 | 0x24, F.deposit(0xFF, 0x9));
		assertEquals(0xC3L | 0x24L, F.deposit(0xFFL, 0x9L));
	}

	@Test
	public void extractInvertsDeposit() {
		for (int v = 0; v <= F.widthMask(); v++) {
			assertEquals(v, F.extract(F.deposit(0x5A5A, v)));
		}
	}

	@Test
	public void mechanismStateDepositKeepsPartialKnowledge() {
		MechanismState base = new MechanismState(0xFF, 0xA5);
		MechanismState value = new MechanismState(0x3, 0x2); // low two bits known
		MechanismState out = F.deposit(base, value);
		assertEquals(0xC3 | 0x0C, out.knownMask());
		assertEquals((0xA5 & ~0x3C) | 0x08, out.bits());
		assertEquals(new MechanismState(0x3, 0x2), F.extract(out));
	}

	@Test
	public void forgetClearsOnlyTheField() {
		assertEquals(new MechanismState(0xC3, 0x81), F.forget(new MechanismState(0xFF, 0xA5)));
	}

	@Test
	public void valueIfFullyKnownRefusesPartialFields() {
		assertEquals(Integer.valueOf(0x9), F.valueIfFullyKnown(new MechanismState(0x3C, 0x24)));
		assertNull(F.valueIfFullyKnown(new MechanismState(0x38, 0x24)));
	}
}
