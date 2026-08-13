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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

/**
 * Pins {@link StackFloor}: where the line between "stack" and "low-page scratch" falls, and that
 * it is a knob rather than a constant. The program-property route is exercised against a real
 * program in {@code StoreForwardingProgramTest.programPropertyMovesTheFloor}; this covers the
 * run-wide route and the parsing, which need no program at all.
 * <p>
 * Every consumer of the floor treats a refusal as "forfeit this forward", so the tests that
 * matter most are the two endpoints -- they are what a future investigator will reach for to
 * reproduce the pre- and post-{@code grm-mej.3}-increment-2 behavior exactly.
 */
public class StackFloorTest {

	private static final AddressSpace RAM =
		new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

	@After
	public void clearRunOverride() {
		System.clearProperty(StackFloor.SYSTEM_PROPERTY);
	}

	private static Address at(long offset) {
		return RAM.getAddress(offset);
	}

	@Test
	public void defaultFloorSplitsTheStackPageAt0140() {
		assertEquals(0x40, StackFloor.floor(null));
		assertFalse(StackFloor.mayAliasStack(null, at(0x0103))); // dodge's scratch cell
		assertFalse(StackFloor.mayAliasStack(null, at(0x013F))); // last scratch byte
		assertTrue(StackFloor.mayAliasStack(null, at(0x0140))); // first assumed-stack byte
		assertTrue(StackFloor.mayAliasStack(null, at(0x01FF))); // the stack's own base
	}

	@Test
	public void addressesOutsideTheStackPageAreNeverStack() {
		assertFalse(StackFloor.mayAliasStack(null, at(0x00C3))); // zero page
		assertFalse(StackFloor.mayAliasStack(null, at(0x00FF)));
		assertFalse(StackFloor.mayAliasStack(null, at(0x0200)));
		assertFalse(StackFloor.mayAliasStack(null, at(0x07EC))); // contra's save slot
	}

	@Test
	public void anUnplaceableCellReadsAsUnsafe() {
		assertTrue(StackFloor.mayAliasStack(null, null));
	}

	/** Floor 0 = "the stack can reach anywhere in the page" = the pre-increment-2 blanket guard. */
	@Test
	public void floorZeroRefusesTheWholePage() {
		System.setProperty(StackFloor.SYSTEM_PROPERTY, "0");
		assertTrue(StackFloor.mayAliasStack(null, at(0x0100)));
		assertTrue(StackFloor.mayAliasStack(null, at(0x0103)));
		assertFalse(StackFloor.mayAliasStack(null, at(0x00FF)));
	}

	/** Floor $100 = "the stack is empty" = increment 2 as shipped, before the floor existed. */
	@Test
	public void floorOfAFullPageAcceptsTheWholePage() {
		System.setProperty(StackFloor.SYSTEM_PROPERTY, "0x100");
		assertFalse(StackFloor.mayAliasStack(null, at(0x0100)));
		assertFalse(StackFloor.mayAliasStack(null, at(0x01FF)));
	}

	@Test
	public void acceptsDecimalAndBothHexSpellings() {
		System.setProperty(StackFloor.SYSTEM_PROPERTY, "128");
		assertEquals(0x80, StackFloor.floor(null));
		System.setProperty(StackFloor.SYSTEM_PROPERTY, "$80");
		assertEquals(0x80, StackFloor.floor(null));
		System.setProperty(StackFloor.SYSTEM_PROPERTY, " 0X80 ");
		assertEquals(0x80, StackFloor.floor(null));
	}

	/**
	 * A tuning knob must never cost a user their import, so anything unparseable or out of range
	 * falls through to the default rather than throwing.
	 */
	@Test
	public void malformedOrOutOfRangeValuesFallBackToTheDefault() {
		for (String bad : new String[] { "", "  ", "deadbeef", "-1", "0x101", "40 60", "$" }) {
			System.setProperty(StackFloor.SYSTEM_PROPERTY, bad);
			assertEquals("floor for \"" + bad + "\"", StackFloor.DEFAULT_FLOOR,
				StackFloor.floor(null));
		}
	}
}
