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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;

/**
 * grm-gipk.7: {@link JumpTableArrays#layPlanar} and friends with a NEGATIVE gap (the hi half below
 * the lo half), and the overlap rule {@code n <= |gap|}.
 */
public class JumpTableArraysPlanarTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".rom", "0x8000", 0x1000);
		program = builder.getProgram();
	}

	private List<Address> targets(int n) {
		List<Address> out = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			out.add(addr(0x8800 + 0x10L * i));
		}
		return out;
	}

	@Test
	public void negativeGapLaysHiHalfBelowLo() {
		List<Address> t = targets(8);
		boolean laid = inTxGet(program, "lay",
			() -> JumpTableArrays.layPlanar(program, addr(0x8110), -8, t));
		assertTrue(laid);
		assertEquals(8, ((Array) program.getListing().getDefinedDataAt(addr(0x8110)).getDataType())
				.getNumElements());
		assertEquals(8, ((Array) program.getListing().getDefinedDataAt(addr(0x8108)).getDataType())
				.getNumElements());
		assertTrue(JumpTableArrays.isLaidPlanar(program, addr(0x8110), -8, t));
		assertFalse(program.getReferenceManager().getReferencesFrom(addr(0x8113)).length == 0);
		assertEquals(0, program.getReferenceManager().getReferencesFrom(addr(0x810b)).length);

		boolean unlaid = inTxGet(program, "unlay",
			() -> JumpTableArrays.unlayPlanar(program, addr(0x8110), -8));
		assertTrue(unlaid);
		assertNull(program.getListing().getDefinedDataAt(addr(0x8110)));
		assertNull(program.getListing().getDefinedDataAt(addr(0x8108)));
	}

	@Test
	public void negativeGapDeclinesOverlappingHalves() {
		List<Address> t = targets(9);
		assertFalse(inTxGet(program, "lay",
			() -> JumpTableArrays.layPlanar(program, addr(0x8110), -8, t)));
		assertNull(program.getListing().getDefinedDataAt(addr(0x8110)));
	}

	@Test
	public void zeroGapAndPositiveGapBehaveAsBefore() {
		assertFalse(inTxGet(program, "zero",
			() -> JumpTableArrays.layPlanar(program, addr(0x8110), 0, targets(2))));
		assertTrue(inTxGet(program, "pos",
			() -> JumpTableArrays.layPlanar(program, addr(0x8100), 8, targets(8))));
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x8108)));
		assertFalse(inTxGet(program, "pos-overlap",
			() -> JumpTableArrays.layPlanar(program, addr(0x8200), 4, targets(5))));
	}
}
