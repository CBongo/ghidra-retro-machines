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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.listing.Function;

import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins {@code HelperDiscovery.findChainWrappers} (bead grm-a0nx): smb3's {@code $FFBF} is
 * {@code JSR $FFD1} that then falls through into {@code $FFC2}, both bank-switch helpers, so a
 * call to it runs both. Layout here: wrapper {@code $8000: JSR $9000} falling into helper B at
 * {@code $8003}; helper A at {@code $9000}.
 */
public class ChainWrapperProgramTest extends AbstractProgramTest {

	private Map<Function, HelperModel> helpers;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		helpers = new LinkedHashMap<>();
	}

	private Function body(String name, long at, String bytes, int len) throws Exception {
		builder.setBytes(hex(at), bytes, true);
		return builder.createEmptyFunction(name, hex(at), len, null);
	}

	private HelperModel helper(Function f, int mask) {
		HelperModel m = new HelperModel(f, f.getEntryPoint(), null, 'A', mask, 0, null,
			f.getEntryPoint(), f.getEntryPoint(), null);
		helpers.put(f, m);
		return m;
	}

	@Test
	public void aJsrIntoOneHelperFallingIntoAnotherIsAChainOfBoth() throws Exception {
		Function wrapper = body("W", 0x8000, "20 00 90", 3);
		Function b = body("B", 0x8003, "ea 60", 2);
		Function a = body("A", 0x9000, "ea 60", 2);
		HelperModel ma = helper(a, 0x03);
		HelperModel mb = helper(b, 0x0C);
		Map<Function, HelperModel> out =
			HelperDiscovery.findChainWrappers(program, helpers, Map.of());
		HelperModel chain = out.get(wrapper);
		assertNotNull("wrapper not admitted", chain);
		assertEquals(2, chain.chain().size());
		assertSame(ma, chain.chain().get(0));
		assertSame(mb, chain.chain().get(1));
		assertEquals(0x0F, chain.effectMask());
		assertNull(chain.constState());
	}

	@Test
	public void aFallThroughTargetThatIsNotAHelperIsNotAChain() throws Exception {
		Function wrapper = body("W", 0x8000, "20 00 90", 3);
		body("B", 0x8003, "ea 60", 2);
		helper(body("A", 0x9000, "ea 60", 2), 0x03);
		assertNull(HelperDiscovery.findChainWrappers(program, helpers, Map.of()).get(wrapper));
	}

	@Test
	public void aJsrTargetThatIsNotAHelperIsNotAChain() throws Exception {
		Function wrapper = body("W", 0x8000, "20 00 90", 3);
		helper(body("B", 0x8003, "ea 60", 2), 0x0C);
		body("A", 0x9000, "ea 60", 2);
		assertNull(HelperDiscovery.findChainWrappers(program, helpers, Map.of()).get(wrapper));
	}

	@Test
	public void aWrapperWithMoreThanTheJsrIsNotAChain() throws Exception {
		Function wrapper = body("W", 0x8000, "20 00 90 ea", 4);
		helper(body("B", 0x8004, "ea 60", 2), 0x0C);
		helper(body("A", 0x9000, "ea 60", 2), 0x03);
		assertNull(HelperDiscovery.findChainWrappers(program, helpers, Map.of()).get(wrapper));
	}

	@Test
	public void aFirstHelperThatClobbersTheSecondsArgumentRegisterDeclines() throws Exception {
		Function wrapper = body("W", 0x8000, "20 00 90", 3);
		// B reads the caller's A (STA $8001 first); A does LDA #$05 (clobbers A)
		helper(body("B", 0x8003, "8d 01 80 60", 4), 0x0C);
		helper(body("A", 0x9000, "a9 05 60", 3), 0x03);
		assertNull(HelperDiscovery.findChainWrappers(program, helpers, Map.of()).get(wrapper));
	}

	@Test
	public void aSecondHelperThatLoadsItsOwnArgumentFirstSurvivesAClobberingFirst()
			throws Exception {
		Function wrapper = body("W", 0x8000, "20 00 90", 3);
		helper(body("B", 0x8003, "a5 10 8d 01 80 60", 6), 0x0C);
		helper(body("A", 0x9000, "a9 05 60", 3), 0x03);
		assertNotNull(HelperDiscovery.findChainWrappers(program, helpers, Map.of()).get(wrapper));
	}
}
