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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Map;

import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link DescriptorSupport#parsePlacementOverride} (bead grm-hsv.3):
 * the shared {@code window:bank} grammar both the NES loader (validateOptions) and the bank
 * analyzer (read side) go through. Imports nothing from {@code ghidra.*} -- the grammar is
 * plain string logic, so no Ghidra runtime bootstrap is needed (same discipline as
 * {@link BankStateTest}). The colon separator, not '=', is deliberate: cmd.exe's
 * analyzeHeadless.bat splits arg values on '='.
 */
public class PlacementOverrideParseTest {

	@Test
	public void singlePairParsesToWindowBankEntry() {
		Map<String, Integer> parsed = DescriptorSupport.parsePlacementOverride("W8000:5");
		assertEquals(1, parsed.size());
		assertEquals(Integer.valueOf(5), parsed.get("W8000"));
	}

	@Test
	public void multiplePairsPreserveInsertionOrder() {
		Map<String, Integer> parsed =
			DescriptorSupport.parsePlacementOverride("W8000:5 WC000:3");
		assertEquals(2, parsed.size());
		assertEquals(Integer.valueOf(5), parsed.get("W8000"));
		assertEquals(Integer.valueOf(3), parsed.get("WC000"));
		assertEquals(new ArrayList<>(parsed.keySet()), java.util.List.of("W8000", "WC000"));
	}

	@Test
	public void extraWhitespaceBetweenAndAroundPairsIsTolerated() {
		Map<String, Integer> parsed =
			DescriptorSupport.parsePlacementOverride("  W8000:5   WC000:3  ");
		assertEquals(2, parsed.size());
		assertEquals(Integer.valueOf(5), parsed.get("W8000"));
		assertEquals(Integer.valueOf(3), parsed.get("WC000"));
	}

	@Test
	public void nullAndBlankYieldEmptyMap() {
		assertTrue(DescriptorSupport.parsePlacementOverride(null).isEmpty());
		assertTrue(DescriptorSupport.parsePlacementOverride("").isEmpty());
		assertTrue(DescriptorSupport.parsePlacementOverride("   ").isEmpty());
	}

	@Test
	public void equalsSeparatorIsRejected() {
		// The old '='-based shape (bank=5:W8000) must not parse -- it is exactly what the
		// headless batch arg parser mangles, and the grammar moved to colons because of it.
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parsePlacementOverride("bank=5:W8000"));
		assertTrue(e.getMessage().contains("window:bank"));
	}

	@Test
	public void missingBankIsRejected() {
		assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parsePlacementOverride("W8000"));
	}

	@Test
	public void nonNumericBankIsRejected() {
		assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parsePlacementOverride("W8000:x"));
	}

	@Test
	public void repeatedWindowIsRejected() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorSupport.parsePlacementOverride("W8000:5 W8000:3"));
		assertTrue(e.getMessage().contains("more than once"));
	}
}
