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

import org.junit.Test;

import retromachines.HelperDiscovery.HelperModel;

/**
 * {@link HelperModel#placement()}'s contract (bead grm-wiwv): a model with a strategy or an
 * argument register answers its own placement, and one with neither -- the degraded
 * multi-mechanism union, a composed tail-call effect, a second-tier wrapper -- refuses, because
 * the {@code lsb == 0} it is built with describes no single field. On {@code nes-mmc5} a latch at lsb 9 summarized
 * under lsb 0 would shift every converted bank by nine bits; throwing makes a future caller
 * that converts through a composed model fail loudly instead.
 */
public class HelperModelPlacementTest {

	@Test
	public void aModelWithAStrategyAnswersItsOwnPlacement() {
		HelperModel model = new HelperModel(null, null, null, 'A', 0x0000FE00, 9,
			new RegisterWriteBankSwitchStrategy(), null, null, null);
		assertEquals(new MechanismPlacement(9, 0x0000FE00), model.placement());
	}

	@Test
	public void anArgumentRegisterWithoutAStrategyStillAnswers() {
		// HelperArgumentRecovery's no-strategy fallback: the argument byte is the field verbatim,
		// positioned at this model's own lsb -- a real placement, so it must not throw.
		HelperModel model = new HelperModel(null, null, null, 'A', 0x0000FE00, 9, null, null,
			null, null);
		assertEquals(new MechanismPlacement(9, 0x0000FE00), model.placement());
	}

	@Test
	public void aModelWithNeitherStrategyNorArgumentRegisterRefuses() {
		// The shape findHelpers' degraded union builds on mmc5: two latches' masks, lsb 0.
		HelperModel union = new HelperModel(null, null, null, null, 0x0000FE00 | 0x007F0000, 0,
			null, null, null, null);
		assertThrows(IllegalStateException.class, union::placement);
	}
}
