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
import static org.junit.Assert.assertSame;

import org.junit.Test;

import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

/**
 * Pins bead {@code grm-dos9.3}: a direct switch's bank comment shows the board's layout-mode
 * field as the in-state knows it ({@link BankAnnotationAdapter#withLayoutMode}), so cv3's
 * {@code STA $5116} no longer renders {@code prg_mode} as "assumed from initial" while the
 * dataflow knows it is 2 -- but only alongside knowledge the write itself has, so an
 * undeterminable write keeps its WARNING.
 * <p>
 * Board: {@code mode} bits 0-1 (the layout field), {@code bank} bits 2-5.
 */
public class LayoutModeEchoTest {

	private static final int MODE = 0x03;
	private static final int BANK = 0x3C;

	private static BoardDescriptorModel.BoardModel board() {
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(
			JsonParser.parseString("""
					{
					  "banking": {
					    "initial_state": 3,
					    "mechanisms": [ { "strategy": "memory-latch" }, { "strategy": "memory-latch" } ],
					    "state": [ { "name": "mode", "bits": 2 }, { "name": "bank", "bits": 4 } ]
					  },
					  "layouts": [
					    { "when": { "mode": 2 },
					      "windows": [ { "name": "lo", "start": 32768, "end": 40959,
					                     "maps": { "expr": "bank * 8192" } } ] },
					    { "when": { "mode": 3 },
					      "windows": [ { "name": "lo", "start": 32768, "end": 40959,
					                     "maps": { "expr": "0" } } ] }
					  ]
					}
					""").getAsJsonObject(),
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board.modeField());
		return board;
	}

	@Test
	public void aBankWriteShowsTheModeTheInStateKnows() {
		BankState deposit = new BankState(BANK, 30 << 2); // bank 30, mode not owned
		BankState in = new BankState(MODE, 2); // the dataflow knows mode 2

		BankState shown = BankAnnotationAdapter.withLayoutMode(deposit, in, BANK, board());

		assertEquals(MODE | BANK, shown.knownMask());
		assertEquals(2 | (30 << 2), shown.bits());
	}

	@Test
	public void aWriteThatResolvedNothingIsLeftAloneSoItStillWarns() {
		BankState nothing = BankState.unknown();

		assertSame(nothing, BankAnnotationAdapter.withLayoutMode(nothing,
			new BankState(MODE, 2), BANK, board()));
	}

	@Test
	public void aModeWriteKeepsItsOwnModeNotTheInStates() {
		BankState deposit = new BankState(MODE, 1); // this mechanism owns and writes mode 1

		BankState shown = BankAnnotationAdapter.withLayoutMode(deposit, new BankState(MODE, 2),
			MODE, board());

		assertEquals(MODE, shown.knownMask());
		assertEquals(1, shown.bits());
	}

	@Test
	public void anUnknownInStateModeAddsNothing() {
		BankState deposit = new BankState(BANK, 5 << 2);

		BankState shown = BankAnnotationAdapter.withLayoutMode(deposit, BankState.unknown(), BANK,
			board());

		assertEquals(BANK, shown.knownMask());
	}
}
