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
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

/**
 * Load-time folding of a curated game descriptor's {@code banking.initial_state} hint (bead
 * {@code grm-hb6.12}) into an already-resolved packed power-on state:
 * {@link DescriptorSupport#applyGameInitialStateHint}. Same tier and same Gson-in/numbers-out
 * style as {@link InitialStateResolutionTest}, which covers the board-only half of this same
 * seam ({@code banking.initial_state_expr}, bead {@code grm-y0ml}) that this hint is folded in
 * AFTER.
 */
public class GameInitialStateHintTest {

	/** nes_mmc3's shape, reduced to the one field the smb3 hint names plus a neighbor, so a
	 *  packing bug that clobbers an adjacent field is visible. LSB-first: select(3), prg_mode(1)
	 *  at bit 3, r6(2) at bit 4. */
	private static final String MMC3_SHAPE = """
			{
			  "banking": {
			    "initial_state": 9,
			    "state": [
			      { "name": "select",   "bits": 3 },
			      { "name": "prg_mode", "bits": 1 },
			      { "name": "r6",       "bits": 2 }
			    ]
			  }
			}
			""";

	private static JsonObject json(String text) {
		return JsonParser.parseString(text).getAsJsonObject();
	}

	private static JsonObject gameDoc(String bankingInitialState) {
		return json("{ \"banking\": { \"initial_state\": " + bankingInitialState + " } }");
	}

	@Test
	public void hintFieldPacksIntoTheRightBits() {
		MessageLog log = new MessageLog();
		// select=1 (bits 0-2), r6=2 (bits 4-5) -> literal 9 = 0b01001 has select=1, prg_mode=1,
		// r6=0. Hint sets prg_mode to 0: expect select and r6 untouched, prg_mode bit cleared.
		Long result = DescriptorSupport.applyGameInitialStateHint(json(MMC3_SHAPE), 9L,
			gameDoc("{ \"prg_mode\": 0 }"), "games/test.gmap", log);
		assertEquals(Long.valueOf(1), result); // 0b00001: select=1, prg_mode=0, r6=0
	}

	@Test
	public void hintBeatsTheCompiledLiteral() {
		MessageLog log = new MessageLog();
		// literal prg_mode is 1 (bit 3 of 9); hint sets it to... itself would be a no-op test,
		// so flip it and confirm the packed result actually changed.
		Long result = DescriptorSupport.applyGameInitialStateHint(json(MMC3_SHAPE), 9L,
			gameDoc("{ \"prg_mode\": 0 }"), "games/test.gmap", log);
		assertEquals("hint must change the packed value away from the compiled literal",
			Long.valueOf(1), result);
	}

	@Test
	public void hintAppliesAfterAndOverInitialStateExpr() {
		MessageLog log = new MessageLog();
		// Simulates the caller sequence in NesRomLoader.load: resolveInitialState runs first
		// (here stood in for by a hand-resolved value, since this method only sees its output),
		// then the game hint is folded in on top and must win.
		String boardWithExpr = MMC3_SHAPE.replace("\"initial_state\": 9,",
			"\"initial_state\": 9, \"initial_state_expr\": { \"r6\": \"image_size\" },");
		long afterExpr = 9L | (3L << 4); // pretend the expr resolved r6 to 3
		Long result = DescriptorSupport.applyGameInitialStateHint(json(boardWithExpr), afterExpr,
			gameDoc("{ \"r6\": 1 }"), "games/test.gmap", log);
		assertEquals(Long.valueOf(9L | (1L << 4)), result);
		assertTrue("overriding an initial_state_expr field must be logged",
			log.toString().contains("overrides"));
		assertTrue(log.toString(), log.toString().contains("r6"));
	}

	@Test
	public void noHintLeavesTheResolvedValueUntouched() {
		MessageLog log = new MessageLog();
		JsonObject gameDoc = json("{ \"game\": { \"id\": \"x\" } }"); // no banking at all
		assertEquals(Long.valueOf(9), DescriptorSupport.applyGameInitialStateHint(
			json(MMC3_SHAPE), 9L, gameDoc, "games/test.gmap", log));
		assertEquals("", log.toString().trim());
	}

	// --- refusal paths (CLAUDE.md: log and refuse that one field, never throw/guess) ---

	@Test
	public void unknownFieldNameIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		Long result = DescriptorSupport.applyGameInitialStateHint(json(MMC3_SHAPE), 9L,
			gameDoc("{ \"nope\": 1 }"), "games/test.gmap", log);
		assertEquals("unknown field must leave the packed value untouched", Long.valueOf(9),
			result);
		assertTrue(log.toString(), log.toString().contains("nope"));
		assertTrue(log.toString(), log.toString().contains("not a banking.state field"));
	}

	@Test
	public void outOfRangeValueIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		// prg_mode is 1 bit wide; 2 does not fit.
		Long result = DescriptorSupport.applyGameInitialStateHint(json(MMC3_SHAPE), 9L,
			gameDoc("{ \"prg_mode\": 2 }"), "games/test.gmap", log);
		assertEquals("out-of-range value must leave the field at its previously resolved value",
			Long.valueOf(9), result);
		assertTrue(log.toString(), log.toString().contains("does not fit"));
		assertTrue(log.toString(), log.toString().contains("prg_mode"));
	}

	@Test
	public void hintOnABoardWithNoResolvedInitialStateIsRefusedWhole() {
		MessageLog log = new MessageLog();
		// resolveInitialState returns null when the board descriptor has no banking.initial_state
		// at all (e.g. NROM) -- nothing to fold a field value into.
		Long result = DescriptorSupport.applyGameInitialStateHint(json("{}"), null,
			gameDoc("{ \"prg_mode\": 1 }"), "games/test.gmap", log);
		assertNull(result);
		assertTrue(log.toString(), log.toString().contains("no banking.initial_state"));
	}

	@Test
	public void malformedHintValueIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		JsonObject gameDoc =
			json("{ \"banking\": { \"initial_state\": { \"prg_mode\": \"not-a-number\" } } }");
		Long result = DescriptorSupport.applyGameInitialStateHint(json(MMC3_SHAPE), 9L, gameDoc,
			"games/test.gmap", log);
		assertEquals(Long.valueOf(9), result);
		assertTrue(log.toString(), log.toString().contains("prg_mode"));
	}
}
