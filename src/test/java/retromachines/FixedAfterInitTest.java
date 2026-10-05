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
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

/**
 * A game descriptor's {@code banking.fixed_after_init} hint (bead grm-mej.12) resolved to a
 * state-bit mask by {@link DescriptorSupport#resolveFixedAfterInitMask}. Same Gson-in/number-out
 * style as {@link GameInitialStateHintTest}.
 */
public class FixedAfterInitTest {

	/** MMC1-like layout, LSB-first: mirroring(2) bits 0-1, prg_mode(2) bits 2-3, prg_bank(5). */
	private static final String BOARD = """
			{ "banking": { "initial_state": 12, "state": [
			  { "name": "mirroring", "bits": 2 },
			  { "name": "prg_mode",  "bits": 2 },
			  { "name": "prg_bank",  "bits": 5 } ] } }
			""";

	private static JsonObject json(String text) {
		return JsonParser.parseString(text).getAsJsonObject();
	}

	private static JsonObject game(String list) {
		return json("{ \"banking\": { \"fixed_after_init\": " + list + " } }");
	}

	@Test
	public void fieldBecomesItsBitRange() {
		MessageLog log = new MessageLog();
		assertEquals(0b1100L, DescriptorSupport.resolveFixedAfterInitMask(json(BOARD),
			game("[\"prg_mode\"]"), "g.gmap", log));
		assertEquals("", log.toString().trim());
	}

	@Test
	public void severalFieldsUnion() {
		assertEquals(0b1111L, DescriptorSupport.resolveFixedAfterInitMask(json(BOARD),
			game("[\"prg_mode\", \"mirroring\"]"), "g.gmap", new MessageLog()));
	}

	@Test
	public void unknownFieldIsLoggedAndIgnored() {
		MessageLog log = new MessageLog();
		assertEquals(0b1100L, DescriptorSupport.resolveFixedAfterInitMask(json(BOARD),
			game("[\"nope\", \"prg_mode\"]"), "g.gmap", log));
		assertTrue(log.toString(), log.toString().contains("nope"));
	}

	@Test
	public void onlyUnknownFieldGivesZero() {
		assertEquals(0L, DescriptorSupport.resolveFixedAfterInitMask(json(BOARD),
			game("[\"nope\"]"), "g.gmap", new MessageLog()));
	}

	@Test
	public void noHintGivesZero() {
		assertEquals(0L, DescriptorSupport.resolveFixedAfterInitMask(json(BOARD),
			json("{ \"game\": {} }"), "g.gmap", new MessageLog()));
	}
}
