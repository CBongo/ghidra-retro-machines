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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** {@link ForthConfig#merge}: member {@code forth} over game {@code forth} (grm-arbi.3). */
public class ForthConfigMergeTest {

	private static JsonObject json(String s) {
		return JsonParser.parseString(s).getAsJsonObject();
	}

	@Test
	public void memberNamesWinAndKeysAreNormalised() {
		JsonObject game = json("""
			{"ip": 126, "w": 129, "docol": 2274, "exit": [2862], "handlers": {},
			 "names": {"2862": {"name": "EXIT"}, "100": {"name": "GAME"}}}""");
		JsonObject member = json("""
			{"names": {"0x0064": {"name": "MEMBER"}, "200": {"name": "ONLY"}},
			 "inline": {"2218": "lit16"}}""");
		ForthConfig cfg = ForthConfig.fromMap(ForthConfig.merge(game, member));
		assertEquals("EXIT", cfg.names().get(2862).name());
		assertEquals("MEMBER", cfg.names().get(100).name());
		assertEquals("ONLY", cfg.names().get(200).name());
		assertEquals(ForthConfig.InlineMode.LIT16, cfg.inline().get(2218));
		assertEquals("GAME", game.getAsJsonObject("names").getAsJsonObject("100").get("name")
				.getAsString());
	}

	@Test
	public void nullsPassThrough() {
		assertNull(ForthConfig.merge(null, null));
		JsonObject game = json("{\"ip\": 1}");
		assertEquals(1, ForthConfig.merge(game, null).get("ip").getAsInt());
	}
}
