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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link NesBoardRegistry#validateUnique} (bead grm-7j5): the
 * cross-descriptor guardrail that turns a duplicate mapper or board-id claim into a build-time
 * failure instead of a scan-order coin flip. Drives the real method over synthetic
 * {@link NesBoardRegistry.Board} records -- no {@code Application} bootstrap needed, since
 * {@code validateUnique} takes an already-built list and never touches resource scanning.
 * <p>
 * The scan-order/{@code Application}-dependent half of grm-7j5 (deterministic sort,
 * {@code machines/}-scoping) is exercised for real every time {@link NesBoardRegistry#boards()}
 * runs against the shipped descriptors, which every headless NES golden fixture
 * (banktest chunk {@code nes-banking}) already does -- a real conflict in the shipped set would
 * fail that gate, not just this one.
 */
public class NesBoardRegistryTest {

	private static NesBoardRegistry.Board board(String id, String mapPath, Integer... mappers) {
		return new NesBoardRegistry.Board(id, id + " board", mapPath, mapPath.replace(".map", ".gdt"),
			List.of(mappers));
	}

	@Test
	public void noConflictPasses() {
		NesBoardRegistry.validateUnique(List.of(
			board("nrom", "machines/nes-nrom.map", 0),
			board("uxrom", "machines/nes-uxrom.map", 2),
			board("bandai-fcg", "machines/nes-bandai-fcg.map", 16, 157, 159)));
		// no exception: distinct ids, distinct mapper numbers (including a multi-mapper board)
	}

	@Test
	public void duplicateMapperNumberFails() {
		IllegalStateException e = assertThrows(IllegalStateException.class,
			() -> NesBoardRegistry.validateUnique(List.of(
				board("nrom", "machines/nes-nrom.map", 0, 2),
				board("uxrom", "machines/nes-uxrom.map", 2))));
		assertTrue(e.getMessage().contains("mapper 2"));
		assertTrue(e.getMessage().contains("nes-nrom.map"));
		assertTrue(e.getMessage().contains("nes-uxrom.map"));
	}

	@Test
	public void duplicateBoardIdFails() {
		IllegalStateException e = assertThrows(IllegalStateException.class,
			() -> NesBoardRegistry.validateUnique(List.of(
				board("nrom", "machines/nes-nrom.map", 0),
				board("nrom", "machines/nes-nrom-alt.map", 99))));
		assertTrue(e.getMessage().contains("nrom"));
		assertTrue(e.getMessage().contains("nes-nrom.map"));
		assertTrue(e.getMessage().contains("nes-nrom-alt.map"));
	}
}
