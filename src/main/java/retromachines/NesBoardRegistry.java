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

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Registry of NES board descriptors, built by scanning the extension's bundled
 * {@code machines/*.map} files for a {@code system.board.ines_mappers} key — the
 * data-driven "board chosen the same way languages are chosen" registry from the
 * vision doc (§3.1): adding a board is adding a descriptor, no Java changes. Boards
 * are keyed by the iNES mapper number(s) they serve; {@link NesRomLoader} resolves
 * the header's mapper to a default board and offers the full list as an import
 * option override.
 */
final class NesBoardRegistry {

	/**
	 * One board descriptor: its system id/display name, the bundled map/gdt resource
	 * paths, and the iNES mapper numbers it serves.
	 */
	record Board(String id, String name, String mapPath, String gdtPath,
			List<Integer> mappers) {}

	private static List<Board> boards;

	private NesBoardRegistry() {
	}

	static synchronized List<Board> boards() {
		if (boards == null) {
			boards = scan();
		}
		return boards;
	}

	/** The board whose {@code ines_mappers} claims this mapper number, or null. */
	static Board forMapper(int mapper) {
		for (Board board : boards()) {
			if (board.mappers().contains(mapper)) {
				return board;
			}
		}
		return null;
	}

	/** The board with this system id (the import-option override key), or null. */
	static Board forId(String id) {
		for (Board board : boards()) {
			if (board.id().equals(id)) {
				return board;
			}
		}
		return null;
	}

	private static List<Board> scan() {
		List<Board> found = new ArrayList<>();
		for (ResourceFile mapFile : Application.findFilesByExtensionInMyModule(".map")) {
			try (InputStreamReader reader =
					new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
				JsonObject map = JsonParser.parseReader(reader).getAsJsonObject();
				JsonObject system = map.getAsJsonObject("system");
				if (system == null || !system.has("board")) {
					continue;
				}
				JsonObject board = system.getAsJsonObject("board");
				if (!board.has("ines_mappers")) {
					continue;
				}
				List<Integer> mappers = new ArrayList<>();
				for (JsonElement mapper : board.getAsJsonArray("ines_mappers")) {
					mappers.add(mapper.getAsInt());
				}
				String base = mapFile.getName().substring(0, mapFile.getName().length() - 4);
				found.add(new Board(system.get("id").getAsString(),
					system.get("name").getAsString(), "machines/" + base + ".map",
					"machines/" + base + ".gdt", mappers));
			}
			catch (Exception e) {
				Msg.warn(NesBoardRegistry.class,
					"Skipping unparseable board descriptor " + mapFile.getName() + ": " + e);
			}
		}
		return found;
	}
}
