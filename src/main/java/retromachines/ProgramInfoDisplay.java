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

import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Program;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Human-readable renderings of machine-read program properties (bead grm-4x8f).
 * <p>
 * Ghidra's About Program view skips every Program Information option whose name contains
 * {@code '.'}, so the dotted {@code "Retro Machines.*"} properties the analyzers parse are
 * invisible there. The properties written here carry the same facts in words, under undotted
 * names, and are display-only: nothing reads them back.
 */
final class ProgramInfoDisplay {

	private ProgramInfoDisplay() {
	}

	/**
	 * Decodes a layout mode into its field name, value and the windows that value selects, e.g.
	 * {@code "prg_mode = 1: $8000 = PRG[second_last]; $A000 = PRG[r7 * 0x2000]; ..."}. Falls
	 * back to {@code "<field> = <mode>"} when the board has no matching layout, and to the bare
	 * number when the board names no layout field.
	 */
	static String layoutModeText(JsonObject boardMap, int mode) {
		String field = BoardStateFields.layoutModeField(boardMap);
		if (field == null) {
			return Integer.toString(mode);
		}
		String head = field + " = " + mode;
		JsonArray layouts = boardMap.getAsJsonArray("layouts");
		for (JsonElement le : layouts) {
			JsonObject layout = le.getAsJsonObject();
			JsonObject when = layout.getAsJsonObject("when");
			if (when == null || !when.has(field) || when.get(field).getAsInt() != mode) {
				continue;
			}
			JsonArray windows = layout.getAsJsonArray("windows");
			if (windows == null || windows.isEmpty()) {
				break;
			}
			StringBuilder sb = new StringBuilder(head).append(": ");
			boolean first = true;
			for (JsonElement we : windows) {
				JsonObject w = we.getAsJsonObject();
				if (!first) {
					sb.append("; ");
				}
				first = false;
				sb.append('$').append(
					String.format("%04X", w.get("start").getAsLong())).append(" = ");
				sb.append(w.has("maps") && w.get("maps").isJsonObject()
						? w.getAsJsonObject("maps").get("expr").getAsString()
						: "?");
			}
			return sb.toString();
		}
		return head;
	}

	/**
	 * Decodes a packed bank state into {@code name=value} pairs in declaration order, e.g.
	 * {@code "select=0 prg_mode=1 r6=0 r7=1"}. Falls back to the decimal number when the board
	 * declares no state fields.
	 */
	static String initialStateText(JsonObject boardMap, long packed) {
		List<FieldSpec> fields = BoardStateFields.parseStateFields(boardMap);
		if (fields.isEmpty()) {
			return Long.toString(packed);
		}
		StringBuilder sb = new StringBuilder();
		for (FieldSpec f : fields) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(f.name()).append('=').append(f.valueIn(packed));
		}
		return sb.toString();
	}

	/**
	 * A SNES mapping in words: {@code "LoROM (FastROM)"}, with a note when the declared map type
	 * disagrees with where the header was found.
	 */
	static String snesMappingText(SnesRomHeader.MapType type, boolean fastRom,
			boolean matchesLocation, long headerOffset) {
		String name = switch (type) {
			case LOROM -> "LoROM";
			case HIROM -> "HiROM";
			case EXHIROM -> "ExHiROM";
			case UNKNOWN -> "unknown";
		};
		StringBuilder sb = new StringBuilder(name);
		sb.append(fastRom ? " (FastROM)" : " (SlowROM)");
		if (!matchesLocation) {
			sb.append("; header declares ").append(name).append(" but was found at $")
					.append(Long.toHexString(headerOffset)).append(", declared mapping used");
		}
		return sb.toString();
	}

	/** Records {@link DescriptorHints#LAYOUT_MODE_DISPLAY_PROPERTY}. */
	static void recordLayoutMode(Program program, JsonObject boardMap, int mode) {
		program.getOptions(Program.PROGRAM_INFO).setString(
			DescriptorHints.LAYOUT_MODE_DISPLAY_PROPERTY, layoutModeText(boardMap, mode));
	}

	/** Records {@link DescriptorHints#INITIAL_STATE_DISPLAY_PROPERTY}. */
	static void recordInitialState(Program program, JsonObject boardMap, long packed) {
		program.getOptions(Program.PROGRAM_INFO).setString(
			DescriptorHints.INITIAL_STATE_DISPLAY_PROPERTY, initialStateText(boardMap, packed));
	}
}
