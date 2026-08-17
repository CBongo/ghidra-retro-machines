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
package retromachines.vectors;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import retromachines.vectors.VectorCase.RamByte;

/**
 * Parses SingleStepTests-shaped vector JSON (bead grm-c9d.2) -- an array of cases, each
 * {@code {"name":..., "initial":{...,"ram":[[addr,val],...]}, "final":{...}, "cycles":[...]}}
 * -- into {@link VectorCase}s. Uses Ghidra's bundled gson ({@code com.google.gson}), already on
 * the test classpath (see {@code retromachines.DescriptorSupport} for the in-repo precedent);
 * no new dependency.
 *
 * <p>Schema-agnostic by construction: every scalar field of an {@code initial}/{@code final}
 * object other than {@code ram} is captured into the register map verbatim, under whatever name
 * the suite uses. {@code cycles} is read only far enough to skip over it -- see
 * {@link VectorCase} for why it carries no information this harness needs.
 */
public final class VectorParser {

	private VectorParser() {
	}

	/** Parses a whole vector file (a JSON array of cases) from a stream. Does not close it. */
	public static List<VectorCase> parse(InputStream in) throws IOException {
		try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			return parse(reader);
		}
	}

	/** Parses a whole vector file (a JSON array of cases) from a reader. Does not close it. */
	public static List<VectorCase> parse(Reader reader) {
		JsonElement root = JsonParser.parseReader(reader);
		return parseArray(root.getAsJsonArray());
	}

	/** Parses an already-loaded JSON array of cases. */
	public static List<VectorCase> parseArray(JsonArray array) {
		List<VectorCase> cases = new ArrayList<>(array.size());
		for (JsonElement e : array) {
			cases.add(parseCase(e.getAsJsonObject()));
		}
		return cases;
	}

	/** Parses one case object. */
	public static VectorCase parseCase(JsonObject obj) {
		String name = obj.has("name") ? obj.get("name").getAsString() : "<unnamed>";
		JsonObject initial = obj.getAsJsonObject("initial");
		JsonObject fin = obj.getAsJsonObject("final");
		return new VectorCase(name, parseRegs(initial), parseRam(initial), parseRegs(fin),
			parseRam(fin));
	}

	/** Every scalar field of {@code state} except {@code ram}, in declaration order. */
	private static Map<String, Integer> parseRegs(JsonObject state) {
		Map<String, Integer> regs = new LinkedHashMap<>();
		for (Map.Entry<String, JsonElement> entry : state.entrySet()) {
			String key = entry.getKey();
			if (key.equals("ram")) {
				continue;
			}
			JsonElement value = entry.getValue();
			if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
				regs.put(key, value.getAsInt());
			}
			// Non-numeric scalar fields (none known today) are silently skipped: this parser's
			// job is the register/ram shape, not validating every field a future suite adds.
		}
		return regs;
	}

	/** The {@code ram: [[addr,val], ...]} sparse list, or empty if the state has none. */
	private static List<RamByte> parseRam(JsonObject state) {
		if (!state.has("ram")) {
			return List.of();
		}
		JsonArray ram = state.getAsJsonArray("ram");
		List<RamByte> out = new ArrayList<>(ram.size());
		for (JsonElement e : ram) {
			JsonArray pair = e.getAsJsonArray();
			out.add(new RamByte(pair.get(0).getAsInt(), pair.get(1).getAsInt()));
		}
		return out;
	}
}
