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
package gdtbuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Standalone build-time tool: reads a machine descriptor YAML (see docs/SCHEMA.md and
 * machines/c64.yaml) and emits a runtime "map" file — a JSON document describing memory
 * regions, banked windows, banking state machine, ROM image slots, and inline symbol
 * sets — for the shipped extension's loader to consume directly, with no YAML parser in
 * the runtime.
 * <p>
 * JSON is used (rather than re-shipping the YAML) because Ghidra already bundles gson
 * ({@code Ghidra/Framework/Generic/lib/gson-2.13.2.jar}), so the runtime loader can parse
 * this file with zero new dependencies. This class itself never touches Ghidra runtime
 * classes (no {@code Application.initializeApplication}) — unlike {@link GdtBuilder},
 * which must bootstrap Ghidra to construct {@code DataType}s, MapCompiler only needs
 * snakeyaml (to read the descriptor) and gson (to write the map), both already on the
 * build-only {@code gdtBuilder} source set's classpath.
 * <p>
 * This class is NEVER shipped with the extension — it runs only as part of the Gradle
 * build (see the {@code buildC64Map} / {@code buildMap} tasks in build.gradle). See
 * docs/MAP_FORMAT.md for the frozen JSON schema this tool produces.
 * <p>
 * Usage: {@code MapCompiler <descriptor.yaml> <output.map>}
 */
public class MapCompiler {

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: MapCompiler <descriptor.yaml> <output.map>");
			System.exit(1);
		}
		File descriptorFile = new File(args[0]).getCanonicalFile();
		File outputMap = new File(args[1]).getCanonicalFile();

		Map<String, Object> descriptor = loadYaml(descriptorFile);

		Map<String, Object> mapDoc = new LinkedHashMap<>();
		mapDoc.put("system", buildSystem(descriptor));
		mapDoc.put("regions", buildRegions(descriptor));
		mapDoc.put("windows", buildWindows(descriptor));
		mapDoc.put("banking", buildBanking(descriptor));
		mapDoc.put("rom_images", buildRomImages(descriptor));
		mapDoc.put("symbols", buildSymbols(descriptor));

		outputMap.getParentFile().mkdirs();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new FileWriter(outputMap)) {
			gson.toJson(mapDoc, w);
		}

		System.err.println(
			"Wrote map to " + outputMap.getAbsolutePath() + " (" + outputMap.length() + " bytes)");
	}

	// ---- system ----

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildSystem(Map<String, Object> descriptor) {
		Map<String, Object> system = (Map<String, Object>) descriptor.get("system");
		if (system == null) {
			throw new IllegalArgumentException("descriptor is missing top-level 'system:' section");
		}
		Map<String, Object> cpu = (Map<String, Object>) system.get("cpu");
		if (cpu == null) {
			throw new IllegalArgumentException("descriptor 'system:' is missing 'cpu:' section");
		}
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("id", requireString(system, "id", "system"));
		out.put("name", requireString(system, "name", "system"));
		out.put("language", requireString(cpu, "language", "system.cpu"));
		return out;
	}

	// ---- regions ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildRegions(Map<String, Object> descriptor) {
		Map<String, Object> memory = (Map<String, Object>) descriptor.get("memory");
		if (memory == null) {
			throw new IllegalArgumentException("descriptor is missing top-level 'memory:' section");
		}
		List<Map<String, Object>> regions = (List<Map<String, Object>>) memory.get("regions");
		if (regions == null) {
			throw new IllegalArgumentException("descriptor 'memory:' is missing 'regions:' list");
		}
		List<Map<String, Object>> out = new ArrayList<>();
		for (Map<String, Object> region : regions) {
			Map<String, Object> r = new LinkedHashMap<>();
			r.put("name", requireString(region, "name", "memory.regions[]"));
			r.put("start", requireAddr(region, "start", "memory.regions[]"));
			r.put("end", requireAddr(region, "end", "memory.regions[]"));
			r.put("kind", requireString(region, "kind", "memory.regions[]"));
			copyIfPresent(region, r, "type");
			copyIfPresent(region, r, "comment");
			copyIfPresent(region, r, "readable");
			copyIfPresent(region, r, "writable");
			copyIfPresent(region, r, "executable");
			out.add(r);
		}
		return out;
	}

	// ---- windows ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildWindows(Map<String, Object> descriptor) {
		Map<String, Object> memory = (Map<String, Object>) descriptor.get("memory");
		if (memory == null) {
			throw new IllegalArgumentException("descriptor is missing top-level 'memory:' section");
		}
		List<Map<String, Object>> windows = (List<Map<String, Object>>) memory.get("windows");
		if (windows == null) {
			throw new IllegalArgumentException("descriptor 'memory:' is missing 'windows:' list");
		}
		List<Map<String, Object>> out = new ArrayList<>();
		for (Map<String, Object> window : windows) {
			Map<String, Object> w = new LinkedHashMap<>();
			w.put("name", requireString(window, "name", "memory.windows[]"));
			w.put("start", requireAddr(window, "start", "memory.windows[]"));
			w.put("end", requireAddr(window, "end", "memory.windows[]"));

			List<Map<String, Object>> occupants = (List<Map<String, Object>>) window.get("occupants");
			if (occupants == null) {
				throw new IllegalArgumentException(
					"window '" + w.get("name") + "' is missing 'occupants:' list");
			}
			List<Map<String, Object>> occupantsOut = new ArrayList<>();
			for (Map<String, Object> occupant : occupants) {
				occupantsOut.add(buildOccupant(occupant));
			}
			w.put("occupants", occupantsOut);
			out.add(w);
		}
		return out;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildOccupant(Map<String, Object> occupant) {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("name", requireString(occupant, "name", "window occupant"));
		o.put("kind", requireString(occupant, "kind", "window occupant"));
		copyIfPresent(occupant, o, "image");
		copyIfPresent(occupant, o, "on_write");
		copyIfPresent(occupant, o, "readable");
		copyIfPresent(occupant, o, "writable");
		copyIfPresent(occupant, o, "executable");

		List<Map<String, Object>> subregions =
			(List<Map<String, Object>>) occupant.get("subregions");
		if (subregions != null) {
			List<Map<String, Object>> subOut = new ArrayList<>();
			for (Map<String, Object> sub : subregions) {
				subOut.add(buildSubregion(sub));
			}
			o.put("subregions", subOut);
		}
		return o;
	}

	private static Map<String, Object> buildSubregion(Map<String, Object> sub) {
		Map<String, Object> s = new LinkedHashMap<>();
		s.put("name", requireString(sub, "name", "subregion"));
		s.put("start", requireAddr(sub, "start", "subregion"));
		copyAddrIfPresent(sub, s, "end");
		copyAddrIfPresent(sub, s, "size");
		copyAddrIfPresent(sub, s, "repeat_to");
		copyIfPresent(sub, s, "kind");
		copyIfPresent(sub, s, "type");
		copyIfPresent(sub, s, "comment");
		copyIfPresent(sub, s, "readable");
		copyIfPresent(sub, s, "writable");
		copyIfPresent(sub, s, "executable");
		return s;
	}

	// ---- banking ----

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildBanking(Map<String, Object> descriptor) {
		Map<String, Object> banking = (Map<String, Object>) descriptor.get("banking");
		if (banking == null) {
			throw new IllegalArgumentException("descriptor is missing top-level 'banking:' section");
		}
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("initial_state", requireAddr(banking, "initial_state", "banking"));
		out.put("context_register", requireString(banking, "context_register", "banking"));

		List<Object> stateBits = (List<Object>) banking.get("state_bits");
		if (stateBits == null) {
			throw new IllegalArgumentException("banking is missing 'state_bits:' list");
		}
		out.put("state_bits", new ArrayList<>(stateBits));

		List<Map<String, Object>> states = (List<Map<String, Object>>) banking.get("states");
		if (states == null) {
			throw new IllegalArgumentException("banking is missing 'states:' list");
		}
		List<Map<String, Object>> statesOut = new ArrayList<>();
		for (Map<String, Object> state : states) {
			Map<String, Object> s = new LinkedHashMap<>();
			for (Map.Entry<String, Object> entry : state.entrySet()) {
				if ("value".equals(entry.getKey())) {
					s.put("value", toInt(entry.getValue()));
				}
				else {
					// window-name -> occupant-name mapping; pass through as-is (strings)
					s.put(entry.getKey(), entry.getValue());
				}
			}
			statesOut.add(s);
		}
		out.put("states", statesOut);
		return out;
	}

	// ---- rom_images ----

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildRomImages(Map<String, Object> descriptor) {
		Map<String, Object> romImages = (Map<String, Object>) descriptor.get("rom_images");
		Map<String, Object> out = new LinkedHashMap<>();
		if (romImages == null) {
			return out;
		}
		for (Map.Entry<String, Object> entry : romImages.entrySet()) {
			Map<String, Object> img = (Map<String, Object>) entry.getValue();
			Map<String, Object> i = new LinkedHashMap<>();
			i.put("size", requireAddr(img, "size", "rom_images." + entry.getKey()));
			i.put("occupant", requireString(img, "occupant", "rom_images." + entry.getKey()));
			out.put(entry.getKey(), i);
		}
		return out;
	}

	// ---- symbols ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildSymbols(Map<String, Object> descriptor) {
		List<Map<String, Object>> symbols = (List<Map<String, Object>>) descriptor.get("symbols");
		List<Map<String, Object>> out = new ArrayList<>();
		if (symbols == null) {
			return out;
		}
		for (Map<String, Object> set : symbols) {
			Map<String, Object> s = new LinkedHashMap<>();
			s.put("set", requireString(set, "set", "symbols[]"));
			s.put("default", parseDefault(set));
			copyIfPresent(set, s, "region");

			List<Map<String, Object>> inline = (List<Map<String, Object>>) set.get("inline");
			List<Map<String, Object>> entriesOut = new ArrayList<>();
			if (inline != null) {
				for (Map<String, Object> entry : inline) {
					Map<String, Object> e = new LinkedHashMap<>();
					e.put("addr", requireAddr(entry, "addr", "symbols entry"));
					e.put("name", requireString(entry, "name", "symbols entry"));
					e.put("kind", requireString(entry, "kind", "symbols entry"));
					copyIfPresent(entry, e, "comment");
					entriesOut.add(e);
				}
			}
			s.put("entries", entriesOut);
			out.add(s);
		}
		return out;
	}

	private static boolean parseDefault(Map<String, Object> set) {
		Object def = set.get("default");
		if (def == null) {
			throw new IllegalArgumentException(
				"symbols set '" + set.get("set") + "' is missing 'default:'");
		}
		if (def instanceof Boolean) {
			return (Boolean) def;
		}
		String s = def.toString().trim().toLowerCase();
		if ("on".equals(s) || "true".equals(s)) {
			return true;
		}
		if ("off".equals(s) || "false".equals(s)) {
			return false;
		}
		throw new IllegalArgumentException(
			"symbols set '" + set.get("set") + "' has unrecognized default: " + def);
	}

	// ---- helpers ----

	private static void copyIfPresent(Map<String, Object> src, Map<String, Object> dst, String key) {
		if (src.containsKey(key) && src.get(key) != null) {
			dst.put(key, src.get(key));
		}
	}

	/** Like copyIfPresent, but converts YAML hex/numeric values to plain ints. */
	private static void copyAddrIfPresent(Map<String, Object> src, Map<String, Object> dst,
			String key) {
		if (src.containsKey(key) && src.get(key) != null) {
			dst.put(key, toInt(src.get(key)));
		}
	}

	private static String requireString(Map<String, Object> map, String key, String context) {
		Object v = map.get(key);
		if (v == null) {
			throw new IllegalArgumentException(context + " is missing required '" + key + ":'");
		}
		return v.toString();
	}

	private static int requireAddr(Map<String, Object> map, String key, String context) {
		Object v = map.get(key);
		if (v == null) {
			throw new IllegalArgumentException(context + " is missing required '" + key + ":'");
		}
		return toInt(v);
	}

	/** snakeyaml parses "0xA000"-style scalars as Integer/Long already; this just normalizes. */
	private static int toInt(Object o) {
		if (o instanceof Number) {
			return ((Number) o).intValue();
		}
		String s = o.toString().trim();
		if (s.toLowerCase().startsWith("0x")) {
			return Integer.parseInt(s.substring(2), 16);
		}
		return Integer.parseInt(s);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> loadYaml(File file) throws IOException {
		try (InputStream in = new FileInputStream(file)) {
			Yaml yaml = new Yaml();
			Object loaded = yaml.load(in);
			if (loaded == null) {
				return new LinkedHashMap<>();
			}
			return (Map<String, Object>) loaded;
		}
	}
}
