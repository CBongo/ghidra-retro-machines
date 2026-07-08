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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Builds descriptor <b>schema 2</b> (docs/SCHEMA.md): the bank state is a named tuple of
 * fields ({@code banking.state}), bank-switch mechanisms are a list of strategy instances
 * ({@code banking.mechanisms}), banked content may live in physical backing spaces
 * ({@code physical:}) that windows map into via a tiny validated expression language
 * ({@code maps: PRG[bank * 0x4000]}), and window sets may be mode-dependent
 * ({@code memory.layouts}). Enumerated occupants + truth-table states (C64 style) remain
 * first-class alongside the computed forms.
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

	/** Expression keywords usable in {@code maps:} alongside state-field names. */
	private static final Set<String> EXPR_KEYWORDS =
		Set.of("last", "second_last", "offset");

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: MapCompiler <descriptor.yaml> <output.map>");
			System.exit(1);
		}
		File descriptorFile = new File(args[0]).getCanonicalFile();
		File outputMap = new File(args[1]).getCanonicalFile();

		Map<String, Object> descriptor = loadYaml(descriptorFile);

		int schemaVersion = requireAddr(descriptor, "schema", "descriptor");
		if (schemaVersion != 2) {
			throw new IllegalArgumentException("unsupported 'schema: " + schemaVersion +
				"' — this MapCompiler builds descriptor schema 2 (see docs/SCHEMA.md)");
		}

		// Cross-section context: windows/layouts/banking validate against each other
		// (maps: expressions reference physical spaces and state fields; states rows
		// reference windows and state fields).
		List<Map<String, Object>> physical = getPhysical(descriptor);
		Set<String> physicalNames = new LinkedHashSet<>();
		if (physical != null) {
			for (Map<String, Object> space : physical) {
				physicalNames.add(requireString(space, "name", "physical[]"));
			}
		}
		LinkedHashMap<String, Integer> stateFields = parseStateFields(descriptor);

		Map<String, Object> mapDoc = new LinkedHashMap<>();
		mapDoc.put("system", buildSystem(descriptor));
		if (physical != null) {
			mapDoc.put("physical", buildPhysical(physical));
		}
		mapDoc.put("regions", buildRegions(descriptor));
		List<Map<String, Object>> windows =
			buildWindows(descriptor, physicalNames, stateFields.keySet());
		mapDoc.put("windows", windows);
		List<Map<String, Object>> layouts =
			buildLayouts(descriptor, physicalNames, stateFields.keySet());
		if (layouts != null) {
			mapDoc.put("layouts", layouts);
		}
		Map<String, Object> banking =
			buildBanking(descriptor, stateFields, enumeratedWindowNames(windows));
		if (banking != null) {
			mapDoc.put("banking", banking);
		}
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

	// ---- physical spaces ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> getPhysical(Map<String, Object> descriptor) {
		return (List<Map<String, Object>>) descriptor.get("physical");
	}

	private static List<Map<String, Object>> buildPhysical(List<Map<String, Object>> physical) {
		List<Map<String, Object>> out = new ArrayList<>();
		for (Map<String, Object> space : physical) {
			Map<String, Object> p = new LinkedHashMap<>();
			p.put("name", requireString(space, "name", "physical[]"));
			copyIfPresent(space, p, "image");
			copyAddrIfPresent(space, p, "size");
			copyIfPresent(space, p, "comment");
			out.add(p);
		}
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

	// ---- windows (enumerated occupants OR computed maps:) ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildWindows(Map<String, Object> descriptor,
			Set<String> physicalNames, Set<String> stateFields) {
		Map<String, Object> memory = (Map<String, Object>) descriptor.get("memory");
		if (memory == null) {
			throw new IllegalArgumentException("descriptor is missing top-level 'memory:' section");
		}
		List<Map<String, Object>> windows = (List<Map<String, Object>>) memory.get("windows");
		if (windows == null) {
			throw new IllegalArgumentException("descriptor 'memory:' is missing 'windows:' list");
		}
		return buildWindowList(windows, physicalNames, stateFields, "memory.windows");
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildWindowList(List<Map<String, Object>> windows,
			Set<String> physicalNames, Set<String> stateFields, String context) {
		List<Map<String, Object>> out = new ArrayList<>();
		for (Map<String, Object> window : windows) {
			Map<String, Object> w = new LinkedHashMap<>();
			String name = requireString(window, "name", context + "[]");
			String windowContext = context + " '" + name + "'";
			w.put("name", name);
			int start = requireAddr(window, "start", windowContext);
			w.put("start", start);
			// end: explicit, or derived from size (schema v2 allows either)
			if (window.containsKey("end")) {
				w.put("end", requireAddr(window, "end", windowContext));
			}
			else if (window.containsKey("size")) {
				w.put("end", start + toInt(window.get("size")) - 1);
			}
			else {
				throw new IllegalArgumentException(
					windowContext + " needs either 'end:' or 'size:'");
			}

			List<Map<String, Object>> occupants =
				(List<Map<String, Object>>) window.get("occupants");
			Object maps = window.get("maps");
			if ((occupants == null) == (maps == null)) {
				throw new IllegalArgumentException(windowContext +
					" must have exactly one of 'occupants:' (enumerated) or 'maps:' (computed)");
			}
			if (occupants != null) {
				List<Map<String, Object>> occupantsOut = new ArrayList<>();
				for (Map<String, Object> occupant : occupants) {
					occupantsOut.add(buildOccupant(occupant));
				}
				w.put("occupants", occupantsOut);
			}
			else {
				w.put("maps",
					parseMapsExpr(maps.toString(), physicalNames, stateFields, windowContext));
				// computed windows have no occupant to hang on_write on; window-level
				// on_write (typically 'mechanism' — stores into mapped ROM are
				// bank-switch events, not memory writes)
				copyIfPresent(window, w, "on_write");
			}
			out.add(w);
		}
		return out;
	}

	/** Names of windows carrying enumerated {@code occupants:} (the ones a
	 * {@code banking.states} truth table must assign). */
	private static Set<String> enumeratedWindowNames(List<Map<String, Object>> windows) {
		Set<String> names = new LinkedHashSet<>();
		for (Map<String, Object> w : windows) {
			if (w.containsKey("occupants")) {
				names.add((String) w.get("name"));
			}
		}
		return names;
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

	// ---- mode-dependent layouts ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildLayouts(Map<String, Object> descriptor,
			Set<String> physicalNames, Set<String> stateFields) {
		Map<String, Object> memory = (Map<String, Object>) descriptor.get("memory");
		List<Map<String, Object>> layouts =
			memory == null ? null : (List<Map<String, Object>>) memory.get("layouts");
		if (layouts == null) {
			return null;
		}
		List<Map<String, Object>> out = new ArrayList<>();
		for (Map<String, Object> layout : layouts) {
			Map<String, Object> l = new LinkedHashMap<>();
			Map<String, Object> when = (Map<String, Object>) layout.get("when");
			if (when == null || when.isEmpty()) {
				throw new IllegalArgumentException("memory.layouts[] entry is missing 'when:'");
			}
			Map<String, Object> whenOut = new LinkedHashMap<>();
			for (Map.Entry<String, Object> cond : when.entrySet()) {
				if (!stateFields.contains(cond.getKey())) {
					throw new IllegalArgumentException("memory.layouts[].when references '" +
						cond.getKey() + "', which is not a banking.state field");
				}
				whenOut.put(cond.getKey(), toInt(cond.getValue()));
			}
			l.put("when", whenOut);
			List<Map<String, Object>> windows =
				(List<Map<String, Object>>) layout.get("windows");
			if (windows == null) {
				throw new IllegalArgumentException("memory.layouts[] entry is missing 'windows:'");
			}
			l.put("windows",
				buildWindowList(windows, physicalNames, stateFields, "memory.layouts[].windows"));
			out.add(l);
		}
		return out;
	}

	// ---- maps: expression mini-language ----

	private static final Pattern MAPS_SHAPE =
		Pattern.compile("^\\s*([A-Za-z_]\\w*)\\s*\\[(.+)]\\s*$");
	private static final Pattern EXPR_TOKEN =
		Pattern.compile("\\G\\s*(0[xX][0-9a-fA-F]+|\\d+|[A-Za-z_]\\w*|[-+*()])");

	/**
	 * Validates a computed-window expression like {@code PRG[bank * 0x4000]} and returns
	 * its structured form {@code {space, expr}}. The grammar is deliberately tiny
	 * (vision doc §5.3): integers, declared state-field names, the keywords
	 * {@code last}/{@code second_last}/{@code offset}, {@code + - *}, and parentheses.
	 * The expression is validated here but kept as a string in the .map; runtime
	 * evaluation is the bank engine's job (M2+).
	 */
	private static Map<String, Object> parseMapsExpr(String maps, Set<String> physicalNames,
			Set<String> stateFields, String context) {
		Matcher shape = MAPS_SHAPE.matcher(maps);
		if (!shape.matches()) {
			throw new IllegalArgumentException(
				context + " maps: '" + maps + "' is not of the form SPACE[expr]");
		}
		String space = shape.group(1);
		String expr = shape.group(2).trim();
		if (!physicalNames.contains(space)) {
			throw new IllegalArgumentException(context + " maps: references physical space '" +
				space + "', which is not declared in 'physical:'");
		}

		Matcher tok = EXPR_TOKEN.matcher(expr);
		int pos = 0;
		int depth = 0;
		boolean expectOperand = true;
		while (pos < expr.length()) {
			if (!tok.find(pos)) {
				throw new IllegalArgumentException(context + " maps: unrecognized token at '" +
					expr.substring(pos).trim() + "' in expression '" + expr + "'");
			}
			String t = tok.group(1);
			pos = tok.end();
			if ("(".equals(t)) {
				expectSyntax(expectOperand, context, expr);
				depth++;
			}
			else if (")".equals(t)) {
				expectSyntax(!expectOperand && depth > 0, context, expr);
				depth--;
			}
			else if (t.length() == 1 && "+-*".contains(t)) {
				expectSyntax(!expectOperand, context, expr);
				expectOperand = true;
			}
			else {
				expectSyntax(expectOperand, context, expr);
				boolean isNumber = Character.isDigit(t.charAt(0));
				if (!isNumber && !stateFields.contains(t) && !EXPR_KEYWORDS.contains(t)) {
					throw new IllegalArgumentException(context + " maps: identifier '" + t +
						"' is neither a banking.state field nor one of " + EXPR_KEYWORDS);
				}
				expectOperand = false;
			}
		}
		expectSyntax(!expectOperand && depth == 0, context, expr);

		Map<String, Object> out = new LinkedHashMap<>();
		out.put("space", space);
		out.put("expr", expr);
		return out;
	}

	private static void expectSyntax(boolean ok, String context, String expr) {
		if (!ok) {
			throw new IllegalArgumentException(
				context + " maps: malformed expression '" + expr + "'");
		}
	}

	// ---- banking ----

	/**
	 * Parses {@code banking.state} — the ordered named tuple of bank-state fields
	 * (schema v2; replaces v1's flat {@code state_bits}). The first field occupies the
	 * least-significant bits of the packed state value, each subsequent field the bits
	 * above it. Returns an ordered name→width map (empty when the descriptor has no
	 * banking section).
	 */
	@SuppressWarnings("unchecked")
	private static LinkedHashMap<String, Integer> parseStateFields(
			Map<String, Object> descriptor) {
		LinkedHashMap<String, Integer> fields = new LinkedHashMap<>();
		Map<String, Object> banking = (Map<String, Object>) descriptor.get("banking");
		if (banking == null) {
			return fields;
		}
		List<Map<String, Object>> state = (List<Map<String, Object>>) banking.get("state");
		if (state == null) {
			throw new IllegalArgumentException("banking is missing 'state:' field-tuple list");
		}
		for (Map<String, Object> field : state) {
			String name = requireString(field, "name", "banking.state[]");
			int bits = requireAddr(field, "bits", "banking.state '" + name + "'");
			if (bits < 1 || bits > 31) {
				throw new IllegalArgumentException(
					"banking.state '" + name + "' has invalid bits: " + bits);
			}
			if (fields.put(name, bits) != null) {
				throw new IllegalArgumentException("banking.state field '" + name + "' declared twice");
			}
		}
		return fields;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildBanking(Map<String, Object> descriptor,
			LinkedHashMap<String, Integer> stateFields, Set<String> enumeratedWindows) {
		Map<String, Object> banking = (Map<String, Object>) descriptor.get("banking");
		if (banking == null) {
			// banking is optional in schema v2 (e.g. NROM has none) — but enumerated
			// windows are meaningless without a states table to pick occupants
			if (!enumeratedWindows.isEmpty()) {
				throw new IllegalArgumentException("windows with 'occupants:' (" +
					enumeratedWindows + ") require a 'banking:' section with a states table");
			}
			return null;
		}
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("initial_state",
			packState(banking.get("initial_state"), stateFields, "banking.initial_state"));
		out.put("context_register", requireString(banking, "context_register", "banking"));

		// state tuple (already validated by parseStateFields)
		List<Map<String, Object>> stateOut = new ArrayList<>();
		for (Map.Entry<String, Integer> field : stateFields.entrySet()) {
			Map<String, Object> f = new LinkedHashMap<>();
			f.put("name", field.getKey());
			f.put("bits", field.getValue());
			stateOut.add(f);
		}
		out.put("state", stateOut);

		// mechanisms: list of strategy instances
		List<Map<String, Object>> mechanisms =
			(List<Map<String, Object>>) banking.get("mechanisms");
		if (mechanisms == null || mechanisms.isEmpty()) {
			throw new IllegalArgumentException("banking is missing 'mechanisms:' list");
		}
		List<Map<String, Object>> mechanismsOut = new ArrayList<>();
		for (Map<String, Object> mechanism : mechanisms) {
			Map<String, Object> m = new LinkedHashMap<>();
			String strategy = requireString(mechanism, "strategy", "banking.mechanisms[]");
			m.put("strategy", strategy);
			Map<String, Object> params = (Map<String, Object>) mechanism.get("params");
			if (params == null) {
				throw new IllegalArgumentException(
					"banking.mechanisms[] '" + strategy + "' is missing 'params:'");
			}
			// params are strategy-specific: passed through opaquely (numbers normalized),
			// interpreted by the matching strategy class at analysis time
			m.put("params", normalizeValues(params));
			List<Object> sets = (List<Object>) mechanism.get("sets");
			if (sets == null || sets.isEmpty()) {
				throw new IllegalArgumentException("banking.mechanisms[] '" + strategy +
					"' is missing 'sets:' (the state fields it feeds)");
			}
			for (Object field : sets) {
				if (!stateFields.containsKey(field.toString())) {
					throw new IllegalArgumentException("banking.mechanisms[] '" + strategy +
						"' sets '" + field + "', which is not a banking.state field");
				}
			}
			m.put("sets", new ArrayList<>(sets));
			mechanismsOut.add(m);
		}
		out.put("mechanisms", mechanismsOut);

		// states: enumerated truth table, rows keyed by state-field values + window names.
		// The packed row value is computed from the field values (field order = bit order).
		List<Map<String, Object>> states = (List<Map<String, Object>>) banking.get("states");
		if (states == null) {
			if (!enumeratedWindows.isEmpty()) {
				throw new IllegalArgumentException("windows with 'occupants:' (" +
					enumeratedWindows + ") require a 'banking.states:' truth table");
			}
			return out;
		}
		List<Map<String, Object>> statesOut = new ArrayList<>();
		for (Map<String, Object> state : states) {
			Map<String, Object> fieldValues = new LinkedHashMap<>();
			Map<String, Object> s = new LinkedHashMap<>();
			s.put("value", null); // placeholder: keep "value" first, fill after the split
			for (Map.Entry<String, Object> entry : state.entrySet()) {
				String key = entry.getKey();
				if (stateFields.containsKey(key)) {
					fieldValues.put(key, entry.getValue());
				}
				else if (enumeratedWindows.contains(key)) {
					// window-name -> occupant-name mapping; pass through as-is (strings)
					s.put(key, entry.getValue());
				}
				else {
					throw new IllegalArgumentException("banking.states row key '" + key +
						"' is neither a banking.state field nor an enumerated window");
				}
			}
			s.put("value", packState(fieldValues, stateFields, "banking.states row"));
			for (String window : enumeratedWindows) {
				if (!s.containsKey(window)) {
					throw new IllegalArgumentException("banking.states row (value " +
						s.get("value") + ") does not assign window '" + window + "'");
				}
			}
			statesOut.add(s);
		}
		out.put("states", statesOut);
		return out;
	}

	/**
	 * Packs a bank-state expression into the flat integer the runtime consumes. Accepts
	 * either an already-packed integer or a per-field map ({@code {LORAM: 1, HIRAM: 1,
	 * CHAREN: 1}}); the map form must assign every declared field, and each value must
	 * fit the field's declared width.
	 */
	@SuppressWarnings("unchecked")
	private static int packState(Object value, LinkedHashMap<String, Integer> stateFields,
			String context) {
		if (value == null) {
			throw new IllegalArgumentException(context + " is missing");
		}
		if (!(value instanceof Map)) {
			return toInt(value);
		}
		Map<String, Object> fieldValues = (Map<String, Object>) value;
		int packed = 0;
		int shift = 0;
		for (Map.Entry<String, Integer> field : stateFields.entrySet()) {
			Object v = fieldValues.get(field.getKey());
			if (v == null) {
				throw new IllegalArgumentException(
					context + " does not assign state field '" + field.getKey() + "'");
			}
			int fieldValue = toInt(v);
			int bits = field.getValue();
			if (fieldValue < 0 || fieldValue >= (1 << bits)) {
				throw new IllegalArgumentException(context + " value " + fieldValue +
					" does not fit state field '" + field.getKey() + "' (" + bits + " bits)");
			}
			packed |= fieldValue << shift;
			shift += bits;
		}
		for (String key : fieldValues.keySet()) {
			if (!stateFields.containsKey(key)) {
				throw new IllegalArgumentException(
					context + " assigns unknown state field '" + key + "'");
			}
		}
		return packed;
	}

	/**
	 * Deep-copies a strategy-specific params tree, normalizing every {@link Number} to a
	 * plain int (snakeyaml already parses {@code 0x}-style scalars numerically) and every
	 * map key to a string (YAML allows integer keys, e.g. select-data target tables).
	 * Strings and booleans pass through untouched.
	 */
	@SuppressWarnings("unchecked")
	private static Object normalizeValues(Object value) {
		if (value instanceof Map) {
			Map<String, Object> out = new LinkedHashMap<>();
			for (Map.Entry<Object, Object> entry : ((Map<Object, Object>) value).entrySet()) {
				out.put(String.valueOf(entry.getKey()), normalizeValues(entry.getValue()));
			}
			return out;
		}
		if (value instanceof List) {
			List<Object> out = new ArrayList<>();
			for (Object item : (List<Object>) value) {
				out.add(normalizeValues(item));
			}
			return out;
		}
		if (value instanceof Number) {
			return ((Number) value).intValue();
		}
		return value;
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
