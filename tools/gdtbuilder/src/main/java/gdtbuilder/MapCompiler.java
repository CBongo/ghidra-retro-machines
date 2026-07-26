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
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

	/**
	 * Expression keywords usable in {@code maps:} alongside state-field names. Kept in lockstep
	 * with the runtime evaluator ({@code DescriptorSupport.ExprParser}): a keyword the compiler
	 * accepts but the runtime cannot resolve produces a descriptor that compiles clean yet fails
	 * to place its window at load time.
	 */
	private static final Set<String> EXPR_KEYWORDS =
		Set.of("last", "second_last");

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: MapCompiler <descriptor.yaml> <output.map>");
			System.exit(1);
		}
		File descriptorFile = new File(args[0]).getCanonicalFile();
		File outputMap = new File(args[1]).getCanonicalFile();

		Map<String, Object> descriptor = YamlSupport.loadComposed(descriptorFile);

		int schemaVersion = requireAddr(descriptor, "schema", "descriptor");
		if (schemaVersion != 2) {
			throw new IllegalArgumentException("unsupported 'schema: " + schemaVersion +
				"' — this MapCompiler builds descriptor schema 2 (see docs/SCHEMA.md)");
		}

		// Cross-section context: windows/layouts/banking validate against each other
		// (maps: expressions reference physical spaces and state fields; states rows
		// reference windows and state fields).
		List<Map<String, Object>> physical = getPhysical(descriptor);
		validateUniqueNames(physical, "name", "physical[] name");
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
		// Windows and layouts are built before regions purely so that a region's
		// copied_from source name can be resolved against the window occupants (a boot copy's
		// source is normally a banked ROM occupant such as the C64's KERNAL, not a region).
		// mapDoc's key order is unchanged -- the puts below still run regions-then-windows.
		List<Map<String, Object>> windows =
			buildWindows(descriptor, physicalNames, stateFields.keySet());
		List<Map<String, Object>> layouts =
			buildLayouts(descriptor, physicalNames, stateFields.keySet());
		List<Map<String, Object>> regions = buildRegions(descriptor);
		validateUniqueNames(regions, "name", "memory.regions[] name");
		validateCopiedFromSources(regions, windows, layouts);
		mapDoc.put("regions", regions);
		mapDoc.put("windows", windows);
		if (usesLoadAddressPlacement(descriptor)) {
			validateRamCoverage(regions, windows);
		}
		if (layouts != null) {
			mapDoc.put("layouts", layouts);
		}
		Map<String, Object> banking =
			buildBanking(descriptor, stateFields, enumeratedWindowNames(windows));
		if (banking != null) {
			mapDoc.put("banking", banking);
		}
		mapDoc.put("rom_images", buildRomImages(descriptor, regions));
		List<Map<String, Object>> symbols =
			buildSymbols(descriptor, descriptorFile.getParentFile());
		validateUniqueNames(symbols, "set", "symbols[] set");
		mapDoc.put("symbols", symbols);
		Map<String, Object> formats = buildFormats(descriptor);
		if (formats != null) {
			mapDoc.put("formats", formats);
		}

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
		// board registry keys (e.g. which iNES mapper numbers this board descriptor
		// serves) — how a container loader picks a descriptor without hardcoding it
		Map<String, Object> board = (Map<String, Object>) system.get("board");
		if (board != null) {
			Map<String, Object> b = new LinkedHashMap<>();
			List<Object> mappers = (List<Object>) board.get("ines_mappers");
			if (mappers != null) {
				List<Object> normalized = new ArrayList<>();
				for (Object mapper : mappers) {
					normalized.add(toInt(mapper));
				}
				b.put("ines_mappers", normalized);
			}
			if (!b.isEmpty()) {
				out.put("board", b);
			}
		}
		// Text/string-search policy (bead grm-1.4 Phase E): system-wide default text
		// encoding, e.g. { encoding: petscii, variant: unshifted_graphics, string_search:
		// { min_length: 4 } }. Passed through verbatim (numeric scalars normalized to
		// ints, same as params/formats elsewhere) -- PetsciiStringAnalyzer interprets the
		// keys, MapCompiler only shuttles them.
		Map<String, Object> text = (Map<String, Object>) system.get("text");
		if (text != null) {
			out.put("text", normalizeValues(text));
		}
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
		String loadTargetName = null;
		for (Map<String, Object> region : regions) {
			Map<String, Object> r = new LinkedHashMap<>();
			String name = requireString(region, "name", "memory.regions[]");
			r.put("name", name);
			int start = requireAddr(region, "start", "memory.regions[]");
			int end = requireAddr(region, "end", "memory.regions[]");
			r.put("start", start);
			r.put("end", end);
			r.put("kind", requireString(region, "kind", "memory.regions[]"));
			List<Map<String, Object>> copiedFrom = buildCopiedFrom(region, name, start, end);
			if (copiedFrom != null) {
				r.put("copied_from", copiedFrom);
			}
			copyIfPresent(region, r, "type");
			copyIfPresent(region, r, "image");
			copyIfPresent(region, r, "comment");
			copyIfPresent(region, r, "readable");
			copyIfPresent(region, r, "writable");
			copyIfPresent(region, r, "executable");
			copyIfPresent(region, r, "load_target");
			copyIfPresent(region, r, "prg_placeable");
			if (Boolean.TRUE.equals(region.get("load_target"))) {
				if (loadTargetName != null) {
					throw new IllegalArgumentException(
						"descriptor 'memory.regions[]' declares 'load_target: true' on both '" +
							loadTargetName + "' and '" + name +
							"'; at most one region may be the load target");
				}
				loadTargetName = name;
			}
			out.add(r);
		}
		return out;
	}

	// ---- boot-copy hints (copied_from, grm-1.7.1.2) ----

	/**
	 * Builds a destination region's {@code copied_from[]} boot-copy hints -- "this sub-range of
	 * me is a verbatim copy of bytes that live over there" (docs/SCHEMA.md, grm-1.7.1.2). The
	 * canonical case is the C64 KERNAL copying CHRGET from ROM {@code $E3A2} into zero page
	 * {@code $0073} at init, which is invisible statically because the destination is
	 * uninitialized RAM.
	 * <p>
	 * Every address key goes through {@link #requireAddr}/{@link #copyAddrIfPresent} rather than
	 * plain {@link #copyIfPresent}: snakeyaml hands {@code 0x0073} back as a {@code String} when
	 * it is quoted or otherwise not scalar-parsed, and gson would then emit a JSON string where
	 * {@code DescriptorCopyHintAnalyzer} calls {@code getAsLong()}.
	 * <p>
	 * The range checks are here rather than at load time deliberately: a hint whose range escapes
	 * its own region, or whose {@code end} precedes its {@code start}, is a descriptor typo, and
	 * an unreadable-source hint is silently ignored at runtime by design
	 * (docs/smc-inplace-vs-overlay.md §6) -- so a typo that never materializes anything would
	 * otherwise look exactly like the legitimate "user supplied no ROM" case. The {@code source}
	 * name is validated separately, by {@link #validateCopiedFromSources}, because it may name a
	 * region or occupant declared later in the file.
	 *
	 * @return the normalized hint list, or null when the region declares none
	 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildCopiedFrom(Map<String, Object> region,
			String regionName, int regionStart, int regionEnd) {
		List<Map<String, Object>> hints =
			(List<Map<String, Object>>) region.get("copied_from");
		if (hints == null) {
			return null;
		}
		String regionContext = "memory.regions[] '" + regionName + "' copied_from[]";
		List<Map<String, Object>> out = new ArrayList<>();
		for (Map<String, Object> hint : hints) {
			String name = requireString(hint, "name", regionContext);
			String context = regionContext + " '" + name + "'";
			Map<String, Object> c = new LinkedHashMap<>();
			c.put("name", name);
			int start = requireAddr(hint, "start", context);
			int end = requireAddr(hint, "end", context);
			c.put("start", start);
			c.put("end", end);
			c.put("source", requireString(hint, "source", context));
			c.put("source_addr", requireAddr(hint, "source_addr", context));
			copyAddrIfPresent(hint, c, "entry");
			copyIfPresent(hint, c, "disassemble");
			copyIfPresent(hint, c, "create_function");
			copyIfPresent(hint, c, "comment");

			if (end < start) {
				throw new IllegalArgumentException(context + " has end $" +
					String.format("%04X", end) + " before start $" + String.format("%04X", start));
			}
			if (start < regionStart || end > regionEnd) {
				throw new IllegalArgumentException(context + " range $" +
					String.format("%04X", start) + "-$" + String.format("%04X", end) +
					" is not inside region '" + regionName + "' ($" +
					String.format("%04X", regionStart) + "-$" +
					String.format("%04X", regionEnd) + ")");
			}
			if (c.containsKey("entry")) {
				int entry = ((Number) c.get("entry")).intValue();
				if (entry < start || entry > end) {
					throw new IllegalArgumentException(context + " entry $" +
						String.format("%04X", entry) + " is not inside the copied range $" +
						String.format("%04X", start) + "-$" + String.format("%04X", end));
				}
			}
			out.add(c);
		}
		validateUniqueNames(out, "name", regionContext + " name");
		return out;
	}

	/**
	 * Checks every {@code copied_from[].source} against the same name space {@code on_write}
	 * resolves in: a declared {@code memory.regions[]} name or a window occupant name (including
	 * occupants that only appear inside a {@code memory.layouts[]} window set). On the C64 the
	 * canonical source, {@code KERNAL}, is a window OCCUPANT (machines/c64.yaml:124) rather than
	 * a region, so both halves of the set are load-bearing.
	 * <p>
	 * This fails the build rather than warning. {@code buildRegions} is otherwise a
	 * {@link #copyIfPresent} whitelist, so a misspelled key vanishes silently -- a failure mode
	 * this repo has already been bitten by -- and a hint naming a block that does not exist can
	 * never materialize anything at load time either.
	 */
	@SuppressWarnings("unchecked")
	private static void validateCopiedFromSources(List<Map<String, Object>> regions,
			List<Map<String, Object>> windows, List<Map<String, Object>> layouts) {
		Set<String> targets = new LinkedHashSet<>();
		for (Map<String, Object> region : regions) {
			targets.add((String) region.get("name"));
		}
		List<Map<String, Object>> allWindows = new ArrayList<>(windows);
		if (layouts != null) {
			for (Map<String, Object> layout : layouts) {
				allWindows.addAll((List<Map<String, Object>>) layout.get("windows"));
			}
		}
		for (Map<String, Object> window : allWindows) {
			List<Map<String, Object>> occupants =
				(List<Map<String, Object>>) window.get("occupants");
			if (occupants == null) {
				continue; // computed (maps:) window -- no enumerated occupant to name
			}
			for (Map<String, Object> occupant : occupants) {
				targets.add((String) occupant.get("name"));
			}
		}
		for (Map<String, Object> region : regions) {
			List<Map<String, Object>> hints =
				(List<Map<String, Object>>) region.get("copied_from");
			if (hints == null) {
				continue;
			}
			for (Map<String, Object> hint : hints) {
				String source = (String) hint.get("source");
				if (!targets.contains(source)) {
					throw new IllegalArgumentException("memory.regions[] '" +
						region.get("name") + "' copied_from[] '" + hint.get("name") +
						"' names source '" + source +
						"', which is neither a declared region nor a window occupant");
				}
			}
		}
	}

	// ---- PRG/RAM placement coverage (grm-z15.4) ----

	/**
	 * True only for descriptors consumed by {@code AbstractCbmPrgLoader} (its
	 * {@code planPrgSlices} is the only code path this coverage check protects): those
	 * declare {@code formats.prg.placement: load_address}, the 2-byte CBM load-address
	 * header convention. Boards loaded by other means (e.g. NES iNES-mapper descriptors,
	 * which have no {@code formats.prg} at all) legitimately have non-contiguous RAM --
	 * e.g. NES's console RAM at $0000-$07FF and cartridge PRG RAM at $6000-$7FFF are
	 * separated by PPU/APU register space with no PRG byte ever placed there.
	 */
	@SuppressWarnings("unchecked")
	private static boolean usesLoadAddressPlacement(Map<String, Object> descriptor) {
		Object formats = descriptor.get("formats");
		if (!(formats instanceof Map)) {
			return false;
		}
		Object prg = ((Map<String, Object>) formats).get("prg");
		if (!(prg instanceof Map)) {
			return false;
		}
		return "load_address".equals(((Map<String, Object>) prg).get("placement"));
	}

	/** One named [start, end] range contributing to the RAM placement union: a
	 * {@code kind: ram} or {@code prg_placeable: true} region, or a window collapsed to its
	 * own [start, end] because at least one of its occupants is {@code kind: ram}. */
	private record PlacementRange(String name, int start, int end) {}

	/**
	 * Validates that {@link AbstractCbmPrgLoader#planPrgSlices}'s placement-target union
	 * (every {@code kind: ram} or {@code prg_placeable: true} region, plus every window that
	 * has a {@code kind: ram} occupant, collapsed to the window's own range since its ram
	 * occupants are mutually-exclusive banks sharing that range) is internally contiguous:
	 * no two placement ranges overlap, and no gap separates the lowest range from the
	 * highest. The union need not start at $0000 or reach $FFFF -- only the span between its
	 * own lowest and highest member must have no hole, matching what planPrgSlices actually
	 * requires (a spanning PRG import fails the moment a byte maps to zero or two targets).
	 */
	@SuppressWarnings("unchecked")
	private static void validateRamCoverage(List<Map<String, Object>> regions,
			List<Map<String, Object>> windows) {
		List<PlacementRange> ranges = new ArrayList<>();
		for (Map<String, Object> region : regions) {
			boolean placeable = "ram".equals(region.get("kind")) ||
				Boolean.TRUE.equals(region.get("prg_placeable"));
			if (placeable) {
				ranges.add(new PlacementRange((String) region.get("name"),
					(Integer) region.get("start"), (Integer) region.get("end")));
			}
		}
		for (Map<String, Object> window : windows) {
			List<Map<String, Object>> occupants =
				(List<Map<String, Object>>) window.get("occupants");
			if (occupants == null) {
				continue; // computed (maps:) window -- no enumerated occupant to be ram
			}
			boolean hasRamOccupant =
				occupants.stream().anyMatch(o -> "ram".equals(o.get("kind")));
			if (hasRamOccupant) {
				ranges.add(new PlacementRange((String) window.get("name"),
					(Integer) window.get("start"), (Integer) window.get("end")));
			}
		}
		if (ranges.isEmpty()) {
			return;
		}
		ranges.sort(Comparator.comparingInt(PlacementRange::start));
		// Sorted-by-start + consecutive-pair comparison suffices to catch every overlap,
		// even a non-adjacent one: if ranges[i] and ranges[k] (k > i+1) overlapped, then
		// ranges[i+1].start (which lies between them) would also fall inside ranges[i]'s
		// span, so the i/i+1 pair would already flag it. Once no consecutive pair overlaps,
		// ends are strictly increasing in start order too, so a plain gap check between
		// consecutive pairs is exact.
		for (int i = 0; i + 1 < ranges.size(); i++) {
			PlacementRange a = ranges.get(i);
			PlacementRange b = ranges.get(i + 1);
			if (a.start() <= b.end() && b.start() <= a.end()) {
				throw new IllegalArgumentException(
					"descriptor RAM placement targets '" + a.name() + "' and '" + b.name() +
						"' overlap at $" + String.format("%04X", Math.max(a.start(), b.start())));
			}
			if (b.start() > a.end() + 1) {
				throw new IllegalArgumentException(
					"descriptor RAM placement coverage has a gap between '" + a.name() +
						"' and '" + b.name() + "' at $" + String.format("%04X", a.end() + 1) +
						"-$" + String.format("%04X", b.start() - 1));
			}
		}
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
		Pattern.compile("\\G\\s*(0[xX][0-9a-fA-F]+|\\d+|[A-Za-z_]\\w*|>>|[-+*()])");

	/**
	 * Validates a computed-window expression like {@code PRG[bank * 0x4000]} and returns
	 * its structured form {@code {space, expr}}. The grammar is deliberately tiny
	 * (vision doc §5.3): integers, declared state-field names, the keywords
	 * {@code last}/{@code second_last}, {@code + - * >>}, and parentheses. {@code >>}
	 * (bead {@code grm-hsv.2}) is a logical right-shift binding at the same precedence
	 * as {@code *} -- see {@code DescriptorSupport.evalExpr}'s javadoc for the full
	 * rationale and precedence rule, which this validator must accept the same shapes
	 * for. The expression is validated here but kept as a string in the .map; runtime
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
			else if (">>".equals(t) || (t.length() == 1 && "+-*".contains(t))) {
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
		int total = fields.values().stream().mapToInt(Integer::intValue).sum();
		if (total > 31) {
			// packState shifts each field by the cumulative width into a 32-bit int, and the
			// runtime derives the whole-state mask as (1 << total) - 1 (BoardBankAnalyzer). Both
			// only hold for total <= 31: at 32+ a field's shift wraps mod-32 (silently corrupting
			// packed values) and (1 << 32) - 1 evaluates to 0 (an empty mask).
			throw new IllegalArgumentException("banking.state total width " + total +
				" bits exceeds 31; the packed bank state is a 32-bit int");
		}
		return fields;
	}

	/** Enforces uniqueness only: entries missing (or with a blank) {@code key} are skipped,
	 *  since name-presence is validated elsewhere by the build* paths (e.g.
	 *  {@link #requireString}). Mirrors {@link GdtBuilder#validateUniqueTypeNames}. */
	private static void validateUniqueNames(List<Map<String, Object>> entries,
			String key, String context) {
		if (entries == null) {
			return;
		}
		Set<String> seen = new HashSet<>();
		for (Map<String, Object> e : entries) {
			Object v = e.get(key);
			if (!(v instanceof String s) || s.trim().isEmpty()) {
				continue; // presence checked elsewhere
			}
			if (!seen.add(s)) {
				throw new IllegalArgumentException(context + " '" + s + "' is declared twice");
			}
		}
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
		if (banking.containsKey("context_register")) {
			Object contextRegister = banking.get("context_register");
			if (!(contextRegister instanceof String) ||
				((String) contextRegister).trim().isEmpty()) {
				throw new IllegalArgumentException(
					"banking 'context_register:' must be a non-empty string when present");
			}
			out.put("context_register", contextRegister);
		}

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
			// 1L (not 1): at bits==31, 1<<31 is Integer.MIN_VALUE (negative), so an int
			// comparison would reject every non-negative value, including 0.
			if (fieldValue < 0 || fieldValue >= (1L << bits)) {
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
	private static Map<String, Object> buildRomImages(Map<String, Object> descriptor,
			List<Map<String, Object>> regions) {
		Map<String, Object> romImages = (Map<String, Object>) descriptor.get("rom_images");
		Map<String, Object> out = new LinkedHashMap<>();
		if (romImages == null) {
			return out;
		}
		for (Map.Entry<String, Object> entry : romImages.entrySet()) {
			Map<String, Object> img = (Map<String, Object>) entry.getValue();
			Map<String, Object> i = new LinkedHashMap<>();
			String context = "rom_images." + entry.getKey();
			int size = requireAddr(img, "size", context);
			i.put("size", size);
			String targetName = requireString(img, "occupant", context);
			i.put("occupant", targetName);
			Map<String, Object> region = findRegion(regions, targetName);
			if (region != null) {
				if (!"rom".equals(region.get("kind"))) {
					throw new IllegalArgumentException(context + " targets region '" + targetName +
						"', whose kind is not 'rom'");
				}
				int regionSize = ((Number) region.get("end")).intValue() -
					((Number) region.get("start")).intValue() + 1;
				if (size != regionSize) {
					throw new IllegalArgumentException(context + " size " + size +
						" does not match target region '" + targetName + "' size " + regionSize);
				}
				Object regionImage = region.get("image");
				if (regionImage != null && !entry.getKey().equals(regionImage.toString())) {
					throw new IllegalArgumentException("memory region '" + targetName +
						"' must declare image: " + entry.getKey() + " to match " + context);
				}
			}
			out.put(entry.getKey(), i);
		}
		for (Map<String, Object> region : regions) {
			Object image = region.get("image");
			if (image == null) {
				continue;
			}
			Object slotObj = out.get(image.toString());
			if (!(slotObj instanceof Map) ||
					!region.get("name").equals(((Map<?, ?>) slotObj).get("occupant"))) {
				throw new IllegalArgumentException("memory region '" + region.get("name") +
					"' references image slot '" + image +
					"', but that slot does not target this region");
			}
		}
		return out;
	}

	private static Map<String, Object> findRegion(List<Map<String, Object>> regions, String name) {
		for (Map<String, Object> region : regions) {
			if (name.equals(region.get("name"))) {
				return region;
			}
		}
		return null;
	}

	// ---- formats ----

	/**
	 * Formats are loader policy data, not compiler behavior. Preserve the documented tree
	 * while normalizing YAML numeric scalars and mapping keys exactly as strategy params are.
	 */
	@SuppressWarnings("unchecked")
	private static Map<String, Object> buildFormats(Map<String, Object> descriptor) {
		Object formats = descriptor.get("formats");
		if (formats == null) {
			return null;
		}
		if (!(formats instanceof Map)) {
			throw new IllegalArgumentException("descriptor 'formats:' must be a mapping");
		}
		return (Map<String, Object>) normalizeValues(formats);
	}

	// ---- symbols ----

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> buildSymbols(Map<String, Object> descriptor,
			File descriptorDir) throws IOException {
		List<Map<String, Object>> symbols = (List<Map<String, Object>>) descriptor.get("symbols");
		List<Map<String, Object>> out = new ArrayList<>();
		if (symbols == null) {
			return out;
		}
		for (Map<String, Object> set : symbols) {
			Map<String, Object> s = new LinkedHashMap<>();
			String setName = requireString(set, "set", "symbols[]");
			s.put("set", setName);
			s.put("default", parseDefault(set));
			copyIfPresent(set, s, "region");

			// Entries come from an inline: list (hand-curated seed) and/or a source: file
			// (bulk symbols generated from mist64/c64ref -- see machines/generated). Inline
			// entries take precedence: an address present inline is not overwritten by the
			// generated source, so the seed acts as authoritative overrides.
			List<Map<String, Object>> entriesOut = new ArrayList<>();
			Set<Integer> seenAddrs = new LinkedHashSet<>();

			List<Map<String, Object>> inline = (List<Map<String, Object>>) set.get("inline");
			if (inline != null) {
				for (Map<String, Object> entry : inline) {
					Map<String, Object> e = symbolEntry(entry, seenAddrs);
					if (e != null) {
						entriesOut.add(e);
					}
				}
			}

			String source = (String) set.get("source");
			if (source != null) {
				File sourceFile = new File(descriptorDir, source);
				if (sourceFile.isFile()) {
					Map<String, Object> sourceDoc = YamlSupport.load(sourceFile);
					List<Map<String, Object>> srcEntries =
						(List<Map<String, Object>>) sourceDoc.get("entries");
					if (srcEntries == null) {
						throw new IllegalArgumentException("symbol set '" + setName +
							"' source file has no top-level 'entries:' list: " + sourceFile);
					}
					for (Map<String, Object> entry : srcEntries) {
						Map<String, Object> e = symbolEntry(entry, seenAddrs);
						if (e != null) {
							entriesOut.add(e);
						}
					}
				}
				else {
					// Referenced but not yet generated -- keep the build working (inline entries
					// still apply) and surface the gap loudly rather than silently producing none.
					System.err.println("WARNING: symbol set '" + setName +
						"' references source file that does not exist (using inline entries only): " +
						sourceFile);
				}
			}

			s.put("entries", entriesOut);
			out.add(s);
		}
		return out;
	}

	/** Normalize one symbol entry ({@code addr}/{@code name}/{@code kind}/{@code comment}),
	 *  or {@code null} if its address was already emitted for this set (dedup; the first
	 *  occurrence -- inline before source -- wins). */
	private static Map<String, Object> symbolEntry(Map<String, Object> entry,
			Set<Integer> seenAddrs) {
		int addr = requireAddr(entry, "addr", "symbols entry");
		if (!seenAddrs.add(addr)) {
			return null;
		}
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("addr", addr);
		e.put("name", requireString(entry, "name", "symbols entry"));
		e.put("kind", requireString(entry, "kind", "symbols entry"));
		copyIfPresent(entry, e, "comment");
		return e;
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
}
