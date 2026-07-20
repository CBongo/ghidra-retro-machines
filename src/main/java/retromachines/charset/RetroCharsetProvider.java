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
package retromachines.charset;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.spi.CharsetProvider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import retromachines.PetsciiMapper;
import retromachines.PetsciiMapper.Variant;

/**
 * JVM {@code ServiceLoader} SPI provider (bead grm-1.4 Phase C) serving the PETSCII and (once
 * {@code data/screencode.map} exists, bead grm-1.4.5) C64 screen-code charsets, backed by the
 * same compiled maps {@link retromachines.PetsciiMapper} uses -- no PETSCII/screencode
 * knowledge is duplicated here, only JSON-resource-&gt;{@link TableCharset} wiring.
 * <p>
 * Registered via {@code META-INF/services/java.nio.charset.spi.CharsetProvider}. Ghidra
 * installs {@code GhidraClassLoader} as the JVM <em>system</em> class loader with extension
 * jars already on its classpath at launch, so this provider is discovered by
 * {@link java.util.ServiceLoader} exactly like a JDK-bundled one -- which also means a
 * throwing/misbehaving provider here would poison {@link Charset#availableCharsets()} for the
 * <em>entire JVM</em>, not just this extension. Every path below is therefore:
 * <ul>
 * <li><b>Lazy</b>: the constructor does nothing that can fail; all resource loading happens on
 * first {@link #charsets()}/{@link #charsetForName(String)} call.</li>
 * <li><b>Memoized</b>: loaded exactly once (double-checked locking on a volatile holder).</li>
 * <li><b>Failure-swallowing</b>: a missing resource or a parse error removes that charset from
 * the registry silently (never an exception out of this class) -- and each of the (currently)
 * four charsets is built independently, so one bad map cannot take the others down with it.</li>
 * </ul>
 * No Ghidra imports anywhere in this file or {@link TableCharset}: both are plain
 * {@code java.nio.charset} code, which is what lets {@code tools/charset/
 * CharsetProviderVerify.java} exercise the real {@code ServiceLoader} path in a plain JVM with
 * no Ghidra runtime at all.
 */
public final class RetroCharsetProvider extends CharsetProvider {

	private static final String PETSCII_RESOURCE = "/retromachines/charset/petscii.map";
	private static final String SCREENCODE_RESOURCE = "/retromachines/charset/screencode.map";

	/** Immutable snapshot of everything this provider currently serves. */
	private static final class Registry {
		static final Registry EMPTY = new Registry(Collections.emptyList(), Collections.emptyMap());

		final List<Charset> all;
		final Map<String, Charset> byLowerName;

		Registry(List<Charset> all, Map<String, Charset> byLowerName) {
			this.all = all;
			this.byLowerName = byLowerName;
		}
	}

	private volatile Registry registry;

	/** Does nothing that can fail: no resource I/O, no parsing. Required so that a
	 *  {@link java.util.ServiceLoader} instantiation failure can never happen here. */
	public RetroCharsetProvider() {
	}

	@Override
	public Iterator<Charset> charsets() {
		return registry().all.iterator();
	}

	@Override
	public Charset charsetForName(String charsetName) {
		if (charsetName == null) {
			return null;
		}
		return registry().byLowerName.get(charsetName.toLowerCase(Locale.ROOT));
	}

	private Registry registry() {
		Registry result = registry;
		if (result == null) {
			synchronized (this) {
				result = registry;
				if (result == null) {
					result = buildRegistrySafely();
					registry = result;
				}
			}
		}
		return result;
	}

	/** Top-level safety net: even if a bug in the building logic below throws something
	 *  unanticipated, this provider still degrades to "serves nothing" rather than
	 *  propagating out of the SPI entry points. */
	private Registry buildRegistrySafely() {
		try {
			List<Charset> all = new ArrayList<>();
			Map<String, Charset> byLowerName = new HashMap<>();

			addPetsciiCharsets(all, byLowerName);
			addScreencodeCharsets(all, byLowerName);

			return new Registry(Collections.unmodifiableList(all),
				Collections.unmodifiableMap(byLowerName));
		}
		catch (Throwable t) {
			return Registry.EMPTY;
		}
	}

	// ---------------------------------------------------------------------------------
	// PETSCII (data/petscii.map, staged by build.gradle's stageCharsetResources task).
	// ---------------------------------------------------------------------------------

	private void addPetsciiCharsets(List<Charset> all, Map<String, Charset> byLowerName) {
		PetsciiMapper mapper = tryLoadPetsciiMapper();
		if (mapper == null) {
			return;
		}
		registerIfBuildable(all, byLowerName, () -> tableCharsetFromPetscii(mapper,
			Variant.UNSHIFTED_GRAPHICS, "x-petscii-unshifted", new String[] { "petscii", "x-petscii" }));
		registerIfBuildable(all, byLowerName, () -> tableCharsetFromPetscii(mapper,
			Variant.SHIFTED_LOWERCASE, "x-petscii-shifted", new String[] { "petscii-shifted" }));
	}

	private static PetsciiMapper tryLoadPetsciiMapper() {
		try (InputStream in = RetroCharsetProvider.class.getResourceAsStream(PETSCII_RESOURCE)) {
			if (in == null) {
				return null;
			}
			return PetsciiMapper.loadFromStream(in);
		}
		catch (Throwable t) {
			return null;
		}
	}

	/** Builds a {@link TableCharset} for one PETSCII variant by exhaustively walking
	 *  {@link PetsciiMapper#toDisplayUnicode} / {@link PetsciiMapper#encodeUnicode} for all 256
	 *  bytes -- this reconstructs the same decode table and (partial, many-to-one) encode map
	 *  {@code PetsciiCompiler} produced, without needing any new accessor on
	 *  {@link PetsciiMapper} beyond what grm-1.4.2 already added. */
	private static Charset tableCharsetFromPetscii(PetsciiMapper mapper, Variant variant,
			String canonicalName, String[] aliases) {
		int[] table = new int[256];
		Map<Integer, Integer> encode = new HashMap<>();
		for (int b = 0; b < 256; b++) {
			int codepoint = mapper.toDisplayUnicode(b, variant).codePointAt(0);
			table[b] = codepoint;
			Integer canonicalByte = mapper.encodeUnicode(codepoint, variant);
			if (canonicalByte != null) {
				encode.put(codepoint, canonicalByte);
			}
		}
		return new TableCharset(canonicalName, aliases, table, encode);
	}

	// ---------------------------------------------------------------------------------
	// Screen codes (data/screencode.map, grm-1.4.5). The resource does not exist yet, so
	// this silently serves nothing until that bead lands it -- exercised today by
	// CharsetProviderVerify's tolerant "currently unsupported" check.
	//
	// Parsed with a small local gson read rather than routing through PetsciiMapper: that
	// class's constructor requires a top-level "variants" key (the escaped-display tables),
	// which the screencode map has no reason to carry. Reusing PetsciiMapper here would mean
	// contorting it to tolerate an absent section it doesn't otherwise need -- not worth it
	// for ~15 lines of straight-line JSON reading.
	// ---------------------------------------------------------------------------------

	private void addScreencodeCharsets(List<Charset> all, Map<String, Charset> byLowerName) {
		JsonObject mapJson = tryLoadScreencodeJson();
		if (mapJson == null) {
			return;
		}
		registerIfBuildable(all, byLowerName, () -> tableCharsetFromScreencodeJson(mapJson,
			"unshifted_graphics", "x-c64-screencode-unshifted", new String[] { "c64-screencode" }));
		registerIfBuildable(all, byLowerName, () -> tableCharsetFromScreencodeJson(mapJson,
			"shifted_lowercase", "x-c64-screencode-shifted", new String[0]));
	}

	private static JsonObject tryLoadScreencodeJson() {
		try (InputStream in = RetroCharsetProvider.class.getResourceAsStream(SCREENCODE_RESOURCE)) {
			if (in == null) {
				return null;
			}
			try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
				return JsonParser.parseReader(reader).getAsJsonObject();
			}
		}
		catch (IOException | RuntimeException e) {
			return null;
		}
	}

	/** Same JSON shape as {@code petscii.map}'s {@code unicode_variants}/{@code encode}
	 *  sections (256-entry codepoint array + decimal-codepoint-string-keyed encode map),
	 *  keyed by {@code variantKey} (e.g. {@code "unshifted_graphics"}). */
	private static Charset tableCharsetFromScreencodeJson(JsonObject mapJson, String variantKey,
			String canonicalName, String[] aliases) {
		JsonObject unicodeVariants = mapJson.getAsJsonObject("unicode_variants");
		JsonObject encodeSection = mapJson.getAsJsonObject("encode");
		JsonArray codepointArray = unicodeVariants.getAsJsonArray(variantKey);
		if (codepointArray.size() != 256) {
			throw new IllegalArgumentException("screencode.map variant '" + variantKey + "' has " +
				codepointArray.size() + " entries, expected 256");
		}
		int[] table = new int[256];
		for (int i = 0; i < 256; i++) {
			table[i] = codepointArray.get(i).getAsInt();
		}
		Map<Integer, Integer> encode = new HashMap<>();
		JsonObject encodeObj = encodeSection.getAsJsonObject(variantKey);
		for (Map.Entry<String, JsonElement> e : encodeObj.entrySet()) {
			encode.put(Integer.parseInt(e.getKey()), e.getValue().getAsInt());
		}
		return new TableCharset(canonicalName, aliases, table, encode);
	}

	// ---------------------------------------------------------------------------------

	@FunctionalInterface
	private interface CharsetBuilder {
		Charset build();
	}

	/** Builds one charset and registers it under its canonical name and all aliases
	 *  (lower-cased, for {@link #charsetForName}'s case-insensitive lookup) -- swallowing any
	 *  failure so one bad charset never affects its siblings. */
	private static void registerIfBuildable(List<Charset> all, Map<String, Charset> byLowerName,
			CharsetBuilder builder) {
		try {
			Charset cs = builder.build();
			all.add(cs);
			byLowerName.put(cs.name().toLowerCase(Locale.ROOT), cs);
			for (String alias : cs.aliases()) {
				byLowerName.put(alias.toLowerCase(Locale.ROOT), cs);
			}
		}
		catch (Throwable t) {
			// Swallow: see class javadoc -- this provider must never throw out of an SPI
			// entry point, and one bad charset must not take its siblings down with it.
		}
	}
}
