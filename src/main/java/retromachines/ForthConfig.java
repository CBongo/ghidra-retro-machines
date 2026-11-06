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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/**
 * Description of one indirect-threaded (ITC) Forth runtime on a 6502 (bead grm-arbi.2): the
 * zero-page registers, the inner-interpreter entry points, and the code-field values that give
 * each word its behaviour. Pure and Ghidra-free, like {@link CbmAutostart.Config}; the format
 * is specified in {@code docs/FORTH.md}.
 * <p>
 * Parsed from the compiled-descriptor JSON form: either the {@code forth} object itself or an
 * object that has one ({@code {"forth": {...}}}). Integers may be JSON numbers or strings
 * ({@code "0x08C4"}, {@code "$08C4"}, decimal); map keys (which JSON forces to be strings) are
 * read the same way, with a bare digit string taken as decimal.
 *
 * @param ip zero-page address of the IP low byte
 * @param w zero-page address of the W low byte
 * @param next NEXT entry address (label only), or -1
 * @param docol code-field VALUE that marks a colon word
 * @param exit CFAs that end a colon body
 * @param handlers code-field VALUE to handler (DOCON, DOVAR, DOUSER, DODOES)
 * @param inline CFA to the inline operand that follows it in a thread
 * @param names CFA to name and optional stack comment
 */
public record ForthConfig(int ip, int w, int next, int docol, List<Integer> exit,
		Map<Integer, Handler> handlers, Map<Integer, InlineMode> inline,
		Map<Integer, Name> names) {

	/** Program-Info property that holds the config JSON until the descriptor section lands. */
	public static final String PROPERTY = "Retro Machines.Forth Config";

	/** Behaviour of a handler code-field value. */
	public enum Role {
		/** Pushes the 16-bit constant at {@code CFA+2}. */
		DOCON,
		/** Pushes the address {@code CFA+2}; the parameter field is data. */
		DOVAR,
		/** Pushes {@code [CFA+2]} plus the 16-bit word at zero page {@code base}. */
		DOUSER,
		/** Layout {@code [handler][does-thread address][data...]}. */
		DODOES
	}

	/**
	 * A handler.
	 *
	 * @param role what the handler does
	 * @param base DOUSER only: zero-page address of the user-area base cell, else -1
	 */
	public record Handler(Role role, int base) {}

	/** What follows a word's cell inside a thread. */
	public enum InlineMode {
		/** One 16-bit literal. */
		LIT16,
		/** One signed 16-bit offset; target is the operand address plus the offset. */
		BRANCH,
		/** One count byte then that many bytes. */
		COUNTED_STRING,
		/** One 16-bit cell that is data (an address constant); typed like a literal. */
		CELL16
	}

	/**
	 * A word name.
	 *
	 * @param name the Forth name
	 * @param comment the stack-effect comment, or null
	 */
	public record Name(String name, String comment) {}

	/**
	 * Tests whether {@code cfa} is a declared thread terminator.
	 *
	 * @param cfa a code-field address
	 * @return true when the word ends a colon body
	 */
	public boolean isExit(int cfa) {
		return exit.contains(cfa);
	}

	/**
	 * Parses a config from JSON text.
	 *
	 * @param json the JSON, an object holding either a {@code forth} object or the mapping itself
	 * @return the config
	 * @throws IllegalArgumentException when the text is not a valid config
	 */
	public static ForthConfig fromJson(String json) {
		try {
			JsonElement root = JsonParser.parseString(json);
			if (!root.isJsonObject()) {
				throw new IllegalArgumentException("Forth config must be a JSON object");
			}
			return fromMap(root.getAsJsonObject());
		}
		catch (com.google.gson.JsonParseException | IllegalStateException |
			UnsupportedOperationException | NumberFormatException e) {
			throw new IllegalArgumentException("bad Forth config: " + e.getMessage(), e);
		}
	}

	/**
	 * Reads the {@code forth} section, the way {@link CbmAutostart#fromMap} reads
	 * {@code autostart}.
	 *
	 * @param map the compiled descriptor (or the section itself)
	 * @return the config, or null when the map has no Forth section
	 */
	public static ForthConfig fromMap(JsonObject map) {
		if (map == null) {
			return null;
		}
		JsonObject f = map;
		if (map.has("forth") && map.get("forth").isJsonObject()) {
			f = map.getAsJsonObject("forth");
		}
		else if (!map.has("docol")) {
			return null;
		}
		int ip = requireInt(f, "ip");
		int w = requireInt(f, "w");
		int docol = requireInt(f, "docol");
		int next = f.has("next") ? asInt(f.get("next")) : -1;

		List<Integer> exits = new ArrayList<>();
		if (f.has("exit")) {
			JsonElement e = f.get("exit");
			if (e.isJsonArray()) {
				for (JsonElement x : e.getAsJsonArray()) {
					exits.add(asInt(x));
				}
			}
			else {
				exits.add(asInt(e));
			}
		}

		Map<Integer, Handler> handlers = new TreeMap<>();
		for (Map.Entry<String, JsonElement> en : obj(f, "handlers").entrySet()) {
			JsonElement v = en.getValue();
			String role = v.isJsonObject() ? v.getAsJsonObject().get("role").getAsString()
					: v.getAsString();
			int base = v.isJsonObject() && v.getAsJsonObject().has("base")
					? asInt(v.getAsJsonObject().get("base")) : -1;
			handlers.put(parseInt(en.getKey()),
				new Handler(Role.valueOf(role.toUpperCase(Locale.ROOT)), base));
		}

		Map<Integer, InlineMode> inline = new TreeMap<>();
		for (Map.Entry<String, JsonElement> en : obj(f, "inline").entrySet()) {
			JsonElement v = en.getValue();
			String mode = v.isJsonObject() ? v.getAsJsonObject().get("mode").getAsString()
					: v.getAsString();
			inline.put(parseInt(en.getKey()),
				InlineMode.valueOf(mode.toUpperCase(Locale.ROOT)));
		}

		Map<Integer, Name> names = new TreeMap<>();
		for (Map.Entry<String, JsonElement> en : obj(f, "names").entrySet()) {
			JsonElement v = en.getValue();
			if (v.isJsonObject()) {
				JsonObject o = v.getAsJsonObject();
				names.put(parseInt(en.getKey()), new Name(o.get("name").getAsString(),
					o.has("comment") ? o.get("comment").getAsString() : null));
			}
			else {
				names.put(parseInt(en.getKey()), new Name(v.getAsString(), null));
			}
		}
		return new ForthConfig(ip, w, next, docol, List.copyOf(exits), Map.copyOf(handlers),
			Map.copyOf(inline), Map.copyOf(names));
	}

	private static JsonObject obj(JsonObject f, String key) {
		return f.has(key) && f.get(key).isJsonObject() ? f.getAsJsonObject(key) : new JsonObject();
	}

	private static int requireInt(JsonObject f, String key) {
		if (!f.has(key)) {
			throw new IllegalArgumentException("Forth config missing '" + key + "'");
		}
		return asInt(f.get(key));
	}

	private static int asInt(JsonElement e) {
		JsonPrimitive p = e.getAsJsonPrimitive();
		return p.isNumber() ? p.getAsInt() : parseInt(p.getAsString());
	}

	/** Parses {@code 0x..}, {@code $..} (hex) or plain decimal. */
	static int parseInt(String s) {
		String t = s.trim();
		if (t.startsWith("0x") || t.startsWith("0X")) {
			return Integer.parseInt(t.substring(2), 16);
		}
		if (t.startsWith("$")) {
			return Integer.parseInt(t.substring(1), 16);
		}
		return Integer.parseInt(t);
	}

	/** Serialises back to the canonical JSON form (round-trips through {@link #fromJson}). */
	public JsonObject toJson() {
		JsonObject f = new JsonObject();
		f.addProperty("ip", ip);
		f.addProperty("w", w);
		if (next >= 0) {
			f.addProperty("next", next);
		}
		f.addProperty("docol", docol);
		JsonArray ex = new JsonArray();
		exit.forEach(ex::add);
		f.add("exit", ex);
		JsonObject h = new JsonObject();
		new TreeMap<>(handlers).forEach((k, v) -> {
			JsonObject o = new JsonObject();
			o.addProperty("role", v.role().name());
			if (v.base() >= 0) {
				o.addProperty("base", v.base());
			}
			h.add(String.valueOf(k), o);
		});
		f.add("handlers", h);
		JsonObject in = new JsonObject();
		new TreeMap<>(inline).forEach((k, v) -> in.addProperty(String.valueOf(k), v.name()));
		f.add("inline", in);
		JsonObject nm = new JsonObject();
		new TreeMap<>(names).forEach((k, v) -> {
			JsonObject o = new JsonObject();
			o.addProperty("name", v.name());
			if (v.comment() != null) {
				o.addProperty("comment", v.comment());
			}
			nm.add(String.valueOf(k), o);
		});
		f.add("names", nm);
		JsonObject root = new JsonObject();
		root.add("forth", f);
		return root;
	}
}
