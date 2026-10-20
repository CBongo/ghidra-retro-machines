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

import com.google.gson.*;

import ghidra.program.model.listing.Program;

/**
 * The per-game {@code banking.*} hint lists that travel descriptor -> program property ->
 * analyzer (bead grm-rx1i.10): one row per list-shaped key, so the loader publish, the property
 * format, the property parse and the exporter are driven from a single table instead of one
 * hand-copied skeleton each. A new list-shaped hint is a new row here (plus its compiler spec in
 * {@code gdtbuilder.GameCompiler} and its consumer); key-specific meaning stays with the
 * consumer ({@link SwitchSiteHints}, {@link ShadowCommits}, ...), never here.
 * <p>
 * Constant order is the order the loader publishes the properties and the exporter writes the
 * YAML keys; it is byte-visible, so do not reorder.
 * {@code banking.initial_state} and {@code banking.fixed_after_init} are not list-of-mappings
 * hints and keep their own paths.
 * <p>
 * The property JSON is {@code {"source": <gmap path>, <arrayKey>: [ <entry>... ]}}; entries are
 * the compiled descriptor's mappings verbatim.
 */
enum BankingHintKind {

	BANK_IDENTIFYING_OFFSETS("bank_identifying_offsets",
		DescriptorHints.BANK_IDENTIFYING_HINTS_PROPERTY, "offsets",
		new String[] { "address" }, new String[] { "shift", "low" },
		new String[] { "bias", "modulus_bits" }),

	SWITCH_SITES("switch_sites", DescriptorHints.SWITCH_SITES_PROPERTY, "sites",
		new String[] { "addr" }, new String[0],
		new String[] { "block", "entry", "comment", "bank" }),

	SAVE_CELLS("save_cells", DescriptorHints.SAVE_CELLS_PROPERTY, "cells",
		new String[] { "address" }, new String[0], new String[0]),

	BANK_STACKS("bank_stacks", DescriptorHints.BANK_STACKS_PROPERTY, "stacks",
		new String[] { "pointer", "slots" }, new String[0], new String[0]),

	SHADOW_COMMITS("shadow_commits", DescriptorHints.SHADOW_COMMITS_PROPERTY, "commits",
		new String[] { "helper", "cell" }, new String[] { "field" }, new String[0]),

	PAIRED_FIELDS("paired_fields", DescriptorHints.PAIRED_FIELDS_PROPERTY, "pairs",
		new String[0], new String[] { "high", "low", "offset" }, new String[0]);

	/** One entry of the array, plus the property's root object (for the {@code source}). */
	@FunctionalInterface
	interface EntryReader<T> {
		T read(JsonObject entry, JsonObject root);
	}

	/** The key under {@code banking:} in the game descriptor (YAML and compiled .gmap). */
	final String yamlKey;
	/** The program-info property the loader publishes the list under. */
	final String property;
	/** The array's key inside the property JSON. */
	final String arrayKey;
	/** Required keys written as hex addresses by the exporter. */
	final String[] hexKeys;
	/** Required keys written as recorded (a string or small integer) by the exporter. */
	final String[] plainKeys;
	/** Keys carried only when present (a boolean only when true), in exporter order. */
	final String[] optionalKeys;

	BankingHintKind(String yamlKey, String property, String arrayKey, String[] hexKeys,
			String[] plainKeys, String[] optionalKeys) {
		this.yamlKey = yamlKey;
		this.property = property;
		this.arrayKey = arrayKey;
		this.hexKeys = hexKeys;
		this.plainKeys = plainKeys;
		this.optionalKeys = optionalKeys;
	}

	/** The property value for {@code gameDescriptor}, or null when it states no such list. */
	String format(JsonObject gameDescriptor, String source) {
		JsonObject banking = gameDescriptor == null ? null
				: gameDescriptor.getAsJsonObject("banking");
		if (banking == null || !banking.has(yamlKey)) {
			return null;
		}
		JsonObject out = new JsonObject();
		out.addProperty("source", source);
		out.add(arrayKey, banking.getAsJsonArray(yamlKey).deepCopy());
		return out.toString();
	}

	/** The recorded {@code source} path, or null when absent/unreadable ("" if it has none). */
	String source(Program program) {
		return DescriptorHints.hintSource(program, property);
	}

	/** True when the program carries a non-blank property for this kind. */
	boolean isRecorded(Program program) {
		String spec = DescriptorHints.programInfoString(program, property);
		return spec != null && !spec.isBlank();
	}

	/** The analyzer-side text for a property that cannot be read. */
	String malformedMessage(String detail) {
		return property + " is malformed (" + detail + "); no " + yamlKey + " hint applied";
	}

	/** The exporter-side text for a property that cannot be read. */
	String notCarriedMessage(String detail) {
		return property + " is malformed (" + detail + "); banking." + yamlKey + " not carried";
	}

	/**
	 * Reads the recorded list through {@code reader}: an empty list when the property is absent
	 * or blank; null (after reporting through {@code problems}) when it, or any entry, is
	 * malformed -- a hint that cannot be read is a hint that is not applied, never a guess.
	 */
	<T> List<T> read(Program program, List<String> problems, EntryReader<T> reader) {
		List<T> out = new ArrayList<>();
		String spec = DescriptorHints.programInfoString(program, property);
		if (spec == null || spec.isBlank()) {
			return out;
		}
		try {
			JsonObject root = JsonParser.parseString(spec).getAsJsonObject();
			for (JsonElement el : root.getAsJsonArray(arrayKey)) {
				out.add(reader.read(el.getAsJsonObject(), root));
			}
		}
		catch (RuntimeException e) {
			problems.add(malformedMessage(e.getMessage()));
			return null;
		}
		return out;
	}

	/** As {@link #read}, but a malformed property yields the immutable empty list. */
	<T> List<T> readOrEmpty(Program program, List<String> problems, EntryReader<T> reader) {
		List<T> out = read(program, problems, reader);
		return out == null ? List.of() : out;
	}
}
