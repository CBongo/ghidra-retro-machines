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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Program-info property names a loader publishes for downstream analyzers, and the codecs for
 * the banking-hint values stored under them (placement override, bank-identifying offsets,
 * save cells, bank stacks, paired fields, async entry points, fixed-after-init and resolved
 * initial-state values). Split out of the former {@code DescriptorSupport} (bead grm-rx1i.12).
 * The hint-kind table itself is {@link BankingHintKind}; this class holds the property
 * constants and the typed readers/formatters over it.
 */
final class DescriptorHints {

	private DescriptorHints() {
	}

	/**
	 * Program-info property where a loader that chose among several board descriptors
	 * (e.g. {@link NesRomLoader} via the iNES mapper registry) records the winning
	 * descriptor's resource path, so downstream analyzers ({@link BoardBankAnalyzer}
	 * subclasses) interpret the program with the same board the loader used.
	 */
	static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	/**
	 * Program-info property where a loader records a user-supplied bank-placement override:
	 * space-separated {@code window:bank} pairs pinning a mode-varying switchable window
	 * instance to hold PRG bank {@code N}. {@link BoardBankAnalyzer} consults it only where
	 * dataflow did not determine the bank at a reference site (flow always wins when it
	 * knows). Grammar and semantics: {@link #parsePlacementOverride}. Engine-generic
	 * (window -> bank), so the read side lives in the machine-independent analyzer.
	 */
	static final String PLACEMENT_OVERRIDE_PROPERTY = "Retro Machines.Placement Override";

	/**
	 * Program-info property where a loader records the <em>resolved</em> packed power-on bank
	 * state, as a decimal string (bead {@code grm-y0ml}). Written only when the descriptor's
	 * {@code banking.initial_state} contains at least one image-relative expression
	 * ({@code banking.initial_state_expr} in the {@code .map}), because only then is the
	 * literal in the {@code .map} an incomplete answer.
	 * <p>
	 * <b>Why a property.</b> An image-relative seed ({@code bank_5117: "(image_size >> 13) -
	 * 1"}) cannot be packed at build time -- the image size is a load-time fact -- and the
	 * analyzer side ({@code BoardModel.parse}) has no image size at all. The loader knows it,
	 * so the loader resolves it once and publishes the answer here, exactly as it publishes
	 * {@link #PLACEMENT_OVERRIDE_PROPERTY} and {@link #ASYNC_ENTRY_POINTS_PROPERTY}.
	 * <p>
	 * The read side degrades: a program imported before this property existed (or by a build
	 * without it) simply has no key, and the analyzer falls back to the {@code .map}'s literal
	 * {@code initial_state} -- which is the packed value of the literal fields with every
	 * expression field contributing 0, i.e. bit-for-bit the behaviour that shipped before.
	 */
	static final String INITIAL_STATE_PROPERTY = "Retro Machines.Initial State";

	/**
	 * Program-info property carrying this program's per-game identity, computed at import from
	 * the image bytes: {@code prg:<64 hex> file:<64 hex>} -- SHA-256 over the cartridge's
	 * program-ROM content only (the primary key; header and trainer excluded, so header rot
	 * does not change it) and SHA-256 over the whole file (the alias key, which is the same
	 * string {@code tools/banktest/realrom/manifest.tsv} pins its rows by).
	 * <p>
	 * Written whether or not any game descriptor matches, because the identity is a fact about
	 * the file rather than a resolution result: a user who later authors an overlay descriptor
	 * reads the key to write off this property. Grammar and semantics:
	 * {@link GameIdentities#parseGameIdentity}. Design: docs/per-game-descriptors-design.md section 2.
	 */
	static final String GAME_IDENTITY_PROPERTY = "Retro Machines.Game Identity";

	/**
	 * A Program Info string property, or null when the program does not carry it. Use this, not
	 * {@code getString(name, "")}: Ghidra's {@code Options.getString(name, default)} REGISTERS the
	 * option with that default, so a bare read would stamp an empty property onto every program
	 * that never had one (grm-hb6.5 tripped exactly this: an empty Game Identity on CBM imports).
	 */
	static String programInfoString(Program program, String name) {
		ghidra.framework.options.Options info =
			program.getOptions(Program.PROGRAM_INFO);
		return info.contains(name) ? info.getString(name, null) : null;
	}

	/**
	 * Program-info property where {@link GameDescriptorRegistry#resolve} records the resolved
	 * game descriptor's path, absent when nothing matched -- the title-tier counterpart of
	 * {@link #MAP_PATH_PROPERTY}.
	 * <p>
	 * Written by {@link NesRomLoader#load} (bead {@code grm-hb6.12}, first increment: curated
	 * only, resolved from {@link #GAME_IDENTITY_PROPERTY} over the bundled
	 * {@code machines/games/*.gmap} set). A user-writable overlay directory (bead
	 * {@code grm-hb6.2}) and runtime YAML (bead {@code grm-hb6.3}) remain future work; this
	 * property's value is unaffected by which source eventually resolved it.
	 */
	static final String GAME_DESCRIPTOR_PROPERTY = "Retro Machines.Game Descriptor";

	/**
	 * Program-info property listing the entry points a loader knows are reached
	 * <em>asynchronously</em> -- on this hardware family, the 6502 {@code NMI} and {@code IRQ}
	 * vector targets. Space-separated {@link Address#toString()} tokens (space-qualified, so
	 * they round-trip through {@code AddressFactory.getAddress}); absent or empty when the
	 * loader identified none.
	 * <p>
	 * <b>Why this is a property rather than a lookup.</b> {@link BoardBankAnalyzer} seeds every
	 * function entry with {@code banking.initial_state} <em>fully known</em>, which is sound
	 * only for an entry the machine reaches from reset. An interrupt fires from arbitrary
	 * mainline context, so the bank live on entry to its handler is whatever the interrupted
	 * code had -- unknown, not the initial state (bead grm-913). Which entries those are is a
	 * fact about the machine's vector table, which the loader already reads; the analyzer is
	 * machine-independent and must not re-derive it. Matching on the {@code NMI}/{@code IRQ}
	 * label names the loader writes would work today but couples the engine to a symbol string
	 * a user can rename.
	 */
	static final String ASYNC_ENTRY_POINTS_PROPERTY = "Retro Machines.Async Entry Points";

	/**
	 * Program-info property carrying the resolved game descriptor's
	 * {@code banking.bank_identifying_offsets} hint (bead grm-mej.7) from the loader, which
	 * resolves the descriptor, to {@link BoardBankAnalyzer}, which verifies each entry against
	 * the ROM-byte derivation before it may license anything
	 * ({@code BankMirrors.withMembershipHints}). JSON: {@code {"source": <descriptor path>,
	 * "offsets": [{address, shift, low, provenance}, ...]}}. Absent when the descriptor states
	 * no such hint. Same loader-publishes / analyzer-reads split as
	 * {@link #ASYNC_ENTRY_POINTS_PROPERTY}.
	 */
	static final String BANK_IDENTIFYING_HINTS_PROPERTY =
		"Retro Machines.Bank Identifying Hints";

	/**
	 * Program-info property carrying the resolved game descriptor's {@code banking.save_cells}
	 * hint (bead grm-mej.9): JSON {@code {"source": <descriptor path>, "cells": [{address,
	 * provenance}, ...]}}. Written by the loader, read at analysis time by
	 * {@link BoardBankAnalyzer} (so re-analysis picks it up) and handed to
	 * {@link SaveRestoreTrampolines}, which treats each cell as surviving a helper's inner call.
	 * Absent when the descriptor states none.
	 */
	static final String SAVE_CELLS_PROPERTY = "Retro Machines.Save Cells";

	/**
	 * Program-info property carrying the resolved game descriptor's {@code banking.switch_sites}
	 * hint (bead grm-hb6.4): JSON {@code {"source": <descriptor path>, "sites": [{addr,
	 * [block], [entry], [comment], provenance}, ...]}}. Written by the loader, read at analysis
	 * time by {@link BoardBankAnalyzer} and {@link BankDataflowEngine} (see
	 * {@link SwitchSiteHints}). Absent when the descriptor states none.
	 */
	static final String SWITCH_SITES_PROPERTY = "Retro Machines.Switch Sites";

	/**
	 * Program-info property carrying the game descriptor's {@code banking.bank_stacks} hint
	 * (bead grm-mej.10): JSON {@code {"source": ..., "stacks": [{pointer, slots, provenance}]}}.
	 * Read at analysis time by {@link BoardBankAnalyzer} and handed to {@link BankStackBrackets}.
	 */
	static final String BANK_STACKS_PROPERTY = "Retro Machines.Bank Stacks";

	/**
	 * Program-info property carrying the game descriptor's {@code banking.shadow_commits} hint
	 * (bead grm-hb6.26): JSON {@code {"source": ..., "commits": [{helper, cell, field,
	 * provenance}]}}. Read at analysis time by {@link BoardBankAnalyzer} and handed to
	 * {@link ShadowCommits}.
	 */
	static final String SHADOW_COMMITS_PROPERTY = "Retro Machines.Shadow Commits";

	/**
	 * Program-info property carrying the game descriptor's {@code banking.paired_fields} hint
	 * (bead grm-mej.10): JSON {@code {"source": ..., "pairs": [{high, low, offset,
	 * provenance}]}}.
	 */
	static final String PAIRED_FIELDS_PROPERTY = "Retro Machines.Paired Fields";

	/**
	 * Program-info property carrying the bit mask (decimal, in the board's packed state layout)
	 * of the state fields a game descriptor's {@code banking.fixed_after_init} hint (bead
	 * grm-mej.12) declares never change after initialization. Written by the loader, which
	 * resolves the descriptor and knows the board's field layout; read by
	 * {@link BankDataflowEngine}, which seeds asynchronous entries with exactly those bits known
	 * at the effective initial value. Absent (or 0) means no hint: async entries stay fully
	 * unknown (grm-913).
	 */
	static final String FIXED_AFTER_INIT_MASK_PROPERTY = "Retro Machines.Fixed After Init Mask";

	/**
	 * Program-info property carrying the iNES mapper number parsed from the cartridge header
	 * (bead {@code grm-3ppn}): a plain decimal string for an iNES 1.0/archaic header (e.g.
	 * {@code "4"}), or {@code "<mapper> (submapper <n>)"} when the header is NES 2.0, since NES
	 * 2.0 headers carry a submapper number that can select a materially different board variant
	 * under the same mapper number.
	 * <p>
	 * Written by {@link NesRomLoader#load} unconditionally -- a fact about the file, parsed
	 * before board resolution and independent of whether a board descriptor was found for it --
	 * so a rejected or unmapped mapper number is still visible on the (otherwise near-empty)
	 * program for troubleshooting. Recorded because board names are not memorable the way mapper
	 * numbers are; see {@link #BOARD_NAME_PROPERTY} for the human-readable counterpart.
	 * <p>
	 * <b>Deliberately NOT under the {@code "Retro Machines."} prefix</b> the machine-read
	 * properties above use (bead {@code grm-x5g2}). This one and
	 * {@link #BOARD_NAME_PROPERTY} exist to be <em>read by a person</em>, and
	 * {@code ProgramDB.getMetadata()} -- what the About/Info program dialogs display -- skips
	 * every Program Information option whose name contains {@link
	 * ghidra.framework.options.Options#DELIMITER} ("ignore second tier options"). Under the
	 * prefix they were written correctly and never shown.
	 */
	static final String INES_MAPPER_PROPERTY = "iNES Mapper";

	/**
	 * Program-info property carrying the resolved board descriptor's human name (bead
	 * {@code grm-3ppn}), e.g. {@code "NES MMC3 (iNES mapper 4)"} -- board descriptor {@code .map}
	 * {@code name} fields are conventionally written to already include the mapper number in
	 * parentheses (see any {@code data/machines/nes-*.map}), so this property does not need to
	 * concatenate {@link #INES_MAPPER_PROPERTY} itself to satisfy that half of the request; it
	 * simply publishes the name the board resolved to.
	 * <p>
	 * Written by {@link NesRomLoader#load} only when a board was resolved (unlike
	 * {@link #INES_MAPPER_PROPERTY}, there is no board name to publish when none matched).
	 */
	static final String BOARD_NAME_PROPERTY = "NES Board";

	/**
	 * Program-info property carrying the layout-mode value the bank analyzer LOCKED (bead
	 * {@code grm-dos9.6}): every mode write reached from reset agreed on it, and no write found
	 * afterwards contradicted it. A plain decimal string, e.g. {@code "2"} for cv3's MMC5 PRG mode 2.
	 * Written by {@link BankAnnotationAdapter#annotateModeLock} while the lock holds and REMOVED
	 * when no lock formed or it was rejected, so a stale value cannot survive a re-analysis.
	 * <p>
	 * Named for people, like {@link #BOARD_NAME_PROPERTY}: no {@code "Retro Machines."} prefix, so
	 * the About/Info program dialogs show it (owner request, 2026-10-11).
	 */
	static final String DETECTED_PRG_MODE_PROPERTY = "Detected PRG mode";

	/** One {@code window:bank} token: capture group 1 = window name, 2 = bank digits. The
	 *  separator is a colon, not '=': the headless {@code analyzeHeadless.bat} arg parser
	 *  (cmd.exe) splits values on '=', so an '='-based grammar can't be passed on Windows. */
	private static final Pattern PLACEMENT_PAIR = Pattern.compile("([A-Za-z0-9_]+):(\\d+)");

	/**
	 * Parses a placement-override spec -- space-separated {@code window:bank} pairs (e.g.
	 * {@code "W8000:5 WC000:3"}, read as "window W8000 holds PRG bank 5") -- into an
	 * insertion-ordered window-name -> bank map. Blank/null input yields an empty map.
	 * Throws {@link IllegalArgumentException} with a user-facing message on malformed syntax
	 * (bad token shape, out-of-range bank, or a repeated window). Window names and bank
	 * ranges are deliberately NOT validated here -- that needs the board descriptor and is
	 * the loader's job in {@code validateOptions}; this is the shared grammar both the loader
	 * (validate) and analyzer (read) go through.
	 */
	static Map<String, Integer> parsePlacementOverride(String spec) {
		Map<String, Integer> byWindow = new LinkedHashMap<>();
		if (spec == null || spec.isBlank()) {
			return byWindow;
		}
		for (String token : spec.trim().split("\\s+")) {
			Matcher m = PLACEMENT_PAIR.matcher(token);
			if (!m.matches()) {
				throw new IllegalArgumentException("malformed placement override '" + token +
					"'; expected window:bank (e.g. W8000:5)");
			}
			String window = m.group(1);
			int bank;
			try {
				bank = Integer.parseInt(m.group(2));
			}
			catch (NumberFormatException e) {
				throw new IllegalArgumentException(
					"placement override '" + token + "': bank number out of range");
			}
			if (byWindow.putIfAbsent(window, bank) != null) {
				throw new IllegalArgumentException(
					"placement override names window '" + window + "' more than once");
			}
		}
		return byWindow;
	}

	// ------------------------------------------------------------------
	// Game-descriptor bank-identifying membership hints (bead grm-mej.7)
	// ------------------------------------------------------------------

	/**
	 * The membership hints {@code program}'s loader recorded, or an empty list. A malformed
	 * property, or a malformed entry, is reported through {@code problems} and contributes
	 * nothing -- a hint that cannot be read is a hint that is not applied, never a guess.
	 */
	static List<BankMirrors.MembershipHint> parseMembershipHints(Program program,
			List<String> problems) {
		return BankingHintKind.BANK_IDENTIFYING_OFFSETS.readOrEmpty(program, problems,
			(o, root) -> {
				String source = root.get("source").getAsString();
				int shift = o.get("shift").getAsInt();
				return new BankMirrors.MembershipHint(o.get("address").getAsLong(), shift,
					o.get("low").getAsInt(), o.has("bias") ? o.get("bias").getAsInt() : 0,
					o.has("modulus_bits") ? o.get("modulus_bits").getAsInt() : shift, source);
			});
	}

	// ------------------------------------------------------------------
	// Game-descriptor save cells (bead grm-mej.9)
	// ------------------------------------------------------------------

	/**
	 * The save-cell addresses {@code program}'s loader recorded (CPU addresses, base space), or
	 * an empty set. A malformed property or entry is reported through {@code problems} and
	 * contributes nothing -- a hint that cannot be read is a hint that is not applied.
	 */
	static Set<Long> parseSaveCells(Program program, List<String> problems) {
		List<Long> cells = BankingHintKind.SAVE_CELLS.read(program, problems,
			(o, root) -> o.get("address").getAsLong());
		return cells == null ? Set.of() : new java.util.LinkedHashSet<>(cells);
	}

	// ------------------------------------------------------------------
	// Game-descriptor RAM bank stacks and paired fields (bead grm-mej.10)
	// ------------------------------------------------------------------

	/** A RAM bank stack: the pointer cell and the slot-array base, CPU addresses. */
	record BankStack(long pointer, long slots) {
	}

	/** {@code high} field always equals {@code low} field's bank plus {@code offset}. */
	record PairedFields(String high, String low, int offset) {
	}

	/**
	 * The {@code source} path recorded in the hint property {@code property}, or null when the
	 * property is absent, blank or unreadable ("" when it carries no source).
	 */
	static String hintSource(Program program, String property) {
		String spec = programInfoString(program, property);
		if (spec == null || spec.isBlank()) {
			return null;
		}
		try {
			JsonObject root = JsonParser.parseString(spec).getAsJsonObject();
			return root.has("source") ? root.get("source").getAsString() : "";
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	/** The {@link #BANK_IDENTIFYING_HINTS_PROPERTY} value, or null when the descriptor states none. */
	static String formatMembershipHints(JsonObject gameDescriptor, String source) {
		return BankingHintKind.BANK_IDENTIFYING_OFFSETS.format(gameDescriptor, source);
	}

	/** The {@link #SWITCH_SITES_PROPERTY} value, or null when the descriptor states none. */
	static String formatSwitchSites(JsonObject gameDescriptor, String source) {
		return BankingHintKind.SWITCH_SITES.format(gameDescriptor, source);
	}

	/** The {@link #SHADOW_COMMITS_PROPERTY} value, or null when the descriptor states none. */
	static String formatShadowCommits(JsonObject gameDescriptor, String source) {
		return BankingHintKind.SHADOW_COMMITS.format(gameDescriptor, source);
	}

	/** The recorded bank stacks, or empty; malformed input is reported and contributes nothing. */
	static List<BankStack> parseBankStacks(Program program, List<String> problems) {
		return BankingHintKind.BANK_STACKS.readOrEmpty(program, problems,
			(o, root) -> new BankStack(o.get("pointer").getAsLong(), o.get("slots").getAsLong()));
	}

	/** The recorded field pairings, or empty; malformed input is reported and ignored. */
	static List<PairedFields> parsePairedFields(Program program, List<String> problems) {
		return BankingHintKind.PAIRED_FIELDS.readOrEmpty(program, problems,
			(o, root) -> new PairedFields(o.get("high").getAsString(), o.get("low").getAsString(),
				o.get("offset").getAsInt()));
	}

	// ------------------------------------------------------------------
	// Asynchronous entry points (bead grm-913)
	// ------------------------------------------------------------------

	/**
	 * Renders {@code addrs} as the {@link #ASYNC_ENTRY_POINTS_PROPERTY} value. Order is the
	 * caller's; duplicates are the caller's problem (the read side is a set, so they are
	 * harmless).
	 */
	static String formatAsyncEntryPoints(Collection<Address> addrs) {
		return addrs.stream().map(Address::toString).collect(Collectors.joining(" "));
	}

	/**
	 * The addresses {@code program}'s loader recorded as asynchronously reached, or an empty
	 * set when the property is absent, blank, or naming something this program's address
	 * factory cannot resolve.
	 * <p>
	 * Unresolvable tokens are skipped rather than raised: this property is an optimization of
	 * soundness, not a correctness precondition, and a program whose blocks moved since import
	 * must still analyze. Skipping costs the weakened seed for that one entry -- the exact
	 * behavior of every program written before this property existed.
	 */
	static Set<Address> parseAsyncEntryPoints(Program program) {
		String spec = program.getOptions(Program.PROGRAM_INFO)
				.getString(ASYNC_ENTRY_POINTS_PROPERTY, null);
		Set<Address> addrs = new LinkedHashSet<>();
		if (spec == null || spec.isBlank()) {
			return addrs;
		}
		for (String token : spec.trim().split("\\s+")) {
			Address addr = program.getAddressFactory().getAddress(token);
			if (addr != null) {
				addrs.add(addr);
			}
		}
		return addrs;
	}

	/**
	 * The mask the loader published in {@link #FIXED_AFTER_INIT_MASK_PROPERTY}, or 0 when the
	 * property is absent, blank, or not a number (ignored, not raised: 0 is the pre-hint
	 * behaviour).
	 */
	static int readFixedAfterInitMask(Program program) {
		String value = program.getOptions(Program.PROGRAM_INFO)
				.getString(FIXED_AFTER_INIT_MASK_PROPERTY, null);
		if (value == null || value.isBlank()) {
			return 0;
		}
		try {
			return Integer.parseInt(value.trim());
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	/**
	 * The resolved packed power-on state a loader published in
	 * {@link #INITIAL_STATE_PROPERTY}, or null when the property is absent, blank, or not a
	 * number (a hand-edited value is ignored, not raised -- the caller's fallback is the
	 * descriptor's own literal, which is always available).
	 */
	static Integer readResolvedInitialState(Program program) {
		String value = program.getOptions(Program.PROGRAM_INFO)
				.getString(INITIAL_STATE_PROPERTY, null);
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			return Integer.valueOf(value.trim());
		}
		catch (NumberFormatException e) {
			return null;
		}
	}
}
