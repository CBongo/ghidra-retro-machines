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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.InvalidAddressException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.AssertException;

/**
 * The system-neutral half of the descriptor-driven loader stack: everything a loader
 * does with a compiled machine descriptor (`machines/&lt;id&gt;.map` JSON + companion
 * `.gdt` type archive) that is not specific to any one system. Extracted from
 * {@link C64PrgLoader} so the NES loader (and later systems) consume descriptors
 * through the same code paths — none of these helpers knows any hardware fact; they
 * only interpret the descriptor schema (docs/MAP_FORMAT.md).
 */
final class DescriptorSupport {

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
	 * Program-info property carrying this program's per-game identity, computed at import from
	 * the image bytes: {@code prg:<64 hex> file:<64 hex>} -- SHA-256 over the cartridge's
	 * program-ROM content only (the primary key; header and trainer excluded, so header rot
	 * does not change it) and SHA-256 over the whole file (the alias key, which is the same
	 * string {@code tools/banktest/realrom/manifest.tsv} pins its rows by).
	 * <p>
	 * Written whether or not any game descriptor matches, because the identity is a fact about
	 * the file rather than a resolution result: a user who later authors an overlay descriptor
	 * reads the key to write off this property. Grammar and semantics:
	 * {@link #parseGameIdentity}. Design: docs/per-game-descriptors-design.md section 2.
	 */
	static final String GAME_IDENTITY_PROPERTY = "Retro Machines.Game Identity";

	/**
	 * Program-info property where a game-descriptor resolver records the resolved descriptor's
	 * path, absent when nothing matched -- the title-tier counterpart of
	 * {@link #MAP_PATH_PROPERTY}.
	 * <p>
	 * <b>Declared, never written (bead grm-hb6.1).</b> Nothing in this extension resolves a game
	 * descriptor yet; the resolver and its writer are beads grm-hb6.2/grm-hb6.3. The constant
	 * exists now so the property NAME is fixed alongside the {@link #GAME_IDENTITY_PROPERTY} it
	 * keys off of, and so the harness scripts that re-declare these names as literals
	 * (tools/banktest/RealRomDump.java) have one place to agree with.
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

	/** One {@code window:bank} token: capture group 1 = window name, 2 = bank digits. The
	 *  separator is a colon, not '=': the headless {@code analyzeHeadless.bat} arg parser
	 *  (cmd.exe) splits values on '=', so an '='-based grammar can't be passed on Windows. */
	private static final Pattern PLACEMENT_PAIR = Pattern.compile("([A-Za-z0-9_]+):(\\d+)");

	/** One {@code prg:}/{@code file:} token of the identity grammar: capture group 1 = key,
	 *  2 = the 64 hex digits. Colon, not '=', for the reason recorded at
	 *  {@link #PLACEMENT_PAIR} -- every grammar in this tier inherits that rule. */
	private static final Pattern IDENTITY_PAIR = Pattern.compile("(prg|file):([0-9a-fA-F]{64})");

	private DescriptorSupport() {
	}

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

	// ------------------------------------------------------------------
	// Per-game identity (bead grm-hb6.1)
	// ------------------------------------------------------------------

	/**
	 * A program's per-game identity: the program-ROM digest (the primary key, computed over
	 * cartridge content with container headers excluded) and the whole-file digest (the alias
	 * key), each 64 hex characters. Both are normalized to lowercase on construction, so two
	 * identities parsed from differently-cased text compare equal -- ROM managers print
	 * uppercase and a hand-authored descriptor will paste whatever the user had.
	 */
	record GameIdentity(String prgSha256, String fileSha256) {

		GameIdentity {
			prgSha256 = requireSha256(prgSha256, "prg");
			fileSha256 = requireSha256(fileSha256, "file");
		}

		private static String requireSha256(String digest, String key) {
			if (digest == null || !digest.matches("[0-9a-fA-F]{64}")) {
				throw new IllegalArgumentException(
					"game identity '" + key + "' must be 64 hex digits, got: " + digest);
			}
			return digest.toLowerCase();
		}

		/** The {@link #GAME_IDENTITY_PROPERTY} value: {@code prg:<hex> file:<hex>}. */
		String toPropertyValue() {
			return "prg:" + prgSha256 + " file:" + fileSha256;
		}
	}

	/**
	 * Parses a {@link #GAME_IDENTITY_PROPERTY} value -- whitespace-separated
	 * {@code prg:<64 hex>} and {@code file:<64 hex>} tokens, order-independent, both required.
	 * <p>
	 * Returns {@code null} for null/blank input, deliberately NOT mirroring
	 * {@link #parsePlacementOverride}'s empty-collection-on-blank: "this program has no
	 * identity" is a distinct state from "an identity whose halves are empty", and only the
	 * former can occur (a loader either writes both halves or writes nothing). Throws
	 * {@link IllegalArgumentException} on anything else malformed -- an unknown key, a repeated
	 * key, a missing half, or a value that is not exactly 64 hex digits.
	 */
	static GameIdentity parseGameIdentity(String spec) {
		if (spec == null || spec.isBlank()) {
			return null;
		}
		String prg = null;
		String file = null;
		for (String token : spec.trim().split("\\s+")) {
			Matcher m = IDENTITY_PAIR.matcher(token);
			if (!m.matches()) {
				throw new IllegalArgumentException("malformed game identity '" + token +
					"'; expected prg:<64 hex> or file:<64 hex>");
			}
			boolean isPrg = "prg".equals(m.group(1));
			if ((isPrg ? prg : file) != null) {
				throw new IllegalArgumentException(
					"game identity names '" + m.group(1) + "' more than once");
			}
			if (isPrg) {
				prg = m.group(2);
			}
			else {
				file = m.group(2);
			}
		}
		if (prg == null || file == null) {
			throw new IllegalArgumentException(
				"game identity needs both prg: and file: digests, got: " + spec.trim());
		}
		return new GameIdentity(prg, file);
	}

	/**
	 * SHA-256 of {@code length} bytes read from {@code in} ({@code length < 0} reads to EOF), as
	 * 64 lowercase hex characters. Does not close {@code in}; throws {@link IOException} if EOF
	 * arrives before {@code length} bytes were read.
	 * <p>
	 * Plain {@link MessageDigest} rather than {@code generic.hash.HashUtilities} (which is on
	 * the classpath and is what Ghidra's own {@code setExecutableSHA256} goes through): this is
	 * the one piece of the identity path a pure-JUnit test must exercise with no Ghidra class on
	 * the stack, and the hex casing is then ours to state rather than to inherit from a Ghidra
	 * internal. Agreement with {@code Program.getExecutableSHA256()} -- and so with
	 * {@code tools/banktest/realrom/manifest.tsv} -- is asserted by a banktest criterion rather
	 * than assumed from a shared implementation.
	 */
	static String sha256Hex(InputStream in, long length) throws IOException {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			// SHA-256 is a required algorithm on every conformant JRE
			throw new AssertException("SHA-256 unavailable", e);
		}
		byte[] buf = new byte[8192];
		long remaining = length;
		while (remaining != 0) {
			int want = remaining < 0 ? buf.length : (int) Math.min(buf.length, remaining);
			int got = in.read(buf, 0, want);
			if (got < 0) {
				if (remaining > 0) {
					throw new IOException(
						"unexpected end of data: " + remaining + " bytes short of " + length);
				}
				break;
			}
			digest.update(buf, 0, got);
			if (remaining > 0) {
				remaining -= got;
			}
		}
		StringBuilder hex = new StringBuilder(64);
		for (byte b : digest.digest()) {
			hex.append(Character.forDigit((b >> 4) & 0xF, 16));
			hex.append(Character.forDigit(b & 0xF, 16));
		}
		return hex.toString();
	}

	// ------------------------------------------------------------------
	// Data types
	// ------------------------------------------------------------------

	static void applyStructType(Program program, AddressSpace baseSpace,
			FileDataTypeManager gdtMgr, JsonObject withTypeAndStart, String source,
			MessageLog log) {

		String typeName = withTypeAndStart.get("type").getAsString();
		long start = withTypeAndStart.get("start").getAsLong();

		DataType archiveType = gdtMgr.getDataType(CategoryPath.ROOT, typeName);
		if (archiveType == null) {
			log.appendMsg("Data type '" + typeName + "' not found in " + source + " archive; skipping");
			return;
		}

		DataTypeManager programDtm = program.getDataTypeManager();
		DataType resolved = programDtm.resolve(archiveType, DataTypeConflictHandler.DEFAULT_HANDLER);

		Address addr = baseSpace.getAddress(start);
		try {
			DataUtilities.createData(program, addr, resolved, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (Exception e) {
			log.appendMsg(
				"Failed to apply data type '" + typeName + "' at 0x" + Long.toHexString(start) +
					": " + e.getMessage());
		}
	}

	// ------------------------------------------------------------------
	// Symbols
	// ------------------------------------------------------------------

	/**
	 * Applies one {@code symbols[]} set: labels every entry, EOL-comments the ones that
	 * carry comments, and hands {@code kind: entry} addresses to {@code functionMarker}
	 * (the loader's {@code markAsFunction}, which is protected and cannot be called from
	 * here) after registering them as external entry points.
	 */
	static void applySymbolSet(Program program, AddressSpace baseSpace, JsonObject set,
			BiConsumer<String, Address> functionMarker, MessageLog log) {

		JsonArray entries = set.getAsJsonArray("entries");
		for (JsonElement ee : entries) {
			JsonObject entry = ee.getAsJsonObject();
			long addr = entry.get("addr").getAsLong();
			String name = entry.get("name").getAsString();
			String kind = entry.has("kind") ? entry.get("kind").getAsString() : "entry";
			String comment = entry.has("comment") ? entry.get("comment").getAsString() : null;

			Address symAddr = baseSpace.getAddress(addr);
			try {
				AnnotationGuard.applyLabel(program, symAddr, name, SourceType.IMPORTED);
				if (kind.equals("entry")) {
					program.getSymbolTable().addExternalEntryPoint(symAddr);
					functionMarker.accept(name, symAddr);
				}
				if (comment != null) {
					// AnnotationGuard.addComment (grm-mej.4): descriptor-applied comments must
					// never clobber a USER_DEFINED one. Comments carry no SourceType, so the
					// guard uses the append-only proxy documented on that method; the comment
					// text itself is the idempotence marker, since (unlike the analyzer's
					// "bank ->" annotations) there is no shared prefix across descriptor
					// comments to key on.
					AnnotationGuard.addComment(program.getListing(), symAddr, CommentType.EOL,
						comment, comment);
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to create symbol '" + name + "' at 0x" +
					Long.toHexString(addr) + ": " + e.getMessage());
			}
		}
	}

	// ------------------------------------------------------------------
	// Bank-state field parsing (banking.state / initial_state)
	// ------------------------------------------------------------------

	/**
	 * One {@code banking.state} field: its name, LSB position, and bit width within the
	 * packed state int. Fields pack LSB-first in declaration order (mirrors
	 * {@code MapCompiler.packState} at build time and {@code BoardDescriptorModel.FieldSpec}
	 * at analysis time -- all three must agree on this layout).
	 */
	record StateField(String name, int lsb, int width) {

		long mask() {
			return (1L << width) - 1;
		}

		/** This field's value as packed into {@code packedState}. */
		long valueIn(long packedState) {
			return (packedState >> lsb) & mask();
		}
	}

	/**
	 * Parses {@code banking.state} into its ordered field tuple, LSB-first. Returns an
	 * empty list when the descriptor has no {@code banking} section (or no {@code state}).
	 */
	static List<StateField> parseStateFields(JsonObject map) {
		List<StateField> fields = new ArrayList<>();
		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("state")) {
			return fields;
		}
		int lsb = 0;
		for (JsonElement fe : banking.getAsJsonArray("state")) {
			JsonObject f = fe.getAsJsonObject();
			String name = f.get("name").getAsString();
			int bits = f.get("bits").getAsInt();
			fields.add(new StateField(name, lsb, bits));
			lsb += bits;
		}
		return fields;
	}

	/**
	 * {@code banking.initial_state}, the packed power-on state -- null when the descriptor
	 * has no {@code banking} section or omits {@code initial_state}.
	 */
	static Long initialState(JsonObject map) {
		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("initial_state")) {
			return null;
		}
		return banking.get("initial_state").getAsLong();
	}

	/** Finds a field by name in a {@link #parseStateFields} result, or null. */
	static StateField findField(List<StateField> fields, String name) {
		for (StateField f : fields) {
			if (f.name().equals(name)) {
				return f;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Window-plan normalization (memory.windows[] + memory.layouts[])
	// ------------------------------------------------------------------

	/**
	 * One window instance in the normalized flat plan produced by {@link #planWindows}.
	 * {@code expr} is null for an enumerated-{@code occupants:} window (C64-style; not
	 * supported by the computed-window loaders -- callers should skip it and log).
	 * {@code modeValue} is null for a mode-invariant window (a top-level
	 * {@code memory.windows[]} entry, or a layout window hoisted because every layout
	 * defines it identically); otherwise it is this instance's {@code when:} value of
	 * {@link LayoutPlan#modeField()}.
	 */
	record PlannedWindow(String name, long start, long end, String expr, String onWrite,
			Integer modeValue) {

		long length() {
			return end - start + 1;
		}
	}

	/**
	 * The normalized result of {@link #planWindows}: {@code invariant} windows are placed
	 * once, unconditionally; {@code varying} windows are one instance per
	 * {@code (name, modeValue)} pair (callers group by name to realize a window's full set
	 * of per-mode instances together, the way {@link #placeHomeInBaseWindow} expects one
	 * candidate list per window). {@code modeField} is the single banking.state field every
	 * layout's {@code when:} keys off of, or null when the descriptor has no
	 * {@code memory.layouts} (or they were ignored -- see {@link #planWindows}), in which
	 * case {@code varying} is always empty.
	 */
	record LayoutPlan(String modeField, List<PlannedWindow> invariant, List<PlannedWindow> varying) {}

	/**
	 * Normalizes a descriptor's window set -- {@code memory.windows[]} (always
	 * mode-invariant) plus {@code memory.layouts[]} (mode-dependent window sets), when
	 * present -- into a flat plan both loaders and (a later bead) the bank analyzer can
	 * consume without re-walking the JSON.
	 *
	 * <p>Runtime constraint, conservative by design (logs and ignores {@code layouts}
	 * entirely rather than guessing): every layout's {@code when:} must name exactly one
	 * field, and it must be the <em>same</em> field across every layout (the "mode field").
	 * Duplicate {@code when:} values across layouts are likewise rejected. Both MMC1 and
	 * MMC3 satisfy this.
	 *
	 * <p>Invariant hoisting: a window name that appears in <em>every</em> layout with an
	 * identical compiled definition (same start/end/maps/on_write -- compared as JSON) is
	 * mode-invariant and is folded into {@link LayoutPlan#invariant()} exactly like a
	 * top-level window (e.g. MMC3's WA000/WE000, which are unchanged across both
	 * {@code prg_mode} layouts). Every other layout window is mode-varying and lands in
	 * {@link LayoutPlan#varying()}.
	 */
	static LayoutPlan planWindows(JsonObject map, MessageLog log, String source) {
		List<PlannedWindow> invariant = new ArrayList<>();
		List<PlannedWindow> varying = new ArrayList<>();

		JsonArray topWindows = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
		for (JsonElement we : topWindows) {
			invariant.add(toPlannedWindow(we.getAsJsonObject(), null));
		}

		if (!map.has("layouts")) {
			return new LayoutPlan(null, invariant, varying);
		}

		String modeField = null;
		List<JsonObject> layoutObjs = new ArrayList<>();
		Set<Integer> seenValues = new LinkedHashSet<>();
		for (JsonElement le : map.getAsJsonArray("layouts")) {
			JsonObject layout = le.getAsJsonObject();
			JsonObject when = layout.getAsJsonObject("when");
			if (when == null || when.entrySet().size() != 1) {
				log.appendMsg(source, "memory.layouts[].when must name exactly one field; " +
					"ignoring memory.layouts[] entirely");
				return new LayoutPlan(null, invariant, varying);
			}
			Map.Entry<String, JsonElement> cond = when.entrySet().iterator().next();
			if (modeField == null) {
				modeField = cond.getKey();
			}
			else if (!modeField.equals(cond.getKey())) {
				log.appendMsg(source, "memory.layouts[] mix mode fields ('" + modeField +
					"' vs '" + cond.getKey() + "'); ignoring memory.layouts[] entirely");
				return new LayoutPlan(null, invariant, varying);
			}
			if (!seenValues.add(cond.getValue().getAsInt())) {
				log.appendMsg(source, "memory.layouts[] has a duplicate when: " + modeField +
					"=" + cond.getValue().getAsInt() + "; ignoring memory.layouts[] entirely");
				return new LayoutPlan(null, invariant, varying);
			}
			layoutObjs.add(layout);
		}

		Map<String, List<JsonObject>> byName = new LinkedHashMap<>();
		for (JsonObject layout : layoutObjs) {
			for (JsonElement lwe : layout.getAsJsonArray("windows")) {
				JsonObject w = lwe.getAsJsonObject();
				byName.computeIfAbsent(w.get("name").getAsString(), k -> new ArrayList<>()).add(w);
			}
		}
		for (Map.Entry<String, List<JsonObject>> entry : byName.entrySet()) {
			List<JsonObject> defs = entry.getValue();
			if (defs.size() == layoutObjs.size() && allIdentical(defs)) {
				invariant.add(toPlannedWindow(defs.get(0), null));
				continue;
			}
			for (JsonObject layout : layoutObjs) {
				int modeValue = layout.getAsJsonObject("when").get(modeField).getAsInt();
				for (JsonElement lwe : layout.getAsJsonArray("windows")) {
					JsonObject w = lwe.getAsJsonObject();
					if (w.get("name").getAsString().equals(entry.getKey())) {
						varying.add(toPlannedWindow(w, modeValue));
					}
				}
			}
		}
		return new LayoutPlan(modeField, invariant, varying);
	}

	private static boolean allIdentical(List<JsonObject> defs) {
		JsonObject first = defs.get(0);
		for (int i = 1; i < defs.size(); i++) {
			if (!first.equals(defs.get(i))) {
				return false;
			}
		}
		return true;
	}

	private static PlannedWindow toPlannedWindow(JsonObject w, Integer modeValue) {
		String name = w.get("name").getAsString();
		long start = w.get("start").getAsLong();
		long end = w.has("end") ? w.get("end").getAsLong()
				: start + w.get("size").getAsLong() - 1;
		String expr = w.has("maps") ? w.getAsJsonObject("maps").get("expr").getAsString() : null;
		String onWrite = w.has("on_write") ? w.get("on_write").getAsString() : null;
		return new PlannedWindow(name, start, end, expr, onWrite, modeValue);
	}

	/**
	 * The bank values each planned window can actually be placed at, for an image of
	 * {@code imageSize} bytes: window name -> the sorted set of {@code banking.state} field
	 * values whose {@code maps:} expression lands a whole window inside the image. This is
	 * the legal bank set of a placement override (bead grm-n5f), and it is deliberately
	 * derived from the same three inputs the loaders' realization loops use -- the window's
	 * own compiled expression, its own length, and the image size -- rather than from any
	 * container-level "bank" unit.
	 * <p>
	 * Why not divide the image size by a fixed unit: a bank value is a <em>field</em> value
	 * fed to the expression, and neither the field's unit nor the window's length is a
	 * property of the container. MMC3's windows are 8 KiB, so a 32 KiB image has four banks
	 * where the iNES header counts two 16 KiB ones; MMC1's mode-0 window is 32 KiB wide but
	 * its expression ({@code (prg_bank >> 1) * 0x8000}) still takes bank values in 16 KiB
	 * units. Evaluating the expression over the field's whole value range and keeping the
	 * in-range results answers both without special-casing either.
	 * <p>
	 * Every planned window name is a key, so callers can tell an unknown window from one
	 * with no placeable bank. The value is empty when the window has no bank to place at
	 * all: enumerated occupants (no expression), a fixed expression (every layout of it
	 * evaluates without a field), or an expression this code cannot resolve to exactly one
	 * declared field -- the same three cases the loaders' realization loops skip. Values are
	 * the union across a mode-varying window's per-layout instances, since a bank is legal
	 * if <em>some</em> reachable mode can hold it.
	 */
	static Map<String, NavigableSet<Integer>> placeableBanks(JsonObject map, long imageSize,
			MessageLog log, String source) {

		LayoutPlan plan = planWindows(map, log, source);
		List<StateField> fields = parseStateFields(map);
		List<PlannedWindow> all = new ArrayList<>(plan.invariant());
		all.addAll(plan.varying());

		Map<String, NavigableSet<Integer>> byWindow = new LinkedHashMap<>();
		for (PlannedWindow pw : all) {
			NavigableSet<Integer> banks =
				byWindow.computeIfAbsent(pw.name(), k -> new TreeSet<>());
			if (pw.expr() == null) {
				continue; // enumerated occupants: no bank values at all
			}
			try {
				DescriptorExpressions.evalConstantExpr(pw.expr(), imageSize, pw.length());
				continue; // fixed instance: nothing to place a bank into
			}
			catch (IllegalArgumentException e) {
				// falls through: bank-state-dependent, like the loaders' realization loops
			}
			Set<String> exprFields = DescriptorExpressions.referencedFields(pw.expr());
			StateField field = exprFields.size() == 1
					? findField(fields, exprFields.iterator().next())
					: null;
			if (field == null) {
				continue; // not resolvable to one declared field; the loader skips it too
			}
			for (long v = 0; v < (1L << field.width()); v++) {
				long srcOffset = DescriptorExpressions.evalExpr(pw.expr(), imageSize, pw.length(),
					Map.of(field.name(), v));
				if (srcOffset >= 0 && srcOffset + pw.length() <= imageSize) {
					banks.add((int) v);
				}
			}
		}
		return byWindow;
	}

	// ------------------------------------------------------------------
	// Home-in-base window placement
	// ------------------------------------------------------------------

	/**
	 * One way to materialize a named candidate occupying a computed window: given
	 * whether it is the home candidate, creates whatever block(s) (if any) it needs
	 * and returns the representative {@link MemoryBlock}, or {@code null} if it
	 * created none (legal -- e.g. an io-kind occupant that only carves subregions,
	 * or a candidate skipped for a loader-specific reason).
	 */
	@FunctionalInterface
	interface WindowCandidate {
		MemoryBlock place(Program program, AddressSpace baseSpace, boolean isHome, MessageLog log);
	}

	/** A named candidate occupant/bank of a computed window, paired with how to place it. */
	record NamedCandidate(String name, WindowCandidate candidate) {}

	/**
	 * Shared "home-in-base" window placement policy used by both banked loaders: of
	 * {@code candidates} occupying one computed window, the one named
	 * {@code homeName} is placed non-overlay (it lives directly in {@code baseSpace},
	 * so references resolve there by default); every other candidate is placed as an
	 * overlay. If no candidate's name equals {@code homeName} (e.g. the home bank
	 * fell out of the image's range), nothing is treated as home -- callers may log
	 * that themselves before calling, since the exact message differs by loader.
	 *
	 * <p>Loader-specific concerns -- which candidates exist, their content, and any
	 * bookkeeping the caller needs about the home candidate (e.g. NES's
	 * {@code PlacedWindow} list) -- stay in the loaders' {@link WindowCandidate}
	 * closures and surrounding code; this helper only owns the placement decision.
	 */
	static void placeHomeInBaseWindow(Program program, AddressSpace baseSpace,
			List<NamedCandidate> candidates, String homeName, MessageLog log) {
		for (NamedCandidate c : candidates) {
			boolean isHome = c.name().equals(homeName);
			c.candidate().place(program, baseSpace, isHome, log);
		}
	}

	// ------------------------------------------------------------------
	// Non-home-bank overlay naming
	// ------------------------------------------------------------------

	/**
	 * Naming convention for a computed window's non-home overlay blocks:
	 * {@code <windowName>_B<bankValue>} for a mode-invariant switchable window (the
	 * original, single-mode form), extended by mode-dependent-layout support (bead
	 * grm-aqf) with two mode-qualified forms: {@code <windowName>_M<modeValue>} for a
	 * mode-varying <em>fixed</em> window's non-home layout instance, and
	 * {@code <windowName>_M<modeValue>_B<bankValue>} for a mode-varying
	 * <em>switchable</em> window's non-home (layout, bank) instance. Used both when a
	 * loader creates an instance's overlay block at load time and when an analyzer later
	 * needs to resolve a bank/mode value back out of an overlay {@link AddressSpace}'s
	 * name.
	 *
	 * <p>The block name also becomes the overlay {@link AddressSpace}'s name --
	 * {@code MemoryBlockUtils} names the overlay space after the block when
	 * {@code isOverlay=true} -- empirically confirmed unmangled (tools/banktest
	 * checkNesBanktest N3, bead grm-5tl.17): {@code AddressSpace.getName()} equals
	 * this exact string, so callers like {@link BoardBankAnalyzer}'s
	 * {@code addOverlayRef()} can look the space up by {@code "<window>_B<bank>"}
	 * with no separate name-mapping table.
	 *
	 * <p><b>Naming-contract caveat:</b> the three suffix forms ({@code _B<n>},
	 * {@code _M<n>}, {@code _M<n>_B<n>}) are told apart purely by string shape (digits
	 * after {@code _B} / {@code _M}, an optional {@code _B} segment after the mode
	 * digits). A window name that itself ends in something shaped like {@code _M3} or
	 * {@code _B2} would be ambiguous with these suffixes and must be avoided by
	 * descriptor authors; none of the shipped or sketch descriptors do this.
	 */
	static final class OverlayNaming {
		private OverlayNaming() {
		}

		/** Builds the {@code <windowName>_B<bankValue>} name for a non-home bank overlay
		 *  of a mode-invariant switchable window. */
		static String bankBlockName(String windowName, int bankValue) {
			return windowName + "_B" + bankValue;
		}

		/**
		 * Parses a bank value back out of an overlay space name, given the owning
		 * window's name. Returns {@code null} if {@code spaceName} does not start
		 * with {@code "<windowName>_B"} or the remainder is not all decimal digits
		 * (e.g. a differently-named overlay space, such as a C64 occupant overlay, or
		 * one of the {@code _M...} mode-qualified forms below).
		 */
		static Integer parseBankValue(String windowName, String spaceName) {
			String prefix = windowName + "_B";
			if (!spaceName.startsWith(prefix)) {
				return null;
			}
			return parseDigits(spaceName.substring(prefix.length()));
		}

		/** Builds the {@code <windowName>_M<modeValue>} name for a mode-varying
		 *  <em>fixed</em> window's non-home layout instance. */
		static String modeBlockName(String windowName, int modeValue) {
			return windowName + "_M" + modeValue;
		}

		/**
		 * Parses a mode value back out of an overlay space name for a mode-varying
		 * fixed window, given the owning window's name. Returns {@code null} if
		 * {@code spaceName} does not start with {@code "<windowName>_M"} or the
		 * remainder is not all decimal digits -- in particular, a
		 * {@code "<windowName>_M<m>_B<v>"} space (see {@link #modeBankBlockName})
		 * fails to parse here because its remainder contains {@code "_B"}.
		 */
		static Integer parseModeValue(String windowName, String spaceName) {
			String prefix = windowName + "_M";
			if (!spaceName.startsWith(prefix)) {
				return null;
			}
			return parseDigits(spaceName.substring(prefix.length()));
		}

		/** A parsed {@code <windowName>_M<mode>_B<bank>} overlay name's (mode, bank)
		 *  pair; see {@link #modeBankBlockName} / {@link #parseModeBankValue}. */
		record ModeBank(int mode, int bank) {}

		/** Builds the {@code <windowName>_M<modeValue>_B<bankValue>} name for a
		 *  mode-varying <em>switchable</em> window's non-home (layout, bank) instance. */
		static String modeBankBlockName(String windowName, int modeValue, int bankValue) {
			return windowName + "_M" + modeValue + "_B" + bankValue;
		}

		/**
		 * Parses the (mode, bank) pair back out of a {@code "<windowName>_M<m>_B<v>"}
		 * overlay space name, given the owning window's name. Returns {@code null} if
		 * {@code spaceName} does not have exactly that shape (both {@code <m>} and
		 * {@code <v>} all decimal digits).
		 */
		static ModeBank parseModeBankValue(String windowName, String spaceName) {
			String prefix = windowName + "_M";
			if (!spaceName.startsWith(prefix)) {
				return null;
			}
			String rest = spaceName.substring(prefix.length());
			int bIdx = rest.indexOf("_B");
			if (bIdx < 0) {
				return null;
			}
			Integer mode = parseDigits(rest.substring(0, bIdx));
			Integer bank = parseDigits(rest.substring(bIdx + 2));
			if (mode == null || bank == null) {
				return null;
			}
			return new ModeBank(mode, bank);
		}

		/** Strict decimal parse: non-empty, decimal digits only (no sign, no
		 *  whitespace -- stricter than {@code Integer.parseInt}), else null. */
		private static Integer parseDigits(String s) {
			if (s.isEmpty()) {
				return null;
			}
			int v = 0;
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				if (c < '0' || c > '9') {
					return null;
				}
				v = v * 10 + (c - '0');
			}
			return v;
		}
	}
}
