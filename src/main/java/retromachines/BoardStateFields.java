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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.util.importer.MessageLog;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * A board descriptor's {@code banking.state} field tuple and the initial-state machinery layered
 * on it: expression-resolved power-on state, the game descriptor's initial-state hint, the
 * fixed-after-init mask and the hinted layout mode. Split out of the former
 * {@code DescriptorSupport} (bead grm-rx1i.12).
 */
final class BoardStateFields {

	private BoardStateFields() {
	}

	// ------------------------------------------------------------------
	// Bank-state field parsing (banking.state / initial_state)
	// ------------------------------------------------------------------

	/**
	 * Parses {@code banking.state} into its ordered field tuple, LSB-first. Returns an
	 * empty list when the descriptor has no {@code banking} section (or no {@code state}).
	 */
	static List<FieldSpec> parseStateFields(JsonObject map) {
		List<FieldSpec> fields = new ArrayList<>();
		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("state")) {
			return fields;
		}
		int lsb = 0;
		for (JsonElement fe : banking.getAsJsonArray("state")) {
			JsonObject f = fe.getAsJsonObject();
			String name = f.get("name").getAsString();
			int bits = f.get("bits").getAsInt();
			fields.add(new FieldSpec(name, lsb, bits));
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

	/**
	 * {@code banking.initial_state} with every image-relative field expression
	 * ({@code banking.initial_state_expr}, bead {@code grm-y0ml}) resolved against
	 * {@code imageSize} and packed into its field's bits. Null exactly when
	 * {@link #initialState} is null.
	 * <p>
	 * Per CLAUDE.md's "loader validation: {@code load()} is authoritative", every failure mode
	 * here logs what went wrong and <b>refuses that one field</b> -- leaving it at the
	 * {@code .map}'s literal value -- rather than throwing or guessing: an unparseable
	 * expression, a name that is not a declared {@code banking.state} field, and a resolved
	 * value that does not fit the field's declared width (the range/width check
	 * {@code MapCompiler.packState} performs on literals, applied here to the resolved value,
	 * since it is the first moment the value exists).
	 */
	static Long resolveInitialState(JsonObject map, long imageSize, MessageLog log,
			String mapPath) {
		Long literal = initialState(map);
		JsonObject banking = map.getAsJsonObject("banking");
		if (literal == null || banking == null || !banking.has("initial_state_expr")) {
			return literal;
		}
		List<FieldSpec> fields = parseStateFields(map);
		long packed = literal;
		for (Map.Entry<String, JsonElement> entry : banking.getAsJsonObject("initial_state_expr")
				.entrySet()) {
			String fieldName = entry.getKey();
			String expr = entry.getValue().getAsString();
			FieldSpec field = findField(fields, fieldName);
			if (field == null) {
				log.appendMsg(mapPath + ": banking.initial_state_expr names '" + fieldName +
					"', which is not a banking.state field; ignoring it");
				continue;
			}
			long value;
			try {
				value = DescriptorExpressions.evalInitialStateExpr(expr, imageSize);
			}
			catch (IllegalArgumentException e) {
				log.appendMsg(mapPath + ": banking.initial_state_expr '" + fieldName + ": " +
					expr + "' could not be evaluated (" + e.getMessage() +
					"); leaving the field at its compiled value");
				continue;
			}
			if (value < 0 || value > field.widthMask()) {
				log.appendMsg(mapPath + ": banking.initial_state_expr '" + fieldName + ": " +
					expr + "' resolves to " + value + " against a " + imageSize +
					"-byte image, which does not fit the field's " + field.width() +
					" bits; leaving the field at its compiled value");
				continue;
			}
			packed = field.pos().deposit(packed, value);
		}
		return packed;
	}

	/**
	 * Folds a resolved game descriptor's {@code banking.initial_state} hint (bead
	 * {@code grm-hb6.12}) into {@code resolvedInitialState} -- itself already the output of
	 * {@link #resolveInitialState}, i.e. this runs strictly AFTER
	 * {@code banking.initial_state_expr} (bead {@code grm-y0ml}), per
	 * docs/per-game-descriptors-design.md's ruling that an import-time hint is folded in last.
	 * <p>
	 * The hint is a field-NAME map ({@code { prg_mode: 1 }}), never a packed integer -- the game
	 * tier must not know the board's bit layout -- so it is packed here, against {@code
	 * boardMap}'s own {@link #parseStateFields} tuple, the only place both the field name and
	 * its width are known together.
	 * <p>
	 * Same failure discipline as {@link #resolveInitialState}, extended one notch further
	 * because a game descriptor is the least trusted input in the system
	 * (docs/per-game-descriptors-design.md section 3.1): a hint naming a field this board does
	 * not declare, or a value too wide for that field, LOGS and refuses that one field, leaving
	 * it at whatever {@code resolvedInitialState} already held -- never throws, never guesses
	 * (CLAUDE.md: {@code load()} is authoritative). A hint present when the board has no
	 * resolved initial state at all (no {@code banking} section, or no {@code initial_state})
	 * refuses the WHOLE hint the same way, since there is nothing to fold a field value into.
	 * Also logs when a hint overrides a value {@code banking.initial_state_expr} had already
	 * set for that field, so a silent override is never invisible to the log.
	 *
	 * @param boardMap the compiled BOARD descriptor (not the game descriptor)
	 * @param resolvedInitialState {@link #resolveInitialState}'s result against {@code boardMap}
	 * @param gameDescriptor the compiled game descriptor ({@code .gmap} JSON)
	 * @param gameDescriptorPath the game descriptor's path, for log messages
	 * @return {@code resolvedInitialState} with the hint's fields applied, or unchanged when the
	 *         game descriptor declares no {@code banking.initial_state} hint
	 */
	static Long applyGameInitialStateHint(JsonObject boardMap, Long resolvedInitialState,
			JsonObject gameDescriptor, String gameDescriptorPath, MessageLog log) {
		JsonObject gameBanking = gameDescriptor.getAsJsonObject("banking");
		if (gameBanking == null || !gameBanking.has("initial_state")) {
			return resolvedInitialState;
		}
		if (resolvedInitialState == null) {
			log.appendMsg(gameDescriptorPath + ": banking.initial_state hint present, but the " +
				"board descriptor has no banking.initial_state of its own to apply it to; " +
				"ignoring the hint");
			return null;
		}
		JsonObject hint = gameBanking.getAsJsonObject("initial_state");
		List<FieldSpec> fields = parseStateFields(boardMap);
		Set<String> exprFields = new LinkedHashSet<>();
		JsonObject boardBanking = boardMap.getAsJsonObject("banking");
		if (boardBanking != null && boardBanking.has("initial_state_expr")) {
			exprFields.addAll(boardBanking.getAsJsonObject("initial_state_expr").keySet());
		}
		long packed = resolvedInitialState;
		for (Map.Entry<String, JsonElement> entry : hint.entrySet()) {
			String fieldName = entry.getKey();
			FieldSpec field = findField(fields, fieldName);
			if (field == null) {
				log.appendMsg(gameDescriptorPath + ": banking.initial_state names '" +
					fieldName + "', which is not a banking.state field of this board; " +
					"ignoring it");
				continue;
			}
			long value;
			try {
				value = entry.getValue().getAsLong();
			}
			catch (RuntimeException e) {
				log.appendMsg(gameDescriptorPath + ": banking.initial_state '" + fieldName +
					"' is not an integer; ignoring it");
				continue;
			}
			if (value < 0 || value > field.widthMask()) {
				log.appendMsg(gameDescriptorPath + ": banking.initial_state '" + fieldName +
					": " + value + "' does not fit the field's " + field.width() +
					" bits; leaving the field at its previously resolved value");
				continue;
			}
			if (exprFields.contains(fieldName)) {
				log.appendMsg(gameDescriptorPath + ": banking.initial_state '" + fieldName +
					"' overrides the value banking.initial_state_expr had set for it");
			}
			packed = field.pos().deposit(packed, value);
		}
		return packed;
	}

	/**
	 * Resolves a game descriptor's {@code banking.fixed_after_init} hint (bead grm-mej.12) to a
	 * bit mask in the board's packed state layout. A name that is not a {@code banking.state}
	 * field of this board is LOGGED and ignored -- never thrown (a game descriptor is the least
	 * trusted input, and {@code load()} is authoritative). Returns 0 when the descriptor states
	 * no such hint or no listed field resolves.
	 */
	static long resolveFixedAfterInitMask(JsonObject boardMap, JsonObject gameDescriptor,
			String gameDescriptorPath, MessageLog log) {
		JsonObject gameBanking = gameDescriptor.getAsJsonObject("banking");
		if (gameBanking == null || !gameBanking.has("fixed_after_init")) {
			return 0;
		}
		List<FieldSpec> fields = parseStateFields(boardMap);
		long mask = 0;
		for (JsonElement el : gameBanking.getAsJsonArray("fixed_after_init")) {
			String name;
			try {
				name = el.getAsString();
			}
			catch (RuntimeException e) {
				log.appendMsg(gameDescriptorPath +
					": banking.fixed_after_init has a non-string entry; ignoring it");
				continue;
			}
			FieldSpec field = findField(fields, name);
			if (field == null) {
				log.appendMsg(gameDescriptorPath + ": banking.fixed_after_init names '" + name +
					"', which is not a banking.state field of this board; ignoring it");
				continue;
			}
			mask |= field.positionedMask();
		}
		return mask;
	}

	/**
	 * The value a game descriptor's {@code banking.initial_state} hint states for the board's
	 * LAYOUT mode field (the single field every {@code memory.layouts[].when} names), or null
	 * when there is none to state -- the board has no layouts, the hint does not name that field,
	 * or {@link #applyGameInitialStateHint} would refuse the value (no resolved initial state to
	 * fold it into, not an integer, too wide for the field). Bead {@code grm-ic5.1}.
	 * <p>
	 * This is what makes a hinted mode a {@code liveMode} for {@link WindowPlanner#planWindows(JsonObject,
	 * MessageLog, String, Integer)}: a human recorded it against the cartridge, which is the
	 * positive evidence grm-ic5's ruling requires before other modes' blocks may be suppressed.
	 * It never logs -- {@link #applyGameInitialStateHint} has already reported every refusal for
	 * the same inputs -- and it refuses in exactly the cases that method refuses, so a hint that
	 * did not move the home layout can never license suppression either.
	 */
	static Integer gameHintedLayoutMode(JsonObject boardMap, Long resolvedInitialState,
			JsonObject gameDescriptor) {
		JsonObject gameBanking = gameDescriptor.getAsJsonObject("banking");
		if (resolvedInitialState == null || gameBanking == null ||
			!gameBanking.has("initial_state")) {
			return null;
		}
		String modeField = layoutModeField(boardMap);
		if (modeField == null) {
			return null;
		}
		JsonObject hint = gameBanking.getAsJsonObject("initial_state");
		FieldSpec field = findField(parseStateFields(boardMap), modeField);
		if (!hint.has(modeField) || field == null) {
			return null;
		}
		long value;
		try {
			value = hint.get(modeField).getAsLong();
		}
		catch (RuntimeException e) {
			return null;
		}
		if (value < 0 || value > field.widthMask()) {
			return null;
		}
		return (int) value;
	}

	/**
	 * The board's LAYOUT mode field -- the single field every {@code memory.layouts[].when}
	 * names, as read off the first layout -- or null when the board has no layouts, or a
	 * {@code when:} that is not a single field (planWindows ignores such layouts entirely).
	 */
	static String layoutModeField(JsonObject boardMap) {
		if (!boardMap.has("layouts")) {
			return null;
		}
		JsonArray layouts = boardMap.getAsJsonArray("layouts");
		if (layouts.isEmpty()) {
			return null;
		}
		JsonObject when = layouts.get(0).getAsJsonObject().getAsJsonObject("when");
		if (when == null || when.entrySet().size() != 1) {
			return null;
		}
		return when.keySet().iterator().next();
	}

	/**
	 * The layout mode a board lets the loader ASSUME known when nothing better states one
	 * (bead {@code grm-ic5}): {@code resolvedInitialState}'s layout-field value, when the board
	 * declares {@code banking.assume_initial_layout_mode} -- else null.
	 * <p>
	 * This is the weakest of the three sources of a known mode (image scan, curated hint, this),
	 * and the only one that is an assumption rather than evidence: the power-on value describes
	 * t=0. The board opts in only where the pinned corpus was surveyed and every exception carries
	 * a hint (MMC1); the analyzer's mode lock catches an unlisted exception afterwards.
	 */
	static Integer assumedLayoutMode(JsonObject boardMap, Long resolvedInitialState) {
		JsonObject banking = boardMap.getAsJsonObject("banking");
		if (resolvedInitialState == null || banking == null ||
			!banking.has("assume_initial_layout_mode") ||
			!banking.get("assume_initial_layout_mode").getAsBoolean()) {
			return null;
		}
		FieldSpec field = findField(parseStateFields(boardMap), layoutModeField(boardMap));
		return field == null ? null : (int) field.valueIn(resolvedInitialState);
	}

	/**
	 * Whether a game descriptor says its title switches layout mode at runtime
	 * ({@code banking.layout_mode_varies: true}, bead {@code grm-ic5}): no mode may then be
	 * taken as known for it, whatever the scan, a hint, or the board's assumption would say.
	 */
	static boolean gameLayoutModeVaries(JsonObject gameDescriptor) {
		JsonObject gameBanking = gameDescriptor.getAsJsonObject("banking");
		return gameBanking != null && gameBanking.has("layout_mode_varies") &&
			gameBanking.get("layout_mode_varies").getAsBoolean();
	}

	/** Finds a field by name in a {@link #parseStateFields} result, or null. */
	static FieldSpec findField(List<FieldSpec> fields, String name) {
		for (FieldSpec f : fields) {
			if (f.name().equals(name)) {
				return f;
			}
		}
		return null;
	}
}
