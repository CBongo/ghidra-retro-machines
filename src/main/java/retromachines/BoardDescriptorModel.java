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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.importer.MessageLog;

/**
 * The immutable, phase-independent board model parsed out of a machine descriptor, together
 * with the small shapes it is built from ({@link FieldSpec}, {@link WindowModel},
 * {@link ComputedWindowModel}, {@link ModeWindowModel} and friends).
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Descriptor model" section without
 * behavior change (bead grm-ft8, from QR-12), so the analyzer's orchestration and dataflow
 * code no longer has to carry the descriptor's data model as well. The types are gathered as
 * nested members of one holder rather than split across seven files because they exist only
 * as parts of a single parse product -- {@link BoardModel#parse} builds all of them in one
 * pass -- and several ({@link Bounded}, {@link OccupantModel}) are three-line shapes that
 * would be noise as standalone compilation units. They stay package-private: nothing outside
 * this package uses them, and {@link FieldSpec} in particular is exposed only far enough for
 * {@code FieldSpecKnownTest} to reach it.
 */
final class BoardDescriptorModel {

	private BoardDescriptorModel() {
	}

	/**
	 * One {@code banking.state} field: its bit position and width within the state int.
	 * Package-private, and it must stay that way: {@link BoardBankAnalyzer} consumes it
	 * throughout, and {@code FieldSpecKnownTest} exercises {@link #fullyKnownIn} directly
	 * without standing up an analyzer. (Before the grm-ft8 extraction this javadoc read
	 * "nothing outside this class uses it", which was true while the record was nested in
	 * {@code BoardBankAnalyzer} and is not any more.)
	 */
	record FieldSpec(String name, int lsb, int width) {

		int positionedMask() {
			return ((1 << width) - 1) << lsb;
		}

		/**
		 * True when dataflow pinned EVERY bit of this field in {@code state}. Knowledge of a
		 * field is all-or-nothing: {@link #valueIn} on a partially known field silently fills
		 * the unknown bits from the board's initial state, so a caller that treats "some bit
		 * known" as knowledge manufactures a bank number nothing actually pinned (grm-v6o).
		 * Note the two forms coincide for a single-bit field, which is what let the wrong test
		 * survive; prefer this method over open-coding either one.
		 */
		boolean fullyKnownIn(BankState state) {
			return (state.knownMask() & positionedMask()) == positionedMask();
		}

		int valueIn(int state) {
			return (state >> lsb) & ((1 << width) - 1);
		}
	}

	record OccupantModel(String name, String kind, String onWrite) {}

	/** An address window with an inclusive {@code [start, end]} offset range in base space. */
	interface Bounded {
		long start();

		long end();
	}

	record WindowModel(String name, long start, long end,
			Map<String, OccupantModel> occupants) implements Bounded {}

	/** A computed window driven by a single state field; per-bank overlays are named
	 *  {@code <name>_B<fieldValue>} by the loader, home bank in base space. */
	record ComputedWindowModel(String name, long start, long end, FieldSpec field,
			String onWrite) implements Bounded {}

	/**
	 * One {@code (windowName, modeValue)} instance out of {@code memory.layouts[]}
	 * (bead grm-qvi): {@code bankField} is null for a mode-varying <em>fixed</em> window
	 * instance (a constant {@code maps:} expr under this mode -- the loader's non-home
	 * layout instances become {@code <name>_M<mode>} overlays), non-null for a
	 * <em>switchable</em> instance (a single-field {@code maps:} expr -- the loader's
	 * per-bank instances become {@code <name>_M<mode>_B<bank>} overlays). Mirrors
	 * {@link NesRomLoader}'s realizeVaryingWindows fixed-vs-switchable test
	 * ({@code referencedFields(expr).isEmpty()}), so the analyzer and loader agree on
	 * which instances are fixed without re-deriving it differently.
	 */
	record ModeWindowModel(String name, long start, long end, int modeValue,
			FieldSpec bankField, String onWrite) {}

	/** Everything phase-independent parsed out of the descriptor. */
	record BoardModel(int mask, int initialState, List<String> stateBitNames,
			List<FieldSpec> fieldSpecs, Map<String, WindowModel> windows,
			Map<String, ComputedWindowModel> computedWindows,
			Map<Integer, Map<String, String>> occupantByWindowForState,
			Map<String, String> homeOccupantByWindow, FieldSpec modeField, int homeModeValue,
			List<ModeWindowModel> modeWindows) {

		/**
		 * Parses the {@code banking} and {@code windows} sections of a board descriptor into
		 * a {@link BoardModel}. Returns {@code null} when a required section is missing or
		 * inconsistent, in which case the caller should skip bank-state analysis (but this is
		 * not an error -- callers should treat a {@code null} result like the other "skip"
		 * paths in {@code added()}, not like an {@link IOException}).
		 */
		static BoardModel parse(JsonObject map, MessageLog log, String source,
				String mapPath) {
			return parse(map, log, source, mapPath, null);
		}

		/**
		 * {@link #parse(JsonObject, MessageLog, String, String)} with the loader's
		 * <em>resolved</em> power-on state (bead {@code grm-y0ml}), which wins over the
		 * descriptor's compiled literal when non-null.
		 * <p>
		 * A descriptor may seed a state field with an image-relative expression
		 * ({@code banking.initial_state_expr}, e.g. MMC5's "the last 8 KiB bank of this
		 * cartridge"). That cannot be packed at build time and cannot be resolved here either:
		 * this method sees only the {@code .map}, never an image size. The loader resolves it
		 * at import and publishes the answer in
		 * {@link DescriptorSupport#INITIAL_STATE_PROPERTY}; {@code resolved} is that value.
		 * Null -- the ordinary case, and the only case for every descriptor without an
		 * expression, plus any program imported before this existed -- keeps the compiled
		 * literal.
		 */
		static BoardModel parse(JsonObject map, MessageLog log, String source, String mapPath,
				Integer resolved) {
			JsonObject banking = map.getAsJsonObject("banking");
			if (banking == null || !banking.has("mechanisms")) {
				log.appendMsg(source, "banking.mechanisms missing from " + mapPath +
					"; skipping bank-state analysis");
				return null;
			}
			if (!banking.has("initial_state")) {
				log.appendMsg(source, "banking.initial_state missing from " + mapPath +
					"; skipping bank-state analysis");
				return null;
			}

			int initialState = banking.get("initial_state").getAsInt();
			if (resolved != null && resolved != initialState) {
				log.appendMsg(source, "using the loader's image-resolved banking.initial_state " +
					resolved + " (the compiled literal in " + mapPath + " is " + initialState +
					"; see banking.initial_state_expr)");
				initialState = resolved;
			}

			// The tracked-bit mask, per-bit annotation names, and field layout come from the
			// banking.state field tuple (LSB first; multi-bit fields expand to name.0, ...).
			List<String> stateBitNames = new ArrayList<>();
			List<FieldSpec> fieldSpecs = new ArrayList<>();
			if (banking.has("state")) {
				for (JsonElement fe : banking.getAsJsonArray("state")) {
					JsonObject field = fe.getAsJsonObject();
					String fieldName = field.get("name").getAsString();
					int bits = field.get("bits").getAsInt();
					fieldSpecs.add(new FieldSpec(fieldName, stateBitNames.size(), bits));
					if (bits == 1) {
						stateBitNames.add(fieldName);
					}
					else {
						for (int i = 0; i < bits; i++) {
							stateBitNames.add(fieldName + "." + i);
						}
					}
				}
			}
			int mask = (1 << stateBitNames.size()) - 1;

			// --- Parse windows: enumerated occupants (C64-style, raw JSON -- PlannedWindow
			// does not carry occupants) come straight off memory.windows[]; computed maps:
			// windows (mode-invariant and mode-varying alike) are driven off the normalized
			// DescriptorSupport.planWindows() plan so this engine and NesRomLoader agree on
			// what a window's instances are without re-walking memory.layouts[] separately.
			Map<String, WindowModel> windowsByName = new LinkedHashMap<>();
			JsonArray windows = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
			for (JsonElement we : windows) {
				JsonObject window = we.getAsJsonObject();
				if (!window.has("occupants")) {
					continue; // computed (maps:) windows are handled via the plan below
				}
				String name = window.get("name").getAsString();
				long start = window.get("start").getAsLong();
				long end = window.get("end").getAsLong();
				Map<String, OccupantModel> occupants = new LinkedHashMap<>();
				for (JsonElement oe : window.getAsJsonArray("occupants")) {
					JsonObject occ = oe.getAsJsonObject();
					String occName = occ.get("name").getAsString();
					String kind = occ.get("kind").getAsString();
					String onWrite = occ.has("on_write") ? occ.get("on_write").getAsString() : null;
					occupants.put(occName, new OccupantModel(occName, kind, onWrite));
				}
				windowsByName.put(name, new WindowModel(name, start, end, occupants));
			}

			DescriptorSupport.LayoutPlan plan = DescriptorSupport.planWindows(map, log, mapPath);

			Map<String, ComputedWindowModel> computedByName = new LinkedHashMap<>();
			for (DescriptorSupport.PlannedWindow pw : plan.invariant()) {
				if (pw.expr() == null) {
					continue; // enumerated occupant window, already handled above
				}
				Set<String> fields = DescriptorExpressions.referencedFields(pw.expr());
				if (fields.isEmpty()) {
					continue; // fixed window -- placed by the loader, never retargeted
				}
				if (fields.size() > 1) {
					log.appendMsg(source, "computed window '" + pw.name() + "' uses " + fields +
						"; multi-field windows are not supported yet -- not retargeting it");
					continue;
				}
				String fieldName = fields.iterator().next();
				FieldSpec fieldSpec = fieldSpecs.stream()
						.filter(f -> f.name().equals(fieldName))
						.findFirst()
						.orElse(null);
				if (fieldSpec == null) {
					log.appendMsg(source, "computed window '" + pw.name() +
						"' references unknown state field '" + fieldName + "'; skipping it");
					continue;
				}
				computedByName.put(pw.name(),
					new ComputedWindowModel(pw.name(), pw.start(), pw.end(), fieldSpec, pw.onWrite()));
			}

			// --- Mode-varying windows (memory.layouts[]) ---
			FieldSpec modeField = null;
			int homeModeValue = 0;
			List<ModeWindowModel> modeWindows = new ArrayList<>();
			if (plan.modeField() != null) {
				modeField = fieldSpecs.stream()
						.filter(f -> f.name().equals(plan.modeField()))
						.findFirst()
						.orElse(null);
				if (modeField == null) {
					log.appendMsg(source, "memory.layouts[] mode field '" + plan.modeField() +
						"' not found in banking.state; skipping mode-varying windows");
				}
				else {
					homeModeValue = modeField.valueIn(initialState);
					for (DescriptorSupport.PlannedWindow pw : plan.varying()) {
						if (pw.expr() == null) {
							log.appendMsg(source, "Window '" + pw.name() +
								"' has enumerated occupants; not supported for mode-varying windows");
							continue;
						}
						Set<String> exprFields = DescriptorExpressions.referencedFields(pw.expr());
						FieldSpec bankField = null;
						if (!exprFields.isEmpty()) {
							if (exprFields.size() > 1) {
								log.appendMsg(source, "mode-varying window '" + pw.name() + "' (mode " +
									plan.modeField() + "=" + pw.modeValue() + ") uses " + exprFields +
									"; multi-field windows are not supported -- skipping that instance");
								continue;
							}
							String fieldName = exprFields.iterator().next();
							bankField = fieldSpecs.stream()
									.filter(f -> f.name().equals(fieldName))
									.findFirst()
									.orElse(null);
							if (bankField == null) {
								log.appendMsg(source, "mode-varying window '" + pw.name() + "' (mode " +
									plan.modeField() + "=" + pw.modeValue() +
									") references unknown state field '" + fieldName +
									"'; skipping that instance");
								continue;
							}
						}
						modeWindows.add(new ModeWindowModel(pw.name(), pw.start(), pw.end(),
							pw.modeValue(), bankField, pw.onWrite()));
					}
				}
			}

			Map<Integer, Map<String, String>> occupantByWindowForState = new LinkedHashMap<>();
			if (banking.has("states")) {
				for (JsonElement se : banking.getAsJsonArray("states")) {
					JsonObject state = se.getAsJsonObject();
					int value = state.get("value").getAsInt();
					Map<String, String> row = new LinkedHashMap<>();
					for (String windowName : windowsByName.keySet()) {
						if (state.has(windowName)) {
							row.put(windowName, state.get(windowName).getAsString());
						}
					}
					occupantByWindowForState.put(value, row);
				}
			}

			Map<String, String> homeOccupantByWindow = occupantByWindowForState.get(initialState);
			if (!windowsByName.isEmpty() && homeOccupantByWindow == null) {
				log.appendMsg(source, "banking.initial_state " + initialState +
					" not found in banking.states; skipping bank-state analysis");
				return null;
			}

			return new BoardModel(mask, initialState, stateBitNames, fieldSpecs, windowsByName,
				computedByName, occupantByWindowForState, homeOccupantByWindow, modeField,
				homeModeValue, modeWindows);
		}
	}
}
