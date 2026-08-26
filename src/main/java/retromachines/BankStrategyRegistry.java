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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Instantiation and positioning of a descriptor's bank-switch mechanisms: the registry that
 * turns {@code banking.mechanisms[]} entries into {@link ConfiguredMechanism}s, each a
 * configured {@link BankSwitchStrategy} paired with the absolute state bits it owns.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Strategy configuration" section
 * without behavior change (bead grm-ft8 increment 2, from QR-12), so the analyzer's
 * orchestration and dataflow code no longer has to carry strategy lookup and bit positioning
 * as well. As with {@link BoardDescriptorModel}, one holder rather than several files: the
 * record and the two methods are a single unit -- {@code configureStrategies} is the only
 * caller of {@code mechanismPositioning}, and the record is the only thing either produces.
 *
 * <p>The one non-mechanical change the move required: both methods log through
 * {@link AnalyzerLog#warn}, whose first parameter is the {@link Analyzer} doing the logging.
 * That used to be {@code this}; it is now threaded in as a leading {@code analyzer}
 * parameter. Nothing else about the moved code differs from its original.
 */
final class BankStrategyRegistry {

	private BankStrategyRegistry() {
	}

	/**
	 * One descriptor mechanism entry, instantiated and positioned: {@code strategy} is the
	 * configured {@link BankSwitchStrategy}, which computes entirely in its own field-local
	 * {@code [0, width)} coordinate space; {@code effectMask} and {@code lsb} say where that
	 * space lands in the board's absolute state bits (see {@link #mechanismPositioning}).
	 * For every shipped (single-mechanism) board {@code effectMask == board.mask()} and
	 * {@code lsb == 0}, so field-local and absolute coincide.
	 */
	record ConfiguredMechanism(BankSwitchStrategy strategy, int effectMask, int lsb) {}

	// ------------------------------------------------------------------
	// Strategy configuration
	// ------------------------------------------------------------------

	/**
	 * Instantiates and configures one {@link BankSwitchStrategy} per descriptor
	 * mechanism entry, matching {@code mechanisms[].strategy} to implementations found
	 * by ClassSearcher. Unknown strategy names are logged and skipped (they belong to
	 * later milestones). Each mechanism is also positioned within the board's absolute
	 * state bits (see {@link #mechanismPositioning}); a mechanism whose positioning
	 * cannot be determined is likewise skipped.
	 */
	static List<ConfiguredMechanism> configureStrategies(Analyzer analyzer, Program program,
			JsonArray mechanisms, BoardModel board, MessageLog log) {
		List<BankSwitchStrategy> prototypes = ClassSearcher.getInstances(BankSwitchStrategy.class);
		List<ConfiguredMechanism> configured = new ArrayList<>();
		for (JsonElement me : mechanisms) {
			JsonObject mechanism = me.getAsJsonObject();
			String strategyName = mechanism.get("strategy").getAsString();
			BankSwitchStrategy prototype = null;
			for (BankSwitchStrategy p : prototypes) {
				if (p.strategyName().equals(strategyName)) {
					prototype = p;
					break;
				}
			}
			if (prototype == null) {
				AnalyzerLog.warn(analyzer, log, "no BankSwitchStrategy implementation for strategy '" +
					strategyName + "'; skipping that mechanism");
				continue;
			}

			int[] positioning = mechanismPositioning(analyzer, mechanism, board, log, strategyName);
			if (positioning == null) {
				continue;
			}
			int effectMask = positioning[0];
			int lsb = positioning[1];

			try {
				BankSwitchStrategy instance =
					prototype.getClass().getDeclaredConstructor().newInstance();
				JsonObject params = mechanism.getAsJsonObject("params");
				// Field-local sub-offsets (grm-6a7.1): a mechanism with several 'sets' fields
				// packed into one physical register (e.g. select-data's select/prg_mode/r6/r7)
				// needs to know where EACH of its own fields sits within its own field-local
				// [0, width) window, not just the window's own overall width. Rather than have
				// every such strategy re-derive that from banking.state by hand (or have YAML
				// authors hand-duplicate offsets that must stay in lockstep with the state
				// tuple), inject it here from the single source of truth: board.fieldSpecs(),
				// the same per-field (lsb, width) this method already used to compute
				// effectMask/lsb above, just re-expressed field-local (subtract this
				// mechanism's own lsb) and keyed by name under params._field_layout. A
				// single-field mechanism (every strategy shipped before this one) never reads
				// this key, so injecting it unconditionally cannot break them.
				if (mechanism.has("sets")) {
					JsonObject fieldLayout = new JsonObject();
					for (JsonElement se : mechanism.getAsJsonArray("sets")) {
						String fieldName = se.getAsString();
						board.fieldSpecs().stream()
								.filter(f -> f.name().equals(fieldName))
								.findFirst()
								.ifPresent(f -> {
									JsonObject fl = new JsonObject();
									fl.addProperty("lsb", f.lsb() - lsb);
									fl.addProperty("width", f.width());
									fieldLayout.add(fieldName, fl);
								});
					}
					params.add("_field_layout", fieldLayout);
				}
				// Strategies always compute in field-local [0, width) coordinates; the mask
				// they configure with is that field-local width, not the whole board mask.
				instance.configure(program, params, effectMask >>> lsb);
				configured.add(new ConfiguredMechanism(instance, effectMask, lsb));
			}
			catch (Exception e) {
				AnalyzerLog.warn(analyzer, log, "failed to configure strategy '" + strategyName + "': " +
					e.getMessage());
			}
		}
		return configured;
	}

	/**
	 * Computes one mechanism's {@code (effectMask, lsb)}: where in the board's absolute
	 * state bits this mechanism's writes land, derived from its {@code sets} field-name
	 * list (the {@code banking.state} fields it writes) -- {@code effectMask} is the union
	 * of those fields' {@link FieldSpec#positionedMask()}, {@code lsb} the lowest of their
	 * lsbs. The engine uses this to translate between a strategy's field-local
	 * {@code [0, width)} coordinate space (what {@link BankSwitchStrategy#computeSwitch}
	 * actually computes in) and the board's absolute state bits, so one mechanism's switch
	 * can fold into the tracked state without disturbing bits another mechanism owns
	 * (grm-ezl). The union is REQUIRED to be one contiguous bit run starting at
	 * {@code lsb} -- a mechanism whose {@code sets} fields are split or interleaved with
	 * another mechanism's is unsupported and is conservatively skipped (logged, not
	 * analyzed) rather than mispositioned.
	 * <p>
	 * A mechanism with no {@code sets} at all (older or minimal descriptors) falls back to
	 * covering the whole board mask at {@code lsb} 0 -- today's single-mechanism-per-board
	 * behavior, verbatim.
	 *
	 * @return {@code {effectMask, lsb}}, or {@code null} to skip this mechanism
	 */
	static int[] mechanismPositioning(Analyzer analyzer, JsonObject mechanism, BoardModel board,
			MessageLog log, String strategyName) {
		if (!mechanism.has("sets") || mechanism.getAsJsonArray("sets").size() == 0) {
			return new int[] { board.mask(), 0 };
		}
		JsonArray sets = mechanism.getAsJsonArray("sets");
		int effectMask = 0;
		int lsb = Integer.MAX_VALUE;
		for (JsonElement se : sets) {
			String fieldName = se.getAsString();
			FieldSpec field = board.fieldSpecs().stream()
					.filter(f -> f.name().equals(fieldName))
					.findFirst()
					.orElse(null);
			if (field == null) {
				AnalyzerLog.warn(analyzer, log, "mechanism '" + strategyName + "' sets unknown state " +
					"field '" + fieldName + "'; skipping that mechanism");
				return null;
			}
			effectMask |= field.positionedMask();
			lsb = Math.min(lsb, field.lsb());
		}
		int widthMask = effectMask >>> lsb;
		if (widthMask == 0 || (widthMask & (widthMask + 1)) != 0) {
			AnalyzerLog.warn(analyzer, log, "mechanism '" + strategyName + "' sets fields " + sets +
				" that are not a contiguous bit run in banking.state; skipping that mechanism");
			return null;
		}
		return new int[] { effectMask, lsb };
	}
}
