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
import java.util.TreeSet;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import retromachines.BankAnnotationAdapter.OffsetResolution;
import retromachines.BankAnnotationAdapter.Seed;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Emission under a {@code banking.live_bank_sets} hint (bead grm-5tl.20.5, phase B): turns the
 * bank states live at a reference site into one fully-known state per candidate bank, so
 * {@link BankAnnotationAdapter#retargetReferences}' existing multi-arm placement (one overlay
 * reference per distinct bank, primacy to the first, base reference retired only when every arm
 * resolved away from home) places a reference into each candidate's overlay.
 * <p>
 * <b>Reference placement only.</b> The expanded list is a local substitute handed to
 * {@code retargetReferences}; it is never stored, never fed back into the dataflow, switch-site
 * comments, violation scans or helper recovery.
 * <p>
 * <b>When it applies.</b> A validated hint ({@link LiveBankSets.Plan}) whose field selects the
 * window one of the instruction's reference seeds reaches, and the instruction does NOT itself
 * reside in a window that field selects (residence is physical, not a dataflow guess: code in a
 * banked window runs in the bank it was placed in). Everything else is untouched.
 * <p>
 * <b>Per state:</b> the field fully known and in {@code valueset} -- kept as is. Not fully known --
 * one state per {@link LiveBankSets.Plan#candidates} member. Known bits contradicting the whole set,
 * or a fully known value outside it -- the HINT WINS: expanded over the whole set, with a warning
 * naming both. Identical expanded states are deduped; order is ascending by value, so primacy is
 * the lowest surviving bank.
 * <p>
 * <b>Pruning</b> (optional): for an instruction whose expandable seed is a single FLOW reference,
 * a candidate bank is dropped when the target does not decode as plausible code in that bank
 * ({@link InlineJumpTableDispatch#decodesAsCode}, bytes only, so the answer does not depend on
 * what has already been disassembled). Data references are never pruned. When every candidate is
 * pruned nothing is expanded and the site keeps what dataflow alone would have placed.
 */
final class LiveBankExpansion {

	/** What expansion decided for one instruction. {@code comment}/{@code warning} are nullable. */
	record Result(List<BankState> states, String comment, String warning) {

		static Result unchanged(List<BankState> states) {
			return new Result(states, null, null);
		}
	}

	private LiveBankExpansion() {
	}

	/**
	 * Expands {@code states} (the whole states live at {@code instr}) under every applied hint.
	 *
	 * @param prune drop candidate banks whose flow target is not plausible code
	 */
	static Result expand(Program program, BoardModel board, Map<String, Set<Integer>> bankUniverse,
			Map<String, Integer> placementOverride, LiveBankSets.Plan plan, Instruction instr,
			AddressSpace baseSpace, List<BankState> states, boolean prune) {
		if (plan.isEmpty() || states.isEmpty()) {
			return Result.unchanged(states);
		}
		List<BankState> current = states;
		List<String> comments = new ArrayList<>();
		List<String> warnings = new ArrayList<>();
		for (LiveBankSets.Hint hint : plan.byField().values()) {
			Applied one = expandOne(program, board, bankUniverse, placementOverride, plan, hint,
				instr, baseSpace, current, prune);
			if (one == null) {
				continue;
			}
			if (one.states != null) {
				current = one.states;
			}
			comments.add(one.comment);
			if (one.warning != null) {
				warnings.add(one.warning);
			}
		}
		return new Result(current, comments.isEmpty() ? null : String.join(" / ", comments),
			warnings.isEmpty() ? null : String.join(" | ", warnings));
	}

	/** One hint's outcome; {@code states} null when nothing was expanded (all pruned). */
	private record Applied(List<BankState> states, String comment, String warning) {
	}

	private static Applied expandOne(Program program, BoardModel board,
			Map<String, Set<Integer>> bankUniverse, Map<String, Integer> placementOverride,
			LiveBankSets.Plan plan, LiveBankSets.Hint hint, Instruction instr, AddressSpace baseSpace,
			List<BankState> states, boolean prune) {
		FieldSpec field = board.field(hint.field());
		if (field == null) {
			return null;
		}
		List<BankAnnotationAdapter.Seed> seeds = BankAnnotationAdapter.seeds(instr, baseSpace);
		long here = instr.getMinAddress().getOffset();
		Set<BankState> out = new LinkedHashSet<>();
		Set<Integer> placed = new TreeSet<>();
		Set<Integer> pruned = new TreeSet<>();
		List<String> warnings = new ArrayList<>();
		boolean touched = false;
		for (BankState state : states) {
			List<Seed> affected = new ArrayList<>();
			for (Seed seed : seeds) {
				FieldSpec selects = BankAnnotationAdapter.bankFieldAt(board, state, seed.offset(),
					seed.refType());
				if (selects != null && selects.name().equals(field.name())) {
					affected.add(seed);
				}
			}
			FieldSpec resident = BankAnnotationAdapter.bankFieldAt(board, state, here);
			if (affected.isEmpty() || (resident != null && resident.name().equals(field.name()))) {
				out.add(state);
				continue;
			}
			int widthMask = field.widthMask();
			int knownLocal = (state.knownMask() >>> field.lsb()) & widthMask;
			int bitsLocal = (state.bits() >>> field.lsb()) & widthMask;
			List<Integer> candidates;
			if (knownLocal == widthMask && hint.valueset().contains(bitsLocal)) {
				out.add(state); // a known, in-set value: nothing to expand
				continue;
			}
			candidates = knownLocal == widthMask ? List.of() : plan.candidates(hint.field(),
				knownLocal, bitsLocal);
			if (candidates == null || candidates.isEmpty()) {
				warnings.add(winsWarning(plan, hint, field, knownLocal, bitsLocal));
				candidates = hint.valueset();
			}
			touched = true;
			boolean pruneHere = prune && affected.size() == 1 && affected.get(0).refType().isFlow();
			for (int v : new TreeSet<>(candidates)) {
				BankState candidate = withField(state, field, v);
				if (pruneHere && !plausible(program, board, bankUniverse, placementOverride,
					baseSpace, candidate, affected.get(0).offset())) {
					pruned.add(v);
					continue;
				}
				placed.add(v);
				out.add(candidate);
			}
		}
		if (!touched) {
			return null;
		}
		String set = hint.valueset().stream().sorted().map(Object::toString)
				.collect(Collectors.joining(","));
		String comment = BankAnnotationAdapter.LIVE_SET_MARKER + "game descriptor " + plan.source() +
			"): " + field.name() + " in {" + set + "}, " +
			(placed.isEmpty() ? "refs placed for none"
					: "refs for " + join(placed)) +
			", pruned " + (pruned.isEmpty() ? "none"
					: join(pruned) + " (target not plausible code there)");
		String warning = warnings.isEmpty() ? null : String.join("; ", warnings);
		if (placed.isEmpty()) {
			// every candidate pruned: leave the instruction's references as dataflow alone placed them
			return new Applied(null, comment, warning);
		}
		return new Applied(new ArrayList<>(out), comment, warning);
	}

	private static String join(Set<Integer> values) {
		return values.stream().map(Object::toString).collect(Collectors.joining(", "));
	}

	private static BankState withField(BankState state, FieldSpec field, int value) {
		int mask = field.positionedMask();
		return new BankState(state.knownMask() | mask,
			(state.bits() & ~mask) | ((value & field.widthMask()) << field.lsb()));
	}

	private static String winsWarning(LiveBankSets.Plan plan, LiveBankSets.Hint hint,
			FieldSpec field, int knownLocal, int bitsLocal) {
		String dataflow = knownLocal == field.widthMask() ? Integer.toString(bitsLocal)
				: "partly known (bits 0x" + Integer.toHexString(bitsLocal & knownLocal) +
					" of mask 0x" + Integer.toHexString(knownLocal) + ")";
		return "live_bank_sets hint from game descriptor " + plan.source() + " WINS here: " +
			"dataflow has " + field.name() + " = " + dataflow + ", which contradicts valueset " +
			hint.valueset() + "; references were expanded over the whole set. Investigate the " +
			"dataflow or the hint";
	}

	/**
	 * Whether the flow target at {@code offset} decodes as plausible code in the bank
	 * {@code candidate} selects. True ("cannot judge, keep") when the target resolves to no
	 * overlay or lies outside initialized memory.
	 */
	private static boolean plausible(Program program, BoardModel board,
			Map<String, Set<Integer>> bankUniverse, Map<String, Integer> placementOverride,
			AddressSpace baseSpace, BankState candidate, long offset) {
		OffsetResolution r = BankAnnotationAdapter.resolveOffsetOccupant(board, bankUniverse,
			candidate, offset, placementOverride);
		if (r == null) {
			return true;
		}
		AddressSpace space = r.home() ? baseSpace
				: program.getAddressFactory().getAddressSpace(r.space());
		if (space == null) {
			return true;
		}
		Address target = space.getAddress(offset);
		if (!program.getMemory().contains(target)) {
			return true;
		}
		return InlineJumpTableDispatch.decodesAsCode(program, target, true);
	}
}
