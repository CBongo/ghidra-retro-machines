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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Window-plan normalization ({@code memory.windows[]} + {@code memory.layouts[]}), the legal bank
 * set of each planned window, and the shared home-in-base placement policy. Used by the NES
 * loader (and, for placement, the CBM loaders). Split out of the former
 * {@code DescriptorSupport} (bead grm-rx1i.12).
 */
final class WindowPlanner {

	private WindowPlanner() {
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
		return planWindows(map, log, source, null);
	}

	/**
	 * {@link #planWindows(JsonObject, MessageLog, String)} with the image's KNOWN mode, which
	 * suppresses every other mode's window instances (bead {@code grm-ic5}, increment 1).
	 * <p>
	 * <b>What {@code liveMode} means, and it is stronger than "the mode field's value".</b> It is
	 * non-null only when the mode was DETERMINED for this image -- resolved from the image by
	 * {@code NesRomLoader.scanImageMode}, or stated by a curated per-game descriptor -- never when
	 * it was merely assumed from {@code banking.initial_state}'s power-on constant. That
	 * distinction is the whole ruling on grm-ic5: a determined mode licenses deleting the other
	 * modes' blocks, a defaulted one does not, because the default describes t=0 and says nothing
	 * about the rest of the program. MMC1 is the worked counterexample -- its mode-3 default is
	 * hardware-correct at reset, yet drmario and tetris run mode 0 and reference the mode-0
	 * overlays EXCLUSIVELY, so suppressing on that default would delete the very blocks their
	 * references point into.
	 * <p>
	 * <b>Invariance is still decided against ALL layouts, deliberately.</b> A window identical
	 * across every mode is hoisted to {@code invariant} (unqualified name) exactly as before, and
	 * only the surviving mode's VARYING instances are emitted. So this increment moves block
	 * COUNTS while leaving every block NAME alone -- MMC3's {@code WA000_B<n>} stays unqualified
	 * and {@code W8000_M1_B<n>} keeps its qualifier. Collapsing a single surviving instance to an
	 * unqualified name is the natural next step and is deliberately NOT done here, so that the
	 * count change and the name change land as separate, separately reviewable diffs.
	 * <p>
	 * A {@code liveMode} matching no layout's {@code when:} suppresses nothing: the mode is
	 * outside what the descriptor models, which is a descriptor/image mismatch rather than a
	 * licence to delete every window.
	 */
	static LayoutPlan planWindows(JsonObject map, MessageLog log, String source,
			Integer liveMode) {
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
				// grm-ic5: a KNOWN mode suppresses the others' instances. Note this filters the
				// EMIT and not the invariance test above, which is what keeps hoisted windows
				// unqualified -- see this method's javadoc.
				if (liveMode != null && modeValue != liveMode && seenValues.contains(liveMode)) {
					continue;
				}
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
		List<FieldSpec> fields = BoardStateFields.parseStateFields(map);
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
			FieldSpec field = exprFields.size() == 1
					? BoardStateFields.findField(fields, exprFields.iterator().next())
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
}
