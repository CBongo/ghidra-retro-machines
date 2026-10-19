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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Per-game {@code banking.shadow_commits} hints (bead grm-hb6.26): "a call to {@code helper}
 * commits {@code field} := the byte in RAM cell {@code cell}, and that cell is coherent with the
 * live field (every write to it is committed by the helper before the bank matters)".
 * <p>
 * The case derivation cannot reach is Dragon Power's GxROM engine: {@code FFE7 PLA / STA $F2 /
 * JSR $FFBE} where {@code $FFBE} re-derives the PRG bank from {@code $F2} through a bus-conflict
 * table. The helper's argument is not in a register, so {@code RE_DERIVED_IN_HELPER} stands.
 * <p>
 * <b>Validation</b> ({@link #plan}, once per analysis run, cheap self-consistency only -- the
 * owner's 2026-10-18 tier ruling; a hint that fails is NOT applied, is reported with a WARNING
 * bookmark naming the descriptor and the failed check, and never throws):
 * <ol>
 * <li>the helper address is the entry of a function {@link HelperDiscovery} modelled as a
 * bank-switch helper;</li>
 * <li>the field is a board state field and lies within that helper's effect mask;</li>
 * <li>the coherence PREMISE: every direct (plain absolute / zero-page) store to the cell found in
 * the program is followed, in its own basic block with no intervening flow change, by a call to
 * the helper. An indexed or indirect store to the cell is invisible to this check, which is why
 * the premise is also a stated fact of the descriptor and not only a verified one.</li>
 * </ol>
 * <b>Consumption</b> ({@link #apply}, at a call to a validated helper): with a direct store to the
 * cell earlier in the call's own basic block, the field takes the value the caller scan recovers
 * for the cell (the hint wins over what dataflow recovered; a disagreement is reported). With no
 * such store, the coherence premise makes the call re-commit the live value, a verified no-op on
 * that field.
 */
final class ShadowCommits {

	/** Bookmark category of this hint's WARNINGs (failed validation; hint overrode dataflow). */
	static final String BOOKMARK_CATEGORY = "Game descriptor shadow commit";

	/** How far a block walk goes before giving up (matches the scanner's backward bound in spirit). */
	private static final int MAX_BLOCK_WALK = 64;

	/** One validated entry. */
	record Valid(long helper, long cell, FieldSpec field, String provenance) {
	}

	/** A hint that was not applied: where to put the bookmark (may be null) and why. */
	record Problem(Address where, String text) {
	}

	/**
	 * The run's validated hints, keyed by the helper's entry OFFSET (a byte-identical home engine
	 * can be modelled once per bank copy, each in its own overlay space, so the offset -- not the
	 * space -- identifies the helper), plus the failures to report.
	 */
	record Plan(String source, Map<Long, Valid> byHelper, List<Problem> problems) {

		static final Plan NONE = new Plan(null, Map.of(), List.of());

		boolean isEmpty() {
			return byHelper.isEmpty();
		}
	}

	private ShadowCommits() {
	}

	// ------------------------------------------------------------------
	// Validation
	// ------------------------------------------------------------------

	private record Entry(long helper, long cell, String field, String provenance) {
	}

	/** The descriptor-recorded source path, or null when absent/unreadable. */
	static String source(Program program) {
		String spec = DescriptorSupport.programInfoString(program,
			DescriptorSupport.SHADOW_COMMITS_PROPERTY);
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

	/**
	 * Reads the property and validates every entry against {@code board} and the modelled
	 * {@code helpers}. {@link Plan#NONE} (and no work) when the descriptor states none.
	 */
	static Plan plan(Program program, BoardModel board, Map<Function, HelperModel> helpers) {
		String spec = DescriptorSupport.programInfoString(program,
			DescriptorSupport.SHADOW_COMMITS_PROPERTY);
		if (spec == null || spec.isBlank()) {
			return Plan.NONE;
		}
		String source = source(program);
		String who = "game descriptor " + (source == null ? "(unknown)" : source);
		List<Entry> entries = new ArrayList<>();
		List<Problem> problems = new ArrayList<>();
		try {
			JsonObject root = JsonParser.parseString(spec).getAsJsonObject();
			for (JsonElement el : root.getAsJsonArray("commits")) {
				JsonObject o = el.getAsJsonObject();
				entries.add(new Entry(o.get("helper").getAsLong(), o.get("cell").getAsLong(),
					o.get("field").getAsString(), o.get("provenance").getAsString()));
			}
		}
		catch (RuntimeException e) {
			problems.add(new Problem(null, DescriptorSupport.SHADOW_COMMITS_PROPERTY +
				" is malformed (" + e.getMessage() + "); no shadow_commits hint applied"));
			return new Plan(source, Map.of(), problems);
		}
		Map<Long, Valid> byHelper = new LinkedHashMap<>();
		for (Entry entry : entries) {
			String what = "shadow_commits hint helper " + hex(entry.helper()) + " cell " +
				hex(entry.cell()) + " field '" + entry.field() + "' from " + who;
			Address where = baseAddress(program, entry.helper());
			String failed = validate(program, board, helpers, entry);
			if (failed != null) {
				problems.add(new Problem(where, what + " was not applied: " + failed));
				continue;
			}
			FieldSpec field = null;
			for (FieldSpec f : board.fieldSpecs()) {
				if (f.name().equals(entry.field())) {
					field = f;
				}
			}
			byHelper.put(entry.helper(),
				new Valid(entry.helper(), entry.cell(), field, entry.provenance()));
		}
		return new Plan(source, byHelper, problems);
	}

	/** Why {@code entry} cannot be applied, or null when it passes every check. */
	private static String validate(Program program, BoardModel board,
			Map<Function, HelperModel> helpers, Entry entry) {
		FieldSpec field = null;
		for (FieldSpec f : board.fieldSpecs()) {
			if (f.name().equals(entry.field())) {
				field = f;
			}
		}
		if (field == null) {
			return "'" + entry.field() + "' is not a banking.state field of this board";
		}
		List<HelperModel> models = new ArrayList<>();
		for (HelperModel h : helpers.values()) {
			if (h.entry().getOffset() == entry.helper() && h.constState() == null) {
				models.add(h);
			}
		}
		if (models.isEmpty()) {
			return "no function at " + hex(entry.helper()) +
				" was recognized as a bank-switch helper";
		}
		for (HelperModel h : models) {
			if ((field.positionedMask() & ~h.effectMask()) != 0) {
				return "the helper at " + h.entry() + " does not deposit all of field '" +
					entry.field() + "' (its effect mask is 0x" + Integer.toHexString(h.effectMask()) +
					", the field's 0x" + Integer.toHexString(field.positionedMask()) + ")";
			}
		}
		Listing listing = program.getListing();
		for (Instruction instr : listing.getInstructions(true)) {
			if (writesCell(instr, entry.cell()) && !followedByHelperCall(instr, entry.helper())) {
				return "the premise fails: the store at " + instr.getMinAddress() + " to cell " +
					hex(entry.cell()) + " is not followed, in its own basic block, by a call to " +
					hex(entry.helper());
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Instruction predicates
	// ------------------------------------------------------------------

	/** A direct (plain absolute / zero-page) write to the cell at {@code cellOffset}. */
	private static boolean writesCell(Instruction instr, long cellOffset) {
		if (!StoredValueScanner.writesMemory(instr)) {
			return false;
		}
		Address target = StoredValueScanner.plainAbsoluteTarget(instr);
		return target != null && target.getOffset() == cellOffset && isCpuSpace(target);
	}

	private static boolean isCpuSpace(Address a) {
		AddressSpace space = a.getAddressSpace();
		return space.isMemorySpace() || space.isOverlaySpace();
	}

	private static boolean callsHelper(Instruction instr, long helperOffset) {
		if (!instr.getFlowType().isCall()) {
			return false;
		}
		Address target = StoredValueScanner.plainAbsoluteTarget(instr);
		return target != null && target.getOffset() == helperOffset;
	}

	/** Whether the run of plain fall-through instructions after {@code store} reaches a call to the helper. */
	private static boolean followedByHelperCall(Instruction store, long helperOffset) {
		Listing listing = store.getProgram().getListing();
		Instruction cur = store;
		for (int i = 0; i < MAX_BLOCK_WALK; i++) {
			if (!cur.getFlowType().equals(FlowType.FALL_THROUGH)) {
				return false;
			}
			Address next = cur.getFallThrough();
			cur = next == null ? null : listing.getInstructionAt(next);
			if (cur == null) {
				return false;
			}
			if (callsHelper(cur, helperOffset)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a direct store to the cell lies earlier in {@code call}'s own basic block -- a run of
	 * plain fall-through instructions ending at the call.
	 */
	private static boolean storeEarlierInBlock(Instruction call, long cellOffset) {
		Instruction cur = call;
		for (int i = 0; i < MAX_BLOCK_WALK; i++) {
			Address from = cur.getFallFrom();
			if (from == null) {
				return false;
			}
			Instruction prev = cur.getProgram().getListing().getInstructionAt(from);
			if (prev == null) {
				return false;
			}
			if (writesCell(prev, cellOffset)) {
				return true;
			}
			if (!prev.getFlowType().equals(FlowType.FALL_THROUGH)) {
				return false;
			}
			cur = prev;
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Consumption
	// ------------------------------------------------------------------

	/**
	 * The validated hint for a call to {@code helper}, or null. A model whose effect mask does not
	 * cover the hinted field (a different modelling of the same offset) is not matched.
	 */
	static Valid hintFor(Plan plan, HelperModel helper) {
		if (plan.isEmpty() || helper.constState() != null) {
			return null;
		}
		Valid v = plan.byHelper().get(helper.entry().getOffset());
		return v != null && (v.field().positionedMask() & ~helper.effectMask()) == 0 ? v : null;
	}

	/**
	 * Applies the hint at one call. Returns {@code recovered} untouched when it does not apply
	 * (including: a store precedes the call but the cell's value is not known at all -- the call's
	 * warning stays, honestly).
	 *
	 * @param notes the engine's per-site hint notes; an applied deposit records one so the
	 *            annotation carries the "(game descriptor hint)" suffix and a disagreement with
	 *            dataflow is reported
	 */
	static CallEffect apply(Plan plan, Map<Address, SwitchSiteHints.HintNote> notes,
			CallEffect recovered, HelperModel helper, BankState outState, Program program,
			Instruction call, StateOracle oracle, StoredValueScanner.ProofMemo crossBlockMemo) {
		Valid hint = hintFor(plan, helper);
		if (hint == null) {
			return recovered;
		}
		FieldSpec field = hint.field();
		int fieldMask = field.positionedMask();
		if ((recovered.ownedMask() & fieldMask) == 0) {
			return recovered;
		}
		if (!storeEarlierInBlock(call, hint.cell())) {
			// Coherence premise: the cell holds the live field value, so the commit re-installs it.
			int owned = recovered.ownedMask() & ~fieldMask;
			BankState state = new BankState(recovered.state().knownMask() & owned,
				recovered.state().bits() & recovered.state().knownMask() & owned);
			boolean resolved = owned == 0 || (owned & ~state.knownMask()) == 0
					|| recovered.argumentResolved();
			return new CallEffect(state, owned, resolved, recovered.noInboundArgument(),
				recovered.secondTierRelay(), recovered.restoreCell(), recovered.readBack());
		}
		Address cell = program.getAddressFactory().getDefaultAddressSpace().getAddress(hint.cell());
		PartialByte value = HelperArgumentRecovery.callerCellAtCall(program, call, helper,
			outState, cell, field.widthMask(), oracle, crossBlockMemo);
		if (value.knownMask() == 0) {
			return recovered;
		}
		int known = (value.knownMask() & field.widthMask()) << field.lsb();
		int bits = (value.bits() & field.widthMask()) << field.lsb();
		BankState before = recovered.state();
		String differs = null;
		if (recovered.argumentResolved() && ((before.bits() ^ bits) & before.knownMask() & known) != 0) {
			differs = render(before.knownMask() & fieldMask, before.bits(), field);
		}
		int newKnown = (before.knownMask() & ~fieldMask) | known;
		int newBits = (before.bits() & ~fieldMask & newKnown) | bits;
		notes.put(call.getMinAddress(), new SwitchSiteHints.HintNote(
			(bits >>> field.lsb()) & field.widthMask(), true, null, differs));
		return new CallEffect(new BankState(newKnown, newBits), recovered.ownedMask(), true,
			recovered.noInboundArgument(), recovered.secondTierRelay(), recovered.restoreCell(),
			recovered.readBack());
	}

	private static String render(int knownMask, int bits, FieldSpec field) {
		int k = knownMask >>> field.lsb();
		int b = bits >>> field.lsb();
		return (k & field.widthMask()) == field.widthMask() ? Integer.toString(b & field.widthMask())
				: "partly known: bits 0x" + Integer.toHexString(b & k) + " of mask 0x" +
					Integer.toHexString(k);
	}

	// ------------------------------------------------------------------
	// Reporting
	// ------------------------------------------------------------------

	/**
	 * Raises (and retracts) this hint's WARNING bookmarks: one per entry that failed validation
	 * (naming the descriptor and the failed check; the call sites fall back to dataflow), and one
	 * per call where an applied hint overrode a DIFFERENT value dataflow had recovered (naming
	 * both). Own category, write-free on a settled program.
	 *
	 * @param valueHintSites addresses a {@code bank:} value hint governs, whose notes are not ours
	 * @return the warning texts raised, for the analyzer log
	 */
	static List<String> report(Program program, Plan plan,
			Map<Address, SwitchSiteHints.HintNote> notes, java.util.Set<Address> valueHintSites) {
		Map<Address, String> wanted = new LinkedHashMap<>();
		List<String> logOnly = new ArrayList<>();
		for (Problem p : plan.problems()) {
			if (p.where() == null) {
				logOnly.add(p.text());
			}
			else {
				wanted.merge(p.where(), p.text(), (a, b) -> a + " | " + b);
			}
		}
		for (Map.Entry<Address, SwitchSiteHints.HintNote> e : notes.entrySet()) {
			SwitchSiteHints.HintNote n = e.getValue();
			if (valueHintSites.contains(e.getKey()) || !n.applied() || n.recovered() == null) {
				continue;
			}
			wanted.put(e.getKey(), "shadow_commits hint from game descriptor " + plan.source() +
				" WINS over the bank dataflow recovered here (" + n.recovered() +
				"); if the recovered value is right, the hint is stale");
		}
		BookmarkManager bookmarks = program.getBookmarkManager();
		List<Bookmark> stale = new ArrayList<>();
		Iterator<Bookmark> it = bookmarks.getBookmarksIterator(BookmarkType.WARNING);
		while (it.hasNext()) {
			Bookmark b = it.next();
			if (BOOKMARK_CATEGORY.equals(b.getCategory()) && !wanted.containsKey(b.getAddress())) {
				stale.add(b);
			}
		}
		for (Bookmark b : stale) {
			bookmarks.removeBookmark(b);
		}
		for (Map.Entry<Address, String> w : wanted.entrySet()) {
			Bookmark existing =
				bookmarks.getBookmark(w.getKey(), BookmarkType.WARNING, BOOKMARK_CATEGORY);
			if (existing == null || !w.getValue().equals(existing.getComment())) {
				bookmarks.setBookmark(w.getKey(), BookmarkType.WARNING, BOOKMARK_CATEGORY,
					w.getValue());
			}
		}
		List<String> out = new ArrayList<>(wanted.values());
		out.addAll(logOnly);
		return out;
	}

	// ------------------------------------------------------------------

	private static String hex(long v) {
		return "0x" + Long.toHexString(v).toUpperCase();
	}

	/** A default-space address for a 16-bit CPU offset, or null when it is not in program memory. */
	private static Address baseAddress(Program program, long offset) {
		try {
			Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
			return a != null && program.getMemory().contains(a) ? a : null;
		}
		catch (RuntimeException e) {
			return null;
		}
	}
}
