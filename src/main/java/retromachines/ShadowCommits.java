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
import java.util.HashSet;
import java.util.Set;

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
	record Valid(long helper, long cell, FieldSpec field, String provenance,
			String directWrite) {

		/**
		 * Whether the FIELD is only ever written through the cell (field coherence): then a call
		 * with no store to the cell is a verified no-op on the field. Otherwise ({@code
		 * directWrite} names a mechanism write of the field outside the committing helpers) the
		 * hint runs in RESTORE mode: a call with no store restores the field from the cell, to a
		 * value the analyzer cannot know.
		 */
		boolean coherent() {
			return directWrite == null;
		}
	}

	/** A hint that was not applied: where to put the bookmark (may be null) and why. */
	record Problem(Address where, String text) {
	}

	/**
	 * The run's validated hints, keyed by the helper's entry OFFSET (a byte-identical home engine
	 * can be modelled once per bank copy, each in its own overlay space, so the offset -- not the
	 * space -- identifies the helper), several per helper when it commits several fields (smb3's
	 * FUN_fc6f commits r6 from one cell and r7 from another), plus the failures to report.
	 */
	record Plan(String source, Map<Long, List<Valid>> byHelper, List<Problem> problems) {

		static final Plan NONE = new Plan(null, Map.of(), List.of());

		/** One line per validated hint naming its mode, for the analyzer log. */
		List<String> modeLines() {
			List<String> out = new ArrayList<>();
			for (List<Valid> vs : byHelper.values()) {
				for (Valid v : vs) {
					out.add("shadow_commits hint helper " + hex(v.helper()) + " cell " +
						hex(v.cell()) + " field '" + v.field().name() + "': " + (v.coherent()
								? "COHERENT mode (the field is only written through the cell)"
								: "RESTORE mode (field also written directly: " + v.directWrite() +
									")"));
				}
			}
			return out;
		}

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
		return BankingHintKind.SHADOW_COMMITS.source(program);
	}

	/**
	 * Reads the property and validates every entry against {@code board} and the modelled
	 * {@code helpers}. {@link Plan#NONE} (and no work) when the descriptor states none.
	 */
	static Plan plan(Program program, BoardModel board, Map<Function, HelperModel> helpers) {
		return plan(program, board, helpers, Map.of());
	}

	/**
	 * As the 3-argument form, with the recognized mechanism-write sites ({@code switchResults}),
	 * which the FIELD-coherence premise needs: a hint whose field is also deposited by a mechanism
	 * write outside every committing helper's body runs in restore mode (see {@link Valid}).
	 */
	static Plan plan(Program program, BoardModel board, Map<Function, HelperModel> helpers,
			Map<Address, BankDataflowEngine.SwitchResult> switchResults) {
		if (!BankingHintKind.SHADOW_COMMITS.isRecorded(program)) {
			return Plan.NONE;
		}
		String source = source(program);
		String who = "game descriptor " + (source == null ? "(unknown)" : source);
		List<Problem> problems = new ArrayList<>();
		List<String> readProblems = new ArrayList<>();
		List<Entry> entries = BankingHintKind.SHADOW_COMMITS.read(program, readProblems,
			(o, root) -> new Entry(o.get("helper").getAsLong(), o.get("cell").getAsLong(),
				o.get("field").getAsString(), o.get("provenance").getAsString()));
		if (entries == null) {
			readProblems.forEach(text -> problems.add(new Problem(null, text)));
			return new Plan(source, Map.of(), problems);
		}
		// Pass 1: the structural checks (helper modelled, field within its effect mask).
		List<Valid> structural = new ArrayList<>();
		for (Entry entry : entries) {
			String failed = validateStructure(board, helpers, entry);
			if (failed != null) {
				problems.add(new Problem(baseAddress(program, entry.helper()),
					describe(entry, who) + " was not applied: " + failed));
				continue;
			}
			FieldSpec field = board.field(entry.field());
			structural.add(new Valid(entry.helper(), entry.cell(), field, entry.provenance(), null));
		}
		// Pass 2: the coherence premise. A store to a cell is committed by ANY structurally
		// valid hint's helper that commits the same field from the same cell, by a call or a
		// tail jump.
		Set<Long> allHelpers = new HashSet<>();
		for (Valid v : structural) {
			allHelpers.add(v.helper());
		}
		Map<Long, List<Valid>> byHelper = new LinkedHashMap<>();
		for (Valid v : structural) {
			Set<Long> committers = new HashSet<>();
			for (Valid other : structural) {
				if (other.cell() == v.cell() && other.field().name().equals(v.field().name())) {
					committers.add(other.helper());
				}
			}
			String failed = validatePremise(program, v, new Committers(program, committers, allHelpers));
			if (failed != null) {
				problems.add(new Problem(baseAddress(program, v.helper()),
					describe(new Entry(v.helper(), v.cell(), v.field().name(), v.provenance()), who) +
						" was not applied: " + failed));
				continue;
			}
			String direct = directFieldWrite(helpers, switchResults, v, committers);
			byHelper.computeIfAbsent(v.helper(), k -> new ArrayList<>())
					.add(new Valid(v.helper(), v.cell(), v.field(), v.provenance(), direct));
		}
		return new Plan(source, byHelper, problems);
	}

	/**
	 * FIELD coherence: a description of a recognized mechanism write that deposits any bit of the
	 * hint's field from OUTSIDE the bodies of every committing helper (so the field can change
	 * without the cell), or null when there is none.
	 */
	private static String directFieldWrite(Map<Function, HelperModel> helpers,
			Map<Address, BankDataflowEngine.SwitchResult> switchResults, Valid v,
			Set<Long> committers) {
		ghidra.program.model.address.AddressSet bodies = new ghidra.program.model.address.AddressSet();
		for (HelperModel h : helpers.values()) {
			if (committers.contains(h.entry().getOffset())) {
				bodies.add(h.function().getBody());
			}
		}
		Address first = null;
		int count = 0;
		for (Map.Entry<Address, BankDataflowEngine.SwitchResult> e : switchResults.entrySet()) {
			if ((e.getValue().effectMask() & v.field().positionedMask()) == 0 ||
				bodies.contains(e.getKey())) {
				continue;
			}
			count++;
			if (first == null || e.getKey().compareTo(first) < 0) {
				first = e.getKey();
			}
		}
		return first == null ? null : count + " mechanism write(s) outside the committing helpers, first at " + first;
	}

	private static String describe(Entry entry, String who) {
		return "shadow_commits hint helper " + hex(entry.helper()) + " cell " + hex(entry.cell()) +
			" field '" + entry.field() + "' from " + who;
	}

	/** Why {@code entry} cannot be applied for want of a helper or field, or null. */
	private static String validateStructure(BoardModel board, Map<Function, HelperModel> helpers,
			Entry entry) {
		FieldSpec field = board.field(entry.field());
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
		return null;
	}

	/** Why the coherence premise fails for {@code v} given the field's committing helpers, or null. */
	private static String validatePremise(Program program, Valid v, Committers committers) {
		for (Instruction instr : program.getListing().getInstructions(true)) {
			if (writesCell(instr, v.cell()) && !committers.followsStore(instr)) {
				return "the premise fails: the store at " + instr.getMinAddress() + " to cell " +
					hex(v.cell()) + " is not followed, in its own basic block, by a call or tail jump to (or a thin wrapper entering) " +
					(committers.direct().size() == 1 ? "" : "any of ") + committers.direct().stream()
							.map(ShadowCommits::hex).sorted().toList() +
					" (the helpers committing field '" + v.field().name() + "' from it)";
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Instruction predicates
	// ------------------------------------------------------------------

	/** A direct (plain absolute / zero-page) write to the cell at {@code cellOffset}. */
	private static boolean writesCell(Instruction instr, long cellOffset) {
		if (!LocalStoreForwarding.writesMemory(instr)) {
			return false;
		}
		Address target = MosOperands.plainAbsoluteTarget(instr);
		return target != null && target.getOffset() == cellOffset && isCpuSpace(target);
	}

	private static boolean isCpuSpace(Address a) {
		AddressSpace space = a.getAddressSpace();
		return space.isMemorySpace() || space.isOverlaySpace();
	}

	/**
	 * The helpers that commit one (cell, field) pair, for the coherence premise. {@code direct}
	 * are the hinted helpers' entry offsets for that pair; {@code all} every hinted helper of the
	 * descriptor (a thin wrapper may call helpers of other fields on its way).
	 * <p>
	 * A store is committed when its own fall-through run reaches a CALL or an unconditional
	 * TAIL JUMP to a direct committer, or to a thin WRAPPER of one: an address whose own
	 * fall-through run (stepping over calls to hinted helpers) calls, jumps to, or falls into a
	 * direct committer. smb3's {@code FFBF JSR $FFD1} falling into {@code FFC2} is the case: it is
	 * not a modelled helper itself, yet every store followed by it is committed.
	 */
	private static final class Committers {
		private final Program program;
		private final Set<Long> direct;
		private final Set<Long> all;
		private final Map<Address, Boolean> wrapperMemo = new java.util.HashMap<>();

		Committers(Program program, Set<Long> direct, Set<Long> all) {
			this.program = program;
			this.direct = direct;
			this.all = all;
		}

		Set<Long> direct() {
			return direct;
		}

		/** Whether the run of plain fall-through instructions after {@code store} commits it. */
		boolean followsStore(Instruction store) {
			Listing listing = program.getListing();
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
				Address target = transferTarget(cur);
				if (target != null && (direct.contains(target.getOffset()) || isWrapper(target))) {
					return true;
				}
			}
			return false;
		}

		private boolean isWrapper(Address entry) {
			Boolean known = wrapperMemo.get(entry);
			if (known == null) {
				wrapperMemo.put(entry, Boolean.FALSE); // a cycle commits nothing
				known = computeWrapper(entry);
				wrapperMemo.put(entry, known);
			}
			return known;
		}

		private boolean computeWrapper(Address entry) {
			Listing listing = program.getListing();
			Instruction cur = listing.getInstructionAt(entry);
			for (int i = 0; i < MAX_BLOCK_WALK && cur != null; i++) {
				if (i > 0 && direct.contains(cur.getMinAddress().getOffset())) {
					return true; // fell into a committer's entry
				}
				Address target = transferTarget(cur);
				if (target != null && direct.contains(target.getOffset())) {
					return true;
				}
				FlowType flow = cur.getFlowType();
				if (flow.isCall()) {
					// step over a call only to a hinted helper (known to return, known effect)
					if (target == null || !all.contains(target.getOffset())) {
						return false;
					}
				}
				else if (!flow.equals(FlowType.FALL_THROUGH)) {
					return false;
				}
				Address next = cur.getFallThrough();
				cur = next == null ? null : listing.getInstructionAt(next);
			}
			return false;
		}
	}

	/** The target of a call or unconditional non-computed jump with a plain absolute operand, else null. */
	private static Address transferTarget(Instruction instr) {
		FlowType flow = instr.getFlowType();
		boolean call = flow.isCall();
		boolean tail = flow.isJump() && flow.isUnConditional() && !flow.isComputed();
		return call || tail ? MosOperands.plainAbsoluteTarget(instr) : null;
	}

	/**
	 * The nearest direct store to the cell earlier in {@code call}'s own basic block -- a run of
	 * plain fall-through instructions ending at the call -- or null.
	 */
	private static Instruction storeEarlierInBlock(Instruction call, long cellOffset) {
		Instruction cur = call;
		for (int i = 0; i < MAX_BLOCK_WALK; i++) {
			Address from = cur.getFallFrom();
			if (from == null) {
				return null;
			}
			Instruction prev = cur.getProgram().getListing().getInstructionAt(from);
			if (prev == null) {
				return null;
			}
			if (writesCell(prev, cellOffset)) {
				return prev;
			}
			if (!prev.getFlowType().equals(FlowType.FALL_THROUGH)) {
				return null;
			}
			cur = prev;
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Consumption
	// ------------------------------------------------------------------

	/**
	 * The validated hints for a call to {@code helper}, empty when none. A model whose effect mask
	 * does not cover a hinted field (a different modelling of the same offset) is not matched for
	 * that hint.
	 */
	static List<Valid> hintsFor(Plan plan, HelperModel helper) {
		if (plan.isEmpty() || helper.constState() != null) {
			return List.of();
		}
		List<Valid> out = new ArrayList<>();
		for (Valid v : plan.byHelper().getOrDefault(helper.entry().getOffset(), List.of())) {
			if ((v.field().positionedMask() & ~helper.effectMask()) == 0) {
				out.add(v);
			}
		}
		return out;
	}

	/**
	 * Applies the hints at one call, each independently and in descriptor order. Returns
	 * {@code recovered} untouched when none applies (including: a store precedes the call but the
	 * cell's value is not known at all -- the call's warning stays, honestly, unless that store
	 * demonstrably stores the enclosing function's INBOUND register, see {@link #relayDetail}).
	 *
	 * @param notes the engine's per-site hint notes; an applied deposit records one so the
	 *            annotation carries the "(game descriptor hint)" suffix and a disagreement with
	 *            dataflow is reported
	 */
	static CallEffect apply(Plan plan, Map<Address, SwitchSiteHints.HintNote> notes,
			CallEffect recovered, HelperModel helper, BankState outState, Program program,
			Instruction call, StateOracle oracle, StoredValueScanner.ProofMemo crossBlockMemo) {
		CallEffect effect = recovered;
		Integer bank = null;
		List<String> differs = new ArrayList<>();
		List<String> relays = new ArrayList<>();
		List<String> restores = new ArrayList<>();
		for (Valid hint : hintsFor(plan, helper)) {
			FieldSpec field = hint.field();
			int fieldMask = field.positionedMask();
			if ((effect.ownedMask() & fieldMask) == 0) {
				continue;
			}
			Instruction store = storeEarlierInBlock(call, hint.cell());
			if (store == null && !hint.coherent()) {
				// RESTORE mode: the field is also written directly elsewhere, so the cell is the
				// last value committed THROUGH it, not the live field. The call restores the
				// field from the cell to a value this analyzer cannot know.
				if (effect.argumentResolved()) {
					continue;
				}
				BankState state = new BankState(effect.state().knownMask() & ~fieldMask,
					effect.state().bits() & ~fieldMask);
				Address restoreFrom = program.getAddressFactory().getDefaultAddressSpace()
						.getAddress(hint.cell());
				effect = effect.withState(state).withResolved(false).withRestoreCell(
					effect.restoreCell() != null ? effect.restoreCell() : restoreFrom);
				restores.add(String.format("%s from $%04X", field.name(), hint.cell()));
				continue;
			}
			if (store == null) {
				// Coherence premise: the cell holds the live field value, so the commit re-installs it.
				int owned = effect.ownedMask() & ~fieldMask;
				BankState state = new BankState(effect.state().knownMask() & owned,
					effect.state().bits() & effect.state().knownMask() & owned);
				boolean resolved = owned == 0 || (owned & ~state.knownMask()) == 0
						|| effect.argumentResolved();
				effect = effect.withState(state).withOwnedMask(owned).withResolved(resolved);
				continue;
			}
			Address cell =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(hint.cell());
			PartialByte value = HelperArgumentRecovery.callerCellAtCall(program, call, helper,
				outState, cell, field.widthMask(), oracle, crossBlockMemo);
			if (value.knownMask() == 0) {
				String relay = effect.argumentResolved() ? null
						: relayDetail(program, call, store, hint);
				if (relay != null) {
					effect = effect.asSecondTierRelay();
					relays.add(relay);
				}
				continue;
			}
			int known = (value.knownMask() & field.widthMask()) << field.lsb();
			int bits = (value.bits() & field.widthMask()) << field.lsb();
			BankState before = effect.state();
			boolean differsHere = recovered.argumentResolved() &&
				((recovered.state().bits() ^ bits) & recovered.state().knownMask() & known) != 0;
			if (differsHere) {
				differs.add(render(recovered.state().knownMask() & fieldMask,
					recovered.state().bits(), field));
			}
			int newKnown = (before.knownMask() & ~fieldMask) | known;
			int newBits = (before.bits() & ~fieldMask & newKnown) | bits;
			if (!recovered.argumentResolved() || differsHere) {
				// a hint that merely agrees with what dataflow resolved itself changes nothing,
				// so it neither earns the "(game descriptor hint)" suffix nor a note
				bank = (bits >>> field.lsb()) & field.widthMask();
			}
			effect = effect.withState(new BankState(newKnown, newBits)).withResolved(
				effect.argumentResolved() || (effect.ownedMask() & ~newKnown) == 0);
		}
		if (!restores.isEmpty() && !effect.argumentResolved() && relays.isEmpty()) {
			relays.add("Bank value is RESTORED here, not resolved: this call's helper " +
				helper.function().getName() + " restores " + String.join(" and ", restores) +
				" (the shadow cell(s) the game committed through earlier). The field is also " +
				"written directly elsewhere in the game (not through the cell), so the cell " +
				"tracks the last value committed through it, not the live bank; the bank after " +
				"this call is that saved value, not a fresh one this analyzer failed to pin " +
				"down -- a property of the game, not a gap in analysis.");
		}
		else if (!restores.isEmpty()) {
			restores.clear();
		}
		if (bank != null || !relays.isEmpty()) {
			notes.put(call.getMinAddress(),
				new SwitchSiteHints.HintNote(bank == null ? 0 : bank, bank != null, null,
					differs.isEmpty() ? null : String.join("; ", differs),
					relays.isEmpty() ? null : String.join(" ", relays)));
		}
		return effect;
	}

	/**
	 * The NOTE text when the store to the hinted cell stores the enclosing function's INBOUND
	 * register on every path ({@link HelperDiscovery#inboundRegisterOrigin} with the store as its
	 * sink; it declines on anything it cannot prove): the committed value is the far-call argument
	 * each caller supplies, so it is resolved at the callers, not here. Null otherwise.
	 */
	private static String relayDetail(Program program, Instruction call, Instruction store,
			Valid hint) {
		char reg = switch (store.getMnemonicString().toUpperCase()) {
			case "STA" -> 'A';
			case "STX" -> 'X';
			case "STY" -> 'Y';
			default -> '?';
		};
		Function fn = program.getFunctionManager().getFunctionContaining(call.getMinAddress());
		if (reg == '?' || fn == null || !fn.getBody().contains(store.getMinAddress())) {
			return null;
		}
		Character origin = HelperDiscovery.inboundRegisterOrigin(program, fn,
			store.getMinAddress(), reg, Map.of());
		if (origin == null) {
			return null;
		}
		return "Bank value is the inbound argument of " + fn.getName() + ": the shadow cell " +
			String.format("$%04X", hint.cell()) + " is stored from register " + reg +
			", which this function never defines" +
			(origin == reg ? "" : " (it holds the inbound " + origin + ")") +
			"; each caller supplies it (a far-call / relay), so it is resolved at the callers, " +
			"not here.";
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
