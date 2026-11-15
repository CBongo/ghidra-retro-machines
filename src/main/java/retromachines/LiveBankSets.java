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
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import retromachines.BoardDescriptorModel.BoardModel.BankedWindow;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Per-game {@code banking.live_bank_sets} hints (bead grm-5tl.20.5, design in grm-5tl.20.3): "the
 * live value of board state field {@code field} is always one of {@code valueset}". The game
 * decides the bank in one place (a request cell, set long before the switch) and applies it in
 * another, so the bank at a banked reference is a SET the analysis cannot narrow by dataflow.
 * <p>
 * <b>The hint wins.</b> Unlike {@link ShadowCommits}, a failed cross-check does not unapply the
 * hint: a contradiction between the descriptor and what dataflow recovered more likely means the
 * dataflow went wrong (docs/per-game-descriptors-design.md section 6.3). Validation therefore
 * WARNS and the hint still applies, except for shape-level impossibility, which refuses it:
 * <ul>
 * <li>{@code field} is not a {@code banking.state} field of the matched board;</li>
 * <li>a {@code valueset} member the field cannot hold (wider than the field, or a bank none of
 * the windows the field maps can realize for this image);</li>
 * <li>{@code request.decode} does not evaluate.</li>
 * </ul>
 * <b>Writer check.</b> Every DIRECT store (absolute or zero-page, unindexed) to {@code
 * request.cell} or {@code applied}, in the fixed bank and every overlay, has its stored value
 * recovered by {@link StoredValueScanner}. A request-cell value is acceptable iff it is in
 * {@code idle} or {@code decode(value)} is in {@code valueset}; an {@code applied} value iff it
 * is in {@code valueset}. An unacceptable value raises a WARNING bookmark AT THE WRITER. A writer
 * whose value is not recovered, a read-modify-write, and an indexed store the references show
 * reaching the cell are counted as "stated, not checked" -- the hint's provenance carries them.
 * Indirect stores ({@code STA (zp),Y}) cannot be located and are invisible to this check.
 * <p>
 * The emission phase asks {@link Plan#candidates} what a banked reference may be under the set.
 */
final class LiveBankSets {

	/** Bookmark category of this hint's WARNINGs (a contradicting writer; a refused hint). */
	static final String BOOKMARK_CATEGORY = "Game descriptor live bank set";

	/** Most unchecked writer addresses named in one log line. */
	private static final int LOG_WRITER_LIMIT = 12;

	/** {@code request:} of one entry. */
	record Request(long cell, String decode, Set<Integer> idle) {
	}

	/** One recorded entry. {@code applied} is a CPU address or null. */
	record Hint(String field, List<Integer> valueset, Request request, Long applied,
			String provenance) {
	}

	/** A finding to report: where to put the bookmark (null = log only) and what to say. */
	record Problem(Address where, String text) {
	}

	/**
	 * The run's applied hints keyed by FIELD NAME, plus the findings to report and the one
	 * analyzer log line per hint.
	 */
	record Plan(String source, Map<String, Hint> byField, List<Problem> problems,
			List<String> logLines) {

		static final Plan NONE = new Plan(null, Map.of(), List.of(), List.of());

		boolean isEmpty() {
			return byField.isEmpty();
		}

		/**
		 * The candidate FIELD values a banked reference may have under the descriptor's set: the
		 * {@code valueset} members of {@code field} agreeing with the tracked state's known bits.
		 * {@code knownMask}/{@code bits} are in the field's own coordinates (bit 0 = the field's
		 * LSB; {@code bits} outside {@code knownMask} are ignored). Null when no applied hint
		 * names {@code field} (the caller keeps its dataflow answer); otherwise members in
		 * descriptor order, EMPTY when the known bits contradict the whole set -- the caller's
		 * "hint wins, warn" row.
		 */
		List<Integer> candidates(String field, int knownMask, int bits) {
			return candidatesOf(byField.get(field), knownMask, bits);
		}
	}

	private LiveBankSets() {
	}

	/** See {@link Plan#candidates}; a pure function of the hint and the known bits. */
	static List<Integer> candidatesOf(Hint hint, int knownMask, int bits) {
		if (hint == null) {
			return null;
		}
		List<Integer> out = new ArrayList<>();
		for (int v : hint.valueset()) {
			if (((v ^ bits) & knownMask) == 0) {
				out.add(v);
			}
		}
		return out;
	}

	/** The descriptor-recorded source path, or null when absent/unreadable. */
	static String source(Program program) {
		return BankingHintKind.LIVE_BANK_SETS.source(program);
	}

	/** Reads the property; null (after reporting through {@code problems}) when malformed. */
	static List<Hint> parse(Program program, List<String> problems) {
		return BankingHintKind.LIVE_BANK_SETS.read(program, problems, (o, root) -> parseEntry(o));
	}

	private static Hint parseEntry(JsonObject o) {
		List<Integer> valueset = new ArrayList<>();
		for (JsonElement el : o.getAsJsonArray("valueset")) {
			valueset.add(el.getAsInt());
		}
		Request request = null;
		if (o.has("request")) {
			JsonObject r = o.getAsJsonObject("request");
			Set<Integer> idle = new TreeSet<>();
			if (r.has("idle")) {
				for (JsonElement el : r.getAsJsonArray("idle")) {
					idle.add(el.getAsInt());
				}
			}
			request = new Request(r.get("cell").getAsLong(), r.get("decode").getAsString(), idle);
		}
		return new Hint(o.get("field").getAsString(), valueset, request,
			o.has("applied") ? o.get("applied").getAsLong() : null,
			o.get("provenance").getAsString());
	}

	/**
	 * Reads and validates every entry once per analysis run against {@code board}: refusals
	 * (shape-level impossibility) are not applied; every other hint applies and has its writers
	 * checked. {@link Plan#NONE} (and no work) when the descriptor states none.
	 *
	 * @param bankUniverse the realized banks per window ({@link BankAnnotationAdapter#bankUniverse})
	 */
	static Plan plan(Program program, BoardModel board, Map<String, Set<Integer>> bankUniverse) {
		if (!BankingHintKind.LIVE_BANK_SETS.isRecorded(program)) {
			return Plan.NONE;
		}
		String source = source(program);
		String who = "game descriptor " + (source == null ? "(unknown)" : source);
		List<Problem> problems = new ArrayList<>();
		List<String> log = new ArrayList<>();
		List<String> readProblems = new ArrayList<>();
		List<Hint> hints = parse(program, readProblems);
		if (hints == null) {
			readProblems.forEach(text -> {
				problems.add(new Problem(null, text));
				log.add(text);
			});
			return new Plan(source, Map.of(), problems, log);
		}
		Map<String, Hint> applied = new LinkedHashMap<>();
		List<Hint> toScan = new ArrayList<>();
		for (Hint hint : hints) {
			String refusal = refusal(board, bankUniverse, hint);
			if (refusal != null) {
				String text = describe(hint, who) + " was not applied: " + refusal;
				problems.add(new Problem(anchor(program), text));
				log.add("live_bank_sets hint field '" + hint.field() + "' valueset " +
					hint.valueset() + ": REFUSED (" + refusal + ")");
				continue;
			}
			applied.put(hint.field(), hint);
			toScan.add(hint);
		}
		if (!toScan.isEmpty()) {
			scanWriters(program, toScan, who, problems, log);
		}
		return new Plan(source, applied, problems, log);
	}

	/**
	 * Where a finding with no writer of its own (a refused hint) is bookmarked: the program's
	 * first entry point, else its lowest address; null when it has neither (log only).
	 */
	private static Address anchor(Program program) {
		var entries = program.getSymbolTable().getExternalEntryPointIterator();
		if (entries.hasNext()) {
			return entries.next();
		}
		return program.getMinAddress();
	}

	/** Why {@code hint} is impossible for this board and image, or null. */
	private static String refusal(BoardModel board, Map<String, Set<Integer>> bankUniverse,
			Hint hint) {
		FieldSpec field = board.field(hint.field());
		if (field == null) {
			return "'" + hint.field() + "' is not a banking.state field of this board";
		}
		List<Set<Integer>> realized = new ArrayList<>();
		for (BankedWindow w : board.bankedWindows()) {
			Set<Integer> banks = bankUniverse.get(w.universeKey());
			if (w.field().name().equals(field.name()) && banks != null && !banks.isEmpty()) {
				realized.add(banks);
			}
		}
		for (int v : hint.valueset()) {
			if (v > field.widthMask()) {
				return "valueset member " + v + " is wider than field '" + field.name() + "' (" +
					Integer.bitCount(field.widthMask()) + " bits)";
			}
			if (!realized.isEmpty()) {
				boolean any = false;
				for (Set<Integer> banks : realized) {
					any |= banks.contains(BankAnnotationAdapter.canonicalBank(board.bankWrap(),
						banks, v));
				}
				if (!any) {
					return "valueset member " + v + " is a bank no window mapped by field '" +
						field.name() + "' realizes in this image";
				}
			}
		}
		if (hint.request() != null) {
			try {
				DescriptorExpressions.evalValueExpr(hint.request().decode(), 0);
			}
			catch (RuntimeException e) {
				return "decode '" + hint.request().decode() + "' is not evaluable (" +
					e.getMessage() + ")";
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Writer check
	// ------------------------------------------------------------------

	/** Per-hint tallies. */
	private static final class Tally {
		int checked;
		int contradicting;
		final List<Address> unchecked = new ArrayList<>();
	}

	private static void scanWriters(Program program, List<Hint> hints, String who,
			List<Problem> problems, List<String> log) {
		Map<Hint, Tally> tallies = new LinkedHashMap<>();
		for (Hint h : hints) {
			tallies.put(h, new Tally());
		}
		AddressSpace cpu = program.getAddressFactory().getDefaultAddressSpace();
		for (Instruction instr : program.getListing().getInstructions(true)) {
			if (!LocalStoreForwarding.writesMemory(instr)) {
				continue;
			}
			Address plain = MosOperands.plainAbsoluteTarget(instr);
			for (Hint hint : hints) {
				Tally tally = tallies.get(hint);
				for (int which = 0; which < 2; which++) {
					Long cell = which == 0 ? (hint.request() == null ? null : hint.request().cell())
							: hint.applied();
					if (cell == null) {
						continue;
					}
					if (plain != null) {
						if (plain.getOffset() != cell || !isCpuSpace(plain)) {
							continue;
						}
						Character reg = MosOperands.storeRegister(instr);
						PartialByte value = reg == null ? PartialByte.unknown()
								: StoredValueScanner.resolveStoredValue(program, instr, reg,
									MechanismState.unknown(), 0xFF, StoredValueScanner.Hooks.INERT);
						if (!value.knowsAll(0xFF)) {
							tally.unchecked.add(instr.getMinAddress());
							continue;
						}
						tally.checked++;
						String bad = which == 0 ? requestProblem(hint, value.bits())
								: appliedProblem(hint, value.bits());
						if (bad != null) {
							tally.contradicting++;
							problems.add(new Problem(instr.getMinAddress(),
								describe(hint, who) + ": " + bad +
									"; the hint STILL APPLIES -- the dataflow or the hint needs " +
									"investigating"));
						}
					}
					else if (MosOperands.writesAddress(instr, cpu.getAddress(cell))) {
						tally.unchecked.add(instr.getMinAddress());
					}
				}
			}
		}
		for (Map.Entry<Hint, Tally> e : tallies.entrySet()) {
			Hint h = e.getKey();
			Tally t = e.getValue();
			List<Address> unchecked = new ArrayList<>(new TreeSet<>(t.unchecked));
			String where = unchecked.stream().limit(LOG_WRITER_LIMIT).map(Object::toString)
					.reduce((a, b) -> a + ", " + b).orElse("");
			log.add("live_bank_sets hint field '" + h.field() + "' valueset " + h.valueset() +
				": applied; cells " + cellsText(h) + ": " + t.checked + " writer(s) checked, " +
				unchecked.size() + " stated, not checked" +
				(unchecked.isEmpty() ? ""
						: " (at " + where +
							(unchecked.size() > LOG_WRITER_LIMIT ? ", ..." : "") + ")") +
				", " + t.contradicting + " contradicting");
		}
	}

	private static String cellsText(Hint h) {
		List<String> cells = new ArrayList<>();
		if (h.request() != null) {
			cells.add("request " + hex(h.request().cell()));
		}
		if (h.applied() != null) {
			cells.add("applied " + hex(h.applied()));
		}
		return cells.isEmpty() ? "(none stated)" : String.join(", ", cells);
	}

	/** Why a request-cell store of {@code value} contradicts {@code hint}, or null. */
	private static String requestProblem(Hint hint, int value) {
		Request r = hint.request();
		if (r.idle().contains(value)) {
			return null;
		}
		long decoded = DescriptorExpressions.evalValueExpr(r.decode(), value);
		if (decoded == (int) decoded && hint.valueset().contains((int) decoded)) {
			return null;
		}
		return "request cell " + hex(r.cell()) + " is stored " + value + ", which decodes (" +
			r.decode() + ") to " + decoded + ", outside valueset " + hint.valueset() +
			" and not an idle value " + r.idle();
	}

	/** Why an applied-cell store of {@code value} contradicts {@code hint}, or null. */
	private static String appliedProblem(Hint hint, int value) {
		return hint.valueset().contains(value) ? null
				: "applied cell " + hex(hint.applied()) + " is stored " + value +
					", outside valueset " + hint.valueset();
	}

	private static boolean isCpuSpace(Address a) {
		AddressSpace space = a.getAddressSpace();
		return space.isMemorySpace() || space.isOverlaySpace();
	}

	private static String describe(Hint hint, String who) {
		return "live_bank_sets hint field '" + hint.field() + "' valueset " + hint.valueset() +
			" from " + who;
	}

	// ------------------------------------------------------------------
	// Reporting
	// ------------------------------------------------------------------

	/**
	 * Raises (and retracts) this hint's WARNING bookmarks: one per contradicting writer, in its own
	 * category, write-free on a settled program (the same sweep every own-category hint uses, so a
	 * writer an earlier round flagged and this round does not is retracted). Findings without an
	 * address are log-only.
	 *
	 * @return the warning texts raised, for the analyzer log
	 */
	static List<String> report(Program program, Plan plan) {
		return report(program, plan, Map.of());
	}

	/**
	 * As {@link #report(Program, Plan)}, plus {@code siteWarnings}: sites where emission had to
	 * override what dataflow knew (the hint wins), keyed by the reference site.
	 */
	static List<String> report(Program program, Plan plan, Map<Address, String> siteWarnings) {
		Map<Address, String> wanted = new LinkedHashMap<>();
		siteWarnings.forEach((at, text) -> wanted.merge(at, text, (a, b) -> a + " | " + b));
		List<String> logOnly = new ArrayList<>();
		for (Problem p : plan.problems()) {
			if (p.where() == null) {
				logOnly.add(p.text());
			}
			else {
				wanted.merge(p.where(), p.text(), (a, b) -> a + " | " + b);
			}
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

	private static String hex(long v) {
		return "0x" + Long.toHexString(v).toUpperCase(java.util.Locale.ROOT);
	}
}
