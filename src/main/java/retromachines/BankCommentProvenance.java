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
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/**
 * The analyzer's record of which bank EOL comments IT wrote, and with exactly what text
 * (bead grm-3mg0) -- so a later analysis round can retract or refresh its own annotation
 * without guessing, and without ever touching a human's.
 *
 * <h2>Why a property map and not a marker string</h2>
 * {@link AnnotationGuard#addComment} is append-only and idempotent on a caller-supplied MARKER
 * substring, which makes it FIRST-WRITER-WINS: once any round leaves a comment containing
 * {@code "bank ->"} at an address, every later round is a no-op there. That is two defects at
 * once. A round that would write NOTHING leaves the earlier round's comment standing (the
 * demonstrated case: {@code nesskiptest} c00c keeps a {@code via FUN_c170} attribution from a
 * pre-repair round in which that helper was still recognized), and a round that would write
 * BETTER text -- dataflow improves as more code is disassembled -- cannot replace a stale
 * partial. Both make the golden depend on the SEQUENCE of analysis rounds rather than on the
 * final program state, which is the real defect: "import then analyze" and "analyze, edit,
 * re-analyze" can disagree, and only the second is what the fixtures measure.
 * <p>
 * The obvious fix -- split the comment on {@code "; "} and drop segments starting with the
 * marker -- is NOT taken, and the reason is the same one {@link AnnotationGuard}'s class javadoc
 * gives for never replacing a comment: {@code "bank -> 5"} is text a HUMAN might plausibly type
 * at a bank-switch site. Matching on it would delete their work, reintroducing exactly the
 * hazard that class exists to close. Ghidra comments carry no {@code SourceType}, so the
 * provenance has to be recorded somewhere; this is that somewhere.
 * <p>
 * {@link Program#getUsrPropertyManager()} gives every program a namespaced, persisted,
 * per-address property store that never appears in the listing. Keeping the EXACT string we
 * wrote (not merely "we wrote here") lets retraction be an exact segment removal and, just as
 * importantly, lets a settled re-run recognize that it has nothing to do.
 *
 * <h2>Write-freedom is a correctness requirement, not an optimization</h2>
 * {@code BoardBankAnalyzer}'s redundant-re-run gate compares a stored stamp against
 * {@link Program#getModificationNumber()}, and its own comment warns that a path which mutates
 * when it should not degrades the gate to "hit, miss, hit, miss". So a round that recomputes
 * the SAME annotation must perform no write at all: {@link #plan} returns
 * {@link Plan#UNCHANGED} in that case, and {@link #sweep} retracts nothing when every recorded
 * address was touched. A settled program therefore costs zero mutations here, exactly as it did
 * before this class existed.
 *
 * <h2>Failing safe when the record and the listing disagree</h2>
 * A user may edit or delete our comment between rounds. Then the recorded text is no longer
 * present and we cannot know which part of what is there is ours. Every such case resolves the
 * same way: <b>touch nothing, and drop the record.</b> We neither retract (we would be cutting
 * into text we did not write) nor re-add (the human's edit is the more recent statement about
 * that address). This is the one direction that cannot destroy work, which is the same
 * principle -- and for the same reason -- as append-only was.
 */
final class BankCommentProvenance {

	/**
	 * The user-property-map name. Namespaced like {@link DescriptorSupport}'s program-info
	 * properties so it cannot collide with another extension's map.
	 */
	static final String PROPERTY_MAP = "Retro Machines.Bank Comment";

	/** The comment type every bank annotation goes in; retraction must target the same one. */
	private static final CommentType TYPE = CommentType.EOL;

	/** How {@link AnnotationGuard#addComment} joins an appended annotation to existing text. */
	private static final String JOIN = "; ";

	private final Program program;
	private final StringPropertyMap map;

	/**
	 * Addresses this run has accounted for -- whether it rewrote them, left them alone as
	 * already-correct, or deliberately declined. {@link #sweep} retracts recorded addresses
	 * NOT in this set, which is precisely "sites an earlier round annotated and this one does
	 * not".
	 */
	private final Set<Address> touched = new LinkedHashSet<>();

	private BankCommentProvenance(Program program, StringPropertyMap map) {
		this.program = program;
		this.map = map;
	}

	/**
	 * Opens (creating if absent) this program's bank-comment provenance map, or null when the
	 * map cannot be created because a map of that name exists with a different value type.
	 * A null result must degrade to the old append-only behaviour rather than failing analysis:
	 * losing retraction is a far smaller harm than refusing to annotate.
	 */
	static BankCommentProvenance open(Program program) {
		StringPropertyMap existing =
			program.getUsrPropertyManager().getStringPropertyMap(PROPERTY_MAP);
		if (existing != null) {
			return new BankCommentProvenance(program, existing);
		}
		try {
			return new BankCommentProvenance(program,
				program.getUsrPropertyManager().createStringPropertyMap(PROPERTY_MAP));
		}
		catch (DuplicateNameException e) {
			return null; // a non-String map already owns the name; degrade, do not throw
		}
	}

	/**
	 * What {@link #plan} decided for one address: the comment text to install ({@code null}
	 * meaning "leave the listing alone"), and whether the provenance record should now hold
	 * {@code record} for this address.
	 */
	record Plan(String comment, String record, boolean write) {

		/** Nothing to do: the listing already says exactly what this round would say. */
		static final Plan UNCHANGED = new Plan(null, null, false);
	}

	/**
	 * Decides what should happen for an annotation of {@code text}, given only strings -- no
	 * {@link Program}, no {@link Listing}, no property map. Static and pure on purpose: this is
	 * the entire rule, it is the part with the subtle cases, and keeping it free of Ghidra types
	 * means it can be exercised exhaustively in a plain JUnit test rather than behind a
	 * {@code ProgramBuilder} fixture (the discipline docs/testing.md asks for).
	 *
	 * @param recorded what this analyzer last recorded writing here, or null if nothing
	 * @param existing the current comment, or null
	 * @param text the annotation this round wants to place
	 * @param marker the caller's idempotence key (see {@link AnnotationGuard#addComment}); when
	 *            the remaining text already carries it, another writer in THIS round got there
	 *            first and we defer, preserving the deferral
	 *            {@code annotatePlacementProvenance} documents
	 */
	static Plan plan(String recorded, String existing, String text, String marker) {
		String base = existing;
		if (recorded != null) {
			if (recorded.equals(text) && containsSegment(existing, recorded)) {
				return Plan.UNCHANGED; // settled: no mutation, see the class javadoc
			}
			base = removeSegment(existing, recorded);
			if (base == null) {
				// Our recorded text is gone -- edited or deleted by a human. Fail safe.
				return new Plan(null, null, false);
			}
		}
		if (base != null && !base.isBlank() && base.contains(marker)) {
			return new Plan(null, null, false); // defer to this round's earlier writer
		}
		String combined = base == null || base.isBlank() ? text : base + JOIN + text;
		return new Plan(combined, text, true);
	}

	/**
	 * Applies {@link #plan}'s decision at {@code addr} and marks the address accounted for, so
	 * {@link #sweep} will not retract it. Returns whether the listing was written.
	 */
	boolean apply(Listing listing, Address addr, String text, String marker) {
		touched.add(addr);
		String existing = listing.getComment(TYPE, addr);
		String recorded = map.getString(addr);
		Plan plan = plan(recorded, existing, text, marker);
		if (!plan.write()) {
			// The fail-safe case: we recorded writing here but can no longer find that text, so
			// a human has edited it. Forget the record -- keeping it would let a later round
			// cut into their words -- and leave the listing untouched.
			if (recorded != null && !containsSegment(existing, recorded)) {
				map.remove(addr);
			}
			return false;
		}
		listing.setComment(addr, TYPE, plan.comment());
		map.add(addr, plan.record());
		return true;
	}

	/**
	 * Retracts every bank comment this analyzer recorded writing at an address the current run
	 * did NOT annotate -- the stale-attribution case grm-3mg0 was filed for. Returns how many
	 * comments were retracted.
	 * <p>
	 * Call once, after the annotation phase has finished and every writer has had its chance;
	 * calling it earlier would retract sites a later writer in the same round is about to
	 * re-establish. On a settled program every recorded address is touched and this writes
	 * nothing.
	 */
	List<Address> sweep(Listing listing) {
		List<Address> stale = new ArrayList<>();
		AddressIterator it = map.getPropertyIterator();
		while (it.hasNext()) {
			Address addr = it.next();
			if (!touched.contains(addr)) {
				stale.add(addr);
			}
		}
		List<Address> retracted = new ArrayList<>();
		for (Address addr : stale) {
			String recorded = map.getString(addr);
			String remaining = removeSegment(listing.getComment(TYPE, addr), recorded);
			if (remaining != null) {
				listing.setComment(addr, TYPE, remaining.isBlank() ? null : remaining);
				retracted.add(addr);
			}
			// remaining == null: a human changed it. Forget the record either way, but leave
			// their text alone -- same fail-safe rule as plan().
			map.remove(addr);
		}
		return retracted;
	}

	/** Whether {@code comment} contains {@code segment} as a whole {@link #JOIN}-separated part. */
	private static boolean containsSegment(String comment, String segment) {
		return removeSegment(comment, segment) != null;
	}

	/**
	 * {@code comment} with the whole segment {@code segment} removed, or null when it is not
	 * present as a complete segment. Whole-segment matching, never substring: a recorded
	 * {@code "bank -> 5"} must not match inside a longer human sentence that happens to quote it.
	 */
	static String removeSegment(String comment, String segment) {
		if (comment == null || segment == null || segment.isEmpty()) {
			return null;
		}
		List<String> kept = new ArrayList<>();
		boolean found = false;
		for (String part : comment.split(java.util.regex.Pattern.quote(JOIN), -1)) {
			if (!found && part.equals(segment)) {
				found = true;
				continue;
			}
			kept.add(part);
		}
		return found ? String.join(JOIN, kept) : null;
	}

	/** The program this record belongs to; used only by tests and assertions. */
	Program program() {
		return program;
	}
}
