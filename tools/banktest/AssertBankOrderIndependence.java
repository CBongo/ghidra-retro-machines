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
// Asserts BankCommentProvenance's central claim end to end (bead grm-q39f): a program
// analyzed ONCE over its FINAL structure must produce the same bank-comment set as one
// analyzed, perturbed, and re-analyzed. Every fixture in this harness measures only the
// second path (import, analyze, perturb via a postScript, re-analyze) -- retromachines/
// BankCommentProvenance.java's plan()/removeSegment() are exhaustively unit-tested, but
// sweep() and this order-independence property are not exercised anywhere. This script
// closes that gap using the nesskiptest fixture as the vehicle, since it already carries
// a perturbing postScript (FixSkipInstructions.java) ahead of it in the chain.
//
// MUST RUN AFTER VerifyBankTest.java (as a second -postScript, via run_one's new $6 slot
// in run-banktest.sh) and after the perturbation that produced the program's CURRENT
// structure -- FixSkipInstructions.java's repair, here. Running earlier would compare
// against a structure that is not actually "final", which would make the comparison
// meaningless rather than merely early.
//
// The method:
//
//   1. Capture "path B" -- the bank-comment set VerifyBankTest.java's own dump would see,
//      using the identical selection rule: every instruction whose EOL comment contains
//      "bank ->". This is what the fixture measures today: analyze, perturb, re-analyze.
//   2. Retract every comment this analyzer recorded writing (via the
//      "Retro Machines.Bank Comment" user property map -- see BankCommentProvenance's
//      class javadoc) by removing the recorded text as a whole "; "-separated segment,
//      then drop the record. This undoes round 2's annotations without touching anything
//      a human might have typed, mirroring BankCommentProvenance.removeSegment's
//      whole-segment-only matching.
//   3. Re-analyze once, over what is now the SAME final structure (the skip idiom is
//      already repaired) but with NO prior annotation to build on -- i.e. "path A": a
//      single settled analysis pass over the final program.
//   4. Capture the resulting comment set with the identical rule.
//   5. Compare. The two sets must be identical, or the property is false.
//
// Retromachines' BankCommentProvenance class is package-private, so its removeSegment
// cannot be called from here (this script has no package declaration, matching every
// other file in this directory) -- removeSegment below is a deliberately small
// re-implementation of the same whole-segment semantics, not a fork of new logic.
//
// Prints exactly one summary line, always:
//
//   ORDERINDEP pathB=<n> pathA=<n> cleared=<n> onlyB=<n> onlyA=<n> differing=<n> verdict=<V>
//
// and, only on a mismatch, one "ORDERINDEP DIFF <addr> B=<text> A=<text>" line per
// differing address (text is "(absent)" on whichever side lacks it). verdict is:
//
//   VACUOUS   pathB or cleared was zero -- nothing was compared, so this run proves
//             nothing and must never be misread as a pass. Without this guard a fixture
//             that happened to annotate nothing would report MATCH on an empty
//             comparison, which is a false assertion of the very property this exists
//             to check.
//   MATCH     the two comment sets are identical, address for address, text for text.
//   MISMATCH  they are not.
//
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.util.StringPropertyMap;

public class AssertBankOrderIndependence extends GhidraScript {

	/**
	 * The bank-comment marker VerifyBankTest.java's own dump selects on (its {@code dump()}
	 * method, "COMMENT" lines) -- kept identical here so path A and path B are captured by
	 * the same rule.
	 */
	private static final String MARKER = "bank ->";

	/**
	 * BankCommentProvenance.PROPERTY_MAP's value, copied literally: that field is
	 * package-private in {@code retromachines} and this script has no package declaration,
	 * so it cannot be referenced directly.
	 */
	private static final String PROPERTY_MAP = "Retro Machines.Bank Comment";

	/** BankCommentProvenance's JOIN constant, copied for the same reason. */
	private static final String JOIN = "; ";

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no program is open");
			return;
		}

		Listing listing = currentProgram.getListing();

		TreeMap<Address, String> pathB = captureBankComments(listing);

		int cleared = retractRecordedComments(listing);

		// Re-analyze over the FINAL structure with no prior annotation to build on: this is
		// "path A", the single-pass side of the comparison. analyzeAll, NOT analyzeChanges, is
		// required here even though the program's code structure is already final: retraction
		// above touches only comments and a user property map, never listing bytes or
		// instructions, so AutoAnalysisManager's incremental "changed addresses" set is empty
		// and analyzeChanges alone would invoke no analyzer at all -- measured directly: with
		// analyzeChanges here, pathA came back EMPTY (BoardBankAnalyzer's added() callback never
		// firing), which would misreport every fixture as a MISMATCH regardless of whether the
		// property actually holds. analyzeAll's reAnalyzeAll(null) marks the ENTIRE program as
		// needing re-analysis regardless of what changed, forcing BoardBankAnalyzer's added() to
		// run its whole-program fixpoint fresh -- which is what "a single settled pass over the
		// final structure" actually means here.
		println("ORDERINDEP re-analyzing after retracting " + cleared + " recorded comment(s)");
		analyzeAll(currentProgram);

		TreeMap<Address, String> pathA = captureBankComments(listing);

		report(pathB, pathA, cleared);
	}

	/**
	 * Every address whose EOL comment contains {@link #MARKER}, with the full comment text
	 * -- the same selection VerifyBankTest.java's dump() uses for its COMMENT lines, so the
	 * two scripts see the same set no matter which runs first.
	 */
	private TreeMap<Address, String> captureBankComments(Listing listing) {
		TreeMap<Address, String> found = new TreeMap<>();
		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();
			String eol = listing.getComment(CommentType.EOL, at);
			if (eol != null && eol.contains(MARKER)) {
				found.put(at, eol);
			}
		}
		return found;
	}

	/**
	 * Undoes every bank comment this analyzer recorded writing, by removing the recorded
	 * text as a whole {@link #JOIN}-separated segment of the current EOL comment (never a
	 * substring match -- see {@code removeSegment}) and dropping the record afterward.
	 * Returns how many addresses were cleared, or 0 if the property map does not exist at
	 * all (an analyzer that never ran, or a program from before this provenance tracking
	 * existed).
	 */
	private int retractRecordedComments(Listing listing) {
		StringPropertyMap map =
			currentProgram.getUsrPropertyManager().getStringPropertyMap(PROPERTY_MAP);
		if (map == null) {
			return 0;
		}
		int cleared = 0;
		// Collect addresses before mutating: StringPropertyMap's iterator contract does not
		// promise to tolerate concurrent removal, the same reason BankCommentProvenance.sweep
		// collects into a List before acting.
		List<Address> recordedAddrs = new ArrayList<>();
		AddressIterator it = map.getPropertyIterator();
		while (it.hasNext()) {
			recordedAddrs.add(it.next());
		}
		for (Address addr : recordedAddrs) {
			String recorded = map.getString(addr);
			String existing = listing.getComment(CommentType.EOL, addr);
			String remaining = removeSegment(existing, recorded);
			if (remaining != null) {
				listing.setComment(addr, CommentType.EOL, remaining.isBlank() ? null : remaining);
				cleared++;
			}
			// remaining == null means the recorded text is no longer present as a whole
			// segment -- a human edited or removed it since the last round. Leave their text
			// alone either way (BankCommentProvenance's fail-safe rule), but still forget the
			// record so path A's re-analysis starts clean at this address.
			map.remove(addr);
		}
		return cleared;
	}

	/**
	 * {@code comment} with the whole segment {@code segment} removed, or null when it is not
	 * present as a complete {@link #JOIN}-separated part. Mirrors
	 * {@code retromachines.BankCommentProvenance#removeSegment} exactly -- whole-segment
	 * matching only, so a recorded {@code "bank -> 5"} can never delete into a longer
	 * human sentence that happens to contain it as a substring.
	 */
	private static String removeSegment(String comment, String segment) {
		if (comment == null || segment == null || segment.isEmpty()) {
			return null;
		}
		List<String> kept = new ArrayList<>();
		boolean found = false;
		for (String part : comment.split(Pattern.quote(JOIN), -1)) {
			if (!found && part.equals(segment)) {
				found = true;
				continue;
			}
			kept.add(part);
		}
		return found ? String.join(JOIN, kept) : null;
	}

	/**
	 * Prints the summary line and, on a mismatch, one DIFF line per differing address.
	 * TreeMap ordering (over {@link Address}) makes both the comparison and the printed
	 * output deterministic, which matters here because the output lands in a log a human
	 * diffs by hand.
	 */
	private void report(TreeMap<Address, String> pathB, TreeMap<Address, String> pathA,
			int cleared) {
		int onlyB = 0;
		int onlyA = 0;
		int differing = 0;
		TreeMap<Address, String[]> diffs = new TreeMap<>();

		for (Map.Entry<Address, String> e : pathB.entrySet()) {
			String bText = e.getValue();
			String aText = pathA.get(e.getKey());
			if (aText == null) {
				onlyB++;
				diffs.put(e.getKey(), new String[] { bText, null });
			}
			else if (!aText.equals(bText)) {
				differing++;
				diffs.put(e.getKey(), new String[] { bText, aText });
			}
		}
		for (Map.Entry<Address, String> e : pathA.entrySet()) {
			if (!pathB.containsKey(e.getKey())) {
				onlyA++;
				diffs.put(e.getKey(), new String[] { null, e.getValue() });
			}
		}

		String verdict;
		if (pathB.isEmpty() || cleared == 0) {
			// Nothing was annotated, or nothing was cleared before the re-analysis: the
			// comparison below would trivially "match" without ever exercising retraction
			// and reconstruction, which is not the property this script exists to check.
			verdict = "VACUOUS";
		}
		else if (diffs.isEmpty()) {
			verdict = "MATCH";
		}
		else {
			verdict = "MISMATCH";
		}

		println("ORDERINDEP pathB=" + pathB.size() + " pathA=" + pathA.size() + " cleared=" +
			cleared + " onlyB=" + onlyB + " onlyA=" + onlyA + " differing=" + differing +
			" verdict=" + verdict);

		if (!"MATCH".equals(verdict) && !"VACUOUS".equals(verdict)) {
			for (Map.Entry<Address, String[]> e : diffs.entrySet()) {
				String bText = e.getValue()[0];
				String aText = e.getValue()[1];
				println("ORDERINDEP DIFF " + fmt(e.getKey()) + " B=" +
					(bText == null ? "(absent)" : bText) + " A=" +
					(aText == null ? "(absent)" : aText));
			}
		}
	}

	private static String fmt(Address a) {
		return String.format("%04x", a.getOffset());
	}
}
