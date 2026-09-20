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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import retromachines.BankAnnotationAdapter.Marked;
import retromachines.BankSwitchStrategy.ValueStop;

/**
 * Pins bead {@code grm-3ou} part 2: every switch site that {@link BankAnnotationAdapter#annotateOrWarn}
 * BOOKMARKS also gets an EOL <em>gap comment</em> ({@code bank ? [kind]}), so the gap is
 * visible in the listing and says which kind it is -- and NO site gets both a gap comment and a
 * {@code bank ->} comment, because the two are renderings of one annotation slot.
 * <p>
 * Drives {@code annotateOrWarn} directly with hand-built {@link BankState}s rather than through
 * a dataflow run, because the property under test is the pairing of comment and bookmark at
 * each EXIT of that method, and the exits are reachable by argument alone. The bookmark type
 * and the comment's {@code WARNING:}/{@code NOTE:} prefix are asserted TOGETHER at every site:
 * the comment is supposed to be a faithful echo of the bookmark, and a test that checked one
 * channel would pass if the two ever drifted.
 * <p>
 * The invariant this guards is also what keeps the real-ROM goldens honest without a format
 * change: {@code RealRomDump} samples only {@code bank ->} comments and bookmarks, so a gap
 * comment is pinned there only through the bookmark it must always accompany.
 */
public class BankGapCommentProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private BoardDescriptorModel.BoardModel board;
	private Map<String, Set<Integer>> universe;
	private final NesBankingAnalyzer analyzer = new NesBankingAnalyzer();

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		board = board();
		universe = BankAnnotationAdapter.bankUniverse(program, board);
	}

	/**
	 * The UxROM shape (borrowed from {@code BaseReferenceRetirementProgramTest}): PRG_LO
	 * computed from a 4-bit {@code bank}, PRG_HI fixed, home bank 0. A computed window is what
	 * gives the bank universe an entry, which the impossible-bank check needs to say anything.
	 */
	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "physical": [ { "name": "PRG", "image": "prg_rom" } ],
				  "windows": [
				    { "name": "PRG_LO", "start": 32768, "end": 49151,
				      "maps": { "space": "PRG", "expr": "bank * 0x4000" },
				      "on_write": "mechanism" },
				    { "name": "PRG_HI", "start": 49152, "end": 65535,
				      "maps": { "space": "PRG", "expr": "last" },
				      "on_write": "mechanism" }
				  ],
				  "banking": {
				    "initial_state": 0,
				    "state": [ { "name": "bank", "bits": 4 } ],
				    "mechanisms": [ { "strategy": "memory-latch" } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel b = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(b);
		return b;
	}

	private Address addr(int a) {
		return builder.addr(String.format("0x%x", a));
	}

	private Marked annotate(Address at, BankState state, String via, ValueStop stop,
			boolean warnDespiteKnowledge) {
		int tx = program.startTransaction("annotate");
		try {
			return BankAnnotationAdapter.annotateOrWarn(analyzer, program, program.getListing(),
				at, state, board, universe, via, "the caller's warning", stop, null,
				warnDespiteKnowledge, null);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private String eol(Address at) {
		return program.getListing().getComment(CommentType.EOL, at);
	}

	/** The single bookmark's type at {@code at}, or null when the site carries none. */
	private String bookmarkType(Address at) {
		Iterator<Bookmark> it = program.getBookmarkManager().getBookmarksIterator();
		String found = null;
		while (it.hasNext()) {
			Bookmark bm = it.next();
			if (bm.getAddress().equals(at)) {
				assertNull("two bookmarks at " + at, found);
				found = bm.getTypeString();
			}
		}
		return found;
	}

	/** The shape every gap exit must produce: a bookmark of {@code type} echoed by the comment. */
	private void assertGap(Address at, String type, String expectedComment) {
		assertEquals(type, bookmarkType(at));
		assertEquals(expectedComment, eol(at));
		assertFalse("a gap comment must never read as a resolved switch",
			eol(at).contains("bank ->"));
	}

	@Test
	public void anAnalyzerLimitGapIsAWarningAndSaysSo() {
		Address at = addr(0xc000);
		assertEquals(Marked.WARNED,
			annotate(at, BankState.unknown(), null, ValueStop.ANALYZER_LIMIT, false));
		assertGap(at, BookmarkType.WARNING, "bank ? [WARNING: analyzer limit]");
	}

	@Test
	public void aForkBudgetGapIsAWarningNamedAsItsOwnKind() {
		Address at = addr(0xc003);
		assertEquals(Marked.WARNED,
			annotate(at, BankState.unknown(), null, ValueStop.MULTI_VALUED_AT_MERGE, false));
		assertGap(at, BookmarkType.WARNING, "bank ? [WARNING: fork budget]");
	}

	@Test
	public void anHonestGapIsANoteAndSaysSo() {
		Address at = addr(0xc006);
		assertEquals(Marked.NOTED,
			annotate(at, BankState.unknown(), null, ValueStop.HELPER_ARGUMENT, false));
		assertGap(at, BookmarkType.NOTE, "bank ? [NOTE: helper argument]");
	}

	/** A call-site gap carries the helper's name where a resolved comment would carry it. */
	@Test
	public void aCallSiteGapNamesTheHelperLikeAResolvedCommentWould() {
		Address at = addr(0xc009);
		assertEquals(Marked.NOTED, annotate(at, BankState.unknown(), "FUN_c170",
			ValueStop.SECOND_TIER_ARGUMENT, false));
		assertGap(at, BookmarkType.NOTE, "bank ? via FUN_c170 [NOTE: second-tier argument]");
	}

	/** A recovered bank the image has no slice for: warned, and the comment says why. */
	@Test
	public void anImpossibleBankIsAWarningGap() {
		Address at = addr(0xc00c);
		// Bank 9 is fully known, and PRG_LO's universe on this program holds only the home
		// bank 0 (no overlay slices were ever created), so 9 has no slice to land in.
		assertEquals(Marked.WARNED,
			annotate(at, BankState.fullyKnown(board.mask(), 9), null, ValueStop.RESOLVED, false));
		assertGap(at, BookmarkType.WARNING, "bank ? [WARNING: impossible bank]");
	}

	/** {@link ValueStop#NO_DEPOSIT} writes nothing at all -- neither channel. */
	@Test
	public void aNoDepositSiteGetsNeitherCommentNorBookmark() {
		Address at = addr(0xc00f);
		assertEquals(Marked.SKIPPED,
			annotate(at, BankState.unknown(), null, ValueStop.NO_DEPOSIT, false));
		assertNull(bookmarkType(at));
		assertNull(eol(at));
	}

	/** A resolved site gets its bank comment and no bookmark; nothing here changed. */
	@Test
	public void aResolvedSiteGetsABankCommentAndNoGap() {
		Address at = addr(0xc012);
		assertEquals(Marked.ANNOTATED,
			annotate(at, BankState.fullyKnown(board.mask(), 0), null, ValueStop.RESOLVED, false));
		assertNull(bookmarkType(at));
		assertTrue(eol(at), eol(at).startsWith("bank -> 0 (bank=0)"));
		assertFalse(eol(at).contains("bank ?"));
	}

	/**
	 * The {@code warnDespiteKnowledge} exit (grm-4bgh.5) is the one bookmarked exit that writes
	 * a BANK comment: the state knows something, and that comment is where the reader learns
	 * it. It must not ALSO get a gap comment -- one slot per address.
	 */
	@Test
	public void aWarnedSiteWithKnowledgeKeepsItsBankCommentAndGetsNoGap() {
		Address at = addr(0xc015);
		assertEquals(Marked.WARNED, annotate(at, BankState.fullyKnown(board.mask(), 0),
			"FUN_c170", ValueStop.ANALYZER_LIMIT, true));
		assertEquals(BookmarkType.WARNING, bookmarkType(at));
		assertTrue(eol(at), eol(at).startsWith("bank -> 0 (bank=0) via FUN_c170"));
		assertFalse(eol(at).contains("bank ?"));
	}

	/**
	 * The two channels are the same slot: a second round at a site that RESOLVED replaces the
	 * gap comment with the bank comment rather than stacking beside it -- through the
	 * append-only fallback path exercised here (no provenance), the family marker is what makes
	 * the bank comment defer to its own earlier gap, so the SAME text is then found twice only
	 * if the family were ignored.
	 */
	@Test
	public void aGapAndABankCommentNeverStackAtOneAddress() {
		Address at = addr(0xc018);
		annotate(at, BankState.unknown(), null, ValueStop.ANALYZER_LIMIT, false);
		annotate(at, BankState.fullyKnown(board.mask(), 0), null, ValueStop.RESOLVED, false);
		// Append-only fallback (provenance == null): first writer wins, exactly as it does for
		// two bank comments. Refresh is the provenance path's job and is pinned in
		// BankCommentProvenanceTest.aResolvedSiteRefreshesItsOwnEarlierGapComment.
		assertEquals("bank ? [WARNING: analyzer limit]", eol(at));
	}
}
