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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

/**
 * Tier-2 coverage of {@code banking.live_bank_sets} (bead grm-5tl.20.5): shape refusals, the
 * writer cross-check (hint wins, WARNING at the writer, unresolved writers "stated, not
 * checked"), bookmark retraction, and the pure candidate-values query.
 */
public class LiveBankSetsProgramTest extends AbstractProgramTest {

	private static final String DESCRIPTOR = "machines/games/test.gmap";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(program.getMemory().getBlock(".zp"));
	}

	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{ "banking": { "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "bank", "bits": 4 } ] } }
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board =
			BoardDescriptorModel.BoardModel.parse(map, new MessageLog(), "test", "test.json");
		assertNotNull(board);
		return board;
	}

	private void publish(String entryJson) {
		JsonObject doc = JsonParser.parseString(
			"{\"banking\": {\"live_bank_sets\": [" + entryJson + "]}}").getAsJsonObject();
		String published = DescriptorHints.formatLiveBankSets(doc, DESCRIPTOR);
		inTx(program, "publish live_bank_sets", () -> program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorHints.LIVE_BANK_SETS_PROPERTY, published));
	}

	private static String entry(String field, String valueset, String decode) {
		return "{\"field\": \"" + field + "\", \"valueset\": " + valueset +
			", \"request\": {\"cell\": 36, \"decode\": \"" + decode + "\", \"idle\": [0]}," +
			" \"applied\": 35, \"provenance\": \"unit test\"}";
	}

	private LiveBankSets.Plan plan() {
		return LiveBankSets.plan(program, board(), Map.of());
	}

	private String warning(Address at) {
		Bookmark bm = program.getBookmarkManager().getBookmark(at, BookmarkType.WARNING,
			LiveBankSets.BOOKMARK_CATEGORY);
		return bm == null ? null : bm.getComment();
	}

	/**
	 * Code at {@code $C000}. LDA #4 / STA $24 (decodes to 3: ok); LDA #9 / STA $24 (8: outside);
	 * LDA #0 / STA $24 (idle); LDA #2 / STA $23 (ok); LDA #7 / STA $23 (outside); LDA $0300 /
	 * STA $24 (unresolved); RTS.
	 */
	private void writers() throws Exception {
		put(0xc000, "a9 04 85 24 a9 09 85 24 a9 00 85 24 a9 02 85 23 a9 07 85 23 "
			+ "ad 00 03 85 24 60");
		inTx(program, "function", () -> {
			try {
				program.getFunctionManager().createFunction("RESET", addr(0xc000),
					new AddressSet(addr(0xc000), addr(0xc019)), SourceType.ANALYSIS);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}

	@Test
	public void aContradictingWriterWarnsAtTheWriterAndTheHintStillApplies() throws Exception {
		writers();
		publish(entry("bank", "[1, 2, 3]", "value - 1"));
		LiveBankSets.Plan plan = plan();

		assertTrue(plan.byField().containsKey("bank"));
		assertEquals(plan.problems().toString(), 2, plan.problems().size());
		assertEquals(addr(0xc006), plan.problems().get(0).where());
		assertTrue(plan.problems().get(0).text(),
			plan.problems().get(0).text().contains("stored 9"));
		assertTrue(plan.problems().get(0).text().contains("decodes (value - 1) to 8"));
		assertTrue(plan.problems().get(0).text().contains("STILL APPLIES"));
		assertEquals(addr(0xc012), plan.problems().get(1).where());
		assertTrue(plan.problems().get(1).text().contains("stored 7"));

		String line = plan.logLines().get(0);
		assertTrue(line, line.contains("applied; cells request 0x24, applied 0x23: 5 writer(s) " +
			"checked, 1 stated, not checked (at c017"));
		assertTrue(line, line.endsWith("2 contradicting"));

		inTx(program, "report", () -> LiveBankSets.report(program, plan));
		assertTrue(warning(addr(0xc006)).contains("stored 9"));
		assertTrue(warning(addr(0xc012)).contains("stored 7"));
		assertNull("acceptable writers are not bookmarked", warning(addr(0xc002)));
		assertNull("an idle value is acceptable", warning(addr(0xc00a)));
		assertNull("an unresolved writer is not a warning", warning(addr(0xc017)));
	}

	@Test
	public void aBookmarkARetractedFindingLeavesIsSwept() throws Exception {
		writers();
		publish(entry("bank", "[1, 2, 3]", "value - 1"));
		LiveBankSets.Plan plan = plan();
		inTx(program, "report", () -> LiveBankSets.report(program, plan));
		assertNotNull(warning(addr(0xc006)));

		// the descriptor is corrected to a set that accepts both stray values
		publish(entry("bank", "[1, 2, 3, 7, 8]", "value - 1"));
		LiveBankSets.Plan wider = plan();
		assertEquals(wider.problems().toString(), 0, wider.problems().size());
		inTx(program, "report", () -> LiveBankSets.report(program, wider));
		assertNull(warning(addr(0xc006)));
		assertNull(warning(addr(0xc012)));
	}

	@Test
	public void shapeImpossibilityRefusesTheHint() throws Exception {
		writers();
		publish(entry("nope", "[1]", "value - 1"));
		LiveBankSets.Plan unknown = plan();
		assertTrue(unknown.byField().isEmpty());
		assertTrue(unknown.problems().get(0).text(),
			unknown.problems().get(0).text().contains("is not a banking.state field"));

		publish(entry("bank", "[1, 16]", "value - 1"));
		LiveBankSets.Plan wide = plan();
		assertTrue(wide.byField().isEmpty());
		assertTrue(wide.problems().get(0).text(),
			wide.problems().get(0).text().contains("wider than field 'bank' (4 bits)"));

		publish(entry("bank", "[1]", "value - nope"));
		LiveBankSets.Plan bad = plan();
		assertTrue(bad.byField().isEmpty());
		assertTrue(bad.problems().get(0).text(),
			bad.problems().get(0).text().contains("not evaluable"));
		assertTrue(bad.logLines().get(0), bad.logLines().get(0).contains("REFUSED"));
	}

	@Test
	public void candidatesIntersectTheSetWithTheKnownBits() {
		LiveBankSets.Hint hint = new LiveBankSets.Hint("bank", List.of(0, 1, 2, 3, 4, 5), null,
			null, "p");
		// nothing known: the whole set, in descriptor order
		assertEquals(List.of(0, 1, 2, 3, 4, 5), LiveBankSets.candidatesOf(hint, 0, 0));
		// bit 2 known set: only 4 and 5
		assertEquals(List.of(4, 5), LiveBankSets.candidatesOf(hint, 0b100, 0b100));
		// bits 0..1 known = 3 (bits outside the mask are ignored)
		assertEquals(List.of(3), LiveBankSets.candidatesOf(hint, 0b011, 0b1111));
		// fully known and outside the set: empty = contradiction
		assertEquals(List.of(), LiveBankSets.candidatesOf(hint, 0b1111, 9));
		// no hint for the field: null
		assertNull(LiveBankSets.candidatesOf(null, 0, 0));
		assertNull(LiveBankSets.Plan.NONE.candidates("bank", 0, 0));
		LiveBankSets.Plan plan =
			new LiveBankSets.Plan("s", Map.of("bank", hint), List.of(), List.of());
		assertEquals(List.of(0, 1, 2, 3), plan.candidates("bank", 0b100, 0));
	}
}
