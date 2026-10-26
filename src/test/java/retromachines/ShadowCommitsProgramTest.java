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

import java.util.List;
import java.util.Locale;
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@code banking.shadow_commits} (bead grm-hb6.26): a call to a bank-switch
 * helper commits a board field from a RAM cell the descriptor names.
 * <p>
 * The shape is the Dragon Power engine in miniature: the helper at {@code $C200} takes its bank in
 * A and latches it ({@code STA $9000 / RTS}); the cell is {@code $10}. Driven through
 * {@link ShadowCommits#plan} and {@link BankDataflowEngine#runDataflow} with a hand-built board,
 * as {@code SwitchSiteHintsProgramTest} does for the {@code bank:} hints.
 */
public class ShadowCommitsProgramTest extends AbstractProgramTest {

	private static final String DESCRIPTOR = "machines/games/test.gmap";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(program.getMemory().getBlock(".zp"));
		put(0xc000, "60");
		inTx(program, "reset function", () -> {
			program.getFunctionManager().createFunction("RESET", addr(0xc000),
				new AddressSet(addr(0xc000), addr(0xc000)), SourceType.ANALYSIS);
		});
		builder.createEntryPoint("0xc000", "RESET");
	}

	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "bank", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board =
			BoardDescriptorModel.BoardModel.parse(map, new MessageLog(), "test", "test.json");
		assertNotNull(board);
		return board;
	}

	private MemoryLatchBankSwitchStrategy latchStrategy(BoardDescriptorModel.BoardModel board) {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9100);
		params.addProperty("mask", board.mask());
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, board.mask());
		return strategy;
	}

	private void makeFunction(int start, int endInclusive, String name) throws Exception {
		inTx(program, "create function " + name, () -> {
			try {
				program.getFunctionManager().createFunction(name, addr(start),
					new AddressSet(addr(start), addr(endInclusive)), SourceType.ANALYSIS);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		builder.createEntryPoint(String.format("0x%x", start), name);
	}

	/** Caller bytes at {@code $C100}; helper {@code STA $9000 / RTS} at {@code $C200}. */
	private Map<Function, HelperDiscovery.HelperModel> build(
			BoardDescriptorModel.BoardModel b, String callerBytes, int callerEnd)
			throws Exception {
		put(0xc100, callerBytes);
		put(0xc200, "8d 00 90 60");
		makeFunction(0xc100, callerEnd, "CALLER");
		makeFunction(0xc200, 0xc203, "HELPER");
		Function helper = program.getFunctionManager().getFunctionAt(addr(0xc200));
		return Map.of(helper, new HelperDiscovery.HelperModel(helper, addr(0xc200), null, 'A',
			b.mask(), 0, latchStrategy(b), addr(0xc200), addr(0xc200), null,
			List.of(addr(0xc200))));
	}

	private void publish(String entriesJson) {
		JsonObject doc = JsonParser.parseString(
			"{\"banking\": {\"shadow_commits\": " + entriesJson + "}}").getAsJsonObject();
		String published = DescriptorHints.formatShadowCommits(doc, DESCRIPTOR);
		inTx(program, "publish shadow_commits", () -> program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorHints.SHADOW_COMMITS_PROPERTY, published));
	}

	private void hint(String field, long cell) {
		publish("[{\"helper\": 49664, \"cell\": " + cell + ", \"field\": \"" + field +
			"\", \"provenance\": \"unit test\"}]");
	}

	private BankDataflowEngine.DataflowResult run(BoardDescriptorModel.BoardModel b,
			Map<Function, HelperDiscovery.HelperModel> helpers, ShadowCommits.Plan plan)
			throws Exception {
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs
					.of(List.of(new BankStrategyRegistry.ConfiguredMechanism(latchStrategy(b),
						b.mask(), 0)), b)
					.withHelpers(helpers)
					.withShadowCommits(plan));
	}

	private String warning(Address at) {
		Bookmark bm = program.getBookmarkManager().getBookmark(at, BookmarkType.WARNING,
			ShadowCommits.BOOKMARK_CATEGORY);
		return bm == null ? null : bm.getComment();
	}

	private void report(ShadowCommits.Plan plan, BankDataflowEngine.DataflowResult result) {
		inTx(program, "report shadow commits", () -> ShadowCommits.report(program, plan,
			result.hintNotes(), java.util.Set.of()));
	}

	// JSR $C200 as the caller's first instruction: nothing wrote the cell in this block.
	private static final String BARE_CALL = "20 00 c2 60";

	@Test
	public void aCallWithNoStoreToTheCellInItsBlockIsAVerifiedNoOpWithNoWarning()
			throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, BARE_CALL, 0xc103);
		BankDataflowEngine.DataflowResult base = run(b, helpers, ShadowCommits.Plan.NONE);
		assertNotNull("baseline: the unresolved call is a call switch",
			base.callSwitches().get(addr(0xc100)));
		assertFalse(base.callSwitches().get(addr(0xc100)).argumentResolved());

		hint("bank", 0x10);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		assertEquals(plan.problems().toString(), 1, plan.byHelper().size());
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);

		assertNull("a verified no-op is neither fold nor annotation",
			result.callSwitches().get(addr(0xc100)));
		assertEquals("the live bank survives the call", 0xF,
			result.stateIn().get(addr(0xc103)).knownMask());
		assertEquals(0, result.stateIn().get(addr(0xc103)).bits());
		report(plan, result);
		assertNull(warning(addr(0xc200)));
	}

	@Test
	public void aStoreToTheCellInTheCallsBlockDepositsItsValueWithTheHintSuffix()
			throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #2 / STA $10 / LDA $11 / JSR $c200: A is clobbered after the store, so only the cell knows
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 a5 11 20 00 c2 60", 0xc109);
		assertFalse("baseline: A is unrecoverable",
			run(b, helpers, ShadowCommits.Plan.NONE).callSwitches().get(addr(0xc106))
					.argumentResolved());

		hint("bank", 0x10);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		assertEquals(plan.problems().toString(), 1, plan.byHelper().size());
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);

		BankDataflowEngine.CallSwitch cs = result.callSwitches().get(addr(0xc106));
		assertTrue(cs.argumentResolved());
		assertEquals(2, cs.effect().bits());
		assertEquals(0xF, cs.effect().knownMask());
		assertEquals(2, result.stateIn().get(addr(0xc109)).bits());
		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc106));
		assertTrue("the annotation's (game descriptor hint) suffix keys off an applied note",
			note != null && note.applied());
		assertNull("agreeing with nothing recovered raises no warning", note.recovered());
	}

	@Test
	public void theHintWinsOverADifferentRecoveredValueAndWarnsWithBoth() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #2 / STA $10 / LDA #5 / JSR: dataflow recovers 5 from the register, the cell holds 2
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 a9 05 20 00 c2 60", 0xc109);
		assertEquals(5, run(b, helpers, ShadowCommits.Plan.NONE).callSwitches()
				.get(addr(0xc106)).effect().bits());

		hint("bank", 0x10);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);

		assertEquals(2, result.callSwitches().get(addr(0xc106)).effect().bits());
		assertEquals("5", result.hintNotes().get(addr(0xc106)).recovered());
		report(plan, result);
		String w = warning(addr(0xc106));
		assertTrue(w, w != null && w.contains("WINS") && w.contains("(5)") &&
			w.contains(DESCRIPTOR));
	}

	@Test
	public void aStoreWhoseValueIsUnknownKeepsTheDataflowEffectAndItsWarning() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA $11 / STA $10 / JSR $c200: the cell's byte is unknown
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a5 11 85 10 20 00 c2 60", 0xc107);
		hint("bank", 0x10);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		assertEquals(plan.problems().toString(), 1, plan.byHelper().size());
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);

		BankDataflowEngine.CallSwitch cs = result.callSwitches().get(addr(0xc104));
		assertNotNull(cs);
		assertFalse("honest: nothing is known, the warning stays", cs.argumentResolved());
		assertNull(result.hintNotes().get(addr(0xc104)));
	}

	@Test
	public void aStoreToTheCellNotFollowedByTheHelperFailsThePremiseAndWarns() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, BARE_CALL, 0xc103);
		// a stray writer of the cell that never calls the helper
		put(0xc300, "85 10 60");
		makeFunction(0xc300, 0xc302, "STRAY");
		hint("bank", 0x10);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue("not applied", plan.byHelper().isEmpty());
		assertEquals(1, plan.problems().size());
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);
		assertNotNull("unchanged: the call is still an unresolved call switch",
			result.callSwitches().get(addr(0xc100)));
		report(plan, result);
		String w = warning(addr(0xc200));
		assertTrue(w, w != null && w.contains("premise") &&
			w.toLowerCase(Locale.ROOT).contains("c300") && w.contains(DESCRIPTOR));
	}

	@Test
	public void anUnknownFieldIsNotAppliedAndWarns() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, BARE_CALL, 0xc103);
		hint("nosuchfield", 0x10);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.byHelper().isEmpty());
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);
		assertNotNull(result.callSwitches().get(addr(0xc100)));
		report(plan, result);
		String w = warning(addr(0xc200));
		assertTrue(w, w != null && w.contains("nosuchfield") && w.contains("banking.state"));
	}

	@Test
	public void aHelperAddressThatIsNotAModelledHelperIsNotAppliedAndWarns() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, BARE_CALL, 0xc103);
		publish("[{\"helper\": 49408, \"cell\": 16, \"field\": \"bank\", \"provenance\": \"x\"}]");

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.byHelper().isEmpty());
		assertTrue(plan.problems().toString(),
			plan.problems().get(0).text().contains("bank-switch helper"));
	}

	// ---- several hints per helper; coherence over the committing set; relay (grm-td2j/grm-wayn) ----

	/** Two 4-bit fields in one byte: {@code lo} (bits 0-3) and {@code hi} (bits 4-7). */
	private BoardDescriptorModel.BoardModel twoFieldBoard() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "lo", "bits": 4 }, { "name": "hi", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board =
			BoardDescriptorModel.BoardModel.parse(map, new MessageLog(), "test", "test.json");
		assertNotNull(board);
		return board;
	}

	private HelperDiscovery.HelperModel modelAt(int entry, BoardDescriptorModel.BoardModel b) {
		Function f = program.getFunctionManager().getFunctionAt(addr(entry));
		return new HelperDiscovery.HelperModel(f, addr(entry), null, 'A', b.mask(), 0,
			latchStrategy(b), addr(entry), addr(entry), null, List.of(addr(entry)));
	}

	/** A second latch helper {@code STA $9000 / RTS} at {@code $C220}, added to {@code helpers}. */
	private Map<Function, HelperDiscovery.HelperModel> withSecondHelper(
			BoardDescriptorModel.BoardModel b, Map<Function, HelperDiscovery.HelperModel> helpers)
			throws Exception {
		put(0xc220, "8d 00 90 60");
		makeFunction(0xc220, 0xc223, "HELPER2");
		Map<Function, HelperDiscovery.HelperModel> all = new java.util.HashMap<>(helpers);
		all.put(program.getFunctionManager().getFunctionAt(addr(0xc220)), modelAt(0xc220, b));
		return all;
	}

	private static final String TWO_HINTS =
		"[{\"helper\": 49664, \"cell\": 16, \"field\": \"lo\", \"provenance\": \"t\"}," +
			" {\"helper\": 49664, \"cell\": 17, \"field\": \"hi\", \"provenance\": \"t\"}]";

	@Test
	public void twoHintsOnOneHelperCommitTheirFieldsFromTheirCells() throws Exception {
		BoardDescriptorModel.BoardModel b = twoFieldBoard();
		// LDA #2 / STA $10 / LDA #3 / STA $11 / LDA $12 / JSR $c200
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 a9 03 85 11 a5 12 20 00 c2 60", 0xc10d);
		assertFalse("baseline: A is unrecoverable",
			run(b, helpers, ShadowCommits.Plan.NONE).callSwitches().get(addr(0xc10a))
					.argumentResolved());
		publish(TWO_HINTS);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertEquals(plan.problems().toString(), 2, plan.byHelper().get(0xc200L).size());
		BankDataflowEngine.CallSwitch cs = run(b, helpers, plan).callSwitches().get(addr(0xc10a));
		assertTrue(cs.argumentResolved());
		assertEquals(0x32, cs.effect().bits());
		assertEquals(0xFF, cs.effect().knownMask());
	}

	@Test
	public void aCellWithNoStoreInTheBlockIsAPerCellNoOpBesideAnotherCellsStore()
			throws Exception {
		BoardDescriptorModel.BoardModel b = twoFieldBoard();
		// LDA #2 / STA $10 / LDA $12 / JSR $c200 -- $11 (hi) not stored here
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 a5 12 20 00 c2 60", 0xc109);
		publish(TWO_HINTS);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		assertEquals(plan.problems().toString(), 2, plan.byHelper().get(0xc200L).size());

		BankDataflowEngine.CallSwitch cs = run(b, helpers, plan).callSwitches().get(addr(0xc106));
		assertTrue(cs.argumentResolved());
		assertEquals("lo committed from the store", 2, cs.effect().bits() & 0xF);
		assertEquals("hi left alone, so not part of this call's effect", 0xF,
			cs.effect().knownMask());
	}

	@Test
	public void aStoreCommittedByADifferentHintedHelperSatisfiesThePremise() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// the store is committed by HELPER2 ($c220), not by the helper whose hint is checked
		Map<Function, HelperDiscovery.HelperModel> helpers =
			withSecondHelper(b, build(b, "a9 02 85 10 20 20 c2 60", 0xc107));
		publish("[{\"helper\": 49664, \"cell\": 16, \"field\": \"bank\", \"provenance\": \"t\"}," +
			" {\"helper\": 49696, \"cell\": 16, \"field\": \"bank\", \"provenance\": \"t\"}]");

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.problems().toString(), plan.problems().isEmpty());
		assertEquals(2, plan.byHelper().size());
	}

	@Test
	public void aStoreCommittedByAnUnhintedHelperFailsThePremise() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers =
			withSecondHelper(b, build(b, "a9 02 85 10 20 20 c2 60", 0xc107));
		hint("bank", 0x10); // only $c200 is hinted; the store is committed by $c220

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.byHelper().isEmpty());
		assertTrue(plan.problems().toString(), plan.problems().get(0).text().contains("c102"));
	}

	@Test
	public void aTailJumpToTheHelperSatisfiesThePremise() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #2 / STA $10 / JMP $c200
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 4c 00 c2", 0xc106);
		hint("bank", 0x10);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.problems().toString(), plan.problems().isEmpty());
		assertEquals(1, plan.byHelper().size());
	}

	@Test
	public void aThinWrapperThatCallsTheHelperSatisfiesThePremise() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #2 / STA $10 / JSR $c300, where $c300 is JSR $c200 / RTS (not itself a helper)
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 20 00 c3 60", 0xc107);
		put(0xc300, "20 00 c2 60");
		makeFunction(0xc300, 0xc303, "WRAPPER");
		hint("bank", 0x10);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.problems().toString(), plan.problems().isEmpty());
	}

	@Test
	public void aStoreFollowedByNothingFailsThePremiseAndNamesTheStore() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #2 / STA $10 / RTS
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, "a9 02 85 10 60", 0xc104);
		hint("bank", 0x10);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.byHelper().isEmpty());
		assertTrue(plan.problems().toString(), plan.problems().get(0).text().contains("c102"));
	}

	@Test
	public void aStoreFollowedByAnUnrelatedCallFailsThePremise() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 02 85 10 20 00 c3 60", 0xc107);
		put(0xc300, "60");
		makeFunction(0xc300, 0xc300, "OTHER");
		hint("bank", 0x10);

		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		assertTrue(plan.byHelper().isEmpty());
		assertTrue(plan.problems().toString(), plan.problems().get(0).text().contains("c102"));
	}

	@Test
	public void aStoreOfTheFunctionsInboundRegisterReclassifiesTheCallAsARelay() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// STA $10 / JSR $c200 / RTS: A at the store is the caller's inbound A
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, "85 10 20 00 c2 60", 0xc105);
		assertFalse(run(b, helpers, ShadowCommits.Plan.NONE).callSwitches().get(addr(0xc102))
				.secondTierRelay());
		hint("bank", 0x10);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		assertEquals(plan.problems().toString(), 1, plan.byHelper().size());

		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);

		BankDataflowEngine.CallSwitch cs = result.callSwitches().get(addr(0xc102));
		assertFalse(cs.argumentResolved());
		assertTrue(cs.secondTierRelay());
		String detail = result.hintNotes().get(addr(0xc102)).honestDetail();
		assertTrue(detail, detail.contains("inbound argument of CALLER") &&
			detail.contains("$0010") && detail.contains("register A"));
		assertFalse("a relay note is not an applied value hint",
			result.hintNotes().get(addr(0xc102)).applied());
	}

	@Test
	public void aStoreOfALocallyLoadedRegisterIsNotARelay() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA $11 / STA $10 / JSR $c200: A is defined locally from an untracked cell
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a5 11 85 10 20 00 c2 60", 0xc107);
		hint("bank", 0x10);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);

		BankDataflowEngine.CallSwitch cs = run(b, helpers, plan).callSwitches().get(addr(0xc104));

		assertFalse(cs.argumentResolved());
		assertFalse("A is defined in this function: nothing to relay", cs.secondTierRelay());
	}

	// ---- field coherence: restore mode (smb3's direct sound-bank writes) ----

	private ShadowCommits.Plan planWithMechanismWrites(BoardDescriptorModel.BoardModel b,
			Map<Function, HelperDiscovery.HelperModel> helpers) throws Exception {
		return ShadowCommits.plan(program, b, helpers,
			run(b, helpers, ShadowCommits.Plan.NONE).switchResults());
	}

	@Test
	public void aFieldOnlyWrittenInsideTheHelperIsCoherentAndANoStoreCallStaysANoOp()
			throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, BARE_CALL, 0xc103);
		hint("bank", 0x10);

		ShadowCommits.Plan plan = planWithMechanismWrites(b, helpers);

		assertTrue(plan.problems().toString(), plan.problems().isEmpty());
		assertTrue("the only mechanism write is the helper's own", plan.byHelper().get(0xc200L)
				.get(0).coherent());
		assertNull(run(b, helpers, plan).callSwitches().get(addr(0xc100)));
		assertTrue(plan.modeLines().get(0), plan.modeLines().get(0).contains("COHERENT"));
	}

	@Test
	public void aDirectWriteOfTheFieldOutsideTheHelpersMakesNoStoreCallsRestores()
			throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #5 / STA $9000 (a direct write of the field) / LDA $12 / JSR $c200
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 05 8d 00 90 a5 12 20 00 c2 60", 0xc10a);
		hint("bank", 0x10);

		ShadowCommits.Plan plan = planWithMechanismWrites(b, helpers);

		assertTrue(plan.problems().toString(), plan.problems().isEmpty());
		assertFalse(plan.byHelper().get(0xc200L).get(0).coherent());
		assertTrue(plan.modeLines().get(0), plan.modeLines().get(0).contains("RESTORE"));
		BankDataflowEngine.DataflowResult result = run(b, helpers, plan);
		BankDataflowEngine.CallSwitch cs = result.callSwitches().get(addr(0xc107));
		assertNotNull("the call is not a no-op", cs);
		assertFalse("the field is not known after the restore", cs.argumentResolved());
		assertNotNull(cs.restoreCell());
		assertEquals(0, result.stateIn().get(addr(0xc10a)).knownMask());
		String detail = result.hintNotes().get(addr(0xc107)).honestDetail();
		assertTrue(detail, detail.contains("RESTORED") && detail.contains("$0010"));
	}

	@Test
	public void inRestoreModeAStoreInTheBlockStillCommitsItsValue() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #5 / STA $9000 / LDA #2 / STA $10 / LDA $12 / JSR $c200
		Map<Function, HelperDiscovery.HelperModel> helpers =
			build(b, "a9 05 8d 00 90 a9 02 85 10 a5 12 20 00 c2 60", 0xc10e);
		hint("bank", 0x10);

		ShadowCommits.Plan plan = planWithMechanismWrites(b, helpers);
		assertFalse(plan.byHelper().get(0xc200L).get(0).coherent());

		BankDataflowEngine.CallSwitch cs = run(b, helpers, plan).callSwitches().get(addr(0xc10b));
		assertTrue(cs.argumentResolved());
		assertEquals(2, cs.effect().bits());
	}

	@Test
	public void withoutThePropertyNothingChanges() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers = build(b, BARE_CALL, 0xc103);
		ShadowCommits.Plan plan = ShadowCommits.plan(program, b, helpers);
		assertTrue(plan.isEmpty());
		assertTrue(plan.problems().isEmpty());

		BankDataflowEngine.DataflowResult a = run(b, helpers, ShadowCommits.Plan.NONE);
		BankDataflowEngine.DataflowResult c = run(b, helpers, plan);
		assertEquals(a.callSwitches(), c.callSwitches());
		assertEquals(a.stateIn(), c.stateIn());
		assertTrue(c.hintNotes().isEmpty());
		report(plan, c);
		assertEquals("no bookmark of the category appears", 0, countBookmarks());
	}

	private int countBookmarks() {
		int n = 0;
		var it = program.getBookmarkManager().getBookmarksIterator(BookmarkType.WARNING);
		while (it.hasNext()) {
			if (ShadowCommits.BOOKMARK_CATEGORY.equals(it.next().getCategory())) {
				n++;
			}
		}
		return n;
	}
}
