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
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@code banking.switch_sites} (bead grm-hb6.4, design sections 6.2 and 8):
 * a SITE hint is a dataflow SEED, never an injected result.
 * <p>
 * The seam is {@link SwitchSiteHints#materialize} plus {@link BankDataflowEngine#runDataflow}
 * with a hand-built board, exactly as {@code BankPathForkProgramTest} drives the engine: no
 * installed extension, no file on disk. The descriptor object is handed in through the same
 * {@link DescriptorHints#formatSwitchSites} the loader uses, so the property under test is the
 * one a real import publishes.
 */
public class SwitchSiteHintsProgramTest extends AbstractProgramTest {

	/** A latch store in bytes no flow reaches: LDA #3 / STA $9000 / RTS. */
	private static final String LATCH_STORE = "a9 03 8d 00 90 60";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		// RAM must be WRITABLE, or a load from it reads as a constant (a read-only block is ROM)
		makeWritable(program.getMemory().getBlock(".zp"));
		// The only reachable code: RESET, a lone RTS. Nothing refers to 0xc100.
		put(0xc000, "60");
		inTx(program, "reset function", () -> {
			program.getFunctionManager().createFunction("RESET", addr(0xc000),
				new ghidra.program.model.address.AddressSet(addr(0xc000), addr(0xc000)),
				ghidra.program.model.symbol.SourceType.ANALYSIS);
		});
		builder.createEntryPoint("0xc000", "RESET");
	}

	private void hint(String sitesYamlAsJson) {
		JsonObject doc = JsonParser.parseString(
			"{\"banking\": {\"switch_sites\": " + sitesYamlAsJson + "}}").getAsJsonObject();
		String published = DescriptorHints.formatSwitchSites(doc, "machines/games/test.gmap");
		inTx(program, "publish switch_sites", () -> program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorHints.SWITCH_SITES_PROPERTY, published));
	}

	private void hintAt(String addrDecimal, String extra) {
		hint("[{\"addr\": " + addrDecimal + extra + ", \"provenance\": \"unit test\"}]");
	}

	private List<Address> materialize(MessageLog log) {
		AtomicReference<List<Address>> out = new AtomicReference<>();
		inTx(program, "materialize", () -> {
			out.set(SwitchSiteHints.materialize(program, TaskMonitor.DUMMY, log));
		});
		return out.get();
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

	private BankDataflowEngine.DataflowResult run() throws Exception {
		return run(board(), null, null);
	}

	private BankDataflowEngine.DataflowResult run(BoardDescriptorModel.BoardModel board,
			Map<Function, HelperDiscovery.HelperModel> helpers,
			HelperDiscovery.BankResolution resolution) throws Exception {
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs
					.of(List.of(new BankStrategyRegistry.ConfiguredMechanism(latchStrategy(board),
						board.mask(), 0)), board)
					.withHelpers(helpers)
					.withBankResolution(resolution));
	}

	/** The UxROM shape: PRG_LO computed from a 4-bit {@code bank}, so the bank universe can bind. */
	private BoardDescriptorModel.BoardModel windowedBoard() {
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

	/** Two 4-bit fields behind one 8-bit latch. */
	private BoardDescriptorModel.BoardModel twoFieldBoard() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "bank", "bits": 4 }, { "name": "chr", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel b = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(b);
		return b;
	}

	private void layUnreachedStore(String bytes) throws Exception {
		builder.setBytes("0xc100", bytes, false);
	}

	@Test
	public void withoutTheHintTheUnreachedStoreIsNeverSeen() throws Exception {
		layUnreachedStore(LATCH_STORE);

		BankDataflowEngine.DataflowResult result = run();

		assertNull(program.getListing().getInstructionAt(addr(0xc100)));
		assertTrue(result.switchResults().isEmpty());
	}

	@Test
	public void theHintDisassemblesAndTheStrategyAnnotatesTheStoreItself() throws Exception {
		layUnreachedStore(LATCH_STORE);
		hintAt("49408", "");

		MessageLog log = new MessageLog();
		List<Address> ready = materialize(log);
		BankDataflowEngine.DataflowResult result = run();

		assertEquals(log.toString(), List.of(addr(0xc100)), ready);
		assertNotNull(program.getListing().getInstructionAt(addr(0xc100)));
		BankDataflowEngine.SwitchResult sr = result.switchResults().get(addr(0xc102));
		assertNotNull("the strategy's own computeSwitch must recognise the store", sr);
		assertEquals("the value is DERIVED from LDA #3, not stated by the hint", 3,
			sr.effect().bits());
	}

	@Test
	public void aHintAtAnAddressThatIsNotASwitchStoreYieldsNoAnnotation() throws Exception {
		layUnreachedStore("a9 03 85 10 60"); // LDA #3 / STA $10 / RTS -- a plain RAM store
		hintAt("49408", "");

		materialize(new MessageLog());
		BankDataflowEngine.DataflowResult result = run();

		assertNotNull("the hint still made it analyzable",
			program.getListing().getInstructionAt(addr(0xc100)));
		assertTrue("seed, don't inject: a wrong hint annotates nothing",
			result.switchResults().isEmpty());
	}

	@Test
	public void entryTrueCreatesAFunctionAndIsIdempotentAcrossRounds() throws Exception {
		layUnreachedStore(LATCH_STORE);
		hintAt("49408", ", \"entry\": true");

		materialize(new MessageLog());
		int functions = program.getFunctionManager().getFunctionCount();
		assertNotNull(program.getFunctionManager().getFunctionAt(addr(0xc100)));
		long modification = program.getModificationNumber();

		materialize(new MessageLog());
		materialize(new MessageLog());

		assertEquals(functions, program.getFunctionManager().getFunctionCount());
		assertEquals("a re-run with nothing missing must not write", modification,
			program.getModificationNumber());
		assertEquals(3, run().switchResults().get(addr(0xc102)).effect().bits());
	}

	@Test
	public void theSeededSiteCarriesProvenanceNamingTheDescriptor() throws Exception {
		layUnreachedStore(LATCH_STORE);
		hintAt("49408", ", \"comment\": \"latch\"");

		materialize(new MessageLog());

		Bookmark b = program.getBookmarkManager().getBookmark(addr(0xc100), BookmarkType.INFO,
			SwitchSiteHints.BOOKMARK_CATEGORY);
		assertNotNull(b);
		assertTrue(b.getComment(), b.getComment().contains("machines/games/test.gmap"));
		assertTrue(b.getComment(), b.getComment().contains("unit test"));
	}

	@Test
	public void anUnresolvableBlockIsLoggedAndSkippedNotFallenBackToTheBaseSpace() throws Exception {
		layUnreachedStore(LATCH_STORE);
		hint("[{\"addr\": 49408, \"block\": \"NO_SUCH_BLOCK\", \"provenance\": \"p\"}]");

		MessageLog log = new MessageLog();
		List<Address> ready = materialize(log);

		assertTrue(log.toString(), log.toString().contains("NO_SUCH_BLOCK"));
		assertNull("the unresolvable block must not fall back to the base space",
			program.getListing().getInstructionAt(addr(0xc100)));
		assertTrue(ready.stream().noneMatch(a -> a.equals(addr(0xc100))));
	}

	@Test
	public void anAddressInteriorToAnInstructionIsNotDisassembled() throws Exception {
		put(0xc100, LATCH_STORE); // disassembled: LDA #3 at c100, STA at c102
		hintAt("49409", ""); // 0xc101: the operand of the LDA

		MessageLog log = new MessageLog();
		List<Address> ready = materialize(log);

		assertTrue(log.toString(), log.toString().contains("interior"));
		assertTrue(ready.isEmpty());
	}

	@Test
	public void malformedPropertyIsReportedAndAppliesNothing() throws Exception {
		layUnreachedStore(LATCH_STORE);
		inTx(program, "garbage", () -> program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorHints.SWITCH_SITES_PROPERTY, "{\"sites\": [{\"x\": 1}]}"));

		MessageLog log = new MessageLog();
		List<Address> ready = materialize(log);

		assertTrue(log.toString(), log.toString().contains("malformed"));
		assertTrue(ready.isEmpty());
		assertTrue(SwitchSiteHints.seedAddresses(program).isEmpty());
	}

	// ------------------------------------------------------------------
	// bank: VALUE hints (bead grm-hb6.20, design section 6.3 as amended 2026-10-18)
	// ------------------------------------------------------------------

	/** LDA $10 (a RAM byte: unrecoverable) / STA $9000 / RTS, disassembled at c100; the STA is c102. */
	private static final String UNKNOWN_STORE = "a5 10 8d 00 90 60";

	private static final String DESCRIPTOR = "machines/games/test.gmap";

	private void bankHintAt(long site, int bank) {
		hint("[{\"addr\": " + site + ", \"bank\": " + bank + ", \"provenance\": \"unit test\"}]");
	}

	/** The WARNING a value hint raised at {@code at}, or null; reports from {@code result} first. */
	private String valueHintWarning(Address at, BankDataflowEngine.DataflowResult result) {
		inTx(program, "report value hints",
			() -> SwitchSiteHints.reportValueHints(program, result.hintNotes()));
		Bookmark b = program.getBookmarkManager().getBookmark(at, BookmarkType.WARNING,
			SwitchSiteHints.VALUE_HINT_CATEGORY);
		return b == null ? null : b.getComment();
	}

	@Test
	public void aValueHintFillsAnOtherwiseUnknownStore() throws Exception {
		put(0xc100, UNKNOWN_STORE);
		hintAt("49410", ""); // a SITE hint only: the seed, no value
		BankDataflowEngine.SwitchResult base = run().switchResults().get(addr(0xc102));
		assertTrue("baseline: nothing recovers the byte: " + base,
			base.stop() != BankSwitchStrategy.ValueStop.RESOLVED);

		bankHintAt(0xc102, 5);
		BankDataflowEngine.DataflowResult result = run();

		BankDataflowEngine.SwitchResult sr = result.switchResults().get(addr(0xc102));
		assertEquals(5, sr.effect().bits());
		assertEquals(0xF, sr.effect().knownMask());
		assertEquals(BankSwitchStrategy.ValueStop.RESOLVED, sr.stop());
		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertTrue(note.applied());
		assertNull("nothing was recovered, so nothing disagrees", note.recovered());
		assertNull("an applied, agreeing hint raises no warning",
			valueHintWarning(addr(0xc102), result));
	}

	@Test
	public void aContradictingValueHintWinsAndWarnsNamingBothValuesAndTheDescriptor()
			throws Exception {
		put(0xc100, LATCH_STORE); // LDA #3 / STA $9000: dataflow recovers 3
		bankHintAt(0xc102, 5);

		BankDataflowEngine.DataflowResult result = run();

		assertEquals("the hint WINS over the recovered 3", 5,
			result.switchResults().get(addr(0xc102)).effect().bits());
		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertTrue(note.applied());
		assertEquals("3", note.recovered());
		String warning = valueHintWarning(addr(0xc102), result);
		assertNotNull(warning);
		assertTrue(warning, warning.contains("5") && warning.contains("(3)"));
		assertTrue(warning, warning.contains(DESCRIPTOR));
	}

	@Test
	public void aValueHintAgreeingWithDataflowRaisesNothing() throws Exception {
		put(0xc100, LATCH_STORE);
		bankHintAt(0xc102, 3);

		BankDataflowEngine.DataflowResult result = run();

		assertEquals(3, result.switchResults().get(addr(0xc102)).effect().bits());
		assertNull(result.hintNotes().get(addr(0xc102)).recovered());
		assertNull(valueHintWarning(addr(0xc102), result));
	}

	@Test
	public void aValueHintTooWideForTheFieldIsNotAppliedAndWarns() throws Exception {
		put(0xc100, LATCH_STORE);
		bankHintAt(0xc102, 16); // the field is 4 bits wide

		BankDataflowEngine.DataflowResult result = run();

		assertEquals("the site keeps the value dataflow recovered", 3,
			result.switchResults().get(addr(0xc102)).effect().bits());
		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("does not fit"));
		String warning = valueHintWarning(addr(0xc102), result);
		assertNotNull(warning);
		assertTrue(warning, warning.contains("not applied") && warning.contains(DESCRIPTOR));
	}

	@Test
	public void aValueHintForABankTheWindowCannotHoldIsNotApplied() throws Exception {
		put(0xc100, LATCH_STORE);
		bankHintAt(0xc102, 5);
		BoardDescriptorModel.BoardModel windowed = windowedBoard();
		// the image realizes three banks of PRG_LO: 0, 1, 2
		HelperDiscovery.BankResolution resolution = new HelperDiscovery.BankResolution(windowed,
			Map.of("PRG_LO", java.util.Set.of(0, 1, 2)), Map.of());

		BankDataflowEngine.DataflowResult result = run(windowed, null, resolution);

		assertEquals(3, result.switchResults().get(addr(0xc102)).effect().bits());
		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("can hold"));

		bankHintAt(0xc102, 2);
		assertEquals("a bank the window does hold is applied", 2,
			run(windowed, null, resolution).switchResults().get(addr(0xc102)).effect().bits());
	}

	@Test
	public void aValueHintAtANonSwitchInstructionWarnsAndAnnotatesNothing() throws Exception {
		put(0xc100, "a9 03 85 10 60"); // LDA #3 / STA $10 / RTS -- a plain RAM store at c102
		bankHintAt(0xc102, 4);

		BankDataflowEngine.DataflowResult result = run();

		assertTrue(result.switchResults().isEmpty());
		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("no latch store or bank-switch helper"));
		assertNotNull(valueHintWarning(addr(0xc102), result));
	}

	@Test
	public void staleValueHintWarningsAreRetractedWhenTheHintGoes() throws Exception {
		put(0xc100, LATCH_STORE);
		bankHintAt(0xc102, 5);
		assertNotNull(valueHintWarning(addr(0xc102), run()));

		hintAt("49410", ""); // the same site, now without a value
		assertNull(valueHintWarning(addr(0xc102), run()));
	}

	@Test
	public void aProgramWithNoValueHintsCarriesNoHintNotes() throws Exception {
		put(0xc100, LATCH_STORE);
		hintAt("49410", "");

		assertTrue(run().hintNotes().isEmpty());
	}

	@Test
	public void theCommentSuffixMarksAHintedBankAndOnlyThen() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		BankState state = BankState.fullyKnown(b.mask(), 5);
		NesBankingAnalyzer analyzer = new NesBankingAnalyzer();
		inTx(program, "annotate", () -> {
			BankAnnotationAdapter.annotateOrWarn(analyzer, program, program.getListing(),
				addr(0xc102), state, b, Map.of(), new BankAnnotationAdapter.Annotation(null, "w",
					BankSwitchStrategy.ValueStop.RESOLVED, null, false, null,
					SwitchSiteHints.HINT_COMMENT_SUFFIX));
			BankAnnotationAdapter.annotateOrWarn(analyzer, program, program.getListing(),
				addr(0xc105), state, b, Map.of(), new BankAnnotationAdapter.Annotation(null, "w",
					BankSwitchStrategy.ValueStop.RESOLVED, null, false, null, ""));
		});
		String hinted = program.getListing().getComment(
			ghidra.program.model.listing.CommentType.EOL, addr(0xc102));
		String plain = program.getListing().getComment(
			ghidra.program.model.listing.CommentType.EOL, addr(0xc105));
		assertTrue(hinted, hinted.startsWith("bank -> 5") && hinted.endsWith("(game descriptor hint)"));
		assertFalse(plain, plain.contains("hint"));
	}

	// ---- a hint at a call to a bank-switch helper ----

	/**
	 * Caller {@code LDA $10 / JSR $c200 / RTS} at c100 (the JSR is c102), helper
	 * {@code STA $9000 / RTS} at c200 taking its bank in A.
	 */
	private Map<Function, HelperDiscovery.HelperModel> buildHelperAndCaller(
			BoardDescriptorModel.BoardModel b, int helperMask, String callerBytes)
			throws Exception {
		put(0xc100, callerBytes);
		put(0xc200, "8d 00 90 60");
		makeFunction(0xc100, 0xc105, "CALLER");
		makeFunction(0xc200, 0xc203, "HELPER");
		MemoryLatchBankSwitchStrategy strategy = latchStrategy(b);
		Function helper = program.getFunctionManager().getFunctionAt(addr(0xc200));
		return Map.of(helper, new HelperDiscovery.HelperModel(helper, addr(0xc200), null, 'A',
			helperMask, 0, strategy, addr(0xc200), addr(0xc200), null, List.of(addr(0xc200))));
	}

	private void makeFunction(int start, int endInclusive, String name) throws Exception {
		inTx(program, "create function " + name, () -> {
			try {
				program.getFunctionManager().createFunction(name, addr(start),
					new ghidra.program.model.address.AddressSet(addr(start), addr(endInclusive)),
					ghidra.program.model.symbol.SourceType.ANALYSIS);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		builder.createEntryPoint(String.format("0x%x", start), name);
	}

	@Test
	public void aValueHintAtAHelperCallResolvesAnUnrecoverableArgument() throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		Map<Function, HelperDiscovery.HelperModel> helpers =
			buildHelperAndCaller(b, b.mask(), "a5 10 20 00 c2 60");
		BankDataflowEngine.CallSwitch before =
			run(b, helpers, null).callSwitches().get(addr(0xc102));
		assertFalse("baseline: LDA $10 leaves the argument unrecovered", before.argumentResolved());

		bankHintAt(0xc102, 6);
		BankDataflowEngine.DataflowResult result = run(b, helpers, null);

		BankDataflowEngine.CallSwitch cs = result.callSwitches().get(addr(0xc102));
		assertTrue(cs.argumentResolved());
		assertEquals(6, cs.effect().bits());
		assertEquals(0xF, cs.effect().knownMask());
		assertEquals(6, result.stateIn().get(addr(0xc105)).bits());
		assertTrue(result.hintNotes().get(addr(0xc102)).applied());
		assertNull(valueHintWarning(addr(0xc102), result));
	}

	@Test
	public void aValueHintAtAHelperCallOverridesAndWarnsOnADifferentRecoveredArgument()
			throws Exception {
		BoardDescriptorModel.BoardModel b = board();
		// LDA #2 / JSR $c200 / RTS: the argument IS recoverable
		Map<Function, HelperDiscovery.HelperModel> helpers =
			buildHelperAndCaller(b, b.mask(), "a9 02 20 00 c2 60");
		assertEquals(2, run(b, helpers, null).callSwitches().get(addr(0xc102)).effect().bits());

		bankHintAt(0xc102, 6);
		BankDataflowEngine.DataflowResult result = run(b, helpers, null);

		assertEquals(6, result.callSwitches().get(addr(0xc102)).effect().bits());
		assertEquals("2", result.hintNotes().get(addr(0xc102)).recovered());
		String warning = valueHintWarning(addr(0xc102), result);
		assertTrue(warning, warning.contains("6") && warning.contains("(2)") &&
			warning.contains(DESCRIPTOR));
	}

	@Test
	public void aValueHintAtAMultiFieldHelperCallIsAmbiguousAndNotApplied() throws Exception {
		// two 4-bit fields behind one 8-bit latch: one call deposits both, so "bank 6" has no referent
		BoardDescriptorModel.BoardModel two = twoFieldBoard();
		Map<Function, HelperDiscovery.HelperModel> helpers =
			buildHelperAndCaller(two, two.mask(), "a5 10 20 00 c2 60");
		bankHintAt(0xc102, 6);

		BankDataflowEngine.DataflowResult result = run(two, helpers, null);

		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("more than one bank field"));
		assertFalse("the call falls back to dataflow", result.callSwitches().get(addr(0xc102))
				.argumentResolved());
		assertNotNull(valueHintWarning(addr(0xc102), result));
	}

	// ---- multi-field mechanisms: the hint names the field the store commits (grm-hb6.22) ----

	/** select(3) | r6(6) | r7(6), MMC3-shaped, with banked windows so select is not a bank. */
	private static final int R6 = 0x3F << 3;
	private static final int R7 = 0x3F << 9;

	private BoardDescriptorModel.BoardModel parseBoard(String json) {
		BoardDescriptorModel.BoardModel b = BoardDescriptorModel.BoardModel.parse(
			JsonParser.parseString(json).getAsJsonObject(), new MessageLog(), "test",
			"test-descriptor.json");
		assertNotNull(b);
		return b;
	}

	private BoardDescriptorModel.BoardModel mmc3Board() {
		return parseBoard("""
				{
				  "physical": [ { "name": "PRG", "image": "prg_rom" } ],
				  "windows": [
				    { "name": "W6", "start": 32768, "end": 40959,
				      "maps": { "space": "PRG", "expr": "r6 * 0x2000" }, "on_write": "mechanism" },
				    { "name": "W7", "start": 40960, "end": 49151,
				      "maps": { "space": "PRG", "expr": "r7 * 0x2000" }, "on_write": "mechanism" },
				    { "name": "FIX", "start": 49152, "end": 65535,
				      "maps": { "space": "PRG", "expr": "last" }, "on_write": "mechanism" }
				  ],
				  "banking": {
				    "initial_state": 0,
				    "state": [ { "name": "select", "bits": 3 }, { "name": "r6", "bits": 6 },
				               { "name": "r7", "bits": 6 } ],
				    "mechanisms": [ { "strategy": "select-data" } ]
				  }
				}
				""");
	}

	private static JsonObject pos(int lsb, int width) {
		JsonObject o = new JsonObject();
		o.addProperty("lsb", lsb);
		o.addProperty("width", width);
		return o;
	}

	private SelectDataBankSwitchStrategy mmc3Strategy(BoardDescriptorModel.BoardModel b) {
		JsonObject layout = new JsonObject();
		layout.add("select", pos(0, 3));
		layout.add("r6", pos(3, 6));
		layout.add("r7", pos(9, 6));
		JsonObject targets = new JsonObject();
		targets.addProperty("6", "r6");
		targets.addProperty("7", "r7");
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.addProperty("select_mask", 0x07);
		params.add("_field_layout", layout);
		params.add("targets", targets);
		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, b.mask());
		return strategy;
	}

	/** mirroring(2) | prg_mode(2) | prg_bank(5), MMC1-shaped, PRG register only. */
	private BoardDescriptorModel.BoardModel mmc1Board() {
		return parseBoard("""
				{
				  "physical": [ { "name": "PRG", "image": "prg_rom" } ],
				  "windows": [
				    { "name": "PRG_LO", "start": 32768, "end": 49151,
				      "maps": { "space": "PRG", "expr": "prg_bank * 0x4000" }, "on_write": "mechanism" },
				    { "name": "PRG_HI", "start": 49152, "end": 65535,
				      "maps": { "space": "PRG", "expr": "last" }, "on_write": "mechanism" }
				  ],
				  "banking": {
				    "initial_state": 0,
				    "state": [ { "name": "mirroring", "bits": 2 }, { "name": "prg_mode", "bits": 2 },
				               { "name": "prg_bank", "bits": 5 } ],
				    "mechanisms": [ { "strategy": "serial-shift" } ]
				  }
				}
				""");
	}

	private SerialShiftBankSwitchStrategy mmc1Strategy(BoardDescriptorModel.BoardModel b) {
		JsonObject layout = new JsonObject();
		layout.add("mirroring", pos(0, 2));
		layout.add("prg_mode", pos(2, 2));
		layout.add("prg_bank", pos(4, 5));
		JsonObject prgBank = new JsonObject();
		prgBank.addProperty("name", "prg_bank");
		prgBank.addProperty("shift", 0);
		prgBank.addProperty("bits", 5);
		com.google.gson.JsonArray fields = new com.google.gson.JsonArray();
		fields.add(prgBank);
		JsonObject prgTarget = new JsonObject();
		prgTarget.add("fields", fields);
		JsonObject targets = new JsonObject();
		targets.add("3", prgTarget);
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.add("_field_layout", layout);
		params.add("targets", targets);
		SerialShiftBankSwitchStrategy strategy = new SerialShiftBankSwitchStrategy();
		strategy.configure(program, params, b.mask());
		return strategy;
	}

	private BankDataflowEngine.DataflowResult runWith(BoardDescriptorModel.BoardModel b,
			BankSwitchStrategy strategy) throws Exception {
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(
				List.of(new BankStrategyRegistry.ConfiguredMechanism(strategy, b.mask(), 0)), b));
	}

	/**
	 * {@code LDA #6 / STA $8000 / <dataLoad> / STA $8001 / RTS} at c100 as a function: the select
	 * store is c102, the data store c107.
	 */
	private void layMmc3(String dataLoad) throws Exception {
		put(0xc100, "a9 06 8d 00 80 " + dataLoad + " 8d 01 80 60");
		makeFunction(0xc100, 0xc10a, "MMC3");
	}

	@Test
	public void aValueHintAtAnMmc3DataWriteNamesTheSelectedRegister() throws Exception {
		layMmc3("a5 10"); // LDA $10: the data byte is unrecoverable
		BoardDescriptorModel.BoardModel b = mmc3Board();
		BankDataflowEngine.SwitchResult before =
			runWith(b, mmc3Strategy(b)).switchResults().get(addr(0xc107));
		assertNotNull(before);
		assertEquals("baseline: r6 is not recovered", 0, before.effect().knownMask() & R6);

		bankHintAt(0xc107, 5);
		BankDataflowEngine.DataflowResult result = runWith(b, mmc3Strategy(b));

		BankDataflowEngine.SwitchResult sr = result.switchResults().get(addr(0xc107));
		assertEquals(R6, sr.effect().knownMask() & R6);
		assertEquals(5, (sr.effect().bits() & R6) >>> 3);
		assertEquals("the select echo is kept", 6, sr.effect().bits() & 7);
		assertEquals("r7 keeps its in-state echo", before.effect().knownMask() & R7,
			sr.effect().knownMask() & R7);
		assertEquals(before.effect().bits() & R7, sr.effect().bits() & R7);
		assertEquals(BankSwitchStrategy.ValueStop.RESOLVED, sr.stop());
		assertTrue(result.hintNotes().get(addr(0xc107)).applied());
		assertNull(valueHintWarning(addr(0xc107), result));
	}

	@Test
	public void aContradictingValueHintAtAnMmc3DataWriteWinsAndWarnsOnTheFieldValue()
			throws Exception {
		layMmc3("a9 02"); // LDA #2: dataflow recovers r6 = 2
		BoardDescriptorModel.BoardModel b = mmc3Board();
		bankHintAt(0xc107, 5);

		BankDataflowEngine.DataflowResult result = runWith(b, mmc3Strategy(b));

		assertEquals(5, (result.switchResults().get(addr(0xc107)).effect().bits() & R6) >>> 3);
		assertEquals("the FIELD's recovered value, not the whole mechanism word", "2",
			result.hintNotes().get(addr(0xc107)).recovered());
		String warning = valueHintWarning(addr(0xc107), result);
		assertTrue(warning, warning != null && warning.contains("(2)"));
	}

	@Test
	public void aValueHintAtAnMmc3DataWriteWithUnknownSelectIsAmbiguous() throws Exception {
		// LDA $10 / STA $8000 (select from RAM) / LDA $11 / STA $8001: R6 or R7, nobody knows
		put(0xc100, "a5 10 8d 00 80 a5 11 8d 01 80 60");
		makeFunction(0xc100, 0xc10a, "MMC3");
		BoardDescriptorModel.BoardModel b = mmc3Board();
		bankHintAt(0xc107, 5);

		SwitchSiteHints.HintNote note = runWith(b, mmc3Strategy(b)).hintNotes().get(addr(0xc107));

		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("more than one bank field"));
	}

	@Test
	public void aValueHintAtAnMmc3SelectWriteIsNotApplied() throws Exception {
		layMmc3("a5 10");
		BoardDescriptorModel.BoardModel b = mmc3Board();
		bankHintAt(0xc102, 6);

		BankDataflowEngine.DataflowResult result = runWith(b, mmc3Strategy(b));

		SwitchSiteHints.HintNote note = result.hintNotes().get(addr(0xc102));
		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("not a bank any window maps by"));
		assertEquals("select keeps what dataflow recovered", 6,
			result.switchResults().get(addr(0xc102)).effect().bits() & 7);
	}

	/**
	 * {@code LDA $10 / AND #$1F} (bit 7 known clear, so not a reset) then a five-write PRG-register
	 * chain {@code STA $E000 / (LSR A / STA $E000) x4 / RTS} at c100; the writes are c104, c108,
	 * c10c, c110 and the commit c114.
	 */
	private void layMmc1Chain() throws Exception {
		put(0xc100, "a5 10 29 1f 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 60");
		makeFunction(0xc100, 0xc117, "MMC1");
	}

	@Test
	public void aValueHintAtAnMmc1CommitResolvesThePrgBank() throws Exception {
		layMmc1Chain();
		BoardDescriptorModel.BoardModel b = mmc1Board();
		bankHintAt(0xc114, 9);

		BankDataflowEngine.DataflowResult result = runWith(b, mmc1Strategy(b));

		BankDataflowEngine.SwitchResult sr = result.switchResults().get(addr(0xc114));
		assertNotNull(sr);
		assertEquals(0x1F0, sr.effect().knownMask() & 0x1F0);
		assertEquals(9, (sr.effect().bits() & 0x1F0) >>> 4);
		assertTrue(result.hintNotes().get(addr(0xc114)).applied());
	}

	@Test
	public void aValueHintAtAnMmc1ShiftWriteBeforeTheCommitIsNotApplied() throws Exception {
		layMmc1Chain();
		BoardDescriptorModel.BoardModel b = mmc1Board();
		bankHintAt(0xc108, 9); // write 2 of 5

		SwitchSiteHints.HintNote note = runWith(b, mmc1Strategy(b)).hintNotes().get(addr(0xc108));

		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("commits no tracked bank field"));
	}

	@Test
	public void aValueHintAtAJsrWithNoHelperKnownIsNotApplied() throws Exception {
		put(0xc100, "a5 10 20 00 c2 60");
		put(0xc200, "8d 00 90 60");
		bankHintAt(0xc102, 6);

		SwitchSiteHints.HintNote note = run().hintNotes().get(addr(0xc102));

		assertFalse(note.applied());
		assertTrue(note.problem(), note.problem().contains("no latch store or bank-switch helper"));
	}
}
