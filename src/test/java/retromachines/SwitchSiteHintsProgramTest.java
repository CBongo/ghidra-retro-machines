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
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@code banking.switch_sites} (bead grm-hb6.4, design sections 6.2 and 8):
 * a SITE hint is a dataflow SEED, never an injected result.
 * <p>
 * The seam is {@link SwitchSiteHints#materialize} plus {@link BankDataflowEngine#runDataflow}
 * with a hand-built board, exactly as {@code BankPathForkProgramTest} drives the engine: no
 * installed extension, no file on disk. The descriptor object is handed in through the same
 * {@link DescriptorSupport#formatSwitchSites} the loader uses, so the property under test is the
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
		String published = DescriptorSupport.formatSwitchSites(doc, "machines/games/test.gmap");
		inTx(program, "publish switch_sites", () -> program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorSupport.SWITCH_SITES_PROPERTY, published));
	}

	private void hintAt(String addrDecimal, String extra) {
		hint("[{\"addr\": " + addrDecimal + extra + ", \"provenance\": \"unit test\"}]");
	}

	private List<Address> materialize(MessageLog log) {
		List<Address>[] out = new List[1];
		inTx(program, "materialize", () -> {
			out[0] = SwitchSiteHints.materialize(program, TaskMonitor.DUMMY, log);
		});
		return out[0];
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

	private BankDataflowEngine.DataflowResult run() throws Exception {
		BoardDescriptorModel.BoardModel board = board();
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9100);
		params.addProperty("mask", board.mask());
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, board.mask());
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			List.of(new BankStrategyRegistry.ConfiguredMechanism(strategy, board.mask(), 0)),
			board, null, Map.of());
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
				.setString(DescriptorSupport.SWITCH_SITES_PROPERTY, "{\"sites\": [{\"x\": 1}]}"));

		MessageLog log = new MessageLog();
		List<Address> ready = materialize(log);

		assertTrue(log.toString(), log.toString().contains("malformed"));
		assertTrue(ready.isEmpty());
		assertTrue(SwitchSiteHints.seedAddresses(program).isEmpty());
	}
}
