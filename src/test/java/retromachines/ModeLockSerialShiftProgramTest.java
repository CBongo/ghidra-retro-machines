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

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import retromachines.BankDataflowEngine.ModeWrite;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins bead {@code grm-dos9.7}: the layout-mode lock forms on an MMC1 (serial-shift) board --
 * and bead {@code grm-dos9.9}: an explicit mode set outvotes the shifter reset's implicit one.
 * <p>
 * Before the fix no MMC1 row ever locked, not even blmaster, which writes prg_mode 3 at every
 * control write. The census counted every direct site whose mechanism owns the mode field, and on
 * MMC1 that is every link of a shift chain: writes 1-4 are {@code NO_DEPOSIT} echoes of the
 * in-state, and inside a control-register helper the chain's first write and its write-5 commit
 * are {@code HELPER_ARGUMENT} -- the value is the caller's, which the census already judges at
 * each call site. Every one of those read as "an unresolved mode write", so the census refused.
 * <p>
 * The fixture is blmaster's shape: RESET loads the control value and calls a five-write helper
 * that shifts it into {@code $8000}.
 */
public class ModeLockSerialShiftProgramTest extends AbstractProgramTest {

	/** mirroring(2) | prg_mode(2) | prg_bank(5), matching machines/nes-mmc1.yaml. */
	private static final int STATE_MASK = 0x1FF;
	private static final int MODE_MASK = 0x0C;


	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createUninitializedMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private void makeFunction(int start, int endInclusive, String name, boolean entryPoint)
			throws Exception {
		inTx(program, "create function", () -> {
			program.getFunctionManager().createFunction(name, addr(start),
				new AddressSet(addr(start), addr(endInclusive)), SourceType.ANALYSIS);
		});
		if (entryPoint) {
			builder.createEntryPoint(String.format("0x%x", start), name);
		}
	}

	private static JsonObject pos(int lsb, int width) {
		JsonObject o = new JsonObject();
		o.addProperty("lsb", lsb);
		o.addProperty("width", width);
		return o;
	}

	private static JsonObject field(String name, int shift, int bits) {
		JsonObject o = new JsonObject();
		o.addProperty("name", name);
		o.addProperty("shift", shift);
		o.addProperty("bits", bits);
		return o;
	}

	private static JsonObject target(JsonObject... fields) {
		JsonArray arr = new JsonArray();
		for (JsonObject f : fields) {
			arr.add(f);
		}
		JsonObject o = new JsonObject();
		o.add("fields", arr);
		return o;
	}

	private BankStrategyRegistry.ConfiguredMechanism mmc1() {
		JsonObject layout = new JsonObject();
		layout.add("mirroring", pos(0, 2));
		layout.add("prg_mode", pos(2, 2));
		layout.add("prg_bank", pos(4, 5));

		JsonObject targets = new JsonObject();
		targets.add("0", target(field("mirroring", 0, 2), field("prg_mode", 2, 2)));
		targets.add("3", target(field("prg_bank", 0, 5)));

		JsonObject reset = new JsonObject();
		reset.addProperty("prg_mode", 3);

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.add("_field_layout", layout);
		params.add("targets", targets);
		params.add("reset", reset);

		SerialShiftBankSwitchStrategy strategy = new SerialShiftBankSwitchStrategy();
		strategy.configure(program, params, STATE_MASK);
		return new BankStrategyRegistry.ConfiguredMechanism(strategy, STATE_MASK, 0);
	}

	/** Power-on prg_mode 3; layouts keyed on prg_mode, so it is the board's mode field. */
	private BoardDescriptorModel.BoardModel board() {
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(
			JsonParser.parseString("""
					{
					  "banking": {
					    "initial_state": 12,
					    "mechanisms": [ { "strategy": "serial-shift" } ],
					    "state": [ { "name": "mirroring", "bits": 2 },
					               { "name": "prg_mode", "bits": 2 },
					               { "name": "prg_bank", "bits": 5 } ]
					  },
					  "layouts": [
					    { "when": { "prg_mode": 0 },
					      "windows": [ { "name": "lo", "start": 32768, "end": 49151,
					                     "maps": { "expr": "prg_bank * 16384" } } ] },
					    { "when": { "prg_mode": 3 },
					      "windows": [ { "name": "lo", "start": 32768, "end": 49151,
					                     "maps": { "expr": "prg_bank * 16384" } } ] }
					  ]
					}
					""").getAsJsonObject(), new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		assertNotNull("the fixture must have a layout-mode field", board.modeField());
		return board;
	}

	/**
	 * RESET at $C000: {@code LDA #control / JSR $C100 / JMP *}. The helper at $C100 is the
	 * unrolled five-write chain into $8000 (the control register) and RTS.
	 */
	private void layResetAndControlHelper(int control) throws Exception {
		put(0xc000, String.format("a9 %02x 20 00 c1 4c 05 c0", control));
		makeFunction(0xc000, 0xc007, "RESET", true);
		put(0xc100, "8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 60");
		makeFunction(0xc100, 0xc113, "SET_CONTROL", false);
	}

	/** Pass 1 finds the helper; pass 2 is the run the analyzer reports, as BoardBankAnalyzer does. */
	private BankDataflowEngine.DataflowResult run() throws Exception {
		List<BankStrategyRegistry.ConfiguredMechanism> mechanisms = List.of(mmc1());
		BankDataflowEngine.DataflowResult pass1 = BankDataflowEngine.runDataflow(program,
			TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(mechanisms, board()));
		Map<Function, HelperModel> helpers =
			HelperDiscovery.findHelpers(program, pass1.switchResults());
		assertFalse("the fixture must yield a helper, or the test proves nothing",
			helpers.isEmpty());
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(mechanisms, board()).withHelpers(helpers));
	}

	/** blmaster's case: the caller passes prg_mode 3, and the mode locks to 3. */
	@Test
	public void aControlHelperCallLocksTheModeDespiteTheChainLinks() throws Exception {
		layResetAndControlHelper(0x0c); // mirroring 0, prg_mode 3

		BankDataflowEngine.DataflowResult result = run();

		assertNotNull("the helper call is the one mode write; it must lock (reason given: " +
			result.noModeLock() + ")", result.modeLock());
		assertFalse(result.modeLock().rejected());
		assertEquals(0x0c, result.modeLock().state().bits() & MODE_MASK);
		assertEquals(addr(0xc002), result.modeLock().source());
	}

	/** The lock is the CALLER's value, not the power-on mode it happens to equal above. */
	@Test
	public void theLockIsTheCallersModeNotThePowerOnMode() throws Exception {
		layResetAndControlHelper(0x00); // prg_mode 0

		BankDataflowEngine.DataflowResult result = run();

		assertNotNull(result.noModeLock(), result.modeLock());
		assertEquals(0, result.modeLock().state().bits() & MODE_MASK);
	}

	/**
	 * drmario's and rcproam's shape (grm-dos9.9): RESET resets the shifter -- the hardware forces
	 * prg_mode 3 -- then the control write sets prg_mode 0. The explicit set outvotes the implicit
	 * one, so the mode locks to 0 and the reset is reported as outvoted, not as a contradiction.
	 */
	@Test
	public void anExplicitModeSetOutvotesTheShifterReset() throws Exception {
		// c000 LDA #$80 / c002 STA $8000 (reset) / c005 LDA #$00 / c007 JSR $C100 / c00a JMP *
		put(0xc000, "a9 80 8d 00 80 a9 00 20 00 c1 4c 0a c0");
		makeFunction(0xc000, 0xc00c, "RESET", true);
		put(0xc100, "8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 60");
		makeFunction(0xc100, 0xc113, "SET_CONTROL", false);

		BankDataflowEngine.DataflowResult result = run();

		assertNotNull(result.noModeLock(), result.modeLock());
		assertFalse("the reset must not contradict the lock: " + result.modeLock().contradictions(),
			result.modeLock().rejected());
		assertEquals(0, result.modeLock().state().bits() & MODE_MASK);
		assertEquals(addr(0xc007), result.modeLock().source());
		assertEquals(List.of(addr(0xc002)), result.modeLock().outvoted());
		assertTrue("the reset write is in the census, marked implicit",
			result.modeLock().writes().get(addr(0xc002)).implicit());
	}

	/**
	 * rcproam's shape (grm-dos9.9): the reset is a helper of its own ({@code ff83}:
	 * {@code LDA #$80 / STA $8000 / RTS}) that RESET calls. The CALL is the census entry, and it
	 * is an implicit set because every site of its helper is.
	 */
	@Test
	public void aCallToAResetOnlyHelperIsOutvotedToo() throws Exception {
		// c000 JSR $C200 (reset) / c003 LDA #$00 / c005 JSR $C100 / c008 JMP *
		put(0xc000, "20 00 c2 a9 00 20 00 c1 4c 08 c0");
		makeFunction(0xc000, 0xc00a, "RESET", true);
		put(0xc100, "8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 60");
		makeFunction(0xc100, 0xc113, "SET_CONTROL", false);
		put(0xc200, "a9 80 8d 00 80 60");
		makeFunction(0xc200, 0xc205, "RESET_SHIFTER", false);

		BankDataflowEngine.DataflowResult result = run();

		assertNotNull(result.noModeLock(), result.modeLock());
		assertFalse("the reset call must not contradict the lock: " +
			result.modeLock().contradictions(), result.modeLock().rejected());
		assertEquals(0, result.modeLock().state().bits() & MODE_MASK);
		assertTrue(result.modeLock().outvoted().toString(),
			result.modeLock().outvoted().contains(addr(0xc000)));
	}

	/**
	 * Bionic Commando's shape (grm-dos9.14): one PRG chain with two entries.
	 *
	 * <pre>
	 * c000  LDA #$0c / JSR c100     ; control: prg_mode 3
	 * c005  LDA #$05 / JSR c216     ; set PRG bank 5 through the shadow-recording entry
	 * c00a  JSR c200                ; restore it from the shadow
	 * c00d  JMP c00d
	 * c200  LDA $65                 ; FUN_dca8: restore entry, reloads the shadow
	 * c202  STA $E000 ... c212      ; five-write chain into the PRG register
	 * c215  RTS
	 * c216  STA $65                 ; FUN_dcbe: records the caller's bank
	 * c218  JMP c202                ; and enters the chain mid-body
	 * </pre>
	 */
	private void layTwoEntryPrgChain() throws Exception {
		layTwoEntryPrgChain(false);
	}

	/** {@link #layTwoEntryPrgChain()}, optionally with RESET also calling {@code SET_PRG_3}. */
	private void layTwoEntryPrgChain(boolean thirdEntry) throws Exception {
		if (thirdEntry) {
			// ... c00a JSR c200 / c00d JSR c21b / c010 JMP c010
			put(0xc000, "a9 0c 20 00 c1 a9 05 20 16 c2 20 00 c2 20 1b c2 4c 10 c0");
			makeFunction(0xc000, 0xc012, "RESET", true);
			put(0xc21b, "a9 03 4c 02 c2"); // LDA #$03 / JMP c202
			makeFunction(0xc21b, 0xc21f, "SET_PRG_3", false);
		}
		else {
			put(0xc000, "a9 0c 20 00 c1 a9 05 20 16 c2 20 00 c2 4c 0d c0");
			makeFunction(0xc000, 0xc00f, "RESET", true);
		}
		put(0xc100, "8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 4a 8d 00 80 60");
		makeFunction(0xc100, 0xc113, "SET_CONTROL", false);
		put(0xc200, "a5 65 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 60");
		makeFunction(0xc200, 0xc215, "RESTORE_PRG", false);
		put(0xc216, "85 65 4c 02 c2");
		makeFunction(0xc216, 0xc21a, "SET_PRG", false);
		// $65 is RAM: the restore proof and the RAM-read stop both require a writable block.
		inTx(program, "zp writable",
			() -> program.getMemory().getBlock(addr(0x65)).setWrite(true));
	}

	/** {@link #run()}, with the analyzer's whole discovery chain (BoardBankAnalyzer.added). */
	private BankDataflowEngine.DataflowResult runWithWrappers() throws Exception {
		List<BankStrategyRegistry.ConfiguredMechanism> mechanisms = List.of(mmc1());
		BankDataflowEngine.DataflowResult pass1 = BankDataflowEngine.runDataflow(program,
			TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(mechanisms, board()));
		Map<Function, HelperModel> helpers = HelperDiscovery.findCallEdgeWrappers(program,
			HelperDiscovery.findPassThroughWrappers(program,
				HelperDiscovery.composeTailCalls(program,
					HelperDiscovery.findHelpers(program, pass1.switchResults())),
				pass1.switchResults()),
			pass1.switchResults());
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(mechanisms, board()).withHelpers(helpers));
	}

	/** The JMP-closed entry is a call-edge wrapper, so its caller's bank is deposited. */
	@Test
	public void aWrapperClosedByAJumpIntoTheChainDepositsItsCallersBank() throws Exception {
		layTwoEntryPrgChain();

		BankDataflowEngine.DataflowResult result = runWithWrappers();

		BankDataflowEngine.CallSwitch call = result.callSwitches().get(addr(0xc007));
		assertNotNull("JSR c216 must be recognized as a helper call", call);
		assertTrue(call.argumentResolved());
		assertEquals("prg_bank 5 (bits 4-8)", 0x50, call.effect().bits() & 0x1F0);
		assertEquals(0x1F0, call.effect().knownMask() & 0x1F0);
	}

	/**
	 * The chain's write 1 sits at a join of the two entries (c200's fall-through and c218's JMP).
	 * Each arm's value is judged elsewhere -- the restore entry's at its own call sites, the
	 * wrapper's at its callers -- so neither the write-1 gate nor the commit votes, and the
	 * control call's prg_mode 3 locks.
	 */
	@Test
	public void aChainJoinedByTwoJudgedEntriesDoesNotBlockTheModeLock() throws Exception {
		layTwoEntryPrgChain();

		BankDataflowEngine.DataflowResult result = runWithWrappers();

		assertEquals(BankSwitchStrategy.ValueStop.ENTRY_SUPPLIED,
			result.switchResults().get(addr(0xc202)).stop());
		assertEquals(BankSwitchStrategy.ValueStop.ENTRY_SUPPLIED,
			result.switchResults().get(addr(0xc212)).stop());
		assertNotNull("reason given: " + result.noModeLock(), result.modeLock());
		assertEquals(0x0c, result.modeLock().state().bits() & MODE_MASK);
	}

	/**
	 * Control: a third way in that sets A itself ({@code c21b LDA #$03 / JMP c202}, a function
	 * of its own) is not a wrapper or a thunk, so nothing judges its value and the chain keeps
	 * its warning -- no lock rests on it.
	 */
	@Test
	public void anArmThatSetsTheRegisterItselfKeepsTheWarning() throws Exception {
		layTwoEntryPrgChain(true);

		BankDataflowEngine.DataflowResult result = runWithWrappers();

		assertEquals(BankSwitchStrategy.ValueStop.ANALYZER_LIMIT,
			result.switchResults().get(addr(0xc202)).stop());
		assertNull(result.modeLock());
	}

	/** Implicit sets vote only when nothing sets the field explicitly (grm-dos9.9). */
	@Test
	public void implicitSetsVoteOnlyWhenNoExplicitSetExists() {
		ModeWrite reset = new ModeWrite(MODE_MASK, new BankState(MODE_MASK, 0xc), null, true);
		ModeWrite control = new ModeWrite(MODE_MASK, new BankState(MODE_MASK, 0x0));

		BankDataflowEngine.ModeLock alone =
			BankDataflowEngine.censusModeLock(Map.of(addr(0xc000), reset), MODE_MASK).lock();
		assertNotNull("a reset alone still locks", alone);
		assertEquals(0xc, alone.state().bits());

		BankDataflowEngine.ModeLock both = BankDataflowEngine.censusModeLock(
			Map.of(addr(0xc000), reset, addr(0xc010), control), MODE_MASK).lock();
		assertNotNull(both);
		assertEquals(0x0, both.state().bits());
		assertEquals(addr(0xc010), both.source());
		BankDataflowEngine.ModeLock checked =
			both.verified(Map.of(addr(0xc000), reset, addr(0xc010), control));
		assertFalse(checked.rejected());
		assertEquals(List.of(addr(0xc000)), checked.outvoted());
	}

	/** The no-lock reasons the analyzer logs (grm-dos9.7's diagnostic). */
	@Test
	public void theCensusSaysWhyNoLockFormed() {
		assertNull("no mode field: nothing to explain",
			BankDataflowEngine.censusModeLock(Map.of(), 0).noLock());
		assertEquals("no reset-reached write owns the field",
			BankDataflowEngine.censusModeLock(Map.of(), MODE_MASK).noLock());

		String unresolved = BankDataflowEngine.censusModeLock(Map.of(
			addr(0xc000), new ModeWrite(MODE_MASK, BankState.unknown(),
				BankSwitchStrategy.ValueStop.ANALYZER_LIMIT)), MODE_MASK).noLock();
		assertTrue(unresolved, unresolved.contains("1 of 1 write(s) leave owned mode bits " +
			"unresolved: c000 (owns 0xc, known 0x0, ANALYZER_LIMIT)"));

		String disagree = BankDataflowEngine.censusModeLock(Map.of(
			addr(0xc000), new ModeWrite(MODE_MASK, new BankState(MODE_MASK, 0x0)),
			addr(0xc010), new ModeWrite(MODE_MASK, new BankState(MODE_MASK, 0xc))),
			MODE_MASK).noLock();
		assertTrue(disagree, disagree.startsWith("disagreement: c010 writes 0xc where c000"));

		String partial = BankDataflowEngine.censusModeLock(Map.of(
			addr(0xc000), new ModeWrite(0x4, new BankState(0x4, 0x4))), MODE_MASK).noLock();
		assertTrue(partial, partial.contains("cover only 0x4 of field mask 0xc"));
	}
}
