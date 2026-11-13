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

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.InterruptExitDefault.HandlerExits;

/**
 * Pins bead {@code grm-5tl.21}: an interrupt handler that exits with a constant bank state
 * supplies the game's DEFAULT for bank state that is genuinely unknown (Rygar's NMI leaves
 * bank 3 switched in), as a fallback ranked with {@code banking.initial_state}, with its own
 * provenance text.
 * <p>
 * The board is one 4-bit {@code bank} field (power-on 0) switched by a latch at {@code $8000};
 * handlers live at {@code $9000} and {@code $9100}.
 */
public class InterruptExitDefaultProgramTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
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
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		return board;
	}

	private BankStrategyRegistry.ConfiguredMechanism latch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0x8000);
		params.addProperty("mask", 0xF);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0xF);
		return new BankStrategyRegistry.ConfiguredMechanism(strategy, 0xF, 0);
	}

	private void handler(int start, int endInclusive, String bytes) throws Exception {
		put(start, bytes);
		inTx(program, "create handler", () -> {
			program.getFunctionManager().createFunction(String.format("ISR_%x", start),
				addr(start), new AddressSet(addr(start), addr(endInclusive)), SourceType.ANALYSIS);
		});
	}

	/** Runs the dataflow with the given handlers declared as async entries; returns the default. */
	private InterruptExitDefault.Result defaultFor(int... entries) throws Exception {
		List<Address> asyncs = new java.util.ArrayList<>();
		for (int e : entries) {
			asyncs.add(addr(e));
		}
		inTx(program, "set async entries", () -> {
			program.getOptions(Program.PROGRAM_INFO).setString(
				DescriptorHints.ASYNC_ENTRY_POINTS_PROPERTY,
				DescriptorHints.formatAsyncEntryPoints(asyncs));
		});
		BoardDescriptorModel.BoardModel board = board();
		BankDataflowEngine.DataflowResult flow = BankDataflowEngine.runDataflow(program,
			TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(List.of(latch()), board));
		return InterruptExitDefault.compute(program.getListing(), asyncs, flow.stateIn(),
			board.fieldSpecs());
	}

	/** LDA #n / STA $8000 / RTI. */
	private static String switchTo(int bank) {
		return String.format("a9 %02x 8d 00 80 40", bank);
	}

	@Test
	public void constantExitNmiProvidesTheDefaultAndItsProvenance() throws Exception {
		handler(0x9000, 0x9005, switchTo(3));

		InterruptExitDefault.Result def = defaultFor(0x9000);

		assertEquals(0xF, def.knownMask());
		assertEquals(3, def.bits());
		assertEquals("default: interrupt exit bank=3 (" + addr(0x9000) + ")", def.describe(0xF));
		BoardDescriptorModel.BoardModel board = board().withInterruptDefault(def);
		assertEquals("a wholly unknown state falls back to the default, not initial_state", 3,
			board.effective(BankState.unknown(), board.mask()));
		assertEquals("initial_state keeps stating power-on", 0, board.initialState());
		assertEquals("a known state is never overridden", 7,
			board.effective(new BankState(0xF, 7), board.mask()));
		assertNull("no unknown bit in the field, nothing to explain", def.describe(0));
	}

	@Test
	public void untouchedNmiProvidesNoDefault() throws Exception {
		handler(0x9000, 0x9000, "40");

		assertTrue(defaultFor(0x9000).isEmpty());
	}

	@Test
	public void nmiExitingWithAnUnknownBankProvidesNoDefault() throws Exception {
		// LDA $0200 / STA $8000 / RTI: switches, but to a value nothing recovers
		handler(0x9000, 0x9005, "ad 00 02 8d 00 80 40");

		assertTrue(defaultFor(0x9000).isEmpty());
	}

	/** A vector aimed at code that returns with RTS (or jumps into mainline) has no interrupt exit. */
	@Test
	public void aSubroutineReturnIsNotAHandlerExit() throws Exception {
		handler(0x9000, 0x9005, "a9 03 8d 00 80 60");

		assertTrue(defaultFor(0x9000).isEmpty());
	}

	@Test
	public void handlersThatDisagreeProvideNoDefault() throws Exception {
		handler(0x9000, 0x9005, switchTo(3));
		handler(0x9100, 0x9105, switchTo(4));

		assertTrue(defaultFor(0x9000, 0x9100).isEmpty());
	}

	@Test
	public void handlersThatAgreeProvideTheDefault() throws Exception {
		handler(0x9000, 0x9005, switchTo(3));
		handler(0x9100, 0x9105, switchTo(3));

		InterruptExitDefault.Result def = defaultFor(0x9000, 0x9100);

		assertEquals(3, def.bits());
		assertEquals("the lowest providing entry is named", addr(0x9000), def.fields().get(0).entry());
	}

	@Test
	public void aKnowingHandlerBesideANeutralOneStillProvides() throws Exception {
		handler(0x9000, 0x9005, switchTo(3));
		handler(0x9100, 0x9100, "40");

		assertEquals(3, defaultFor(0x9000, 0x9100).bits());
	}

	/** One exit knows the bank, the other does not: the handler has no constant exit. */
	@Test
	public void mixedKnownAndUnknownExitsProvideNoDefault() throws Exception {
		// 9000 LDX $0200 / 9003 BEQ $900b / 9005 LDA #3 / 9007 STA $8000 / 900a RTI / 900b RTI
		handler(0x9000, 0x900b, "ae 00 02 f0 06 a9 03 8d 00 80 40 40");

		assertTrue(defaultFor(0x9000).isEmpty());
	}

	// ------------------------------------------------------------------
	// Pure classification: several fields, per field
	// ------------------------------------------------------------------

	/** A handler may provide one field and conflict on another; only the clean one defaults. */
	@Test
	public void fieldsAreClassifiedIndependently() {
		FieldSpec a = new FieldSpec("a", 0, 2);
		FieldSpec b = new FieldSpec("b", 2, 2);
		Address entry = addr(0x9000);
		// exit 1: a=1 b=2; exit 2: a=1 b=3
		HandlerExits h = new HandlerExits(entry, BankState.unknown(), false,
			List.of(new BankState(0xF, 0x9), new BankState(0xF, 0xD)));

		InterruptExitDefault.Result def = InterruptExitDefault.derive(List.of(h), List.of(a, b));

		assertEquals(0x3, def.knownMask());
		assertEquals(0x1, def.bits());
		assertEquals(0x1 | 0xC, def.apply(0xC | 0x2));
		assertEquals("default: interrupt exit a=1 (" + entry + ")", def.describe(0xF));
		assertNull("an unknown bit outside the defaulted field is not explained by it",
			def.describe(0xC));
	}

	/** A field already known at the handler's entry says nothing about the handler. */
	@Test
	public void aFieldKnownAtEntryIsNeutral() {
		FieldSpec a = new FieldSpec("a", 0, 2);
		HandlerExits h = new HandlerExits(addr(0x9000), new BankState(0x3, 0x2), false,
			List.of(new BankState(0x3, 0x2)));

		assertTrue(InterruptExitDefault.derive(List.of(h), List.of(a)).isEmpty());
	}

	/** Flow the walk could not follow means the exits are not all known. */
	@Test
	public void unresolvedFlowConflicts() {
		FieldSpec a = new FieldSpec("a", 0, 2);
		HandlerExits h = new HandlerExits(addr(0x9000), BankState.unknown(), true,
			List.of(new BankState(0x3, 0x1)));

		assertTrue(InterruptExitDefault.derive(List.of(h), List.of(a)).isEmpty());
	}
}
