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

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Pins bead {@code grm-dos9.4}: a field the caller has set is still known inside the callee.
 * <p>
 * cv3 (MMC5) is the customer. Its RESET sets {@code prg_mode} 2 through {@code $5100}, but the
 * board powers up in mode 3. The engine used to seed EVERY function entry with the power-on
 * state marked fully known, so at each callee the caller's mode 2 merged against a seed that
 * also claimed to know the mode, the two disagreed, and the field went unknown in every
 * function RESET called. Now only real entries are seeded up front; a function entry is seeded
 * with the power-on state only as a fallback, when no reached code calls it.
 * <p>
 * The board here is cv3's shape cut down: a 2-bit {@code mode} field (bits 0-1, power-on 3) and
 * a 4-bit {@code bank} field (bits 2-5, power-on 0), each set by its own memory latch.
 */
public class CallerStateReachesCalleeProgramTest extends AbstractBundledLanguageTest {

	private static final int MODE_MASK = 0x03;
	private static final int BANK_MASK = 0x3C;

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private void put(int addr, String hex) throws Exception {
		builder.setBytes(String.format("0x%x", addr), hex, true);
	}

	private Address addr(int a) {
		return builder.addr(String.format("0x%x", a));
	}

	private void makeFunction(int start, int endInclusive, String name, boolean entryPoint)
			throws Exception {
		int tx = program.startTransaction("create function");
		try {
			program.getFunctionManager().createFunction(name, addr(start),
				new AddressSet(addr(start), addr(endInclusive)), SourceType.ANALYSIS);
		}
		finally {
			program.endTransaction(tx, true);
		}
		if (entryPoint) {
			builder.createEntryPoint(String.format("0x%x", start), name);
		}
	}

	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 3,
				    "mechanisms": [ { "strategy": "memory-latch" }, { "strategy": "memory-latch" } ],
				    "state": [ { "name": "mode", "bits": 2 }, { "name": "bank", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		return board;
	}

	private BankStrategyRegistry.ConfiguredMechanism latch(int start, int widthMask,
			int effectMask, int lsb) {
		JsonObject params = new JsonObject();
		params.addProperty("start", start);
		params.addProperty("end", start);
		params.addProperty("mask", widthMask);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, widthMask);
		return new BankStrategyRegistry.ConfiguredMechanism(strategy, effectMask, lsb);
	}

	private BankDataflowEngine.DataflowResult run() throws Exception {
		BoardDescriptorModel.BoardModel board = board();
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			List.of(latch(0x9000, 0x3, MODE_MASK, 0), latch(0xa000, 0xF, BANK_MASK, 2)), board,
			null, java.util.Map.of());
	}

	/**
	 * <pre>
	 * c000  LDA #$02 / STA $9000   ; mode 2 (power-on is 3)
	 * c005  JSR $c010
	 * c008  RTS
	 * c010  LDA #$05 / STA $a000   ; bank 5 -- the callee's own switch
	 * c015  RTS
	 * </pre>
	 */
	@Test
	public void modeSetByTheCallerIsStillKnownAtTheCalleesSwitch() throws Exception {
		put(0xc000, "a9 02 8d 00 90 20 10 c0 60");
		put(0xc010, "a9 05 8d 00 a0 60");
		makeFunction(0xc000, 0xc008, "RESET", true);
		makeFunction(0xc010, 0xc015, "CALLEE", false);

		BankDataflowEngine.DataflowResult result = run();

		BankState entry = result.stateIn().get(addr(0xc010));
		assertNotNull("the callee must be reached through the call", entry);
		assertEquals("mode must arrive known from the caller, not merged against a power-on seed",
			MODE_MASK, entry.knownMask() & MODE_MASK);
		assertEquals(2, entry.bits() & MODE_MASK);

		BankState atSwitch = result.stateIn().get(addr(0xc012));
		assertEquals(MODE_MASK, atSwitch.knownMask() & MODE_MASK);
		assertEquals(2, atSwitch.bits() & MODE_MASK);
	}

	/**
	 * The fallback: a function no reached code calls still gets the power-on state, so the old
	 * policy's coverage is kept. Here CALLEE has no caller at all.
	 */
	@Test
	public void aFunctionNothingCallsIsStillSeededWithThePowerOnState() throws Exception {
		put(0xc000, "a9 02 8d 00 90 60");
		put(0xc010, "a9 05 8d 00 a0 60");
		makeFunction(0xc000, 0xc005, "RESET", true);
		makeFunction(0xc010, 0xc015, "ORPHAN", false);

		BankDataflowEngine.DataflowResult result = run();

		BankState entry = result.stateIn().get(addr(0xc010));
		assertNotNull("an uncalled function must still be seeded", entry);
		assertEquals(MODE_MASK | BANK_MASK, entry.knownMask() & (MODE_MASK | BANK_MASK));
		assertEquals("power-on: mode 3, bank 0", 3, entry.bits() & (MODE_MASK | BANK_MASK));
	}

	/**
	 * An unreached chain: ORPHAN (no caller) calls INNER. Only ORPHAN is a fallback root; INNER
	 * takes ORPHAN's state through the call, so ORPHAN's mode 1 survives into INNER rather than
	 * meeting a second power-on seed there.
	 */
	@Test
	public void anUnreachedCallChainIsSeededAtItsRootOnly() throws Exception {
		put(0xc000, "60"); // RESET: RTS
		put(0xc010, "a9 01 8d 00 90 20 20 c0 60"); // ORPHAN: mode 1, JSR INNER
		put(0xc020, "a9 05 8d 00 a0 60"); // INNER: bank 5
		makeFunction(0xc000, 0xc000, "RESET", true);
		makeFunction(0xc010, 0xc018, "ORPHAN", false);
		makeFunction(0xc020, 0xc025, "INNER", false);

		BankDataflowEngine.DataflowResult result = run();

		BankState inner = result.stateIn().get(addr(0xc020));
		assertNotNull(inner);
		assertEquals(MODE_MASK, inner.knownMask() & MODE_MASK);
		assertEquals(1, inner.bits() & MODE_MASK);
	}
}
