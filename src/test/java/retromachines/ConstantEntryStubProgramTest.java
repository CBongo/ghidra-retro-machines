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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import retromachines.BankDataflowEngine.SwitchResult;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins {@code HelperDiscovery.findConstantEntryStubs} (bead grm-bbe7): the Punch-Out!! shape of
 * a bank-switch helper with several immediate-entry stubs that branch into its shared write.
 * <pre>
 *   A010  LDA $02        ; the helper's own entry (bank from a shadow)
 *   A012  STA $9FFF      ; the shared mechanism write (the only recognized site)
 *   A015  STA $0D / RTS
 *   A020  LDA #$07 / BNE A012      ; one-hop stub: bank 7
 *   A030  LDA #$0C / BNE A036      ; two-hop stub through a shared tail: bank 12
 *   A036  STA $0E / BNE A012
 * </pre>
 * Driven directly against a hand-built helper map, like {@link TailCallCompositionProgramTest}:
 * the end-to-end half is the {@code punchout} real-ROM row. Every decline test has an
 * anti-vacuity partner that ADMITS against an otherwise identical fixture.
 */
public class ConstantEntryStubProgramTest extends AbstractProgramTest {

	private static final long HELPER = 0xA010;
	private static final long SITE = 0xA012;

	private MemoryLatchBankSwitchStrategy strategy;
	private Map<Address, SwitchResult> switchResults;
	private Map<Function, HelperModel> helpers;
	private Function helper;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("mask", 0x0F);
		strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0x0F);

		put(HELPER, "a5 02"); // LDA $02
		put(SITE, "8d ff 9f"); // STA $9FFF   <- the shared mechanism write
		put(0xA015, "85 0d 60"); // STA $0D / RTS
		helper = builder.createEmptyFunction("FUN_a010", hex(HELPER), 8, null);

		Address site = addr(SITE);
		switchResults = Map.of(site, new SwitchResult(BankState.unknown(), 0x0F, 0, strategy,
			BankSwitchStrategy.ValueStop.ANALYZER_LIMIT));
		helpers = Map.of(helper, new HelperModel(helper, helper.getEntryPoint(), null, 'A', 0x0F,
			0, strategy, site, site, null, List.of(site)));
	}

	private Function stub(String name, long at, int size) throws Exception {
		return builder.createEmptyFunction(name, hex(at), size, null);
	}

	private Map<Function, HelperModel> find() {
		return HelperDiscovery.findConstantEntryStubs(program, helpers, switchResults);
	}

	private void assertAdmits(Map<Function, HelperModel> found, Function stub, int bank) {
		HelperModel model = found.get(stub);
		assertNotNull(stub.getName() + " was not admitted", model);
		assertEquals(BankState.fullyKnown(0x0F, bank), model.constState());
		assertEquals(0x0F, model.effectMask());
	}

	/** One hop: an immediate load and a branch it decides, landing on the shared write. */
	@Test
	public void aOneHopStubResolvesToItsImmediate() throws Exception {
		put(0xA020, "a9 07 d0 ee"); // LDA #$07 / BNE A012
		Function s = stub("FUN_a020", 0xA020, 4);

		assertAdmits(find(), s, 7);
	}

	/**
	 * Two hops through a shared tail: the second branch is NOT decidable from the instruction
	 * before it (a store sits between the load and the branch, and the tail is a join), but the
	 * walk follows one concrete path, so the load's flags still decide it.
	 */
	@Test
	public void aTwoHopStubThroughASharedTailResolves() throws Exception {
		put(0xA030, "a9 0c d0 02"); // LDA #$0C / BNE A036
		put(0xA034, "ea ea"); // dead fall-through filler
		put(0xA036, "85 0e d0 d8"); // STA $0E / BNE A012
		Function s = stub("FUN_a030", 0xA030, 4);
		stub("FUN_a036", 0xA036, 4);

		assertAdmits(find(), s, 12);
	}

	/** The helper's own entry loads from RAM, so it is not a stub and is not re-admitted. */
	@Test
	public void theHelperItselfIsNotAStub() throws Exception {
		assertSame(helpers.get(helper), find().get(helper));
	}

	/** A branch whose flag the walk cannot decide declines. */
	@Test
	public void anUndecidableBranchDeclines() throws Exception {
		put(0xA020, "a5 03 d0 ee"); // LDA $03 / BNE A012  -- A unknown, Z unknown
		Function s = stub("FUN_a020", 0xA020, 4);

		assertFalse(find().containsKey(s));
	}

	/** A branch the immediate decides NOT taken falls through to RTS: no landing, decline. */
	@Test
	public void aBranchDecidedNotTakenDoesNotLand() throws Exception {
		put(0xA020, "a9 00 d0 ee"); // LDA #$00 / BNE A012 -- Z set, never taken
		put(0xA024, "60"); // RTS
		Function s = stub("FUN_a020", 0xA020, 5);

		assertFalse(find().containsKey(s));
	}

	/** A call on the path may change anything: decline. */
	@Test
	public void aCallOnThePathDeclines() throws Exception {
		put(0xA020, "a9 07 20 00 a1 d0 e9"); // LDA #$07 / JSR $A100 / BNE A012
		Function s = stub("FUN_a020", 0xA020, 7);

		assertFalse(find().containsKey(s));
	}

	/** The constant is in X but the helper's mechanism write stores A: nothing to resolve. */
	@Test
	public void aConstantInTheWrongRegisterDeclines() throws Exception {
		put(0xA020, "a2 07 d0 ee"); // LDX #$07 / BNE A012
		Function s = stub("FUN_a020", 0xA020, 4);

		assertFalse(find().containsKey(s));
	}

	/** Anti-vacuity: the fixture of the decline tests above admits once the register is right. */
	@Test
	public void theWrongRegisterFixtureAdmitsWithTheRightRegister() throws Exception {
		put(0xA020, "a9 07 d0 ee"); // LDA #$07 / BNE A012
		Function s = stub("FUN_a020", 0xA020, 4);

		assertTrue(find().containsKey(s));
	}

	/** A stub that lands on something that is not a recognized write declines. */
	@Test
	public void aBranchIntoNonMechanismCodeDeclines() throws Exception {
		put(0xA020, "a9 07 d0 0a"); // LDA #$07 / BNE A02E
		put(0xA02E, "ea 60"); // NOP / RTS
		Function s = stub("FUN_a020", 0xA020, 4);
		stub("FUN_a02e", 0xA02E, 2);

		assertFalse(find().containsKey(s));
	}
}
