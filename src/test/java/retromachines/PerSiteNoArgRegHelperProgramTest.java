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
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

import retromachines.BankDataflowEngine.ArgumentSought;
import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins two behaviours added by bead grm-fekc.
 * <p>
 * <b>1. Per-site recovery without an argument register</b>
 * ({@code HelperModel.recoversPerSiteWithoutArgReg} /
 * {@code HelperArgumentRecovery.recoverPerSiteWithoutArgReg}). A select-data helper whose sites
 * store from DIFFERENT registers leaves {@code argReg} null, which used to short-circuit recovery.
 * The motivating shape is tmnt3's {@code FUN_8705}:
 * <pre>
 *   LDY #$47 / STY $8000 (select R7) / STA $8001 (R7 = A) / DEY / CLC / ADC #$01 /
 *   STY $8000 (select R6) / STA $8001 (R6 = A+1) / RTS
 * </pre>
 * Each site is now re-derived under the caller's registers instead.
 * <p>
 * <b>2. Fold order</b> ({@code HelperArgumentRecovery.foldDeposits}). The {@code primary} deposit
 * (the max-address {@code switchSite}) is folded at its own address-order position rather than
 * used as the seed, so a LATER site wins over an earlier one on a shared field. The motivating
 * shape is rcransom's {@code FUN_ff29}: {@code LDA #$07 / STA $8000} ... {@code LDA $fb /
 * STA $8000} -- the folded select must be UNKNOWN, not the stale 7.
 */
public class PerSiteNoArgRegHelperProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/** Same select/data configuration as {@code MultiDepositHelperProgramTest}. */
	private SelectDataBankSwitchStrategy strategy() {
		JsonObject fieldLayout = new JsonObject();
		JsonObject selectLayout = new JsonObject();
		selectLayout.addProperty("lsb", 0);
		selectLayout.addProperty("width", 4);
		fieldLayout.add("select", selectLayout);
		JsonObject r6Layout = new JsonObject();
		r6Layout.addProperty("lsb", 4);
		r6Layout.addProperty("width", 4);
		fieldLayout.add("r6", r6Layout);
		JsonObject r7Layout = new JsonObject();
		r7Layout.addProperty("lsb", 8);
		r7Layout.addProperty("width", 4);
		fieldLayout.add("r7", r7Layout);

		JsonObject targets = new JsonObject();
		targets.addProperty("6", "r6");
		targets.addProperty("7", "r7");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.add("targets", targets);
		params.add("_field_layout", fieldLayout);

		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, 0xFFF);
		return strategy;
	}

	private static final int SELECT_MASK = 0x00F;
	private static final int R6_MASK = 0x0F0;
	private static final int R7_MASK = 0xF00;

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/** argReg = null, all sites listed, switchSite = max site, firstSite = min site. */
	private HelperModel nullArgRegModel(BankSwitchStrategy strategy, String... sites) {
		List<Address> addrs = new ArrayList<>();
		for (String s : sites) {
			addrs.add(builder.addr(s));
		}
		return new HelperModel(null, builder.addr("0x9100"), null, null, 0xFFF, 0, strategy,
			addrs.get(addrs.size() - 1), addrs.get(0), null, addrs);
	}

	private CallEffect recover(HelperModel helper) throws Exception {
		Instruction callInstr = instructionAt("0x8002");
		return HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.unknown(), new HashMap<>(), new HashSet<>());
	}

	/** Caller: LDA #$05 / JSR $9100. */
	private void buildCaller() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "20 00 91", true); // JSR $9100
	}

	/** The FUN_8705 shape. Sites: $9102, $9105, $910c, $910f. */
	private HelperModel buildFun8705() throws Exception {
		buildCaller();
		builder.setBytes("0x9100", "a0 47", true); // LDY #$47
		builder.setBytes("0x9102", "8c 00 90", true); // STY $9000   select R7
		builder.setBytes("0x9105", "8d 01 90", true); // STA $9001   R7 = A
		builder.setBytes("0x9108", "88", true); // DEY
		builder.setBytes("0x9109", "18", true); // CLC
		builder.setBytes("0x910a", "69 01", true); // ADC #$01
		builder.setBytes("0x910c", "8c 00 90", true); // STY $9000   select R6
		builder.setBytes("0x910f", "8d 01 90", true); // STA $9001   R6 = A+1
		builder.setBytes("0x9112", "60", true); // RTS
		return nullArgRegModel(strategy(), "0x9102", "0x9105", "0x910c", "0x910f");
	}

	// ------------------------------------------------------------------
	// a. recoversPerSiteWithoutArgReg predicate
	// ------------------------------------------------------------------

	@Test
	public void predicateRequiresNullArgRegStrategyAndSwitchSite() throws Exception {
		HelperModel perSite = buildFun8705();
		assertTrue(perSite.recoversPerSiteWithoutArgReg());

		HelperModel noStrategy = new HelperModel(null, builder.addr("0x9100"), null, null, 0xFFF,
			0, null, builder.addr("0x910f"), builder.addr("0x9102"), null, null);
		assertFalse("a null strategy (union / tail-composed model) stays excluded",
			noStrategy.recoversPerSiteWithoutArgReg());

		HelperModel withArgReg = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFFF,
			0, strategy(), builder.addr("0x910f"), builder.addr("0x9102"), null, null);
		assertFalse("a model with an argReg takes the ordinary register path",
			withArgReg.recoversPerSiteWithoutArgReg());
	}

	// ------------------------------------------------------------------
	// b. FUN_8705 end to end
	// ------------------------------------------------------------------

	@Test
	public void fun8705ShapeRecoversPerSiteUnderCallerRegisters() throws Exception {
		HelperModel helper = buildFun8705();
		CallEffect result = recover(helper);
		assertEquals(SELECT_MASK | R6_MASK | R7_MASK, result.ownedMask());
		assertTrue(result.argumentResolved());
		assertEquals(R7_MASK, result.state().knownMask() & R7_MASK);
		assertEquals(0x500, result.state().bits() & R7_MASK);
		assertEquals(R6_MASK, result.state().knownMask() & R6_MASK);
		assertEquals(0x060, result.state().bits() & R6_MASK);
	}

	// ------------------------------------------------------------------
	// c. Fold order: later site wins
	// ------------------------------------------------------------------

	@Test
	public void laterUnresolvableSelectWinsOverEarlierConstant() throws Exception {
		buildCaller();
		builder.setBytes("0x9100", "a9 07", true); // LDA #$07
		builder.setBytes("0x9102", "8d 00 90", true); // STA $9000   select 7
		builder.setBytes("0x9105", "a5 fb", true); // LDA $fb     unknown RAM byte
		builder.setBytes("0x9107", "8d 00 90", true); // STA $9000   select = ?
		builder.setBytes("0x910a", "60", true); // RTS
		HelperModel helper = nullArgRegModel(strategy(), "0x9102", "0x9107");
		assertTrue(helper.recoversPerSiteWithoutArgReg());

		CallEffect result = recover(helper);
		assertEquals("select is still owned by the call", SELECT_MASK,
			result.ownedMask() & SELECT_MASK);
		assertEquals("the later unknown write wins -- the stale 7 must not survive", 0,
			result.state().knownMask() & SELECT_MASK);
	}

	// ------------------------------------------------------------------
	// d. ArgumentSought
	// ------------------------------------------------------------------

	@Test
	public void argumentSoughtIsSoughtForPerSiteModel() throws Exception {
		HelperModel helper = buildFun8705();
		assertEquals(ArgumentSought.SOUGHT, ArgumentSought.of(helper));

		HelperModel noStrategy = new HelperModel(null, builder.addr("0x9100"), null, null, 0xFFF,
			0, null, builder.addr("0x910f"), builder.addr("0x9102"), null, null);
		assertEquals(ArgumentSought.NO_ARGUMENT_REGISTER, ArgumentSought.of(noStrategy));
	}
}
