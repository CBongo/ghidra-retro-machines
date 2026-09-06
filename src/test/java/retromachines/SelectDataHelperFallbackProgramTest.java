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

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;

import retromachines.BankSwitchStrategy.HelperDeposit;

/**
 * Pins {@link SelectDataBankSwitchStrategy}'s {@code depositHelperArgument} env-taking override
 * (bead grm-4bgh increment 4) -- the mini-inline FALLBACK this strategy previously lacked, which
 * gave {@link MemoryLatchBankSwitchStrategy} its own answer to a helper that TRANSFORMS or
 * clobbers its argument register rather than merely relaying it (grm-hum increment 2), but never
 * to a select-data (MMC3-shaped) mechanism.
 * <p>
 * Both tests call the env-taking override directly, mirroring
 * {@code MemoryLatchStrategyProgramTest}'s {@code envAt}-based tests: the fixture is a bare
 * data-write instruction whose helper has NO prologue at all (its entry coincides with the
 * switch site), so {@link StoredValueScanner}'s backward scan for the stored register meets the
 * {@link RegisterEnv} stop on its very first check and adopts the caller's register value
 * directly -- the simplest fixture that exercises the fallback without needing a real
 * multi-instruction prologue.
 */
public class SelectDataHelperFallbackProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/**
	 * A select/data pair over {@code $9000-$9FFF} with one tracked target: select value 1 routes
	 * a data write to field {@code r}. {@code select} occupies field-local bits {@code [0,4)},
	 * {@code r} occupies {@code [4,8)} -- disjoint, so packing one {@link BankState} with both is
	 * unambiguous.
	 */
	private SelectDataBankSwitchStrategy strategy() {
		JsonObject fieldLayout = new JsonObject();
		JsonObject selectLayout = new JsonObject();
		selectLayout.addProperty("lsb", 0);
		selectLayout.addProperty("width", 4);
		fieldLayout.add("select", selectLayout);
		JsonObject rLayout = new JsonObject();
		rLayout.addProperty("lsb", 4);
		rLayout.addProperty("width", 4);
		fieldLayout.add("r", rLayout);

		JsonObject targets = new JsonObject();
		targets.addProperty("1", "r");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.add("targets", targets);
		params.add("_field_layout", fieldLayout);

		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, 0xFF);
		return strategy;
	}

	/** {@code select} known as 1 (the tracked target), {@code r} left unknown. */
	private BankState selectKnownAsOne() {
		return new BankState(0x0F, 0x01);
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/**
	 * <b>The headline case.</b> {@code argValue} arrives wholly unknown -- the shape
	 * {@code HelperArgumentRecovery} produces for a helper whose prologue transforms or clobbers
	 * its argument register -- but the data write's OWN stored register (A, here) is derivable
	 * under the caller's {@link RegisterEnv} because the helper has no prologue standing between
	 * its entry and the switch site: {@link StoredValueScanner}'s backward scan meets the env's
	 * entry stop immediately and adopts the caller's A. The deposit must now carry that value in
	 * field {@code r}, where {@code select == 1} routes it.
	 */
	@Test
	public void unresolvedArgValueFallsBackToEnvEvaluation() throws Exception {
		builder.setBytes("0x9101", "8d 01 90", true); // STA $9001 <- entry == switchSite, odd = data write

		Instruction switchSite = instructionAt("0x9101");
		RegisterEnv callerRegs = new RegisterEnv(builder.addr("0x9101"),
			BankState.fullyKnown(0xFF, 0x2A), BankState.unknown(), BankState.unknown());

		HelperDeposit deposit = strategy().depositHelperArgument(program, switchSite,
			BankState.unknown(), selectKnownAsOne(), 0xFF, callerRegs);

		assertEquals("only the routed target field r is owned", 0xF0, deposit.ownedMask());
		assertEquals("r's 4 bits are fully resolved via the caller's A", 0xF0,
			deposit.value().knownMask() & 0xF0);
		assertEquals("$2A's low nibble (0xA) lands in r, field-local at bit 4", 0xA0,
			deposit.value().bits() & 0xF0);
	}

	/**
	 * <b>The non-substitution guarantee.</b> When {@code argValue} already resolves, the
	 * env-taking override must be byte-identical to the plain 5-arg deposit -- the fallback is
	 * additive, never a replacement, so a call site that already worked today is untouched. The
	 * caller's A is seeded with a WRONG, fully-confident, DIFFERENT value on purpose: if the
	 * override ever started preferring evaluation over a resolved {@code argValue}, this would
	 * catch it immediately.
	 */
	@Test
	public void resolvedArgValueIsUnaffectedByCallerRegs() throws Exception {
		builder.setBytes("0x9101", "8d 01 90", true); // STA $9001 <- entry == switchSite, odd = data write

		Instruction switchSite = instructionAt("0x9101");
		BankState argValue = BankState.fullyKnown(0xFF, 0x33);
		BankState inState = selectKnownAsOne();
		RegisterEnv misleadingCallerRegs = new RegisterEnv(builder.addr("0x9101"),
			BankState.fullyKnown(0xFF, 0x99), BankState.unknown(), BankState.unknown());

		SelectDataBankSwitchStrategy strategy = strategy();
		HelperDeposit viaEnv = strategy.depositHelperArgument(program, switchSite, argValue,
			inState, 0xFF, misleadingCallerRegs);
		HelperDeposit viaPlain =
			strategy.depositHelperArgument(program, switchSite, argValue, inState, 0xFF);

		assertEquals("a resolved argValue must not be overridden by callerRegs", viaPlain, viaEnv);
		assertEquals("r takes argValue's 0x33 low nibble (0x3), not A's 0x99", 0x30,
			viaEnv.value().bits() & 0xF0);
	}
}
