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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import retromachines.BankSwitchStrategy.SwitchOutcome;
import retromachines.BankSwitchStrategy.ValueStop;

/**
 * Pins {@link ValueStop#NO_DEPOSIT} at the site shapes that deposit nothing BY DESIGN (bead
 * grm-pdd6), across both strategies that have such sites.
 * <p>
 * The bug this guards against is a classification one, not a value one: these sites echo
 * {@code inState} verbatim, so before this reason existed they arrived at
 * {@link BankAnnotationAdapter#annotateOrWarn} indistinguishable from a site whose value
 * recovery had been attempted and had failed -- and were bookmarked with that method's
 * "mechanism write with a genuinely undeterminable value" WARNING. Measured on megaman2: the
 * four warnings at {@code c024/c028/c02c/c030} are the first four links of the very chain that
 * RESOLVES {@code prg_bank=12} at {@code c034}.
 * <p>
 * Every assertion below is on {@link SwitchOutcome#stop()}, and each is paired with an assertion
 * that the VALUE is still the echo -- because the fix must not change what flows, only what is
 * said about it. A test that only checked the stop reason would pass just as happily if the echo
 * had been replaced by a poison.
 */
public class NoDepositSiteProgramTest extends AbstractBundledLanguageTest {

	/** mirroring(2) | prg_mode(2) | prg_bank(5), matching machines/nes-mmc1.yaml. */
	private static final int MMC1_STATE_MASK = 0x1FF;
	/** CHR0 target's address (bits 14:13 = 1) -- unconfigured in {@link #mmc1()}. */
	private static final int CHR0_OFFSET = 0xA000;
	/** PRG target's address (bits 14:13 = 3). */
	private static final int PRG_OFFSET = 0xE000;

	/** select(3) | prg0(6) | prg1(6), a stripped MMC3-shaped packing. */
	private static final int MMC3_STATE_MASK = 0x7FFF;

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	// ------------------------------------------------------------------
	// Scaffolding -- the descriptor shapes, copied in spirit from
	// SerialShiftMirrorConsumptionProgramTest
	// ------------------------------------------------------------------

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

	/** The real MMC1 mechanism, CHR0/CHR1 deliberately unconfigured as the shipped descriptor
	 *  leaves them. */
	private SerialShiftBankSwitchStrategy mmc1() {
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
		strategy.configure(program, params, MMC1_STATE_MASK);
		return strategy;
	}

	/**
	 * An MMC3-shaped select/data pair over {@code $8000-$9FFF}: select values 6 and 7 map to
	 * {@code prg0}/{@code prg1}, and 0-5 (the CHR registers R0-R5) are deliberately untracked
	 * -- the no-poison contract in that strategy's class javadoc, and the select-data half of
	 * this bead.
	 */
	private SelectDataBankSwitchStrategy mmc3() {
		JsonObject layout = new JsonObject();
		layout.add("select", pos(0, 3));
		layout.add("prg0", pos(3, 6));
		layout.add("prg1", pos(9, 6));

		JsonObject targets = new JsonObject();
		targets.addProperty("6", "prg0");
		targets.addProperty("7", "prg1");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.addProperty("select_mask", 0x07);
		params.add("_field_layout", layout);
		params.add("targets", targets);

		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, MMC3_STATE_MASK);
		return strategy;
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private static String hex(long addr) {
		return String.format("0x%x", addr);
	}

	private static String staAbs(int offset) {
		return String.format("8d %02x %02x", offset & 0xFF, (offset >>> 8) & 0xFF);
	}

	/** Writes 1..5's addresses of a built chain, indexed from zero. */
	private String[] buildChain(long startAddr, String preInstrBytes, int writeOffset)
			throws Exception {
		long addr = startAddr;
		builder.setBytes(hex(addr), preInstrBytes, true);
		addr += preInstrBytes.split(" ").length;

		String[] writes = new String[5];
		for (int i = 0; i < 5; i++) {
			if (i > 0) {
				builder.setBytes(hex(addr), "4a", true); // LSR A
				addr += 1;
			}
			writes[i] = hex(addr);
			builder.setBytes(writes[i], staAbs(writeOffset), true);
			addr += 3;
		}
		return writes;
	}

	private SwitchOutcome outcomeAt(BankSwitchStrategy strategy, String address,
			BankState inState) {
		SwitchOutcome outcome =
			strategy.computeSwitchOutcome(program, instructionAt(address), inState);
		assertNotNull("fixture produced no mechanism write at " + address +
			" -- no write reference? the test would prove nothing", outcome);
		return outcome;
	}

	private static void assertEcho(BankState inState, SwitchOutcome outcome) {
		assertEquals("a NO_DEPOSIT site must echo the in-state's known bits: " + outcome,
			inState.knownMask(), outcome.value().knownMask());
		assertEquals("a NO_DEPOSIT site must echo the in-state's values: " + outcome,
			inState.bits(), outcome.value().bits());
	}

	// ------------------------------------------------------------------
	// 1. Serial shift: a chain's writes 1-4 deposit nothing; write 5 commits
	// ------------------------------------------------------------------

	/**
	 * megaman2's shape exactly: five writes, and the first four are the ones that were being
	 * reported as undeterminable values. {@code LDA #$0C} makes write 5's commit RESOLVED, so
	 * this also shows the two classifications coexisting in ONE chain -- which is the whole
	 * point, since a fix that classified the whole chain NO_DEPOSIT would lose the bank.
	 */
	@Test
	public void chainWritesOneThroughFourDepositNothingAndTheFifthCommits() throws Exception {
		String[] writes = buildChain(0x9000, "a9 0c", PRG_OFFSET); // LDA #$0C
		SerialShiftBankSwitchStrategy mmc1 = mmc1();
		BankState in = BankState.fullyKnown(MMC1_STATE_MASK, 0);

		for (int i = 0; i < 4; i++) {
			SwitchOutcome outcome = outcomeAt(mmc1, writes[i], in);
			assertEquals("chain write " + (i + 1) + " deposits nothing by design",
				ValueStop.NO_DEPOSIT, outcome.stop());
			assertEcho(in, outcome);
		}

		SwitchOutcome commit = outcomeAt(mmc1, writes[4], in);
		assertEquals("write 5 is where the chain actually commits", ValueStop.RESOLVED,
			commit.stop());
	}

	/**
	 * The echo must be classified NO_DEPOSIT even from an all-unknown in-state, which is the
	 * state grm-913 left these sites in and therefore the case that actually fires on a real
	 * ROM. This is the assertion that would have failed before the fix: {@code knownMask() == 0}
	 * is exactly what routed the site to the WARNING.
	 */
	@Test
	public void chainWriteFromAnUnknownInStateIsStillNoDeposit() throws Exception {
		String[] writes = buildChain(0x9100, "a9 0c", PRG_OFFSET);
		SwitchOutcome outcome = outcomeAt(mmc1(), writes[1], BankState.unknown());
		assertEquals("an echo of an unknown state is still not a failed recovery",
			ValueStop.NO_DEPOSIT, outcome.stop());
		assertEquals("nothing may be deposited here", 0, outcome.value().knownMask());
	}

	/**
	 * A write to an UNCONFIGURED target (MMC1 CHR0): recognized, deliberately discarded. The
	 * commit position of a valid chain, so the only thing distinguishing it from the case above
	 * is which target the five writes land on.
	 */
	@Test
	public void writeToAnUnconfiguredTargetDepositsNothing() throws Exception {
		String[] writes = buildChain(0x9200, "a9 0c", CHR0_OFFSET);
		BankState in = BankState.fullyKnown(MMC1_STATE_MASK, 0);
		SwitchOutcome outcome = outcomeAt(mmc1(), writes[4], in);
		assertEquals("an un-configured target is discarded, not un-recovered",
			ValueStop.NO_DEPOSIT, outcome.stop());
		assertEcho(in, outcome);
	}

	// ------------------------------------------------------------------
	// 2. Select-data: a data write to an untracked select target
	// ------------------------------------------------------------------

	/**
	 * Select 2 (an MMC3 CHR register) then a data write: the strategy recognizes the write and
	 * chooses not to represent it, so nothing is deposited and nothing was attempted. Real
	 * games issue these every frame, which is why this shape is a candidate for a large share
	 * of the MMC3 rows' warning census (grm-nqxt).
	 */
	@Test
	public void dataWriteToAnUntrackedSelectTargetDepositsNothing() throws Exception {
		builder.setBytes("0x9300", "8d 01 80", true); // STA $8001 -- the data port
		SelectDataBankSwitchStrategy mmc3 = mmc3();
		// select=2 (CHR R2), every field known so the echo is visible as knowledge preserved.
		BankState in = BankState.fullyKnown(MMC3_STATE_MASK, 2);

		SwitchOutcome outcome = outcomeAt(mmc3, "0x9300", in);
		assertEquals("an untracked select target is discarded, not un-recovered",
			ValueStop.NO_DEPOSIT, outcome.stop());
		assertEcho(in, outcome);
	}

	/**
	 * The contrasting case, so the test above cannot pass by the strategy having gone uniformly
	 * quiet: select 6 IS a tracked target, so the same data write is a real deposit and must NOT
	 * be NO_DEPOSIT.
	 */
	@Test
	public void dataWriteToATrackedSelectTargetIsStillADeposit() throws Exception {
		builder.setBytes("0x9400", "a9 05", true); // LDA #$05
		builder.setBytes("0x9402", "8d 01 80", true); // STA $8001
		BankState in = BankState.fullyKnown(MMC3_STATE_MASK, 6);

		SwitchOutcome outcome = outcomeAt(mmc3(), "0x9402", in);
		assertEquals("a tracked target's data write deposits a bank", ValueStop.RESOLVED,
			outcome.stop());
	}
}
