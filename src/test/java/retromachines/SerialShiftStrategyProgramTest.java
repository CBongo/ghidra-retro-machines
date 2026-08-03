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

/**
 * Pins {@link SerialShiftBankSwitchStrategy}'s handling of a read-modify-write into the MMC1
 * shift-register range (bead grm-4kc) -- the self-modifying reset idiom, which used to poison
 * the whole mechanism at the one instruction whose value is most determinable.
 * <p>
 * This is the first JUnit coverage this strategy has had; before it, serial-shift was exercised
 * only by the headless {@code nesserialtest}/{@code nesmmc1test} fixtures.
 * <p>
 * <b>Fixture technique.</b> The idiom needs an instruction that writes a byte inside its own
 * encoding, with a CHOSEN value. Pointing an {@code INC} at its own address always reads the
 * opcode {@code $EE} (that is bionic's real case, and it is tested), so to reach other bytes the
 * tests point the instruction at its own OPERAND-LOW byte and pick the address so that byte is
 * the value under test: {@code INC $80FF} placed at {@code $80FE} encodes {@code EE FF 80}, so
 * the byte it reads at {@code $80FF} is {@code $FF}. That is how Bill &amp; Ted's and
 * Shinsenden's documented cases are reproduced exactly.
 * <p>
 * Every case runs against an in-state where all three fields are KNOWN, so a poison is visible
 * as knowledge being destroyed rather than merely absent.
 */
public class SerialShiftStrategyProgramTest extends AbstractBundledLanguageTest {

	/** mirroring(2) | prg_mode(2) | prg_bank(5), matching machines/nes-mmc1.yaml. */
	private static final int STATE_MASK = 0x1FF;
	private static final int PRG_MODE_MASK = 0x0C;
	private static final int PRG_MODE_3 = 3 << 2;

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
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

	/** The real MMC1 mechanism: whole-range serial port, Control + PRG targets, bit-7 reset. */
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
		strategy.configure(program, params, STATE_MASK);
		return strategy;
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/** Everything known and zero, so a poison shows up as knowledge destroyed. */
	private static BankState allKnownZero() {
		return BankState.fullyKnown(STATE_MASK, 0);
	}

	/**
	 * Runs the strategy over the instruction at {@code address} and asserts it was recognized
	 * as a mechanism write at all -- if it was not, the fixture failed to produce a write
	 * reference and the test would otherwise pass vacuously.
	 */
	private BankState switchAt(String address) {
		BankState result = mmc1().computeSwitch(program, instructionAt(address), allKnownZero());
		assertNotNull("fixture produced no mechanism write at " + address +
			" -- no write reference? the test would prove nothing", result);
		return result;
	}

	private void assertReset(BankState result) {
		assertEquals("prg_mode should be fully known after a reset: " + result, PRG_MODE_MASK,
			result.knownMask() & PRG_MODE_MASK);
		assertEquals("reset must deposit prg_mode=3: " + result, PRG_MODE_3,
			result.bits() & PRG_MODE_MASK);
	}

	private void assertPoisoned(BankState result) {
		assertEquals("every tracked field should have been poisoned: " + result, 0,
			result.knownMask());
	}

	// ------------------------------------------------------------------
	// Tier A -- the first bus write is the unmodified byte, whatever the op
	// ------------------------------------------------------------------

	/**
	 * Bionic Commando's actual RESET, byte for byte: {@code $FFE1: EE E1 FF  INC $FFE1}, an
	 * INC on its own opcode. Here at {@code $8010} so the encoding is identical in shape.
	 * {@code $EE} has bit 7 set, so it resets the shifter and forces prg_mode=3.
	 */
	@Test
	public void incOnItsOwnOpcodeIsAReset() throws Exception {
		builder.setBytes("0x8010", "ee 10 80", true); // INC $8010 -- reads its own $EE

		assertReset(switchAt("0x8010"));
	}

	/**
	 * Bill &amp; Ted's Excellent Adventure: INC on a location holding {@code $FF}, so the two
	 * bus writes are {@code $FF} then {@code $00} -- bit 7 set, then clear. The wiki says the
	 * second write is ignored for data and that a bit-7 reset is never ignored, so this IS a
	 * reset. It is the case that proves the rule must be an OR: requiring bit 7 in BOTH writes
	 * would decline a reset a real game depends on.
	 */
	@Test
	public void incOnAnFfByteIsAResetEvenThoughTheSecondWriteIsZero() throws Exception {
		builder.setBytes("0x80fe", "ee ff 80", true); // INC $80FF -- reads its own operand $FF

		assertReset(switchAt("0x80fe"));
	}

	/**
	 * Tier A asks nothing about the operation, which is the whole point: a bit-7-set first
	 * write resets whatever the instruction does with the value afterwards. {@code LSR} can
	 * never SET bit 7, so under a result-only rule this would be declined.
	 */
	@Test
	public void lsrOnAByteWithBit7SetIsStillAReset() throws Exception {
		builder.setBytes("0x80fe", "4e ff 80", true); // LSR $80FF -- reads its own operand $FF

		assertReset(switchAt("0x80fe"));
	}

	// ------------------------------------------------------------------
	// Tier B -- bit 7 arrives on the second write (INC/DEC only)
	// ------------------------------------------------------------------

	/** Shinsenden's direction: clear then set. {@code $7F + 1 = $80}, so the second write resets. */
	@Test
	public void incThatCarriesIntoBit7IsAReset() throws Exception {
		builder.setBytes("0x807e", "ee 7f 80", true); // INC $807F -- reads its own operand $7F

		assertReset(switchAt("0x807e"));
	}

	/** {@code DEC $00 = $FF}: the other way to set bit 7 on the second write. */
	@Test
	public void decThatBorrowsIntoBit7IsAReset() throws Exception {
		builder.setBytes("0x80ff", "ce 00 81", true); // DEC $8100 -- reads its own operand $00

		assertReset(switchAt("0x80ff"));
	}

	/** Neither write sets bit 7: a data write whose shifted contribution cannot be attributed. */
	@Test
	public void incWithBit7ClearInBothWritesPoisons() throws Exception {
		builder.setBytes("0x807d", "ee 7e 80", true); // INC $807E -- reads its own operand $7E

		assertPoisoned(switchAt("0x807d"));
	}

	// ------------------------------------------------------------------
	// Deliberately not modeled -- pinned so adding them is a conscious act
	// ------------------------------------------------------------------

	/**
	 * {@code ASL $7F = $FE}, so the true answer is "reset" -- but no surveyed game spells the
	 * reset with a shift, and the fallback already raises a WARNING bookmark, so an instance
	 * would surface rather than hide. This test exists so that adding {@code ASL}/{@code ROL}
	 * later is a deliberate change with a failing assertion to flip, not an accident.
	 */
	@Test
	public void aslThatWouldCarryBit6IntoBit7IsNotModeled() throws Exception {
		builder.setBytes("0x807e", "0e 7f 80", true); // ASL $807F -- reads its own operand $7F

		assertPoisoned(switchAt("0x807e"));
	}

	/** {@code ROR} puts the CARRY in bit 7, which is genuinely underivable here. */
	@Test
	public void rorWithBit7ClearIsNotModeled() throws Exception {
		builder.setBytes("0x807e", "6e 7f 80", true); // ROR $807F -- reads its own operand $7F

		assertPoisoned(switchAt("0x807e"));
	}

	/**
	 * A read-modify-write whose target is NOT inside its own encoding. The byte would have to
	 * come from memory, and on an MMC1 board every address is shadowed by the 32K-mode
	 * overlays -- so this stays declined (see grm-4kc's deferred tier).
	 */
	@Test
	public void rmwOnAnUnrelatedAddressStillPoisons() throws Exception {
		builder.setBytes("0x8010", "ee 00 90", true); // INC $9000 -- not self-referential

		assertPoisoned(switchAt("0x8010"));
	}

	// ------------------------------------------------------------------
	// The ordinary path must not regress
	// ------------------------------------------------------------------

	/** The STA spelling of the same reset (Zelda/Metroid's quad-reset) is untouched. */
	@Test
	public void plainBit7StoreIsStillAReset() throws Exception {
		builder.setBytes("0x8000", "a9 80", true); // LDA #$80
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000

		assertReset(switchAt("0x8002"));
	}

	/** A bit-7-clear store that is not part of a 5-write chain still poisons. */
	@Test
	public void isolatedBit7ClearStoreStillPoisons() throws Exception {
		builder.setBytes("0x8000", "a9 02", true); // LDA #$02
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000

		assertPoisoned(switchAt("0x8002"));
	}
}
