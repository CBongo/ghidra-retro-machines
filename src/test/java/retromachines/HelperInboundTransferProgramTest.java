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
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.mem.MemoryBlock;

import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins bead grm-hsv.15: a bank-switch helper whose argument arrives in one register and reaches
 * the mechanism through ANOTHER, by a transfer and a scratch-cell spill at its entry. Metroid's
 * PRG helper is the worked case, transcribed byte for byte (c4e8/c4ef):
 * <pre>
 *   c4e8  LDA #0 / STA $24 / DEY / STY $23     second entry: Y := Y-1, falls into c4ef
 *   c4ef  TYA / STA $00 / LDA $28 / AND #$18 / ORA $00 / STA $28 /
 *         STA $E000 / (LSR / STA $E000) x4 / RTS      MMC1 serial write
 * </pre>
 * Placed at a made-up {@code $c0f9}/{@code $c100}. The real chain is A &lt;- ORA $00 &lt;- STA $00
 * &lt;- TYA &lt;- Y at entry; the {@code $28} shadow's masked bits stay unknown, so a call resolves
 * prg_bank bits 0-2 only (grm-hsv.14 would supply the rest).
 */
public class HelperInboundTransferProgramTest extends AbstractProgramTest {

	/** mirroring(2) | prg_mode(2) | prg_bank(5), as machines/nes-mmc1.yaml. */
	private static final int STATE_MASK = 0x1FF;
	private static final int PRG_BANK_LOW3 = 0x7 << 4;

	private static final String SERIAL_TAIL =
		"4a 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 4a 8d 00 e0 60";
	/** c100: TYA / STA $00 / LDA $28 / AND #$18 / ORA $00 / STA $28 / STA $E000 / (LSR / STA)x4 / RTS */
	private static final String HELPER = "98 85 00 a5 28 29 18 05 00 85 28 8d 00 e0 " + SERIAL_TAIL;
	/** c0f9: LDA #0 / STA $24 / DEY / STY $23, falling into c100 */
	private static final String DEY_ENTRY = "a9 00 85 24 88 84 23";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		MemoryBlock ram = builder.createMemory("RAM", "0x0", 0x800);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(ram);
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

	/** The five-write serial chain whose first write sits at {@code first}. */
	private HelperModel model(long entry, long first) {
		return new HelperModel(null, addr(entry), null, 'A', STATE_MASK, 0, mmc1(),
			addr(first + 12), addr(first), null,
			List.of(addr(first), addr(first + 4), addr(first + 8), addr(first + 12),
				addr(first + 16)));
	}

	private CallEffect callAt(long call, HelperModel helper) {
		StateOracle oracle = a -> BankState.unknown();
		return HelperArgumentRecovery.recoverCallArgument(program, instructionAt(addr(call)),
			helper, BankState.unknown(), new HashMap<>(), new HashMap<>(), RegisterEnv.NONE,
			oracle);
	}

	private void assertPrgBankLow3(CallEffect effect, int value) {
		assertEquals("prg_bank bits 0-2 are known; bits 3-4 (the $28 shadow's) are not",
			PRG_BANK_LOW3, effect.state().knownMask() & (0x1F << 4));
		assertEquals(value << 4, effect.state().bits() & PRG_BANK_LOW3);
		assertFalse("the argument DOES reach the mechanism", effect.noInboundArgument());
	}

	/** {@code LDY #5 / JSR $c100}: prg_bank bits 0-2 = 5, through TYA / STA $00 / ORA $00. */
	@Test
	public void tyaSpillOraResolvesTheLowBits() throws Exception {
		put(0xc000, "a0 05 20 00 c1 60");
		put(0xc100, HELPER);
		CallEffect effect = callAt(0xc002, model(0xc100, 0xc10b));
		assertPrgBankLow3(effect, 5);
	}

	/** Metroid c56f: {@code LDY #0 / JSR c4ef}. */
	@Test
	public void ldyZeroResolvesBankZero() throws Exception {
		put(0xc000, "a0 00 20 00 c1 60");
		put(0xc100, HELPER);
		assertPrgBankLow3(callAt(0xc002, model(0xc100, 0xc10b)), 0);
	}

	/**
	 * Metroid c4e2/c7c1/c7d2: Y comes from RAM, so nothing is known, but the helper DOES take
	 * an inbound argument, so the call must not claim it takes none.
	 */
	@Test
	public void unknownYIsHonestNotNoInboundArgument() throws Exception {
		put(0xc000, "a4 24 20 00 c1 60");
		put(0xc100, HELPER);
		CallEffect effect = callAt(0xc002, model(0xc100, 0xc10b));
		assertFalse(effect.argumentResolved());
		assertFalse("Y reaches the mechanism through TYA / STA $00 / ORA $00",
			effect.noInboundArgument());
	}

	/** The DEY second entry: {@code LDY #4} into c0f9 means bank 3. */
	@Test
	public void deySecondEntryAppliesTheStep() throws Exception {
		put(0xc000, "a0 04 20 f9 c0 60");
		put(0xc0f9, DEY_ENTRY);
		put(0xc100, HELPER);
		put(0xc200, "a0 01 20 00 c1 60"); // a second caller makes c100 a real join
		assertPrgBankLow3(callAt(0xc002, model(0xc0f9, 0xc10b)), 3);
	}

	/** The same helper entered at c100 directly sees no step. */
	@Test
	public void theFirstEntryAppliesNoStep() throws Exception {
		put(0xc000, "a0 04 20 00 c1 60");
		put(0xc0f9, DEY_ENTRY);
		put(0xc100, HELPER);
		assertPrgBankLow3(callAt(0xc002, model(0xc100, 0xc10b)), 4);
	}

	/**
	 * Negative: the spill cell is overwritten between the STA and the ORA, so the byte the OR
	 * folds in is not Y's. Must not claim the caller's Y.
	 */
	@Test
	public void anOverwrittenScratchCellDoesNotRecover() throws Exception {
		put(0xc000, "a0 05 20 00 c1 60");
		// TYA / STA $00 / LDA #$00 / STA $00 / LDA $28 / AND #$18 / ORA $00 / STA $28 / STA $E000 ...
		put(0xc100, "98 85 00 a9 00 85 00 a5 28 29 18 05 00 85 28 8d 00 e0 " + SERIAL_TAIL);
		CallEffect effect = callAt(0xc002, model(0xc100, 0xc112));
		// ($28 & $18) | 0 : bits 0-2 would be the helper's own constant zero, never Y = 5.
		assertEquals(0, effect.state().bits() & PRG_BANK_LOW3);
	}

	/** Negative: a call between the spill and the reload may rewrite the cell. */
	@Test
	public void aCallBetweenSpillAndReloadDoesNotRecover() throws Exception {
		put(0xc000, "a0 05 20 00 c1 60");
		put(0xc0f0, "60"); // callee
		// TYA / STA $00 / JSR $c0f0 / LDA $28 / AND #$18 / ORA $00 / STA $28 / STA $E000 ...
		put(0xc100, "98 85 00 20 f0 c0 a5 28 29 18 05 00 85 28 8d 00 e0 " + SERIAL_TAIL);
		CallEffect effect = callAt(0xc002, model(0xc100, 0xc10f));
		assertEquals("no bank bit may be claimed across the call", 0,
			effect.state().knownMask() & PRG_BANK_LOW3);
		assertFalse(effect.argumentResolved());
	}

	/**
	 * Metroid c4b2 (control register): the helper builds its own constant, so the caller's A
	 * is irrelevant -- the answer must be the same with the caller's A unknown, and the call
	 * still takes no inbound argument. Bit 0 of the written byte is (($47 >> 3) & 1) = 0.
	 */
	@Test
	public void aHelperConstantResolvesWhateverTheCallerHolds() throws Exception {
		put(0xc000, "a5 10 20 00 c1 60"); // LDA $10 : caller A unknown
		// NOP / NOP / LDA #$47 / LSR x3 / AND #1 / STA $00 / LDA $25 / AND #$FE / ORA $00 /
		// STA $25 / STA $8000 / (LSR / STA $8000) x4 / RTS
		put(0xc100, "ea ea a9 47 4a 4a 4a 29 01 85 00 a5 25 29 fe 05 00 85 25 8d 00 80 " +
			SERIAL_TAIL);
		CallEffect effect = callAt(0xc002, model(0xc100, 0xc113));
		// the fixture's chain writes $E000 (prg_bank, field bit 4): bit 0 of it is known zero
		assertEquals("bit 0 of the field is known", 0x10, effect.state().knownMask() & 0x10);
		assertEquals(0, effect.state().bits() & 0x10);
		assertTrue(effect.noInboundArgument());
	}

	/** The taint walk itself: constants the helper supplies never read as inbound. */
	@Test
	public void aHelperThatLoadsAConstantTakesNoInboundRegister() throws Exception {
		put(0xc100, "a9 07 8d 00 e0 60");
		assertFalse(HelperArgumentRecovery.inboundRegisterReaches(program, addr(0xc100),
			addr(0xc102), 'A'));
		put(0xc200, "98 8d 00 e0 60");
		assertTrue(HelperArgumentRecovery.inboundRegisterReaches(program, addr(0xc200),
			addr(0xc201), 'A'));
	}
}
