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

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import retromachines.BankSwitchStrategy.HelperDeposit;

/**
 * Pins {@link SelectDataBankSwitchStrategy}'s counted-loop select set (bead grm-ml6q): a
 * data-write helper whose OWN select write is computed from a counted loop's counter poisons
 * only the tracked targets that counter can reach -- none, for smb3 {@code FUN_ffad}'s walk over
 * the six CHR registers. Before this, a select the helper did not supply as one constant
 * poisoned R6|R7 whatever the loop could actually reach.
 */
public class CountedLoopSelectHelperProgramTest extends AbstractProgramTest {

	private static final int R6 = 0x0F0;
	private static final int R7 = 0xF00;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/** MMC3-shaped: select/data over {@code $8000-$9FFF}, select = byte bits 0..2, targets 6 -> r6
	 *  and 7 -> r7; every other select value is an untracked (CHR) register. */
	private SelectDataBankSwitchStrategy strategy() {
		JsonObject fieldLayout = new JsonObject();
		fieldLayout.add("select", field(0, 3));
		fieldLayout.add("r6", field(4, 4));
		fieldLayout.add("r7", field(8, 4));

		JsonObject targets = new JsonObject();
		targets.addProperty("6", "r6");
		targets.addProperty("7", "r7");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_mask", 0x07);
		params.addProperty("select_field", "select");
		params.add("targets", targets);
		params.add("_field_layout", fieldLayout);

		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, 0xFFF);
		return strategy;
	}

	private static JsonObject field(int lsb, int width) {
		JsonObject f = new JsonObject();
		f.addProperty("lsb", lsb);
		f.addProperty("width", width);
		return f;
	}

	/**
	 * smb3 {@code FUN_ffad}'s shape at {@code $c000}, seeded by {@code seed} (two bytes):
	 * <pre>
	 *   c000: seed           ; LDY #n, or a non-constant load
	 *   c002: TYA            ; L
	 *   c003: ORA #$40
	 *   c005: STA $8000      ; select = Y | $40
	 *   c008: LDA $0719,Y
	 *   c00b: STA $8001      ; data write  &lt;- the switch site
	 *   c00e: DEY
	 *   c00f: BPL L
	 *   c011: RTS
	 * </pre>
	 */
	private HelperDeposit depositAtDataWrite(String seed) throws Exception {
		builder.setBytes("0xc000", seed + " 98 09 40 8d 00 80 b9 19 07 8d 01 80 88 10 f1 60", true);
		// The caller's select is unknown, so only the helper's own select can route the write.
		return strategy().depositHelperArgument(program, instructionAt("0xc00b"),
			PartialByte.unknown(), new MechanismState(0, 0), 0xFFF);
	}

	/** <b>The headline case.</b> Y in [0,5] puts select in {0..5}: CHR only, a verified no-op. */
	@Test
	public void chrOnlyLoopOwnsNothing() throws Exception {
		assertEquals(0, depositAtDataWrite("a0 05").ownedMask());
	}

	/** Y in [0,6] reaches select 6 but never 7: only R6 is poisoned. */
	@Test
	public void loopReachingR6PoisonsOnlyR6() throws Exception {
		assertEquals(R6, depositAtDataWrite("a0 06").ownedMask());
	}

	/** An unprovable seed ({@code LDY $10}) declines the set and keeps the old full poison. */
	@Test
	public void unprovableSeedPoisonsEveryTarget() throws Exception {
		assertEquals(R6 | R7, depositAtDataWrite("a4 10").ownedMask());
	}
}
