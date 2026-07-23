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

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

/**
 * De-risks the headless Ghidra program-fixture path inside a Gradle {@code Test} task
 * (bead grm-32f.1 spike): {@link AbstractGenericTest} must bootstrap {@code Application},
 * and {@link ProgramBuilder} must resolve the shipped 6502 language, entirely outside the
 * Ghidra GUI/headless-analyzer launcher. {@code ToyProgramBuilder} is deliberately NOT used
 * here -- its {@code Toy:*:builder} pseudo-language is not part of the binary install and
 * throws {@code LanguageNotFoundException}; {@code "6502:LE:16:default"} is a real shipped
 * language and works from a plain {@code ProgramBuilder}.
 * <p>
 * Template: {@code ghidra.app.analyzers.CondenseFillerBytesAnalyzerTest} in the Ghidra
 * source tree (Features/Base/src/test), with {@code ToyProgramBuilder} swapped for
 * {@code ProgramBuilder} and a 6502 instruction sequence in place of its Toy-language one.
 * <p>
 * Exercises real extension logic (Option A from the task brief): builds a tiny
 * {@code LDA #imm ; STA $01} sequence and runs it through
 * {@link RegisterWriteBankSwitchStrategy#computeSwitch}, which internally delegates to the
 * package-private {@link StoredValueScanner#resolveStoredValue} backward mask-algebra
 * scan -- the same production path {@code BoardBankAnalyzer} drives.
 */
public class BankStrategyProgramTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	public BankStrategyProgramTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
	}

	@Test
	public void programResolvesShippedSixFiveOhTwoLanguageHeadlessly() {
		assertEquals("6502:LE:16:default", program.getLanguage().getLanguageID().getIdAsString());
		assertNotNull(program.getMemory().getBlock(".text"));
	}

	@Test
	public void registerWriteStrategyRecoversStoredBankValue() throws Exception {
		// LDA #$05 ; STA $01 -- the "set bank via immediate load" idiom RegisterWrite
		// BankSwitchStrategy's javadoc documents (C64 $01 port, mask == whole byte here).
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 01", true); // STA $01

		Listing listing = program.getListing();
		Instruction storeInstr = listing.getInstructionAt(builder.addr("0x8002"));
		assertNotNull("STA $01 did not disassemble", storeInstr);

		JsonObject params = new JsonObject();
		params.addProperty("address", 1);

		RegisterWriteBankSwitchStrategy strategy = new RegisterWriteBankSwitchStrategy();
		strategy.configure(program, params, 0xFF);

		BankState result = strategy.computeSwitch(program, storeInstr, BankState.unknown());

		assertEquals(0xFF, result.knownMask());
		assertEquals(0x05, result.bits());
	}
}
