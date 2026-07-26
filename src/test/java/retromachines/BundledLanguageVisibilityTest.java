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

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

/**
 * Proves the bead grm-2pi plumbing works: this module's own bundled sleigh language resolves
 * from a plain Gradle {@code test} JVM, and disassembles. Before grm-2pi this class's
 * {@code setUp} threw {@code LanguageNotFoundException}.
 * <p>
 * The {@code STA $01} case is the one that matters beyond mere language lookup: it is the
 * 6510's whole reason for existing (bead grm-bk6), routing the on-die I/O port at
 * {@code $00}/{@code $01} through the {@code PORT} register instead of memory. A stock 6502
 * would render the same bytes as a memory store, so a passing assertion here also confirms we
 * loaded OUR language and not Ghidra's.
 */
public class BundledLanguageVisibilityTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6510:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
	}

	@Test
	public void bundledSixFiveOneZeroLanguageResolves() {
		assertEquals("6510:LE:16:default",
			program.getLanguage().getLanguageID().getIdAsString());
		assertEquals("6510", program.getLanguage().getProcessor().toString());
	}

	@Test
	public void bundledLanguageDisassembles() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05

		Listing listing = program.getListing();
		Instruction lda = listing.getInstructionAt(builder.addr("0x8000"));
		assertNotNull("LDA #$05 did not disassemble", lda);
		assertEquals("LDA", lda.getMnemonicString());
	}

	@Test
	public void zeroPageOneRoutesThroughThePortRegister() throws Exception {
		builder.setBytes("0x8000", "85 01", true); // STA $01 -> STA PORT

		Instruction sta = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("STA $01 did not disassemble", sta);
		assertEquals("STA", sta.getMnemonicString());
		assertEquals("PORT", sta.getDefaultOperandRepresentation(0));
	}
}
