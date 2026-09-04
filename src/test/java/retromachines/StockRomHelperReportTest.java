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

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins the stock-system-ROM reporting filter (grm-5tl.19): a bank-switch helper that lives in
 * a user-supplied KERNAL/BASIC image is still recognized, but is kept out of the summary line
 * the user reads.
 * <p>
 * The shape is the C64's, where {@code IOINIT} at {@code $FDA3} resets the 6510 port and so
 * writes the very mechanism the analyzer is looking for. The discriminator under test is
 * <em>provenance</em> -- {@link MemoryBlock#getSourceName()} equal to
 * {@link DescriptorMemory#STOCK_ROM_SOURCE}, stamped by {@code AbstractCbmPrgLoader} when it
 * fills a block from a ROM file the user pointed at -- and deliberately not block permissions,
 * which cannot tell a stock KERNAL from a NES PRG bank.
 */
public class StockRomHelperReportTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x2000", 0x1000);        // the imported program
		MemoryBlock kernal = builder.createMemory("KERNAL", "0xe000", 0x2000);
		program = builder.getProgram();

		int tx = program.startTransaction("stamp ROM provenance");
		try {
			kernal.setSourceName(DescriptorMemory.STOCK_ROM_SOURCE);
			kernal.setWrite(false);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Function function(String name, String entry) throws Exception {
		builder.createEmptyFunction(name, entry, 3, null);
		Function f = program.getFunctionManager().getFunctionAt(builder.addr(entry));
		assertNotNull("no function created at " + entry, f);
		return f;
	}

	@Test
	public void addressInStockRomBlockIsRecognizedAsSuch() {
		assertTrue("KERNAL block is stock ROM",
			DescriptorMemory.inStockSystemRom(program, builder.addr("0xfda3")));
	}

	@Test
	public void addressInTheImportedProgramIsNot() {
		assertFalse("the imported PRG is not stock ROM",
			DescriptorMemory.inStockSystemRom(program, builder.addr("0x2000")));
	}

	@Test
	public void unmappedAddressIsNot() {
		assertFalse("nothing is mapped at $8000",
			DescriptorMemory.inStockSystemRom(program, builder.addr("0x8000")));
	}

	/**
	 * A non-writable block alone must NOT count: that is exactly a NES PRG bank, where the
	 * helper is the user's own code.
	 */
	@Test
	public void readOnlyWithoutRomProvenanceIsNot() throws Exception {
		MemoryBlock prg = program.getMemory().getBlock("PRG");
		int tx = program.startTransaction("make PRG read-only");
		try {
			prg.setWrite(false);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertFalse("read-only is not the discriminator",
			DescriptorMemory.inStockSystemRom(program, builder.addr("0x2000")));
	}

	@Test
	public void partitionSplitsGameHelpersFromSystemRomOnes() throws Exception {
		Function game = function("switchBank", "0x2000");
		Function ioinit = function("IOINIT", "0xfda3");

		BoardBankAnalyzer.HelperReport report =
			BoardBankAnalyzer.partitionHelpers(program, List.of(game, ioinit));

		assertEquals(List.of("switchBank"), report.gameHelpers());
		assertEquals(List.of("IOINIT"), report.systemRomHelpers());
	}

	@Test
	public void partitionSortsEachSideByName() throws Exception {
		Function b = function("zzz", "0x2000");
		Function a = function("aaa", "0x2010");
		Function romB = function("kzzz", "0xfda3");
		Function romA = function("kaaa", "0xfd00");

		BoardBankAnalyzer.HelperReport report =
			BoardBankAnalyzer.partitionHelpers(program, List.of(b, a, romB, romA));

		assertEquals(List.of("aaa", "zzz"), report.gameHelpers());
		assertEquals(List.of("kaaa", "kzzz"), report.systemRomHelpers());
	}
}
