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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import retromachines.BankSwitchStrategy.ValueStop;

/**
 * Pins the "no static store to this cell" test that lets {@link ValueStop#RUNTIME_SOURCE} cover a
 * load from writable memory (bead grm-rr5p). The rule is honest only for a cell nothing could ever
 * have determined; a parameter latch -- written elsewhere, read here -- is grm-hum's population
 * and must stay {@link ValueStop#ANALYZER_LIMIT}. Measured 2026-10-04: nesmirrortest c102 ($59) and
 * dbz_datach cc2a are latches; $30/$31/$33 and banktest2's $0400 are untouched.
 * <p>
 * Every test ends in {@code LDA <cell> / STA $8000} and asks the scanner why the stored byte did
 * not resolve. ProgramBuilder blocks are read-only by default, so the RAM block is made writable
 * explicitly (see {@link StoreForwardingProgramTest}).
 */
public class RuntimeSourceNoStoreProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		int tx = program.startTransaction("writable");
		try {
			zp.setWrite(true);
			ram.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private ValueStop stopOfStoreAt(String address) {
		Instruction store = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, store);
		return StoredValueScanner.resolveStoredValueScan(program, store, 'A', BankState.unknown(),
			0x07, NO_HOOKS, RegisterEnv.NONE).stop();
	}

	@Test
	public void untouchedAbsoluteRamCellIsRuntimeSource() throws Exception {
		builder.setBytes("0x8000", "ad 00 04", true); // LDA $0400
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000
		assertEquals(ValueStop.RUNTIME_SOURCE, stopOfStoreAt("0x8003"));
	}

	@Test
	public void untouchedZeroPageCellWithNoIndexedStoreIsRuntimeSource() throws Exception {
		builder.setBytes("0x8000", "a5 30", true); // LDA $30
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8005", "85 31", true); // STA $31  (a different cell)
		assertEquals(ValueStop.RUNTIME_SOURCE, stopOfStoreAt("0x8002"));
	}

	@Test
	public void cellWithAStaticStoreElsewhereStaysAnalyzerLimit() throws Exception {
		builder.setBytes("0x8000", "ad 00 04", true); // LDA $0400
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8010", "8d 00 04", true); // STA $0400   <- the latch write
		assertEquals(ValueStop.ANALYZER_LIMIT, stopOfStoreAt("0x8003"));
	}

	@Test
	public void zeroPageCellWithAStaticStoreElsewhereStaysAnalyzerLimit() throws Exception {
		builder.setBytes("0x8000", "a5 59", true); // LDA $59
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8010", "85 59", true); // STA $59
		assertEquals(ValueStop.ANALYZER_LIMIT, stopOfStoreAt("0x8002"));
	}

	@Test
	public void zeroPageCellWithAnIndexedStoreAnywhereStaysAnalyzerLimit() throws Exception {
		builder.setBytes("0x8000", "a5 30", true); // LDA $30
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8010", "95 00", true); // STA $00,X  -- may reach $30
		assertEquals(ValueStop.ANALYZER_LIMIT, stopOfStoreAt("0x8002"));
	}

	@Test
	public void indirectStoreAlsoBlocksZeroPage() throws Exception {
		builder.setBytes("0x8000", "a5 30", true); // LDA $30
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8010", "91 10", true); // STA ($10),Y
		assertEquals(ValueStop.ANALYZER_LIMIT, stopOfStoreAt("0x8002"));
	}

	@Test
	public void indexedStoreDoesNotBlockNonZeroPageCell() throws Exception {
		builder.setBytes("0x8000", "ad 00 04", true); // LDA $0400
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8010", "9d 00 05", true); // STA $0500,X
		assertEquals(ValueStop.RUNTIME_SOURCE, stopOfStoreAt("0x8003"));
	}

	@Test
	public void absoluteIndexedStoreWhoseWindowCoversTheCellStaysAnalyzerLimit() throws Exception {
		builder.setBytes("0x8000", "ad 00 04", true); // LDA $0400
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8010", "9d f0 03", true); // STA $03F0,X -- reaches $0400 at X=$10
		assertEquals(ValueStop.ANALYZER_LIMIT, stopOfStoreAt("0x8003"));
	}
}
