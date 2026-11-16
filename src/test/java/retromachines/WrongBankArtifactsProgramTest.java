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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@link WrongBankArtifacts} (bead grm-z0d7.1): the base-space function a
 * retired retargeted call leaves orphaned is removed, along with the decode only it reached,
 * and nothing else.
 */
public class WrongBankArtifactsProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace base;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x4000);
		program = builder.getProgram();
		base = program.getAddressFactory().getDefaultAddressSpace();
	}

	private Address addr(int a) {
		return base.getAddress(a);
	}

	private void function(int a, SourceType source) throws Exception {
		int tx = program.startTransaction("fn");
		try {
			program.getFunctionManager().createFunction(
				source == SourceType.USER_DEFINED ? "mine" : null, addr(a),
				new AddressSet(addr(a), addr(a)), source);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private List<WrongBankArtifacts.Removal> remove(int target) {
		int tx = program.startTransaction("remove");
		try {
			return WrongBankArtifacts.remove(null, program, Map.of(addr(target), addr(0xC000)),
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private boolean hasInstr(int a) {
		return program.getListing().getInstructionAt(addr(a)) != null;
	}

	/** (a) The entry is mid-run in genuine code (PLA falls into it): function goes, code stays. */
	@Test
	public void functionInsideGenuineCodeIsRemovedAndInstructionsKept() throws Exception {
		builder.setBytes("0x8000", "68 AA 60", true); // PLA / TAX / RTS
		function(0x8001, SourceType.DEFAULT);
		assertNotNull(program.getFunctionManager().getFunctionAt(addr(0x8001)));

		List<WrongBankArtifacts.Removal> done = remove(0x8001);

		assertEquals(1, done.size());
		assertEquals(0, done.get(0).instrs());
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x8001)));
		assertTrue(hasInstr(0x8000) && hasInstr(0x8001) && hasInstr(0x8002));
		Bookmark b = program.getBookmarkManager().getBookmark(addr(0x8001), BookmarkType.ANALYSIS,
			WrongBankArtifacts.CATEGORY);
		assertNotNull(b);
		assertTrue(b.getComment(), b.getComment().startsWith("instrs=0 funcs=1"));
		assertTrue("second call is a no-op", remove(0x8001).isEmpty());
	}

	/** (b) A misaligned run only the entry reaches: cleared, and the real instruction returns. */
	@Test
	public void misalignedRunIsClearedAndHomeBankDecodeRestored() throws Exception {
		// Real flow: 9000 LDA $76,X ; 9002 STA $0076,Y ; 9005 RTS. Entry 9003 is 76 00 ROR $00,X.
		builder.setBytes("0x9000", "B5 76 99 76 00 60", false);
		builder.disassemble("0x9003", 3, true);
		function(0x9003, SourceType.DEFAULT);
		builder.disassemble("0x9000", 2, true);
		assertTrue(hasInstr(0x9000));
		assertFalse("the misaligned run blocks the real instruction", hasInstr(0x9002));
		assertTrue(hasInstr(0x9003));

		List<WrongBankArtifacts.Removal> done = remove(0x9003);

		assertEquals(1, done.size());
		assertEquals(2, done.get(0).instrs()); // ROR + RTS
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x9003)));
		assertTrue(hasInstr(0x9000));
		assertTrue("the home bank's own instruction is back", hasInstr(0x9002));
		assertEquals("STA", program.getListing().getInstructionAt(addr(0x9002)).getMnemonicString());
		assertFalse(hasInstr(0x9003));
		assertEquals(2, done.get(0).redecoded());
	}

	/** (c) Another reference still roots the function: kept. */
	@Test
	public void functionWithAnotherReferenceIsKept() throws Exception {
		builder.setBytes("0x8100", "60", true);
		builder.setBytes("0x8000", "20 00 81", true); // JSR $8100
		function(0x8100, SourceType.DEFAULT);

		assertTrue(remove(0x8100).isEmpty());
		assertNotNull(program.getFunctionManager().getFunctionAt(addr(0x8100)));
		assertTrue(hasInstr(0x8100));
	}

	/** (d) A user-defined symbol protects the function. */
	@Test
	public void userDefinedFunctionIsKept() throws Exception {
		builder.setBytes("0x8200", "60", true);
		function(0x8200, SourceType.USER_DEFINED);

		assertTrue(remove(0x8200).isEmpty());
		assertNotNull(program.getFunctionManager().getFunctionAt(addr(0x8200)));
		assertTrue(hasInstr(0x8200));
	}

	/** (e) An orphaned run nothing blocks: function removed, instructions kept. */
	@Test
	public void unblockingRunKeepsItsInstructions() throws Exception {
		builder.setBytes("0x8300", "A9 01 8D 00 02 60", true); // LDA #1 / STA $0200 / RTS
		function(0x8300, SourceType.DEFAULT);

		List<WrongBankArtifacts.Removal> done = remove(0x8300);

		assertEquals(1, done.size());
		assertEquals(0, done.get(0).instrs());
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x8300)));
		assertTrue(hasInstr(0x8300) && hasInstr(0x8302) && hasInstr(0x8305));
	}
}
