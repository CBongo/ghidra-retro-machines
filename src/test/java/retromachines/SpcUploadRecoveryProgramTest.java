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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * End-to-end on a hand-assembled 65816 program: emulation against the IPL model, the
 * handshake-signature candidate search, and materialization into an SPC700 program. The
 * program uploads the two bytes {@code 11 22} to SPC700 {@code $0200} and jumps to {@code $0300}.
 */
public class SpcUploadRecoveryProgramTest extends AbstractProgramTest {

	/** LDA #imm / STA abs sequences for: dest $0200, kick, 2 data bytes, entry $0300. */
	private static final String UPLOAD =
		"A900 8D4221 A902 8D4321 A901 8D4121 A9CC 8D4021" +   // dest $0200, transfer, kick
			"A911 8D4121 A900 8D4021" +                        // byte 0 = $11, index 0
			"A922 8D4121 A901 8D4021" +                        // byte 1 = $22, index 1
			"A900 8D4221 A903 8D4321 A900 8D4121 A904 8D4021" + // entry $0300, jump, cmd $04
			"80FE";                                            // spin

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("spc-upload", "65816:LE:24:retro");
		builder.createMemory("ROM_00_8000", "0x008000", 0x8000);
		program = builder.getProgram();
	}

	private static String compact(String s) {
		return s.replace(" ", "");
	}

	@Test
	public void resetStrategyRecoversTheUpload() throws Exception {
		put(0x8000, compact(UPLOAD));
		put(0xFFFC, "0080");

		SpcUploadRecovery.Result r = new SpcUploadRecovery(program).recover(null, TaskMonitor.DUMMY);
		assertTrue(r.stop().toString(), r.success());
		assertEquals(SpcUploadRecovery.Strategy.RESET, r.strategy());
		assertEquals(0x0300, r.entry());
		assertEquals(1, r.blocks().size());
		SpcIplModel.Block b = r.blocks().get(0);
		assertEquals(0x0200, b.dest());
		assertArrayEquals(new byte[] { 0x11, 0x22 }, b.bytes());
		assertEquals(0x8011, b.issuerPc() & 0xFFFF);
	}

	@Test
	public void uploaderStrategyFindsRoutineByHandshakeSignature() throws Exception {
		put(0x8000, "80FE");                   // reset spins forever
		put(0xFFFC, "0080");
		put(0x8010, "4C0090");                 // JMP $9000: the call a candidate search follows
		put(0x9000, compact("C210 A2AABB EC4021 D0FB E210 " + UPLOAD));

		List<Address> candidates = SpcUploadRecovery.findUploaderCandidates(program);
		assertEquals(List.of(addr(0x9000)), candidates);

		StopConditions small = StopConditions.builder().instructionFuel(20_000).build();
		SpcUploadRecovery.Result r = new SpcUploadRecovery(program).recover(small, TaskMonitor.DUMMY);
		assertTrue(r.stop().toString(), r.success());
		assertEquals(SpcUploadRecovery.Strategy.UPLOADER, r.strategy());
		assertEquals(addr(0x9000), r.uploaderEntry());
		assertEquals(2, r.attempts().size());
		assertEquals(SpcUploadRecovery.Stop.FUEL, r.attempts().get(0).stop());
		assertEquals(0x0300, r.entry());
		assertArrayEquals(new byte[] { 0x11, 0x22 }, r.blocks().get(0).bytes());
	}

	@Test
	public void romWithoutHandshakeFailsHonestly() throws Exception {
		put(0x8000, "80FE");
		put(0xFFFC, "0080");
		assertFalse(SpcUploadRecovery.usesApuPort(program));
		StopConditions small = StopConditions.builder().instructionFuel(1000).build();
		SpcUploadRecovery.Result r = new SpcUploadRecovery(program).recover(small, TaskMonitor.DUMMY);
		assertFalse(r.success());
		assertEquals(SpcUploadRecovery.Stop.FUEL, r.stop());
		assertEquals(-1, r.entry());
	}

	@Test
	public void materializerBuildsOneSpc700Program() throws Exception {
		put(0x8000, compact(UPLOAD));
		put(0xFFFC, "0080");
		SpcUploadRecovery.Result r = new SpcUploadRecovery(program).recover(null, TaskMonitor.DUMMY);
		assertTrue(r.success());

		ProgramDB spc = SpcProgramMaterializer.build(r, "t.spc700", this, false, TaskMonitor.DUMMY);
		try {
			assertEquals(SpcProgramMaterializer.LANGUAGE_ID, spc.getLanguageID().getIdAsString());
			MemoryBlock up = spc.getMemory().getBlock("UPLOAD_0200");
			assertNotNull(up);
			assertTrue(up.isInitialized());
			assertEquals(2, up.getSize());
			assertEquals(0x11, up.getByte(up.getStart()) & 0xFF);
			assertEquals(0x22, up.getByte(up.getStart().add(1)) & 0xFF);
			assertTrue(up.getComment().contains("spc-upload"));
			assertTrue(up.getComment().contains("upload #0"));
			MemoryBlock ipl = spc.getMemory().getBlock("IPL_ROM_FFC0");
			assertNotNull(ipl);
			assertFalse(ipl.isInitialized());
			assertEquals(0x10000, spc.getMemory().getNumAddresses());
			Symbol entry = spc.getSymbolTable().getPrimarySymbol(
				spc.getAddressFactory().getDefaultAddressSpace().getAddress(0x0300));
			assertNotNull(entry);
			assertEquals(SpcProgramMaterializer.ENTRY_LABEL, entry.getName());
		}
		finally {
			spc.release(this);
		}
	}

	@Test
	public void laterUploadsWinInTheAccumulatedImage() {
		SpcIplModel ipl = new SpcIplModel();
		ipl.portWritten(2, 0x00);
		ipl.portWritten(3, 0x02);
		ipl.portWritten(1, 1);
		ipl.portWritten(0, 0xCC);
		ipl.instructionBoundary(1, 1);
		ipl.portWritten(1, 0xAA);
		ipl.portWritten(0, 0);
		ipl.instructionBoundary(2, 2);
		ipl.portWritten(1, 0xBB);
		ipl.portWritten(0, 1);
		ipl.instructionBoundary(3, 3);
		// second command overlapping the second byte
		ipl.portWritten(2, 0x01);
		ipl.portWritten(3, 0x02);
		ipl.portWritten(1, 1);
		ipl.portWritten(0, 0x04);
		ipl.instructionBoundary(4, 4);
		ipl.portWritten(1, 0xCC);
		ipl.portWritten(0, 0);
		ipl.instructionBoundary(5, 5);
		SpcProgramMaterializer.Image img = SpcProgramMaterializer.accumulate(ipl.blocks());
		assertEquals(0xAA, img.data()[0x200] & 0xFF);
		assertEquals(0xCC, img.data()[0x201] & 0xFF);
		assertEquals(0, img.writers()[0x200]);
		assertEquals(1, img.writers()[0x201]);
		assertFalse(img.written(0x202));
	}
}
