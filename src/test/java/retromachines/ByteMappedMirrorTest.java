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

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins the Ghidra behaviour that decides `grm-9nxj.6`: CODE DISASSEMBLES INSIDE A BYTE-MAPPED
 * BLOCK -- bytes come from the canonical block, instructions are created at the mirror's own
 * addresses. Measured here rather than assumed, and kept because a SNES loader's mirror policy
 * depends on it: if a future Ghidra stopped allowing it, the loader would silently lose two of
 * every five call targets and this test is what would say so.
 *
 * <p>The SNES maps one physical ROM at two address ranges -- banks {@code $80-$FF} mirror
 * {@code $00-$7F} -- and the corpus measurement in docs/snes-memory-map-decision.md says both
 * halves are live, with 40% of {@code JSL}/{@code JML} targets naming the high mirror. So the
 * loader's mirror policy decides whether two of every five call targets land in mapped memory or
 * in nothing. {@code createByteMappedBlock} is the natural modelling of a hardware mirror, and the
 * one existing third-party SNES loader uses it -- but that only settles that the BLOCKS can be
 * created, not that CODE can live in them. It can: this test passes.
 */
public class ByteMappedMirrorTest extends AbstractBundledLanguageTest {

	@Test
	public void codeDisassemblesInsideAByteMappedMirror() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", "65816:LE:24:retro");
		builder.createMemory("rom", "0x008000", 0x100);
		ProgramDB program = builder.getProgram();

		int tx = program.startTransaction("mirror");
		MemoryBlock mirror;
		try {
			mirror = program.getMemory()
					.createByteMappedBlock("rom_mirror", builder.addr("0x808000"),
						builder.addr("0x008000"), 0x100, false);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertNotNull("byte-mapped mirror block was not created", mirror);

		// Bytes written to the canonical block only.
		builder.setBytes("0x008000", "a9 12 ea");

		// ... and disassembled through the mirror's addresses only.
		builder.disassemble("0x808000", 3);

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x808000"));
		assertNotNull("no instruction at the mirror address -- code cannot live in a " +
			"byte-mapped block, so mirror policy (a) is not viable as written", lda);
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals(2, lda.getLength());

		Instruction nop = program.getListing().getInstructionAt(builder.addr("0x808002"));
		assertNotNull("the mirror's second instruction did not decode", nop);
		assertEquals("NOP", nop.getMnemonicString());
	}
}
