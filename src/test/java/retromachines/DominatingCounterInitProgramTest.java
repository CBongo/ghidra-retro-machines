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
import static org.junit.Assert.assertNull;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

/**
 * {@link LoopIdioms#findDominatingCounterInit} (grm-7pp) on a SYNTHETIC two-loop dispatch in the
 * db3 shape -- one counter load, a branch, then a copy loop on each arm:
 * <pre>
 *   8000  LDX #$05
 *   8002  LDA $10 / BMI $8010
 *   8006  LDA $8100,X / STA $0200,X / DEX / BPL $8006     ; loop A
 *   800f  RTS
 *   8010  LDA $8200,X / STA $0200,X / DEX / BPL $8010     ; loop B
 *   8019  RTS
 * </pre>
 * Hand-built bytes, nothing copied from a ROM. The linear lookback cannot see the init from loop B
 * (and from A only by being near); the walk must find it on both arms, and must give up whenever
 * another path could carry a different value.
 */
public class DominatingCounterInitProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final String HEAD = "a2 05 a5 10 30 0a ";
	private static final String LOOPS = "bd 00 81 9d 00 02 ca 10 f7 60 " +
		"bd 00 82 9d 00 02 ca 10 f7 60";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB build(String head, String extra) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		builder.setBytes("0x8000", head + LOOPS, true);
		if (extra != null) {
			builder.setBytes("0x8300", extra, true);
		}
		return builder.getProgram();
	}

	private Integer initValue(ProgramDB program, long loopHead, long branch) {
		Instruction lda = program.getListing().getInstructionAt(addr(loopHead));
		Instruction br = program.getListing().getInstructionAt(addr(branch));
		assertNotNull(lda);
		assertNotNull(br);
		Instruction init = LoopIdioms.findDominatingCounterInit(program, lda,
			LoopIdioms.indexReg(lda), br);
		return init == null ? null : MosOperands.immediateOperandValue(init);
	}

	@Test
	public void sharedInitIsFoundOnBothArms() throws Exception {
		ProgramDB p = build(HEAD, null);
		assertEquals(Integer.valueOf(5), initValue(p, 0x8006, 0x800d));
		assertEquals(Integer.valueOf(5), initValue(p, 0x8010, 0x8017));
	}

	@Test
	public void anotherWriterOnThePathDeclines() throws Exception {
		// INX / NOP in place of LDA $10: X may no longer be the loaded value.
		ProgramDB p = build("a2 05 e8 ea 30 0a ", null);
		assertNull(initValue(p, 0x8006, 0x800d));
		assertNull(initValue(p, 0x8010, 0x8017));
	}

	@Test
	public void secondEntryDiffersWithADifferentValueDeclines() throws Exception {
		ProgramDB p = build(HEAD, "a2 07 4c 06 80");
		assertNull(initValue(p, 0x8006, 0x800d));
		// Loop B is not entered from the extra jump.
		assertEquals(Integer.valueOf(5), initValue(p, 0x8010, 0x8017));
	}

	@Test
	public void aSecondEntryWithNoInitDeclines() throws Exception {
		ProgramDB p = build(HEAD, "4c 06 80");
		assertNull(initValue(p, 0x8006, 0x800d));
	}

	@Test
	public void aSecondEntryWithTheSameValueIsFine() throws Exception {
		ProgramDB p = build(HEAD, "a2 05 4c 06 80");
		assertEquals(Integer.valueOf(5), initValue(p, 0x8006, 0x800d));
	}

	@Test
	public void aCallOnThePathDeclines() throws Exception {
		// JSR $8300 between the init and the branch: the callee may clobber X.
		ProgramDB p = build("a2 05 20 00 83 30 09 ", "60");
		assertNull(initValue(p, 0x8007, 0x800e));
	}
}
