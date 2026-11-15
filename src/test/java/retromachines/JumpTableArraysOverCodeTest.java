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

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

/**
 * grm-mav1: {@link JumpTableArrays#layWords} over a table that a conditional branch's fall-through
 * disassembled as junk code (megaman {@code c89e}, after the last case's {@code BMI}). Code that
 * only fall-through reaches is cleared and the array laid; code something branches into is not.
 */
public class JumpTableArraysOverCodeTest extends AbstractProgramTest {

	private static final long TABLE = 0x8010;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".rom", "0x8000", 0x100);
		// 8000: BMI $8000 (its fall-through is 8002), NOP padding to the table at 8010 whose
		// bytes decode as code: 40 RTI, 80 80 NOP #imm ...
		builder.setBytes("0x8000", "30 fe", false);
		builder.setBytes("0x8002", "ea ea ea ea ea ea ea ea ea ea ea ea ea ea", false);
		builder.setBytes("0x8010", "40 80 41 80 42 80 43 80", false);
		builder.setBytes("0x8040", "60 60 60 60", true);
		program = builder.getProgram();
	}

	private List<Address> targets() {
		return List.of(addr(0x8040), addr(0x8041), addr(0x8042), addr(0x8043));
	}

	private void disassembleTable() {
		inTx(program, "dis", () -> new DisassembleCommand(new AddressSet(addr(0x8000), addr(TABLE + 7)),
			null, true).applyTo(program));
	}

	@Test
	public void clearsJunkCodeNothingJumpsInto() throws Exception {
		disassembleTable();
		assertNotNull(program.getListing().getInstructionAt(addr(TABLE + 2)));
		assertTrue(inTxGet(program, "lay",
			() -> JumpTableArrays.layWords(program, addr(TABLE), targets(), true)));
		assertNull(program.getListing().getInstructionContaining(addr(TABLE + 3)));
		Array laid = (Array) program.getListing().getDefinedDataAt(addr(TABLE)).getDataType();
		assertEquals(4, laid.getNumElements());
	}

	@Test
	public void declinesWhenCodeIsBranchedInto() throws Exception {
		disassembleTable();
		inTx(program, "ref", () -> program.getReferenceManager().addMemoryReference(addr(0x8000),
			addr(TABLE + 2), RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, 0));
		assertFalse(inTxGet(program, "lay",
			() -> JumpTableArrays.layWords(program, addr(TABLE), targets(), true)));
		assertNotNull(program.getListing().getInstructionContaining(addr(TABLE + 2)));
	}
}
