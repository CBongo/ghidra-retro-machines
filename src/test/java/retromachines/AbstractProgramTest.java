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

import static org.junit.Assert.assertNotNull;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Base for {@code ProgramBuilder} tests that keep one {@code builder}/{@code program} pair as
 * fields (bead grm-w9ev.3). A subclass's {@code @Before} assigns both, typically
 * {@code builder = newBuilder("name", languageId); program = builder.getProgram();}, and then
 * gets the small address/byte/instruction helpers every such test used to re-declare privately.
 */
public abstract class AbstractProgramTest extends AbstractBundledLanguageTest {

	protected ProgramBuilder builder;
	protected ProgramDB program;

	protected Address addr(String address) {
		return builder.addr(address);
	}

	protected Address addr(long offset) {
		return builder.addr(hex(offset));
	}

	protected void put(String address, String hex) throws Exception {
		builder.setBytes(address, hex, true);
	}

	protected void put(long address, String hex) throws Exception {
		builder.setBytes(hex(address), hex, true);
	}

	protected Instruction instructionAt(String address) {
		return instructionAt(builder.addr(address));
	}

	protected Instruction instructionAt(Address address) {
		Instruction instr = program.getListing().getInstructionAt(address);
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	protected void setWritable(MemoryBlock block, boolean writable) {
		inTx(program, "set block write permission", () -> {
			block.setWrite(writable);
		});
	}

	protected void makeWritable(MemoryBlock block) {
		setWritable(block, true);
	}
}
