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

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;

/**
 * grm-gipk.21: {@link JumpTableArrays#clearStaleLoadTableData} clears exactly stock's leftover
 * over-read load-table units (single, constant, integer, of the load size) past the kept entries,
 * and nothing else. The shape is ff1 B14 {@code a354}: two one-byte loads at {@code t}/{@code t+1},
 * 128 entries each, laid by stock as single constant bytes over real code.
 */
public class JumpTableArraysStaleLoadTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".rom", "0x8000", 0x1000);
		program = builder.getProgram();
	}

	/** Stock's labelLoadTable unit: one ByteDataType, marked constant. */
	private void stockByte(long offset) throws Exception {
		Data d = program.getListing().createData(addr(offset), ByteDataType.dataType);
		MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
	}

	@Test
	public void clearsStockUnitsPastTheKeptEntriesOnly() throws Exception {
		inTx(program, "setup", () -> {
			for (long a = 0x8100; a < 0x8200; a++) {
				stockByte(a);
			}
		});
		// Kept: 8 word entries from the lowest table = 0x8100..0x810f.
		AddressSet keep = new AddressSet(addr(0x8100), addr(0x810f));
		int cleared = inTxGet(program, "clear", () -> JumpTableArrays.clearStaleLoadTableData(
			program, addr(0x8100).getAddressSpace(),
			List.of(new long[] { 0x8100, 1, 128 }, new long[] { 0x8101, 1, 128 }), keep));
		// Stock's extent is 0x8100..0x8180; minus the 16 kept bytes = 0x8110..0x8180 = 113.
		assertEquals(113, cleared);
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x8100)));
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x810f)));
		assertNull(program.getListing().getDefinedDataAt(addr(0x8110)));
		assertNull(program.getListing().getDefinedDataAt(addr(0x8180)));
		// Outside stock's own extent: untouched.
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x8181)));
	}

	@Test
	public void leavesDataThatIsNotStocksShape() throws Exception {
		inTx(program, "setup", () -> {
			// a plain (non-constant) byte, a constant word, and a constant byte
			program.getListing().createData(addr(0x8120), ByteDataType.dataType);
			Data w = program.getListing().createData(addr(0x8130), WordDataType.dataType);
			MutabilitySettingsDefinition.DEF.setChoice(w, MutabilitySettingsDefinition.CONSTANT);
			stockByte(0x8140);
		});
		int cleared = inTxGet(program, "clear", () -> JumpTableArrays.clearStaleLoadTableData(
			program, addr(0x8100).getAddressSpace(), List.<long[]> of(new long[] { 0x8100, 1, 128 }),
			new AddressSet()));
		assertEquals(1, cleared);
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x8120)));
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x8130)));
		assertNull(program.getListing().getDefinedDataAt(addr(0x8140)));
	}
}
