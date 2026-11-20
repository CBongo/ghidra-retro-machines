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
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;

/**
 * grm-9nxj.43: {@link SnesTrampolineScanner} reads an absolute store's bank from the tracked DBR
 * and only falls back to "low RAM" when DBR is unknown. The code at $8000 writes
 * {@code JMP $9000} to $0100 (the NMI vector's RAM trampoline) with absolute stores.
 */
public class SnesTrampolineScannerDbrTest extends AbstractProgramTest {

	private static final String CODE = "a9 4c 8d 00 01 a9 00 8d 01 01 a9 90 8d 02 01 60";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		builder.createMemory("ROM_0", "0x8000", 0x8000);
		program = builder.getProgram();
		builder.setBytes("0xffea", "00 01", false);   // NMI vector -> $0100
		builder.setBytes("0x8000", CODE, false);
		builder.setBytes("0x9000", "60", false);
		inTx(program, "flags", () -> {
			program.getProgramContext().setValue(program.getRegister("ctx_MF"),
				addr(0x8000), addr(0x8fff), BigInteger.ONE);
			program.getProgramContext().setValue(program.getRegister("ctx_EF"),
				addr(0x8000), addr(0x8fff), BigInteger.ZERO);
		});
		builder.disassemble("0x8000", 16, false);
	}

	private void dbr(int v) throws Exception {
		inTx(program, "DBR", () -> program.getProgramContext().setValue(
			program.getRegister("DBR"), addr(0x8000), addr(0x8fff), BigInteger.valueOf(v)));
	}

	private List<SnesTrampolineScanner.Handler> scan(List<String> notes) {
		return SnesTrampolineScanner.scan(program, notes);
	}

	@Test
	public void unknownDbrKeepsTheLowRamAssumption() {
		List<String> notes = new ArrayList<>();
		List<SnesTrampolineScanner.Handler> h = scan(notes);
		assertEquals(1, h.size());
		Address entry = h.get(0).entry();
		assertEquals(addr(0x9000), entry);
		assertTrue(notes.toString(), notes.toString().contains("0 tracked and agreeing"));
		assertTrue(notes.toString(), notes.toString().contains("3 unknown"));
	}

	@Test
	public void trackedWramDbrAgreesAndStillFinds() throws Exception {
		dbr(0x7e);
		List<String> notes = new ArrayList<>();
		assertEquals(1, scan(notes).size());
		assertTrue(notes.toString(), notes.toString().contains("3 tracked and agreeing"));
	}

	@Test
	public void trackedDbrOutsideLowRamDropsTheStores() throws Exception {
		dbr(0x7f);   // $7F:0100 is not the NMI trampoline's RAM
		List<String> notes = new ArrayList<>();
		assertEquals(0, scan(notes).size());
		assertTrue(notes.toString(), notes.toString().contains("3 tracked and outside low RAM"));
	}

	@Test
	public void trackedRomBankDbrStillMirrorsLowRam() throws Exception {
		dbr(0x01);   // banks $00-$3F mirror the low 8K of WRAM
		assertEquals(1, scan(new ArrayList<>()).size());
	}
}
