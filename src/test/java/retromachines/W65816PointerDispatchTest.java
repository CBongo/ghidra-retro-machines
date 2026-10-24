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

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.lang.Register;

/**
 * {@link W65816JumpTableAnalyzer#pointerDispatch}: the pointer-variable dispatch shapes measured
 * on the snes-analysis rows (bead grm-9nxj.5.8).
 */
public class W65816PointerDispatchTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
		setContext("0x8000", "0x8fff", "ctx_EF", 0);
	}

	private W65816JumpTableAnalyzer.Dispatch dispatchAt(String bytes, String jumpAt)
			throws Exception {
		builder.setBytes("0x8000", bytes, false);
		builder.disassemble("0x8000", 0x40, false);
		return W65816JumpTableAnalyzer.pointerDispatch(program.getListing(), instructionAt(jumpAt));
	}

	/** FF3 $C0:77FE: REP #$20 / LDA long,X / STA $2D / SEP #$20 / JMP ($002D). */
	@Test
	public void sixteenBitLoadAndStore() throws Exception {
		var d = dispatchAt("c2 20 bf 00 81 00 85 2d e2 20 6c 2d 00", "0x800a");
		assertNotNull(d);
		assertEquals(addr("0x8100"), d.table());
		assertEquals(0L, d.targetBank());
		assertEquals(addr("0x8002"), d.index().getMinAddress());
	}

	/** FF2 $00:E0D0: byte pairs into direct page $3D/$3E, jumped through ($063D): D=$0600. */
	@Test
	public void bytePairsMatchDirectPageByLowByte() throws Exception {
		var d = dispatchAt("bd 00 81 85 3d bd 01 81 85 3e 6c 3d 06", "0x800a");
		assertNotNull(d);
		assertEquals(addr("0x8100"), d.table());
	}

	/** FF2 $03:869C: byte pairs plus LDA #$03 / STA ptr+2 / JML [ptr]: targets in bank $03. */
	@Test
	public void longPointerTakesTheConstantBank() throws Exception {
		var d = dispatchAt("bd 00 81 85 80 bd 01 81 85 81 a9 03 85 82 dc 80 00", "0x800e");
		assertNotNull(d);
		assertEquals(addr("0x8100"), d.table());
		assertEquals(0x030000L, d.targetBank());
	}

	/** INX between the two loads: they read different entries, so it is not one word table. */
	@Test
	public void indexChangingBetweenLoadsIsNotMatched() throws Exception {
		assertNull(dispatchAt("bd 00 81 85 3d e8 bd 01 81 85 3e 6c 3d 00", "0x800b"));
	}

	/** The high byte loaded from somewhere other than table+1. */
	@Test
	public void splitTablesAreNotMatched() throws Exception {
		assertNull(dispatchAt("bd 00 81 85 3d bd 00 82 85 3e 6c 3d 00", "0x800a"));
	}

	/** FF3 $C2:47F8: LDA $3A6E / BEQ skip / TAX / JMP ($80F5,X) never reads entry 0. */
	@Test
	public void beqGuardedIndexStartsAtTheSecondEntry() throws Exception {
		builder.setBytes("0x8000", "ad 6e 3a f0 03 aa 7c f5 80", false);
		builder.disassemble("0x8000", 0x20, false);
		var d = W65816JumpTableAnalyzer.dispatchOf(program.getListing(), instructionAt("0x8006"));
		assertEquals(addr("0x80f7"), d.table());
	}

	/** Without the guard the table starts where the operand says. */
	@Test
	public void unguardedIndexStartsAtTheFirstEntry() throws Exception {
		builder.setBytes("0x8000", "ad 6e 3a aa 7c f5 80", false);
		builder.disassemble("0x8000", 0x20, false);
		var d = W65816JumpTableAnalyzer.dispatchOf(program.getListing(), instructionAt("0x8004"));
		assertEquals(addr("0x80f5"), d.table());
	}

	private void setContext(String start, String end, String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull("no context field named " + field, register);
		inTx(program, "set " + field, () -> {
			program.getProgramContext()
					.setValue(register, builder.addr(start), builder.addr(end),
						BigInteger.valueOf(value));
		});
	}
}
