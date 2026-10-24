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

import java.math.BigInteger;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

/**
 * PHP/PLP brackets (bead grm-9nxj.5.5): a {@code PLP} restores the width its matching
 * {@code PHP} saved, both in {@link W65816WidthEffects}' routine summary and in
 * {@link W65816WidthAnalyzer#matchingPhps}' pairing.
 */
public class W65816PhpPlpTest extends AbstractProgramTest {

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
		setContext("0x8000", "0x8fff", "ctx_EF", 0);
	}

	/** {@code PHP ; REP #$20 ; LDA #$1234 ; PLP ; RTS}: the caller's M survives the call. */
	@Test
	public void bracketedRoutinePreservesTheCallersWidth() throws Exception {
		builder.setBytes("0x8000", "08 c2 20 a9 34 12 28 60", false);
		builder.disassemble("0x8000", 8, true);

		W65816WidthEffects.Effect e = new W65816WidthEffects(program).effect(addr("0x8000"));
		assertEquals("PLP restores what PHP saved: M is inherited on return",
			W65816WidthEffects.INHERITED, e.m().exit());
		assertFalse("REP sets M before the immediate", e.m().needs());
	}

	/** {@code REP #$20 ; PLP ; RTS} with no PHP: the pulled status is unknowable here. */
	@Test
	public void unmatchedPlpLeavesTheWidthUnknown() throws Exception {
		builder.setBytes("0x8000", "c2 20 28 60", false);
		builder.disassemble("0x8000", 4, true);

		W65816WidthEffects.Effect e = new W65816WidthEffects(program).effect(addr("0x8000"));
		assertEquals(W65816WidthEffects.UNKNOWN, e.m().exit());
	}

	/** Nested brackets restore innermost first: the outer PLP returns the entry width. */
	@Test
	public void nestedBracketsUnwindInOrder() throws Exception {
		// PHP ; SEP #$20 ; PHP ; REP #$20 ; PLP ; PLP ; RTS
		builder.setBytes("0x8000", "08 e2 20 08 c2 20 28 28 60", false);
		builder.disassemble("0x8000", 9, true);

		W65816WidthEffects.Effect e = new W65816WidthEffects(program).effect(addr("0x8000"));
		assertEquals(W65816WidthEffects.INHERITED, e.m().exit());
	}

	/** The pairing walks back over an inner bracket to the PHP the outer PLP pulls. */
	@Test
	public void pairingSkipsAnInnerBracket() throws Exception {
		builder.setBytes("0x8000", "08 e2 20 08 c2 20 28 28 60", false);
		builder.disassemble("0x8000", 9, true);

		Set<Instruction> outer = W65816WidthAnalyzer.matchingPhps(program, instructionAt("0x8007"));
		assertNotNull(outer);
		assertEquals(1, outer.size());
		assertEquals(addr("0x8000"), outer.iterator().next().getMinAddress());
		Set<Instruction> inner = W65816WidthAnalyzer.matchingPhps(program, instructionAt("0x8006"));
		assertEquals(addr("0x8003"), inner.iterator().next().getMinAddress());
	}

	/** A PLP some path reaches from a routine entry with no PHP on it cannot be paired. */
	@Test
	public void plpReachedFromAnEntryIsUnpaired() throws Exception {
		// $8000: JSR $8100 ; RTS     $8100: REP #$20 ; PLP ; RTS
		builder.setBytes("0x8000", "20 00 81 60", false);
		builder.setBytes("0x8100", "c2 20 28 60", false);
		builder.disassemble("0x8000", 0x200, true);

		assertNull(W65816WidthAnalyzer.matchingPhps(program, instructionAt("0x8102")));
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
