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

	/**
	 * grm-9nxj.46 (FF3 {@code $C2:4F08}): {@code PHX ; PHP ; REP #$10 ; PLP ; PLX ; RTS} at X=1.
	 * The PLX after the PLP is one byte at either width, so its decode never "needed" X, but it
	 * runs at the X the PHP saved and pulls one byte; left at the REP's X=0 it pulled two.
	 */
	@Test
	public void plpContinuationGetsTheSavedWidthEvenWhenLengthsAgree() throws Exception {
		setContext("0x8000", "0x8fff", "ctx_XF", 1);
		setContext("0x8000", "0x8fff", "ctx_MF", 1);
		builder.setBytes("0x8000", "da 08 c2 10 28 fa 60", false);
		builder.disassemble("0x8000", 7, true);
		Register x = program.getRegister("ctx_XF");
		assertEquals("precondition: the language decodes the PLX at the REP's width",
			BigInteger.ZERO, program.getListing().getInstructionAt(addr("0x8005")).getValue(x, false));

		inTx(program, "analyze", () -> new W65816WidthAnalyzer().added(program,
			new ghidra.program.model.address.AddressSet(addr("0x8000"), addr("0x8006")),
			ghidra.util.task.TaskMonitor.DUMMY, new ghidra.app.util.importer.MessageLog()));

		Instruction plx = program.getListing().getInstructionAt(addr("0x8005"));
		assertNotNull(plx);
		assertEquals("PLP restored the X the PHP saved", BigInteger.ONE, plx.getValue(x, false));
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

	/**
	 * grm-9nxj.53, F-Zero {@code $03:8070}: {@code PHP ; JMP ($8100,X)} into handlers that
	 * each {@code PLP ; RTL}. The resolved targets are followed with the PHP still saved, so M
	 * is inherited on return; unresolved, the routine had no return at all.
	 */
	@Test
	public void resolvedDispatchIsFollowedIntoItsHandlers() throws Exception {
		builder.setBytes("0x8000", "08 e2 20 7c 00 81", false);   // PHP ; SEP #$20 ; JMP ($8100,X)
		builder.setBytes("0x8200", "28 6b", false);               // PLP ; RTL
		builder.setBytes("0x8210", "ea 28 6b", false);            // NOP ; PLP ; RTL
		builder.disassemble("0x8000", 6, true);
		builder.disassemble("0x8200", 2, true);
		builder.disassemble("0x8210", 3, true);
		W65816WidthEffects.Effect unresolved =
			new W65816WidthEffects(program).effect(addr("0x8000"));
		assertEquals(W65816WidthEffects.NO_RETURN, unresolved.m().exit());

		inTx(program, "refs", () -> {
			for (String t : new String[] { "0x8200", "0x8210" }) {
				program.getReferenceManager().addMemoryReference(addr("0x8003"), addr(t),
					ghidra.program.model.symbol.RefType.COMPUTED_JUMP,
					ghidra.program.model.symbol.SourceType.ANALYSIS, 0);
			}
		});
		W65816WidthEffects.Effect e = new W65816WidthEffects(program).effect(addr("0x8000"));
		assertEquals(W65816WidthEffects.INHERITED, e.m().exit());
	}

	/**
	 * grm-9nxj.54, F-Zero's far-call callees: some returns preserve M, the rest {@code SEP #$20}
	 * first. Mixed as a summary, but one value (1) for a caller at M=1, and two for one at M=0.
	 */
	@Test
	public void preservedOrSetExitResolvesAgainstTheCallersWidth() throws Exception {
		builder.setBytes("0x8000", "d0 02 e2 20 6b", false);   // BNE +2 ; SEP #$20 ; RTL
		builder.disassemble("0x8000", 5, true);

		W65816WidthEffects.Flag m = new W65816WidthEffects(program).effect(addr("0x8000")).m();
		assertEquals(W65816WidthEffects.UNKNOWN, m.exit());
		assertEquals(1, m.knownAfter(1));
		assertEquals(-1, m.knownAfter(0));
	}

	/** A caller of that routine forks at the call, so its own outcomes stay {inherited, 1}. */
	@Test
	public void callIntoAPreservedOrSetRoutineForksTheCallersPath() throws Exception {
		builder.setBytes("0x8100", "d0 02 e2 20 60", false);   // BNE +2 ; SEP #$20 ; RTS
		builder.setBytes("0x8000", "20 00 81 60", false);      // JSR $8100 ; RTS
		builder.disassemble("0x8100", 5, true);
		builder.disassemble("0x8000", 4, true);

		W65816WidthEffects.Flag m = new W65816WidthEffects(program).effect(addr("0x8000")).m();
		assertEquals(W65816WidthEffects.bit(W65816WidthEffects.INHERITED) |
			W65816WidthEffects.bit(1), m.outcomes());
		assertEquals(1, m.knownAfter(1));
	}

	/**
	 * F-Zero {@code $03:94CF PHP / ... / JMP $95D6}, the JMP carrying a CALL_RETURN override,
	 * into a {@code PLP / RTL} epilogue: walked on with the PHP still saved, so M is inherited.
	 * Summarized alone, the epilogue's PLP pulled a status it never saw (UNKNOWN).
	 */
	@Test
	public void callReturnOverriddenJmpIntoASharedEpilogueKeepsThePhpStack() throws Exception {
		builder.setBytes("0x8000", "08 e2 20 4c 00 82", false);   // PHP ; SEP #$20 ; JMP $8200
		builder.setBytes("0x8200", "28 6b", false);               // PLP ; RTL
		builder.disassemble("0x8000", 6, true);
		builder.disassemble("0x8200", 2, true);
		inTx(program, "override", () -> program.getListing().getInstructionAt(addr("0x8003"))
				.setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN));

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
