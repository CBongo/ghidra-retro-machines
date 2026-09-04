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
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.task.TaskMonitor;

/**
 * Acceptance for the bundled 65816 language (beads grm-9nxj.1 and grm-9nxj.2):
 * {@code 65816:LE:24:retro} resolves, decodes at both accumulator widths, and -- the point of
 * the exercise -- yields immediates as CONSTANTS.
 * <p>
 * The constant assertions are the ones that matter. Upstream models every operand, immediates
 * included, as a reference dereferenced out of the instruction stream, so {@code LDA #$12}
 * emitted a {@code LOAD} of the byte at {@code inst_start+1} instead of the value {@code 0x12}.
 * Upstream files that as a cosmetic complaint about operand rendering; here it defeats
 * {@code SymbolicPropogator} and therefore every bank-value recovery path in this extension,
 * whose central idiom is {@code LDA #bank} / {@code STA <mechanism>}. Asserting on the p-code
 * rather than on the listing text is deliberate: the rendering was only ever the symptom.
 * <p>
 * Width is established by writing the context register directly, which is what a loader (or
 * the per-entry-point inference of bead grm-9nxj.5) will do, and what the upstream project
 * tells users to do by hand through the GUI's "Processor Options...". One case drives the
 * width through {@code REP} instead, to prove the spec's {@code globalset} stamping works.
 */
public class W65816LanguageTest extends AbstractBundledLanguageTest {

	private static final String LANGUAGE_ID = "65816:LE:24:retro";

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", LANGUAGE_ID);
		builder.createMemory(".text", "0x8000", 0x1000);
		program = builder.getProgram();
	}

	@Test
	public void bundledLanguageResolves() {
		assertEquals(LANGUAGE_ID, program.getLanguage().getLanguageID().getIdAsString());
		assertEquals("65816", program.getLanguage().getProcessor().toString());
	}

	/**
	 * The processor spec's context defaults. Upstream ships no {@code <context_data>} at all,
	 * which left the context register all-zero -- native mode with 16-bit registers -- while a
	 * 65816 resets into emulation mode. An 8-bit immediate here is that default asserting
	 * itself: {@code A9 12} must be two bytes, not three.
	 */
	@Test
	public void resetsIntoEmulationModeWithEightBitRegisters() throws Exception {
		builder.setBytes("0x8000", "a9 12 ea", true); // LDA #$12 ; NOP

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("LDA #$12 did not disassemble", lda);
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals("immediate should be one byte under the emulation-mode default", 2,
			lda.getLength());

		Instruction nop = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("the following NOP did not decode -- the LDA mis-lengthed", nop);
		assertEquals("NOP", nop.getMnemonicString());
	}

	@Test
	public void eightBitImmediateIsAConstantNotALoad() throws Exception {
		builder.setBytes("0x8000", "a9 12", true); // LDA #$12

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull(lda);
		assertNoLoad(lda);
		assertTrue("the immediate value 0x12 is not present as a constant in the p-code: " +
			pcodeText(lda), mentionsConstant(lda, 0x12));
	}

	@Test
	public void sixteenBitImmediateIsAConstantNotALoad() throws Exception {
		setContext("0x8000", "0x8004", "ctx_EF", 0);
		setContext("0x8000", "0x8004", "ctx_MF", 0);
		builder.setBytes("0x8000", "a9 34 12", true); // LDA #$1234

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("LDA #$1234 did not disassemble", lda);
		assertEquals("a 16-bit accumulator takes a two-byte immediate", 3, lda.getLength());
		assertNoLoad(lda);
		assertTrue("the immediate value 0x1234 is not present as a constant in the p-code: " +
			pcodeText(lda), mentionsConstant(lda, 0x1234));
	}

	/**
	 * {@code REP #$20} clearing the M flag must widen the FOLLOWING instruction, which is the
	 * spec's {@code globalset} stamping doing its job. Native mode is established first,
	 * because in emulation mode {@code REP} deliberately does not touch M/X -- the hardware
	 * forces both to 1 there, and the spec models that with separate constructors.
	 */
	@Test
	public void repWidensTheFollowingImmediate() throws Exception {
		setContext("0x8000", "0x8010", "ctx_EF", 0);
		builder.setBytes("0x8000", "c2 20 a9 34 12", true); // REP #$20 ; LDA #$1234

		Instruction rep = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("REP #$20 did not disassemble", rep);
		assertEquals("REP", rep.getMnemonicString());

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("no instruction after REP -- context did not flow", lda);
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals("REP #$20 should have widened the accumulator", 3, lda.getLength());
	}

	/**
	 * The acceptance criterion this whole exercise exists for (bead grm-9nxj.2): not merely that
	 * the immediate is a constant in the p-code, but that {@code SymbolicPropogator} -- the
	 * machinery {@code StoredValueScanner} and the {@code BoardBankAnalyzer} strategies are built
	 * on -- actually recovers the value across the store. {@code LDA #bank} / {@code STA
	 * <mechanism>} is the idiom every bank-switch strategy keys on, so this is the shape that
	 * decides whether the SNES gets bank recovery at all.
	 *
	 * <p>Against upstream's spec the accumulator here would hold the result of a LOAD from the
	 * instruction stream, and the propagator would report no value.
	 */
	@Test
	public void symbolicPropogatorRecoversABankValueFromAnImmediate() throws Exception {
		builder.setBytes("0x8000", "a9 05", true);    // LDA #$05
		builder.setBytes("0x8002", "8d 00 21", true); // STA $2100

		SymbolicPropogator propagator = new SymbolicPropogator(program);
		AddressSet body = new AddressSet(builder.addr("0x8000"), builder.addr("0x8004"));
		propagator.flowConstants(builder.addr("0x8000"), body, null, true, TaskMonitor.DUMMY);

		Value accumulator = propagator.getRegisterValue(builder.addr("0x8002"),
			program.getLanguage().getRegister("A"));
		assertNotNull("the propagator recovered no accumulator value at the store -- the " +
			"immediate is still opaque to it", accumulator);
		assertEquals(0x05, accumulator.getValue());
	}

	/**
	 * The 65816's own addressing modes, which a 6502-derived language would not have: a 24-bit
	 * long operand and a block move. Both are heavily used by real code (bead grm-9wbv measured
	 * 152,073 long-form operands and 9,504 block moves across the SNES disassembly corpus).
	 */
	@Test
	public void decodesSixtyFiveEightSixteenOnlyAddressing() throws Exception {
		builder.setBytes("0x8000", "af 00 20 7e", true); // LDA $7E2000
		builder.setBytes("0x8004", "54 7e 7e", true);    // MVN $7E,$7E

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("long-addressed LDA did not disassemble", lda);
		assertEquals("LDA", lda.getMnemonicString());
		assertEquals(4, lda.getLength());

		Instruction mvn = program.getListing().getInstructionAt(builder.addr("0x8004"));
		assertNotNull("MVN did not disassemble", mvn);
		assertEquals("MVN", mvn.getMnemonicString());
		assertEquals(3, mvn.getLength());
	}

	/**
	 * Upstream had CPY's two width variants selected by SWAPPED context constraints, so with
	 * 8-bit index registers the 16-bit body ran -- comparing a 16-bit Y against a two-byte read
	 * whose second byte is the next opcode. CPX, defined immediately above it, was always
	 * right. Unswapped as part of grm-9nxj.2; this pins it.
	 */
	@Test
	public void cpyUsesTheEightBitBodyWhenIndexRegistersAreEightBit() throws Exception {
		setContext("0x8000", "0x8004", "ctx_EF", 0);
		setContext("0x8000", "0x8004", "ctx_XF", 1);
		builder.setBytes("0x8000", "c0 05", true); // CPY #$05

		Instruction cpy = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("CPY #$05 did not disassemble", cpy);
		assertEquals("CPY", cpy.getMnemonicString());
		assertEquals(2, cpy.getLength());
		assertNoLoad(cpy);
		assertTrue("CPY should read the low half of Y under XF=1, not all 16 bits: " +
			pcodeText(cpy), readsRegister(cpy, "YLow"));
		assertFalse("CPY read the full 16-bit Y despite 8-bit index registers: " +
			pcodeText(cpy), readsRegister(cpy, "Y"));
	}

	private void setContext(String start, String end, String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull("no context field named " + field, register);
		int tx = program.startTransaction("set " + field);
		try {
			program.getProgramContext()
					.setValue(register, builder.addr(start), builder.addr(end),
						BigInteger.valueOf(value));
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/**
	 * Whether any p-code input is a read of exactly this register. Matching on the varnode's
	 * address and size rather than on rendered text: {@link PcodeOp#toString} prints varnodes
	 * positionally ({@code (register, 0x14, 1)}), so a name never appears in it.
	 */
	private boolean readsRegister(Instruction instruction, String registerName) {
		Register register = program.getLanguage().getRegister(registerName);
		assertNotNull("no register named " + registerName, register);
		for (PcodeOp op : instruction.getPcode()) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				if (register.getAddress().equals(op.getInput(i).getAddress()) &&
					register.getMinimumByteSize() == op.getInput(i).getSize()) {
					return true;
				}
			}
		}
		return false;
	}

	private static void assertNoLoad(Instruction instruction) {
		for (PcodeOp op : instruction.getPcode()) {
			assertFalse(instruction.getMnemonicString() +
				" still dereferences its operand out of the instruction stream: " +
				pcodeText(instruction), op.getOpcode() == PcodeOp.LOAD);
		}
	}

	private static boolean mentionsConstant(Instruction instruction, long value) {
		for (PcodeOp op : instruction.getPcode()) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				if (op.getInput(i).isConstant() && op.getInput(i).getOffset() == value) {
					return true;
				}
			}
		}
		return false;
	}

	private static String pcodeText(Instruction instruction) {
		StringBuilder text = new StringBuilder();
		for (PcodeOp op : instruction.getPcode()) {
			text.append("\n  ").append(op);
		}
		return text.toString();
	}
}
