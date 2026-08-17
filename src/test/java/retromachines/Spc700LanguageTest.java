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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

/**
 * Coverage for the vendored SPC700 language (bead grm-c9d.1), id {@code SPC700:LE:16:retro}.
 * The decode table is SPCdra's, carried over verbatim; see {@code NOTICE} and
 * {@code data/languages/spc700core.sinc}/{@code spc700ops.sinc}.
 * <p>
 * <b>DELIBERATELY does not assert p-code.</b> The semantics in {@code spc700ops.sinc} are
 * known-incorrect and are being rewritten against this file as a diff base (bead
 * grm-c9d.3). Do NOT add a p-code/PcodeOp assertion here to "improve coverage" -- doing so
 * would pin broken behaviour that the rewrite is specifically meant to replace. This class
 * covers only what is sound today: mnemonic text, full operand text, and instruction length
 * (disassembly).
 * <p>
 * Full operand text (via {@link Instruction#toString()}) is pinned deliberately, not
 * incidentally: grm-c9d.3's leading plan restructures the {@code ADDR8}/{@code ADDR16}
 * subtables (splitting them into an address-valued form for data and a dynamic one for jump
 * targets), and those subtables are what supply operand *display*, not just semantics. That
 * rewrite could silently change rendering (e.g. {@code 0x10} vs {@code $10} vs {@code dp})
 * with mnemonic-only assertions never noticing. These assertions are the only thing standing
 * guard against that -- do not weaken them back to mnemonic-only.
 */
public class Spc700LanguageTest extends AbstractBundledLanguageTest {

	private static final String LANGUAGE_ID = "SPC700:LE:16:retro";

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", LANGUAGE_ID);
		builder.createMemory(".ram", "0x0", 0x10000);
		program = builder.getProgram();
	}

	private Instruction decode(String bytes) throws Exception {
		builder.setBytes("0x0200", bytes, true);
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(builder.addr("0x0200"));
		assertNotNull("bytes did not disassemble: " + bytes, instr);
		return instr;
	}

	@Test
	public void languageResolves() {
		assertEquals(LANGUAGE_ID, program.getLanguage().getLanguageID().getIdAsString());
		assertEquals("SPC700", program.getLanguage().getProcessor().toString());
	}

	@Test
	public void movAImmediate() throws Exception {
		// E8 xx -> MOV A,#imm ; spc700ops.sinc: ":MOV A,\"#\"^imm8 is op=0xE8 & A; imm8"
		Instruction instr = decode("e8 05");
		assertEquals("MOV", instr.getMnemonicString());
		assertEquals("MOV A,#0x5", instr.toString());
		assertEquals(2, instr.getLength());
	}

	@Test
	public void movADirectPage() throws Exception {
		// E4 xx -> MOV A,dp ; spc700ops.sinc: ":MOV A,ADDR8 is op=0xE4 & A; ADDR8"
		// ADDR8's default display of imm8=0x10 is the bare hex value "0x10" (no dp/$ marker).
		Instruction instr = decode("e4 10");
		assertEquals("MOV", instr.getMnemonicString());
		assertEquals("MOV A,0x10", instr.toString());
		assertEquals(2, instr.getLength());
	}

	@Test
	public void movAAbsolute() throws Exception {
		// E5 lo hi -> MOV A,!abs ; spc700ops.sinc: ":MOV A,\" !\"^ADDR16 is op=0xE5 & A; ADDR16"
		// The "!" literal from the constructor's display piece marks the absolute (16-bit) form.
		Instruction instr = decode("e5 34 12");
		assertEquals("MOV", instr.getMnemonicString());
		assertEquals("MOV A,!0x1234", instr.toString());
		assertEquals(3, instr.getLength());
	}

	@Test
	public void incA() throws Exception {
		// BC -> INC A ; spc700ops.sinc: ":INC A is op=0xBC & A { A = A + 1; }"
		Instruction instr = decode("bc");
		assertEquals("INC", instr.getMnemonicString());
		assertEquals("INC A", instr.toString());
		assertEquals(1, instr.getLength());
	}

	@Test
	public void bcsBranchTarget() throws Exception {
		// B0 xx -> BCS raddr8 ; spc700ops.sinc: ":BCS RADDR8 is op=0xB0; RADDR8"
		// RADDR8's addr = inst_next + simm8. inst_next of "0200: B0 xx" is 0202.
		// simm8 = 0x10 (16) -> target = 0x0212.
		Instruction instr = decode("b0 10");
		assertEquals("BCS", instr.getMnemonicString());
		assertEquals("BCS 0x0212", instr.toString());
		assertEquals(2, instr.getLength());
	}

	@Test
	public void tcall() throws Exception {
		// 01 -> TCALL 0 ; op_lo=0x1 & op_hi -- opcode byte = (op_hi<<4)|1, op_hi=0 here.
		// op_hi has no explicit print format in spc700.sinc's token definition, so it prints
		// as the default hex token value "0x0" rather than the decimal "0" a human would write.
		Instruction instr = decode("01");
		assertEquals("TCALL", instr.getMnemonicString());
		assertEquals("TCALL 0x0", instr.toString());
		assertEquals(1, instr.getLength());
	}

	@Test
	public void set1() throws Exception {
		// 02 -> SET1 dp.0 ; op_lo=0x2 & bbb=0 & aaa=0 -> byte 0x02
		// spc700ops.sinc: ":SET1 ADDR8^\".\"aaa is op_lo=0x2 & bbb=0 & aaa; ADDR8" ->
		// ADDR8 display "0x10" then literal "." then aaa's default hex display "0x0".
		Instruction instr = decode("02 10");
		assertEquals("SET1", instr.getMnemonicString());
		assertEquals("SET1 0x10.0x0", instr.toString());
		assertEquals(2, instr.getLength());
	}

	@Test
	public void bbs() throws Exception {
		// 03 -> BBS dp.0,rel ; op_lo=0x3 & bbb=0 & aaa=0 -> byte 0x03
		// spc700ops.sinc: ":BBS ADDR8^\",\"^aaa,RADDR8 is op_lo=0x3 & bbb=0 & aaa; ADDR8;
		// RADDR8" -> ADDR8 "0x10", literal ",", aaa "0x0", operand-separator ",", then the
		// RADDR8 branch target: inst_next of "0200: 03 10 05" (length 3) is 0203, simm8=0x05
		// -> target 0x0208.
		Instruction instr = decode("03 10 05");
		assertEquals("BBS", instr.getMnemonicString());
		assertEquals("BBS 0x10,0x0,0x0208", instr.toString());
		assertEquals(3, instr.getLength());
	}
}
