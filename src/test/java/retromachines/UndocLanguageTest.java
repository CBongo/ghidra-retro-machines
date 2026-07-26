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

import java.util.Arrays;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;

/**
 * Per-opcode coverage of the undocumented-opcode language variants (bead grm-azg):
 * {@code 6510:LE:16:undoc} and {@code 6502:LE:16:undoc}, plus the absolute-mode port
 * routing fix that landed in {@code 6510:LE:16:default} alongside them.
 * <p>
 * This tier only became reachable in bead grm-2pi -- see {@link AbstractBundledLanguageTest}
 * for why a bundled language is invisible to a plain {@code AbstractGenericTest}. Before
 * that, the only coverage available for these languages was the headless golden suite,
 * which asserts on program-wide behavior rather than on individual opcodes.
 * <p>
 * The instruction semantics themselves are vendored (see {@code NOTICE}); what is genuinely
 * ours, and therefore what these tests concentrate on, is (a) that the variants exist and
 * decode at all, and (b) the PORT/PORTDDR routing layered on top of them, which upstream
 * knows nothing about.
 */
public class UndocLanguageTest extends AbstractBundledLanguageTest {

	private static final String UNDOC_6510 = "6510:LE:16:undoc";
	private static final String UNDOC_6502 = "6502:LE:16:undoc";
	private static final String DEFAULT_6510 = "6510:LE:16:default";

	/** A program in {@code languageId} with zero page and a code block at $8000. */
	private ProgramBuilder builderFor(String languageId) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", languageId);
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		return builder;
	}

	/** Assembles {@code bytes} at $8000 and returns the decoded instruction. */
	private Instruction decode(ProgramBuilder builder, String bytes) throws Exception {
		builder.setBytes("0x8000", bytes, true);
		Instruction instr =
			builder.getProgram().getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("bytes did not disassemble: " + bytes, instr);
		return instr;
	}

	private static String resultObjects(Instruction instr) {
		return Arrays.stream(instr.getResultObjects())
				.map(Object::toString)
				.collect(Collectors.joining(","));
	}

	// ---------------------------------------------------------------- existence

	@Test
	public void undocVariantsResolve() throws Exception {
		for (String id : new String[] { UNDOC_6510, UNDOC_6502 }) {
			ProgramDB program = builderFor(id).getProgram();
			assertEquals(id, program.getLanguage().getLanguageID().getIdAsString());
		}
	}

	// ------------------------------------------------------- undocumented decode

	@Test
	public void representativeUndocumentedOpcodesDecode() throws Exception {
		// One per family, covering both the shared-table forms (SLO/DCP/ISC via OP3) and
		// the explicitly-spelled ones (LAX/SAX), plus the immediate group and JAM.
		String[][] cases = {
			{ "07 10", "SLO" },   // SLO $10   -- ASL memory then ORA
			{ "27 10", "RLA" },   // RLA $10
			{ "47 10", "SRE" },   // SRE $10
			{ "67 10", "RRA" },   // RRA $10
			{ "c7 10", "DCP" },   // DCP $10
			{ "e7 10", "ISC" },   // ISC $10
			{ "87 10", "SAX" },   // SAX $10
			{ "a7 10", "LAX" },   // LAX $10
			{ "0b 42", "ANC" },   // ANC #$42
			{ "4b 42", "ALR" },   // ALR #$42
			{ "6b 42", "ARR" },   // ARR #$42
			{ "cb 42", "SBX" },   // SBX #$42
			{ "eb 42", "SBC" },   // SBC #$42 -- the undocumented alias of $E9
			{ "02", "JAM" },      // JAM/KIL
		};
		for (String[] c : cases) {
			ProgramBuilder builder = builderFor(UNDOC_6510);
			assertEquals("byte(s) " + c[0], c[1], decode(builder, c[0]).getMnemonicString());
		}
	}

	@Test
	public void undocumentedOpcodesStayInvalidInTheDefaultLanguage() throws Exception {
		// The whole point of shipping these as an opt-in variant: the default language must
		// NOT decode them, so speculative disassembly still stops inside data regions.
		ProgramBuilder builder = builderFor(DEFAULT_6510);
		builder.setBytes("0x8000", "07 10", true); // SLO $10
		assertNull("SLO decoded in the default language; the variants are not isolated",
			builder.getProgram().getListing().getInstructionAt(builder.addr("0x8000")));
	}

	@Test
	public void jamHasNoFallthrough() throws Exception {
		// JAM locks the CPU. Modeled as a self-loop, so flow stops here rather than running
		// on through whatever follows -- the one undocumented opcode that HELPS code/data
		// separation.
		Instruction jam = decode(builderFor(UNDOC_6510), "02");
		assertFalse("JAM must not fall through", jam.hasFallthrough());
	}

	@Test
	public void laxLoadsBothAccumulatorAndIndex() throws Exception {
		String written = resultObjects(decode(builderFor(UNDOC_6510), "a7 10")); // LAX $10
		assertTrue("LAX should write A, wrote: " + written, written.contains("A"));
		assertTrue("LAX should write X, wrote: " + written, written.contains("X"));
	}

	@Test
	public void saxSetsNoFlags() throws Exception {
		// SAX stores A&X and is documented to leave every flag alone -- an easy thing for a
		// hand-written spec to get wrong by copying a store-with-flags template.
		String written = resultObjects(decode(builderFor(UNDOC_6510), "87 10")); // SAX $10
		for (String flag : new String[] { "N", "Z", "C", "V" }) {
			assertFalse("SAX must not write " + flag + ", wrote: " + written,
				Arrays.asList(written.split(",")).contains(flag));
		}
	}

	// ------------------------------------------------------------- port routing

	@Test
	public void undocumentedOpcodesRouteZeroPageThroughThePort() throws Exception {
		// $01 reached via zero page. Without these overrides the vendored spec would make
		// SLO $01 a plain memory store in a program where STA $01 is PORT dataflow.
		assertEquals("PORT",
			decode(builderFor(UNDOC_6510), "07 01").getDefaultOperandRepresentation(0)); // SLO $01
		assertEquals("PORT",
			decode(builderFor(UNDOC_6510), "87 01").getDefaultOperandRepresentation(0)); // SAX $01
		assertEquals("PORT",
			decode(builderFor(UNDOC_6510), "a7 01").getDefaultOperandRepresentation(0)); // LAX $01
		assertEquals("PORTDDR",
			decode(builderFor(UNDOC_6510), "87 00").getDefaultOperandRepresentation(0)); // SAX $00
	}

	@Test
	public void undocumentedOpcodesRouteAbsoluteThroughThePort() throws Exception {
		// The same two registers reached the long way: SAX $0001 / LAX $0001. The hardware
		// decodes $0001 and $01 to the identical on-die register.
		assertEquals("PORT",
			decode(builderFor(UNDOC_6510), "8f 01 00").getDefaultOperandRepresentation(0));
		assertEquals("PORT",
			decode(builderFor(UNDOC_6510), "af 01 00").getDefaultOperandRepresentation(0));
		assertEquals("PORT",
			decode(builderFor(UNDOC_6510), "0f 01 00").getDefaultOperandRepresentation(0)); // SLO $0001
	}

	@Test
	public void indexedAccessesToZeroPageOneStayMemory() throws Exception {
		// LAX $01,Y -- the effective address is computed at runtime, so routing it to PORT
		// would be a lie whenever Y is non-zero.
		String operand = decode(builderFor(UNDOC_6510), "b7 01").getDefaultOperandRepresentation(0);
		assertFalse("indexed access must not route to PORT, got: " + operand,
			operand.contains("PORT"));
	}

	// Absolute-mode routing in the DEFAULT language is covered by
	// BundledLanguageVisibilityTest, alongside the rest of that language's port behavior.

	@Test
	public void plainSixFiveOhTwoUndocVariantHasNoPortRouting() throws Exception {
		// 6502:LE:16:undoc is for NMOS 6502 systems with no on-die port, so $01 must stay
		// ordinary memory even though the undocumented opcodes are present.
		Instruction sax = decode(builderFor(UNDOC_6502), "87 01");
		assertEquals("SAX", sax.getMnemonicString());
		assertFalse("6502 variant must not route to PORT, got: " +
			sax.getDefaultOperandRepresentation(0),
			sax.getDefaultOperandRepresentation(0).contains("PORT"));
	}
}
