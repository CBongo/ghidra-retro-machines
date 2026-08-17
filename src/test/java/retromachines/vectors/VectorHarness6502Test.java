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
package retromachines.vectors;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

import retromachines.vectors.VectorRunner.CaseResult;

/**
 * Proves the {@link VectorRunner}/{@link VectorParser} harness (bead grm-c9d.2) against
 * Ghidra's stock {@code 6502:LE:16:default} -- deliberately NOT against SPC700, which is being
 * vendored in parallel (bead grm-c9d.1) and is not assumed to exist here. A handful of
 * hand-written vectors, in the exact upstream SingleStepTests JSON shape, stand in for the real
 * suite.
 *
 * <p>{@code 6502:LE:16:default} resolves from a plain {@code AbstractGenericTest} with no
 * bundled-module grafting (see {@code AbstractBundledLanguageTest}'s javadoc for why that
 * distinction matters and when the bundled variant is needed instead -- SPC700's own vector
 * tests will need it once grm-c9d.1 lands).
 *
 * <p>Deliberately avoids the flag registers (N/V/B/D/I/Z/C on 6502 are separate one-byte
 * registers, not a packed status byte the way SPC700's PSW is) -- exercising
 * {@link FlagLayout} decomposition is {@link OpcodeBaselineTest}'s job, in isolation from any
 * real emulation.
 */
public class VectorHarness6502Test extends AbstractGenericTest {

	private static final String LANGUAGE_ID = "6502:LE:16:default";

	/**
	 * Four vectors in upstream SingleStepTests JSON shape: LDA #imm (twice, exercising both a
	 * nonzero and a zero-page store), INX, and TAX. Register field names deliberately use the
	 * suite convention ({@code pc,a,x,y,s}) rather than any project-specific naming, since the
	 * whole point of {@link VectorParser} is not caring what a suite calls its registers.
	 */
	private static final String VECTORS_JSON = """
		[
		  {"name":"a9-lda-imm-nonzero",
		   "initial":{"pc":4096,"a":0,"x":0,"y":0,"s":255,"ram":[[4096,169],[4097,5]]},
		   "final":  {"pc":4098,"a":5,"x":0,"y":0,"s":255,"ram":[[4096,169],[4097,5]]}},
		  {"name":"a9-lda-imm-zero",
		   "initial":{"pc":8192,"a":255,"x":0,"y":0,"s":255,"ram":[[8192,169],[8193,0]]},
		   "final":  {"pc":8194,"a":0,"x":0,"y":0,"s":255,"ram":[[8192,169],[8193,0]]}},
		  {"name":"e8-inx",
		   "initial":{"pc":4096,"a":0,"x":127,"y":0,"s":255,"ram":[[4096,232]]},
		   "final":  {"pc":4097,"a":0,"x":128,"y":0,"s":255,"ram":[[4096,232]]}},
		  {"name":"aa-tax",
		   "initial":{"pc":4096,"a":66,"x":0,"y":0,"s":255,"ram":[[4096,170]]},
		   "final":  {"pc":4097,"a":66,"x":66,"y":0,"s":255,"ram":[[4096,170]]}},
		  {"name":"85-sta-zp",
		   "initial":{"pc":4096,"a":153,"x":0,"y":0,"s":255,
		              "ram":[[4096,133],[4097,16],[16,0]]},
		   "final":  {"pc":4098,"a":153,"x":0,"y":0,"s":255,"ram":[[16,153]]}}
		]
		""";

	private VectorRunner newRunner() throws Exception {
		Language language = new ProgramBuilder("Test", LANGUAGE_ID).getProgram().getLanguage();
		Map<String, Register> registerMap = new LinkedHashMap<>();
		registerMap.put("pc", language.getRegister("PC"));
		registerMap.put("a", language.getRegister("A"));
		registerMap.put("x", language.getRegister("X"));
		registerMap.put("y", language.getRegister("Y"));
		registerMap.put("s", language.getRegister("S"));
		return new VectorRunner(language, registerMap);
	}

	@Test
	public void handWrittenVectorsPassAgainstStock6502() throws Exception {
		VectorRunner runner = newRunner();
		List<VectorCase> cases = VectorParser.parse(new StringReader(VECTORS_JSON));
		assertTrue("expected at least one hand-written vector", cases.size() >= 4);
		for (VectorCase c : cases) {
			CaseResult result = runner.run(c);
			assertTrue(result.toString(), result.pass());
		}
	}

	/**
	 * Verification step 4 of the grm-c9d.2 bead spec: a harness nobody has seen fail is not a
	 * harness. Deliberately corrupts a vector's expected final register value and confirms the
	 * runner reports a specific, correctly-named mismatch rather than silently passing.
	 */
	@Test
	public void harnessDetectsACorruptedExpectation() throws Exception {
		VectorRunner runner = newRunner();
		List<VectorCase> cases = VectorParser.parse(new StringReader(VECTORS_JSON));
		VectorCase original = cases.get(0); // a9-lda-imm-nonzero: real final a = 5
		Map<String, Integer> corruptedFinal = new LinkedHashMap<>(original.finalRegs());
		corruptedFinal.put("a", 6); // wrong on purpose -- LDA #$05 cannot leave A = 6
		VectorCase corrupted = new VectorCase(original.name() + "-corrupted",
			original.initialRegs(), original.initialRam(), corruptedFinal, original.finalRam());

		CaseResult result = runner.run(corrupted);
		assertFalse("corrupted vector must be reported as a failure", result.pass());
		assertTrue("expected an 'A' mismatch naming both values, got: " + result.mismatches(),
			result.mismatches().stream()
					.anyMatch(m -> m.startsWith("A ") && m.contains("0x5") && m.contains("0x6")));

		// And the harness must still be right about everything it did NOT corrupt: the
		// once-corrupted run's mismatch list is exactly the one field we changed, not a cascade.
		assertTrue("corrupting only 'a' must not also report unrelated mismatches: " +
			result.mismatches(), result.mismatches().size() == 1);
	}

	/**
	 * Same idea, but on the RAM side: {@code STA $10} must write $99 to zero page $10;
	 * corrupting that expectation must be caught with an address-qualified message, not confused
	 * with a register mismatch.
	 */
	@Test
	public void harnessDetectsACorruptedRamExpectation() throws Exception {
		VectorRunner runner = newRunner();
		List<VectorCase> cases = VectorParser.parse(new StringReader(VECTORS_JSON));
		VectorCase original = cases.get(4); // 85-sta-zp: real final ram[0x10] = 0x99
		List<VectorCase.RamByte> corruptedRam =
			List.of(new VectorCase.RamByte(0x10, 0x42)); // wrong on purpose
		VectorCase corrupted = new VectorCase(original.name() + "-corrupted",
			original.initialRegs(), original.initialRam(), original.finalRegs(), corruptedRam);

		CaseResult result = runner.run(corrupted);
		assertFalse("corrupted RAM vector must be reported as a failure", result.pass());
		assertTrue("expected a $10 mismatch naming both values, got: " + result.mismatches(),
			result.mismatches().stream()
					.anyMatch(m -> m.startsWith("$10 ") && m.contains("0x99") && m.contains("0x42")));
	}
}
