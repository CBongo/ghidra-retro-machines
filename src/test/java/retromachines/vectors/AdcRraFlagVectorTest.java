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

import static org.junit.Assert.assertTrue;

import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

import retromachines.AbstractBundledLanguageTest;
import retromachines.vectors.VectorRunner.CaseResult;

/**
 * Tier-2 p-code vector coverage (bead grm-o9k) for the ADC carry-out/overflow fix in
 * {@code data/languages/6502core.sinc} and its mirror in RRA
 * ({@code data/languages/6510_illegal.sinc}). Reuses the {@link VectorRunner}/{@link
 * VectorParser} harness established for SPC700 (bead grm-c9d.2) exactly as anticipated in
 * {@link VectorRunner}'s class doc -- same class, a different register map and language id.
 *
 * <p>Before this fix, {@code ADC}/{@code RRA} computed {@code C = carry(A, op1)} <em>before</em>
 * folding in the carry-in, dropping a carry-out that arises only from the carry-in, and then set
 * {@code V = C} -- aliasing signed overflow to that (already wrong) unsigned carry. Every case
 * below independently pins {@code A}, {@code C}, and {@code V} against the standard 6502 ADC
 * truth table, so a regression back to either bug fails a specific assertion rather than a vague
 * "something changed".
 *
 * <p>ADC is exercised against {@code 6510:LE:16:default} -- the fixed macro body lives in
 * {@code 6502core.sinc}, shared byte-for-byte by all three bundled languages named in grm-o9k's
 * scope, so one representative language suffices for the ADC opcode itself. RRA only exists in
 * the undocumented-opcode variants, so it is exercised against {@code 6510:LE:16:undoc} (the
 * same variant {@code UndocLanguageTest} uses), via zero-page addressing so the ROR-then-ADC
 * write-back is also observable.
 */
public class AdcRraFlagVectorTest extends AbstractBundledLanguageTest {

	private static final String DEFAULT_6510 = "6510:LE:16:default";
	private static final String UNDOC_6510 = "6510:LE:16:undoc";

	/**
	 * ADC #imm ($69) at $8000, four cases from the standard 6502 truth table:
	 * <ul>
	 * <li>{@code adc-carry-in-produces-carry-out}: A=$FF, op=$00, C=1 -&gt; A=$00, C=1, V=0.
	 *     The repro for bug (1): folding {@code tmpC} into a single {@code A + op1 + tmpC}
	 *     computes {@code carry($FF,$00)=0} and clears C, but the carry-in alone overflows.
	 * <li>{@code adc-signed-overflow-no-carry}: A=$50, op=$50, C=0 -&gt; A=$A0, C=0, V=1. The
	 *     repro for bug (2): no unsigned carry, but +80+80 overflows signed into negative.
	 * <li>{@code adc-carry-and-overflow-both-set}: A=$D0, op=$90, C=0 -&gt; A=$60, C=1, V=1.
	 *     Both flags set together -- makes sure the fix does not overcorrect into never
	 *     setting both at once.
	 * <li>{@code adc-carry-set-overflow-clear}: A=$FF, op=$FF, C=0 -&gt; A=$FE, C=1, V=0. The
	 *     mirror of the previous case: unsigned carry with NO signed overflow (-1 + -1 = -2,
	 *     representable), proving C and V are no longer aliased in either direction.
	 * </ul>
	 *
	 * <p>Every case expecting {@code V=0} starts from {@code v:1}, so it pins that V is actively
	 * CLEARED rather than merely left alone. A case starting from {@code v:0} cannot tell those
	 * apart, and the old {@code V = C} bug would still pass one.
	 */
	private static final String ADC_VECTORS_JSON = """
		[
		  {"name":"adc-carry-in-produces-carry-out",
		   "initial":{"pc":32768,"a":255,"c":1,"v":1,"ram":[[32768,105],[32769,0]]},
		   "final":  {"pc":32770,"a":0,"c":1,"v":0,"ram":[[32768,105],[32769,0]]}},
		  {"name":"adc-signed-overflow-no-carry",
		   "initial":{"pc":32768,"a":80,"c":0,"v":0,"ram":[[32768,105],[32769,80]]},
		   "final":  {"pc":32770,"a":160,"c":0,"v":1,"ram":[[32768,105],[32769,80]]}},
		  {"name":"adc-carry-and-overflow-both-set",
		   "initial":{"pc":32768,"a":208,"c":0,"v":0,"ram":[[32768,105],[32769,144]]},
		   "final":  {"pc":32770,"a":96,"c":1,"v":1,"ram":[[32768,105],[32769,144]]}},
		  {"name":"adc-carry-set-overflow-clear",
		   "initial":{"pc":32768,"a":255,"c":0,"v":1,"ram":[[32768,105],[32769,255]]},
		   "final":  {"pc":32770,"a":254,"c":1,"v":0,"ram":[[32768,105],[32769,255]]}}
		]
		""";

	/**
	 * RRA $10 ($67 10) at $8000, the same four truth-table points as {@link #ADC_VECTORS_JSON}
	 * but reached through ROR-then-ADC: the pre-rotate byte at $10 and the incoming C are chosen
	 * so the post-rotate value and the ROR's carry-out reproduce the exact same (A, op1, tmpC)
	 * triple ADC sees above -- see the class doc. $10's final value is also asserted, proving the
	 * ROR write-back landed before the ADC half ran.
	 *
	 * <p>As in the ADC set, every case expecting {@code V=0} starts from {@code v:1}, pinning that
	 * V is actively cleared rather than merely left alone.
	 */
	private static final String RRA_VECTORS_JSON = """
		[
		  {"name":"rra-carry-in-produces-carry-out",
		   "initial":{"pc":32768,"a":255,"c":0,"v":1,"ram":[[32768,103],[32769,16],[16,1]]},
		   "final":  {"pc":32770,"a":0,"c":1,"v":0,"ram":[[16,0]]}},
		  {"name":"rra-signed-overflow-no-carry",
		   "initial":{"pc":32768,"a":80,"c":0,"v":0,"ram":[[32768,103],[32769,16],[16,160]]},
		   "final":  {"pc":32770,"a":160,"c":0,"v":1,"ram":[[16,80]]}},
		  {"name":"rra-carry-and-overflow-both-set",
		   "initial":{"pc":32768,"a":208,"c":1,"v":0,"ram":[[32768,103],[32769,16],[16,32]]},
		   "final":  {"pc":32770,"a":96,"c":1,"v":1,"ram":[[16,144]]}},
		  {"name":"rra-carry-set-overflow-clear",
		   "initial":{"pc":32768,"a":255,"c":1,"v":1,"ram":[[32768,103],[32769,16],[16,254]]},
		   "final":  {"pc":32770,"a":254,"c":1,"v":0,"ram":[[16,255]]}}
		]
		""";

	private VectorRunner newRunner(String languageId) throws Exception {
		Language language = new ProgramBuilder("Test", languageId).getProgram().getLanguage();
		Map<String, Register> registerMap = new LinkedHashMap<>();
		registerMap.put("pc", language.getRegister("PC"));
		registerMap.put("a", language.getRegister("A"));
		registerMap.put("c", language.getRegister("C"));
		registerMap.put("v", language.getRegister("V"));
		return new VectorRunner(language, registerMap);
	}

	private void assertAllPass(VectorRunner runner, String json) throws Exception {
		List<VectorCase> cases = VectorParser.parse(new StringReader(json));
		assertTrue("expected at least one vector", cases.size() >= 4);
		for (VectorCase c : cases) {
			CaseResult result = runner.run(c);
			assertTrue(result.toString(), result.pass());
		}
	}

	@Test
	public void adcCarryAndOverflowMatchThe6502TruthTable() throws Exception {
		assertAllPass(newRunner(DEFAULT_6510), ADC_VECTORS_JSON);
	}

	@Test
	public void rraCarryAndOverflowMatchThe6502TruthTable() throws Exception {
		assertAllPass(newRunner(UNDOC_6510), RRA_VECTORS_JSON);
	}
}
