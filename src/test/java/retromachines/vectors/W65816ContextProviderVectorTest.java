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
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

import retromachines.AbstractBundledLanguageTest;
import retromachines.vectors.VectorRunner.CaseResult;

/**
 * End-to-end proof for {@link VectorRunner#withContextProvider} (bead grm-wrmf): a per-case
 * {@code ctx_MF} override actually reaches {@code SleighInstructionDecoder} and selects a
 * different subtable, not merely a value that gets recorded and dropped.
 *
 * <p>{@code 65816:LE:24:retro} (bead grm-9nxj.1) is the one bundled language in this project
 * whose decode genuinely depends on processor CONTEXT, not just registers/RAM: {@code
 * 658xx.sinc}'s two {@code LDA} immediate constructors are keyed on {@code ctx_MF} alone (the
 * 8-bit and 16-bit forms at lines ~845/857), and {@code w65816.pspec} defaults the whole address
 * space to {@code ctx_MF=1} (8-bit, the state a real 65816 resets into). That default is exactly
 * what {@link VectorRunner#seed} falls back to when no provider is set -- so the SAME three
 * bytes, {@code A9 34 12} ({@code LDA #imm}), decode two genuinely different instructions
 * depending on which context reaches the decoder: 8-bit ({@code LDA #$34}, 2 bytes, leaving the
 * trailing {@code 12} unconsumed) with no provider, or 16-bit ({@code LDA #$1234}, 3 bytes) when
 * a provider forces {@code ctx_MF=0}. Proving the SAME bytes take both paths under the harness'
 * own control -- not two different opcodes that happen to disassemble differently -- is the
 * strongest cheap proof available that the hook reaches decode rather than being seeded and
 * ignored.
 *
 * <p>Deliberately narrow: this does not attempt {@code compare()}'s register masking or
 * {@code OpcodeBaseline}'s one-row-per-opcode model, both mode-dependent and both explicitly
 * out of scope for grm-wrmf (left for grm-9nxj.3). It also does not assert anything about
 * {@code 65816:LE:24:retro}'s p-code correctness beyond M/X width selection -- that language's
 * immediate-operand modelling and broader semantics are unverified (grm-9nxj.2/.4) and are not
 * this test's concern.
 */
public class W65816ContextProviderVectorTest extends AbstractBundledLanguageTest {

	private static final String LANGUAGE_ID = "65816:LE:24:retro";

	/**
	 * {@code LDA #imm} ({@code A9}) at $008000, 8-bit case: {@code A9 05} -&gt; {@code A=$05},
	 * {@code PC} advances 2. Exercises the harness' EXISTING behaviour (no context provider),
	 * which must stay exactly as it was for every pre-grm-wrmf caller -- this language's default
	 * context ({@code w65816.pspec}'s {@code context_set}) already happens to be {@code
	 * ctx_MF=1}, so {@code overrideContextWithDefault()} alone decodes this correctly.
	 */
	private static final String LDA_IMM_8BIT_JSON = """
		[
		  {"name":"lda-imm-8bit-default-context",
		   "initial":{"pc":32768,"ram":[[32768,169],[32769,5]]},
		   "final":  {"pc":32770,"a":5}}
		]
		""";

	/**
	 * The SAME opcode byte plus two operand bytes, {@code A9 34 12} at $009000 -- reused by both
	 * {@link #contextProviderSelects16BitDecode} (with a provider forcing {@code ctx_MF=0}) and
	 * {@link #withoutProviderSameBytesDecode8Bit} (without one), so the two tests differ only in
	 * whether a context provider is installed, isolating that as the cause of the different
	 * outcome.
	 */
	private static final String LDA_IMM_16BIT_BYTES_JSON = """
		[
		  {"name":"lda-imm-widened-by-provider",
		   "initial":{"pc":36864,"ram":[[36864,169],[36865,52],[36866,18]]},
		   "final":  {"pc":36867,"c":4660}}
		]
		""";

	private Language language;

	private VectorRunner newRunner() throws Exception {
		language = new ProgramBuilder("Test", LANGUAGE_ID).getProgram().getLanguage();
		Map<String, Register> registerMap = new LinkedHashMap<>();
		registerMap.put("pc", language.getRegister("PC"));
		registerMap.put("a", language.getRegister("A"));
		registerMap.put("c", language.getRegister("C"));
		return new VectorRunner(language, registerMap);
	}

	/** Forces the 16-bit accumulator width ({@code ctx_MF=0}) for every case it is asked about. */
	private Function<VectorCase, RegisterValue> forceSixteenBitAccumulator() {
		Register ctxMf = language.getRegister("ctx_MF");
		return c -> new RegisterValue(ctxMf, BigInteger.ZERO);
	}

	@Test
	public void noProviderKeepsTodaysDefaultContextBehaviour() throws Exception {
		VectorRunner runner = newRunner();
		List<VectorCase> cases = VectorParser.parse(new StringReader(LDA_IMM_8BIT_JSON));
		for (VectorCase c : cases) {
			CaseResult result = runner.run(c);
			assertTrue(result.toString(), result.pass());
		}
	}

	@Test
	public void contextProviderSelects16BitDecode() throws Exception {
		VectorRunner runner = newRunner();
		runner.withContextProvider(forceSixteenBitAccumulator());
		List<VectorCase> cases = VectorParser.parse(new StringReader(LDA_IMM_16BIT_BYTES_JSON));
		for (VectorCase c : cases) {
			CaseResult result = runner.run(c);
			assertTrue(result.toString(), result.pass());
		}
	}

	/**
	 * The control: identical bytes to {@link #contextProviderSelects16BitDecode}, but with no
	 * provider installed, must decode 8-bit (per the default context) and land on a DIFFERENT
	 * final state -- {@code A=$34} from a 2-byte instruction, not {@code C=$1234} from a 3-byte
	 * one. This is bead grm-wrmf's motivating bug made concrete: without a per-case context hook,
	 * a 65816 vector suite that expects widened cases to decode wide would silently get every one
	 * of them decoded 8-bit instead, and would report a plausible-looking PASS/FAIL split that
	 * reads as a language defect rather than as the harness feeding the wrong context.
	 */
	@Test
	public void withoutProviderSameBytesDecode8Bit() throws Exception {
		VectorRunner runner = newRunner();
		List<VectorCase> cases = VectorParser.parse(new StringReader(LDA_IMM_16BIT_BYTES_JSON));
		VectorCase widened = cases.get(0);
		VectorCase narrow = new VectorCase(widened.name() + "-narrow-control",
			widened.initialRegs(), widened.initialRam(),
			Map.of("a", 0x34), List.of());

		CaseResult result = runner.run(narrow);
		assertTrue(result.toString(), result.pass());
	}
}
