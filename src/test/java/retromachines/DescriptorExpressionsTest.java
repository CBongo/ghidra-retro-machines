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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.Test;

/**
 * Pure-JUnit coverage of {@link DescriptorExpressions} (QR-12 increment 5): the computed-window
 * {@code maps:} expression grammar -- integer literals, {@code last}/{@code second_last},
 * {@code + - * >>} with precedence, parentheses, and bank-state field references. Imports
 * nothing from {@code ghidra.*} -- like {@link PlacementOverrideParseTest}, this is plain string
 * arithmetic with no Ghidra runtime bootstrap needed.
 */
public class DescriptorExpressionsTest {

	private static final long IMAGE_SIZE = 0x40000; // 256 KiB
	private static final long WINDOW_SIZE = 0x4000; // 16 KiB

	// --- evalConstantExpr: literals, last/second_last, precedence, parens ---

	@Test
	public void decimalLiteralEvaluatesToItself() {
		assertEquals(0, DescriptorExpressions.evalConstantExpr("0", IMAGE_SIZE, WINDOW_SIZE));
		assertEquals(12345,
			DescriptorExpressions.evalConstantExpr("12345", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void hexLiteralEvaluatesToItself() {
		assertEquals(0x8000, DescriptorExpressions.evalConstantExpr("0x8000", IMAGE_SIZE, WINDOW_SIZE));
		assertEquals(0xFF, DescriptorExpressions.evalConstantExpr("0XFF", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void lastIsImageSizeMinusWindowSize() {
		assertEquals(IMAGE_SIZE - WINDOW_SIZE,
			DescriptorExpressions.evalConstantExpr("last", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void secondLastIsImageSizeMinusTwoWindows() {
		assertEquals(IMAGE_SIZE - 2 * WINDOW_SIZE,
			DescriptorExpressions.evalConstantExpr("second_last", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void additionAndSubtractionAreLeftAssociative() {
		assertEquals(1 + 2 - 3 + 4,
			DescriptorExpressions.evalConstantExpr("1 + 2 - 3 + 4", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void multiplicationBindsTighterThanAddition() {
		// 2 + 3*4 = 14, not (2+3)*4 = 20
		assertEquals(14, DescriptorExpressions.evalConstantExpr("2 + 3 * 4", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void shiftBindsAtSamePrecedenceAsMultiplyLeftAssociative() {
		// (prg_bank >> 1) * 0x8000 shape, MMC1's 32K mode -- constant subset here
		assertEquals((8 >> 1) * 3, DescriptorExpressions.evalConstantExpr("8 >> 1 * 3", IMAGE_SIZE, WINDOW_SIZE));
		// * and >> chain left-to-right: (2 * 8) >> 2 = 4, not 2 * (8 >> 2) = 4 too -- use a case
		// that actually distinguishes the two groupings.
		assertEquals((2 * 8) >>> 1, DescriptorExpressions.evalConstantExpr("2 * 8 >> 1", IMAGE_SIZE, WINDOW_SIZE));
		assertEquals((16 >>> 2) * 3, DescriptorExpressions.evalConstantExpr("16 >> 2 * 3", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void parenthesesOverridePrecedence() {
		assertEquals((2 + 3) * 4,
			DescriptorExpressions.evalConstantExpr("(2 + 3) * 4", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void nestedParenthesesAreSupported() {
		assertEquals(((1 + 2) * (3 + 4)),
			DescriptorExpressions.evalConstantExpr("((1 + 2) * (3 + 4))", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void whitespaceAroundTokensIsTolerated() {
		assertEquals(7, DescriptorExpressions.evalConstantExpr("  1 + 2 * 3  ", IMAGE_SIZE, WINDOW_SIZE));
	}

	// --- evalExpr: bound state-field identifiers ---

	@Test
	public void evalExprResolvesBoundIdentifier() {
		long v = DescriptorExpressions.evalExpr("prg_bank * 0x4000", IMAGE_SIZE, WINDOW_SIZE,
			Map.of("prg_bank", 5L));
		assertEquals(5 * 0x4000, v);
	}

	@Test
	public void evalExprCombinesIdentifierWithLastAndArithmetic() {
		long v = DescriptorExpressions.evalExpr("last - bank * 0x2000", IMAGE_SIZE, WINDOW_SIZE,
			Map.of("bank", 3L));
		assertEquals((IMAGE_SIZE - WINDOW_SIZE) - 3 * 0x2000, v);
	}

	@Test
	public void evalConstantExprIsEvalExprWithEmptyEnv() {
		assertEquals(DescriptorExpressions.evalExpr("last - 0x1000", IMAGE_SIZE, WINDOW_SIZE, Map.of()),
			DescriptorExpressions.evalConstantExpr("last - 0x1000", IMAGE_SIZE, WINDOW_SIZE));
	}

	// --- referencedFields ---

	@Test
	public void referencedFieldsFindsSingleIdentifier() {
		assertEquals(Set.of("prg_bank"),
			DescriptorExpressions.referencedFields("prg_bank * 0x4000"));
	}

	@Test
	public void referencedFieldsExcludesLastAndSecondLastKeywords() {
		assertEquals(Set.of(),
			DescriptorExpressions.referencedFields("last - second_last + 0x100"));
	}

	@Test
	public void referencedFieldsFindsMultipleDistinctIdentifiers() {
		assertEquals(Set.of("prg_bank", "chr_bank"),
			DescriptorExpressions.referencedFields("prg_bank * 0x4000 + chr_bank"));
	}

	@Test
	public void referencedFieldsDoesNotMatchIdentifierInsideHexLiteral() {
		// 'x4000' inside the hex literal '0x4000' must not be treated as an identifier.
		assertEquals(Set.of(), DescriptorExpressions.referencedFields("0x4000 + 0xABCD"));
	}

	@Test
	public void referencedFieldsDeduplicatesRepeatedIdentifier() {
		assertEquals(Set.of("bank"),
			DescriptorExpressions.referencedFields("bank + bank * 2"));
	}

	@Test
	public void referencedFieldsExcludesImageSizeKeyword() {
		// bead grm-y0ml: image_size is bound by the evaluator, so treating it as a state-field
		// name would misreport a window as depending on bank state that does not exist.
		assertEquals(Set.of(),
			DescriptorExpressions.referencedFields("(image_size >> 13) - 1"));
		assertEquals(Set.of("prg_bank"),
			DescriptorExpressions.referencedFields("prg_bank + image_size"));
	}

	// --- image_size / initial-state expressions (bead grm-y0ml) ---

	@Test
	public void imageSizeEvaluatesToTheImageSize() {
		assertEquals(IMAGE_SIZE,
			DescriptorExpressions.evalConstantExpr("image_size", IMAGE_SIZE, WINDOW_SIZE));
		assertEquals(IMAGE_SIZE, DescriptorExpressions.evalInitialStateExpr("image_size",
			IMAGE_SIZE));
	}

	@Test
	public void mmc5TopBankSeedResolvesPerImageSize() {
		// machines/nes-mmc5.yaml's bank_5117 seed: the last 8 KiB bank of the image.
		String expr = "(image_size >> 13) - 1";
		assertEquals(7, DescriptorExpressions.evalInitialStateExpr(expr, 0x10000)); // 64 KiB
		assertEquals(15, DescriptorExpressions.evalInitialStateExpr(expr, 0x20000)); // 128 KiB
		// 1 MiB is where the wiki's literal $5117 reset value (0xFF -> bank 0x7F) is exact.
		assertEquals(0x7F, DescriptorExpressions.evalInitialStateExpr(expr, 0x100000));
	}

	@Test
	public void initialStateExprRejectsLastAndSecondLast() {
		// The units differ: 'last' is a BYTE OFFSET, an initial_state field is a BANK NUMBER.
		for (String expr : new String[] { "last", "second_last", "last - 0x2000" }) {
			IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> DescriptorExpressions.evalInitialStateExpr(expr, IMAGE_SIZE));
			assertTrue(e.getMessage().contains("image_size"));
		}
	}

	/**
	 * {@code MapCompiler} carries its OWN implementation of this grammar for its compile-time
	 * range probe, because the build-time compiler is a separate, Ghidra-free source set that
	 * cannot see this class (see {@code MapCompiler}'s javadoc). This test is what keeps that
	 * duplicate honest -- the test source set has both on its classpath, so the two are
	 * compared directly rather than by a comment asking the next person to remember.
	 */
	@Test
	public void mapCompilerEvaluatorAgreesWithThisOne() {
		String[] exprs = { "image_size", "(image_size >> 13) - 1", "image_size >> 14", "0x10",
			"image_size * 2 + 1", "(image_size - 0x4000) >> 13", "2 + 3 * 4",
			"image_size >> 2 >> 2", "image_size - 0x2000" };
		for (long imageSize : new long[] { 0x4000, 0x10000, 0x20000, 0x100000 }) {
			for (String expr : exprs) {
				assertEquals("MapCompiler and DescriptorExpressions disagree on '" + expr +
					"' at image size " + imageSize,
					DescriptorExpressions.evalInitialStateExpr(expr, imageSize),
					gdtbuilder.MapCompiler.evalInitialExpr(expr, imageSize));
			}
		}
	}

	@Test
	public void initialStateExprRejectsStateFieldName() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalInitialStateExpr("prg_bank + 1", IMAGE_SIZE));
		assertTrue(e.getMessage().contains("prg_bank"));
	}

	// --- malformed input / error paths ---

	@Test
	public void unresolvedIdentifierInConstantExprThrows() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalConstantExpr("prg_bank * 0x4000", IMAGE_SIZE, WINDOW_SIZE));
		assertTrue(e.getMessage().contains("bank state"));
		assertTrue(e.getMessage().contains("prg_bank"));
	}

	@Test
	public void identifierNotInEnvThrows() {
		assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalExpr("other_field", IMAGE_SIZE, WINDOW_SIZE, Map.of()));
	}

	@Test
	public void unbalancedParenthesesThrow() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalConstantExpr("(1 + 2", IMAGE_SIZE, WINDOW_SIZE));
		assertTrue(e.getMessage().contains("unbalanced parentheses"));
	}

	@Test
	public void trailingGarbageThrows() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalConstantExpr("1 + 2 )", IMAGE_SIZE, WINDOW_SIZE));
		assertTrue(e.getMessage().contains("trailing garbage"));
	}

	@Test
	public void emptyExpressionThrows() {
		assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalConstantExpr("", IMAGE_SIZE, WINDOW_SIZE));
	}

	@Test
	public void malformedTokenAfterOperatorThrows() {
		// Nothing follows the '+' before the parser hits end of input.
		assertThrows(IllegalArgumentException.class,
			() -> DescriptorExpressions.evalConstantExpr("1 + ", IMAGE_SIZE, WINDOW_SIZE));
	}
}
