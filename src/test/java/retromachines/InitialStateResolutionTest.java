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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

import retromachines.BoardDescriptorModel.BoardModel;

/**
 * Load-time resolution of an image-relative {@code banking.initial_state} (bead
 * {@code grm-y0ml}): {@link DescriptorSupport#resolveInitialState} and the analyzer side's
 * preference for the loader's resolved value in {@link BoardModel#parse}.
 * <p>
 * Same tier as {@link BoardModelParseTest} -- Gson in, numbers out, with
 * {@code ghidra.app.util.importer.MessageLog} the only {@code ghidra.*} type on the stack. The
 * loader's <em>publication</em> of the resolved value (the PROGRAM_INFO property) and the block
 * placement that follows from it are asserted end to end by the {@code nesmmc5test} headless
 * fixture instead, which is where an image actually exists.
 */
public class InitialStateResolutionTest {

	/** MMC5's shape, reduced: a 2-bit mode plus a 7-bit bank register seeded image-relative. */
	private static final String MMC5_SHAPE = """
			{
			  "banking": {
			    "initial_state": 3,
			    "initial_state_expr": { "bank_hi": "(image_size >> 13) - 1" },
			    "mechanisms": [ { "strategy": "memory-latch" } ],
			    "state": [
			      { "name": "prg_mode", "bits": 2 },
			      { "name": "bank_hi", "bits": 7 }
			    ]
			  }
			}
			""";

	private static JsonObject json(String text) {
		return JsonParser.parseString(text).getAsJsonObject();
	}

	private static Long resolve(String text, long imageSize, MessageLog log) {
		return DescriptorSupport.resolveInitialState(json(text), imageSize, log, "test.map");
	}

	@Test
	public void expressionFieldResolvesAgainstTheImageAndKeepsLiteralFields() {
		MessageLog log = new MessageLog();
		// 64 KiB -> bank 7; prg_mode's literal 3 (bits 0-1) must survive untouched.
		assertEquals(Long.valueOf((7L << 2) | 3), resolve(MMC5_SHAPE, 0x10000, log));
		// 1 MiB -> bank 0x7F, the wiki's literal $5117 reset value.
		assertEquals(Long.valueOf((0x7FL << 2) | 3), resolve(MMC5_SHAPE, 0x100000, log));
	}

	@Test
	public void descriptorWithoutExpressionsIsUntouched() {
		// The C64/PET path and every NES board but MMC5: no initial_state_expr key at all.
		MessageLog log = new MessageLog();
		String text = """
				{
				  "banking": {
				    "initial_state": 7,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "LORAM", "bits": 1 }, { "name": "HIRAM", "bits": 1 },
				               { "name": "CHAREN", "bits": 1 } ]
				  }
				}
				""";
		assertEquals(Long.valueOf(7), resolve(text, 0x2000, log));
		assertEquals("", log.toString().trim());
	}

	@Test
	public void bankinglessDescriptorResolvesToNull() {
		assertNull(resolve("{}", 0x10000, new MessageLog()));
	}

	/**
	 * The width check {@code MapCompiler.packState} performs on literals, applied to the
	 * resolved value -- the first moment it exists. Per CLAUDE.md's "loader validation:
	 * {@code load()} is authoritative", the field is REFUSED (left at its compiled value) with
	 * a clear message, not thrown on and not guessed at.
	 */
	@Test
	public void resolvedValueTooWideForTheFieldIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		String text = MMC5_SHAPE.replace("(image_size >> 13) - 1", "image_size - 0x2000");
		assertEquals("field left at its compiled value", Long.valueOf(3),
			resolve(text, 0x10000, log));
		assertTrue(log.toString(), log.toString().contains("does not fit"));
		assertTrue(log.toString(), log.toString().contains("bank_hi"));
	}

	@Test
	public void expressionNamingAnUndeclaredFieldIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		String text = MMC5_SHAPE.replace("\"bank_hi\": \"(image", "\"bank_nope\": \"(image");
		assertEquals(Long.valueOf(3), resolve(text, 0x10000, log));
		assertTrue(log.toString(), log.toString().contains("bank_nope"));
	}

	@Test
	public void unevaluableExpressionIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		// Only a hand-edited .map can get here: MapCompiler rejects this at build time.
		String text = MMC5_SHAPE.replace("(image_size >> 13) - 1", "last");
		assertEquals(Long.valueOf(3), resolve(text, 0x10000, log));
		assertTrue(log.toString(), log.toString().contains("could not be evaluated"));
	}

	// --- the analyzer side ---

	@Test
	public void parsePrefersTheLoaderResolvedInitialState() {
		MessageLog log = new MessageLog();
		BoardModel board = BoardModel.parse(json(MMC5_SHAPE), log, "test", "test.map",
			Integer.valueOf((7 << 2) | 3));
		assertEquals((7 << 2) | 3, board.initialState());
		assertTrue(log.toString(), log.toString().contains("image-resolved"));
	}

	@Test
	public void parseFallsBackToTheCompiledLiteralWhenNothingWasPublished() {
		// A program imported by a build that did not write the property (or by an older one).
		MessageLog log = new MessageLog();
		BoardModel board = BoardModel.parse(json(MMC5_SHAPE), log, "test", "test.map", null);
		assertEquals(3, board.initialState());
		assertEquals("", log.toString().trim());
	}
}
