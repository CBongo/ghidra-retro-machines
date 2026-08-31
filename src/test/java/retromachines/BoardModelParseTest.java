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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

import retromachines.BoardDescriptorModel.BankWrap;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.ComputedWindowModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.ModeWindowModel;
import retromachines.BoardDescriptorModel.WindowModel;

/**
 * Direct coverage of {@link BoardModel#parse} without standing up an analyzer (bead grm-ft8).
 * Increment 1 moved this parse out of {@code BoardBankAnalyzer} verbatim and deliberately left
 * it covered only through the end-to-end golden suite, where a failure says "some fixture moved"
 * rather than "this parse branch is wrong"; this test closes that half of QR-12's acceptance
 * criterion.
 * <p>
 * It touches {@code ghidra.app.util.importer.MessageLog} and nothing else from {@code ghidra.*}:
 * {@link BoardModel#parse} is Gson in, records out, and the only Ghidra type in its signature is
 * the log it appends skip reasons to. No {@code Program}, no {@code ClassSearcher}, no runtime
 * bootstrap -- so this stays in the fast pure-logic tier alongside {@link FieldSpecKnownTest}.
 * <p>
 * The descriptor fragments below are the {@code memory} section shape the compiler emits:
 * {@code banking} plus {@code windows[]} and (for the mode-varying cases) {@code layouts[]}.
 * They are deliberately hand-written rather than loaded from {@code data/descriptors}, so a
 * descriptor edit cannot silently change what a branch here is asserting.
 */
public class BoardModelParseTest {

	private static final String SOURCE = "BoardModelParseTest";
	private static final String MAP_PATH = "test-descriptor.json";

	private static JsonObject json(String text) {
		return JsonParser.parseString(text).getAsJsonObject();
	}

	private static BoardModel parse(String text, MessageLog log) {
		return BoardModel.parse(json(text), log, SOURCE, MAP_PATH);
	}

	/**
	 * A complete, well-formed board: a 2-bit {@code bank} and a 1-bit {@code mode}, one
	 * enumerated-occupant window, one computed ({@code maps:}) window driven by {@code bank},
	 * and one fixed {@code maps:} window that references no state field at all.
	 */
	private static final String WELL_FORMED = """
			{
			  "banking": {
			    "initial_state": 5,
			    "mechanisms": [ { "strategy": "memory-latch" } ],
			    "state": [
			      { "name": "bank", "bits": 2 },
			      { "name": "mode", "bits": 1 }
			    ],
			    "states": [
			      { "value": 5, "romwin": "romA" },
			      { "value": 1, "romwin": "romB" }
			    ]
			  },
			  "windows": [
			    { "name": "romwin", "start": 32768, "end": 40959,
			      "occupants": [
			        { "name": "romA", "kind": "rom" },
			        { "name": "romB", "kind": "rom", "on_write": "latch" }
			      ] },
			    { "name": "swin", "start": 40960, "size": 8192,
			      "maps": { "expr": "bank * 8192" } },
			    { "name": "fixedwin", "start": 49152, "end": 57343,
			      "maps": { "expr": "0" } }
			  ]
			}
			""";

	@Test
	public void wellFormedDescriptorYieldsTheExpectedStateLayout() {
		BoardModel board = parse(WELL_FORMED, new MessageLog());
		assertNotNull(board);

		// bank occupies bits 0..1 and mode bit 2, assigned LSB-first in banking.state order.
		assertEquals(List.of(new FieldSpec("bank", 0, 2), new FieldSpec("mode", 2, 1)),
			board.fieldSpecs());
		// A multi-bit field expands to name.0/name.1; a single-bit field keeps its bare name.
		assertEquals(List.of("bank.0", "bank.1", "mode"), board.stateBitNames());
		// The mask is derived from the bit-name count, not declared: 3 bits -> 0b111.
		assertEquals(0x7, board.mask());
		assertEquals(5, board.initialState());
	}

	@Test
	public void wellFormedDescriptorYieldsTheExpectedWindows() {
		BoardModel board = parse(WELL_FORMED, new MessageLog());
		assertNotNull(board);

		// Only the enumerated-occupant window becomes a WindowModel; maps: windows do not.
		assertEquals(List.of("romwin"), List.copyOf(board.windows().keySet()));
		WindowModel rom = board.windows().get("romwin");
		assertEquals(32768L, rom.start());
		assertEquals(40959L, rom.end());
		assertEquals(List.of("romA", "romB"), List.copyOf(rom.occupants().keySet()));
		assertNull(rom.occupants().get("romA").onWrite());
		assertEquals("latch", rom.occupants().get("romB").onWrite());
		assertEquals("rom", rom.occupants().get("romB").kind());

		// A single-field maps: window is computed; a field-free one is fixed and dropped,
		// because the loader places it once and the analyzer never retargets it.
		assertEquals(List.of("swin"), List.copyOf(board.computedWindows().keySet()));
		ComputedWindowModel swin = board.computedWindows().get("swin");
		assertEquals(40960L, swin.start());
		// "size": 8192 with no "end" resolves to start + size - 1.
		assertEquals(49151L, swin.end());
		assertEquals(new FieldSpec("bank", 0, 2), swin.field());
	}

	@Test
	public void wellFormedDescriptorResolvesTheHomeOccupantRow() {
		BoardModel board = parse(WELL_FORMED, new MessageLog());
		assertNotNull(board);

		assertEquals(List.of(5, 1), List.copyOf(board.occupantByWindowForState().keySet()));
		assertEquals("romB", board.occupantByWindowForState().get(1).get("romwin"));
		// The home row is the one keyed by initial_state, not the first listed.
		assertEquals("romA", board.homeOccupantByWindow().get("romwin"));

		// No layouts[] means no mode axis at all.
		assertNull(board.modeField());
		assertEquals(0, board.homeModeValue());
		assertTrue(board.modeWindows().isEmpty());
	}

	@Test
	public void missingBankingSectionSkips() {
		MessageLog log = new MessageLog();
		assertNull(parse("{ \"windows\": [] }", log));
		assertTrue(log.toString().contains("banking.mechanisms missing"));
	}

	@Test
	public void bankingWithoutMechanismsSkips() {
		MessageLog log = new MessageLog();
		assertNull(parse("{ \"banking\": { \"initial_state\": 0 } }", log));
		assertTrue(log.toString().contains("banking.mechanisms missing"));
	}

	@Test
	public void bankingWithoutInitialStateSkips() {
		MessageLog log = new MessageLog();
		assertNull(parse("{ \"banking\": { \"mechanisms\": [] } }", log));
		assertTrue(log.toString().contains("banking.initial_state missing"));
	}

	/**
	 * The degenerate board: mechanisms and an initial state, but no {@code state} tuple and no
	 * windows. This parses -- it is not an error -- and every derived collection comes back
	 * empty, with a mask of 0 rather than a fabricated one.
	 */
	@Test
	public void absentStateTupleYieldsAnEmptyButValidBoard() {
		MessageLog log = new MessageLog();
		BoardModel board = parse("""
				{ "banking": { "initial_state": 0, "mechanisms": [ { "strategy": "x" } ] } }
				""", log);
		assertNotNull(board);
		assertEquals(0, board.mask());
		assertEquals(0, board.initialState());
		assertTrue(board.stateBitNames().isEmpty());
		assertTrue(board.fieldSpecs().isEmpty());
		assertTrue(board.windows().isEmpty());
		assertTrue(board.computedWindows().isEmpty());
		assertTrue(board.occupantByWindowForState().isEmpty());
		// No windows means no home row is required, so a null one is not a skip.
		assertNull(board.homeOccupantByWindow());
	}

	/**
	 * With enumerated windows present, an {@code initial_state} that names no row in
	 * {@code banking.states} IS a skip: there is no way to say what occupies each window at
	 * reset. (Contrast the previous test, where the absence of windows makes it moot.)
	 */
	@Test
	public void initialStateAbsentFromStatesSkipsWhenWindowsExist() {
		MessageLog log = new MessageLog();
		assertNull(parse("""
				{
				  "banking": {
				    "initial_state": 3,
				    "mechanisms": [ { "strategy": "x" } ],
				    "state": [ { "name": "bank", "bits": 2 } ],
				    "states": [ { "value": 0, "romwin": "romA" } ]
				  },
				  "windows": [
				    { "name": "romwin", "start": 32768, "end": 40959,
				      "occupants": [ { "name": "romA", "kind": "rom" } ] }
				  ]
				}
				""", log));
		assertTrue(log.toString().contains("not found in banking.states"));
	}

	@Test
	public void computedWindowOnAnUnknownFieldIsDroppedNotFatal() {
		MessageLog log = new MessageLog();
		BoardModel board = parse("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "x" } ],
				    "state": [ { "name": "bank", "bits": 2 } ]
				  },
				  "windows": [
				    { "name": "swin", "start": 40960, "end": 49151,
				      "maps": { "expr": "chr * 8192" } }
				  ]
				}
				""", log);
		assertNotNull(board);
		assertTrue(board.computedWindows().isEmpty());
		assertTrue(log.toString().contains("references unknown state field 'chr'"));
	}

	@Test
	public void multiFieldComputedWindowIsDroppedNotFatal() {
		MessageLog log = new MessageLog();
		BoardModel board = parse("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "x" } ],
				    "state": [ { "name": "bank", "bits": 2 }, { "name": "hi", "bits": 1 } ]
				  },
				  "windows": [
				    { "name": "swin", "start": 40960, "end": 49151,
				      "maps": { "expr": "hi * 32768 + bank * 8192" } }
				  ]
				}
				""", log);
		assertNotNull(board);
		assertTrue(board.computedWindows().isEmpty());
		assertTrue(log.toString().contains("multi-field windows are not supported"));
	}

	/**
	 * The mode axis: two {@code layouts[]} entries that differ for the same window name make it
	 * mode-varying, one instance per mode. The {@code mode=0} instance maps to a constant, so
	 * it is a FIXED instance ({@code bankField} null); the {@code mode=1} instance is driven by
	 * {@code bank}, so it is SWITCHABLE.
	 */
	@Test
	public void modeVaryingLayoutsProduceOneInstancePerMode() {
		MessageLog log = new MessageLog();
		BoardModel board = parse("""
				{
				  "banking": {
				    "initial_state": 4,
				    "mechanisms": [ { "strategy": "x" } ],
				    "state": [ { "name": "bank", "bits": 2 }, { "name": "mode", "bits": 1 } ]
				  },
				  "layouts": [
				    { "when": { "mode": 0 },
				      "windows": [ { "name": "lo", "start": 0, "end": 8191,
				                     "maps": { "expr": "0" } } ] },
				    { "when": { "mode": 1 },
				      "windows": [ { "name": "lo", "start": 0, "end": 8191,
				                     "maps": { "expr": "bank * 8192" }, "on_write": "latch" } ] }
				  ]
				}
				""", log);
		assertNotNull(board);
		assertEquals(new FieldSpec("mode", 2, 1), board.modeField());
		// initial_state 0b100 puts mode at 1, so mode 1 is home.
		assertEquals(1, board.homeModeValue());

		assertEquals(2, board.modeWindows().size());
		ModeWindowModel fixed = board.modeWindows().get(0);
		assertEquals("lo", fixed.name());
		assertEquals(0, fixed.modeValue());
		assertNull(fixed.bankField());
		assertNull(fixed.onWrite());

		ModeWindowModel switchable = board.modeWindows().get(1);
		assertEquals(1, switchable.modeValue());
		assertEquals(new FieldSpec("bank", 0, 2), switchable.bankField());
		assertEquals("latch", switchable.onWrite());
	}

	/**
	 * A mode field that {@code banking.state} never declares cannot be positioned, so the whole
	 * mode axis is dropped -- logged, and with the rest of the board still parsed.
	 */
	@Test
	public void modeFieldMissingFromStateDropsTheModeAxis() {
		MessageLog log = new MessageLog();
		BoardModel board = parse("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "x" } ],
				    "state": [ { "name": "bank", "bits": 2 } ]
				  },
				  "layouts": [
				    { "when": { "mode": 0 },
				      "windows": [ { "name": "lo", "start": 0, "end": 8191,
				                     "maps": { "expr": "0" } } ] },
				    { "when": { "mode": 1 },
				      "windows": [ { "name": "lo", "start": 0, "end": 8191,
				                     "maps": { "expr": "bank * 8192" } } ] }
				  ]
				}
				""", log);
		assertNotNull(board);
		assertNull(board.modeField());
		assertEquals(0, board.homeModeValue());
		assertTrue(board.modeWindows().isEmpty());
		assertTrue(log.toString().contains("not found in banking.state"));
	}

	/**
	 * {@code banking.bank_wrap} (bead grm-p25h) is optional and off by default -- the property
	 * that keeps every board but MMC5 bit-for-bit unchanged, since
	 * {@link BankAnnotationAdapter#canonicalBank} is the identity when it is null.
	 */
	@Test
	public void bankWrapIsAbsentUnlessDeclared() {
		assertNull(parse(WELL_FORMED, new MessageLog()).bankWrap());
	}

	@Test
	public void declaredImageBankWrapIsCarried() {
		BoardModel board =
			parse(WELL_FORMED.replace("\"initial_state\": 5,",
				"\"initial_state\": 5, \"bank_wrap\": \"image\","), new MessageLog());
		assertEquals(BankWrap.IMAGE, board.bankWrap());
	}

	/** The second form: a JSON NUMBER is an explicit, unguarded mask, not a policy name. */
	@Test
	public void declaredExplicitMaskBankWrapIsCarried() {
		BoardModel board =
			parse(WELL_FORMED.replace("\"initial_state\": 5,",
				"\"initial_state\": 5, \"bank_wrap\": 31,"), new MessageLog());
		assertEquals(BankWrap.ofMask(31), board.bankWrap());
	}

	/**
	 * An unrecognized policy is refused, not half-applied: the rest of the board still parses
	 * and nothing wraps. MapCompiler rejects it at build time, so this only guards a
	 * hand-edited {@code .map}.
	 */
	@Test
	public void unknownBankWrapPolicyIsRefusedAndLogged() {
		MessageLog log = new MessageLog();
		BoardModel board =
			parse(WELL_FORMED.replace("\"initial_state\": 5,",
				"\"initial_state\": 5, \"bank_wrap\": \"mirror\","), log);
		assertNotNull(board);
		assertNull(board.bankWrap());
		assertTrue(log.toString().contains("not a recognized policy"));
	}
}
