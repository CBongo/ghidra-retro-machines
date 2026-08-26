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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import retromachines.BoardDescriptorModel.BoardModel;

/**
 * Direct coverage of {@link BankStrategyRegistry#mechanismPositioning} without standing up an
 * analyzer or a {@code Program} (bead grm-ft8 increment 2). The method is nearly pure -- a
 * descriptor mechanism object and a {@link BoardModel} in, {@code {effectMask, lsb}} out -- and
 * it is the half of the registry that decides where one mechanism's writes land in the board's
 * absolute state bits, so a mistake here silently mispositions every switch that mechanism
 * recognizes.
 * <p>
 * The one Ghidra-shaped dependency is the {@link ghidra.app.services.Analyzer} the method logs
 * skip reasons through; a name-only {@link AbstractAnalyzer} subclass satisfies it (its
 * constructor stores three fields and touches nothing else), which keeps this in the fast
 * pure-logic tier next to {@link BoardModelParseTest}. {@code configureStrategies} itself is NOT
 * covered here: it calls {@code ClassSearcher.getInstances}, which needs the Ghidra class-finder
 * bootstrap, so it stays end-to-end-tested.
 */
public class MechanismPositioningTest {

	/** Name-only analyzer, standing in for the one that would be doing the logging. */
	private static class StubAnalyzer extends AbstractAnalyzer {
		StubAnalyzer() {
			super("MechanismPositioningTest", "test stub", AnalyzerType.INSTRUCTION_ANALYZER);
		}

		@Override
		public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
				MessageLog log) {
			throw new UnsupportedOperationException("never analyzed");
		}
	}

	/**
	 * Three fields packed LSB-first: {@code bank} at bits 0..1, {@code mode} at bit 2,
	 * {@code hi} at bit 3 -- so the board mask is 0b1111 and {@code bank}+{@code mode} are
	 * adjacent while {@code bank}+{@code hi} are not.
	 */
	private static BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "x" } ],
				    "state": [
				      { "name": "bank", "bits": 2 },
				      { "name": "mode", "bits": 1 },
				      { "name": "hi", "bits": 1 }
				    ]
				  }
				}
				""").getAsJsonObject();
		BoardModel board = BoardModel.parse(map, new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		return board;
	}

	private static JsonObject mechanism(String json) {
		return JsonParser.parseString(json).getAsJsonObject();
	}

	private static int[] position(JsonObject mech, MessageLog log) {
		return BankStrategyRegistry.mechanismPositioning(new StubAnalyzer(), mech, board(), log,
			"test-strategy");
	}

	/**
	 * The compatibility path: a mechanism that declares no {@code sets} covers the whole board
	 * at lsb 0, which is the single-mechanism-per-board behavior every descriptor had before
	 * {@code sets} existed.
	 */
	@Test
	public void mechanismWithoutSetsCoversTheWholeBoard() {
		assertArrayEquals(new int[] { 0xF, 0 },
			position(mechanism("{ \"strategy\": \"x\" }"), new MessageLog()));
	}

	/** An empty {@code sets} array is treated as absent, not as "sets nothing". */
	@Test
	public void mechanismWithEmptySetsCoversTheWholeBoard() {
		assertArrayEquals(new int[] { 0xF, 0 },
			position(mechanism("{ \"strategy\": \"x\", \"sets\": [] }"), new MessageLog()));
	}

	@Test
	public void singleFieldAtTheBottomPositionsAtLsbZero() {
		assertArrayEquals(new int[] { 0x3, 0 },
			position(mechanism("{ \"sets\": [\"bank\"] }"), new MessageLog()));
	}

	/** A field above bit 0 reports its own lsb, so the strategy can compute field-locally. */
	@Test
	public void singleFieldAboveTheBottomReportsItsOwnLsb() {
		assertArrayEquals(new int[] { 0x4, 2 },
			position(mechanism("{ \"sets\": [\"mode\"] }"), new MessageLog()));
		assertArrayEquals(new int[] { 0x8, 3 },
			position(mechanism("{ \"sets\": [\"hi\"] }"), new MessageLog()));
	}

	/** Adjacent fields union into one run; the lsb is the lowest of them. */
	@Test
	public void adjacentFieldsUnionIntoOneContiguousRun() {
		assertArrayEquals(new int[] { 0x7, 0 },
			position(mechanism("{ \"sets\": [\"bank\", \"mode\"] }"), new MessageLog()));
		assertArrayEquals(new int[] { 0xC, 2 },
			position(mechanism("{ \"sets\": [\"mode\", \"hi\"] }"), new MessageLog()));
	}

	/** Order within {@code sets} is irrelevant -- it is a union plus a minimum. */
	@Test
	public void setsOrderDoesNotMatter() {
		assertArrayEquals(position(mechanism("{ \"sets\": [\"bank\", \"mode\"] }"), new MessageLog()),
			position(mechanism("{ \"sets\": [\"mode\", \"bank\"] }"), new MessageLog()));
	}

	/**
	 * A gap in the union cannot be expressed as one field-local {@code [0, width)} window, so
	 * the mechanism is skipped rather than mispositioned. Here {@code bank}|{@code hi} is
	 * 0b1011, whose {@code mode} bit belongs to somebody else.
	 */
	@Test
	public void nonContiguousSetsAreSkipped() {
		MessageLog log = new MessageLog();
		assertNull(position(mechanism("{ \"sets\": [\"bank\", \"hi\"] }"), log));
		assertTrue(log.toString().contains("not a contiguous bit run"));
	}

	@Test
	public void unknownFieldIsSkipped() {
		MessageLog log = new MessageLog();
		assertNull(position(mechanism("{ \"sets\": [\"chr\"] }"), log));
		assertTrue(log.toString().contains("sets unknown state field 'chr'"));
	}

	/** One unknown name poisons the whole mechanism, even alongside known ones. */
	@Test
	public void unknownFieldAlongsideAKnownOneStillSkips() {
		MessageLog log = new MessageLog();
		assertNull(position(mechanism("{ \"sets\": [\"bank\", \"chr\"] }"), log));
		assertTrue(log.toString().contains("sets unknown state field 'chr'"));
	}
}
