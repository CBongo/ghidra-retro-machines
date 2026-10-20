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

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Pins bead {@code grm-dos9.6}: the layout-mode field is LOCKED to the one value every
 * reset-reached write gives it, and async entries and unreached functions are seeded with it.
 * <p>
 * The owner's observation behind it: most games set the PRG mode once at reset, or rewrite it on
 * every control-register write but always to the same value. cv3 (MMC5 mode 2) and blmaster
 * (MMC1 mode 3, NMI-reached code) needed per-game hints for exactly this. A lock that later turns
 * out wrong is discarded (the whole run is redone without it) and reported, never silently kept.
 * <p>
 * The board: a 2-bit {@code mode} field (bits 0-1, power-on 3) that keys the layouts, and a 4-bit
 * {@code bank} field (bits 2-5, power-on 0), each set by its own memory latch ($9000 / $A000).
 * The NMI handler at $C100 is the loader-declared async entry (grm-913).
 */
public class ModeLockProgramTest extends AbstractProgramTest {

	private static final int MODE_MASK = 0x03;
	private static final int BANK_MASK = 0x3C;
	private static final int NMI = 0xc100;


	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createUninitializedMemory(".zp", "0x0", 0x100); // RAM: no constant to read
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private void makeFunction(int start, int endInclusive, String name, boolean entryPoint)
			throws Exception {
		inTx(program, "create function", () -> {
			program.getFunctionManager().createFunction(name, addr(start),
				new AddressSet(addr(start), addr(endInclusive)), SourceType.ANALYSIS);
		});
		if (entryPoint) {
			builder.createEntryPoint(String.format("0x%x", start), name);
		}
	}

	/** NMI at $C100: bank 5, RTI. Declared async, as NesRomLoader declares the vectors. */
	private void layNmi() throws Exception {
		layNmi("a9 05 8d 00 a0 40"); // LDA #$05 / STA $A000 / RTI
	}

	private void layNmi(String hex) throws Exception {
		put(NMI, hex);
		makeFunction(NMI, NMI + hex.split(" ").length - 1, "NMI", false);
		inTx(program, "async entries", () -> {
			program.getOptions(Program.PROGRAM_INFO).setString(
				DescriptorSupport.ASYNC_ENTRY_POINTS_PROPERTY,
				DescriptorSupport.formatAsyncEntryPoints(List.of(addr(NMI))));
		});
	}

	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 3,
				    "mechanisms": [ { "strategy": "memory-latch" }, { "strategy": "memory-latch" } ],
				    "state": [ { "name": "mode", "bits": 2 }, { "name": "bank", "bits": 4 } ]
				  },
				  "layouts": [
				    { "when": { "mode": 2 },
				      "windows": [ { "name": "lo", "start": 32768, "end": 40959,
				                     "maps": { "expr": "bank * 8192" } } ] },
				    { "when": { "mode": 3 },
				      "windows": [ { "name": "lo", "start": 32768, "end": 40959,
				                     "maps": { "expr": "0" } } ] }
				  ]
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		assertNotNull("the fixture must have a layout-mode field", board.modeField());
		return board;
	}

	private BankStrategyRegistry.ConfiguredMechanism latch(int start, int widthMask,
			int effectMask, int lsb) {
		JsonObject params = new JsonObject();
		params.addProperty("start", start);
		params.addProperty("end", start);
		params.addProperty("mask", widthMask);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, widthMask);
		return new BankStrategyRegistry.ConfiguredMechanism(strategy, effectMask, lsb);
	}

	private BankDataflowEngine.DataflowResult run() throws Exception {
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			BankDataflowEngine.DataflowInputs.of(
				List.of(latch(0x9000, 0x3, MODE_MASK, 0), latch(0xa000, 0xF, BANK_MASK, 2)),
				board()));
	}

	private static void assertModeKnown(BankState s, int mode) {
		assertNotNull(s);
		assertEquals("mode must be known", MODE_MASK, s.knownMask() & MODE_MASK);
		assertEquals(mode, s.bits() & MODE_MASK);
	}

	private static void assertModeUnknown(BankState s) {
		assertNotNull(s);
		assertEquals("mode must be unknown", 0, s.knownMask() & MODE_MASK);
	}

	/** RESET: mode 2, then idle. The NMI entry is seeded with mode 2 known, bank unknown. */
	@Test
	public void resetsOnlyModeWriteLocksTheModeForTheInterruptHandler() throws Exception {
		put(0xc000, "a9 02 8d 00 90 4c 05 c0"); // LDA #$02 / STA $9000 / JMP *
		makeFunction(0xc000, 0xc007, "RESET", true);
		layNmi();

		BankDataflowEngine.DataflowResult result = run();

		assertNotNull("one resolved write: the mode locks", result.modeLock());
		assertFalse(result.modeLock().rejected());
		assertEquals(addr(0xc002), result.modeLock().source());
		BankState nmi = result.stateIn().get(addr(NMI));
		assertModeKnown(nmi, 2);
		assertEquals("the bank stays unknown on an async entry (grm-913)", 0,
			nmi.knownMask() & BANK_MASK);
	}

	/** A function nothing calls is seeded with the power-on bank but the LOCKED mode. */
	@Test
	public void anUnreachedFunctionIsSeededWithTheLockedMode() throws Exception {
		put(0xc000, "a9 02 8d 00 90 60");
		put(0xc010, "a9 05 8d 00 a0 60");
		makeFunction(0xc000, 0xc005, "RESET", true);
		makeFunction(0xc010, 0xc015, "ORPHAN", false);

		BankDataflowEngine.DataflowResult result = run();

		BankState orphan = result.stateIn().get(addr(0xc010));
		assertModeKnown(orphan, 2);
		assertEquals("power-on bank 0, known", BANK_MASK, orphan.knownMask() & BANK_MASK);
		assertEquals(0, orphan.bits() & BANK_MASK);
	}

	/** RESET writes two different modes: no lock, and the NMI stays mode-unknown. */
	@Test
	public void disagreeingResetWritesFormNoLock() throws Exception {
		put(0xc000, "a9 02 8d 00 90 a9 01 8d 00 90 4c 0a c0");
		makeFunction(0xc000, 0xc00c, "RESET", true);
		layNmi();

		BankDataflowEngine.DataflowResult result = run();

		assertNull(result.modeLock());
		assertModeUnknown(result.stateIn().get(addr(NMI)));
	}

	/** RESET writes a mode loaded from RAM: unresolved, so no lock. */
	@Test
	public void anUnresolvedResetWriteFormsNoLock() throws Exception {
		put(0xc000, "a5 10 8d 00 90 4c 05 c0"); // LDA $10 / STA $9000 / JMP *
		makeFunction(0xc000, 0xc007, "RESET", true);
		layNmi();

		BankDataflowEngine.DataflowResult result = run();

		assertNull(result.modeLock());
		assertModeUnknown(result.stateIn().get(addr(NMI)));
	}

	/** No mode write anywhere reached from reset: nothing to lock. */
	@Test
	public void noModeWriteFormsNoLock() throws Exception {
		put(0xc000, "4c 00 c0"); // JMP *
		makeFunction(0xc000, 0xc002, "RESET", true);
		layNmi();

		assertNull(run().modeLock());
	}

	/**
	 * The lock forms from RESET's mode 2, then the NMI handler writes mode 1. Verification
	 * rejects the lock, the run is redone without it (the NMI entry is mode-unknown again), and
	 * the rejected lock names the NMI's write as the contradiction -- the analyzer's warning.
	 */
	@Test
	public void aLaterContradictingWriteRejectsTheLockAndTheRunIsRedone() throws Exception {
		put(0xc000, "a9 02 8d 00 90 4c 05 c0");
		makeFunction(0xc000, 0xc007, "RESET", true);
		layNmi("a9 01 8d 00 90 40"); // LDA #$01 / STA $9000 / RTI

		BankDataflowEngine.DataflowResult result = run();

		BankDataflowEngine.ModeLock lock = result.modeLock();
		assertNotNull("the rejected lock rides along as evidence", lock);
		assertTrue(lock.rejected());
		assertEquals(List.of(addr(NMI + 2)), lock.contradictions());
		assertEquals(1, lock.writes().get(addr(NMI + 2)).effect().bits() & MODE_MASK);
		assertModeUnknown(result.stateIn().get(addr(NMI)));
	}

	/**
	 * The owner's ruling (2026-10-11): a wrong lock is significant enough to warn about. The
	 * analyzer raises one WARNING at each contradicting write and a NOTE at the lock's source,
	 * in their own bookmark category -- and a later round whose lock holds clears them.
	 */
	@Test
	public void aRejectedLockRaisesAWarningAtTheContradictionAndALaterRoundClearsIt()
			throws Exception {
		aLaterContradictingWriteRejectsTheLockAndTheRunIsRedone();
		BankDataflowEngine.DataflowResult result = run();
		NesBankingAnalyzer analyzer = new NesBankingAnalyzer();
		String category = analyzer.getBookmarkCategory() + " mode lock";

		int tx = program.startTransaction("annotate");
		int warned;
		try {
			warned = BankAnnotationAdapter.annotateModeLock(analyzer, program, board(),
				result.modeLock(), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals(1, warned);
		Bookmark warning = program.getBookmarkManager()
				.getBookmark(addr(NMI + 2), BookmarkType.WARNING, category);
		assertNotNull("the contradicting write carries the warning", warning);
		assertTrue(warning.getComment(), warning.getComment().contains("mode=2"));
		assertTrue(warning.getComment(), warning.getComment().contains("mode=1"));
		assertNotNull("the lock's source carries the note", program.getBookmarkManager()
				.getBookmark(addr(0xc002), BookmarkType.NOTE, category));

		tx = program.startTransaction("annotate again, lock holds");
		try {
			warned = BankAnnotationAdapter.annotateModeLock(analyzer, program, board(), null,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals(0, warned);
		assertNull("a round without a rejected lock clears the stale warning",
			program.getBookmarkManager().getBookmark(addr(NMI + 2), BookmarkType.WARNING,
				category));
	}

	private int annotate(BankDataflowEngine.ModeLock lock) throws Exception {
		int tx = program.startTransaction("annotate");
		try {
			return BankAnnotationAdapter.annotateModeLock(new NesBankingAnalyzer(), program,
				board(), lock, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private String detectedMode() {
		return program.getOptions(Program.PROGRAM_INFO)
				.getString(DescriptorSupport.DETECTED_PRG_MODE_PROPERTY, null);
	}

	/**
	 * Owner ruling 2026-10-11: a post-lock write whose mode bits do not resolve (smb2's
	 * {@code TYA / ORA #$80 / STA $8000} loop is the real case) KEEPS the lock. The write
	 * deposits the locked mode on the bits it owns, so code after it still knows the mode; the
	 * site is listed as assumed and NOTEd, and the detected mode is published.
	 */
	@Test
	public void anUnresolvedLaterWriteKeepsTheLockAndIsNotedAsAssumed() throws Exception {
		put(0xc000, "a9 02 8d 00 90 4c 05 c0");
		makeFunction(0xc000, 0xc007, "RESET", true);
		layNmi("a5 10 8d 00 90 a9 05 8d 00 a0 40"); // LDA $10 / STA $9000 / LDA #5 / STA $A000

		BankDataflowEngine.DataflowResult result = run();

		BankDataflowEngine.ModeLock lock = result.modeLock();
		assertNotNull(lock);
		assertFalse("an unresolved write does not disprove the lock", lock.rejected());
		assertEquals(List.of(addr(NMI + 2)), lock.assumed());
		assertModeKnown(result.stateIn().get(addr(NMI + 7)), 2);

		assertEquals(0, annotate(lock));
		String category = new NesBankingAnalyzer().getBookmarkCategory() + " mode lock";
		Bookmark note = program.getBookmarkManager()
				.getBookmark(addr(NMI + 2), BookmarkType.NOTE, category);
		assertNotNull("the assumption is visible at the site it was made", note);
		assertTrue(note.getComment(), note.getComment().contains("assumed to stay 2"));
		assertEquals("2", detectedMode());
	}

	/** The detected mode is published while a lock holds, and removed when it is rejected. */
	@Test
	public void detectedModePropertyIsSetForAHeldLockAndErasedForARejectedOne()
			throws Exception {
		put(0xc000, "a9 02 8d 00 90 4c 05 c0");
		makeFunction(0xc000, 0xc007, "RESET", true);
		layNmi();
		annotate(run().modeLock());
		assertEquals("2", detectedMode());

		// A later round whose lock was rejected (the engine path is pinned above, by
		// aLaterContradictingWriteRejectsTheLockAndTheRunIsRedone): the property must go.
		BankDataflowEngine.ModeLock rejected = new BankDataflowEngine.ModeLock(
			new BankState(MODE_MASK, 2), addr(0xc002), List.of(addr(NMI)), List.of(),
			java.util.Map.of(addr(NMI),
				new BankDataflowEngine.ModeWrite(MODE_MASK, new BankState(MODE_MASK, 1))));
		assertTrue(rejected.rejected());
		annotate(rejected);
		assertNull("a rejected lock erases the property", detectedMode());
	}
}
