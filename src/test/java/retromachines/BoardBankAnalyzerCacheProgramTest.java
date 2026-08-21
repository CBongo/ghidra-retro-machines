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

import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.NumericUtilities;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Tier-2 coverage of the {@code LAST_COMPLETED} redundant-rerun cache (grm-w3m, QR-07 of
 * {@code docs/QUALITY_REVIEW_2026-08-10.md}): {@link BoardBankAnalyzer} must key its
 * skip-cache on {@link Program#getModificationNumber()} captured at run <em>exit</em>, not
 * on the old function-count/instruction-count fingerprint, which a same-count retype could
 * leave stale.
 * <p>
 * Drives {@link BoardBankAnalyzer#added} directly (bypassing {@code canAnalyze}/the
 * framework's analysis scheduler, exactly as {@code DescriptorCopyHintAnalyzerTest} does for
 * its analyzer) against a throwaway minimal descriptor. The descriptor cannot be handed in as
 * a parsed object -- {@code added()} always resolves {@code getMapPath(program)} through
 * {@code DescriptorSupport.loadMap}, which in turn goes through
 * {@code Application.findDataFileInAnyModule} -- so it is written to a real file under this
 * module's {@code data/machines/} (found live via {@code grm.moduleDir}, exactly like the
 * shipped {@code machines/c64.map} that {@code NesPlacementValidationTest} reads the same
 * way) and removed again in {@link #tearDown}. {@code data/machines/*.map} files are already
 * gitignored build products, so a stray throwaway file here is harmless as long as it does
 * not outlive the test.
 */
public class BoardBankAnalyzerCacheProgramTest extends AbstractBundledLanguageTest {

	private static final String MAP_NAME = "w3m-cachetest.map";

	/**
	 * One 8-bit {@code bank} field, one {@code register-write} mechanism at address 1
	 * (mirroring the C64 $01 port idiom {@code BankStrategyProgramTest} already exercises),
	 * no windows -- the engine's window/mirror/helper machinery all degrade to empty
	 * no-ops with no {@code windows}/{@code layouts} section, which is exactly what keeps
	 * this fixture small while still exercising the real {@code added()} pipeline end to
	 * end (dataflow, value recovery, EOL annotation).
	 */
	private static final String MAP_JSON = """
		{
		  "banking": {
		    "state": [ { "name": "bank", "bits": 8 } ],
		    "initial_state": 0,
		    "mechanisms": [
		      { "strategy": "register-write", "params": { "address": 1 } }
		    ]
		  }
		}
		""";

	/** Points the engine at {@link #MAP_JSON}; loader gating is irrelevant since the test
	 *  drives {@code added()} directly rather than through {@code canAnalyze}. */
	private static class TestAnalyzer extends BoardBankAnalyzer {
		TestAnalyzer() {
			super("W3M Cache Test Analyzer", "grm-w3m cache regression fixture");
		}

		@Override
		protected String getLoaderName() {
			return "w3m-cache-test-loader";
		}

		@Override
		protected String getMapPath(Program program) {
			return "machines/" + MAP_NAME;
		}
	}

	private ProgramBuilder builder;
	private ProgramDB program;
	private File mapFile;

	@Before
	public void setUp() throws Exception {
		injectBankSwitchStrategyExtensionPoint();
		String moduleDir = System.getProperty(MODULE_DIR_PROPERTY);
		assertNotNull("grm.moduleDir is not set -- run these tests through Gradle", moduleDir);
		mapFile = new File(new File(moduleDir, "data/machines"), MAP_NAME);
		try (FileWriter writer = new FileWriter(mapFile)) {
			writer.write(MAP_JSON);
		}

		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x2000);
		program = builder.getProgram();
	}

	/**
	 * Makes {@code register-write} resolvable through
	 * {@code BoardBankAnalyzer.configureStrategies}'s {@code ClassSearcher.getInstances
	 * (BankSwitchStrategy.class)} call, without ever calling the real
	 * {@link ClassSearcher#search}.
	 * <p>
	 * {@code ClassSearcher.getInstances} returns nothing at all until a search has
	 * actually run once -- something the normal Ghidra launchers do during startup but
	 * that never happens on this bare JUnit path. The obvious fix,
	 * {@code ClassSearcher.search(TaskMonitor.DUMMY)}, is exactly what NOT to do here:
	 * {@code hasSearched} is a process-wide static latch with no way to undo it, and a
	 * real search also populates every OTHER extension-point suffix on the classpath --
	 * including {@code Analyzer} -- for the rest of this JVM. Since every other Tier-2
	 * test in this module builds programs with {@code ProgramBuilder.setBytes(..., true)}
	 * / {@code disassemble()}, which calls {@code AutoAnalysisManager.startAnalysis}, a
	 * real search silently turns those calls from the no-ops they have always been (no
	 * analyzers discoverable) into real background analysis runs against unrelated
	 * fixtures -- confirmed by hand: adding a bare {@code ClassSearcher.search(...)} call
	 * here reproducibly broke unrelated classes elsewhere in the same {@code gradle test}
	 * run with {@code OverlappingFunctionException}, even though they pass in isolation.
	 * <p>
	 * So this reflectively seeds JUST the {@code BankSwitchStrategy} suffix bucket with
	 * one entry (this test only ever needs {@code register-write}) and flips
	 * {@code hasSearched} straight to {@code true}, skipping the actual classpath walk
	 * entirely. Every other suffix's bucket -- {@code Analyzer} included -- stays absent,
	 * so {@code ClassSearcher.getClasses} keeps returning empty for them exactly as it did
	 * before any test ever touched the class, and {@code AutoAnalysisManager.startAnalysis}
	 * remains a no-op everywhere else. {@code loadExtensionPoint}'s {@code path} argument
	 * is only consulted for the (disabled-by-default) restricted-extension classloader
	 * path, so any placeholder string is fine there. If a real search somehow already ran
	 * (some other test called it first), this leaves {@code ClassSearcher} alone --
	 * {@code register-write} would already be discoverable from that real scan.
	 */
	@SuppressWarnings("unchecked")
	private static void injectBankSwitchStrategyExtensionPoint() throws Exception {
		Field hasSearchedField = ClassSearcher.class.getDeclaredField("hasSearched");
		hasSearchedField.setAccessible(true);
		if (hasSearchedField.getBoolean(null)) {
			return;
		}
		Field mapField = ClassSearcher.class.getDeclaredField("extensionPointSuffixToInfoMap");
		mapField.setAccessible(true);
		Map<String, Set<ClassFileInfo>> map = new HashMap<>();
		map.put("BankSwitchStrategy", Set.of(new ClassFileInfo("grm-w3m-test-injected",
			RegisterWriteBankSwitchStrategy.class.getName(), "BankSwitchStrategy")));
		mapField.set(null, map);
		hasSearchedField.set(null, true);
	}

	@After
	public void tearDown() {
		if (mapFile != null) {
			mapFile.delete();
		}
	}

	/** Runs {@code added()} inside its own transaction, exactly as auto-analysis does. */
	private boolean apply(TestAnalyzer analyzer, MessageLog log) throws CancelledException {
		int tx = program.startTransaction("bank analysis");
		boolean commit = false;
		try {
			boolean done = analyzer.added(program, new AddressSet(), TaskMonitor.DUMMY, log);
			commit = true;
			return done;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	/**
	 * Overwrites the bytes at {@code address} and re-disassembles, replacing whatever
	 * instruction was already there -- a same-length "retype" that preserves both the
	 * function count and the total instruction count. {@code ProgramBuilder.setBytes}
	 * cannot be reused for this: writing over live instruction bytes throws
	 * ("Memory change conflicts with instruction"), so the stale code unit must be
	 * cleared first.
	 */
	private void retype(String address, String hex) throws Exception {
		Address addr = builder.addr(address);
		byte[] bytes = NumericUtilities.convertStringToBytes(hex);
		int tx = program.startTransaction("retype");
		boolean commit = false;
		try {
			program.getListing().clearCodeUnits(addr, addr.add(bytes.length - 1), false);
			program.getMemory().setBytes(addr, bytes);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		builder.disassemble(address, bytes.length);
	}

	private String eolComment(String address) {
		Listing listing = program.getListing();
		return listing.getComment(CommentType.EOL, builder.addr(address));
	}

	/**
	 * White-box peek at {@code BoardBankAnalyzer.LAST_COMPLETED}'s stored modification
	 * number for {@link #program}, via reflection -- the field and its {@code RunStamp}
	 * record are both {@code private}, and this is the only way to observe the cache's
	 * actual invariant directly rather than inferring it from side effects that the
	 * "never overwrite an existing bank comment" annotation rule can mask.
	 */
	@SuppressWarnings("unchecked")
	private static Object rawStamp(Program program) throws Exception {
		Field field = BoardBankAnalyzer.class.getDeclaredField("LAST_COMPLETED");
		field.setAccessible(true);
		Map<Object, Object> map = (Map<Object, Object>) field.get(null);
		return map.get(program);
	}

	private static long stampModificationNumber(Object stamp) throws Exception {
		Method accessor = stamp.getClass().getDeclaredMethod("modificationNumber");
		accessor.setAccessible(true);
		return (Long) accessor.invoke(stamp);
	}

	/**
	 * Two functions, only the first performing a real mechanism write ({@code STA $01});
	 * the second writes a different address ({@code STA $02}) so it starts out
	 * unrecognized by the {@code register-write} mechanism.
	 */
	private void buildFixture() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 01", true); // STA $01 -- mechanism write, bank=5
		builder.createEmptyFunction("f1", "0x8000", 4, null);

		builder.setBytes("0x9000", "a9 07", true); // LDA #$07
		builder.setBytes("0x9002", "85 02", true); // STA $02 -- NOT the mechanism address
		builder.createEmptyFunction("f2", "0x9000", 4, null);
	}

	// ------------------------------------------------------------------
	// 1. The actual regression: a same-count retype must be picked up.
	// ------------------------------------------------------------------

	@Test
	public void regressionRerunsAfterEditPreservingBothCounts() throws Exception {
		buildFixture();
		TestAnalyzer analyzer = new TestAnalyzer();

		assertTrue(apply(analyzer, new MessageLog()));
		String firstComment = eolComment("0x8002");
		assertNotNull("first run should annotate the recognized switch at 0x8002",
			firstComment);
		assertTrue("wrong bank value in first-run annotation: " + firstComment,
			firstComment.contains("bank -> 5"));
		assertNull("0x9002 is not the mechanism address yet; must not be annotated",
			eolComment("0x9002"));

		int functionsBefore = program.getFunctionManager().getFunctionCount();
		long instructionsBefore = program.getListing().getNumInstructions();

		// Retype 0x9002 from "STA $02" to "STA $01": same instruction length and count,
		// same function count, but it is now a recognized mechanism write (bank=7, from
		// the LDA #$07 already sitting at 0x9000) that the first run never saw. This is
		// QR-07's failure mode: a count-only fingerprint cannot see this edit at all.
		retype("0x9002", "85 01"); // STA $01 -- now a mechanism write

		assertEquals("fixture must preserve function count for this to be a regression test",
			functionsBefore, program.getFunctionManager().getFunctionCount());
		assertEquals(
			"fixture must preserve instruction count for this to be a regression test",
			instructionsBefore, program.getListing().getNumInstructions());

		assertTrue(apply(analyzer, new MessageLog()));
		String secondComment = eolComment("0x9002");
		assertNotNull("a same-count retype must be detected and re-annotated, not skipped " +
			"as a redundant rerun", secondComment);
		assertTrue("wrong bank value in re-run annotation: " + secondComment,
			secondComment.contains("bank -> 7"));
	}

	// ------------------------------------------------------------------
	// 2. A truly unchanged invocation is still skipped (the cache still works).
	// ------------------------------------------------------------------

	@Test
	public void trulyUnchangedInvocationIsSkipped() throws Exception {
		buildFixture();
		TestAnalyzer analyzer = new TestAnalyzer();

		assertTrue(apply(analyzer, new MessageLog()));
		Object firstStamp = rawStamp(program);
		assertNotNull("first completed run must populate the cache", firstStamp);
		long firstModNum = stampModificationNumber(firstStamp);
		String commentAfterFirstRun = eolComment("0x8002");
		assertNotNull(commentAfterFirstRun);

		// The gate itself reads program.getModificationNumber() AFTER AnalyzerRunLog.
		// markCompleted()'s own Options write on every call (hit or miss), so the stamp
		// stored on a completed run must be captured AFTER that same write too, or the two
		// reads are permanently misaligned by markCompleted()'s own bump and a truly
		// unchanged next invocation would never hit the gate at all -- exactly the ordering
		// bug this test caught against an earlier draft of the fix (markCompleted() called
		// AFTER the LAST_COMPLETED.put() snapshot instead of before it).
		//
		// What the gate actually promises, and what matters here: the CACHED stamp does not
		// move across redundant calls, i.e. the analysis body itself did not run again. If
		// the gate had instead missed and done a full rerun, it would have recorded a NEW
		// (higher) modification number into LAST_COMPLETED, since a full run's own writes
		// happen before its own exit-time capture -- so firstModNum == secondModNum (and,
		// two calls later, == thirdModNum) is exactly the "truly unchanged invocation is
		// still skipped" claim, not a weaker proxy for it.
		assertTrue(apply(analyzer, new MessageLog()));
		Object secondStamp = rawStamp(program);
		assertNotNull(secondStamp);
		long secondModNum = stampModificationNumber(secondStamp);

		assertTrue(apply(analyzer, new MessageLog()));
		Object thirdStamp = rawStamp(program);
		assertNotNull(thirdStamp);
		long thirdModNum = stampModificationNumber(thirdStamp);

		assertEquals("the cached stamp must not move on a skipped (redundant) run -- a " +
			"moved stamp means the gate missed and the analysis body ran again",
			firstModNum, secondModNum);
		assertEquals("the gate must keep hitting on a THIRD redundant call, not just the " +
			"first one", firstModNum, thirdModNum);
		assertEquals("a skipped run must not touch the existing annotation",
			commentAfterFirstRun, eolComment("0x8002"));
	}

	// ------------------------------------------------------------------
	// 3. Cancellation never records a completed stamp.
	// ------------------------------------------------------------------

	@Test
	public void cancellationNeverRecordsACompletedStamp() throws Exception {
		buildFixture();
		TestAnalyzer analyzer = new TestAnalyzer();

		TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
		cancelled.cancel();
		assertTrue("monitor must actually report cancelled for this test to mean anything",
			cancelled.isCancelled());

		int tx = program.startTransaction("bank analysis (cancelled)");
		boolean commit = false;
		CancelledException thrown = null;
		try {
			try {
				analyzer.added(program, new AddressSet(), cancelled, new MessageLog());
			}
			catch (CancelledException e) {
				thrown = e;
			}
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		assertNotNull("added() must propagate CancelledException from a pre-cancelled monitor",
			thrown);

		assertNull("a cancelled run must never populate the completed-run cache",
			rawStamp(program));
	}

	/** Sanity check that the fixture itself behaves as designed (not a cache assertion). */
	@Test
	public void fixtureSetupIsSane() throws Exception {
		buildFixture();
		assertFalse("this fixture is meaningless without disassembled instructions",
			program.getListing().getNumInstructions() == 0);
	}
}
