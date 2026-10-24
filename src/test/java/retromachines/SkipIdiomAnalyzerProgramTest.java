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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SkipIdiomRepair} (the recognizer shared with {@code FixSkipInstructions.java}) and the
 * one-shot {@link SkipIdiomAnalyzer} on a reduction of wizwarr's bc05 (grm-9xr):
 * <pre>
 *   8000  LDA #$02
 *   8002  BIT $03A9   ; A9 03 hides LDA #$03 at 8003; tail is the RTS at 8005   -> STRONG
 *   8005  RTS
 *
 *   8010  NOP
 *   8011  BIT $10A5   ; A5 10 hides LDA $10 at 8012; tail is the RTS at 8014    -> WEAK
 *   8014  RTS
 * </pre>
 */
public class SkipIdiomAnalyzerProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB build(boolean withIdiom) throws Exception {
		builder = newBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x100);
		if (withIdiom) {
			builder.setBytes("0x8000", "a9 02 2c a9 03 60", true);
			builder.setBytes("0x8010", "ea 2c a5 10 60", true);
		}
		else {
			builder.setBytes("0x8000", "a9 02 8d 00 02 60", true);
		}
		return builder.getProgram();
	}

	private void runAnalyzer(ProgramDB program, SkipIdiomAnalyzer analyzer) throws Exception {
		inTxGet(program, "analyze", () -> {
			assertTrue(analyzer.canAnalyze(program));
			analyzer.added(program, program.getMemory().getLoadedAndInitializedAddressSet(),
				TaskMonitor.DUMMY, new MessageLog());
			return null;
		});
	}

	@Test
	public void isOneShotAndOffByDefault() throws Exception {
		ProgramDB program = build(true);
		SkipIdiomAnalyzer analyzer = new SkipIdiomAnalyzer();
		assertFalse("must not run on import", analyzer.getDefaultEnablement(program));
		assertTrue("must be offered under Analysis > One Shot",
			analyzer.supportsOneTimeAnalysis());
	}

	@Test
	public void recognizerTiersBothCandidates() throws Exception {
		ProgramDB program = build(true);
		var found = SkipIdiomRepair.collect(program,
			program.getMemory().getLoadedAndInitializedAddressSet(),
			SkipIdiomRepair.Options.defaultCarriers(), TaskMonitor.DUMMY);
		assertEquals(2, found.size());
		assertEquals(addr(0x8003), found.get(0).entry());
		assertEquals(SkipIdiomRepair.Confidence.STRONG, found.get(0).confidence());
		assertEquals(addr(0x8005), found.get(0).tail());
		assertEquals(addr(0x8012), found.get(1).entry());
		assertEquals(SkipIdiomRepair.Confidence.WEAK, found.get(1).confidence());
	}

	@Test
	public void sharedRunReportsTheScriptsLines() throws Exception {
		ProgramDB program = build(true);
		List<String> out = new ArrayList<>();
		inTxGet(program, "run", () -> SkipIdiomRepair.run(program,
			program.getMemory().getLoadedAndInitializedAddressSet(),
			new SkipIdiomRepair.Options(SkipIdiomRepair.Options.defaultCarriers(), false, false,
				true),
			TaskMonitor.DUMMY, out::add, out::add));
		assertEquals(List.of(
			"SKIPFIX candidate 8002 BIT hides 8003 LDA [STRONG]",
			"SKIPFIX applied 8002 len=1 entry=8003",
			"SKIPFIX candidate 8011 BIT hides 8012 LDA [WEAK] (not applied)",
			"SKIPFIX summary candidates=2 referenced=0 strong=1 weak=1 applied=1 failed=0"), out);
	}

	@Test
	public void analyzerAppliesConfidentAndBookmarksTheRest() throws Exception {
		ProgramDB program = build(true);
		runAnalyzer(program, new SkipIdiomAnalyzer());

		assertNotNull("hidden LDA #$03 recovered", program.getListing().getInstructionAt(addr(0x8003)));
		assertTrue(program.getListing().getInstructionAt(addr(0x8002)).isLengthOverridden());
		assertNotNull("function at the recovered entry",
			program.getListing().getFunctionAt(addr(0x8003)));
		assertNotNull(program.getBookmarkManager().getBookmark(addr(0x8003), BookmarkType.INFO,
			SkipIdiomRepair.INFO_BOOKMARK_CATEGORY));

		assertNull("WEAK candidate not applied", program.getListing().getInstructionAt(addr(0x8012)));
		assertFalse(program.getListing().getInstructionAt(addr(0x8011)).isLengthOverridden());
		Bookmark note = program.getBookmarkManager().getBookmark(addr(0x8011),
			BookmarkType.NOTE, SkipIdiomAnalyzer.CATEGORY);
		assertNotNull("unapplied candidate is bookmarked", note);
		assertTrue(note.getComment().contains("[WEAK]"));
	}

	@Test
	public void weakOptionAppliesWeakCandidates() throws Exception {
		ProgramDB program = build(true);
		inTxGet(program, "run", () -> SkipIdiomRepair.run(program,
			program.getMemory().getLoadedAndInitializedAddressSet(),
			new SkipIdiomRepair.Options(SkipIdiomRepair.Options.defaultCarriers(), true, false,
				false),
			TaskMonitor.DUMMY, s -> {
			}, s -> {
			}));
		assertNotNull(program.getListing().getInstructionAt(addr(0x8012)));
		assertNull("function:false", program.getListing().getFunctionAt(addr(0x8012)));
	}

	@Test
	public void doesNothingWithoutCarriers() throws Exception {
		ProgramDB program = build(false);
		long before = program.getModificationNumber();
		runAnalyzer(program, new SkipIdiomAnalyzer());
		assertEquals(before, program.getModificationNumber());
		assertFalse(program.getBookmarkManager().getBookmarksIterator().hasNext());
	}
}
