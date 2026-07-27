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
import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@link RunFromElsewhere}, the public facade every run-from-elsewhere
 * front-end goes through (grm-1.7.1.1). {@link TransferMaterializerTest} covers the placement
 * policy underneath; what is tested here is the layer the facade adds on top of it, which exists
 * because two of the four front-ends take their arguments from a human or a hand-written YAML
 * file rather than from real instruction operands:
 *
 * <ul>
 * <li><b>Validation.</b> A bad request is refused with a reason, never silently turned into an
 * overlay in the wrong place.</li>
 * <li><b>{@code alreadyPresent}.</b> The materializer reports {@code SKIPPED} both for "already
 * done" and for "failed"; re-running after supplying a ROM is the documented recovery path, so
 * the facade has to tell those apart.</li>
 * <li><b>{@code originLabel}.</b> Three front-ends share one materializer and only one of them
 * has a loop, so the provenance text is parameterized.</li>
 * <li><b>A null provenance site.</b> A descriptor directive has no instruction to annotate.</li>
 * <li><b>The transaction precondition</b>, which is what keeps a Swing action from corrupting the
 * program by calling straight through.</li>
 * </ul>
 */
public class RunFromElsewhereTest extends AbstractBundledLanguageTest {

	private static final String CATEGORY = "Test";

	private ProgramBuilder newBuilder() throws Exception {
		return new ProgramBuilder("Test", "6502:LE:16:default");
	}

	/**
	 * A program with eight readable source bytes at {@code 0x2000} and an uninitialized 0x1000-byte
	 * RAM block at {@code 0xC000} -- the ordinary carvable case, so any {@code SKIPPED} in these
	 * tests comes from the facade rather than from the placement policy.
	 */
	private ProgramDB carvableProgram(ProgramBuilder builder) throws Exception {
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		uninitializedRam(builder, "RAM_C000", "0xC000", 0x1000);
		return builder.getProgram();
	}

	/** Runs {@link RunFromElsewhere#apply} inside its own transaction, as real callers do. */
	private RunFromElsewhere.Result apply(ProgramDB program, RunFromElsewhere.Request request) {
		int tx = program.startTransaction("apply");
		boolean commit = false;
		try {
			RunFromElsewhere.Result result = RunFromElsewhere.apply(program, request, CATEGORY,
				TaskMonitor.DUMMY, new MessageLog());
			commit = true;
			return result;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	private static Bookmark bookmarkAt(ProgramDB program, Address address) {
		Bookmark[] marks = program.getBookmarkManager().getBookmarks(address);
		return marks.length == 0 ? null : marks[0];
	}

	// ------------------------------------------------------------------
	// 1. request() rejects what can never be a transfer
	// ------------------------------------------------------------------

	@Test
	public void requestRejectsNullAddressesAndNonPositiveLengths() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);
		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");

		for (Runnable bad : new Runnable[] {
			() -> RunFromElsewhere.request(null, dst, 8),
			() -> RunFromElsewhere.request(src, null, 8),
			() -> RunFromElsewhere.request(src, dst, 0),
			() -> RunFromElsewhere.request(src, dst, -1) }) {
			try {
				bad.run();
				fail("expected IllegalArgumentException");
			}
			catch (IllegalArgumentException expected) {
				// the point: a structurally impossible request never reaches the program
			}
		}
		assertNull(program.getMemory().getBlock("COPY_c000"));
	}

	// ------------------------------------------------------------------
	// 2. apply() refuses a well-formed but impossible request, with a reason
	// ------------------------------------------------------------------

	@Test
	public void destinationRunningOffTheAddressSpaceIsRefusedNotOverlaid() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);

		// 0xFFF8 + 0x100 bytes runs past the top of a 16-bit space. The old path would have fallen
		// through canCarve's overflow check into an overlay; the facade refuses outright.
		RunFromElsewhere.Result result = apply(program,
			RunFromElsewhere.request(builder.addr("0x2000"), builder.addr("0xFFF8"), 0x100));

		assertFalse(result.materialized());
		assertFalse(result.alreadyPresent());
		assertTrue("refusal should name the problem: " + result.detail(),
			result.detail().contains("runs off the end"));
		assertNull(program.getMemory().getBlock("COPY_fff8"));
	}

	@Test
	public void entryPointOutsideTheDestinationRangeIsRefused() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);

		// A mid-block entry is legal (headered payloads); one past the end of the copy is not.
		RunFromElsewhere.Result result = apply(program,
			RunFromElsewhere.request(builder.addr("0x2000"), builder.addr("0xC000"), 8)
					.entryPoint(builder.addr("0xC010")));

		assertFalse(result.materialized());
		assertTrue("refusal should name the problem: " + result.detail(),
			result.detail().contains("not inside the destination range"));
		assertNull(program.getMemory().getBlock("COPY_c000"));
	}

	@Test
	public void unimplementedTransformIsRefusedBeforeTouchingMemory() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);

		RunFromElsewhere.Result result = apply(program,
			RunFromElsewhere.request(builder.addr("0x2000"), builder.addr("0xC000"), 8)
					.transform(TransferTransform.ROLLING_XOR));

		assertFalse(result.materialized());
		assertTrue(result.detail().contains("not implemented"));
		assertNull(program.getMemory().getBlock("COPY_c000"));
	}

	// ------------------------------------------------------------------
	// 3. The happy path, and alreadyPresent on a second pass
	// ------------------------------------------------------------------

	@Test
	public void secondApplyReportsAlreadyPresentRatherThanFailure() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);
		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");

		RunFromElsewhere.Result first =
			apply(program, RunFromElsewhere.request(src, dst, 8).originLabel("copy loop"));

		assertEquals(TransferPlacement.IN_PLACE, first.placement());
		assertEquals("COPY_c000", first.blockName());
		assertFalse(first.alreadyPresent());
		assertTrue(first.satisfied());

		RunFromElsewhere.Result second =
			apply(program, RunFromElsewhere.request(src, dst, 8).originLabel("copy loop"));

		// Both report SKIPPED, so alreadyPresent is the only thing that distinguishes an
		// idempotent re-run -- the documented "supply the ROM, then re-run" path -- from a failure.
		assertEquals(TransferPlacement.SKIPPED, second.placement());
		assertTrue(second.alreadyPresent());
		assertTrue(second.satisfied());
		assertEquals("COPY_c000", second.blockName());
	}

	// ------------------------------------------------------------------
	// 4. originLabel reaches the provenance text
	// ------------------------------------------------------------------

	@Test
	public void originLabelAppearsInSiteBookmarkAndComment() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);
		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");

		apply(program, RunFromElsewhere.request(src, dst, 8)
				.provenanceSite(src)
				.originLabel("manual transfer"));

		Bookmark site = bookmarkAt(program, src);
		assertNotNull("expected a provenance bookmark at the site", site);
		assertTrue("bookmark should name the front-end, not 'copy loop': " + site.getComment(),
			site.getComment().startsWith("manual transfer -> COPY_c000"));
		assertEquals("manual transfer -> COPY_c000",
			program.getListing().getCodeUnitAt(src).getComment(
				ghidra.program.model.listing.CommentType.EOL));
	}

	// ------------------------------------------------------------------
	// 5. A null provenance site: bytes land, nothing is annotated at a site
	// ------------------------------------------------------------------

	@Test
	public void nullProvenanceSiteStillMaterializesAndBookmarksOnlyTheDestination()
			throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);
		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");

		// A descriptor copied_from directive has no instruction to point at (grm-1.7.1.2).
		RunFromElsewhere.Result result = apply(program, RunFromElsewhere.request(src, dst, 8)
				.originLabel("descriptor copied_from hint"));

		assertEquals(TransferPlacement.IN_PLACE, result.placement());
		assertNull("no site bookmark without a site", bookmarkAt(program, src));
		Bookmark dest = bookmarkAt(program, dst);
		assertNotNull("the destination bookmark is unconditional", dest);
		assertTrue(dest.getComment().contains("run-from-elsewhere copy of"));
	}

	@Test
	public void unreadableSourceWithNoSiteProducesNothingAndNoWarningBookmark() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createUninitializedMemory("ROM", "0xE000", 0x100);
		uninitializedRam(builder, "RAM_C000", "0xC000", 0x100);
		ProgramDB program = builder.getProgram();

		// The ROM-gated rule of docs/smc-inplace-vs-overlay.md section 6: no readable source means
		// the directive is ignored entirely -- log note only, no block, and with no instruction to
		// anchor to, not even a warning bookmark.
		RunFromElsewhere.Result result =
			apply(program, RunFromElsewhere.request(builder.addr("0xE000"),
				builder.addr("0xC000"), 8).originLabel("descriptor copied_from hint"));

		assertFalse(result.materialized());
		assertFalse(result.alreadyPresent());
		assertNull(program.getMemory().getBlock("COPY_c000"));
		assertNull(bookmarkAt(program, builder.addr("0xE000")));
		assertNull(bookmarkAt(program, builder.addr("0xC000")));
	}

	// ------------------------------------------------------------------
	// 6. The transaction precondition
	// ------------------------------------------------------------------

	@Test
	public void applyWithoutATransactionFailsImmediately() throws Exception {
		ProgramBuilder builder = newBuilder();
		ProgramDB program = carvableProgram(builder);

		try {
			RunFromElsewhere.apply(program,
				RunFromElsewhere.request(builder.addr("0x2000"), builder.addr("0xC000"), 8),
				CATEGORY, TaskMonitor.DUMMY, new MessageLog());
			fail("expected IllegalStateException outside a transaction");
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("transaction"));
		}
		assertNull(program.getMemory().getBlock("COPY_c000"));
	}
}
