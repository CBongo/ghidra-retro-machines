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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of {@link DescriptorCopyHintAnalyzer} (grm-1.7.1.2): the descriptor
 * {@code copied_from} directive, and above all the <b>ROM gate</b> that decides whether it does
 * anything at all.
 *
 * <p>The gate is the load-bearing half. Per docs/smc-inplace-vs-overlay.md §6 a directive whose
 * source bytes are unreadable is <em>ignored</em> -- no block, no overlay fallback, not even a
 * warning bookmark (there is no instruction to hang one on), only a log line. A C64 imported
 * without a KERNAL dump must therefore look exactly as it did before this analyzer existed, and
 * the "supply the ROM and re-run" path must then produce the copy. Both halves are asserted here.
 *
 * <p>The analyzer is driven through its {@code applyAll} seam rather than {@code added()}:
 * {@code DescriptorResources.loadMap} resolves through
 * {@code Application.findDataFileInAnyModule}, which searches installed module data directories
 * only, so no descriptor written into a {@code TemporaryFolder} would ever be found from a plain
 * JUnit JVM. Handing {@code applyAll} a parsed map tests the directive semantics -- address
 * resolution, the gate, the placement -- without pretending to test Ghidra's resource lookup. The
 * end-to-end path (real descriptor, real loader, real ROM option) is the headless
 * {@code copyhinttest}/{@code copyhintnorom} fixtures' job.
 */
public class DescriptorCopyHintAnalyzerTest extends AbstractBundledLanguageTest {

	/**
	 * The shipped C64 shape reduced to what the directive needs: ZEROPAGE as the destination
	 * region carrying the CHRGET hint, sourced from {@code KERNAL} at {@code $E3A2}. Disassembly
	 * is off here -- placement and gating are what this class covers.
	 */
	private static final String MAP_JSON = """
		{
		  "regions": [
		    { "name": "ZEROPAGE", "start": 2, "end": 255, "kind": "ram",
		      "copied_from": [
		        { "name": "CHRGET", "start": 115, "end": 138, "source": "KERNAL",
		          "source_addr": 58274, "comment": "CHRGET fetch routine" } ] },
		    { "name": "RAM_MAIN", "start": 2048, "end": 40959, "kind": "ram" }
		  ]
		}
		""";

	/** 0x0073..0x008A inclusive: the 24 bytes CHRGET occupies. */
	private static final int CHRGET_LEN = 0x18;

	private static JsonObject map() {
		return JsonParser.parseString(MAP_JSON).getAsJsonObject();
	}

	private ProgramBuilder newBuilder() throws Exception {
		return new ProgramBuilder("Test", "6502:LE:16:default");
	}

	/**
	 * The C64's zero page as the loader leaves it: one uninitialized RAM block covering the whole
	 * region, so the destination is carvable and any skip comes from the gate rather than from the
	 * placement policy.
	 */
	private static void addZeroPage(ProgramBuilder builder) throws Exception {
		uninitializedRam(builder, "ZEROPAGE", "0x0002", 0xFE);
	}

	/** Runs the analyzer's directive pass inside its own transaction, as auto-analysis does. */
	private boolean apply(ProgramDB program) {
		int tx = program.startTransaction("copy hints");
		boolean commit = false;
		try {
			boolean done = new DescriptorCopyHintAnalyzer().applyAll(program, map(),
				TaskMonitor.DUMMY, new MessageLog());
			commit = true;
			return done;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	/** The synthetic KERNAL of {@code tools/banktest/mkromtest.py}: {@code byte[i] = i & 0xFF}, so
	 *  {@code $E3A2} reads {@code $A2} and CHRGET's 24 bytes are the run {@code $A2..$B9}. */
	private static byte[] expectedChrget() {
		byte[] expected = new byte[CHRGET_LEN];
		for (int i = 0; i < CHRGET_LEN; i++) {
			expected[i] = (byte) (0xA2 + i);
		}
		return expected;
	}

	// ------------------------------------------------------------------
	// 1. The ROM gate: no readable source, no anything
	// ------------------------------------------------------------------

	@Test
	public void unreadableSourceMaterializesNothing() throws Exception {
		ProgramBuilder builder = newBuilder();
		addZeroPage(builder);
		// KERNAL present but uninitialized -- exactly a C64 imported with no -loader-kernalRom.
		builder.createUninitializedMemory("KERNAL", "0xE000", 0x2000);
		ProgramDB program = builder.getProgram();

		assertTrue("the pass should complete, not fail", apply(program));

		assertNull("no block may be created from an unreadable source",
			program.getMemory().getBlock("COPY_0073"));
		// The destination block must be untouched: not split, still uninitialized.
		MemoryBlock zp = program.getMemory().getBlock(builder.addr("0x0073"));
		assertEquals("ZEROPAGE", zp.getName());
		assertEquals(builder.addr("0x0002"), zp.getStart());
		assertEquals(builder.addr("0x00FF"), zp.getEnd());
		assertEquals(2, program.getMemory().getBlocks().length);
		// No instruction to anchor a warning to, so the skip is a log note only.
		assertEquals("no bookmark may be left at the destination", 0,
			program.getBookmarkManager().getBookmarks(builder.addr("0x0073")).length);
	}

	@Test
	public void absentSourceBlockMaterializesNothing() throws Exception {
		ProgramBuilder builder = newBuilder();
		addZeroPage(builder);
		// No KERNAL block at all: the source address resolves into a hole in the base space, which
		// gate 0 must treat exactly like uninitialized bytes rather than throwing.
		ProgramDB program = builder.getProgram();

		assertTrue(apply(program));
		assertNull(program.getMemory().getBlock("COPY_0073"));
		assertEquals(1, program.getMemory().getBlocks().length);
	}

	// ------------------------------------------------------------------
	// 2. Readable source: an in-place carve at the declared range
	// ------------------------------------------------------------------

	@Test
	public void readableSourceCarvesTheDeclaredRangeInPlace() throws Exception {
		ProgramBuilder builder = newBuilder();
		addZeroPage(builder);
		builder.createMemory("KERNAL", "0xE000", 0x2000);
		setKernalPattern(builder);
		ProgramDB program = builder.getProgram();

		assertTrue(apply(program));

		MemoryBlock copy = program.getMemory().getBlock("COPY_0073");
		assertNotNull("a readable source must materialize the directive", copy);
		assertTrue("the copy must be real bytes, not a byte map", copy.isInitialized());
		assertEquals("carved at the declared destination", builder.addr("0x0073"),
			copy.getStart());
		assertEquals("carved to the declared end", builder.addr("0x008A"), copy.getEnd());
		// The point of the in-place placement (grm-chu): a base-space JSR $0073 resolves here.
		assertEquals("the copy must live in the base space, not an overlay",
			program.getAddressFactory().getDefaultAddressSpace(),
			copy.getStart().getAddressSpace());

		byte[] recovered = new byte[CHRGET_LEN];
		copy.getBytes(copy.getStart(), recovered);
		assertArrayEquals("wrong source bytes -- source_addr resolved to the wrong place",
			expectedChrget(), recovered);

		// Provenance: the destination bookmark is unconditional, and the descriptor's own prose
		// survives on the block alongside the materializer's placement note.
		assertTrue("expected a provenance bookmark at the destination",
			program.getBookmarkManager().getBookmarks(builder.addr("0x0073")).length > 0);
		assertTrue("descriptor comment was dropped: " + copy.getComment(),
			copy.getComment().startsWith("CHRGET fetch routine -- "));

		// The carve leaves the rest of zero page alone, still uninitialized.
		MemoryBlock head = program.getMemory().getBlock(builder.addr("0x0002"));
		assertEquals(builder.addr("0x0072"), head.getEnd());
		assertTrue("the untouched head must stay uninitialized", !head.isInitialized());
		MemoryBlock tail = program.getMemory().getBlock(builder.addr("0x008B"));
		assertEquals(builder.addr("0x00FF"), tail.getEnd());
		assertTrue("the untouched tail must stay uninitialized", !tail.isInitialized());
	}

	@Test
	public void reapplyingIsIdempotent() throws Exception {
		ProgramBuilder builder = newBuilder();
		addZeroPage(builder);
		builder.createMemory("KERNAL", "0xE000", 0x2000);
		setKernalPattern(builder);
		ProgramDB program = builder.getProgram();

		apply(program);
		int blocksAfterFirst = program.getMemory().getBlocks().length;
		apply(program);

		// Re-running is the documented recovery path once a ROM arrives, so a second pass over an
		// already-materialized directive must be a no-op rather than a second carve.
		assertEquals(blocksAfterFirst, program.getMemory().getBlocks().length);
		MemoryBlock copy = program.getMemory().getBlock("COPY_0073");
		byte[] recovered = new byte[CHRGET_LEN];
		copy.getBytes(copy.getStart(), recovered);
		assertArrayEquals(expectedChrget(), recovered);
	}

	// ------------------------------------------------------------------
	// 3. Source resolution follows the named block, not just the base space
	// ------------------------------------------------------------------

	@Test
	public void sourceResolvesThroughTheNamedBlockWhenItIsNotHome() throws Exception {
		ProgramBuilder builder = newBuilder();
		addZeroPage(builder);
		// RAM is home at $E000 (a C64 in an all-RAM bank state) and KERNAL lives in its own
		// overlay space, as AbstractCbmPrgLoader.createWindowOccupant places a non-home occupant.
		// Resolving source_addr in the base space would read the RAM, so the hint must follow the
		// block its `source` names.
		builder.createUninitializedMemory("RAM_E000", "0xE000", 0x2000);
		builder.createOverlayMemory("KERNAL", "0xE000", 0x2000);
		ProgramDB program = builder.getProgram();
		MemoryBlock kernal = program.getMemory().getBlock("KERNAL");
		int tx = program.startTransaction("fill");
		try {
			program.getMemory().setBytes(kernal.getStart().add(0x3A2), expectedChrget());
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertTrue(apply(program));

		MemoryBlock copy = program.getMemory().getBlock("COPY_0073");
		assertNotNull("the overlay-homed source should still be readable", copy);
		byte[] recovered = new byte[CHRGET_LEN];
		copy.getBytes(copy.getStart(), recovered);
		assertArrayEquals(expectedChrget(), recovered);
	}

	/** Writes {@code byte[i] = i & 0xFF} over CHRGET's window of the KERNAL block, so {@code $E3A2}
	 *  is {@code $A2} -- the same synthetic pattern the headless {@code kernal.bin} carries. */
	private static void setKernalPattern(ProgramBuilder builder) throws Exception {
		builder.setBytes("0xE3A2", expectedChrget());
	}
}
