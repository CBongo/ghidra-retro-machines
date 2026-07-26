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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 ({@code AbstractGenericTest} + {@code ProgramBuilder}) coverage of
 * {@link TransferMaterializer#materialize} -- the grm-chu placement policy that decides whether a
 * recovered run-from-elsewhere copy is carved into its containing block <em>in place</em> or
 * falls back to a byte-mapped {@code OVERLAY}, plus the carve geometry itself (bead grm-chu).
 * Each test builds its own minimal memory map with a plain {@code ProgramBuilder} (no loader, no
 * analyzer) so the placement decision and the carve/overlay mechanics are exercised in isolation,
 * mirroring {@link BankStrategyProgramTest}'s style. {@code TransferMaterializer},
 * {@code TransferSpec}, and {@code TransferPlacement} are all package-private, so
 * this test lives in {@code retromachines} to reach them directly -- there is no public API to
 * test through.
 *
 * <p>Every test calls {@link #materialize} inside its own {@code program.startTransaction} /
 * {@code endTransaction} pair, since the production method mutates memory (splits, converts,
 * writes bytes, bookmarks) and {@code ProgramBuilder}'s own transaction helper is not in scope
 * once the builder has handed back its {@code ProgramDB}.
 */
public class TransferMaterializerTest extends AbstractGenericTest {

	private static final String CATEGORY = "Test";

	private ProgramBuilder newBuilder() throws Exception {
		return new ProgramBuilder("Test", "6502:LE:16:default");
	}

	/** Runs {@link TransferMaterializer#materialize} inside its own transaction, as production
	 *  callers (the analyzer, the loader) always do. */
	private TransferPlacement materialize(ProgramDB program, TransferSpec spec) {
		int tx = program.startTransaction("materialize");
		boolean commit = false;
		try {
			TransferPlacement placement =
				TransferMaterializer.materialize(program, spec, CATEGORY, TaskMonitor.DUMMY,
					new MessageLog());
			commit = true;
			return placement;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	/** A plain verbatim copy spec: {@code IDENTITY} transform, disassembly off (the carve/overlay
	 *  decision and the memory map are what these tests exercise, not disassembly -- that is
	 *  covered by the headless {@code copyloop}/{@code copydata}/{@code copyoverlay} fixtures). */
	private static TransferSpec identitySpec(Address src, Address dst, int len,
			TransferTarget target, Address provenanceSite) {
		return new TransferSpec(src, dst, len, TransferTransform.IDENTITY, target,
			provenanceSite, TransferSpec.Confidence.CANDIDATE, false, false, dst, null,
			"copy loop");
	}

	private static void assertBlock(MemoryBlock block, String name, Address start, Address end,
			boolean initialized) {
		assertNotNull("expected a block at " + start, block);
		assertEquals("block name", name, block.getName());
		assertEquals("block start", start, block.getStart());
		assertEquals("block end", end, block.getEnd());
		assertEquals("block " + name + " isInitialized", initialized, block.isInitialized());
	}

	private static void assertNoSplitNames(ProgramDB program) {
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			assertFalse("block name leaked a Memory.split() default: " + b.getName(),
				b.getName().endsWith(".split"));
		}
	}

	private static byte[] readBlock(MemoryBlock block, int len) throws Exception {
		byte[] buf = new byte[len];
		block.getBytes(block.getStart(), buf);
		return buf;
	}

	/** Address+name+init snapshot of every block, for idempotence's before/after comparison. */
	private static List<String> snapshotBlocks(ProgramDB program) {
		List<String> out = new ArrayList<>();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			out.add(b.getName() + " " + b.getStart() + "-" + b.getEnd() + " init=" +
				b.isInitialized());
		}
		return out;
	}

	// ------------------------------------------------------------------
	// 1. Unreadable source -> SKIPPED, no block of any kind
	// ------------------------------------------------------------------

	@Test
	public void unreadableSourceIsSkippedAndLeavesDestinationBlockUnsplit() throws Exception {
		ProgramBuilder builder = newBuilder();
		// Source range is uninitialized -- Memory.getBytes over it throws, so gate 0 fails.
		builder.createUninitializedMemory("SRC", "0x2000", 0x10);
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x10);
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");
		TransferSpec spec =
			identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.SKIPPED, placement);
		assertNull("no COPY_ block should exist", program.getMemory().getBlock("COPY_c000"));
		// Destination's containing block is untouched: same name, same start/end, still
		// uninitialized -- gate 0 fires before any split/convert/write is attempted.
		assertBlock(program.getMemory().getBlock(dst), "RAM_C000", dst, builder.addr("0xC00f"),
			false);

		// Gate 0's documented behavior: a WARNING bookmark at the provenance site, so the missing
		// source can be found and supplied later (materialization is idempotent -- see test 7).
		boolean warned = false;
		for (Bookmark bm : program.getBookmarkManager().getBookmarks(src)) {
			if (CATEGORY.equals(bm.getCategory()) && "Warning".equals(bm.getTypeString())) {
				warned = true;
			}
		}
		assertTrue("expected a WARNING bookmark at the provenance site", warned);
	}

	// ------------------------------------------------------------------
	// 2. Non-IDENTITY transform -> SKIPPED, no block created
	// ------------------------------------------------------------------

	@Test
	public void nonIdentityTransformIsSkippedEvenWhenDestinationIsCarvable() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		// A destination that WOULD be perfectly carvable under IDENTITY -- proves the transform
		// check is its own fence, not a side effect of an unreadable source or bad geometry.
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x10);
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");
		Address end = builder.addr("0xC00f");
		// CONSTANT_XOR: grm-1.7.1 recovers verbatim copies only, so a transformed transfer has no
		// computed bytes to place. This is also the fence that stops a future decrypt-unification
		// (grm-1.7.2) from carving a destination and overwriting its real encrypted bytes with a
		// synthetic fill -- canCarve re-checks the same condition independently for exactly that
		// reason (see TransferMaterializer's class javadoc).
		TransferSpec spec = new TransferSpec(src, dst, 8, TransferTransform.CONSTANT_XOR,
			TransferTarget.SAME_SPACE, src, TransferSpec.Confidence.CANDIDATE, false,
			false, dst, null, "copy loop");

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.SKIPPED, placement);
		assertNull(program.getMemory().getBlock("COPY_c000"));
		assertBlock(program.getMemory().getBlock(dst), "RAM_C000", dst, end, false);
	}

	// ------------------------------------------------------------------
	// 3. Destination block already initialized -> OVERLAY
	// ------------------------------------------------------------------

	@Test
	public void initializedDestinationBlockFallsBackToOverlay() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		// Destination already holds real (loaded) bytes -- never overwrite them with a carve.
		builder.createMemory("RAM_C000", "0xC000", 0x10);
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");
		Address end = builder.addr("0xC00f");
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.OVERLAY, placement);
		MemoryBlock overlay = program.getMemory().getBlock("COPY_c000");
		assertNotNull(overlay);
		assertTrue("carved-overlay block should be an overlay block", overlay.isOverlay());
		assertTrue(overlay.getStart().getAddressSpace().isOverlaySpace());
		// The original initialized block is completely untouched: not split, not renamed.
		assertBlock(program.getMemory().getBlock(dst), "RAM_C000", dst, end, true);
	}

	// ------------------------------------------------------------------
	// 4. Destination range straddles two blocks -> OVERLAY
	// ------------------------------------------------------------------

	@Test
	public void destinationStraddlingTwoBlocksFallsBackToOverlay() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		// Two adjacent uninitialized blocks; dst..dst+len-1 crosses the boundary between them.
		builder.createUninitializedMemory("BLOCK_A", "0xC000", 4); // C000-C003
		builder.createUninitializedMemory("BLOCK_B", "0xC004", 4); // C004-C007
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC002"); // range C002-C005: half in A, half in B
		TransferSpec spec = identitySpec(src, dst, 4, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.OVERLAY, placement);
		MemoryBlock overlay = program.getMemory().getBlock("COPY_c002");
		assertNotNull(overlay);
		assertTrue(overlay.isOverlay());
		// Neither original block was split or converted -- multi-block carve is out of scope.
		assertBlock(program.getMemory().getBlock(builder.addr("0xC000")), "BLOCK_A",
			builder.addr("0xC000"), builder.addr("0xC003"), false);
		assertBlock(program.getMemory().getBlock(builder.addr("0xC004")), "BLOCK_B",
			builder.addr("0xC004"), builder.addr("0xC007"), false);
	}

	// ------------------------------------------------------------------
	// 4b. Wholly unmapped destination -> NEW_BLOCK (grm-1.7.6)
	// ------------------------------------------------------------------

	@Test
	public void whollyUnmappedDestinationGetsItsOwnBaseSpaceBlock() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		// Nothing at all covers 0x6000 -- the case of an NES board whose descriptor declares no
		// PRG-RAM region. There is no block to carve, but equally no conflict to avoid, so an
		// overlay would be the worst of the three placements: the bytes belong in the base space
		// where a JSR into them resolves for free.
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0x6000");
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.NEW_BLOCK, placement);
		MemoryBlock block = program.getMemory().getBlock("COPY_6000");
		assertBlock(block, "COPY_6000", dst, builder.addr("0x6007"), true);
		assertFalse("the whole point is a base-space block, not an overlay", block.isOverlay());
		assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, readBlock(block, 8));
	}

	@Test
	public void destinationStartingInAHoleButEndingInABlockFallsBackToOverlay() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		builder.createUninitializedMemory("RAM_6004", "0x6004", 4); // 6004-6007; 6000-6003 is a hole
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0x6000"); // range 6000-6007: half hole, half block

		TransferPlacement placement =
			materialize(program, identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src));

		// getBlock(dst) is null here too, so the emptiness test has to be whole-range: creating a
		// block over this range would collide with RAM_6004.
		assertEquals(TransferPlacement.OVERLAY, placement);
		assertTrue(program.getMemory().getBlock("COPY_6000").isOverlay());
		assertBlock(program.getMemory().getBlock(builder.addr("0x6004")), "RAM_6004",
			builder.addr("0x6004"), builder.addr("0x6007"), false);
	}

	// ------------------------------------------------------------------
	// 5. TargetKind.SAME_SPACE_OVERLAY forces OVERLAY even when carvable
	// ------------------------------------------------------------------

	@Test
	public void explicitOverlayTargetIsHonoredEvenWhenCarvable() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "01 02 03 04 05 06 07 08");
		// A destination that is otherwise perfectly carvable (whole uninitialized DEFAULT block).
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x10);
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");
		Address end = builder.addr("0xC00f");
		TransferSpec spec =
			identitySpec(src, dst, 8, TransferTarget.SAME_SPACE_OVERLAY, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.OVERLAY, placement);
		MemoryBlock overlay = program.getMemory().getBlock("COPY_c000");
		assertNotNull(overlay);
		assertTrue(overlay.isOverlay());
		// The carvable block was left exactly as it was -- the front-end asked for the overlay
		// representation and got it, with no split/convert side effect.
		assertBlock(program.getMemory().getBlock(dst), "RAM_C000", dst, end, false);
	}

	// ------------------------------------------------------------------
	// 6. Carve geometry -- four cases
	// ------------------------------------------------------------------

	@Test
	public void carveInteriorOfBlockYieldsThreeBlocks() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "11 12 13 14 15 16 17 18");
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x1000); // C000-CFFF
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC100"); // strictly interior
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.IN_PLACE, placement);
		// 3 carve pieces (RAM_C000, COPY_c100, RAM_C000_C108) + the untouched SRC block.
		assertEquals(4, program.getMemory().getBlocks().length);
		assertBlock(program.getMemory().getBlock(builder.addr("0xC000")), "RAM_C000",
			builder.addr("0xC000"), builder.addr("0xC0ff"), false);
		MemoryBlock copy = program.getMemory().getBlock("COPY_c100");
		assertBlock(copy, "COPY_c100", dst, builder.addr("0xC107"), true);
		assertBlock(program.getMemory().getBlock(builder.addr("0xC108")), "RAM_C000_C108",
			builder.addr("0xC108"), builder.addr("0xCfff"), false);
		assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
			readBlock(copy, 8));
		assertNoSplitNames(program);
	}

	@Test
	public void carveAtBlockStartYieldsTwoBlocks() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x200e", 0x10);
		builder.setBytes("0x200e", "01 02 03 04 05 06 07 08");
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x1000); // C000-CFFF
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x200e");
		Address dst = builder.addr("0xC000"); // dst == block start
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.IN_PLACE, placement);
		// 2 carve pieces (COPY_c000, RAM_C000_C008) + the untouched SRC block.
		assertEquals(3, program.getMemory().getBlocks().length);
		// The bare name RAM_C000 is consumed by the carve -- there is no lower fragment to keep it.
		assertNull(program.getMemory().getBlock("RAM_C000"));
		MemoryBlock copy = program.getMemory().getBlock("COPY_c000");
		assertBlock(copy, "COPY_c000", dst, builder.addr("0xC007"), true);
		assertBlock(program.getMemory().getBlock(builder.addr("0xC008")), "RAM_C000_C008",
			builder.addr("0xC008"), builder.addr("0xCfff"), false);
		assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, readBlock(copy, 8));
		assertNoSplitNames(program);
	}

	@Test
	public void carveAtBlockEndYieldsTwoBlocks() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "21 22 23 24 25 26 27 28");
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x1000); // C000-CFFF
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xCFF8"); // dst end (0xCFFF) == block end
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.IN_PLACE, placement);
		// 2 carve pieces (RAM_C000, COPY_cff8) + the untouched SRC block.
		assertEquals(3, program.getMemory().getBlocks().length);
		assertBlock(program.getMemory().getBlock(builder.addr("0xC000")), "RAM_C000",
			builder.addr("0xC000"), builder.addr("0xCff7"), false);
		MemoryBlock copy = program.getMemory().getBlock("COPY_cff8");
		assertBlock(copy, "COPY_cff8", dst, builder.addr("0xCfff"), true);
		assertArrayEquals(new byte[] {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
			readBlock(copy, 8));
		assertNoSplitNames(program);
	}

	@Test
	public void carveOfWholeBlockYieldsOneBlockWithNoSplits() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x2000", 0x10);
		builder.setBytes("0x2000", "31 32 33 34 35 36 37 38");
		builder.createUninitializedMemory("RAM_C000", "0xC000", 8); // C000-C007, exactly len
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x2000");
		Address dst = builder.addr("0xC000");
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		TransferPlacement placement = materialize(program, spec);

		assertEquals(TransferPlacement.IN_PLACE, placement);
		// 1 carve piece (COPY_c000, no splits at all) + the untouched SRC block.
		assertEquals(2, program.getMemory().getBlocks().length);
		MemoryBlock copy = program.getMemory().getBlock("COPY_c000");
		assertBlock(copy, "COPY_c000", dst, builder.addr("0xC007"), true);
		assertArrayEquals(new byte[] {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38},
			readBlock(copy, 8));
		assertNoSplitNames(program);
	}

	// ------------------------------------------------------------------
	// 7. Idempotence
	// ------------------------------------------------------------------

	@Test
	public void secondMaterializePassIsSkippedAndLeavesMapUnchanged() throws Exception {
		ProgramBuilder builder = newBuilder();
		builder.createMemory("SRC", "0x200e", 0x10);
		builder.setBytes("0x200e", "01 02 03 04 05 06 07 08");
		builder.createUninitializedMemory("RAM_C000", "0xC000", 0x1000);
		ProgramDB program = builder.getProgram();

		Address src = builder.addr("0x200e");
		Address dst = builder.addr("0xC000");
		TransferSpec spec = identitySpec(src, dst, 8, TransferTarget.SAME_SPACE, src);

		assertEquals(TransferPlacement.IN_PLACE, materialize(program, spec));
		List<String> before = snapshotBlocks(program);

		assertEquals(TransferPlacement.SKIPPED, materialize(program, spec));
		List<String> after = snapshotBlocks(program);

		assertEquals("a re-run must not touch the map a prior pass already materialized", before,
			after);
	}
}
