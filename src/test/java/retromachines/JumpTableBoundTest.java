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
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import retromachines.JumpTableBound.LoadTableEntry;
import retromachines.JumpTableBound.Result;

/**
 * Pure-logic tests for {@link JumpTableBound} (grm-eyn). Shapes are taken from the megaman bank 5
 * table (a737, 8 real entries, decompiler recovers 128) and the C++ reference's own worked
 * examples in {@code lowest-target-475cf359.patch}.
 */
public class JumpTableBoundTest {

	/** Build a garbage-but-deterministic target list: real targets first, then junk that never
	 *  dips below the lowest real target, so only the table-extent collision can cut it off. */
	private static List<Long> targets(long... values) {
		List<Long> list = new ArrayList<>();
		for (long v : values) {
			list.add(v);
		}
		return list;
	}

	private static List<Long> targetsWithJunk(long[] real, long junkBase, int junkCount) {
		List<Long> list = new ArrayList<>(targets(real));
		for (int i = 0; i < junkCount; i++) {
			list.add(junkBase + i); // never below the real minimum by construction of the fixtures
		}
		return list;
	}

	/** megaman e000, table-after-code (grm-akiv): switch e000, table e0ed, the owner's true length
	 *  18. The lowest-target rule declines; the switch window cuts at the 19th entry (a1ad, the
	 *  switchable window), with the entries after it also outside. Real bytes from the survey. */
	@Test
	public void tableAfterCodeBoundsByWindowToEighteen() {
		List<Long> targets = targets(0xe003, 0xe06f, 0xe076, 0xe065, 0xe076, 0xe065, 0xe076,
			0xe0a2, 0xe0ca, 0xe04d, 0xe06f, 0xe076, 0xe065, 0xe076, 0xe065, 0xe076, 0xe0a2, 0xe0ca,
			0xa1ad, 0xf006, 0x6001, 0xa2b9, 0x85e2, 0xb904);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0xe0ed, 1, 48));

		assertFalse(JumpTableBound.bound(targets, tables).isBounded());
		Result r = JumpTableBound.boundBySwitchWindow(0xe000, targets, tables);
		assertTrue(r.isBounded());
		assertEquals(18, r.count());
		assertEquals(JumpTableBound.Rule.SWITCH_WINDOW, r.rule());
		assertEquals(0xe003, r.lowestTarget());
	}

	/** Back-to-back tables (tmnt 8f34): the over-read runs into the next table's entries, which
	 *  are VALID code addresses (8cfb..8e66) -- but below the switch, so the window still cuts. */
	@Test
	public void windowCutsWhereOverReadEntersTheNextTable() {
		List<Long> targets =
			targets(0x8f37, 0x8f37, 0x8f45, 0x8f71, 0x8f55, 0x8f37, 0x8cfb, 0x8d22, 0x8d70, 0x8e66);
		Result r = JumpTableBound.boundBySwitchWindow(0x8f34, targets,
			List.of(new LoadTableEntry(0x8fb8, 1, 20)));
		assertTrue(r.isBounded());
		assertEquals(6, r.count());
	}

	/** contra 849f (grm-t223, owner's read): table 86bf is 7 entries, then 8285's table at 86cd,
	 *  whose 4 targets all fall inside 849f's window -- the window alone keeps 11. 86cd being
	 *  another switch's table start stops the walk at 7. */
	@Test
	public void windowStopsAtTheNextTablePackedAfterIt() {
		List<Long> targets = targets(0x8651, 0x8651, 0x8673, 0x86a6, 0x8683, 0x86a6, 0x8651,
			0x8500, 0x8522, 0x855c, 0x84a2, 0xc000, 0xd000, 0xe000);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x86bf, 1, 28));

		Result windowOnly = JumpTableBound.boundBySwitchWindow(0x849f, targets, tables);
		assertEquals(11, windowOnly.count());
		Result r = JumpTableBound.boundBySwitchWindow(0x849f, targets, tables, List.of(0x86cdL));
		assertTrue(r.isBounded());
		assertEquals(7, r.count());
		assertEquals(JumpTableBound.Rule.WINDOW_AT_NEIGHBOUR, r.rule());
		assertEquals(0x8651, r.lowestTarget());
	}

	/** When the window would stop at the neighbour anyway (tmnt 8fb8 running into 8fc4), the plain
	 *  window rule applies unchanged; an off-boundary or own start is ignored, not a decline. */
	@Test
	public void windowNeighbourOnlyTightensTheWindow() {
		List<Long> targets =
			targets(0x8f37, 0x8f37, 0x8f45, 0x8f71, 0x8f55, 0x8f37, 0x8cfb, 0x8d22, 0x8d70, 0x8e66);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x8fb8, 1, 20));
		Result r = JumpTableBound.boundBySwitchWindow(0x8f34, targets, tables, List.of(0x8fc4L));
		assertEquals(6, r.count());
		assertEquals(JumpTableBound.Rule.SWITCH_WINDOW, r.rule());

		List<Long> contra = targets(0x8651, 0x8651, 0x8673, 0x86a6, 0x8683, 0x86a6, 0x8651,
			0x8500, 0x8522, 0x855c, 0x84a2, 0xc000, 0xd000, 0xe000);
		List<LoadTableEntry> contraTables = List.of(new LoadTableEntry(0x86bf, 1, 28));
		assertEquals(11, JumpTableBound.boundBySwitchWindow(0x849f, contra, contraTables,
			List.of(0x86ceL, 0x86bfL, 0x9000L)).count());
	}

	/** An out-of-window entry followed straight away by in-window ones may be a real case that
	 *  jumps to shared code: decline rather than cut there. */
	@Test
	public void windowDeclinesWhenTheTableComesBackIntoTheWindow() {
		List<Long> targets = targets(0x8010, 0x8020, 0x9000, 0x8030, 0x8040, 0x8050);
		assertFalse(JumpTableBound.boundBySwitchWindow(0x8000, targets,
			List.of(new LoadTableEntry(0x8100, 1, 12))).isBounded());
	}

	/** Entry 0 outside the window, or a table before the switch: not this layout. */
	@Test
	public void windowDeclinesOtherLayouts() {
		List<LoadTableEntry> after = List.of(new LoadTableEntry(0x8100, 1, 8));
		assertFalse(JumpTableBound.boundBySwitchWindow(0x8000,
			targets(0x9000, 0x8010, 0x8020, 0x8030), after).isBounded());
		assertFalse(JumpTableBound.boundBySwitchWindow(0x8200,
			targets(0x8210, 0x8220, 0x9000, 0x9000), after).isBounded());
		// Only one entry in the window: too few to call it a table.
		assertFalse(JumpTableBound.boundBySwitchWindow(0x8000,
			targets(0x8010, 0x9000, 0x9000, 0x9000), after).isBounded());
	}

	/** The megaman bank-5 shape: one COLLAPSED interleaved lo/hi table, size 1, num 256 (128
	 *  cases), table at 0xa737, first real target the byte right after the table (0xa747, i.e.
	 *  table + 16 = 0x10 bytes = 8 entries * 2 bytes/entry), 8 real entries, then garbage. */
	@Test
	public void megamanShapedInterleavedTableBoundsToEight() {
		long tableStart = 0xa737;
		long[] real = { 0xa747, 0xa76d, 0xa784, 0xa7a1, 0xa7cd, 0xa7fa, 0xa827, 0xa893 };
		List<Long> targets = targetsWithJunk(real, 0xb000, 120);
		List<LoadTableEntry> tables =
			List.of(new LoadTableEntry(tableStart, 1, 256));

		Result r = JumpTableBound.bound(targets, tables);
		assertTrue(r.isBounded());
		assertEquals(8, r.count());
		assertEquals(0xa747, r.lowestTarget());
	}

	/** Split lo/hi tables (two SEPARATE collapsed tables of size 1, num 16 each) covering 8 real
	 *  cases -- must bound identically to the interleaved case. Chosen so the combined per-entry
	 *  extent (chunk 1 byte per table, hi table dominates since it starts later) only catches up
	 *  to the lowest real target -- 0x1018, sitting right at the 8th entry's own extent -- at
	 *  the 9th entry, exactly mirroring the megaman shape's "first real target is the byte right
	 *  after the table" property but split across two collapsed tables. */
	@Test
	public void splitLoHiTablesBoundToEight() {
		long loStart = 0x1000;
		long hiStart = 0x1010;
		long[] real =
			{ 0x1018, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080, 0x1090 };
		List<Long> targets = targetsWithJunk(real, 0x2000, 8);
		List<LoadTableEntry> tables =
			List.of(new LoadTableEntry(loStart, 1, 16), new LoadTableEntry(hiStart, 1, 16));

		Result r = JumpTableBound.bound(targets, tables);
		assertTrue(r.isBounded());
		assertEquals(8, r.count());
		assertEquals(0x1018, r.lowestTarget());
	}

	/** A stride-3 table (e.g. bank/lo/hi triples), single collapsed table entrySize 3, num equal
	 *  to the case count so chunk == entrySize regardless of case count. Table spans
	 *  [0x9000, 0x9000+30); the 3rd entry's own extent (0x900c) is the first to exceed the
	 *  lowest real target (0x900b), so cutoff lands at 3. */
	@Test
	public void stride3TableBounds() {
		long tableStart = 0x9000;
		long[] real = { 0x900b, 0x9050, 0x9070 };
		List<Long> targets = targetsWithJunk(real, 0xa000, 7);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 3, 10));

		Result r = JumpTableBound.bound(targets, tables);
		assertTrue(r.isBounded());
		assertEquals(3, r.count());
	}

	/** A table stored ABOVE its targets: the idiom does not apply, decline unconditionally. */
	@Test
	public void tableAboveItsTargetsDeclines() {
		long tableStart = 0xb000; // above every target below
		long[] real = { 0xa000, 0xa010, 0xa020, 0xa030 };
		List<Long> targets = targets(real);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 4));

		Result r = JumpTableBound.bound(targets, tables);
		assertFalse(r.isBounded());
	}

	/** A fixed extra load (collapsed num == 1) alongside the real moving table must be ignored,
	 *  not treated as part of the table shape or bounded against. */
	@Test
	public void fixedExtraLoadIsIgnored() {
		long tableStart = 0xa737;
		long fixedLookup = 0xf000; // far away, must not affect the bound
		long[] real = { 0xa747, 0xa76d, 0xa784, 0xa7a1, 0xa7cd, 0xa7fa, 0xa827, 0xa893 };
		List<Long> targets = targetsWithJunk(real, 0xb000, 120);
		List<LoadTableEntry> tables =
			List.of(new LoadTableEntry(tableStart, 1, 256), new LoadTableEntry(fixedLookup, 1, 1));

		Result r = JumpTableBound.bound(targets, tables);
		assertTrue(r.isBounded());
		assertEquals(8, r.count());
	}

	/** size*num not divisible by the case count on a moving table -> decline: shape not
	 *  understood. */
	@Test
	public void nonDivisibleExtentDeclines() {
		long tableStart = 0xa000;
		// caseCount 7, but the moving table's extent (1*10=10) doesn't divide by 7.
		List<Long> targets = targetsWithJunk(new long[] { 0xa100, 0xa110 }, 0xb000, 5);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 10));

		Result r = JumpTableBound.bound(targets, tables);
		assertFalse(r.isBounded());
	}

	/** The default case is excluded by the caller before calling in, so a caseCount of 1 (the
	 *  bare minimum after stripping default from a 2-entry raw list) declines: fewer than 2
	 *  entries can't be told from a fixed load. */
	@Test
	public void fewerThanTwoEntriesDeclines() {
		List<Long> targets = targets(0xa100);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0xa000, 1, 1));

		Result r = JumpTableBound.bound(targets, tables);
		assertFalse(r.isBounded());
	}

	/** No moving table at all (every load table is a fixed num==1 lookup) -> decline: no table
	 *  shape to bound. */
	@Test
	public void noMovingTableDeclines() {
		List<Long> targets = targets(0xa100, 0xa110);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0xa000, 1, 1));

		Result r = JumpTableBound.bound(targets, tables);
		assertFalse(r.isBounded());
	}

	/** The bound never exceeds the input entry count, even when the table's own extent never
	 *  collides with any target (a legitimately-sized table with no over-read). */
	@Test
	public void boundNeverExceedsInputCount() {
		long tableStart = 0xa000;
		// 4-entry table, chunk 1 byte/entry -> spans [a000,a004); every target is comfortably
		// past that, so nothing is cut off and count == caseCount.
		long[] real = { 0xa100, 0xa110, 0xa120, 0xa130 };
		List<Long> targets = targets(real);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 4));

		Result r = JumpTableBound.bound(targets, tables);
		assertTrue(r.isBounded());
		assertEquals(4, r.count());
		assertTrue(r.count() <= targets.size());
	}

	/** Sanity: an empty/degenerate targets list declines rather than throwing. */
	@Test
	public void emptyTargetsDeclines() {
		Result r = JumpTableBound.bound(new ArrayList<>(), List.of(new LoadTableEntry(0, 1, 1)));
		assertFalse(r.isBounded());
	}

	/** lwings dcaf/dcb3 (grm-fxtp): a collapsed size-1/num-256 table (128 cases) whose first 64
	 *  entries are plausible code above the table, and entry 64 is a garbage over-read address
	 *  BELOW the table -- which, before grm-fxtp, dragged minTarget under tableStart and declined
	 *  the whole table. With the table's own block supplied, the walk now cuts at 64 instead. */
	@Test
	public void belowTableEntryCutsInsteadOfDeclining() {
		long tableStart = 0xdcb3;
		int realCount = 64;
		long[] real = new long[realCount];
		for (int k = 0; k < realCount; k++) {
			real[k] = 0xdd37 + k * 0x80; // arbitrary, always above tableStart and within the block
		}
		List<Long> targets = new ArrayList<>(targets(real));
		targets.add(0x8c84L); // entry 64: garbage, below the table
		targets.add(0x9c94L); // confirm entries: also below the table
		targets.add(0xd0deL);
		targets.add(0xd003L);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 2 * targets.size()));
		JumpTableBound.Block block = new JumpTableBound.Block(0xc000, 0xffff);

		Result r = JumpTableBound.bound(targets, tables, block);
		assertTrue(r.isBounded());
		assertEquals(64, r.count());
		assertEquals(JumpTableBound.Rule.BELOW_TABLE_CUT, r.rule());

		// Without a block, the refinement is disabled and the table declines exactly as before.
		assertFalse(JumpTableBound.bound(targets, tables).isBounded());
	}

	/** cv3 e137 (grm-fxtp): the table sits in a switchable-window block but the "real" targets are
	 *  in the fixed bank block, with a garbage entry that dips below the table's own start
	 *  triggering the cut -- "below the table" means nothing across blocks, so the same-block guard
	 *  must decline rather than cut, even though a below-table entry was found. */
	@Test
	public void belowTableCutDeclinesWhenTargetsAreInADifferentBlock() {
		long tableStart = 0x9f31;
		List<Long> targets = targets(0xd030, 0xee50, 0x8123, 0xd040, 0xd050);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 2 * targets.size()));
		JumpTableBound.Block block = new JumpTableBound.Block(0x8000, 0x9fff); // the table's block

		Result r = JumpTableBound.bound(targets, tables, block);
		assertFalse(r.isBounded());
	}

	/** A below-table entry immediately followed by an in-block, above-table entry may be a real
	 *  case reaching shared code -- the confirm guard must decline rather than cut. */
	@Test
	public void belowTableCutDeclinesWhenConfirmEntryComesBackAboveTheTable() {
		long tableStart = 0xc000;
		List<Long> targets = targets(0xc100, 0xc110, 0xc120, 0xb000, 0xc130, 0xc140);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 2 * targets.size()));
		JumpTableBound.Block block = new JumpTableBound.Block(0xa000, 0xffff);

		// grm-rsxe: the in-block below-table entry (b000) is now skipped rather than cut at, so the
		// walk keeps all six -- either way the table must not shrink at the below-table entry.
		Result r = JumpTableBound.bound(targets, tables, block);
		assertTrue(!r.isBounded() || r.count() == targets.size());
	}

	/** Block unknown ({@code null}) disables the refinement entirely: a below-table entry still
	 *  drags minTarget down and declines, exactly as the pre-grm-fxtp 2-arg overload always did. */
	@Test
	public void belowTableCutDisabledWhenBlockUnknown() {
		long tableStart = 0xdcb3;
		long[] real = { 0xdd37, 0xde37, 0xdf37 };
		List<Long> targets = new ArrayList<>(targets(real));
		targets.add(0x8c84L);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 2 * targets.size()));

		assertFalse(JumpTableBound.bound(targets, tables, null).isBounded());
		assertFalse(JumpTableBound.bound(targets, tables).isBounded());
	}

	/** Two moving tables with different entry sizes (1 and 3 bytes) composing correctly: the
	 *  wider table dominates the per-entry extent, and cutoff follows its progression exactly
	 *  as the single-table case does. A positive control showing multiple moving tables compose
	 *  fine when both individually divide the case count. */
	@Test
	public void allMovingTablesMustDivideIndividually() {
		long aStart = 0xa000; // size 1, chunk 1 -- dominated by table B below
		long bStart = 0xa100; // size 3, chunk 3 -- table B's extent decides the cutoff
		long[] real = { 0xa109, 0xa200, 0xa210 };
		List<Long> targets = new ArrayList<>(Arrays.asList(real[0], real[1], real[2]));
		targets.add(0xb000L);
		targets.add(0xb001L);
		List<LoadTableEntry> tables =
			List.of(new LoadTableEntry(aStart, 1, 5), new LoadTableEntry(bStart, 3, 5));

		Result r = JumpTableBound.bound(targets, tables);
		assertTrue(r.isBounded());
		assertEquals(3, r.count());
	}

	/** Case targets exactly as the decompiler derives them from an UN-doubled index over 2-byte
	 *  entries (grm-yjiq): case {@code i} reads {@code image[i]} and {@code image[i+1]}, so
	 *  consecutive cases overlap by a byte and every odd case straddles two entries. */
	private static List<Long> overlappingCases(int[] image, int caseCount) {
		List<Long> list = new ArrayList<>();
		for (int i = 0; i < caseCount; i++) {
			list.add((long) (image[i] | (image[i + 1] << 8)));
		}
		return list;
	}

	/** A table image: {@code entries} 2-byte little-endian pointers, then {@code tail} filler
	 *  bytes standing in for the code after the table. */
	private static int[] tableImage(long[] entries, int[] tail) {
		int[] image = new int[entries.length * 2 + tail.length];
		for (int k = 0; k < entries.length; k++) {
			image[2 * k] = (int) (entries[k] & 0xff);
			image[2 * k + 1] = (int) (entries[k] >> 8);
		}
		System.arraycopy(tail, 0, image, entries.length * 2, tail.length);
		return image;
	}

	/** The overlapping shape rcproam 9ad4 has ({@code LDX $0d / LDA tbl,X / LDA tbl+1,X / JMP
	 *  ($001e)}, the index kept pre-doubled in RAM, bounded only to 0..7f by a sign test): 128
	 *  cases over ONE size-1 load table of 129 bytes. Here with a table-before-code layout (13
	 *  entries, the lowest target the byte right after them), so the lowest-target rule itself
	 *  applies to the even cases; rcproam's real layout needs the valid-target rule instead (see
	 *  {@link #rcproam9ad4CutsAtFirstEntryOutsideCode}). */
	@Test
	public void undoubledIndexOverOverlappingTableKeepsEvenCases() {
		long tableStart = 0x9aeb;
		long[] real = { 0x9b05, 0x9b40, 0x9b77, 0x9bb0, 0x9c02, 0x9c31, 0x9c80, 0x9cc5, 0x9d10,
			0x9d44, 0x9d90, 0x9dd1, 0x9e20 };
		// Code after the table: JSR ff89 at 9b06 among it, as in the ROM (the over-read case 0x1d
		// lands on that JSR's operand and yields the bogus target ff89).
		int[] tail = new int[116];
		for (int k = 0; k < tail.length; k++) {
			tail[k] = (k * 37 + 0x11) & 0xff;
		}
		tail[1] = 0x20; // 9b06: JSR
		tail[2] = 0x89; // 9b07
		tail[3] = 0xff; // 9b08
		int[] image = tableImage(real, tail);
		List<Long> targets = overlappingCases(image, 128);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(tableStart, 1, 129));

		Result r = JumpTableBound.bound(targets, tables,
			new JumpTableBound.Block(0x8000, 0xbfff));
		assertTrue(r.isBounded());
		assertEquals(2, r.stride());
		assertEquals(13, r.count());
		assertEquals(0x9b05, r.lowestTarget());
		List<Long> kept = r.keep(targets);
		assertEquals(13, kept.size());
		for (int k = 0; k < real.length; k++) {
			assertEquals(real[k], (long) kept.get(k));
		}
	}

	/** The same table walked the pre-grm-yjiq way would be wrong, which is why the even cases are
	 *  selected rather than the extent merely widened: case 1 straddles entries 0 and 1 (hi byte
	 *  of 9b05, lo byte of 9b40 = 0x409b), which sits below the table and would have dragged the
	 *  lowest target under it. Kept here as the reason, pinned. */
	@Test
	public void oddCaseOfOverlappingTableIsGarbage() {
		int[] image = tableImage(new long[] { 0x9b05, 0x9b40 }, new int[] { 0, 0, 0 });
		List<Long> targets = overlappingCases(image, 4);
		assertEquals(0x409bL, (long) targets.get(1));
	}

	/** The overlapping shape needs exactly one moving table, one byte wide, of caseCount + 1
	 *  bytes; anything else still declines as a non-divisible extent. */
	@Test
	public void overlappingShapeIsRecognisedNarrowly() {
		List<Long> targets = targetsWithJunk(new long[] { 0xa100, 0xa110 }, 0xb000, 6); // 8 cases
		assertFalse(JumpTableBound.bound(targets,
			List.of(new LoadTableEntry(0xa000, 1, 10))).isBounded()); // +2, not +1
		assertFalse(JumpTableBound.bound(targets,
			List.of(new LoadTableEntry(0xa000, 3, 3))).isBounded()); // 9 bytes, but 3 wide
		assertFalse(JumpTableBound.bound(targets, List.of(new LoadTableEntry(0xa000, 1, 9),
			new LoadTableEntry(0xa200, 1, 16))).isBounded()); // a second moving table
		assertTrue(JumpTableBound.bound(targets,
			List.of(new LoadTableEntry(0xa000, 1, 9), new LoadTableEntry(0xf000, 1, 1)))
				.isBounded()); // a fixed load beside it is ignored, as everywhere else
	}

	/** Fewer than 4 cases leaves fewer than 2 even ones: decline. */
	@Test
	public void overlappingShapeNeedsFourCases() {
		List<Long> targets = targets(0xa100, 0x00a1, 0xa110);
		assertFalse(
			JumpTableBound.bound(targets, List.of(new LoadTableEntry(0xa000, 1, 4))).isBounded());
	}

	/** The switch-window rule (table after code) takes the same even-case view. Switch e000,
	 *  cases e003..e0ca, table e0ed; three real entries, then the over-read leaves the window. */
	@Test
	public void switchWindowAlsoKeepsEvenCasesOfOverlappingTable() {
		long[] real = { 0xe003, 0xe040, 0xe0ca };
		int[] image = tableImage(real, new int[] { 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a });
		List<Long> targets = overlappingCases(image, 14);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0xe0ed, 1, 15));

		assertFalse(JumpTableBound.bound(targets, tables).isBounded());
		Result r = JumpTableBound.boundBySwitchWindow(0xe000, targets, tables);
		assertTrue(r.isBounded());
		assertEquals(2, r.stride());
		assertEquals(3, r.count());
		assertEquals(List.of(0xe003L, 0xe040L, 0xe0caL), r.keep(targets));
	}

	/** An ordinary bound keeps stride 1 and keep() is the plain prefix. */
	@Test
	public void ordinaryBoundKeepsPrefix() {
		long[] real = { 0xa747, 0xa76d, 0xa784, 0xa7a1, 0xa7cd, 0xa7fa, 0xa827, 0xa893 };
		List<Long> targets = targetsWithJunk(real, 0xb000, 120);
		Result r = JumpTableBound.bound(targets, List.of(new LoadTableEntry(0xa737, 1, 256)));
		assertEquals(1, r.stride());
		assertEquals(targets.subList(0, 8), r.keep(targets));
	}

	/** rcproam 9ad4, from the ROM (sha 4aaaa0f1...): the 26 bytes at 9aeb, then the code at 9b05.
	 *  Its eleven handlers (index 0..$14, the largest value the game stores to $0d) sit on both
	 *  sides of the table, so the lowest-target and switch-window rules both decline; entries 11
	 *  and 12 read as 2120 and 2725 (unmapped PPU mirror), entry 13 as 11a9 (unmapped), and that
	 *  is where the table ends. The in-code test mirrors rcproam's blocks: RAM 0000-07ff and the
	 *  PPU/APU registers are not code; only PRG (8000-ffff) and PRG_RAM are initialized. */
	@Test
	public void rcproam9ad4CutsAtFirstEntryOutsideCode() {
		int[] table = { 0x60, 0x81, 0x05, 0x9b, 0x9d, 0x91, 0x61, 0x8d, 0xa5, 0x87, 0x85, 0x8d,
			0x9a, 0x83, 0x39, 0x82, 0xc8, 0xd0, 0x65, 0x9d, 0x8e, 0x9d, 0x20, 0x21, 0x25, 0x27 };
		int[] code = { 0xa9, 0x11, 0x20, 0x89, 0xff, 0x20, 0xea, 0x8e, 0xa9, 0x10, 0x20, 0x89,
			0xff, 0xa9, 0x3f, 0x8d, 0x06, 0x20, 0xa9, 0x0d, 0x8d, 0x06, 0x20, 0xa5, 0x09, 0x4a,
			0x4a };
		int[] image = new int[table.length + code.length];
		System.arraycopy(table, 0, image, 0, table.length);
		System.arraycopy(code, 0, image, table.length, code.length);
		int caseCount = image.length - 1;
		List<Long> targets = overlappingCases(image, caseCount);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x9aeb, 1, caseCount + 1));
		List<Boolean> inCode = new ArrayList<>();
		for (long t : targets) {
			inCode.add(t >= 0x6000);
		}

		JumpTableBound.Block prg = new JumpTableBound.Block(0x8000, 0xffff);
		assertFalse(JumpTableBound.bound(targets, tables, prg).isBounded());
		assertFalse(JumpTableBound.boundBySwitchWindow(0x9ad4, targets, tables).isBounded());
		Result r = JumpTableBound.boundByValidTargets(targets, tables, inCode);
		assertTrue(r.isBounded());
		assertEquals(JumpTableBound.Rule.VALID_TARGET_CUT, r.rule());
		assertEquals(2, r.stride());
		assertEquals(11, r.count());
		assertEquals(List.of(0x8160L, 0x9b05L, 0x919dL, 0x8d61L, 0x87a5L, 0x8d85L, 0x839aL,
			0x8239L, 0xd0c8L, 0x9d65L, 0x9d8eL), r.keep(targets));
		assertEquals(0x8160, r.lowestTarget());
	}

	/** The valid-target rule declines when a confirm entry is plausible again, when every even
	 *  entry is plausible, and for any shape other than the overlapping byte table. */
	@Test
	public void validTargetRuleDeclines() {
		List<Long> targets = new ArrayList<>();
		for (int i = 0; i < 12; i++) {
			targets.add(0x8000L + i);
		}
		List<LoadTableEntry> overlapping = List.of(new LoadTableEntry(0x9000, 1, 13));
		// even entries: in, in, in, OUT, in -> the confirm entry after the cut comes back
		List<Boolean> comesBack = List.of(true, false, true, false, true, false, false, false,
			true, false, false, false);
		assertFalse(JumpTableBound.boundByValidTargets(targets, overlapping, comesBack).isBounded());
		List<Boolean> allIn = new ArrayList<>();
		for (int i = 0; i < 12; i++) {
			allIn.add(i % 2 == 0);
		}
		assertFalse(JumpTableBound.boundByValidTargets(targets, overlapping, allIn).isBounded());
		List<Boolean> cutAt3 = List.of(true, false, true, false, true, false, false, false,
			false, false, false, false);
		assertTrue(JumpTableBound.boundByValidTargets(targets, overlapping, cutAt3).isBounded());
		assertFalse(JumpTableBound.boundByValidTargets(targets,
			List.of(new LoadTableEntry(0x9000, 1, 24)), cutAt3).isBounded()); // ordinary shape
	}

	/** dodge W8000_M3_B3::8445, from the ROM: {@code LDA $d0 / AND #$c0 / LSR x5 / TAY / LDA
	 *  $8449,Y / LDA $844a,Y / JMP ($004d)} -- the index is scaled by shifting, so Y is 0/2/4/6 and
	 *  the decompiler sees 8 stride-1 cases over 9 bytes. Real table: 4 entries (8451 848a 84c5
	 *  8451), ending at 8451, its own lowest target, where the code resumes. */
	@Test
	public void dodge8445ShiftScaledIndexBoundsToFour() {
		int[] image = { 0x51, 0x84, 0x8a, 0x84, 0xc5, 0x84, 0x51, 0x84, 0xa5, 0xd0 };
		List<Long> targets = overlappingCases(image, 8);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x8449, 1, 9));

		Result r = JumpTableBound.bound(targets, tables, new JumpTableBound.Block(0x8000, 0xbfff));
		assertTrue(r.isBounded());
		assertEquals(JumpTableBound.Rule.LOWEST_TARGET, r.rule());
		assertEquals(2, r.stride());
		assertEquals(List.of(0x8451L, 0x848aL, 0x84c5L, 0x8451L), r.keep(targets));
	}

	/** dbz2 cb97, from the ROM: {@code LDA $2f / ASL A / BCS / TAY / LDA $dd47,Y / ... / JMP
	 *  ($0021)}, and the IRQ handler's {@code cbfd JMP ($0026)} reads its own table at dd65 -- so
	 *  cb97 has exactly (dd65 - dd47) / 2 = 15 entries. These are the 44 the decompiler walks.
	 *  Every extent rule declines (the handlers sit below both the switch and the table), and
	 *  grm-os9b measured the valid-target cut keeping 32 by running through cbfd's handlers. */
	@Test
	public void dbz2Cb97CutsAtTheNeighbourTable() {
		List<Long> targets = targets(0xc9da, 0xca40, 0xca22, 0xc944, 0xc950, 0xc95c, 0xc89c,
			0xc884, 0xc8ba, 0xc8a8, 0xca34, 0xc9fe, 0xc968, 0xca0a, 0xc9f2, 0xddd8, 0xddcd,
			0xdddb, 0xde4a, 0xded2, 0xde2e, 0xddd5, 0xdf24, 0xdf52, 0xdf82, 0xddd5, 0xe020,
			0xe06b, 0xddd5, 0xddfd, 0xe03c, 0x80c9, 0x0290, 0x00a9, 0x328d, 0xa800, 0x9fbe,
			0xbddd, 0xff80, 0x358d, 0xbd00, 0xff81, 0x368d, 0x6000);
		// the interleaved lo/hi bytes arrive as one collapsed size-1 table over both halves
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0xdd47, 1, 88));

		assertFalse(JumpTableBound.bound(targets, tables,
			new JumpTableBound.Block(0xc000, 0xffff)).isBounded());
		assertFalse(JumpTableBound.boundBySwitchWindow(0xcb97, targets, tables).isBounded());

		// as the analyzer builds it: initialized, non-volatile memory (RAM and PPU are neither)
		List<Boolean> inCode = new ArrayList<>();
		for (long t : targets) {
			inCode.add(t >= 0x6000);
		}
		// its own start is ignored; a start past the extent (dd9f) is not a neighbour
		Result r = JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0xdd47L, 0xdd65L, 0xdd9fL + 0x40), inCode);
		assertTrue(r.isBounded());
		assertEquals(JumpTableBound.Rule.NEIGHBOUR_TABLE, r.rule());
		assertEquals(15, r.count());
		assertEquals(1, r.stride());
		assertEquals(0xc884, r.lowestTarget());
		// a "neighbour" past the RAM entry at case 32 (0290) would keep it: decline
		assertFalse(JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0xdd47L + 2 * 34), inCode).isBounded());
	}

	/** The neighbour-table rule declines with no neighbour inside the extent, with a neighbour
	 *  start off this table's entry boundary, when fewer than 2 entries would be kept, and when a
	 *  kept entry cannot be code. */
	@Test
	public void neighbourTableRuleDeclines() {
		List<Long> targets = new ArrayList<>();
		List<Boolean> inCode = new ArrayList<>();
		for (int i = 0; i < 10; i++) {
			targets.add(0x8000L + 3 * i);
			inCode.add(true);
		}
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x9000, 2, 10));
		assertFalse(JumpTableBound.boundByNeighbourTable(targets, tables, List.of(), inCode)
				.isBounded());
		assertFalse(JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0x9000L, 0x9014L, 0x8ffeL), inCode).isBounded()); // own start, end, before
		assertFalse(JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0x9007L), inCode).isBounded()); // mid-entry
		assertFalse(JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0x9002L), inCode).isBounded()); // would keep 1
		Result r = JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0x900cL, 0x9008L), inCode);
		assertTrue(r.isBounded());
		assertEquals(4, r.count()); // the LOWEST neighbour wins
		inCode.set(2, false);
		assertFalse(JumpTableBound.boundByNeighbourTable(targets, tables,
			List.of(0x9008L), inCode).isBounded()); // a kept entry is not code
	}

	/** tmnt bank 5 940a (grm-rsxe): 45 real entries with handlers on BOTH sides of the table, all
	 *  in the table's own bank. Entry 17 (91c6) is the first below the table; it used to trigger
	 *  the grm-fxtp cut (17 entries). An in-block below-table target is a real handler, so the
	 *  walk now runs on to the lowest target ABOVE the table, 9464 = entry 0 = 940a + 2*45. */
	@Test
	public void inBlockBelowTableTargetsAreSkippedNotCut() {
		List<Long> targets = targets(0x9464, 0x97d7, 0x94af, 0x979b, 0x9977, 0x94a5, 0x982b,
			0x9464, 0x94be, 0x9539, 0x9464, 0x9464, 0x9464, 0x978e, 0x97d7, 0x97d7, 0x9464, 0x91c6,
			0x9288, 0x92f3, 0x9983, 0x99d9, 0x99e5, 0x9a0e, 0x864b, 0x8708, 0x877e, 0x87c0, 0x87f8,
			0x8a94, 0x8b05, 0x8b8d, 0x8b99, 0x8c06, 0x9464, 0x9c5c, 0x9d88, 0x9b93, 0x9dab, 0xa0bf,
			0xa0ba, 0xa34c, 0xa34f, 0xa3c3, 0xa59f, 0xbd60, 0x0520, 0xa80a);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x940a, 1, 2 * targets.size()));
		JumpTableBound.Block block = new JumpTableBound.Block(0x8000, 0xbfff);

		Result r = JumpTableBound.bound(targets, tables, block);
		assertTrue(r.isBounded());
		assertEquals(45, r.count());
		assertEquals(JumpTableBound.Rule.LOWEST_TARGET, r.rule());
		assertEquals(0x9464, r.lowestTarget());
	}

	/** tmnt bank 5 9477 (grm-rsxe): entry 0 (9464) is below the table, so every extent rule
	 *  declines; the table really ends at 94a5, which is 940a's entry 5. Cut there: 23 entries. */
	@Test
	public void knownCodeFromAnotherTableCutsTheTable() {
		List<Long> targets = targets(0x9464, 0x9833, 0x969f, 0x983f, 0x832f, 0x9726, 0x9464,
			0x9464, 0x9464, 0x9464, 0x9464, 0x9464, 0x9464, 0x9851, 0x9870, 0x9833, 0x987c, 0x98d7,
			0x9908, 0x9464, 0x9464, 0x9464, 0x96eb, 0xfe20, 0xbd97, 0x0440);
		List<LoadTableEntry> tables = List.of(new LoadTableEntry(0x9477, 1, 2 * targets.size()));
		List<Boolean> inCode = new ArrayList<>();
		for (long t : targets) {
			inCode.add(t >= 0x8000);
		}
		assertFalse(JumpTableBound.bound(targets, tables,
			new JumpTableBound.Block(0x8000, 0xbfff)).isBounded());

		Result r = JumpTableBound.boundByKnownCode(targets, tables, List.of(0x94a5L, 0x97d7L),
			inCode);
		assertTrue(r.isBounded());
		assertEquals(23, r.count());
		assertEquals(JumpTableBound.Rule.KNOWN_CODE, r.rule());

		// No code start inside the table's extent: nothing to cut at.
		assertFalse(JumpTableBound.boundByKnownCode(targets, tables, List.of(0x97d7L), inCode)
			.isBounded());
		// A kept entry that cannot be code means the code start lies past garbage: decline.
		List<Boolean> garbage = new ArrayList<>(inCode);
		garbage.set(3, false);
		assertFalse(JumpTableBound.boundByKnownCode(targets, tables, List.of(0x94a5L), garbage)
			.isBounded());
	}
}
