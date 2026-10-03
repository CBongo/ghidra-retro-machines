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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Coverage for grm-j2kl: the "JSR inline jump table" / SMB "JumpEngine" idiom. No ROM bytes are
 * copied in anywhere here -- every shape is a hand-built minimal reproduction of the idiom
 * described in the bead (smb's {@code 8e04} dispatcher and db3's {@code 803a}).
 *
 * <p>Split into three groups: pure recognizer coverage ({@link InlineJumpTableDispatch#recognizeDispatcher}),
 * pure bound coverage ({@link InlineJumpTableDispatch#tableEntriesAt}), and one end-to-end run of
 * {@link InlineJumpTableDispatchAnalyzer} against a synthetic call site.
 */
public class InlineJumpTableDispatchAnalyzerTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB freshProgram() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x8000); // 0x8000-0xffff, ROM
		return builder.getProgram();
	}

	// ---------------------------------------------------------------------
	// Recognizer: positive shapes.
	// ---------------------------------------------------------------------

	/** The smb 8e04 shape: ASL/TAY BEFORE the PLA pair, no save/restore noise. */
	@Test
	public void recognizesSmbShapeDispatcher() throws Exception {
		ProgramDB program = freshProgram();
		long entry = 0x8e00;
		builder.setBytes(String.format("0x%x", entry),
			"0a a8 68 85 04 68 85 05 c8 b1 04 85 06 c8 b1 04 85 07 6c 06 00", true);

		Boolean result = InlineJumpTableDispatch.recognizeDispatcher(program, addr(entry));
		assertEquals(Boolean.TRUE, result);
	}

	/** The db3 803a shape: a harmless STY save before the index is captured, INY BEFORE the PLA
	 *  pair, and a harmless LDY restore after both loads. */
	@Test
	public void recognizesDb3ShapeDispatcherWithSaveRestoreNoise() throws Exception {
		ProgramDB program = freshProgram();
		long entry = 0x803a;
		// STY $10; ASL A; TAY; INY; PLA; STA $11; PLA; STA $12;
		// LDA ($11),Y; STA $13; INY; LDA ($11),Y; STA $14; LDY $10; JMP ($0013)
		builder.setBytes(String.format("0x%x", entry),
			"84 10 0a a8 c8 68 85 11 68 85 12 b1 11 85 13 c8 b1 11 85 14 a4 10 6c 13 00", true);

		Boolean result = InlineJumpTableDispatch.recognizeDispatcher(program, addr(entry));
		assertEquals(Boolean.TRUE, result);
	}

	// ---------------------------------------------------------------------
	// Recognizer: declines.
	// ---------------------------------------------------------------------

	/** A different idiom entirely: an inline-ARGUMENT routine that pops its return address and
	 *  returns via RTS, never reaching the two loads + indirect JMP shape. */
	@Test
	public void declinesInlineArgumentRoutine() throws Exception {
		ProgramDB program = freshProgram();
		long entry = 0x8f00;
		// PLA; STA $04; PLA; STA $05; RTS
		builder.setBytes(String.format("0x%x", entry), "68 85 04 68 85 05 60", true);

		Boolean result = InlineJumpTableDispatch.recognizeDispatcher(program, addr(entry));
		assertEquals(Boolean.FALSE, result);
	}

	/** Near-miss on the smb shape: the INY between the two indirect loads is missing, so the
	 *  second load reads at the same Y as the first instead of Y+1. */
	@Test
	public void declinesNearMissMissingInyBetweenLoads() throws Exception {
		ProgramDB program = freshProgram();
		long entry = 0x8f40;
		// ASL A; TAY; PLA; STA $04; PLA; STA $05; INY; LDA ($04),Y; STA $06;
		// LDA ($04),Y; STA $07; JMP ($0006)   -- missing the second INY
		builder.setBytes(String.format("0x%x", entry),
			"0a a8 68 85 04 68 85 05 c8 b1 04 85 06 b1 04 85 07 6c 06 00", true);

		Boolean result = InlineJumpTableDispatch.recognizeDispatcher(program, addr(entry));
		assertEquals(Boolean.FALSE, result);
	}

	// ---------------------------------------------------------------------
	// Bound: pure logic over raw table bytes (no JSR needed).
	// ---------------------------------------------------------------------

	/** The db3 9d0a table shape: 10 real entries whose lowest target sits exactly at
	 *  {@code tableStart + 20} (mirroring 9d1e = 9d0a + 10*2), followed by an 11th entry that
	 *  would collide with that lowest target's own bytes -- cut there, per grm-eyn's rule. */
	@Test
	public void boundsTableAtLowestTargetLikeDb3() throws Exception {
		ProgramDB program = freshProgram();
		long tableStart = 0x9d0a;
		int tx = program.startTransaction("build table");
		try {
			for (int i = 0; i < 11; i++) {
				long target = tableStart + 20 + 2L * i;
				builder.setBytes(String.format("0x%x", tableStart + 2L * i),
					String.format("%02x %02x", target & 0xff, (target >> 8) & 0xff), false);
			}
		}
		finally {
			program.endTransaction(tx, true);
		}

		List<Address> entries = InlineJumpTableDispatch.tableEntriesAt(program, addr(tableStart));
		assertEquals(10, entries.size());
		for (int i = 0; i < 10; i++) {
			assertEquals(addr(tableStart + 20 + 2L * i), entries.get(i));
		}
	}

	/** A table entry whose word decodes into RAM (uninitialized memory) rather than code: not
	 *  something the site's own address space can hold code at, so the scan stops there. */
	@Test
	public void boundsTableAtFirstEntryIntoUninitializedMemory() throws Exception {
		ProgramDB program = freshProgram();
		long tableStart = 0x9e00;
		int tx = program.startTransaction("build table");
		try {
			for (int i = 0; i < 3; i++) {
				long target = tableStart + 40 + 2L * i;
				builder.setBytes(String.format("0x%x", tableStart + 2L * i),
					String.format("%02x %02x", target & 0xff, (target >> 8) & 0xff), false);
				builder.setBytes(String.format("0x%x", target), "60", false); // RTS
			}
			// 4th entry: points into the zero-page RAM block, which is uninitialized.
			builder.setBytes(String.format("0x%x", tableStart + 6), "50 00", false);
		}
		finally {
			program.endTransaction(tx, true);
		}

		List<Address> entries = InlineJumpTableDispatch.tableEntriesAt(program, addr(tableStart));
		assertEquals(3, entries.size());
	}

	/**
	 * Handlers on BOTH sides of the table, the common JumpEngine layout (smb's c282 enemy-ID
	 * table: 55 entries, targets from c2f0 up and c787 up). Below-table targets are ignored for
	 * the bound; the table ends where the lowest above-table target begins, even though the
	 * words after that point would still read as valid ROM addresses.
	 */
	@Test
	public void boundsStraddlingTableAtLowestAboveTableTarget() throws Exception {
		ProgramDB program = freshProgram();
		long tableStart = 0x9500;
		// Three below the table, then 0x950c = tableStart + 6 entries * 2, then one further up.
		long[] targets = { 0x8100, 0x8110, 0x8120, 0x9520, 0x950c, 0x9530 };
		int tx = program.startTransaction("build table");
		try {
			for (int i = 0; i < targets.length; i++) {
				builder.setBytes(String.format("0x%x", tableStart + 2L * i),
					String.format("%02x %02x", targets[i] & 0xff, (targets[i] >> 8) & 0xff), false);
			}
			// The handler at 950c: its bytes, read as a word, point back into ROM (0x8120).
			builder.setBytes("0x950c", "20 81", false);
		}
		finally {
			program.endTransaction(tx, true);
		}

		InlineJumpTableDispatch.CallSiteScan scan =
			InlineJumpTableDispatch.scanTable(program, addr(tableStart));
		assertEquals(InlineJumpTableDispatch.Cut.ABOVE_TABLE_TARGET, scan.cut);
		assertEquals(6, scan.kept.size());
		for (int i = 0; i < targets.length; i++) {
			assertEquals(addr(targets[i]), scan.kept.get(i));
		}
	}

	/**
	 * A table that ends only at an invalid word, whose last two words are really the next
	 * routine's bytes: one lands mid-instruction of existing code, one on a BRK. Both are
	 * trimmed; the real entries before them are kept. A mid-table entry is never judged: the
	 * trim stops at the first plausible target from the end.
	 */
	@Test
	public void trimsImplausibleTailOfTableEndingAtInvalidWord() throws Exception {
		ProgramDB program = freshProgram();
		long tableStart = 0x9500;
		int tx = program.startTransaction("build table");
		try {
			builder.setBytes("0x8100", "ea 60", false); // NOP; RTS
			builder.setBytes("0x8110", "a9 00", true); // LDA #$00, disassembled
			builder.setBytes("0x8120", "00 00", false); // BRK
			// 8100, 8111 (mid-LDA, but NOT at the tail), 8100, then 8111 and 8120 at the tail,
			// then 0050 (RAM) ends the table.
			builder.setBytes(String.format("0x%x", tableStart),
				"00 81 11 81 00 81 11 81 20 81 50 00", false);
		}
		finally {
			program.endTransaction(tx, true);
		}

		InlineJumpTableDispatch.CallSiteScan scan =
			InlineJumpTableDispatch.scanTable(program, addr(tableStart));
		assertEquals(InlineJumpTableDispatch.Cut.INVALID_WORD, scan.cut);
		assertEquals(List.of(addr(0x8100), addr(0x8111), addr(0x8100)), scan.kept);
	}

	/**
	 * Nothing ends the table within {@link InlineJumpTableDispatch#MAX_TABLE_ENTRIES}: every word
	 * is a valid ROM address below the table, so no above-table target ever bounds it. No
	 * length can be trusted, so the whole site is declined.
	 */
	@Test
	public void declinesSiteWhenNothingEndsTheTable() throws Exception {
		ProgramDB program = freshProgram();
		long tableStart = 0x9500;
		int tx = program.startTransaction("build table");
		try {
			for (int i = 0; i <= InlineJumpTableDispatch.MAX_TABLE_ENTRIES; i++) {
				builder.setBytes(String.format("0x%x", tableStart + 2L * i), "00 81", false);
			}
		}
		finally {
			program.endTransaction(tx, true);
		}

		InlineJumpTableDispatch.CallSiteScan scan =
			InlineJumpTableDispatch.scanTable(program, addr(tableStart));
		assertEquals(InlineJumpTableDispatch.Cut.DECLINED, scan.cut);
		assertTrue(scan.kept.isEmpty());
	}

	/**
	 * grm-j2kl follow-up item 3: a table inside a BANKED OVERLAY (the switchable window) whose
	 * entries point into the FIXED bank -- always represented in the base/physical space, never
	 * overlaid. Resolving the target in the overlay space alone would find no memory block there
	 * (the overlay only has a block over the switchable range) and wrongly stop the scan; this
	 * must instead resolve into the physical space, mirroring how a direct JSR/JMP from that
	 * overlay into the fixed bank resolves.
	 */
	@Test
	public void resolvesTargetInFixedBankWhenTableIsInBankedOverlay() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory("PRG_HI", "0xc000", 0x4000); // fixed bank, base/physical space
		var overlay = builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000); // switchable
		ProgramDB program = builder.getProgram();

		long tableStart = 0x9000; // inside the overlay window
		long target0 = 0xc010; // fixed bank -- base/physical space only
		long target1 = 0xc020;
		int tx = program.startTransaction("build table");
		try {
			builder.setBytes(String.format("PRG_LO_B1::%x", tableStart),
				String.format("%02x %02x %02x %02x", target0 & 0xff, (target0 >> 8) & 0xff,
					target1 & 0xff, (target1 >> 8) & 0xff),
				false);
			builder.setBytes(String.format("0x%x", target0), "ea 60", false);
			builder.setBytes(String.format("0x%x", target1), "ea 60", false);
		}
		finally {
			program.endTransaction(tx, true);
		}

		var overlaySpace = overlay.getStart().getAddressSpace();
		Address tableStartAddr = overlaySpace.getAddress(tableStart);
		InlineJumpTableDispatch.CallSiteScan scan =
			InlineJumpTableDispatch.scanTable(program, tableStartAddr);
		assertEquals(2, scan.kept.size());

		var physicalSpace = overlaySpace.getPhysicalSpace();
		assertEquals(physicalSpace, scan.kept.get(0).getAddressSpace());
		assertEquals(target0, scan.kept.get(0).getOffset());
		assertEquals(physicalSpace, scan.kept.get(1).getAddressSpace());
		assertEquals(target1, scan.kept.get(1).getOffset());
	}

	/**
	 * grm-rnf0's new positive bound: a real FLOW reference (zelda's {@code e691 BEQ $e6b8}) lands
	 * at the position the 10th table word would otherwise occupy, from a source BEFORE the table
	 * starts. The table must end there, keeping only the 9 real entries before it -- mirroring
	 * zelda's {@code e6a6} table exactly (9 entries, cut at {@code e6b8}).
	 */
	@Test
	public void cutsTableAtRanIntoCodeBoundLikeZelda() throws Exception {
		ProgramDB program = freshProgram();
		long tableStart = 0x9500;
		long branchSource = 0x9490; // before the table -- real code
		long realCodeAddr = tableStart + 2L * 9; // where entry 9 would start
		int tx = program.startTransaction("build table");
		try {
			for (int i = 0; i < 9; i++) {
				long target = 0x8500 + 0x10L * i; // below the table -- never bounds it
				builder.setBytes(String.format("0x%x", tableStart + 2L * i),
					String.format("%02x %02x", target & 0xff, (target >> 8) & 0xff), false);
			}
			builder.setBytes(String.format("0x%x", realCodeAddr), "a4 98", false); // LDY $98
			program.getReferenceManager().addMemoryReference(addr(branchSource), addr(realCodeAddr),
				RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS, 0);
		}
		finally {
			program.endTransaction(tx, true);
		}

		InlineJumpTableDispatch.CallSiteScan scan =
			InlineJumpTableDispatch.scanTable(program, addr(tableStart));
		assertEquals(InlineJumpTableDispatch.Cut.RAN_INTO_CODE, scan.cut);
		assertEquals(9, scan.kept.size());
		assertTrue("a positive bound must not trim anything", scan.trimmed.isEmpty());
	}

	/**
	 * grm-rnf0: a table entry pointing into a DIFFERENT banked window than the table's own block
	 * (the table lives in the fixed bank; the target is in the switchable {@code $8000} window,
	 * whose HOME occupant's bytes here are a lone {@code BRK} -- implausible if judged, like
	 * zelda's handlers would be if read through the wrong bank). Cross-window entries at the tail
	 * must survive the implausible-tail trim: only the state-side pass (BoardBankAnalyzer, once it
	 * knows the live bank) can judge them.
	 */
	@Test
	public void doesNotTrimCrossWindowTailEntry() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory("PRG_HI", "0xc000", 0x4000); // fixed bank -- the table lives here
		builder.createMemory("W8000_HOME", "0x8000", 0x4000); // $8000 window's home occupant
		builder.createOverlayMemory("W8000_B1", "0x8000", 0x4000); // another bank of that window
		ProgramDB program = builder.getProgram();

		long tableStart = 0xc100;
		long crossWindowTarget = 0xb517; // inside the $8000 window
		int tx = program.startTransaction("build table");
		try {
			builder.setBytes(String.format("0x%x", crossWindowTarget), "00 00", false); // BRK BRK
			builder.setBytes(String.format("0x%x", tableStart),
				String.format("%02x %02x 50 00", crossWindowTarget & 0xff,
					(crossWindowTarget >> 8) & 0xff), // then 0x0050 -- RAM, INVALID_WORD
				false);
		}
		finally {
			program.endTransaction(tx, true);
		}

		InlineJumpTableDispatch.CallSiteScan scan =
			InlineJumpTableDispatch.scanTable(program, addr(tableStart));
		assertEquals(InlineJumpTableDispatch.Cut.INVALID_WORD, scan.cut);
		assertEquals(1, scan.kept.size());
		assertEquals(crossWindowTarget, scan.kept.get(0).getOffset());
		assertTrue("a cross-window tail entry must not be trimmed", scan.trimmed.isEmpty());
	}

	/**
	 * grm-rnf0, end to end: {@link InlineJumpTableDispatchAnalyzer} must lay a cross-window entry
	 * as pointer data with a base-space DATA reference (what {@code BoardBankAnalyzer}'s state-side
	 * pass needs to find and resolve), but must NOT disassemble or create a function at that
	 * base-space address -- those bytes belong to whichever bank the state-side pass finds live,
	 * not necessarily the HOME bank these base-space bytes hold.
	 */
	@Test
	public void crossWindowEntryIsNotDisassembledInBaseSpace() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory("PRG_HI", "0xc000", 0x4000); // fixed bank
		builder.createMemory("W8000_HOME", "0x8000", 0x4000); // $8000 window's home occupant
		builder.createOverlayMemory("W8000_B1", "0x8000", 0x4000); // another bank of that window
		ProgramDB program = builder.getProgram();

		long dispatch = 0xc000;
		long caller = 0xc100;
		long crossWindowTarget = 0xb517; // inside the $8000 window -- NOT this table's own block
		long sameSpaceTarget = 0xc200; // in the fixed bank, same as the table -- disassembled as usual

		builder.setBytes(String.format("0x%x", dispatch),
			"0a a8 68 85 04 68 85 05 c8 b1 04 85 06 c8 b1 04 85 07 6c 06 00", false);
		builder.setBytes(String.format("0x%x", caller),
			String.format("20 %02x %02x %02x %02x %02x %02x", dispatch & 0xff, (dispatch >> 8) & 0xff,
				crossWindowTarget & 0xff, (crossWindowTarget >> 8) & 0xff, sameSpaceTarget & 0xff,
				(sameSpaceTarget >> 8) & 0xff),
			false);
		builder.setBytes(String.format("0x%x", crossWindowTarget), "ea ea ea ea ea 60", false); // plausible
		builder.setBytes(String.format("0x%x", sameSpaceTarget), "ea 60", false);
		// end-of-table marker: an invalid (RAM) word right after the two entries above.
		builder.setBytes(String.format("0x%x", caller + 7), "50 00", false);

		builder.disassemble(String.format("0x%x", dispatch), 20, true);
		builder.disassemble(String.format("0x%x", caller), 3, true);

		InlineJumpTableDispatchAnalyzer analyzer = new InlineJumpTableDispatchAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(addr(caller), addr(caller + 2)), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

		Address entry0 = addr(caller + 3);
		Data data0 = program.getListing().getDataAt(entry0);
		assertNotNull("cross-window entry must still be laid as pointer data", data0);
		assertTrue("cross-window entry must still be a pointer", data0.isPointer());
		boolean sawBaseRef = false;
		for (Reference ref : data0.getReferencesFrom()) {
			if (ref.getToAddress().getOffset() == crossWindowTarget) {
				sawBaseRef = true;
			}
		}
		assertTrue("cross-window entry must keep its base-space DATA reference", sawBaseRef);
		assertNull("cross-window target must NOT be disassembled in base space",
			program.getListing().getInstructionAt(addr(crossWindowTarget)));
		assertNull("cross-window target must get no function in base space",
			program.getFunctionManager().getFunctionAt(addr(crossWindowTarget)));

		Address entry1 = addr(caller + 5);
		Data data1 = program.getListing().getDataAt(entry1);
		assertNotNull("same-space entry must still be laid as pointer data", data1);
		assertNotNull("same-space target must be disassembled as usual",
			program.getListing().getInstructionAt(addr(sameSpaceTarget)));
	}

	// ---------------------------------------------------------------------
	// End to end: the analyzer against a synthetic call site.
	// ---------------------------------------------------------------------

	@Test
	public void resolvesCallSiteAndClearsFallthroughGarbage() throws Exception {
		ProgramDB program = freshProgram();
		long dispatch = 0x8e00;
		long caller = 0x9000;
		long target0 = 0x9200;
		long target1 = 0x9300;
		long target2 = 0x9400;

		builder.setBytes(String.format("0x%x", dispatch),
			"0a a8 68 85 04 68 85 05 c8 b1 04 85 06 c8 b1 04 85 07 6c 06 00", false);
		// JSR dispatch; table of 3 words, little-endian, low byte 0x00 so the FIRST table byte
		// alone decodes as a lone BRK (terminal) when stock linear disassembly falls through the
		// JSR into it -- a deliberately small, controllable stand-in for the "AND $xx" garbage
		// the bead describes at smb 8218.
		builder.setBytes(String.format("0x%x", caller),
			String.format("20 %02x %02x 00 %02x 00 %02x 00 %02x", dispatch & 0xff,
				(dispatch >> 8) & 0xff, (target0 >> 8) & 0xff, (target1 >> 8) & 0xff,
				(target2 >> 8) & 0xff),
			false);
		builder.setBytes(String.format("0x%x", target0), "ea 60", false); // NOP; RTS
		builder.setBytes(String.format("0x%x", target1), "ea 60", false);
		builder.setBytes(String.format("0x%x", target2), "ea 60", false);

		// Simulate stock disassembly: decode the dispatcher body (as if reached via the call),
		// then the JSR and its fallthrough into the table -- exactly what leaves garbage there
		// today.
		builder.disassemble(String.format("0x%x", dispatch), 20, true);
		// Restrict the window to the JSR plus the table's first byte: DisassembleCommand's
		// restricted set (ProgramBuilder.disassemble passes the same set as both the seed and the
		// restriction) would otherwise stop disassembly from ever reaching the fallthrough at all,
		// which is not what stock analysis does -- it only needs to reach far enough to show a
		// garbage instruction exists there for the precondition check below.
		builder.disassemble(String.format("0x%x", caller), 4, true);

		Instruction jsr = program.getListing().getInstructionAt(addr(caller));
		assertNotNull("JSR must be disassembled before the analyzer runs", jsr);
		assertNotNull("dispatcher body must be disassembled (followed via the call) before the " +
			"analyzer runs", program.getListing().getInstructionAt(addr(dispatch)));
		Instruction garbage = program.getListing().getInstructionAt(addr(caller + 3));
		assertNotNull("precondition: stock disassembly left a garbage instruction at the table",
			garbage);

		InlineJumpTableDispatchAnalyzer analyzer = new InlineJumpTableDispatchAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(addr(caller), addr(caller + 2)),
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

		Function dispatcher = program.getFunctionManager().getFunctionAt(addr(dispatch));
		assertNotNull("dispatcher function must exist after analysis", dispatcher);
		assertTrue("dispatcher must be marked non-returning", dispatcher.hasNoReturn());

		jsr = program.getListing().getInstructionAt(addr(caller));
		assertNull("JSR must no longer fall through into the table", jsr.getFallThrough());

		assertNull("the garbage instruction at the table must be gone",
			program.getListing().getInstructionAt(addr(caller + 3)));

		for (int i = 0; i < 3; i++) {
			Address entryAddr = addr(caller + 3 + 2L * i);
			Data data = program.getListing().getDataAt(entryAddr);
			assertNotNull("table entry " + i + " must be data", data);
			assertTrue("table entry " + i + " must be a pointer", data.isPointer());
			Pointer ptrType = (Pointer) data.getDataType();
			assertEquals(2, ptrType.getLength());
		}

		assertNotNull("target0 must be disassembled",
			program.getListing().getInstructionAt(addr(target0)));
		assertNotNull("target1 must be disassembled",
			program.getListing().getInstructionAt(addr(target1)));
		assertNotNull("target2 must be disassembled",
			program.getListing().getInstructionAt(addr(target2)));
	}
}
