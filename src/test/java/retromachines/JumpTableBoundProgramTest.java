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

import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskMonitor;

/**
 * End-to-end coverage of {@link JumpTableBoundAnalyzer} against a SYNTHETIC 6502 dispatch in
 * the megaman bank-5 shape (grm-eyn) -- no ROM bytes are copied in; the ROM is copyrighted and
 * this is a hand-built minimal reproduction of the idiom described in the bead.
 *
 * <p><b>The shape.</b> {@code ASL A / TAY / LDA $8200,Y / STA $04 / LDA $8201,Y / STA $05 /
 * JMP ($0004)}: an interleaved lo/hi table at $8200 with 8 real entries (16 bytes), so the
 * decompiler collapses the two indexed loads into ONE table (size 1, num 256) and, because
 * nothing bounds the incoming byte in {@code A}, recovers case addresses for the full raw index
 * range -- the CONTROL below pins that this over-read is real on stock Ghidra before asserting
 * the analyzer fixes it. The real targets are placed starting exactly at table-plus-16-bytes
 * (mirroring megaman's a737/a747), and the "code after the table" -- the remaining 240 bytes of
 * the notional 256-byte table region -- is filled with a repeating in-range address
 * ({@code $8200}, the table's own start) rather than genuine instructions: what matters for
 * jump-table recovery is that each fake entry decodes to a valid address in mapped memory, not
 * that it disassembles as anything meaningful, and a fixed repeat keeps the arithmetic exact
 * rather than incidental to whatever bytes a real instruction sequence happens to encode as.
 */
public class JumpTableBoundProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long TABLE = 0x8200;
	private static final long[] REAL_TARGETS =
		{ 0x8210, 0x8230, 0x8250, 0x8270, 0x8290, 0x82b0, 0x82d0, 0x82f0 };

	/** Set by {@link #buildProgram} so tests can resolve addresses with {@link #addr}. */
	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	/** The switch instruction ({@code JMP ($0004)}) sits 12 bytes into the dispatcher, plus 2
	 *  more if {@code maskIndex} prepended an {@code AND #$07}. */
	private long switchOffset(boolean maskIndex) {
		return 0x8000 + (maskIndex ? 2 : 0) + 12;
	}

	/** Builds the dispatcher + table program. {@code maskIndex} inserts an {@code AND #$07}
	 *  right after the incoming byte is loaded into {@code A}, giving the decompiler an actual
	 *  bound (the negative "explicit bound" case). {@code tableAddr} lets the table-above-code
	 *  negative case relocate the table without touching anything else. */
	private ProgramDB buildProgram(long tableAddr, boolean maskIndex) throws Exception {
		return buildProgram(tableAddr, maskIndex, TABLE);
	}

	/** As above, with every fake entry after the 8 real ones pointing at {@code junk}. */
	private ProgramDB buildProgram(long tableAddr, boolean maskIndex, long junk)
			throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);

		StringBuilder code = new StringBuilder();
		if (maskIndex) {
			code.append("29 07 "); // AND #$07 -- masks to exactly the 8 real entries (0..7)
		}
		code.append("0a a8 "); // ASL A ; TAY
		code.append(String.format("b9 %02x %02x ", tableAddr & 0xff, (tableAddr >> 8) & 0xff)); // LDA tbl,Y
		code.append("85 04 "); // STA $04
		code.append(
			String.format("b9 %02x %02x ", (tableAddr + 1) & 0xff, ((tableAddr + 1) >> 8) & 0xff)); // LDA tbl+1,Y
		code.append("85 05 "); // STA $05
		code.append("6c 04 00"); // JMP ($0004)
		builder.setBytes("0x8000", code.toString().trim(), true);

		// The 8 real entries: interleaved lo/hi, table+0..15.
		StringBuilder table = new StringBuilder();
		for (long target : REAL_TARGETS) {
			table.append(String.format("%02x %02x ", target & 0xff, (target >> 8) & 0xff));
		}
		// The remaining 240 bytes of the notional 256-byte (size 1 x num 256) collapsed table:
		// every fake entry repeats the address of the table itself ($8200) -- valid mapped
		// memory, so the raw decompiler recovery keeps going instead of bailing out early.
		for (int i = 8; i < 128; i++) {
			table.append(String.format("%02x %02x ", junk & 0xff, (junk >> 8) & 0xff));
		}
		builder.setBytes(String.format("0x%x", tableAddr), table.toString().trim(), false);

		return builder.getProgram();
	}

	private Function createFunction(ProgramDB program, Address entry) {
		return inTxGet(program, "fn", () -> {
			CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
			cmd.applyTo(program, TaskMonitor.DUMMY);
			return cmd.getFunction();
		});
	}

	private DecompileResults decompileWithJumpLoads(ProgramDB program, Function function) {
		DecompInterface ifc = new DecompInterface();
		try {
			JumpTableBoundAnalyzer.configureDecompiler(program, ifc);
			assertTrue("decompiler did not open: " + ifc.getLastMessage(),
				ifc.openProgram(program));
			return ifc.decompileFunction(function, 30, TaskMonitor.DUMMY);
		}
		finally {
			ifc.dispose();
		}
	}

	/** THE CONTROL: without the analyzer, stock Ghidra's own jump-table recovery over-reads
	 *  well past the 8 real entries. Required by the brief -- if this doesn't hold the whole
	 *  test is worthless, so it is asserted first and explicitly. */
	@Test
	public void controlWithoutAnalyzerOverReadsPastEight() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		Function function = createFunction(program, addr(0x8000));
		DecompileResults results = decompileWithJumpLoads(program, function);
		assertTrue("control did not decompile: " + results.getErrorMessage(),
			results.decompileCompleted());
		HighFunction hfunction = results.getHighFunction();
		assertNotNull(hfunction);
		JumpTable[] tables = hfunction.getJumpTables();
		assertTrue("expected at least one recovered jump table", tables.length >= 1);
		int caseCount = countRealCases(tables[0]);
		assertTrue("control should over-read past the 8 real entries, got " + caseCount,
			caseCount > 8);
	}

	/** With the analyzer run first, the stock decompiler (run the same way afterwards) sees
	 *  the override and reports exactly the 8 real targets; the durable EOL-comment artifact
	 *  is also present since {@code MessageLog} output is invisible headlessly. */
	@Test
	public void analyzerBoundsToTheEightRealTargets() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		Address dispatcher = addr(0x8000);
		Function function = createFunction(program, dispatcher);

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});

		DecompileResults results = decompileWithJumpLoads(program, function);
		assertTrue("post-override decompile failed: " + results.getErrorMessage(),
			results.decompileCompleted());
		HighFunction hfunction = results.getHighFunction();
		JumpTable[] tables = hfunction.getJumpTables();
		assertEquals(1, tables.length);
		Address[] cases = tables[0].getCases();
		assertEquals(8, cases.length);
		for (int i = 0; i < REAL_TARGETS.length; i++) {
			assertEquals(addr(REAL_TARGETS[i]), cases[i]);
		}

		String comment = program.getListing()
				.getComment(CommentType.EOL, addr(switchOffset(false)));
		assertNotNull("expected the [JumpTableBound] artifact comment", comment);
		assertTrue(comment, comment.contains("[JumpTableBound]"));
		assertTrue(comment, comment.contains("-> 8 entries"));
	}

	/** Real-ROM measurement (grm-eyn follow-up) showed most switches are NOT yet inside a
	 *  defined function at {@code CODE_ANALYSIS.before()} -- functions appear later, at {@code
	 *  FUNCTION_ANALYSIS}. This is the same dispatch with NO {@link Function} created at all: the
	 *  analyzer must resolve an {@link UndefinedFunction} itself (as stock {@code
	 *  DecompilerSwitchAnalyzer.FindFunctionCallback} does), and -- since there is no real
	 *  function to anchor a {@code JumpTable} override's namespace to -- fall back to pinning the
	 *  table by writing computed references directly on the switch instruction and disassembling
	 *  the kept targets. The CONTROL first confirms the over-read is real from the same
	 *  UndefinedFunction path stock would use; afterward the switch carries exactly the 8 real
	 *  targets as {@code COMPUTED_JUMP} references, which is exactly the predicate stock's own
	 *  {@code FindFunctionCallback.process} uses to skip a location it has already seen --
	 *  i.e. stock switch analysis leaves this site alone from here on. */
	@Test
	public void analyzerPinsUndefinedFunctionSwitchByReferences() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		Address dispatcher = addr(0x8000);
		Address switchAddr = addr(switchOffset(false));

		UndefinedFunction control =
			UndefinedFunction.findFunctionUsingSimpleBlockModel(program, dispatcher,
				TaskMonitor.DUMMY);
		assertNotNull("expected the simple block model to find the dispatcher body", control);
		DecompileResults controlResults = decompileWithJumpLoads(program, control);
		assertTrue("control did not decompile: " + controlResults.getErrorMessage(),
			controlResults.decompileCompleted());
		JumpTable[] controlTables = controlResults.getHighFunction().getJumpTables();
		assertTrue("expected at least one recovered jump table", controlTables.length >= 1);
		int controlCount = countRealCases(controlTables[0]);
		assertTrue("control should over-read past the 8 real entries, got " + controlCount,
			controlCount > 8);

		// No CreateFunctionCmd anywhere -- there genuinely is no Function registered at the
		// dispatcher; the analyzer must resolve its own UndefinedFunction, exactly like stock.
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		assertNull("test precondition: no function should be registered yet",
			program.getFunctionManager().getFunctionContaining(dispatcher));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(dispatcher, switchAddr.add(2)),
				TaskMonitor.DUMMY, new MessageLog());
		});

		Instruction switchInstr = program.getListing().getInstructionAt(switchAddr);
		assertNotNull(switchInstr);
		Reference[] refs = switchInstr.getReferencesFrom();
		assertEquals(8, refs.length);
		for (int i = 0; i < REAL_TARGETS.length; i++) {
			Reference ref = refs[i];
			assertEquals(addr(REAL_TARGETS[i]), ref.getToAddress());
			assertEquals(RefType.COMPUTED_JUMP, ref.getReferenceType());
			assertEquals(SourceType.ANALYSIS, ref.getSource());
			// The exact predicate stock's FindFunctionCallback.process uses to bail out of a
			// location it has already seen -- confirming it will never revisit this site.
			assertTrue("reference must read as computed (stock's own skip predicate)",
				ref.getReferenceType().isComputed());
		}

		// The kept targets were undefined data (part of the table region); pinning must have
		// disassembled them.
		for (long target : REAL_TARGETS) {
			assertNotNull("expected " + Long.toHexString(target) + " to be disassembled",
				program.getListing().getInstructionAt(addr(target)));
		}

		String comment = program.getListing().getComment(CommentType.EOL, switchAddr);
		assertNotNull("expected the [JumpTableBound] artifact comment", comment);
		assertTrue(comment, comment.contains("[JumpTableBound]"));
		assertTrue(comment, comment.contains("-> 8 entries"));
	}

	/** Real-ROM measurement (second grm-eyn follow-up, orchestrator-run 46-title corpus) found
	 *  coverage fixed (only 1 skip corpus-wide) but EVERY table inside a banked overlay space
	 *  still declined -- megaman {@code PRG_LO_B5::a734} stayed at 93 targets, ff1's
	 *  {@code W8000_M3_B14::b174} at 104, etc., while every plain-{@code RAM::}-space table
	 *  bounded correctly. Diagnosis with the same synthetic dispatch placed in an overlay
	 *  (mirroring this project's own real loader convention -- see the {@code D1a/D1b/D1c}
	 *  golden criteria: a home bank occupies its window un-suffixed in BASE space while every
	 *  other bank is a separate overlay over the SAME numeric range) confirmed the hypothesis:
	 *  when a jump table's real 16 bytes live in one memory (here, a small BASE block) and its
	 *  case targets resolve into an adjacent OVERLAY, {@code JumpTable.getLoadTables()} reports
	 *  the load table's address in the BASE/physical space ({@code RAM:}) while {@code
	 *  getCases()} reports the targets in the overlay space ({@code PRG_LO_B5::}) -- exact-space
	 *  equality then drops the load table entirely (0 moving tables survive the filter),
	 *  and {@link JumpTableBound} declines for want of any table shape at all. This is the
	 *  regression test for the fix: {@link AddressSpace#getPhysicalSpace()}-based comparison
	 *  (see {@code JumpTableBoundAnalyzer#sameMemory}), recognizing an overlay and its own
	 *  physical space as the same memory without conflating two SIBLING overlays (which would be
	 *  a genuine over-generalization -- not exercised here, but why the fix compares pairwise
	 *  physical-of relationships rather than blanket physical-space equality). */
	@Test
	public void analyzerBoundsAcrossOverlayPhysicalSpaceMismatch() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		// The real 16 bytes of table live in a small BASE (non-overlay) block -- exactly
		// [0x8000, 0x8010). The rest of the notional 256-byte table region (the "over-read" past
		// the real entries) and the real target addresses themselves live in an OVERLAY that
		// starts exactly where the base block ends, so there is no gap and no overlap between
		// the two, and no ambiguity about which block backs which address.
		long overlayTable = 0x8000; // BASE space
		long[] overlayTargets =
			{ 0x8010, 0x8030, 0x8050, 0x8070, 0x8090, 0x80b0, 0x80d0, 0x80f0 }; // OVERLAY space
		builder.createMemory("fixed", "0x8000", 0x10);
		MemoryBlock overlay = builder.createOverlayMemory("PRG_LO_B5", "0x8010", 0x1000);
		Address ovBase = overlay.getStart();

		StringBuilder table = new StringBuilder();
		for (long target : overlayTargets) {
			table.append(String.format("%02x %02x ", target & 0xff, (target >> 8) & 0xff));
		}
		builder.setBytes(String.format("0x%x", overlayTable), table.toString().trim(), false);

		// The remaining 240 bytes of the notional table region, in OVERLAY space: every fake
		// entry repeats a valid overlay address (one of the real targets) so the raw decompiler
		// recovery keeps going instead of bailing out on an invalid address.
		StringBuilder junk = new StringBuilder();
		for (int i = 8; i < 128; i++) {
			junk.append(
				String.format("%02x %02x ", overlayTargets[0] & 0xff, (overlayTargets[0] >> 8) & 0xff));
		}
		builder.setBytes(ovBase.toString(), junk.toString().trim(), false);

		// The dispatcher sits well clear of the table's byte range, still inside the overlay.
		// Its absolute operand ($8000/$8001) falls OUTSIDE the overlay's own mapped range (which
		// starts at $8010), so it resolves unambiguously to the BASE block.
		Address dispatchAddr = ovBase.getAddressSpace().getAddress(0x8900);
		StringBuilder code = new StringBuilder();
		code.append("0a a8 "); // ASL A ; TAY
		code.append(String.format("b9 %02x %02x ", overlayTable & 0xff, (overlayTable >> 8) & 0xff));
		code.append("85 04 ");
		code.append(String.format("b9 %02x %02x ", (overlayTable + 1) & 0xff,
			((overlayTable + 1) >> 8) & 0xff));
		code.append("85 05 ");
		code.append("6c 04 00"); // JMP ($0004)
		builder.setBytes(dispatchAddr.toString(), code.toString().trim(), true);
		Address switchAddr = dispatchAddr.add(12);

		ProgramDB program = builder.getProgram();

		// CONTROL: confirm the over-read from the same UndefinedFunction path stock would use
		// (no function is registered at this priority for a fresh overlay switch either).
		UndefinedFunction control = UndefinedFunction.findFunctionUsingSimpleBlockModel(program,
			dispatchAddr, TaskMonitor.DUMMY);
		assertNotNull(control);
		DecompileResults controlResults = decompileWithJumpLoads(program, control);
		assertTrue("control did not decompile: " + controlResults.getErrorMessage(),
			controlResults.decompileCompleted());
		JumpTable[] controlTables = controlResults.getHighFunction().getJumpTables();
		assertTrue("expected at least one recovered jump table", controlTables.length >= 1);
		int controlCount = countRealCases(controlTables[0]);
		assertTrue("control should over-read past the 8 real entries, got " + controlCount,
			controlCount > 8);

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(dispatchAddr, switchAddr.add(2)),
				TaskMonitor.DUMMY, new MessageLog());
		});

		// No real Function exists here either (still an UndefinedFunction case), so the analyzer
		// took the reference-pinning path, not the override path -- verify it the same way
		// analyzerPinsUndefinedFunctionSwitchByReferences does, directly on the instruction,
		// rather than re-decompiling the same stale UndefinedFunction object (whose body a
		// SimpleBlockModel captured before pinning disassembled new instructions into it).
		Instruction switchInstr = program.getListing().getInstructionAt(switchAddr);
		assertNotNull(switchInstr);
		Reference[] refs = switchInstr.getReferencesFrom();
		assertEquals(8, refs.length);
		for (int i = 0; i < overlayTargets.length; i++) {
			Reference ref = refs[i];
			assertEquals(ovBase.getAddressSpace().getAddress(overlayTargets[i]), ref.getToAddress());
			assertEquals(RefType.COMPUTED_JUMP, ref.getReferenceType());
			assertEquals(SourceType.ANALYSIS, ref.getSource());
		}

		String comment = program.getListing().getComment(CommentType.EOL, switchAddr);
		assertNotNull("expected the [JumpTableBound] artifact comment", comment);
		assertTrue(comment, comment.contains("[JumpTableBound]"));
		assertTrue(comment, comment.contains("-> 8 entries"));
	}

	/** Negative: an explicit bound ({@code AND #$07}) gives the decompiler its own true case
	 *  count already, so the analyzer must be a no-op -- no override written. */
	@Test
	public void explicitlyBoundedTableIsLeftUntouched() throws Exception {
		ProgramDB program = buildProgram(TABLE, true);
		Address dispatcher = addr(0x8000);
		Function function = createFunction(program, dispatcher);

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});

		assertNoOverrideWritten(program, function, true);
	}

	/** grm-k50b: the same explicitly bounded table. The lowest-target bound keeps all 8 cases,
	 *  confirming the decompiler's count, so the table is laid as word[8] with its references --
	 *  and nothing else: no override, no comment. A second pass changes nothing. */
	@Test
	public void confirmedCountIsLaidAsWordArrayWithoutComment() throws Exception {
		ProgramDB program = buildProgram(TABLE, true);
		Function function = createFunction(program, addr(0x8000));
		for (int pass = 0; pass < 2; pass++) {
			inTx(program, "analyze", () -> {
				new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
					TaskMonitor.DUMMY, new MessageLog());
			});
			assertWordArrayWithRefs(program, 8);
		}
		assertNoOverrideWritten(program, function, true);
	}

	/** grm-vzp2: stock switch analysis, run after we laid the confirmed array, labels the table's
	 *  hi-byte half (tbl+1) as its own byte table, and its forced CreateDataCmd there clears our
	 *  whole word[8] (the control, asserted). The relay pass restores it, references included. */
	@Test
	public void arrayClearedByStockSwitchAnalysisIsRelaid() throws Exception {
		ProgramDB program = buildProgram(TABLE, true);
		Function function = createFunction(program, addr(0x8000));
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});
		assertWordArrayWithRefs(program, 8);

		DecompileResults stock = decompileWithJumpLoads(program, function);
		assertTrue(stock.getErrorMessage(), stock.decompileCompleted());
		inTx(program, "stock", () -> {
			new DecompilerSwitchAnalysisCmd(stock).applyTo(program, TaskMonitor.DUMMY);
		});
		ghidra.program.model.listing.Data atTable =
			program.getListing().getDefinedDataAt(addr(TABLE));
		assertTrue("control: stock cleared the array",
			atTable == null || !(atTable.getDataType() instanceof ghidra.program.model.data.Array));

		inTx(program, "relay", () -> assertEquals(1, analyzer.relayCleared(program)));
		assertWordArrayWithRefs(program, 8);
		inTx(program, "relay again", () -> assertEquals(0, analyzer.relayCleared(program)));
	}

	/** grm-k50b negative: no guard, but a zero word after the 8 real entries stops the
	 *  decompiler's recovery there anyway. The 8 cases are right, but nothing proves it, so
	 *  no array: the stop is the zero word's, not a guard's. */
	@Test
	public void zeroWordStopIsNotAConfirmedCount() throws Exception {
		ProgramDB program = buildProgram(TABLE, false, 0);
		Function function = createFunction(program, addr(0x8000));
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
				TaskMonitor.DUMMY, new MessageLog());
		});
		assertNull(program.getListing().getDefinedDataAt(addr(TABLE)));
	}

	/** Table AFTER its code (grm-akiv, the megaman e000 layout): the lowest-target rule declines,
	 *  and the switch window bounds it to the 8 real targets, which all lie between the switch
	 *  ($800c) and the table ($8500). The fake entries point past the table ($8600). */
	@Test
	public void tableAfterCodeIsBoundedBySwitchWindow() throws Exception {
		ProgramDB program = buildProgram(0x8500, false, 0x8600);
		Function function = createFunction(program, addr(0x8000));

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});

		DecompileResults results = decompileWithJumpLoads(program, function);
		assertTrue(results.decompileCompleted());
		Address[] cases = results.getHighFunction().getJumpTables()[0].getCases();
		assertEquals(8, cases.length);
		for (int i = 0; i < REAL_TARGETS.length; i++) {
			assertEquals(addr(REAL_TARGETS[i]), cases[i]);
		}
		String comment = program.getListing()
				.getComment(CommentType.EOL, addr(switchOffset(false)));
		assertNotNull(comment);
		assertTrue(comment, comment.contains("-> 8 entries (targets between switch and table, laid word[8])"));
	}

	/** Negative: a table stored ABOVE its targets whose over-read stays INSIDE the switch window
	 *  (every fake entry is $8200, between the switch and the table) -- the lowest-target rule
	 *  does not apply and the window rule finds no end, so decline, no override. */
	@Test
	public void tableAboveItsTargetsIsLeftUntouched() throws Exception {
		long aboveTable = 0x8500; // above every REAL_TARGETS entry
		ProgramDB program = buildProgram(aboveTable, false);
		Address dispatcher = addr(0x8000);
		Function function = createFunction(program, dispatcher);

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});

		assertNoOverrideWritten(program, function, false);
		// grm-k50b: a decline is not a confirmed count; no array either.
		assertNull(program.getListing().getDefinedDataAt(addr(aboveTable)));
	}

	/** grm-jt7s (megaman2 92e4): the usual order is stock switch analysis FIRST, laying a
	 *  reference, a {@code switchD_::caseD_} label and disassembly at every over-read case, and the
	 *  override LATER. Every fake entry here points at {@code $8400}, garbage that decodes as
	 *  {@code ORA ($00,X) / SED / BRK}. After the late bound, the switch carries only the 8 real
	 *  targets and the garbage nothing else reaches is cleared, label and function body included. */
	@Test
	public void lateOverrideRetractsStockOverReadCases() throws Exception {
		long junk = 0x8400;
		ProgramDB program = buildProgram(TABLE, false, junk);
		Address switchAddr = addr(switchOffset(false));
		inTx(program, "garbage", () -> {
			try {
				builder.setBytes(String.format("0x%x", junk), "01 00 f8 00", false);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		Function function = createFunction(program, addr(0x8000));
		DecompileResults stock = decompileWithJumpLoads(program, function);
		assertTrue(stock.getErrorMessage(), stock.decompileCompleted());
		inTx(program, "stock", () -> {
			new DecompilerSwitchAnalysisCmd(stock).applyTo(program, TaskMonitor.DUMMY);
			CreateFunctionCmd.fixupFunctionBody(program, function, TaskMonitor.DUMMY);
		});
		// The control: stock really laid the over-read this test is about.
		assertNotNull(program.getListing().getInstructionAt(addr(junk)));
		assertTrue(targetsOf(program, switchAddr).contains(addr(junk)));

		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
				TaskMonitor.DUMMY, new MessageLog());
		});

		java.util.Set<Address> expected = new java.util.HashSet<>();
		for (long t : REAL_TARGETS) {
			expected.add(addr(t));
		}
		assertEquals(expected, targetsOf(program, switchAddr));
		assertNull("garbage reached only by the over-read is cleared",
			program.getListing().getInstructionAt(addr(junk)));
		assertEquals(0, program.getSymbolTable().getSymbols(addr(junk)).length);
		assertTrue(!function.getBody().contains(addr(junk)));
	}

	/** grm-vrkk.11 (contra 849f): the same stock-first order, but the bound lands as a reference
	 *  PIN (no real function owns the switch yet), which replaces every reference itself. It must
	 *  still retract stock's over-read: the stale {@code caseD_} label and the garbage only the
	 *  over-read reached. */
	@Test
	public void pinRetractsStockOverReadCases() throws Exception {
		long junk = 0x8400;
		ProgramDB program = buildProgram(TABLE, false, junk);
		Address switchAddr = addr(switchOffset(false));
		setBytes(program, junk, "01 00 f8 00", false); // ORA ($00,X) / SED / BRK
		UndefinedFunction undefined = layStockOverRead(program, switchAddr, junk);

		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().boundFunctions(program, java.util.Set.of(undefined),
				TaskMonitor.DUMMY, new MessageLog());
		});

		assertEquals(realTargets(), targetsOf(program, switchAddr));
		assertNull("garbage reached only by the over-read is cleared",
			program.getListing().getInstructionAt(addr(junk)));
		assertEquals(0, program.getSymbolTable().getSymbols(addr(junk)).length);
	}

	/** grm-vrkk.11: an over-read target that real code falls through into is reached, though no
	 *  reference says so. The pin's retraction drops its label but must keep the code. */
	@Test
	public void pinRetractionKeepsCodeReachedByFallThrough() throws Exception {
		long junk = 0x8401;
		ProgramDB program = buildProgram(TABLE, false, junk);
		Address switchAddr = addr(switchOffset(false));
		setBytes(program, 0x8400, "ea 60", true); // NOP / RTS: real code that falls into the target
		createFunction(program, addr(0x8400));
		UndefinedFunction undefined = layStockOverRead(program, switchAddr, junk);

		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().boundFunctions(program, java.util.Set.of(undefined),
				TaskMonitor.DUMMY, new MessageLog());
		});

		assertEquals(realTargets(), targetsOf(program, switchAddr));
		assertNotNull("code reached by fall-through stays",
			program.getListing().getInstructionAt(addr(junk)));
		for (ghidra.program.model.symbol.Symbol s : program.getSymbolTable().getSymbols(addr(junk))) {
			assertTrue("stale caseD_ label removed: " + s.getName(true),
				!s.getParentNamespace().getName().startsWith("switchD_"));
		}
	}

	/** grm-vrkk.11 (contra 8e53): an over-read target that over-read JUNK falls into is reached
	 *  only by code the same retraction clears, so it is cleared too -- unlike a target real code
	 *  falls into ({@link #pinRetractionKeepsCodeReachedByFallThrough}). Entry 9 points at
	 *  {@code $8402}, which the junk at {@code $8400} (also an over-read target) falls into. */
	@Test
	public void pinRetractionClearsJunkFallingIntoJunk() throws Exception {
		long junk = 0x8400;
		ProgramDB program = buildProgram(TABLE, false, junk);
		Address switchAddr = addr(switchOffset(false));
		setBytes(program, junk, "a9 00 40", false); // LDA #0 / RTI
		setBytes(program, TABLE + 2 * 9, "02 84", false); // entry 9 -> $8402
		UndefinedFunction undefined = layStockOverRead(program, switchAddr, junk);
		assertTrue("control: stock also reached the fallen-into target",
			targetsOf(program, switchAddr).contains(addr(junk + 2)));

		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().boundFunctions(program, java.util.Set.of(undefined),
				TaskMonitor.DUMMY, new MessageLog());
		});

		assertEquals(realTargets(), targetsOf(program, switchAddr));
		assertNull(program.getListing().getInstructionAt(addr(junk)));
		assertNull("junk falling into junk is cleared",
			program.getListing().getInstructionAt(addr(junk + 2)));
	}

	/** grm-deve: the bounded table reads as word[8] with one DATA reference per entry to its case
	 *  target, and nothing is laid over the over-read entries (their bytes are the table's tail and
	 *  beyond, which hold the targets' own code region here). */
	@Test
	public void overrideLaysWordArrayOverKeptEntriesOnly() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		Function function = createFunction(program, addr(0x8000));
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
				TaskMonitor.DUMMY, new MessageLog());
		});
		assertWordArrayWithRefs(program, 8);
		String comment = program.getListing().getComment(CommentType.EOL, addr(switchOffset(false)));
		assertNotNull(comment);
		assertTrue(comment, comment.contains(", laid word[8]"));
	}

	/** grm-deve plus grm-vrkk.11: pin path after stock over-read. The array must not shield the
	 *  retraction: the junk reached only by over-read entries is still cleared. */
	@Test
	public void pinLaysWordArrayAndStillRetractsOverRead() throws Exception {
		long junk = 0x8400;
		ProgramDB program = buildProgram(TABLE, false, junk);
		Address switchAddr = addr(switchOffset(false));
		setBytes(program, junk, "01 00 f8 00", false);
		UndefinedFunction undefined = layStockOverRead(program, switchAddr, junk);

		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().boundFunctions(program, java.util.Set.of(undefined),
				TaskMonitor.DUMMY, new MessageLog());
		});

		assertEquals(realTargets(), targetsOf(program, switchAddr));
		assertNull("garbage reached only by the over-read is cleared",
			program.getListing().getInstructionAt(addr(junk)));
		assertWordArrayWithRefs(program, 8);
		for (Reference r : program.getReferenceManager().getReferencesTo(addr(junk))) {
			assertTrue("no reference into over-read junk: " + r, false);
		}
	}

	/** grm-deve: a pass over an already-bounded, already-laid table changes nothing. */
	@Test
	public void layingIsIdempotent() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		Function function = createFunction(program, addr(0x8000));
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});
		long modified = program.getModificationNumber();
		inTx(program, "again", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});
		assertWordArrayWithRefs(program, 8);
		assertEquals(modified, program.getModificationNumber());
	}

	/** grm-deve decline: someone else's defined data at the table start is a claim we leave alone;
	 *  the bound itself still lands as before, with no array and no data references. */
	@Test
	public void foreignDataAtTableStartDeclinesTheArray() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		Function function = createFunction(program, addr(0x8000));
		inTx(program, "foreign", () -> {
			try {
				program.getListing().createData(addr(TABLE),
					ghidra.program.model.data.DWordDataType.dataType);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
				TaskMonitor.DUMMY, new MessageLog());
		});
		assertTrue("dword".equalsIgnoreCase(program.getListing().getDefinedDataAt(addr(TABLE)).getDataType()
				.getName()));
		assertEquals(0, dataRefsFrom(program, TABLE, TABLE + 0x20).size());
		String comment = program.getListing().getComment(CommentType.EOL, addr(switchOffset(false)));
		assertNotNull(comment);
		assertTrue(comment, comment.contains("-> 8 entries"));
		assertTrue(comment, !comment.contains("laid"));
	}

	/** grm-deve: the layer clears stock's byte array (tail included), refuses over instructions,
	 *  and {@code unlay} takes back its own array and references. */
	@Test
	public void layerClearsStockBytesDeclinesOverCodeAndUnlays() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		java.util.List<Address> targets = java.util.List.of(addr(0x8210), addr(0x8230));
		inTx(program, "stock-like", () -> {
			try {
				program.getListing().createData(addr(TABLE),
					new ghidra.program.model.data.ArrayDataType(
						ghidra.program.model.data.ByteDataType.dataType, 64, 1));
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		inTx(program, "lay", () -> assertTrue(JumpTableArrays.layWords(program, addr(TABLE), targets)));
		assertWordArrayWithRefs(program, 2);
		assertNull("stock's over-read tail is gone",
			program.getListing().getDefinedDataAt(addr(TABLE + 4)));
		assertTrue(JumpTableArrays.isLaid(program, addr(TABLE), targets));
		inTx(program, "unlay", () -> assertTrue(JumpTableArrays.unlay(program, addr(TABLE))));
		assertNull(program.getListing().getDefinedDataAt(addr(TABLE)));
		assertEquals(0, dataRefsFrom(program, TABLE, TABLE + 0x20).size());

		setBytes(program, 0x8300, "ea ea ea ea", true);
		inTx(program, "decline", () -> assertTrue(
			!JumpTableArrays.layWords(program, addr(0x82fe), targets)));
		assertNull(program.getListing().getDefinedDataAt(addr(0x82fe)));
	}

	/** grm-deve: an RTS-trick style table (entry = target - 1, the dispatch adds the one back) is
	 *  laid the same way, each entry referring to its real target, never to word + 0. */
	@Test
	public void targetMinusOneTableIsLaidWithReferencesToTheTargets() throws Exception {
		ProgramDB program = buildProgram(TABLE, false);
		StringBuilder table = new StringBuilder();
		for (long target : REAL_TARGETS) {
			table.append(String.format("%02x %02x ", (target - 1) & 0xff, ((target - 1) >> 8) & 0xff));
		}
		inTx(program, "clear", () -> program.getListing().clearCodeUnits(addr(0x8000), addr(0x8020),
			false));
		setBytes(program, TABLE, table.toString().trim(), false);
		// ASL A / TAY / LDA tbl,Y / CLC / ADC #1 / STA $04 / LDA tbl+1,Y / ADC #0 / STA $05 / JMP ($0004)
		setBytes(program, 0x8000, "0a a8 b9 00 82 18 69 01 85 04 b9 01 82 69 00 85 05 6c 04 00",
			true);
		Function function = createFunction(program, addr(0x8000));
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(function.getBody()),
				TaskMonitor.DUMMY, new MessageLog());
		});
		assertWordArrayWithRefs(program, 8);
		long switchAt = 0x8000 + 0x11;
		String comment = program.getListing().getComment(CommentType.EOL, addr(switchAt));
		assertNotNull(comment);
		assertTrue(comment, comment.contains("laid word[8] (RTS-trick: entry = target - 1)"));
	}

	/**
	 * grm-d3tu: a planar lo/hi dispatch ({@code AND #$3F / TAY / LDA lo,Y / STA $04 / LDA hi,Y / STA $05 /
	 * JMP ($0004)}, the AND giving a bound which makes the decompiler count 64 cases), 8 real entries, halves 8 bytes apart so the high half ends where the code
	 * begins. Every byte past the real low bytes is the high byte $82 or filler $88 ({@code DEY}),
	 * so all over-read targets land in mapped code.
	 */
	private ProgramDB buildPlanarProgram() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		builder.setBytes("0x8000", "29 3f a8 b9 00 82 85 04 b9 08 82 85 05 6c 04 00", true);
		StringBuilder table = new StringBuilder();
		for (long target : REAL_TARGETS) {
			table.append(String.format("%02x ", target & 0xff));
		}
		for (int i = 0; i < 8; i++) {
			table.append("82 ");
		}
		for (int i = 16; i < 80; i++) {
			table.append("88 ");
		}
		builder.setBytes("0x8200", table.toString().trim(), false);
		StringBuilder code = new StringBuilder();
		for (int i = 0; i < 0xb0; i++) {
			code.append("ea "); // NOPs under the handlers past the table
		}
		builder.setBytes("0x8250", code.toString().trim(), false);
		return builder.getProgram();
	}

	private void analyzePlanar(ProgramDB program, JumpTableBoundAnalyzer analyzer, Function function)
			throws Exception {
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		});
	}

	/** byte[8] at lo and at lo+8; entry i of the low array refers to REAL_TARGETS[i], nothing else
	 *  in the neighbourhood carries a data reference (the high half and over-read entries: none). */
	private void assertPlanarArraysWithRefs(ProgramDB program) {
		for (long at : new long[] { TABLE, TABLE + 8 }) {
			ghidra.program.model.listing.Data d = program.getListing().getDefinedDataAt(addr(at));
			assertNotNull("expected an array at " + Long.toHexString(at), d);
			ghidra.program.model.data.Array a = (ghidra.program.model.data.Array) d.getDataType();
			assertEquals("byte[8]", a.getDataType().getName() + "[" + a.getNumElements() + "]");
		}
		java.util.List<Reference> refs = dataRefsFrom(program, TABLE - 0x100, TABLE + 0x400);
		assertEquals(8, refs.size());
		for (Reference r : refs) {
			int i = (int) (r.getFromAddress().getOffset() - TABLE);
			assertTrue("reference from a low entry", i >= 0 && i < 8);
			assertEquals(addr(REAL_TARGETS[i]), r.getToAddress());
			assertEquals(SourceType.ANALYSIS, r.getSource());
		}
	}

	@Test
	public void planarTableIsLaidAsTwoByteArraysWithRefsFromLoEntries() throws Exception {
		ProgramDB program = buildPlanarProgram();
		Function function = createFunction(program, addr(0x8000));
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		analyzePlanar(program, analyzer, function);
		assertPlanarArraysWithRefs(program);
		String comment = program.getListing().getComment(CommentType.EOL, addr(0x800d));
		assertNotNull(comment);
		assertTrue(comment, comment.contains("planar lo/hi tables 8 apart"));
		assertTrue(comment, comment.contains("laid byte[8] lo/hi"));
		long modified = program.getModificationNumber();
		analyzePlanar(program, analyzer, function);
		assertPlanarArraysWithRefs(program);
		assertEquals(modified, program.getModificationNumber());
	}

	/** grm-d3tu plus grm-vzp2: whatever stock switch analysis does to our pair, the relay pass
	 *  restores it (or finds it intact). */
	@Test
	public void planarPairClearedByStockSwitchAnalysisIsRelaid() throws Exception {
		ProgramDB program = buildPlanarProgram();
		Function function = createFunction(program, addr(0x8000));
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		analyzePlanar(program, analyzer, function);
		assertPlanarArraysWithRefs(program);
		DecompileResults stock = decompileWithJumpLoads(program, function);
		assertTrue(stock.getErrorMessage(), stock.decompileCompleted());
		inTx(program, "stock", () -> {
			new DecompilerSwitchAnalysisCmd(stock).applyTo(program, TaskMonitor.DUMMY);
		});
		boolean intact = JumpTableArrays.isLaidPlanar(program, addr(TABLE), 8, realTargetList());
		// Stock left the pair alone here (observed); relay is then a no-op ...
		inTx(program, "relay", () -> assertEquals(intact ? 0 : 1, analyzer.relayCleared(program)));
		assertPlanarArraysWithRefs(program);
		// ... so force the clobber it could cause: one merged byte array over both halves, as stock lays by load size.
		inTx(program, "clobber", () -> {
			try {
				program.getListing().clearCodeUnits(addr(TABLE), addr(TABLE + 0xf), false);
				program.getReferenceManager().removeAllReferencesFrom(addr(TABLE), addr(TABLE + 7));
				program.getListing().createData(addr(TABLE),
					new ghidra.program.model.data.ArrayDataType(
						ghidra.program.model.data.ByteDataType.dataType, 16, 1));
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		inTx(program, "relay clobbered", () -> assertEquals(1, analyzer.relayCleared(program)));
		assertPlanarArraysWithRefs(program);
	}

	/** grm-d3tu: the layer is all-or-nothing across the halves, absorbs stock's merged byte array,
	 *  and {@code unlayPlanar} takes back the pair and its references. */
	@Test
	public void planarLayerDeclinesOverCodeAbsorbsStockAndUnlays() throws Exception {
		ProgramDB program = buildPlanarProgram();
		java.util.List<Address> targets = realTargetList().subList(0, 4);
		inTx(program, "stock-like", () -> {
			try {
				program.getListing().createData(addr(TABLE),
					new ghidra.program.model.data.ArrayDataType(
						ghidra.program.model.data.ByteDataType.dataType, 64, 1));
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		inTx(program, "lay", () -> assertTrue(JumpTableArrays.layPlanar(program, addr(TABLE), 8,
			targets)));
		assertTrue(JumpTableArrays.isLaidPlanar(program, addr(TABLE), 8, targets));
		assertNull("stock's merged array tail is gone",
			program.getListing().getDefinedDataAt(addr(TABLE + 16)));
		assertEquals(4, dataRefsFrom(program, TABLE - 0x100, TABLE + 0x400).size());
		inTx(program, "unlay", () -> assertTrue(JumpTableArrays.unlayPlanar(program, addr(TABLE), 8)));
		assertNull(program.getListing().getDefinedDataAt(addr(TABLE)));
		assertNull(program.getListing().getDefinedDataAt(addr(TABLE + 8)));
		assertEquals(0, dataRefsFrom(program, TABLE - 0x100, TABLE + 0x400).size());

		// An instruction over the HIGH half declines, leaving the low half untouched.
		setBytes(program, TABLE + 0x108, "ea ea", true);
		inTx(program, "decline", () -> assertTrue(
			!JumpTableArrays.layPlanar(program, addr(TABLE + 0x100), 8, targets)));
		assertNull(program.getListing().getDefinedDataAt(addr(TABLE + 0x100)));
		// Halves that would overlap decline.
		inTx(program, "overlap", () -> assertTrue(
			!JumpTableArrays.layPlanar(program, addr(TABLE), 2, targets)));
	}

	private java.util.List<Address> realTargetList() {
		java.util.List<Address> out = new java.util.ArrayList<>();
		for (long t : REAL_TARGETS) {
			out.add(addr(t));
		}
		return out;
	}

	/** word[count] at the table, entry i referring to REAL_TARGETS[i] by a DATA reference, and no
	 *  data reference from anywhere else in the table's neighbourhood. */
	private void assertWordArrayWithRefs(ProgramDB program, int count) {
		ghidra.program.model.listing.Data d = program.getListing().getDefinedDataAt(addr(TABLE));
		assertNotNull("expected an array at the table", d);
		assertEquals("word[" + count + "]",
			((ghidra.program.model.data.Array) d.getDataType()).getDataType().getName() + "[" +
				((ghidra.program.model.data.Array) d.getDataType()).getNumElements() + "]");
		java.util.List<Reference> refs = dataRefsFrom(program, TABLE - 0x100, TABLE + 0x400);
		assertEquals(count, refs.size());
		for (Reference r : refs) {
			int i = (int) (r.getFromAddress().getOffset() - TABLE) / 2;
			assertEquals(addr(REAL_TARGETS[i]), r.getToAddress());
			assertEquals(SourceType.ANALYSIS, r.getSource());
		}
	}

	private java.util.List<Reference> dataRefsFrom(ProgramDB program, long from, long to) {
		java.util.List<Reference> out = new java.util.ArrayList<>();
		for (long a = from; a <= to; a++) {
			for (Reference r : program.getReferenceManager().getReferencesFrom(addr(a))) {
				if (RefType.DATA.equals(r.getReferenceType())) {
					out.add(r);
				}
			}
		}
		return out;
	}

	private void setBytes(ProgramDB program, long at, String bytes, boolean disassemble) {
		inTx(program, "bytes", () -> {
			try {
				builder.setBytes(String.format("0x%x", at), bytes, disassemble);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}

	/** Runs stock switch analysis on the dispatcher's {@link UndefinedFunction} (no real function
	 *  exists) and checks the control: the over-read really reached {@code junk}. */
	private UndefinedFunction layStockOverRead(ProgramDB program, Address switchAddr, long junk) {
		UndefinedFunction undefined = UndefinedFunction.findFunctionUsingSimpleBlockModel(program,
			addr(0x8000), TaskMonitor.DUMMY);
		assertNotNull(undefined);
		DecompileResults stock = decompileWithJumpLoads(program, undefined);
		assertTrue(stock.getErrorMessage(), stock.decompileCompleted());
		inTx(program, "stock", () -> {
			new DecompilerSwitchAnalysisCmd(stock).applyTo(program, TaskMonitor.DUMMY);
		});
		assertNotNull(program.getListing().getInstructionAt(addr(junk)));
		assertTrue(targetsOf(program, switchAddr).contains(addr(junk)));
		boolean labelled = false;
		for (ghidra.program.model.symbol.Symbol s : program.getSymbolTable().getSymbols(addr(junk))) {
			labelled |= s.getParentNamespace().getName().equals("switchD_" + switchAddr);
		}
		assertTrue("control: stock labelled the over-read target", labelled);
		assertNull("test precondition: still no real function at the switch",
			program.getFunctionManager().getFunctionContaining(switchAddr));
		return undefined;
	}

	private java.util.Set<Address> realTargets() {
		java.util.Set<Address> expected = new java.util.HashSet<>();
		for (long t : REAL_TARGETS) {
			expected.add(addr(t));
		}
		return expected;
	}

	/** The targets of every computed-jump reference on {@code switchAddr}. */
	private java.util.Set<Address> targetsOf(ProgramDB program, Address switchAddr) {
		java.util.Set<Address> targets = new java.util.HashSet<>();
		for (Reference ref : program.getReferenceManager().getReferencesFrom(switchAddr)) {
			if (RefType.COMPUTED_JUMP.equals(ref.getReferenceType())) {
				targets.add(ref.getToAddress());
			}
		}
		return targets;
	}

	private void assertNoOverrideWritten(ProgramDB program, Function function, boolean maskIndex) {
		DecompileResults results = decompileWithJumpLoads(program, function);
		assertTrue(results.decompileCompleted());
		// No override means no artifact comment either (the analyzer must be a total no-op).
		String comment =
			program.getListing().getComment(CommentType.EOL, addr(switchOffset(maskIndex)));
		assertNull("analyzer must not leave a comment when it declines", comment);
	}

	/** The number of non-default cases {@code table} reports, i.e. what the analyzer would
	 *  receive as its input case count. */
	private int countRealCases(JumpTable table) {
		Address[] cases = table.getCases();
		Integer[] labels = table.getLabelValues();
		int count = 0;
		for (int i = 0; i < cases.length; i++) {
			boolean isDefault =
				(i >= labels.length) || (labels[i] != null && labels[i] == 0xbad1abe1);
			if (!isDefault) {
				count++;
			}
		}
		return count;
	}
}
