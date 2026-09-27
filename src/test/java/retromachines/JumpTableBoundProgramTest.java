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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
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
		builder = new ProgramBuilder("Test", LANG);
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
			table.append(String.format("%02x %02x ", TABLE & 0xff, (TABLE >> 8) & 0xff));
		}
		builder.setBytes(String.format("0x%x", tableAddr), table.toString().trim(), false);

		return builder.getProgram();
	}

	private Function createFunction(ProgramDB program, Address entry) {
		int tx = program.startTransaction("fn");
		try {
			CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
			cmd.applyTo(program, TaskMonitor.DUMMY);
			return cmd.getFunction();
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private DecompileResults decompileWithJumpLoads(ProgramDB program, Function function) {
		DecompInterface ifc = new DecompInterface();
		try {
			new SwitchAnalysisDecompileConfigurer(program).configure(ifc);
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
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

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
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(dispatcher, switchAddr.add(2)),
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

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
		builder = new ProgramBuilder("Test", LANG);
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
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(dispatchAddr, switchAddr.add(2)),
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

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
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertNoOverrideWritten(program, function, true);
	}

	/** Negative: a table stored ABOVE its targets never qualifies for the rule -- decline,
	 *  no override. */
	@Test
	public void tableAboveItsTargetsIsLeftUntouched() throws Exception {
		long aboveTable = 0x8500; // above every REAL_TARGETS entry
		ProgramDB program = buildProgram(aboveTable, false);
		Address dispatcher = addr(0x8000);
		Function function = createFunction(program, dispatcher);

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(function.getBody()), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertNoOverrideWritten(program, function, false);
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
