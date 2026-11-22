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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * End-to-end coverage of {@link SplitDispatchTableAnalyzer} against a SYNTHETIC reproduction of
 * rcproam's split dispatch (grm-3er5) -- no ROM bytes copied in. The caller loads an interleaved
 * lo/hi table entry into {@code $1e/$1f} and calls a shared {@code JMP ($001e)} stub:
 * <pre>
 *   9000: TAY / LDA tbl,Y / STA $1e / LDA tbl+1,Y / STA $1f / JSR $8068 / RTS
 *   8068: JMP ($001e)
 * </pre>
 * Handlers are single {@code RTS} bytes, left undefined so the analyzer's own disassembly is
 * what the assertions observe.
 */
public class SplitDispatchTableAnalyzerTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long STUB = 0x8068;
	private static final long CALLER = 0x9000;
	private static final long CALLER2 = 0x9040;
	private static final long TABLE = 0x9100;
	private static final long[] HANDLERS = { 0x9200, 0x9210, 0x9220, 0x9230 };

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private static String word(long w) {
		return String.format("%02x %02x", w & 0xff, (w >> 8) & 0xff);
	}

	/** {@code TAY / LDA tbl,Y / STA $1e / LDA tbl+1,Y / STA $1f / JSR stub / RTS}, or with the
	 *  two loads in high-byte-first order. */
	private static String caller(long table, boolean hiFirst) {
		String lo = "b9 " + word(table) + " 85 1e";
		String hi = "b9 " + word(table + 1) + " 85 1f";
		return "a8 " + (hiFirst ? hi + " " + lo : lo + " " + hi) + " 20 " + word(STUB) + " 60";
	}

	private ProgramDB build(String tableHex, boolean hiFirst, String stubHex) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		builder.setBytes(String.format("0x%x", STUB), stubHex, true);
		builder.setBytes(String.format("0x%x", CALLER), caller(TABLE, hiFirst), true);
		builder.setBytes(String.format("0x%x", TABLE), tableHex, false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		return builder.getProgram();
	}

	private void run(ProgramDB program) throws Exception {
		SplitDispatchTableAnalyzer analyzer = new SplitDispatchTableAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(addr(0x8000), addr(0xffff)), TaskMonitor.DUMMY,
				new MessageLog());
		});
	}

	private List<Long> stubTargets(ProgramDB program) {
		List<Long> out = new ArrayList<>();
		for (Reference r : program.getListing().getInstructionAt(addr(STUB)).getReferencesFrom()) {
			assertEquals(RefType.COMPUTED_CALL, r.getReferenceType());
			out.add(r.getToAddress().getOffset());
		}
		out.sort(null);
		return out;
	}

	/** The table runs into code three entries in: exactly those three handlers are followed. */
	@Test
	public void followsTableUntilItRunsIntoCode() throws Exception {
		ProgramDB program = build(
			word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " + word(HANDLERS[2]) + " ea 60",
			false, "6c 1e 00");
		// the bytes after the third entry are reachable code
		inTx(program, "code", () -> {
			new ghidra.app.cmd.disassemble.DisassembleCommand(addr(TABLE + 6), null, true)
					.applyTo(program);
		});
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2]), stubTargets(program));
		for (int i = 0; i < 3; i++) {
			Instruction h = program.getListing().getInstructionAt(addr(HANDLERS[i]));
			assertNotNull("handler " + i + " disassembled", h);
		}
		String eol = program.getListing().getComment(CommentType.EOL, addr(CALLER + 11));
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 3-entry table at 9100"));
	}

	/** A RAM target ends the table; nothing after it is taken, even a valid-looking entry. */
	@Test
	public void stopsAtFirstTargetOutsideCodeMemory() throws Exception {
		ProgramDB program = build(word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " +
			word(0x0300) + " " + word(HANDLERS[3]), true, "6c 1e 00");
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1]), stubTargets(program));
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[3])));
	}

	/** Two tables laid end to end: the first stops where the second (another site's) begins. */
	@Test
	public void stopsAtTheNextSitesTable() throws Exception {
		ProgramDB program = build(word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " +
			word(HANDLERS[2]) + " " + word(HANDLERS[3]) + " " + word(0x0400), false,
			"6c 1e 00");
		inTx(program, "caller2", () -> {
			builder.setBytes(String.format("0x%x", CALLER2), caller(TABLE + 4, false), true);
		});
		run(program);
		// first table: entries 0-1 (stops at 9104); second: 2-3 (stops at the RAM entry)
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2], HANDLERS[3]),
			stubTargets(program));
		String eol = program.getListing().getComment(CommentType.EOL, addr(CALLER + 11));
		assertTrue(eol, eol.startsWith("split dispatch: 2-entry table at 9100"));
	}

	/** One plausible entry is not a table: decline, add nothing. */
	@Test
	public void declinesWithFewerThanTwoEntries() throws Exception {
		ProgramDB program = build(word(HANDLERS[0]) + " " + word(0x2002), false, "6c 1e 00");
		run(program);
		assertEquals(List.of(), stubTargets(program));
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[0])));
	}

	/** The callee is not a JMP (P) stub: not this idiom. */
	@Test
	public void ignoresCallsToOrdinaryRoutines() throws Exception {
		ProgramDB program = build(word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " +
			word(0x0300), false, "60 ea ea");
		run(program);
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[0])));
		assertNull(program.getListing().getComment(CommentType.EOL, addr(CALLER + 11)));
	}

	/** grm-cqwn's inline form, shaped like wizwarr's NMI state dispatch: {@code LDX $03 / LDA
	 *  tbl,X / STA $66 / LDA tbl+1,X / STA $67 / JMP ($0066)} with the table straight after the
	 *  jump. Entry 2's handler is the first byte past the table and is not disassembled, so only
	 *  the lowest-target rule stops the walk before the valid-looking word that follows. */
	private ProgramDB buildInline(String computedRefTo) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		long table = CALLER + 15;
		builder.setBytes(String.format("0x%x", CALLER), "a6 03 bd " + word(table) + " 85 66 bd " +
			word(table + 1) + " 85 67 6c 66 00", true);
		builder.setBytes(String.format("0x%x", table), word(HANDLERS[0]) + " " +
			word(HANDLERS[1]) + " " + word(table + 6) + " " + word(HANDLERS[3]), false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		ProgramDB program = builder.getProgram();
		if (computedRefTo != null) {
			inTx(program, "ref", () -> {
				program.getListing().getInstructionAt(addr(CALLER + 12)).addMnemonicReference(
					addr(Long.parseLong(computedRefTo, 16)), RefType.COMPUTED_JUMP,
					ghidra.program.model.symbol.SourceType.ANALYSIS);
			});
		}
		return program;
	}

	private List<Long> computedTargets(ProgramDB program, long at) {
		List<Long> out = new ArrayList<>();
		for (Reference r : program.getListing().getInstructionAt(addr(at)).getReferencesFrom()) {
			if (r.getReferenceType().isComputed()) {
				out.add(r.getToAddress().getOffset());
			}
		}
		out.sort(null);
		return out;
	}

	@Test
	public void followsInlineDispatchUpToItsOwnLowestTarget() throws Exception {
		ProgramDB program = buildInline(null);
		run(program);
		long jmp = CALLER + 12;
		assertEquals(List.of(CALLER + 21, HANDLERS[0], HANDLERS[1]), computedTargets(program, jmp));
		assertNull("the word past the table is not an entry",
			program.getListing().getInstructionAt(addr(HANDLERS[3])));
		String eol = program.getListing().getComment(CommentType.EOL, addr(jmp));
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 3-entry table at 900f"));
		assertTrue(eol, eol.endsWith("(grm-cqwn)"));
	}

	private static final long HELPER = 0x9300;
	private static final long OTHER = 0x9040;

	/** grm-gipk.34.1: the inline form with a gap, the ultimaav {@code 88f4} / {@code 8a3f} shapes.
	 *  {@code LDX $03 / LDA tbl,X / STA $02 / LDA tbl+1,X / STA $03 / <gapHex> / JMP ($0002)}; the
	 *  table (three handlers, then a RAM entry) sits at {@code $9100}, the helper at {@code $9300}.
	 *  {@code otherHex}, when given, is a second block at {@code $9040}. */
	private ProgramDB buildGap(String gapHex, String helperHex, String otherHex) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		builder.setBytes(String.format("0x%x", CALLER), "a6 03 bd " + word(TABLE) + " 85 02 bd " +
			word(TABLE + 1) + " 85 03 " + gapHex + " 6c 02 00", true);
		builder.setBytes(String.format("0x%x", TABLE), word(HANDLERS[0]) + " " + word(HANDLERS[1]) +
			" " + word(HANDLERS[2]) + " " + word(0x0300), false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		builder.setBytes(String.format("0x%x", HELPER), helperHex, true);
		if (otherHex != null) {
			builder.setBytes(String.format("0x%x", OTHER), otherHex, true);
		}
		return builder.getProgram();
	}

	private static long gapJmp(String gapHex) {
		return CALLER + 12 + (gapHex.isEmpty() ? 0 : gapHex.split(" ").length);
	}

	private static final String JSR_HELPER = "20 " + "00 93";
	/** {@code LDY $20 / LDA $8bb3,Y / TAY / TXA / SEC / SBC $8bc5,Y / RTS}: no stores at all. */
	private static final String CLEAN_HELPER = "a4 20 b9 b3 8b a8 8a 38 f9 c5 8b 60";

	private void assertFollowed(ProgramDB program, String gapHex) {
		long jmp = gapJmp(gapHex);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2]), computedTargets(program, jmp));
		String eol = program.getListing().getComment(CommentType.EOL, addr(jmp));
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 3-entry table at 9100"));
		assertTrue(eol, eol.endsWith("(grm-gipk.34.1)"));
	}

	private void assertDeclined(ProgramDB program, String gapHex) {
		assertEquals(List.of(), computedTargets(program, gapJmp(gapHex)));
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[0])));
	}

	@Test
	public void followsInlineDispatchAcrossAStoreFreeHelperCall() throws Exception {
		ProgramDB program = buildGap(JSR_HELPER, CLEAN_HELPER, null);
		run(program);
		assertFollowed(program, JSR_HELPER);
	}

	@Test
	public void followsInlineDispatchAcrossPlaTaxAndHelperCall() throws Exception {
		String gap = "68 aa " + JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertFollowed(program, gap);
	}

	@Test
	public void declinesWhenTheHelperStoresToThePointer() throws Exception {
		ProgramDB program = buildGap(JSR_HELPER, "a9 00 85 02 60", null);
		run(program);
		assertDeclined(program, JSR_HELPER);
	}

	@Test
	public void declinesWhenTheHelperStoresToThePointerHighByteViaAbsolute() throws Exception {
		ProgramDB program = buildGap(JSR_HELPER, "a9 00 8d 03 00 60", null);
		run(program);
		assertDeclined(program, JSR_HELPER);
	}

	@Test
	public void declinesWhenTheHelperStoresThroughAnIndirectPointer() throws Exception {
		ProgramDB program = buildGap(JSR_HELPER, "a9 00 91 10 60", null);
		run(program);
		assertDeclined(program, JSR_HELPER);
	}

	@Test
	public void declinesWhenTheHelperStoresIndexedInZeroPage() throws Exception {
		ProgramDB program = buildGap(JSR_HELPER, "a9 00 95 40 60", null);
		run(program);
		assertDeclined(program, JSR_HELPER);
	}

	@Test
	public void acceptsAHelperThatStoresElsewhere() throws Exception {
		ProgramDB program = buildGap(JSR_HELPER, "a9 00 85 40 8d 00 03 60", null);
		run(program);
		assertFollowed(program, JSR_HELPER);
	}

	@Test
	public void declinesWhenTheHelperCallsAnUnsafeNestedHelper() throws Exception {
		// 9300: JSR 9304 / RTS;  9304: STA $03 / RTS
		ProgramDB program = buildGap(JSR_HELPER, "20 04 93 60 85 03 60", null);
		run(program);
		assertDeclined(program, JSR_HELPER);
	}

	@Test
	public void followsAGapWithAStoreAndAReadModifyWriteElsewhere() throws Exception {
		String gap = "85 40 e6 41 " + JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertFollowed(program, gap);
	}

	@Test
	public void declinesAGapWithAStoreToThePointer() throws Exception {
		String gap = "85 02 " + JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertDeclined(program, gap);
	}

	@Test
	public void declinesAGapWithAReadModifyWriteOfThePointerHighByte() throws Exception {
		String gap = "e6 03 " + JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertDeclined(program, gap);
	}

	@Test
	public void declinesWhenTheWalkHitsAConditionalBranch() throws Exception {
		String gap = "d0 00 " + JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertDeclined(program, gap);
	}

	@Test
	public void declinesAWalkLongerThanSixteenInstructions() throws Exception {
		String gap = "ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea";
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertDeclined(program, gap);
	}

	@Test
	public void followsAWalkOfExactlySixteenInstructions() throws Exception {
		String gap = "ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea";
		ProgramDB program = buildGap(gap, CLEAN_HELPER, null);
		run(program);
		assertFollowed(program, gap);
	}

	@Test
	public void stillFollowsTheQuadWhenAnotherPathJumpsIntoTheIndirectJump() throws Exception {
		String gap = JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, "4c " + word(gapJmp(gap)));
		run(program);
		assertFollowed(program, gap);
	}

	@Test
	public void stillFollowsTheQuadWhenAnotherPathJumpsIntoTheGap() throws Exception {
		String gap = "68 aa " + JSR_HELPER;
		ProgramDB program = buildGap(gap, CLEAN_HELPER, "4c " + word(CALLER + 13));
		run(program);
		assertFollowed(program, gap);
	}

	/** dragonpower {@code f59a}/{@code f5af}/{@code f5c8}: three quads, one table each, merging
	 *  into one tail {@code INY / STY $83 / INC $80 / JMP ($0000)}. Quad 1 falls into the tail;
	 *  quads 2 and 3 run some more code and {@code JMP} to it. */
	@Test
	public void followsThreeQuadsMergingIntoOneIndirectJump() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		long t1 = 0x9100;
		long t2 = 0x9106;
		long t3 = 0x910a;
		builder.setBytes("0x9000", "b9 " + word(t1) + " 85 00 b9 " + word(t1 + 1) + " 85 01 " +
			"a4 83 c8 84 83 e6 80 6c 00 00", true);
		String tail = "a4 83 c8 b1 81 85 02 4c " + word(0x900c);
		builder.setBytes("0x9040", "b9 " + word(t2) + " 85 00 b9 " + word(t2 + 1) + " 85 01 " + tail,
			true);
		builder.setBytes("0x9080", "b9 " + word(t3) + " 85 00 b9 " + word(t3 + 1) + " 85 01 " + tail,
			true);
		builder.setBytes("0x9100", word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " +
			word(HANDLERS[2]) + " " + word(HANDLERS[3]) + " " + word(HANDLERS[0]) + " " +
			word(HANDLERS[1]) + " " + word(HANDLERS[2]) + " " + word(0x0300), false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		ProgramDB program = builder.getProgram();
		run(program);
		long jmp = 0x9011;
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2], HANDLERS[3]),
			computedTargets(program, jmp));
		String eol = program.getListing().getComment(CommentType.EOL, addr(jmp));
		assertNotNull(eol);
		assertTrue(eol, eol.contains("3-entry table at 9100"));
		assertTrue(eol, eol.contains("(grm-gipk.34.1)"));
		assertTrue(eol, eol.contains("table at 9106"));
		assertTrue(eol, eol.contains("table at 910a"));
		assertTrue(eol, eol.contains("(grm-gipk.34.3)"));
	}

	private ProgramDB buildLeading(String tableHex) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		builder.setBytes(String.format("0x%x", CALLER), "a6 03 bd " + word(TABLE) + " 85 02 bd " +
			word(TABLE + 1) + " 85 03 6c 02 00", true);
		builder.setBytes(String.format("0x%x", TABLE), tableHex, false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		return builder.getProgram();
	}

	private String leadingEol(ProgramDB program) {
		return program.getListing().getComment(CommentType.EOL, addr(CALLER + 12));
	}

	@Test
	public void skipsOneLeadingNullEntry() throws Exception {
		ProgramDB program = buildLeading(word(0) + " " + word(HANDLERS[0]) + " " +
			word(HANDLERS[1]) + " " + word(HANDLERS[2]) + " " + word(0x0300));
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2]),
			computedTargets(program, CALLER + 12));
		String eol = leadingEol(program);
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 4-entry table at 9100 (1 leading null)"));
	}

	@Test
	public void skipsTwoLeadingNullEntries() throws Exception {
		ProgramDB program = buildLeading(word(0) + " " + word(0) + " " + word(HANDLERS[1]) + " " +
			word(HANDLERS[2]) + " " + word(0x0300));
		run(program);
		assertEquals(List.of(HANDLERS[1], HANDLERS[2]), computedTargets(program, CALLER + 12));
		String eol = leadingEol(program);
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 4-entry table at 9100 (2 leading nulls)"));
	}

	@Test
	public void declinesAnAllNullTable() throws Exception {
		ProgramDB program = buildLeading(word(0) + " " + word(0) + " " + word(0) + " " + word(0) +
			" " + word(0) + " " + word(0));
		run(program);
		assertEquals(List.of(), computedTargets(program, CALLER + 12));
	}

	@Test
	public void aNullInTheMiddleStillEndsTheWalk() throws Exception {
		ProgramDB program = buildLeading(word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " +
			word(0) + " " + word(HANDLERS[2]));
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1]), computedTargets(program, CALLER + 12));
		String eol = leadingEol(program);
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 2-entry table at 9100 via"));
	}

	/** Switch analysis already resolved the inline jump: leave it alone. */
	@Test
	public void leavesAnAlreadyResolvedInlineJumpAlone() throws Exception {
		ProgramDB program = buildInline("9200");
		run(program);
		assertEquals(List.of(HANDLERS[0]), computedTargets(program, CALLER + 12));
		assertNull(program.getListing().getComment(CommentType.EOL, addr(CALLER + 12)));
	}

	/** grm-gipk.28: JumpTableBound pinned the inline jump by references alone (no function holds
	 *  it, no override can be consumed), so its targets are COMPUTED_JUMP and made no function.
	 *  The split dispatch still resolves it: every pin is retyped to a call and the walk adds the
	 *  rest. */
	@Test
	public void upgradesAnOrphanBoundPinToCalls() throws Exception {
		ProgramDB program = buildInline("9200");
		long jmp = CALLER + 12;
		inTx(program, "bound", () -> program.getListing().setComment(addr(jmp), CommentType.EOL,
			"[JumpTableBound] table at 900f bounded 128 -> 1 entries (laid word[1])"));
		run(program);
		assertEquals(List.of(CALLER + 21, HANDLERS[0], HANDLERS[1]), computedTargets(program, jmp));
		for (Reference r : program.getListing().getInstructionAt(addr(jmp)).getReferencesFrom()) {
			if (r.getReferenceType().isComputed()) {
				assertEquals(RefType.COMPUTED_CALL, r.getReferenceType());
			}
		}
	}

	/** A bound that a function owns is a switch for stock analysis to resolve: leave it alone. */
	@Test
	public void leavesAnOwnedBoundPinAlone() throws Exception {
		ProgramDB program = buildInline("9200");
		long jmp = CALLER + 12;
		inTx(program, "bound", () -> {
			program.getListing().setComment(addr(jmp), CommentType.EOL,
				"[JumpTableBound] table at 900f bounded 128 -> 1 entries (laid word[1])");
			program.getFunctionManager().createFunction("f", addr(CALLER),
				new AddressSet(addr(CALLER), addr(jmp + 2)),
				ghidra.program.model.symbol.SourceType.USER_DEFINED);
		});
		run(program);
		assertEquals(List.of(HANDLERS[0]), computedTargets(program, jmp));
	}

	/** A jump-table override (its {@code switch} label) already owns the inline jump, though stock
	 *  switch analysis has not laid its references down yet: leave it alone. */
	@Test
	public void leavesAnOverriddenInlineJumpAlone() throws Exception {
		ProgramDB program = buildInline(null);
		inTx(program, "label", () -> {
			program.getSymbolTable().createLabel(addr(CALLER + 12), "switch",
				ghidra.program.model.symbol.SourceType.USER_DEFINED);
		});
		run(program);
		assertEquals(List.of(), computedTargets(program, CALLER + 12));
	}

	/** The caller runs from one block and the table sits in another (a banked window): the bytes
	 *  there are whichever bank is mapped, so the table is not established -- decline. */
	@Test
	public void declinesTableOutsideTheCallersBlock() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory("PRG_LO", "0x8000", 0x4000);
		builder.createMemory("PRG_HI", "0xc000", 0x4000);
		builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000);
		long stub = 0xc068;
		long caller = 0xd000;
		String call = "a8 b9 " + word(TABLE) + " 85 1e b9 " + word(TABLE + 1) + " 85 1f 20 " +
			word(stub) + " 60";
		builder.setBytes(String.format("0x%x", stub), "6c 1e 00", true);
		builder.setBytes(String.format("0x%x", caller), call, true);
		builder.setBytes(String.format("0x%x", TABLE),
			word(HANDLERS[0]) + " " + word(HANDLERS[1]) + " " + word(0x0300), false);
		ProgramDB program = builder.getProgram();
		run(program);
		assertEquals(0,
			program.getListing().getInstructionAt(addr(stub)).getReferencesFrom().length);
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[0])));
	}

	/** grm-gipk.33: a PLANAR split table, the megaman2 {@code 82d5} shape. {@code LDY $a9} (a RAM
	 *  variable, so no recoverable index) then {@code LDA lo,Y / STA $08 / LDA hi,Y / STA $09 /
	 *  JMP ($0008)}. The high bytes start {@code loBytes.length} after the low ones, which is the
	 *  only statement of the table's extent. With {@code guard}, {@code CPY #2 / BCS} sits between. */
	private ProgramDB buildPlanar(String loHex, String hiHex, int distance, boolean guard)
			throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		String loads = "b9 " + word(TABLE) + " 85 08 b9 " + word(TABLE + distance) + " 85 09 6c 08 00";
		String code = "a4 a9 " + (guard ? "c0 02 b0 0d " : "") + loads + " 60";
		builder.setBytes(String.format("0x%x", CALLER), code, true);
		builder.setBytes(String.format("0x%x", TABLE), loHex, false);
		builder.setBytes(String.format("0x%x", TABLE + distance), hiHex, false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		return builder.getProgram();
	}

	private long jmpOf(boolean guard) {
		return CALLER + (guard ? 4 : 0) + 12;
	}

	/** Lo and hi tables 4 apart: the base distance is the count, all four handlers are followed. */
	@Test
	public void planarTableCountComesFromTheBaseDistance() throws Exception {
		ProgramDB program = buildPlanar("00 10 20 30", "92 92 92 92", 4, false);
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2], HANDLERS[3]),
			computedTargets(program, jmpOf(false)));
		String eol = program.getListing().getComment(CommentType.EOL, addr(jmpOf(false)));
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith("split dispatch: 4-entry table at 9100 (high bytes at 9104)"));
	}

	/** The mirror order, high bytes first: the distance still bounds the low table. */
	@Test
	public void planarTableWithTheHighBytesFirst() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		builder.setBytes(String.format("0x%x", CALLER), "a4 a9 b9 " + word(TABLE + 3) +
			" 85 08 b9 " + word(TABLE) + " 85 09 6c 08 00 60", true);
		builder.setBytes(String.format("0x%x", TABLE), "92 92 92", false);
		builder.setBytes(String.format("0x%x", TABLE + 3), "00 10 20", false);
		for (long h : HANDLERS) {
			builder.setBytes(String.format("0x%x", h), "60", false);
		}
		ProgramDB program = builder.getProgram();
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2]),
			computedTargets(program, jmpOf(false)));
	}

	/** Trimmed at both ends: a leading entry that is RAM, and a trailing one that is RAM, are
	 *  not targets; the valid middle is. */
	@Test
	public void planarTableIsTrimmedAtBothEnds() throws Exception {
		ProgramDB program = buildPlanar("00 00 10 20 00", "03 92 92 92 03", 5, false);
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1], HANDLERS[2]),
			computedTargets(program, jmpOf(false)));
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[3])));
	}

	/** A recovered index guard ({@code CPY #2 / BCS}) beats the base distance: only 2 of the 4
	 *  slots are reached, and the other two handlers are not followed. */
	@Test
	public void planarIndexGuardBeatsTheBaseDistance() throws Exception {
		ProgramDB program = buildPlanar("00 10 20 30", "92 92 92 92", 4, true);
		run(program);
		assertEquals(List.of(HANDLERS[0], HANDLERS[1]), computedTargets(program, jmpOf(true)));
		assertNull(program.getListing().getInstructionAt(addr(HANDLERS[2])));
	}

	/** Bases further apart than a byte index can span are not one table: decline. */
	@Test
	public void planarBasesTooFarApartAreDeclined() throws Exception {
		ProgramDB program = buildPlanar("00 10 20 30", "92 92 92 92", 0x200, false);
		run(program);
		assertEquals(List.of(), computedTargets(program, jmpOf(false)));
	}
}
