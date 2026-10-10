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
		builder = new ProgramBuilder("Test", LANG);
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
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(addr(0x8000), addr(0xffff)), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
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
		int tx = program.startTransaction("code");
		try {
			new ghidra.app.cmd.disassemble.DisassembleCommand(addr(TABLE + 6), null, true)
					.applyTo(program);
		}
		finally {
			program.endTransaction(tx, true);
		}
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
		int tx = program.startTransaction("caller2");
		try {
			builder.setBytes(String.format("0x%x", CALLER2), caller(TABLE + 4, false), true);
		}
		finally {
			program.endTransaction(tx, true);
		}
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
		builder = new ProgramBuilder("Test", LANG);
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
			int tx = program.startTransaction("ref");
			try {
				program.getListing().getInstructionAt(addr(CALLER + 12)).addMnemonicReference(
					addr(Long.parseLong(computedRefTo, 16)), RefType.COMPUTED_JUMP,
					ghidra.program.model.symbol.SourceType.ANALYSIS);
			}
			finally {
				program.endTransaction(tx, true);
			}
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

	/** Switch analysis already resolved the inline jump: leave it alone. */
	@Test
	public void leavesAnAlreadyResolvedInlineJumpAlone() throws Exception {
		ProgramDB program = buildInline("9200");
		run(program);
		assertEquals(List.of(HANDLERS[0]), computedTargets(program, CALLER + 12));
		assertNull(program.getListing().getComment(CommentType.EOL, addr(CALLER + 12)));
	}

	/** A jump-table override (its {@code switch} label) already owns the inline jump, though stock
	 *  switch analysis has not laid its references down yet: leave it alone. */
	@Test
	public void leavesAnOverriddenInlineJumpAlone() throws Exception {
		ProgramDB program = buildInline(null);
		int tx = program.startTransaction("label");
		try {
			program.getSymbolTable().createLabel(addr(CALLER + 12), "switch",
				ghidra.program.model.symbol.SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}
		run(program);
		assertEquals(List.of(), computedTargets(program, CALLER + 12));
	}

	/** The caller runs from one block and the table sits in another (a banked window): the bytes
	 *  there are whichever bank is mapped, so the table is not established -- decline. */
	@Test
	public void declinesTableOutsideTheCallersBlock() throws Exception {
		builder = new ProgramBuilder("Test", LANG);
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
}
