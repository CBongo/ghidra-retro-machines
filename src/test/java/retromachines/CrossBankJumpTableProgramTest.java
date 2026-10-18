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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * A BNROM-shaped bus-conflict trampoline (Deadly Towers, grm-pwuh): the dispatch switches to
 * bank 2 with {@code LDX $8100 / STX $8100} and ONLY THEN reads its jump table, so the table
 * the CPU reads is bank 2's while the decompiler reads the executing bank's. Pins
 * {@link BankContext} (what the switched-in state is, and where an address then lands) and the
 * {@link JumpTableBoundAnalyzer} cross-bank branch that re-reads the table from that bank and
 * pins references into its space.
 */
public class CrossBankJumpTableProgramTest extends AbstractBundledLanguageTest {

	private static final long TABLE = 0x9000;

	private ProgramBuilder builder;
	private ProgramDB program;

	/** Seeds JUST the {@code BankSwitchStrategy} bucket; see BoardBankAnalyzerCacheProgramTest. */
	@SuppressWarnings("unchecked")
	private static void injectMemoryLatchStrategy() throws Exception {
		Field hasSearchedField = ClassSearcher.class.getDeclaredField("hasSearched");
		hasSearchedField.setAccessible(true);
		Field mapField = ClassSearcher.class.getDeclaredField("extensionPointSuffixToInfoMap");
		mapField.setAccessible(true);
		// Another test may already have seeded the bucket (with register-write only), so ADD to
		// whatever is there rather than returning early; a bucket from a real search already has it.
		Map<String, Set<ClassFileInfo>> old =
			(Map<String, Set<ClassFileInfo>>) mapField.get(null);
		Set<ClassFileInfo> bucket = new HashSet<>();
		if (old != null && old.get("BankSwitchStrategy") != null) {
			bucket.addAll(old.get("BankSwitchStrategy"));
		}
		// Seed register-write too: BoardBankAnalyzerCacheProgramTest returns early once the
		// searched latch is set and relies on it being discoverable.
		for (Class<?> strategy : new Class<?>[] { MemoryLatchBankSwitchStrategy.class,
			RegisterWriteBankSwitchStrategy.class }) {
			String name = strategy.getName();
			if (bucket.stream().noneMatch(c -> c.name().equals(name))) {
				bucket.add(new ClassFileInfo("grm-pwuh-test-injected", name, "BankSwitchStrategy"));
			}
		}
		Map<String, Set<ClassFileInfo>> map = new HashMap<>();
		if (old != null) {
			map.putAll(old);
		}
		map.put("BankSwitchStrategy", bucket);
		mapField.set(null, map);
		hasSearchedField.set(null, true);
	}

	private static String le16(long v) {
		return String.format("%02x %02x ", v & 0xff, (v >> 8) & 0xff);
	}

	@Before
	public void setUp() throws Exception {
		injectMemoryLatchStrategy();
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory("PRG_ALL", "0x8000", 0x8000); // home bank 0, in base space
		for (int b = 1; b <= 3; b++) {
			builder.createOverlayMemory("PRG_ALL_B" + b, "0x8000", 0x8000);
		}
		program = builder.getProgram();

		// Same trampoline in every bank, as Deadly Towers replicates it. Byte 02 at $8100.
		String code = "ae 00 81 " + "8e 00 81 " // LDX $8100 ; STX $8100  (bank 2)
			+ "0a aa " // ASL A ; TAX
			+ "bd 00 90 85 00 " // LDA $9000,X ; STA $00
			+ "bd 01 90 85 01 " // LDA $9001,X ; STA $01
			+ "6c 00 00"; // JMP ($0000)  -- at $8011
		StringBuilder wrongBank = new StringBuilder(); // bank 0's table: 128 plausible targets
		StringBuilder bank2 = new StringBuilder(); // bank 2's table: 8 real, then junk = table
		for (int i = 0; i < 128; i++) {
			wrongBank.append(le16(0x8200 + 0x10 * i));
			bank2.append(le16(i < 8 ? 0x9010 + 0x20 * i : TABLE));
		}
		for (int b = 0; b <= 3; b++) {
			Address base = bankAddr(b, 0x8000);
			builder.setBytes(base.toString(), code, b == 0);
			builder.setBytes(bankAddr(b, 0x8100).toString(), "02", false);
			builder.setBytes(bankAddr(b, TABLE).toString(),
				(b == 2 ? bank2 : wrongBank).toString().trim(), false);
		}
		inTx(program, "describe import", () -> {
			program.setExecutableFormat(NesRomLoader.NAME);
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorSupport.MAP_PATH_PROPERTY, "machines/nes-bnrom.map");
		});
	}

	private Address bankAddr(int bank, long offset) {
		return bank == 0 ? builder.addr(hex(offset))
				: program.getAddressFactory().getAddressSpace("PRG_ALL_B" + bank)
						.getAddress(offset);
	}

	@Test
	public void bankContextKnowsTheSwitchedInBankAndResolvesTheTable() throws Exception {
		Address jmp = bankAddr(0, 0x8012);
		Instruction jmpInstr = program.getListing().getInstructionAt(jmp);
		assertNotNull("JMP not disassembled", jmpInstr);

		BankContext ctx = BankContext.forProgram(program);
		assertNotNull("not recognised as a banked-board import", ctx);

		BankState state = ctx.stateBefore(jmpInstr);
		assertEquals("bank bits must be fully known after the STX", 3, state.knownMask() & 3);
		assertEquals(2, state.bits() & 3);

		Address resolved = ctx.resolve(jmpInstr, builder.addr(hex(TABLE)));
		assertEquals(bankAddr(2, TABLE), resolved);
	}

	@Test
	public void noStateIsInventedAcrossAJoin() throws Exception {
		// The LDA $9000,X is not preceded by the STX within the walk once a join is introduced:
		// a branch into the ASL makes it a join, so nothing before it may be assumed.
		Address asl = bankAddr(0, 0x8006);
		inTx(program, "add incoming branch", () -> {
			program.getReferenceManager().addMemoryReference(bankAddr(0, 0x8000), asl,
				ghidra.program.model.symbol.RefType.UNCONDITIONAL_JUMP,
				ghidra.program.model.symbol.SourceType.ANALYSIS, -1);
		});
		Instruction jmpInstr = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		assertNotNull(ctx);
		assertEquals(0, ctx.stateBefore(jmpInstr).knownMask() & 3);
		assertNull(ctx.resolve(jmpInstr, builder.addr(hex(TABLE))));
	}

	@Test
	public void analyzerRereadsTheTableFromTheSwitchedInBankAndPinsItsSpace() throws Exception {
		Address jmp = bankAddr(0, 0x8012);
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(bankAddr(0, 0x8000), jmp),
				TaskMonitor.DUMMY, new MessageLog());
		});

		Set<Address> targets = new HashSet<>();
		for (Reference ref : program.getListing().getInstructionAt(jmp).getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				targets.add(ref.getToAddress());
			}
		}
		Set<Address> expected = new HashSet<>();
		for (int i = 0; i < 8; i++) {
			expected.add(bankAddr(2, 0x9010 + 0x20 * i));
		}
		assertEquals("references must be the bank-2 table's real targets, in bank 2's space",
			expected, targets);

		String comment = program.getListing().getComment(CommentType.EOL, jmp);
		assertNotNull(comment);
		assertTrue(comment, comment.contains("[JumpTableBound]"));
		assertTrue(comment, comment.contains("switched-in bank PRG_ALL_B2"));
	}

	/** The switched-in bank's own copy reads an overlapping table: corroborated. */
	@Test
	public void switchedInCopyReadingAnOverlappingTableCorroborates() throws Exception {
		Instruction jmp = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		assertNotNull(ctx);
		var b2 = program.getAddressFactory().getAddressSpace("PRG_ALL_B2");
		// B2's copy reads $9000; the range [$8ff0, $9010) overlaps it.
		assertTrue(ctx.switchedInCopyReadsTableIn(jmp, b2, 0x8ff0, 0x9010));
		// A range wholly elsewhere does not.
		assertTrue(!ctx.switchedInCopyReadsTableIn(jmp, b2, 0x8000, 0x9000));
	}

	/**
	 * Bank 2's copy reads a different table: not corroborated as overlapping. Since grm-q4ga the
	 * analyzer reads the table where the copy points ($a000), and declines here only because bank 2
	 * holds no valid entries there.
	 */
	@Test
	public void switchedInCopyReadingElsewhereDoesNotCorroborateAndAnalyzerDeclines()
			throws Exception {
		inTx(program, "retarget bank 2's table load", () -> {
			// LDA $9000,X at offset 8 -> LDA $a000,X (operand high byte at 0x800a)
			program.getMemory().setByte(bankAddr(2, 0x800a), (byte) 0xa0);
			program.getMemory().setByte(bankAddr(2, 0x800f), (byte) 0xa0);
		});
		Instruction jmp = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		var b2 = program.getAddressFactory().getAddressSpace("PRG_ALL_B2");
		assertTrue(!ctx.switchedInCopyReadsTableIn(jmp, b2, 0x9000, 0x9100));

		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(bankAddr(0, 0x8000), bankAddr(0, 0x8012)),
				TaskMonitor.DUMMY, new MessageLog());
		});
		String comment = program.getListing().getComment(CommentType.EOL, bankAddr(0, 0x8012));
		assertTrue("declined: no cross-bank comment, got " + comment,
			comment == null || !comment.contains("switched-in bank"));
	}

	/** Moves bank 2's copy's two table loads to read {@code $a000/$a001}, and gives bank 2 a table
	 *  there: 8 real targets, then entries pointing at the table itself. */
	private void moveBank2TableTo0xa000() throws Exception {
		StringBuilder table = new StringBuilder();
		for (int i = 0; i < 128; i++) {
			table.append(le16(i < 8 ? 0xa010 + 0x20 * i : 0xa000));
		}
		inTx(program, "move bank 2's table", () -> {
			program.getMemory().setByte(bankAddr(2, 0x800a), (byte) 0xa0);
			program.getMemory().setByte(bankAddr(2, 0x800f), (byte) 0xa0);
		});
		builder.setBytes(bankAddr(2, 0xa000).toString(), table.toString().trim(), false);
	}

	/** grm-q4ga: the copy's table operand moved by a constant, so the shift is that constant. */
	@Test
	public void switchedInCopyTableShiftIsTheCopysOperandDelta() throws Exception {
		Instruction jmp = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		var b2 = program.getAddressFactory().getAddressSpace("PRG_ALL_B2");
		assertEquals(Long.valueOf(0), ctx.switchedInCopyTableShift(jmp, b2, TABLE, TABLE + 0x100));
		moveBank2TableTo0xa000();
		assertEquals(Long.valueOf(0x1000),
			ctx.switchedInCopyTableShift(jmp, b2, TABLE, TABLE + 0x100));
	}

	/** Two loads moved by different amounts are no single table: no shift. */
	@Test
	public void switchedInCopyTableShiftNeedsEveryLoadToAgree() throws Exception {
		inTx(program, "move only the low-byte load", () -> {
			program.getMemory().setByte(bankAddr(2, 0x800a), (byte) 0xa0);
		});
		Instruction jmp = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		var b2 = program.getAddressFactory().getAddressSpace("PRG_ALL_B2");
		assertNull(ctx.switchedInCopyTableShift(jmp, b2, TABLE, TABLE + 0x100));
	}

	/** grm-q4ga: the analyzer reads the table the switched-in copy reads (deadly_towers' banks). */
	@Test
	public void analyzerReadsTheTableTheSwitchedInCopyReads() throws Exception {
		moveBank2TableTo0xa000();
		Address jmp = bankAddr(0, 0x8012);
		JumpTableBoundAnalyzer analyzer = new JumpTableBoundAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(bankAddr(0, 0x8000), jmp),
				TaskMonitor.DUMMY, new MessageLog());
		});
		Set<Address> targets = new HashSet<>();
		for (Reference ref : program.getListing().getInstructionAt(jmp).getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				targets.add(ref.getToAddress());
			}
		}
		Set<Address> expected = new HashSet<>();
		for (int i = 0; i < 8; i++) {
			expected.add(bankAddr(2, 0xa010 + 0x20 * i));
		}
		assertEquals(expected, targets);
	}

	/**
	 * grm-q4ga: a call's return into base code that the state's bank holds different bytes for
	 * cannot happen under that state; byte-identical copies (the trampoline) still can.
	 */
	@Test
	public void callReturnIntoDifferentBytesReturnsElsewhere() throws Exception {
		BankContext ctx = BankContext.forProgram(program);
		BankState bank2 = BankState.fullyKnown(3, 2);
		// $8006 (ASL / TAX) is byte-identical in every bank: the return lands on these bytes.
		assertTrue(!BankDataflowEngine.returnsElsewhere(program, program.getListing(),
			bankAddr(0, 0x8006), bank2, ctx.resolution()));
		inTx(program, "change bank 2's byte at $8006", () -> {
			program.getMemory().setByte(bankAddr(2, 0x8006), (byte) 0xea); // NOP
		});
		assertTrue(BankDataflowEngine.returnsElsewhere(program, program.getListing(),
			bankAddr(0, 0x8006), bank2, ctx.resolution()));
		// Under the home bank, or an unknown state, the base bytes are what runs.
		assertTrue(!BankDataflowEngine.returnsElsewhere(program, program.getListing(),
			bankAddr(0, 0x8006), BankState.fullyKnown(3, 0), ctx.resolution()));
		assertTrue(!BankDataflowEngine.returnsElsewhere(program, program.getListing(),
			bankAddr(0, 0x8006), BankState.unknown(), ctx.resolution()));
	}

	/** Window arithmetic the analyzer uses: a copy reading one stride below our base (lo - 2)
	 *  corroborates; two strides below (lo - 4) does not. Bank 2's copy reads $9000/$9001. */
	@Test
	public void oneStrideBelowCorroboratesTwoStridesBelowDoesNot() throws Exception {
		Instruction jmp = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		var b2 = program.getAddressFactory().getAddressSpace("PRG_ALL_B2");
		long stride = 2;
		long ourBase = 0x9002; // B2 reads 9000, one stride below
		assertTrue(ctx.switchedInCopyReadsTableIn(jmp, b2, ourBase - stride, ourBase + 0x10));
		ourBase = 0x9004; // two strides below
		assertTrue(!ctx.switchedInCopyReadsTableIn(jmp, b2, ourBase - stride, ourBase + 0x10));
	}

	/** An indexed STORE to the table range is not a table read. */
	@Test
	public void indexedStoresDoNotCorroborate() throws Exception {
		inTx(program, "turn bank 2's table loads into stores", () -> {
			program.getMemory().setByte(bankAddr(2, 0x8008), (byte) 0x9d); // STA $9000,X
			program.getMemory().setByte(bankAddr(2, 0x800d), (byte) 0x9d); // STA $9001,X
		});
		Instruction jmp = program.getListing().getInstructionAt(bankAddr(0, 0x8012));
		BankContext ctx = BankContext.forProgram(program);
		var b2 = program.getAddressFactory().getAddressSpace("PRG_ALL_B2");
		assertTrue(!ctx.switchedInCopyReadsTableIn(jmp, b2, 0x9000, 0x9100));
	}
}
