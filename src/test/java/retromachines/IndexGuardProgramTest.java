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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * grm-c9d.8.2: the index-guard table on a synthetic SPC700 dispatch in the shape of Super Mario
 * World's 0d44, with no ROM bytes. The only caller guards the routine with {@code CMP A,#$DA /
 * BCC}, so A is {@code $DA..$FF}, X = 2A mod 256 = {@code $B4..$FE}, and the table is slots
 * 90..127 of the one at {@code $0EDC} (so {@code $0F90..$0FDA}), two of them {@code $0000}
 * placeholders. The slots before it hold decoy pointers a decompiler with no bound reads as
 * entries.
 * <pre>
 *   0c9b CALL $125E / CMP A,#$DA / BCC $0CA5 / CALL $0D40 / 0ca5 RET
 *   0d40 ASL A / MOV X,A / MOV A,#0 / 0d44 JMP [!$0EDC+X]
 * </pre>
 */
public class IndexGuardProgramTest extends AbstractProgramTest {

	private static final long BASE = 0x0edc;
	private static final long SWITCH = 0x0d44;
	private static final int FIRST_SLOT = 90;
	private static final int SLOTS = 38;
	/** Slots (relative to the guarded span) holding a $0000 placeholder, as at SMW's 0f96/0fb6. */
	private static final Set<Integer> UNUSED = Set.of(3, 21);
	private static final String GUARDED = "3f 5e 12 68 da 90 03 3f 40 0d 6f";
	private static final String UNGUARDED = "3f 5e 12 3f 40 0d 6f";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", SpcProgramMaterializer.LANGUAGE_ID);
		builder.createMemory(".ram", "0x0", 0x10000);
		program = builder.getProgram();
	}

	private static String word(long w) {
		return String.format("%02x %02x ", w & 0xff, (w >> 8) & 0xff);
	}

	private static long realTarget(int i) {
		return 0x2000 + 0x10L * i;
	}

	/** The routine, its caller, the table and the handlers. {@code guard} false drops CMP/BCC. */
	private void build(String caller) throws Exception {
		builder.setBytes("0xd40", "1c 5d e8 00 1f dc 0e", true);
		builder.setBytes("0x125e", "6f", false);
		builder.setBytes("0xc9b", caller, true);
		// decoy slots 0..89: each points at its own NOP/RET handler well above the table
		StringBuilder decoys = new StringBuilder();
		for (int s = 0; s < FIRST_SLOT; s++) {
			long t = 0x3000 + 0x10L * s;
			builder.setBytes(hex(t), "00 6f", false);
			decoys.append(word(t));
		}
		builder.setBytes(hex(BASE), decoys.toString(), false);
		StringBuilder real = new StringBuilder();
		for (int i = 0; i < SLOTS; i++) {
			if (UNUSED.contains(i)) {
				real.append(word(0));
				continue;
			}
			builder.setBytes(hex(realTarget(i)), "00 6f", false);
			real.append(word(realTarget(i)));
		}
		builder.setBytes(hex(BASE + 2L * FIRST_SLOT), real.toString(), false);
	}

	private Set<Address> expectedTargets() {
		Set<Address> out = new HashSet<>();
		for (int i = 0; i < SLOTS; i++) {
			if (!UNUSED.contains(i)) {
				out.add(addr(realTarget(i)));
			}
		}
		return out;
	}

	private Set<Address> computedTargets() {
		Set<Address> out = new HashSet<>();
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(SWITCH))) {
			if (RefType.COMPUTED_JUMP.equals(r.getReferenceType())) {
				out.add(r.getToAddress());
			}
		}
		return out;
	}

	private IndexGuardRecovery.Span recover() {
		return IndexGuardRecovery.recover(program,
			program.getListing().getInstructionAt(addr(SWITCH)), addr(BASE), 2);
	}

	// ---- the recovery alone --------------------------------------------------------------

	@Test
	public void callerSideGuardGivesTheSmwSlots() throws Exception {
		build(GUARDED);
		IndexGuardRecovery.Span span = recover();
		assertNotNull(span);
		assertEquals(90, span.first());
		assertEquals(127, span.last());
		assertTrue(span.evidence(), span.evidence().contains("caller 0ca2"));
		assertTrue(span.evidence(), span.evidence().contains("BCC not taken"));
	}

	@Test
	public void unguardedCallerDeclines() throws Exception {
		build(UNGUARDED);
		assertNull(recover());
	}

	@Test
	public void oneUnguardedCallerAmongGuardedOnesDeclines() throws Exception {
		build(GUARDED);
		builder.setBytes("0x1300", "3f 40 0d 6f", true); // a second caller, no CMP in front
		assertNull(recover());
	}

	@Test
	public void twoGuardedCallersJoinTheirRanges() throws Exception {
		build(GUARDED);
		// a second caller passing A in $e0..$ff only: the hull is still $da..$ff
		builder.setBytes("0x1300", "68 e0 90 03 3f 40 0d 6f", true);
		IndexGuardRecovery.Span span = recover();
		assertNotNull(span);
		assertEquals(90, span.first());
		assertEquals(127, span.last());
	}

	@Test
	public void aWriteToTheComparedRegisterBetweenGuardAndCallDeclines() throws Exception {
		// CMP A,#$da / BCC / MOV A,#5 / CALL: A is no longer what was compared
		build("3f 5e 12 68 da 90 05 e8 05 3f 40 0d 6f");
		assertNull(recover());
	}

	@Test
	public void aWriteToAnotherRegisterBetweenGuardAndCallStillGuards() throws Exception {
		build("3f 5e 12 68 da 90 05 8d 00 3f 40 0d 6f"); // MOV Y,#0
		IndexGuardRecovery.Span span = recover();
		assertNotNull(span);
		assertEquals(90, span.first());
	}

	@Test
	public void guardMustBeTheBranchNotTakenPath() throws Exception {
		// BCS in place of BCC: not taken means A < $da, a different range (0..$d9 doubled wraps)
		build("3f 5e 12 68 da b0 03 3f 40 0d 6f");
		assertNull(recover());
	}

	/** In-function form: the guard is just before the switch, BCS this time: A &lt; $10. */
	@Test
	public void inFunctionBcsGuard() throws Exception {
		builder.setBytes("0xd00", "68 10 b0 05 1c 5d 1f 00 08 6f", true);
		builder.disassemble("0xd00", 10, true);
		var sw = program.getListing().getInstructionAt(addr(0xd06));
		assertNotNull(sw);
		IndexGuardRecovery.Span span = IndexGuardRecovery.recover(program, sw, addr(0x800), 2);
		assertNotNull(span);
		assertEquals(0, span.first());
		assertEquals(15, span.last());
		assertTrue(span.evidence(), span.evidence().contains("BCS not taken"));
	}

	// ---- through the analyzer ------------------------------------------------------------

	/** The first pass: no function owns the switch yet, so the table is pinned by references. */
	@Test
	public void pinPathReachesExactlyTheGuardedTargets() throws Exception {
		build(GUARDED);
		builder.disassemble("0xd40", 7, true);
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(addr(0xd40), addr(0xd46)),
				TaskMonitor.DUMMY, new MessageLog());
		});
		assertEquals(expectedTargets(), computedTargets());
		assertFalse("a $0000 slot is never a case target",
			computedTargets().contains(addr(0)));
		String comment = program.getListing().getComment(CommentType.EOL, addr(SWITCH));
		assertNotNull(comment);
		assertTrue(comment, comment.contains("after INDEX_GUARD leading trim) -> 38 entries"));
		assertTrue(comment, comment.contains("slots 90..127"));
		assertTrue(comment, comment.contains("2 unused ($0000) slot(s) not case targets"));
	}

	/** The later pass: FUN_0d40 exists, stock already over-read the switch, an override lands. */
	@Test
	public void overridePathReplacesTheOverRead() throws Exception {
		build(GUARDED);
		builder.disassemble("0xd40", 7, true);
		Function function = inTxGet(program, "fn", () -> {
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr(0xd40));
			cmd.applyTo(program, TaskMonitor.DUMMY);
			return cmd.getFunction();
		});
		DecompileResults stock = decompile(function);
		assertTrue(stock.getErrorMessage(), stock.decompileCompleted());
		inTx(program, "stock", () -> {
			new DecompilerSwitchAnalysisCmd(stock).applyTo(program, TaskMonitor.DUMMY);
			CreateFunctionCmd.fixupFunctionBody(program, function, TaskMonitor.DUMMY);
		});
		assertTrue("control: stock reads decoy slots too", computedTargets().size() > SLOTS);
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().boundFunctions(program, Set.of(function), TaskMonitor.DUMMY,
				new MessageLog());
		});
		assertEquals(expectedTargets(), computedTargets());
		String comment = program.getListing().getComment(CommentType.EOL, addr(SWITCH));
		assertNotNull(comment);
		assertTrue(comment, comment.contains("INDEX_GUARD"));
		// The decompiler lists each target once (the aliases of the two placeholders merge into their
		// neighbours), and nothing is ever a case at $0000.
		DecompileResults after = decompile(function);
		assertTrue(after.getErrorMessage(), after.decompileCompleted());
		var tables = after.getHighFunction().getJumpTables();
		assertEquals(1, tables.length);
		assertEquals(expectedTargets(), new HashSet<>(Arrays.asList(tables[0].getCases())));
		for (Address c : tables[0].getCases()) {
			assertFalse(c.getOffset() == 0);
		}
	}

	@Test
	public void unguardedCallerLeavesTheTableAlone() throws Exception {
		build(UNGUARDED);
		builder.disassemble("0xd40", 7, true);
		inTx(program, "analyze", () -> {
			new JumpTableBoundAnalyzer().added(program, new AddressSet(addr(0xd40), addr(0xd46)),
				TaskMonitor.DUMMY, new MessageLog());
		});
		String comment = program.getListing().getComment(CommentType.EOL, addr(SWITCH));
		assertTrue(String.valueOf(comment), comment == null || !comment.contains("INDEX_GUARD"));
	}

	private DecompileResults decompile(Function function) {
		DecompInterface ifc = new DecompInterface();
		try {
			JumpTableBoundAnalyzer.configureDecompiler(program, ifc);
			assertTrue(ifc.getLastMessage(), ifc.openProgram(program));
			return ifc.decompileFunction(function, 30, TaskMonitor.DUMMY);
		}
		finally {
			ifc.dispose();
		}
	}
}
