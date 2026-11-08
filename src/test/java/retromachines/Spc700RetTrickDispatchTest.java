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

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * grm-gipk.8: the SPC700 form of the RTS trick. A minimal reproduction of the AKAO command dispatch
 * at Chrono Trigger 0e10 (same shape at FF3 0a12/0c69, Lemmings 1175, Secret of Mana 100e):
 * <pre>
 *   MOV A,X / AND A,#$1f / ASL A / MOV Y,A /
 *   MOV A,!$16c1+Y / PUSH A / MOV A,!$16c0+Y / PUSH A / RET
 * </pre>
 * {@code RET} pops the target itself, so the table holds exact addresses (bias 0).
 */
public class Spc700RetTrickDispatchTest extends AbstractProgramTest {

	private static final long DISPATCH = 0x0e00;
	private static final long RET = 0x0e10;
	/** The CT dispatcher, verbatim from the recovered driver. */
	private static final String CT_DISPATCH = "7d 28 1f 1c fd f6 c1 16 2d f6 c0 16 2d 6f";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", SpcProgramMaterializer.LANGUAGE_ID);
		builder.createMemory(".ram", "0x0", 0x10000);
		program = builder.getProgram();
	}

	private static String word(long w) {
		return String.format("%02x %02x", w & 0xff, (w >> 8) & 0xff);
	}

	/** Lays the dispatcher bytes at {@code DISPATCH + 2}, decodes them, runs the analyzer. */
	private void run(String dispatcherBytes) throws Exception {
		lay(dispatcherBytes);
		analyze();
	}

	private void lay(String dispatcherBytes) throws Exception {
		long start = RET - dispatcherBytes.split(" ").length + 1;
		builder.setBytes(hex(start), dispatcherBytes, false);
		int len = dispatcherBytes.split(" ").length;
		builder.disassemble(hex(start), len, true);
	}

	private void analyze() throws Exception {
		RtsTrickDispatchAnalyzer analyzer = new RtsTrickDispatchAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(addr(DISPATCH), addr(RET)), TaskMonitor.DUMMY,
				new MessageLog());
		});
	}

	/** Exact-address table at $16c0, ended by an entry that points into the table itself. */
	private void table(long... targets) throws Exception {
		StringBuilder t = new StringBuilder();
		for (long x : targets) {
			builder.setBytes(hex(x), "00 6f", false); // NOP; RET
			t.append(word(x)).append(' ');
		}
		t.append(word(0x16c0));
		builder.setBytes("0x16c0", t.toString(), false);
	}

	/** {@code BRA target} at $0df0, just below the dispatcher, so it is a join into the window. */
	private void branchTo(long target) throws Exception {
		long rel = target - (0x0df0 + 2);
		builder.setBytes("0x0df0", String.format("2f %02x", rel & 0xff), false);
		builder.disassemble("0x0df0", 2, true);
	}

	private List<Address> computedJumpTargets() {
		List<Address> out = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(RET))) {
			if (r.getReferenceType().equals(RefType.COMPUTED_JUMP)) {
				out.add(r.getToAddress());
			}
		}
		return out;
	}

	@Test
	public void akaoDispatchResolvesExactTargets() throws Exception {
		long[] t = { 0x2000, 0x2010, 0x2020 };
		table(t);
		run(CT_DISPATCH);

		RtsTrickDispatch.Shape shape = RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(RET)));
		assertNotNull(shape);
		assertEquals(0, shape.bias());
		assertTrue(shape.interleaved());

		Data d = program.getListing().getDefinedDataAt(addr(0x16c0));
		assertNotNull(d);
		Array a = (Array) d.getDataType();
		assertTrue(a.getDataType() instanceof WordDataType);
		assertEquals(3, a.getNumElements());
		assertEquals("targets are the words themselves, not word + 1",
			List.of(addr(t[0]), addr(t[1]), addr(t[2])), computedJumpTargets());
		for (long x : t) {
			assertNotNull("target " + hex(x) + " disassembled",
				program.getListing().getInstructionAt(addr(x)));
			assertNull("no function at " + hex(x),
				program.getFunctionManager().getFunctionAt(addr(x)));
		}
	}

	/** Al Unser 043e, Speed Racer 0839, Pugsley 053c: command numbers start at 1, slot 0 is junk. */
	@Test
	public void oneBasedTableSkipsUnusableEntryZero() throws Exception {
		long[] t = { 0x2000, 0x2010, 0x2020, 0x2030, 0x2040 };
		StringBuilder words = new StringBuilder(word(0x16c0)).append(' '); // slot 0: into the table
		for (long x : t) {
			builder.setBytes(hex(x), "00 6f", false);
			words.append(word(x)).append(' ');
		}
		words.append(word(0x16c4)); // into the table: ends it
		builder.setBytes("0x16c0", words.toString(), false);
		run(CT_DISPATCH);
		RtsTrickDispatch.Site site = RtsTrickDispatch.scan(program, RtsTrickDispatch.recognize(
			program, program.getListing().getInstructionAt(addr(RET))));
		assertNotNull(site);
		assertEquals(addr(0x16c2), site.loBase);
		assertEquals(RtsTrickDispatch.Cut.INVALID_TARGET, site.cut);
		assertEquals(List.of(addr(t[0]), addr(t[1]), addr(t[2]), addr(t[3]), addr(t[4])),
			computedJumpTargets());
	}

	/** Too short a run after an unusable entry 0 is still declined: no stop signal to trust. */
	@Test
	public void oneBasedTableNeedsAFewEntries() throws Exception {
		builder.setBytes(hex(0x2000), "00 6f", false);
		builder.setBytes("0x16c0", word(0x16c0) + " " + word(0x2000) + " " + word(0x16c4), false);
		run(CT_DISPATCH);
		assertTrue(computedJumpTargets().isEmpty());
	}

	/** Al Unser 043e: unused commands point at a stray BRK byte; the table runs on past them. */
	@Test
	public void brkPlaceholderEntriesDoNotEndTheTable() throws Exception {
		builder.setBytes(hex(0x2f00), "0f", false); // the placeholder BRK
		long[] real = { 0x2000, 0x2010, 0x2020, 0x2030 };
		for (long x : real) {
			builder.setBytes(hex(x), "00 6f", false);
		}
		long[] words = { 0x2f00, real[0], 0x2f00, real[1], real[2], real[3], 0x2f00, 0x16c4 };
		StringBuilder w = new StringBuilder();
		for (long x : words) {
			w.append(word(x)).append(' ');
		}
		builder.setBytes("0x16c0", w.toString().trim(), false);
		run(CT_DISPATCH);
		RtsTrickDispatch.Site site = RtsTrickDispatch.scan(program, RtsTrickDispatch.recognize(
			program, program.getListing().getInstructionAt(addr(RET))));
		assertNotNull(site);
		assertEquals("the trailing placeholder is not part of the table", 6, site.targets.size());
		assertEquals(addr(0x2f00), site.targets.get(0));
		assertEquals(addr(real[3]), site.targets.get(5));
	}

	@Test
	public void andMaskCapsTheTable() throws Exception {
		// FF3 0a12: AND A,#$0f / ASL A / MOV Y,A allows 16 entries, and the words after them are
		// still plausible code addresses that no other rule would end on.
		long[] t = new long[20];
		StringBuilder words = new StringBuilder();
		for (int i = 0; i < t.length; i++) {
			t[i] = 0x2000 + 0x10L * i;
			builder.setBytes(hex(t[i]), "00 6f", false);
			words.append(word(t[i])).append(' ');
		}
		builder.setBytes("0x16c0", words.toString().trim(), false);
		run("7d 28 0f 1c fd f6 c1 16 2d f6 c0 16 2d 6f");

		RtsTrickDispatch.Shape shape = RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(RET)));
		assertEquals(16, shape.maskCap());
		RtsTrickDispatch.Site site = RtsTrickDispatch.scan(program, shape);
		assertEquals(RtsTrickDispatch.Cut.MASK, site.cut);
		assertEquals(16, site.targets.size());
		assertEquals(16, computedJumpTargets().size());
	}

	@Test
	public void flowIntoTheSharedRetStillResolves() throws Exception {
		// CT 0e10 / FF3 0c69 / SoM 100e: another path branches straight to the RET.
		table(0x2000, 0x2010);
		branchTo(RET);
		run(CT_DISPATCH);
		assertEquals(List.of(addr(0x2000), addr(0x2010)), computedJumpTargets());
	}

	@Test
	public void flowBetweenThePushesDeclines() throws Exception {
		table(0x2000, 0x2010);
		branchTo(RET - 4); // the second MOV A,!$16c0+Y
		run(CT_DISPATCH);
		assertTrue(computedJumpTargets().isEmpty());
	}

	@Test
	public void flowIntoTheLastPushDeclines() throws Exception {
		table(0x2000, 0x2010);
		branchTo(RET - 1); // the second PUSH A: another path could push its own low byte
		run(CT_DISPATCH);
		assertTrue(computedJumpTargets().isEmpty());
	}

	@Test
	public void flowAfterTheLastPushStillResolves() throws Exception {
		// radical 0c89 / Terranigma 0468 (grm-gipk.12): a path joins between the last push and the
		// RET. It brings its own stack, like a join at the RET itself.
		table(0x2000, 0x2010);
		branchTo(RET - 1); // the NOP between PUSH A and RET
		run(CT_DISPATCH.replace(" 2d 6f", " 2d 00 6f"));
		assertEquals(List.of(addr(0x2000), addr(0x2010)), computedJumpTargets());
	}

	@Test
	public void indexWrittenBetweenTheLoadsDeclines() throws Exception {
		table(0x2000, 0x2010);
		// MOV Y,#$00 between the two loads: the second load reads a different entry.
		run("f6 c1 16 2d 8d 00 f6 c0 16 2d 6f");
		assertNull(RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(RET))));
		assertTrue(computedJumpTargets().isEmpty());
	}

	@Test
	public void stackPointerWrittenBeforeRetDeclines() throws Exception {
		table(0x2000, 0x2010);
		// MOV SP,X between the last push and RET: the RET no longer pops the pushed pair.
		run("f6 c1 16 2d f6 c0 16 2d bd 6f");
		assertNull(RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(RET))));
	}

	@Test
	public void popInTheWindowDeclines() throws Exception {
		table(0x2000, 0x2010);
		// PUSH A / ... / POP X / RET: the bookkeeping shape the survey kept as a false positive.
		run("f6 c1 16 2d f6 c0 16 2d ce 6f");
		assertNull(RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(RET))));
	}

	// ---- grm-gipk.18: caller-side CMP guard (7th Saga 077f) --------------------------------

	/** The 7th Saga dispatcher: ASL A / MOV Y,A / table $16c0 (low) $16c1 (high) / RET at $0e10. */
	private static final String ASL_DISPATCH = "1c fd f6 c1 16 2d f6 c0 16 2d 6f";
	private static final long LOAD = 0x0e08; // MOV A,!$16c1+Y, the first table load

	/** The guarded range of Y at the first table load, or null. */
	private IndexGuard.Range guard() {
		IndexGuardRecovery.LoadGuard g = IndexGuardRecovery
				.guardedIndexedLoad(program, program.getListing().getInstructionAt(addr(LOAD)));
		return g == null ? null : g.range();
	}
	private static final long SHIFTED = 0x1780;

	/** {@code CMP A,#$df / BEQ end / BCC end / CALL !$0e06 / RET}: A in $e0..$ff, at {@code at}. */
	private void guardedCaller(long at) throws Exception {
		builder.setBytes(hex(at), "68 df f0 05 90 03 3f 06 0e 6f", false);
		builder.disassemble(hex(at), 10, true);
	}

	private void shiftedTable(int n) throws Exception {
		// the unshifted reading ($16c0..) is junk: words pointing into the table itself
		builder.setBytes("0x16c0", ("c0 16 ").repeat(0x60).trim(), false);
		StringBuilder t = new StringBuilder();
		for (int i = 0; i < n; i++) {
			long x = 0x2000 + 0x10L * i;
			builder.setBytes(hex(x), "00 6f", false);
			t.append(word(x)).append(' ');
		}
		t.append(word(SHIFTED));
		builder.setBytes(hex(SHIFTED), t.toString().trim(), false);
	}

	private void assertShifted(int n) {
		if (n == 0) { // the shifted table was NOT used
			RtsTrickDispatch.Site site = RtsTrickDispatch.scan(program, RtsTrickDispatch.recognize(
				program, program.getListing().getInstructionAt(addr(RET))));
			assertTrue(site == null || !addr(SHIFTED).equals(site.loBase));
			return;
		}
		List<Address> want = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			want.add(addr(0x2000 + 0x10L * i));
		}
		assertEquals(want, computedJumpTargets());
	}

	@Test
	public void callerGuardShiftsTheTable() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		guardedCaller(0x0d00);
		analyze();
		assertEquals(new IndexGuard.Range(0xc0, 0xfe, 2), guard());
		assertShifted(6);
	}

	@Test
	public void guardCapsTheCount() throws Exception {
		// CMP A,#3 / BCS end: A in 0..2, so 3 entries although the words run on.
		for (int i = 0; i < 8; i++) {
			builder.setBytes(hex(0x2000 + 0x10L * i), "00 6f", false);
		}
		StringBuilder t = new StringBuilder();
		for (int i = 0; i < 8; i++) {
			t.append(word(0x2000 + 0x10L * i)).append(' ');
		}
		builder.setBytes("0x16c0", t.toString().trim(), false);
		lay(ASL_DISPATCH);
		builder.setBytes("0x0d00", "68 03 b0 03 3f 06 0e 6f", false);
		builder.disassemble("0x0d00", 8, true);
		analyze();
		assertEquals(new IndexGuard.Range(0, 4, 2), guard());
		assertShifted(3);
	}

	@Test
	public void guardInsideTheDispatcherCounts() throws Exception {
		shiftedTable(6);
		// CMP A,#$df / BEQ end / BCC end / ASL A / MOV Y,A / ... : the guard falls into the entry.
		builder.setBytes("0x0e00", "68 df f0 0f 90 0d", false);
		lay(ASL_DISPATCH);
		builder.setBytes("0x0e00", "68 df f0 0f 90 0d", false);
		builder.disassemble("0x0e00", 6, true);
		analyze();
		assertEquals(new IndexGuard.Range(0xc0, 0xfe, 2), guard());
		assertShifted(6);
	}

	@Test
	public void callersThatDisagreeJoinToTheHull() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		guardedCaller(0x0d00);
		builder.setBytes("0x0d20", "68 ef f0 05 90 03 3f 06 0e 6f", false);
		builder.disassemble("0x0d20", 10, true);
		analyze();
		// A in e0..ff and f0..ff: the hull, Y c0..fe
		assertEquals(new IndexGuard.Range(0xc0, 0xfe, 2), guard());
		assertShifted(6);
	}

	@Test
	public void oneUnguardedCallerGivesNoGuard() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		guardedCaller(0x0d00);
		builder.setBytes("0x0d20", "3f 06 0e 6f", false);
		builder.disassemble("0x0d20", 4, true);
		analyze();
		assertNull(guard());
		assertShifted(0);
	}

	@Test
	public void unguardedCallerGivesNoGuard() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		builder.setBytes("0x0d00", "3f 06 0e 6f", false);
		builder.disassemble("0x0d00", 4, true);
		analyze();
		assertNull(guard());
		assertShifted(0);
	}

	@Test
	public void instructionBetweenGuardAndCallGivesNoGuard() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		// a MOV A,X between the branches and the CALL replaces A
		builder.setBytes("0x0d00", "68 df f0 06 90 04 7d 3f 06 0e 6f", false);
		builder.disassemble("0x0d00", 11, true);
		analyze();
		assertNull(guard());
		assertShifted(0);
	}

	@Test
	public void joinIntoTheCallGivesNoGuard() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		guardedCaller(0x0d00);
		// BRA straight to the CALL bypasses the guard
		builder.setBytes("0x0d30", "2f " + String.format("%02x", (0x0d06 - 0x0d32) & 0xff), false);
		builder.disassemble("0x0d30", 2, true);
		analyze();
		assertNull(guard());
		assertShifted(0);
	}

	@Test
	public void joinIntoTheBranchChainGivesNoGuard() throws Exception {
		shiftedTable(6);
		lay(ASL_DISPATCH);
		guardedCaller(0x0d00);
		// BRA into the BCC (0d04) skips the CMP, so the chain is not fall-through-only
		builder.setBytes("0x0d30", "2f " + String.format("%02x", (0x0d04 - 0x0d32) & 0xff), false);
		builder.disassemble("0x0d30", 2, true);
		analyze();
		assertNull(guard());
		assertShifted(0);
	}

	@Test
	public void guardIsIgnoredOutsideSpc700Shape() throws Exception {
		// AND-masked index: no guard lookup, the mask rules.
		table(0x2000, 0x2010);
		run(CT_DISPATCH);
		assertEquals(List.of(addr(0x2000), addr(0x2010)), computedJumpTargets());
	}
}
