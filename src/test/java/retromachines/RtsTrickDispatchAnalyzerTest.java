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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * grm-gipk.7: the 6502 RTS trick. Hand-built minimal reproductions of adventure_island's shapes:
 * bd50 (planar, hi table pushed first from the LOWER address) and 8dd1/c6c9/c95c (interleaved).
 */
public class RtsTrickDispatchAnalyzerTest extends AbstractProgramTest {

	private static final String DISPATCH = "0x8000";

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private static String word(long w) {
		return String.format("%02x %02x", w & 0xff, (w >> 8) & 0xff);
	}

	/** Lays the dispatcher bytes, decodes them, and runs the analyzer over them. */
	private void run(String dispatcherBytes) throws Exception {
		builder.setBytes(DISPATCH, dispatcherBytes, false);
		int len = dispatcherBytes.split(" ").length;
		builder.disassemble(DISPATCH, len, true);
		RtsTrickDispatchAnalyzer analyzer = new RtsTrickDispatchAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(addr(0x8000), addr(0x8000 + len - 1)),
				TaskMonitor.DUMMY, new MessageLog());
		});
	}

	private void handlers(long... targets) throws Exception {
		for (long t : targets) {
			builder.setBytes(hex(t), "ea 60", false); // NOP; RTS
		}
	}

	private List<Address> computedJumpTargets(long rts) {
		List<Address> out = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr(rts))) {
			if (r.getReferenceType().equals(RefType.COMPUTED_JUMP)) {
				out.add(r.getToAddress());
			}
		}
		return out;
	}

	private void assertTargetsDisassembledWithoutFunctions(long... targets) {
		for (long t : targets) {
			assertNotNull("target " + hex(t) + " disassembled",
				program.getListing().getInstructionAt(addr(t)));
			assertNull("no function at " + hex(t), program.getFunctionManager().getFunctionAt(addr(t)));
		}
	}

	// ---------------------------------------------------------------------

	@Test
	public void interleavedTableIsLaidReferencedAndDisassembled() throws Exception {
		long[] t = { 0x9200, 0x9210, 0x9220 };
		handlers(t);
		// LDA $9101,Y / PHA / LDA $9100,Y / PHA / RTS
		StringBuilder table = new StringBuilder();
		for (long x : t) {
			table.append(word(x - 1)).append(' ');
		}
		table.append("4f 00"); // 4th word: target $0050, uninitialized RAM -> ends the table
		builder.setBytes("0x9100", table.toString(), false);
		run("b9 01 91 48 b9 00 91 48 60");

		Data d = program.getListing().getDefinedDataAt(addr(0x9100));
		assertNotNull(d);
		Array a = (Array) d.getDataType();
		assertTrue(a.getDataType() instanceof WordDataType);
		assertEquals(3, a.getNumElements());
		for (int i = 0; i < 3; i++) {
			boolean ref = false;
			for (Reference r : program.getReferenceManager().getReferencesFrom(addr(0x9100 + 2L * i))) {
				ref |= RefType.DATA.equals(r.getReferenceType()) && r.getToAddress().equals(addr(t[i]));
			}
			assertTrue("entry " + i + " has a DATA ref to the real (word+1) target", ref);
		}
		assertEquals(List.of(addr(t[0]), addr(t[1]), addr(t[2])), computedJumpTargets(0x8008));
		assertTargetsDisassembledWithoutFunctions(t);
	}

	@Test
	public void hiFirstPlanarTableWithNegativeGap() throws Exception {
		// bd50 shape: LDA hi,X / PHA / LDA lo,X / PHA / RTS, hi at $9008 BELOW lo at $9010.
		long[] t = new long[8];
		StringBuilder hi = new StringBuilder();
		StringBuilder lo = new StringBuilder();
		for (int i = 0; i < 8; i++) {
			t[i] = 0x9200 + 0x10L * i;
			long w = t[i] - 1;
			hi.append(String.format("%02x ", (w >> 8) & 0xff));
			lo.append(String.format("%02x ", w & 0xff));
		}
		handlers(t);
		builder.setBytes("0x9008", hi.toString().trim(), false);
		builder.setBytes("0x9010", lo.toString().trim(), false);
		run("bd 08 90 48 bd 10 90 48 60");

		RtsTrickDispatch.Shape shape = RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(0x8008)));
		assertEquals(-8, shape.gap());
		assertEquals(RtsTrickDispatch.Cut.GAP, RtsTrickDispatch.scan(program, shape).cut);

		Data loArr = program.getListing().getDefinedDataAt(addr(0x9010));
		Data hiArr = program.getListing().getDefinedDataAt(addr(0x9008));
		assertEquals(8, ((Array) loArr.getDataType()).getNumElements());
		assertEquals(8, ((Array) hiArr.getDataType()).getNumElements());
		for (int i = 0; i < 8; i++) {
			boolean ref = false;
			for (Reference r : program.getReferenceManager().getReferencesFrom(addr(0x9010 + i))) {
				ref |= RefType.DATA.equals(r.getReferenceType()) && r.getToAddress().equals(addr(t[i]));
			}
			assertTrue("lo entry " + i + " refs its target", ref);
		}
		assertEquals(8, computedJumpTargets(0x8008).size());
		assertTargetsDisassembledWithoutFunctions(t);
	}

	@Test
	public void loFirstPlanarTable() throws Exception {
		// hi at $9110 (pushed first), lo at $9100; five entries, then lo=hi=0 -> target $0001.
		long[] t = { 0x9200, 0x9210, 0x9220, 0x9230, 0x9240 };
		handlers(t);
		StringBuilder hi = new StringBuilder();
		StringBuilder lo = new StringBuilder();
		for (long x : t) {
			hi.append(String.format("%02x ", ((x - 1) >> 8) & 0xff));
			lo.append(String.format("%02x ", (x - 1) & 0xff));
		}
		builder.setBytes("0x9100", lo.toString().trim(), false);
		builder.setBytes("0x9110", hi.toString().trim(), false);
		run("b9 10 91 48 b9 00 91 48 60");

		assertEquals(5, ((Array) program.getListing().getDefinedDataAt(addr(0x9100)).getDataType())
				.getNumElements());
		assertEquals(5, computedJumpTargets(0x8008).size());
		assertTargetsDisassembledWithoutFunctions(t);
	}

	@Test
	public void lowestTargetCutsAnOverRead() throws Exception {
		// Entry 0's target $9104 lies inside the table's own extent: entry 2 (bytes $9104..) is the
		// first handler's code, which would read as a plausible word ($92a9 -> $92aa).
		builder.setBytes("0x9100", "03 91 ff 92", false);
		builder.setBytes("0x9104", "a9 92 60", false); // LDA #$92; RTS (entry 0's handler)
		builder.setBytes("0x92aa", "60", false);
		handlers(0x9300);
		run("b9 01 91 48 b9 00 91 48 60");

		RtsTrickDispatch.Shape shape = RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(0x8008)));
		RtsTrickDispatch.Site site = RtsTrickDispatch.scan(program, shape);
		assertEquals(RtsTrickDispatch.Cut.ABOVE_TABLE_TARGET, site.cut);
		assertEquals(List.of(addr(0x9104), addr(0x9300)), site.targets);
	}

	/**
	 * adventure_island 8efe/8f8e: two interleaved tables back to back, the first running straight
	 * into the plausible words of the second. The neighbour table's base ends the first.
	 */
	@Test
	public void neighbourTableBaseEndsTheTableBeforeIt() throws Exception {
		long[] a = { 0x9200, 0x9210, 0x9220 };
		long[] b = { 0x9230, 0x9240 };
		handlers(a);
		handlers(b);
		builder.setBytes("0x9100", word(a[0] - 1) + " " + word(a[1] - 1) + " " + word(a[2] - 1) + " " +
			word(b[0] - 1) + " " + word(b[1] - 1) + " 4f 00", false);
		builder.setBytes("0x8000", "b9 01 91 48 b9 00 91 48 60", false); // table A at $9100
		builder.setBytes("0x8100", "b9 07 91 48 b9 06 91 48 60", false); // table B at $9106
		builder.disassemble("0x8000", 9, true);
		builder.disassemble("0x8100", 9, true);

		RtsTrickDispatchAnalyzer analyzer = new RtsTrickDispatchAnalyzer();
		inTx(program, "analyze", () -> {
			analyzer.added(program,
				new AddressSet(addr(0x8000), addr(0x8008)).union(new AddressSet(addr(0x8100), addr(0x8108))),
				TaskMonitor.DUMMY, new MessageLog());
		});

		assertEquals(3, ((Array) program.getListing().getDefinedDataAt(addr(0x9100)).getDataType())
				.getNumElements());
		assertEquals(3, computedJumpTargets(0x8008).size());
		assertEquals(2, ((Array) program.getListing().getDefinedDataAt(addr(0x9106)).getDataType())
				.getNumElements());
		assertEquals(2, computedJumpTargets(0x8108).size());

		RtsTrickDispatch.Shape shapeA = RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(0x8008)));
		assertEquals(RtsTrickDispatch.Cut.NEIGHBOUR_TABLE,
			RtsTrickDispatch.scan(program, shapeA, List.of(addr(0x9100), addr(0x9106))).cut);
		assertEquals("without the neighbour it over-reads into B's words", 5,
			RtsTrickDispatch.scan(program, shapeA).targets.size());
	}

	@Test
	public void toleratesNoiseBetweenPartsButNotRWrites() throws Exception {
		builder.setBytes("0x9100", "ff 91 0f 92", false);
		builder.setBytes("0x8100", "b9 01 91 48 ea b9 00 91 48 ea 60", false);
		builder.setBytes("0x8200", "b9 01 91 48 c8 b9 00 91 48 60", false);
		builder.disassemble("0x8100", 11, true);
		builder.disassemble("0x8200", 10, true);
		assertNotNull(RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(0x810a))));
		assertNull("INY between the loads writes R", RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(0x8209))));
	}

	// ---------------------------------------------------------------------
	// Negatives.
	// ---------------------------------------------------------------------

	@Test
	public void plainRtsIsNotADispatch() throws Exception {
		run("a9 00 60");
		Instruction rts = program.getListing().getInstructionAt(addr(0x8002));
		assertNull(RtsTrickDispatch.recognize(program, rts));
		assertTrue(computedJumpTargets(0x8002).isEmpty());
	}

	@Test
	public void plaBetweenThePushesDeclines() throws Exception {
		builder.setBytes("0x9100", "ff 91 0f 92 1f 92", false);
		handlers(0x9200, 0x9210, 0x9220);
		run("b9 01 91 48 68 b9 00 91 48 60");
		assertNull(RtsTrickDispatch.recognize(program,
			program.getListing().getInstructionAt(addr(0x8009))));
		assertTrue(computedJumpTargets(0x8009).isEmpty());
		assertNull(program.getListing().getInstructionAt(addr(0x9200)));
	}

	@Test
	public void repeatedAddedCallsAreIdempotent() throws Exception {
		long[] t = { 0x9200, 0x9210 };
		handlers(t);
		builder.setBytes("0x9100", word(t[0] - 1) + " " + word(t[1] - 1) + " 4f 00", false);
		run("b9 01 91 48 b9 00 91 48 60");
		RtsTrickDispatchAnalyzer analyzer = new RtsTrickDispatchAnalyzer();
		inTx(program, "again", () -> {
			analyzer.added(program, new AddressSet(addr(0x8000), addr(0x8008)), TaskMonitor.DUMMY,
				new MessageLog());
		});
		assertEquals(2, computedJumpTargets(0x8008).size());
		assertEquals(2, ((Array) program.getListing().getDefinedDataAt(addr(0x9100)).getDataType())
				.getNumElements());
	}
}
