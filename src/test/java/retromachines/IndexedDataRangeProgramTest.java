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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * {@code ProgramBuilder} coverage of {@link IndexedDataRangeAnalyzer} / {@link IndexLoopRange}
 * (grm-9nxj.41.3): a register-indexed absolute read is acted on only when a guard or a strong
 * loop proof pins both ends of its index, and never on the shape of its target. ROM is the
 * non-writable {@code PRG} block at {@code $8000}; tables sit at {@code $9000}.
 */
public class IndexedDataRangeProgramTest extends AbstractProgramTest {

	private IndexedDataRangeAnalyzer.Counts counts;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		var prg = builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		setWritable(prg, false);
	}

	/** Stand-in for Ghidra's operand-reference analysis: a READ reference per abs,X/abs,Y operand. */
	private void addOperandReferences() {
		inTx(program, "refs", () -> {
			for (Instruction i : program.getListing().getInstructions(true)) {
				if (i.getLength() != 3 || i.getNumOperands() != 1 || i.getFlowType().isJump() ||
					i.getFlowType().isCall() || i.getReferencesFrom().length > 0) {
					continue;
				}
				boolean idx = false;
				long base = -1;
				for (Object o : i.getOpObjects(0)) {
					idx |= o instanceof ghidra.program.model.lang.Register;
					if (o instanceof ghidra.program.model.scalar.Scalar sc) {
						base = sc.getUnsignedValue();
					}
				}
				if (idx && base >= 0) {
					program.getReferenceManager().addMemoryReference(i.getMinAddress(),
						addr(base), ghidra.program.model.symbol.RefType.READ,
						ghidra.program.model.symbol.SourceType.ANALYSIS, 0);
				}
			}
		});
	}

	private void run() throws Exception {
		if (counts == null) {
			addOperandReferences();
		}
		inTx(program, "analyze", () -> {
			counts = IndexedDataRangeAnalyzer.analyze(program,
				new AddressSet(addr(0x8000), addr(0xffff)), TaskMonitor.DUMMY);
		});
	}

	private Reference primaryRef(String at) {
		Instruction i = instructionAt(at);
		for (Reference r : i.getReferencesFrom()) {
			if (r.isMemoryReference() && r.isPrimary() && r.getOperandIndex() == 0) {
				return r;
			}
		}
		return null;
	}

	private OffsetReference primaryOffsetRef(String at) {
		Reference r = primaryRef(at);
		return r instanceof OffsetReference o ? o : null;
	}

	private Data arrayAt(long a) {
		Data d = program.getListing().getDefinedDataAt(addr(a));
		return d != null && d.getNumComponents() > 0 ? d : null;
	}

	/** {@code CPX #4 / BCS out / LDA $9000,X}: the guard says X is 0..3, so 4 bytes at $9000. */
	@Test
	public void guardProvenReadSizesTheTable() throws Exception {
		put("0x8000", "e0 04"); // CPX #4
		put("0x8002", "b0 03"); // BCS $8007
		put("0x8004", "bd 00 90"); // LDA $9000,X
		put("0x8007", "60"); // RTS
		run();
		assertEquals(1, counts.byGuard);
		Data arr = arrayAt(0x9000);
		assertNotNull("array at the table", arr);
		assertEquals(4, arr.getLength());
		assertNull("lo == 0: the reference stays plain", primaryOffsetRef("0x8004"));
	}

	/**
	 * smb de68's shape: {@code LDX #4 / L: CMP $9000,X / DEX / BNE L}. X runs 4..1, so the
	 * table is $9001..$9004 and the operand reads {@code table-1}; $9000 is not table.
	 */
	@Test
	public void dexBneCountdownMovesTheReferenceAndSizesTheTable() throws Exception {
		countdown();
		run();
		assertEquals(1, counts.byLoop);
		assertEquals(1, counts.refsMoved);
		OffsetReference ref = primaryOffsetRef("0x8002");
		assertNotNull("offset reference", ref);
		assertEquals(addr(0x9001), ref.getBaseAddress());
		assertEquals(-1, ref.getOffset());
		assertEquals("to stays the operand's own value", addr(0x9000), ref.getToAddress());
		int memRefs = 0;
		for (Reference r : instructionAt("0x8002").getReferencesFrom()) {
			if (r.isMemoryReference()) {
				memRefs++;
			}
		}
		assertEquals("no duplicate reference", 1, memRefs);
		Data arr = arrayAt(0x9001);
		assertNotNull(arr);
		assertEquals(4, arr.getLength());
		assertNull("$9000 is not table", program.getListing().getDefinedDataAt(addr(0x9000)));
	}

	private void countdown() throws Exception {
		put("0x8000", "a2 04"); // LDX #4
		put("0x8002", "dd 00 90"); // L: CMP $9000,X
		put("0x8005", "ca"); // DEX
		put("0x8006", "d0 fa"); // BNE L
		put("0x8008", "60"); // RTS
	}

	/** An instruction inside the proven range: the reference still moves, nothing is sized. */
	@Test
	public void rangeOverInstructionDeclinesSizingButMovesTheReference() throws Exception {
		countdown();
		put("0x9003", "ea"); // NOP inside $9001..$9004
		run();
		assertNotNull(primaryOffsetRef("0x8002"));
		assertNull(arrayAt(0x9001));
		assertEquals(1, counts.arraysSkippedOverlap);
		assertNotNull("the instruction survives",
			program.getListing().getInstructionAt(addr(0x9003)));
	}

	/** The guard says 0..2, the loop says 1..4: both prove, they differ, the site is declined. */
	@Test
	public void conflictingGuardAndLoopDeclines() throws Exception {
		put("0x8000", "a2 04"); // LDX #4
		put("0x8002", "e0 03"); // L: CPX #3
		put("0x8004", "b0 03"); // BCS $8009
		put("0x8006", "bd 00 90"); // LDA $9000,X
		put("0x8009", "ca"); // DEX
		put("0x800a", "d0 f6"); // BNE L
		put("0x800c", "60");
		run();
		assertEquals(1, counts.declinedDisagree);
		assertEquals(0, counts.proven);
		assertNull(arrayAt(0x9000));
		assertNull(primaryOffsetRef("0x8006"));
	}

	/** A callee that writes X breaks the proof: nothing is done. */
	@Test
	public void calleeThatWritesXDeclines() throws Exception {
		put("0x8000", "a2 04"); // LDX #4
		put("0x8002", "bd 00 90"); // L: LDA $9000,X
		put("0x8005", "20 00 81"); // JSR $8100
		put("0x8008", "ca"); // DEX
		put("0x8009", "d0 f7"); // BNE L
		put("0x800b", "60");
		put("0x8100", "e8 60"); // INX / RTS
		run();
		assertEquals(0, counts.proven);
		assertNull(primaryOffsetRef("0x8002"));
		assertNull(arrayAt(0x9000));
	}

	/** The same loop with a callee that leaves X alone is proven through the call. */
	@Test
	public void calleePreservingXIsTransparent() throws Exception {
		put("0x8000", "a2 04");
		put("0x8002", "bd 00 90");
		put("0x8005", "20 00 81");
		put("0x8008", "ca");
		put("0x8009", "d0 f7");
		put("0x800b", "60");
		put("0x8100", "60"); // RTS
		run();
		assertEquals(1, counts.proven);
		assertNotNull(primaryOffsetRef("0x8002"));
		assertNotNull(arrayAt(0x9001));
	}

	/** The index saved around a clobber is restored: TXA/PHA..PLA/TAX keeps the proof. */
	@Test
	public void saveRestoreAroundClobberKeepsTheProof() throws Exception {
		put("0x8000", "a2 03"); // LDX #3
		put("0x8002", "bd 00 90"); // L: LDA $9000,X
		put("0x8005", "8a"); // TXA
		put("0x8006", "48"); // PHA
		put("0x8007", "a2 00"); // LDX #0   (clobber)
		put("0x8009", "68"); // PLA
		put("0x800a", "aa"); // TAX
		put("0x800b", "ca"); // DEX
		put("0x800c", "d0 f4"); // BNE L
		put("0x800e", "60");
		run();
		assertEquals(1, counts.byLoop);
		Data arr = arrayAt(0x9001);
		assertNotNull(arr);
		assertEquals(3, arr.getLength());
	}

	/** An unproven index (no guard, no loop) is left alone, whatever its base lands on. */
	@Test
	public void unprovenReadIsUntouched() throws Exception {
		put("0x8000", "bd 00 90"); // LDA $9000,X
		put("0x8003", "60");
		run();
		assertEquals(0, counts.proven);
		assertNull(arrayAt(0x9000));
	}

	/** Two proven reads whose spans overlap give ONE array, not two. */
	@Test
	public void overlappingProvenReadsMergeIntoOneArray() throws Exception {
		put("0x8000", "a2 04"); // LDX #4
		put("0x8002", "dd 00 90"); // L: CMP $9000,X     -> $9001..$9004
		put("0x8005", "7d 01 90"); // ADC $9001,X        -> $9002..$9005
		put("0x8008", "ca");
		put("0x8009", "d0 f7");
		put("0x800b", "60");
		run();
		Data arr = arrayAt(0x9001);
		assertNotNull(arr);
		assertEquals(5, arr.getLength());
		assertEquals(1, counts.arraysCreated);
	}

	/** A larger array already there covers the range: nothing is created or cleared. */
	@Test
	public void existingCoveringArrayIsLeftAlone() throws Exception {
		countdown();
		inTx(program, "array", () -> program.getListing().createData(addr(0x9000),
			new ArrayDataType(ByteDataType.dataType, 16, 1)));
		run();
		assertEquals(0, counts.arraysCreated);
		assertEquals(1, counts.arraysSkippedCovered);
		assertEquals(16, program.getListing().getDefinedDataAt(addr(0x9000)).getLength());
	}

	/** Table bytes in writable memory are not ROM data: no action. */
	@Test
	public void writableBlockIsDeclined() throws Exception {
		setWritable(program.getMemory().getBlock(addr(0x8000)), true);
		countdown();
		run();
		assertEquals(1, counts.declinedBlock);
		assertFalse(counts.arraysCreated > 0);
		assertNull(primaryOffsetRef("0x8002"));
	}

	/** A second run changes nothing: the reference is already anchored, the array exists. */
	@Test
	public void secondRunIsIdempotent() throws Exception {
		countdown();
		run();
		run();
		assertEquals(0, counts.refsMoved);
		assertEquals(0, counts.arraysCreated);
		assertEquals(4, arrayAt(0x9001).getLength());
	}
}
