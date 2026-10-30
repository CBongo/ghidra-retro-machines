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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * grm-gipk.11: the 65816 RTS trick ({@link W65816RtsTrick}, {@link W65816RtsTrickAnalyzer}).
 * The dispatcher always starts at $8000 (M=0, X=0, E=0); handlers are single {@code RTS} bytes at
 * $8200, $8210, ...; abs tables live at $8100.
 */
public class W65816RtsTrickTest extends AbstractProgramTest {

	private static final long[] HANDLERS = { 0x8200, 0x8210, 0x8220, 0x8230, 0x8240, 0x8250 };

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "65816:LE:24:retro");
		MemoryBlock rom = builder.createMemory(".rom", "0x8000", 0x1000);
		MemoryBlock rom1 = builder.createMemory(".rom1", "0x018000", 0x1000);
		program = builder.getProgram();
		for (MemoryBlock b : new MemoryBlock[] { rom, rom1 }) {
			setWritable(b, false);
			inTx(program, "rom executable", () -> b.setExecute(true));
		}
		setContext("0x8000", "0x8fff", "ctx_EF", 0);
		setContext("0x8000", "0x8fff", "ctx_MF", 0);
		setContext("0x8000", "0x8fff", "ctx_XF", 0);
		for (long t : HANDLERS) {
			builder.setBytes(hex(t), "60", false);
		}
	}

	private void setContext(String start, String end, String field, int value) throws Exception {
		Register register = program.getLanguage().getRegister(field);
		assertNotNull(register);
		inTx(program, "set " + field, () -> program.getProgramContext()
				.setValue(register, builder.addr(start), builder.addr(end),
					BigInteger.valueOf(value)));
	}

	/** Little-endian words at {@code at}. */
	private void words(String at, int... ws) throws Exception {
		StringBuilder sb = new StringBuilder();
		for (int w : ws) {
			sb.append(String.format("%02x %02x ", w & 0xff, (w >> 8) & 0xff));
		}
		builder.setBytes(at, sb.toString().trim(), false);
	}

	/** Lays and decodes the dispatcher at $8000; returns the address of its last byte (the return). */
	private Address dispatcher(String bytes) throws Exception {
		builder.setBytes("0x8000", bytes, false);
		int n = bytes.split(" ").length;
		builder.disassemble("0x8000", n, false);
		return addr(0x8000L + n - 1);
	}

	private W65816RtsTrick.Shape recognize(Address rts) {
		return W65816RtsTrick.recognize(program, instructionAt(rts));
	}

	private void analyze(Address rts) throws Exception {
		W65816RtsTrickAnalyzer analyzer = new W65816RtsTrickAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> analyzer.added(program, new AddressSet(addr(0x8000), rts),
			TaskMonitor.DUMMY, new MessageLog()));
	}

	private List<Address> jumpTargets(Address rts) {
		List<Address> out = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesFrom(rts)) {
			if (r.getReferenceType().equals(RefType.COMPUTED_JUMP)) {
				out.add(r.getToAddress());
			}
		}
		return out;
	}

	private void assertTargets(Address rts, long... expected) {
		List<Address> got = jumpTargets(rts);
		assertEquals(got.toString(), expected.length, got.size());
		for (long e : expected) {
			assertTrue(hex(e) + " missing from " + got, got.contains(addr(e)));
			assertNotNull("not decoded at " + hex(e), program.getListing().getInstructionAt(addr(e)));
		}
	}

	private void assertArray(long at, int n) {
		Data d = program.getListing().getDefinedDataAt(addr(at));
		assertNotNull("no table at " + hex(at), d);
		assertEquals(n, ((Array) d.getDataType()).getNumElements());
	}

	/** {@code BRA target} at $8020, so a flow reference lands on {@code target}. */
	private void branchTo(long target) throws Exception {
		builder.setBytes("0x8020", String.format("80 %02x", (target - 0x8022) & 0xff), false);
		builder.disassemble("0x8020", 2, true);
	}

	@Test
	public void absXWordTableTargetsAreWordPlusOne() throws Exception {
		words("0x8100", 0x81ff, 0x820f, 0x821f, 0x0000);
		Address rts = dispatcher("0a aa bd 00 81 48 60");
		W65816RtsTrick.Shape s = recognize(rts);
		assertNotNull(s);
		assertEquals(addr(0x8100), s.table());
		assertEquals(1, s.bias());
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210, 0x8220);
		assertArray(0x8100, 3);
		assertTrue(program.getListing().getComment(
			ghidra.program.model.listing.CommentType.EOL, rts).contains("65816 RTS trick"));
	}

	@Test
	public void decATargetsAreTheWordsThemselves() throws Exception {
		words("0x8100", 0x8200, 0x8210, 0x8220, 0x0000);
		Address rts = dispatcher("0a aa bd 00 81 3a 48 60");
		assertEquals(0, recognize(rts).bias());
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210, 0x8220);
	}

	@Test
	public void twoDecAsGiveBiasMinusOne() throws Exception {
		Address rts = dispatcher("0a aa bd 00 81 3a 3a 48 60");
		assertEquals(-1, recognize(rts).bias());
	}

	@Test
	public void longXTableInAnotherBankTargetsTheReturnsBank() throws Exception {
		words("0x018000", 0x81ff, 0x820f, 0x0000);
		Address rts = dispatcher("0a aa bf 00 80 01 48 60");
		W65816RtsTrick.Shape s = recognize(rts);
		assertNotNull(s);
		assertEquals(addr("0x018000"), s.table());
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210);
		assertArray(0x018000, 2);
	}

	@Test
	public void absYIsRecognized() throws Exception {
		words("0x8100", 0x81ff, 0x820f, 0x0000);
		Address rts = dispatcher("b9 00 81 48 60");
		assertNotNull(recognize(rts));
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210);
	}

	@Test
	public void noiseAfterThePushStillResolves() throws Exception {
		words("0x8100", 0x81ff, 0x820f, 0x0000);
		// Madden 96 / Timecop: LDX dp, LDX #imm; and a SEP before the return (Road Riot).
		Address rts = dispatcher("0a aa bd 00 81 48 a6 67 a2 c0 17 e2 20 60");
		assertNotNull(recognize(rts));
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210);
	}

	@Test
	public void earlierPushOfAReturnAddressIsIrrelevant() throws Exception {
		words("0x8100", 0x81ff, 0x820f, 0x0000);
		Address rts = dispatcher("f4 fb 86 bd 00 81 48 60");
		assertNotNull(recognize(rts));
	}

	@Test
	public void eightBitAccumulatorPushDeclines() throws Exception {
		// SEP #$20 leaves M=1 at the load and the push.
		Address rts = dispatcher("e2 20 0a aa bd 00 81 48 60");
		assertNull(recognize(rts));
	}

	@Test
	public void pullBetweenPushAndReturnDeclines() throws Exception {
		assertNull(recognize(dispatcher("0a aa bd 00 81 48 68 60")));
	}

	@Test
	public void secondPushBetweenPushAndReturnDeclines() throws Exception {
		assertNull(recognize(dispatcher("0a aa bd 00 81 48 da 60")));
	}

	@Test
	public void joinIntoTheDecAOrPushDeclinesButJoinIntoTheReturnResolves() throws Exception {
		Address rts = dispatcher("0a aa bd 00 81 3a 48 60");
		branchTo(0x8005);
		assertNull("join into DEC A", recognize(rts));
	}

	@Test
	public void joinIntoThePushDeclines() throws Exception {
		Address rts = dispatcher("0a aa bd 00 81 48 60");
		branchTo(0x8005);
		assertNull(recognize(rts));
	}

	@Test
	public void joinIntoTheReturnStillResolves() throws Exception {
		words("0x8100", 0x81ff, 0x820f, 0x0000);
		Address rts = dispatcher("0a aa bd 00 81 48 60");
		branchTo(0x8006);
		assertNotNull(recognize(rts));
	}

	@Test
	public void joinIntoTheLoadItselfResolves() throws Exception {
		Address rts = dispatcher("0a aa bd 00 81 48 60");
		branchTo(0x8002);
		assertNotNull(recognize(rts));
	}

	@Test
	public void absRamTableDeclines() throws Exception {
		assertNull(recognize(dispatcher("bd 00 01 48 60")));
	}

	@Test
	public void longRamBankTableDeclines() throws Exception {
		assertNull(recognize(dispatcher("bf 00 90 7e 48 60")));
	}

	@Test
	public void longLowWordBelow8000Declines() throws Exception {
		assertNull(recognize(dispatcher("bf 00 10 02 48 60")));
	}

	@Test
	public void rtlIsNotMatched() throws Exception {
		Address rtl = dispatcher("0a aa bd 00 81 48 6b");
		assertNull(recognize(rtl));
	}

	@Test
	public void inlineTableRightAfterTheReturnEndsAtANonPlausibleEntry() throws Exception {
		// Wolf3D c020d6: the table starts at RTS + 1.
		words("0x8008", 0x81ff, 0x820f, 0x821f, 0x0000, 0x8210);
		Address rts = dispatcher("0a aa bf 08 80 00 48 60");
		assertEquals(addr(0x8008), recognize(rts).table());
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210, 0x8220);
		assertArray(0x8008, 3);
	}

	@Test
	public void tableEndsWhereAnEntryPointsIntoItself() throws Exception {
		// Entry 2's target is $800c, the table's own third word.
		words("0x8008", 0x81ff, 0x820f, 0x800b, 0x821f);
		Address rts = dispatcher("0a aa bf 08 80 00 48 60");
		analyze(rts);
		assertTargets(rts, 0x8200, 0x8210);
		assertArray(0x8008, 2);
	}

	@Test
	public void andMaskCapsTheTable() throws Exception {
		words("0x8100", 0x81ff, 0x820f, 0x821f, 0x822f, 0x823f, 0x824f);
		Address rts = dispatcher("29 03 00 0a aa bd 00 81 48 60");
		assertEquals(4, recognize(rts).cap());
		analyze(rts);
		assertArray(0x8100, 4);
		assertEquals(4, jumpTargets(rts).size());
	}

	@Test
	public void singleEntryTableIsDeclined() throws Exception {
		words("0x8100", 0x81ff, 0x0000);
		Address rts = dispatcher("0a aa bd 00 81 48 60");
		analyze(rts);
		assertTrue(jumpTargets(rts).isEmpty());
	}

	/** Madden NFL '94 $C5:A748: the table ends where the words cross into the bank's other half. */
	@Test
	public void tableEndsWhereTargetsCrossIntoTheOtherHalfOfTheBank() throws Exception {
		MemoryBlock lo = builder.createMemory(".lo", "0x0000", 0x8000);
		setWritable(lo, false);
		inTx(program, "lo executable", () -> lo.setExecute(true));
		builder.setBytes("0x1100", "60", false);
		words("0x8100", 0x81ff, 0x820f, 0x10ff, 0x821f);
		Address rts = dispatcher("0a aa bd 00 81 48 60");
		analyze(rts);
		assertArray(0x8100, 2);
		assertTargets(rts, 0x8200, 0x8210);
	}

	/**
	 * LoROM FastROM code runs in a byte-mapped mirror ($80:8000 onto the ROM), whose block reports
	 * isInitialized() false; the targets there are still ROM (Urban Strike $80:8BCC, grm-gipk.11).
	 */
	@Test
	public void targetsInAByteMappedMirrorResolve() throws Exception {
		inTx(program, "mirror", () -> {
			MemoryBlock m = program.getMemory().createByteMappedBlock("ROM_80_8000_mirror",
				addr(0x808000), addr(0x8000), 0x1000, false);
			m.setExecute(true);
			m.setWrite(false);
		});
		setContext("0x808000", "0x808fff", "ctx_EF", 0);
		setContext("0x808000", "0x808fff", "ctx_MF", 0);
		setContext("0x808000", "0x808fff", "ctx_XF", 0);
		words("0x8100", 0x81ff, 0x820f, 0x0000);
		builder.setBytes("0x8000", "0a aa bd 00 81 48 60", false);
		builder.disassemble("0x808000", 7, false);
		Address rts = addr(0x808006);
		W65816RtsTrickAnalyzer analyzer = new W65816RtsTrickAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0x808000), rts), TaskMonitor.DUMMY, new MessageLog()));
		List<Address> got = jumpTargets(rts);
		assertEquals(got.toString(), 2, got.size());
		assertTrue(got.contains(addr(0x808200)));
		assertTrue(got.contains(addr(0x808210)));
	}

	@Test
	public void returnWithoutPushIsNotMatched() throws Exception {
		Instruction in = instructionAt(dispatcher("0a aa 60"));
		assertNull(W65816RtsTrick.recognize(program, in));
	}
}
