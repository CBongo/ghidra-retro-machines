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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * grm-gipk.14: the 65816 RTL trick ({@link W65816RtlTrick}, {@link W65816RtlTrickAnalyzer}). The
 * dispatcher starts at $8000 (M=0, X=0, E=0); handlers are single {@code RTS} bytes at $8200,
 * $8210, ... in bank 0 and $01:8200 in bank 1; tables live at $8100.
 */
public class W65816RtlTrickTest extends AbstractProgramTest {

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
		for (long t : new long[] { 0x8200, 0x8210, 0x8220, 0x8230, 0x8240, 0x018200 }) {
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

	/** Lays and decodes the dispatcher at $8000; returns the address of its last byte (the RTL). */
	private Address dispatcher(String bytes) throws Exception {
		builder.setBytes("0x8000", bytes, false);
		int n = bytes.split(" ").length;
		builder.disassemble("0x8000", n, false);
		return addr(0x8000L + n - 1);
	}

	private W65816RtlTrick.Shape recognize(Address rtl) {
		return W65816RtlTrick.recognize(program, instructionAt(rtl));
	}

	private void analyze(Address rtl) throws Exception {
		W65816RtlTrickAnalyzer analyzer = new W65816RtlTrickAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> analyzer.added(program, new AddressSet(addr(0x8000), rtl),
			TaskMonitor.DUMMY, new MessageLog()));
	}

	private List<Address> jumpTargets(Address rtl) {
		List<Address> out = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesFrom(rtl)) {
			if (r.getReferenceType().equals(RefType.COMPUTED_JUMP)) {
				out.add(r.getToAddress());
			}
		}
		return out;
	}

	private void assertTargets(Address rtl, long... expected) {
		List<Address> got = jumpTargets(rtl);
		assertEquals(got.toString(), expected.length, got.size());
		for (long e : expected) {
			assertTrue(hex(e) + " missing from " + got, got.contains(addr(e)));
			assertNotNull("not decoded at " + hex(e), program.getListing().getInstructionAt(addr(e)));
		}
	}

	private void assertRecords(long at, int n, int stride) {
		Data d = program.getListing().getDefinedDataAt(addr(at));
		assertNotNull("no table at " + hex(at), d);
		Array a = (Array) d.getDataType();
		assertEquals(n, a.getNumElements());
		assertEquals(stride, a.getElementLength());
	}

	private void branchTo(long target) throws Exception {
		builder.setBytes("0x8020", String.format("80 %02x", (target - 0x8022) & 0xff), false);
		builder.disassemble("0x8020", 2, true);
	}

	/** SEP #$20 / LDA $8102,X / PHA / REP #$20 / LDA $8100,X / [DEC A] / PHA / RTL (word-first). */
	private static final String WORD_FIRST = "e2 20 bd 02 81 48 c2 20 bd 00 81 48 6b";

	@Test
	public void wordFirstStride3TargetsAreWordPlusOne() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 0f 82 00 1f 82 00 00 00 00", false);
		Address rtl = dispatcher(WORD_FIRST);
		W65816RtlTrick.Shape s = recognize(rtl);
		assertNotNull(s);
		assertEquals(addr(0x8100), s.table());
		assertFalse(s.bankFirst());
		assertEquals(1, s.bias());
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x8210, 0x8220);
		assertRecords(0x8100, 3, 3);
		assertTrue(program.getListing().getComment(
			ghidra.program.model.listing.CommentType.EOL, rtl).contains("65816 RTL trick"));
	}

	@Test
	public void decABiasMakesTheWordsExact() throws Exception {
		builder.setBytes("0x8100", "00 82 00 10 82 00 20 82 00 00 00 00", false);
		Address rtl = dispatcher("e2 20 bd 02 81 48 c2 20 bd 00 81 3a 48 6b");
		assertEquals(0, recognize(rtl).bias());
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x8210, 0x8220);
	}

	@Test
	public void bankFirstAbsYStride3() throws Exception {
		// LDA $813d,Y (bank) / LDA $813e,Y (word): records [bank, lo, hi].
		builder.setBytes("0x813d", "00 ff 81 00 0f 82 00 1f 82 00 00 00", false);
		Address rtl = dispatcher("e2 20 b9 3d 81 48 c2 20 b9 3e 81 48 6b");
		W65816RtlTrick.Shape s = recognize(rtl);
		assertNotNull(s);
		assertTrue(s.bankFirst());
		assertEquals(addr(0x813d), s.table());
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x8210, 0x8220);
		assertRecords(0x813d, 3, 3);
	}

	@Test
	public void stride4IsChosenWhenStride3ReadsGarbage() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 00 0f 82 00 00 1f 82 00 00 2f 82 00 00 00 00 00 00",
			false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x8210, 0x8220, 0x8230);
		assertRecords(0x8100, 4, 4);
	}

	@Test
	public void stride3WinsWhenStride4ReadsGarbage() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 0f 82 00 1f 82 00 2f 82 00 00 00 00", false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		assertRecords(0x8100, 4, 3);
	}

	@Test
	public void eachRecordCarriesItsOwnBank() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 ff 81 01 0f 82 00 00 00 00", false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x018200, 0x8210);
		assertRecords(0x8100, 3, 3);
	}

	@Test
	public void implausibleBankEndsTheTable() throws Exception {
		// The third record's bank is $7E (WRAM): not ROM, so the table ends there.
		builder.setBytes("0x8100", "ff 81 00 0f 82 00 1f 82 7e 2f 82 00", false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x8210);
	}

	@Test
	public void secondSiteOnTheSameTableReusesIt() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 0f 82 00 1f 82 00 00 00 00", false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		builder.setBytes("0x8040", WORD_FIRST, false);
		builder.disassemble("0x8040", 13, false);
		Address rtl2 = addr(0x804c);
		W65816RtlTrickAnalyzer analyzer = new W65816RtlTrickAnalyzer();
		inTx(program, "analyze2", () -> analyzer.added(program,
			new AddressSet(addr(0x8040), rtl2), TaskMonitor.DUMMY, new MessageLog()));
		assertTargets(rtl2, 0x8200, 0x8210, 0x8220);
		assertRecords(0x8100, 3, 3);
	}

	@Test
	public void aTableStopsAtAnotherDispatchsFirstRecord() throws Exception {
		// Site A's table is 3 records, then plausible records that are site B's table at $8109.
		builder.setBytes("0x8100",
			"ff 81 00 0f 82 00 1f 82 00 2f 82 00 3f 82 00 00 00 00", false);
		Address rtlA = dispatcher(WORD_FIRST);
		builder.setBytes("0x8040", "e2 20 bd 0b 81 48 c2 20 bd 09 81 48 6b", false);
		builder.disassemble("0x8040", 13, false);
		Address rtlB = addr(0x804c);
		W65816RtlTrickAnalyzer analyzer = new W65816RtlTrickAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program, new AddressSet(addr(0x8000), rtlB),
			TaskMonitor.DUMMY, new MessageLog()));
		assertTargets(rtlA, 0x8200, 0x8210, 0x8220);
		assertTargets(rtlB, 0x8230, 0x8240);
		assertRecords(0x8100, 3, 3);
		assertRecords(0x8109, 2, 3);
	}

	/** ABC Monday Night Football $82BE: sparse records, $FFFF (offset 0 after the +1) marks a free slot. */
	@Test
	public void unusedSlotsAreKeptInTheArrayButGetNoTargetOrReference() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 ff ff 00 ff ff 00 0f 82 00 1f 82 00 ff ff 00 00 00 00",
			false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		assertTargets(rtl, 0x8200, 0x8210, 0x8220);
		assertRecords(0x8100, 5, 3);   // the trailing free slot is dropped
		assertTrue(program.getReferenceManager().getReferencesFrom(addr(0x8103)).length == 0);
		assertEquals(1, program.getReferenceManager().getReferencesFrom(addr(0x8109)).length);
	}

	@Test
	public void singleRecordIsDeclined() throws Exception {
		builder.setBytes("0x8100", "ff 81 00 00 00 00", false);
		Address rtl = dispatcher(WORD_FIRST);
		analyze(rtl);
		assertTrue(jumpTargets(rtl).isEmpty());
	}

	@Test
	public void ramTableDeclines() throws Exception {
		assertNull(recognize(dispatcher("e2 20 bd 02 01 48 c2 20 bd 00 01 48 6b")));
	}

	@Test
	public void mismatchedIndexRegistersDecline() throws Exception {
		assertNull(recognize(dispatcher("e2 20 bd 02 81 48 c2 20 b9 00 81 48 6b")));
	}

	@Test
	public void operandsNotOneRecordApartDecline() throws Exception {
		assertNull(recognize(dispatcher("e2 20 bd 05 81 48 c2 20 bd 00 81 48 6b")));
	}

	@Test
	public void stackOpBetweenThePushesDeclines() throws Exception {
		assertNull(recognize(dispatcher("e2 20 bd 02 81 48 da c2 20 bd 00 81 48 6b")));
	}

	@Test
	public void eightBitWordPushDeclines() throws Exception {
		assertNull(recognize(dispatcher("e2 20 bd 02 81 48 bd 00 81 48 6b")));
	}

	@Test
	public void joinIntoTheWindowDeclines() throws Exception {
		Address rtl = dispatcher(WORD_FIRST);
		branchTo(0x8008);   // the word load
		assertNull(recognize(rtl));
	}

	@Test
	public void joinIntoTheBankPushDeclines() throws Exception {
		Address rtl = dispatcher(WORD_FIRST);
		branchTo(0x8005);
		assertNull(recognize(rtl));
	}

	@Test
	public void joinIntoTheBankLoadOrTheReturnStillResolves() throws Exception {
		Address rtl = dispatcher(WORD_FIRST);
		branchTo(0x8002);
		assertNotNull(recognize(rtl));
	}

	@Test
	public void rtsIsNotMatched() throws Exception {
		assertNull(recognize(dispatcher("e2 20 bd 02 81 48 c2 20 bd 00 81 48 60")));
	}
}
