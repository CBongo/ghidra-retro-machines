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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * {@link TwoLevelPointerDispatch} / {@link TwoLevelPointerDispatchAnalyzer} (grm-gipk.23)
 * against a SYNTHETIC dispatcher in cv3 bank 20's shape -- hand-built, no ROM bytes copied:
 *
 * <pre>
 *   8000  LDA $07c2,X / ASL / TAY / LDA T,Y / STA $00 / LDA T+1,Y / STA $01
 *         LDA $07c8,X / AND #$03 / ASL / TAY
 *         LDA ($00),Y / STA $02 / INY / LDA ($00),Y / STA $03
 *         JMP ($0002)
 *   T:    IA IB                       ; outer: ends at IA, the lowest inner table above it
 *   IA:   H1 H2                       ; ends where IB begins
 *   IB:   H3 H4 H5 H6 H7              ; AND #$03 caps it at 4: H7 is never claimed
 *   8200  handlers, NOP / RTS each
 * </pre>
 */
public class TwoLevelPointerDispatchTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long BASE = 0x8000;
	private static final long H1 = 0x8200;
	private static final long FAR = 0xc000;
	/** NO_CAP's repeated handler: more than 128 words above its table, so nothing ends it. */
	private static final long FAR_HANDLER = 0xb000;

	private enum Variant {
		BASELINE,
		/** Negative: T is the dispatch's own code (TMNT2/conflict-style hit). */
		TABLE_IN_CODE,
		/** Negative: every outer word points into another memory block (out of bank). */
		OUT_OF_BANK_OUTER,
		/** Negative: no AND cap and a run of plausible words nothing ends within 128. */
		NO_CAP
	}

	private ProgramBuilder builder;
	private long jmpAt;
	private long tableAt;
	private long innerA;
	private long innerB;

	private Address addr(long offset) {
		return builder.addr(hex(offset));
	}

	private static String bytes(List<Integer> b) {
		StringBuilder sb = new StringBuilder();
		for (int v : b) {
			sb.append(String.format("%02x ", v & 0xff));
		}
		return sb.toString().trim();
	}

	private static void word(List<Integer> b, long w) {
		b.add((int) (w & 0xff));
		b.add((int) ((w >> 8) & 0xff));
	}

	private ProgramDB build(Variant v) throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory(".rom", hex(BASE), 0x4000); // ROM: reports non-writable
		builder.createMemory(".fixed", hex(FAR), 0x4000);

		// Code is 34 bytes from BASE; the JMP is its last 3.
		long codeLen = 34;
		jmpAt = BASE + codeLen - 3;
		// TABLE_IN_CODE: T is the JMP's own operand, as in the survey's TMNT2 hits.
		tableAt = v == Variant.TABLE_IN_CODE ? jmpAt + 1 : BASE + codeLen;
		long outerAt = BASE + codeLen; // where the outer words physically sit
		innerA = outerAt + 4;
		innerB = innerA + 4;

		List<Integer> c = new ArrayList<>();
		c.addAll(List.of(0xbd, 0xc2, 0x07, 0x0a, 0xa8)); // LDA $07c2,X / ASL / TAY
		c.add(0xb9); word(c, tableAt); c.addAll(List.of(0x85, 0x00)); // LDA T,Y / STA $00
		c.add(0xb9); word(c, tableAt + 1); c.addAll(List.of(0x85, 0x01)); // LDA T+1,Y / STA $01
		c.addAll(List.of(0xbd, 0xc8, 0x07)); // LDA $07c8,X
		if (v == Variant.NO_CAP) {
			c.addAll(List.of(0xea, 0xea)); // NOP / NOP in place of AND #$03
		}
		else {
			c.addAll(List.of(0x29, 0x03)); // AND #$03
		}
		c.addAll(List.of(0x0a, 0xa8)); // ASL / TAY
		c.addAll(List.of(0xb1, 0x00, 0x85, 0x02, 0xc8, 0xb1, 0x00, 0x85, 0x03)); // inner pair
		c.addAll(List.of(0x6c, 0x02, 0x00)); // JMP ($0002)
		assertEquals(codeLen, c.size());
		builder.setBytes(hex(BASE), bytes(c), true);

		List<Integer> t = new ArrayList<>();
		if (v == Variant.OUT_OF_BANK_OUTER) {
			word(t, FAR);
			word(t, FAR + 4);
		}
		else {
			word(t, innerA);
			word(t, innerB);
		}
		word(t, H1);
		word(t, H1 + 2);
		if (v == Variant.NO_CAP) {
			for (int i = 0; i < 130; i++) {
				word(t, FAR_HANDLER); // never ends: no cap, nothing above it, all plausible
			}
		}
		else {
			for (int i = 2; i < 7; i++) {
				word(t, H1 + 2L * i);
			}
		}
		builder.setBytes(hex(outerAt), bytes(t), false);
		// handlers: NOP / RTS each, 2 bytes apart
		List<Integer> h = new ArrayList<>();
		for (int i = 0; i < 8; i++) {
			h.addAll(List.of(0xea, 0x60));
		}
		builder.setBytes(hex(H1), bytes(h), false);
		builder.setBytes(hex(FAR_HANDLER), "ea 60", false);
		// the out-of-bank variant's would-be inner tables, so only the bank rule declines it
		List<Integer> far = new ArrayList<>();
		word(far, H1);
		word(far, H1 + 2);
		word(far, H1 + 4);
		builder.setBytes(hex(FAR), bytes(far), false);
		return builder.getProgram();
	}

	private void run(ProgramDB program) throws Exception {
		TwoLevelPointerDispatchAnalyzer analyzer = new TwoLevelPointerDispatchAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(addr(BASE), addr(BASE + 0x40)),
				TaskMonitor.DUMMY, new MessageLog());
		});
	}

	private Set<Address> computedTargets(ProgramDB program) {
		Instruction jmp = program.getListing().getInstructionAt(addr(jmpAt));
		assertNotNull(jmp);
		Set<Address> out = new LinkedHashSet<>();
		for (Reference ref : jmp.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				assertEquals(RefType.COMPUTED_JUMP, ref.getReferenceType());
				out.add(ref.getToAddress());
			}
		}
		return out;
	}

	private Set<Address> handlers(int from, int to) {
		Set<Address> s = new LinkedHashSet<>();
		for (int i = from; i < to; i++) {
			s.add(addr(H1 + 2L * i));
		}
		return s;
	}

	@Test
	public void resolvesBothLevelsAndDisassemblesHandlers() throws Exception {
		ProgramDB program = build(Variant.BASELINE);
		run(program);
		assertEquals(handlers(0, 6), computedTargets(program));
		for (Address a : handlers(0, 6)) {
			assertNotNull("handler " + a + " disassembled", program.getListing().getInstructionAt(a));
		}
		assertNotNull("outer table laid", program.getListing().getDefinedDataAt(addr(tableAt)));
		assertNotNull("inner table A laid", program.getListing().getDefinedDataAt(addr(innerA)));
		assertNotNull("inner table B laid", program.getListing().getDefinedDataAt(addr(innerB)));
	}

	@Test
	public void boundsEachLevelByItsRule() throws Exception {
		ProgramDB program = build(Variant.BASELINE);
		TwoLevelPointerDispatch.Shape shape = TwoLevelPointerDispatch.match(program,
			program.getListing().getInstructionAt(addr(jmpAt)));
		assertNotNull(shape);
		assertEquals(addr(tableAt), shape.outer());
		assertEquals(Integer.valueOf(4), shape.innerCap());
		assertNull("outer index comes from an unmasked type", shape.outerCap());
		TwoLevelPointerDispatch.Resolution r = TwoLevelPointerDispatch.resolve(program, shape);
		assertNull(r.declined());
		assertEquals(List.of(addr(innerA), addr(innerB)), r.outer().entries());
		assertEquals(TwoLevelPointerDispatch.Cut.ABOVE_TABLE_TARGET, r.outer().cut());
		TwoLevelPointerDispatch.Table a = r.inner().get(addr(innerA));
		assertEquals(List.of(addr(H1), addr(H1 + 2)), a.entries());
		assertEquals(TwoLevelPointerDispatch.Cut.NEXT_TABLE, a.cut());
		TwoLevelPointerDispatch.Table b = r.inner().get(addr(innerB));
		assertEquals(List.copyOf(handlers(2, 6)), b.entries());
		assertEquals("AND #$03 caps the inner table at 4 entries",
			TwoLevelPointerDispatch.Cut.INDEX_CAP, b.cut());
	}

	@Test
	public void andCapKeepsTheFifthHandlerUnclaimed() throws Exception {
		ProgramDB program = build(Variant.BASELINE);
		run(program);
		assertTrue(!computedTargets(program).contains(addr(H1 + 12)));
		assertNull("H7 is never disassembled", program.getListing().getInstructionAt(addr(H1 + 12)));
	}

	@Test
	public void declinesWhenTableIsTheDispatchCode() throws Exception {
		assertDeclined(Variant.TABLE_IN_CODE);
	}

	@Test
	public void declinesOutOfBankOuterWords() throws Exception {
		assertDeclined(Variant.OUT_OF_BANK_OUTER);
	}

	@Test
	public void declinesUnboundedInnerTableWithoutCap() throws Exception {
		ProgramDB program = build(Variant.NO_CAP);
		TwoLevelPointerDispatch.Shape shape = TwoLevelPointerDispatch.match(program,
			program.getListing().getInstructionAt(addr(jmpAt)));
		assertNotNull(shape);
		assertNull(shape.innerCap());
		run(program);
		// IA still ends at IB, but IB runs on with nothing to end it: only IA's handlers count.
		assertEquals(handlers(0, 2), computedTargets(program));
	}

	private void assertDeclined(Variant v) throws Exception {
		ProgramDB program = build(v);
		run(program);
		assertEquals(Set.of(), computedTargets(program));
		assertNull(program.getListing().getInstructionAt(addr(H1)));
	}
}
