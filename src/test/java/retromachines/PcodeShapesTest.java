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
import java.util.List;
import java.util.OptionalInt;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * {@link PcodeShapes} and {@link CpuRegs} over real decoded bytes (bead grm-jjuc, wave 0): stock
 * {@code 6502}, bundled {@code 6510} and {@code 6502:undoc}, {@code 65816} (native 16-bit, native
 * 8-bit and emulation via the context fields) and {@code SPC700}. Each test decodes ONE instruction.
 */
public class PcodeShapesTest extends AbstractBundledLanguageTest {

	private static final String L6502 = "6502:LE:16:default";
	private static final String L6510 = "6510:LE:16:default";
	private static final String LUNDOC = "6502:LE:16:undoc";
	private static final String L65816 = "65816:LE:24:retro";
	private static final String LSPC = "SPC700:LE:16:retro";

	private Instruction ins(String lang, String bytes) throws Exception {
		return ins(lang, bytes, -1, -1, -1);
	}

	/** {@code ef/mf/xf < 0} leaves the 65816 context at its default. */
	private Instruction ins(String lang, String bytes, int ef, int mf, int xf) throws Exception {
		ProgramBuilder b = newBuilder("T", lang);
		b.createMemory(".ram", "0x0", 0x10000);
		b.setBytes("0x0200", bytes, false);
		int[] vals = { ef, mf, xf };
		String[] names = { "ctx_EF", "ctx_MF", "ctx_XF" };
		for (int k = 0; k < 3; k++) {
			if (vals[k] >= 0) {
				Register r = b.getProgram().getLanguage().getRegister(names[k]);
				int tx = b.getProgram().startTransaction("ctx");
				b.getProgram().getProgramContext().setValue(r, b.addr("0x0200"), b.addr("0x02ff"),
					BigInteger.valueOf(vals[k]));
				b.getProgram().endTransaction(tx, true);
			}
		}
		b.disassemble("0x0200", bytes.split(" ").length, true);
		Instruction i = b.getProgram().getListing().getInstructionAt(b.addr("0x0200"));
		assertNotNull("did not disassemble: " + bytes, i);
		return i;
	}

	private static CpuRegs regs(Instruction i) {
		return CpuRegs.of(i.getProgram().getLanguage());
	}

	private static void assertDelta(int expected, Instruction i) {
		assertEquals(i.toString(), OptionalInt.of(expected),
			PcodeShapes.netStackDelta(i, regs(i)));
	}

	private static void assertBranch(Instruction i, CpuRegs.FlagKind kind, boolean whenSet) {
		PcodeShapes.FlagBranch fb = PcodeShapes.branchOnFlag(i);
		assertNotNull(i.toString(), fb);
		assertEquals(i.toString(), kind, fb.kind());
		assertEquals(i.toString(), whenSet, fb.takenWhenSet());
	}

	// ------------------------------------------------------------------ CpuRegs

	@Test
	public void cpuRegsResolvesRolesPerFamily() throws Exception {
		CpuRegs r = regs(ins(L6502, "ea"));
		assertEquals("A", r.acc().getName());
		assertNull("6502 has no wide accumulator (C is the carry flag)", r.accWide());
		assertEquals("C", r.carry().reg().getName());
		assertEquals("SP", r.sp().getName());
		assertNull(r.psw());
		assertTrue(r.ioPorts().isEmpty());

		CpuRegs r10 = regs(ins(L6510, "ea"));
		assertEquals(2, r10.ioPorts().size());

		CpuRegs r16 = regs(ins(L65816, "ea"));
		assertEquals("C is the 65816 16-bit accumulator", "C", r16.accWide().getName());
		assertEquals("A", r16.acc().getName());
		assertEquals("CF", r16.carry().reg().getName());
		assertEquals("XLow", r16.xLow().getName());
		assertNotNull(r16.decimal());

		CpuRegs spc = regs(ins(LSPC, "00"));
		assertEquals("PSW", spc.psw().getName());
		assertEquals(0, spc.carry().bit());
		assertEquals(7, spc.negative().bit());
		assertNull("SPC700 has no decimal flag", spc.decimal());
		assertNull(spc.xLow());
	}

	// ------------------------------------------------------------------ 6502 stack

	@Test
	public void stackOps6502() throws Exception {
		Instruction pha = ins(L6502, "48");
		assertDelta(-1, pha);
		assertEquals(regs(pha).acc(), PcodeShapes.pushedRegister(pha));
		assertNull("a push is not a memory store", PcodeShapes.storeSource(pha));
		assertFalse(PcodeShapes.writesMemory(pha));

		Instruction pla = ins(L6502, "68");
		assertDelta(1, pla);
		assertEquals(regs(pla).acc(), PcodeShapes.pulledRegister(pla));
		assertNull("a pull is not a memory load", PcodeShapes.loadDestination(pla));
		assertTrue(PcodeShapes.writesRegister(pla, regs(pla).acc()));

		Instruction php = ins(L6502, "08");
		assertDelta(-1, php);
		assertNull("PHP pushes a computed status byte", PcodeShapes.pushedRegister(php));
		Instruction plp = ins(L6502, "28");
		assertDelta(1, plp);
		assertNull(PcodeShapes.pulledRegister(plp));

		Instruction jsr = ins(L6502, "20 00 10");
		assertDelta(-2, jsr);
		assertNull(PcodeShapes.pushedRegister(jsr));
		assertFalse("JSR is not a write of A", PcodeShapes.writesRegister(jsr, regs(jsr).acc()));
		assertFalse(PcodeShapes.writesRegister(jsr, regs(jsr).x()));
		assertFalse(PcodeShapes.isReturnOp(jsr));

		Instruction rts = ins(L6502, "60");
		assertDelta(2, rts);
		assertTrue(PcodeShapes.isReturnOp(rts));
		assertNull(PcodeShapes.pulledRegister(rts));
		assertDelta(3, ins(L6502, "40"));
	}

	@Test
	public void transfers6502() throws Exception {
		Instruction tax = ins(L6502, "aa");
		CpuRegs r = regs(tax);
		assertEquals(r.acc(), PcodeShapes.copySource(tax, r.x()));
		assertNull(PcodeShapes.copySource(tax, r.acc()));
		assertTrue(PcodeShapes.readsRegister(tax, r.acc()));
		assertFalse(PcodeShapes.readsRegister(tax, r.x()));
		assertTrue(PcodeShapes.writesRegister(tax, r.x()));
		assertFalse(PcodeShapes.writesRegister(tax, r.acc()));

		Instruction txa = ins(L6502, "8a");
		assertEquals(r.x(), PcodeShapes.copySource(txa, r.acc()));
		Instruction tya = ins(L6502, "98");
		assertEquals(r.y(), PcodeShapes.copySource(tya, r.acc()));

		Instruction tsx = ins(L6502, "ba");
		assertEquals("S", PcodeShapes.copySource(tsx, r.x()).getName());
		assertDelta(0, tsx);

		Instruction txs = ins(L6502, "9a");
		assertEquals("TXS writes SP non-constantly", OptionalInt.empty(),
			PcodeShapes.netStackDelta(txs, r));
		assertEquals(r.x(), PcodeShapes.copySource(txs, r.spViews().get(0)));
		assertFalse(PcodeShapes.writesRegister(txs, r.x()));
	}

	@Test
	public void loadsAndConstants6502() throws Exception {
		Instruction imm = ins(L6502, "a9 05");
		CpuRegs r = regs(imm);
		assertEquals(Long.valueOf(5), PcodeShapes.constantInto(imm, r.acc()));
		assertNull(PcodeShapes.loadDestination(imm));
		assertNull(PcodeShapes.copySource(imm, r.acc()));
		assertFalse(PcodeShapes.readsRegister(imm, r.acc()));

		Instruction abs = ins(L6502, "ad 00 90");
		assertEquals(r.acc(), PcodeShapes.loadDestination(abs));
		assertNull(PcodeShapes.constantInto(abs, r.acc()));

		Instruction ind = ins(L6502, "b1 12");
		assertEquals(r.acc(), PcodeShapes.loadDestination(ind));
		assertTrue(PcodeShapes.readsRegister(ind, r.y()));

		Instruction ldx = ins(L6502, "a6 12");
		assertEquals(r.x(), PcodeShapes.loadDestination(ldx));

		Instruction sec = ins(L6502, "38");
		assertEquals(Long.valueOf(1), PcodeShapes.constantInto(sec, r.carry().reg()));
		Instruction clc = ins(L6502, "18");
		assertEquals(Long.valueOf(0), PcodeShapes.constantInto(clc, r.carry().reg()));

		Instruction adc = ins(L6502, "6d 00 90");
		assertNull("ADC computes; it does not load", PcodeShapes.loadDestination(adc));
		assertTrue(PcodeShapes.writesRegister(adc, r.acc()));
	}

	@Test
	public void stores6502() throws Exception {
		Instruction sta = ins(L6502, "8d 00 90");
		CpuRegs r = regs(sta);
		assertEquals(r.acc(), PcodeShapes.storeSource(sta));
		List<Address> w = PcodeShapes.memoryWrites(sta);
		assertEquals(1, w.size());
		assertEquals(0x9000, w.get(0).getOffset());
		assertFalse("fixed-address store has no STORE op", PcodeShapes.hasComputedStore(sta));
		assertTrue(PcodeShapes.writesMemory(sta));
		assertFalse(PcodeShapes.writesRegister(sta, r.acc()));

		Instruction stx = ins(L6502, "86 12");
		assertEquals(r.x(), PcodeShapes.storeSource(stx));
		Instruction sty = ins(L6502, "84 12");
		assertEquals(r.y(), PcodeShapes.storeSource(sty));

		Instruction ind = ins(L6502, "91 12");
		assertEquals(r.acc(), PcodeShapes.storeSource(ind));
		assertTrue(PcodeShapes.hasComputedStore(ind));
		assertTrue(PcodeShapes.memoryWrites(ind).isEmpty());

		Instruction inc = ins(L6502, "e6 12");
		assertNull("INC zp is read-modify-write, not a register store", PcodeShapes.storeSource(inc));
		assertEquals(1, PcodeShapes.memoryWrites(inc).size());
	}

	@Test
	public void shiftsAndIncrements6502() throws Exception {
		Instruction asl = ins(L6502, "0a");
		CpuRegs r = regs(asl);
		assertTrue(PcodeShapes.shiftLeftBy1(asl, r.acc()));
		assertTrue(PcodeShapes.writesRegister(asl, r.acc()));
		Instruction aslMem = ins(L6502, "06 12");
		assertFalse(PcodeShapes.shiftLeftBy1(aslMem, r.acc()));
		assertFalse("ASL zp leaves A alone", PcodeShapes.writesRegister(aslMem, r.acc()));
		assertEquals(1, PcodeShapes.memoryWrites(aslMem).size());
		assertFalse("ROL is not a plain shift", PcodeShapes.shiftLeftBy1(ins(L6502, "2a"), r.acc()));
		assertFalse(PcodeShapes.shiftLeftBy1(ins(L6502, "4a"), r.acc()));

		Instruction inx = ins(L6502, "e8");
		assertEquals(Integer.valueOf(1), PcodeShapes.incrementOf(inx, r.x()));
		assertNull(PcodeShapes.incrementOf(inx, r.y()));
		assertTrue(PcodeShapes.readsRegister(inx, r.x()));
		assertEquals(Integer.valueOf(-1), PcodeShapes.incrementOf(ins(L6502, "88"), r.y()));
		assertEquals(Integer.valueOf(-1), PcodeShapes.incrementOf(ins(L6502, "ca"), r.x()));
		assertNull(PcodeShapes.incrementOf(ins(L6502, "e6 12"), r.acc()));
		assertNull(PcodeShapes.incrementOf(ins(L6502, "aa"), r.x()));
	}

	@Test
	public void branches6502() throws Exception {
		assertBranch(ins(L6502, "f0 05"), CpuRegs.FlagKind.ZERO, true);
		assertBranch(ins(L6502, "d0 05"), CpuRegs.FlagKind.ZERO, false);
		assertBranch(ins(L6502, "b0 05"), CpuRegs.FlagKind.CARRY, true);
		assertBranch(ins(L6502, "90 05"), CpuRegs.FlagKind.CARRY, false);
		assertBranch(ins(L6502, "30 05"), CpuRegs.FlagKind.NEGATIVE, true);
		assertBranch(ins(L6502, "10 05"), CpuRegs.FlagKind.NEGATIVE, false);
		assertBranch(ins(L6502, "70 05"), CpuRegs.FlagKind.OVERFLOW, true);
		assertBranch(ins(L6502, "50 05"), CpuRegs.FlagKind.OVERFLOW, false);
		assertNull(PcodeShapes.branchOnFlag(ins(L6502, "4c 00 10")));
		assertNull(PcodeShapes.branchOnFlag(ins(L6502, "ea")));
	}

	@Test
	public void reads6502() throws Exception {
		Instruction cmp = ins(L6502, "c9 01");
		CpuRegs r = regs(cmp);
		assertTrue(PcodeShapes.readsRegister(cmp, r.acc()));
		assertFalse("CMP writes flags only", PcodeShapes.writesRegister(cmp, r.acc()));
		assertTrue(PcodeShapes.writesRegister(cmp, r.carry().reg()));
		Instruction nop = ins(L6502, "ea");
		assertTrue(PcodeShapes.memoryWrites(nop).isEmpty());
		assertFalse(PcodeShapes.writesRegister(nop, r.acc()));
		assertDelta(0, nop);
	}

	// ------------------------------------------------------------------ 6510 / undoc

	@Test
	public void portRegister6510() throws Exception {
		Instruction sta = ins(L6510, "85 01");
		CpuRegs r = regs(sta);
		Register port = sta.getProgram().getLanguage().getRegister("PORT");
		assertTrue("the port is a register write", PcodeShapes.writesRegister(sta, port));
		assertEquals("and a memory-mapped store of A", r.acc(), PcodeShapes.storeSource(sta));
		assertEquals(1, PcodeShapes.memoryWrites(sta).size());
		assertFalse(PcodeShapes.writesRegister(sta, r.acc()));

		Instruction lda = ins(L6510, "a5 01");
		assertEquals(r.acc(), PcodeShapes.loadDestination(lda));
		assertTrue(PcodeShapes.readsRegister(lda, port));
	}

	@Test
	public void undocumentedOpcodesAreCovered() throws Exception {
		Instruction lax = ins(LUNDOC, "a7 12");
		CpuRegs r = regs(lax);
		assertTrue(PcodeShapes.writesRegister(lax, r.acc()));
		assertTrue(PcodeShapes.writesRegister(lax, r.x()));
		assertFalse(PcodeShapes.writesRegister(lax, r.y()));
	}

	// ------------------------------------------------------------------ 65816

	@Test
	public void stack65816() throws Exception {
		CpuRegs r = regs(ins(L65816, "ea"));
		// native, M=0 X=0: 16-bit
		Instruction pha16 = ins(L65816, "48", 0, 0, 0);
		assertDelta(-2, pha16);
		assertEquals("16-bit PHA pushes C", r.accWide(), PcodeShapes.pushedRegister(pha16));
		Instruction pla16 = ins(L65816, "68", 0, 0, 0);
		assertDelta(2, pla16);
		assertEquals(r.accWide(), PcodeShapes.pulledRegister(pla16));
		Instruction phx16 = ins(L65816, "da", 0, 0, 0);
		assertDelta(-2, phx16);
		assertEquals(r.x(), PcodeShapes.pushedRegister(phx16));
		assertEquals(r.x(), PcodeShapes.pulledRegister(ins(L65816, "fa", 0, 0, 0)));

		// native, M=1 X=1: 8-bit
		Instruction pha8 = ins(L65816, "48", 0, 1, 1);
		assertDelta(-1, pha8);
		assertEquals(r.acc(), PcodeShapes.pushedRegister(pha8));
		assertDelta(1, ins(L65816, "68", 0, 1, 1));

		// emulation: only SPLow moves
		Instruction pha = ins(L65816, "48", 1, 1, 1);
		assertDelta(-1, pha);
		assertEquals(r.acc(), PcodeShapes.pushedRegister(pha));
		assertDelta(1, ins(L65816, "68", 1, 1, 1));

		assertDelta(-2, ins(L65816, "20 00 10", 0, 1, 1));
		assertDelta(-3, ins(L65816, "22 00 10 01", 0, 1, 1));
		Instruction rtl = ins(L65816, "6b", 0, 1, 1);
		assertDelta(3, rtl);
		assertTrue(PcodeShapes.isReturnOp(rtl));
		assertDelta(2, ins(L65816, "60", 0, 1, 1));
		assertDelta(-2, ins(L65816, "f4 00 10", 0, 1, 1));
		assertEquals("TCS sets SP from C", OptionalInt.empty(),
			PcodeShapes.netStackDelta(ins(L65816, "1b", 0, 1, 1), r));

		Instruction phb = ins(L65816, "8b", 0, 1, 1);
		assertEquals("DBR", PcodeShapes.pushedRegister(phb).getName());
		assertEquals("DBR", PcodeShapes.pulledRegister(ins(L65816, "ab", 0, 1, 1)).getName());
		assertNull("PLP pulls flags only", PcodeShapes.pulledRegister(ins(L65816, "28", 0, 1, 1)));
	}

	@Test
	public void transfersAndFlags65816() throws Exception {
		Instruction tax16 = ins(L65816, "aa", 0, 0, 0);
		CpuRegs r = regs(tax16);
		assertEquals("16-bit TAX copies C", r.accWide(), PcodeShapes.copySource(tax16, r.x()));
		Instruction tax8 = ins(L65816, "aa", 0, 1, 1);
		assertEquals(r.acc(), PcodeShapes.copySource(tax8, r.xLow()));
		assertEquals(r.y(), PcodeShapes.copySource(ins(L65816, "bb", 0, 0, 0), r.x()));
		Instruction txy = ins(L65816, "9b", 0, 0, 0);
		assertEquals(r.x(), PcodeShapes.copySource(txy, r.y()));

		Instruction xba = ins(L65816, "eb", 0, 1, 1);
		Register b = xba.getProgram().getLanguage().getRegister("B");
		assertEquals("XBA swaps through a temp", b, PcodeShapes.copySource(xba, r.acc()));
		assertEquals(r.acc(), PcodeShapes.copySource(xba, b));

		Instruction lda8 = ins(L65816, "a9 01", 0, 1, 1);
		assertEquals(Long.valueOf(1), PcodeShapes.constantInto(lda8, r.acc()));
		Instruction inc16 = ins(L65816, "1a", 0, 0, 0);
		assertEquals(Integer.valueOf(1), PcodeShapes.incrementOf(inc16, r.accWide()));
		assertTrue("16-bit INC writes the 8-bit alias A too",
			PcodeShapes.writesRegister(inc16, r.acc()));
		assertBranch(ins(L65816, "f0 05", 0, 1, 1), CpuRegs.FlagKind.ZERO, true);
		assertBranch(ins(L65816, "d0 05", 0, 1, 1), CpuRegs.FlagKind.ZERO, false);
		assertBranch(ins(L65816, "b0 05", 0, 1, 1), CpuRegs.FlagKind.CARRY, true);
		assertBranch(ins(L65816, "10 05", 0, 1, 1), CpuRegs.FlagKind.NEGATIVE, false);
		assertNull("BRA is unconditional", PcodeShapes.branchOnFlag(ins(L65816, "80 05", 0, 1, 1)));
		assertTrue(PcodeShapes.shiftLeftBy1(ins(L65816, "0a", 0, 1, 1), r.acc()));
	}

	// ------------------------------------------------------------------ SPC700

	@Test
	public void stackSpc700() throws Exception {
		Instruction push = ins(LSPC, "2d");
		CpuRegs r = regs(push);
		assertDelta(-1, push);
		assertEquals(r.acc(), PcodeShapes.pushedRegister(push));
		assertFalse("a push is not a memory store", PcodeShapes.hasComputedStore(push));
		assertNull(PcodeShapes.storeSource(push));

		Instruction pop = ins(LSPC, "ae");
		assertDelta(1, pop);
		assertEquals(r.acc(), PcodeShapes.pulledRegister(pop));
		assertNull(PcodeShapes.loadDestination(pop));
		assertEquals(r.x(), PcodeShapes.pushedRegister(ins(LSPC, "4d")));
		assertNull("POP PSW pulls flags", PcodeShapes.pulledRegister(ins(LSPC, "8e")));

		Instruction ret = ins(LSPC, "6f");
		assertDelta(2, ret);
		assertTrue(PcodeShapes.isReturnOp(ret));
		assertDelta(3, ins(LSPC, "7f"));
		assertDelta(-2, ins(LSPC, "3f 00 10"));
		assertEquals("MOV SP,X", OptionalInt.empty(),
			PcodeShapes.netStackDelta(ins(LSPC, "bd"), r));
	}

	@Test
	public void movesSpc700() throws Exception {
		Instruction movXA = ins(LSPC, "5d");
		CpuRegs r = regs(movXA);
		assertEquals(r.acc(), PcodeShapes.copySource(movXA, r.x()));
		Instruction movXSp = ins(LSPC, "9d");
		assertEquals(r.sp(), PcodeShapes.copySource(movXSp, r.x()));

		Instruction imm = ins(LSPC, "e8 07");
		assertEquals(Long.valueOf(7), PcodeShapes.constantInto(imm, r.acc()));
		assertNull(PcodeShapes.loadDestination(imm));

		Instruction ld = ins(LSPC, "e4 12");
		assertEquals(r.acc(), PcodeShapes.loadDestination(ld));
		assertNull(PcodeShapes.copySource(ld, r.acc()));

		Instruction st = ins(LSPC, "c4 12");
		assertEquals(r.acc(), PcodeShapes.storeSource(st));
		assertTrue("direct-page access goes through a computed address",
			PcodeShapes.hasComputedStore(st));
		assertFalse(PcodeShapes.writesRegister(st, r.acc()));

		Instruction inc = ins(LSPC, "bc");
		assertEquals(Integer.valueOf(1), PcodeShapes.incrementOf(inc, r.acc()));
		assertTrue(PcodeShapes.shiftLeftBy1(ins(LSPC, "1c"), r.acc()));
		assertEquals(Integer.valueOf(-1), PcodeShapes.incrementOf(ins(LSPC, "9c"), r.acc()));
	}

	@Test
	public void branchesSpc700() throws Exception {
		assertBranch(ins(LSPC, "f0 05"), CpuRegs.FlagKind.ZERO, true);
		assertBranch(ins(LSPC, "d0 05"), CpuRegs.FlagKind.ZERO, false);
		assertBranch(ins(LSPC, "b0 05"), CpuRegs.FlagKind.CARRY, true);
		assertBranch(ins(LSPC, "90 05"), CpuRegs.FlagKind.CARRY, false);
		assertBranch(ins(LSPC, "30 05"), CpuRegs.FlagKind.NEGATIVE, true);
		assertBranch(ins(LSPC, "10 05"), CpuRegs.FlagKind.NEGATIVE, false);
		assertBranch(ins(LSPC, "70 05"), CpuRegs.FlagKind.OVERFLOW, true);
		assertBranch(ins(LSPC, "50 05"), CpuRegs.FlagKind.OVERFLOW, false);
	}

	@Test
	public void bitOpsShiftsAndRmw6502() throws Exception {
		Instruction and = ins(L6502, "29 0f");
		CpuRegs r = regs(and);
		assertEquals(PcodeOp.INT_AND, PcodeShapes.bitOpOn(and, r.acc()));
		assertEquals(PcodeOp.INT_OR, PcodeShapes.bitOpOn(ins(L6502, "0d 00 90"), r.acc()));
		assertEquals(PcodeOp.INT_XOR, PcodeShapes.bitOpOn(ins(L6502, "49 01"), r.acc()));
		assertEquals(-1, PcodeShapes.bitOpOn(ins(L6502, "a9 01"), r.acc()));
		assertEquals(-1, PcodeShapes.bitOpOn(ins(L6502, "69 01"), r.acc()));

		assertTrue(PcodeShapes.shiftRightBy1(ins(L6502, "4a"), r.acc()));
		assertFalse("memory LSR writes no A",
			PcodeShapes.shiftRightBy1(ins(L6502, "46 12"), r.acc()));
		assertFalse("ROR is not a plain shift",
			PcodeShapes.shiftRightBy1(ins(L6502, "6a"), r.acc()));
		assertFalse(PcodeShapes.shiftRightBy1(ins(L6502, "0a"), r.acc()));

		assertEquals(Integer.valueOf(1), PcodeShapes.rmwIncrement(ins(L6502, "ee 00 90")));
		assertEquals(Integer.valueOf(-1), PcodeShapes.rmwIncrement(ins(L6502, "c6 12")));
		assertEquals(Integer.valueOf(1), PcodeShapes.rmwIncrement(ins(L6502, "fe 00 90")));
		assertNull(PcodeShapes.rmwIncrement(ins(L6502, "e8")));
		assertNull(PcodeShapes.rmwIncrement(ins(L6502, "8d 00 90")));
		assertNull(PcodeShapes.rmwIncrement(ins(L6502, "0e 00 90")));
	}

	@Test
	public void mosOperandsStackAndLoads6502() throws Exception {
		assertEquals(MosOperands.StackOp.PUSH_A, MosOperands.stackOp(ins(L6502, "48")));
		assertEquals(MosOperands.StackOp.PUSH_STATUS, MosOperands.stackOp(ins(L6502, "08")));
		assertEquals(MosOperands.StackOp.PULL_A, MosOperands.stackOp(ins(L6502, "68")));
		assertEquals(MosOperands.StackOp.PULL_STATUS, MosOperands.stackOp(ins(L6502, "28")));
		assertEquals(MosOperands.StackOp.NONE, MosOperands.stackOp(ins(L6502, "60")));
		assertEquals(MosOperands.StackOp.NONE, MosOperands.stackOp(ins(L6502, "9a")));
		assertTrue(MosOperands.isSubroutineReturn(ins(L6502, "60")));
		assertFalse(MosOperands.isSubroutineReturn(ins(L6502, "40")));
		assertTrue(MosOperands.isInterruptReturn(ins(L6502, "40")));
		assertEquals('A', MosOperands.loadedRegister(ins(L6502, "a9 01")));
		assertEquals('X', MosOperands.loadedRegister(ins(L6502, "ae 00 90")));
		assertEquals('Y', MosOperands.loadedRegister(ins(L6502, "b4 12")));
		assertEquals(0, MosOperands.loadedRegister(ins(L6502, "aa")));
		assertEquals(0, MosOperands.loadedRegister(ins(L6502, "69 01")));
		assertEquals(Character.valueOf('A'), MosOperands.transferSource(ins(L6502, "aa"), 'X'));
		assertNull(MosOperands.transferSource(ins(L6502, "aa"), 'A'));
		assertTrue(MosOperands.copiesStackPointerInto(ins(L6502, "ba"), 'X'));
		assertFalse(MosOperands.copiesStackPointerInto(ins(L6502, "aa"), 'X'));
		assertTrue(MosOperands.incrementsBy(ins(L6502, "ca"), 'X', -1));
		assertTrue(MosOperands.isBne(ins(L6502, "d0 05")));
		assertTrue(MosOperands.isZnBranch(ins(L6502, "10 05")));
		assertFalse(MosOperands.isZnBranch(ins(L6502, "90 05")));
		assertTrue(MosOperands.znBranchTaken(ins(L6502, "10 05"), false, false));
		assertEquals(Integer.valueOf(0), MosOperands.constantCarry(ins(L6502, "18")));
		assertEquals(Integer.valueOf(1), MosOperands.constantCarry(ins(L6502, "38")));
		assertNull(MosOperands.constantCarry(ins(L6502, "ea")));
		assertTrue(MosOperands.writesMemory(ins(L6502, "8d 00 90")));
		assertTrue(MosOperands.writesMemory(ins(L6502, "e6 12")));
		assertFalse(MosOperands.writesMemory(ins(L6502, "0a")));
		assertFalse(MosOperands.writesMemory(ins(L6502, "48")));
		assertFalse(MosOperands.writesMemory(ins(L6502, "20 00 90")));
		assertTrue(MosOperands.storesRegister(ins(L6502, "9d 00 90"), 'A'));
		assertTrue("BRK is a computed jump", ins(L6502, "00").getFlowType().isComputed());
	}

	@Test
	public void dispatchRecognizerShapes() throws Exception {
		// absolute-indexed accumulator loads: 6502 LDA abs,X / abs,Y, SPC700 MOV A,!abs+X / +Y
		CpuRegs r = regs(ins(L6502, "ea"));
		PcodeShapes.IndexedLoad ldx = PcodeShapes.indexedLoad(ins(L6502, "bd 34 12"));
		assertEquals(r.acc(), ldx.dst());
		assertEquals(r.x(), ldx.index());
		assertEquals(0x1234, ldx.base());
		assertEquals(r.y(), PcodeShapes.indexedLoad(ins(L6502, "b9 34 12")).index());
		assertNull(PcodeShapes.indexedLoad(ins(L6502, "ad 34 12")));
		assertNull(PcodeShapes.indexedLoad(ins(L6502, "b1 12")));
		CpuRegs spc = regs(ins(LSPC, "00"));
		PcodeShapes.IndexedLoad sx = PcodeShapes.indexedLoad(ins(LSPC, "f5 34 12"));
		assertEquals(spc.acc(), sx.dst());
		assertEquals(spc.x(), sx.index());
		assertEquals(0x1234, sx.base());
		assertEquals(spc.y(), PcodeShapes.indexedLoad(ins(LSPC, "f6 34 12")).index());

		// AND #imm
		assertEquals(Long.valueOf(0x0f),
			PcodeShapes.bitOpConstant(ins(L6502, "29 0f"), r.acc(), PcodeOp.INT_AND));
		assertNull(PcodeShapes.bitOpConstant(ins(L6502, "25 0f"), r.acc(), PcodeOp.INT_AND));
		assertNull(PcodeShapes.bitOpConstant(ins(L6502, "09 0f"), r.acc(), PcodeOp.INT_AND));
		assertEquals(Long.valueOf(0x07),
			PcodeShapes.bitOpConstant(ins(LSPC, "28 07"), spc.acc(), PcodeOp.INT_AND));

		// CMP/CPX #imm and which register
		assertEquals(Long.valueOf(0x20), PcodeShapes.compareImmediate(ins(L6502, "c9 20"), r.acc()));
		assertEquals(Long.valueOf(5), PcodeShapes.compareImmediate(ins(L6502, "e0 05"), r.x()));
		assertNull(PcodeShapes.compareImmediate(ins(L6502, "cd 00 90"), r.acc()));
		assertEquals(Long.valueOf(0x20), PcodeShapes.compareImmediate(ins(LSPC, "68 20"), spc.acc()));
		assertEquals(Long.valueOf(9), PcodeShapes.compareImmediate(ins(LSPC, "c8 09"), spc.x()));
		assertTrue(MosOperands.comparesRegister(ins(L6502, "c9 20"), 'A'));
		assertTrue(MosOperands.comparesRegister(ins(L6502, "e0 05"), 'X'));
		assertFalse(MosOperands.comparesRegister(ins(L6502, "e0 05"), 'A'));
		assertFalse(MosOperands.comparesRegister(ins(L6502, "69 05"), 'A'));
		assertFalse(MosOperands.comparesRegister(ins(L6502, "aa"), 'A'));
		assertTrue(MosOperands.comparesRegister(ins(LSPC, "c8 09"), 'X'));
		assertTrue(MosOperands.isImmediateOperand(ins(L6502, "e0 05")));
		assertFalse(MosOperands.isImmediateOperand(ins(L6502, "e4 05")));
		assertTrue(MosOperands.isBpl(ins(L6502, "10 05")));
		assertFalse(MosOperands.isBpl(ins(L6502, "30 05")));
		assertTrue(MosOperands.isEorOnAccumulator(ins(L6502, "49 ff")));
		assertFalse(MosOperands.isEorOnAccumulator(ins(L6502, "29 ff")));

		// returns, CPU-correct: RTI pulls status, RTL pops 3 but is a subroutine-style return
		assertTrue(MosOperands.isSubroutineReturn(ins(L6502, "60")));
		assertFalse(MosOperands.isInterruptReturn(ins(L6502, "60")));
		assertTrue(MosOperands.isInterruptReturn(ins(L65816, "40")));
		assertFalse(MosOperands.isSubroutineReturn(ins(L65816, "40")));
		assertFalse("RTL is no interrupt return", MosOperands.isInterruptReturn(ins(L65816, "6b")));
		assertTrue(MosOperands.isSubroutineReturn(ins(LSPC, "6f")));
		assertFalse(MosOperands.isSubroutineReturn(ins(LSPC, "7f")));
		assertTrue(MosOperands.isInterruptReturn(ins(LSPC, "7f")));
		assertFalse("the 6502-family RTS test leaves the SPC700 RET out",
			MosOperands.isRts(ins(LSPC, "6f")));
		assertTrue(MosOperands.isRts(ins(L6502, "60")));
		assertTrue(MosOperands.isRtsOrRti(ins(L6502, "40")));

		// software interrupt, stack touching, JSR
		assertTrue(MosOperands.isSoftwareInterrupt(ins(L6502, "00")));
		assertFalse(MosOperands.isSoftwareInterrupt(ins(L6502, "6c 00 90")));
		assertTrue(MosOperands.rebasesStackPointer(ins(L6502, "9a")));
		assertFalse(MosOperands.rebasesStackPointer(ins(L6502, "48")));
		assertTrue(MosOperands.touchesStack(ins(L6502, "48")));
		assertTrue(MosOperands.touchesStack(ins(L6502, "9a")));
		assertFalse(MosOperands.touchesStack(ins(L6502, "aa")));
		assertTrue(MosOperands.isJsr(ins(L6502, "20 00 90")));
		assertFalse(MosOperands.isJsr(ins(L6502, "4c 00 90")));
		assertFalse(MosOperands.isJsr(ins(LSPC, "3f 00 90")));
		assertTrue(MosOperands.isNativeCall(ins(L6502, "20 00 90")));
		assertFalse(MosOperands.isNativeCall(ins(L6502, "4c 00 90")));
	}
}
