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
import java.util.Locale;
import java.util.Set;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import retromachines.W65816Shapes.Role;

/**
 * {@link W65816Shapes} against the mnemonic classification the 65816 analyzers used before grm-jjuc
 * wave 3: every opcode, in emulation, native 16-bit, native 8-bit and mixed-width contexts, must be
 * classified by its p-code exactly as the old per-mnemonic switches classified it. This is the
 * equivalence proof for the pure refactor.
 */
public class W65816ShapesTest extends AbstractBundledLanguageTest {

	private static final int[][] CTXS =
		{ { 0, 0, 0 }, { 0, 1, 1 }, { 0, 1, 0 }, { 0, 0, 1 }, { 1, 1, 1 } };
	private static final long ADDR = 0x200;

	@Test
	public void everyOpcodeMatchesTheMnemonicModel() throws Exception {
		int checked = 0;
		int pushes = 0;
		int pulls = 0;
		int loads = 0;
		int xfers = 0;
		int kinds = 0;
		for (int[] c : CTXS) {
			ProgramBuilder b = newBuilder("T", "65816:LE:24:retro");
			b.createMemory(".ram", "0x0", 0x10000);
			for (int op = 0; op < 256; op++) {
				String bytes = String.format("%02x 34 12 56", op);
				int tx0 = b.getProgram().startTransaction("clr");
				b.getProgram().getListing().clearCodeUnits(b.addr("0x0200"), b.addr("0x02ff"),
					false);
				b.getProgram().endTransaction(tx0, true);
				b.setBytes("0x0200", bytes, false);
				String[] n = { "ctx_EF", "ctx_MF", "ctx_XF" };
				for (int k = 0; k < 3; k++) {
					Register r = b.getProgram().getLanguage().getRegister(n[k]);
					int tx = b.getProgram().startTransaction("c");
					b.getProgram().getProgramContext().setValue(r, b.addr("0x0200"),
						b.addr("0x02ff"), BigInteger.valueOf(c[k]));
					b.getProgram().endTransaction(tx, true);
				}
				b.disassemble("0x0200", 4, true);
				Instruction ins = b.getProgram().getListing().getInstructionAt(b.addr("0x0200"));
				if (ins == null) {
					continue;
				}
				checked++;
				String mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
				String where = "E" + c[0] + "M" + c[1] + "X" + c[2] + " " + ins;
				boolean emu = c[0] == 1;
				int mBytes = emu || c[1] == 1 ? 1 : 2;
				int xBytes = emu || c[2] == 1 ? 1 : 2;

				// pushes
				W65816Shapes.Push p = W65816Shapes.push(ins);
				switch (mn) {
					case "PHA" -> assertPush(where, p, Role.A, mBytes, null);
					case "PHX" -> assertPush(where, p, Role.X, xBytes, null);
					case "PHY" -> assertPush(where, p, Role.Y, xBytes, null);
					case "PHB" -> assertPush(where, p, Role.DBR, 1, null);
					case "PHK" -> assertPush(where, p, Role.NONE, 1, 0L);
					case "PHD" -> assertPush(where, p, Role.DP, 2, null);
					case "PEI" -> assertPush(where, p, Role.NONE, 2, null);
					case "PHP" -> assertPush(where, p, Role.NONE, 1, null);
					case "PEA" -> assertPush(where, p, Role.NONE, 2, 0x1234L);
					case "PER" -> assertPush(where, p, Role.NONE, 2, (ADDR + 3 + 0x1234) & 0xffff);
					default -> assertNull(where + " must not be a push", p);
				}
				if (p != null) {
					pushes++;
				}

				// pulls
				W65816Shapes.Pull q = W65816Shapes.pull(ins);
				switch (mn) {
					case "PLA" -> assertPull(where, q, Role.A, mBytes);
					case "PLX" -> assertPull(where, q, Role.X, xBytes);
					case "PLY" -> assertPull(where, q, Role.Y, xBytes);
					case "PLB" -> assertPull(where, q, Role.DBR, 1);
					case "PLD" -> assertPull(where, q, Role.DP, 2);
					case "PLP" -> assertPull(where, q, Role.NONE, 1);
					default -> assertNull(where + " must not be a pull", q);
				}
				if (q != null) {
					pulls++;
				}

				// constant loads into A/X/Y
				W65816Shapes.ConstLoad cl = W65816Shapes.constLoad(ins);
				boolean imm = ins.getLength() > 1 && ins.getNumOperands() > 0 &&
					ins.getDefaultOperandRepresentation(0).startsWith("#");
				Set<String> loadsMn = Set.of("LDA", "LDX", "LDY");
				if (loadsMn.contains(mn) && imm) {
					assertNotNull(where, cl);
					assertEquals(where, Role.valueOf(String.valueOf(mn.charAt(2))), cl.role());
					int len = ins.getLength() - 1;
					assertEquals(where, len, cl.bytes());
					long expect = len == 2 ? 0x1234 : 0x34;
					assertEquals(where, expect, cl.value());
					loads++;
				}
				else {
					assertNull(where + " must not be a constant load", cl);
				}

				// transfers of the registers the analyzers model
				W65816Shapes.Transfer t = W65816Shapes.transfer(ins);
				Role src = null;
				Role dst = null;
				switch (mn) {
					case "TAX" -> { src = Role.A; dst = Role.X; }
					case "TAY" -> { src = Role.A; dst = Role.Y; }
					case "TXA" -> { src = Role.X; dst = Role.A; }
					case "TYA" -> { src = Role.Y; dst = Role.A; }
					case "TCD" -> { src = Role.A; dst = Role.DP; }
					case "TDC" -> { src = Role.DP; dst = Role.A; }
					default -> { }
				}
				if (src != null) {
					assertNotNull(where, t);
					assertEquals(where, src, t.src());
					assertEquals(where, dst, t.dst());
					xfers++;
				}
				else if (t != null) {
					// anything else seen as a transfer must not collide with the modelled six
					boolean modelled = (t.src() == Role.A && (t.dst() == Role.X ||
						t.dst() == Role.Y || t.dst() == Role.DP)) ||
						(t.dst() == Role.A && (t.src() == Role.X || t.src() == Role.Y ||
							t.src() == Role.DP));
					assertTrue(where + " collides with a modelled transfer: " + t, !modelled);
				}
				String rep0 = ins.getNumOperands() > 0 ? ins.getDefaultOperandRepresentation(0) : "";
				assertEquals(where, mn.equals("PHK"), W65816Shapes.pushesProgramBank(ins));
				assertEquals(where, mn.equals("PEA") ? 0x1234 : mn.equals("PER") ?
					(int) ((ADDR + 3 + 0x1234) & 0xffff) : -1, W65816Shapes.pushedConstantWord(ins));
				assertEquals(where, mn.equals("PHA"), W65816Shapes.pushesAccumulator(ins));
				assertEquals(where, mn.equals("DEC") && (rep0.isEmpty() || rep0.equals("A")),
					W65816Shapes.decrementsAccumulator(ins));
				assertEquals(where,
					Set.of("PHA", "PHX", "PHY", "PHB", "PHD", "PHK", "PHP", "PEA", "PEI", "PER",
						"PLA", "PLX", "PLY", "PLB", "PLD", "PLP", "TCS", "TXS", "JSR", "JSL",
						"RTI", "BRK", "COP").contains(mn),
					W65816Shapes.touchesStack(ins));
				assertEquals(where, mn.equals("TAX"), W65816Shapes.copiesAccumulatorToX(ins));
				assertEquals(where, mn.equals("ASL") && (rep0.isEmpty() || rep0.equals("A")),
					W65816Shapes.shiftsAccumulatorLeft(ins));
				assertEquals(where, mn.equals("BEQ"),
					W65816Shapes.branchesOn(ins, CpuRegs.FlagKind.ZERO, true));
				assertEquals(where, mn.equals("BCC"),
					W65816Shapes.branchesOn(ins, CpuRegs.FlagKind.CARRY, false));
				assertEquals(where, mn.equals("BCS"),
					W65816Shapes.branchesOn(ins, CpuRegs.FlagKind.CARRY, true));
				assertEquals(where, mn.equals("XBA"), W65816Shapes.swapsAccumulatorHalves(ins));
				assertEquals(where, (mn.equals("TCD") || mn.equals("PLD")),
					W65816Shapes.writesDp(ins));
				assertEquals(where, mn.equals("TXS") || mn.equals("TCS"),
					W65816Shapes.rebasesStack(ins));

				// returns, calls, dispatch jumps
				assertEquals(where, mn.equals("RTS") || mn.equals("RTL"),
					W65816Shapes.isReturn(ins));
				assertEquals(where, mn.equals("RTI"), MosOperands.isInterruptReturn(ins));
				assertEquals(where, mn.equals("RTS") ? "RTS" : mn.equals("RTL") ? "RTL" : null,
					W65816Shapes.returnKind(ins));
				assertEquals(where, mn.equals("JSR") || mn.equals("JSL"),
					W65816Shapes.isCall(ins));
				assertEquals(where,
					(mn.equals("JMP") && ins.getFlowType().isComputed()) ||
						(mn.equals("JML") && ins.getFlowType().isComputed()),
					W65816Shapes.isDispatchJump(ins));
				if (mn.equals("JSR") || mn.equals("JSL")) {
					assertEquals(where, mn.equals("JSR") ? 2 : 3, W65816Shapes.callPushBytes(ins));
				}
				if (!ins.getFlowType().isJump() && !ins.getFlowType().isCall() &&
					!ins.getFlowType().isTerminal() && ins.getNumOperands() > 0) {
					String rep = ins.getDefaultOperandRepresentation(0);
					if (!rep.contains("(") && !rep.contains("[") && !rep.contains(",S") &&
						!rep.startsWith("#") && ins.getLength() > 1 && !mn.equals("PEA") &&
						!mn.equals("PER") && !mn.equals("MVN") && !mn.equals("MVP")) {
						assertEquals(where + " " + rep, typeOfOld(mn),
							W65816Shapes.memAccessKind(ins));
						kinds++;
					}
				}
				if (mn.equals("MVN") || mn.equals("MVP")) {
					assertEquals(where, Long.valueOf(0x34), W65816Shapes.constIntoDbr(ins));
				}
				else {
					assertNull(where, W65816Shapes.constIntoDbr(ins));
				}
			}
		}
		assertTrue("decoded " + checked, checked > 1000);
		assertTrue("kinds " + kinds, kinds > 200);
		assertTrue(pushes > 40 && pulls > 25 && loads > 10 && xfers > 15);
	}

	private static ghidra.program.model.symbol.RefType typeOfOld(String mn) {
		return switch (mn) {
			case "STA", "STX", "STY", "STZ" -> ghidra.program.model.symbol.RefType.WRITE;
			case "INC", "DEC", "ASL", "LSR", "ROL", "ROR", "TSB", "TRB" ->
				ghidra.program.model.symbol.RefType.READ_WRITE;
			default -> ghidra.program.model.symbol.RefType.READ;
		};
	}

	private static void assertPush(String where, W65816Shapes.Push p, Role role, int bytes,
			Long constant) {
		assertNotNull(where, p);
		assertEquals(where, role, p.role());
		assertEquals(where, bytes, p.bytes());
		assertEquals(where, constant, p.constant());
	}

	private static void assertPull(String where, W65816Shapes.Pull p, Role role, int bytes) {
		assertNotNull(where, p);
		assertEquals(where, role, p.role());
		assertEquals(where, bytes, p.bytes());
	}
}
