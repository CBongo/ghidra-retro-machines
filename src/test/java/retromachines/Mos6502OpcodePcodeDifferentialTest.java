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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Differential test of the bundled {@code 6502:LE:16:nmos} and {@code 6502:LE:16:2a03}
 * languages against stock Ghidra's {@code 6502:LE:16:default} (bead grm-yvmw).
 * <p>
 * Every opcode byte is placed with operand bytes {@code 34 12} in its own 8-byte cell and
 * disassembled in each language. The set stock decodes is the documented set (152 opcodes: 151 documented plus stock's $89);
 * the set is the 151 documented opcodes plus $89 (stock decodes it as STA #imm); each new language must decode the same set with the same length and mnemonic, and must emit
 * identical p-code (unique-space temporaries renumbered by first appearance) except for the
 * opcodes pinned in {@link #EXPECTED_PCODE_DIFFS}: ADC/SBC (the grm-o9k/grm-ef46 flag fixes,
 * plus decimal mode in nmos) and the grm-m9nu hardware conventions.
 */
public class Mos6502OpcodePcodeDifferentialTest extends AbstractBundledLanguageTest {

	private static final String STOCK = "6502:LE:16:default";

	/**
	 * Opcodes (mnemonic and hex byte) whose p-code is expected to differ from stock, in both new
	 * languages: every ADC and SBC (grm-o9k/grm-ef46 carry and overflow fixes; decimal mode in
	 * nmos); every (zp,X) and (zp),Y operand form of ORA/AND/EOR/ADC/STA/LDA/CMP/SBC (the
	 * zero-page pointer wraps within page 0, per the 65x02 vectors); and the grm-m9nu hardware
	 * conventions for BRK, JSR, RTS and PHP. JMP (ind) and RTI match stock.
	 */
	private static final String EXPECTED_PCODE_DIFFS =
		"[ADC(61), ADC(65), ADC(69), ADC(6d), ADC(71), ADC(75), ADC(79), ADC(7d), AND(21), " +
			"AND(31), BRK(00), CMP(c1), CMP(d1), EOR(41), EOR(51), JSR(20), LDA(a1), LDA(b1), " +
			"ORA(01), ORA(11), PHP(08), RTS(60), SBC(e1), SBC(e5), SBC(e9), SBC(ed), SBC(f1), " +
			"SBC(f5), SBC(f9), SBC(fd), STA(81), STA(91)]";

	/**
	 * The opcodes whose p-code differs between 2a03undoc and undoc: every ADC, SBC (including the
	 * $EB alias), RRA and ISC, plus ARR -- exactly the ones with a decimal branch.
	 */
	private static final String EXPECTED_UNDOC_DIFFS =
		"[ADC(61), ADC(65), ADC(69), ADC(6d), ADC(71), ADC(75), ADC(79), ADC(7d), ARR(6b), " +
			"ISC(e3), ISC(e7), ISC(ef), ISC(f3), ISC(f7), ISC(fb), ISC(ff), RRA(63), RRA(67), " +
			"RRA(6f), RRA(73), RRA(77), RRA(7b), RRA(7f), SBC(e1), SBC(e5), SBC(e9), SBC(eb), " +
			"SBC(ed), SBC(f1), SBC(f5), SBC(f9), SBC(fd)]";

	private static final Pattern UNIQUE = Pattern.compile("\\(unique, 0x([0-9a-f]+), ");

	private record Decoded(int length, String mnemonic, List<String> pcode) {
	}

	private Map<Integer, Decoded> decodeAll(String languageId) throws Exception {
		ProgramBuilder b = newBuilder("Diff", languageId);
		b.createMemory("RAM", "0x0", 0x10000);
		for (int op = 0; op < 256; op++) {
			b.setBytes(hex(0x8000 + op * 8), String.format("%02x 34 12", op), false);
			b.disassemble(hex(0x8000 + op * 8), 3, false);
		}
		Program p = b.getProgram();
		Map<Integer, Decoded> out = new TreeMap<>();
		for (int op = 0; op < 256; op++) {
			Address a = b.addr(hex(0x8000 + op * 8));
			Instruction insn = p.getListing().getInstructionAt(a);
			if (insn == null) {
				continue;
			}
			out.put(op, new Decoded(insn.getLength(), insn.getMnemonicString(),
				normalize(insn.getPcode())));
		}
		return out;
	}

	private static List<String> normalize(PcodeOp[] ops) {
		Map<String, String> renumber = new TreeMap<>();
		List<String> lines = new ArrayList<>();
		for (PcodeOp op : ops) {
			Matcher m = UNIQUE.matcher(op.toString());
			StringBuilder sb = new StringBuilder();
			while (m.find()) {
				String id = renumber.computeIfAbsent(m.group(1), k -> "u" + renumber.size());
				m.appendReplacement(sb, "(unique, " + id + ", ");
			}
			m.appendTail(sb);
			// drop the sequence-number prefix, which shifts whenever a branch is added
			lines.add(sb.toString().replaceFirst("^\\S+ : ", ""));
		}
		return lines;
	}

	@Test
	public void documentedOpcodesMatchStockExceptPinnedDifferences() throws Exception {
		Map<Integer, Decoded> stock = decodeAll(STOCK);
		assertEquals("stock decoded opcodes " + stock.keySet(), 152, stock.size());
		for (String lang : new String[] { "6502:LE:16:nmos", "6502:LE:16:2a03" }) {
			Map<Integer, Decoded> ours = decodeAll(lang);
			assertEquals(lang + " decoded opcode set", stock.keySet(), ours.keySet());
			TreeSet<String> differing = new TreeSet<>();
			for (var e : stock.entrySet()) {
				Decoded s = e.getValue();
				Decoded o = ours.get(e.getKey());
				String where = String.format("%s opcode %02x", lang, e.getKey());
				assertEquals(where + " length", s.length(), o.length());
				assertEquals(where + " mnemonic", s.mnemonic(), o.mnemonic());
				if (!s.pcode().equals(o.pcode())) {
					differing.add(String.format("%s(%02x)", s.mnemonic(), e.getKey()));
				}
			}
			assertEquals(lang + " opcodes with differing p-code", EXPECTED_PCODE_DIFFS,
				differing.toString());
		}
	}

	/**
	 * {@code 6502:LE:16:2a03undoc} must decode exactly what {@code 6502:LE:16:undoc} does and
	 * emit identical p-code except in the decimal-mode paths: the opcodes whose ALU step is an
	 * NMOS add or subtract (ADC, SBC and its $EB alias, RRA, ISC) plus ARR. Every such opcode
	 * must differ (the 2A03 variant lost its D branch) and no other may.
	 */
	@Test
	public void twoA03UndocDiffersFromUndocOnlyInDecimalPaths() throws Exception {
		Map<Integer, Decoded> undoc = decodeAll("6502:LE:16:undoc");
		Map<Integer, Decoded> ours = decodeAll("6502:LE:16:2a03undoc");
		assertEquals("decoded opcode set", undoc.keySet(), ours.keySet());
		TreeSet<String> differing = new TreeSet<>();
		for (var e : undoc.entrySet()) {
			Decoded u = e.getValue();
			Decoded o = ours.get(e.getKey());
			String where = String.format("opcode %02x", e.getKey());
			assertEquals(where + " length", u.length(), o.length());
			assertEquals(where + " mnemonic", u.mnemonic(), o.mnemonic());
			if (!u.pcode().equals(o.pcode())) {
				differing.add(String.format("%s(%02x)", u.mnemonic(), e.getKey()));
			}
		}
		assertEquals("2a03undoc opcodes with p-code differing from undoc", EXPECTED_UNDOC_DIFFS,
			differing.toString());
	}
}
