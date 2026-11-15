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
//Raw-byte coverage census: of every JSR/JMP abs pattern in a fixed range that targets a banked
//window, and of every zero-page store to a given cell, how many are real instructions.
//@category RetroMachines.Probe
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

/**
 * Narrow real-ROM probe (grm-5tl.20.5, kept and generalized in grm-gipk.26): a raw-byte census
 * of how much of the code that SHOULD be there analysis actually disassembled. Scans the
 * default (fixed) space only, so banked copies are not counted.
 *
 * <ul>
 * <li>{@code LBSCOV} lines: every {@code 20 lo hi} / {@code 4C lo hi} byte pattern in
 * {@code GRM_WCC_FIXED} (default {@code c000-fffd}) whose target lies in {@code GRM_WCC_WINDOW}
 * (default {@code 8000-bfff}), classified INSN (a JSR/JMP instruction starts there), OPERAND
 * (inside or as another instruction -- usually a false pattern), DATA (under defined data, with
 * that data's start, type and length -- which names who laid it), or UNDISASSEMBLED, with the
 * instruction's outgoing references ({@code *} = primary).</li>
 * <li>{@code CELLCOV} lines, when {@code GRM_WCC_CELL=<zp hex>} is set: every {@code STA/STX/STY
 * zp} pattern ({@code 85/86/84 cell}) to that cell, classified the same way.</li>
 * </ul>
 * A raw pattern is not proof of a site (a table byte can look like a JSR), so read the totals as
 * an upper bound on missed sites. Run as {@code REALROM_EXTRA_POSTSCRIPT=WindowCallCoverageProbe.java}
 * with {@code REALROM_WORK_DIR=<dir>}; output is in {@code <dir>/<id>.log}.
 */
public class WindowCallCoverageProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		long[] fixed = range(System.getenv("GRM_WCC_FIXED"), 0xc000, 0xfffd);
		long[] window = range(System.getenv("GRM_WCC_WINDOW"), 0x8000, 0xbfff);
		AddressSpace base = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Listing listing = currentProgram.getListing();

		int[] calls = new int[4];
		int[] stores = new int[4];
		String cellEnv = System.getenv("GRM_WCC_CELL");
		int cell = cellEnv == null || cellEnv.isBlank() ? -1 : Integer.parseInt(cellEnv.trim(), 16);
		for (long a = fixed[0]; a <= fixed[1]; a++) {
			Address at = base.getAddress(a);
			int op = getByte(at) & 0xff;
			if (op == 0x20 || op == 0x4c) {
				int tgt = (getByte(at.add(2)) & 0xff) << 8 | (getByte(at.add(1)) & 0xff);
				if (tgt >= window[0] && tgt <= window[1]) {
					int k = classify(listing, at, op == 0x20 ? "JSR" : "JMP");
					calls[k]++;
					println(String.format("LBSCOV %04x -> %04x %s %s%s refs: %s", a, tgt,
						op == 0x20 ? "JSR" : "JMP", STATE[k], dataNote(listing, at),
						refs(listing.getInstructionAt(at))));
				}
			}
			if (cell >= 0 && (op == 0x85 || op == 0x86 || op == 0x84) &&
				(getByte(at.add(1)) & 0xff) == cell) {
				String mn = op == 0x85 ? "STA" : op == 0x86 ? "STX" : "STY";
				int k = classify(listing, at, mn);
				stores[k]++;
				println(String.format("CELLCOV %04x %s $%02x %s", a, mn, cell, STATE[k]));
			}
		}
		println(String.format(
			"LBSCOV total raw=%d instruction=%d operandOrOther=%d undisassembled=%d data=%d",
			calls[0] + calls[1] + calls[2] + calls[3], calls[0], calls[1], calls[2], calls[3]));
		if (cell >= 0) {
			println(String.format(
				"CELLCOV total raw=%d instruction=%d operandOrOther=%d undisassembled=%d data=%d",
				stores[0] + stores[1] + stores[2] + stores[3], stores[0], stores[1], stores[2],
				stores[3]));
		}
	}

	private static final String[] STATE = { "INSN", "OPERAND", "UNDISASSEMBLED", "DATA" };

	private static int classify(Listing listing, Address at, String mnemonic) {
		Instruction i = listing.getInstructionAt(at);
		if (i != null) {
			return mnemonic.equals(i.getMnemonicString()) ? 0 : 1;
		}
		if (listing.getInstructionContaining(at) != null) {
			return 1;
		}
		return listing.getDefinedDataContaining(at) != null ? 3 : 2;
	}

	/** For a site under defined data: the outermost data's start, type and length, which names
	 *  who laid it (a pointer array from switch analysis, a string, ...). */
	private static String dataNote(Listing listing, Address at) {
		Data d = listing.getDefinedDataContaining(at);
		if (d == null) {
			return "";
		}
		return String.format("(%s %s len=%d)", d.getMinAddress(), d.getDataType().getName(),
			d.getLength());
	}

	private static String refs(Instruction i) {
		if (i == null) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (Reference r : i.getReferencesFrom()) {
			sb.append(r.getToAddress()).append(r.isPrimary() ? "* " : " ");
		}
		return sb.toString().trim();
	}

	private static long[] range(String env, long lo, long hi) {
		if (env == null || env.isBlank()) {
			return new long[] { lo, hi };
		}
		String[] p = env.trim().split("-");
		return new long[] { Long.parseLong(p[0], 16), Long.parseLong(p[1], 16) };
	}
}
