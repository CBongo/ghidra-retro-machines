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
// Read-only golden dump for the OPT-IN `spc-snap` rows of the real-ROM tier
// (tools/banktest/realrom-test.sh check spc-snap), bead grm-c9d.9: real .spc sound-state snapshots
// imported by SpcSnapshotLoader with auto-analysis ON.
//
// Emits a BOUNDED, COPYRIGHT-SAFE block between === REALROM BEGIN === and === REALROM END ===
// holding only our own derived metadata -- block inventory, header registers, the entry source,
// the recovered stack-chain frames (addresses and call kinds), instruction/function/Error counts
// and the mnemonic (not operands, not bytes) at each seeded address. No RAM bytes, no song text:
// only the ID666 game title (a short identifier) and the emulator byte are echoed.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class SpcSnapRealRomDump extends GhidraScript {

	private static final String P = "SPC.";

	@Override
	protected void run() throws Exception {
		RealRomDumpSupport out = new RealRomDumpSupport(this, currentProgram);
		Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
		out.begin();
		println("REALROM language " + currentProgram.getLanguageID().getIdAsString());
		println("REALROM format " + currentProgram.getExecutableFormat());

		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			println("REALROM block " + b.getName() + " " + RealRomDumpSupport.fmt(b.getStart(), 4) +
				"-" + RealRomDumpSupport.fmt(b.getEnd(), 4) + " overlay=" + b.isOverlay() +
				" init=" + b.isInitialized());
		}
		println("REALROM id666 " + info.getString(P + "ID666", "NONE") + " game=[" +
			info.getString(P + "Game title", "") + "] emulator=" +
			info.getString(P + "Emulator used", "NONE"));
		println("REALROM header pc=" + info.getString(P + "Header PC", "NONE") + " sp=" +
			info.getString(P + "SP", "NONE") + " psw=" + info.getString(P + "PSW", "NONE") +
			" ipl=" + info.getString(P + "IPL mapped in", "NONE"));
		println("REALROM entry " + info.getString(P + "Entry", "NONE") + " source=" +
			info.getString(P + "Entry source", "NONE"));

		// The stack chain, as the loader recorded it.
		println("REALROM stack frames " + info.getString(P + "Stack frames", "off"));
		println("REALROM stack chain " + info.getString(P + "Stack chain", "off"));
		println("REALROM stack end " + info.getString(P + "Stack chain end", "off"));

		List<String> seeds = new ArrayList<>();
		Address outermostRet = null;

		for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(false)) {
			String n = s.getName();
			if (!(n.equals("SPC_ENTRY") || n.startsWith("SPC_RET_") || n.startsWith("SPC_CALLEE_"))) {
				continue;
			}
			seeds.add(n + " " + RealRomDumpSupport.fmt(s.getAddress(), 4) + " fn=" +
				(currentProgram.getFunctionManager().getFunctionAt(s.getAddress()) != null) +
				" op=" + mnemonic(s.getAddress()));
		}
		seeds.sort(null);
		for (String s : seeds) {
			println("REALROM seed " + s);
		}

		// Is the outermost recovered frame inside a loop? A backward flow from the code that
		// follows its return address to (or before) the call site is the main-loop signature.
		int frames = parse(info.getString(P + "Stack frames", "0"));
		if (frames > 0) {
			for (Symbol s : currentProgram.getSymbolTable().getSymbols("SPC_RET_" + frames)) {
				outermostRet = s.getAddress();
			}
		}
		if (outermostRet != null) {
			String loop = "no";
			Address a = outermostRet;
			for (int i = 0; i < 12 && a != null; i++) {
				Instruction in = currentProgram.getListing().getInstructionAt(a);
				if (in == null) {
					break;
				}
				for (Reference r : in.getReferencesFrom()) {
					if (r.getReferenceType().isFlow() && !r.getReferenceType().isCall() &&
						r.getToAddress().compareTo(outermostRet) < 0 &&
						outermostRet.getOffset() - r.getToAddress().getOffset() <= 0x40) {
						loop = "yes at " + RealRomDumpSupport.fmt(in.getAddress(), 4) + " -> " +
							RealRomDumpSupport.fmt(r.getToAddress(), 4);
					}
				}
				if (!loop.equals("no") || !in.getFlowType().hasFallthrough()) {
					break;
				}
				a = in.getFallThrough();
			}
			println("REALROM stack outermost " + RealRomDumpSupport.fmt(outermostRet, 4) +
				" backward-flow=" + loop);
		}

		int errors = 0;
		var bi = currentProgram.getBookmarkManager().getBookmarksIterator("Error");
		while (bi.hasNext()) {
			bi.next();
			errors++;
		}
		println("REALROM count instructions " + currentProgram.getListing().getNumInstructions());
		println("REALROM count functions " + currentProgram.getFunctionManager().getFunctionCount());
		println("REALROM count bookmarks.error " + errors);
		out.end();
	}

	private String mnemonic(Address a) {
		Instruction in = currentProgram.getListing().getInstructionAt(a);
		return in == null ? "-" : in.getMnemonicString();
	}

	private static int parse(String s) {
		try {
			return Integer.parseInt(s.trim());
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}
}
