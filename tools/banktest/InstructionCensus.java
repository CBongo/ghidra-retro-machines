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
// Per-memory-block instruction census for A/B'ing two toolchains or two builds on one ROM
// (bead grm-qp5x.4). RealRomDump's `count instrs.inOverlay` is one number for the whole
// program; when it moves by hundreds and every bank annotation is unchanged, the question is
// WHICH blocks lost or gained code, and at which addresses -- so the delta can be read in a
// disassembler rather than argued about.
//
// Emits one `CENSUS block <name> <count>` line per block and one `CENSUS instr <block> <addr>
// <mnemonic>` line per instruction, then `CENSUS ranges <block> <a-b,c-d,...>` collapsing the
// starts into runs so a diff of two runs shows contiguous ranges rather than thousands of
// lines. Run it as REALROM_EXTRA_POSTSCRIPT on realrom-test.sh; the golden carve ignores it
// (it fences nothing under REALROM). Read-only; name-agnostic; no ROM bytes.
//
//   REALROM_EXTRA_POSTSCRIPT=InstructionCensus.java \
//     bash tools/banktest/realrom-test.sh check nes --only rcransom --no-build
//   grep '^INFO  InstructionCensus.java> CENSUS' <work>/rcransom.log | sed 's/^.*> //'
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;

public class InstructionCensus extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, List<Instruction>> byBlock = new TreeMap<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			MemoryBlock block = currentProgram.getMemory().getBlock(instr.getMinAddress());
			String name = block == null ? "<none>" : block.getName();
			byBlock.computeIfAbsent(name, k -> new ArrayList<>()).add(instr);
		}
		for (Map.Entry<String, List<Instruction>> e : byBlock.entrySet()) {
			println("CENSUS block " + e.getKey() + " " + e.getValue().size());
		}
		for (Map.Entry<String, List<Instruction>> e : byBlock.entrySet()) {
			StringBuilder ranges = new StringBuilder();
			Address runStart = null;
			Address runEnd = null;
			for (Instruction instr : e.getValue()) {
				println("CENSUS instr " + e.getKey() + " " + fmt(instr.getMinAddress()) + " " +
					instr.getMnemonicString());
				Address a = instr.getMinAddress();
				if (runEnd != null && a.equals(runEnd.add(1))) {
					runEnd = instr.getMaxAddress();
					continue;
				}
				if (runStart != null) {
					ranges.append(fmt(runStart)).append('-').append(fmt(runEnd)).append(',');
				}
				runStart = a;
				runEnd = instr.getMaxAddress();
			}
			if (runStart != null) {
				ranges.append(fmt(runStart)).append('-').append(fmt(runEnd));
			}
			println("CENSUS ranges " + e.getKey() + " " + ranges);
		}
	}

	private static String fmt(Address a) {
		return String.format("%04x", a.getOffset());
	}
}
