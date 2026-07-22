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
// Read-only measurement script for gauging analyzer scale on real-world ROMs
// (as opposed to the small synthetic banktest*/nesbanktest* fixtures driven by
// run-banktest.sh). Never mutates the program -- prints COUNTS ONLY, since a
// real ROM can carry ~191 overlay blocks/spaces and thousands of references,
// and per-item dumps (as VerifyBankTest.dump() does for the small fixtures)
// would flood the log at that scale. Driven by measure-overlay-scale.sh.
//@category RetroMachines.Test

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class OverlayScaleMeasure extends GhidraScript {

	@Override
	protected void run() throws Exception {
		int blocksTotal = 0;
		int blocksOverlay = 0;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			blocksTotal++;
			if (block.isOverlay()) {
				blocksOverlay++;
			}
		}

		int spacesTotal = 0;
		int spacesOverlay = 0;
		for (AddressSpace space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
			spacesTotal++;
			if (space.isOverlaySpace()) {
				spacesOverlay++;
			}
		}

		long refsIntoOverlay = 0;
		InstructionIterator instrs = currentProgram.getListing().getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			for (Reference r : instr.getReferencesFrom()) {
				if (r.getToAddress().getAddressSpace().isOverlaySpace()) {
					refsIntoOverlay++;
				}
			}
		}

		long bookmarksWarning = 0;
		Iterator<Bookmark> bms = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bms.hasNext()) {
			Bookmark bm = bms.next();
			if ("Warning".equals(bm.getTypeString())) {
				bookmarksWarning++;
			}
		}

		println("=== MEASURE BEGIN ===");
		println("MEASURE program " + currentProgram.getName());
		println("MEASURE blocks.total " + blocksTotal);
		println("MEASURE blocks.overlay " + blocksOverlay);
		println("MEASURE spaces.total " + spacesTotal);
		println("MEASURE spaces.overlay " + spacesOverlay);
		println("MEASURE refs.intoOverlay " + refsIntoOverlay);
		println("MEASURE bookmarks.warning " + bookmarksWarning);
		println("=== MEASURE END ===");
	}
}
