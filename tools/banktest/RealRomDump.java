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
// Read-only golden dump for the OPTIONAL, hash-pinned real-ROM test tier
// (tools/banktest/realrom-test.sh). A middle ground between OverlayScaleMeasure.java
// (counts only, for scale measurement) and VerifyBankTest.java's dump() (every item,
// which floods at real-cartridge scale, ~191 overlays / thousands of refs).
//
// Emits a BOUNDED, NORMALIZED, COPYRIGHT-SAFE block between
//   === REALROM BEGIN ===  /  === REALROM END ===
// containing ONLY our own derived analysis metadata -- board identity, the program's
// SHA-256, memory-block layout (name/range/overlay-ness), counts of overlay spaces /
// cross-bank references / bank-switch comments / warning bookmarks / banked
// instructions, and a bounded, sorted SAMPLE of the bank-switch comments, cross-bank
// overlay references, and warning bookmarks. It never emits ROM bytes or disassembled
// instruction text, so the resulting golden is safe to commit even though the ROM it
// was derived from is not. Name-agnostic (unlike VerifyBankTest's name dispatch) so it
// runs on any real ROM. Driven by realrom-test.sh.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class RealRomDump extends GhidraScript {

	// Cap the per-category sample so a large cartridge cannot blow the golden up.
	// Full counts still catch regressions; the sample catches qualitative drift in
	// the lowest-addressed annotations.
	private static final int SAMPLE = 25;

	// Program-info property the loader stamps with the board's .map path
	// (DescriptorSupport.MAP_PATH_PROPERTY / .PLACEMENT_OVERRIDE_PROPERTY -- kept as
	// literals here so this script needs no extension classes on its path).
	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";
	private static final String PLACEMENT_OVERRIDE_PROPERTY = "Retro Machines.Placement Override";

	@Override
	protected void run() throws Exception {
		List<String> blocks = new ArrayList<>();
		int blocksTotal = 0;
		int blocksOverlay = 0;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			blocksTotal++;
			if (block.isOverlay()) {
				blocksOverlay++;
			}
			blocks.add("block " + block.getName() + " " + fmt(block.getStart()) + "-" +
				fmt(block.getEnd()) + " overlay=" + block.isOverlay());
		}

		int spacesOverlay = 0;
		for (AddressSpace space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
			if (space.isOverlaySpace()) {
				spacesOverlay++;
			}
		}

		List<String> bankComments = new ArrayList<>();
		List<String> overlayRefs = new ArrayList<>();
		long refsIntoOverlay = 0;
		long instrsInOverlay = 0;
		InstructionIterator instrs = currentProgram.getListing().getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();
			if (at.getAddressSpace().isOverlaySpace()) {
				instrsInOverlay++;
			}

			String eol = currentProgram.getListing().getComment(CommentType.EOL, at);
			if (eol != null && eol.contains("bank ->")) {
				bankComments.add(fmt(at) + " " + eol);
			}

			for (Reference r : instr.getReferencesFrom()) {
				AddressSpace toSpace = r.getToAddress().getAddressSpace();
				if (toSpace.isOverlaySpace()) {
					refsIntoOverlay++;
					overlayRefs.add(fmt(at) + " -> " + toSpace.getName() + "::" +
						fmt(r.getToAddress()) + " " + r.getReferenceType().getName() +
						" primary=" + r.isPrimary());
				}
			}
		}

		List<String> warnings = new ArrayList<>();
		long warningCount = 0;
		Iterator<Bookmark> bms = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bms.hasNext()) {
			Bookmark bm = bms.next();
			if ("Warning".equals(bm.getTypeString())) {
				warningCount++;
				warnings.add(fmt(bm.getAddress()) + " [" + bm.getCategory() + "] " + bm.getComment());
			}
		}

		Collections.sort(blocks);
		Collections.sort(bankComments);
		Collections.sort(overlayRefs);
		Collections.sort(warnings);

		String sha = currentProgram.getExecutableSHA256();
		String mapPath = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(MAP_PATH_PROPERTY, null);
		String placement = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(PLACEMENT_OVERRIDE_PROPERTY, null);

		println("=== REALROM BEGIN ===");
		println("REALROM program " + currentProgram.getName());
		println("REALROM sha256 " + (sha == null ? "NONE" : sha));
		println("REALROM map " + (mapPath == null ? "NONE" : mapPath));
		println("REALROM placement " + (placement == null ? "NONE" : placement));

		// Full block layout -- bounded by the board's window/bank count (<=~200).
		for (String line : blocks) {
			println("REALROM " + line);
		}

		println("REALROM count blocks.total " + blocksTotal);
		println("REALROM count blocks.overlay " + blocksOverlay);
		println("REALROM count spaces.overlay " + spacesOverlay);
		println("REALROM count refs.intoOverlay " + refsIntoOverlay);
		println("REALROM count instrs.inOverlay " + instrsInOverlay);
		println("REALROM count bankComments " + bankComments.size());
		println("REALROM count warnings " + warningCount);

		emitSample("bankcomment", bankComments);
		emitSample("ref", overlayRefs);
		emitSample("warn", warnings);

		println("=== REALROM END ===");
	}

	// Print the first SAMPLE (sorted) entries of a category, so the golden stays small
	// and stable while still pinning concrete annotation text.
	private void emitSample(String tag, List<String> lines) {
		int n = Math.min(SAMPLE, lines.size());
		for (int i = 0; i < n; i++) {
			println("REALROM sample." + tag + " " + lines.get(i));
		}
	}

	// 6502 is a 16-bit CPU; every offset fits in 4 hex digits. Block/ref identity comes
	// from the (overlay) space name, printed alongside where it matters.
	private String fmt(Address addr) {
		return String.format("%04x", addr.getOffset());
	}
}
