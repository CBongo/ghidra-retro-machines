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
// SHA-256, the SHA-256 of its PRG slice alone (the loader's per-game identity key, bead
// grm-hb6.1 -- this is the value a curated per-game descriptor's `prg_sha256` field is
// copied from), memory-block layout (name/range/overlay-ness), counts of overlay spaces /
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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

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

	// Program-info property the loader stamps with this image's per-game identity,
	// "prg:<64 hex> file:<64 hex>" (DescriptorSupport.GAME_IDENTITY_PROPERTY -- kept as a
	// literal here for the same reason as the two above).
	private static final String GAME_IDENTITY_PROPERTY = "Retro Machines.Game Identity";

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

		// Deliberately named symbols (bead grm-mej.4). IMPORTED and USER_DEFINED only -- and the
		// exclusion of ANALYSIS is the whole point, learned the hard way.
		//
		// DEFAULT was the obvious filter (it is what hides Ghidra's FUN_/LAB_/DAT_ names) and it is
		// what the synthetic dump in VerifyBankTest uses. It is not enough here. Ghidra's own
		// jump-table analyzer tags its switch-case labels ANALYSIS, not DEFAULT, so on a real ROM
		// that filter admits them in bulk: megaman alone contributed 1522 lines of caseD_* -- on a
		// row that is simultaneously bistable (grm-g73) and carries a known jump-table over-read
		// (grm-eyn), so every one of them is free to flap. That is exactly the "tracks DISASSEMBLY
		// rather than intent, churns on every unrelated change, nobody reads the diff" failure the
		// filter exists to prevent, arriving through a door DEFAULT does not close.
		//
		// The synthetic fixtures could not have caught this: none of them has a switch table.
		//
		// CONSEQUENCE, stated rather than hidden: an analyzer-created label (ANALYSIS) is invisible
		// in THIS dump. Naming is pinned by Tier 2 and by the synthetic goldens, which do emit it;
		// real-ROM coverage of analyzer-created names would need a way to tell ours from Ghidra's,
		// and there is none today.
		List<String> symbols = new ArrayList<>();
		long symbolCount = 0;
		for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(false)) {
			SourceType src = sym.getSource();
			if (src == SourceType.IMPORTED || src == SourceType.USER_DEFINED) {
				symbolCount++;
				symbols.add(fmt(sym.getAddress()) + " " + sym.getName() + " " + src +
					(sym.isPrimary() ? " primary=true" : " primary=false"));
			}
		}

		Collections.sort(blocks);
		Collections.sort(symbols);
		Collections.sort(bankComments);
		Collections.sort(overlayRefs);
		Collections.sort(warnings);

		String sha = currentProgram.getExecutableSHA256();
		String mapPath = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(MAP_PATH_PROPERTY, null);
		String placement = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(PLACEMENT_OVERRIDE_PROPERTY, null);
		String prgSha = prgSha256(currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(GAME_IDENTITY_PROPERTY, null));

		println("=== REALROM BEGIN ===");
		println("REALROM program " + currentProgram.getName());
		println("REALROM sha256 " + (sha == null ? "NONE" : sha));
		println("REALROM prgsha256 " + prgSha);
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
		println("REALROM count symbols " + symbolCount);

		emitSample("bankcomment", bankComments);
		emitSample("ref", overlayRefs);
		emitSample("warn", warnings);
		emitSample("symbol", symbols);

		println("=== REALROM END ===");
	}

	// The "prg:" half of a "prg:<64 hex> file:<64 hex>" identity value -- the per-game key a
	// curated descriptor is written against. The "file:" half is already emitted as
	// "REALROM sha256", so only this one is new. NONE (the file's sentinel for an absent
	// property) when no loader stamped an identity or the value carries no prg: token.
	private String prgSha256(String identity) {
		if (identity != null) {
			for (String token : identity.trim().split("\\s+")) {
				if (token.startsWith("prg:")) {
					return token.substring("prg:".length());
				}
			}
		}
		return "NONE";
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
