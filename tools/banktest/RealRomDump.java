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
// cross-bank references / bank-switch comments / warning and note bookmarks / banked
// instructions, and a bounded, sorted SAMPLE of the bank-switch comments, cross-bank
// overlay references, and warning and note bookmarks. It never emits ROM bytes or
// disassembled instruction text, so the resulting golden is safe to commit even though the
// ROM it was derived from is not. Name-agnostic (unlike VerifyBankTest's name dispatch) so
// it runs on any real ROM. Driven by realrom-test.sh.
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

	// Per-category sample caps (bead grm-3pnz). This was ONE constant, SAMPLE = 25, serving
	// every category -- and the categories differ ~18x in size, so that single number was
	// quietly doing two unrelated jobs: keeping refs (13997 lines across the 33-row corpus)
	// from blowing the goldens up, and, as an unintended side effect, discarding the
	// bankComments and warnings a bless review actually reads.
	//
	// THE TRUNCATION IS BY ADDRESS, WHICH IS THE PART THAT BIT. emitSample prints a prefix of
	// a SORTED list, so on any row over the cap the highest-addressed annotations can never
	// appear. On 6502 that hides exactly the region worth watching: the reset/NMI/IRQ vectors
	// and the fixed high bank at $Fxxx. The old comment here described this as catching
	// "qualitative drift in the lowest-addressed annotations" -- an honest description of the
	// limitation, but it read as design intent, and it was not one. Nobody chose to stop
	// watching $F000-$FFFF.
	//
	// refs stays capped: it is 18x the other categories combined and is the least informative
	// line-kind per byte, so uncapping it would grow the corpus ~17x for little. The
	// annotation categories go to 250, which clears every row in the current corpus with
	// headroom (worst rows: bankComments 181 on smb3, warnings 43 on rcransom).
	private static final int SAMPLE_REFS = 25;
	private static final int SAMPLE_BANKCOMMENTS = 250;
	private static final int SAMPLE_WARNINGS = 250;
	private static final int SAMPLE_NOTES = 250;

	// Symbols are already filtered to IMPORTED/USER_DEFINED (bead grm-mej.4), which holds
	// every row in the corpus to 18 -- well under the historical cap. Left where it was;
	// raising it would move nothing.
	private static final int SAMPLE_SYMBOLS = 25;

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
		// Split on the SOURCE space (bead grm-jwh). refs.intoOverlay counts every reference
		// whose TARGET is an overlay regardless of where it came from, which conflates two
		// different things: an actual RETARGET (a reference we redirected out of the base
		// space into a bank) and an ordinary INTRA-OVERLAY branch that exists only because
		// Ghidra disassembled the overlay after the first retarget bootstrapped it. The
		// second term dominates on a working title, so the combined number is fine as a
		// coarse did-anything-happen signal (grm-8iy used it that way) but is NOT a
		// fix-effectiveness metric: a change that doubles the retargets and one that merely
		// disassembles deeper inside an already-reached overlay move it identically.
		//
		// The two sub-counters PARTITION the total by construction (a source space either is
		// or is not an overlay), so retargeted + intraOverlay == intoOverlay on every row.
		// The total is kept so that invariant is checkable in the golden itself, and so the
		// existing coarse signal stays comparable across the format change.
		long refsRetargeted = 0;
		long refsIntraOverlay = 0;
		long instrsInOverlay = 0;
		InstructionIterator instrs = currentProgram.getListing().getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();
			boolean fromOverlay = at.getAddressSpace().isOverlaySpace();
			if (fromOverlay) {
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
					if (fromOverlay) {
						refsIntraOverlay++;
					}
					else {
						refsRetargeted++;
					}
					overlayRefs.add(fmt(at) + " -> " + toSpace.getName() + "::" +
						fmt(r.getToAddress()) + " " + r.getReferenceType().getName() +
						" primary=" + r.isPrimary());
				}
			}
		}

		// Warning and Note bookmarks are collected by TYPE, not by category -- deliberately,
		// and note that this means both counts are cross-analyzer. The existing warnings
		// count has always been this way (the corpus today holds [NesBankingAnalyzer],
		// [CopyLoopAnalyzer] and Ghidra's own [Bad Instruction] under it), and the sample
		// lines carry the category so a reader can separate the channels.
		//
		// The note channel is new (bead grm-3ou part 1). grm-3ou reclassifies an unrecovered
		// bank site whose value is genuinely runtime-determined from WARNING down to NOTE --
		// and this dump sampled only Warning bookmarks, so every downgraded site would have
		// silently VANISHED from the goldens, turning an honest reclassification into what
		// looks like a fix. Emitting the count and sample unconditionally NOW, while it still
		// reads 0 for bank sites, means that behaviour change lands as ordinary reviewable
		// movement rather than needing a second format re-bless of all 33 goldens.
		//
		// It is `notes`, not grm-3ou's proposed `bankNotes`: BookmarkType.NOTE is already
		// emitted by CopyLoopAnalyzer and TransferMaterializer, so a bank-specific name would
		// claim a filter this counter does not apply -- which is the exact dishonest-metric
		// problem grm-jwh is filed about, and not one worth reintroducing in the same commit
		// that fixes it.
		List<String> warnings = new ArrayList<>();
		List<String> notes = new ArrayList<>();
		long warningCount = 0;
		long noteCount = 0;
		Iterator<Bookmark> bms = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bms.hasNext()) {
			Bookmark bm = bms.next();
			String line = fmt(bm.getAddress()) + " [" + bm.getCategory() + "] " + bm.getComment();
			if ("Warning".equals(bm.getTypeString())) {
				warningCount++;
				warnings.add(line);
			}
			else if ("Note".equals(bm.getTypeString())) {
				noteCount++;
				notes.add(line);
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
		Collections.sort(notes);

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
		println("REALROM count refs.intoOverlay.retargeted " + refsRetargeted);
		println("REALROM count refs.intoOverlay.intraOverlay " + refsIntraOverlay);
		println("REALROM count instrs.inOverlay " + instrsInOverlay);
		println("REALROM count bankComments " + bankComments.size());
		println("REALROM count warnings " + warningCount);
		println("REALROM count notes " + noteCount);
		println("REALROM count symbols " + symbolCount);

		emitSample("bankcomment", bankComments, SAMPLE_BANKCOMMENTS);
		emitSample("ref", overlayRefs, SAMPLE_REFS);
		emitSample("warn", warnings, SAMPLE_WARNINGS);
		emitSample("note", notes, SAMPLE_NOTES);
		emitSample("symbol", symbols, SAMPLE_SYMBOLS);

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

	// Print the first `cap` (sorted) entries of a category, so the golden stays small and
	// stable while still pinning concrete annotation text.
	//
	// When the cap actually bites, say so IN THE GOLDEN. The truncation used to be silent,
	// which is how it went years without anyone noticing that the sample is a prefix by
	// address and the high addresses were simply gone (bead grm-3pnz). A marker line costs
	// one line on the rows that are truncated, makes the remaining refs cap self-documenting,
	// and means a future reader can never again mistake "absent from the sample" for "absent
	// from the program".
	private void emitSample(String tag, List<String> lines, int cap) {
		int n = Math.min(cap, lines.size());
		for (int i = 0; i < n; i++) {
			println("REALROM sample." + tag + " " + lines.get(i));
		}
		if (n < lines.size()) {
			println("REALROM sample." + tag + ".truncated " + n + " of " + lines.size());
		}
	}

	// 6502 is a 16-bit CPU; every offset fits in 4 hex digits. Block/ref identity comes
	// from the (overlay) space name, printed alongside where it matters.
	private String fmt(Address addr) {
		return String.format("%04x", addr.getOffset());
	}
}
