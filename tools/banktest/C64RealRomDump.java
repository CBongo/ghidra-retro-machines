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
// Read-only golden dump for the C64 .prg rows of the real-ROM tier (bead grm-t3n.1;
// tools/banktest/realrom-test.sh, platform `c64`). The C64 sibling of RealRomDump.java, which
// hard-codes NES invariants (PPU/APU blocks and symbols) and so cannot run on a C64 image.
//
// Emits a BOUNDED, NORMALIZED, COPYRIGHT-SAFE block between === REALROM BEGIN === and
// === REALROM END === holding only our own derived analysis metadata (counts, addresses,
// analyzer messages) -- never ROM bytes or instruction text. Platform-neutral lines keep
// RealRomDump's spelling (program/sha256/prgsha256/map/placement/block/count/sample.*).
//
// ADDED for C64: instruction and function counts, undefined bytes in the loaded range, a
// BIT-skip carrier census, and per-outcome counts for the decrypt-loop, copy-loop and
// skip-idiom analyzers.
//
// BIT-skip census is a SIMPLE CENSUS, not SkipIdiomRepair's logic (that class is package
// scoped inside the extension and not callable from a script): a carrier is any BIT
// instruction; it is "entered" when some flow reference targets one of its operand bytes
// (the 6502 skip idiom: BIT abs hides a 2-byte instruction at +1, or +2 hides a 1-byte one).
// The analyzers' own verdicts are counted separately from their bookmarks.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class C64RealRomDump extends GhidraScript {

	private static final int SAMPLE_BANKCOMMENTS = 250;
	private static final int SAMPLE_WARNINGS = 250;
	private static final int SAMPLE_NOTES = 250;
	private static final int SAMPLE_SYMBOLS = 25;
	private static final int SAMPLE_BIT = 100;

	private static final String PLACEMENT_OVERRIDE_PROPERTY = "Retro Machines.Placement Override";
	private static final String GAME_IDENTITY_PROPERTY = "Game Identity";

	private static final String CAT_DECRYPT = "C64DecryptLoopAnalyzer";
	private static final String CAT_COPY = "CopyLoopAnalyzer";
	private static final String CAT_SKIP = "Skip Idiom Candidate";
	private static final String CAT_OFFCUT = "Offcut Instruction";
	// C64ForthAnalyzer (grm-arbi.3): its rejected-candidate bookmarks and [Forth] plate comments.
	private static final String CAT_FORTH = "ForthAnalyzer";
	private static final String FORTH_PLATE = "[Forth] ";
	private static final int SAMPLE_FORTH = 40;

	// Fixed by c64.map on EVERY row (identical in all ten first-run dumps): checked, not printed.
	// They still count toward `count blocks.total`.
	private static final List<String> FIXED_BLOCKS = List.of(
		"block P6510 0000-0001 overlay=false",
		"block BASIC a000-bfff overlay=false",
		"block VIC d000-d3ff overlay=false",
		"block SID d400-d7ff overlay=false",
		"block COLOR_RAM d800-dbff overlay=false",
		"block CIA1 dc00-dcff overlay=false",
		"block CIA2 dd00-ddff overlay=false",
		"block IO1 de00-deff overlay=false",
		"block IO2 df00-dfff overlay=false",
		"block KERNAL e000-ffff overlay=false",
		"block CHARGEN d000-dfff overlay=true",
		"block RAM_D000 d000-dfff overlay=true");

	// KERNAL jump-table symbols the descriptor imports on every row (a sample of the vector).
	private static final List<String> FIXED_SYMBOLS = List.of(
		"ff81 CINT IMPORTED primary=true", "ff84 IOINIT IMPORTED primary=true",
		"ffa5 ACPTR IMPORTED primary=true", "ffba SETLFS IMPORTED primary=true",
		"ffbd SETNAM IMPORTED primary=true", "ffc0 OPEN IMPORTED primary=true",
		"ffd2 CHROUT IMPORTED primary=true", "ffd5 LOAD IMPORTED primary=true",
		"ffe4 GETIN IMPORTED primary=true");

	// Blocks that are system ROM / IO / system-owned, not loaded program bytes.
	private static final Set<String> NOT_LOADED = Set.of("KERNAL", "BASIC", "CHARGEN", "IO1", "IO2",
		"VIC", "SID", "CIA1", "CIA2", "COLOR_RAM", "P6510");

	@Override
	protected void run() throws Exception {
		RealRomDumpSupport out = new RealRomDumpSupport(this, currentProgram);

		List<String> blocks = new ArrayList<>();
		int blocksTotal = 0;
		int blocksOverlay = 0;
		java.util.HashSet<String> overlaySpacesWithBlock = new java.util.HashSet<>();
		long loadedBytes = 0;
		long undefinedBytes = 0;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			blocksTotal++;
			if (block.isOverlay()) {
				blocksOverlay++;
				overlaySpacesWithBlock.add(block.getStart().getAddressSpace().getName());
			}
			blocks.add("block " + block.getName() + " " + fmt(block.getStart()) + "-" +
				fmt(block.getEnd()) + " overlay=" + block.isOverlay());
			if (block.isInitialized() && !NOT_LOADED.contains(block.getName())) {
				loadedBytes += block.getSize();
				for (CodeUnit cu : currentProgram.getListing().getCodeUnits(
					new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd()),
					true)) {
					if (cu instanceof Data d && !d.isDefined()) {
						undefinedBytes += cu.getLength();
					}
				}
			}
		}
		int spacesOverlay = out.overlaySpaceCount();

		List<String> bankComments = new ArrayList<>();
		long instrCount = 0;
		long instrsInOverlay = 0;
		long bitCarriers = 0;
		long bitEntered = 0;
		List<String> bitLines = new ArrayList<>();
		InstructionIterator instrs = currentProgram.getListing().getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();
			instrCount++;
			if (at.getAddressSpace().isOverlaySpace()) {
				instrsInOverlay++;
			}
			String eol = currentProgram.getListing().getComment(CommentType.EOL, at);
			if (eol != null && eol.contains("bank ->")) {
				bankComments.add(fmt(at) + " " + eol);
			}
			if ("BIT".equals(instr.getMnemonicString()) && instr.getLength() > 1) {
				bitCarriers++;
				boolean entered = false;
				for (int i = 1; i < instr.getLength() && !entered; i++) {
					for (Reference r : currentProgram.getReferenceManager()
							.getReferencesTo(at.add(i))) {
						if (r.getReferenceType().isFlow()) {
							entered = true;
							break;
						}
					}
				}
				if (entered) {
					bitEntered++;
					bitLines.add(fmt(at) + " BIT len=" + instr.getLength() + " entered");
				}
			}
		}
		long functionCount = currentProgram.getFunctionManager().getFunctionCount();

		// Bookmarks by type, as RealRomDump does, plus per-analyzer outcome counts.
		List<String> warnings = new ArrayList<>();
		List<String> notes = new ArrayList<>();
		long warningCount = 0;
		long noteCount = 0;
		TreeMap<String, Long> outcomes = new TreeMap<>();
		Iterator<Bookmark> bms = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bms.hasNext()) {
			Bookmark bm = bms.next();
			String type = bm.getTypeString();
			String cat = bm.getCategory();
			String comment = bm.getComment();
			String line = fmt(bm.getAddress()) + " [" + cat + "] " + comment;
			if ("Warning".equals(type)) {
				warningCount++;
				warnings.add(line);
			}
			else if ("Note".equals(type)) {
				noteCount++;
				notes.add(line);
			}
			String outcome = classify(type, cat, comment);
			if (outcome != null) {
				outcomes.merge(outcome, 1L, Long::sum);
			}
		}

		// Forth words by kind (from the plate comment each accepted word gets) and rejections.
		long forthWords = 0;
		long forthColon = 0;
		long forthCode = 0;
		long forthData = 0;
		long forthDoes = 0;
		long forthVector = 0;
		List<String> forthLines = new ArrayList<>();
		Iterator<Address> plates = currentProgram.getListing()
				.getCommentAddressIterator(CommentType.PLATE, currentProgram.getMemory(), true);
		while (plates.hasNext()) {
			Address pa = plates.next();
			String plate = currentProgram.getListing().getComment(CommentType.PLATE, pa);
			if (plate == null || !plate.startsWith(FORTH_PLATE)) {
				continue;
			}
			String body = plate.substring(FORTH_PLATE.length());
			forthWords++;
			if (body.startsWith(": ")) {
				forthColon++;
			}
			else if (body.startsWith("code word ")) {
				forthCode++;
			}
			else if (body.contains(" CONSTANT ") || body.startsWith("VARIABLE ") ||
				body.contains(" USER ")) {
				forthData++;
			}
			else if (body.startsWith("VECTOR: ")) {
				forthVector++;
			}
			else {
				forthDoes++;
			}
			forthLines.add(fmt(pa) + " " + body.replace('\n', '|'));
		}
		long forthRejected = outcomes.getOrDefault("forth.rejected", 0L);

		List<String> symbols = out.deliberateSymbols(4, true);
		long symbolCount = symbols.size();
		symbols = out.requireAndRemove("symbol", symbols, FIXED_SYMBOLS);

		Collections.sort(blocks);
		for (String fixed : FIXED_BLOCKS) {
			if (!blocks.remove(fixed)) {
				out.fail("block", "missing [" + fixed + "]");
			}
		}
		// Not RealRomDump's "each overlay block is its own overlay space": a C64 overlay space
		// (RAM_A000, RAM_E000, ...) may hold SEVERAL blocks when a PRG placement splits it
		// (e.g. RAM_A000 + RAM_A000_A79A, or PRG_FFFA inside RAM_E000). The invariant that
		// does hold: every overlay space has at least one block, and every overlay block
		// lives in a counted overlay space.
		out.requireEq("spaces.overlay==distinct overlay spaces holding blocks", spacesOverlay,
			overlaySpacesWithBlock.size());
		Collections.sort(bankComments);
		Collections.sort(warnings);
		Collections.sort(notes);
		Collections.sort(bitLines);

		String placement = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(PLACEMENT_OVERRIDE_PROPERTY, null);
		String prgSha = prgSha256(currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(GAME_IDENTITY_PROPERTY, null));

		out.begin();
		println("REALROM prgsha256 " + prgSha);
		println("REALROM map " + out.mapPath());
		println("REALROM placement " + (placement == null ? "NONE" : placement));
		for (String line : blocks) {
			println("REALROM " + line);
		}
		println("REALROM count blocks.total " + blocksTotal);
		println("REALROM count blocks.overlay " + blocksOverlay);
		println("REALROM count spaces.overlay " + spacesOverlay);
		println("REALROM count instructions " + instrCount);
		println("REALROM count instrs.inOverlay " + instrsInOverlay);
		println("REALROM count functions " + functionCount);
		println("REALROM count loaded.bytes " + loadedBytes);
		println("REALROM count loaded.undefinedBytes " + undefinedBytes);
		println("REALROM count bit.carriers " + bitCarriers);
		println("REALROM count bit.entered " + bitEntered);
		println("REALROM count bankComments " + bankComments.size());
		println("REALROM count warnings " + warningCount);
		println("REALROM count notes " + noteCount);
		println("REALROM count symbols " + symbolCount);
		for (String key : new String[] { "decrypt.materialized", "decrypt.suspect",
			"decrypt.candidate", "decrypt.unbounded", "decrypt.notApplied", "decrypt.other",
			"copy.declined", "copy.unbounded", "copy.other", "skip.candidateNote",
			"skip.offcutInfo" }) {
			println("REALROM count " + key + " " + outcomes.getOrDefault(key, 0L));
		}
		println("REALROM count forth.words " + forthWords);
		println("REALROM count forth.colon " + forthColon);
		println("REALROM count forth.code " + forthCode);
		println("REALROM count forth.data " + forthData);
		println("REALROM count forth.does " + forthDoes);
		println("REALROM count forth.vector " + forthVector);
		println("REALROM count forth.rejected " + forthRejected);
		out.emitSample("sample.forth", forthLines, SAMPLE_FORTH);
		out.emitSample("sample.bankcomment", bankComments, SAMPLE_BANKCOMMENTS);
		out.emitSample("sample.warn", warnings, SAMPLE_WARNINGS);
		out.emitSample("sample.note", notes, SAMPLE_NOTES);
		out.emitSample("sample.symbol", symbols, SAMPLE_SYMBOLS);
		out.emitSample("sample.bit", bitLines, SAMPLE_BIT);
		out.end();
	}

	// Maps a bookmark to a named outcome counter, or null when it is not one of the analyzers'
	// verdicts. Keyed off the analyzers' message prefixes (C64DecryptLoopAnalyzer, CopyLoopAnalyzer).
	private String classify(String type, String cat, String comment) {
		String c = comment == null ? "" : comment;
		if (CAT_DECRYPT.equals(cat)) {
			if (c.startsWith("SUSPECT decrypted")) {
				return "decrypt.suspect";
			}
			if (c.startsWith("decrypted ")) {
				return "decrypt.materialized";
			}
			if (c.startsWith("decrypted range start")) {
				return null; // companion bookmark of the line above
			}
			if (c.startsWith("possible decrypt loop")) {
				return "decrypt.candidate";
			}
			if (c.contains("could not be bounded")) {
				return "decrypt.unbounded";
			}
			if (c.contains("not applied") || c.contains("could not read")) {
				return "decrypt.notApplied";
			}
			return "decrypt.other";
		}
		if (CAT_COPY.equals(cat)) {
			if (c.contains("could not be bounded")) {
				return "copy.unbounded";
			}
			if (c.contains("NOT materialized")) {
				return "copy.declined";
			}
			return "copy.other";
		}
		if (CAT_SKIP.equals(cat)) {
			return "skip.candidateNote";
		}
		if (CAT_FORTH.equals(cat) && c.startsWith("rejected colon candidate")) {
			return "forth.rejected";
		}
		if (CAT_OFFCUT.equals(cat)) {
			return "skip.offcutInfo";
		}
		return null;
	}

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

	private String fmt(Address addr) {
		return RealRomDumpSupport.fmt(addr, 4);
	}
}
