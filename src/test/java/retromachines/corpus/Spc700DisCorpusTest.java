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
package retromachines.corpus;

import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;

import retromachines.AbstractBundledLanguageTest;
import retromachines.corpus.DisListing.Kind;
import retromachines.corpus.DisListing.Row;

/**
 * Differential comparison of {@code SPC700:LE:16:retro} disassembly against the nine
 * hand-annotated SPC700 listings in the project owner's game-music-extraction working tree
 * (bead grm-uy9s). Opt-in via {@code GRM_SPC700_DIS_CORPUS}, which names the {@code snes/}
 * directory holding the per-title subdirectories.
 *
 * <p><b>This is not a golden-file test and must never become one by accident.</b> The listings
 * are a source of leads, not of truth: the 2000-2001 disassembler that produced them may or may
 * not be as accurate as Ghidra's, so every disagreement is a question with both sides open. The
 * class therefore <em>reports</em> -- it writes a full per-row TSV to
 * {@code build/spc700-dis-corpus/} for offline triage -- and asserts only the things that are
 * genuinely our problem regardless of who is right about the mnemonics:
 * <ul>
 * <li>every byte sequence the listing calls code must disassemble at all, and
 * <li>the parse itself must stay sound (no unclassifiable lines, no overlapping upload blocks
 *     silently flattened).
 * </ul>
 * Mnemonic and operand differences are counted and dumped, never asserted.
 *
 * <p><b>Why the listing's code/data split drives the disassembly.</b> The seed set is exactly the
 * addresses the listing calls {@link Kind#CODE}, with {@code followFlow} off, and the restricted
 * set is every address the listing covers at all. So each of the listing's instruction starts is
 * decoded on its own terms and the disassembler never wanders into a pointer table -- which both
 * keeps the row-to-row alignment exact and makes the comparison a test of the decode table rather
 * than of flow recovery. That code/data map is itself the second asset in these files: a fresh
 * Ghidra import of an SPC image has nothing like it.
 *
 * <p><b>When {@code GRM_SPC700_DIS_CORPUS} is unset this Assume-skips</b>, unlike the exhaustive
 * vector tier which fails loudly. The difference is deliberate and follows what a green run is
 * allowed to mean: the vector tier is a correctness gate whose silent absence would flatter us,
 * while this class asserts almost nothing and exists to produce a report. There is no green here
 * to protect. It is excluded from the {@code test} task for the ordinary reason -- the corpus is
 * user-supplied and cannot be shipped -- and runs from the {@code spc700DisCorpusTest} task.
 */
public class Spc700DisCorpusTest extends AbstractBundledLanguageTest {

	private static final String LANGUAGE_ID = "SPC700:LE:16:retro";
	private static final String CORPUS_ENV = "GRM_SPC700_DIS_CORPUS";

	/**
	 * Title subdirectory to listing filename, in the bead's hand-comment-count priority order --
	 * except for ff2, which leads on the owner's account rather than on any measurement.
	 *
	 * <p>ff2 is the origin title (May 2000, a year before the rest) and the most thoroughly
	 * analyzed in the corpus, but most of that analysis was done <em>on a paper printout, in
	 * pencil</em>, so it is also among the least annotated on disk -- 132 commented lines of
	 * 2224. Ranking by comment density would put it near the bottom, which is exactly backwards,
	 * and no inspection of the files could reveal that. Its listing is a {@code .txt}, not a
	 * {@code .dis}, and covers only the driver's code block ($0800-$19A8, verified byte-for-byte
	 * against the ROM extraction -- see {@code tools/spc700/extract-upload-blocks.py}), not the
	 * seven sample and directory-table blocks that ship with it.
	 */
	private static final String[][] LISTINGS = {
		{ "ff2", "ff2spc.txt" },
		{ "ff3", "ff3spc.dis" },
		{ "ff5", "ff5spc.dis" },
		{ "som", "somspc.dis" },
		{ "ct", "ctspc.dis" },
		{ "sd3", "sd3spc.dis" },
		{ "gradius3", "g3spc.dis" },
		{ "mario", "mariospc.dis" },
		{ "lem", "lemspc.dis" },
		{ "fzero", "fzerospc.dis" },
	};

	@Test
	public void compareAgainstHandListings() throws Exception {
		String configured = System.getenv(CORPUS_ENV);
		assumeTrue(
			CORPUS_ENV + " is not set -- skipping the .dis corpus comparison (grm-uy9s)",
			configured != null && !configured.isBlank());

		Path root = Path.of(configured);
		Path outDir = Path.of("build", "spc700-dis-corpus");
		Files.createDirectories(outDir);

		List<String> summary = new ArrayList<>();
		List<String> problems = new ArrayList<>();
		List<String> residue = new ArrayList<>();
		summary.add("listing\tcode\tdata\tnarr\tundecoded\tsplit\tlenDiff\ttextDiff\toverlap");
		residue.add("listing\tline\taddr\tbytes\ttheirText\tourText\tcomment");

		for (String[] entry : LISTINGS) {
			Path file = root.resolve(entry[0]).resolve(entry[1]);
			if (!Files.isRegularFile(file)) {
				problems.add("missing listing: " + file);
				continue;
			}
			summary.add(compareOne(entry[0], file, outDir, problems, residue));
		}

		Files.write(outDir.resolve("summary.tsv"), summary, StandardCharsets.UTF_8);
		Files.write(outDir.resolve("residue.tsv"), residue, StandardCharsets.UTF_8);
		for (String line : summary) {
			System.out.println(line);
		}
		if (!problems.isEmpty()) {
			fail(String.join("\n", problems));
		}
	}

	private String compareOne(String title, Path file, Path outDir, List<String> problems,
			List<String> residue) throws Exception {
		DisListing listing = DisListing.parse(file);
		ProgramBuilder builder = new ProgramBuilder(title, LANGUAGE_ID);
		builder.createMemory(".ram", "0x0", 0x10000);
		ProgramDB program = builder.getProgram();

		int from = listing.minAddress();
		int to = listing.maxAddress();
		builder.setBytes(hex(from), listing.imageBytes(from, to), false);

		AddressSet seeds = new AddressSet();
		AddressSet covered = new AddressSet();
		AddressSet codeBytes = new AddressSet();
		for (Row row : listing.rows()) {
			if (row.kind() == Kind.NARRATIVE || row.length() == 0) {
				continue;
			}
			Address start = builder.addr(hex(row.address()));
			Address end = builder.addr(hex(row.address() + row.length() - 1));
			covered.addRange(start, end);
			if (row.kind() == Kind.CODE) {
				seeds.addRange(start, start);
				codeBytes.addRange(start, end);
			}
		}

		// A byte the listing writes twice with different values only matters if it is a byte we
		// disassemble; both instances in this corpus are one-byte address-column slips inside a
		// data table (see DisListing.conflicts), which cannot affect any instruction.
		for (int conflict : listing.conflicts()) {
			if (codeBytes.contains(builder.addr(hex(conflict)))) {
				problems.add(String.format("%s: image byte %04X written twice with conflicting " +
					"values and is inside a listing-declared instruction -- a flat 64K image " +
					"cannot represent this listing", title, conflict));
			}
		}

		int tx = program.startTransaction("disassemble corpus seeds");
		try {
			new DisassembleCommand(seeds, covered, false).applyTo(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}

		List<String> report = new ArrayList<>();
		report.add("line\taddr\tbytes\tkind\ttheirLen\tourLen\ttheirText\tourText\tcomment");
		int code = 0;
		int data = 0;
		int narrative = 0;
		int undecoded = 0;
		int split = 0;
		int lenDiff = 0;
		int textDiff = 0;

		for (Row row : listing.rows()) {
			switch (row.kind()) {
				case NARRATIVE -> {
					narrative++;
					report.add(String.format("%d\t%04X\t\tNARRATIVE\t\t\t\t\t%s", row.lineNumber(),
						row.address(), nz(row.comment())));
					continue;
				}
				case DATA -> {
					data++;
					report.add(String.format("%d\t%04X\t%s\tDATA\t%d\t\t\t\t%s", row.lineNumber(),
						row.address(), row.byteText(), row.length(), nz(row.comment())));
					continue;
				}
				case CODE -> code++;
			}
			Address at = builder.addr(hex(row.address()));
			Instruction instr = program.getListing().getInstructionAt(at);
			String kind = "CODE";
			if (instr == null) {
				// A listing line whose bytes are already inside an instruction we started
				// earlier. Two quite different causes produce this, neither of them a decode
				// dispute, so compare against the containing instruction and let the text
				// comparison separate them:
				//
				//  - The tool's line-splitting when a label comment falls in the middle of an
				//    instruction: it emits the bytes before the label on one line and the
				//    remaining bytes plus the whole mnemonic on the next. g3spc.dis renders
				//    "F6 00 D8  MOV A,$D800+Y" at $20D4 as a bare "20D4 F6 00", a "; 29" label
				//    line, then "20D6 D8  MOV A,$D800+Y". The texts then agree.
				//  - Deliberately overlapping instruction streams, which the ff3 listing
				//    annotates by hand: a one-byte-consuming opcode whose immediate operand IS
				//    the next instruction, used to skip it. "029F E5  MOV A,$ADEB ; pseudo op
				//    to skip instruction" is followed by "02A0 EB AD  MOV Y,$AD" -- both are
				//    correct decodes, of different entry points, and the listing shows both.
				//    The texts then differ, and the row lands in the residue where a human can
				//    see it, which is the right outcome: it is real information about the code,
				//    not a defect on either side.
				instr = program.getListing().getInstructionContaining(at);
				kind = instr == null ? "CODE-UNDECODED" : "CODE-SPLIT";
			}
			String ourText = instr == null ? "" : instr.toString().replaceAll("\\s+", " ");
			int ourLen = instr == null ? 0 : instr.getLength();
			if (instr == null) {
				undecoded++;
			}
			else {
				if (!"CODE-SPLIT".equals(kind)) {
					if (ourLen != row.length()) {
						lenDiff++;
					}
				}
				else {
					split++;
				}
				if (!equivalent(row.text(), ourText)) {
					textDiff++;
					residue.add(String.format("%s\t%d\t%04X\t%s\t%s\t%s\t%s", title,
						row.lineNumber(), row.address(), row.byteText(), row.text(), ourText,
						nz(row.comment())));
				}
			}
			report.add(String.format("%d\t%04X\t%s\t%s\t%d\t%d\t%s\t%s\t%s", row.lineNumber(),
				row.address(), row.byteText(), kind, row.length(), ourLen, row.text(), ourText,
				nz(row.comment())));
		}

		Files.write(outDir.resolve(title + ".tsv"), report, StandardCharsets.UTF_8);
		Files.write(outDir.resolve(title + "-datamap.tsv"), dataMap(listing),
			StandardCharsets.UTF_8);
		if (undecoded != 0) {
			problems.add(title + ": " + undecoded + " of " + code +
				" listing-declared code rows did not disassemble at all (see " + outDir + "/" +
				title + ".tsv)");
		}
		builder.dispose();
		return String.format("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d", title, code, data, narrative,
			undecoded, split, lenDiff, textDiff, listing.conflicts().size());
	}

	/**
	 * The listing's own code/data separation, collapsed to contiguous data regions and tagged
	 * with the section heading that introduces each.
	 *
	 * <p>This is the second, independent asset in these files and it is worth having whether or
	 * not the mnemonics agree: a fresh Ghidra import of an SPC image has no idea where code stops
	 * and the vcmd dispatch table starts, and every one of these listings marks exactly that,
	 * usually with a heading naming what the table is for ({@code ; vcmd dispatch table (D2-FF)},
	 * {@code ; table for CPU cmds 80-8F and F0-FF}). What it becomes -- disassembly hints, a
	 * fixture for an analyzer that recovers such tables, expectations for one -- is a later
	 * decision; this just extracts it in a form that survives outside the .dis file.
	 *
	 * <p>The {@code entries} column counts listing rows in the region, which for a pointer table
	 * is its entry count, and {@code labels} joins their per-row annotations ({@code 00}, {@code
	 * D2}, {@code FE-00}) -- those are the table's index domain, and they are the reason the
	 * region is worth more than a "this is data" flag.
	 */
	private static List<String> dataMap(DisListing listing) {
		List<String> out = new ArrayList<>();
		out.add("start\tend\tbytes\tentries\theading\tlabels");
		String heading = "";
		int start = -1;
		int end = -1;
		int entries = 0;
		StringBuilder labels = new StringBuilder();
		String pendingHeading = "";
		for (Row row : listing.rows()) {
			// A heading ends the region it follows as surely as an instruction does: two
			// distinct tables often abut with nothing but the heading between them (somspc.dis
			// runs the CPU-cmd-FE subcommand table straight into the vcmd dispatch table at
			// $1428), and merging them would throw away the boundary this map exists to record.
			boolean isHeading =
				row.kind() == Kind.NARRATIVE && row.comment() != null && !row.comment().isBlank();
			boolean isData = row.kind() == Kind.DATA && row.length() > 0;
			if (start >= 0 && !isData) {
				out.add(String.format("%04X\t%04X\t%d\t%d\t%s\t%s", start, end, end - start + 1,
					entries, heading, labels));
				start = -1;
			}
			if (isHeading) {
				pendingHeading = row.comment();
			}
			else if (row.kind() == Kind.CODE) {
				pendingHeading = "";
			}
			if (!isData) {
				continue;
			}
			if (start < 0) {
				start = row.address();
				heading = pendingHeading;
				entries = 0;
				labels.setLength(0);
			}
			end = row.address() + row.length() - 1;
			entries++;
			if (row.comment() != null && labels.length() < 400) {
				labels.append(labels.length() == 0 ? "" : ",").append(row.comment());
			}
		}
		if (start >= 0) {
			out.add(String.format("%04X\t%04X\t%d\t%d\t%s\t%s", start, end, end - start + 1,
				entries, heading, labels));
		}
		return out;
	}

	/**
	 * Cosmetic-difference filter for the summary counter only -- the per-row TSV always carries
	 * both texts verbatim, so nothing this collapses is lost to triage.
	 *
	 * <p>Everything it absorbs is a difference in how the two tools <em>spell</em> a decode both
	 * agree on, never a difference in what was decoded. Concretely:
	 * <ul>
	 * <li><b>Radix and padding.</b> Their {@code $F0} / {@code $0208}, our {@code 0xf0} /
	 *     {@code 0x0208}. Numbers are reduced to their value, so an operand whose <em>value</em>
	 *     differs still survives as a difference -- which is the point.
	 * <li><b>The {@code !} absolute marker.</b> We print it (it comes from the {@code ADDR16}
	 *     constructor's display piece); their tool distinguishes absolute from direct page by
	 *     printing four hex digits instead of two, which the radix rule above has already
	 *     erased. Nothing is lost by dropping it: with the opcode byte fixed, the addressing
	 *     mode is fixed too, so a genuine dispute would have to show up as a different operand
	 *     value, and that still does.
	 * <li><b>Bit-index spelling.</b> Their {@code SET1 $B1.#5}, {@code SET1 $A1,#07} and
	 *     {@code MOV1 $86.5,C} against our {@code SET1 0xb1.0x5} -- the listing is not even
	 *     self-consistent here, using {@code .#5}, {@code ,#07} and {@code .5} in the same
	 *     corpus. Bare {@code #}-prefixed digits are read as a value and {@code ,}/{@code .} are
	 *     folded together; an immediate is unaffected because both tools always give one a radix
	 *     prefix ({@code #$05} / {@code #0x5}).
	 * <li><b>The {@code <d>}/{@code <s>} destination/source annotations</b> their tool adds to
	 *     the dp,dp forms ({@code OR $8F<d>,$24<s>}). Commentary on the operand order, not a
	 *     claim about it.
	 * </ul>
	 *
	 * <p>It deliberately does <em>not</em> touch the remaining addressing-mode punctuation
	 * ({@code (X)}, {@code (X)+}, {@code [dp+X]}, {@code +Y}, the {@code /} of {@code OR1
	 * C,/dp.bit}), which both tools spell identically -- so a disagreement there survives to the
	 * residue, where it belongs.
	 */
	static boolean equivalent(String theirs, String ours) {
		return canonical(theirs).equals(canonical(ours));
	}

	private static String canonical(String text) {
		StringBuilder out = new StringBuilder();
		String s = text.toLowerCase().replace('\t', ' ').replaceAll("<[a-z]>", "");
		for (int i = 0; i < s.length();) {
			char c = s.charAt(i);
			int radixStart = -1;
			if (c == '$') {
				radixStart = i + 1;
			}
			else if (c == '0' && i + 1 < s.length() && s.charAt(i + 1) == 'x') {
				radixStart = i + 2;
			}
			else if (c == '#' && i + 1 < s.length() && Character.digit(s.charAt(i + 1), 16) >= 0 &&
				!(s.charAt(i + 1) == '0' && i + 2 < s.length() && s.charAt(i + 2) == 'x')) {
				// A bare "#7"/"#07" bit index, never an immediate: both tools always give an
				// immediate a radix prefix, so "#$05"/"#0x5" fall through to the branches above
				// and keep their '#'.
				radixStart = i + 1;
			}
			if (radixStart >= 0) {
				int j = radixStart;
				while (j < s.length() && Character.digit(s.charAt(j), 16) >= 0) {
					j++;
				}
				if (j > radixStart) {
					// '@' is not otherwise producible by either tool, so a normalized number can
					// never be confused with the immediate marker '#' that may precede it.
					out.append('@')
							.append(Long.toString(Long.parseLong(s.substring(radixStart, j), 16),
								16));
					i = j;
					continue;
				}
			}
			if (c == '.') {
				// Bit-index separator: their ".#5", ",#07" and bare ".5" all mean the same
				// thing, so fold the separator and read an unprefixed index as a value.
				c = ',';
				int j = i + 1;
				while (j < s.length() && Character.digit(s.charAt(j), 16) >= 0) {
					j++;
				}
				if (j > i + 1 && (j >= s.length() || s.charAt(j) != 'x')) {
					out.append(',')
							.append('@')
							.append(Long.toString(Long.parseLong(s.substring(i + 1, j), 16), 16));
					i = j;
					continue;
				}
			}
			if (c != ' ' && c != '!') {
				out.append(c);
			}
			i++;
		}
		return out.toString();
	}

	private static String hex(int address) {
		return String.format("0x%04x", address & 0xffff);
	}

	private static String nz(String s) {
		return s == null ? "" : s;
	}
}
