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

import java.io.IOException;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recognizes a tokenized-BASIC-start C64 PRG ({@link C64PrgLoader#NAME}), walks the
 * line-link chain ({@link C64BasicWalker}), types the link/line-number words, writes a
 * petcat-compatible detokenized comment per line, and fixes the loader's
 * function-at-load-address wart for these programs by locating the real machine-language
 * entry point from a {@code SYS <decimal>} line and marking a function there instead
 * (bead grm-odt.1).
 * <p>
 * <b>Token source of truth:</b> this class transcribes no token table. It reads the
 * {@code BASIC_V2_TOKEN} enum directly out of the bundled {@code machines/c64.gdt}
 * archive (see {@link BasicV2TokenLookup}) -- the same archive
 * {@link C64PrgLoader}/{@link DescriptorSupport} use for IO-chip register structs. The
 * enum is read from the archive's own data type manager, not resolved into the
 * program's, because it is only ever queried for member names here (token bytes are
 * rendered into a listing comment, never typed onto the byte itself -- see the
 * class-level data-typing note below).
 * <p>
 * <b>Text rendering:</b> every non-token PETSCII byte (including everything inside a
 * quoted string, and the raw comment body after a {@code REM} token) goes through
 * {@link PetsciiMapper} with {@link PetsciiMapper.Variant#UNSHIFTED_GRAPHICS} -- the
 * variant a stock C64 boots into (uppercase/graphics mode), matching what a BASIC
 * program listing looks like on power-up. A future per-program variant override (for
 * programs that POKE the shift flag or issue a shift-lowercase control code) is not
 * implemented here.
 * <p>
 * <b>Data typing:</b> only the 2-byte link and 2-byte line-number fields are typed
 * ({@link WordDataType}, with an EOL comment naming the field); the tokenized text bytes
 * between the line number and the {@code $00} terminator are left undefined. The
 * detokenized rendering already carries the full meaning of those bytes in a PRE comment
 * at the line's start address (petcat-style: {@code "<line number> <rendered text>"});
 * typing them as a byte array would duplicate that information less readably (a raw hex
 * dump next to a comment that already says what it means) and would block any more
 * specific future typing (e.g. per-opcode structuring) of the same bytes.
 */
public class C64BasicAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C64 BASIC Detokenizer";
	private static final String DESCRIPTION =
		"Walks a tokenized-BASIC-start C64 PRG's line-link chain, types the line link/" +
			"number words, writes petcat-compatible detokenized comments, and marks the " +
			"real ML entry point from a SYS line (instead of the loader's load-address " +
			"function mark, which is wrong for BASIC-start programs).";

	private static final String CATEGORY = "C64BasicAnalyzer";
	private static final String GDT_PATH = "machines/c64.gdt";

	public C64BasicAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Run early -- right after format analysis, before Ghidra's own block/disassembly
		// analyzers reach the load address -- so the function this analyzer marks at the
		// SYS target (not the load address, which the loader now deliberately leaves
		// unmarked for BASIC-start PRGs) is what downstream disassembly/reference/
		// function analysis sees.
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		return format != null && format.equals(C64PrgLoader.NAME);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		MemoryBlock prgBlock = program.getMemory().getBlock("PRG");
		if (prgBlock == null) {
			return true; // nothing this analyzer can do without knowing the PRG's extent
		}
		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		long loadAddr = prgBlock.getStart().getOffset();
		long limitAddr = prgBlock.getEnd().getOffset() + 1;

		C64BasicWalker.ByteSource src = addr -> {
			if (addr < loadAddr || addr >= limitAddr) {
				return -1;
			}
			try {
				return program.getMemory().getByte(baseSpace.getAddress(addr)) & 0xFF;
			}
			catch (MemoryAccessException e) {
				return -1;
			}
		};

		// Same structural sniff C64PrgLoader used to decide whether to skip its
		// load-address function mark -- see C64BasicWalker.isBasicStart's javadoc for why
		// this (not "walk() found >= 1 line") is the right gate: plain machine code can
		// spuriously produce a single bogus "line" out of a coincidental $00 byte, and
		// without this same check here this analyzer would type/comment that bogus line
		// (which is exactly what happened before this check was added -- see grm-odt.1).
		if (!C64BasicWalker.isBasicStart(src, loadAddr, limitAddr)) {
			return true;
		}
		C64BasicWalker.WalkResult result = C64BasicWalker.walk(src, loadAddr, limitAddr);
		if (result.lines().isEmpty()) {
			return true; // trivially empty BASIC program; nothing to annotate
		}
		log.appendMsg(getName(), NAME + " running: " + result.lines().size() +
			" BASIC line(s) at 0x" + Long.toHexString(loadAddr));

		FileDataTypeManager gdtMgr;
		try {
			gdtMgr = DescriptorSupport.openGdt(GDT_PATH);
		}
		catch (IOException e) {
			log.appendMsg(getName(), "Failed to open " + GDT_PATH + ": " + e.getMessage());
			return false;
		}
		PetsciiMapper petscii;
		try {
			petscii = PetsciiMapper.load();
		}
		catch (IOException e) {
			log.appendMsg(getName(), "Failed to load petscii.map: " + e.getMessage());
			gdtMgr.close();
			return false;
		}

		try {
			BasicTokenLookup tokenLookup = BasicV2TokenLookup.fromGdt(gdtMgr);
			if (tokenLookup == null) {
				log.appendMsg(getName(),
					"BASIC_V2_TOKEN enum not found in " + GDT_PATH + "; token bytes will " +
						"render as raw PETSCII escapes only");
			}

			boolean sysHandled = false;
			for (C64BasicWalker.BasicLine line : result.lines()) {
				monitor.checkCancelled();

				Address lineAddr = baseSpace.getAddress(line.lineAddr());
				Address lineNumAddr = baseSpace.getAddress(line.lineAddr() + 2);
				typeWord(program, lineAddr, "line link", log);
				typeWord(program, lineNumAddr, "line number", log);

				int textLen = (int) (line.terminatorAddr() - line.textStart());
				byte[] textBytes = new byte[textLen];
				try {
					program.getMemory().getBytes(baseSpace.getAddress(line.textStart()), textBytes);
				}
				catch (MemoryAccessException e) {
					log.appendMsg(getName(), "Failed to read line text at 0x" +
						Long.toHexString(line.textStart()) + ": " + e.getMessage());
					continue;
				}

				LineRender rendered = renderLine(textBytes, tokenLookup, petscii);
				String listing = line.lineNumber() + " " + rendered.text();
				program.getListing().setComment(lineAddr, CommentType.PRE, listing);

				if (!sysHandled && (rendered.sysTarget() != null || rendered.sysNonLiteral())) {
					sysHandled = true;
					if (rendered.sysTarget() != null) {
						markSysEntry(program, monitor, baseSpace, rendered.sysTarget(),
							line.lineNumber(), log);
					}
					else {
						program.getBookmarkManager().setBookmark(lineAddr, BookmarkType.NOTE,
							CATEGORY, "SYS argument on line " + line.lineNumber() +
								" is not a simple decimal literal; not marking a function");
					}
				}
			}

			if (result.isMalformed()) {
				Address at = baseSpace.getAddress(result.malformedAt());
				String detail = result.expectedNextAddr() == null
						? "line link 0x" + Long.toHexString(result.malformedLink()) +
							" is not readable/parseable as a valid next line"
						: "line link 0x" + Long.toHexString(result.malformedLink()) +
							" does not match the address reached by scanning to this line's " +
							"terminator (0x" + Long.toHexString(result.expectedNextAddr()) + ")";
				program.getBookmarkManager().setBookmark(at, BookmarkType.WARNING, CATEGORY,
					"Malformed BASIC line link at 0x" + Long.toHexString(result.malformedAt()) +
						": " + detail + "; stopped walking the line chain here");
				log.appendMsg(getName(), "Malformed BASIC line link: " + detail);
			}
		}
		finally {
			gdtMgr.close();
		}

		return true;
	}

	private void typeWord(Program program, Address at, String fieldName, MessageLog log) {
		try {
			DataUtilities.createData(program, at, WordDataType.dataType, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			program.getListing().setComment(at, CommentType.EOL, fieldName);
		}
		catch (Exception e) {
			log.appendMsg(getName(),
				"Failed to type " + fieldName + " word at 0x" + at + ": " + e.getMessage());
		}
	}

	private void markSysEntry(Program program, TaskMonitor monitor, AddressSpace baseSpace,
			int sysTarget, int lineNumber, MessageLog log) {
		try {
			Address sysAddr = baseSpace.getAddress(sysTarget & 0xFFFF);
			program.getSymbolTable().addExternalEntryPoint(sysAddr);
			if (program.getSymbolTable().getPrimarySymbol(sysAddr) == null) {
				program.getSymbolTable().createLabel(sysAddr, "sys_entry", SourceType.IMPORTED);
			}
			new CreateFunctionCmd(sysAddr).applyTo(program, monitor);
			program.getListing().setComment(sysAddr, CommentType.PLATE,
				"SYS target from BASIC line " + lineNumber);
		}
		catch (Exception e) {
			log.appendMsg(getName(), "Failed to mark SYS entry at " + sysTarget + ": " +
				e.getMessage());
		}
	}

	// ------------------------------------------------------------------
	// Detokenizer
	// ------------------------------------------------------------------

	/** One line's rendering: the petcat-style text (line number not included), plus SYS
	 *  detection state (see grm-odt.1's SYS-detection scope: simple decimal literal only). */
	private record LineRender(String text, Integer sysTarget, boolean sysNonLiteral) {
	}

	/**
	 * Renders one BASIC line's tokenized text bytes into petcat-style display text, and
	 * (as a side effect of the same single pass) detects a {@code SYS <decimal>}
	 * occurrence in this line.
	 * <p>
	 * State machine: outside quotes and not past a {@code REM} token, a byte &gt;= $80 is
	 * looked up as a token (dialect-supplied via {@code tokenLookup}); a {@code $22}
	 * toggles quote state; every other byte -- including every byte once inside quotes
	 * (control/graphics codes are literal PETSCII there, never tokens) and every byte
	 * after a {@code REM} token (the rest of the line is raw PETSCII to the terminator,
	 * matching the real tokenizer, which stops crunching entirely once it emits REM) --
	 * renders via {@link PetsciiMapper}. Unlike REM, a {@code DATA} statement is
	 * <em>not</em> given special raw-text treatment: real BASIC 2 tokenizes DATA argument
	 * text exactly like anywhere else outside quotes (the well-known "DATA GOTO tokenizes
	 * GOTO" gotcha, which petcat's tokenizer/detokenizer also reproduces), so no
	 * DATA-specific branch exists here -- the general outside-quotes rule already does
	 * the right thing, and a colon following DATA text needs no special casing either
	 * (it is just PETSCII $3A, never a token, rendered like any other byte &lt; $80).
	 */
	private LineRender renderLine(byte[] data, BasicTokenLookup tokenLookup, PetsciiMapper petscii) {
		StringBuilder sb = new StringBuilder();
		boolean inQuotes = false;
		boolean afterRem = false;
		Integer sysTarget = null;
		boolean sysNonLiteral = false;
		int i = 0;
		int n = data.length;

		while (i < n) {
			int b = data[i] & 0xFF;

			if (afterRem) {
				sb.append(petscii.toDisplayEscaped(b, PetsciiMapper.Variant.UNSHIFTED_GRAPHICS));
				i++;
				continue;
			}

			if (!inQuotes && b >= 0x80 && tokenLookup != null) {
				BasicTokenLookup.Match m = tokenLookup.lookup(data, i);
				if (m != null) {
					sb.append(m.name());
					if ("REM".equals(m.name())) {
						afterRem = true;
					}
					else if ("SYS".equals(m.name()) && sysTarget == null && !sysNonLiteral) {
						int j = i + m.bytesConsumed();
						while (j < n && (data[j] & 0xFF) == 0x20) {
							j++;
						}
						long value = 0;
						boolean any = false;
						while (j < n) {
							int d = data[j] & 0xFF;
							if (d < 0x30 || d > 0x39) {
								break;
							}
							value = value * 10 + (d - 0x30);
							any = true;
							j++;
						}
						if (any) {
							sysTarget = (int) value;
						}
						else {
							sysNonLiteral = true;
						}
					}
					i += m.bytesConsumed();
					continue;
				}
				// Unassigned token-range byte (e.g. BASIC 2's $CC-$FF) falls through to
				// the raw PETSCII render below, escaped like any other byte.
			}

			if (b == 0x22) {
				inQuotes = !inQuotes;
			}
			sb.append(petscii.toDisplayEscaped(b, PetsciiMapper.Variant.UNSHIFTED_GRAPHICS));
			i++;
		}

		return new LineRender(sb.toString(), sysTarget, sysNonLiteral);
	}
}
