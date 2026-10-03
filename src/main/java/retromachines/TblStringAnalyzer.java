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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import retromachines.text.TblTable;

/**
 * Decodes end-token-terminated text runs with a per-game {@code .tbl} table (bead
 * {@code grm-pqk}). Gated on the {@value TblTableSupport#OPTIONS_NODE} program options node the
 * loader fills when the user supplies a table at import; absent that, {@link #canAnalyze} is
 * false and the analyzer never appears in the options dialog.
 *
 * <p><b>Output (MVP):</b> a PRE comment {@code TBL: <decoded text><end label>} and a NOTE bookmark
 * (category {@value #CATEGORY}) at each run's first byte -- the {@link C64BasicAnalyzer}
 * philosophy of annotating rather than retyping. No datatype is applied: a per-game dynamic
 * table cannot be a JVM charset, and a custom dynamic datatype is a possible later phase.
 *
 * <p><b>Search:</b> over loaded, initialized memory, left to right: at each still-undefined
 * byte, try {@link TblTable#decodeRun}; a run needs a terminating end token and at least
 * "Minimum string length" decoded entries. A hit consumes the run; a miss advances one byte.
 * Because the scan is leftmost-first and greedy, a run is anchored at the first decodable byte,
 * which can include a few junk bytes before the real start when the table maps most bytes (the
 * table's own coverage decides how selective this is). Runs touching defined data or
 * instructions are skipped, so running at low priority leaves code alone. A PRE comment the
 * user (or anything else) already wrote is never overwritten; this analyzer's own comment is
 * refreshed on re-analysis.
 *
 * <p><b>Mirrors:</b> byte-mapped blocks ({@code MemoryBlock.isMapped()}) are excluded from the
 * search, so a string is annotated once at its canonical address, not once per mirror
 * (grm-a6n0), as are separate blocks over the same file bytes (see {@link #excludeMirrors}).
 * <b>Known limitation:</b> the leftmost-greedy start is kept as is -- no rule
 * (trim to an incoming reference, etc.) is clean without reference data this analyzer runs too
 * early to rely on, and a wrong trim would drop real text; supply a table whose coverage does
 * not map the padding byte to keep starts tight.
 */
public class TblStringAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Text Table Strings";
	private static final String DESCRIPTION =
		"Decodes end-token-terminated strings with the per-game .tbl text table supplied at " +
			"import and annotates them with PRE comments and bookmarks (bead grm-pqk).";

	static final String CATEGORY = "TblStringAnalyzer";
	static final String COMMENT_PREFIX = "TBL: ";

	private static final String MIN_LENGTH_OPTION = "Minimum string length";
	private static final int DEFAULT_MIN_LENGTH = 4;
	/** Longest run (bytes, end token included) the scan will follow before giving up. */
	private static final int MAX_RUN_BYTES = 512;

	private int minLength = DEFAULT_MIN_LENGTH;

	/** Creates the table-gated text analyzer. */
	public TblStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Speculative like the ASCII/PETSCII string analyzers: run after code discovery so
		// the leftover undefined bytes are all that is considered.
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	/**
	 * Tests whether the loader stored a usable text table.
	 *
	 * @param program the program to inspect
	 * @return {@code true} when a table is present and parses
	 */
	@Override
	public boolean canAnalyze(Program program) {
		try {
			return TblTableSupport.fromProgram(program) != null;
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(MIN_LENGTH_OPTION, minLength, null,
			"Fewest decoded table entries (excluding the end token) a run needs to be annotated.");
		minLength = Math.max(1, options.getInt(MIN_LENGTH_OPTION, minLength));
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		minLength = Math.max(1, options.getInt(MIN_LENGTH_OPTION, minLength));
	}

	/**
	 * Scans the given addresses for table-decodable strings and annotates them.
	 *
	 * @param program the program being analyzed
	 * @param set the addresses to inspect
	 * @param monitor the task cancellation monitor
	 * @param log the analysis message log
	 * @return {@code true} when analysis completed or was not applicable
	 * @throws CancelledException if the task was cancelled
	 */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		TblTable table;
		try {
			table = TblTableSupport.fromProgram(program);
		}
		catch (RuntimeException e) {
			AnalyzerLog.warn(this, log, "Stored text table no longer parses: " + e.getMessage());
			return false;
		}
		if (table == null) {
			return true;
		}

		AddressSet searchable = new AddressSet(set);
		searchable = searchable.intersect(program.getMemory().getLoadedAndInitializedAddressSet());
		excludeMirrors(program, searchable);
		int found = 0;
		int skipped = 0;
		for (AddressRange range : searchable.getAddressRanges()) {
			monitor.checkCancelled();
			byte[] data = new byte[(int) Math.min(range.getLength(), Integer.MAX_VALUE)];
			try {
				program.getMemory().getBytes(range.getMinAddress(), data);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			int p = 0;
			while (p < data.length) {
				if ((p & 0xFFF) == 0) {
					monitor.checkCancelled();
				}
				TblTable.Run run = table.decodeRun(data, p, MAX_RUN_BYTES);
				if (run == null || run.entryCount() < minLength) {
					p++;
					continue;
				}
				Address start = range.getMinAddress().add(p);
				Address end = start.add(run.length() - 1);
				if (!DataUtilities.isUndefinedRange(program, start, end)) {
					p++;
					continue;
				}
				String endLabel = table.render(data, p + run.length() - 1, 1);
				if (annotate(program, start, run, endLabel)) {
					found++;
				}
				else {
					skipped++;
				}
				p += run.length();
			}
		}
		AnalyzerLog.info(this, NAME + " running: annotated " + found + " string(s)" +
			(skipped > 0 ? ", left " + skipped + " alone (existing PRE comment)" : ""));
		return true;
	}

	/**
	 * Removes every mirror block from the search set so a string is annotated once, at its
	 * canonical (lowest-addressed) copy (grm-a6n0). Two shapes occur: a byte-mapped block
	 * ({@code isMapped()}, a view of another block), and an independent block backed by the very
	 * same bytes of the image -- same FileBytes and offset -- such as the NROM-128 loader's
	 * separate {@code PRG_LO}/{@code PRG_HI} windows. Blocks are visited in address order, so the
	 * first one claiming a given file range is the canonical one.
	 */
	private static void excludeMirrors(Program program, AddressSet searchable) {
		Set<String> claimed = new HashSet<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isMapped()) {
				searchable.delete(block.getStart(), block.getEnd());
				continue;
			}
			List<MemoryBlockSourceInfo> infos = block.getSourceInfos();
			if (infos.size() != 1 || infos.get(0).getFileBytes().isEmpty()) {
				continue;
			}
			MemoryBlockSourceInfo info = infos.get(0);
			FileBytes fb = info.getFileBytes().get();
			String key = fb.getFilename() + ":" + fb.getFileOffset() + ":" + fb.getSize() + ":" +
				info.getFileBytesOffset() + ":" + info.getLength();
			if (!claimed.add(key)) {
				searchable.delete(block.getStart(), block.getEnd());
			}
		}
	}

	private static boolean annotate(Program program, Address start, TblTable.Run run,
			String endLabel) {
		Listing listing = program.getListing();
		String existing = listing.getComment(CommentType.PRE, start);
		if (existing != null && !existing.startsWith(COMMENT_PREFIX)) {
			return false; // somebody else's comment: never clobber
		}
		String text = run.text().replace("\r", "").replace("\n", "\\n");
		listing.setComment(start, CommentType.PRE, COMMENT_PREFIX + text + endLabel);
		program.getBookmarkManager().setBookmark(start, BookmarkType.NOTE, CATEGORY,
			"text: " + text);
		return true;
	}
}
