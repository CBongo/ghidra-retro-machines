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

import com.google.gson.JsonObject;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.ascii.CharSetRecognizer;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import retromachines.data.PetsciiShiftedStringDataType;
import retromachines.data.PetsciiStringDataType;
import retromachines.data.TerminatedPetsciiShiftedStringDataType;
import retromachines.data.TerminatedPetsciiStringDataType;

/**
 * Descriptor-gated PETSCII string search analyzer (bead {@code grm-1.4}, Phase E). Layers
 * on top of the same PETSCII charsets/datatypes {@link retromachines.charset.RetroCharsetProvider}
 * and {@code retromachines.data.*} register for the GUI's string charset/datatype pickers
 * (bead {@code grm-1.4.3}): this analyzer is what makes Ghidra's own "Search &gt; For Strings"
 * mechanism (hardcoded to ASCII, see class-level notes on {@link StringSearcher}) find PETSCII
 * runs automatically during auto-analysis.
 * <p>
 * <b>Gating:</b> only runs when the importing loader recorded a compiled descriptor
 * ({@link DescriptorSupport#MAP_PATH_PROPERTY}) whose {@code system.text} declares
 * {@code encoding: petscii} AND carries a {@code string_search} subtree (its mere presence
 * is the opt-in -- a descriptor author who wants PETSCII string typing adds it; one who
 * doesn't, omits it). {@code system.text.variant} selects which datatype pair
 * ({@code unshifted_graphics} -&gt; {@link PetsciiStringDataType}/
 * {@link TerminatedPetsciiStringDataType}, {@code shifted_lowercase} -&gt;
 * {@link PetsciiShiftedStringDataType}/{@link TerminatedPetsciiShiftedStringDataType}) is
 * applied; {@code system.text.string_search.min_length} sets the minimum run length
 * (default 4).
 * <p>
 * <b>Search:</b> uses {@link StringSearcher}'s {@code CharSetRecognizer} overload with a
 * small recognizer accepting PETSCII's printable/identity range (0x20-0x5F, shared with
 * ASCII) plus, for the shifted variant, the C1-mirrored uppercase range (0xC1-0xDA) --
 * see docs/petscii.md's mirror-range convention. Alignment 1, all-char-widths false,
 * no forced null termination (fixed vs. terminated is decided per found run in the
 * callback, not by the searcher). Because {@code StringSearcher} still adds a UTF-16
 * matcher whenever the language's wide-char size is 2 regardless of the all-char-widths
 * flag, the callback filters out anything but the plain single-byte
 * {@link StringDataType} sequences the recognizer actually drives.
 * <p>
 * <b>Typing:</b> a found run is only ever typed into a fully undefined range (never
 * clobbers existing data/instructions/references); if the byte immediately following the
 * run is a readable, still-undefined {@code $00}, the terminated datatype is applied over
 * the run plus that byte, otherwise the fixed-length datatype is applied over exactly the
 * run. Late priority ({@link AnalysisPriority#LOW_PRIORITY}, matching the speculative
 * nature of ASCII's own {@code StringsAnalyzer}) so disassembly/code discovery has already
 * claimed real instructions before this analyzer considers the leftover undefined bytes.
 */
public class PetsciiStringAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "PETSCII Strings";
	private static final String DESCRIPTION =
		"Searches descriptor-declared PETSCII text for printable runs and types them as " +
			"PetsciiString/TerminatedPetsciiString data (bead grm-1.4).";

	/** Descriptor-selected analyzer policy: minimum run length and which datatype pair
	 *  (fixed, terminated) to apply for the configured variant. */
	private record TextConfig(int minLength, String variant, DataType fixedType,
			DataType terminatedType) {
	}

	public PetsciiStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Speculative, like ASCII's own StringsAnalyzer: run late so real code/data
		// discovery has already claimed everything it can before this analyzer considers
		// the leftover undefined bytes.
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return textConfig(program) != null;
		}
		catch (IOException | RuntimeException e) {
			return false;
		}
	}

	/** Resolves the descriptor-selected PETSCII string-search policy, or {@code null} if
	 *  this program has no descriptor, or its descriptor has no {@code system.text} with
	 *  {@code encoding: petscii} and a {@code string_search} subtree. */
	private static TextConfig textConfig(Program program) throws IOException {
		String mapPath = program.getOptions(Program.PROGRAM_INFO).getString(
			DescriptorSupport.MAP_PATH_PROPERTY, "");
		if (mapPath == null || mapPath.isBlank()) {
			return null;
		}
		JsonObject map = DescriptorSupport.loadMap(mapPath);
		JsonObject system = map.getAsJsonObject("system");
		JsonObject text = system == null ? null : system.getAsJsonObject("text");
		if (text == null || !text.has("string_search")) {
			return null;
		}
		String encoding = text.has("encoding") ? text.get("encoding").getAsString() : null;
		if (!"petscii".equals(encoding)) {
			return null;
		}
		String variant =
			text.has("variant") ? text.get("variant").getAsString() : "unshifted_graphics";
		DataType fixedType;
		DataType terminatedType;
		switch (variant) {
			case "unshifted_graphics" -> {
				fixedType = PetsciiStringDataType.dataType;
				terminatedType = TerminatedPetsciiStringDataType.dataType;
			}
			case "shifted_lowercase" -> {
				fixedType = PetsciiShiftedStringDataType.dataType;
				terminatedType = TerminatedPetsciiShiftedStringDataType.dataType;
			}
			default -> throw new IllegalArgumentException(
				"system.text has unknown variant '" + variant + "'");
		}
		JsonObject search = text.getAsJsonObject("string_search");
		int minLength = search.has("min_length") ? search.get("min_length").getAsInt() : 4;
		return new TextConfig(minLength, variant, fixedType, terminatedType);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean completed = analyze(program, set, monitor, log);
		if (completed) {
			AnalyzerRunLog.markCompleted(program, getClass());
		}
		return completed;
	}

	private boolean analyze(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		TextConfig config;
		try {
			config = textConfig(program);
		}
		catch (IOException | RuntimeException e) {
			log.appendMsg(getName(), "Failed to read PETSCII text descriptor policy: " +
				e.getMessage());
			return false;
		}
		if (config == null) {
			return true;
		}

		boolean verbose = AnalyzerRunLog.isInitialRun(program, getClass());

		CharSetRecognizer recognizer = new PetsciiCharSetRecognizer(config.variant());
		StringSearcher searcher =
			new StringSearcher(program, recognizer, config.minLength(), 1, false, false);

		int[] appliedCount = { 0 };
		FoundStringCallback callback = found -> {
			if (monitor.isCancelled()) {
				return;
			}
			if (tryApply(program, found, config, log)) {
				appliedCount[0]++;
			}
		};
		// searchLoadedMemoryBlocksOnly=true restricts the search to
		// program.getMemory().getLoadedAndInitializedAddressSet() intersected with `set`
		// (see AbstractStringSearcher.updateAddressesToSearch) -- uninitialized/unloaded
		// memory (I/O, uninitialized ROM windows) is never scanned.
		searcher.search(set, callback, true, monitor);

		if (verbose) {
			log.appendMsg(getName(),
				NAME + " running: applied " + appliedCount[0] + " PETSCII string(s)");
		}
		return true;
	}

	/**
	 * Applies the configured PETSCII datatype to one found run, or does nothing (returning
	 * {@code false}) if it fails any guard: not a plain single-byte-per-char sequence (the
	 * UTF-16 side-scan {@link StringSearcher} performs whenever the language's wide-char
	 * size is 2, regardless of the all-char-widths flag), or the run's addresses are not
	 * entirely undefined (never overwrites existing data/instructions).
	 * <p>
	 * <b>Terminator convention:</b> {@code ghidra.util.ascii.MinLengthCharSequenceMatcher}
	 * (which drives {@link StringSearcher} here) already folds a run's trailing
	 * {@code $00} into the found sequence/{@link FoundString} itself when the run ended
	 * that way -- {@code found.getEndAddress()} is the {@code $00} byte's own address,
	 * not one past it. So "was this run null-terminated" is answered by reading the byte at
	 * {@code found.getEndAddress()}, never by peeking a byte further; peeking further
	 * would (as an earlier version of this method did) read into whatever follows the
	 * match instead of the match's own last byte.
	 */
	private boolean tryApply(Program program, FoundString found, TextConfig config,
			MessageLog log) {
		if (!(found.getDataType() instanceof StringDataType)) {
			// Not our single-byte-per-char match -- the searcher's automatic UTF-16 (or
			// UTF-32) side-scan matcher, which uses UnicodeDataType/Unicode32DataType.
			return false;
		}
		Address start = found.getAddress();
		Address end = found.getEndAddress();
		if (!DataUtilities.isUndefinedRange(program, start, end)) {
			return false;
		}

		boolean terminated;
		try {
			terminated = (program.getMemory().getByte(end) & 0xFF) == 0;
		}
		catch (MemoryAccessException e) {
			terminated = false;
		}

		try {
			DataType dataType = terminated ? config.terminatedType() : config.fixedType();
			DataUtilities.createData(program, start, dataType, found.getLength(),
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			return true;
		}
		catch (Exception e) {
			log.appendMsg(getName(),
				"Failed to type PETSCII string at 0x" + start + ": " + e.getMessage());
			return false;
		}
	}

	/** Accepts PETSCII's printable/identity range (0x20-0x5F, identical to ASCII in that
	 *  span) always, plus the shifted variant's C1-mirrored uppercase range (0xC1-0xDA;
	 *  see docs/petscii.md's mirror-range convention) when configured. */
	private static final class PetsciiCharSetRecognizer implements CharSetRecognizer {
		private final boolean shifted;

		PetsciiCharSetRecognizer(String variant) {
			this.shifted = "shifted_lowercase".equals(variant);
		}

		@Override
		public boolean contains(int c) {
			if (c >= 0x20 && c <= 0x5F) {
				return true;
			}
			return shifted && c >= 0xC1 && c <= 0xDA;
		}
	}
}
