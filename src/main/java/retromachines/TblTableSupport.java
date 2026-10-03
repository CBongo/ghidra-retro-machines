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

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;

import retromachines.text.TblTable;

/**
 * Loader-side plumbing for the optional per-game {@code .tbl} text table (bead
 * {@code grm-pqk}), shared so a second loader (SNES) can offer the same option by calling the same
 * four methods.
 *
 * <p>The raw table text is stored VERBATIM in the program, in a dedicated options node
 * ({@value #OPTIONS_NODE}), together with the source file name. Storing the text rather than the
 * path keeps a project portable and means re-analysis never needs the original file;
 * {@link TblStringAnalyzer} reads it back with {@link #fromProgram}. The text is stored raw
 * rather than parsed, so a future grammar extension re-reads existing programs correctly.
 */
final class TblTableSupport {

	/** Program options node holding the table. Its absence means "no table supplied". */
	static final String OPTIONS_NODE = "Retro Text Table";

	/** Option key (inside {@link #OPTIONS_NODE}): the raw {@code .tbl} text. */
	static final String TEXT_KEY = "Table Text";

	/** Option key (inside {@link #OPTIONS_NODE}): the source file's name (no directory). */
	static final String SOURCE_KEY = "Source File";

	/** Import-dialog label of the option. */
	static final String OPTION_NAME = "Text Table (.tbl)";

	/** Headless argument: {@code -loader-tblFile <path>}. */
	static final String CMD_ARG = Loader.COMMAND_LINE_ARG_PREFIX + "-tblFile";

	private TblTableSupport() {
	}

	/**
	 * Creates the loader option, pre-filled in the GUI from the remembered path. Headless imports
	 * never read the persistent preferences, only the command-line value.
	 *
	 * @param prefKey the per-loader preference key
	 * @return the option
	 */
	static Option newOption(String prefKey) {
		String saved = SystemUtilities.isInHeadlessMode() ? ""
				: Preferences.getProperty(prefKey, "", true);
		return new RomFileOption(OPTION_NAME, saved, CMD_ARG);
	}

	/**
	 * Checks the option value without side effects.
	 *
	 * @param options the loader's options
	 * @return an error message, or {@code null} when no table was given or it is usable
	 */
	static String validate(List<Option> options) {
		String path = OptionUtils.getOption(OPTION_NAME, options, "");
		if (path == null || path.isBlank()) {
			return null;
		}
		try {
			TblTable.parse(readText(new File(path.trim())));
			return null;
		}
		catch (IOException | RuntimeException e) {
			return OPTION_NAME + ": " + e.getMessage();
		}
	}

	/**
	 * Applies the option at import time: reads the file, checks that it parses, and records
	 * the raw text in the program. A problem is logged and nothing is stored (the import
	 * itself proceeds -- the table is an optional annotation, not a precondition).
	 *
	 * @param program the program being created
	 * @param options the loader's options
	 * @param prefKey the per-loader preference key to remember the path under (GUI only)
	 * @param log the import log
	 */
	static void apply(Program program, List<Option> options, String prefKey, MessageLog log) {
		String path = OptionUtils.getOption(OPTION_NAME, options, "");
		if (path == null || path.isBlank()) {
			return;
		}
		File file = new File(path.trim());
		String text;
		try {
			text = readText(file);
			TblTable table = TblTable.parse(text);
			for (String w : table.warnings()) {
				log.appendMsg(OPTION_NAME + ": " + file.getName() + ": " + w);
			}
			log.appendMsg("text table " + file.getName() + ": " + table.size() + " entries");
		}
		catch (IOException | RuntimeException e) {
			log.appendMsg(OPTION_NAME + ": " + path.trim() + ": " + e.getMessage() +
				" -- ignoring the text table");
			return;
		}
		Options node = program.getOptions(OPTIONS_NODE);
		node.setString(SOURCE_KEY, file.getName());
		node.setString(TEXT_KEY, text);
		if (!SystemUtilities.isInHeadlessMode()) {
			Preferences.setProperty(prefKey, path.trim());
			Preferences.store();
		}
	}

	/**
	 * Reads the table stored in a program.
	 *
	 * @param program the program to inspect
	 * @return the parsed table, or {@code null} when none was stored
	 * @throws IllegalArgumentException when the stored text no longer parses
	 */
	static TblTable fromProgram(Program program) {
		String text = program.getOptions(OPTIONS_NODE).getString(TEXT_KEY, "");
		if (text == null || text.isEmpty()) {
			return null;
		}
		return TblTable.parse(text);
	}

	/** Returns the stored source file name, or an empty string. */
	static String sourceName(Program program) {
		return program.getOptions(OPTIONS_NODE).getString(SOURCE_KEY, "");
	}

	/** Reads a table file: strict UTF-8, falling back to ISO-8859-1 for legacy encodings. */
	static String readText(File file) throws IOException {
		if (!file.isFile()) {
			throw new IOException("file not found: " + file);
		}
		byte[] bytes = Files.readAllBytes(file.toPath());
		try {
			return StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(bytes)).toString();
		}
		catch (CharacterCodingException e) {
			return new String(bytes, StandardCharsets.ISO_8859_1);
		}
	}
}
