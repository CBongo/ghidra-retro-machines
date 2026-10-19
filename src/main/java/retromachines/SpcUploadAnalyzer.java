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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Annotates the places in a SNES ROM where the 65816 uploads a sound driver to the SPC700
 * (bead grm-1.7.3). It runs {@link SpcUploadRecovery} -- the 65816 under p-code emulation
 * against the SPC700 IPL handshake model -- and, on a complete upload, puts a bookmark and a
 * pre-comment at each uploader instruction that issued a transfer command, summarizing the
 * blocks and the entry address the ROM finally jumped to.
 *
 * <p>This analyzer does <em>not</em> create the SPC700 program: analyzers do not create
 * Programs. The {@code ExtractSpcUpload} script materializes the recovered image
 * ({@link SpcProgramMaterializer}) into the project.
 *
 * <p>Cost is bounded: it only runs on programs imported by {@link SnesRomLoader} (not merely
 * {@code 65816:LE:24:retro}, so another 65816 machine is never treated as a SNES) whose ROM addresses
 * the APU port window at all ({@link SpcUploadRecovery#usesApuPort}), and a run is capped by
 * the instruction-fuel and wall-clock options. A program that does not complete the handshake
 * is left unannotated (an info line in the log only), so unrelated SNES imports do not change.
 * Each program is analyzed at most once per session.
 */
public class SpcUploadAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "SPC700 Upload Recovery";
	private static final String DESCRIPTION =
		"Emulates the 65816 against the SPC700 IPL boot-ROM handshake on $2140-$2143 to find " +
			"the sound-driver uploads, and bookmarks each uploader site with the blocks and " +
			"entry address it sends.";
	private static final String CATEGORY = "SpcUploadAnalyzer";

	private static final String OPT_FUEL = "Instruction limit per attempt";
	private static final String OPT_WALL = "Wall-clock limit per attempt (seconds)";

	private static final Set<Program> DONE =
		Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

	private long fuel = SpcUploadRecovery.DEFAULT_FUEL;
	private int wallSeconds = (int) (SpcUploadRecovery.DEFAULT_WALLCLOCK_MILLIS / 1000);

	/** Creates the SPC700 upload recovery analyzer. */
	public SpcUploadAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return SpcUploadRecovery.isSnesRom(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_FUEL, fuel, null,
			"Maximum 65816 instructions emulated per entry attempt");
		options.registerOption(OPT_WALL, wallSeconds, null,
			"Maximum wall-clock seconds per entry attempt");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		fuel = options.getLong(OPT_FUEL, fuel);
		wallSeconds = options.getInt(OPT_WALL, wallSeconds);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		if (!SpcUploadRecovery.isSnesRom(program) || !DONE.add(program)) {
			return false;
		}
		if (!SpcUploadRecovery.usesApuPort(program)) {
			AnalyzerLog.info(this, "no access to the APU port window; skipping");
			return true;
		}
		StopConditions stop = StopConditions.builder().instructionFuel(fuel)
				.wallClockMillis(wallSeconds * 1000L).build();
		SpcUploadRecovery.Result result = new SpcUploadRecovery(program).recover(stop, monitor);
		if (!result.success()) {
			AnalyzerLog.info(this, "no complete SPC700 upload recovered (" + result.stop() + ", " +
				result.steps() + " steps, " + result.blocks().size() + " block(s))");
			return true;
		}
		annotate(program, result);
		AnalyzerLog.info(this, summary(result));
		return true;
	}

	private void annotate(Program program, SpcUploadRecovery.Result result) {
		Map<Address, StringBuilder> bySite = new LinkedHashMap<>();
		for (SpcIplModel.Block b : result.blocks()) {
			Address site = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(b.issuerPc());
			bySite.computeIfAbsent(site, k -> new StringBuilder())
					.append(String.format("\n  $%04X (%d bytes)", b.dest(), b.length()));
		}
		for (Map.Entry<Address, StringBuilder> e : bySite.entrySet()) {
			String text = "uploads to SPC700:" + e.getValue() +
				String.format("\n  then entry $%04X", result.entry());
			program.getBookmarkManager().setBookmark(e.getKey(), BookmarkType.NOTE, CATEGORY,
				"SPC700 upload: " + text.replace('\n', ' ').replaceAll("\\s+", " "));
			AnalyzerCommentRecord.set(program, e.getKey(), CommentType.PRE,
				"SPC700 IPL upload command (" + result.strategy() + ")\n" + text.substring(
					text.indexOf('\n') + 1));
		}
	}

	private static String summary(SpcUploadRecovery.Result result) {
		StringBuilder sb = new StringBuilder("recovered " + result.blocks().size() +
			" SPC700 upload block(s), entry " + String.format("$%04X", result.entry()) + " via " +
			result.strategy());
		if (result.uploaderEntry() != null) {
			sb.append(" at ").append(result.uploaderEntry());
		}
		sb.append(" (").append(result.steps()).append(" steps)");
		return sb.toString();
	}
}
