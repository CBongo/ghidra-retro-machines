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

import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * One-shot front-end for the 6502 skip-idiom repair (grm-9xr), sharing every line of recognition
 * and repair with {@code ghidra_scripts/FixSkipInstructions.java} through
 * {@link SkipIdiomRepair}.
 *
 * <p><b>Deliberately one-shot and off by default.</b> The repair truncates a real instruction
 * ({@code setLengthOverride}) and disassembles inside its operand; the idiom is rare (a GME-wide
 * sweep found 12 of 19 titles with no carrier, 9 of 41 candidates confident enough to apply), so
 * running it on import was measured and declined (grm-pfp). It is reachable from Analysis > One
 * Shot, with {@code carriers}/{@code weak}/{@code function} as persisted analysis options.
 *
 * <p>Applies only what the script applies by default: REFERENCED and STRONG candidates (WEAK only
 * with the option). The script reports to the console only; here every candidate that is
 * <i>not</i> applied also gets a NOTE bookmark in category {@value #CATEGORY} on the carrier, so
 * a GUI user can find it. No listing comments are written, so there is nothing for
 * {@code AnalyzerCommentRecord} to track; the applied repairs carry the script's own
 * "Offcut Instruction" INFO bookmark.
 *
 * @see SkipIdiomRepair
 */
public class SkipIdiomAnalyzer extends AbstractAnalyzer {

	static final String NAME = "Retro Skip Idiom";
	private static final String DESCRIPTION =
		"Recovers the 6502 skip idiom (BIT-skip): an instruction whose operand bytes are " +
			"themselves a valid instruction entered from elsewhere. Truncates the carrier and " +
			"disassembles the hidden entry (grm-pfp, grm-9xr). One-shot: mutates the " +
			"instruction stream, so run it on purpose.";

	/** Bookmark category for candidates that were reported but not applied. */
	static final String CATEGORY = "Skip Idiom Candidate";

	static final String OPT_CARRIERS = "Carrier mnemonics";
	static final String OPT_WEAK = "Apply weak candidates";
	static final String OPT_FUNCTION = "Create functions at recovered entries";

	private static final Set<String> SUPPORTED_PROCESSORS = Set.of("6502", "6510");

	private Set<String> carriers = SkipIdiomRepair.Options.defaultCarriers();
	private boolean applyWeak = false;
	private boolean makeFunction = true;

	public SkipIdiomAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return processor != null && SUPPORTED_PROCESSORS.contains(processor.toString());
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_CARRIERS, String.join(",", carriers), null,
			"Comma-separated mnemonics that may carry a skip. BIT abs skips 2 bytes and BIT zp " +
				"1; CMP and LDA immediate are occasionally used to skip 1.");
		options.registerOption(OPT_WEAK, applyWeak, null,
			"Also apply WEAK candidates (valid decode, nothing corroborates it). Across the " +
				"measured NES corpus these were decoded noise; they are bookmarked either way.");
		options.registerOption(OPT_FUNCTION, makeFunction, null,
			"Create a function at each recovered entry so dataflow analyses evaluate it.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		try {
			carriers = SkipIdiomRepair.parseCarriers(options.getString(OPT_CARRIERS,
				String.join(",", carriers)));
		}
		catch (IllegalArgumentException e) {
			// Keep the previous carriers; the Options panel has no way to veto a value.
			AnalyzerLog.info(this, "ignoring bad carriers option: " + e.getMessage());
		}
		applyWeak = options.getBoolean(OPT_WEAK, applyWeak);
		makeFunction = options.getBoolean(OPT_FUNCTION, makeFunction);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		SkipIdiomRepair.Options options =
			new SkipIdiomRepair.Options(carriers, applyWeak, false, makeFunction);
		SkipIdiomRepair.Summary summary = SkipIdiomRepair.run(program, set, options, monitor,
			line -> AnalyzerLog.info(this, line), line -> AnalyzerLog.warn(this, log, line));
		for (SkipIdiomRepair.Candidate c : summary.candidates()) {
			if (!SkipIdiomRepair.wouldApply(c, options)) {
				program.getBookmarkManager().setBookmark(c.carrier().getMinAddress(),
					BookmarkType.NOTE, CATEGORY, c.carrier().getMnemonicString() + " hides " +
						c.entry() + " " + c.hiddenMnemonic() + " [" + c.confidence() +
						"]; not applied");
			}
		}
		monitor.checkCancelled();
		return true;
	}
}
