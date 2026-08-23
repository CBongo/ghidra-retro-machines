/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package retromachines;

import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;

/**
 * The three-way split an analyzer's diagnostics have to make, in one place (grm-6jfp).
 * <p>
 * <b>Why this class exists.</b> An {@link Analyzer}'s {@link MessageLog} is not a log at
 * all: {@code MessageLog.appendMsg} only appends to an in-memory buffer, and the sole
 * non-test consumer of the analysis MessageLog in the whole Ghidra tree is
 * {@code AutoAnalysisPlugin.analysisEnded}, which does
 * <pre>if (log.hasMessages()) { log.write(...); ...show a MultiLineMessageDialog... }</pre>
 * There is <em>no severity in a MessageLog</em>, so the guard is "is there anything in
 * here at all". Consequences, both of which this class exists to fix:
 * <ul>
 * <li><b>Any</b> content pops a modal "There were warnings/errors issued during analysis"
 * dialog in the GUI on <em>every</em> re-analysis. Routine chatter written there is
 * therefore using a warnings/errors channel for information. That is the annoyance
 * grm-olp was filed about, and its temporal "only log on the initial run" workaround
 * (which this class replaces) silenced later runs' diagnostics entirely as collateral.</li>
 * <li>{@code AutoAnalysisPlugin} is a GUI plugin. {@code HeadlessAnalyzer} never touches
 * the analysis MessageLog, so nothing calls {@code write()} headlessly and the buffer is
 * discarded. Our <em>genuine analyzer warnings are invisible in a headless run</em> --
 * a bigger hole than the one grm-6jfp was filed about.</li>
 * </ul>
 * So: routine diagnostics go to {@link Msg} only, and genuine warnings go to both.
 * <ul>
 * <li>{@link #info} / {@link #debug} -- routine progress and summary lines.
 * <b>These must never touch the MessageLog</b>, or the popup comes back. Use
 * {@code debug} for anything that can emit per-function/per-site volume.</li>
 * <li>{@link #warn} -- genuine warnings, failures and malformed input. Goes to the
 * MessageLog (GUI dialog + the {@code write()} dump into application.log) <em>and</em> to
 * {@code Msg.warn}, which is the only half a headless run can see.</li>
 * </ul>
 * <p>
 * <b>One rule for choosing between them that is not obvious: if the site already sets a
 * WARNING bookmark carrying the same message, the log echo is {@link #info}, not
 * {@link #warn}.</b> The bookmark is the durable, user-visible, test-assertable record;
 * sending the same text through the MessageLog as well buys nothing except a modal dialog
 * on every settled analysis of any program that trips it. {@code BoardBankAnalyzer}'s
 * no-mechanism-write diagnostic is the worked example -- {@code db3} trips it
 * ({@code tools/banktest/realrom/expected/db3.dump:27}), so it is not a hypothetical.
 * Reserve {@code warn} for findings with no other durable record: load failures,
 * malformed input that stops processing, strategy configuration failures.
 * <p>
 * <b>The duplication in the GUI is deliberate; do not "fix" it.</b> Because the mirror is
 * unconditional, a warning raised during a GUI analysis lands in application.log twice:
 * once from {@code Msg.warn} when it is raised, and once inside the {@code write()} dump
 * at {@code analysisEnded}. Gating the mirror on
 * {@code SystemUtilities.isInHeadlessMode()} would remove the duplicate, at the cost of
 * making logging behaviour mode-dependent -- exactly the GUI-vs-headless split shape this
 * project has been bitten by before (see CLAUDE.md on
 * {@code Loader.validateOptions()}). Disk is cheap; a behavioural split is not.
 *
 * @see <a href="urn:bead:grm-6jfp">grm-6jfp</a> (this design)
 * @see <a href="urn:bead:grm-olp">grm-olp</a> (the original severity-split request)
 */
final class AnalyzerLog {

	private AnalyzerLog() {
	}

	/**
	 * A genuine warning: something failed, was malformed, or was skipped in a way the user
	 * needs to know about. Recorded in the analyzer's {@link MessageLog} (GUI) <em>and</em>
	 * via {@link Msg#warn} (headless, and application.log).
	 */
	static void warn(Analyzer analyzer, MessageLog log, String message) {
		log.appendMsg(analyzer.getName(), message);
		Msg.warn(analyzer, analyzer.getName() + ": " + message);
	}

	/**
	 * Routine progress/summary chatter. {@link Msg} only -- deliberately NOT the
	 * {@link MessageLog}, whose only consumer treats any content as a warning worth a
	 * modal dialog.
	 */
	static void info(Analyzer analyzer, String message) {
		Msg.info(analyzer, analyzer.getName() + ": " + message);
	}

	/**
	 * As {@link #info}, for lines that can run to hundreds per program (per-function or
	 * per-site detail). {@link Msg} only, for the same reason.
	 */
	static void debug(Analyzer analyzer, String message) {
		Msg.debug(analyzer, analyzer.getName() + ": " + message);
	}
}
