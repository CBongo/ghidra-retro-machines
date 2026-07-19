/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package retromachines;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/** Persistent policy for showing routine analyzer chatter only on its initial run. */
final class AnalyzerRunLog {

	// v2 deliberately ignores completion flags written by the original lifecycle policy:
	// that policy also marked descriptor/resource failures complete, permanently silencing
	// the first later successful run in saved Programs. Every Program gets one clean retry
	// after upgrading, then resumes the normal persistent one-shot behavior.
	private static final String KEY_PREFIX = "Retro Machines: initial run completed v2: ";

	private AnalyzerRunLog() {
	}

	static boolean isInitialRun(Program program, Class<?> analyzerClass) {
		return !options(program).getBoolean(key(analyzerClass), false);
	}

	static void markCompleted(Program program, Class<?> analyzerClass) {
		options(program).setBoolean(key(analyzerClass), true);
	}

	private static Options options(Program program) {
		return program.getOptions(Program.ANALYSIS_PROPERTIES);
	}

	private static String key(Class<?> analyzerClass) {
		return KEY_PREFIX + analyzerClass.getName();
	}
}
