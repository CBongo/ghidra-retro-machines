/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package retromachines;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/** Persistent policy for showing routine analyzer chatter only on its initial run. */
final class AnalyzerRunLog {

	private static final String KEY_PREFIX = "Retro Machines: initial run completed: ";

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
