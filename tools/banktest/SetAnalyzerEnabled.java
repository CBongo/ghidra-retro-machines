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
// Turns one auto-analyzer on or off before auto-analysis runs (bead grm-8uaz), so a fixture can
// import the SAME image twice -- once with an analyzer live, once with it suppressed -- and
// compare what Ghidra's OWN pipeline did in each case. That comparison is what
// BaseSpaceCensus.java measures; this script only prepares the precondition for it.
//
// MUST RUN AS A -preScript. Headless runs -preScript before auto-analysis and -postScript
// after, and the option has to be set before analysis reads it -- setting it afterward would
// change nothing about what already ran.
//
// Pass whitespace-free key:value tokens, matching the idiom every other script in this
// directory tree uses (see ghidra_scripts/FixSkipInstructions.java):
//
//   -preScript SetAnalyzerEnabled.java analyzer:NES_Bank_State enabled:false
//
//   analyzer   the analyzer's display name, with SPACES REPLACED BY UNDERSCORES -- script
//              arguments are space-separated, and analyzer names contain spaces (e.g.
//              "NES Bank State", NesBankingAnalyzer.java:33), so there is no other way to name
//              one on this command line. After converting underscores back to spaces, the name
//              is resolved against the option names Ghidra actually registered for this
//              program (program.getOptions(Program.ANALYSIS_PROPERTIES).getOptionNames()):
//              first an exact match, and failing that, a unique case-insensitive substring
//              match -- so "analyzer:Bank_State" also resolves to "NES Bank State" as long as
//              no other registered analyzer's name also contains "bank state".
//   enabled    true or false.
//
// FAILS LOUDLY, ALWAYS -- this is the entire point of the script existing as a separate,
// reviewable step rather than an inline option-set buried in a fixture. GhidraScript's own
// setAnalysisOption(Program, String, String) (bead-verified against Ghidra 12.1.3,
// GhidraScript.java:1448) requires options.contains(optionName) and, on failure, headless does
// nothing but Msg.error and RETURN NORMALLY -- it does not throw. A caller that trusted it alone
// would see analysis proceed with the analyzer in whatever state it already had, silently, which
// is exactly the false-positive this fixture exists to rule out. So every failure mode below is
// checked explicitly and this script throws rather than returning -- unresolvable analyzer name,
// zero matches, more than one match, or (the belt-and-suspenders check) the value read back from
// the options object after the set not equalling what was requested.
//
// Prints exactly one line on success:
//
//   SETANALYZER <resolved option name> enabled=<true|false> (was <true|false>)
//
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class SetAnalyzerEnabled extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("SETANALYZER no program is open");
			throw new IllegalStateException("SetAnalyzerEnabled: no program is open");
		}

		String analyzerArg = null;
		String enabledArg = null;
		for (String arg : getScriptArgs()) {
			String[] kv = arg.split(":", 2);
			if (kv.length != 2 || kv[0].isEmpty() || kv[1].isEmpty()) {
				fail("malformed argument '" + arg + "'; expected key:value with no whitespace");
			}
			switch (kv[0]) {
				case "analyzer" -> analyzerArg = kv[1];
				case "enabled" -> enabledArg = kv[1];
				default -> fail("unknown key '" + kv[0] + "' in argument '" + arg +
					"'; expected one of analyzer, enabled");
			}
		}
		if (analyzerArg == null) {
			fail("missing required argument 'analyzer:<name>' (underscores stand for spaces)");
		}
		if (enabledArg == null) {
			fail("missing required argument 'enabled:true|false'");
		}
		boolean wantEnabled;
		if (enabledArg.equalsIgnoreCase("true")) {
			wantEnabled = true;
		}
		else if (enabledArg.equalsIgnoreCase("false")) {
			wantEnabled = false;
		}
		else {
			fail("enabled must be true or false, got '" + enabledArg + "'");
			return; // unreachable -- fail() always throws; keeps the compiler happy
		}

		String wanted = analyzerArg.replace('_', ' ');
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		String resolved = resolveAnalyzerName(options, wanted);

		boolean was = options.getBoolean(resolved, false);
		options.setBoolean(resolved, wantEnabled);

		// Belt-and-suspenders: setAnalysisOption's headless failure mode (Msg.error, then return
		// normally with the option UNCHANGED) is exactly the silent hazard this script exists to
		// rule out. Reading the value straight back from the SAME Options object we just wrote is
		// a stronger check than trusting the setter's return -- it observes what a subsequent
		// analyzeAll() will actually see, not what the setter merely claims to have done.
		boolean readBack = options.getBoolean(resolved, !wantEnabled);
		if (readBack != wantEnabled) {
			fail("wrote enabled=" + wantEnabled + " for '" + resolved +
				"' but read back " + readBack + " -- the set did not take");
		}

		println("SETANALYZER " + resolved + " enabled=" + wantEnabled + " (was " + was + ")");
	}

	/**
	 * Resolves {@code wanted} against the analyzer option names actually registered for this
	 * program: an exact match first, else a unique case-insensitive substring match. Throws
	 * (via {@link #fail}) on zero or more-than-one match -- an analyzer name is meaningless to
	 * silently guess at, and a language/processor combination that never registers the analyzer
	 * at all (wrong board, or a renamed analyzer) must be caught here, not read as "already
	 * off".
	 * <p>
	 * DUPLICATED, not shared, in {@code BaseSpaceCensus.java}: both are standalone
	 * {@code GhidraScript}s with no package declaration (matching every other script in this
	 * directory), so there is no class either could import the other from.
	 */
	private String resolveAnalyzerName(Options options, String wanted) {
		List<String> names = options.getOptionNames();
		for (String name : names) {
			if (name.equals(wanted)) {
				return name;
			}
		}
		List<String> candidates = new ArrayList<>();
		for (String name : names) {
			if (name.toLowerCase().contains(wanted.toLowerCase())) {
				candidates.add(name);
			}
		}
		if (candidates.isEmpty()) {
			fail("no registered analysis option matches '" + wanted +
				"' (exact or case-insensitive substring); registered option names: " + names);
		}
		if (candidates.size() > 1) {
			fail("'" + wanted + "' matches more than one registered analysis option, " +
				"ambiguous: " + candidates);
		}
		return candidates.get(0);
	}

	/** Reports loudly on both channels and throws, so headless never proceeds past a bad state. */
	private void fail(String message) {
		printerr("SETANALYZER FAILED: " + message);
		throw new IllegalStateException("SetAnalyzerEnabled: " + message);
	}
}
