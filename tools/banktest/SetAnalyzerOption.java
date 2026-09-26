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
// Sets one ENUM-valued analyzer option before auto-analysis runs (bead grm-4wqd), modeled
// closely on SetAnalyzerEnabled.java's shape and failure discipline -- see that file's header
// for the general rationale (why this must run as a -preScript, why every failure mode is
// checked explicitly rather than trusted to Ghidra's own setAnalysisOption). This script exists
// specifically so the real-ROM tier can force StoredValueScanner's Constant Evaluator option to
// PCODE for a report-only A/B run, without adding a retromachines-specific compile dependency
// here: the option's enum TYPE is discovered from its own CURRENT value via reflection
// (Enum.valueOf against that runtime class), not imported.
//
// MUST RUN AS A -preScript, for the same reason as SetAnalyzerEnabled: headless applies
// -preScript before auto-analysis and -postScript after, and the option has to be set before
// analysis reads it.
//
// Pass whitespace-free key:value tokens:
//
//   -preScript SetAnalyzerOption.java analyzer:NES_Bank_State option:Constant_Evaluator value:PCODE
//
//   analyzer   the analyzer's display name, with SPACES REPLACED BY UNDERSCORES (see
//              SetAnalyzerEnabled.java's header for why -- script arguments are space-separated
//              and analyzer names contain spaces).
//   option     the option's leaf name, same underscore-for-space convention. Concatenated with
//              analyzer as "<analyzer>.<option>" and resolved against the option names Ghidra
//              actually registered for this program
//              (program.getOptions(Program.ANALYSIS_PROPERTIES).getOptionNames()): first an
//              exact match, else a unique case-insensitive substring match.
//   value      the enum CONSTANT NAME to set, e.g. PCODE or TABLE -- matched by
//              Enum.valueOf(...) against the option's OWN current value's runtime class, so
//              this script never needs to import the enum type itself.
//
// FAILS LOUDLY, ALWAYS: an unresolvable option name, an option that is not enum-valued (its
// current value is null or not an Enum), an unknown constant name for that enum, or a read-back
// after the set that does not match what was requested, all throw rather than let analysis
// proceed with a state this script could not confirm.
//
// Prints exactly one line on success:
//
//   SETANALYZEROPTION <resolved option name> value=<name> (was <name>)
//
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class SetAnalyzerOption extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("SETANALYZEROPTION no program is open");
			throw new IllegalStateException("SetAnalyzerOption: no program is open");
		}

		String analyzerArg = null;
		String optionArg = null;
		String valueArg = null;
		for (String arg : getScriptArgs()) {
			String[] kv = arg.split(":", 2);
			if (kv.length != 2 || kv[0].isEmpty() || kv[1].isEmpty()) {
				fail("malformed argument '" + arg + "'; expected key:value with no whitespace");
			}
			switch (kv[0]) {
				case "analyzer" -> analyzerArg = kv[1];
				case "option" -> optionArg = kv[1];
				case "value" -> valueArg = kv[1];
				default -> fail("unknown key '" + kv[0] + "' in argument '" + arg +
					"'; expected one of analyzer, option, value");
			}
		}
		if (analyzerArg == null) {
			fail("missing required argument 'analyzer:<name>' (underscores stand for spaces)");
		}
		if (optionArg == null) {
			fail("missing required argument 'option:<name>' (underscores stand for spaces)");
		}
		if (valueArg == null) {
			fail("missing required argument 'value:<enum constant name>'");
		}

		String wanted = analyzerArg.replace('_', ' ') + "." + optionArg.replace('_', ' ');
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		String resolved = resolveOptionName(options, wanted);

		Object current = options.getObject(resolved, null);
		if (current == null) {
			fail("'" + resolved + "' has no current value -- either unregistered for this " +
				"program's language/loader, or genuinely unset with no default");
		}
		if (!(current instanceof Enum<?> currentEnum)) {
			fail("'" + resolved + "' is not enum-valued (current value's class: " +
				current.getClass().getName() + ")");
			return; // unreachable -- fail() always throws
		}

		Class<? extends Enum> enumClass = currentEnum.getClass();
		Enum<?> wantedValue;
		try {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			Enum raw = Enum.valueOf(enumClass, valueArg);
			wantedValue = raw;
		}
		catch (IllegalArgumentException e) {
			List<String> constantNames = new ArrayList<>();
			for (Object c : enumClass.getEnumConstants()) {
				constantNames.add(((Enum<?>) c).name());
			}
			fail("'" + valueArg + "' is not a constant of " + enumClass.getSimpleName() +
				"; valid values: " + constantNames);
			return; // unreachable
		}

		String was = currentEnum.name();
		options.putObject(resolved, wantedValue);

		// Belt-and-suspenders, matching SetAnalyzerEnabled: read back from the SAME Options
		// object we just wrote, not the setter's own success (which this API does not even
		// signal a failure through).
		Object readBack = options.getObject(resolved, null);
		if (!(readBack instanceof Enum<?> readBackEnum) || !readBackEnum.name().equals(valueArg)) {
			fail("wrote value=" + valueArg + " for '" + resolved + "' but read back " +
				readBack + " -- the set did not take");
		}

		println("SETANALYZEROPTION " + resolved + " value=" + valueArg + " (was " + was + ")");
	}

	/**
	 * Resolves {@code wanted} against the option names actually registered for this program:
	 * an exact match first, else a unique case-insensitive substring match. See
	 * {@code SetAnalyzerEnabled.resolveAnalyzerName}'s javadoc for why this throws rather than
	 * guesses on zero or more than one match -- same reasoning, applied to a dotted
	 * "analyzer.option" path instead of a bare analyzer name.
	 * <p>
	 * DUPLICATED, not shared, for the same reason {@code SetAnalyzerEnabled} and
	 * {@code BaseSpaceCensus} duplicate it rather than share it: standalone {@code GhidraScript}s
	 * with no package declaration have no class either could import the other from.
	 */
	private String resolveOptionName(Options options, String wanted) {
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
		printerr("SETANALYZEROPTION FAILED: " + message);
		throw new IllegalStateException("SetAnalyzerOption: " + message);
	}
}
