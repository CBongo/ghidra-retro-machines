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
// Counts how much of the program Ghidra's OWN pipeline disassembled in BASE SPACE -- the real
// PRG addresses at $8000-$FFFF, as opposed to the per-bank OVERLAY spaces this project's board
// descriptors create to hold every bank's content simultaneously (bead grm-8uaz).
//
// WHY BASE SPACE SPECIFICALLY. This project's own bank-switch analysis moves annotated,
// recognized code INTO overlay spaces; it does not touch base space at all in the process of
// doing that. Base-space disassembly is therefore produced entirely by Ghidra's stock pipeline
// (import-time disassembly plus whatever the shipped analyzers, ours included, trigger there),
// and the property this fixture exists to check -- "enabling our analyzer must never REDUCE how
// much base-space code Ghidra disassembles" -- is a claim about exactly that quantity. grm-nems
// is the proof this is not hypothetical: tmnt measured 3426 base-space instructions / 117
// functions with "NES Bank State" disabled, and only 2006 / 67 with it enabled, on a cold cache
// -- turning the analyzer ON made Ghidra's stock disassembly pass produce LESS code, not more.
// Nothing anywhere asserted that regression; this script is what a fixture can assert it with.
//
// MUST RUN AS A -postScript, after auto-analysis (so there is something to count) and after any
// -preScript that changed the analyzer's enabled state -- see run-banktest.sh's run_census.
//
// Emits exactly:
//
//   CENSUS analyzer <resolved-name>=<true|false>
//   CENSUS instrs.baseSpace <n>
//   CENSUS functions.baseSpace <n>
//
// or, if the "NES Bank State" option is not registered on this program at all (wrong
// language/board -- the option never exists outside a 6502 NES import), "CENSUS analyzer
// <name>=ABSENT" in place of the first line, with the two counts still printed: base-space
// disassembly is a well-defined quantity whether or not our analyzer is even in play, and a
// caller comparing two runs needs both counts either way.
//
//@category RetroMachines.Test

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class BaseSpaceCensus extends GhidraScript {

	/** Matches SetAnalyzerEnabled.java's default target; kept as a literal for the same reason
	 * that script's header explains -- script args are the only way to name an analyzer whose
	 * display name contains a space, and this script has none to parse, so the name it reports
	 * on is fixed rather than configurable. */
	private static final String WANTED_ANALYZER = "NES Bank State";

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no program is open");
			return;
		}

		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		String resolved = resolveAnalyzerName(options, WANTED_ANALYZER);
		if (resolved == null) {
			println("CENSUS analyzer " + WANTED_ANALYZER + "=ABSENT");
		}
		else {
			println("CENSUS analyzer " + resolved + "=" + options.getBoolean(resolved, false));
		}

		Listing listing = currentProgram.getListing();

		int instrCount = 0;
		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			if (isBaseSpace(instr.getMinAddress())) {
				instrCount++;
			}
		}

		int funcCount = 0;
		FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
		while (funcs.hasNext()) {
			Function func = funcs.next();
			if (isBaseSpace(func.getEntryPoint())) {
				funcCount++;
			}
		}

		println("CENSUS instrs.baseSpace " + instrCount);
		println("CENSUS functions.baseSpace " + funcCount);
	}

	private static boolean isBaseSpace(Address at) {
		return !at.getAddressSpace().isOverlaySpace();
	}

	/**
	 * Resolves {@code wanted} against the analysis option names actually registered for this
	 * program -- an exact match first, else a unique case-insensitive substring match -- or
	 * null if none matches. Unlike SetAnalyzerEnabled.java's resolver, an unresolved name is NOT
	 * fatal here: this script is a read-only census, run on both the "on" and "off" legs of
	 * run_census, and the "off" leg is exactly the case where a caller might reasonably expect
	 * the option to still exist but be false, not absent -- so ABSENT is reported as data, not
	 * treated as an error. An AMBIGUOUS match (more than one candidate), though, is still a
	 * caller-visible problem worth failing loudly on: silently picking one would misreport which
	 * analyzer's state the census is describing.
	 * <p>
	 * DUPLICATED, not shared, from {@code SetAnalyzerEnabled.java}: both are standalone
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
		String match = null;
		for (String name : names) {
			if (name.toLowerCase().contains(wanted.toLowerCase())) {
				if (match != null) {
					printerr("CENSUS FAILED: '" + wanted +
						"' matches more than one registered analysis option, ambiguous: " +
						match + ", " + name);
					throw new IllegalStateException(
						"BaseSpaceCensus: ambiguous analyzer name '" + wanted + "'");
				}
				match = name;
			}
		}
		return match;
	}
}
