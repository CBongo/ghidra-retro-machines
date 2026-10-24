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
// Recovers the 6502 "skip" idiom (BIT-skip / skip2 / skipword): a harmless instruction whose
// OPERAND BYTES are themselves a valid instruction, so that entering at the carrier consumes
// them as data and entering two bytes later executes them as code. Two entry points, one
// shared tail (bead grm-pfp; found by hand in Wizards & Warriors at $BC08).
//
//     bc05:  LDA #$02
//            BIT $03A9         ; assembles as 2C A9 03
//            JMP $FF69         ; <- the shared tail: a far-call bank helper
//     bc08:   LDA #$03         ; the A9 03 operand bytes of the BIT above
//
// $BC05 is disassembled first, so $BC08's bytes are already claimed as BIT's operand and
// Ghidra can create neither an instruction nor a function there. The LDA #$03 call site --
// and with it the whole of bank 3 -- does not exist in the program.
//
// DERIVED FROM Ghidra's own FixOffcutInstructionScript (Features/Base/ghidra_scripts), whose
// setLengthOverride + disassemble + bookmark-swap sequence this script reuses verbatim in
// spirit. That script is gated on a flow reference ALREADY landing at the offcut address
// (isOffcutFlowReference) -- which is exactly what this bug prevents, so the tool that would
// repair it is gated on the very thing being repaired. The net-new logic here is only the
// pattern match that SEEDS its own evidence; the repair machinery is all upstream's.
//
// CONFIDENCE, and why it is tiered. Structural validity alone is too weak: BIT $10A5 also
// "hides" a perfectly valid LDA $10, and firing on that would truncate a genuine memory read.
// So every candidate is classified, and by default only the confident ones are applied:
//
//   REFERENCED  something already flows to the offcut address. This is upstream's own
//               criterion, and it is dispositive -- the reference is direct evidence of an
//               entry point.
//   STRONG      the instruction that falls through INTO the carrier has the same mnemonic as
//               the hidden one (LDA #$02 skipped in favour of LDA #$03). This is the classic
//               shape of the idiom: two entries choosing between alternative parameter loads
//               before converging, and it is what a hand-written skip almost always looks like.
//   WEAK        structurally valid, no corroboration. Reported, not applied, unless weak:true.
//
// Interactive: run with no arguments and answer the two prompts. It scans the selection if there
// is one, else the whole program, and reports every candidate it finds -- with its tier -- to the
// console whether or not it applies anything. THE FIRST PROMPT DEFAULTS SAFE: declining it (or
// dismissing the dialog, which askYesNo reports as "no") reports and changes nothing, so a user
// meeting an unfamiliar ROM can look before leaping. The GUI cannot pass script arguments, so
// these prompts are the ONLY way to reach dry-run from the Script Manager.
//
// Headless: pass whitespace-free key:value tokens as script arguments, e.g.
//
//   -postScript FixSkipInstructions.java weak:true function:false
//
//   carriers    comma-separated mnemonics that may carry a skip (default BIT). The 6502's
//               canonical carriers are BIT abs (skips 2 bytes) and BIT zp (skips 1); CMP and
//               LDA immediate are occasionally used to skip 1. Case-insensitive.
//   weak        apply WEAK candidates too (default false -- they are reported either way)
//   dryrun      report candidates and apply nothing (default false)
//   function    create a function at each recovered entry point (default true)
//   reanalyze   re-run analysis over the changes when anything was applied (default true)
//   range       restrict the scan to start-end, e.g. range:bc00-bd00
//
// MUST RUN AFTER DISASSEMBLY -- the conflict it repairs does not exist until then. Headless,
// that means -postScript, never -preScript.
//
//@category RetroMachines
//@menupath Tools.Retro Machines.Fix Skip Instructions

import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

import retromachines.SkipIdiomRepair;
import retromachines.TypedAddress;

/**
 * The reference front-end. Recognition and repair live in {@link SkipIdiomRepair}, shared with the
 * one-shot {@code SkipIdiomAnalyzer} (grm-9xr); this script only collects arguments, picks the
 * scope and re-runs analysis.
 */
public class FixSkipInstructions extends GhidraScript {

	/** Dialog title for the interactive prompts. */
	private static final String TITLE = "Fix Skip Instructions";

	// Options, defaulted here and overridden by parseArgs.
	private Set<String> carriers = SkipIdiomRepair.Options.defaultCarriers();
	private boolean applyWeak = false;
	private boolean dryRun = false;
	private boolean makeFunction = true;
	private boolean reanalyze = true;
	private Address rangeStart = null;
	private Address rangeEnd = null;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no program is open");
			return;
		}
		// The branch exists for the reason RunFromElsewhereTransfer's does:
		// GhidraScript.loadAskValue consumes ONE POSITIONAL script argument per ask* call
		// whenever any arguments are present, matching by call order and never by name. A
		// conditional prompt (and the second one below IS conditional) would therefore shift the
		// argument stream out of alignment. So the headless path parses named tokens itself and
		// calls no ask* method at all, and the interactive path is reachable only with an empty
		// argument array.
		if (getScriptArgs().length == 0) {
			askForOptions();
		}
		else if (!parseArgs(getScriptArgs())) {
			// parseArgs already printed the reason; throw so headless logs REPORT SCRIPT ERROR
			// instead of reading a returned-from script as success (grm-h649).
			throw new IllegalArgumentException("FixSkipInstructions: " + argError);
		}

		AddressSetView scope = scanScope();
		println("SKIPFIX scanning " + scope.getMinAddress() + "-" + scope.getMaxAddress() +
			" for carriers " + carriers);

		SkipIdiomRepair.Summary summary = SkipIdiomRepair.run(currentProgram, scope,
			new SkipIdiomRepair.Options(carriers, applyWeak, dryRun, makeFunction), monitor,
			this::println, this::printerr);

		// New instructions are not analyzed by the analyzers that already ran -- headless
		// finishes analyzeAll before postScripts, and in the GUI the change lands after the
		// analysis pass. Without this the recovered call site exists in the listing but no
		// bank has been recovered from it, which is the entire point of the exercise.
		if (summary.applied() > 0 && reanalyze) {
			println("SKIPFIX re-analyzing changes");
			analyzeChanges(currentProgram);
		}
	}

	// ------------------------------------------------------------------
	// Interactive front-end
	// ------------------------------------------------------------------

	/**
	 * Prompt for the two choices that can change what lands in the program. Only reachable with
	 * an empty argument array, which is what makes the CONDITIONAL second prompt safe here (see
	 * the branch in {@code run}).
	 * <p>
	 * <b>The first question is phrased so that "no" is the safe answer, and that is deliberate.</b>
	 * {@code askYesNo} does not throw {@code CancelledException} -- a dismissed dialog is simply
	 * "no" -- so a user who closes the window rather than answering must land on "report and
	 * change nothing". Asking "dry run?" instead would give the opposite default and turn a
	 * dismissed dialog into instruction truncation the user never agreed to.
	 * <p>
	 * The remaining options ({@code carriers}, {@code function}, {@code reanalyze},
	 * {@code range}) are not prompted for: each has a defensible default, a selection already
	 * expresses {@code range} in the GUI's own idiom, and every extra dialog is one more thing to
	 * click through before the answer everyone actually wants. They stay reachable headless.
	 */
	private void askForOptions() {
		boolean apply = askYesNo(TITLE,
			"Apply the repairs?\n\nChoosing No -- or dismissing this dialog -- reports every " +
				"candidate found, with its confidence tier, and changes nothing.");
		dryRun = !apply;
		applyWeak = apply && askYesNo(TITLE,
			"Also apply WEAK candidates?\n\nWEAK means the bytes decode to a valid instruction " +
				"but nothing corroborates it -- no reference, and no matching load falling into " +
				"the carrier. Across the measured NES corpus 32 of 41 candidates were WEAK and " +
				"they hid BRK/SEI/BVS, i.e. decoded noise. Say No unless you have a specific " +
				"reason.");
	}

	// ------------------------------------------------------------------
	// Scope and arguments
	// ------------------------------------------------------------------

	/**
	 * Where to scan: an explicit {@code range:} if given, else the selection if there is one,
	 * else every loaded byte. Scanning everything is the useful default here -- unlike
	 * upstream, which acts on a reference it did not have to find, this script has to go
	 * looking, and a whole-program scan is what makes the incidence count meaningful.
	 */
	private AddressSetView scanScope() {
		if (rangeStart != null) {
			return new AddressSet(rangeStart, rangeEnd);
		}
		if (currentSelection != null && !currentSelection.isEmpty()) {
			return new AddressSet(currentSelection);
		}
		return currentProgram.getMemory().getLoadedAndInitializedAddressSet();
	}

	/**
	 * Parse {@code key:value} tokens, returning false after reporting why not. Fails loud on
	 * anything unrecognized: the argument list is the headless user's only feedback channel,
	 * and a typo'd key quietly ignored would run at defaults the user never asked for.
	 */
	private boolean parseArgs(String[] args) {
		for (String arg : args) {
			// split(":", 2) is mandatory, not stylistic: an overlay-space address is itself
			// SPACE:offset on a banked board, so an unbounded split would truncate the value.
			String[] kv = arg.split(":", 2);
			if (kv.length != 2 || kv[0].isEmpty() || kv[1].isEmpty()) {
				argError("malformed argument '" + arg + "'; expected key:value with no whitespace");
				return false;
			}
			String key = kv[0];
			String value = kv[1];
			try {
				switch (key) {
					case "carriers" -> carriers = SkipIdiomRepair.parseCarriers(value);
					case "weak" -> applyWeak = flag(key, value);
					case "dryrun" -> dryRun = flag(key, value);
					case "function" -> makeFunction = flag(key, value);
					case "reanalyze" -> reanalyze = flag(key, value);
					case "range" -> parseRange(value);
					default -> {
						argError("unknown key '" + key + "' in argument '" + arg + "'; expected " +
							"one of carriers, weak, dryrun, function, reanalyze, range");
						return false;
					}
				}
			}
			catch (IllegalArgumentException e) {
				argError("bad value in argument '" + arg + "': " + e.getMessage());
				return false;
			}
		}
		return true;
	}

	/** {@code start-end}, inclusive. Addresses are hex, as everywhere else in Ghidra. */
	private void parseRange(String value) {
		String[] halves = value.split("-", 2);
		if (halves.length != 2) {
			throw new IllegalArgumentException("range must be start-end, got '" + value + "'");
		}
		rangeStart = address(halves[0]);
		rangeEnd = address(halves[1]);
		if (rangeStart == null || rangeEnd == null) {
			throw new IllegalArgumentException("unparseable address in range '" + value + "'");
		}
		if (rangeEnd.compareTo(rangeStart) < 0) {
			throw new IllegalArgumentException("range end precedes its start: '" + value + "'");
		}
	}

	/** The last argument problem parseArgs reported, carried into the exception run() throws. */
	private String argError = "bad arguments";

	/** Reports an argument problem on the console and remembers it for the exception. */
	private void argError(String message) {
		argError = message;
		printerr(message);
	}

	/**
	 * An address token: hex, {@code $}/{@code 0x}-prefixed or not, optionally
	 * {@code SPACE:offset}. {@link TypedAddress} names a space that does not exist (grm-h649).
	 */
	private Address address(String text) {
		return TypedAddress.parse(currentProgram, text);
	}

	/** A strict boolean: anything but true/false is a typo worth failing on, not a false. */
	private static boolean flag(String key, String value) {
		if (value.equalsIgnoreCase("true")) {
			return true;
		}
		if (value.equalsIgnoreCase("false")) {
			return false;
		}
		throw new IllegalArgumentException(key + " must be true or false, got '" + value + "'");
	}
}
