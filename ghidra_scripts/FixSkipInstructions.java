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
// Interactive: run with no arguments; scans the selection if there is one, else the whole
// program, and reports every candidate it finds before applying the confident ones.
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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

public class FixSkipInstructions extends GhidraScript {

	/** Bookmark category for provenance, matching upstream FixOffcutInstructionScript's. */
	private static final String INFO_BOOKMARK_CATEGORY = "Offcut Instruction";
	private static final String INFO_BOOKMARK_COMMENT = "Fixed skip-idiom offcut instruction";

	/** How confident we are that the hidden bytes are a real entry point. */
	private enum Confidence {
		/** A flow reference already lands at the offcut: upstream's own, dispositive, test. */
		REFERENCED,
		/** The instruction falling through into the carrier is the hidden one's alternative. */
		STRONG,
		/** Structurally valid, uncorroborated. Reported; applied only with weak:true. */
		WEAK
	}

	/**
	 * One recognized skip: {@code carrier} hides an instruction starting at {@code entry}, and
	 * both streams converge on {@code tail}. The tail is captured at recognition time on
	 * purpose -- {@code carrier.getMaxAddress()} moves once the length override is applied, so
	 * after the repair there is no way to recompute it.
	 */
	private record Candidate(Instruction carrier, Address entry, Address tail,
			String hiddenMnemonic, Confidence confidence) {
	}

	private Listing listing;
	private BookmarkManager bookmarks;
	private int alignment;

	// Options, defaulted here and overridden by parseArgs.
	private Set<String> carriers = new LinkedHashSet<>(List.of("BIT"));
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
		if (getScriptArgs().length != 0 && !parseArgs(getScriptArgs())) {
			return; // parseArgs already reported the reason
		}

		listing = currentProgram.getListing();
		bookmarks = currentProgram.getBookmarkManager();
		alignment = currentProgram.getLanguage().getInstructionAlignment();

		AddressSetView scope = scanScope();
		println("SKIPFIX scanning " + scope.getMinAddress() + "-" + scope.getMaxAddress() +
			" for carriers " + carriers);

		// Two phases on purpose. Applying a fix disassembles new code, which invalidates the
		// instruction iterator we would still be walking; collecting first also means dryrun
		// reports exactly the set that a real run would act on, rather than a prefix of it.
		List<Candidate> candidates = collect(scope);

		int applied = 0;
		int failed = 0;
		for (Candidate c : candidates) {
			boolean act = !dryRun && (c.confidence() != Confidence.WEAK || applyWeak);
			// One stable, greppable line per candidate, in both environments: the headless
			// regression fixture asserts on it and a GUI user reads it in the console.
			println("SKIPFIX candidate " + c.carrier().getMinAddress() + " " +
				c.carrier().getMnemonicString() + " hides " + c.entry() + " " +
				c.hiddenMnemonic() + " [" + c.confidence() + "]" + (act ? "" : " (not applied)"));
			if (!act) {
				continue;
			}
			try {
				fix(c);
				applied++;
			}
			catch (Exception e) {
				// A dynamic offcut (one whose repair depends on run-time context) raises here.
				// Report and keep going: one unrepairable carrier must not cost the rest.
				printerr("SKIPFIX failed at " + c.carrier().getMinAddress() + ": " + e);
				failed++;
			}
		}

		println("SKIPFIX summary candidates=" + candidates.size() + " referenced=" +
			count(candidates, Confidence.REFERENCED) + " strong=" +
			count(candidates, Confidence.STRONG) + " weak=" + count(candidates, Confidence.WEAK) +
			" applied=" + applied + " failed=" + failed);

		// New instructions are not analyzed by the analyzers that already ran -- headless
		// finishes analyzeAll before postScripts, and in the GUI the change lands after the
		// analysis pass. Without this the recovered call site exists in the listing but no
		// bank has been recovered from it, which is the entire point of the exercise.
		if (applied > 0 && reanalyze) {
			println("SKIPFIX re-analyzing changes");
			analyzeChanges(currentProgram);
		}
	}

	// ------------------------------------------------------------------
	// Recognition
	// ------------------------------------------------------------------

	/** Every skip carrier in {@code scope}, classified. Mutates nothing. */
	private List<Candidate> collect(AddressSetView scope) {
		List<Candidate> found = new ArrayList<>();
		PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);
		InstructionIterator instrs = listing.getInstructions(scope, true);
		while (instrs.hasNext() && !monitor.isCancelled()) {
			Instruction carrier = instrs.next();
			// An instruction already truncated has been dealt with -- by this script on an
			// earlier run, by upstream's, or by hand. Re-truncating it would be wrong twice
			// over: the offcut is already exposed, and getMaxAddress no longer means what the
			// convergence test below assumes.
			if (carrier.isLengthOverridden() || carrier.getLength() < 2) {
				continue;
			}
			if (!carriers.contains(carrier.getMnemonicString().toUpperCase())) {
				continue;
			}
			Candidate c = classify(pdis, carrier);
			if (c != null) {
				found.add(c);
			}
		}
		return found;
	}

	/**
	 * Classify {@code carrier} as a skip, or return null. A carrier qualifies when some address
	 * strictly inside it begins an instruction that ENDS EXACTLY WHERE THE CARRIER ENDS -- the
	 * two streams converging on a shared tail is what makes this the skip idiom rather than a
	 * coincidence of bytes -- and that shared tail is itself already disassembled.
	 */
	private Candidate classify(PseudoDisassembler pdis, Instruction carrier) {
		Address carrierStart = carrier.getMinAddress();
		Address carrierEnd = carrier.getMaxAddress();

		// The shared tail. Both entries exist in order to reach it, so if the byte after the
		// carrier is not code, whatever this is, it is not a skip.
		Address tail = carrierEnd.next();
		if (tail == null || listing.getInstructionAt(tail) == null) {
			return null;
		}

		for (int offset = 1; offset < carrier.getLength(); offset++) {
			Address entry = carrierStart.add(offset);
			if ((entry.getOffset() % alignment) != 0) {
				continue;
			}
			PseudoInstruction hidden = pseudoDisassemble(pdis, entry);
			if (hidden == null || !hidden.getMaxAddress().equals(carrierEnd)) {
				continue;
			}
			return new Candidate(carrier, entry, tail, hidden.getMnemonicString(),
				confidenceOf(carrier, entry, hidden));
		}
		return null;
	}

	/**
	 * How much corroboration there is that {@code entry} is a real entry point rather than a
	 * lucky decode of a genuine operand. See the header comment for what each tier means.
	 */
	private Confidence confidenceOf(Instruction carrier, Address entry, PseudoInstruction hidden) {
		for (Reference ref : getReferencesTo(entry)) {
			if (ref.getReferenceType().isFlow()) {
				return Confidence.REFERENCED;
			}
		}
		// The alternative-parameter shape: something falls INTO the carrier having just done
		// the same thing the hidden instruction does, with a different operand. Comparing
		// mnemonics (not bytes) is deliberate -- LDA #$02 and LDA $02 are both plausible
		// alternatives to LDA #$03, and both are the idiom.
		Instruction prev = listing.getInstructionBefore(carrier.getMinAddress());
		if (prev != null && carrier.getMinAddress().equals(prev.getFallThrough()) &&
			prev.getMnemonicString().equals(hidden.getMnemonicString())) {
			return Confidence.STRONG;
		}
		return Confidence.WEAK;
	}

	/**
	 * The instruction the bytes at {@code at} would form, or null if they form none. Only the
	 * prototype is needed, which is what makes a pseudo-disassembly the right validity test:
	 * it answers "could an instruction exist here" without creating one.
	 */
	private PseudoInstruction pseudoDisassemble(PseudoDisassembler pdis, Address at) {
		try {
			return pdis.disassemble(at);
		}
		catch (InsufficientBytesException | UnknownInstructionException
				| UnknownContextException e) {
			return null; // not an instruction -- an ordinary, expected answer, not an error
		}
	}

	private static int count(List<Candidate> candidates, Confidence confidence) {
		return (int) candidates.stream().filter(c -> c.confidence() == confidence).count();
	}

	// ------------------------------------------------------------------
	// Repair -- upstream FixOffcutInstructionScript's sequence
	// ------------------------------------------------------------------

	/**
	 * Truncate the carrier so the hidden bytes are free, disassemble them, and swap the stale
	 * "conflicting instruction" error bookmark for an informational one. No transaction is
	 * opened here: GhidraScript.executeNormal wraps run() in start()/end(true), so one is
	 * already open and a second would only nest a redundant undo entry.
	 */
	private void fix(Candidate c) throws Exception {
		int length = (int) c.entry().subtract(c.carrier().getMinAddress());
		// The truncated carrier keeps falling through to the SHARED TAIL, not into the bytes it
		// just exposed -- which is what makes the repair honest for both entry points at once.
		// This is Ghidra's doing, not ours, and it is worth knowing because the opposite would
		// be a silent disaster: the visible stream would acquire the hidden instruction's
		// effect (LDA #$02 "falling through" into LDA #$03, i.e. the wrong bank asserted with
		// confidence at a real call site). InstructionDB.getDefaultFallThroughOffset returns
		// the PROTOTYPE's length, so getDefaultFallThrough is unaffected by the override, and
		// setLengthOverride -> addLengthOverrideFallthroughRef even materializes that as an
		// explicit FALL_THROUGH reference. Verified in the listing on wizwarr: after the
		// repair, bc07's fallthrough is bc0a and not bc08. Do NOT "fix" this with
		// setFallThrough(tail) -- setFallThrough compares against the default and clears the
		// override, so it is a no-op that only obscures where the behaviour comes from.
		c.carrier().setLengthOverride(length);
		Address landed = c.carrier().getFallThrough();
		if (!c.tail().equals(landed)) {
			// Cheap standing check on the paragraph above rather than a comment asserting it
			// once. If a future Ghidra ever does derive the fallthrough from the override, the
			// visible stream is being corrupted and the user needs to hear about it here.
			printerr("SKIPFIX carrier " + c.carrier().getMinAddress() + " falls through to " +
				landed + ", not to the shared tail " + c.tail() +
				"; the pre-existing stream through this carrier is now WRONG");
		}
		disassemble(c.entry());
		fixBookmark(c.entry());
		if (makeFunction && listing.getInstructionAt(c.entry()) != null &&
			getFunctionAt(c.entry()) == null) {
			// Nothing falls into a recovered offcut entry -- by construction the only way to
			// arrive there is a jump the analysis could not resolve. Left as a loose
			// instruction it belongs to no function body, so no dataflow pass ever evaluates
			// it and the call site stays as invisible as it was before the repair.
			createFunction(c.entry(), null);
		}
		println("SKIPFIX applied " + c.carrier().getMinAddress() + " len=" + length + " entry=" +
			c.entry());
	}

	/**
	 * Replace the "conflicting instruction" ERROR bookmark the failed disassembly left with an
	 * INFO one. Upstream's caveat applies unchanged: two potentially conflicting context flows
	 * now exist at this address, and applying this script asserts that the exposed one is the
	 * interesting reading.
	 */
	private void fixBookmark(Address at) {
		Bookmark bookmark = bookmarks.getBookmark(at, BookmarkType.ERROR,
			Disassembler.ERROR_BOOKMARK_CATEGORY);
		if (bookmark != null) {
			bookmarks.removeBookmark(bookmark);
		}
		bookmarks.setBookmark(at, BookmarkType.INFO, INFO_BOOKMARK_CATEGORY,
			INFO_BOOKMARK_COMMENT);
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
				printerr("malformed argument '" + arg + "'; expected key:value with no whitespace");
				return false;
			}
			String key = kv[0];
			String value = kv[1];
			try {
				switch (key) {
					case "carriers" -> carriers = parseCarriers(value);
					case "weak" -> applyWeak = flag(key, value);
					case "dryrun" -> dryRun = flag(key, value);
					case "function" -> makeFunction = flag(key, value);
					case "reanalyze" -> reanalyze = flag(key, value);
					case "range" -> parseRange(value);
					default -> {
						printerr("unknown key '" + key + "' in argument '" + arg + "'; expected " +
							"one of carriers, weak, dryrun, function, reanalyze, range");
						return false;
					}
				}
			}
			catch (IllegalArgumentException e) {
				printerr("bad value in argument '" + arg + "': " + e.getMessage());
				return false;
			}
		}
		return true;
	}

	private static Set<String> parseCarriers(String value) {
		Set<String> parsed = new LinkedHashSet<>();
		for (String mnemonic : value.split(",")) {
			if (!mnemonic.isEmpty()) {
				parsed.add(mnemonic.toUpperCase());
			}
		}
		if (parsed.isEmpty()) {
			throw new IllegalArgumentException("carriers must name at least one mnemonic");
		}
		return parsed;
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

	/**
	 * An address token. {@code parseAddress} already accepts a {@code 0x} prefix and a
	 * {@code SPACE:offset} qualifier; only the assembler-style {@code $} needs stripping.
	 */
	private Address address(String text) {
		return parseAddress(text.startsWith("$") ? text.substring(1) : text);
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
