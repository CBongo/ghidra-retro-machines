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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * The 6502 "skip" idiom (BIT-skip / skip2 / skipword) recognizer and repair (beads grm-pfp,
 * grm-9xr), shared by the {@code FixSkipInstructions} script and {@link SkipIdiomAnalyzer} so the
 * two front-ends cannot drift. The script is the reference implementation and its console output
 * is pinned by the {@code nesskiptest} fixture; the explanatory header there describes the idiom
 * and the tiers.
 *
 * <p>The repair MUTATES the instruction stream ({@code setLengthOverride} truncates a real
 * instruction and disassembles inside its operand), so callers must hold an open transaction.
 */
public final class SkipIdiomRepair {

	/** Bookmark category for provenance, matching upstream FixOffcutInstructionScript's. */
	public static final String INFO_BOOKMARK_CATEGORY = "Offcut Instruction";
	public static final String INFO_BOOKMARK_COMMENT = "Fixed skip-idiom offcut instruction";

	/** How confident we are that the hidden bytes are a real entry point. */
	public enum Confidence {
		/** A flow reference already lands at the offcut: upstream's own, dispositive, test. */
		REFERENCED,
		/** The instruction falling through into the carrier is the hidden one's alternative. */
		STRONG,
		/** Structurally valid, uncorroborated. Reported; applied only with weak. */
		WEAK
	}

	/**
	 * One recognized skip: {@code carrier} hides an instruction starting at {@code entry}, and
	 * both streams converge on {@code tail}. The tail is captured at recognition time on
	 * purpose -- {@code carrier.getMaxAddress()} moves once the length override is applied.
	 */
	public record Candidate(Instruction carrier, Address entry, Address tail,
			String hiddenMnemonic, Confidence confidence) {
	}

	/** What to do. {@code carriers} holds upper-case mnemonics. */
	public record Options(Set<String> carriers, boolean applyWeak, boolean dryRun,
			boolean makeFunction) {
		public static Set<String> defaultCarriers() {
			return new LinkedHashSet<>(List.of("BIT"));
		}
	}

	/** Totals of one {@link #run}. */
	public record Summary(List<Candidate> candidates, int applied, int failed) {
		public int count(Confidence confidence) {
			return (int) candidates.stream().filter(c -> c.confidence() == confidence).count();
		}
	}

	private SkipIdiomRepair() {
	}

	/** Whether this candidate would be repaired under {@code options}. */
	public static boolean wouldApply(Candidate c, Options options) {
		return !options.dryRun() && (c.confidence() != Confidence.WEAK || options.applyWeak());
	}

	/** Comma-separated mnemonics, upper-cased; throws if none. */
	public static Set<String> parseCarriers(String value) {
		Set<String> parsed = new LinkedHashSet<>();
		for (String mnemonic : value.split(",")) {
			String m = mnemonic.trim();
			if (!m.isEmpty()) {
				parsed.add(m.toUpperCase());
			}
		}
		if (parsed.isEmpty()) {
			throw new IllegalArgumentException("carriers must name at least one mnemonic");
		}
		return parsed;
	}

	/**
	 * Collect every candidate in {@code scope}, then (two phases, on purpose: applying a fix
	 * invalidates the instruction iterator, and collecting first makes dry-run report exactly the
	 * set a real run acts on) report and apply them. One stable, greppable line per candidate goes
	 * to {@code out}, failures to {@code err}, and a summary line last.
	 */
	public static Summary run(Program program, AddressSetView scope, Options options,
			TaskMonitor monitor, Consumer<String> out, Consumer<String> err) {
		List<Candidate> candidates = collect(program, scope, options.carriers(), monitor);

		int applied = 0;
		int failed = 0;
		for (Candidate c : candidates) {
			boolean act = wouldApply(c, options);
			out.accept("SKIPFIX candidate " + c.carrier().getMinAddress() + " " +
				c.carrier().getMnemonicString() + " hides " + c.entry() + " " +
				c.hiddenMnemonic() + " [" + c.confidence() + "]" + (act ? "" : " (not applied)"));
			if (!act) {
				continue;
			}
			try {
				fix(program, c, options.makeFunction(), monitor, out, err);
				applied++;
			}
			catch (Exception e) {
				// A dynamic offcut (one whose repair depends on run-time context) raises here.
				// Report and keep going: one unrepairable carrier must not cost the rest.
				err.accept("SKIPFIX failed at " + c.carrier().getMinAddress() + ": " + e);
				failed++;
			}
		}
		Summary summary = new Summary(candidates, applied, failed);
		out.accept("SKIPFIX summary candidates=" + candidates.size() + " referenced=" +
			summary.count(Confidence.REFERENCED) + " strong=" + summary.count(Confidence.STRONG) +
			" weak=" + summary.count(Confidence.WEAK) + " applied=" + applied + " failed=" +
			failed);
		return summary;
	}

	// ------------------------------------------------------------------
	// Recognition
	// ------------------------------------------------------------------

	/** Every skip carrier in {@code scope}, classified. Mutates nothing. */
	public static List<Candidate> collect(Program program, AddressSetView scope,
			Set<String> carriers, TaskMonitor monitor) {
		List<Candidate> found = new ArrayList<>();
		Listing listing = program.getListing();
		int alignment = program.getLanguage().getInstructionAlignment();
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		InstructionIterator instrs = listing.getInstructions(scope, true);
		while (instrs.hasNext() && !monitor.isCancelled()) {
			Instruction carrier = instrs.next();
			// An instruction already truncated has been dealt with -- by this repair on an
			// earlier run, by upstream's, or by hand. Re-truncating it would be wrong twice
			// over: the offcut is already exposed, and getMaxAddress no longer means what the
			// convergence test below assumes.
			if (carrier.isLengthOverridden() || carrier.getLength() < 2) {
				continue;
			}
			if (!carriers.contains(carrier.getMnemonicString().toUpperCase())) {
				continue;
			}
			Candidate c = classify(program, listing, alignment, pdis, carrier);
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
	private static Candidate classify(Program program, Listing listing, int alignment,
			PseudoDisassembler pdis, Instruction carrier) {
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
				confidenceOf(program, listing, carrier, entry, hidden));
		}
		return null;
	}

	/**
	 * How much corroboration there is that {@code entry} is a real entry point rather than a
	 * lucky decode of a genuine operand.
	 */
	private static Confidence confidenceOf(Program program, Listing listing, Instruction carrier,
			Address entry, PseudoInstruction hidden) {
		for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
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
	 * prototype is needed, which is what makes a pseudo-disassembly the right validity test.
	 */
	private static PseudoInstruction pseudoDisassemble(PseudoDisassembler pdis, Address at) {
		try {
			return pdis.disassemble(at);
		}
		catch (InsufficientBytesException | UnknownInstructionException
				| UnknownContextException e) {
			return null; // not an instruction -- an ordinary, expected answer, not an error
		}
	}

	// ------------------------------------------------------------------
	// Repair -- upstream FixOffcutInstructionScript's sequence
	// ------------------------------------------------------------------

	/**
	 * Truncate the carrier so the hidden bytes are free, disassemble them, and swap the stale
	 * "conflicting instruction" error bookmark for an informational one. The caller owns the
	 * transaction.
	 */
	public static void fix(Program program, Candidate c, boolean makeFunction,
			TaskMonitor monitor, Consumer<String> out, Consumer<String> err) throws Exception {
		Listing listing = program.getListing();
		int length = (int) c.entry().subtract(c.carrier().getMinAddress());
		// The truncated carrier keeps falling through to the SHARED TAIL, not into the bytes it
		// just exposed -- which is what makes the repair honest for both entry points at once.
		// This is Ghidra's doing, not ours: InstructionDB.getDefaultFallThroughOffset returns
		// the PROTOTYPE's length, so the fallthrough is unaffected by the override, and
		// setLengthOverride -> addLengthOverrideFallthroughRef materializes it as an explicit
		// FALL_THROUGH reference. Verified on wizwarr: after the repair, bc07's fallthrough is
		// bc0a and not bc08. Do NOT "fix" this with setFallThrough(tail) -- it compares against
		// the default and clears the override.
		c.carrier().setLengthOverride(length);
		Address landed = c.carrier().getFallThrough();
		if (!c.tail().equals(landed)) {
			// Cheap standing check on the paragraph above. If a future Ghidra ever derives the
			// fallthrough from the override, the visible stream is being corrupted.
			err.accept("SKIPFIX carrier " + c.carrier().getMinAddress() + " falls through to " +
				landed + ", not to the shared tail " + c.tail() +
				"; the pre-existing stream through this carrier is now WRONG");
		}
		new DisassembleCommand(c.entry(), null, true).applyTo(program, monitor);
		fixBookmark(program.getBookmarkManager(), c.entry());
		if (makeFunction && listing.getInstructionAt(c.entry()) != null &&
			listing.getFunctionAt(c.entry()) == null) {
			// Nothing falls into a recovered offcut entry; left as a loose instruction it
			// belongs to no function body, so no dataflow pass would evaluate it.
			new CreateFunctionCmd(c.entry()).applyTo(program, monitor);
		}
		out.accept("SKIPFIX applied " + c.carrier().getMinAddress() + " len=" + length +
			" entry=" + c.entry());
	}

	/**
	 * Replace the "conflicting instruction" ERROR bookmark the failed disassembly left with an
	 * INFO one. Upstream's caveat applies unchanged: two potentially conflicting context flows
	 * now exist at this address, and applying this asserts the exposed one is the interesting
	 * reading.
	 */
	private static void fixBookmark(BookmarkManager bookmarks, Address at) {
		Bookmark bookmark = bookmarks.getBookmark(at, BookmarkType.ERROR,
			Disassembler.ERROR_BOOKMARK_CATEGORY);
		if (bookmark != null) {
			bookmarks.removeBookmark(bookmark);
		}
		bookmarks.setBookmark(at, BookmarkType.INFO, INFO_BOOKMARK_CATEGORY,
			INFO_BOOKMARK_COMMENT);
	}
}
