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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import static retromachines.BankDataflowEngine.toFieldLocal;
import static retromachines.HelperDiscovery.calledHelper;
import static retromachines.HelperDiscovery.reachableEntries;

import retromachines.BankDataflowEngine.DataflowResult;
import retromachines.BankDataflowEngine.SwitchResult;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.Bounded;
import retromachines.BoardDescriptorModel.ComputedWindowModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.ModeWindowModel;
import retromachines.BoardDescriptorModel.OccupantModel;
import retromachines.BoardDescriptorModel.WindowModel;
import retromachines.HelperDiscovery.HelperModel;

/**
 * The Ghidra mutation/annotation adapter for {@code BoardBankAnalyzer}'s completed dataflow:
 * EOL comment annotation of resolved bank-switch sites, function-level bank-state summaries
 * and call-site requirement violation warnings, cross-bank reference retargeting into overlay
 * spaces, and {@code banking.context_register} stamping.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Annotation", "Function-level
 * bank-state summaries", "Reference retargeting" and "Context stamping" sections without
 * behavior change (bead grm-ft8 increment 4, from QR-12), taken before increment 3 ("dataflow
 * engine returning facts") because the dependency runs one way: this code reads the dataflow
 * engine's output ({@link DataflowResult}, {@link SwitchResult}, {@link HelperModel}), and the
 * dataflow engine never calls back into this one. One holder, not four files, following
 * {@link BoardDescriptorModel} and {@link BankStrategyRegistry}'s precedent in this package.
 *
 * <p>The one non-mechanical change every method here shares with {@link BankStrategyRegistry}:
 * several log through {@link AnalyzerLog#warn}/{@code info}/{@code debug}, whose first
 * parameter is the {@link ghidra.app.services.Analyzer} doing the logging -- that used to be
 * {@code this}, and is now threaded in as a leading {@code analyzer} parameter. Two methods
 * ({@code annotateOrWarn}, {@code annotateBankRequirementViolations}) also call
 * {@code BoardBankAnalyzer.getBookmarkCategory()}, a protected, overridable instance method not
 * expressible through the generic {@code Analyzer} interface, so {@code analyzer} is typed
 * {@link BoardBankAnalyzer} here rather than {@code Analyzer} at those two call sites.
 * {@code helperArgumentCallSites} no longer needs a threaded receiver for this reason:
 * {@code calledHelper} became {@code static} as of grm-shnf step 2 and is referenced here via
 * {@code import static} instead. {@code toFieldLocal} and {@code reachableEntries} are static helpers,
 * referenced here via {@code import static} so the call sites themselves are byte-identical to
 * their originals; {@code toFieldLocal} moved to {@link BankDataflowEngine} with the Dataflow
 * section (bead grm-gqrj) and {@code reachableEntries} moved to {@link HelperDiscovery} with the
 * rest of the Helper-call-propagation section's discovery half (bead grm-shnf step 3).
 * {@code findModeWindowInstance}
 * moved here with "Reference retargeting" but is also called from
 * {@code BankDataflowEngine.clampToResidence} -- the one place this increment's own code is
 * called back INTO from the dataflow side; that call site was qualified
 * {@code BankAnnotationAdapter.findModeWindowInstance(...)} and {@code findModeWindowInstance}
 * widened from {@code private} to package-private to allow it.
 */
final class BankAnnotationAdapter {

	private BankAnnotationAdapter() {
	}

	// ------------------------------------------------------------------
	// Annotation
	// ------------------------------------------------------------------

	/**
	 * Annotates a resolved bank-switch site with an EOL comment. When {@code newState}
	 * is fully known, the comment is {@code bank -> 5 (RAM_A000/IO/RAM_E000)} on
	 * enumerated boards (occupant row) and {@code bank -> 5 (bank=5)} on single-field
	 * computed boards (the {@code effective} value IS the bank there). On a multi-field
	 * computed board (MMC1/MMC3/Bandai FCG) the {@code effective} value is a packed state
	 * tuple, not a bank index, so instead of a cryptic decimal the comment leads with the
	 * field breakdown itself: {@code bank -> select=0,prg_mode=1,r6=0,r7=1} (grm-y20).
	 * When only some bits are known, the comment marks the state with a trailing
	 * {@code ?} and spells out, by {@code banking.state} field name, which bits are
	 * actually known versus merely assumed from {@code banking.initial_state} -- e.g.
	 * {@code bank -> 7? (BASIC/IO/KERNAL) [known: LORAM=1; assumed from initial:
	 * HIRAM,CHAREN]} (enumerated) or {@code bank -> select=7,...,r7=26? [known: ...;
	 * assumed from initial: ...]} (packed tuple). Call-site switches carry the helper's
	 * name.
	 */
	/**
	 * Records one recovered switch site: an EOL annotation when at least one tracked bank
	 * bit is known, or a warning bookmark -- the caller's {@code warning} when value recovery
	 * pinned down no bit at all, or the impossible-bank diagnostic when it pinned down a bank
	 * the image has no slice for ({@link #impossibleBank}). Returns the number of warnings
	 * raised (0 or 1) for the caller's tally.
	 */
	static int annotateOrWarn(BoardBankAnalyzer analyzer, Program program, Listing listing,
			Address addr, BankState state, BoardModel board,
			Map<String, Set<Integer>> bankUniverse, String viaHelper, String warning) {
		if (state.knownMask() == 0) {
			program.getBookmarkManager()
					.setBookmark(addr, BookmarkType.WARNING, analyzer.getBookmarkCategory(), warning);
			return 1;
		}
		ImpossibleBank impossible = impossibleBank(board, state, bankUniverse);
		if (impossible != null) {
			program.getBookmarkManager().setBookmark(addr, BookmarkType.WARNING,
				analyzer.getBookmarkCategory(), impossible.message());
			return 1;
		}
		annotateBankSwitch(listing, addr, state, board, viaHelper);
		return 0;
	}

	/**
	 * A recovered bank index for which the loaded image holds no slice (bead grm-hum
	 * increment 3): {@code window} is the switchable window whose field named it,
	 * {@code bank} the recovered value, {@code realized} how many banks that window actually
	 * has.
	 */
	private record ImpossibleBank(String window, int bank, int realized) {
		String message() {
			return "Bank state becomes unknown here: recovered bank " + bank + " for window " +
				window + ", but this image provides only " + realized + " bank(s) for it. " +
				"A bank index with no corresponding image slice is a value-RECOVERY bug, not a " +
				"game behavior, so this site is left unannotated and nothing is retargeted from " +
				"it. Hardware aliasing (a board that decodes fewer latch bits than the field is " +
				"wide selects some in-range bank instead of faulting) is deliberately NOT " +
				"modeled: that is per-board wiring, and folding it on speculation would turn a " +
				"loud wrong answer into a quiet plausible one -- see docs/vision-board-banking.md " +
				"section 10 item 10, bead grm-hum.";
		}
	}

	/**
	 * The first switchable window whose FULLY RECOVERED bank field names a bank this image does
	 * not have, or null when every such window resolves to a real occupant.
	 * <p>
	 * Only fields whose bits are entirely known in {@code state} are checked. A partially known
	 * field renders from {@code banking.initial_state} in the annotation
	 * ({@link BankState#effective}), and the initial state is a descriptor-declared, in-range
	 * value -- flagging it would be flagging the fallback, not a recovered value.
	 * <p>
	 * "Does not have" is read off the program itself rather than recomputed from the container
	 * header: the loader creates one block per bank value whose slice fits inside the image and
	 * skips the rest ("bank values beyond the image simply don't exist",
	 * {@code NesRomLoader.realizeComputedWindow}), so the realized set IS the image's statement
	 * of how many banks the board is fitted with, and it is by construction the same set
	 * {@link #retargetReferences} can find an overlay space for.
	 */
	private static ImpossibleBank impossibleBank(BoardModel board, BankState state,
			Map<String, Set<Integer>> bankUniverse) {
		if (bankUniverse.isEmpty()) {
			return null;
		}
		int effective = state.effective(board.initialState(), board.mask());
		for (ComputedWindowModel w : board.computedWindows().values()) {
			ImpossibleBank bad =
				checkBank(bankUniverse, w.name(), w.name(), w.field(), state, effective);
			if (bad != null) {
				return bad;
			}
		}
		FieldSpec modeField = board.modeField();
		if (modeField != null && modeField.fullyKnownIn(state)) {
			int mode = modeField.valueIn(effective);
			for (ModeWindowModel w : board.modeWindows()) {
				if (w.modeValue() != mode || w.bankField() == null) {
					continue;
				}
				ImpossibleBank bad = checkBank(bankUniverse, modeBankKey(w.name(), mode), w.name(),
					w.bankField(), state, effective);
				if (bad != null) {
					return bad;
				}
			}
		}
		return null;
	}

	/** One window's bank field against its realized bank set; see {@link #impossibleBank}. */
	private static ImpossibleBank checkBank(Map<String, Set<Integer>> bankUniverse, String key,
			String windowName, FieldSpec field, BankState state, int effective) {
		if (!field.fullyKnownIn(state)) {
			return null;
		}
		Set<Integer> realized = bankUniverse.get(key);
		if (realized == null || realized.isEmpty()) {
			return null; // nothing realized for this window at all -- not our diagnostic to make
		}
		int bank = field.valueIn(effective);
		return realized.contains(bank) ? null
				: new ImpossibleBank(windowName, bank, realized.size());
	}

	/**
	 * Every address on this program that mirrors the live bank (bead grm-mej.2) -- see
	 * {@link BankMirrors} for what each kind means and {@link BankSwitchStrategy#observeMirrors}
	 * for how it reaches the strategies.
	 * <p>
	 * Runs between the two dataflow passes because both halves need pass 1: the code half scans
	 * back from {@code flow.switchResults()}' recognized mechanism writes, and the argument-cell
	 * half needs the helper models built from them. It is the same slot, and the same reason,
	 * that puts {@link #findHelpers} here.
	 * <p>
	 * <b>Only mode-INVARIANT switchable windows are content-scanned.</b> A mode-varying window's
	 * bank images live under {@code <name>_M<mode>_B<bank>} and its realized-bank set is per
	 * mode instance, so "the byte at K identifies the bank" would have to be qualified by mode
	 * to mean anything. No board that has one also has the ROM-identifying convention (it is a
	 * cartridge idiom, and mode windows are the home-computer shape), so it is left out rather
	 * than guessed at.
	 */
	static BankMirrors deriveBankMirrors(Program program,
			BoardModel board, Map<String, Set<Integer>> bankUniverse, DataflowResult flow,
			Map<Function, HelperModel> helpers) {
		BankMirrors.Discovery discovery =
			new BankMirrors.Discovery(program.getAddressFactory().getDefaultAddressSpace());
		for (ComputedWindowModel w : board.computedWindows().values()) {
			Set<Integer> banks = bankUniverse.get(w.name());
			if (banks != null) {
				discovery.addRomIdentifying(BankMirrors.romIdentifyingOffsets(program, w.name(),
					w.start(), w.end(), banks));
			}
		}
		discovery.scanWriteThroughShadows(program, flow.switchResults().keySet());
		discovery.scanArgumentCells(program,
			helperArgumentCallSites(program, flow, helpers));
		// Route (c) LAST and deliberately so: "a copy of something that already mirrors the live
		// bank" can only be judged once (a) and (b) have established what does.
		discovery.scanSaveSlotCopies(program);
		return discovery.build();
	}

	/**
	 * The symbol-name prefix for each {@link BankMirrors.Kind}, iterated in NAME precedence
	 * order (highest first) by {@link #nameBankMirrors} -- a {@link LinkedHashMap} so insertion
	 * order doubles as the precedence order rather than needing a second table.
	 * <p>
	 * {@code SAVE_SLOT} and {@code INPUT} precede {@code WRITE_THROUGH} and
	 * {@code ROM_IDENTIFYING} deliberately: they are the two kinds that hold a bank which is
	 * NOT the live one (see {@link BankMirrors.Kind}'s javadoc), and a cell that reads like a
	 * live shadow but is actually one of those is exactly the trap this labelling exists to
	 * flag -- so when a cell carries both, the name should say the dangerous thing, not the
	 * safe one. The full kind set still goes in the comment ({@link #nameBankMirrors}), so
	 * nothing is lost to the one-name-per-address limit; this ordering only decides what wins
	 * the symbol table's single primary label.
	 */
	private static final Map<BankMirrors.Kind, String> MIRROR_NAME_PREFIX = new LinkedHashMap<>();
	static {
		MIRROR_NAME_PREFIX.put(BankMirrors.Kind.SAVE_SLOT, "bank_saved_");
		MIRROR_NAME_PREFIX.put(BankMirrors.Kind.INPUT, "bank_request_");
		MIRROR_NAME_PREFIX.put(BankMirrors.Kind.WRITE_THROUGH, "bank_shadow_");
		MIRROR_NAME_PREFIX.put(BankMirrors.Kind.ROM_IDENTIFYING, "bank_id_");
	}

	/**
	 * How many evidence addresses {@link #nameBankMirrors} lists in one cell's comment before
	 * truncating. Blaster Master's {@code $D3} -- the one multi-role cell traced by hand for
	 * grm-mej.2 -- has five write sites across five functions, so a cap has to clear that
	 * without the comment running unbounded on some future board with a more diffuse idiom; 6
	 * clears the measured case with one slot to spare and stays a one-line comment.
	 */
	private static final int MIRROR_COMMENT_EVIDENCE_CAP = 6;

	/**
	 * Turns the mirror set {@link #deriveBankMirrors} derived into symbols and comments (bead
	 * grm-mej.4) -- the documentary payoff of grm-mej.2's derivation, otherwise invisible in the
	 * listing. Runs once, after pass 2 (mirror classification does not change after that) and
	 * before Phase 2's unrelated annotation work over the same listing.
	 * <p>
	 * <b>The offset suffix is unconditional</b>, appended to every name regardless of whether it
	 * would collide without it. A board legitimately has more than one mirror of the same kind --
	 * Blaster Master has two write-through shadows, {@code $DB} and {@code $D3} -- and a
	 * "bare name unless it collides" rule would make the bare-vs-suffixed choice depend on
	 * discovery order, which is not a property a symbol name should expose. Matches this
	 * codebase's other derived-name convention ({@code COPY_6c90}, {@code DECRYPTED_%04x}): the
	 * offset is always in the name.
	 * <p>
	 * <b>One name per address</b>, chosen by {@link #MIRROR_NAME_PREFIX}'s precedence, because
	 * Ghidra gives one primary label per address and a cell can carry several kinds at once
	 * (Blaster Master's {@code $D3} is {@code INPUT|SAVE_SLOT}). The comment carries the full
	 * kind set regardless of which one won the name.
	 * <p>
	 * Routed entirely through {@link AnnotationGuard}, so a {@code USER_DEFINED} label or a
	 * comment a human already wrote here is never displaced, and re-running the analyzer (the
	 * framework does, per {@code added()}'s own re-run gate) neither churns the symbol table nor
	 * stacks a second copy of the comment -- {@link AnnotationGuard#applyLabel} is a no-op once
	 * the name exists, and {@link AnnotationGuard#addComment}'s {@code "bank mirror:"} marker
	 * stops the comment from growing on a second pass.
	 * <p>
	 * <b>The comment must never contain the literal {@code "bank ->"}.</b> Both golden dumps
	 * (headless {@code VerifyBankTest}, real-ROM {@code RealRomDump}) count EOL comments
	 * containing exactly that substring as {@code bankComments}, and it is the vocabulary
	 * {@link #annotateBankSwitch} and {@link #annotatePlacementProvenance} use for switch-value
	 * provenance -- a mirror comment using it too would inflate a metric other beads reason
	 * against. Hence {@code "bank mirror:"} rather than anything starting with {@code "bank"}
	 * that could textually collide.
	 */
	// Package-private and static (rather than private) so BankMirrorNamingProgramTest can drive
	// it directly against a hand-built BankMirrors set, without needing a full board descriptor
	// and added() run -- the same reasoning that keeps BankMirrors.Discovery's derivation and
	// MemoryLatchBankSwitchStrategy's consumption separately testable (see
	// BankMirrorConsumptionProgramTest's class javadoc).
	static void nameBankMirrors(Program program, Listing listing, BankMirrors mirrors,
			AddressSpace baseSpace) {
		for (Map.Entry<Long, Set<BankMirrors.Kind>> entry : mirrors.byOffset().entrySet()) {
			long offset = entry.getKey();
			Set<BankMirrors.Kind> kinds = entry.getValue();
			Address addr = baseSpace.getAddress(offset);

			BankMirrors.Kind primary = null;
			for (BankMirrors.Kind candidate : MIRROR_NAME_PREFIX.keySet()) {
				if (kinds.contains(candidate)) {
					primary = candidate;
					break;
				}
			}
			if (primary == null) {
				continue; // defensive: every kind in the enum has a prefix above
			}
			String name = MIRROR_NAME_PREFIX.get(primary) + String.format("%04x", offset);
			try {
				AnnotationGuard.applyLabel(program, addr, name, SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				// Generated names are letters/digits/underscore only, so this is unreachable in
				// practice -- surface it loudly rather than silently dropping the label.
				throw new RuntimeException(
					"bank mirror label '" + name + "' at " + addr + " rejected: " +
						e.getMessage(), e);
			}

			List<String> kindNames = kinds.stream().map(Enum::name).sorted().toList();
			List<Address> evidence = new ArrayList<>(mirrors.evidenceSites(addr));
			Collections.sort(evidence);
			List<String> evidenceHex = new ArrayList<>();
			for (int i = 0; i < evidence.size() && i < MIRROR_COMMENT_EVIDENCE_CAP; i++) {
				evidenceHex.add(String.format("%04x", evidence.get(i).getOffset()));
			}
			String more = evidence.size() > MIRROR_COMMENT_EVIDENCE_CAP
					? " (+" + (evidence.size() - MIRROR_COMMENT_EVIDENCE_CAP) + " more)" : "";
			String comment = evidenceHex.isEmpty()
					? "bank mirror: " + kindNames
					: "bank mirror: " + kindNames + " established at " +
						String.join(", ", evidenceHex) + more;
			AnnotationGuard.addComment(listing, addr, CommentType.EOL, comment, "bank mirror:");
		}
	}

	/**
	 * Every call site that reaches a bank-switch helper taking its bank in a known register,
	 * paired with that register -- the starting points for {@link BankMirrors}' argument-cell
	 * route (b).
	 * <p>
	 * Resolution goes through {@link #calledHelper} rather than through the reference manager so
	 * that pass-through wrappers, mid-body entries and relays are followed exactly as the
	 * dataflow follows them; a discovery pass that resolved calls its own way would nominate
	 * cells for call sites the engine does not agree are helper calls.
	 */
	private static Map<Address, Character> helperArgumentCallSites(Program program,
			DataflowResult flow, Map<Function, HelperModel> helpers) {
		Map<Address, Character> sites = new LinkedHashMap<>();
		if (helpers.isEmpty()) {
			return sites;
		}
		Listing listing = program.getListing();
		for (Address addr : flow.stateIn().keySet()) {
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null || !instr.getFlowType().isCall()) {
				continue;
			}
			HelperModel helper = calledHelper(program, instr, helpers);
			if (helper != null && helper.argReg() != null) {
				sites.put(addr, helper.argReg());
			}
		}
		return sites;
	}

	/** Key under which {@link #bankUniverse} files a mode-varying window instance's banks. */
	private static String modeBankKey(String windowName, int modeValue) {
		return windowName + "_M" + modeValue;
	}

	/**
	 * Which bank values each switchable window actually has an image slice for, keyed by window
	 * name (mode-invariant computed windows) or by {@link #modeBankKey} (one mode-varying
	 * window instance). Derived once per run from the program's own address spaces plus the
	 * one home bank the loader realizes in BASE space rather than as an overlay -- see
	 * {@link DescriptorSupport.OverlayNaming} for the naming contract this parses back, and
	 * {@link #impossibleBank} for why the program rather than the container header is the
	 * authority.
	 */
	static Map<String, Set<Integer>> bankUniverse(Program program, BoardModel board) {
		Map<String, Set<Integer>> universe = new LinkedHashMap<>();
		for (ComputedWindowModel w : board.computedWindows().values()) {
			universe.put(w.name(), realizedBanks(program, w.name(),
				w.field().valueIn(board.initialState())));
		}
		FieldSpec modeField = board.modeField();
		for (ModeWindowModel w : board.modeWindows()) {
			if (w.bankField() == null) {
				continue;
			}
			boolean homeMode = modeField != null && w.modeValue() == board.homeModeValue();
			universe.put(modeBankKey(w.name(), w.modeValue()), realizedModeBanks(program, w.name(),
				w.modeValue(), homeMode ? w.bankField().valueIn(board.initialState()) : null));
		}
		return universe;
	}

	/**
	 * The bank values realized for a mode-invariant computed window: {@code homeBank}, which
	 * the loader places in base space, plus every {@code <window>_B<n>} overlay space it
	 * created. Package-private for the Tier-2 test that pins the derivation.
	 */
	static Set<Integer> realizedBanks(Program program, String windowName, int homeBank) {
		Set<Integer> banks = new LinkedHashSet<>();
		banks.add(homeBank);
		for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
			if (!space.isOverlaySpace()) {
				continue;
			}
			Integer v =
				DescriptorSupport.OverlayNaming.parseBankValue(windowName, space.getName());
			if (v != null) {
				banks.add(v);
			}
		}
		return banks;
	}

	/**
	 * The bank values realized for one mode-varying window instance: every
	 * {@code <window>_M<mode>_B<n>} overlay space, plus {@code homeBank} when this instance is
	 * the home layout (exactly one (mode, bank) pair across the whole window lives in base
	 * space; {@code homeBank} is null for every other mode).
	 */
	static Set<Integer> realizedModeBanks(Program program, String windowName, int modeValue,
			Integer homeBank) {
		Set<Integer> banks = new LinkedHashSet<>();
		if (homeBank != null) {
			banks.add(homeBank);
		}
		for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
			if (!space.isOverlaySpace()) {
				continue;
			}
			DescriptorSupport.OverlayNaming.ModeBank mb =
				DescriptorSupport.OverlayNaming.parseModeBankValue(windowName, space.getName());
			if (mb != null && mb.mode() == modeValue) {
				banks.add(mb.bank());
			}
		}
		return banks;
	}

	private static void annotateBankSwitch(Listing listing, Address addr, BankState newState,
			BoardModel board, String viaHelper) {
		int mask = board.mask();
		int effective = newState.effective(board.initialState(), mask);
		String desc = describeState(board, effective);
		String via = viaHelper == null ? "" : " via " + viaHelper;

		// Whether describeState resolved this state to an occupant ROW (enumerated board,
		// e.g. C64 BASIC/IO/KERNAL) rather than a field tuple. Mirrors describeState's
		// first branch.
		boolean enumerated = !board.windows().isEmpty()
				&& board.occupantByWindowForState().get(effective) != null;
		// On a multi-field computed board (MMC1/MMC3/Bandai FCG) the "effective" value is a
		// PACKED state tuple, not a PRG bank index -- rendering it as a bare decimal
		// ("bank -> 26639") is cryptic and fully redundant with the field breakdown that
		// follows. Lead with the field tuple itself instead (grm-y20). Single-field boards
		// keep the plain "bank -> 5 (bank=5)" form (there the number IS the bank), and
		// enumerated boards keep "bank -> 5 (occupants)".
		boolean packedTuple = !enumerated && board.fieldSpecs().size() > 1;
		// Fully-known head, and the partial head with the "?" uncertainty marker in its
		// conventional spot: right after the state value for enumerated/single-field
		// boards ("7? (BASIC/IO/KERNAL)"), right after the field tuple for packed boards
		// ("select=7,...,r7=26?").
		String head = packedTuple ? desc : effective + " (" + desc + ")";
		String headQ = packedTuple ? desc + "?" : effective + "? (" + desc + ")";

		String bankComment;
		if (newState.knownMask() == mask) {
			bankComment = "bank -> " + head + via;
		}
		else {
			List<String> known = new ArrayList<>();
			List<String> assumed = new ArrayList<>();
			// Walk every tracked state bit, not just the low 8: boards can carry >8
			// (nes-serialtest = 9). mask is a contiguous low mask ((1<<N)-1), so its
			// width is N; the mask guard below still skips any bit outside it.
			int width = 32 - Integer.numberOfLeadingZeros(mask);
			for (int bit = 0; bit < width; bit++) {
				int bitMask = 1 << bit;
				if ((mask & bitMask) == 0) {
					continue;
				}
				String name = bit < board.stateBitNames().size() ? board.stateBitNames().get(bit)
						: ("bit" + bit);
				if ((newState.knownMask() & bitMask) != 0) {
					known.add(name + "=" + ((newState.bits() & bitMask) != 0 ? 1 : 0));
				}
				else {
					assumed.add(name);
				}
			}
			bankComment = "bank -> " + headQ + via + " [known: " +
				String.join(",", known) + "; assumed from initial: " + String.join(",", assumed) +
				"]";
		}

		// Placement-provenance vocabulary (grm-hsv.3): tag dataflow-recovered switch values so
		// they read distinctly from override placements ("[user override]", see
		// annotatePlacementProvenance) and future self-ref inference. Gated to mode-varying
		// boards -- the only ones where placement can be ambiguous -- so other boards' goldens
		// stay byte-identical.
		if (board.modeField() != null) {
			bankComment += " [switch-value flow]";
		}

		AnnotationGuard.addComment(listing, addr, CommentType.EOL, bankComment, "bank ->");
	}

	/**
	 * Records that the reference at {@code addr} was placed into bank {@code bank} because the
	 * user pinned it via the {@link DescriptorSupport#PLACEMENT_OVERRIDE_PROPERTY} override --
	 * dataflow did not recover the switchable bank here (grm-hsv.3). Uses the {@code bank ->}
	 * vocabulary so the provenance shows in the listing and the banktest dump, and defers to an
	 * existing bank-switch annotation rather than clobbering it.
	 */
	private static void annotatePlacementProvenance(Listing listing, Address addr, int bank) {
		String comment = "bank -> " + bank + " [user override]";
		AnnotationGuard.addComment(listing, addr, CommentType.EOL, comment, "bank ->");
	}

	/**
	 * Reads and parses the user bank-placement override
	 * ({@link DescriptorSupport#PLACEMENT_OVERRIDE_PROPERTY}) a loader may have persisted:
	 * a window-name -> bank map applied in {@link #retargetReferences} where dataflow left a
	 * switchable bank unknown. Absent -> empty; a malformed value (should not happen -- the
	 * loader validated it) is logged and ignored, matching the loader-degradation convention.
	 */
	static Map<String, Integer> readPlacementOverride(BoardBankAnalyzer analyzer, Program program,
			MessageLog log) {
		String spec = program.getOptions(Program.PROGRAM_INFO)
				.getString(DescriptorSupport.PLACEMENT_OVERRIDE_PROPERTY, null);
		if (spec == null || spec.isBlank()) {
			return Map.of();
		}
		try {
			Map<String, Integer> override = DescriptorSupport.parsePlacementOverride(spec);
			if (!override.isEmpty()) {
				AnalyzerLog.info(analyzer, "placement override active: " + override);
			}
			return override;
		}
		catch (IllegalArgumentException e) {
			AnalyzerLog.warn(analyzer, log,
				"ignoring malformed placement override '" + spec + "': " + e.getMessage());
			return Map.of();
		}
	}

	/**
	 * Human description of an effective state: the occupant row on enumerated boards
	 * ({@code BASIC/IO/KERNAL}), field values on computed boards ({@code bank=3}).
	 */
	private static String describeState(BoardModel board, int effective) {
		Map<String, String> stateRow = board.occupantByWindowForState().get(effective);
		if (stateRow != null && !board.windows().isEmpty()) {
			List<String> parts = new ArrayList<>();
			for (String windowName : board.windows().keySet()) {
				parts.add(stateRow.getOrDefault(windowName, "?"));
			}
			return String.join("/", parts);
		}
		if (!board.fieldSpecs().isEmpty()) {
			List<String> parts = new ArrayList<>();
			for (FieldSpec f : board.fieldSpecs()) {
				parts.add(f.name() + "=" + f.valueIn(effective));
			}
			return String.join(",", parts);
		}
		return "?";
	}

	// ------------------------------------------------------------------
	// Function-level bank-state summaries (grm-6a7.2, M3 scope)
	// ------------------------------------------------------------------

	/**
	 * Derives a {@link FunctionBankSummary} for every {@link Function} from the completed
	 * Phase-1/2 dataflow ({@code flow}), then flags direct call sites that violate a
	 * callee's {@code requiresOnEntry}: a WARNING bookmark, never a change to the tracked
	 * state. This is a read-only annotation layer -- nothing computed here is fed back
	 * into {@code flow} or re-influences {@link #runDataflow}; M3 deliberately excludes
	 * any back-propagation/narrowing of Phase-1 state from these summaries (a mutual-
	 * fixpoint/termination-risk problem left to M4+, see the module doc / vision doc §9).
	 * <p>
	 * <b>exitState</b>: {@code flow.stateIn()} only retains each instruction's IN-state,
	 * not a separate OUT-state map. RTS/RTI never match a mechanism write (no shipped
	 * strategy recognizes a return instruction as a switch site), so an RTS/RTI's retained
	 * IN-state already equals its OUT-state -- the state control returns to the caller
	 * with. Merging (agree-bit join, same as {@link BankState#merge}) over every such exit
	 * instruction in a function's body is therefore a free, sound read-off; no separate
	 * OUT-state tracking needed.
	 * <p>
	 * <b>modifiedMask</b>: the union of every switch site's {@code effectMask} inside the
	 * function's own body, plus (bottom-up over the direct call graph) every directly
	 * called function's own {@code modifiedMask}. Indirect calls (the call instruction's
	 * flow does not resolve to a {@link Function} entry) are not found by the body walk
	 * below at all, so they never propagate -- a deliberate M3 conservatism (an indirect
	 * call's real target modifications are simply not counted; documented, not silently
	 * unsound, since {@code modifiedMask} is only ever used to log summaries in M3, never
	 * to gate anything).
	 * <p>
	 * <b>requiresOnEntry</b> (M3 scope: known-ness only -- value-level requirements, e.g.
	 * "select must equal exactly 6", are NOT modeled, only "select must be KNOWN"):
	 * for each switch site in a function's own body whose matched strategy answers
	 * {@link BankSwitchStrategy#effectDependsOnPriorState(Program, Instruction, BankState)}
	 * {@code true} <em>at that site</em> (i.e. an unknown
	 * outcome at the site is evidence the dispatch NEEDED a state bit it did not have on
	 * entry, not merely that {@code computeSwitch} happened to consult {@code inState}),
	 * the bits the switch's OWN effect ends up NOT knowing that the flowed-in
	 * {@code inState} ALSO did not know -- {@code effectMask & ~inState.knownMask &
	 * ~effect.knownMask()}. That intersection is exactly "the dispatch needed this bit
	 * and didn't have it": a strategy that does not depend on prior state (every cacheable
	 * strategy qualifies automatically, since {@code effectDependsOnPriorState()} defaults
	 * to {@code !cacheable()}) never contributes, and one that does but whose effect came
	 * out fully known anyway (e.g. a plain {@code LDA #imm/STA} sequence, or a masked-RMW
	 * read-back that resolved cleanly from known in-state) also contributes nothing, since
	 * {@code ~effect.knownMask()} is empty there. The predicate is deliberately not
	 * {@link BankSwitchStrategy#cacheable()} itself: a write-only mechanism such as
	 * serial-shift (MMC1) is non-cacheable purely because it ECHOES {@code inState}
	 * unchanged on its no-op branches, and inferring a requirement from its unknown
	 * outcome would produce false violations whose unknown-ness actually came from an
	 * unresolved DATA value, never from missing bank state. The question is asked per SITE
	 * for the same reason it is not asked as {@code cacheable()}, one level finer: memory-latch
	 * became non-cacheable in grm-mej.2 because it reads the bank back at the few sites that
	 * load a bank MIRROR, and answering per strategy there would have declared a requirement at
	 * every latch site that came out unknown for any reason at all. Bits the function itself
	 * establishes BEFORE a later consuming site are automatically excluded -- not by explicit
	 * program-order subtraction, but because {@code flow.stateIn()} at that later site
	 * already reflects every predecessor on the real CFG, including earlier code in the same
	 * function; no separate bookkeeping is needed or attempted. This own-body requirement
	 * is then unioned (again bottom-up over the direct call graph) with each directly
	 * called function's own {@code requiresOnEntry}, narrowed at the call site by
	 * {@code ~callSiteInState.knownMask()} -- exactly the same rule the violation check
	 * below applies at every caller, so a function that reliably establishes a callee's
	 * requirement before calling it does not itself inherit that requirement. Recursion
	 * and mutual recursion are handled by plain chaotic iteration to a fixpoint (masks
	 * only ever grow, so this always terminates) rather than an explicit SCC computation --
	 * equivalent result, simpler code. Indirect calls: not propagated, same as
	 * {@code modifiedMask} above.
	 *
	 * @return the number of new violation WARNING bookmarks placed
	 */
	static int annotateBankRequirementViolations(BoardBankAnalyzer analyzer, Program program,
			Listing listing, DataflowResult flow, BoardModel board, Set<Address> alreadyWarned,
			MessageLog log) {

		FunctionManager fm = program.getFunctionManager();

		// --- own (intra-function) contribution from this function's own switch sites ---
		Map<Function, Integer> ownModified = new LinkedHashMap<>();
		Map<Function, Integer> ownRequires = new LinkedHashMap<>();
		for (Map.Entry<Address, SwitchResult> e : flow.switchResults().entrySet()) {
			Address addr = e.getKey();
			Function f = fm.getFunctionContaining(addr);
			if (f == null) {
				continue; // switch site outside any known function -- not summarized
			}
			SwitchResult sr = e.getValue();
			ownModified.merge(f, sr.effectMask(), (a, b) -> a | b);
			BankState siteIn = flow.stateIn().get(addr);
			// Per SITE, not per strategy (grm-mej.2 §2d): a mechanism that reads the bank back
			// only at the handful of sites that actually do so must not blame every OTHER site's
			// unknown outcome on missing bank state. The strategy-wide predicate is the default
			// this resolves to for every strategy that does not override the overload. The real
			// site in-state is passed, narrowed to the mechanism's field-local coordinates as
			// everywhere else -- BankState.unknown() would over-report, since a mirror read
			// resolves (to unknown) whether or not the bank was known here.
			if (sr.strategy() != null && siteIn != null &&
				sr.strategy().effectDependsOnPriorState(program, listing.getInstructionAt(addr),
					toFieldLocal(siteIn, sr.lsb(), sr.effectMask()))) {
				int required = sr.effectMask() & ~(siteIn.knownMask() & sr.effectMask()) &
					~sr.effect().knownMask();
				if (required != 0) {
					ownRequires.merge(f, required, (a, b) -> a | b);
				}
			}
		}

		// --- direct call graph + exit points, one walk per function body (Ghidra's own
		// FunctionManager/references -- an unresolved indirect call flow target is simply
		// not a Function, so calledFunctions() below never includes it) ---
		List<Function> functions = new ArrayList<>();
		Map<Function, List<DirectCallSite>> callSites = new LinkedHashMap<>();
		Map<Function, List<Address>> exitAddrs = new LinkedHashMap<>();
		FunctionIterator allFuncs = fm.getFunctions(true);
		for (Function f : allFuncs) {
			functions.add(f);
			List<DirectCallSite> calls = new ArrayList<>();
			List<Address> exits = new ArrayList<>();
			for (Instruction instr : listing.getInstructions(f.getBody(), true)) {
				Address addr = instr.getMinAddress();
				if (flow.stateIn().get(addr) == null) {
					continue; // dataflow never reached this instruction (dead code)
				}
				if (instr.getFlowType().isCall()) {
					// reachableEntries, not getFlows(), so a call through a thunk or a relay
					// trampoline contributes the real callee to this graph rather than a
					// 3-byte stub that modifies nothing. Only getFunctionAt hits are taken:
					// this graph's nodes are Functions, and a mid-body entry has no Function
					// to be a node -- attributing it to its container would claim the caller
					// runs a body it entered partway into.
					for (Address flowAddr : reachableEntries(program, instr)) {
						Function callee = fm.getFunctionAt(flowAddr);
						if (callee == null || callee.isThunk()) {
							continue; // keep hopping: a thunk modifies nothing itself
						}
						calls.add(new DirectCallSite(addr, callee));
						break; // a direct call resolves to exactly one target
					}
				}
				else if (instr.getFlowType().isTerminal()) {
					exits.add(addr);
				}
			}
			callSites.put(f, calls);
			exitAddrs.put(f, exits);
		}

		// --- bottom-up propagation by chaotic iteration: modifiedMask/requiresOnEntry are
		// monotone non-decreasing set unions over a finite universe (the board's state
		// bits), so repeatedly relaxing every function against its direct callees
		// converges regardless of call-graph shape -- recursive/mutually-recursive SCCs
		// included, without singling them out for special handling ---
		Map<Function, Integer> modifiedMask = new LinkedHashMap<>();
		Map<Function, Integer> requiresOnEntry = new LinkedHashMap<>();
		for (Function f : functions) {
			modifiedMask.put(f, ownModified.getOrDefault(f, 0));
			requiresOnEntry.put(f, ownRequires.getOrDefault(f, 0));
		}
		boolean changed = true;
		while (changed) {
			changed = false;
			for (Function f : functions) {
				int mMask = modifiedMask.get(f);
				int rMask = requiresOnEntry.get(f);
				for (DirectCallSite cs : callSites.get(f)) {
					mMask |= modifiedMask.getOrDefault(cs.callee(), 0);
					BankState callerIn = flow.stateIn().get(cs.addr());
					if (callerIn != null) {
						rMask |= requiresOnEntry.getOrDefault(cs.callee(), 0) & ~callerIn.knownMask();
					}
				}
				if (mMask != modifiedMask.get(f) || rMask != requiresOnEntry.get(f)) {
					modifiedMask.put(f, mMask);
					requiresOnEntry.put(f, rMask);
					changed = true;
				}
			}
		}

		// --- exitState + one DEBUG-ish log line per function with a non-trivial summary
		// (M3 scope: log only, no persistence/UI) ---
		for (Function f : functions) {
			int mMask = modifiedMask.get(f);
			int rMask = requiresOnEntry.get(f);
			if (mMask == 0 && rMask == 0) {
				continue;
			}
			BankState exitState = null;
			for (Address addr : exitAddrs.get(f)) {
				BankState s = flow.stateIn().get(addr);
				if (s == null) {
					continue;
				}
				exitState = exitState == null ? s : BankState.merge(exitState, s);
			}
			if (exitState == null) {
				exitState = BankState.unknown();
			}
			AnalyzerLog.debug(analyzer, "[bank-summary] " + f.getName() + ": modifies " +
				describeBits(board, mMask) + "; requires on entry " + describeBits(board, rMask) +
				"; exit " + exitState);
		}

		// --- violation scan: a direct call site whose caller in-state is missing bits the
		// callee's requiresOnEntry needs. Dedupe policy: skip a site this run's own
		// switch/call-switch warning loop already bookmarked (alreadyWarned) -- that
		// existing WARNING already flags the site as bank-state-unsound; stacking a second
		// bookmark there would be redundant, not additional signal. A callee recognized as
		// a helper (findHelpers) is NOT unconditionally skipped: the existing helper-call
		// annotation only warns when the call's OWN argument recovery came up empty, which
		// is silent exactly in the case this feature targets (a data-only helper whose
		// caller never established the dispatch field the helper's mechanism consumes) --
		// see the module's bead report for the concrete MMC3 select+data investigation. ---
		int violations = 0;
		for (Function f : functions) {
			for (DirectCallSite cs : callSites.get(f)) {
				int required = requiresOnEntry.getOrDefault(cs.callee(), 0);
				if (required == 0 || alreadyWarned.contains(cs.addr())) {
					continue;
				}
				BankState callerIn = flow.stateIn().get(cs.addr());
				if (callerIn == null) {
					continue;
				}
				int missing = required & ~callerIn.knownMask();
				if (missing == 0) {
					continue;
				}
				program.getBookmarkManager().setBookmark(cs.addr(), BookmarkType.WARNING,
					analyzer.getBookmarkCategory(), "Bank state requirement violated: call to " +
						cs.callee().getName() + " requires " + describeBits(board, missing) +
						" known on entry, but it is unknown here");
				violations++;
			}
		}
		return violations;
	}

	/** One direct call site inside a function's body: {@code addr} is the call
	 *  instruction, {@code callee} the {@link Function} its flow resolves to. */
	private record DirectCallSite(Address addr, Function callee) {}

	/**
	 * A function's Phase-3 bank-state transfer summary (grm-6a7.2). {@code exitState} is
	 * the agree-bit merge of the tracked IN-state at every RTS/RTI in the function's body
	 * (its OUT-state too -- see {@link #annotateBankRequirementViolations}'s javadoc), or
	 * {@link BankState#unknown()} when the function has no tracked exit instruction at all
	 * (e.g. an infinite-loop routine). {@code modifiedMask} is which board state bits any
	 * execution of this function (or anything it directly calls, transitively) may change.
	 * {@code requiresOnEntry} is which board state bits must be KNOWN on entry for this
	 * function's own switch dispatch and its (transitive, direct-call-only) callees' to be
	 * sound -- known-ness only, not a required value (M3 scope). Currently computed
	 * in-line by {@link #annotateBankRequirementViolations} rather than materialized as a
	 * standalone map; this record documents the exact data model that computation
	 * populates per function, for anything that wants to consume it wholesale later
	 * (e.g. M4's UI/persistence).
	 */
	private record FunctionBankSummary(BankState exitState, int modifiedMask, int requiresOnEntry) {}

	/** Human-readable rendering of a board state bitmask, by {@code banking.state} field
	 *  name (deduplicated -- a multi-bit field's several tracked bits collapse to its one
	 *  name), matching the field-name vocabulary {@link #annotateBankSwitch} already uses.
	 *  {@code "(none)"} for an empty mask; a raw hex fallback for bits outside every known
	 *  field (should not occur for a mask derived from {@code board.mask()}). */
	private static String describeBits(BoardModel board, int bitMask) {
		if (bitMask == 0) {
			return "(none)";
		}
		List<String> names = new ArrayList<>();
		for (FieldSpec f : board.fieldSpecs()) {
			if ((f.positionedMask() & bitMask) != 0 && !names.contains(f.name())) {
				names.add(f.name());
			}
		}
		if (names.isEmpty()) {
			return "0x" + Integer.toHexString(bitMask);
		}
		return String.join(",", names);
	}

	// ------------------------------------------------------------------
	// Reference retargeting
	// ------------------------------------------------------------------

	static int retargetReferences(BoardBankAnalyzer analyzer, Program program,
			ReferenceManager refMgr, AddressSpace baseSpace, Instruction instr, BoardModel board,
			BankState inState, Map<String, Integer> placementOverride, TaskMonitor monitor,
			MessageLog log) {

		int effective = inState.effective(board.initialState(), board.mask());
		Map<String, String> stateRow = board.occupantByWindowForState().get(effective);

		int added = 0;
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (!to.getAddressSpace().equals(baseSpace)) {
				continue;
			}
			long offset = to.getOffset();
			RefType refType = ref.getReferenceType();
			int opIndex = ref.getOperandIndex();

			WindowModel window = findWindow(board.windows(), offset);
			if (window != null && stateRow != null) {
				String occupantName = stateRow.get(window.name());
				OccupantModel occupant =
					occupantName == null ? null : window.occupants().get(occupantName);
				if (occupant == null) {
					continue;
				}
				// The home occupant already lives in base space at this offset, so any target
				// that resolves to it needs no overlay reference.
				String homeOccupant = board.homeOccupantByWindow().get(window.name());
				String readTarget = occupantName;
				String writeTarget =
					occupant.onWrite() != null ? occupant.onWrite() : occupantName;

				if (refType.isRead() && refType.isWrite() && !readTarget.equals(writeTarget)) {
					// A read-modify-write (e.g. INC $D000) across a write-under-ROM boundary
					// reads one occupant and writes another; emit both sides rather than
					// dropping the read. Keep the write primary (the pre-fix behavior) and add
					// the read as a secondary reference.
					boolean primaryTaken = false;
					if (!writeTarget.equals(homeOccupant)) {
						int n = addOverlayRef(analyzer, program, refMgr, instr, offset, opIndex,
							writeTarget, RefType.WRITE, true, monitor, log);
						added += n;
						primaryTaken = n > 0;
					}
					if (!readTarget.equals(homeOccupant)) {
						added += addOverlayRef(analyzer, program, refMgr, instr, offset, opIndex,
							readTarget, RefType.READ, !primaryTaken, monitor, log);
					}
				}
				else {
					String target = refType.isWrite() ? writeTarget : readTarget;
					if (!target.equals(homeOccupant)) {
						added += addOverlayRef(analyzer, program, refMgr, instr, offset, opIndex,
							target, refType, true, monitor, log);
					}
				}
			}
			else {
				ComputedWindowModel computed = findWindow(board.computedWindows(), offset);
				if (computed != null) {
					if (refType.isWrite() && "mechanism".equals(computed.onWrite())) {
						// a store here is a mapper-latch poke, not a memory write; the
						// strategy already models it -- nothing to retarget.
						continue;
					}
					FieldSpec field = computed.field();
					int bankValue = field.valueIn(effective);
					if (bankValue == field.valueIn(board.initialState())) {
						// the home bank lives in base space at this offset -- default is right.
						continue;
					}
					added += addOverlayRef(analyzer, program, refMgr, instr, offset, opIndex,
						DescriptorSupport.OverlayNaming.bankBlockName(computed.name(), bankValue),
						refType, true, monitor, log);
				}
				else if (board.modeField() != null) {
					// memory.layouts[] mode-varying window: two-level lookup -- which layout
					// (mode) is active, then which instance of this window that layout defines
					// covers the offset.
					int modeValue = board.modeField().valueIn(effective);
					ModeWindowModel instance = findModeWindowAt(board.modeWindows(), modeValue, offset);
					if (instance == null) {
						// offset not covered by any instance of this window under the active mode
						continue;
					}
					if (refType.isWrite() && "mechanism".equals(instance.onWrite())) {
						continue;
					}
					if (instance.bankField() == null) {
						// fixed instance for this mode
						if (modeValue == board.homeModeValue()) {
							// home mode's fixed instance lives in base space -- default is right.
							continue;
						}
						added += addOverlayRef(analyzer, program, refMgr, instr, offset, opIndex,
							DescriptorSupport.OverlayNaming.modeBlockName(instance.name(), modeValue),
							refType, true, monitor, log);
					}
					else {
						int bank = instance.bankField().valueIn(effective);
						// When dataflow did not pin the switchable bank at this site, the value
						// above is just the initial-state fallback; a user placement override for
						// this window instance takes over (flow always wins when it knows). See
						// grm-hsv.3 -- the override is the residual escape hatch, never a guess.
						// Knowledge is all-or-nothing per field -- see FieldSpec.fullyKnownIn; a
						// partially known multi-bit bank select must NOT suppress the override
						// (grm-v6o).
						boolean bankKnown = instance.bankField().fullyKnownIn(inState);
						Integer overrideBank = placementOverride.get(instance.name());
						boolean overridden = !bankKnown && overrideBank != null;
						if (overridden) {
							bank = overrideBank;
						}
						if (modeValue == board.homeModeValue() &&
							bank == instance.bankField().valueIn(board.initialState())) {
							// home mode's home bank lives in base space -- default is right.
							continue;
						}
						added += addOverlayRef(analyzer, program, refMgr, instr, offset, opIndex,
							DescriptorSupport.OverlayNaming.modeBankBlockName(instance.name(), modeValue,
								bank), refType, true, monitor, log);
						if (overridden) {
							annotatePlacementProvenance(program.getListing(), instr.getMinAddress(),
								bank);
						}
					}
				}
			}
		}
		return added;
	}

	/**
	 * Adds (or reuses) one analysis reference from {@code instr}'s operand {@code opIndex} to
	 * {@code offset} within the overlay space named {@code targetSpaceName}, typed
	 * {@code refType} and optionally marked primary. Flow references also kick disassembly
	 * (and function creation for calls) at the overlay target so a cross-bank branch resolves.
	 * Returns 1 if a reference was placed, 0 if no overlay space of that name exists.
	 */
	private static int addOverlayRef(BoardBankAnalyzer analyzer, Program program,
			ReferenceManager refMgr, Instruction instr, long offset, int opIndex,
			String targetSpaceName, RefType refType, boolean makePrimary, TaskMonitor monitor,
			MessageLog log) {
		AddressSpace overlaySpace = program.getAddressFactory().getAddressSpace(targetSpaceName);
		if (overlaySpace == null) {
			// Reaching here with a bank suffix means the state named a bank the image has no
			// slice for. That is not silent any more: the site that RECOVERED the impossible
			// value carries the WARNING bookmark (annotateOrWarn -> impossibleBank, grm-hum
			// increment 3), which is both a better place to look and a user-visible finding
			// rather than a log line. This branch stays as the belt-and-braces "retarget
			// nothing" half of that ruling, and still covers a descriptor/loader mismatch that
			// no recovered value is to blame for.
			AnalyzerLog.warn(analyzer, log, "No overlay address space named '" + targetSpaceName +
				"'; cannot retarget reference from " + instr.getMinAddress());
			return 0;
		}
		Address overlayAddr = overlaySpace.getAddress(offset);

		Reference existingAnalysisRef = null;
		for (Reference r : refMgr.getReferencesFrom(instr.getMinAddress(), opIndex)) {
			if (r.getToAddress().equals(overlayAddr)) {
				existingAnalysisRef = r;
				break;
			}
		}
		Reference newRef = existingAnalysisRef != null ? existingAnalysisRef
				: refMgr.addMemoryReference(instr.getMinAddress(), overlayAddr, refType,
					SourceType.ANALYSIS, opIndex);
		// grm-mej.4: setPrimary would bump whatever reference currently holds primacy on this
		// operand. If that is a USER_DEFINED reference -- the user pinned a different target by
		// hand -- an analysis-derived overlay ref must not displace it.
		if (makePrimary &&
			AnnotationGuard.mayDisplace(refMgr.getPrimaryReferenceFrom(instr.getMinAddress(), opIndex))) {
			refMgr.setPrimary(newRef, true);
		}

		// Adding a reference does not by itself pull the target into analysis: a cross-bank
		// JSR/JMP target in an overlay would stay undisassembled bytes. Kick disassembly (and
		// function creation for calls) there; the framework then re-runs this analyzer over the
		// new instructions until convergence (their in-overlay bank state comes from the
		// residence clamp).
		if (refType.isFlow() &&
			program.getListing().getInstructionAt(overlayAddr) == null) {
			// getInstructionAt matches only instruction START addresses, so it is null at an
			// address INTERIOR to an existing instruction as well as at undisassembled bytes.
			// Those two cases need different handling: CodeManager.checkInstructionSet
			// truncates a block before the conflicting unit and throws nothing, so a
			// DisassembleCommand aimed at an offcut address FAILS SILENTLY -- it returns fewer
			// addresses and leaves only an ERROR bookmark behind. Say so instead (grm-pfp);
			// ghidra_scripts/FixSkipInstructions.java is what repairs the 6502 skip idiom that
			// produces this, and it must be a deliberate act, not a side effect of retargeting.
			Instruction occupant = program.getListing().getInstructionContaining(overlayAddr);
			if (occupant != null) {
				AnalyzerLog.warn(analyzer, log, "Reference from " + instr.getMinAddress() + " targets " +
					overlayAddr + ", which is interior to the instruction at " +
					occupant.getMinAddress() + "; not disassembling (run FixSkipInstructions.java " +
					"if this is a skip-idiom entry point)");
				return 1;
			}
			new DisassembleCommand(overlayAddr, null, true).applyTo(program, monitor);
			if (refType.isCall() &&
				program.getListing().getInstructionAt(overlayAddr) != null &&
				program.getFunctionManager().getFunctionAt(overlayAddr) == null) {
				new CreateFunctionCmd(overlayAddr).applyTo(program, monitor);
			}
		}
		return 1;
	}

	/** The window (enumerated or computed) whose {@code [start, end]} contains {@code offset}, or null. */
	private static <T extends Bounded> T findWindow(Map<String, T> windowsByName, long offset) {
		for (T w : windowsByName.values()) {
			if (offset >= w.start() && offset <= w.end()) {
				return w;
			}
		}
		return null;
	}

	/** The mode-varying window instance active under {@code modeValue} whose {@code [start,
	 *  end]} contains {@code offset}, or null (offset not covered by this window under this
	 *  mode -- e.g. a mode that doesn't define a window at all at this location). */
	private static ModeWindowModel findModeWindowAt(List<ModeWindowModel> modeWindows,
			int modeValue, long offset) {
		for (ModeWindowModel w : modeWindows) {
			if (w.modeValue() == modeValue && offset >= w.start() && offset <= w.end()) {
				return w;
			}
		}
		return null;
	}

	/** The mode-varying window instance named {@code name} under {@code modeValue}, or null. */
	static ModeWindowModel findModeWindowInstance(List<ModeWindowModel> modeWindows,
			String name, int modeValue) {
		for (ModeWindowModel w : modeWindows) {
			if (w.name().equals(name) && w.modeValue() == modeValue) {
				return w;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Context stamping (dormant until a language declares the register)
	// ------------------------------------------------------------------

	/**
	 * Stamps fully-known bank states into the descriptor's
	 * {@code banking.context_register} over instruction ranges -- the L4 state channel
	 * the RFC's resolution hook consumes. Programs whose language does not declare the
	 * register (today: everything -- the bundled 6510 stays system-neutral and declares no
	 * bank-state register, only the on-die port) skip this silently; the value+mask model
	 * of {@link BankState} maps 1:1 onto {@code RegisterValue} when partial stamping
	 * becomes worthwhile.
	 */
	static void stampContextRegister(BoardBankAnalyzer analyzer, Program program,
			JsonObject banking, Map<Address, BankState> stateIn, Listing listing, int mask,
			MessageLog log) {
		if (!banking.has("context_register")) {
			return;
		}
		Register register = program.getRegister(banking.get("context_register").getAsString());
		if (register == null) {
			AnalyzerLog.warn(analyzer, log, "context_register '" +
				banking.get("context_register").getAsString() +
				"' is not a register declared by this language; context stamping skipped");
			return;
		}
		int stamped = 0;
		for (Map.Entry<Address, BankState> entry : stateIn.entrySet()) {
			BankState state = entry.getValue();
			if (state.knownMask() != mask) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(entry.getKey());
			if (instr == null) {
				continue;
			}
			try {
				program.getProgramContext().setValue(register, instr.getMinAddress(),
					instr.getMaxAddress(), BigInteger.valueOf(state.bits()));
				stamped++;
			}
			catch (Exception e) {
				AnalyzerLog.warn(analyzer, log,
					"context stamp failed at " + entry.getKey() + ": " + e.getMessage());
				return;
			}
		}
		if (stamped > 0) {
			AnalyzerLog.info(analyzer,
				"stamped " + register.getName() + " over " + stamped + " instructions");
		}
	}
}
