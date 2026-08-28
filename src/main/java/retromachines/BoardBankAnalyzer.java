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

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.stream.Collectors;

import com.google.gson.JsonObject;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static retromachines.BankDataflowEngine.overwrite;
import static retromachines.BankDataflowEngine.position;
import static retromachines.BankDataflowEngine.runDataflow;

import retromachines.BankDataflowEngine.CallSwitch;
import retromachines.BankDataflowEngine.DataflowResult;
import retromachines.BankDataflowEngine.SwitchResult;
import retromachines.BankStrategyRegistry.ConfiguredMechanism;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.ComputedWindowModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.ModeWindowModel;

/**
 * The machine-independent board-level bank analyzer engine (vision doc §6, L2).
 * <p>
 * Everything per-board comes from a compiled schema-v2 descriptor: the bank-state field
 * tuple ({@code banking.state}), the switch mechanisms ({@code banking.mechanisms} --
 * each matched to a {@link BankSwitchStrategy} implementation by name and configured
 * with its params), the window model (enumerated occupant truth table, C64-style, or
 * computed {@code maps:} windows backed by per-bank overlays, NES-mapper-style), and
 * the initial state. The engine owns what is the same on every machine:
 * <ul>
 * <li><b>Forward dataflow to fixpoint</b> over disassembled instructions, seeded with
 * {@code banking.initial_state} at every entry point and function start, with per-bit
 * partial knowledge ({@link BankState}) and agree-bit merges at control-flow joins.
 * Instructions physically located in a bank overlay ({@code WINDOW_B<n>}) have that
 * window's field clamped to {@code n} -- code cannot execute from a bank that is not
 * mapped in.</li>
 * <li><b>Switch recognition and value recovery</b> delegated to the configured
 * strategies (first strategy that recognizes an instruction wins).</li>
 * <li><b>Helper-call propagation</b>: real code often switches banks through a helper
 * ({@code LDA #bank / JSR SelectBank}, where the helper does the store -- possibly via
 * an indexed bus-conflict table the local scan cannot resolve). After a first dataflow
 * pass, every function containing a recognized mechanism write becomes a <em>switch
 * helper</em>; a second pass treats each call to one as a switch site whose value is
 * the helper's own constant result when it has one, else the immediate register
 * argument recovered at the call site (bank-in-A/X/Y convention), else unknown.</li>
 * <li><b>Annotation</b>: EOL comments at resolved switch sites (with per-bit known/
 * assumed provenance when knowledge is partial; call-site switches name the helper),
 * WARNING bookmarks when a switch leaves no tracked bit known.</li>
 * <li><b>Application</b> (interim overlay generation): for references landing in a
 * banked window, an ANALYSIS reference into the effective occupant's overlay space
 * (enumerated windows -- including the {@code on_write} occupant for writes, e.g.
 * write-under-ROM) or the effective bank's overlay block (computed windows; writes are
 * latch pokes when the window declares {@code on_write: mechanism} and are left
 * alone), marked primary. Unknown bits assume their initial-state value.</li>
 * <li><b>Context stamping</b>: when the program's language actually declares the
 * descriptor's {@code banking.context_register}, fully-known states are stamped over
 * instruction ranges via {@code ProgramContext.setValue}. No shipped language declares a
 * bank-state register -- the bundled 6510 (grm-bk6) models the on-die port but stays
 * system-neutral about banking -- so this stays dormant until an application-layer state
 * register exists (a per-system pspec alias or the RFC #9349 resolution hook).</li>
 * </ul>
 * Concrete subclasses (e.g. {@link C64BankingAnalyzer}) supply only the loader gate,
 * the descriptor path, and the analyzer's name -- no analysis logic.
 */
public abstract class BoardBankAnalyzer extends AbstractAnalyzer {

	/**
	 * Modification stamp of the last <em>completed</em> {@link #added} run per program
	 * (grm-5tl.13.3, hardened by grm-w3m). Phase 2's overlay retargeting disassembles
	 * cross-bank targets, and the framework answers each batch of new code by
	 * re-invoking {@code added()}, which re-seeds the whole-program fixpoint from
	 * scratch -- deliberately so, because that reseed is how bank state reaches the
	 * newly discovered code (its callers are outside the delta set, so processing only
	 * {@code set} would silently under-annotate). The consequence is up to O(rounds x
	 * whole-program) work; this cache skips a re-run <em>only</em> when it is provably
	 * redundant: nothing about the program has changed since the last run completed.
	 * All-or-nothing -- phase-1 output is never cached or diff-merged across runs
	 * (annotateBankSwitch never overwrites an existing bank comment, so a stale partial
	 * merge would compound).
	 * <p>
	 * The invariant: the stored value is {@link Program#getModificationNumber()} read at
	 * run <em>exit</em>, after this run's own writes (comments, bookmarks, overlay
	 * references, symbols) have already bumped it. A later invocation skips only when
	 * the program's modification number still equals that exit-time value -- i.e.
	 * nothing, including our own prior writes, has touched the program since. Reading
	 * the number at <em>entry</em> instead (as a structural fingerprint legitimately can,
	 * see {@link #reachedFixpoint}) would be wrong here: this analyzer's own writes bump
	 * the modification number during the run, so an entry-captured value would never
	 * match the number observed on the very next invocation and the cache would never
	 * hit. {@code getModificationNumber()} is incremented synchronously by
	 * {@code DomainObjectAdapter.fireEvent} on every change record fired -- including
	 * comment/bookmark/reference/symbol edits made mid-transaction, not only at commit --
	 * so an exit-time read already reflects this run's own mutations.
	 * <ul>
	 * <li>The descriptor is identified by {@code mapPath} (stored alongside the
	 * modification number); a program re-pointed at a different board map re-runs even
	 * with an unchanged modification number. Edits to the map <em>file's content</em>
	 * under an unchanged path are not detected -- acceptable for compiled resources
	 * bundled with the extension.</li>
	 * <li>A run that throws (e.g. {@link CancelledException}) stores nothing and will
	 * re-run in full: the {@code put} below only happens after a structurally stable
	 * completion, and an exception unwinds past it.</li>
	 * </ul>
	 * Keyed weakly by {@link Program} identity so closed programs drop out; synchronized
	 * because distinct programs may be analyzed on distinct threads.
	 */
	private static final Map<Program, RunStamp> LAST_COMPLETED =
		Collections.synchronizedMap(new WeakHashMap<>());

	/**
	 * What {@link #LAST_COMPLETED} remembers: the exit-time
	 * {@link Program#getModificationNumber()} + descriptor path.
	 */
	private record RunStamp(long modificationNumber, String mapPath) {}

	/** Function and instruction counts packed into disjoint bit ranges (not a hash). */
	private static long fingerprint(Program program) {
		return ((long) program.getFunctionManager().getFunctionCount() << 40) ^
			program.getListing().getNumInstructions();
	}

	/** Structural completion predicate, protected so the banktest lifecycle probe can
	 * verify that changing rounds stay initial while stable rounds complete. */
	protected static boolean reachedFixpoint(long entryFingerprint, long exitFingerprint) {
		return entryFingerprint == exitFingerprint;
	}

	protected BoardBankAnalyzer(String name, String description) {
		super(name, description, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after Ghidra's own reference analysis has laid down the default (base-space)
		// operand/flow references we need to inspect and, where wrong, supersede.
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	/**
	 * The executable-format name of the loader whose "home-in-base" per-bank overlay
	 * layout the engine's reference retargeting assumes (e.g. {@link C64PrgLoader#NAME}).
	 * Only programs imported by that loader are analyzed.
	 */
	protected abstract String getLoaderName();

	@Override
	public boolean canAnalyze(Program program) {
		// Gate on the loader that produced this program: only its imports lay out memory
		// "home-in-base" with per-bank overlays the way the engine's retargeting assumes.
		// AbstractProgramLoader stamps the executable-format property with the Loader's name.
		String format = program.getExecutableFormat();
		return format != null && format.equals(getLoaderName());
	}

	/**
	 * Resource path of this program's compiled descriptor, e.g. {@code machines/c64.map}
	 * (a per-board constant on single-board systems; read from the program on systems
	 * where the loader chose among boards). {@code null} skips analysis.
	 */
	protected abstract String getMapPath(Program program);

	/** Category used for this analyzer's bookmarks; defaults to the concrete class name. */
	protected String getBookmarkCategory() {
		return getClass().getSimpleName();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		String tag = getClass().getSimpleName();
		String mapPath = getMapPath(program);
		if (mapPath == null) {
			return false;
		}

		// Redundant-re-run gate (grm-5tl.13.3, grm-w3m): see LAST_COMPLETED for the
		// invariants. fingerprint(program) below is the SEPARATE structural
		// entry/exit fixpoint test (unchanged; see reachedFixpoint) that decides
		// whether THIS round is structurally stable -- not the redundant-rerun gate.
		long entryFingerprint = fingerprint(program);
		RunStamp last = LAST_COMPLETED.get(program);
		if (last != null && last.modificationNumber() == program.getModificationNumber() &&
			last.mapPath().equals(mapPath)) {
			// THIS BRANCH MUST NOT WRITE ANYTHING TO THE PROGRAM (grm-6jfp). The gate above
			// compares the stored exit-time stamp against program.getModificationNumber(),
			// so any mutation on the skip path -- including an Options write, which fires a
			// change event and advances the number even when it sets true -> true -- would
			// make the gate miss on the very next invocation (the stored stamp can never
			// catch up to a number this branch keeps bumping), degrading the cache to
			// "hit, miss, hit, miss, ...". That hazard used to be live: this branch called
			// AnalyzerRunLog.markCompleted() and leaned on the initial-run `verbose` flag to
			// keep the write to its one real transition. Both are gone; logging now goes to
			// Msg, which touches no program state, so the skip path is write-free by
			// construction and needs no guard.
			AnalyzerLog.info(this, tag + ": no program changes since last " +
				"completed run; skipping redundant whole-program re-analysis");
			return true;
		}
		AnalyzerLog.info(this, tag + " running (" + mapPath + ")");

		JsonObject map;
		try {
			map = DescriptorResources.loadMap(mapPath);
		}
		catch (IOException e) {
			AnalyzerLog.warn(this, log, "Failed to load " + mapPath + ": " + e.getMessage());
			return false;
		}

		BoardModel board = BoardModel.parse(map, log, getName(), mapPath);
		if (board == null) {
			return true;
		}

		Map<String, Integer> placementOverride =
			BankAnnotationAdapter.readPlacementOverride(this, program, log);

		JsonObject banking = map.getAsJsonObject("banking");
		List<ConfiguredMechanism> mechanisms = BankStrategyRegistry.configureStrategies(this,
			program, banking.getAsJsonArray("mechanisms"), board, log);
		if (mechanisms.isEmpty()) {
			AnalyzerLog.warn(this, log, "no usable bank-switch strategy in " + mapPath +
				" banking; skipping bank-state analysis");
			return true;
		}

		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

		// --- Phase 1: forward dataflow to fixpoint; rerun with helper knowledge if any ---
		Listing listing = program.getListing();
		DataflowResult flow =
			runDataflow(program, monitor, listing, mechanisms, board, null, Set.of());

		// Order is load-bearing. findCallEdgeWrappers runs LAST so its relay lookups see
		// pass-through wrappers as helpers; it is also why exitEffect never encounters a relay
		// model. See findCallEdgeWrappers' javadoc for the one gap this order leaves open.
		Map<Function, HelperModel> helpers = findCallEdgeWrappers(program,
			findPassThroughWrappers(program,
				composeTailCalls(program, findHelpers(program, flow.switchResults())),
				flow.switchResults()),
			flow.switchResults());
		if (!helpers.isEmpty()) {
			AnalyzerLog.info(this, helpers.size() + " bank-switch helper function(s): " +
				helpers.keySet().stream().map(Function::getName).sorted().toList());
		}

		// Which banks each switchable window actually has an image slice for (grm-hum
		// increment 3). Derived once, here, because it is a property of the loaded program and
		// cannot change under the analysis. Hoisted above the second dataflow pass by grm-mej.2:
		// bank-mirror derivation asks the same realized-bank question, and deriving it twice
		// would let the two answers drift.
		Map<String, Set<Integer>> bankUniverse = BankAnnotationAdapter.bankUniverse(program, board);

		// --- Bank mirrors (grm-mej.2): the addresses that mirror the LIVE bank, derived from
		// pass 1's recognized switch sites plus the loaded bank images, and handed to every
		// configured strategy BEFORE the second pass so a strategy that consumes them sees them
		// at every site rather than at the ones pass 2 happens to revisit. ---
		BankMirrors mirrors =
			BankAnnotationAdapter.deriveBankMirrors(program, board, bankUniverse, flow, helpers);
		for (ConfiguredMechanism cm : mechanisms) {
			cm.strategy().observeMirrors(mirrors);
		}
		if (!mirrors.isEmpty()) {
			AnalyzerLog.info(this, "bank mirrors: " + mirrors);
		}

		// --- Save/restore trampolines (grm-mej.3): helpers whose NET effect on the tracked field
		// is nothing, because they put the entry bank back before returning. Derived once, here,
		// because it is a property of each helper's body and of the mirror set -- never inside the
		// fixpoint, where it would be a whole-body walk per dequeue per call site. It has to come
		// after deriveBankMirrors: the proof that the saved byte IS the entry bank is that it was
		// loaded from a live-bank mirror. ---
		Set<Function> restoringTrampolines = new LinkedHashSet<>();
		for (HelperModel h : helpers.values()) {
			if (restoresEntryBank(program, h, mirrors, flow.switchResults().keySet())) {
				restoringTrampolines.add(h.function());
			}
		}
		if (!restoringTrampolines.isEmpty()) {
			AnalyzerLog.info(this, "save/restore trampolines (calls are verified no-ops): " +
				restoringTrampolines.stream().map(Function::getName).sorted().toList());
		}

		// The second pass is what lets the analysis see anything pass 1 structurally could not.
		// Helpers were the original reason; mirrors are a second one, and gating on EITHER is
		// what makes a board with mirrors but no helper actually benefit. Passing an EMPTY
		// helper map is deliberately equivalent to pass 1's null (runDataflow's helper branch is
		// a lookup that misses), so a mirrors-only rerun changes nothing on its own.
		if (!helpers.isEmpty() || !mirrors.isEmpty()) {
			flow = runDataflow(program, monitor, listing, mechanisms, board, helpers,
				restoringTrampolines);
		}

		// --- Bank mirror naming (grm-mej.4): turn the derived mirror set into symbols and
		// comments, so the documentary payoff of grm-mej.2's derivation is visible in the
		// listing rather than only in the strategies that consume it. After pass 2 (mirrors
		// are already final by then) and before Phase 2, which is unrelated annotation work
		// over the same listing. ---
		BankAnnotationAdapter.nameBankMirrors(program, listing, mirrors, baseSpace);

		// --- Phase 2: annotate bank switches + retarget references ---
		ReferenceManager refMgr = program.getReferenceManager();
		int refsAdded = 0;
		int warnings = 0;
		// Addresses that already carry a WARNING bookmark from this loop -- Phase 3's
		// violation scan below dedupes against this set rather than stacking a second
		// bookmark on a site the existing switch/call-switch warning already covers.
		Set<Address> alreadyWarned = new LinkedHashSet<>();
		for (Map.Entry<Address, BankState> entry : flow.stateIn().entrySet()) {
			monitor.checkCancelled();
			Address addr = entry.getKey();
			BankState inState = entry.getValue();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}

			SwitchResult switchResult = flow.switchResults().get(addr);
			if (switchResult != null) {
				int w = BankAnnotationAdapter.annotateOrWarn(this, program, listing, addr,
					switchResult.effect(), board, bankUniverse, null,
					"Bank state becomes unknown here: mechanism write with a genuinely " +
						"undeterminable value (value recovery could not pin down even one " +
						"tracked bank bit -- e.g. a load of an unrelated address followed " +
						"directly by the store, with no AND/ORA immediate to constrain it)");
				warnings += w;
				if (w > 0) {
					alreadyWarned.add(addr);
				}
			}

			CallSwitch callSwitch = flow.callSwitches().get(addr);
			if (callSwitch != null) {
				// Warn iff the call's OWN recovery came up empty (same rule a direct switch's
				// pure effect gets); when it resolved, render the comment from the folded
				// post-call state so unowned fields show their real dataflow knowledge -- see
				// CallSwitch's javadoc.
				BankState annotState = callSwitch.effect().knownMask() == 0
						? callSwitch.effect() : callSwitch.stateAfter();
				int w = BankAnnotationAdapter.annotateOrWarn(this, program, listing, addr, annotState,
					board, bankUniverse, callSwitch.helperName(),
					"Bank state becomes unknown here: call to bank-switch helper " +
						callSwitch.helperName() + " whose bank argument could not be " +
						"recovered at this call site");
				warnings += w;
				if (w > 0) {
					alreadyWarned.add(addr);
				}
			}

			refsAdded += BankAnnotationAdapter.retargetReferences(this, program, refMgr, baseSpace,
				instr, board, inState, placementOverride, monitor, log);
		}

		// --- Phase 3: function-level bank-state summaries + call-site requirement
		// violations (bead grm-6a7.2, design D, M3 scope: read-only annotation layer,
		// derived AFTER the Phase-1/2 fixpoint above -- see the method's javadoc for what
		// is and is not fed back into the dataflow) ---
		int violations = BankAnnotationAdapter.annotateBankRequirementViolations(this, program,
			listing, flow, board, alreadyWarned, log);

		// --- Context stamping: only when the language actually declares the register ---
		BankAnnotationAdapter.stampContextRegister(this, program, banking, flow.stateIn(), listing,
			board.mask(), log);

		// A phase-2 retarget may have disassembled code or created functions. Such a
		// round returned successfully, but it is deliberately not the completed initial
		// analysis: the framework must invoke us again so the whole-program fixpoint can
		// reach that newly discovered code. Defer the definitive summary until an
		// invocation leaves the structural fingerprint stable.
		boolean stable = reachedFixpoint(entryFingerprint, fingerprint(program));
		if (stable) {
			AnalyzerLog.info(this, tag + ": " + flow.stateIn().size() + " instructions tracked, " +
				refsAdded + " overlay references added/confirmed, " + warnings +
				" unknown-state warnings, " + violations + " bank-state requirement violations");
		}

		// A structurally changing round is deliberately not complete and must not populate
		// the completed-run cache. The framework follow-on therefore runs in full; only a
		// stable round's EXIT-time modification number can become the redundant-rerun
		// baseline (see LAST_COMPLETED's javadoc for why entry-time would never hit).
		// This is also why cancellation can never record a completed stamp: a
		// CancelledException thrown by monitor.checkCancelled() anywhere above (phase 1/2
		// dataflow, phase 3 violation scan, context stamping) propagates straight out of
		// added() and unwinds past this point, so `stable` is never reached and the put()
		// below never executes on a cancelled run.
		if (stable) {
			manageNoMechanismWriteDiagnostic(program, mechanisms, flow, log);
			// The snapshot below has to be the LAST of this run's own writes: anything
			// written after it leaves the stored stamp instantly stale, so the skip gate at
			// the top of added() misses on the very next invocation. That used to be a live
			// hazard here -- this block also called AnalyzerRunLog.markCompleted(), an
			// Options write that advances program.getModificationNumber() even when it sets
			// true -> true, so it had to be both ordered before this put() AND gated (on the
			// initial-run `verbose` flag) to stop it bumping the number on every later
			// completed run. grm-6jfp deleted the initial-run policy and that write with it,
			// so the only writes a run performs now are its actual analysis edits and the
			// ordering requirement is trivially met.
			LAST_COMPLETED.put(program, new RunStamp(program.getModificationNumber(), mapPath));
		}
		return true;
	}

	/**
	 * Category for the "declared a mechanism but observed no write" diagnostic bookmark.
	 * Deliberately distinct from {@link #getBookmarkCategory()} so the single
	 * program-level diagnostic can be set/retracted unambiguously; it is still a
	 * {@link BookmarkType#WARNING} so tooling that counts warnings by type sees it.
	 */
	private static final String NO_WRITE_CATEGORY = "no bank-switch write observed";

	/**
	 * On a settled (fixpoint-stable) run, reconcile the "board declares a bank-switch
	 * mechanism but no mechanism write was observed anywhere" diagnostic. The concern
	 * (grm-9oz) is silence: some real ROMs (Contra/UxROM, Dragon Ball 3/Bandai FCG) load
	 * with the correct overlay layout yet the forward dataflow never classifies any store
	 * as a mechanism write -- so no bank comments, no cross-bank refs, and, before this,
	 * no warning either.
	 *
	 * <p>The zero can be transient: the analyzer re-runs to a whole-program fixpoint and is
	 * re-triggered whenever another analyzer later disassembles the switch routine. So this
	 * only fires on the settled run, and it <em>retracts</em> itself if a later settled run
	 * does observe a write -- i.e. the diagnostic reflects the settled state, not any
	 * intermediate round. The bookmark is anchored at the image base (a stable,
	 * non-switch-site address) so set and retract target the same one.
	 */
	private void manageNoMechanismWriteDiagnostic(Program program,
			List<ConfiguredMechanism> mechanisms, DataflowResult flow, MessageLog log) {
		BookmarkManager bm = program.getBookmarkManager();
		Address at = program.getImageBase();
		boolean observedWrite =
			!flow.switchResults().isEmpty() || !flow.callSwitches().isEmpty();
		if (observedWrite) {
			Bookmark stale = bm.getBookmark(at, BookmarkType.WARNING, NO_WRITE_CATEGORY);
			if (stale != null) {
				bm.removeBookmark(stale);
			}
			return;
		}
		String strategies = mechanisms.stream()
				.map(m -> m.strategy().strategyName())
				.distinct()
				.collect(Collectors.joining(", "));
		String msg = "Board declares " + mechanisms.size() + " bank-switch mechanism(s) [" +
			strategies + "] but no mechanism write was observed in analyzed code; no bank " +
			"annotations were produced. The switch routine may be unreached (e.g. entered " +
			"only via an indirect/table jump auto-analysis did not disassemble).";
		bm.setBookmark(at, BookmarkType.WARNING, NO_WRITE_CATEGORY, msg);
		// info, NOT warn, even though this is a real finding -- the WARNING BOOKMARK set
		// immediately above is the durable record, and it carries this same text. Routing the
		// echo through the MessageLog too would pop the analysis dialog on every settled run
		// of any program that trips this, which is exactly the annoyance grm-olp was filed
		// about; grm-olp gated this line for that reason and grm-6jfp keeps the decision.
		// Not hypothetical: db3 trips it (tools/banktest/realrom/expected/db3.dump:27).
		// THE RULE: when a site already sets a WARNING bookmark carrying the same message,
		// the log echo is info. Reserve warn for findings with no other durable record.
		AnalyzerLog.info(this, getClass().getSimpleName() + ": " + msg);
	}

	// ------------------------------------------------------------------
	// Helper-call propagation
	// ------------------------------------------------------------------

	/**
	 * Every function containing a recognized mechanism write is a bank-switch helper. This
	 * deliberately misses a real shape: a pass-through wrapper that writes no mechanism of
	 * its own and simply falls through into the function that does (Castlevania 2's
	 * {@code FUN_c183 -> FUN_c185 -> FUN_c187}, TMNT's {@code FUN_cea5 -> FUN_cea7}, Wizards
	 * & Warriors' AxROM {@code $ce89 -> $ce8b}). {@link #findPassThroughWrappers} admits
	 * those into the map afterward, by re-keying rather than by relaxing this containment
	 * rule.
	 * <p>
	 * When all of a helper's switch results are fully known and agree, calling it
	 * unconditionally produces that state; otherwise the helper's effect depends on its
	 * caller (bank-argument convention) and is recovered per call site.
	 * <p>
	 * A helper's sites all belonging to the same mechanism (the common case, and the only
	 * case on every shipped board) merge exactly as before, keyed off that mechanism's
	 * {@code effectMask}/{@code lsb}. A helper whose sites belong to <em>different</em>
	 * mechanisms (e.g. one function that can be reached with either a bank-mechanism write
	 * or a mode-mechanism write on different call paths) degrades conservatively: the
	 * const/register agreement is dropped ({@code constState = argReg = null}, forcing
	 * per-call-site {@link #recoverCallArgument} which itself returns unknown without an
	 * argument register) and {@code effectMask} becomes the union of every site's mask, so
	 * the caller-side unknown-effect fold in {@link BankDataflowEngine#runDataflow} wipes every field this
	 * helper might touch rather than under- or mis-covering it.
	 * <p>
	 * <b>Two of the rules below became load-bearing in new ways with grm-hum increment 2</b>,
	 * and neither needed a code change for it -- which is worth saying out loud, because both
	 * are now depended on by a path they were not written for:
	 * <ul>
	 * <li><b>{@code constState} disagreement -&gt; {@code null}</b> (just below) is what routes a
	 * multi-site helper into per-call recovery <em>at all</em>. Mega Man's {@code FUN_d846}
	 * switches to bank 6, then to a loop-carried unknown, then back to 6; those three disagree,
	 * so the helper has no constant effect and every call site is recovered individually. Had
	 * they agreed, the mini-inline would never run.</li>
	 * <li><b>The max-address {@code switchSite} rule</b> (see the comment on it below) now
	 * decides which site a <em>memory-latch</em> multi-site helper commits through, not just
	 * which sub-field a serial-shift chain selects: it is the site
	 * {@link BankSwitchStrategy#depositHelperArgument} mini-inlines. That picks the right site
	 * <em>inside the body</em> for {@code FUN_d846}, whose last site by address ({@code $D88D},
	 * the post-loop restore) is also the last one its body executes. <b>It is a heuristic, and
	 * address order is not execution order in general</b> -- a helper whose exit path branches
	 * backward to an earlier switch would be committed to the wrong site by it. Nothing shipped
	 * does that today; a helper that did would need real terminal-site analysis rather than a
	 * max(). And "inside the body" is a real qualifier, not a formality: {@code FUN_d846} then
	 * tail-jumps to {@code FUN_c3b3}, so the bank live at its RETURN is 5 rather than the 6
	 * {@code $D88D} deposits -- see {@link #composeTailCalls}, which is what makes the
	 * body-local answer safe to build here.</li>
	 * </ul>
	 * <p>
	 * The map this returns is post-processed by {@link #composeTailCalls} before anything sees
	 * it, because the body-local answer is not the whole answer: see that method for why a
	 * helper's effect is the state at its RETURN, not at the last write in its own body.
	 */
	private static Map<Function, HelperModel> findHelpers(Program program,
			Map<Address, SwitchResult> switchResults) {
		Map<Function, HelperModel> helpers = new LinkedHashMap<>();
		for (Map.Entry<Address, SwitchResult> entry : switchResults.entrySet()) {
			Function f = program.getFunctionManager().getFunctionContaining(entry.getKey());
			if (f == null) {
				continue;
			}
			SwitchResult site = entry.getValue();
			BankState result = site.effect();
			Instruction store = program.getListing().getInstructionAt(entry.getKey());
			Character reg = store == null ? null : StoredValueScanner.storeRegister(store);

			HelperModel existing = helpers.get(f);
			if (existing == null) {
				helpers.put(f, new HelperModel(f, f.getEntryPoint(),
					result.knownMask() == site.effectMask() ? result : null, reg,
					site.effectMask(), site.lsb(), site.strategy(), entry.getKey(),
					entry.getKey(), null));
			}
			else if (existing.effectMask() == site.effectMask() && existing.lsb() == site.lsb()) {
				BankState constState = existing.constState() != null
						&& !existing.constState().equals(result) ? null : existing.constState();
				Character argReg = Objects.equals(existing.argReg(), reg) ? reg : null;
				// When several instructions in this helper share the same mechanism (e.g. a
				// serial-shift chain's 5 stores), the switch site that decides WHICH sub-field
				// a call-site argument commits through is the one whose own address encodes
				// that decision. What we actually want is THE LAST RECOGNIZED WRITE ON THE PATH
				// TO THIS HELPER'S RETURN; the highest-address one is a PROXY for that, and the
				// proxy is only valid while control cannot leave the function body -- see
				// HelperModel.switchSite's javadoc and composeTailCalls, which repairs the one
				// way control routinely does leave it (a tail call). Within the body the proxy
				// holds for every idiom this engine recognizes: the last write in program order
				// is an unrolled chain's write-5 STA, or a counted loop's closing BNE, both of
				// which sit after their chain's earlier writes. Keeping the max-address entry is
				// a no-op for every single-instruction mechanism (register-write, memory-latch:
				// exactly one site per helper) and picks the correct commit site for
				// serial-shift.
				Address switchSite = entry.getKey().compareTo(existing.switchSite()) > 0
						? entry.getKey() : existing.switchSite();
				// The mirror of the max above, and NOT a proxy for anything: the lowest-addressed
				// site is exactly what midBodyEntryHelper needs to decide whether entering
				// somewhere other than the top still runs every site this model summarizes.
				Address firstSite = entry.getKey().compareTo(existing.firstSite()) < 0
						? entry.getKey() : existing.firstSite();
				helpers.put(f, new HelperModel(f, f.getEntryPoint(), constState, argReg,
					site.effectMask(), site.lsb(), site.strategy(), switchSite, firstSite,
					null));
			}
			else {
				// Sites in this helper belong to different mechanisms -- degrade to the
				// conservative union (see javadoc above). argReg is forced null, so
				// recoverCallArgument short-circuits before ever consulting strategy/
				// switchSite -- both left null/unset is safe. firstSite goes with them: a null
				// there makes midBodyEntryHelper decline, which is the right answer for a model
				// that no longer describes one coherent mechanism.
				helpers.put(f, new HelperModel(f, f.getEntryPoint(), null, null,
					existing.effectMask() | site.effectMask(), 0, null, null, null, null));
			}
		}
		return helpers;
	}

	/**
	 * Depth cap for {@link #composeTailCalls}' fixpoint. Real chains are one or two links
	 * (Mega Man's {@code FUN_d846 -> FUN_c3b3} is one); the cap exists so a pathological
	 * chain declines instead of running away, alongside the visited-set cycle guard in
	 * {@link #exitEffect}.
	 * <p>
	 * <b>This javadoc used to cite Mega Man's {@code FUN_f105} (which tail-jumps to ITSELF at
	 * {@code $F10F}) as what made the cycle guard non-hypothetical. That was wrong</b>, measured
	 * while writing grm-432's coverage. Ghidra's {@code SharedReturnAnalysisCmd} explicitly
	 * SKIPS a jump whose containing function's entry is the jump target ("just an internal jump
	 * reference to the top of the function"), so a self-{@code JMP} never receives
	 * {@code CALL_RETURN}, never becomes {@code CALL_TERMINATOR}, and so is never terminal --
	 * which means {@link #exitInstructions} never yields it and the cycle guard is never reached
	 * by that route at all. {@code FUN_f105} does not exercise this guard.
	 * <p>
	 * The guard is still load-bearing and still correct: a cycle of TWO OR MORE functions is
	 * presented normally, each tail {@code JMP} landing on a different function's entry, and
	 * reaches {@code !onStack.add(f)} exactly as intended. That mutual shape is what
	 * {@code nesuxhelpertest}'s {@code PingA}/{@code PingB} pair and
	 * {@code TailCallCompositionProgramTest} pin. Note the depth cap BACKSTOPS the cycle guard
	 * -- deleting the cycle check alone still terminates, by running to depth 9 and declining
	 * there -- so the two must be covered by distinguishing which branch is taken, not by
	 * deleting one and watching for a hang.
	 */
	private static final int MAX_TAIL_CALL_DEPTH = 8;

	/**
	 * Round cap for {@link #findPassThroughWrappers}'s fixpoint. This is a POLICY bound, not
	 * a termination crutch -- termination is already STRUCTURAL: each round only admits a
	 * wrapper strictly BELOW, in address order, the model it wraps ({@code
	 * isPassThroughInto} requires the wrapper's body to fall straight through into
	 * {@code model.entry()}), and the result map's keys dedupe, so nothing can be
	 * re-admitted or looped on. Castlevania 2's three-function stack
	 * ({@code FUN_c183 -> FUN_c185 -> FUN_c187}) is the deepest chain measured on any
	 * shipped board.
	 */
	private static final int MAX_WRAPPER_CHAIN = 3;

	/**
	 * Re-summarizes every helper whose control flow LEAVES ITS BODY by a tail call, so its
	 * modeled effect is the bank state at its RETURN rather than at the last recognized write
	 * inside its own body (bead grm-hum increment 2b).
	 * <p>
	 * <b>The defect this repairs shipped wrong answers.</b> {@link #findHelpers} summarizes a
	 * helper by the max-address recognized write in its own body, which is a sound proxy for
	 * "the last write before the return" only while control cannot leave that body. A tail call
	 * is exactly when it can. On Mega Man, {@code FUN_d131}'s only own site is
	 * {@code $D135 STA $C006}, so it modeled as a constant bank 6 and every call to it folded
	 * bank 6 -- but it ends {@code $D159 JMP $C3B3}, and {@code FUN_c3b3} latches bank 5, so the
	 * live bank after the call is 5. {@code FUN_d846} and {@code FUN_c55d} tail-jump to the same
	 * routine with the same consequence.
	 * <p>
	 * <b>This is a SUMMARY fix, not a dataflow fix.</b> {@link BankDataflowEngine#runDataflow} already treats a
	 * {@code CALL_TERMINATOR} jump as a call ({@code getFlowType().isCall()} is true for it --
	 * Ghidra's shared-return analysis rewrites a jump to another function's entry that way) and
	 * already folds the callee helper's effect there, so the tracked state at the end of these
	 * functions was right all along. Only {@link HelperModel} discarded it.
	 * <p>
	 * <b>The rule is NARROWED, not replaced.</b> A helper with no tail call to a recognized
	 * helper is returned completely untouched, so the max-address summary keeps deciding
	 * every case it was already right about -- a serial-shift chain's commit site, and the
	 * restore-before-RTS trampolines in {@code nesbanktest2}, whose last write really is the
	 * last one executed. A tail call to a function this engine does not model as a helper is
	 * likewise a no-op, which is exactly what {@link BankDataflowEngine#runDataflow} folds for a call to one.
	 * <p>
	 * <b>Where it composes:</b> a tail-callee that is a recognized helper with a
	 * caller-independent effect (its own {@code constState}, or one it composes to) overwrites
	 * the bits it owns on top of the caller's own deposit -- callee wins on its own bits, which
	 * is just {@link BankDataflowEngine#overwrite}. When the callee owns every bit the caller's body could touch,
	 * the composite is caller-independent even if the caller's body alone was not; that is Mega
	 * Man's {@code FUN_d846}, whose own three sites disagree (6 / loop-carried unknown / 6) yet
	 * whose exit is unconditionally {@code FUN_c3b3}'s bank 5.
	 * <p>
	 * <b>Everywhere else it DECLINES</b> -- returns a helper owning the mechanism with no
	 * recovered value, which yields a WARNING bookmark at each call site instead of an
	 * annotation. That covers a caller-dependent tail-callee, several exits whose composed
	 * effects disagree, a cycle, and the depth cap. Losing an annotation beats shipping a wrong
	 * bank; that is the whole point of this pass.
	 */
	// Package-private (not private) so TailCallCompositionProgramTest (grm-432) can drive the
	// four DECLINE branches directly against a hand-built helper map -- the same precedent as
	// HelperModel and restoresEntryBank, and the only reachable seam: everything above this in
	// added() needs a board descriptor and a real import, which is the Tier 3 tier. No behavior
	// change: every other member keeps its own visibility.
	static Map<Function, HelperModel> composeTailCalls(Program program,
			Map<Function, HelperModel> helpers) {
		Map<Function, HelperModel> composed = new LinkedHashMap<>(helpers);
		for (Function f : helpers.keySet()) {
			TailEffect effect = exitEffect(program, f, helpers, new LinkedHashSet<>(), 0);
			if (!effect.composed()) {
				continue; // no tail call out of this body -- the body-local summary stands
			}
			// argReg/strategy/switchSite are deliberately dropped: they describe the helper's
			// OWN body, which is no longer what this model asserts. A composed constant needs
			// none of them (runDataflow uses constState directly), and a decline needs none
			// either (recoverCallArgument short-circuits on the null argReg).
			composed.put(f, new HelperModel(f, f.getEntryPoint(), effect.constState(), null,
				effect.effectMask(), 0, null, null, null, null));
		}
		return composed;
	}

	/**
	 * One helper's composed exit effect. {@code declined} means "no value may be asserted for
	 * this helper" (the caller must warn); otherwise a null {@code constState} means the effect
	 * is caller-dependent and the body-local {@link HelperModel} still describes it.
	 * {@code composed} records whether a tail call to a recognized helper actually contributed
	 * -- when it is false the helper must be left exactly as {@link #findHelpers} built it.
	 */
	private record TailEffect(BankState constState, int effectMask, boolean declined,
			boolean composed) {}

	/**
	 * The effect {@code f} leaves behind when it returns to ITS caller, following tail calls.
	 * See {@link #composeTailCalls} for the rules; {@code onStack} is the cycle guard and
	 * {@code depth} the bound.
	 */
	private static TailEffect exitEffect(Program program, Function f, Map<Function, HelperModel> helpers,
			Set<Function> onStack, int depth) {
		HelperModel model = helpers.get(f);
		int ownMask = model.effectMask();
		if (depth > MAX_TAIL_CALL_DEPTH || !onStack.add(f)) {
			return new TailEffect(null, ownMask, true, true);
		}
		try {
			TailEffect merged = null;
			boolean sawHelperTailCall = false;
			for (Instruction exit : exitInstructions(program, f)) {
				HelperModel callee = exit.getFlowType().isCall()
						? calledHelper(program, exit, helpers)
						: null;
				TailEffect here;
				if (callee == null) {
					// RTS/RTI, or a tail call to a function this engine does not model as a
					// bank-switch helper -- the same no-op runDataflow folds for a call to one.
					here = new TailEffect(model.constState(), ownMask, false, false);
				}
				else {
					sawHelperTailCall = true;
					here = composeWithCallee(model,
						exitEffect(program, callee.function(), helpers, onStack, depth + 1));
				}
				merged = merged == null ? here : agreeOrDecline(merged, here, ownMask);
			}
			if (merged == null || !sawHelperTailCall) {
				return new TailEffect(model.constState(), ownMask, false, false);
			}
			return merged;
		}
		finally {
			onStack.remove(f);
		}
	}

	/** {@code model}'s own deposit with its tail-callee's laid over the bits the callee owns. */
	private static TailEffect composeWithCallee(HelperModel model, TailEffect callee) {
		int ownMask = model.effectMask();
		int union = ownMask | callee.effectMask();
		if (callee.declined() || callee.constState() == null) {
			// nothing assertable about the callee, so nothing assertable about this helper
			return new TailEffect(null, union, true, true);
		}
		if (model.constState() != null) {
			return new TailEffect(overwrite(model.constState(), callee.constState(),
				callee.effectMask()), union, false, true);
		}
		if ((callee.effectMask() & ownMask) == ownMask) {
			// The callee overwrites every bit this helper's own body could touch, so whatever
			// the body did with them is irrelevant and the composite is caller-independent even
			// though the body alone was not. Mega Man's FUN_d846 lands here.
			return new TailEffect(callee.constState(), union, false, true);
		}
		return new TailEffect(null, union, true, true);
	}

	/** Two exits' composed effects when they agree, a decline owning both masks when they don't. */
	private static TailEffect agreeOrDecline(TailEffect a, TailEffect b, int ownMask) {
		int union = a.effectMask() | b.effectMask() | ownMask;
		if (!a.declined() && !b.declined() && a.effectMask() == b.effectMask() &&
			Objects.equals(a.constState(), b.constState())) {
			return new TailEffect(a.constState(), a.effectMask(), false,
				a.composed() || b.composed());
		}
		return new TailEffect(null, union, true, true);
	}

	/**
	 * Admits pass-through wrapper functions into {@code helpers} by re-keying each helper's
	 * model onto the entry of a function that falls straight through into it without
	 * writing any mechanism of its own (bead grm-2dr increment 1).
	 * <p>
	 * <b>Why {@link #findHelpers} misses these.</b> {@link #findHelpers} admits a function
	 * as a helper only if it CONTAINS a recognized mechanism write. Real NES ROMs route
	 * bank switching through small trampolines that write nothing and simply fall through
	 * into the real helper -- Castlevania 2's {@code FUN_c183} ({@code STA $1C}) falls into
	 * {@code FUN_c185} ({@code LDA $1C}), which falls into {@code FUN_c187} (the MMC1
	 * serial-shift chain itself, {@code firstSite} {@code $c18e}); TMNT's {@code FUN_cea5}
	 * ({@code STA $21}) falls into {@code FUN_cea7} (whose own body starts {@code SEC / ROR
	 * $F0} before the chain at {@code $ceaa}); Wizards & Warriors' {@code $ce89} falls into
	 * {@code $ce8b}, an AxROM single-write latch -- named specifically because this rule is
	 * NOT scoped to serial-shift boards. Calls land on the wrapper's entry, which is not a
	 * key {@link #findHelpers} ever produces, so {@link #calledHelper} misses and the call
	 * site's argument is never recovered.
	 * <p>
	 * <b>Why re-keying alone is sound.</b> {@link #argumentSurvivesPrologue} walks LINEARLY
	 * BY ADDRESS from {@code entry} to {@code firstSite} with NO REFERENCE TO FUNCTION
	 * BOUNDARIES. Because a wrapper is address-contiguous with the helper it falls into,
	 * re-keying the helper's model onto the wrapper's entry makes that ONE EXISTING WALK
	 * cover the wrapper's body and the helper's own prologue with no change to that method
	 * at all. On cv2: {@code STA $1C} records {@code $1C} in {@code argumentCells};
	 * {@code LDA $1C} is recognized as a restore via {@code argumentReloadSource} so
	 * {@code holdsArgument} stays true; then {@code FUN_c187}'s own {@code PHA} /
	 * {@code LDA #$01} / {@code STA $0103} / {@code PLA} save-restore pair resolves exactly
	 * as it already does today.
	 * <p>
	 * <b>NOT HANDLED HERE, deliberately:</b> blmaster's {@code FUN_e61b} reaches its helper by
	 * an internal {@code JSR}, so it is not address-contiguous with it. {@link
	 * #isPassThroughInto}'s {@code getFlows().length == 0} condition (a call's flows include
	 * its target) excludes that BY CONSTRUCTION -- there is no special case for it here, and
	 * there should not be one. That edge is {@link #findCallEdgeWrappers}' job (grm-2dr
	 * increment 2), which reuses this method's sibling predicate on the wrapper's PREFIX rather
	 * than widening this one.
	 * <p>
	 * {@code switchResults} is threaded through so "the wrapper writes no mechanism" is
	 * asserted LOCALLY, against the same map the rest of this analysis already trusts,
	 * rather than by assuming {@link #findHelpers} completely characterizes every function
	 * that is not a helper.
	 * <p>
	 * Runs in rounds, capped by {@link #MAX_WRAPPER_CHAIN}, so a stack of wrappers is
	 * admitted one link per round: on cv2, round 1 admits {@code FUN_c185} against
	 * {@code FUN_c187}'s model, and round 2 admits {@code FUN_c183} against the model NOW
	 * keyed on {@code FUN_c185}'s entry -- matched against {@link HelperModel#entry}, NOT
	 * {@code model.function().getEntryPoint()}, which is exactly what lets round 2 see round
	 * 1's work. Each round scans a SNAPSHOT of the map's keys ({@code List.copyOf}), never
	 * the live map, so a wrapper admitted mid-round cannot itself be re-wrapped in the same
	 * pass -- preserving the deterministic ordering the backing {@link LinkedHashMap} exists
	 * for. A round that admits nothing ends the fixpoint early.
	 * <p>
	 * A helper whose model {@link #composeTailCalls} already composed is NOT skipped here --
	 * both outcomes of wrapping one are already correct without a special case: a composed
	 * constant takes {@link BankDataflowEngine#runDataflow}'s {@code constState} branch directly and never
	 * touches the nulled {@code argReg}/{@code switchSite} fields a wrapper would also leave
	 * untouched, and a composed decline short-circuits in {@link #recoverCallArgument} on
	 * the null {@code argReg}, producing a warning plus honest poison exactly as a direct
	 * call to it would.
	 */
	private static Map<Function, HelperModel> findPassThroughWrappers(Program program,
			Map<Function, HelperModel> helpers, Map<Address, SwitchResult> switchResults) {
		Map<Function, HelperModel> result = new LinkedHashMap<>(helpers);
		FunctionManager fm = program.getFunctionManager();
		for (int round = 0; round < MAX_WRAPPER_CHAIN; round++) {
			boolean added = false;
			for (Function key : List.copyOf(result.keySet())) {
				HelperModel model = result.get(key);
				Address before = model.entry().previous();
				if (before == null) {
					continue;
				}
				Function wrapper = fm.getFunctionContaining(before);
				if (wrapper == null || result.containsKey(wrapper)) {
					continue;
				}
				if (isPassThroughInto(program, wrapper, model.entry(), switchResults)) {
					result.put(wrapper, model.atFallThroughWrapper(wrapper));
					added = true;
				}
			}
			if (!added) {
				break;
			}
		}
		return result;
	}

	/**
	 * Whether {@code wrapper} does nothing but fall straight through into {@code target}: no
	 * branch, no jump, no call, no fallthrough override, no gap in disassembly, and no
	 * recognized mechanism write anywhere in its body. Structured as one linear cursor walk
	 * from {@code wrapper.getEntryPoint()} to {@code target}, deliberately shaped like
	 * {@link #argumentSurvivesPrologue} so the two read alike -- both exist to answer "does
	 * this straight-line stretch of code preserve something", the caller's byte there versus
	 * the fact that nothing has happened yet here.
	 * <p>
	 * EVERY condition below must hold for every instruction on the walk:
	 * <ul>
	 * <li>{@code wrapper.getBody()} is a single contiguous range starting at
	 * {@code wrapper.getEntryPoint()} -- a disjoint body would make "walk linearly to the
	 * end" meaningless.</li>
	 * <li>{@code getInstructionAt(cursor) != null} at every step -- disassembly
	 * completeness. This is LOAD-BEARING in a way it is not for
	 * {@code argumentSurvivesPrologue}: the {@code constState}-inherit path in
	 * {@link HelperModel#atFallThroughWrapper} bypasses {@code argumentSurvivesPrologue}
	 * entirely (a constant helper never calls it), so nothing else on that path ever checks
	 * for a disassembly gap in the wrapper's body -- this method is the only place that
	 * does.</li>
	 * <li>{@code instr.getFlows().length == 0} -- no branch, no jump, and no {@code JSR} (a
	 * call's flows include its target). This is what keeps blmaster's {@code FUN_e61b} out of
	 * {@link #findPassThroughWrappers} by construction, since it reaches its helper via an
	 * internal {@code JSR} rather than a fallthrough.</li>
	 * <li>{@code !instr.getFlowType().isTerminal()} -- NOT redundant with the flows check
	 * above: {@code RTS}/{@code RTI} have zero flows too, and neither falls through
	 * anywhere.</li>
	 * <li>{@code instr.getFallThrough()} equals {@code instr.getMaxAddress().next()} -- the
	 * fallthrough-OVERRIDE check. Ghidra allows an instruction's fallthrough to be
	 * overridden even when it has no flows and is not terminal, which would falsify both the
	 * pass-through claim and the linear-by-address walk this entire design -- here and in
	 * {@code argumentSurvivesPrologue} -- rests on.</li>
	 * <li>{@code !switchResults.containsKey(cursor)} -- writes no mechanism, asserted
	 * locally against the same map the rest of the analysis trusts rather than assuming
	 * {@link #findHelpers} completely characterizes every non-helper function.</li>
	 * </ul>
	 * The walk must land EXACTLY on {@code target}; overshooting or undershooting it is not
	 * a pass-through. Package-private static, not private, so a JUnit test can pin it
	 * directly, following the precedent of {@link #reachableEntries} and
	 * {@link #argumentSurvivesPrologue}.
	 * <p>
	 * <b>{@code target} has TWO meanings, by two callers</b> (grm-2dr increment 2).
	 * {@link #findPassThroughWrappers} passes a wrapped HELPER'S ENTRY, asking "does this
	 * wrapper fall straight into that helper?". {@link #findCallEdgeWrappers} passes a CALL SITE
	 * INSIDE the wrapper's own body, asking "does control reach that call unconditionally, with
	 * nothing bank-relevant happening first?". The predicate is identical for both because the
	 * question is: every step from the entry to here is plain, disassembled, inert
	 * fallthrough. In the second use the body-max bound never binds -- the target lies inside
	 * the body, so the walk returns on reaching it.
	 * <p>
	 * <b>Why bounding the walk by {@code getBody()} is safe, and not merely convenient.</b>
	 * Ghidra function bodies CANNOT OVERLAP: both {@code FunctionManagerDB.createFunction}
	 * and {@code setFunctionBody} route through the namespace manager and convert an
	 * {@code OverlappingNamespaceException} into an {@code OverlappingFunctionException}
	 * (verified against the targeted Ghidra source). Body assignment is therefore
	 * first-come-claims-it: whichever function is created first owns the addresses, and a
	 * later one is clipped at that boundary. So a wrapper's body is GUARANTEED to stop at or
	 * before {@code target}, and the early return when the cursor reaches {@code target}
	 * cannot silently accept a body that overruns it.
	 * <p>
	 * The same rule explains, from the other side, why this shape exists at all -- and why
	 * bead grm-78b is its mirror image. Whether a fallthrough chain surfaces as ONE BIG
	 * FUNCTION or as WRAPPER PLUS HELPER is decided purely by what got created first. On cv2
	 * all three entries were created, so each body was clipped and the wrappers are visible
	 * here; on blmaster nothing created a function at {@code f23b}, so {@code FUN_f1ca}'s
	 * body swallowed the RESET routine whole and its register writes were misattributed.
	 * Same mechanism, opposite outcomes.
	 * <p>
	 * Note this bound is a property of the FUNCTION MODEL, not of the decompiler, which is
	 * not bounded by function bodies at all: {@code Funcdata::startProcessing} calls
	 * {@code followFlow} over the whole address space, so a decompiled listing happily
	 * continues past a body's end. Do not read decompiler output as evidence about where a
	 * function's body stops.
	 */
	static boolean isPassThroughInto(Program program, Function wrapper, Address target,
			Map<Address, SwitchResult> switchResults) {
		AddressSetView body = wrapper.getBody();
		if (body.getNumAddressRanges() != 1 ||
			!body.getMinAddress().equals(wrapper.getEntryPoint())) {
			return false;
		}
		Listing listing = program.getListing();
		Address end = body.getMaxAddress();
		Address cursor = wrapper.getEntryPoint();
		while (cursor != null && cursor.compareTo(end) <= 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return false;
			}
			if (instr.getFlows().length > 0 || instr.getFlowType().isTerminal()) {
				return false;
			}
			Address next = instr.getMaxAddress().next();
			Address fallThrough = instr.getFallThrough();
			if (next == null || fallThrough == null || !fallThrough.equals(next)) {
				return false;
			}
			if (switchResults.containsKey(cursor)) {
				return false;
			}
			if (next.equals(target)) {
				return true;
			}
			cursor = next;
		}
		return false;
	}

	/**
	 * {@code helpers}, plus every CALL-EDGE wrapper of one: a function that writes no mechanism
	 * itself and reaches a real helper by an interior {@code JSR} rather than by falling through
	 * into it (bead grm-2dr increment 2). The sibling of {@link #findPassThroughWrappers}, for
	 * the edge that one excludes by construction.
	 * <p>
	 * blmaster's {@code FUN_e61b} is the shape the increment exists for -- twelve call sites, and
	 * before this every one of them silently unrecovered:
	 * <pre>
	 *   e61b  STA $DB        ; stash the caller's requested PRG bank in the shadow
	 *         ...            ; straight-line, reloads A from $DB
	 *   e627  JSR $e63c      ; the relay -- FUN_e63c is the real MMC1 serial-shift helper
	 *         ...            ; calls FUN_eb98 in a loop
	 *         RTS
	 * </pre>
	 * Call RECOGNITION already worked: the golden warned at {@code e627} naming
	 * {@code FUN_e63c}. What failed was ARGUMENT recovery, because the caller's {@code LDA #imm}
	 * is two frames from the store and {@code e61b} was not a helper, so nothing looked.
	 * <p>
	 * <b>TWO gates, and the second does not subsume the first.</b>
	 * <ul>
	 * <li>STRUCTURAL: {@link #isPassThroughInto} with {@code target} = the relay call site. The
	 * reuse is exact rather than opportunistic -- <em>the prefix of a call-edge wrapper, up to
	 * its relay call, is precisely a pass-through into that call site</em> -- and it is what
	 * proves the relay is REACHED UNCONDITIONALLY. Its body-max bound is harmless because the
	 * call site is inside the body, so the walk lands on it and returns first.</li>
	 * <li>VALUE: {@link #argumentSurvivesPrologue} over {@link #prologueSegments}, which proves
	 * the caller's byte is still in {@code argReg} when the helper's first site reads it. On
	 * blmaster this is exactly the {@code argumentCells}/{@code argumentReloadSource}
	 * save-restore model (grm-mu7 increment 2) recognizing the {@code STA $DB} / {@code LDA $DB}
	 * pair -- the same machinery that made cv2's {@code STA $1C} / {@code LDA $1C} work in
	 * increment 1.</li>
	 * </ul>
	 * <b>The value gate alone would be unsound, which is not obvious.</b> A branch does NOT make
	 * {@link #argumentSurvivesPrologue} decline: a nonzero {@code getFlows().length} only clears
	 * {@code straightLine} and {@code argumentCells}, and the walk CONTINUES. A prefix that
	 * branches around the relay call but never writes {@code argReg} would pass it -- and then
	 * every claim below about the wrapper's effect would rest on a call that might not run.
	 * <p>
	 * A tail {@code JMP} that Ghidra's shared-return analysis retyped {@code CALL_TERMINATOR}
	 * reports {@code isCall()} and counts as a relay. It is the SOUNDER case: control never
	 * returns to the wrapper, so there is no post-relay body to assume anything about.
	 * <p>
	 * <b>What is checked versus what is ASSUMED.</b> Checked: the prefix is inert and
	 * unconditional; no recognized mechanism write appears ANYWHERE in the wrapper's body (the
	 * whole body, not just the prefix -- a write after the relay would make the wrapper's effect
	 * not the helper's); no SECOND known-helper call appears there either. Assumed: that calls
	 * after the relay to functions this engine does not model as helpers are bank-neutral.
	 * <p>
	 * <b>{@code FUN_eb98} is the load-bearing instance of that assumption and it holds BY
	 * ACCIDENT, not by construction.</b> {@code e61b}'s loop calls it; {@code eb98} itself
	 * {@code JSR}s {@code e63c} twice -- {@code ec53} with a constant 5 for the duration of some
	 * work, then {@code ec5b} with the {@code $DB} value to put the requested bank back. The net
	 * effect at {@code e61b}'s return is the requested bank, so the model is right; it would not
	 * be if the restore were missing. {@code eb98} escapes admission here twice over: it
	 * contains no mechanism write, so {@link #findHelpers} never sees it, and it makes TWO
	 * known-helper calls, so the exactly-one rule rejects it as a wrapper. Both facts are
	 * load-bearing for {@code e61b} -- were {@code eb98} ever a helper, {@code e61b} would see
	 * two relay candidates and be rejected, which would then be the correct conservative answer.
	 * <p>
	 * This EXTENDS an existing standard rather than introducing a new unsoundness:
	 * {@link BankDataflowEngine#runDataflow} already folds a call to a non-helper as a no-op on bank state, and
	 * {@link #composeTailCalls} already writes that down for the tail-call case. But the
	 * extension is real and worth naming -- increment 1 CHECKED inertness per instruction over
	 * the whole wrapper body, while this checks it over the prefix and ASSUMES it over the tail.
	 * <p>
	 * {@link #exitEffect} is not reusable here, for a one-sentence reason: it composes effects at
	 * a function's EXIT instructions and deliberately nulls {@code argReg}/{@code strategy}/
	 * {@code switchSite} because they describe a body its result no longer summarizes -- while a
	 * relay is MID-BODY and exists precisely to PRESERVE {@code argReg} so the caller's value can
	 * be recovered. The two machineries want opposite things from the same fields.
	 * <p>
	 * <b>ONE ROUND, and the exactly-one count is taken against the IMMUTABLE INPUT map.</b> That
	 * is a correctness requirement, not a budget: the exactly-one rule is NON-MONOTONE in the
	 * helper set, so admitting X could flip Y's count from one to two and turn an admission into
	 * a rejection. With rounds, the answer would depend on candidate iteration order -- the same
	 * class of bug increment 1's snapshot guards against, but one a snapshot alone does NOT fix,
	 * since the snapshot would grow between rounds. Counting against the input makes this a
	 * PURE, ORDER-INDEPENDENT function of its arguments. Note the contrast with
	 * {@link #findPassThroughWrappers}, which looks similar but whose termination is STRUCTURAL
	 * with {@link #MAX_WRAPPER_CHAIN} merely a policy cap; here termination is trivially one
	 * pass.
	 * <p>
	 * Runs LAST in the helper-discovery chain, so it sees the richest helper set -- a relay
	 * landing on a pass-through wrapper admitted by increment 1 resolves through
	 * {@link #calledHelper} and counts toward the exactly-one tally. The converse, a pass-through
	 * wrapper OF a call-edge wrapper, is not reachable under this order; that is a documented gap
	 * with no measured instance, cheaply closed later by a second
	 * {@link #findPassThroughWrappers} call, which would stay deterministic because call-edge
	 * decisions are fixed by then. A wrapped model that ALREADY carries a relay is rejected: the
	 * prologue would need three segments, and {@link #prologueSegments} expresses two.
	 */
	private static Map<Function, HelperModel> findCallEdgeWrappers(Program program,
			Map<Function, HelperModel> helpers, Map<Address, SwitchResult> switchResults) {
		Map<Function, HelperModel> result = new LinkedHashMap<>(helpers);
		// Address-ordered and materialized before use, matching findPassThroughWrappers'
		// List.copyOf discipline: the enumeration must not depend on live map or iterator state.
		List<Function> candidates = new ArrayList<>();
		program.getFunctionManager().getFunctions(true).forEach(candidates::add);
		Listing listing = program.getListing();
		for (Function wrapper : candidates) {
			// helpers, never result: the count that decides admission is taken against the
			// immutable input, which is what makes this pass order-independent.
			if (helpers.containsKey(wrapper)) {
				continue;
			}
			if (wrapper.getBody().getNumAddressRanges() != 1) {
				continue;
			}
			Address relayCall = null;
			HelperModel wrapped = null;
			boolean rejected = false;
			for (Instruction instr : listing.getInstructions(wrapper.getBody(), true)) {
				if (switchResults.containsKey(instr.getMinAddress())) {
					rejected = true; // writes a mechanism -- a helper, not a wrapper
					break;
				}
				if (!instr.getFlowType().isCall()) {
					continue;
				}
				HelperModel target = calledHelper(program, instr, helpers);
				if (target == null) {
					continue; // a call to something this engine does not model -- assumed inert
				}
				if (relayCall != null) {
					rejected = true; // a second known-helper call
					break;
				}
				relayCall = instr.getMinAddress();
				wrapped = target;
			}
			if (rejected || relayCall == null || wrapped.relay() != null ||
				wrapped.argReg() == null || wrapped.firstSite() == null) {
				continue;
			}
			if (!isPassThroughInto(program, wrapper, relayCall, switchResults)) {
				continue;
			}
			HelperModel model = wrapped.atCallEdgeWrapper(wrapper, relayCall);
			if (!argumentSurvivesPrologue(program, prologueSegments(model), model.argReg())) {
				continue;
			}
			result.put(wrapper, model);
		}
		return result;
	}

	/**
	 * Every instruction in {@code f} that ends a path through it: {@code RTS}/{@code RTI}
	 * ({@code TERMINATOR}) and a tail call out of the body ({@code CALL_TERMINATOR} -- a jump
	 * to another function's entry, which Ghidra's shared-return analysis rewrites into a
	 * call-with-no-fall-through). Both report {@link ghidra.program.model.symbol.FlowType#isTerminal()};
	 * they are told apart by {@code isCall()}, the same test {@link BankDataflowEngine#runDataflow} already uses
	 * to route a {@code CALL_TERMINATOR} jump through the helper-call path.
	 * <p>
	 * A plain unconditional jump that leaves the body WITHOUT landing on a function entry is
	 * not terminal and so is not seen here. Ghidra normally absorbs such a target into this
	 * function's body instead, which makes it an internal branch the max-address rule already
	 * covers; a genuinely bodiless jump out would be a gap, not a wrong answer, since it can
	 * only leave the body-local summary in place.
	 */
	private static List<Instruction> exitInstructions(Program program, Function f) {
		List<Instruction> exits = new ArrayList<>();
		for (Instruction instr : program.getListing().getInstructions(f.getBody(), true)) {
			if (instr.getFlowType().isTerminal()) {
				exits.add(instr);
			}
		}
		return exits;
	}

	/**
	 * Hop cap for {@link #reachableEntries}. A real argument relay is one link -- a jump-table
	 * slot, or Ghidra's own thunk typing of the same. Three is slack, not a modeled depth.
	 */
	private static final int MAX_RELAY_HOPS = 3;

	/**
	 * The addresses control can actually arrive at from this call: its direct flow targets,
	 * then each one followed through Ghidra thunks and one-instruction unconditional-jump
	 * trampolines, in that order (nearest first, so a direct hit always wins over a hop).
	 * <p>
	 * <b>Why a call's flow target is not always where it lands.</b> Games route bank switches
	 * through a jump table of 3-byte slots, and Ghidra types those two different ways depending
	 * on nothing the game did. Bionic Commando's {@code $D751 JMP $DCC3} becomes
	 * {@code thunk_FUN_dcc3} because {@code $DCC3} happens to be a function entry; its
	 * {@code $D6E2 JMP $DCAA} stays an ordinary one-instruction function, because {@code $DCAA}
	 * is mid-body. Both are the same idiom and both were invisible: the thunk is a different
	 * {@code Function} than the helper, and the trampoline is not the helper at all, so the old
	 * {@code getFunctionAt} + map lookup missed both and returned null -- which
	 * {@link BankDataflowEngine#runDataflow} folds as a call that does nothing to bank state. A SILENT miss, and
	 * measurably the whole story on two real cartridges: every one of Bionic Commando's 5 bank
	 * call sites and all 59 of Final Fantasy's reach their helper only through a hop.
	 * <p>
	 * Package-private and static so it can be tested against a {@code ProgramBuilder} program
	 * on its own -- it is a function of {@code (program, callInstr)} and nothing else, with no
	 * analyzer state, no board, and no dependence on any helper having been found yet.
	 */
	static List<Address> reachableEntries(Program program, Instruction callInstr) {
		List<Address> entries = new ArrayList<>();
		for (Address flow : callInstr.getFlows()) {
			Set<Address> seen = new LinkedHashSet<>();
			Address cur = flow;
			for (int hop = 0; cur != null && seen.add(cur); hop++) {
				entries.add(cur);
				cur = hop < MAX_RELAY_HOPS ? relayTarget(program, cur) : null;
			}
		}
		return entries;
	}

	/**
	 * One hop from {@code at} through a thunk or a one-instruction unconditional-jump
	 * trampoline, or null if {@code at} is neither.
	 * <p>
	 * The one-instruction requirement is what keeps this from following ordinary tail jumps.
	 * A {@code JMP} at the end of a longer body is reached only after that body has run, so
	 * attributing the jump's target to a call that entered at the top would credit the caller
	 * with a helper it reaches only via other code -- and that case already has an owner:
	 * {@link #composeTailCalls}, which composes the two effects rather than substituting one
	 * for the other. Here the trampoline body IS the jump, so there is nothing to compose.
	 */
	private static Address relayTarget(Program program, Address at) {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(at);
		if (f != null && f.isThunk()) {
			Function thunked = f.getThunkedFunction(true);
			if (thunked != null) {
				return thunked.getEntryPoint();
			}
		}
		Instruction instr = program.getListing().getInstructionAt(at);
		// isCall() is deliberately NOT excluded: shared-return analysis retypes a tail JMP as
		// CALL_TERMINATOR, which reports both isCall() and isJump(). A one-instruction body
		// that does that is still a relay. A JSR is isCall() but not isJump(), so it is out.
		//
		// isComputed() IS excluded, and that exclusion is load-bearing rather than tidiness.
		// A relay's defining property is that its target is encoded in the instruction, so
		// "where this call lands" stays a static fact; a computed jump's target is read from
		// memory at run time and is not that instruction's property at all. Measured cost of
		// getting this wrong, on Mega Man 2: the 6502's BRK is specified as
		// `goto [*:2 0xFFFE]`, so every filler $00 byte Ghidra disassembles becomes a
		// one-instruction "relay" into the IRQ handler. Following those reached RESET from
		// unrelated call sites, poisoning bank state that nothing had written, and cost 285
		// resolved overlay instructions -- a silent miss traded for a loud wrong answer.
		if (instr == null || !instr.getFlowType().isJump() ||
			instr.getFlowType().isConditional() || instr.getFlowType().isComputed()) {
			return null;
		}
		Function owner = fm.getFunctionContaining(at);
		if (owner != null && (!owner.getEntryPoint().equals(at) ||
			owner.getBody().getNumAddresses() != instr.getLength())) {
			return null;
		}
		Address[] flows = instr.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	/**
	 * How a helper is named in a user-visible warning. The function's name, except for a
	 * mid-body entry, where naming the function would point the reader at {@code FUN_dca8}
	 * when the call actually went to {@code LAB_dcaa} -- an address whose whole significance
	 * is that it is NOT the function entry.
	 */
	static String helperLabel(Program program, HelperModel helper) {
		if (helper.entry().equals(helper.function().getEntryPoint())) {
			return helper.function().getName();
		}
		Symbol sym = program.getSymbolTable().getPrimarySymbol(helper.entry());
		return (sym == null ? helper.entry().toString() : sym.getName()) + " (mid-body entry in " +
			helper.function().getName() + ")";
	}

	/**
	 * The helper this call instruction targets, or null.
	 * <p>
	 * This relies on {@code helpers} already containing an entry keyed on the actual call
	 * target, which is why a call landing on a pass-through wrapper's entry (Castlevania
	 * 2's {@code FUN_c183}, TMNT's {@code FUN_cea5}, Wizards & Warriors' {@code $ce89}) does
	 * not silently miss here: {@link #findPassThroughWrappers} re-keys the wrapped helper's
	 * model onto the wrapper's own entry BEFORE this method ever runs, so the lookup below
	 * hits it the same way it would hit a direct call.
	 */
	static HelperModel calledHelper(Program program, Instruction callInstr,
			Map<Function, HelperModel> helpers) {
		FunctionManager fm = program.getFunctionManager();
		for (Address entry : reachableEntries(program, callInstr)) {
			Function f = fm.getFunctionAt(entry);
			if (f != null) {
				HelperModel helper = helpers.get(f);
				if (helper != null) {
					return helper;
				}
				continue; // a real function that is not a helper -- not a mid-body entry either
			}
			HelperModel midBody = midBodyEntryHelper(program, entry, helpers);
			if (midBody != null) {
				return midBody;
			}
		}
		return null;
	}

	/**
	 * A helper model for control arriving INSIDE a helper's body rather than at its entry, or
	 * null when this address is not an admissible mid-body entry.
	 * <p>
	 * <b>The admission test is "no recognized site strictly precedes {@code entry}".</b> That
	 * is what makes reusing the containing function's summary exact rather than a guess:
	 * entering here still runs the body's entire recognized site set, in the same order, so
	 * {@code effectMask}, {@code lsb}, {@code strategy} and {@code switchSite} all still
	 * describe this path -- no reachability over- or under-approximation is involved. Entering
	 * PAST a site (a {@code JSR} into the middle of a serial-shift chain) fails the test and is
	 * declined rather than guessed at: its real effect is a partial chain, which this model has
	 * no way to express. {@code constState} is dropped regardless; see
	 * {@link HelperModel#atMidBodyEntry}.
	 * <p>
	 * Resolution is demand-driven -- only an address some call actually reaches is ever tested
	 * -- rather than enumerating every branch target in every helper body. A mid-body entry
	 * that nothing calls cannot change any answer, and enumerating would mean inventing a rule
	 * for which of a loop's internal labels count as entry points.
	 * <p>
	 * <b>A CALL-EDGE wrapper is declined outright, and the admission test above cannot be
	 * trusted to do it</b> (bead grm-2dr increment 2). Such a model's {@code firstSite} lives in
	 * a DIFFERENT function and is therefore greater than every address in {@code owner}'s body,
	 * so {@code entry > firstSite} is false for every mid-body address in the wrapper --
	 * including ones PAST the relay call, where the {@code JSR} into the real helper has already
	 * been skipped and no bank switch happens on that path at all. The test's whole
	 * justification -- "entering here still runs the body's entire recognized site set" -- does
	 * not survive a relay, because the site set is not in this body and a branch inside the
	 * wrapper could route around the call that reaches it. The check is deliberately blunt
	 * ({@code relay != null}) rather than {@code entry <= relay.callSite()}: nothing measured
	 * needs the finer rule, and the coarse one cannot be wrong.
	 */
	private static HelperModel midBodyEntryHelper(Program program, Address entry,
			Map<Function, HelperModel> helpers) {
		FunctionManager fm = program.getFunctionManager();
		if (fm.getFunctionAt(entry) != null) {
			return null; // a function entry, not a mid-body one -- calledHelper handles it
		}
		Function owner = fm.getFunctionContaining(entry);
		if (owner == null) {
			return null;
		}
		HelperModel model = helpers.get(owner);
		if (model == null || model.relay() != null || model.firstSite() == null ||
			entry.compareTo(model.firstSite()) > 0) {
			return null;
		}
		return model.atMidBodyEntry(entry);
	}

	/**
	 * Recovers the bank argument at a helper call site by running the shared backward scan
	 * for an immediate value in the register the helper actually reads ({@code LDA #bank /
	 * JSR SelectBank}, or the X/Y equivalent). The argument register is taken from the
	 * helper's own mechanism-write ({@link HelperModel#argReg}) rather than guessed, so a
	 * caller that also loads an unrelated immediate into another register no longer misleads
	 * the scan. By the helper convention the register holds the <em>field value itself</em>,
	 * so no mechanism transform is applied beyond the field-local width mask -- the scan
	 * resolves in the helper's own mechanism's field-local {@code [0, width)} space (same
	 * convention as {@link BankSwitchStrategy#computeSwitch}). The recovered byte is then
	 * handed to the matched strategy's {@link BankSwitchStrategy#depositHelperArgument},
	 * which knows -- from the helper's own recognized {@link HelperModel#switchSite} --
	 * whether this mechanism's field-local space is one field (the recovered byte deposits
	 * verbatim, owning the whole field-local width, the historical behavior) or several
	 * disjoint sub-fields keyed by which switch site is in play (serial-shift) OR by the
	 * caller's own TRACKED STATE at the call site (select-data -- a bare data-write helper's
	 * routing depends on whichever register the caller's select last picked, which the
	 * switch site's address alone cannot tell us): only that call knows which sub-field the
	 * recovered value actually commits through, and therefore which bits this call site may
	 * claim ownership of ({@link CallEffect#ownedMask} -- see
	 * {@link BankSwitchStrategy.HelperDeposit}'s javadoc for why that is tracked separately
	 * from the value's own known bits). To support the state-routed case, {@code callSiteIn}
	 * (the caller's board-absolute state under which this call executes -- the same
	 * {@code outState} {@link BankDataflowEngine#runDataflow} folds the call's own effect into) is narrowed to
	 * this helper's mechanism's field-local space exactly like {@code argValue} before being
	 * handed to {@link BankSwitchStrategy#depositHelperArgument}; a strategy whose routing is
	 * address-keyed instead (serial-shift) simply ignores it. Both the value and the
	 * owned-bits mask are positioned back into the board's absolute state bits before
	 * returning, exactly as a direct dataflow switch's result is. Returns an unknown value
	 * owning the WHOLE mechanism when the argument register itself is unknown (the helper's
	 * sites disagreed on it) -- conservatively wiping everything this helper's mechanism
	 * could possibly touch, the historical behavior for that degrade case.
	 * <p>
	 * <b>The "register holds the field value" convention is a fallback, not the whole story</b>
	 * (grm-hum increment 2). It is blind in three ways: the argument may arrive in a register
	 * other than the one the helper's mechanism write stores (Contra's helper takes its bank in
	 * Y and stores A, and {@link #findHelpers} can only see the store); the value may need the
	 * mechanism's own {@code shift}/{@code mask} extraction; and on a bus-conflict board the
	 * driven value is not the latched one. So this also hands the strategy the CALL SITE'S WHOLE
	 * REGISTER ENVIRONMENT ({@link #callSiteRegisters}), letting a strategy that can do better --
	 * {@code memory-latch} does -- re-evaluate its own switch site under those registers instead.
	 * {@code argValue} keeps its exact prior meaning either way, because {@code select-data}
	 * decodes a byte field out of it.
	 * <p>
	 * <b>The convention also assumes the helper does not eat its own argument</b> (grm-mu7).
	 * {@code argReg} is whatever register the mechanism write STORES, which is the only
	 * evidence {@link #findHelpers} has -- but a helper whose prologue reloads the bank from
	 * RAM ({@code LDA $65 / STA $E000}) stores A without ever reading the caller's A, so the
	 * caller's value is not the argument and depositing it would ship a confident wrong bank.
	 * {@link #argumentSurvivesPrologue} tests that precondition over {@code entry..firstSite},
	 * and a failure falls through rather than short-circuiting, so the strategy still decides
	 * ownership and only the bits this call really writes are poisoned.
	 * <p>
	 * <b>That fallback has THREE outcomes, not two</b> (bead grm-67g), tried in this order once
	 * the caller's register is ruled out:
	 * <ol>
	 * <li>the caller's byte arriving through MEMORY -- {@link #inboundArgumentCell} proves the
	 * helper consumes a cell it never writes, and {@link StoredValueScanner#callerCellValue}
	 * reads what the caller stored there (smb3's {@code $0720});</li>
	 * <li>the helper's OWN value where its body supplies a constant --
	 * {@link #valueSuppliedInsideHelper} (grm-cxb), reading whichever site the strategy says
	 * consumes the byte ({@link #helperValueSite});</li>
	 * <li>unknown.</li>
	 * </ol>
	 * So a failed prologue test is not by itself a guarantee of silence. It is skipped for a strategy
	 * that re-derives the value inside the
	 * helper instead of consuming {@code argValue} -- see
	 * {@link BankSwitchStrategy#consumesHelperArgument}, and note that memory-latch's Contra
	 * helper is a prologue-clobber case that must keep resolving.
	 * <p>
	 * {@code envCache} memoizes that environment per call address for the duration of one
	 * {@link BankDataflowEngine#runDataflow}; see its declaration there for why it is not optional.
	 * <p>
	 * <b>The environment is PROLOGUE-FILTERED, per register</b> (bead grm-k90). What
	 * {@link #callSiteRegisters} scans is the caller's raw A/X/Y, and for a WRAPPER model the
	 * wrapper's body executes between the caller and the point the env claims to describe -- it
	 * may freely write X or Y, and {@link #isPassThroughInto} admits an {@code LDX #imm} without
	 * blinking. For a CALL-EDGE wrapper it is worse than theoretical: the scan stops at
	 * {@code relay.calleeEntry()} and never walks the wrapper's prefix at all, so an unfiltered
	 * env would hand a strategy a register value the wrapper had already overwritten. Each of
	 * A/X/Y is therefore passed through only where
	 * {@link #argumentSurvivesPrologue(Program, List, char)} holds for THAT register over
	 * {@link #prologueSegments}, and comes back {@link BankState#unknown()} otherwise. The test
	 * is per-register precisely because the answers differ: on Contra's {@code FUN_c139} wrapper
	 * ({@code LDA $8000 / STA $07ec}, falling into {@code FUN_c13f}) A does not survive and Y
	 * does, and it is Y the latch actually consumes.
	 * <p>
	 * This is uniform across ordinary helpers, pass-through wrappers and call-edge wrappers, and
	 * for an ordinary helper it is not a behavior change in any measured case -- the same
	 * predicate over the same span already gated {@code argValue} just above. Note the
	 * interaction with the crossable join below: for a PASS-THROUGH wrapper the scan now walks
	 * the wrapper's prefix itself, so a register the filter would have zeroed is one the scan
	 * clobbers on its own before ever reaching the stop. The filter is therefore
	 * redundant-but-harmless there, and load-bearing for the call-edge case where the prefix is
	 * never walked. It is kept for both because "the env describes the caller's registers as
	 * they are at the point the env stops" is the invariant, and an invariant that holds only on
	 * the paths that happen to re-derive it is not one.
	 * <p>
	 * <b>And it nominates the join the scan may cross</b> ({@link #crossableWrapperJoin}), which
	 * is what makes the stop reachable at all for a pass-through wrapper. The bead's own filed
	 * hypothesis -- that these call sites fail because {@code recoverCallArgument} gates the
	 * whole path on {@code argumentSurvivesPrologue} with {@code reg == argReg == 'A'} -- is
	 * WRONG for memory-latch, and worth recording so nobody re-derives it: that gate is skipped
	 * entirely, because {@link BankSwitchStrategy#consumesHelperArgument} is false for
	 * memory-latch. The real failure was the join refusal killing the walk two instructions
	 * short of the env's stop.
	 */
	static CallEffect recoverCallArgument(Program program, Instruction callInstr,
			HelperModel helper, BankState callSiteIn, Map<Address, RegisterEnv> envCache,
			Set<Function> restoringTrampolines) {
		if (restoringTrampolines.contains(helper.function())) {
			// A VERIFIED no-op (grm-mej.3): this helper puts the entry bank back before returning,
			// so the call owns nothing. Answered before argReg is even consulted, because the
			// argument is genuinely irrelevant here -- it selects the bank the INNER call runs in,
			// and that is over by the time the caller resumes. See restoresEntryBank.
			return new CallEffect(BankState.unknown(), 0);
		}
		Character reg = helper.argReg();
		if (reg == null) {
			return new CallEffect(BankState.unknown(), helper.effectMask());
		}
		int stateMask = helper.effectMask() >>> helper.lsb();
		BankState local = StoredValueScanner.resolveStoredValue(program, callInstr, reg,
			BankState.unknown(), stateMask, NO_HOOKS);
		// grm-mu7: what the caller left in argReg is this helper's argument only if the helper
		// still has it when the first switch site reads it. Withholding the value (rather than
		// short-circuiting the whole call) is deliberate -- it routes the call down the exact
		// path an unresolvable caller-side scan already takes, so the strategy still decides
		// which bits this site owns and poisons only those. Strategies that re-derive the value
		// inside the helper are exempt; see BankSwitchStrategy.consumesHelperArgument.
		//
		// grm-67g: the caller's byte may still reach the site THROUGH MEMORY even when it does not
		// reach it in the register -- smb3's `LDA #$1b / STA $0720 / JSR $ffc2` against a helper
		// that reloads A from $0720. So this branch makes two attempts before giving up, in the
		// order caller's-cell then helper's-own-constant, and both are strictly additive: it only
		// ever runs where the register answer was already discarded.
		if ((helper.strategy() == null || helper.strategy().consumesHelperArgument()) &&
			!argumentSurvivesPrologue(program, prologueSegments(helper), reg)) {
			Address inbound = inboundArgumentCell(program, helper, reg);
			BankState viaCell = inbound == null ? BankState.unknown()
					: StoredValueScanner.callerCellValue(program, callInstr, inbound, stateMask,
						NO_HOOKS);
			// Partial knowledge counts, matching how combine() and setFieldFromByte already treat
			// a per-bit answer. NO_HOOKS for the same reason the caller-side register scan above
			// uses it: that scan runs in the CALLER, outside any mechanism's interpretation -- see
			// callSiteRegisters. With no resolveLoad there is also nothing whose validity a
			// mid-scan mechanism write could invalidate; a store to $8000 is stepped over on the
			// strength of being a provably different cell, which is the honest reason.
			local = viaCell.knownMask() != 0 ? viaCell
					: valueSuppliedInsideHelper(program, helper, reg, stateMask);
		}
		Instruction switchSite = helper.switchSite() == null ? null
				: program.getListing().getInstructionAt(helper.switchSite());
		if (helper.strategy() == null || switchSite == null) {
			return new CallEffect(position(local, helper.lsb(), helper.effectMask()),
				helper.effectMask());
		}
		BankState localIn = new BankState(
			(callSiteIn.knownMask() & helper.effectMask()) >>> helper.lsb(),
			(callSiteIn.bits() & helper.effectMask()) >>> helper.lsb());
		// helper.entry(), not function().getEntryPoint(): the mini-inline scan must stop where
		// control actually arrived. For a mid-body entry those differ, and stopping at the
		// function entry would walk the scan back through the very prologue this call skipped.
		// For a CALL-EDGE wrapper it is the relay's callee entry instead: the scan runs inside
		// the WRAPPED helper, so stopping at the wrapper's entry would let it run off the
		// helper's own entry and back into the wrapper's tail (grm-2dr increment 2).
		Address scanStop = insideHelperEntry(helper);
		RegisterEnv callerRegs = envCache.computeIfAbsent(callInstr.getMinAddress(),
			a -> callSiteRegisters(program, callInstr, scanStop,
				crossableWrapperJoin(program, helper.firstSite(), scanStop), helper));
		BankSwitchStrategy.HelperDeposit deposit = helper.strategy()
				.depositHelperArgument(program, switchSite, local, localIn, stateMask, callerRegs);
		BankState positionedValue = position(deposit.value(), helper.lsb(), helper.effectMask());
		int positionedOwnedMask = (deposit.ownedMask() << helper.lsb()) & helper.effectMask();
		return new CallEffect(positionedValue, positionedOwnedMask);
	}

	/**
	 * Whether a value the CALLER left in {@code reg} is still there when the helper's first
	 * recognized switch site reads it -- the soundness precondition for
	 * {@link #recoverCallArgument} handing that value to a strategy that takes it at face
	 * value (grm-mu7).
	 * <p>
	 * <b>The bound is {@code firstSite}, emphatically not {@code switchSite}.</b> The argument
	 * has to survive as far as the FIRST site because that is where the mechanism consumes it;
	 * what happens after is the mechanism's own business, and a serial-shift chain's
	 * {@code STA/LSR A/STA/...} clobbers A four times between its first write and its last by
	 * design. Walking to {@code switchSite} would therefore decline every serial-shift helper
	 * on the planet -- it would "fix" this bug by disabling the feature.
	 * <p>
	 * <b>{@code entry}, not the function's entry point.</b> The prologue this must inspect is
	 * the part of it a given call actually runs. Bionic Commando's {@code FUN_dca8} is exactly
	 * why: entering at {@code $DCA8} runs {@code LDA $65} and the caller's A is irrelevant,
	 * while entering at {@code $DCAA} -- the mid-body entry its jump table really uses -- skips
	 * that load and takes the bank in A. One function, two answers, told apart by nothing but
	 * this address; a mid-body entry equal to {@code firstSite} walks an empty range and
	 * correctly keeps its argument.
	 * <p>
	 * Declining conditions, all conservative -- a false decline costs one annotation, a false
	 * accept ships a wrong bank:
	 * <ul>
	 * <li><b>Anything that writes {@code reg}</b>, asked of the language rather than a mnemonic
	 * list so an undocumented or synthetic opcode cannot slip past.</li>
	 * <li><b>Any call</b>: the callee's register effects are not modeled here at all.</li>
	 * <li><b>A gap in the disassembly</b>, i.e. the walk cannot reach {@code firstSite} through
	 * contiguous instructions. Undisassembled bytes in the middle of a helper body are bytes
	 * whose register effects are unknown, which is not the same as harmless.</li>
	 * <li><b>A missing {@code firstSite}</b> -- {@code findHelpers}' multi-mechanism degrade
	 * case, where the model no longer describes one coherent mechanism and there is nothing
	 * meaningful to walk to.</li>
	 * </ul>
	 * <b>A CLOBBER IS NOT A LOSS WHEN THE PROLOGUE SAVED THE ARGUMENT FIRST.</b> This is not a
	 * refinement, it is the difference between working and not working, and it was measured the
	 * expensive way: the first version of this method tested only "does anything write
	 * {@code reg}", and that silently destroyed three real ROMs. Castlevania 2's {@code FUN_c187},
	 * byte-exact:
	 * <pre>
	 *   c187  PHA            ; save the caller's bank argument
	 *   c188  LDA #$01       ; the naive test declines HERE
	 *   c18a  STA $0103
	 *   c18d  PLA            ; ...but this puts the argument back
	 *   c18e  STA $FFFF      ; firstSite: the chain consumes A, correctly
	 * </pre>
	 * The argument survives perfectly well -- across the stack. Declining cost Kid Icarus all 215
	 * of its overlay instructions, Dodgeball all 10692 of its, and Castlevania 2 both of its bank
	 * comments; the synthetic goldens all passed, because none of them saves and restores.
	 * <p>
	 * So the walk carries an abstract state instead of a single flag: whether {@code reg} still
	 * holds the caller's value, a shadow stack of which pushed bytes ARE that value, and the set
	 * of memory cells it was stored to and not yet overwritten. {@code PHA} pushes the current
	 * answer, {@code PLA} pops it back, and {@code PHP}/{@code PLP} are modelled purely to keep
	 * the depth honest so an interleaved status push cannot make a later {@code PLA} pop the
	 * wrong byte. Anything else that moves the stack pointer abandons the model rather than guess
	 * at the new depth.
	 * <p>
	 * <b>The memory half is not optional either</b> -- the same three ROMs need both. Double
	 * Dribble's {@code FUN_ff08} restores from the stack and then immediately parks the argument
	 * in RAM, because it needs A again for an unrelated shadow:
	 * <pre>
	 *   ff11  PLA            ; the argument is back...
	 *   ff12  STA $0103      ; ...and immediately parked in memory
	 *   ff15  LDA $ff        ; A reused for the mirroring shadow
	 *   ff1a  STA $ff
	 *   ff1c  LDA $0103      ; the argument is reloaded HERE
	 *   ff1f  STA $FFFF      ; firstSite
	 * </pre>
	 * A load counts as a restore only when it reads a cell this walk watched the argument being
	 * written to and nothing has written since; every other write to {@code reg} loses it. An
	 * indexed store forgets every tracked cell, since its target is runtime-dependent and could
	 * have landed on any of them.
	 * <p>
	 * <b>This is a PRESERVATION model, not a value model.</b> It answers only "does the caller's
	 * byte still reach the first site", never "what is it" -- the value still comes from the
	 * caller-side scan. Teaching {@link StoredValueScanner} to carry values through the stack and
	 * across blocks is a different and much larger capability, tracked by {@code grm-mej.3} and
	 * blocked on {@code grm-mej.2}; nothing here anticipates it.
	 * <p>
	 * <b>Soundness of the save/restore half.</b> The clobber half of this walk is linear in
	 * address order, which is a proxy for execution order in the same way
	 * {@code HelperModel.switchSite}'s max-address rule is, and it errs SAFE: a prologue that
	 * branches around a clobber is declined even though the argument survives the taken path.
	 * The save/restore half does not get that for free -- a branch that skipped a {@code PLA}
	 * would make "restored" a claim about a path that never runs, and that error points the
	 * unsafe way. It is therefore trusted only over genuinely straight-line code: any
	 * non-fall-through flow in the range abandons the shadow stack, after which a {@code PLA} is
	 * an ordinary clobber again. Clobber detection itself is unaffected and stays conservative.
	 * <p>
	 * <b>Where the memory half and the stack half collide</b>: a push writes memory too, at
	 * {@code $0100 + S}, so a tracked cell in the stack page could be clobbered by the very
	 * {@code PHA} this walk models as a pure save. {@link StackFloor} draws that line, applied
	 * by {@link #forgetCellsThePushMayHaveHit}; the same floor governs
	 * {@code StoredValueScanner.forwardedStoreValue} and {@link #inboundArgumentCell}, so all
	 * three walks now make one assumption instead of three tacit ones.
	 */
	/**
	 * Drops every tracked cell a {@code PHA}/{@code PHP} could have landed on, per
	 * {@link StackFloor}. The pushes are otherwise {@code modelled = true} and so skip the
	 * generic {@code argumentCells.removeIf} below -- which is right for the register half (a
	 * push does not clobber {@code reg}) and wrong for the memory half, since a push does write
	 * memory, at an address no detector in {@link StoredValueScanner} can name because it is
	 * {@code $0100 + S}. Below the floor this removes nothing, which is the whole point: the
	 * measured cell in Double Dribble and Castlevania 2 is {@code $0103}.
	 */
	private static void forgetCellsThePushMayHaveHit(Program program, Set<Address> argumentCells) {
		argumentCells.removeIf(cell -> StackFloor.mayAliasStack(program, cell));
	}

	static boolean argumentSurvivesPrologue(Program program, Address entry, Address firstSite,
			char reg) {
		if (entry == null || firstSite == null || entry.compareTo(firstSite) > 0) {
			return false;
		}
		Register register = program.getLanguage().getRegister(String.valueOf(reg));
		if (register == null) {
			return false; // cannot ask the question -> do not assume the favorable answer
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		Listing listing = program.getListing();
		// Does argReg still hold what the CALLER left in it?
		boolean holdsArgument = true;
		// The saved-value stack: one entry per byte this walk watched being pushed, true when
		// that byte IS the caller's argument. Only consulted while straightLine holds.
		Deque<Boolean> saved = new ArrayDeque<>();
		// The memory half of the same idea: cells this walk watched the argument being stored to
		// and which nothing has overwritten since, so a load from one is a restore.
		//
		// Note the DUAL of this set, inboundArgumentCell (grm-67g): a cell enters here only when
		// the HELPER stores argReg into it, and enters there only when the helper never does. A
		// helper cannot satisfy both, which is what lets recoverCallArgument try them in sequence
		// without the order mattering.
		Set<Address> argumentCells = new LinkedHashSet<>();
		// Whether the save/restore model is still trustworthy. Cleared by anything that moves
		// the stack pointer in a way this does not model, and by any non-fall-through flow --
		// see the javadoc's soundness note.
		boolean straightLine = true;
		Address cursor = entry;
		while (cursor.compareTo(firstSite) < 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || instr.getFlowType().isCall()) {
				return false;
			}
			boolean modelled = false;
			if (reg == 'A') {
				switch (instr.getMnemonicString()) {
					case "PHA" -> {
						if (straightLine) {
							saved.push(holdsArgument);
						}
						forgetCellsThePushMayHaveHit(program, argumentCells);
						modelled = true;
					}
					case "PLA" -> {
						if (straightLine && !saved.isEmpty()) {
							holdsArgument = saved.pop();
						}
						else {
							// Popping a byte this walk never watched being pushed: it belongs to
							// the caller's frame or to code we did not model, and the depth is out
							// of step from here on either way.
							holdsArgument = false;
							straightLine = false;
						}
						modelled = true;
					}
					case "PHP" -> {
						// Modelled only to keep the DEPTH right, so an interleaved status push
						// cannot make a later PLA pop the wrong byte. A status byte is never the
						// argument.
						if (straightLine) {
							saved.push(Boolean.FALSE);
						}
						forgetCellsThePushMayHaveHit(program, argumentCells);
						modelled = true;
					}
					case "PLP" -> {
						if (straightLine && !saved.isEmpty()) {
							saved.pop();
						}
						else {
							straightLine = false;
						}
						modelled = true;
					}
					default -> {
						// fall through to the generic tests below
					}
				}
			}
			if (!modelled) {
				// Any write to a cell we were relying on ends that reliance, whatever wrote it
				// (a plain store, or an INC/ASL-style read-modify-write).
				argumentCells.removeIf(cell -> StoredValueScanner.writesAddress(instr, cell));
				Character stored = StoredValueScanner.storeRegister(instr);
				if (stored != null && stored.charValue() == reg && holdsArgument && straightLine) {
					Address cell = StoredValueScanner.plainAbsoluteTarget(instr);
					if (cell != null) {
						argumentCells.add(cell);
					}
					else {
						// An indexed store's target is runtime-dependent, so it may have landed on
						// any tracked cell. Forget all of them rather than pick.
						argumentCells.clear();
					}
				}
				if (StoredValueScanner.writesRegister(instr, register)) {
					// A load is a RESTORE when it reads back a cell this walk watched the argument
					// being written to; every other write to argReg loses it.
					Address from = argumentReloadSource(instr, reg);
					holdsArgument = straightLine && from != null && argumentCells.contains(from);
				}
				// Anything else that touches the stack pointer (TXS, or a PHX/PLX-style push on a
				// variant that has one) desynchronises the depth, so stop believing the model
				// rather than let a later PLA pop the wrong entry.
				if (stackPointer == null || writesStackPointer(instr, stackPointer)) {
					straightLine = false;
				}
			}
			// A branch or jump means the walk's straight line is not necessarily a real path, so
			// a PLA after it cannot be trusted to pair with a PHA before it. Plain clobber
			// detection is unaffected and stays conservative.
			if (instr.getFlows().length > 0) {
				straightLine = false;
				argumentCells.clear();
			}
			cursor = instr.getMaxAddress().next();
			if (cursor == null) {
				return false; // ran off the end of the space before reaching firstSite
			}
		}
		return cursor.equals(firstSite) && holdsArgument;
	}

	/**
	 * The byte the helper puts into {@code reg} itself, for the case where
	 * {@link #argumentSurvivesPrologue} has just proved the CALLER's byte does not reach the
	 * first switch site (grm-cxb).
	 * <p>
	 * <b>Declining is not the only honest answer there.</b> Something reaches that site, and once
	 * the caller's value is ruled out it can only have come from inside the helper. Kid Icarus's
	 * {@code FUN_eb07} is the shape that makes this worth doing:
	 * <pre>
	 *   eb07  LDA #$0F       ; the helper supplies its OWN value
	 *   eb09  STA $9FFF      ; firstSite -- $9FFF decodes to MMC1 target 0, Control
	 *   eb0c  LSR A / STA $9FFF / ...
	 * </pre>
	 * It takes no argument at all, and {@code 0x0F} commits {@code mirroring=3, prg_mode=3}. But a
	 * chain helper never has a {@code constState} -- writes 1-4 of a chain echo the in-state and
	 * write 5 commits, so {@link #findHelpers}' multi-site disagreement rule nulls it, by design
	 * -- so every one of them is routed through per-call recovery, where the prologue guard sees
	 * that {@code LDA #$0F} clobber and declines. Scanning here recovers the answer the helper's
	 * own body already knows: {@code SerialShiftBankSwitchStrategy.computeSwitch} resolves exactly
	 * this byte, from exactly this instruction, when it evaluates the chain's commit.
	 * <p>
	 * <b>The caller's registers are passed as explicitly UNKNOWN</b>, not omitted. The scan must
	 * stop at {@code entry} -- otherwise it walks back into whatever code physically precedes the
	 * helper and reads it as a prologue -- but it must also not adopt the caller's values there,
	 * because the whole reason we are here is that those values provably do not survive.
	 * {@link RegisterEnv} carries both halves of that: the stop address, and what to believe at
	 * it.
	 * <p>
	 * Bionic Commando's {@code FUN_dca8} ({@code LDA $65}) still declines, on its own merits: the
	 * scan reaches a RAM load it cannot resolve and returns unknown. That is the difference this
	 * whole area turns on -- a helper that supplies a CONSTANT is knowable, one that supplies a
	 * RAM read is not, and neither has anything to do with the caller.
	 * <p>
	 * <b>This is now the LAST resort, not the only one</b> (bead grm-67g):
	 * {@link #recoverCallArgument} tries {@link #inboundArgumentCell} first, so a RAM load whose
	 * cell the CALLER wrote is answered there. The {@code FUN_dca8} decline therefore stands only
	 * where no caller stored to {@code $65} in the same basic block -- which is the honest
	 * refinement, since "the helper reads RAM" was never the real question. "Whose byte is in that
	 * RAM" is.
	 */
	private static BankState valueSuppliedInsideHelper(Program program, HelperModel helper,
			char reg, int stateMask) {
		Address readAt = helperValueSite(helper);
		Instruction site = readAt == null ? null : program.getListing().getInstructionAt(readAt);
		if (site == null) {
			return BankState.unknown();
		}
		RegisterEnv insideOnly = new RegisterEnv(insideHelperEntry(helper), BankState.unknown(),
			BankState.unknown(), BankState.unknown());
		return StoredValueScanner.resolveStoredValue(program, site, reg, BankState.unknown(),
			stateMask, NO_HOOKS, insideOnly);
	}

	/**
	 * The site at which this helper's mechanism CONSUMES the byte in {@code argReg} -- which of a
	 * multi-write helper's sites is the one whose value ends up in the tracked field (bead
	 * grm-67g).
	 * <p>
	 * WHICH site that is, is the strategy's call and not a constant. For every single-site
	 * mechanism {@code firstSite} and {@code switchSite} are the same instruction and the question
	 * does not arise; the two multi-site shapes want opposite answers, and select-data reading
	 * {@code firstSite} is what shipped smb3's confident wrong {@code r7=7} -- {@code firstSite}
	 * there holds the {@code $8000} register-SELECT byte, not the bank. See
	 * {@link BankSwitchStrategy#suppliesHelperValueAtFirstSite}.
	 * <p>
	 * <b>This is NOT the same bound as {@link #argumentSurvivesPrologue}'s</b>, which is
	 * emphatically {@code firstSite} for every strategy -- and the two are consistent rather than
	 * in tension. That predicate asks whether the CALLER's byte is still in the register when the
	 * mechanism starts, and a serial-shift chain clobbers A four times between its first write and
	 * its last BY DESIGN, so walking to {@code switchSite} there would decline every serial-shift
	 * helper on the planet. The clobbers that make that true all fall AFTER {@code firstSite}, so
	 * for serial-shift this method answers {@code firstSite} too and both walks stop short of
	 * them. One selector therefore serves both multi-site shapes without a special case.
	 * <p>
	 * Two consumers: {@link #valueSuppliedInsideHelper} (what the helper's own body puts in the
	 * register) and {@link #inboundArgumentCell} (what cell the caller's byte arrives in). Same
	 * question, different storage class.
	 */
	private static Address helperValueSite(HelperModel helper) {
		return helper.strategy() == null || helper.strategy().suppliesHelperValueAtFirstSite()
				? helper.firstSite()
				: helper.switchSite();
	}

	/**
	 * Where a backward scan that runs INSIDE the helper must stop -- the address control
	 * arrived at in the body that actually contains {@code firstSite}.
	 * <p>
	 * For every ordinary helper, and for a pass-through wrapper, that is {@code entry}: the
	 * wrapper is address-contiguous with the helper, so one body's worth of addresses runs from
	 * {@code entry} to {@code firstSite} and stopping at {@code entry} is right. For a CALL-EDGE
	 * wrapper it is emphatically not: {@code entry} is the WRAPPER's, while {@code firstSite}
	 * lives in the wrapped helper, and the addresses between them are the wrapper's own tail.
	 * A scan bounded by the wrapper's entry would run off the helper's entry, walk backwards
	 * through that tail, and read instructions the call never executed as the helper's prologue
	 * -- the precise hazard {@link #valueSuppliedInsideHelper}'s javadoc already warns about for
	 * the unbounded case.
	 * <p>
	 * Two consumers: {@link #valueSuppliedInsideHelper}'s {@link RegisterEnv} stop address, and
	 * the one {@link #recoverCallArgument} hands {@link #callSiteRegisters} for
	 * {@link BankSwitchStrategy#depositHelperArgument}'s mini-inlining.
	 * <p>
	 * <b>For a pass-through wrapper, contiguity makes the walk POSSIBLE but does not make this
	 * stop REACHABLE</b> (bead grm-k90) -- the gap in the paragraph above, and the whole of
	 * Contra's defect. The addresses do run linearly from {@code entry} to {@code firstSite}, so
	 * the answer here is right; what the argument omits is that the WRAPPED helper's own entry
	 * sits on that line and is a control-flow join, because the callers who bypass the wrapper
	 * jump straight to it. {@code StoredValueScanner}'s join refusal fires there and the scan
	 * returns unknown two instructions short of this stop. That is repaired by licensing exactly
	 * that one join rather than by moving the stop -- see {@link #crossableWrapperJoin}, which
	 * also records why moving it would have been the worse fix.
	 */
	private static Address insideHelperEntry(HelperModel helper) {
		return helper.relay() == null ? helper.entry() : helper.relay().calleeEntry();
	}

	/**
	 * How many instructions {@link #restoresEntryBank} will walk before giving up. A save/restore
	 * trampoline is a dozen instructions of frame around one inner call; a body that has not
	 * reached its own restore in this many is not the idiom, whatever else it is.
	 */
	private static final int MAX_TRAMPOLINE_SCAN = 64;

	/**
	 * Whether this helper's net effect on the tracked bank field is NOTHING, because it saves the
	 * live bank on entry, switches, calls out, and puts the saved bank back before returning
	 * (bead grm-mej.3). When true, a call to it deposits {@code ownedMask = 0} -- a verified
	 * no-op -- instead of the honest-but-pessimistic unknown that poisons the caller's state and
	 * raises a warning at every call site.
	 * <p>
	 * Ironsword/Wizards &amp; Warriors 2's {@code FUN_ffc0} is the shape, transcribed byte-exact in
	 * {@link MemoryLatchBankSwitchStrategy}'s {@code depositHelperArgument}:
	 * <pre>
	 *   FFC4: LDA $C5 / PHA       ; save the CURRENT bank shadow
	 *   FFC7: AND #$18 / ORA $C3 / STA $C5
	 *   FFCD: STA $8000           ; COMMIT -- switch to the requested bank
	 *   FFD0: JSR $FFDA           ; run the target routine IN that bank
	 *   FFD3: PLA / STA $C5
	 *   FFD6: STA $8000           ; RESTORE -- the saved shadow goes back  &lt;- switchSite
	 * </pre>
	 * The requested bank is live only for the inner call; by the time the caller resumes, the old
	 * bank is back. That is why {@code argValue} is the one answer definitely wrong here, and why
	 * this predicate is about a RELATION ("what comes out equals what went in") rather than a
	 * value -- no value domain is needed, and none is used.
	 * <p>
	 * <b>What makes the pushed byte the ENTRY bank</b> is grm-mej.2, which is exactly why this bead
	 * was blocked on it: {@code $C5} is a derived {@link BankMirrors.Kind#WRITE_THROUGH} mirror, so
	 * a load of it BEFORE any mechanism write reads the bank that was live on entry. A load after
	 * one reads the bank the helper just installed, which is a different claim entirely -- hence
	 * {@code sawMechanismWrite}. {@link BankMirrors.Kind#SAVE_SLOT} and {@link BankMirrors.Kind#INPUT}
	 * are refused for the H2 reason: they hold a bank that is deliberately NOT the live one.
	 * The composite-shadow detail handles itself -- {@code $C5}'s bits 3-4 are VRAM/mirroring, and a
	 * mirror only ever speaks for the tracked field bits, which is precisely the scope of the claim.
	 * <p>
	 * <b>CROSSING THE INNER CALL IS AN ARGUMENT, NOT AN ASSUMPTION, and the distinction is the
	 * whole soundness case.</b> The tempting phrasing is "assume a called subroutine is
	 * stack-balanced", which fails SILENTLY when it is false: the pop would report "this is the
	 * entry bank" while the hardware pulls some other byte, and {@code ownedMask = 0} emits neither
	 * a comment nor a warning. It does not need to be assumed. The pushed byte sits BELOW the
	 * return address, and {@code RTS} pops exactly the two bytes at {@code SP+1,SP+2}. A callee
	 * whose net stack delta at its {@code RTS} is non-zero pops the wrong bytes as a return address
	 * and lands somewhere other than the instruction after the {@code JSR} -- so the restore never
	 * runs. <b>Reaching the fall-through is itself the witness that the callee was balanced and the
	 * slot is intact.</b> A callee that resets {@code SP} with {@code TXS} is covered by the same
	 * argument: it does not then {@code RTS} back to you. An NMI/IRQ arriving mid-span pushes three
	 * bytes and {@code RTI} pops them. The claim is therefore conditional in exactly the way all
	 * dataflow here is -- <em>if this path executes, the callee was balanced</em>.
	 * <p>
	 * <b>Analysing the callee is not an alternative</b>, and it is worth saying so because it is the
	 * obvious next idea. Ironsword's inner call is {@code JSR $FFDA -> JMP ($00C1)}, an indirect
	 * jump into arbitrary game code: any guard that inspects the callee (no {@code TXS} in its body,
	 * balanced push/pull counts) declines here, so the payoff evaporates and the guard buys nothing
	 * the return-mechanism argument has not already given.
	 * <p>
	 * <b>The one shape this cannot see</b>, and it is far narrower than "an unbalanced callee": a
	 * routine that BOTH returns to the fall-through AND consumed the slot beneath its own return
	 * address -- i.e. popped the return address, ran, and deliberately pushed the caller's address
	 * back. That is constructed behaviour, not incidental imbalance.
	 * <p>
	 * <b>The deliberate unbalanced constructions that DO occur are handled, and not by this
	 * argument.</b> 6502 code routinely jumps by pushing {@code target-1} and executing
	 * {@code RTS} ({@code LDA #hi / PHA / LDA #lo / PHA / RTS} -- the standard indirect-jump and
	 * jump-table idiom). Inside a CALLEE it is covered above: such a routine does not return to
	 * our fall-through, so the conditional claim never applies to it. Inside THIS helper's body it
	 * is over-determined -- {@code RTS}'s own p-code decrements the stack pointer, so the
	 * {@code writesStackPointer} guard declines it before the fall-through requirement is even
	 * reached. The shape that genuinely needs the fall-through requirement is an UNRESOLVED
	 * computed jump, which writes no stack pointer and names no flow target; see the comment at
	 * that guard.
	 * <p>
	 * Everything else is refused rather than modelled. Any branch or jump abandons the walk, because
	 * "restored" is a claim that points the UNSAFE way if a path could skip the restore; a
	 * {@code PLA} with nothing pushed, a stack-pointer write, an indirect call, and a call with no
	 * fall-through all end it. Computed once per helper after mirror derivation -- never inside the
	 * fixpoint, where it would be a whole-body walk per dequeue per call site.
	 *
	 * @param switchSites every recognized mechanism-write address from pass 1
	 */
	// Package-private (not private) so BankSaveRestoreTrampolineProgramTest can call this
	// directly with a hand-built HelperModel; see the visibility note on HelperModel itself.
	static boolean restoresEntryBank(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites) {
		Address switchSite = helper.switchSite();
		if (switchSite == null || mirrors.isEmpty()) {
			return false;
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			return false; // cannot verify the depth model -> do not assume the favorable answer
		}
		Listing listing = program.getListing();
		// One entry per byte this walk watched being pushed, true when that byte IS the bank that
		// was live on entry.
		Deque<Boolean> saved = new ArrayDeque<>();
		boolean holdsEntryBank = false;
		boolean sawMechanismWrite = false;

		Address cursor = insideHelperEntry(helper);
		for (int i = 0; i < MAX_TRAMPOLINE_SCAN; i++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return false;
			}
			if (cursor.equals(switchSite)) {
				// The restore itself. It commits A, so the helper is a verified no-op exactly when
				// A holds the bank that was live on entry.
				Character stored = StoredValueScanner.storeRegister(instr);
				return holdsEntryBank && stored != null && stored.charValue() == 'A';
			}

			boolean modelled = true;
			switch (instr.getMnemonicString().toUpperCase()) {
				case "PHA" -> saved.push(holdsEntryBank);
				case "PLA" -> {
					if (saved.isEmpty()) {
						return false; // popping the caller's frame, or a depth this walk lost
					}
					holdsEntryBank = saved.pop();
				}
				// PHP/PLP are modelled ONLY to keep the depth honest, so an interleaved status
				// push cannot make a later PLA pop the wrong byte. A status byte is never a bank.
				case "PHP" -> saved.push(Boolean.FALSE);
				case "PLP" -> {
					if (saved.isEmpty()) {
						return false;
					}
					saved.pop();
				}
				default -> modelled = false;
			}

			if (!modelled) {
				if (instr.getFlowType().isCall()) {
					// The inner call. Allowed, and the pushed slot survives it -- see the javadoc's
					// return-mechanism argument. Two guards first, because that argument is void
					// when control demonstrably does not come back: a computed call gives no
					// fall-through reasoning at all, and a missing fall-through is Ghidra saying
					// the callee does not return.
					if (instr.getFlowType().isComputed() || instr.getFallThrough() == null) {
						return false;
					}
					holdsEntryBank = false; // the callee may clobber A; the stack slot is what carries
					cursor = instr.getFallThrough();
					continue;
				}
				if (switchSites.contains(instr.getMinAddress())) {
					sawMechanismWrite = true;
				}
				Address from = argumentReloadSource(instr, 'A');
				if (!sawMechanismWrite && from != null && isLiveBankMirror(mirrors, from)) {
					holdsEntryBank = true;
				}
				else if (StoredValueScanner.modifiesRegister(instr, 'A')) {
					holdsEntryBank = false;
				}
				if (writesStackPointer(instr, stackPointer)) {
					return false;
				}
				// The walk may only advance along a REAL fall-through, and the test is stated that
				// way round on purpose: "has no outgoing flows" is not the same property and does
				// not cover an UNRESOLVED computed jump, which writes no stack pointer and names
				// no flow target, so every other guard here is blind to it. Left to a flows-based
				// test the walk would march straight past one into code that is not on this path
				// and could find a PLA or the restore site sitting there.
				//
				// Requiring a fall-through refuses that plus resolved jumps and conditional
				// branches (whose other edge could skip the restore, making "no-op" confidently
				// wrong). Note the 6502 push-target-and-return idiom -- LDA #hi / PHA / LDA #lo /
				// PHA / RTS, the ordinary way this CPU does an indirect jump -- is caught here
				// too, but it is over-determined rather than a case for this guard: RTS's own
				// p-code decrements SP, so writesStackPointer above already declines it. Do not
				// read the test that covers it as pinning this line specifically.
				if (instr.getFlows().length > 0 || instr.getFallThrough() == null) {
					return false;
				}
			}
			cursor = instr.getFallThrough();
			if (cursor == null) {
				return false; // a modelled stack op with no fall-through: off the line, decline
			}
		}
		return false;
	}

	/**
	 * Whether a load of {@code addr} reads the bank that is live right now. Only
	 * {@link BankMirrors.Kind#WRITE_THROUGH} and {@link BankMirrors.Kind#ROM_IDENTIFYING} do --
	 * the same two kinds the strategies answer from tracked state, and for the same H2 reason.
	 */
	private static boolean isLiveBankMirror(BankMirrors mirrors, Address addr) {
		return mirrors.is(addr, BankMirrors.Kind.WRITE_THROUGH) ||
			mirrors.is(addr, BankMirrors.Kind.ROM_IDENTIFYING);
	}

	/**
	 * One half-open, linear-by-address stretch {@code [from, to)} of the prologue a call runs
	 * before the helper's mechanism reads its argument (bead grm-2dr increment 2).
	 * <p>
	 * Package-private so a Tier 2 test can construct one; {@code BoardBankAnalyzer}'s own
	 * records are private, which is what kept increment 1's wrapper tests at the predicate
	 * level.
	 */
	record PrologueSegment(Address from, Address to) {}

	/**
	 * {@link #argumentSurvivesPrologue} over a prologue that is more than one contiguous span:
	 * a literal AND, evaluating each segment independently (bead grm-2dr increment 2).
	 * <p>
	 * <b>The single-segment case is byte-for-byte unchanged</b> -- same method, same body, same
	 * answer -- because a one-element list delegates once and returns exactly what the three-
	 * address form returns. Only a call-edge wrapper ever supplies two.
	 * <p>
	 * <b>Resetting the save/restore model between segments is deliberate, and it errs in the
	 * safe direction.</b> Each delegated call starts with fresh {@code holdsArgument},
	 * {@code saved}, {@code argumentCells} and {@code straightLine}, so a {@code PHA} in
	 * segment 1 cannot pair with a {@code PLA} in segment 2, and a cell the argument was stored
	 * to in segment 1 cannot make a segment-2 load read as a restore. Both refusals
	 * UNDER-approximate survival, so the cost is at most a missing annotation -- never a
	 * confidently wrong bank, which this engine treats as strictly worse. blmaster is
	 * unaffected either way: its {@code STA $DB} and {@code LDA $DB} both live in segment 1.
	 * <p>
	 * An EMPTY segment ({@code from.equals(to)}) is trivially true, and that is load-bearing
	 * rather than incidental: the loop's bound test is {@code cursor < to}, so it never
	 * executes and the method returns {@code cursor.equals(to) && holdsArgument}. That is
	 * exactly blmaster's second segment, since {@code FUN_e63c}'s {@code STA $FFFF} IS its entry
	 * instruction and so its {@code entry} and {@code firstSite} coincide.
	 * <p>
	 * An EMPTY LIST is false, not vacuously true -- there is no prologue to have proved
	 * anything about, and returning true there would hand a strategy a caller's byte on no
	 * evidence at all.
	 */
	static boolean argumentSurvivesPrologue(Program program, List<PrologueSegment> segments,
			char reg) {
		if (segments.isEmpty()) {
			return false;
		}
		for (PrologueSegment segment : segments) {
			if (!argumentSurvivesPrologue(program, segment.from(), segment.to(), reg)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The stretches of code a call into {@code helper} runs before its mechanism reads the
	 * argument: one span for an ordinary helper, two for a call-edge wrapper.
	 * <p>
	 * DERIVED, not stored on {@link HelperModel}. It is a pure function of {@code entry},
	 * {@code firstSite} and {@code relay}, all already on the record; storing it would duplicate
	 * state that {@link HelperModel#atMidBodyEntry} and
	 * {@link HelperModel#atFallThroughWrapper} re-key underneath, and would drag a list into the
	 * record's equality.
	 * <p>
	 * <b>Why passing the relay's call site as segment 1's END bound does not trip
	 * {@link #argumentSurvivesPrologue}'s own {@code isCall()} rejection.</b> That loop's bound
	 * test is {@code cursor.compareTo(to) < 0}, so it STOPS BEFORE INSPECTING the instruction at
	 * {@code to} -- the relay {@code JSR} is the boundary, never a walked instruction. This
	 * looks like an accident and is not: it is the whole reason segmenting works without
	 * touching the predicate.
	 */
	private static List<PrologueSegment> prologueSegments(HelperModel helper) {
		if (helper.relay() == null) {
			return List.of(new PrologueSegment(helper.entry(), helper.firstSite()));
		}
		return List.of(new PrologueSegment(helper.entry(), helper.relay().callSite()),
			new PrologueSegment(helper.relay().calleeEntry(), helper.firstSite()));
	}

	/**
	 * The address {@code instr} reloads {@code reg} from, when it is a plain load whose target is
	 * statically certain -- the memory half of {@link #argumentSurvivesPrologue}'s save/restore
	 * model, and the load-side predicate of {@link #inboundArgumentCell}. Null for anything else,
	 * including an immediate load (no address operand at all) and an indexed one
	 * ({@link StoredValueScanner#plainAbsoluteTarget} refuses those, since their target is
	 * runtime-dependent).
	 */
	private static Address argumentReloadSource(Instruction instr, char reg) {
		if (!("LD" + reg).equals(instr.getMnemonicString())) {
			return null;
		}
		return StoredValueScanner.plainAbsoluteTarget(instr);
	}

	/**
	 * The memory cell a helper takes its argument IN, when the caller passes the bank through RAM
	 * rather than in a register (bead grm-67g) -- or null when no such cell is provable.
	 * <p>
	 * <b>The claim.</b> If the helper's LAST write to {@code reg} before its value-consuming site
	 * is a plain load from cell C, and nothing between the entry and that site could have written
	 * C, then C still holds what the CALLER put there. C is therefore an inbound argument, and its
	 * value must be resolved at the CALL SITE ({@link StoredValueScanner#callerCellValue}) rather
	 * than by scanning for {@code reg} there.
	 * <p>
	 * <b>This is the exact dual of {@link #argumentSurvivesPrologue}'s {@code argumentCells}
	 * set</b>, and the two are MUTUALLY EXCLUSIVE by construction. That set admits C only when the
	 * HELPER stores {@code reg} into it (a save/restore across the prologue); this admits C only
	 * when the helper NEVER stores to it. So a helper cannot satisfy both, which is why the order
	 * in which {@link #recoverCallArgument} tries them is not a judgement call -- hoisting this
	 * above the survives-prologue test could not change an answer, only cost a walk.
	 * <p>
	 * <b>Worked example</b>, smb3's {@code FUN_ffc2} with {@code reg == 'A'} and the value site at
	 * {@code $FFC7} (select-data consumes at {@code switchSite}, not {@code firstSite}):
	 * <pre>
	 *   ffc2  LDA #$47      ; clears cell -- an immediate is not a reload
	 *   ffc4  STA $0721     ; lands in `written`, and PROVES a different cell than $0720
	 *   ffc6  STA $8000     ; firstSite, walked THROUGH: the select byte is not the bank
	 *   ffc7  LDA $0720     ; sets cell = $0720   &lt;- the answer
	 *   ffc9  STA $8001     ; the value site; walk stops here
	 * </pre>
	 * The caller side then finishes it: {@code ca23 LDA #$1b / STA $0720 / JSR $ffc2} resolves
	 * {@code $0720} to {@code $1b = 27}. And the counter-example {@code written} exists for is one
	 * instruction away -- a helper whose {@code $FFC4} were {@code STA $0720} would be supplying
	 * its OWN byte, and without that set this would confidently ship {@code $47} as the bank,
	 * which is the very number the regression this bead tracks shipped.
	 * <p>
	 * <b>Not a restoration of anything.</b> smb3's correct {@code r7=27/26} predates the prologue
	 * guard, but it was never sourced from the shadow: {@code local} was simply the caller-side
	 * REGISTER scan, and {@code LDA #$1b / STA $0720 / JSR} happens to leave {@code $1b} still in
	 * A. That is luck the idiom happens to grant, not a mechanism. This rule reaches the same
	 * number for a sound reason, and keeps reaching it when the caller's A is clobbered.
	 * <p>
	 * <b>The bound is {@link #helperValueSite}, not {@code firstSite}</b> -- see that method for
	 * why the two predicates want opposite-looking bounds for the same underlying reason.
	 * <p>
	 * <b>{@link #insideHelperEntry}, not the function's entry point.</b> Bionic Commando's
	 * {@code FUN_dca8} ({@code LDA $65 / STA $E000}) is a real inbound-cell helper when entered at
	 * {@code $DCA8}; entered mid-body at {@code $DCAA} the walk starts past the load, finds no
	 * reload, and correctly returns null -- one function, two answers, exactly as
	 * {@link #argumentSurvivesPrologue} documents for its own walk. It also means a FALL-THROUGH
	 * wrapper's prefix IS walked, which matters more than it looks: {@code isPassThroughInto}
	 * forbids a wrapper from writing the MECHANISM but not from writing ordinary RAM, so a
	 * wrapper containing {@code STA $0720} is admissible and only the walk starting at the
	 * wrapper's entry catches it.
	 * <p>
	 * <b>A CALL-EDGE wrapper declines outright.</b> There {@link #insideHelperEntry} is the
	 * relay's callee entry, so the walk would cover only the second prologue segment and never see
	 * the wrapper's own prefix. blmaster's shape is the counterexample: a wrapper doing
	 * {@code STA $22 / LDA $22 / JSR helper} in front of a helper whose body begins {@code LDA $22}
	 * would look like an inbound cell, and the value would be resolved at the JSR INTO THE WRAPPER
	 * -- i.e. the byte the wrapper was about to overwrite. Stale, confident, wrong. Today the
	 * branch that calls this is unreachable for a relay model at all ({@code findCallEdgeWrappers}
	 * uses {@link #argumentSurvivesPrologue} as its ADMISSION gate, so every relay helper in the
	 * map already answers true there), so this guard is defensive -- but the invariant is one
	 * refactor away from moving. A generalization over {@link #prologueSegments} must NOT reset
	 * {@code written} per segment the way {@link #argumentSurvivesPrologue} resets its shadow
	 * stack: that reset under-approximates and errs safe, while forgetting the wrapper's
	 * {@code STA $22} errs the unsafe way. Same segment list, opposite discipline.
	 * <p>
	 * <b>Every flow declines here</b>, where {@link #argumentSurvivesPrologue} merely stops
	 * trusting its save/restore model. A branch costs that predicate a fold; here it would let a
	 * linear-by-address walk skip a write to C, or count one that never executes, and both point
	 * the unsafe way.
	 * <p>
	 * <b>{@link StoredValueScanner#writesMemory}, not {@code writesAddress}.</b> The reference-only
	 * test under-reports (an indirect store has no concrete result address, refless stores exist,
	 * and the read-modify-write mnemonics are invisible to {@code storeRegister}). In the
	 * save/restore model a missed write is bounded by {@code holdsArgument}; here it is directly a
	 * confident wrong bank.
	 *
	 * <b>A cell in the live part of the stack page is refused</b> ({@link StackFloor}). This walk
	 * is the one place where the hazard is not hypothetical: the caller reached {@code entry}
	 * through a {@code JSR}, which pushed two bytes, and neither that nor a {@code PHA} inside
	 * the range is visible to {@link StoredValueScanner#writesMemory}. Unlike the other two
	 * consumers of the floor, a wrong answer here is a confident wrong bank rather than a
	 * forfeited forward, so the guard matters most here even though the code is smallest.
	 *
	 * @param entry     where control actually arrives -- {@link #insideHelperEntry}
	 * @param valueSite where the mechanism consumes the byte -- {@link #helperValueSite}
	 */
	static Address inboundArgumentCell(Program program, Address entry, Address valueSite, char reg) {
		if (entry == null || valueSite == null || entry.compareTo(valueSite) > 0) {
			return null;
		}
		Register register = program.getLanguage().getRegister(String.valueOf(reg));
		if (register == null) {
			return null; // cannot ask the question -> do not assume the favorable answer
		}
		Listing listing = program.getListing();
		// The cell reg was LAST plainly loaded from, or null when reg's current value came from
		// anywhere else. Set and cleared by the same statement, which is the whole trick.
		Address cell = null;
		// Every address this walk saw written, accumulated over the WHOLE range rather than tested
		// as we go: in FUN_ffc2 the STA $0721 precedes the LDA $0720 that names the cell, so a
		// check applied only after the load would miss a store in the same position.
		Set<Address> written = new LinkedHashSet<>();
		Address cursor = entry;
		while (cursor.compareTo(valueSite) < 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || instr.getFlowType().isCall() || instr.getFlowType().isTerminal() ||
				instr.getFlows().length > 0) {
				return null;
			}
			Address fallThrough = instr.getFallThrough();
			Address next = instr.getMaxAddress().next();
			if (next == null || fallThrough == null || !fallThrough.equals(next)) {
				return null; // a gap, an override, or the end of the space -- not one linear path
			}
			if (StoredValueScanner.writesMemory(instr)) {
				Address target = StoredValueScanner.effectiveOperandTarget(program, instr, NO_HOOKS,
					RegisterEnv.NONE);
				if (target == null) {
					return null; // a write this scanner cannot place may have landed on the cell
				}
				written.add(target);
			}
			if (StoredValueScanner.writesRegister(instr, register)) {
				cell = argumentReloadSource(instr, reg);
			}
			cursor = next;
		}
		// StackFloor: the caller's own JSR pushed a return address, and any PHA in the range was
		// stepped over as inert, both at addresses writesMemory cannot name. A cell at or above
		// the floor may therefore have been clobbered between the caller's store and this load.
		// (The null-cell case reaches mayAliasStack's "unplaceable reads as unsafe" answer and
		// would be rejected by the cell != null test below regardless -- same verdict either way.)
		return cursor.equals(valueSite) && cell != null && !written.contains(cell) &&
			!StackFloor.mayAliasStack(program, cell) ? cell : null;
	}

	/** {@link #inboundArgumentCell} asked of a helper model; null for a call-edge wrapper. */
	private static Address inboundArgumentCell(Program program, HelperModel helper, char reg) {
		if (helper.relay() != null) {
			return null;
		}
		return inboundArgumentCell(program, insideHelperEntry(helper), helperValueSite(helper), reg);
	}

	/**
	 * Whether {@code instr} moves the stack pointer, for {@link #argumentSurvivesPrologue}'s
	 * shadow stack.
	 * <p>
	 * <b>Compared by BASE register, not by identity.</b> The 6502 declares the stack pointer
	 * twice over the same bytes -- a two-byte {@code SP} and a one-byte {@code S} -- and
	 * {@code CompilerSpec.getStackPointer()} answers one while {@code TXS}'s p-code writes the
	 * other. An {@code equals} test (which is what {@link StoredValueScanner#writesRegister}
	 * deliberately does, and must keep doing for A/X/Y) therefore reports that {@code TXS} does
	 * not touch the stack, and the shadow stack would go on trusting a depth that had just moved
	 * underneath it. Measured, not theorised: the {@code TXS} case was the one unit test that
	 * failed on the identity comparison.
	 * <p>
	 * Package-private for a second consumer (grm-mej.3 increment 2):
	 * {@code StoredValueScanner.findMatchingPush} needs the identical base-register-aware test
	 * for its own PHA/PLA depth pairing, over a BACKWARD walk rather than this method's forward
	 * one. Reused verbatim rather than reimplemented so the two walks cannot silently drift apart
	 * on what "moves the stack pointer" means.
	 */
	static boolean writesStackPointer(Instruction instr, Register stackPointer) {
		Register wanted = stackPointer.getBaseRegister();
		for (Object o : instr.getResultObjects()) {
			if (o instanceof Register r && wanted.equals(r.getBaseRegister())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * What A, X and Y hold at {@code callInstr}, packaged with {@code entryAddr} (the called
	 * helper's entry) as the address a backward scan started inside that helper must stop at.
	 * This is what makes {@link BankSwitchStrategy#depositHelperArgument}'s mini-inlining
	 * possible without any input-register discovery: the scan inside the helper is
	 * demand-driven, so supplying all three registers and letting it pull whichever it actually
	 * reads is both simpler and strictly more capable than deducing an argument convention
	 * (grm-hum increment 2 -- Contra's helper takes its bank in Y while {@link #findHelpers}
	 * can only see the {@code STA}'s A).
	 * <p>
	 * <b>Masked to {@code 0xFF}, deliberately not to the mechanism's {@code stateMask}.</b> An
	 * index register is not the mechanism's field: Contra's UxROM latch has {@code mask: 0x0F},
	 * and narrowing Y to four bits would truncate the very index used to read the bank table.
	 * {@code argValue}'s {@code stateMask} narrowing in {@link #recoverCallArgument} is a
	 * different question (the field value itself) and keeps it.
	 * <p>
	 * {@link #NO_HOOKS} is used because the scan runs in the CALLER, outside any mechanism's
	 * interpretation: the caller's mechanism writes are not this helper's, and no strategy's
	 * load resolution applies to a register the caller is merely setting up. A register the
	 * scan cannot pin down comes back {@link BankState#unknown()}, which is what keeps a
	 * RAM-sourced argument honestly unresolved instead of guessed.
	 * <p>
	 * <b>Each register is then filtered by whether it SURVIVES the prologue</b> (bead grm-k90).
	 * The three scans above run in the caller and answer "what did the caller leave here"; the
	 * env claims something stronger -- "what holds at {@code entryAddr}" -- and for a WRAPPER
	 * model those differ, because the wrapper's own body runs in between and nothing forbids it
	 * writing X or Y ({@link #isPassThroughInto} admits an {@code LDX #imm} without blinking).
	 * {@link #argumentSurvivesPrologue(Program, List, char)} over {@link #prologueSegments} is
	 * exactly the question, so it is asked ONCE PER REGISTER rather than once for
	 * {@link HelperModel#argReg}, and a register that does not survive is handed back as
	 * {@link BankState#unknown()} instead of the caller's stale value. Per-register is the whole
	 * point: on Contra's {@code FUN_c139} A does not survive ({@code LDA $8000}) while Y does,
	 * and Y is the one the latch consumes -- running the test on {@code argReg} alone would let
	 * a clobber of a register nobody reads suppress a correct recovery.
	 * <p>
	 * For an ordinary helper this cannot change an answer that was already right: the scan
	 * inside the helper walks that same prologue itself and meets any clobber before it reaches
	 * the stop. It is LOAD-BEARING for a CALL-EDGE wrapper, where the scan stops at
	 * {@code relay.calleeEntry()} and the wrapper's prefix is never walked at all -- that is the
	 * soundness hole this bead was originally filed on, and it is closed here rather than by
	 * forcing X/Y to unknown for wrapper models wholesale (considered and rejected in grm-2dr
	 * increment 2 as strictly less precise).
	 * <p>
	 * {@code crossableJoin} is passed through untouched; see {@link #crossableWrapperJoin} for
	 * where it comes from and {@link RegisterEnv} for why crossing it is sound.
	 */
	private static RegisterEnv callSiteRegisters(Program program, Instruction callInstr,
			Address entryAddr, Address crossableJoin, HelperModel helper) {
		List<PrologueSegment> prologue = prologueSegments(helper);
		return new RegisterEnv(entryAddr, crossableJoin,
			surviving(program, callInstr, 'A', prologue),
			surviving(program, callInstr, 'X', prologue),
			surviving(program, callInstr, 'Y', prologue));
	}

	/**
	 * What the caller left in {@code reg}, or {@link BankState#unknown()} when the helper's
	 * prologue does not preserve it as far as the site that reads it -- one register's worth of
	 * {@link #callSiteRegisters}' filter (bead grm-k90).
	 * <p>
	 * The survival test is evaluated FIRST and the scan skipped when it fails, which is a small
	 * efficiency win but mostly a statement of intent: a value that cannot be attributed is not
	 * merely discarded afterwards, it is never derived.
	 */
	private static BankState surviving(Program program, Instruction callInstr, char reg,
			List<PrologueSegment> prologue) {
		if (!argumentSurvivesPrologue(program, prologue, reg)) {
			return BankState.unknown();
		}
		return StoredValueScanner.resolveStoredValue(program, callInstr, reg, BankState.unknown(),
			0xFF, NO_HOOKS);
	}

	/**
	 * The one control-flow join a mini-inline scan for {@code helper} may walk through, or
	 * {@code null} for the overwhelmingly common "none" (bead grm-k90).
	 * <p>
	 * <b>The problem it solves.</b> For a PASS-THROUGH WRAPPER, {@link #insideHelperEntry}
	 * correctly reports the WRAPPER's entry as where control arrived -- but that stop is not
	 * REACHABLE. The scan starts at the switch site, inside the wrapped helper, and the wrapped
	 * helper's own entry lies between it and the stop. That entry is a genuine control-flow join,
	 * because the direct callers who bypass the wrapper jump straight to it, so
	 * {@code StoredValueScanner}'s join refusal fires and the walk dies short of the env. On
	 * Contra this is the entire defect: {@code c0cb LDY #1 / JSR $c13f} resolves because its stop
	 * IS the join and {@code stopsAt} is tested first, while the identical {@code c094 LDY #1 /
	 * JSR $c139} warns because its stop is two instructions further back and the join wins the
	 * race.
	 * <p>
	 * <b>What is nominated.</b> "The entry of the body that actually contains {@code firstSite}"
	 * -- which is what {@link #insideHelperEntry}'s javadoc already claims to compute and, for a
	 * pass-through wrapper, does not. It is taken from the function containing {@code firstSite}
	 * rather than stored on {@link HelperModel} deliberately: {@link HelperModel#atFallThroughWrapper}
	 * overwrites {@code entry} with the wrapper's, so recording the wrapped entry would mean a
	 * new field on a ten-field record, and one that would have to be threaded correctly through a
	 * CHAIN of wrappers. Deriving it gets the chained case right for free -- every outer wrapper
	 * is contiguous with the next and contributes no join of its own, so the function containing
	 * {@code firstSite} is the innermost helper however many wrappers are stacked on it.
	 * <p>
	 * <b>The window test is what keeps it honest</b>, and it is not a formality -- it is the only
	 * thing standing between this and licensing a join nobody proved anything about. The nominee
	 * must lie STRICTLY after {@code scanStop} and at or before {@code firstSite}. Walk the four
	 * model shapes:
	 * <ul>
	 * <li>ORDINARY HELPER: the nominee IS {@code scanStop}, not strictly after it, so
	 * {@code null}. Byte-for-byte no change, which is what lets this land without re-blessing
	 * every golden.</li>
	 * <li>MID-BODY ENTRY (Bionic Commando's {@code $DCAA} inside {@code FUN_dca8}): the nominee is
	 * {@code dca8}, BEFORE the stop, so {@code null}. That case must not regress and structurally
	 * cannot -- the whole point of a mid-body entry is that the prologue was skipped, and
	 * licensing a join behind the stop would walk the scan into exactly the code the call
	 * avoided.</li>
	 * <li>PASS-THROUGH WRAPPER (Contra): {@code c139 < c13f <= c142}. Nominated. This is the
	 * fix.</li>
	 * <li>CALL-EDGE WRAPPER: {@code scanStop} is {@code relay.calleeEntry()}. If the wrapped model
	 * is itself a pass-through wrapper the nominee is after it and crossing is licensed by THAT
	 * wrapper's own {@link #isPassThroughInto} proof; otherwise the nominee is the stop and this
	 * returns {@code null}.</li>
	 * </ul>
	 * In every nominated case the span between stop and nominee is a pass-through wrapper's body,
	 * which {@link #isPassThroughInto} has already proved is straight-line, fully disassembled,
	 * mechanism-inert and reached only by unconditional fallthrough. That proof is the licence;
	 * see {@link RegisterEnv}'s class javadoc for why it is sufficient.
	 * <p>
	 * <b>Why the join is crossed rather than the stop simply MOVED to the nominee.</b> Moving it
	 * would have been a smaller change and it is the wrong one. The scan would then stop at the
	 * wrapped helper's entry and adopt {@link #callSiteRegisters}' prologue-FILTERED values,
	 * throwing away whatever the wrapper's own body supplies -- a wrapper of the shape
	 * {@code LDY #3} / fall-through-into-helper would report Y unknown (the filter correctly says
	 * Y does not survive a prologue that writes it) where today's scan reads the {@code LDY #3}
	 * directly. Crossing keeps the walk going through the wrapper's prefix, so its writes and
	 * loads are read natively by the machinery that already knows how, and the filter is left to
	 * do its work only at the true outer stop.
	 * <p>
	 * Takes {@code firstSite} and {@code scanStop} loose rather than a {@link HelperModel},
	 * and is package-private static, for one reason: {@code HelperModel} is private, so a test
	 * that wanted a model could not build one -- the constraint that kept grm-2dr increment 1's
	 * wrapper tests at the predicate level. Same precedent as {@link #argumentSurvivesPrologue}
	 * and {@link #isPassThroughInto}, and the two parameters are the only two the window test
	 * reads anyway.
	 */
	static Address crossableWrapperJoin(Program program, Address firstSite, Address scanStop) {
		if (firstSite == null || scanStop == null) {
			return null;
		}
		Function body = program.getFunctionManager().getFunctionContaining(firstSite);
		if (body == null) {
			return null;
		}
		Address nominee = body.getEntryPoint();
		if (nominee.compareTo(scanStop) <= 0 || nominee.compareTo(firstSite) > 0) {
			return null;
		}
		return nominee;
	}

	/**
	 * A helper call site's positioned effect: {@code state} is the recovered value in the
	 * board's absolute state bits (like {@link SwitchResult#effect}); {@code ownedMask} is
	 * which of those absolute bits this call site is authoritative over -- the mask
	 * {@link BankDataflowEngine#runDataflow} folds {@code state} into via {@link BankDataflowEngine#overwrite}, distinct from
	 * {@code state.knownMask()} for exactly the reason {@link BankSwitchStrategy.HelperDeposit}
	 * documents (a touched-but-unresolved bit is owned and poisoned; an untouched bit is
	 * neither).
	 */
	record CallEffect(BankState state, int ownedMask) {}

	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};

	/**
	 * A helper function's modeled effect: a constant state, or null = caller-supplied. For
	 * caller-supplied helpers, {@code argReg} is the register (A/X/Y) the helper stores into
	 * its mechanism -- i.e. the register by which the caller passes the bank field -- or null
	 * when the helper's switch sites disagree on that register or use a non-{@code ST<reg>}
	 * write, in which case the argument convention is unknown. {@code effectMask}/{@code lsb}
	 * are the mechanism's positioning (or the conservative union of several, when the
	 * helper's sites span more than one mechanism -- see {@link #findHelpers}), used to fold
	 * this helper's effect into only the state bits it actually owns. {@code strategy} is the
	 * matched mechanism's strategy (null when the sites disagree, per {@code findHelpers}'s
	 * degrade case -- unused there since {@code argReg} is also forced null and
	 * {@link #recoverCallArgument} short-circuits before ever consulting {@code strategy});
	 * {@code switchSite} is the recognized switch instruction that
	 * {@link BankSwitchStrategy#depositHelperArgument} is asked to interpret a call site's
	 * argument against.
	 * <p>
	 * <b>What {@code switchSite} MEANS is "the last recognized write on the path to this
	 * helper's RETURN".</b> {@link #findHelpers} implements that as the highest-address site
	 * when a helper's sites span several instructions of the same mechanism -- e.g. a
	 * serial-shift chain's 5 stores all resolve to the same target address here, but for an
	 * idiom where they could legitimately differ, the LAST write is the one whose address
	 * actually decides the target, per {@link SerialShiftBankSwitchStrategy}.
	 * <p>
	 * <b>Max-address is only a PROXY for that meaning, and it is valid only while control
	 * cannot leave the function body.</b> A tail call is exactly when it can: Mega Man's
	 * {@code FUN_d131} contains one site ({@code $D135 STA $C006}, bank 6) and then ends
	 * {@code $D159 JMP $C3B3}, so the bank live at its return is {@code FUN_c3b3}'s 5, not its
	 * own 6. {@link #composeTailCalls} post-processes {@link #findHelpers}' map to repair that
	 * -- composing the callee's effect in where it can, declining where it cannot -- so nothing
	 * downstream ever sees a body-local summary of a helper that tail-calls another one. The
	 * proxy is still a heuristic WITHIN the body (address order is not execution order in
	 * general: a helper whose exit path branches backward to an earlier switch would be
	 * committed to the wrong site by it); nothing shipped does that today, and a helper that
	 * did would need real terminal-site analysis rather than a max().
	 * <p>
	 * <b>{@code entry} is WHERE CONTROL ARRIVED, which is not always {@code function}'s entry
	 * point.</b> A game may jump directly into the middle of a switch routine, deliberately
	 * skipping a prologue that would clobber the argument register -- Bionic Commando's
	 * {@code $D6E2 JMP $DCAA} lands on the first {@code STA $E000} of a 5-write chain, past the
	 * {@code $DCA8 LDA $65} that would have overwritten A. Ghidra keeps {@code $DCAA} mid-body,
	 * so {@code getFunctionContaining} answers {@code FUN_dca8} and a model keyed on the
	 * function alone describes the argument at the WRONG entry. See
	 * {@link #midBodyEntryHelper} for how such an entry is admitted and what it costs.
	 * {@code entry} is also the {@link RegisterEnv} stop address {@link #recoverCallArgument}
	 * hands the mini-inline scan, which must stop where control actually entered.
	 * <p>
	 * {@code firstSite} is the LOWEST-addressed recognized site in the body, the mirror of
	 * {@code switchSite}'s max, and is null in the same degraded cases {@code switchSite} is.
	 * It has two consumers, both of which want "the first thing this body does that matters":
	 * {@link #midBodyEntryHelper}'s admission test (does entering here still run every site?)
	 * and {@link #argumentSurvivesPrologue}'s walk bound (does the caller's argument survive
	 * as far as the site that consumes it?). Together with {@code entry} it delimits exactly
	 * the prologue a given call runs before the mechanism reads its argument -- EXCEPT when
	 * {@code relay} is non-null, which is precisely the case where that stops being one span;
	 * see {@link Relay} and {@link #prologueSegments}.
	 * <p>
	 * <b>{@code relay} is the one field that is not about this helper's own body</b> (bead
	 * grm-2dr increment 2). It is null for every model {@link #findHelpers},
	 * {@link #composeTailCalls} and {@link #findPassThroughWrappers} produce, and non-null only
	 * for a CALL-EDGE wrapper -- a function that writes no mechanism and reaches the real helper
	 * by an interior {@code JSR} rather than by falling through into it. Every other field is
	 * then inherited from the wrapped helper and describes ITS body, while {@code entry}
	 * describes the wrapper's; {@code relay} is what stitches the two together.
	 */
	// Package-private (not private) so BankSaveRestoreTrampolineProgramTest (grm-mej.3
	// increment 1) can construct a HelperModel directly to drive restoresEntryBank -- the
	// established pattern in this file for a helper that a same-package Tier 2 test needs to
	// reach but that has no other production caller outside BoardBankAnalyzer. No behavior
	// change: every other member keeps its own visibility.
	record HelperModel(Function function, Address entry, BankState constState,
			Character argReg, int effectMask, int lsb, BankSwitchStrategy strategy,
			Address switchSite, Address firstSite, Relay relay) {

		/**
		 * This helper re-keyed to a mid-body {@code entry}, with {@code constState} dropped.
		 * <p>
		 * Dropping the constant is the one thing that cannot be reused. A constant is a claim
		 * about what the whole body does when entered at the top, and a mid-body entry is
		 * precisely a path that skipped part of that -- shipping it would ship a wrong bank,
		 * which this engine treats as strictly worse than shipping none. Nulling it routes the
		 * call through {@link #recoverCallArgument}, which re-derives the value from the call
		 * site's own registers. Everything else survives because
		 * {@link #midBodyEntryHelper}'s admission test guarantees the entry still runs the
		 * body's entire recognized site set.
		 */
		HelperModel atMidBodyEntry(Address midBody) {
			return new HelperModel(function, midBody, null, argReg, effectMask, lsb, strategy,
				switchSite, firstSite, relay);
		}

		/**
		 * This helper re-keyed onto a pass-through wrapper that falls straight through into
		 * it, for {@link #findPassThroughWrappers} (bead grm-2dr increment 1).
		 * <p>
		 * {@code function} MUST become {@code wrapper}, not stay the wrapped helper's own
		 * function: {@link #helperLabel} compares {@code entry} against
		 * {@code function.getEntryPoint()} to decide whether to print a plain function name
		 * or a "mid-body entry in ..." qualifier, so leaving {@code function} pointed at the
		 * helper would print the misleading claim that the wrapper's entry is a mid-body
		 * entry INTO the helper's own function. It also keeps this record's {@code function}
		 * field equal to its own map key, which {@link #exitEffect}'s
		 * {@code helpers.get(callee.function())} lookup depends on to find a callee's model
		 * again by its own key.
		 * <p>
		 * {@code constState} is INHERITED, not dropped -- and that is an IDENTITY, not a
		 * guess, and the exact DUAL of {@link #atMidBodyEntry}: a mid-body entry runs a
		 * SUBSET of the body (it drops the constant because the skipped prefix might have
		 * been where the summarized effect came from), while a pass-through wrapper's caller
		 * runs a SUPERSET of the body -- an inert prefix (the wrapper itself) plus the
		 * ENTIRE wrapped body, unabridged. {@link #isPassThroughInto}'s admission predicate
		 * already guarantees the wrapper's body is fully disassembled, writes no mechanism,
		 * makes no call, and transfers control to nothing but {@code target} (this helper's
		 * own {@code entry}) -- so it changes no tracked bank bit, and whatever constant this
		 * helper asserts when entered at the top still holds when entered at the wrapper's
		 * top instead.
		 * <p>
		 * {@code relay} is carried through rather than nulled. Under the phase order at
		 * {@link #added}'s helper-discovery chain, {@link #findCallEdgeWrappers} runs
		 * LAST, so this method can never actually see a non-null one today -- but a pass-through
		 * wrapper OF a call-edge wrapper is address-contiguous and inert, so the first prologue
		 * segment simply widens to start at the outer wrapper's entry and stays correct.
		 * Dropping it would be a latent bug the day that order changes.
		 */
		HelperModel atFallThroughWrapper(Function wrapper) {
			return new HelperModel(wrapper, wrapper.getEntryPoint(), constState, argReg,
				effectMask, lsb, strategy, switchSite, firstSite, relay);
		}

		/**
		 * This helper re-keyed onto a CALL-EDGE wrapper -- one that reaches it by an interior
		 * {@code JSR} (or a tail {@code JMP} retyped {@code CALL_TERMINATOR}) rather than by
		 * falling through into it, for {@link #findCallEdgeWrappers} (bead grm-2dr increment 2).
		 * blmaster's {@code FUN_e61b} is the shape: {@code STA $DB} on entry, the argument
		 * reloaded from that shadow, then {@code $e627 JSR $e63c} into the real MMC1 chain.
		 * <p>
		 * {@code function} MUST become {@code wrapper} for both reasons
		 * {@link #atFallThroughWrapper} documents -- {@link #helperLabel}'s "mid-body entry in
		 * ..." qualifier, and keeping this record's {@code function} equal to its own map key
		 * for {@link #exitEffect}'s lookup.
		 * <p>
		 * <b>The {@link Relay}'s callee entry is {@code entry}, NOT
		 * {@code function().getEntryPoint()}.</b> If the helper being wrapped is itself a
		 * pass-through wrapper, {@code entry} is where control actually arrives and is the
		 * correct start for the second prologue segment; the function's own entry point would
		 * be the same address only by coincidence.
		 * <p>
		 * <b>{@code constState} is INHERITED, and this is the WEAKEST of the three re-keyings.</b>
		 * Place it on the axis: {@link #atMidBodyEntry} inherits a SUBSET of the body and so must
		 * drop the constant; {@link #atFallThroughWrapper} inherits a strict SUPERSET (inert
		 * prefix plus the entire wrapped body) and so inherits it as an IDENTITY; a call-edge
		 * wrapper is NEITHER, because its body continues after the relay call. Inheriting rests
		 * on four conditions {@link #findCallEdgeWrappers} checks -- the prefix
		 * {@code [entry, callSite)} is inert and unconditional, no recognized mechanism write
		 * appears ANYWHERE in the wrapper's body, no second known-helper call appears there
		 * either, and the relay call is therefore guaranteed to execute -- plus one it ASSUMES:
		 * that calls after the relay to functions this engine does not model as helpers are
		 * bank-neutral. That last one is genuinely weaker than
		 * {@link #atFallThroughWrapper}'s, where inertness is CHECKED per instruction over the
		 * whole body rather than assumed over the tail. Inheriting rather than dropping is the
		 * consistent choice: the same assumption already underwrites the {@code argReg} path,
		 * so declining it only for the constant would buy nothing.
		 */
		HelperModel atCallEdgeWrapper(Function wrapper, Address callSite) {
			return new HelperModel(wrapper, wrapper.getEntryPoint(), constState, argReg,
				effectMask, lsb, strategy, switchSite, firstSite, new Relay(callSite, entry));
		}
	}

	/**
	 * A call-edge wrapper's relay: the call instruction inside the wrapper that reaches the real
	 * bank-switch helper, and the address that call lands on (bead grm-2dr increment 2).
	 * <p>
	 * Its whole job is to record that a {@link HelperModel}'s prologue is TWO DISJOINT SPANS
	 * rather than one. For an ordinary helper the caller's argument has to survive
	 * {@code [entry, firstSite)}, one linear-by-address stretch. For a call-edge wrapper it has
	 * to survive {@code [wrapper entry, callSite)} and then {@code [calleeEntry, firstSite)} --
	 * and the addresses BETWEEN those two spans are the wrapper's own tail, which the call never
	 * executes on its way in. Walking straight from the wrapper's entry to the helper's first
	 * site would walk over that tail and read it as prologue, which is why this cannot be
	 * expressed by re-keying {@code entry} alone the way {@link HelperModel#atFallThroughWrapper}
	 * does.
	 * <p>
	 * Three consumers, all of which would otherwise silently use the wrapper's entry where the
	 * WRAPPED HELPER's is meant: {@link #prologueSegments}, {@link #valueSuppliedInsideHelper}
	 * and {@link #callSiteRegisters}'s stop address. A fourth, {@link #midBodyEntryHelper},
	 * declines outright on a non-null relay.
	 */
	private record Relay(Address callSite, Address calleeEntry) {}
}
