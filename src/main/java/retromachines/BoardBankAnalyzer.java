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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static retromachines.BankDataflowEngine.runDataflow;
import static retromachines.HelperDiscovery.composeTailCalls;
import static retromachines.HelperDiscovery.findCallEdgeWrappers;
import static retromachines.HelperDiscovery.findHelpers;
import static retromachines.HelperDiscovery.findPassThroughWrappers;
import static retromachines.SaveRestoreTrampolines.restoresEntryBank;

import retromachines.BankDataflowEngine.CallSwitch;
import retromachines.BankDataflowEngine.DataflowResult;
import retromachines.BankDataflowEngine.SwitchResult;
import retromachines.BankStrategyRegistry.ConfiguredMechanism;
import retromachines.BoardDescriptorModel.BoardModel;
import retromachines.BoardDescriptorModel.ComputedWindowModel;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.BoardDescriptorModel.ModeWindowModel;
import retromachines.HelperDiscovery.HelperModel;

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
	/**
	 * How many retracted addresses the sweep names in its log line before summarising the rest
	 * (bead grm-3mg0). Enough to identify the movement on any realistic program -- the whole
	 * 33-row real-ROM corpus produced ONE retraction in total -- without risking a wall of text.
	 */
	private static final int RETRACTION_LOG_LIMIT = 10;

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

		BoardModel board = BoardModel.parse(map, log, getName(), mapPath,
			DescriptorSupport.readResolvedInitialState(program));
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
		// The provenance record (bead grm-3mg0) spans the whole phase: every bank comment this
		// round writes is recorded in it, and the sweep after the loop retracts the ones an
		// EARLIER round wrote at sites this round no longer annotates. Null when the property
		// map is unavailable, which degrades to the old append-only behaviour -- see
		// BankCommentProvenance.open.
		BankCommentProvenance provenance = BankCommentProvenance.open(program);
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
						"directly by the store, with no AND/ORA immediate to constrain it)",
					provenance);
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
						"recovered at this call site", provenance);
				warnings += w;
				if (w > 0) {
					alreadyWarned.add(addr);
				}
			}

			refsAdded += BankAnnotationAdapter.retargetReferences(this, program, refMgr, baseSpace,
				instr, board, bankUniverse, inState, placementOverride, monitor, log, provenance);
		}

		// Retract bank comments an EARLIER round wrote at sites this round did not annotate
		// (bead grm-3mg0). Must run AFTER the whole loop: both writers above and
		// retargetReferences' placement-provenance note can establish a site, so retracting
		// mid-loop would cut a comment a later iteration is about to re-record. Write-free on a
		// settled program, which the redundant-re-run gate above depends on.
		if (provenance != null) {
			List<Address> retracted = provenance.sweep(listing);
			if (!retracted.isEmpty()) {
				// Name the ADDRESSES, not just the count. A retraction is invisible in the
				// golden dumps whenever the site sorts past RealRomDump's SAMPLE cap (bead
				// grm-3pnz) -- smb3's single retraction did exactly that on the run this was
				// added for, leaving `count bankComments 181 -> 180` and no way to tell which
				// site moved. Bounded so a pathological program cannot flood the log.
				String where = retracted.stream()
						.limit(RETRACTION_LOG_LIMIT)
						.map(Object::toString)
						.collect(Collectors.joining(", "));
				String more = retracted.size() > RETRACTION_LOG_LIMIT
						? ", ... (" + (retracted.size() - RETRACTION_LOG_LIMIT) + " more)" : "";
				AnalyzerLog.info(this, tag + ": retracted " + retracted.size() +
					" stale bank comment(s) from an earlier analysis round at " + where + more);
			}
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

}
