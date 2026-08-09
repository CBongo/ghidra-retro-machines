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
import java.math.BigInteger;
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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
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
import ghidra.program.model.symbol.Symbol;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

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
	 * Fingerprint of the last <em>completed</em> {@link #added} run per program
	 * (grm-5tl.13.3). Phase 2's overlay retargeting disassembles cross-bank targets, and
	 * the framework answers each batch of new code by re-invoking {@code added()}, which
	 * re-seeds the whole-program fixpoint from scratch -- deliberately so, because that
	 * reseed is how bank state reaches the newly discovered code (its callers are outside
	 * the delta set, so processing only {@code set} would silently under-annotate). The
	 * consequence is up to O(rounds x whole-program) work; this cache skips a re-run
	 * <em>only</em> when it is provably redundant: nothing this analyzer reads has changed
	 * since the last run completed. All-or-nothing -- phase-1 output is never cached or
	 * diff-merged across runs (annotateBankSwitch never overwrites an existing bank
	 * comment, so a stale partial merge would compound).
	 * <p>
	 * Coverage assumptions behind the fingerprint (function count + instruction count,
	 * both O(1) reads):
	 * <ul>
	 * <li>Everything the analysis consumes is a function of the instruction set, the
	 * function entries (dataflow seeds and helper models), and the descriptor. New or
	 * removed code/functions -- including this analyzer's own phase-2 side effects --
	 * always move one of the two counts; the stored value is captured at run
	 * <em>entry</em>, so a run's own mutations unmatch the very next invocation.</li>
	 * <li>Operand/flow references (which strategies inspect via
	 * {@code getReferencesFrom}) are laid down at disassembly time and by the reference
	 * analyzers this analyzer is prioritized after -- reference changes relevant here do
	 * not occur without accompanying instruction changes.</li>
	 * <li>The descriptor is identified by {@code mapPath} (stored alongside the counts);
	 * a program re-pointed at a different board map re-runs even with identical counts.
	 * Edits to the map <em>file's content</em> under an unchanged path are not detected
	 * -- acceptable for compiled resources bundled with the extension.</li>
	 * <li>A run that throws (e.g. {@link CancelledException}) stores nothing and will
	 * re-run in full. A future change that makes the analysis consume mutable inputs
	 * outside these (say, reading a context register other analyzers write) must widen
	 * the fingerprint or drop the cache.</li>
	 * </ul>
	 * Keyed weakly by {@link Program} identity so closed programs drop out; synchronized
	 * because distinct programs may be analyzed on distinct threads.
	 */
	private static final Map<Program, RunStamp> LAST_COMPLETED =
		Collections.synchronizedMap(new WeakHashMap<>());

	/** What {@link #LAST_COMPLETED} remembers: entry-time fingerprint + descriptor path. */
	private record RunStamp(long fingerprint, String mapPath) {}

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
		boolean verbose = AnalyzerRunLog.isInitialRun(program, getClass());
		String mapPath = getMapPath(program);
		if (mapPath == null) {
			return false;
		}

		// Redundant-re-run gate (grm-5tl.13.3): see LAST_COMPLETED for the invariants.
		long fingerprint = fingerprint(program);
		RunStamp last = LAST_COMPLETED.get(program);
		if (last != null && last.fingerprint() == fingerprint && last.mapPath().equals(mapPath)) {
			if (verbose) {
				log.appendMsg(getName(), tag + ": no function/instruction changes since last " +
					"completed run; skipping redundant whole-program re-analysis");
			}
			AnalyzerRunLog.markCompleted(program, getClass());
			return true;
		}
		if (verbose) {
			log.appendMsg(getName(), tag + " running (" + mapPath + ")");
		}

		JsonObject map;
		try {
			map = DescriptorSupport.loadMap(mapPath);
		}
		catch (IOException e) {
			log.appendMsg(getName(), "Failed to load " + mapPath + ": " + e.getMessage());
			return false;
		}

		BoardModel board = BoardModel.parse(map, log, getName(), mapPath);
		if (board == null) {
			return true;
		}

		Map<String, Integer> placementOverride = readPlacementOverride(program, log, verbose);

		JsonObject banking = map.getAsJsonObject("banking");
		List<ConfiguredMechanism> mechanisms = configureStrategies(program,
			banking.getAsJsonArray("mechanisms"), board, log);
		if (mechanisms.isEmpty()) {
			log.appendMsg(getName(), "no usable bank-switch strategy in " + mapPath +
				" banking; skipping bank-state analysis");
			return true;
		}

		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

		// --- Phase 1: forward dataflow to fixpoint; rerun with helper knowledge if any ---
		Listing listing = program.getListing();
		DataflowResult flow = runDataflow(program, monitor, listing, mechanisms, board, null);

		// Order is load-bearing. findCallEdgeWrappers runs LAST so its relay lookups see
		// pass-through wrappers as helpers; it is also why exitEffect never encounters a relay
		// model. See findCallEdgeWrappers' javadoc for the one gap this order leaves open.
		Map<Function, HelperModel> helpers = findCallEdgeWrappers(program,
			findPassThroughWrappers(program,
				composeTailCalls(program, findHelpers(program, flow.switchResults())),
				flow.switchResults()),
			flow.switchResults());
		if (!helpers.isEmpty()) {
			if (verbose) {
				log.appendMsg(getName(), helpers.size() + " bank-switch helper function(s): " +
					helpers.keySet().stream().map(Function::getName).sorted().toList());
			}
			flow = runDataflow(program, monitor, listing, mechanisms, board, helpers);
		}

		// --- Phase 2: annotate bank switches + retarget references ---
		ReferenceManager refMgr = program.getReferenceManager();
		int refsAdded = 0;
		int warnings = 0;
		// Addresses that already carry a WARNING bookmark from this loop -- Phase 3's
		// violation scan below dedupes against this set rather than stacking a second
		// bookmark on a site the existing switch/call-switch warning already covers.
		Set<Address> alreadyWarned = new LinkedHashSet<>();
		// Which banks each switchable window actually has an image slice for (grm-hum
		// increment 3). Derived once, here, because it is a property of the loaded program and
		// cannot change under the annotation loop.
		Map<String, Set<Integer>> bankUniverse = bankUniverse(program, board);
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
				int w = annotateOrWarn(program, listing, addr, switchResult.effect(), board,
					bankUniverse, null,
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
				int w = annotateOrWarn(program, listing, addr, annotState, board, bankUniverse,
					callSwitch.helperName(),
					"Bank state becomes unknown here: call to bank-switch helper " +
						callSwitch.helperName() + " whose bank argument could not be " +
						"recovered at this call site");
				warnings += w;
				if (w > 0) {
					alreadyWarned.add(addr);
				}
			}

			refsAdded += retargetReferences(program, refMgr, baseSpace, instr, board, inState,
				placementOverride, monitor, log);
		}

		// --- Phase 3: function-level bank-state summaries + call-site requirement
		// violations (bead grm-6a7.2, design D, M3 scope: read-only annotation layer,
		// derived AFTER the Phase-1/2 fixpoint above -- see the method's javadoc for what
		// is and is not fed back into the dataflow) ---
		int violations = annotateBankRequirementViolations(program, listing, flow, board,
			alreadyWarned, log, verbose);

		// --- Context stamping: only when the language actually declares the register ---
		stampContextRegister(program, banking, flow.stateIn(), listing, board.mask(), log, verbose);

		// A phase-2 retarget may have disassembled code or created functions. Such a
		// round returned successfully, but it is deliberately not the completed initial
		// analysis: the framework must invoke us again so the whole-program fixpoint can
		// reach that newly discovered code. Keep first-run verbosity alive and defer the
		// definitive summary until an invocation leaves the structural fingerprint stable.
		boolean stable = reachedFixpoint(fingerprint, fingerprint(program));
		if (verbose && stable) {
			log.appendMsg(getName(), tag + ": " + flow.stateIn().size() + " instructions tracked, " +
				refsAdded + " overlay references added/confirmed, " + warnings +
				" unknown-state warnings, " + violations + " bank-state requirement violations");
		}

		// A structurally changing round is deliberately not complete and must not populate
		// the completed-run cache. The framework follow-on therefore runs in full; only its
		// stable entry fingerprint can become the redundant-rerun baseline.
		if (stable) {
			manageNoMechanismWriteDiagnostic(program, mechanisms, flow, log, verbose);
			LAST_COMPLETED.put(program, new RunStamp(fingerprint, mapPath));
			AnalyzerRunLog.markCompleted(program, getClass());
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
			List<ConfiguredMechanism> mechanisms, DataflowResult flow, MessageLog log,
			boolean verbose) {
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
		if (verbose) {
			log.appendMsg(getName(), getClass().getSimpleName() + ": " + msg);
		}
	}

	// ------------------------------------------------------------------
	// Strategy configuration
	// ------------------------------------------------------------------

	/**
	 * Instantiates and configures one {@link BankSwitchStrategy} per descriptor
	 * mechanism entry, matching {@code mechanisms[].strategy} to implementations found
	 * by ClassSearcher. Unknown strategy names are logged and skipped (they belong to
	 * later milestones). Each mechanism is also positioned within the board's absolute
	 * state bits (see {@link #mechanismPositioning}); a mechanism whose positioning
	 * cannot be determined is likewise skipped.
	 */
	private List<ConfiguredMechanism> configureStrategies(Program program, JsonArray mechanisms,
			BoardModel board, MessageLog log) {
		List<BankSwitchStrategy> prototypes = ClassSearcher.getInstances(BankSwitchStrategy.class);
		List<ConfiguredMechanism> configured = new ArrayList<>();
		for (JsonElement me : mechanisms) {
			JsonObject mechanism = me.getAsJsonObject();
			String strategyName = mechanism.get("strategy").getAsString();
			BankSwitchStrategy prototype = null;
			for (BankSwitchStrategy p : prototypes) {
				if (p.strategyName().equals(strategyName)) {
					prototype = p;
					break;
				}
			}
			if (prototype == null) {
				log.appendMsg(getName(), "no BankSwitchStrategy implementation for strategy '" +
					strategyName + "'; skipping that mechanism");
				continue;
			}

			int[] positioning = mechanismPositioning(mechanism, board, log, strategyName);
			if (positioning == null) {
				continue;
			}
			int effectMask = positioning[0];
			int lsb = positioning[1];

			try {
				BankSwitchStrategy instance =
					prototype.getClass().getDeclaredConstructor().newInstance();
				JsonObject params = mechanism.getAsJsonObject("params");
				// Field-local sub-offsets (grm-6a7.1): a mechanism with several 'sets' fields
				// packed into one physical register (e.g. select-data's select/prg_mode/r6/r7)
				// needs to know where EACH of its own fields sits within its own field-local
				// [0, width) window, not just the window's own overall width. Rather than have
				// every such strategy re-derive that from banking.state by hand (or have YAML
				// authors hand-duplicate offsets that must stay in lockstep with the state
				// tuple), inject it here from the single source of truth: board.fieldSpecs(),
				// the same per-field (lsb, width) this method already used to compute
				// effectMask/lsb above, just re-expressed field-local (subtract this
				// mechanism's own lsb) and keyed by name under params._field_layout. A
				// single-field mechanism (every strategy shipped before this one) never reads
				// this key, so injecting it unconditionally cannot break them.
				if (mechanism.has("sets")) {
					JsonObject fieldLayout = new JsonObject();
					for (JsonElement se : mechanism.getAsJsonArray("sets")) {
						String fieldName = se.getAsString();
						board.fieldSpecs().stream()
								.filter(f -> f.name().equals(fieldName))
								.findFirst()
								.ifPresent(f -> {
									JsonObject fl = new JsonObject();
									fl.addProperty("lsb", f.lsb() - lsb);
									fl.addProperty("width", f.width());
									fieldLayout.add(fieldName, fl);
								});
					}
					params.add("_field_layout", fieldLayout);
				}
				// Strategies always compute in field-local [0, width) coordinates; the mask
				// they configure with is that field-local width, not the whole board mask.
				instance.configure(program, params, effectMask >>> lsb);
				configured.add(new ConfiguredMechanism(instance, effectMask, lsb));
			}
			catch (Exception e) {
				log.appendMsg(getName(), "failed to configure strategy '" + strategyName + "': " +
					e.getMessage());
			}
		}
		return configured;
	}

	/**
	 * Computes one mechanism's {@code (effectMask, lsb)}: where in the board's absolute
	 * state bits this mechanism's writes land, derived from its {@code sets} field-name
	 * list (the {@code banking.state} fields it writes) -- {@code effectMask} is the union
	 * of those fields' {@link FieldSpec#positionedMask()}, {@code lsb} the lowest of their
	 * lsbs. The engine uses this to translate between a strategy's field-local
	 * {@code [0, width)} coordinate space (what {@link BankSwitchStrategy#computeSwitch}
	 * actually computes in) and the board's absolute state bits, so one mechanism's switch
	 * can fold into the tracked state without disturbing bits another mechanism owns
	 * (grm-ezl). The union is REQUIRED to be one contiguous bit run starting at
	 * {@code lsb} -- a mechanism whose {@code sets} fields are split or interleaved with
	 * another mechanism's is unsupported and is conservatively skipped (logged, not
	 * analyzed) rather than mispositioned.
	 * <p>
	 * A mechanism with no {@code sets} at all (older or minimal descriptors) falls back to
	 * covering the whole board mask at {@code lsb} 0 -- today's single-mechanism-per-board
	 * behavior, verbatim.
	 *
	 * @return {@code {effectMask, lsb}}, or {@code null} to skip this mechanism
	 */
	private int[] mechanismPositioning(JsonObject mechanism, BoardModel board, MessageLog log,
			String strategyName) {
		if (!mechanism.has("sets") || mechanism.getAsJsonArray("sets").size() == 0) {
			return new int[] { board.mask(), 0 };
		}
		JsonArray sets = mechanism.getAsJsonArray("sets");
		int effectMask = 0;
		int lsb = Integer.MAX_VALUE;
		for (JsonElement se : sets) {
			String fieldName = se.getAsString();
			FieldSpec field = board.fieldSpecs().stream()
					.filter(f -> f.name().equals(fieldName))
					.findFirst()
					.orElse(null);
			if (field == null) {
				log.appendMsg(getName(), "mechanism '" + strategyName + "' sets unknown state " +
					"field '" + fieldName + "'; skipping that mechanism");
				return null;
			}
			effectMask |= field.positionedMask();
			lsb = Math.min(lsb, field.lsb());
		}
		int widthMask = effectMask >>> lsb;
		if (widthMask == 0 || (widthMask & (widthMask + 1)) != 0) {
			log.appendMsg(getName(), "mechanism '" + strategyName + "' sets fields " + sets +
				" that are not a contiguous bit run in banking.state; skipping that mechanism");
			return null;
		}
		return new int[] { effectMask, lsb };
	}

	// ------------------------------------------------------------------
	// Dataflow
	// ------------------------------------------------------------------

	/**
	 * One forward-dataflow run to fixpoint. When {@code helpers} is non-null, a call to
	 * a helper function is itself a switch site: the state on the call's fall-through is
	 * the helper's effect, not the flowed-through in-state (the call target's entry is
	 * still seeded with the in-state -- the switch happens inside the helper).
	 */
	private DataflowResult runDataflow(Program program, TaskMonitor monitor, Listing listing,
			List<ConfiguredMechanism> mechanisms, BoardModel board,
			Map<Function, HelperModel> helpers) throws CancelledException {

		Map<Address, BankState> stateIn = new HashMap<>();
		Map<Address, SwitchResult> switchResults = new HashMap<>();
		Map<Address, CallSwitch> callSwitches = new HashMap<>();
		Deque<Address> worklist = new ArrayDeque<>();
		Map<String, int[]> clampCache = new HashMap<>();
		// Scoped to this runDataflow call (not a field): phase 1/2 separation guarantees no
		// instruction appears mid-fixpoint, so per-call scoping sidesteps any staleness
		// question. See the strategy-probe loop below for the soundness invariant this relies
		// on (grm-5tl.13.2).
		Map<Address, MatchInfo> matchCache = new HashMap<>();
		// Likewise scoped to this runDataflow call: the A/X/Y a helper call site supplies
		// (grm-hum increment 2). Purely an efficiency memo -- callSiteRegisters is a function of
		// (program, call address) alone, since its three scans use NO_HOOKS and never consult
		// tracked state -- but a necessary one: without it, three backward scans plus a
		// strategy's mini-inline would rerun on EVERY dequeue of every helper call address across
		// the whole fixpoint. Mega Man (25 switch sites, a large fixpoint) is where that bites.
		Map<Address, RegisterEnv> callSiteRegCache = new HashMap<>();

		Set<Address> seeds = new LinkedHashSet<>();
		AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
		while (eps.hasNext()) {
			seeds.add(eps.next());
		}
		FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
		for (Function f : funcs) {
			seeds.add(f.getEntryPoint());
		}

		BankState seedState = BankState.fullyKnown(board.mask(), board.initialState());
		for (Address seed : seeds) {
			mergeAndEnqueue(seed, seedState, stateIn, worklist, listing, board, clampCache);
		}

		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Address addr = worklist.poll();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			BankState inState = stateIn.get(addr);
			BankState outState = inState;

			// Strategy-probe memoization (grm-5tl.13.2): both shipped strategies gate
			// computeSwitch on an instruction-only predicate (MemoryLatch's writesInRange,
			// RegisterWrite's writesMechanism) that fully determines whether the result is
			// null -- neither ever returns null for an instruction its predicate accepts, so
			// "which mechanism matches this address" (if any) does not depend on inState, only
			// the *value* a non-cacheable match produces does. That lets us cache the matched
			// mechanism's identity per address across dequeues and, on a cache hit, either reuse
			// a cacheable strategy's state-independent result outright or re-probe only the one
			// non-cacheable strategy that matched -- never the others, and never re-run the
			// whole ordered loop. A future strategy whose match/no-match outcome genuinely
			// depends on inState would violate this; the fallback below (treat an unexpected
			// null from the cached strategy as no-match for this dequeue, rather than
			// re-probing every strategy) stays conservative in that case instead of unsound.
			//
			// Every strategy computes in its mechanism's field-local [0, width) coordinate
			// space, never the board's absolute state bits: the in-state handed to
			// computeSwitch is narrowed to that mechanism's effectMask/lsb, and a non-null
			// result is positioned back into absolute bits before it touches stateIn.
			MatchInfo cached = matchCache.get(addr);
			ConfiguredMechanism matchedMechanism;
			BankState switchedLocal;
			if (cached == null) {
				ConfiguredMechanism matched = null;
				BankState result = null;
				for (ConfiguredMechanism cm : mechanisms) {
					BankState localIn = toFieldLocal(inState, cm.lsb(), cm.effectMask());
					result = cm.strategy().computeSwitch(program, instr, localIn);
					if (result != null) {
						matched = cm;
						break;
					}
				}
				matchedMechanism = matched;
				switchedLocal = matched == null ? null : result;
				matchCache.put(addr, new MatchInfo(matched,
					matched != null && matched.strategy().cacheable() ? result : null));
			}
			else if (cached.mechanism() == null) {
				// no strategy's instruction-level predicate matches this address
				matchedMechanism = null;
				switchedLocal = null;
			}
			else if (cached.result() != null) {
				// cacheable strategy matched before; its result here is state-independent
				matchedMechanism = cached.mechanism();
				switchedLocal = cached.result();
			}
			else {
				// non-cacheable strategy matched before; only it can match here, re-probe it
				// alone with the current in-state
				matchedMechanism = cached.mechanism();
				BankState localIn =
					toFieldLocal(inState, matchedMechanism.lsb(), matchedMechanism.effectMask());
				switchedLocal = matchedMechanism.strategy().computeSwitch(program, instr, localIn);
			}
			if (switchedLocal != null) {
				// Fold: this mechanism's switch REPLACES only the bits it owns (effectMask),
				// preserving whatever the rest of the tracked state already knew about other
				// mechanisms' fields. For a single-mechanism board effectMask covers every
				// tracked bit, so this reduces exactly to the old whole-state replace.
				BankState positionedEffect =
					position(switchedLocal, matchedMechanism.lsb(), matchedMechanism.effectMask());
				switchResults.put(addr, new SwitchResult(positionedEffect,
					matchedMechanism.effectMask(), matchedMechanism.lsb(),
					matchedMechanism.strategy()));
				outState = overwrite(inState, positionedEffect, matchedMechanism.effectMask());
			}

			BankState fallState = outState;
			if (helpers != null && instr.getFlowType().isCall()) {
				HelperModel helper = calledHelper(program, instr, helpers);
				if (helper != null) {
					CallEffect callEffect = helper.constState() != null
							? new CallEffect(helper.constState(), helper.effectMask())
							: recoverCallArgument(program, instr, helper, outState,
								callSiteRegCache);
					// ownedMask == 0 means this call site is a verified no-op on every tracked
					// bit (e.g. a serial-shift helper whose switch site targets an unconfigured
					// CHR register) -- skip both the fold (a no-op regardless, since
					// callEffect.state()'s knownMask is always a subset of ownedMask by
					// construction) and the annotation, so a provably-inert call gets neither a
					// misleading "bank -> ?" comment nor a spurious WARNING bookmark.
					if (callEffect.ownedMask() != 0) {
						fallState = overwrite(outState, callEffect.state(), callEffect.ownedMask());
						// The annotation state echoes the in-state only within the helper's own
						// mechanism window -- see CallSwitch's javadoc.
						BankState mechIn = new BankState(outState.knownMask() & helper.effectMask(),
							outState.bits() & helper.effectMask());
						callSwitches.put(addr, new CallSwitch(helperLabel(program, helper),
							callEffect.state(),
							overwrite(mechIn, callEffect.state(), callEffect.ownedMask())));
					}
				}
			}

			for (Address flowAddr : instr.getFlows()) {
				mergeAndEnqueue(flowAddr, outState, stateIn, worklist, listing, board, clampCache);
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough != null) {
				mergeAndEnqueue(fallThrough, fallState, stateIn, worklist, listing, board,
					clampCache);
			}
		}
		return new DataflowResult(stateIn, switchResults, callSwitches);
	}

	/**
	 * Narrows a board-absolute {@link BankState} to one mechanism's field-local
	 * {@code [0, width)} coordinate space: the bits outside {@code effectMask} are
	 * discarded and the surviving bits are shifted down by {@code lsb}. This is what a
	 * {@link BankSwitchStrategy} actually sees as its {@code inState} -- e.g. its own
	 * mechanism read back ({@code LDA} of a register-write's own address/register)
	 * resolves against only the field(s) that mechanism owns, not the whole board state.
	 * The inverse of {@link #position}.
	 */
	private static BankState toFieldLocal(BankState state, int lsb, int effectMask) {
		return new BankState((state.knownMask() & effectMask) >>> lsb,
			(state.bits() & effectMask) >>> lsb);
	}

	/**
	 * Positions a mechanism's field-local {@code [0, width)} result back into the board's
	 * absolute state bits: shifted up by {@code lsb} and masked to {@code effectMask} (a
	 * defensive mask -- a well-behaved strategy result is already {@code <= width} bits,
	 * but this keeps a stray high bit from a strategy from ever leaking outside the
	 * mechanism's own field). The inverse of {@link #toFieldLocal}.
	 */
	private static BankState position(BankState fieldLocal, int lsb, int effectMask) {
		return new BankState((fieldLocal.knownMask() << lsb) & effectMask,
			(fieldLocal.bits() << lsb) & effectMask);
	}

	/**
	 * Folds a mechanism's positioned effect into a base state: bits inside {@code mask}
	 * take the effect's knowledge (whether known or not), every other bit keeps whatever
	 * {@code base} already knew. {@code effect}'s known bits are always a subset of
	 * {@code mask} by construction ({@link #position} masks to it), so this is a clean
	 * per-bit replace, not a merge -- one mechanism's switch never has to agree with what
	 * was known before it fired. When {@code mask} covers every tracked bit (every shipped
	 * board today, since each has exactly one mechanism spanning the whole board mask),
	 * this reduces to replacing the state outright, matching the engine's original
	 * single-mechanism behavior exactly.
	 */
	private static BankState overwrite(BankState base, BankState effect, int mask) {
		return new BankState((base.knownMask() & ~mask) | effect.knownMask(),
			(base.bits() & ~mask) | effect.bits());
	}

	private void mergeAndEnqueue(Address addr, BankState incoming, Map<Address, BankState> stateIn,
			Deque<Address> worklist, Listing listing, BoardModel board,
			Map<String, int[]> clampCache) {
		if (listing.getInstructionAt(addr) == null) {
			// not (yet) disassembled / not code -- nothing to track here
			return;
		}
		BankState existing = stateIn.get(addr);
		BankState merged = existing == null ? incoming : BankState.merge(existing, incoming);
		merged = clampToResidence(addr, merged, board, clampCache);
		if (existing == null || !merged.equals(existing)) {
			stateIn.put(addr, merged);
			worklist.add(addr);
		}
		// else: unchanged, already processed with this exact state -- nothing to do
	}

	/**
	 * Execution implies mapping: an instruction physically inside a computed window's
	 * bank overlay {@code WINDOW_B<n>} can only be running while that window's field
	 * holds {@code n}, so those bits are forced known regardless of what flowed in.
	 * (Idempotent and deterministic per address, so the fixpoint still terminates.)
	 */
	private BankState clampToResidence(Address addr, BankState state, BoardModel board,
			Map<String, int[]> clampCache) {
		AddressSpace space = addr.getAddressSpace();
		if (!space.isOverlaySpace()) {
			return state;
		}
		int[] clamp = clampCache.computeIfAbsent(space.getName(), name -> {
			for (ComputedWindowModel w : board.computedWindows().values()) {
				Integer v = DescriptorSupport.OverlayNaming.parseBankValue(w.name(), name);
				if (v != null) {
					FieldSpec f = w.field();
					return new int[] { f.positionedMask(), (v << f.lsb()) & f.positionedMask() };
				}
				// null: not one of ours (e.g. a C64 occupant overlay) -- keep looking
			}
			if (board.modeField() != null) {
				FieldSpec modeField = board.modeField();
				Set<String> windowNames = new LinkedHashSet<>();
				for (ModeWindowModel w : board.modeWindows()) {
					windowNames.add(w.name());
				}
				for (String windowName : windowNames) {
					DescriptorSupport.OverlayNaming.ModeBank mb =
						DescriptorSupport.OverlayNaming.parseModeBankValue(windowName, name);
					if (mb != null) {
						ModeWindowModel instance =
							findModeWindowInstance(board.modeWindows(), windowName, mb.mode());
						if (instance != null && instance.bankField() != null) {
							FieldSpec bankField = instance.bankField();
							int posMask = modeField.positionedMask() | bankField.positionedMask();
							int posBits =
								((mb.mode() << modeField.lsb()) & modeField.positionedMask()) |
									((mb.bank() << bankField.lsb()) & bankField.positionedMask());
							return new int[] { posMask, posBits };
						}
						continue;
					}
					Integer mv = DescriptorSupport.OverlayNaming.parseModeValue(windowName, name);
					if (mv != null) {
						return new int[] { modeField.positionedMask(),
							(mv << modeField.lsb()) & modeField.positionedMask() };
					}
				}
			}
			return new int[0];
		});
		if (clamp.length == 0) {
			return state;
		}
		return new BankState(state.knownMask() | clamp[0],
			(state.bits() & ~clamp[0]) | clamp[1]);
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
	 * the caller-side unknown-effect fold in {@link #runDataflow} wipes every field this
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
	private Map<Function, HelperModel> findHelpers(Program program,
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
	 * chain declines instead of running away, alongside the visited-set cycle guard that
	 * {@code FUN_f105} (which tail-jumps to ITSELF at {@code $F10F}) makes non-hypothetical.
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
	 * <b>This is a SUMMARY fix, not a dataflow fix.</b> {@link #runDataflow} already treats a
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
	 * likewise a no-op, which is exactly what {@link #runDataflow} folds for a call to one.
	 * <p>
	 * <b>Where it composes:</b> a tail-callee that is a recognized helper with a
	 * caller-independent effect (its own {@code constState}, or one it composes to) overwrites
	 * the bits it owns on top of the caller's own deposit -- callee wins on its own bits, which
	 * is just {@link #overwrite}. When the callee owns every bit the caller's body could touch,
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
	private Map<Function, HelperModel> composeTailCalls(Program program,
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
	private TailEffect exitEffect(Program program, Function f, Map<Function, HelperModel> helpers,
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
	private TailEffect composeWithCallee(HelperModel model, TailEffect callee) {
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
	private TailEffect agreeOrDecline(TailEffect a, TailEffect b, int ownMask) {
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
	 * constant takes {@link #runDataflow}'s {@code constState} branch directly and never
	 * touches the nulled {@code argReg}/{@code switchSite} fields a wrapper would also leave
	 * untouched, and a composed decline short-circuits in {@link #recoverCallArgument} on
	 * the null {@code argReg}, producing a warning plus honest poison exactly as a direct
	 * call to it would.
	 */
	private Map<Function, HelperModel> findPassThroughWrappers(Program program,
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
	 * {@link #runDataflow} already folds a call to a non-helper as a no-op on bank state, and
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
	private Map<Function, HelperModel> findCallEdgeWrappers(Program program,
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
	 * they are told apart by {@code isCall()}, the same test {@link #runDataflow} already uses
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
	 * {@link #runDataflow} folds as a call that does nothing to bank state. A SILENT miss, and
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
	private static String helperLabel(Program program, HelperModel helper) {
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
	private HelperModel calledHelper(Program program, Instruction callInstr,
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
	private HelperModel midBodyEntryHelper(Program program, Address entry,
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
	 * {@code outState} {@link #runDataflow} folds the call's own effect into) is narrowed to
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
	 * and a failure withholds {@code argValue} (leaving it unknown) rather than short-
	 * circuiting, so the strategy still decides ownership and only the bits this call really
	 * writes are poisoned. It is skipped for a strategy that re-derives the value inside the
	 * helper instead of consuming {@code argValue} -- see
	 * {@link BankSwitchStrategy#consumesHelperArgument}, and note that memory-latch's Contra
	 * helper is a prologue-clobber case that must keep resolving.
	 * <p>
	 * {@code envCache} memoizes that environment per call address for the duration of one
	 * {@link #runDataflow}; see its declaration there for why it is not optional.
	 */
	private CallEffect recoverCallArgument(Program program, Instruction callInstr,
			HelperModel helper, BankState callSiteIn, Map<Address, RegisterEnv> envCache) {
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
		if ((helper.strategy() == null || helper.strategy().consumesHelperArgument()) &&
			!argumentSurvivesPrologue(program, prologueSegments(helper), reg)) {
			local = valueSuppliedInsideHelper(program, helper, reg, stateMask);
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
			a -> callSiteRegisters(program, callInstr, scanStop));
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
	 */
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
	 */
	private static BankState valueSuppliedInsideHelper(Program program, HelperModel helper,
			char reg, int stateMask) {
		Instruction firstSite = helper.firstSite() == null ? null
				: program.getListing().getInstructionAt(helper.firstSite());
		if (firstSite == null) {
			return BankState.unknown();
		}
		RegisterEnv insideOnly = new RegisterEnv(insideHelperEntry(helper), BankState.unknown(),
			BankState.unknown(), BankState.unknown());
		return StoredValueScanner.resolveStoredValue(program, firstSite, reg, BankState.unknown(),
			stateMask, NO_HOOKS, insideOnly);
	}

	/**
	 * The address {@code instr} reloads {@code reg} from, when it is a plain load whose target is
	 * statically certain -- the memory half of {@link #argumentSurvivesPrologue}'s save/restore
	 * model. Null for anything else, including an immediate load (no address operand at all) and
	 * an indexed one ({@link StoredValueScanner#plainAbsoluteTarget} refuses those, since their
	 * target is runtime-dependent).
	 */
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
	 */
	private static Address insideHelperEntry(HelperModel helper) {
		return helper.relay() == null ? helper.entry() : helper.relay().calleeEntry();
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

	private static Address argumentReloadSource(Instruction instr, char reg) {
		if (!("LD" + reg).equals(instr.getMnemonicString())) {
			return null;
		}
		return StoredValueScanner.plainAbsoluteTarget(instr);
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
	 */
	private static boolean writesStackPointer(Instruction instr, Register stackPointer) {
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
	 */
	private RegisterEnv callSiteRegisters(Program program, Instruction callInstr,
			Address entryAddr) {
		return new RegisterEnv(entryAddr,
			StoredValueScanner.resolveStoredValue(program, callInstr, 'A', BankState.unknown(),
				0xFF, NO_HOOKS),
			StoredValueScanner.resolveStoredValue(program, callInstr, 'X', BankState.unknown(),
				0xFF, NO_HOOKS),
			StoredValueScanner.resolveStoredValue(program, callInstr, 'Y', BankState.unknown(),
				0xFF, NO_HOOKS));
	}

	/**
	 * A helper call site's positioned effect: {@code state} is the recovered value in the
	 * board's absolute state bits (like {@link SwitchResult#effect}); {@code ownedMask} is
	 * which of those absolute bits this call site is authoritative over -- the mask
	 * {@link #runDataflow} folds {@code state} into via {@link #overwrite}, distinct from
	 * {@code state.knownMask()} for exactly the reason {@link BankSwitchStrategy.HelperDeposit}
	 * documents (a touched-but-unresolved bit is owned and poisoned; an untouched bit is
	 * neither).
	 */
	private record CallEffect(BankState state, int ownedMask) {}

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
	private int annotateOrWarn(Program program, Listing listing, Address addr, BankState state,
			BoardModel board, Map<String, Set<Integer>> bankUniverse, String viaHelper,
			String warning) {
		if (state.knownMask() == 0) {
			program.getBookmarkManager()
					.setBookmark(addr, BookmarkType.WARNING, getBookmarkCategory(), warning);
			return 1;
		}
		ImpossibleBank impossible = impossibleBank(board, state, bankUniverse);
		if (impossible != null) {
			program.getBookmarkManager().setBookmark(addr, BookmarkType.WARNING,
				getBookmarkCategory(), impossible.message());
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
	private ImpossibleBank impossibleBank(BoardModel board, BankState state,
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
		if (modeField != null &&
			(state.knownMask() & modeField.positionedMask()) == modeField.positionedMask()) {
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
	private ImpossibleBank checkBank(Map<String, Set<Integer>> bankUniverse, String key,
			String windowName, FieldSpec field, BankState state, int effective) {
		if ((state.knownMask() & field.positionedMask()) != field.positionedMask()) {
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
	private Map<String, Set<Integer>> bankUniverse(Program program, BoardModel board) {
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

	private void annotateBankSwitch(Listing listing, Address addr, BankState newState,
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

		String existing = listing.getComment(CommentType.EOL, addr);
		if (existing == null || existing.isBlank()) {
			listing.setComment(addr, CommentType.EOL, bankComment);
		}
		else if (!existing.contains("bank ->")) {
			listing.setComment(addr, CommentType.EOL, existing + "; " + bankComment);
		}
	}

	/**
	 * Records that the reference at {@code addr} was placed into bank {@code bank} because the
	 * user pinned it via the {@link DescriptorSupport#PLACEMENT_OVERRIDE_PROPERTY} override --
	 * dataflow did not recover the switchable bank here (grm-hsv.3). Uses the {@code bank ->}
	 * vocabulary so the provenance shows in the listing and the banktest dump, and defers to an
	 * existing bank-switch annotation rather than clobbering it.
	 */
	private void annotatePlacementProvenance(Listing listing, Address addr, int bank) {
		String comment = "bank -> " + bank + " [user override]";
		String existing = listing.getComment(CommentType.EOL, addr);
		if (existing == null || existing.isBlank()) {
			listing.setComment(addr, CommentType.EOL, comment);
		}
		else if (!existing.contains("bank ->")) {
			listing.setComment(addr, CommentType.EOL, existing + "; " + comment);
		}
	}

	/**
	 * Reads and parses the user bank-placement override
	 * ({@link DescriptorSupport#PLACEMENT_OVERRIDE_PROPERTY}) a loader may have persisted:
	 * a window-name -> bank map applied in {@link #retargetReferences} where dataflow left a
	 * switchable bank unknown. Absent -> empty; a malformed value (should not happen -- the
	 * loader validated it) is logged and ignored, matching the loader-degradation convention.
	 */
	private Map<String, Integer> readPlacementOverride(Program program, MessageLog log,
			boolean verbose) {
		String spec = program.getOptions(Program.PROGRAM_INFO)
				.getString(DescriptorSupport.PLACEMENT_OVERRIDE_PROPERTY, null);
		if (spec == null || spec.isBlank()) {
			return Map.of();
		}
		try {
			Map<String, Integer> override = DescriptorSupport.parsePlacementOverride(spec);
			if (verbose && !override.isEmpty()) {
				log.appendMsg(getName(), "placement override active: " + override);
			}
			return override;
		}
		catch (IllegalArgumentException e) {
			log.appendMsg(getName(),
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
	 * {@link BankSwitchStrategy#effectDependsOnPriorState()} {@code true} (i.e. an unknown
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
	 * unresolved DATA value, never from missing bank state. Bits the function itself
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
	private int annotateBankRequirementViolations(Program program, Listing listing,
			DataflowResult flow, BoardModel board, Set<Address> alreadyWarned, MessageLog log,
			boolean verbose) {

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
			if (sr.strategy() != null && sr.strategy().effectDependsOnPriorState()) {
				BankState siteIn = flow.stateIn().get(addr);
				if (siteIn != null) {
					int required = sr.effectMask() & ~(siteIn.knownMask() & sr.effectMask()) &
						~sr.effect().knownMask();
					if (required != 0) {
						ownRequires.merge(f, required, (a, b) -> a | b);
					}
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
			if (verbose) {
				log.appendMsg(getName(), "[bank-summary] " + f.getName() + ": modifies " +
					describeBits(board, mMask) + "; requires on entry " + describeBits(board, rMask) +
					"; exit " + exitState);
			}
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
					getBookmarkCategory(), "Bank state requirement violated: call to " +
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

	private int retargetReferences(Program program, ReferenceManager refMgr,
			AddressSpace baseSpace, Instruction instr, BoardModel board, BankState inState,
			Map<String, Integer> placementOverride, TaskMonitor monitor, MessageLog log) {

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
						int n = addOverlayRef(program, refMgr, instr, offset, opIndex, writeTarget,
							RefType.WRITE, true, monitor, log);
						added += n;
						primaryTaken = n > 0;
					}
					if (!readTarget.equals(homeOccupant)) {
						added += addOverlayRef(program, refMgr, instr, offset, opIndex, readTarget,
							RefType.READ, !primaryTaken, monitor, log);
					}
				}
				else {
					String target = refType.isWrite() ? writeTarget : readTarget;
					if (!target.equals(homeOccupant)) {
						added += addOverlayRef(program, refMgr, instr, offset, opIndex, target,
							refType, true, monitor, log);
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
					added += addOverlayRef(program, refMgr, instr, offset, opIndex,
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
						added += addOverlayRef(program, refMgr, instr, offset, opIndex,
							DescriptorSupport.OverlayNaming.modeBlockName(instance.name(), modeValue),
							refType, true, monitor, log);
					}
					else {
						int bank = instance.bankField().valueIn(effective);
						// When dataflow did not pin the switchable bank at this site, the value
						// above is just the initial-state fallback; a user placement override for
						// this window instance takes over (flow always wins when it knows). See
						// grm-hsv.3 -- the override is the residual escape hatch, never a guess.
						boolean bankKnown =
							(inState.knownMask() & instance.bankField().positionedMask()) != 0;
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
						added += addOverlayRef(program, refMgr, instr, offset, opIndex,
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
	private int addOverlayRef(Program program, ReferenceManager refMgr, Instruction instr,
			long offset, int opIndex, String targetSpaceName, RefType refType, boolean makePrimary,
			TaskMonitor monitor, MessageLog log) {
		AddressSpace overlaySpace = program.getAddressFactory().getAddressSpace(targetSpaceName);
		if (overlaySpace == null) {
			// Reaching here with a bank suffix means the state named a bank the image has no
			// slice for. That is not silent any more: the site that RECOVERED the impossible
			// value carries the WARNING bookmark (annotateOrWarn -> impossibleBank, grm-hum
			// increment 3), which is both a better place to look and a user-visible finding
			// rather than a log line. This branch stays as the belt-and-braces "retarget
			// nothing" half of that ruling, and still covers a descriptor/loader mismatch that
			// no recovered value is to blame for.
			log.appendMsg(getName(), "No overlay address space named '" + targetSpaceName +
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
		if (makePrimary) {
			refMgr.setPrimary(newRef, true);
		}

		// Adding a reference does not by itself pull the target into analysis: a cross-bank
		// JSR/JMP target in an overlay would stay undisassembled bytes. Kick disassembly (and
		// function creation for calls) there; the framework then re-runs this analyzer over the
		// new instructions until convergence (their in-overlay bank state comes from the
		// residence clamp).
		if (refType.isFlow() &&
			program.getListing().getInstructionAt(overlayAddr) == null) {
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
	private static ModeWindowModel findModeWindowInstance(List<ModeWindowModel> modeWindows,
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
	private void stampContextRegister(Program program, JsonObject banking,
			Map<Address, BankState> stateIn, Listing listing, int mask, MessageLog log,
			boolean verbose) {
		if (!banking.has("context_register")) {
			return;
		}
		Register register = program.getRegister(banking.get("context_register").getAsString());
		if (register == null) {
			log.appendMsg(getName(), "context_register '" +
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
				log.appendMsg(getName(),
					"context stamp failed at " + entry.getKey() + ": " + e.getMessage());
				return;
			}
		}
		if (verbose && stamped > 0) {
			log.appendMsg(getName(),
				"stamped " + register.getName() + " over " + stamped + " instructions");
		}
	}

	// ------------------------------------------------------------------
	// Descriptor model
	// ------------------------------------------------------------------

	/** One {@code banking.state} field: its bit position and width within the state int. */
	private record FieldSpec(String name, int lsb, int width) {

		int positionedMask() {
			return ((1 << width) - 1) << lsb;
		}

		int valueIn(int state) {
			return (state >> lsb) & ((1 << width) - 1);
		}
	}

	private record OccupantModel(String name, String kind, String onWrite) {}

	/** An address window with an inclusive {@code [start, end]} offset range in base space. */
	private interface Bounded {
		long start();

		long end();
	}

	private record WindowModel(String name, long start, long end,
			Map<String, OccupantModel> occupants) implements Bounded {}

	/** A computed window driven by a single state field; per-bank overlays are named
	 *  {@code <name>_B<fieldValue>} by the loader, home bank in base space. */
	private record ComputedWindowModel(String name, long start, long end, FieldSpec field,
			String onWrite) implements Bounded {}

	/**
	 * One {@code (windowName, modeValue)} instance out of {@code memory.layouts[]}
	 * (bead grm-qvi): {@code bankField} is null for a mode-varying <em>fixed</em> window
	 * instance (a constant {@code maps:} expr under this mode -- the loader's non-home
	 * layout instances become {@code <name>_M<mode>} overlays), non-null for a
	 * <em>switchable</em> instance (a single-field {@code maps:} expr -- the loader's
	 * per-bank instances become {@code <name>_M<mode>_B<bank>} overlays). Mirrors
	 * {@link NesRomLoader}'s realizeVaryingWindows fixed-vs-switchable test
	 * ({@code referencedFields(expr).isEmpty()}), so the analyzer and loader agree on
	 * which instances are fixed without re-deriving it differently.
	 */
	private record ModeWindowModel(String name, long start, long end, int modeValue,
			FieldSpec bankField, String onWrite) {}

	/** Everything phase-independent parsed out of the descriptor. */
	private record BoardModel(int mask, int initialState, List<String> stateBitNames,
			List<FieldSpec> fieldSpecs, Map<String, WindowModel> windows,
			Map<String, ComputedWindowModel> computedWindows,
			Map<Integer, Map<String, String>> occupantByWindowForState,
			Map<String, String> homeOccupantByWindow, FieldSpec modeField, int homeModeValue,
			List<ModeWindowModel> modeWindows) {

		/**
		 * Parses the {@code banking} and {@code windows} sections of a board descriptor into
		 * a {@link BoardModel}. Returns {@code null} when a required section is missing or
		 * inconsistent, in which case the caller should skip bank-state analysis (but this is
		 * not an error -- callers should treat a {@code null} result like the other "skip"
		 * paths in {@code added()}, not like an {@link IOException}).
		 */
		private static BoardModel parse(JsonObject map, MessageLog log, String source,
				String mapPath) {
			JsonObject banking = map.getAsJsonObject("banking");
			if (banking == null || !banking.has("mechanisms")) {
				log.appendMsg(source, "banking.mechanisms missing from " + mapPath +
					"; skipping bank-state analysis");
				return null;
			}
			if (!banking.has("initial_state")) {
				log.appendMsg(source, "banking.initial_state missing from " + mapPath +
					"; skipping bank-state analysis");
				return null;
			}

			int initialState = banking.get("initial_state").getAsInt();

			// The tracked-bit mask, per-bit annotation names, and field layout come from the
			// banking.state field tuple (LSB first; multi-bit fields expand to name.0, ...).
			List<String> stateBitNames = new ArrayList<>();
			List<FieldSpec> fieldSpecs = new ArrayList<>();
			if (banking.has("state")) {
				for (JsonElement fe : banking.getAsJsonArray("state")) {
					JsonObject field = fe.getAsJsonObject();
					String fieldName = field.get("name").getAsString();
					int bits = field.get("bits").getAsInt();
					fieldSpecs.add(new FieldSpec(fieldName, stateBitNames.size(), bits));
					if (bits == 1) {
						stateBitNames.add(fieldName);
					}
					else {
						for (int i = 0; i < bits; i++) {
							stateBitNames.add(fieldName + "." + i);
						}
					}
				}
			}
			int mask = (1 << stateBitNames.size()) - 1;

			// --- Parse windows: enumerated occupants (C64-style, raw JSON -- PlannedWindow
			// does not carry occupants) come straight off memory.windows[]; computed maps:
			// windows (mode-invariant and mode-varying alike) are driven off the normalized
			// DescriptorSupport.planWindows() plan so this engine and NesRomLoader agree on
			// what a window's instances are without re-walking memory.layouts[] separately.
			Map<String, WindowModel> windowsByName = new LinkedHashMap<>();
			JsonArray windows = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
			for (JsonElement we : windows) {
				JsonObject window = we.getAsJsonObject();
				if (!window.has("occupants")) {
					continue; // computed (maps:) windows are handled via the plan below
				}
				String name = window.get("name").getAsString();
				long start = window.get("start").getAsLong();
				long end = window.get("end").getAsLong();
				Map<String, OccupantModel> occupants = new LinkedHashMap<>();
				for (JsonElement oe : window.getAsJsonArray("occupants")) {
					JsonObject occ = oe.getAsJsonObject();
					String occName = occ.get("name").getAsString();
					String kind = occ.get("kind").getAsString();
					String onWrite = occ.has("on_write") ? occ.get("on_write").getAsString() : null;
					occupants.put(occName, new OccupantModel(occName, kind, onWrite));
				}
				windowsByName.put(name, new WindowModel(name, start, end, occupants));
			}

			DescriptorSupport.LayoutPlan plan = DescriptorSupport.planWindows(map, log, mapPath);

			Map<String, ComputedWindowModel> computedByName = new LinkedHashMap<>();
			for (DescriptorSupport.PlannedWindow pw : plan.invariant()) {
				if (pw.expr() == null) {
					continue; // enumerated occupant window, already handled above
				}
				Set<String> fields = DescriptorSupport.referencedFields(pw.expr());
				if (fields.isEmpty()) {
					continue; // fixed window -- placed by the loader, never retargeted
				}
				if (fields.size() > 1) {
					log.appendMsg(source, "computed window '" + pw.name() + "' uses " + fields +
						"; multi-field windows are not supported yet -- not retargeting it");
					continue;
				}
				String fieldName = fields.iterator().next();
				FieldSpec fieldSpec = fieldSpecs.stream()
						.filter(f -> f.name().equals(fieldName))
						.findFirst()
						.orElse(null);
				if (fieldSpec == null) {
					log.appendMsg(source, "computed window '" + pw.name() +
						"' references unknown state field '" + fieldName + "'; skipping it");
					continue;
				}
				computedByName.put(pw.name(),
					new ComputedWindowModel(pw.name(), pw.start(), pw.end(), fieldSpec, pw.onWrite()));
			}

			// --- Mode-varying windows (memory.layouts[]) ---
			FieldSpec modeField = null;
			int homeModeValue = 0;
			List<ModeWindowModel> modeWindows = new ArrayList<>();
			if (plan.modeField() != null) {
				modeField = fieldSpecs.stream()
						.filter(f -> f.name().equals(plan.modeField()))
						.findFirst()
						.orElse(null);
				if (modeField == null) {
					log.appendMsg(source, "memory.layouts[] mode field '" + plan.modeField() +
						"' not found in banking.state; skipping mode-varying windows");
				}
				else {
					homeModeValue = modeField.valueIn(initialState);
					for (DescriptorSupport.PlannedWindow pw : plan.varying()) {
						if (pw.expr() == null) {
							log.appendMsg(source, "Window '" + pw.name() +
								"' has enumerated occupants; not supported for mode-varying windows");
							continue;
						}
						Set<String> exprFields = DescriptorSupport.referencedFields(pw.expr());
						FieldSpec bankField = null;
						if (!exprFields.isEmpty()) {
							if (exprFields.size() > 1) {
								log.appendMsg(source, "mode-varying window '" + pw.name() + "' (mode " +
									plan.modeField() + "=" + pw.modeValue() + ") uses " + exprFields +
									"; multi-field windows are not supported -- skipping that instance");
								continue;
							}
							String fieldName = exprFields.iterator().next();
							bankField = fieldSpecs.stream()
									.filter(f -> f.name().equals(fieldName))
									.findFirst()
									.orElse(null);
							if (bankField == null) {
								log.appendMsg(source, "mode-varying window '" + pw.name() + "' (mode " +
									plan.modeField() + "=" + pw.modeValue() +
									") references unknown state field '" + fieldName +
									"'; skipping that instance");
								continue;
							}
						}
						modeWindows.add(new ModeWindowModel(pw.name(), pw.start(), pw.end(),
							pw.modeValue(), bankField, pw.onWrite()));
					}
				}
			}

			Map<Integer, Map<String, String>> occupantByWindowForState = new LinkedHashMap<>();
			if (banking.has("states")) {
				for (JsonElement se : banking.getAsJsonArray("states")) {
					JsonObject state = se.getAsJsonObject();
					int value = state.get("value").getAsInt();
					Map<String, String> row = new LinkedHashMap<>();
					for (String windowName : windowsByName.keySet()) {
						if (state.has(windowName)) {
							row.put(windowName, state.get(windowName).getAsString());
						}
					}
					occupantByWindowForState.put(value, row);
				}
			}

			Map<String, String> homeOccupantByWindow = occupantByWindowForState.get(initialState);
			if (!windowsByName.isEmpty() && homeOccupantByWindow == null) {
				log.appendMsg(source, "banking.initial_state " + initialState +
					" not found in banking.states; skipping bank-state analysis");
				return null;
			}

			return new BoardModel(mask, initialState, stateBitNames, fieldSpecs, windowsByName,
				computedByName, occupantByWindowForState, homeOccupantByWindow, modeField,
				homeModeValue, modeWindows);
		}
	}

	/**
	 * One descriptor mechanism entry, instantiated and positioned: {@code strategy} is the
	 * configured {@link BankSwitchStrategy}, which computes entirely in its own field-local
	 * {@code [0, width)} coordinate space; {@code effectMask} and {@code lsb} say where that
	 * space lands in the board's absolute state bits (see {@link #mechanismPositioning}).
	 * For every shipped (single-mechanism) board {@code effectMask == board.mask()} and
	 * {@code lsb == 0}, so field-local and absolute coincide.
	 */
	private record ConfiguredMechanism(BankSwitchStrategy strategy, int effectMask, int lsb) {}

	/**
	 * One recognized switch site's positioned effect (grm-ezl): {@code effect} is the pure
	 * effect of the mechanism that matched here -- positioned into absolute state bits, but
	 * <em>not</em> folded against any in-state -- kept separately from the folded
	 * {@code stateIn} because annotation and helper-classification key off the pure effect,
	 * not the composite. {@code effectMask}/{@code lsb} identify which mechanism produced it
	 * (the same pair as the matching {@link ConfiguredMechanism}), so downstream consumers
	 * (helper classification, call-argument recovery) know which bits it's authoritative
	 * over without re-deriving it from the descriptor. {@code strategy} is the matched
	 * mechanism's own strategy instance, carried through so a helper call site can later
	 * ask it to position a recovered argument via
	 * {@link BankSwitchStrategy#depositHelperArgument} instead of the engine guessing.
	 */
	private record SwitchResult(BankState effect, int effectMask, int lsb,
			BankSwitchStrategy strategy) {}

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
	private record HelperModel(Function function, Address entry, BankState constState,
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

	/**
	 * A resolved call-site switch (for annotation, distinct from direct switches).
	 * {@code effect} is the call's own recovered deposit (positioned, known bits limited to
	 * what the argument scan resolved of the bits this call site owns) -- the WARN decision
	 * keys off it, exactly as a direct switch warns off its pure effect. {@code stateAfter}
	 * is the post-call state of the helper's own MECHANISM WINDOW: the in-state narrowed to
	 * the helper's {@code effectMask}, overwritten by {@code effect} on the call's owned
	 * bits. The COMMENT is rendered from it, because a helper deposit, unlike a
	 * {@code computeSwitch} result, has no in-state echoed into it: without this, every
	 * sibling field the call doesn't own would render as "assumed from initial" even when
	 * the dataflow knows it perfectly well. Narrowing the echo to the mechanism window
	 * (rather than folding over the whole tracked state) keeps the comment's knowledge
	 * horizon identical to a direct switch's at the same spot -- a {@code computeSwitch}
	 * result echoes exactly its own mechanism's in-state bits, never another mechanism's,
	 * so a helper-call comment on a multi-mechanism board keeps showing other mechanisms'
	 * fields as assumed, exactly as it always did. For a single-field helper (owned == the
	 * whole mechanism window) {@code stateAfter == effect}, so the historical path is
	 * unchanged byte-for-byte.
	 */
	private record CallSwitch(String helperName, BankState effect, BankState stateAfter) {}

	/**
	 * Per-address strategy-probe cache entry for {@link #runDataflow} (grm-5tl.13.2).
	 * {@code mechanism == null} records that no strategy's instruction-level predicate
	 * matched this address at all. Otherwise {@code mechanism} is the one mechanism whose
	 * strategy predicate matched; {@code result} holds its state-independent, field-local
	 * result when {@link BankSwitchStrategy#cacheable()} is true, or {@code null} when the
	 * match was found but the value must be recomputed from the current in-state on every
	 * dequeue.
	 */
	private record MatchInfo(ConfiguredMechanism mechanism, BankState result) {}

	private record DataflowResult(Map<Address, BankState> stateIn,
			Map<Address, SwitchResult> switchResults, Map<Address, CallSwitch> callSwitches) {}
}
