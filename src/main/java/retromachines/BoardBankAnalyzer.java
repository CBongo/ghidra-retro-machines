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

		Map<Function, HelperModel> helpers = findHelpers(program, flow.switchResults());
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
				int w = annotateOrWarn(program, listing, addr, switchResult.effect(), board, null,
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
				int w = annotateOrWarn(program, listing, addr, annotState, board,
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
							: recoverCallArgument(program, instr, helper, outState);
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
						callSwitches.put(addr, new CallSwitch(helper.function().getName(),
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
	 * Every function containing a recognized mechanism write is a bank-switch helper.
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
				helpers.put(f, new HelperModel(f,
					result.knownMask() == site.effectMask() ? result : null, reg,
					site.effectMask(), site.lsb(), site.strategy(), entry.getKey()));
			}
			else if (existing.effectMask() == site.effectMask() && existing.lsb() == site.lsb()) {
				BankState constState = existing.constState() != null
						&& !existing.constState().equals(result) ? null : existing.constState();
				Character argReg = Objects.equals(existing.argReg(), reg) ? reg : null;
				// When several instructions in this helper share the same mechanism (e.g. a
				// serial-shift chain's 5 stores), the switch site that decides WHICH sub-field
				// a call-site argument commits through is the one whose own address encodes
				// that decision -- for every idiom this engine recognizes, that is the LAST
				// (highest-address) recognized write in program order (an unrolled chain's
				// write-5 STA, or a counted loop's closing BNE, both of which sit after their
				// chain's earlier writes). Keeping the max-address entry is a no-op for every
				// single-instruction mechanism (register-write, memory-latch: exactly one site
				// per helper) and picks the correct commit site for serial-shift.
				Address switchSite = entry.getKey().compareTo(existing.switchSite()) > 0
						? entry.getKey() : existing.switchSite();
				helpers.put(f, new HelperModel(f, constState, argReg,
					site.effectMask(), site.lsb(), site.strategy(), switchSite));
			}
			else {
				// Sites in this helper belong to different mechanisms -- degrade to the
				// conservative union (see javadoc above). argReg is forced null, so
				// recoverCallArgument short-circuits before ever consulting strategy/
				// switchSite -- both left null/unset is safe.
				helpers.put(f, new HelperModel(f, null, null,
					existing.effectMask() | site.effectMask(), 0, null, null));
			}
		}
		return helpers;
	}

	/** The helper this call instruction targets, or null. */
	private HelperModel calledHelper(Program program, Instruction callInstr,
			Map<Function, HelperModel> helpers) {
		for (Address flowAddr : callInstr.getFlows()) {
			Function f = program.getFunctionManager().getFunctionAt(flowAddr);
			if (f != null) {
				HelperModel helper = helpers.get(f);
				if (helper != null) {
					return helper;
				}
			}
		}
		return null;
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
	 */
	private CallEffect recoverCallArgument(Program program, Instruction callInstr,
			HelperModel helper, BankState callSiteIn) {
		Character reg = helper.argReg();
		if (reg == null) {
			return new CallEffect(BankState.unknown(), helper.effectMask());
		}
		int stateMask = helper.effectMask() >>> helper.lsb();
		BankState local = StoredValueScanner.resolveStoredValue(program, callInstr, reg,
			BankState.unknown(), stateMask, NO_HOOKS);
		Instruction switchSite = helper.switchSite() == null ? null
				: program.getListing().getInstructionAt(helper.switchSite());
		if (helper.strategy() == null || switchSite == null) {
			return new CallEffect(position(local, helper.lsb(), helper.effectMask()),
				helper.effectMask());
		}
		BankState localIn = new BankState(
			(callSiteIn.knownMask() & helper.effectMask()) >>> helper.lsb(),
			(callSiteIn.bits() & helper.effectMask()) >>> helper.lsb());
		BankSwitchStrategy.HelperDeposit deposit =
			helper.strategy().depositHelperArgument(program, switchSite, local, localIn, stateMask);
		BankState positionedValue = position(deposit.value(), helper.lsb(), helper.effectMask());
		int positionedOwnedMask = (deposit.ownedMask() << helper.lsb()) & helper.effectMask();
		return new CallEffect(positionedValue, positionedOwnedMask);
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
		public BankState resolveLoad(Instruction loadInstr, BankState inStateAtStore) {
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
	 * bit is known, or the {@code warning} bookmark when value recovery pinned down no bit
	 * at all. Returns the number of warnings raised (0 or 1) for the caller's tally.
	 */
	private int annotateOrWarn(Program program, Listing listing, Address addr, BankState state,
			BoardModel board, String viaHelper, String warning) {
		if (state.knownMask() == 0) {
			program.getBookmarkManager()
					.setBookmark(addr, BookmarkType.WARNING, getBookmarkCategory(), warning);
			return 1;
		}
		annotateBankSwitch(listing, addr, state, board, viaHelper);
		return 0;
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
	 * for each switch site in a function's own body whose matched strategy is not
	 * {@link BankSwitchStrategy#cacheable()} (i.e. {@code computeSwitch} may consult
	 * {@code inState}), the bits the switch's OWN effect ends up NOT knowing that the
	 * flowed-in {@code inState} ALSO did not know -- {@code effectMask & ~inState.knownMask
	 * & ~effect.knownMask()}. That intersection is exactly "the dispatch needed this bit
	 * and didn't have it": a cacheable strategy (pure function of program+instruction)
	 * never contributes, and a non-cacheable strategy whose effect came out fully known
	 * anyway (e.g. a plain {@code LDA #imm/STA} sequence, or a masked-RMW read-back that
	 * resolved cleanly from known in-state) also contributes nothing, since
	 * {@code ~effect.knownMask()} is empty there. Bits the function itself establishes
	 * BEFORE a later consuming site are automatically excluded -- not by explicit program-
	 * order subtraction, but because {@code flow.stateIn()} at that later site already
	 * reflects every predecessor on the real CFG, including earlier code in the same
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
			if (sr.strategy() != null && !sr.strategy().cacheable()) {
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
					for (Address flowAddr : instr.getFlows()) {
						Function callee = fm.getFunctionAt(flowAddr);
						if (callee != null) {
							calls.add(new DirectCallSite(addr, callee));
							break; // a direct call resolves to exactly one target
						}
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
	 * {@code switchSite} is the recognized switch instruction (the highest-address one, when
	 * a helper's sites span several instructions of the same mechanism -- e.g. a serial-shift
	 * chain's 5 stores all resolve to the same target address here, but for an idiom where
	 * they could legitimately differ, the LAST write is the one whose address actually
	 * decides the target, per {@link SerialShiftBankSwitchStrategy}) that
	 * {@link BankSwitchStrategy#depositHelperArgument} is asked to interpret a call site's
	 * argument against.
	 */
	private record HelperModel(Function function, BankState constState, Character argReg,
			int effectMask, int lsb, BankSwitchStrategy strategy, Address switchSite) {}

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
