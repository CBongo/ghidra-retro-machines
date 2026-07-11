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
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
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

		// Redundant-re-run gate (grm-5tl.13.3): see LAST_COMPLETED for the invariants.
		long fingerprint = fingerprint(program);
		RunStamp last = LAST_COMPLETED.get(program);
		if (last != null && last.fingerprint() == fingerprint && last.mapPath().equals(mapPath)) {
			log.appendMsg(getName(), tag + ": no function/instruction changes since last " +
				"completed run; skipping redundant whole-program re-analysis");
			return true;
		}
		log.appendMsg(getName(), tag + " running (" + mapPath + ")");

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
			log.appendMsg(getName(), helpers.size() + " bank-switch helper function(s): " +
				helpers.keySet().stream().map(Function::getName).sorted().toList());
			flow = runDataflow(program, monitor, listing, mechanisms, board, helpers);
		}

		// --- Phase 2: annotate bank switches + retarget references ---
		ReferenceManager refMgr = program.getReferenceManager();
		int refsAdded = 0;
		int warnings = 0;
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
				warnings += annotateOrWarn(program, listing, addr, switchResult.effect(), board, null,
					"Bank state becomes unknown here: mechanism write with a genuinely " +
						"undeterminable value (value recovery could not pin down even one " +
						"tracked bank bit -- e.g. a load of an unrelated address followed " +
						"directly by the store, with no AND/ORA immediate to constrain it)");
			}

			CallSwitch callSwitch = flow.callSwitches().get(addr);
			if (callSwitch != null) {
				warnings += annotateOrWarn(program, listing, addr, callSwitch.state(), board,
					callSwitch.helperName(),
					"Bank state becomes unknown here: call to bank-switch helper " +
						callSwitch.helperName() + " whose bank argument could not be " +
						"recovered at this call site");
			}

			int effective = inState.effective(board.initialState(), board.mask());
			refsAdded += retargetReferences(program, refMgr, baseSpace, instr, board, effective,
				monitor, log);
		}

		// --- Context stamping: only when the language actually declares the register ---
		stampContextRegister(program, banking, flow.stateIn(), listing, board.mask(), log);

		log.appendMsg(getName(), tag + ": " + flow.stateIn().size() + " instructions tracked, " +
			refsAdded + " overlay references added/confirmed, " + warnings +
			" unknown-state warnings");

		// Record the ENTRY-time fingerprint only now that the run completed: phase 2's own
		// disassembly/function side effects have moved the live counts past it, so the
		// framework round they trigger will not match and will run in full.
		LAST_COMPLETED.put(program, new RunStamp(fingerprint, mapPath));
		return true;
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
				// Strategies always compute in field-local [0, width) coordinates; the mask
				// they configure with is that field-local width, not the whole board mask.
				instance.configure(program, mechanism.getAsJsonObject("params"), effectMask >>> lsb);
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
					matchedMechanism.effectMask(), matchedMechanism.lsb()));
				outState = overwrite(inState, positionedEffect, matchedMechanism.effectMask());
			}

			BankState fallState = outState;
			if (helpers != null && instr.getFlowType().isCall()) {
				HelperModel helper = calledHelper(program, instr, helpers);
				if (helper != null) {
					BankState effect = helper.constState() != null ? helper.constState()
							: recoverCallArgument(program, instr, helper);
					callSwitches.put(addr, new CallSwitch(helper.function().getName(), effect));
					fallState = overwrite(outState, effect, helper.effectMask());
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
					site.effectMask(), site.lsb()));
			}
			else if (existing.effectMask() == site.effectMask() && existing.lsb() == site.lsb()) {
				BankState constState = existing.constState() != null
						&& !existing.constState().equals(result) ? null : existing.constState();
				Character argReg = Objects.equals(existing.argReg(), reg) ? reg : null;
				helpers.put(f, new HelperModel(f, constState, argReg,
					site.effectMask(), site.lsb()));
			}
			else {
				// Sites in this helper belong to different mechanisms -- degrade to the
				// conservative union (see javadoc above).
				helpers.put(f, new HelperModel(f, null, null,
					existing.effectMask() | site.effectMask(), 0));
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
	 * convention as {@link BankSwitchStrategy#computeSwitch}), and the result is positioned
	 * back into the board's absolute state bits before returning, exactly as a direct
	 * dataflow switch would be. Returns a positioned {@link BankState#unknown()} when the
	 * argument register is unknown or its value does not resolve -- the caller conservatively
	 * loses the bank state across the call.
	 */
	private BankState recoverCallArgument(Program program, Instruction callInstr,
			HelperModel helper) {
		Character reg = helper.argReg();
		if (reg == null) {
			return BankState.unknown();
		}
		BankState local = StoredValueScanner.resolveStoredValue(program, callInstr, reg,
			BankState.unknown(), helper.effectMask() >>> helper.lsb(), NO_HOOKS);
		return position(local, helper.lsb(), helper.effectMask());
	}

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
	 * is fully known, the comment is {@code bank -> 5 (RAM_A000/IO/RAM_E000)} (occupant
	 * row on enumerated boards, {@code bank=5} field values on computed boards). When
	 * only some bits are known, the comment marks the effective state with a trailing
	 * {@code ?} and spells out, by {@code banking.state} field name, which bits are
	 * actually known versus merely assumed from {@code banking.initial_state} -- e.g.
	 * {@code bank -> 7? (BASIC/IO/KERNAL) [known: LORAM=1; assumed from initial:
	 * HIRAM,CHAREN]}. Call-site switches carry the helper's name.
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

		String bankComment;
		if (newState.knownMask() == mask) {
			bankComment = "bank -> " + effective + " (" + desc + ")" + via;
		}
		else {
			List<String> known = new ArrayList<>();
			List<String> assumed = new ArrayList<>();
			for (int bit = 0; bit < 8; bit++) {
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
			bankComment = "bank -> " + effective + "? (" + desc + ")" + via + " [known: " +
				String.join(",", known) + "; assumed from initial: " + String.join(",", assumed) +
				"]";
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
	// Reference retargeting
	// ------------------------------------------------------------------

	private int retargetReferences(Program program, ReferenceManager refMgr,
			AddressSpace baseSpace, Instruction instr, BoardModel board, int effective,
			TaskMonitor monitor, MessageLog log) {

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
				if (computed == null) {
					continue;
				}
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
					DescriptorSupport.OverlayNaming.bankBlockName(computed.name(), bankValue), refType,
					true, monitor, log);
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
			Map<Address, BankState> stateIn, Listing listing, int mask, MessageLog log) {
		if (!banking.has("context_register")) {
			return;
		}
		Register register = program.getRegister(banking.get("context_register").getAsString());
		if (register == null) {
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
		if (stamped > 0) {
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

	/** Everything phase-independent parsed out of the descriptor. */
	private record BoardModel(int mask, int initialState, List<String> stateBitNames,
			List<FieldSpec> fieldSpecs, Map<String, WindowModel> windows,
			Map<String, ComputedWindowModel> computedWindows,
			Map<Integer, Map<String, String>> occupantByWindowForState,
			Map<String, String> homeOccupantByWindow) {

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

			// --- Parse windows (enumerated occupants OR computed maps:) + banking states ---
			Map<String, WindowModel> windowsByName = new LinkedHashMap<>();
			Map<String, ComputedWindowModel> computedByName = new LinkedHashMap<>();
			JsonArray windows = map.has("windows") ? map.getAsJsonArray("windows") : new JsonArray();
			for (JsonElement we : windows) {
				JsonObject window = we.getAsJsonObject();
				String name = window.get("name").getAsString();
				long start = window.get("start").getAsLong();
				long end = window.get("end").getAsLong();
				if (window.has("occupants")) {
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
				else if (window.has("maps")) {
					String expr = window.getAsJsonObject("maps").get("expr").getAsString();
					Set<String> fields = DescriptorSupport.referencedFields(expr);
					if (fields.isEmpty()) {
						continue; // fixed window -- placed by the loader, never retargeted
					}
					if (fields.size() > 1) {
						log.appendMsg(source, "computed window '" + name + "' uses " + fields +
							"; multi-field windows are not supported yet -- not retargeting it");
						continue;
					}
					String fieldName = fields.iterator().next();
					FieldSpec fieldSpec = fieldSpecs.stream()
							.filter(f -> f.name().equals(fieldName))
							.findFirst()
							.orElse(null);
					if (fieldSpec == null) {
						log.appendMsg(source, "computed window '" + name +
							"' references unknown state field '" + fieldName + "'; skipping it");
						continue;
					}
					String onWrite = window.has("on_write") ? window.get("on_write").getAsString() : null;
					computedByName.put(name,
						new ComputedWindowModel(name, start, end, fieldSpec, onWrite));
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
				computedByName, occupantByWindowForState, homeOccupantByWindow);
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
	 * over without re-deriving it from the descriptor.
	 */
	private record SwitchResult(BankState effect, int effectMask, int lsb) {}

	/**
	 * A helper function's modeled effect: a constant state, or null = caller-supplied. For
	 * caller-supplied helpers, {@code argReg} is the register (A/X/Y) the helper stores into
	 * its mechanism -- i.e. the register by which the caller passes the bank field -- or null
	 * when the helper's switch sites disagree on that register or use a non-{@code ST<reg>}
	 * write, in which case the argument convention is unknown. {@code effectMask}/{@code lsb}
	 * are the mechanism's positioning (or the conservative union of several, when the
	 * helper's sites span more than one mechanism -- see {@link #findHelpers}), used to fold
	 * this helper's effect into only the state bits it actually owns.
	 */
	private record HelperModel(Function function, BankState constState, Character argReg,
			int effectMask, int lsb) {}

	/** A resolved call-site switch (for annotation, distinct from direct switches). */
	private record CallSwitch(String helperName, BankState state) {}

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
