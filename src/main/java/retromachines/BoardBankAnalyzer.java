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
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
 * instruction ranges via {@code ProgramContext.setValue}. Stock languages (6502) don't
 * declare it, so this stays dormant until the bundled 6510 language lands (grm-bk6).</li>
 * </ul>
 * Concrete subclasses (e.g. {@link C64BankingAnalyzer}) supply only the loader gate,
 * the descriptor path, and the analyzer's name -- no analysis logic.
 */
public abstract class BoardBankAnalyzer extends AbstractAnalyzer {

	protected BoardBankAnalyzer(String name, String description) {
		super(name, description, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after Ghidra's own reference analysis has laid down the default (base-space)
		// operand/flow references we need to inspect and, where wrong, supersede.
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
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
		log.appendMsg(getName(), tag + " running (" + mapPath + ")");

		JsonObject map;
		try {
			map = DescriptorSupport.loadMap(mapPath);
		}
		catch (IOException e) {
			log.appendMsg(getName(), "Failed to load " + mapPath + ": " + e.getMessage());
			return false;
		}

		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("mechanisms")) {
			log.appendMsg(getName(), "banking.mechanisms missing from " + mapPath +
				"; skipping bank-state analysis");
			return true;
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

		List<BankSwitchStrategy> strategies =
			configureStrategies(program, banking.getAsJsonArray("mechanisms"), mask, log);
		if (strategies.isEmpty()) {
			log.appendMsg(getName(), "no usable bank-switch strategy in " + mapPath +
				" banking; skipping bank-state analysis");
			return true;
		}

		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

		// --- Parse windows (enumerated occupants OR computed maps:) + banking states ---
		Map<String, WindowModel> windowsByName = new LinkedHashMap<>();
		Map<String, ComputedWindowModel> computedByName = new LinkedHashMap<>();
		for (JsonElement we : map.getAsJsonArray("windows")) {
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
					log.appendMsg(getName(), "computed window '" + name + "' uses " + fields +
						"; multi-field windows are not supported yet -- not retargeting it");
					continue;
				}
				String fieldName = fields.iterator().next();
				FieldSpec fieldSpec = fieldSpecs.stream()
						.filter(f -> f.name().equals(fieldName))
						.findFirst()
						.orElse(null);
				if (fieldSpec == null) {
					log.appendMsg(getName(), "computed window '" + name +
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
			log.appendMsg(getName(), "banking.initial_state " + initialState +
				" not found in banking.states; skipping bank-state analysis");
			return true;
		}

		BoardModel board = new BoardModel(mask, initialState, stateBitNames, fieldSpecs,
			windowsByName, computedByName, occupantByWindowForState, homeOccupantByWindow);

		// --- Phase 1: forward dataflow to fixpoint; rerun with helper knowledge if any ---
		Listing listing = program.getListing();
		DataflowResult flow = runDataflow(program, monitor, listing, strategies, board, null);

		Map<Function, HelperModel> helpers = findHelpers(program, flow.switchResults(), board);
		if (!helpers.isEmpty()) {
			log.appendMsg(getName(), helpers.size() + " bank-switch helper function(s): " +
				helpers.keySet().stream().map(Function::getName).sorted().toList());
			flow = runDataflow(program, monitor, listing, strategies, board, helpers);
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

			BankState switched = flow.switchResults().get(addr);
			if (switched != null) {
				if (switched.knownMask() == 0) {
					warnings++;
					program.getBookmarkManager()
							.setBookmark(addr, BookmarkType.WARNING, getBookmarkCategory(),
								"Bank state becomes unknown here: mechanism write with a " +
									"genuinely undeterminable value (value recovery could not " +
									"pin down even one tracked bank bit -- e.g. a load of an " +
									"unrelated address followed directly by the store, with no " +
									"AND/ORA immediate to constrain it)");
				}
				else {
					annotateBankSwitch(listing, addr, switched, board, null);
				}
			}

			CallSwitch callSwitch = flow.callSwitches().get(addr);
			if (callSwitch != null) {
				if (callSwitch.state().knownMask() == 0) {
					warnings++;
					program.getBookmarkManager()
							.setBookmark(addr, BookmarkType.WARNING, getBookmarkCategory(),
								"Bank state becomes unknown here: call to bank-switch helper " +
									callSwitch.helperName() + " whose bank argument could not " +
									"be recovered at this call site");
				}
				else {
					annotateBankSwitch(listing, addr, callSwitch.state(), board,
						callSwitch.helperName());
				}
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
		return true;
	}

	// ------------------------------------------------------------------
	// Strategy configuration
	// ------------------------------------------------------------------

	/**
	 * Instantiates and configures one {@link BankSwitchStrategy} per descriptor
	 * mechanism entry, matching {@code mechanisms[].strategy} to implementations found
	 * by ClassSearcher. Unknown strategy names are logged and skipped (they belong to
	 * later milestones).
	 */
	private List<BankSwitchStrategy> configureStrategies(Program program, JsonArray mechanisms,
			int stateMask, MessageLog log) {
		List<BankSwitchStrategy> prototypes = ClassSearcher.getInstances(BankSwitchStrategy.class);
		List<BankSwitchStrategy> configured = new ArrayList<>();
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
			try {
				BankSwitchStrategy instance =
					prototype.getClass().getDeclaredConstructor().newInstance();
				instance.configure(program, mechanism.getAsJsonObject("params"), stateMask);
				configured.add(instance);
			}
			catch (Exception e) {
				log.appendMsg(getName(), "failed to configure strategy '" + strategyName + "': " +
					e.getMessage());
			}
		}
		return configured;
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
			List<BankSwitchStrategy> strategies, BoardModel board,
			Map<Function, HelperModel> helpers) throws CancelledException {

		Map<Address, BankState> stateIn = new HashMap<>();
		Map<Address, BankState> switchResults = new HashMap<>();
		Map<Address, CallSwitch> callSwitches = new HashMap<>();
		Deque<Address> worklist = new ArrayDeque<>();
		Map<String, int[]> clampCache = new HashMap<>();

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

			for (BankSwitchStrategy strategy : strategies) {
				BankState switched = strategy.computeSwitch(program, instr, inState);
				if (switched != null) {
					switchResults.put(addr, switched);
					outState = switched;
					break;
				}
			}

			BankState fallState = outState;
			if (helpers != null && instr.getFlowType().isCall()) {
				HelperModel helper = calledHelper(program, instr, helpers);
				if (helper != null) {
					BankState afterCall = helper.constState() != null ? helper.constState()
							: recoverCallArgument(program, instr, board.mask());
					callSwitches.put(addr, new CallSwitch(helper.function().getName(), afterCall));
					fallState = afterCall;
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
				String prefix = w.name() + "_B";
				if (name.startsWith(prefix)) {
					try {
						int v = Integer.parseInt(name.substring(prefix.length()));
						FieldSpec f = w.field();
						return new int[] { f.positionedMask(), (v << f.lsb()) & f.positionedMask() };
					}
					catch (NumberFormatException e) {
						// not one of ours (e.g. a C64 occupant overlay) -- fall through
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
	 */
	private Map<Function, HelperModel> findHelpers(Program program,
			Map<Address, BankState> switchResults, BoardModel board) {
		Map<Function, HelperModel> helpers = new LinkedHashMap<>();
		for (Map.Entry<Address, BankState> entry : switchResults.entrySet()) {
			Function f = program.getFunctionManager().getFunctionContaining(entry.getKey());
			if (f == null) {
				continue;
			}
			BankState result = entry.getValue();
			HelperModel existing = helpers.get(f);
			if (existing == null) {
				helpers.put(f, new HelperModel(f,
					result.knownMask() == board.mask() ? result : null));
			}
			else if (existing.constState() != null && !existing.constState().equals(result)) {
				helpers.put(f, new HelperModel(f, null));
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
	 * Recovers the bank argument at a helper call site by running the shared backward
	 * scan for an immediate register value as of the call ({@code LDA #bank / JSR
	 * SelectBank} and its X/Y variants). By the helper convention the register holds the
	 * <em>field value itself</em>, so no mechanism transform is applied beyond the state
	 * mask. Returns {@link BankState#unknown()} when no register resolves -- the caller
	 * conservatively loses the bank state across the call.
	 */
	private BankState recoverCallArgument(Program program, Instruction callInstr, int mask) {
		for (char reg : new char[] { 'A', 'X', 'Y' }) {
			BankState v = StoredValueScanner.resolveStoredValue(program, callInstr, reg,
				BankState.unknown(), mask, NO_HOOKS);
			if (v.knownMask() != 0) {
				return v;
			}
		}
		return BankState.unknown();
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

			String targetSpaceName = null;

			WindowModel window = findWindow(board.windows(), offset);
			if (window != null && stateRow != null) {
				String occupantName = stateRow.get(window.name());
				OccupantModel occupant =
					occupantName == null ? null : window.occupants().get(occupantName);
				if (occupant == null) {
					continue;
				}
				String targetOccupant;
				if (refType.isWrite()) {
					targetOccupant =
						occupant.onWrite() != null ? occupant.onWrite() : occupantName;
				}
				else {
					targetOccupant = occupantName;
				}
				String homeOccupant = board.homeOccupantByWindow().get(window.name());
				if (targetOccupant.equals(homeOccupant)) {
					// resolves to the home occupant, which already lives in base space at
					// this offset -- the default reference is correct.
					continue;
				}
				targetSpaceName = targetOccupant;
			}
			else {
				ComputedWindowModel computed = findComputedWindow(board.computedWindows(), offset);
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
				targetSpaceName = computed.name() + "_B" + bankValue;
			}

			AddressSpace overlaySpace = program.getAddressFactory().getAddressSpace(targetSpaceName);
			if (overlaySpace == null) {
				log.appendMsg(getName(), "No overlay address space named '" + targetSpaceName +
					"'; cannot retarget reference from " + instr.getMinAddress());
				continue;
			}
			Address overlayAddr = overlaySpace.getAddress(offset);

			int opIndex = ref.getOperandIndex();
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
			refMgr.setPrimary(newRef, true);
			added++;

			// Adding a reference does not by itself pull the target into analysis: a
			// cross-bank JSR/JMP target in an overlay would stay undisassembled bytes.
			// Kick disassembly (and function creation for calls) there; the framework
			// then re-runs this analyzer over the new instructions until convergence
			// (their in-overlay bank state comes from the residence clamp).
			if (refType.isFlow() &&
				program.getListing().getInstructionAt(overlayAddr) == null) {
				new DisassembleCommand(overlayAddr, null, true).applyTo(program, monitor);
				if (refType.isCall() &&
					program.getListing().getInstructionAt(overlayAddr) != null &&
					program.getFunctionManager().getFunctionAt(overlayAddr) == null) {
					new CreateFunctionCmd(overlayAddr).applyTo(program, monitor);
				}
			}
		}
		return added;
	}

	private static WindowModel findWindow(Map<String, WindowModel> windowsByName, long offset) {
		for (WindowModel w : windowsByName.values()) {
			if (offset >= w.start() && offset <= w.end()) {
				return w;
			}
		}
		return null;
	}

	private static ComputedWindowModel findComputedWindow(
			Map<String, ComputedWindowModel> computedByName, long offset) {
		for (ComputedWindowModel w : computedByName.values()) {
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
	 * register (today: everything, until the bundled 6510 language of grm-bk6) skip this
	 * silently; the value+mask model of {@link BankState} maps 1:1 onto
	 * {@code RegisterValue} when partial stamping becomes worthwhile.
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

	private record WindowModel(String name, long start, long end,
			Map<String, OccupantModel> occupants) {}

	/** A computed window driven by a single state field; per-bank overlays are named
	 *  {@code <name>_B<fieldValue>} by the loader, home bank in base space. */
	private record ComputedWindowModel(String name, long start, long end, FieldSpec field,
			String onWrite) {}

	/** Everything phase-independent parsed out of the descriptor. */
	private record BoardModel(int mask, int initialState, List<String> stateBitNames,
			List<FieldSpec> fieldSpecs, Map<String, WindowModel> windows,
			Map<String, ComputedWindowModel> computedWindows,
			Map<Integer, Map<String, String>> occupantByWindowForState,
			Map<String, String> homeOccupantByWindow) {}

	/** A helper function's modeled effect: a constant state, or null = caller-supplied. */
	private record HelperModel(Function function, BankState constState) {}

	/** A resolved call-site switch (for annotation, distinct from direct switches). */
	private record CallSwitch(String helperName, BankState state) {}

	private record DataflowResult(Map<Address, BankState> stateIn,
			Map<Address, BankState> switchResults, Map<Address, CallSwitch> callSwitches) {}
}
