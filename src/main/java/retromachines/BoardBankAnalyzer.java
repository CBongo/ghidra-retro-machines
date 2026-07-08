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
 * with its params), the enumerated window/occupant truth table, and the initial state.
 * The engine owns what is the same on every machine:
 * <ul>
 * <li><b>Forward dataflow to fixpoint</b> over disassembled instructions, seeded with
 * {@code banking.initial_state} at every entry point and function start, with per-bit
 * partial knowledge ({@link BankState}) and agree-bit merges at control-flow joins.</li>
 * <li><b>Switch recognition and value recovery</b> delegated to the configured
 * strategies (first strategy that recognizes an instruction wins).</li>
 * <li><b>Annotation</b>: EOL comments at resolved switch sites (with per-bit known/
 * assumed provenance when knowledge is partial), WARNING bookmarks only when a switch
 * leaves no tracked bit known.</li>
 * <li><b>Application</b> (interim overlay generation): for references landing in an
 * enumerated banked window, an ANALYSIS reference into the effective occupant's overlay
 * space (or its {@code on_write} occupant for writes -- including write-under-ROM),
 * marked primary. Unknown bits assume their initial-state value.</li>
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

	/** Resource path of this board's compiled descriptor, e.g. {@code machines/c64.map}. */
	protected abstract String getMapPath();

	/** Category used for this analyzer's bookmarks; defaults to the concrete class name. */
	protected String getBookmarkCategory() {
		return getClass().getSimpleName();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		String tag = getClass().getSimpleName();
		log.appendMsg(getName(), tag + " running");

		JsonObject map;
		try {
			map = DescriptorSupport.loadMap(getMapPath());
		}
		catch (IOException e) {
			log.appendMsg(getName(), "Failed to load " + getMapPath() + ": " + e.getMessage());
			return false;
		}

		JsonObject banking = map.getAsJsonObject("banking");
		if (banking == null || !banking.has("mechanisms")) {
			log.appendMsg(getName(), "banking.mechanisms missing from " + getMapPath() +
				"; skipping bank-state analysis");
			return true;
		}

		int initialState = banking.get("initial_state").getAsInt();

		// The tracked-bit mask and per-bit annotation names come from the banking.state
		// field tuple (LSB first; multi-bit fields expand to name.0, name.1, ...).
		List<String> stateBitNames = new ArrayList<>();
		if (banking.has("state")) {
			for (JsonElement fe : banking.getAsJsonArray("state")) {
				JsonObject field = fe.getAsJsonObject();
				String fieldName = field.get("name").getAsString();
				int bits = field.get("bits").getAsInt();
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
			log.appendMsg(getName(), "no usable bank-switch strategy in " + getMapPath() +
				" banking; skipping bank-state analysis");
			return true;
		}

		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();

		// --- Parse windows + banking states ---
		Map<String, WindowModel> windowsByName = new LinkedHashMap<>();
		for (JsonElement we : map.getAsJsonArray("windows")) {
			JsonObject window = we.getAsJsonObject();
			if (!window.has("occupants")) {
				continue; // computed windows are the loader's / bank engine's concern
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
		if (homeOccupantByWindow == null) {
			log.appendMsg(getName(), "banking.initial_state " + initialState +
				" not found in banking.states; skipping bank-state analysis");
			return true;
		}

		// --- Phase 1: forward dataflow to fixpoint (bank state per instruction address) ---
		Listing listing = program.getListing();
		Map<Address, BankState> stateIn = new HashMap<>();
		Map<Address, BankState> switchResults = new HashMap<>();
		Deque<Address> worklist = new ArrayDeque<>();

		Set<Address> seeds = new LinkedHashSet<>();
		AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
		while (eps.hasNext()) {
			seeds.add(eps.next());
		}
		FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
		for (Function f : funcs) {
			seeds.add(f.getEntryPoint());
		}

		BankState seedState = BankState.fullyKnown(mask, initialState);
		for (Address seed : seeds) {
			mergeAndEnqueue(seed, seedState, stateIn, worklist, listing);
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

			for (Address flow : instr.getFlows()) {
				mergeAndEnqueue(flow, outState, stateIn, worklist, listing);
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough != null) {
				mergeAndEnqueue(fallThrough, outState, stateIn, worklist, listing);
			}
		}

		// --- Phase 2: annotate bank switches + retarget references ---
		ReferenceManager refMgr = program.getReferenceManager();
		int refsAdded = 0;
		int warnings = 0;
		for (Map.Entry<Address, BankState> entry : stateIn.entrySet()) {
			monitor.checkCancelled();
			Address addr = entry.getKey();
			BankState inState = entry.getValue();
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}

			BankState switched = switchResults.get(addr);
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
					annotateBankSwitch(listing, addr, switched, initialState, mask, stateBitNames,
						windowsByName.keySet(), occupantByWindowForState);
				}
			}

			int effective = inState.effective(initialState, mask);
			Map<String, String> stateRow = occupantByWindowForState.get(effective);
			if (stateRow == null) {
				continue;
			}

			refsAdded += retargetReferences(program, refMgr, baseSpace, instr, windowsByName,
				stateRow, homeOccupantByWindow, log);
		}

		// --- Context stamping: only when the language actually declares the register ---
		stampContextRegister(program, banking, stateIn, listing, mask, log);

		log.appendMsg(getName(), tag + ": " + stateIn.size() + " instructions tracked, " +
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

	private void mergeAndEnqueue(Address addr, BankState incoming, Map<Address, BankState> stateIn,
			Deque<Address> worklist, Listing listing) {
		if (listing.getInstructionAt(addr) == null) {
			// not (yet) disassembled / not code -- nothing to track here
			return;
		}
		BankState existing = stateIn.get(addr);
		BankState merged = existing == null ? incoming : BankState.merge(existing, incoming);
		if (existing == null || !merged.equals(existing)) {
			stateIn.put(addr, merged);
			worklist.add(addr);
		}
		// else: unchanged, already processed with this exact state -- nothing to do
	}

	// ------------------------------------------------------------------
	// Annotation
	// ------------------------------------------------------------------

	/**
	 * Annotates a resolved bank-switch store with an EOL comment. When {@code newState}
	 * is fully known, the comment is {@code bank -> 5 (RAM_A000/IO/RAM_E000)}. When only
	 * some bits are known, the comment marks the effective state with a trailing
	 * {@code ?} and spells out, by {@code banking.state} field name, which bits are
	 * actually known versus merely assumed from {@code banking.initial_state} -- e.g.
	 * {@code bank -> 7? (BASIC/IO/KERNAL) [known: LORAM=1; assumed from initial:
	 * HIRAM,CHAREN]}.
	 */
	private void annotateBankSwitch(Listing listing, Address addr, BankState newState,
			int initialState, int mask, List<String> stateBitNames, Set<String> windowNames,
			Map<Integer, Map<String, String>> occupantByWindowForState) {
		int effective = newState.effective(initialState, mask);
		Map<String, String> stateRow = occupantByWindowForState.get(effective);
		String desc = describeState(windowNames, stateRow);

		String bankComment;
		if (newState.knownMask() == mask) {
			bankComment = "bank -> " + effective + " (" + desc + ")";
		}
		else {
			List<String> known = new ArrayList<>();
			List<String> assumed = new ArrayList<>();
			for (int bit = 0; bit < 8; bit++) {
				int bitMask = 1 << bit;
				if ((mask & bitMask) == 0) {
					continue;
				}
				String name = bit < stateBitNames.size() ? stateBitNames.get(bit)
						: ("bit" + bit);
				if ((newState.knownMask() & bitMask) != 0) {
					known.add(name + "=" + ((newState.bits() & bitMask) != 0 ? 1 : 0));
				}
				else {
					assumed.add(name);
				}
			}
			bankComment = "bank -> " + effective + "? (" + desc + ") [known: " +
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

	private static String describeState(Set<String> windowNames, Map<String, String> stateRow) {
		if (stateRow == null) {
			return "?";
		}
		List<String> parts = new ArrayList<>();
		for (String windowName : windowNames) {
			parts.add(stateRow.getOrDefault(windowName, "?"));
		}
		return String.join("/", parts);
	}

	// ------------------------------------------------------------------
	// Reference retargeting
	// ------------------------------------------------------------------

	private int retargetReferences(Program program, ReferenceManager refMgr,
			AddressSpace baseSpace, Instruction instr, Map<String, WindowModel> windowsByName,
			Map<String, String> stateRow, Map<String, String> homeOccupantByWindow,
			MessageLog log) {

		int added = 0;
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (!to.getAddressSpace().equals(baseSpace)) {
				continue;
			}
			long offset = to.getOffset();

			WindowModel window = findWindow(windowsByName, offset);
			if (window == null) {
				continue;
			}
			String occupantName = stateRow.get(window.name);
			if (occupantName == null) {
				continue;
			}
			OccupantModel occupant = window.occupants.get(occupantName);
			if (occupant == null) {
				continue;
			}

			RefType refType = ref.getReferenceType();
			String targetOccupant;
			if (refType.isWrite()) {
				targetOccupant = occupant.onWrite != null ? occupant.onWrite : occupantName;
			}
			else {
				targetOccupant = occupantName;
			}

			String homeOccupant = homeOccupantByWindow.get(window.name);
			if (targetOccupant.equals(homeOccupant)) {
				// resolves to the home occupant, which already lives in base space at this
				// offset -- the default reference the reference analyzer laid down is correct.
				continue;
			}

			AddressSpace overlaySpace = program.getAddressFactory().getAddressSpace(targetOccupant);
			if (overlaySpace == null) {
				log.appendMsg(getName(), "No overlay address space named '" + targetOccupant +
					"' for window '" + window.name + "'; cannot retarget reference from " +
					instr.getMinAddress());
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
		}
		return added;
	}

	private static WindowModel findWindow(Map<String, WindowModel> windowsByName, long offset) {
		for (WindowModel w : windowsByName.values()) {
			if (offset >= w.start && offset <= w.end) {
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

	private record OccupantModel(String name, String kind, String onWrite) {}

	private record WindowModel(String name, long start, long end,
			Map<String, OccupantModel> occupants) {}
}
