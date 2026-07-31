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
// Read-only diagnostic for real ROMs that produce ZERO bank annotations on a board where a
// sibling title on the same mapper resolves thousands of refs (Contra/UxROM and Dragon Ball
// 3/Bandai-FCG vs Mega Man/UxROM). It answers "why did the memory-latch mechanism never
// fire?" by measuring, per store site, every gate the production pipeline applies -- and by
// looking for latch stores in bytes the disassembler never reached at all.
//
// THE THREE ROOT CAUSES IT SEPARATES
//   (i)   the store IS disassembled but sits in NO function -- BoardBankAnalyzer.runDataflow
//         (:568-576) seeds ONLY from external entry points + function entry points, so an
//         orphan store is never dequeued; and with no constant-propagation coverage the
//         indexed operand never acquires a reference either, so it is doubly invisible.
//   (ii)  the store was never disassembled -- the bytes are there, but nothing flowed to
//         them, so there is no Instruction for runDataflow to see at all (mergeAndEnqueue,
//         :744-747, silently drops any address with no instruction).
//   (iii) the store is reachable AND in a function and STILL invisible, because
//         MemoryLatchBankSwitchStrategy.writesInRange (:193-203) inspects only
//         instr.getReferencesFrom() looking for a write ref in [start,end] in the DEFAULT
//         address space. A 6502 indexed operand (STA table,X) arrives as a Scalar and gets
//         no reference until constant propagation manufactures one; and a store living in a
//         bank overlay can carry a write ref in an OVERLAY space, which fails production's
//         `to.getAddressSpace().equals(space)` test even though the offset is in range.
//
// Emits a bounded block between
//   === BANKREACH BEGIN ===  /  === BANKREACH END ===
// with every line prefixed "BANKREACH ".
//
// COPYRIGHT POSTURE -- follows RealRomDump.java's rule (its header, ~:16-30): no ROM bytes
// and no disassembled instruction text. A store site is described by its register letter and
// addressing mode, never by its operand text. The ONE deliberate exception is the
// undisassembled-byte candidate scan (§8), whose entire product IS a byte-derived opcode +
// 16-bit operand -- that is the finding, and it cannot be reported without it. Even so this
// output is diagnostic-only and is never committed: realrom-test.sh's awk carve (~:204)
// extracts only the REALROM block, so nothing here can leak into a golden.
//
// USAGE (opt-in, alongside the normal dump):
//   REALROM_EXTRA_POSTSCRIPT=BankReachProbe.java bash tools/banktest/realrom-test.sh check <romdir>
// Run it in its OWN invocation: the realrom cache key (~:121-131) hashes RealRomDump.java
// only, so a cached `check`/`bless` pair would silently skip the import this script needs.
//
// WHY THE HELPERS ARE RE-IMPLEMENTED HERE
// retromachines.StoredValueScanner, retromachines.LoopIdioms and
// retromachines.DescriptorSupport are package-private, and this script is not in that
// package. Widening any of them would make a production class public FOREVER for the sake of
// a diagnostic, so instead the three tiny helpers this probe needs are re-implemented
// privately below, each pinned to the production line numbers it mirrors. The redundancy is
// a feature, not a cost: an independent re-implementation means a DISAGREEMENT with
// production is itself a finding rather than a silent shared bug.
//@category RetroMachines.Test

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

public class BankReachProbe extends GhidraScript {

	/**
	 * Cap on the {@code today=YES} (already-working) site sample. Sites with
	 * {@code today=NO} are emitted in FULL and ahead of these -- they are the entire payload
	 * of this diagnostic, and a truncated list of them would be worse than useless when the
	 * question is "which addresses would a per-game hint have to name?".
	 */
	private static final int SAMPLE_SITES = 200;

	/** Cap on emitted byte-scan candidates; the count line still reports the full total. */
	private static final int SAMPLE_CAND = 100;

	/**
	 * Cap on the {@code verdict.hint} address list. A hint a human actually writes names a
	 * handful of addresses; a thousand-entry list is noise. Truncation is reported on its own
	 * {@code note} line so the number is never silently lost.
	 */
	private static final int HINT_MAX = 32;

	/**
	 * Program-info property the loader stamps with the board's .map path
	 * (DescriptorSupport.MAP_PATH_PROPERTY -- kept as a literal here, exactly as
	 * RealRomDump.java:57-60 does, so this script needs no extension classes on its path;
	 * DescriptorSupport is package-private and unreachable from a script regardless).
	 */
	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	/** Opcodes the byte scan hunts for: absolute-addressed 6502 stores, whose 16-bit operand
	 *  follows little-endian. Zero-page and indirect stores are excluded on purpose -- their
	 *  operand cannot name a $8000-$FFFF latch range, so they could only add false hits. */
	private static final int[] STORE_OPCODES = { 0x8D, 0x9D, 0x99, 0x8E, 0x8C };

	// ------------------------------------------------------------------
	// Model
	// ------------------------------------------------------------------

	/** One configured {@code memory-latch} mechanism, mirroring the four params
	 *  {@link ghidra.program.model.listing.Program}-side production reads in
	 *  MemoryLatchBankSwitchStrategy.configure (:129-137). {@code index} is the mechanism's
	 *  position in the descriptor's {@code banking.mechanisms[]} array (NOT its position
	 *  among memory-latch mechanisms), so {@code mech=<i>} points straight at the JSON. */
	private static final class Mech {
		final int index;
		final long start;
		final long end;
		final long addrMask;
		final long addrMatch;

		Mech(int index, long start, long end, long addrMask, long addrMatch) {
			this.index = index;
			this.start = start;
			this.end = end;
			this.addrMask = addrMask;
			this.addrMatch = addrMatch;
		}

		boolean inRange(long offset) {
			return offset >= start && offset <= end;
		}

		/** Verbatim MemoryLatchBankSwitchStrategy.matchesDecode (:211-213). */
		boolean matchesDecode(long offset) {
			return addrMask == 0 || (offset & addrMask) == addrMatch;
		}
	}

	/** One store instruction whose operand names an address inside some mechanism's latch
	 *  range, together with every gate production applies to it. */
	private static final class Site {
		Address at;
		Mech mech;
		char reg;
		boolean indexed;
		long base;
		boolean ovl;
		String decode;
		String func;
		boolean reach;
		int refs;
		boolean write;
		boolean today;
	}

	// ------------------------------------------------------------------
	// Entry point
	// ------------------------------------------------------------------

	@Override
	protected void run() throws Exception {
		// The fence is opened and closed unconditionally, and every failure inside becomes a
		// "BANKREACH error" line: a stack trace escaping run() would leave headless emitting a
		// half-open block that the caller's carve cannot interpret.
		println("=== BANKREACH BEGIN ===");
		try {
			probe();
		}
		catch (Exception e) {
			println("BANKREACH error " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		println("=== BANKREACH END ===");
	}

	private void probe() throws Exception {
		Program program = currentProgram;
		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

		String sha = program.getExecutableSHA256();
		String mapPath = program.getOptions(Program.PROGRAM_INFO).getString(MAP_PATH_PROPERTY, null);

		println("BANKREACH program " + program.getName());
		println("BANKREACH sha256 " + (sha == null ? "NONE" : sha));
		println("BANKREACH map " + (mapPath == null ? "NONE" : mapPath));

		if (mapPath == null || mapPath.isBlank()) {
			println("BANKREACH error no '" + MAP_PATH_PROPERTY + "' property -- this program was " +
				"not imported by a RetroMachines loader, so there is no board to probe");
			return;
		}

		List<Mech> mechs;
		try {
			mechs = loadMechanisms(mapPath);
		}
		catch (Exception e) {
			println("BANKREACH error descriptor " + mapPath + ": " + e.getClass().getSimpleName() +
				": " + e.getMessage());
			return;
		}
		for (Mech m : mechs) {
			println("BANKREACH mech " + m.index + " memory-latch start=" + off(m.start) + " end=" +
				off(m.end) + " addrMask=" + hex(m.addrMask) + " addrMatch=" + hex(m.addrMatch));
		}
		if (mechs.isEmpty()) {
			println("BANKREACH error descriptor " + mapPath +
				" declares no banking.mechanisms[] entry with strategy 'memory-latch'");
			return;
		}

		// --- 3. seeds: byte-for-byte the set runDataflow builds (:568-576) ---------
		Set<Address> seeds = new LinkedHashSet<>();
		int entryPoints = 0;
		AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
		while (eps.hasNext()) {
			seeds.add(eps.next());
			entryPoints++;
		}
		int functionEntries = 0;
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			seeds.add(f.getEntryPoint());
			functionEntries++;
		}

		// --- 4. reachability ------------------------------------------------------
		Set<Address> reached = reachable(listing, seeds);

		// --- 5. site enumeration --------------------------------------------------
		List<Site> sites = new ArrayList<>();
		long instrsTotal = 0;
		long storesTotal = 0;
		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrs.next();
			instrsTotal++;
			Character reg = storeRegister(instr);
			if (reg == null) {
				continue;
			}
			storesTotal++;

			// Decode the target from the OPERAND, never from references: the whole point is
			// that production's reference-based gate is what fails here, so a reference-based
			// decode would be blind in exactly the cases we are hunting.
			boolean indexed = false;
			Address target = plainAbsoluteTarget(instr);
			if (target == null) {
				target = indexedBase(instr);
				indexed = target != null;
			}
			if (target == null) {
				continue; // zero-page-indirect / (zp),Y / no address operand -- cannot name a latch
			}

			// Normalize to the default space BY OFFSET. A store executing from a bank overlay
			// yields an overlay-space operand address (LoopIdioms.indexedBase builds the base in
			// the executing instruction's space), and comparing that against a base-space range
			// would drop every overlay-resident latch store. The descriptor's start/end are
			// base-space offsets, so the comparison must happen there too.
			Address normalized;
			try {
				normalized = defaultSpace.getAddress(target.getOffset());
			}
			catch (AddressOutOfBoundsException e) {
				continue; // an operand value no default-space address can hold
			}
			long offset = normalized.getOffset();
			Mech mech = null;
			for (Mech m : mechs) {
				if (m.inRange(offset)) {
					// First match wins, mirroring runDataflow's ordered mechanism loop
					// (:617-624), which breaks on the first strategy that claims the address.
					mech = m;
					break;
				}
			}
			if (mech == null) {
				continue;
			}

			Site s = new Site();
			s.at = instr.getMinAddress();
			s.mech = mech;
			s.reg = reg;
			s.indexed = indexed;
			s.base = offset;
			s.ovl = s.at.getAddressSpace().isOverlaySpace();
			// UNDECIDED: with an addr_mask the decode depends on (base + index) & mask, and the
			// index is a runtime value -- the base alone genuinely cannot decide it. Calling such
			// a site MISS would be a fabricated negative.
			s.decode = mech.addrMask != 0 && indexed ? "UNDECIDED"
					: mech.matchesDecode(offset) ? "MATCH" : "MISS";
			Function containing = program.getFunctionManager().getFunctionContaining(s.at);
			s.func = containing == null ? "NONE" : containing.getName();
			s.reach = reached.contains(s.at);
			s.refs = instr.getReferencesFrom().length;
			s.write = writesRangeAnySpace(instr, mech);
			s.today = writesInRange(instr, mech, defaultSpace);
			sites.add(s);
		}

		// --- 6. per-site emission -------------------------------------------------
		// Written out rather than composed from Comparator.comparing/thenComparing: the
		// method-reference form of thenComparing is ambiguous against its Comparator overload
		// and the explicit form reads no worse.
		Comparator<Site> byAddress = (a, b) -> {
			int c = a.at.compareTo(b.at);
			return c != 0 ? c : render(a).compareTo(render(b));
		};
		List<Site> invisible = new ArrayList<>();
		List<Site> visible = new ArrayList<>();
		for (Site s : sites) {
			(s.today ? visible : invisible).add(s);
		}
		invisible.sort(byAddress);
		visible.sort(byAddress);
		for (Site s : invisible) {
			println("BANKREACH " + render(s));
		}
		int shown = Math.min(SAMPLE_SITES, visible.size());
		for (int i = 0; i < shown; i++) {
			println("BANKREACH " + render(visible.get(i)));
		}
		if (shown < visible.size()) {
			println("BANKREACH note sites.truncated " + (visible.size() - shown) +
				" further today=YES site(s) omitted (cap " + SAMPLE_SITES + ")");
		}

		// --- 7. per-block undisassembled bytes ------------------------------------
		// Only initialized, non-writable blocks: RAM and uninitialized regions have no bytes
		// that could hold an undiscovered store, and reporting them would bury the ROM signal.
		AddressSet romBytes = new AddressSet();
		for (MemoryBlock b : memory.getBlocks()) {
			if (!b.isInitialized() || b.isWrite()) {
				continue;
			}
			AddressSet blockSet = new AddressSet(b.getStart(), b.getEnd());
			AddressSetView undefined = listing.getUndefinedRanges(blockSet, true, monitor);
			long blockInstrs = 0;
			InstructionIterator bi = listing.getInstructions(blockSet, true);
			while (bi.hasNext()) {
				bi.next();
				blockInstrs++;
			}
			println("BANKREACH block " + b.getName() + " " + fmt(b.getStart()) + "-" +
				fmt(b.getEnd()) + " undefinedBytes=" + undefined.getNumAddresses() + " instrs=" +
				blockInstrs);
			romBytes.add(undefined);
		}

		// --- 8. candidate byte scan ------------------------------------------------
		List<String> candidates = new ArrayList<>();
		int[] candCounts = new int[2]; // { total, decodeMatch }
		scanCandidates(memory, romBytes, mechs, candidates, candCounts);
		println("BANKREACH note cand.unverified a byte scan over UNDISASSEMBLED bytes cannot tell " +
			"code from a coincidental byte pair (a data table, a sprite row, the tail of a longer " +
			"instruction); every 'cand' line is a lead to confirm by hand, never a finding");
		int candShown = Math.min(SAMPLE_CAND, candidates.size());
		for (int i = 0; i < candShown; i++) {
			println("BANKREACH " + candidates.get(i));
		}
		if (candShown < candidates.size()) {
			println("BANKREACH note cand.truncated " + (candidates.size() - candShown) +
				" further candidate(s) omitted (cap " + SAMPLE_CAND + ")");
		}

		// --- 9. counts --------------------------------------------------------------
		long absSites = sites.stream().filter(s -> !s.indexed).count();
		long idxSites = sites.stream().filter(s -> s.indexed).count();
		long decMatch = sites.stream().filter(s -> "MATCH".equals(s.decode)).count();
		long decMiss = sites.stream().filter(s -> "MISS".equals(s.decode)).count();
		long decUnd = sites.stream().filter(s -> "UNDECIDED".equals(s.decode)).count();
		long inFunc = sites.stream().filter(s -> !"NONE".equals(s.func)).count();
		long orphan = sites.size() - inFunc;
		long reachSites = sites.stream().filter(s -> s.reach).count();
		long withWrite = sites.stream().filter(s -> s.write).count();

		println("BANKREACH count seeds.entryPoints " + entryPoints);
		println("BANKREACH count seeds.functionEntries " + functionEntries);
		println("BANKREACH count instrs.total " + instrsTotal);
		println("BANKREACH count instrs.reachable " + reached.size());
		println("BANKREACH count stores.total " + storesTotal);
		println("BANKREACH count sites.total " + sites.size());
		println("BANKREACH count sites.abs " + absSites);
		println("BANKREACH count sites.indexed " + idxSites);
		println("BANKREACH count sites.decodeMatch " + decMatch);
		println("BANKREACH count sites.decodeMiss " + decMiss);
		println("BANKREACH count sites.decodeUndecided " + decUnd);
		println("BANKREACH count sites.inFunction " + inFunc);
		println("BANKREACH count sites.orphan " + orphan);
		println("BANKREACH count sites.reachable " + reachSites);
		println("BANKREACH count sites.withWriteRef " + withWrite);
		println("BANKREACH count sites.wouldMatchToday " + visible.size());
		println("BANKREACH count cand.total " + candCounts[0]);
		println("BANKREACH count cand.decodeMatch " + candCounts[1]);

		// --- 10. verdicts -----------------------------------------------------------
		long invisibleReachable =
			sites.stream().filter(s -> s.reach && !"NONE".equals(s.func) && !s.today).count();
		println("BANKREACH verdict.i orphan-sites " + orphan);
		println("BANKREACH verdict.ii no-site-in-disassembled-code " + sites.isEmpty());
		println("BANKREACH verdict.iii invisible-reachable-sites " + invisibleReachable);

		// The hint payload: confirmed store addresses first (those production cannot see today),
		// then the unverified byte-scan leads. Offsets only -- a per-game hint names a CPU
		// address, and two bank overlays holding the same offset collapse to one entry on
		// purpose (a hint that names $c123 means "the store at $c123", whichever bank it is in).
		Set<String> hint = new LinkedHashSet<>();
		for (Site s : invisible) {
			hint.add(fmt(s.at));
		}
		for (String c : candidates) {
			// "cand <addr> op=..." -- the address is the second token.
			String[] parts = c.split(" ");
			if (parts.length > 1) {
				hint.add(parts[1]);
			}
		}
		List<String> hintList = new ArrayList<>(hint);
		int hintShown = Math.min(HINT_MAX, hintList.size());
		println("BANKREACH verdict.hint " + String.join(",", hintList.subList(0, hintShown)));
		if (hintShown < hintList.size()) {
			println("BANKREACH note hint.truncated " + (hintList.size() - hintShown) +
				" further address(es) omitted (cap " + HINT_MAX + ")");
		}
	}

	// ------------------------------------------------------------------
	// Reachability
	// ------------------------------------------------------------------

	/**
	 * The set of instruction addresses runDataflow would ever dequeue, with the bank state
	 * removed: seeds, then {@code instr.getFlows()} + {@code getFallThrough()} to fixpoint
	 * (:687-694), dropping any address with no instruction exactly as {@code mergeAndEnqueue}
	 * does (:744-747). Dropping the state is sound for this question -- state affects the
	 * VALUE a switch produces, never which addresses are visited.
	 */
	private Set<Address> reachable(Listing listing, Set<Address> seeds) throws Exception {
		Set<Address> reached = new HashSet<>();
		Deque<Address> work = new ArrayDeque<>(seeds);
		while (!work.isEmpty()) {
			monitor.checkCancelled();
			Address addr = work.poll();
			if (reached.contains(addr)) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				// not (yet) disassembled / not code, or an address inside an instruction rather
				// than at its start -- production drops it here too
				continue;
			}
			reached.add(addr);
			for (Address flow : instr.getFlows()) {
				work.push(flow);
			}
			Address fallThrough = instr.getFallThrough();
			if (fallThrough != null) {
				work.push(fallThrough);
			}
		}
		return reached;
	}

	// ------------------------------------------------------------------
	// The two write predicates
	// ------------------------------------------------------------------

	/**
	 * VERBATIM re-implementation of MemoryLatchBankSwitchStrategy.writesInRange (:193-203),
	 * including the default-space equality test. This is the "would production see it?"
	 * column: whenever it disagrees with {@link #writesRangeAnySpace}, the difference is
	 * purely the address space the reference landed in.
	 */
	private boolean writesInRange(Instruction instr, Mech mech, AddressSpace space) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && to.getAddressSpace().equals(space) &&
				to.getOffset() >= mech.start && to.getOffset() <= mech.end &&
				mech.matchesDecode(to.getOffset())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Deliberately LOOSER than production: any write reference whose OFFSET falls in the latch
	 * range, in any address space and ignoring the decode predicate. A site that is
	 * {@code write=YES today=NO} has a perfectly good write reference that production throws
	 * away -- which localizes the failure to the space test (or the decode), not to the
	 * absence of a reference.
	 */
	private boolean writesRangeAnySpace(Instruction instr, Mech mech) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && mech.inRange(to.getOffset())) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Re-implemented production helpers (see the file header for why)
	// ------------------------------------------------------------------

	/** Mirrors StoredValueScanner.storeRegister (:255-261): 'A'/'X'/'Y' for STA/STX/STY, else
	 *  null. Read-modify-write stores (INC/ASL/...) are excluded there and here. */
	private static Character storeRegister(Instruction instr) {
		String mnem = instr.getMnemonicString().toUpperCase();
		if (mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY")) {
			return mnem.charAt(2); // 'A' | 'X' | 'Y'
		}
		return null;
	}

	/** Mirrors StoredValueScanner.plainAbsoluteTarget (:341-355): the single constant address
	 *  an operand names, or null when any register participates (indexed/indirect) or when the
	 *  operand names none or several. */
	private static Address plainAbsoluteTarget(Instruction instr) {
		Address addr = null;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register) {
				return null; // indexed -- runtime-dependent target
			}
			if (obj instanceof Address a) {
				if (addr != null) {
					return null;
				}
				addr = a;
			}
		}
		return addr;
	}

	/** Mirrors LoopIdioms.indexedBase (:82-111): the base of an indexed operand (abs,X /
	 *  abs,Y / zp,X), built in the EXECUTING instruction's space -- which for an out-of-overlay
	 *  offset already resolves back to the base space (see that method's javadoc, :69-81). */
	private static Address indexedBase(Instruction instr) {
		Long base = null;
		boolean indexed = false;
		for (Object obj : instr.getOpObjects(0)) {
			if (obj instanceof Register) {
				indexed = true;
			}
			else if (obj instanceof Address a) {
				if (base != null) {
					return null;
				}
				base = a.getOffset();
			}
			else if (obj instanceof Scalar s) {
				if (base != null) {
					return null;
				}
				base = s.getUnsignedValue();
			}
		}
		if (!indexed || base == null) {
			return null;
		}
		try {
			return instr.getMinAddress().getAddressSpace().getAddress(base);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	// ------------------------------------------------------------------
	// Descriptor
	// ------------------------------------------------------------------

	/**
	 * The descriptor's {@code memory-latch} mechanisms, resolved through the same bundled-data
	 * lookup DescriptorSupport.loadMap (:142-151) uses. A malformed or partial mechanism is
	 * skipped rather than fatal -- one bad entry should not blind the whole probe.
	 */
	private List<Mech> loadMechanisms(String mapPath) throws Exception {
		ResourceFile mapFile = Application.findDataFileInAnyModule(mapPath);
		if (mapFile == null) {
			throw new IOException("could not find bundled data file " + mapPath);
		}
		JsonObject root;
		try (InputStreamReader reader =
			new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			root = JsonParser.parseReader(reader).getAsJsonObject();
		}
		List<Mech> out = new ArrayList<>();
		JsonObject banking = root.has("banking") ? root.getAsJsonObject("banking") : null;
		if (banking == null || !banking.has("mechanisms")) {
			return out;
		}
		JsonArray mechanisms = banking.getAsJsonArray("mechanisms");
		int index = 0;
		for (JsonElement element : mechanisms) {
			int here = index++;
			if (!element.isJsonObject()) {
				continue;
			}
			JsonObject mech = element.getAsJsonObject();
			if (!mech.has("strategy") || !"memory-latch".equals(mech.get("strategy").getAsString())) {
				continue;
			}
			if (!mech.has("params")) {
				println("BANKREACH error mechanism " + here + " has no params; skipped");
				continue;
			}
			JsonObject params = mech.getAsJsonObject("params");
			if (!params.has("start") || !params.has("end")) {
				println("BANKREACH error mechanism " + here + " lacks start/end; skipped");
				continue;
			}
			out.add(new Mech(here, params.get("start").getAsLong(), params.get("end").getAsLong(),
				params.has("addr_mask") ? params.get("addr_mask").getAsLong() : 0,
				params.has("addr_match") ? params.get("addr_match").getAsLong() : 0));
		}
		return out;
	}

	// ------------------------------------------------------------------
	// Byte scan
	// ------------------------------------------------------------------

	/**
	 * Hunts absolute 6502 store opcodes followed by a little-endian operand inside a latch
	 * range, over bytes the disassembler never claimed. This is root cause (ii)'s evidence:
	 * if the ONLY latch stores in the image live here, no amount of dataflow tuning can help --
	 * the bytes must be disassembled first.
	 * <p>
	 * UNVERIFIED BY CONSTRUCTION: this is a raw byte-pattern scan over data. A jump table, a
	 * sprite row, or the tail of some longer instruction can spell {@code 8D xx 80} by pure
	 * coincidence, and nothing here can tell the difference. Treat every hit as a lead.
	 * <p>
	 * Chunks overlap by two bytes so a three-byte pattern straddling a chunk boundary is still
	 * seen exactly once.
	 */
	private void scanCandidates(Memory memory, AddressSetView undefined, List<Mech> mechs,
			List<String> out, int[] counts) throws Exception {
		final int chunkSize = 1 << 16;
		for (AddressRange range : undefined.getAddressRanges()) {
			monitor.checkCancelled();
			long length = range.getLength();
			Address rangeStart = range.getMinAddress();
			long done = 0;
			while (done < length) {
				int want = (int) Math.min(chunkSize, length - done);
				if (want < 3) {
					break; // no room for opcode + 16-bit operand
				}
				Address chunkStart;
				try {
					chunkStart = rangeStart.add(done);
				}
				catch (AddressOutOfBoundsException e) {
					break;
				}
				byte[] buf = new byte[want];
				int got;
				try {
					got = memory.getBytes(chunkStart, buf, 0, want);
				}
				catch (MemoryAccessException e) {
					break; // uninitialized hole inside a nominally initialized block
				}
				for (int i = 0; i + 2 < got; i++) {
					int op = buf[i] & 0xFF;
					if (!isStoreOpcode(op)) {
						continue;
					}
					long target = (buf[i + 1] & 0xFF) | ((buf[i + 2] & 0xFF) << 8);
					Mech mech = null;
					for (Mech m : mechs) {
						if (m.inRange(target)) {
							mech = m;
							break;
						}
					}
					if (mech == null) {
						continue;
					}
					// For the indexed opcodes (9D/99) this decodes the BASE, not base+index, so
					// with an addr_mask the verdict is indicative only -- same caveat as a site's
					// decode=UNDECIDED, kept as MATCH/MISS here because the emitted schema is
					// binary and these lines are unverified anyway.
					boolean match = mech.matchesDecode(target);
					counts[0]++;
					if (match) {
						counts[1]++;
					}
					try {
						out.add("cand " + fmt(chunkStart.add(i)) + " op=" +
							String.format("%02x", op) + " target=" + off(target) + " decode=" +
							(match ? "MATCH" : "MISS"));
					}
					catch (AddressOutOfBoundsException e) {
						// cannot name the address; the count above still records the hit
					}
				}
				done += want - 2;
			}
		}
	}

	private static boolean isStoreOpcode(int op) {
		for (int candidate : STORE_OPCODES) {
			if (candidate == op) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Formatting
	// ------------------------------------------------------------------

	/**
	 * One site line. {@code space=} is appended beyond the core field list because on a banked
	 * machine the same 4-hex offset exists in every bank overlay -- without it two different
	 * stores render identically and the reader cannot tell which bank a finding is in.
	 */
	private String render(Site s) {
		return "site " + fmt(s.at) + " mech=" + s.mech.index + " reg=" + s.reg + " mode=" +
			(s.indexed ? "IDX" : "ABS") + " base=" + off(s.base) + " ovl=" + s.ovl + " decode=" +
			s.decode + " func=" + s.func + " reach=" + (s.reach ? "YES" : "NO") + " refs=" +
			s.refs + " write=" + (s.write ? "YES" : "NO") + " today=" + (s.today ? "YES" : "NO") +
			" space=" + s.at.getAddressSpace().getName();
	}

	/** 6502 is a 16-bit CPU; every offset fits in 4 hex digits. Space identity, where it
	 *  matters, is printed alongside (see {@link #render}). Mirrors RealRomDump.fmt. */
	private String fmt(Address addr) {
		return String.format("%04x", addr.getOffset());
	}

	/** {@link #fmt} for a bare offset that has no Address (an operand value, a range bound). */
	private static String off(long offset) {
		return String.format("%04x", offset);
	}

	/** Masks are bit patterns, not addresses -- printed minimally so 0 reads as "absent". */
	private static String hex(long value) {
		return Long.toHexString(value);
	}
}
