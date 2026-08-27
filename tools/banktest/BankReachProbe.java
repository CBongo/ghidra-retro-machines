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
// 3/Bandai-FCG vs Mega Man/UxROM -- and, since grm-8iy, the GME titles that still resolve not
// one instruction into overlay space). It answers "why did the bank-switch mechanism never
// fire?" by measuring, per store site, every gate the production pipeline applies -- and by
// looking for latch stores in bytes the disassembler never reached at all.
//
// WHICH BOARDS IT RUNS ON (grm-8iy.2)
// Three strategies are accepted: memory-latch (UxROM/AxROM/BNROM/Bandai FCG), serial-shift
// (MMC1) and select-data (MMC3). All three take their write range from the same two params,
// start/end -- MemoryLatchBankSwitchStrategy.configure (:129-137),
// SerialShiftBankSwitchStrategy.configure (:180-181),
// SelectDataBankSwitchStrategy.configure (:106-107) -- so one Mech record models all three;
// only memory-latch also reads addr_mask/addr_match, which is why the decode= column reports
// NA on the other two instead of fabricating a MATCH out of an absent mask.
//
// Until grm-8iy.2 this probe hard-filtered strategy=="memory-latch" and bailed out with "no
// memory-latch mechanism" on everything else. Of grm-8iy's six remaining zero-resolvers
// (cv2, blmaster, smb2, tmnt, wizwarr, rcransom) that left it running on exactly ONE --
// wizwarr, the only AxROM title -- so the MMC1 and MMC3 questions could not even be asked.
//
// THE THREE ROOT CAUSES IT SEPARATES
//   (i)   the store IS disassembled but sits in NO function -- BankDataflowEngine.runDataflow
//         (BankDataflowEngine.java:137-145) seeds ONLY from external entry points + function
//         entry points, so an orphan store is never dequeued; and with no constant-propagation
//         coverage the indexed operand never acquires a reference either, so it is doubly
//         invisible.
//   (ii)  the store was never disassembled -- the bytes are there, but nothing flowed to
//         them, so there is no Instruction for runDataflow to see at all (mergeAndEnqueue,
//         BankDataflowEngine.java:323-326, silently drops any address with no instruction).
//   (iii) the store is reachable AND in a function and STILL produced no annotation, because
//         the matched strategy's own write predicate never claimed it. For memory-latch that
//         predicate is TWO TIERS: an authoritative write reference first, then operand decode
//         (operandStoresInRange) for the stores that carry no reference at all. A 6502 indexed
//         operand (STA table,X) arrives as a Scalar and gets no reference until constant
//         propagation manufactures one, and const-prop covers function bodies only -- tier 2
//         is what catches those. serial-shift and select-data have a DIFFERENT, strictly
//         narrower predicate; see "PRODUCTION'S OTHER TWO PREDICATES" below.
//
//         A once-true claim this list used to make is now RETIRED, recorded only so the change
//         is not re-derived from scratch: memory-latch's range test used to require the DEFAULT
//         address space, so a store executing from a bank overlay was skipped for carrying its
//         write ref in an overlay space; inLatchRange now tests the PHYSICAL space and overlays
//         count. (serial-shift/select-data still test the space strictly -- again, see below.)
//
// WHAT today= MEANS -- IT IS PRODUCTION'S OWN ANSWER, NOT A RE-DERIVATION (grm-8iy.2)
//         today = an EOL comment containing "bank ->"
//              OR a WARNING bookmark whose text starts "Bank state becomes unknown here:"
//         BoardBankAnalyzer.annotateOrWarn (:1439-1455) is TOTAL over the sites production
//         classified as mechanism writes: knownMask()==0 -> WARNING bookmark; a recovered bank
//         with no image slice -> WARNING bookmark (ImpossibleBank.message, :1465, same
//         prefix); otherwise annotateBankSwitch (:1617-1690), every branch of which writes a
//         comment containing "bank ->". So every site production saw carries one of the two
//         marks, and no site it did not see carries either. That makes today= authoritative
//         AND board-agnostic in one stroke, instead of needing a fresh writesInRange mirror
//         per strategy. today.src= reports which of the two marks answered.
//
//         annotateOrWarn serves BOTH the direct-switch path (:296) and the call-switch path
//         (:316), so both marks also appear at JSR call sites -- wizwarr carries one such
//         bookmark at $bc0a, "call to bank-switch helper FUN_ff69". They cannot contaminate
//         today=, which is only ever queried at an enumerated §5 site, and every one of those
//         is an STA/STX/STY. That is why bookmarks.switchUnknown (all of them) legitimately
//         exceeds sites.todayWarn (the ones that landed on a store): wizwarr 5 vs 4.
//
//         EXCLUDED ON PURPOSE: the Phase-3 "Bank state requirement violated:" bookmarks
//         (annotateBankRequirementViolations, ~:1818). Those sit at CALL sites, not switch
//         sites, so counting them would report a caller as a switch site. The prefix test
//         excludes them structurally, and the number skipped is emitted as
//         bookmarks.violationExcluded so the filter is measured rather than assumed.
//
// THE RE-IMPLEMENTED PREDICATE IS KEPT AS A CROSS-CHECK: mirror.ref / mirror.operand /
//         mirror.agree, renamed from today.ref / today.operand. It no longer answers the
//         question -- it audits the answer. A disagreement with production is precisely the
//         finding the re-implementation doctrine exists to surface (see "WHY THE HELPERS ARE
//         RE-IMPLEMENTED" below), so mirror.agree=NO on a memory-latch board is a bug in one
//         of the two and 'count mirror.disagree' totals them. On serial-shift/select-data the
//         mirror does not model production at all, so mirror.agree is NA: the two tiers still
//         describe the instruction truthfully ("carries a write ref in range" / "its operand
//         names the range"), they simply are not that board's predicate.
//
//         BOTH TIERS ARE MIRRORED AND BOTH MUST STAY MIRRORED. grm-8cq: this script
//         reproduced tier 1 alone, long after grm-3x1 added tier 2, so every refless indexed
//         store reported today=NO while production saw it perfectly well -- a confidently
//         wrong reading that cost a real investigation. Splitting the report per tier is what
//         localizes a future drift to the tier that caused it; taking today= from production
//         is what stops such a drift from being believed in the first place.
//
// PRODUCTION'S OTHER TWO PREDICATES -- read this before interpreting write=YES today=NO on an
// MMC1/MMC3 board. SerialShiftBankSwitchStrategy.writesInRange (:801-810) and
// SelectDataBankSwitchStrategy.writesInRange (:305-314) are ONE tier -- an authoritative write
// reference -- and they compare the address space with equals(), not getPhysicalSpace(). So
// unlike memory-latch they see neither a refless indexed store (no tier 2) nor a write
// reference that landed in a bank overlay's space. Both, however, DO accept a
// read-modify-write in range as a mechanism write (isMechanismWrite delegates straight to
// writesInRange, with the INC-reset idiom of grm-4kc handled downstream), whereas §5's site
// enumeration mirrors StoredValueScanner.storeRegister and so lists only STA/STX/STY. That
// blind spot is measured, not hidden: 'count stores.rmwInRange'.
//
// Emits a bounded block between
//   === BANKREACH BEGIN ===  /  === BANKREACH END ===
// with every line prefixed "BANKREACH ".
//
// COPYRIGHT POSTURE -- follows RealRomDump.java's rule (its header, ~:16-30): no ROM bytes
// and no disassembled instruction text. A store site is described by its register letter and
// addressing mode, never by its operand text. The ONE deliberate exception is the
// undisassembled-byte candidate scan (§8), whose entire product IS a byte-derived opcode +
// 16-bit operand -- that is the finding, and it cannot be reported without it. This SCRIPT is
// committed and documented (tools/banktest/realrom/README.md); its OUTPUT never is.
// realrom-test.sh's awk carve (~:204) extracts only the REALROM block, so nothing emitted
// here can reach a golden.
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
// production is itself a finding rather than a silent shared bug -- which is exactly what
// mirror.agree now reports.
//
// BEADS: grm-8cq / grm-3x1 / grm-9oz (original), grm-8iy + grm-8iy.2 (three strategies,
// authoritative today=).
//@category RetroMachines.Test

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
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
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
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

	/** The one memory-latch strategy name, kept as a constant because several columns are
	 *  meaningful only on it (addr_mask decode, and the mirror this probe cross-checks with). */
	private static final String MEMORY_LATCH = "memory-latch";

	/**
	 * The strategies whose write range is fully described by {@code start}/{@code end}, and so
	 * by this probe's {@link Mech}. Every other strategy (register-write, ...) decides its
	 * range differently and would be mis-modelled here, so it is reported as unsupported
	 * rather than silently probed.
	 */
	private static final List<String> ACCEPTED_STRATEGIES =
		List.of(MEMORY_LATCH, "serial-shift", "select-data");

	/**
	 * Prefix of every WARNING bookmark {@code BoardBankAnalyzer.annotateOrWarn} (:1439-1455)
	 * raises at a SWITCH site -- both the "recovery pinned down no bit" text (:298, :318) and
	 * {@code ImpossibleBank.message} (:1465) begin with it.
	 */
	private static final String SWITCH_UNKNOWN_PREFIX = "Bank state becomes unknown here:";

	/**
	 * Prefix of the Phase-3 bookmarks ({@code annotateBankRequirementViolations}, ~:1818),
	 * which sit at CALL sites. Excluded from {@code today=} on purpose: a caller is not a
	 * switch site, and counting one as such would invent sites that do not exist.
	 */
	private static final String REQUIREMENT_VIOLATED_PREFIX = "Bank state requirement violated:";

	/** {@code Bookmark.getTypeString()} for a warning; the literal, exactly as
	 *  RealRomDump.java:123 uses it. */
	private static final String WARNING_TYPE = "Warning";

	/** Opcodes the byte scan hunts for: absolute-addressed 6502 stores, whose 16-bit operand
	 *  follows little-endian. Zero-page and indirect stores are excluded on purpose -- their
	 *  operand cannot name a $8000-$FFFF latch range, so they could only add false hits. */
	private static final int[] STORE_OPCODES = { 0x8D, 0x9D, 0x99, 0x8E, 0x8C };

	// ------------------------------------------------------------------
	// Model
	// ------------------------------------------------------------------

	/**
	 * One configured mechanism of an {@link #ACCEPTED_STRATEGIES accepted} strategy.
	 * {@code start}/{@code end} are read identically by all three
	 * (MemoryLatchBankSwitchStrategy.configure :129-137, SerialShiftBankSwitchStrategy.configure
	 * :180-181, SelectDataBankSwitchStrategy.configure :106-107). {@code addrMask}/
	 * {@code addrMatch} exist ONLY on memory-latch; on the other two they are absent from the
	 * schema entirely and stay 0 here, which is why {@link #memoryLatch()} gates every column
	 * derived from them rather than letting "mask 0 always matches" read as a real MATCH.
	 * <p>
	 * {@code index} is the mechanism's position in the descriptor's {@code banking.mechanisms[]}
	 * array (NOT its position among accepted ones), so {@code mech=<i>} points straight at the
	 * JSON.
	 */
	private static final class Mech {
		final int index;
		final String strategy;
		final long start;
		final long end;
		final long addrMask;
		final long addrMatch;

		Mech(int index, String strategy, long start, long end, long addrMask, long addrMatch) {
			this.index = index;
			this.strategy = strategy;
			this.start = start;
			this.end = end;
			this.addrMask = addrMask;
			this.addrMatch = addrMatch;
		}

		/** Whether the addr_mask decode and the re-implemented mirror apply to this mechanism. */
		boolean memoryLatch() {
			return MEMORY_LATCH.equals(strategy);
		}

		boolean inRange(long offset) {
			return offset >= start && offset <= end;
		}

		/** Verbatim MemoryLatchBankSwitchStrategy.matchesDecode (:211-213). Callers must gate on
		 *  {@link #memoryLatch()}: elsewhere there is no mask to satisfy, so a "true" here means
		 *  "not applicable", not "matched". */
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
		/** Production wrote a {@code bank ->} EOL comment here (annotateBankSwitch, :1617). */
		boolean todayComment;
		/** Production raised a {@code Bank state becomes unknown here:} WARNING bookmark here. */
		boolean todayWarn;
		/** Cross-check tier 1: an authoritative write reference (memory-latch's own tier 1). */
		boolean mirrorRef;
		/** Cross-check tier 2: operand decode (memory-latch's operandStoresInRange). */
		boolean mirrorOperand;

		/** What production actually did here -- see the file header's {@code today=} section.
		 *  annotateOrWarn is total over the sites it classified, so exactly one of the two marks
		 *  is present at a site production saw, and neither at one it did not. */
		boolean today() {
			return todayComment || todayWarn;
		}

		/** Which mark answered {@link #today()} -- so a surprising YES localizes itself. */
		String todaySource() {
			if (todayComment && todayWarn) {
				return "comment+warn"; // annotateOrWarn does not do this; seeing it IS a finding
			}
			return todayComment ? "comment" : todayWarn ? "warn" : "NONE";
		}

		/** The re-implemented MemoryLatchBankSwitchStrategy.writesInRange verdict (grm-8cq). */
		boolean mirror() {
			return mirrorRef || mirrorOperand;
		}

		/** Whether the mirror agrees with production, or NA where the mirror does not model it
		 *  (serial-shift / select-data have their own, narrower predicate). */
		String mirrorAgree() {
			if (!mech.memoryLatch()) {
				return "NA";
			}
			return mirror() == today() ? "YES" : "NO";
		}
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
		// Every strategy name the descriptor declares, accepted or not -- so the bail-out below
		// says what the board actually IS instead of only what it is not.
		List<String> declared = new ArrayList<>();
		try {
			mechs = loadMechanisms(mapPath, declared);
		}
		catch (Exception e) {
			println("BANKREACH error descriptor " + mapPath + ": " + e.getClass().getSimpleName() +
				": " + e.getMessage());
			return;
		}
		for (Mech m : mechs) {
			// addr_mask/addr_match are memory-latch-only params; printing "0" for a board whose
			// schema has no such key would read as "a mask is configured and it is zero".
			println("BANKREACH mech " + m.index + " strategy=" + m.strategy + " start=" +
				off(m.start) + " end=" + off(m.end) + " addrMask=" +
				(m.memoryLatch() ? hex(m.addrMask) : "NA") + " addrMatch=" +
				(m.memoryLatch() ? hex(m.addrMatch) : "NA"));
		}
		if (mechs.isEmpty()) {
			println("BANKREACH error descriptor " + mapPath + " declares no banking.mechanisms[] " +
				"entry with a strategy this probe models (" + String.join(", ", ACCEPTED_STRATEGIES) +
				"); declared: " + (declared.isEmpty() ? "NONE" : String.join(", ", declared)));
			return;
		}

		// --- 3. seeds: byte-for-byte the set runDataflow builds (BankDataflowEngine.java:137-145) ---
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

		// --- 4b. production's own answer (grm-8iy.2) ------------------------------
		// The switch-site WARNING bookmarks, collected once. The Phase-3 requirement-violation
		// bookmarks are counted but NOT collected: they mark call sites, and folding them in
		// would report a caller as a switch site.
		Set<Address> switchUnknown = new HashSet<>();
		long violationBookmarks = 0;
		Iterator<Bookmark> bookmarks = program.getBookmarkManager().getBookmarksIterator();
		while (bookmarks.hasNext()) {
			monitor.checkCancelled();
			Bookmark bm = bookmarks.next();
			if (!WARNING_TYPE.equals(bm.getTypeString())) {
				continue;
			}
			String text = bm.getComment();
			if (text == null) {
				continue;
			}
			if (text.startsWith(SWITCH_UNKNOWN_PREFIX)) {
				switchUnknown.add(bm.getAddress());
			}
			else if (text.startsWith(REQUIREMENT_VIOLATED_PREFIX)) {
				violationBookmarks++;
			}
		}

		// --- 5. site enumeration --------------------------------------------------
		List<Site> sites = new ArrayList<>();
		long instrsTotal = 0;
		long storesTotal = 0;
		// Instructions that write a mechanism range WITHOUT being STA/STX/STY -- on 6502 that
		// means a read-modify-write (INC/ASL/ROL/...), plus the illegal store opcodes. Production's
		// mechanism-write gate ACCEPTS these (memory-latch's tier 1, and both other strategies'
		// single tier, test references alone with no storeRegister filter), but this section
		// mirrors StoredValueScanner.storeRegister and so cannot attribute a stored value to one.
		// Counting them keeps the gap measured instead of silently absent -- bionic's MMC1 reset
		// is `INC $FFE1` and is a real, determinable switch site (grm-4kc).
		long rmwInRange = 0;
		InstructionIterator instrs = listing.getInstructions(true);
		while (instrs.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrs.next();
			instrsTotal++;
			Character reg = storeRegister(instr);
			if (reg == null) {
				for (Mech m : mechs) {
					if (writesRangeAnySpace(instr, m)) {
						rmwInRange++;
						break;
					}
				}
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
			// NA: addr_mask/addr_match are memory-latch-only params, so on serial-shift and
			// select-data there is no decode to pass or fail and MATCH would be a fabricated
			// positive. UNDECIDED: with an addr_mask the decode depends on (base + index) & mask,
			// and the index is a runtime value -- the base alone genuinely cannot decide it, so
			// MISS would be a fabricated negative.
			s.decode = !mech.memoryLatch() ? "NA"
					: mech.addrMask != 0 && indexed ? "UNDECIDED"
					: mech.matchesDecode(offset) ? "MATCH" : "MISS";
			Function containing = program.getFunctionManager().getFunctionContaining(s.at);
			s.func = containing == null ? "NONE" : containing.getName();
			s.reach = reached.contains(s.at);
			s.refs = instr.getReferencesFrom().length;
			s.write = writesRangeAnySpace(instr, mech);
			// Production's own verdict, read off the program rather than re-derived.
			String eol = listing.getComment(CommentType.EOL, s.at);
			s.todayComment = eol != null && eol.contains("bank ->");
			s.todayWarn = switchUnknown.contains(s.at);
			// ... and the independent re-implementation that audits it.
			s.mirrorRef = writesInRangeTier1(instr, mech, defaultSpace);
			s.mirrorOperand = writesInRangeTier2(instr, mech, defaultSpace);
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
			(s.today() ? visible : invisible).add(s);
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
		int[] candCounts = new int[3]; // { total, decodeMatch, decodeNA }
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
		long decNA = sites.stream().filter(s -> "NA".equals(s.decode)).count();
		long inFunc = sites.stream().filter(s -> !"NONE".equals(s.func)).count();
		long orphan = sites.size() - inFunc;
		long reachSites = sites.stream().filter(s -> s.reach).count();
		long withWrite = sites.stream().filter(s -> s.write).count();
		long todayComment = sites.stream().filter(s -> s.todayComment).count();
		long todayWarn = sites.stream().filter(s -> s.todayWarn).count();
		// Only memory-latch mechanisms are mirrored; elsewhere mirrorAgree() is NA and a
		// difference means nothing (see the file header).
		long mirrorDisagree = sites.stream().filter(s -> "NO".equals(s.mirrorAgree())).count();

		println("BANKREACH count seeds.entryPoints " + entryPoints);
		println("BANKREACH count seeds.functionEntries " + functionEntries);
		println("BANKREACH count instrs.total " + instrsTotal);
		println("BANKREACH count instrs.reachable " + reached.size());
		println("BANKREACH count stores.total " + storesTotal);
		println("BANKREACH count stores.rmwInRange " + rmwInRange);
		println("BANKREACH count sites.total " + sites.size());
		println("BANKREACH count sites.abs " + absSites);
		println("BANKREACH count sites.indexed " + idxSites);
		println("BANKREACH count sites.decodeMatch " + decMatch);
		println("BANKREACH count sites.decodeMiss " + decMiss);
		println("BANKREACH count sites.decodeUndecided " + decUnd);
		println("BANKREACH count sites.decodeNA " + decNA);
		println("BANKREACH count sites.inFunction " + inFunc);
		println("BANKREACH count sites.orphan " + orphan);
		println("BANKREACH count sites.reachable " + reachSites);
		println("BANKREACH count sites.withWriteRef " + withWrite);
		println("BANKREACH count sites.wouldMatchToday " + visible.size());
		println("BANKREACH count sites.todayComment " + todayComment);
		println("BANKREACH count sites.todayWarn " + todayWarn);
		println("BANKREACH count bookmarks.switchUnknown " + switchUnknown.size());
		println("BANKREACH count bookmarks.violationExcluded " + violationBookmarks);
		println("BANKREACH count mirror.disagree " + mirrorDisagree);
		println("BANKREACH count cand.total " + candCounts[0]);
		println("BANKREACH count cand.decodeMatch " + candCounts[1]);
		println("BANKREACH count cand.decodeNA " + candCounts[2]);
		if (mirrorDisagree > 0) {
			println("BANKREACH note mirror.disagree this probe's re-implementation of " +
				"MemoryLatchBankSwitchStrategy.writesInRange and production's own annotations " +
				"disagree at " + mirrorDisagree + " site(s) (mirror.agree=NO). That is a FINDING, " +
				"not noise: exactly one of the two is wrong. Compare mirror.ref/mirror.operand " +
				"against today.src to localize it (grm-8cq).");
		}

		// --- 10. verdicts -----------------------------------------------------------
		// (iii) is now "production produced no annotation here", read off the program, so it
		// covers whatever the matched strategy's own predicate is -- memory-latch's two tiers,
		// or serial-shift/select-data's single reference tier -- without modelling any of them.
		long invisibleReachable =
			sites.stream().filter(s -> s.reach && !"NONE".equals(s.func) && !s.today()).count();
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
	 * (BankDataflowEngine.java:266-273), dropping any address with no instruction exactly as
	 * {@code mergeAndEnqueue} does (BankDataflowEngine.java:323-326). Dropping the state is
	 * sound for this question -- state affects the VALUE a switch produces, never which
	 * addresses are visited.
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
	 * Re-implementation of {@code MemoryLatchBankSwitchStrategy.writesInRange}, which is TWO
	 * TIERS and both must be reproduced here. Since grm-8iy.2 this is no longer the
	 * {@code today=} column -- that is read straight off production's own annotations (see the
	 * file header) -- it is the CROSS-CHECK that audits it, reported as
	 * {@code mirror.ref}/{@code mirror.operand}/{@code mirror.agree}. When production's
	 * predicate changes, this is still the thing that has to change with it; the difference is
	 * that a failure to keep up now shows as {@code mirror.agree=NO} instead of as a wrong
	 * answer.
	 * <p>
	 * <b>It models memory-latch ONLY.</b> {@code SerialShiftBankSwitchStrategy.writesInRange}
	 * (:801-810) and {@code SelectDataBankSwitchStrategy.writesInRange} (:305-314) are a single
	 * reference tier with a strict {@code equals()} space test -- no tier 2 and no overlay
	 * tolerance. Rather than grow a mirror per strategy, {@link Site#mirrorAgree()} reports NA
	 * off memory-latch; the two tiers below still describe the instruction truthfully there,
	 * they are just not that board's predicate.
	 * <p>
	 * <b>Both tiers, or the answer inverts.</b> grm-8cq: this mirrored tier 1 alone, long after
	 * grm-3x1 added tier 2, so every refless indexed store -- exactly the sites tier 2 exists to
	 * catch -- reported {@code today=NO} while production saw them perfectly well via tier 2.
	 * On megaman that produced an apparently decisive "production does not see these sites"
	 * reading and sent an investigation down a blind alley. A diagnostic that is confidently
	 * wrong is worse than no diagnostic.
	 * <p>
	 * <b>Tier 1 accepts overlays</b>, via {@code getPhysicalSpace()}. Production's
	 * {@code inLatchRange} tests the PHYSICAL space, so a latch store executing from inside a
	 * {@code PRG_LO_B<n>} window -- whose write reference lands in that overlay's space -- is in
	 * range. An earlier production did test the space strictly, which is what root cause (iii)
	 * in the file header describes; that test is gone and the header now says so.
	 * <p>
	 * <b>Tier 2 mirrors {@code operandStoresInRange}</b>, including its two soundness rulings:
	 * only true {@code STA}/{@code STX}/{@code STY} qualify (a read-modify-write keeps
	 * tier-1-only behaviour deliberately, because production answers {@code unknown()} for those
	 * and newly seeing one would poison rather than recover), and an INDEXED operand under a
	 * configured {@code addr_mask} declines, because {@code base & mask} says nothing about
	 * {@code (base + X) & mask}. Only the base is range-tested, never {@code base + 0xFF}.
	 * <p>
	 * Reported split as {@code today.ref}/{@code today.operand} so a future divergence localizes
	 * itself to the tier that drifted instead of presenting as one opaque wrong answer.
	 */
	private boolean writesInRange(Instruction instr, Mech mech, AddressSpace space) {
		return writesInRangeTier1(instr, mech, space) || writesInRangeTier2(instr, mech, space);
	}

	/** Tier 1: an authoritative write reference. Physical-space test, so overlays count. */
	private boolean writesInRangeTier1(Instruction instr, Mech mech, AddressSpace space) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() &&
				to.getAddressSpace().getPhysicalSpace().equals(space) &&
				mech.inRange(to.getOffset()) && mech.matchesDecode(to.getOffset())) {
				return true;
			}
		}
		return false;
	}

	/** Tier 2: operand decode, for the stores that carry no write reference at all. */
	private boolean writesInRangeTier2(Instruction instr, Mech mech, AddressSpace space) {
		if (storeRegister(instr) == null) {
			return false; // RMW stores stay tier-1-only, as in production
		}
		Address target = plainAbsoluteTarget(instr);
		if (target != null) {
			return inPhysical(target, space) && mech.inRange(target.getOffset()) &&
				mech.matchesDecode(target.getOffset());
		}
		Address base = indexedBase(instr);
		if (base == null || mech.addrMask != 0) {
			return false; // base & mask says nothing about (base + X) & mask
		}
		return inPhysical(base, space) && mech.inRange(base.getOffset());
	}

	/** Production's {@code inLatchRange} space half: an overlay over the code space counts. */
	private static boolean inPhysical(Address addr, AddressSpace space) {
		return addr.getAddressSpace().getPhysicalSpace().equals(space);
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
	 * The descriptor's mechanisms whose strategy is one of {@link #ACCEPTED_STRATEGIES},
	 * resolved through the same bundled-data lookup DescriptorResources.loadMap (:142-151) uses.
	 * A malformed or partial mechanism is skipped rather than fatal -- one bad entry should not
	 * blind the whole probe. Every strategy name encountered, accepted or not, is appended to
	 * {@code declared} so the caller's bail-out can name what the board actually is.
	 */
	private List<Mech> loadMechanisms(String mapPath, List<String> declared) throws Exception {
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
			if (!mech.has("strategy")) {
				continue;
			}
			String strategy = mech.get("strategy").getAsString();
			if (!declared.contains(strategy)) {
				declared.add(strategy);
			}
			if (!ACCEPTED_STRATEGIES.contains(strategy)) {
				continue; // range not described by start/end -- would be mis-modelled here
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
			// addr_mask/addr_match are read unconditionally but are memory-latch-only in the
			// schema; on the other two strategies they are absent and stay 0, which every
			// consumer gates behind Mech.memoryLatch() rather than reading as "mask of 0".
			out.add(new Mech(here, strategy, params.get("start").getAsLong(),
				params.get("end").getAsLong(),
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
					// binary and these lines are unverified anyway. Off memory-latch there is no
					// mask in the schema at all, so the column is NA rather than a free MATCH.
					String decode = !mech.memoryLatch() ? "NA"
							: mech.matchesDecode(target) ? "MATCH" : "MISS";
					counts[0]++;
					if ("MATCH".equals(decode)) {
						counts[1]++;
					}
					else if ("NA".equals(decode)) {
						counts[2]++;
					}
					try {
						out.add("cand " + fmt(chunkStart.add(i)) + " op=" +
							String.format("%02x", op) + " target=" + off(target) + " decode=" +
							decode);
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
		return "site " + fmt(s.at) + " mech=" + s.mech.index + " strategy=" + s.mech.strategy +
			" reg=" + s.reg + " mode=" + (s.indexed ? "IDX" : "ABS") + " base=" + off(s.base) +
			" ovl=" + s.ovl + " decode=" + s.decode + " func=" + s.func + " reach=" +
			(s.reach ? "YES" : "NO") + " refs=" + s.refs + " write=" + (s.write ? "YES" : "NO") +
			" today=" + (s.today() ? "YES" : "NO") + " today.src=" + s.todaySource() +
			" mirror.ref=" + (s.mirrorRef ? "YES" : "NO") +
			" mirror.operand=" + (s.mirrorOperand ? "YES" : "NO") +
			" mirror.agree=" + s.mirrorAgree() +
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
