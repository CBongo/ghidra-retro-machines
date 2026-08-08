// Independent, board-agnostic check on findHelpers' definition of a "bank-switch helper
// function": TWO separately-derived populations of such functions, reported side by side,
// where the DISAGREEMENT between them is the finding -- not either number alone.
//
// POPULATION 1 -- mechanism-derived ("mech"). Every STA/STX/STY whose operand resolves (via
// plainAbsoluteTarget, then indexedBase) to an address inside a mechanism range the board
// descriptor declares (banking.mechanisms[], loaded the same way BankReachProbe.java loads it)
// is a "mechsite"; the function containing it is a helper. This is what the PRODUCTION rule
// (BoardBankAnalyzer.findHelpers / StoredValueScanner) actually keys on -- a real mechanism
// write, not a diagnostic side effect.
//
// POPULATION 2 -- warning-derived ("warn"), the ORIGINAL population this probe shipped with,
// and now KNOWN FLAWED (grm-8iy.3). Every function containing ANY "Warning" bookmark, with no
// text filter and no mechanism check, was counted as a helper. On "blmaster" that inflated 5
// real helpers into 36 site functions and a "constant argument" count from 2 to 13. It also
// UNDER-counts: a real helper production resolves cleanly (FUN_e68c on blmaster) carries no
// Warning bookmark and was never enumerated by this population at all.
//
// The warn population is kept anyway, deliberately, not deleted -- classified by bookmark-text
// prefix (switchUnknown / violation / other) rather than filtered. The mech population is
// itself a fresh, unaudited re-derivation (see "WHY THE HELPERS ARE RE-IMPLEMENTED" below), so
// a warn-only or mech-only function is evidence about WHICH of the two populations is wrong on
// a given title, not noise to discard. Every function found by either method is tagged
// pop=BOTH / MECH-ONLY / WARN-ONLY, call-site tallies are reported once per population
// (TALLY.mech, TALLY.warn) exactly as each population would see them, and TALLY.delta isolates
// what the two disagree about.
//
// Section 5 (the grm-nju gate) goes further and PROTOTYPES the proposed constant-argument
// recovery fix, because the value of that fix hinges on an unproven premise: that callers pass
// a CONSTANT bank. It walks every call instruction in the program through a private copy of
// the proposed BoardBankAnalyzer.reachableEntries -- following Ghidra thunks and
// one-instruction unconditional-JMP trampolines -- and, for each call that would newly reach a
// helper function, reports whether the instruction immediately before it is an immediate load,
// and whether that immediate's destination register matches the helper's own store register.
//
// Re-implementing the production rule here rather than calling it is deliberate, the same
// choice BankReachProbe.java makes: a disagreement between the two is itself a finding. This
// script must NOT call BoardBankAnalyzer/findHelpers/StoredValueScanner -- see "WHY THE
// HELPERS ARE RE-IMPLEMENTED" below.
//
// This SCRIPT is committed and documented (tools/banktest/realrom/README.md); its OUTPUT is
// never committed and never part of a golden -- the same posture as BankReachProbe.java's
// header.
//
// WHY THE HELPERS ARE RE-IMPLEMENTED HERE
// retromachines.StoredValueScanner and retromachines.DescriptorSupport are package-private,
// and this script is not in that package. Widening either to public would do so FOREVER for
// the sake of a diagnostic, so storeRegister / plainAbsoluteTarget / indexedBase /
// loadMechanisms are re-implemented privately below. They are DUPLICATED from
// BankReachProbe.java rather than extracted to a shared class -- the established convention
// here (BankReachProbe.java:135-143, BankConsumerProbe.java:2050-2061) -- and each duplicate
// names the BankReachProbe method it mirrors.
//
// BEADS: grm-nju (constant-argument prototype), grm-8iy.3 (the warn-only population was a
// false premise; this mech/warn split is the fix, and TALLY.mech is what to compare against a
// golden's bankComments going forward).
//@category RetroMachines.Test

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

public class HelperShapeProbe extends GhidraScript {

	/**
	 * Program-info property the loader stamps with the board's .map path. Mirrors
	 * BankReachProbe.MAP_PATH_PROPERTY (~:213) -- kept as a literal here for the same reason
	 * that one is: DescriptorSupport is package-private and unreachable from a script.
	 */
	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	/** Mirrors BankReachProbe.MEMORY_LATCH (~:217). */
	private static final String MEMORY_LATCH = "memory-latch";

	/**
	 * Mirrors BankReachProbe.ACCEPTED_STRATEGIES (~:225): the strategies whose write range is
	 * fully described by start/end, and so by this probe's {@link Mech}.
	 */
	private static final List<String> ACCEPTED_STRATEGIES =
		List.of(MEMORY_LATCH, "serial-shift", "select-data");

	/** Mirrors BankReachProbe.SWITCH_UNKNOWN_PREFIX (~:233). */
	private static final String SWITCH_UNKNOWN_PREFIX = "Bank state becomes unknown here:";

	/** Mirrors BankReachProbe.REQUIREMENT_VIOLATED_PREFIX (~:240): Phase-3 bookmarks that sit
	 *  at CALL sites, not switch sites. Not excluded here (this probe keeps every Warning
	 *  bookmark, unlike BankReachProbe's today=), just classified into its own bucket. */
	private static final String REQUIREMENT_VIOLATED_PREFIX = "Bank state requirement violated:";

	/** Mirrors BankReachProbe.WARNING_TYPE (~:244). */
	private static final String WARNING_TYPE = "Warning";

	/** Real relay chains are one link; 3 is slack, not a modeled depth. */
	private static final int MAX_HOPS = 3;

	// ------------------------------------------------------------------
	// Model
	// ------------------------------------------------------------------

	/**
	 * One configured mechanism of an {@link #ACCEPTED_STRATEGIES accepted} strategy. Trimmed
	 * from BankReachProbe.Mech (~:268-296): this probe only needs a plain start/end range match
	 * to decide "is this store site a mechanism write", not BankReachProbe's addr_mask decode
	 * verdict (that column answers a different question -- MATCH/MISS/UNDECIDED -- that this
	 * probe does not ask).
	 */
	private static final class Mech {
		final int index;
		final String strategy;
		final long start;
		final long end;

		Mech(int index, String strategy, long start, long end) {
			this.index = index;
			this.strategy = strategy;
			this.start = start;
			this.end = end;
		}

		boolean inRange(long offset) {
			return offset >= start && offset <= end;
		}
	}

	/** One mechanism-range store site, retained so its owning function can aggregate register
	 *  agreement, first/last address, and which mechanism/offset it hit. */
	private static final class MechSite {
		final Address at;
		final char reg;
		final Mech mech;
		final long offset;

		MechSite(Address at, char reg, Mech mech, long offset) {
			this.at = at;
			this.reg = reg;
			this.mech = mech;
			this.offset = offset;
		}
	}

	/** Per-function aggregate of the mechanism-derived population. Instructions are visited in
	 *  address order (listing.getInstructions(true)), so the first site added is mechFirst and
	 *  the last is mechLast with no separate sort needed. */
	private static final class MechAgg {
		final List<MechSite> sites = new ArrayList<>();
		Address first;
		Address last;
		Mech mech; // the mechanism at the first (lowest-address) site
		long latch; // the target offset at that same first site
		Character reg; // register common to all sites so far, or already MIXED
		boolean mixed;

		void add(Address at, char r, Mech m, long offset) {
			sites.add(new MechSite(at, r, m, offset));
			if (first == null) {
				first = at;
				mech = m;
				latch = offset;
			}
			last = at;
			if (reg == null) {
				reg = r;
			}
			else if (reg != r) {
				mixed = true;
			}
		}

		String storeRegText() {
			return mixed ? "MIXED" : String.valueOf(reg);
		}
	}

	/** Per-function aggregate of the warning-derived population: every Warning bookmark inside
	 *  the function, classified by text prefix, but NONE filtered out -- the whole point of
	 *  this population is that it is the probe's original, unfiltered one. */
	private static final class WarnAgg {
		final List<Address> sites = new ArrayList<>();
		final Map<String, Integer> kindCounts = new LinkedHashMap<>();

		void add(Address at, String kind) {
			sites.add(at);
			kindCounts.merge(kind, 1, Integer::sum);
		}

		String kindsText() {
			if (kindCounts.isEmpty()) {
				return "NONE";
			}
			StringBuilder sb = new StringBuilder();
			for (Map.Entry<String, Integer> e : kindCounts.entrySet()) {
				if (sb.length() > 0) {
					sb.append(',');
				}
				sb.append(e.getKey()).append(':').append(e.getValue());
			}
			return sb.toString();
		}
	}

	// ------------------------------------------------------------------
	// Entry point
	// ------------------------------------------------------------------

	@Override
	public void run() throws Exception {
		// Fence opened and closed unconditionally, matching BankReachProbe's header wording: a
		// stack trace escaping run() would leave headless emitting a half-open block that the
		// caller's carve cannot interpret.
		println("=== HELPERSHAPE BEGIN ===");
		try {
			probe();
		}
		catch (Exception e) {
			println("HELPERSHAPE error " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		println("=== HELPERSHAPE END ===");
	}

	private void probe() throws Exception {
		Listing listing = currentProgram.getListing();
		FunctionManager fm = currentProgram.getFunctionManager();

		// ------------------------------------------------------------------
		// Population 1: mechanism-derived
		// ------------------------------------------------------------------
		Map<Function, MechAgg> mechByFunc = new LinkedHashMap<>();
		boolean mechAvailable = false;
		String mapPath =
			currentProgram.getOptions(Program.PROGRAM_INFO).getString(MAP_PATH_PROPERTY, null);
		List<String> declared = new ArrayList<>();
		String mechUnavailableReason = null;
		List<Mech> mechs = new ArrayList<>();
		if (mapPath == null || mapPath.isBlank()) {
			mechUnavailableReason = "no '" + MAP_PATH_PROPERTY + "' property on this program";
		}
		else {
			try {
				mechs = loadMechanisms(mapPath, declared);
			}
			catch (Exception e) {
				mechUnavailableReason = "descriptor " + mapPath + ": " +
					e.getClass().getSimpleName() + ": " + e.getMessage();
			}
			if (mechUnavailableReason == null && mechs.isEmpty()) {
				mechUnavailableReason = "descriptor " + mapPath + " declares no " +
					"banking.mechanisms[] entry with a strategy this probe models (" +
					String.join(", ", ACCEPTED_STRATEGIES) + ")";
			}
		}
		if (mechUnavailableReason != null) {
			// Board-agnosticism: print the reason and move on WITHOUT a mech tally row -- a
			// zeroed row would read as "zero helpers found" rather than "not even attempted".
			println("HELPERSHAPE note mech.unavailable " + mechUnavailableReason + "; declared: " +
				(declared.isEmpty() ? "NONE" : String.join(", ", declared)));
		}
		else {
			mechAvailable = true;
			AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
			long rmwSkipped = 0;
			InstructionIterator mechInstrs = listing.getInstructions(true);
			while (mechInstrs.hasNext()) {
				monitor.checkCancelled();
				Instruction instr = mechInstrs.next();
				Character reg = storeRegister(instr);
				if (reg == null) {
					// Not an STA/STX/STY. On 6502 a non-store instruction that still WRITES a
					// mechanism range is a read-modify-write (INC/ASL/ROL/...); production's own
					// mechanism-write gate accepts those, this probe's storeRegister-based site
					// enumeration structurally cannot, so the gap is counted rather than hidden.
					for (Mech m : mechs) {
						if (writesRangeAnySpace(instr, m)) {
							rmwSkipped++;
							break;
						}
					}
					continue;
				}
				// Decode the target from the OPERAND, mirroring BankReachProbe's site
				// enumeration (~:494-502): plainAbsoluteTarget first, indexedBase as fallback.
				Address target = plainAbsoluteTarget(instr);
				if (target == null) {
					target = indexedBase(instr);
				}
				if (target == null) {
					continue; // zero-page-indirect / (zp),Y / no address operand
				}
				// Normalize BY OFFSET into the default space so an overlay-resident store is not
				// dropped -- mirrors BankReachProbe's soundness comment at ~:504-508.
				Address normalized;
				try {
					normalized = defaultSpace.getAddress(target.getOffset());
				}
				catch (AddressOutOfBoundsException e) {
					continue;
				}
				long offset = normalized.getOffset();
				Mech mech = null;
				for (Mech m : mechs) {
					if (m.inRange(offset)) {
						mech = m; // first match wins, mirroring runDataflow's ordered loop
						break;
					}
				}
				if (mech == null) {
					continue;
				}
				Address at = instr.getMinAddress();
				Function owner = fm.getFunctionContaining(at);
				if (owner == null) {
					println("HELPERSHAPE mechsite " + at + " IN NO FUNCTION latch=" + off(offset));
					continue;
				}
				mechByFunc.computeIfAbsent(owner, k -> new MechAgg()).add(at, reg, mech, offset);
			}
			println("HELPERSHAPE count mechsites.rmwSkipped " + rmwSkipped);
		}

		// ------------------------------------------------------------------
		// Population 2: warning-derived (kept, now classified)
		// ------------------------------------------------------------------
		Map<Function, WarnAgg> warnByFunc = new LinkedHashMap<>();
		long warnTotal = 0;
		long warnSwitchUnknown = 0;
		long warnViolation = 0;
		long warnOther = 0;
		long warnNoFunction = 0;
		BookmarkManager bm = currentProgram.getBookmarkManager();
		Iterator<Bookmark> it = bm.getBookmarksIterator(WARNING_TYPE);
		while (it.hasNext()) {
			Bookmark b = it.next();
			warnTotal++;
			Address a = b.getAddress();
			String text = b.getComment();
			String kind;
			if (text != null && text.startsWith(SWITCH_UNKNOWN_PREFIX)) {
				kind = "switchUnknown";
				warnSwitchUnknown++;
			}
			else if (text != null && text.startsWith(REQUIREMENT_VIOLATED_PREFIX)) {
				kind = "violation";
				warnViolation++;
			}
			else {
				kind = "other";
				warnOther++;
			}
			Function f = fm.getFunctionContaining(a);
			if (f == null) {
				warnNoFunction++;
				println("HELPERSHAPE site " + a + " IN NO FUNCTION");
				continue;
			}
			warnByFunc.computeIfAbsent(f, k -> new WarnAgg()).add(a, kind);
		}

		// ------------------------------------------------------------------
		// Per-helper detail, one function at a time, either population
		// ------------------------------------------------------------------
		Set<Function> allFuncs = new LinkedHashSet<>();
		allFuncs.addAll(mechByFunc.keySet());
		allFuncs.addAll(warnByFunc.keySet());

		for (Function f : allFuncs) {
			MechAgg ma = mechByFunc.get(f);
			WarnAgg wa = warnByFunc.get(f);
			String pop = ma != null && wa != null ? "BOTH" : ma != null ? "MECH-ONLY" : "WARN-ONLY";

			StringBuilder line = new StringBuilder();
			line.append("HELPERSHAPE helper ").append(f.getName())
				.append(" entry=").append(f.getEntryPoint())
				.append(" body=").append(f.getBody().getMinAddress()).append('-')
				.append(f.getBody().getMaxAddress())
				.append(" pop=").append(pop);
			if (ma != null) {
				line.append(" mech=").append(ma.mech.index)
					.append(" strategy=").append(ma.mech.strategy)
					.append(" mechSites=").append(ma.sites.size())
					.append(" mechFirst=").append(ma.first)
					.append(" mechLast=").append(ma.last)
					.append(" latch=").append(off(ma.latch))
					.append(" storeReg=").append(ma.storeRegText());
			}
			if (wa != null) {
				line.append(" warnSites=").append(wa.sites.size())
					.append(" warnKinds=").append(wa.kindsText());
			}
			println(line.toString());

			// 2. What flows INTO this function, and how.
			reportCallers(f, listing, fm, 0);

			// 3/4. Site-level detail: the warn sites when this function has any (preserving what
			// was previously reported), else the mech sites -- the closest analog for a
			// MECH-ONLY function, which has no bookmark sites to show at all.
			List<Address> sitesForBlocks;
			if (wa != null) {
				sitesForBlocks = wa.sites;
			}
			else {
				sitesForBlocks = new ArrayList<>();
				for (MechSite ms : ma.sites) {
					sitesForBlocks.add(ms.at);
				}
			}
			for (Address s : sitesForBlocks) {
				reportIncoming(s, listing, fm, "site");
			}
			reportIncoming(f.getEntryPoint(), listing, fm, "entry");
			for (String s : precedingContext(sitesForBlocks.get(0), listing, 4)) {
				println("HELPERSHAPE   pre " + s);
			}
			println("HELPERSHAPE   site " + sitesForBlocks.get(0) + ": " +
				listing.getInstructionAt(sitesForBlocks.get(0)));
		}

		reportReachableCallSites(mechByFunc, warnByFunc, mechAvailable, listing, fm);

		println("HELPERSHAPE  TALLY.bookmarks warnTotal=" + warnTotal + " switchUnknown=" +
			warnSwitchUnknown + " violation=" + warnViolation + " other=" + warnOther +
			" noFunction=" + warnNoFunction);
		println("HELPERSHAPE  note tally.legacy the single pre-fix 'TALLY reachableCallSites=.. " +
			"constArg=..' line reported the TALLY.warn row; TALLY.mech is the " +
			"production-aligned population and is the one to compare against a golden's " +
			"bankComments (bead grm-8iy.3)");
	}

	/**
	 * Section 5 -- the grm-nju gate, now run once against the UNION of both populations. Every
	 * call instruction in the program, resolved through {@link #reachableEntries}, reported
	 * when it lands inside a function either population recognizes as a helper. Tallied
	 * separately per population (TALLY.mech / TALLY.warn) because a call landing in a BOTH
	 * function counts toward both -- it really is a call into a helper by either definition --
	 * while TALLY.delta isolates the calls that only one definition would ever see.
	 */
	private void reportReachableCallSites(Map<Function, MechAgg> mechByFunc,
			Map<Function, WarnAgg> warnByFunc, boolean mechAvailable, Listing listing,
			FunctionManager fm) throws Exception {
		println("HELPERSHAPE --- section 5: call sites reachable into helper functions ---");
		println("HELPERSHAPE note constarg.method the immediate is the ONE physically preceding " +
			"instruction with no basic-block or reaching-definition analysis, so an immediate " +
			"separated from the call reads as unknown and one reached only on a not-taken path " +
			"reads as CONST -- an independent naive re-derivation, deliberately not production's " +
			"scanner.");

		int totalMech = 0;
		int totalWarn = 0;
		int viaHopMech = 0;
		int viaHopWarn = 0;
		int midBodyMech = 0;
		int midBodyWarn = 0;
		Set<Address> callInstrsMech = new LinkedHashSet<>();
		Set<Address> callInstrsWarn = new LinkedHashSet<>();
		Set<Address> constArgMech = new LinkedHashSet<>();
		Set<Address> constArgWarn = new LinkedHashSet<>();
		Set<Address> constArgRegMatch = new LinkedHashSet<>();
		Set<Address> constArgRegMismatch = new LinkedHashSet<>();
		Set<Address> constArgRegMixed = new LinkedHashSet<>();
		Set<Address> tailCallMech = new LinkedHashSet<>();
		Set<Address> tailCallWarn = new LinkedHashSet<>();
		// Delta bookkeeping: CONST call instructions attributed ONLY through one population --
		// i.e. the owning function is MECH-ONLY (never found via warn) or WARN-ONLY (never
		// found via mech), not BOTH.
		Set<Address> constArgMechOnly = new LinkedHashSet<>();
		Set<Address> constArgWarnOnly = new LinkedHashSet<>();

		for (Instruction call : listing.getInstructions(true)) {
			// Kept exactly as before: this filter admits a JMP Ghidra retyped as a tail call,
			// which is correct -- see the tailCall tally below rather than excluding it here.
			if (!call.getFlowType().isCall()) {
				continue;
			}
			for (Address entry : reachableEntries(call, listing, fm)) {
				Function owner = fm.getFunctionContaining(entry);
				if (owner == null) {
					continue;
				}
				MechAgg ma = mechByFunc.get(owner);
				WarnAgg wa = warnByFunc.get(owner);
				if (ma == null && wa == null) {
					continue;
				}
				String pop = ma != null && wa != null ? "BOTH" : ma != null ? "MECH-ONLY" : "WARN-ONLY";

				boolean hopped = !Arrays.asList(call.getFlows()).contains(entry);
				boolean mid = !entry.equals(owner.getEntryPoint());
				Instruction prev = listing.getInstructionBefore(call.getMinAddress());
				Character immReg = destReg(prev);
				String arg = immReg != null ? "CONST" : "computed/unknown";
				// helperArgReg mirrors production's own register-consistency rule
				// (Site 1's storeReg), independently re-derived: NONE when the owner carries no
				// mech-population data at all (a WARN-ONLY function), MIXED when its mech sites
				// disagree on register, else the single register all its sites share.
				String helperArgReg = ma != null ? ma.storeRegText() : "NONE";
				String regMatch;
				if (ma == null || "MIXED".equals(helperArgReg) || immReg == null) {
					// NA, deliberately, in all three cases -- including immReg==null. YES/NO is a
					// claim that two known registers agree or disagree, and with no immediate at
					// all there is no second register to compare; printing NO there would read as
					// "the caller used the wrong register", which is exactly the kind of number
					// meaning-something-other-than-it-looks that this probe's rewrite exists to
					// stop. The regMatch tallies below only ever count CONST sites anyway, so
					// this changes wording, not arithmetic.
					regMatch = "NA";
				}
				else {
					regMatch = immReg.charValue() == helperArgReg.charAt(0) ? "YES" : "NO";
				}
				boolean isTail = call.getFlowType().isCall() && call.getFlowType().isTerminal();
				Address callAddr = call.getMinAddress();

				if (ma != null) {
					totalMech++;
					if (hopped) {
						viaHopMech++;
					}
					if (mid) {
						midBodyMech++;
					}
					callInstrsMech.add(callAddr);
					if (immReg != null) {
						constArgMech.add(callAddr);
						if ("YES".equals(regMatch)) {
							constArgRegMatch.add(callAddr);
						}
						else if ("NO".equals(regMatch)) {
							constArgRegMismatch.add(callAddr);
						}
						else if ("MIXED".equals(helperArgReg)) {
							constArgRegMixed.add(callAddr);
						}
						if ("MECH-ONLY".equals(pop)) {
							constArgMechOnly.add(callAddr);
						}
					}
					if (isTail) {
						tailCallMech.add(callAddr);
					}
				}
				if (wa != null) {
					totalWarn++;
					if (hopped) {
						viaHopWarn++;
					}
					if (mid) {
						midBodyWarn++;
					}
					callInstrsWarn.add(callAddr);
					if (immReg != null) {
						constArgWarn.add(callAddr);
						if ("WARN-ONLY".equals(pop)) {
							constArgWarnOnly.add(callAddr);
						}
					}
					if (isTail) {
						tailCallWarn.add(callAddr);
					}
				}

				println("HELPERSHAPE  call " + callAddr + " flow=" + call.getFlowType() + " " +
					call + " chain=" + hopChain(call, listing, fm) +
					" -> entry " + entry + " in " + owner.getName() +
					" pop=" + pop +
					(mid ? " MID-BODY" : " (function entry)") +
					(hopped ? " VIA-HOP" : "") +
					" arg=" + arg +
					" immReg=" + (immReg == null ? "NONE" : immReg) +
					" helperArgReg=" + helperArgReg +
					" regMatch=" + regMatch +
					" prev=" + (prev == null ? "none" : prev.toString()));
			}
		}

		if (mechAvailable) {
			println("HELPERSHAPE  TALLY.mech helperFuncs=" + mechByFunc.size() +
				" reachableCallSites=" + totalMech + " callInstrs=" + callInstrsMech.size() +
				" constArg=" + constArgMech.size() + " constArgRegMatch=" +
				constArgRegMatch.size() + " constArgRegMismatch=" + constArgRegMismatch.size() +
				" constArgRegMixed=" + constArgRegMixed.size() + " viaThunkOrTrampoline=" +
				viaHopMech + " midBodyEntry=" + midBodyMech + " tailCall=" + tailCallMech.size());
		}
		println("HELPERSHAPE  TALLY.warn helperFuncs=" + warnByFunc.size() +
			" reachableCallSites=" + totalWarn + " callInstrs=" + callInstrsWarn.size() +
			" constArg=" + constArgWarn.size() + " viaThunkOrTrampoline=" + viaHopWarn +
			" midBodyEntry=" + midBodyWarn + " tailCall=" + tailCallWarn.size());

		int both = 0;
		int mechOnly = 0;
		int warnOnly = 0;
		Set<Function> allFuncs = new LinkedHashSet<>();
		allFuncs.addAll(mechByFunc.keySet());
		allFuncs.addAll(warnByFunc.keySet());
		for (Function f : allFuncs) {
			boolean m = mechByFunc.containsKey(f);
			boolean w = warnByFunc.containsKey(f);
			if (m && w) {
				both++;
			}
			else if (m) {
				mechOnly++;
			}
			else {
				warnOnly++;
			}
		}
		println("HELPERSHAPE  TALLY.delta helperFuncs.both=" + both + " helperFuncs.mechOnly=" +
			mechOnly + " helperFuncs.warnOnly=" + warnOnly + " constArg.mechOnly=" +
			constArgMechOnly.size() + " constArg.warnOnly=" + constArgWarnOnly.size());
	}

	/** The {@code n} instructions physically preceding {@code at}, oldest first. */
	private List<String> precedingContext(Address at, Listing listing, int n) {
		List<String> pre = new ArrayList<>();
		Instruction cur = listing.getInstructionAt(at);
		for (int i = 0; i < n && cur != null; i++) {
			Instruction p = listing.getInstructionBefore(cur.getMinAddress());
			if (p == null) {
				break;
			}
			pre.add(0, p.getMinAddress() + ": " + p.toString());
			cur = p;
		}
		return pre;
	}

	/** Register-aware replacement for the old text-only isImmediateLoad: the destination
	 *  register of an {@code LDA/LDX/LDY #imm}, or null. The "#" substring test and the rule
	 *  that only the ONE physically preceding instruction is examined are both KEPT exactly as
	 *  before -- see the {@code constarg.method} note this probe emits once per run -- they are
	 *  the intentional naive re-derivation, not a bug to fix. */
	private Character destReg(Instruction instr) {
		if (instr == null || !instr.toString().contains("#")) {
			return null;
		}
		String mnem = instr.getMnemonicString();
		if (mnem.equals("LDA")) {
			return 'A';
		}
		if (mnem.equals("LDX")) {
			return 'X';
		}
		if (mnem.equals("LDY")) {
			return 'Y';
		}
		return null;
	}

	/**
	 * Prototype of the proposed {@code BoardBankAnalyzer.reachableEntries}: the addresses
	 * control can actually arrive at from this call, following Ghidra thunks and
	 * one-instruction unconditional-JMP trampolines, bounded at {@link #MAX_HOPS} with a
	 * visited set as the cycle guard.
	 * <p>
	 * The two hop forms are NOT interchangeable. Ghidra types {@code d751 JMP dcc3} as
	 * {@code thunk_FUN_dcc3} because {@code dcc3} is a function entry; it does NOT type
	 * {@code d6e2 JMP dcaa} as a thunk, because {@code dcaa} is mid-body. Only the second
	 * form needs the manual walk, and it is exactly the form the helper model cannot see.
	 */
	private List<Address> reachableEntries(Instruction callInstr, Listing listing,
			FunctionManager fm) {
		List<Address> entries = new ArrayList<>();
		for (Address flow : callInstr.getFlows()) {
			Set<Address> seen = new LinkedHashSet<>();
			Address cur = flow;
			for (int hop = 0; cur != null && seen.add(cur); hop++) {
				entries.add(cur);
				if (hop >= MAX_HOPS) {
					break;
				}
				cur = hopTarget(cur, listing, fm);
			}
		}
		return entries;
	}

	/** Each hop spelled out -- which rule fired, and what the instruction there was. */
	private String hopChain(Instruction callInstr, Listing listing, FunctionManager fm) {
		StringBuilder sb = new StringBuilder();
		for (Address flow : callInstr.getFlows()) {
			Set<Address> seen = new LinkedHashSet<>();
			Address cur = flow;
			for (int hop = 0; cur != null && seen.add(cur); hop++) {
				Function at = fm.getFunctionAt(cur);
				Function owner = fm.getFunctionContaining(cur);
				Instruction here = listing.getInstructionAt(cur);
				sb.append(hop == 0 ? "[" : " => ").append(cur)
						.append("{").append(here == null ? "?" : here.toString())
						.append(at != null && at.isThunk() ? ",THUNK" : "")
						.append(owner == null ? ",no-function" : ",in=" + owner.getName())
						.append("}");
				cur = hop < MAX_HOPS ? hopTarget(cur, listing, fm) : null;
			}
			sb.append("]");
		}
		return sb.toString();
	}

	/** One hop through a thunk or a one-instruction JMP trampoline, or null if neither. */
	private Address hopTarget(Address at, Listing listing, FunctionManager fm) {
		Function f = fm.getFunctionAt(at);
		if (f != null && f.isThunk()) {
			Function thunked = f.getThunkedFunction(true);
			if (thunked != null) {
				return thunked.getEntryPoint();
			}
		}
		Instruction instr = listing.getInstructionAt(at);
		// isComputed() excluded: the 6502's BRK is `goto [*:2 0xFFFE]`, so every filler $00
		// byte would otherwise read as a one-instruction relay into the IRQ handler.
		if (instr == null || instr.getFlowType().isCall() ||
			!instr.getFlowType().isJump() || instr.getFlowType().isConditional() ||
			instr.getFlowType().isComputed()) {
			return null;
		}
		// A trampoline is a function (or a bodiless stretch) that is ONLY this jump. A JMP
		// at the end of a longer body is an ordinary tail jump, not an argument relay, and
		// following it would attribute the callee to a call that ran other code first.
		Function owner = fm.getFunctionContaining(at);
		if (owner != null && (!owner.getEntryPoint().equals(at) ||
			owner.getBody().getNumAddresses() != instr.getLength())) {
			return null;
		}
		Address[] flows = instr.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	/** Incoming flow references to one address, plus whether a function or label exists there.
	 *  An address with incoming flow that is NOT its function's entry is a mid-body entry point:
	 *  the backward value scan is right to refuse to walk past it (another path reaches it with
	 *  different registers), but that refusal is also the signal that it IS an entry with its own
	 *  argument convention. */
	private void reportIncoming(Address a, Listing listing, FunctionManager fm, String tag)
			throws Exception {
		Function at = fm.getFunctionAt(a);
		Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(a);
		List<String> in = new ArrayList<>();
		ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(a);
		while (refs.hasNext() && in.size() < 8) {
			Reference r = refs.next();
			if (!r.getReferenceType().isFlow()) {
				continue;
			}
			Instruction from = listing.getInstructionAt(r.getFromAddress());
			in.add(r.getFromAddress() + "(" + (from == null ? "?" : from.getMnemonicString()) +
				"," + r.getReferenceType() + ")");
		}
		Instruction here = listing.getInstructionAt(a);
		println("HELPERSHAPE   " + tag + " " + a +
			" instr=" + (here == null ? "?" : here.toString()) +
			" functionAt=" + (at == null ? "none" : at.getName()) +
			" label=" + (sym == null ? "none" : sym.getName()) +
			" incomingFlow=" + (in.isEmpty() ? "NONE(fallthrough only)" : in));
	}

	/** Callers of f, one level up, noting JSR (call) vs JMP (tail call) -- and recursing once
	 *  through a tail call, which is how an argument-relay trampoline reaches a helper. */
	private void reportCallers(Function f, Listing listing, FunctionManager fm, int depth)
			throws Exception {
		if (depth > 2) {
			return;
		}
		String pad = "  ".repeat(depth + 1);
		ReferenceIterator refs =
			currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
		int n = 0;
		while (refs.hasNext() && n < 12) {
			Reference r = refs.next();
			if (!r.getReferenceType().isFlow()) {
				continue;
			}
			n++;
			Instruction from = listing.getInstructionAt(r.getFromAddress());
			Function fromFunc = fm.getFunctionContaining(r.getFromAddress());
			String kind = from == null ? "?" : from.getFlowType().isCall() ? "JSR" : "JMP/branch";
			println("HELPERSHAPE " + pad + "from " + r.getFromAddress() + " " + kind +
				" in=" + (fromFunc == null ? "NO-FUNCTION" : fromFunc.getName()) +
				" instr=" + (from == null ? "?" : from.toString()));
			// What the caller does BEFORE the call is the whole question for grm-nju: an
			// "LDA #imm" here means the argument is a constant and recovery would succeed.
			// Previously printed only on the tail-call branch, which is the one shape where
			// it does not answer that question.
			for (String s : precedingContext(r.getFromAddress(), listing, 4)) {
				println("HELPERSHAPE " + pad + "  pre " + s);
			}
			// A tail call means the CALLER is the routine the game actually invokes; recurse.
			if (from != null && !from.getFlowType().isCall() && fromFunc != null &&
				!fromFunc.equals(f)) {
				println("HELPERSHAPE " + pad + "  (tail call -- callers of " +
					fromFunc.getName() + ":)");
				// Show what that trampoline does before jumping.
				Instruction p = listing.getInstructionAt(fromFunc.getEntryPoint());
				for (int i = 0; i < 4 && p != null; i++) {
					println("HELPERSHAPE " + pad + "    body " + p.getMinAddress() + ": " + p);
					p = p.getNext();
				}
				reportCallers(fromFunc, listing, fm, depth + 1);
			}
		}
		if (n == 0) {
			println("HELPERSHAPE " + pad + "(no flow references to this entry point)");
		}
	}

	// ------------------------------------------------------------------
	// Re-implemented production helpers (see the file header for why)
	// ------------------------------------------------------------------

	/** Mirrors BankReachProbe.storeRegister (~:854-860), itself a mirror of
	 *  StoredValueScanner.storeRegister: 'A'/'X'/'Y' for STA/STX/STY, else null.
	 *  Read-modify-write stores (INC/ASL/...) are excluded there and here. */
	private static Character storeRegister(Instruction instr) {
		String mnem = instr.getMnemonicString().toUpperCase();
		if (mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY")) {
			return mnem.charAt(2); // 'A' | 'X' | 'Y'
		}
		return null;
	}

	/** Mirrors BankReachProbe.plainAbsoluteTarget (~:865-880): the single constant address an
	 *  operand names, or null when any register participates (indexed/indirect) or when the
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

	/** Mirrors BankReachProbe.indexedBase (~:884-910): the base of an indexed operand (abs,X /
	 *  abs,Y / zp,X), built in the EXECUTING instruction's space -- which for an out-of-overlay
	 *  offset already resolves back to the base space. */
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

	/** Deliberately LOOSER than production: any write reference whose OFFSET falls in a
	 *  mechanism's latch range, in any address space. Mirrors BankReachProbe's
	 *  writesRangeAnySpace (~:838-846); used here only to measure mechsites.rmwSkipped -- stores
	 *  that write a mechanism range without being STA/STX/STY, which storeRegister
	 *  intentionally excludes just as StoredValueScanner.storeRegister does in production. */
	private static boolean writesRangeAnySpace(Instruction instr, Mech mech) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && mech.inRange(to.getOffset())) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Descriptor
	// ------------------------------------------------------------------

	/**
	 * Mirrors BankReachProbe.loadMechanisms (~:926-975), trimmed to start/end only (see
	 * {@link Mech}'s javadoc for why). The descriptor's mechanisms whose strategy is one of
	 * {@link #ACCEPTED_STRATEGIES}, resolved through the same bundled-data lookup
	 * DescriptorSupport.loadMap uses. A malformed or partial mechanism is skipped rather than
	 * fatal. Every strategy name encountered, accepted or not, is appended to {@code declared}
	 * so the caller's unavailable-note can name what the board actually is.
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
				continue;
			}
			JsonObject params = mech.getAsJsonObject("params");
			if (!params.has("start") || !params.has("end")) {
				continue;
			}
			out.add(new Mech(here, strategy, params.get("start").getAsLong(),
				params.get("end").getAsLong()));
		}
		return out;
	}

	// ------------------------------------------------------------------
	// Formatting
	// ------------------------------------------------------------------

	/** Bare-offset formatting for a value with no Address (e.g. latch). Mirrors
	 *  BankReachProbe.off. */
	private static String off(long offset) {
		return String.format("%04x", offset);
	}
}
