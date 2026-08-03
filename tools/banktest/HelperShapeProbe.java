// THROWAWAY diagnostic (not committed): answers "would findHelpers model the routine that
// actually carries the bank argument?" for a serial-shift board, which BankReachProbe.java
// does not cover (it hard-requires a memory-latch mechanism).
//
// For every WARNING bookmark this analyzer left, report the containing function, then for
// each such function report its callers and whether the call is a JSR or a JMP (tail call),
// and the handful of instructions leading up to the first site. That is exactly the input
// findHelpers/composeTailCalls consume, so it shows whether the game's real call sites ever
// see a function the helper model knows about.
//
// Section 5 (grm-nju gate) goes further and PROTOTYPES the proposed fix, because the value
// of that fix hinges on an unproven premise: that callers pass a CONSTANT bank. It walks
// every call instruction in the program through a private copy of the proposed
// BoardBankAnalyzer.reachableEntries -- following Ghidra thunks and one-instruction
// unconditional-JMP trampolines -- and, for each call that would newly reach a site
// function, reports whether the instruction immediately before it is an immediate load.
// Re-implementing the production rule here rather than calling it is deliberate, the same
// choice BankReachProbe.java makes: a disagreement between the two is itself a finding.
//
// Diagnostic only -- never committed, never part of a golden.
//@category RetroMachines.Test

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class HelperShapeProbe extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("=== HELPERSHAPE BEGIN ===");
		Listing listing = currentProgram.getListing();
		FunctionManager fm = currentProgram.getFunctionManager();

		// 1. Warning sites -> containing function.
		Set<Function> siteFuncs = new LinkedHashSet<>();
		Map<Function, List<Address>> sitesByFunc = new LinkedHashMap<>();
		BookmarkManager bm = currentProgram.getBookmarkManager();
		Iterator<Bookmark> it = bm.getBookmarksIterator("Warning");
		while (it.hasNext()) {
			Bookmark b = it.next();
			Address a = b.getAddress();
			Function f = fm.getFunctionContaining(a);
			if (f == null) {
				println("HELPERSHAPE site " + a + " IN NO FUNCTION");
				continue;
			}
			siteFuncs.add(f);
			sitesByFunc.computeIfAbsent(f, k -> new ArrayList<>()).add(a);
		}

		for (Function f : siteFuncs) {
			List<Address> sites = sitesByFunc.get(f);
			println("HELPERSHAPE func " + f.getName() + " entry=" + f.getEntryPoint() +
				" body=" + f.getBody().getMinAddress() + "-" + f.getBody().getMaxAddress() +
				" sites=" + sites.size() + " first=" + sites.get(0));

			// 2. What flows INTO this function, and how.
			reportCallers(f, listing, fm, 0);

			// 3. Is any site itself a jump/call target? A site entered directly, bypassing the
			// instructions that physically precede it, is a second ENTRY POINT into the same
			// chain -- and the argument convention at that entry may differ from the function
			// entry's. That is invisible to a helper model keyed on the containing function.
			for (Address s : sites) {
				reportIncoming(s, listing, fm, "site");
			}
			// The function entry too, for contrast.
			reportIncoming(f.getEntryPoint(), listing, fm, "entry");

			// 4. The instructions right before the first site -- where the value comes from.
			for (String s : precedingContext(sites.get(0), listing, 4)) {
				println("HELPERSHAPE   pre " + s);
			}
			println("HELPERSHAPE   site " + sites.get(0) + ": " +
				listing.getInstructionAt(sites.get(0)));
		}

		reportReachableCallSites(siteFuncs, sitesByFunc, listing, fm);
		println("=== HELPERSHAPE END ===");
	}

	/**
	 * Section 5 -- the grm-nju gate. Every call instruction in the program, resolved through
	 * {@link #reachableEntries}, and reported when it lands inside a function that owns a
	 * warning site. Three tallies, which are the numbers the decision turns on:
	 * <ul>
	 * <li>{@code CONST} -- the instruction immediately before the call is an immediate load,
	 * i.e. the caller really does pass a constant and value recovery would succeed;</li>
	 * <li>{@code thunk} / {@code trampoline} hops -- how the call reaches the helper at all,
	 * i.e. whether thunk resolution is what unlocks it;</li>
	 * <li>{@code MID-BODY} -- the entry reached is not the function's entry point, so the
	 * helper model keyed on the containing function describes the wrong argument.</li>
	 * </ul>
	 */
	private void reportReachableCallSites(Set<Function> siteFuncs,
			Map<Function, List<Address>> sitesByFunc, Listing listing, FunctionManager fm)
			throws Exception {
		println("HELPERSHAPE --- section 5: call sites reachable into site functions ---");
		int total = 0;
		int constArg = 0;
		int viaHop = 0;
		int midBody = 0;
		for (Instruction call : listing.getInstructions(true)) {
			if (!call.getFlowType().isCall()) {
				continue;
			}
			for (Address entry : reachableEntries(call, listing, fm)) {
				Function owner = fm.getFunctionContaining(entry);
				if (owner == null || !siteFuncs.contains(owner)) {
					continue;
				}
				total++;
				boolean hopped = !Arrays.asList(call.getFlows()).contains(entry);
				boolean mid = !entry.equals(owner.getEntryPoint());
				// "At or before every recognized site" is the guard the fix will apply: only
				// then does entering here still run the whole recognized site set, which is
				// what makes reusing the function-body summary exact rather than a guess.
				Address lowestSite = sitesByFunc.get(owner).get(0);
				for (Address s : sitesByFunc.get(owner)) {
					if (s.compareTo(lowestSite) < 0) {
						lowestSite = s;
					}
				}
				boolean beforeAllSites = entry.compareTo(lowestSite) <= 0;
				Instruction prev = listing.getInstructionBefore(call.getMinAddress());
				boolean immediate = isImmediateLoad(prev);
				if (hopped) {
					viaHop++;
				}
				if (mid) {
					midBody++;
				}
				if (immediate) {
					constArg++;
				}
				println("HELPERSHAPE  call " + call.getMinAddress() + " " + call +
					" chain=" + hopChain(call, listing, fm) +
					" -> entry " + entry + " in " + owner.getName() +
					(mid ? " MID-BODY" : " (function entry)") +
					(hopped ? " VIA-HOP" : "") +
					(beforeAllSites ? "" : " AFTER-A-SITE(would be rejected)") +
					" arg=" + (immediate ? "CONST" : "computed/unknown") +
					" prev=" + (prev == null ? "none" : prev.toString()));
			}
		}
		println("HELPERSHAPE  TALLY reachableCallSites=" + total + " constArg=" + constArg +
			" viaThunkOrTrampoline=" + viaHop + " midBodyEntry=" + midBody);
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

	/** True for {@code LDA/LDX/LDY #imm} -- the shape value recovery can fold directly. */
	private boolean isImmediateLoad(Instruction instr) {
		if (instr == null) {
			return false;
		}
		String mnem = instr.getMnemonicString();
		return (mnem.equals("LDA") || mnem.equals("LDX") || mnem.equals("LDY")) &&
			instr.toString().contains("#");
	}

	/** Real relay chains are one link; 3 is slack, not a modeled depth. */
	private static final int MAX_HOPS = 3;

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
}
