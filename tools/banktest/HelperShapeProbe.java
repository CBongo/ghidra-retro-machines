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
			Instruction cur = listing.getInstructionAt(sites.get(0));
			List<String> pre = new ArrayList<>();
			for (int i = 0; i < 4 && cur != null; i++) {
				Instruction p = listing.getInstructionBefore(cur.getMinAddress());
				if (p == null) {
					break;
				}
				pre.add(0, p.getMinAddress() + ": " + p.toString());
				cur = p;
			}
			for (String s : pre) {
				println("HELPERSHAPE   pre " + s);
			}
			println("HELPERSHAPE   site " + sites.get(0) + ": " +
				listing.getInstructionAt(sites.get(0)));
		}
		println("=== HELPERSHAPE END ===");
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
