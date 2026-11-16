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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.task.TaskMonitor;

/**
 * Removes the base-space FUNCTION (and, where provably unreached, decode) that a retired
 * retargeted CALL reference leaves orphaned (bead grm-z0d7.1, under the amended grm-8uaz rule).
 * <p>
 * Ghidra's "Subroutine References" makes a function at every JSR target in round one, before
 * any bank analysis. When {@link BankAnnotationAdapter#retargetReferences} later proves the call
 * runs in another bank and retires the stock base-space reference, the base-space function it
 * created is a wrong-bank artifact: inside genuine home-bank code it is a stray entry (smb3
 * {@code FUN_b0ff}), and over home-bank bytes it can be a misaligned decode that blocks the home
 * bank's own instruction (smb3 {@code FUN_ab67} over {@code ab66 STA $0076,Y}). Both fed stock
 * FindNoReturnFunctions false evidence (grm-z0d7).
 * <p>
 * The rule is that this class may remove a base-space function entry, or decode run, only when
 * every root into it is a reference this analyzer retargeted. A candidate is therefore only
 * ever the target of a reference retired this round, and is removed only if nothing else roots
 * it: no remaining reference of any type, no instruction falling into it, no external entry
 * point, no user-defined symbol, no protected location. Instructions are cleared only if they
 * are reached exclusively from the candidate; an instruction any outside flow reaches stays. The
 * home bank's decode is then restored by disassembling at every surviving instruction's
 * fall-through that lands in the cleared bytes.
 * <p>
 * Every removal leaves an ANALYSIS bookmark at the entry in {@link #CATEGORY} whose comment
 * {@code instrs=<n> funcs=<n> redecoded=<n> retargetedFrom=<addr>} is what the base-space
 * census sums (tools/banktest/BaseSpaceCensus.java). Idempotent: a second call finds no
 * function at the entry and writes nothing.
 */
final class WrongBankArtifacts {

	/** Bookmark category the census reads. Keep in step with BaseSpaceCensus.java. */
	static final String CATEGORY = "Wrong-bank artifact removed";

	/** Longest instruction, for the look-back that finds a fall-through into cleared bytes. */
	private static final int MAX_INSTRUCTION_LENGTH = 4;

	record Removal(Address entry, Address retargetedFrom, int instrs, int funcs, int redecoded) {
	}

	private WrongBankArtifacts() {
	}

	/**
	 * Removes each orphaned candidate that passes the rules in the class comment.
	 *
	 * @param candidates retired call target to the call site whose reference was retired
	 * @return the removals performed, in address order
	 */
	static List<Removal> remove(BoardBankAnalyzer analyzer, Program program,
			Map<Address, Address> candidates, TaskMonitor monitor) {
		List<Removal> done = new ArrayList<>();
		for (Map.Entry<Address, Address> e : new java.util.TreeMap<>(candidates).entrySet()) {
			Removal r = removeOne(program, e.getKey(), e.getValue(), monitor);
			if (r != null) {
				done.add(r);
				if (analyzer != null) {
					AnalyzerLog.info(analyzer, "wrong-bank artifact removed at " + r.entry() +
						": " + r.funcs() + " function, " + r.instrs() + " instruction(s) cleared, " +
						r.redecoded() + " re-decoded, retargeted from " + r.retargetedFrom() +
						" (grm-z0d7.1)");
				}
			}
		}
		return done;
	}

	private static Removal removeOne(Program program, Address entry, Address from,
			TaskMonitor monitor) {
		FunctionManager fm = program.getFunctionManager();
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		Function fn = fm.getFunctionAt(entry);
		if (fn == null || fn.isExternal() || fn.isThunk()) {
			return null;
		}
		if (refMgr.hasReferencesTo(entry) ||
			program.getSymbolTable().isExternalEntryPoint(entry)) {
			return null;
		}
		Symbol sym = fn.getSymbol();
		if (sym != null && sym.getSource() == SourceType.USER_DEFINED) {
			return null;
		}
		AddressSetView prot = AutoAnalysisManager.getAnalysisManager(program)
				.getProtectedLocations();
		if (prot != null && prot.contains(entry)) {
			return null;
		}
		Instruction head = listing.getInstructionAt(entry);
		boolean fallenInto = head != null && head.getFallFrom() != null;

		// Decide what to clear BEFORE removing anything.
		List<Instruction> clear = new ArrayList<>();
		if (head != null && !fallenInto) {
			clear = exclusiveRun(program, head);
			// Positive proof only: clear the run only if it BLOCKS a surviving decode.
			if (!blocksSurvivingDecode(program, clear)) {
				clear = new ArrayList<>();
			}
		}
		fm.removeFunction(entry);

		int redecoded = 0;
		if (!clear.isEmpty()) {
			Set<Address> starts = new TreeSet<>();
			for (Instruction i : clear) {
				starts.add(i.getMinAddress());
			}
			for (Instruction i : clear) {
				listing.clearCodeUnits(i.getMinAddress(), i.getMaxAddress(), false);
				// clearCodeUnits leaves references; drop the cleared instruction's own flow
				// references so they stop acting as flow edges out of bytes that are not code.
				for (Reference ref : refMgr.getReferencesFrom(i.getMinAddress())) {
					if (ref.getReferenceType().isFlow() && ref.getSource() != SourceType.USER_DEFINED) {
						refMgr.delete(ref);
					}
				}
			}
			AddressSet restart = new AddressSet();
			for (Address c : starts) {
				for (int k = 1; k <= MAX_INSTRUCTION_LENGTH; k++) {
					Address prev;
					try {
						prev = c.subtract(k);
					}
					catch (RuntimeException ex) {
						break;
					}
					Instruction p = listing.getInstructionContaining(prev);
					if (p == null || starts.contains(p.getMinAddress()) || !p.hasFallthrough()) {
						continue;
					}
					Address ft = p.getFallThrough();
					if (ft != null && ft.getAddressSpace().equals(entry.getAddressSpace()) &&
						listing.getInstructionContaining(ft) == null) {
						restart.add(ft);
					}
				}
			}
			if (!restart.isEmpty()) {
				DisassembleCommand cmd = new DisassembleCommand(restart, null, true);
				cmd.applyTo(program, monitor);
				AddressSetView got = cmd.getDisassembledAddressSet();
				if (got != null) {
					for (Instruction ignored : listing.getInstructions(got, true)) {
						redecoded++;
					}
				}
			}
		}

		String comment = "instrs=" + clear.size() + " funcs=1 redecoded=" + redecoded +
			" retargetedFrom=" + from;
		program.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS, CATEGORY, comment);
		return new Removal(entry, from, clear.size(), 1, redecoded);
	}

	/**
	 * True if some instruction OUTSIDE {@code run} falls through to an address that is not an
	 * instruction start and lies in [run start - 3, run end]: existing decode wants bytes the run
	 * sits on (smb3 ab64 LDA falls to undefined ab66, run starts ab67). Without such proof the run
	 * may be genuine home-bank code reached by flow this analysis cannot see, so it is kept.
	 */
	private static boolean blocksSurvivingDecode(Program program, List<Instruction> run) {
		if (run.isEmpty()) {
			return false;
		}
		Listing listing = program.getListing();
		Set<Address> in = new HashSet<>();
		Address lo = run.get(0).getMinAddress();
		Address hi = run.get(0).getMaxAddress();
		for (Instruction i : run) {
			in.add(i.getMinAddress());
			if (i.getMinAddress().compareTo(lo) < 0) {
				lo = i.getMinAddress();
			}
			if (i.getMaxAddress().compareTo(hi) > 0) {
				hi = i.getMaxAddress();
			}
		}
		Address from;
		try {
			from = lo.subtract(MAX_INSTRUCTION_LENGTH - 1);
		}
		catch (RuntimeException e) {
			from = lo;
		}
		for (Instruction i : listing.getInstructions(new AddressSet(from, hi), true)) {
			if (in.contains(i.getMinAddress()) || !i.hasFallthrough()) {
				continue;
			}
			Address f = i.getFallThrough();
			if (f != null && f.compareTo(from) >= 0 && f.compareTo(hi) <= 0 &&
				listing.getInstructionAt(f) == null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The instructions reached ONLY from {@code head}: follows fall-through and non-call flow
	 * references, admitting a successor only if no function starts there, it is not an external
	 * entry point, no instruction outside the run falls into it and every reference to it comes
	 * from inside the run. Calls are never followed (a callee is somebody else's code).
	 */
	private static List<Instruction> exclusiveRun(Program program, Instruction head) {
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		Set<Address> in = new HashSet<>();
		List<Instruction> run = new ArrayList<>();
		List<Instruction> work = new ArrayList<>();
		in.add(head.getMinAddress());
		run.add(head);
		work.add(head);
		while (!work.isEmpty()) {
			Instruction i = work.remove(work.size() - 1);
			List<Address> next = new ArrayList<>();
			if (i.hasFallthrough() && i.getFallThrough() != null) {
				next.add(i.getFallThrough());
			}
			for (Reference ref : i.getReferencesFrom()) {
				if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isCall() &&
					ref.getToAddress().isMemoryAddress()) {
					next.add(ref.getToAddress());
				}
			}
			for (Address a : next) {
				Instruction s = listing.getInstructionAt(a);
				if (s == null || in.contains(a) ||
					program.getFunctionManager().getFunctionAt(a) != null ||
					program.getSymbolTable().isExternalEntryPoint(a)) {
					continue;
				}
				Address ff = s.getFallFrom();
				if (ff != null && !in.contains(ff)) {
					continue;
				}
				boolean outside = false;
				for (Reference r : refMgr.getReferencesTo(a)) {
					if (!in.contains(r.getFromAddress())) {
						outside = true;
						break;
					}
				}
				if (outside) {
					continue;
				}
				in.add(a);
				run.add(s);
				work.add(s);
			}
		}
		return run;
	}
}
