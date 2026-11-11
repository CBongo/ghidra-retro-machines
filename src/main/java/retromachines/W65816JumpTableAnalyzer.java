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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the targets of 65816 {@code JMP (abs,X)} / {@code JSR (abs,X)} dispatches and decodes
 * each one at the M/X/E in effect at the dispatch (bead grm-9nxj.5.4).
 *
 * <p><b>The defect.</b> A computed flow gives Ghidra no target, so every handler reached only
 * through a jump table is never decoded at all -- and when something else later wanders into one,
 * it arrives with whatever width that path holds. Chrono Trigger has 35 {@code JSR (abs,X)} sites,
 * Final Fantasy III 15 plus 10 {@code JMP (abs,X)}; before this analyzer none had a target.
 *
 * <p><b>The recovery.</b> {@link W65816JumpTables#bound} decides how many entries the table has;
 * this class supplies the listing-side evidence: an {@code AND #mask} scaled into X caps the index,
 * a table cannot overlap code, data or another dispatch's table, and a target must be ROM that is
 * neither mid-instruction nor data and whose first few instructions, decoded at the dispatch's
 * width, contain no desync opcode. The table is then defined as a word array (so nothing later
 * decodes it as code), each target gets a computed flow reference, and every target not yet
 * decoded has the dispatch's E/M/X stamped and is disassembled -- the ArmAnalyzer pattern: stamp
 * the mode a flow arrives in, let disassembly consume it. {@code JSR} targets become functions.
 *
 * <p>A target already decoded at another width whose decode depends on it (W65816WidthEffects)
 * gets a warning bookmark rather than a repair: one address holds one decode.
 *
 * <p>Emulation-mode dispatches are declined: on the real-ROM rows every one measured was operand
 * bytes decoded at the wrong width, not a dispatch.
 */
public class W65816JumpTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 Jump Tables";
	private static final String DESCRIPTION =
		"Recovers JMP (abs,X) / JSR (abs,X) jump-table targets and decodes each at the M/X width " +
			"in effect at the dispatch (grm-9nxj.5.4).";

	/** Instructions decoded ahead from a candidate target before it is accepted. */
	private static final int LOOKAHEAD = 16;
	private static final Set<String> DESYNC = Set.of("BRK", "COP", "WDM", "STP");
	/** Mnemonics that change the width unknowably, after which the lookahead means nothing. */
	private static final Set<String> WIDTH_CHANGE = Set.of("PLP", "XCE");

	private static final String COMMENT_PREFIX = "65816 jump table ";

	/** Dispatch sites already handled, per program: each is resolved at most once. */
	private static final Map<Program, Set<Address>> DONE =
		Collections.synchronizedMap(new WeakHashMap<>());
	/** Tables this analyzer defined, per program, with the dispatches that read each. */
	private static final Map<Program, Map<Address, Set<Address>>> TABLES =
		Collections.synchronizedMap(new WeakHashMap<>());
	/**
	 * grm-gipk.16.8: code-derived table starts whose table was laid one entry away, per program,
	 * mapped to where it was laid. Later dispatches through the same code start reuse it, and the
	 * overread repair does not cut such a table at its own code start.
	 */
	private static final Map<Program, Map<Address, Address>> ADOPTED =
		Collections.synchronizedMap(new WeakHashMap<>());

	/** grm-hf5h.3: the jump site of each switch override written, to the entry of its owner. */
	private static final Map<Program, Map<Address, Address>> OVERRIDES =
		Collections.synchronizedMap(new WeakHashMap<>());

	public W65816JumpTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Beside the call-width analyzer: after disassembly, before functions settle.
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return W65816WidthEffects.applies(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		W65816WidthEffects effects = new W65816WidthEffects(program);
		Listing listing = program.getListing();
		Set<Address> done =
			DONE.computeIfAbsent(program, p -> Collections.synchronizedSet(new LinkedHashSet<>()));
		Map<Address, Set<Address>> tables = TABLES.computeIfAbsent(program,
			p -> Collections.synchronizedMap(new LinkedHashMap<>()));
		Map<Address, Address> adopted = ADOPTED.computeIfAbsent(program,
			p -> Collections.synchronizedMap(new LinkedHashMap<>()));
		// Every dispatch's table start, program-wide: one table ends where another begins.
		Set<Address> tableStarts = new LinkedHashSet<>();
		// grm-gipk.16.11: the dispatch instructions (site and index load) reading each start.
		Map<Address, Set<Address>> readers = new LinkedHashMap<>();
		for (Instruction in : listing.getInstructions(true)) {
			Dispatch d = in.getFlowType().isComputed() ? dispatchOf(listing, in) : null;
			if (d != null) {
				tableStarts.add(d.table());
				Set<Address> r = readers.computeIfAbsent(d.table(), t -> new LinkedHashSet<>());
				r.add(in.getMinAddress());
				if (d.index() != null) {
					r.add(d.index().getMinAddress());
				}
			}
		}
		repairOverreads(program, tables, tableStarts, adopted, monitor);

		List<Instruction> sites = new ArrayList<>();
		for (Instruction in : listing.getInstructions(set, true)) {
			if (dispatchOf(listing, in) != null && !done.contains(in.getMinAddress())) {
				sites.add(in);
			}
		}
		if (sites.isEmpty()) {
			return true;
		}

		int resolved = 0;
		int decoded = 0;
		int warned = 0;
		for (Instruction site : sites) {
			monitor.checkCancelled();
			Address siteAddr = site.getMinAddress();
			done.add(siteAddr);
			site = listing.getInstructionAt(siteAddr);   // an earlier site may have re-decoded it
			Dispatch dispatch = site == null ? null : dispatchOf(listing, site);
			if (dispatch == null || effects.emulation(site) || hasFlowTargets(site)) {
				continue;
			}
			Address table = dispatch.table();
			long targetBank = dispatch.targetBank();
			Map<Register, Integer> ctx = context(program, site);
			int cap = indexCap(listing, dispatch.index());
			List<Long> targets = new ArrayList<>();
			// Several dispatches often share one table (CT $C1:B80D has four): the first defines
			// it, the rest reuse its extent rather than finding its bytes taken.
			// Where the table was laid: its code-derived start, or one entry away (grm-gipk.16.8).
			Address laid = adopted.getOrDefault(table, table);
			int n = sharedTableEntries(program, laid, targetBank, cap, targets);
			boolean shared = n > 0;
			if (!shared) {
				Set<Address> own = new LinkedHashSet<>();
				own.add(siteAddr);
				if (dispatch.index() != null) {
					own.add(dispatch.index().getMinAddress());
				}
				// grm-gipk.16.11: another dispatch's reference to an entry-aligned overlapping
				// start is the same table seen from one entry over, not an outside reference.
				for (Map.Entry<Address, Set<Address>> rd : readers.entrySet()) {
					if (alignedOverlap(table, rd.getKey())) {
						own.addAll(rd.getValue());
					}
				}
				TableScorer.Result<Long, W65816JumpTables.End> r =
					walkTable(program, table, targetBank, cap, ctx, tableStarts, own);
				targets.addAll(r.targets());
				n = r.count();
				if (r.endedBy() == W65816JumpTables.End.ENTRY_REFERENCED) {
					AnalyzerLog.info(this, "dispatch " + siteAddr + ": table " + table + " ended at " +
						"entry " + n + " by ENTRY_REFERENCED " + EntryReferences.find(program,
							table.add(2L * n), extentOf(table, cap), own).describe());
				}
				// grm-gipk.16.6: would the bytes read better one entry either side of the
				// code-derived start? Adopted where the code reads nothing (grm-gipk.16.8), else
				// logged only.
				List<TableScorer.Candidate<Integer>> starts = new ArrayList<>();
				starts.add(new TableScorer.Candidate<>(0, 1.0));
				starts.add(new TableScorer.Candidate<>(1, ALT_PRIOR));
				if ((table.getOffset() & 0xffff) >= 2) {
					starts.add(new TableScorer.Candidate<>(-1, ALT_PRIOR));
				}
				// The code's own start is not another table's start for the shifted readings.
				Set<Address> others = new LinkedHashSet<>(tableStarts);
				others.remove(table);
				List<TableScorer.Ranked<Integer, Long, W65816JumpTables.End>> ranked =
					TableScorer.rank(starts, k -> k == 0 ? r
						: walkTable(program, table.add(2L * k), targetBank, cap, ctx, others, own));
				String why = TableScorer.disagreement(ranked, 0);
				var adopt = TableScorer.adoption(ranked, 0, MIN_ADOPTED_ENTRIES);
				if (adopt != null) {
					laid = table.add(2L * adopt.key());
					targets.clear();
					targets.addAll(adopt.result().targets());
					n = adopt.result().count();
					adopted.put(table, laid);
					AnalyzerLog.info(this, "dispatch " + siteAddr + ": table " + table +
						" start adopted at " + laid + " (entry offset " + adopt.key() + "): " + why);
				}
				else if (why != null) {
					AnalyzerLog.info(this, "dispatch " + siteAddr + ": table " + table +
						" start check (entry offset): " + why);
				}
			}
			if (n == 0) {
				AnalyzerLog.info(this, "dispatch " + siteAddr + ": no plausible entry at " + table);
				continue;
			}
			if (W65816JumpTables.unusedCount(targets) > 0) {
				AnalyzerLog.info(this, "dispatch " + siteAddr + ": table " + laid + ": " + n +
					" entries" + placeholders(targets));
			}
			boolean call = site.getFlowType().isCall();
			// grm-iv4i: one DATA reference per entry into bank:word, as on the NES side.
			if (!shared) {
				for (Address s : tableStarts) {
					if (alignedOverlap(laid, s)) {
						JumpTableArrays.unlay(program, s);   // laid from the overlapping start
					}
				}
			}
			if (!shared && !JumpTableArrays.layWords(program, laid, entryTargets(laid, targets))) {
				AnalyzerLog.info(this, "dispatch " + siteAddr + ": could not define table at " +
					laid);
				continue;
			}
			referTable(program, dispatch.index(), laid);
			RefType type = call ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP;
			Set<Address> unique = new LinkedHashSet<>();
			for (long t : targets) {
				if (t != W65816JumpTables.UNUSED_ENTRY) {
					unique.add(table.getNewAddress(t));
				}
			}
			for (Address t : unique) {
				program.getReferenceManager().addMemoryReference(siteAddr, t, type,
					SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			}
			for (Address t : unique) {
				monitor.checkCancelled();
				Instruction existing = listing.getInstructionAt(t);
				if (existing != null) {
					warned += warnIfOtherWidth(program, effects, site, existing) ? 1 : 0;
				}
				else if (stampAndDisassemble(this, program, t, ctx, monitor)) {
					decoded++;
				}
				if (call && program.getFunctionManager().getFunctionAt(t) == null &&
					listing.getInstructionAt(t) != null) {
					new CreateFunctionCmd(t).applyTo(program, monitor);
				}
			}
			tables.computeIfAbsent(laid, t -> new LinkedHashSet<>()).add(siteAddr);
			AnalyzerCommentRecord.replaceOwn(program, siteAddr, CommentType.EOL,
				note(laid, n, unique.size(), ctx, cap) + placeholders(targets), COMMENT_PREFIX);
			// grm-hf5h.3: the switch override, now if a function already holds the jump, else the
			// relocator writes it when one is created (see writeOverrideFor).
			if (!call) {
				Function owner = program.getFunctionManager().getFunctionContaining(siteAddr);
				if (owner != null) {
					writeOverrideFor(this, program, owner, site, log);
				}
			}
			resolved++;
		}
		if (resolved > 0) {
			AnalyzerLog.info(this, "resolved " + resolved + " jump table(s); decoded " + decoded +
				" new target(s); " + warned + " target(s) already decoded at another width");
		}
		return true;
	}

	/**
	 * grm-hf5h.3: the destinations of a 65816 dispatch's switch override: the {@code ANALYSIS}
	 * computed-jump references this analyzer laid on {@code jmp}, in the space the references
	 * point to (the bank or overlay the entries were decoded in).
	 */
	private static List<Address> overrideDests(Instruction jmp) {
		Set<Address> dests = new LinkedHashSet<>();
		for (Reference ref : jmp.getReferencesFrom()) {
			if (RefType.COMPUTED_JUMP.equals(ref.getReferenceType()) &&
				ref.getSource() == SourceType.ANALYSIS) {
				dests.add(ref.getToAddress());
			}
		}
		return new ArrayList<>(dests);
	}

	/**
	 * grm-hf5h.3: writes the {@link ghidra.program.model.pcode.JumpTable} override for the
	 * {@code JMP (abs,X)} / {@code JML [abs]} dispatch {@code jmp} on {@code function}, with the
	 * entries this analyzer referenced as its destinations, when it has none yet. Without it the
	 * decompiler cannot model the 65816 dispatch and prints "Could not recover jumptable".
	 * Calls ({@code JSR (abs,X)}) are skipped: they decompile as CALLIND, which a switch override
	 * does not apply to. The RTS/RTL tricks have no indirect branch to override either.
	 *
	 * @return whether an override was written
	 */
	static boolean writeOverrideFor(Analyzer analyzer, Program program, Function function,
			Instruction jmp, MessageLog log) {
		if (jmp.getFlowType().isCall() || !jmp.getFlowType().isComputed() ||
			!jmp.getFlowType().isJump()) {
			return false;
		}
		Address at = jmp.getMinAddress();
		if (JumpTableBoundAnalyzer.alreadyOverridden(program, function, at)) {
			return false;
		}
		List<Address> dests = overrideDests(jmp);
		// A destination with no instruction (the analyzer could not decode it) makes the
		// decompiler process die on the override (w_ff3, six functions); leave those to the
		// "treat as call" fallback.
		for (Address d : dests) {
			if (program.getListing().getInstructionAt(d) == null) {
				AnalyzerLog.info(analyzer, "no switch override at " + at + ": destination " + d +
					" is not decoded");
				return false;
			}
		}
		boolean wrote = TwoLevelPointerDispatchAnalyzer.writeOverride(analyzer, program, function,
			at, dests, log);
		if (wrote) {
			OVERRIDES.computeIfAbsent(program,
				p -> Collections.synchronizedMap(new LinkedHashMap<>())).put(at,
					function.getEntryPoint());
			growBodyToHandlers(program, function);
		}
		return wrote;
	}

	/**
	 * grm-hf5h.5: the switch's handlers belong to the dispatcher, as on 6502. The references were
	 * laid after the body was computed, so recompute the flow body and ADD to the owner what no
	 * other function holds. Stock {@code fixupFunctionBody} is not used: its overlap handling
	 * carves address ranges out of other functions (w_fzero lost FUN_008acd and FUN_00d0aa that
	 * way, their code left in no function). A handler that is inside, or the entry of, another
	 * function stays that function's.
	 */
	private static void growBodyToHandlers(Program program, Function function) {
		AddressSet grown = new AddressSet(function.getBody());
		AddressSet flow = new AddressSet(CreateFunctionCmd.getFunctionBody(program,
			function.getEntryPoint(), false, TaskMonitor.DUMMY));
		Iterator<Function> others = program.getFunctionManager().getFunctionsOverlapping(flow);
		while (others.hasNext()) {
			Function other = others.next();
			if (!other.equals(function)) {
				flow.delete(other.getBody());
			}
		}
		grown.add(flow);
		if (grown.equals(function.getBody())) {
			return;
		}
		try {
			function.setBody(grown);
		}
		catch (OverlappingFunctionException e) {
			// leave the body as it is
		}
	}

	/**
	 * grm-hf5h.3: the deferred half, called by {@link JumpTableOverrideRelocatorAnalyzer} for each
	 * computed jump in a newly created function: writes the override when {@code jmp} is a
	 * dispatch this analyzer resolved (a 65816 table shape, with its references) and has none.
	 */
	static boolean writeDeferredOverride(Analyzer analyzer, Program program, Function function,
			Instruction jmp, MessageLog log) {
		if (!W65816WidthEffects.applies(program) ||
			dispatchOf(program.getListing(), jmp) == null) {
			return false;
		}
		return writeOverrideFor(analyzer, program, function, jmp, log);
	}

	/**
	 * grm-hf5h.3: after {@link #repairOverreads} changed a table's references, an override written
	 * from the old ones is stale: removes it and writes one from the references that remain.
	 */
	private void refreshOverride(Program program, Instruction site, Address at) {
		Function owner = program.getFunctionManager().getFunctionContaining(at);
		if (owner == null || !clearOverride(program, owner, at)) {
			return;
		}
		if (site != null) {
			writeOverrideFor(this, program, owner, site, new MessageLog());
		}
	}

	/** Removes {@code owner}'s override namespace for the jump at {@code at}; whether there was one. */
	private static boolean clearOverride(Program program, Function owner, Address at) {
		Namespace overrideSpace = HighFunction.findOverrideSpace(owner);
		if (overrideSpace == null) {
			return false;
		}
		SymbolTable symtab = program.getSymbolTable();
		Namespace jmpSpace = HighFunction.findNamespace(symtab, overrideSpace, "jmp_" + at);
		if (jmpSpace == null) {
			return false;
		}
		Symbol jmpSym = symtab.getNamespaceSymbol(jmpSpace.getName(), overrideSpace);
		try {
			HighFunction.clearNamespace(symtab, jmpSpace);
		}
		catch (InvalidInputException e) {
			return false;
		}
		if (jmpSym != null) {
			jmpSym.delete();
		}
		return true;
	}

	/**
	 * grm-hf5h.3: an override is only valid while its owner function still contains the jump. A
	 * later pass can shrink the function (w_ff3 FUN_c31ff4, cut after a non-returning JSR) or clear
	 * the bytes of a dispatch that turned out to be data; the decompiler process then dies on the
	 * override. At the end of analysis, drops every override this analyzer wrote whose owner no
	 * longer contains a decoded jump at its site.
	 */
	@Override
	public void analysisEnded(Program program) {
		Map<Address, Address> written = OVERRIDES.get(program);
		if (written == null || written.isEmpty()) {
			return;
		}
		int dropped = 0;
		int tx = program.startTransaction("Drop stranded 65816 jump table overrides");
		try {
			for (Map.Entry<Address, Address> e : new ArrayList<>(written.entrySet())) {
				Address site = e.getKey();
				Function owner = program.getFunctionManager().getFunctionAt(e.getValue());
				if (owner == null) {
					written.remove(site);
					continue;
				}
				if (!owner.getBody().contains(site) ||
					program.getListing().getInstructionAt(site) == null) {
					if (clearOverride(program, owner, site)) {
						dropped++;
					}
					written.remove(site);
				}
			}
			// grm-hf5h.5: function creation and body fixups that ran after an override was
			// written carve addresses out of the grown owner (w_fzero FUN_0088d8: 1299 -> 1105
			// addresses, its flow still reaching the handlers), so grow each survivor once more.
			Set<Address> grownOwners = new LinkedHashSet<>(written.values());
			for (Address entry : grownOwners) {
				Function owner = program.getFunctionManager().getFunctionAt(entry);
				if (owner != null) {
					growBodyToHandlers(program, owner);
				}
			}
		}
		finally {
			program.endTransaction(tx, true);
		}
		if (dropped > 0) {
			AnalyzerLog.info(this, "dropped " + dropped +
				" stranded switch override(s): owner no longer contains the jump");
		}
	}

	/**
	 * grm-9nxj.25: a READ reference from the instruction that reads the table -- the {@code JMP/JSR
	 * (abs,X)} itself, or a pointer dispatch's {@code LDA tbl,X} -- to where the table was laid, so
	 * the table's XREFs name its dispatcher (before, only the targets were referenced). Not added
	 * twice (a stock operand reference to the same address counts). Primary only when the operand
	 * names that address: a table laid one entry in (a {@code BEQ}-guarded index, an adopted start)
	 * keeps the operand showing its own value. {@link #unreferTable} undoes it.
	 */
	static void referTable(Program program, Instruction reader, Address laid) {
		ReferenceManager refs = program.getReferenceManager();
		for (Reference r : refs.getReferencesFrom(reader.getMinAddress())) {
			if (r.getToAddress().equals(laid) && !r.getReferenceType().isFlow()) {
				return;
			}
		}
		Reference ref = refs.addMemoryReference(reader.getMinAddress(), laid, RefType.READ,
			SourceType.ANALYSIS, 0);
		if (ref.isPrimary() && (operandValue(reader) & 0xffff) != (laid.getOffset() & 0xffff)) {
			refs.setPrimary(ref, false);
		}
	}

	/** Removes {@link #referTable}'s reference from {@code reader} to a withdrawn table. */
	static void unreferTable(Program program, Address reader, Address table) {
		ReferenceManager refs = program.getReferenceManager();
		for (Reference r : refs.getReferencesFrom(reader)) {
			if (r.getToAddress().equals(table) && RefType.READ.equals(r.getReferenceType()) &&
				r.getSource() == SourceType.ANALYSIS) {
				refs.delete(r);
			}
		}
	}

	private static String note(Address table, int n, int targets, Map<Register, Integer> ctx,
			int cap) {
		return COMMENT_PREFIX + table + ": " + n + " entr" + (n == 1 ? "y" : "ies") + ", " +
			targets + " target(s) decoded at " + describe(ctx) +
			(cap < W65816JumpTables.MAX_ENTRIES ? " (index reaches " + cap + ")" : "");
	}

	/**
	 * A table is bounded with the code known when it was found; analysis may later decode real
	 * code that runs into its tail (FF3 {@code $C2:4710} took a 17th entry whose bytes are the
	 * {@code PHX / PHY} at the start of a routine reached afterwards; its three sibling tables
	 * have 16). The disassembler then stops at the table with an error bookmark. Each such
	 * conflict shrinks the table to end before it: the lost entries' flow references go, and the
	 * code is decoded there after all. A conflict at the first entry removes the table.
	 *
	 * <p>Likewise a dispatch decoded later may read a table that starts inside an earlier one
	 * (FF2 {@code $03:BF43}'s table {@code $03:C11C} lies inside {@code $03:BCF5}'s, bounded at
	 * {@code $03:C104} before the second dispatch was reached): the earlier table is cut where the
	 * later one begins, so the later one finds its bytes free (grm-9nxj.5.8).
	 */
	private void repairOverreads(Program program, Map<Address, Set<Address>> tables,
			Set<Address> tableStarts, Map<Address, Address> adopted, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		var bookmarks = program.getBookmarkManager();
		for (Map.Entry<Address, Set<Address>> t : new ArrayList<>(tables.entrySet())) {
			monitor.checkCancelled();
			Address table = t.getKey();
			Data d = listing.getDataAt(table);
			if (d == null || !(d.getDataType() instanceof Array a)) {
				continue;
			}
			int n = a.getNumElements();
			Address end = table.add(2L * n - 1);
			int keep = n;
			long targetBank = table.getOffset() & 0xff0000L;
			for (Address site : t.getValue()) {
				Instruction in = listing.getInstructionAt(site);
				Dispatch dp = in == null ? null : dispatchOf(listing, in);
				if (dp != null) {
					targetBank = dp.targetBank();
					break;
				}
			}
			List<Address> conflicts = new ArrayList<>();
			var it = bookmarks.getBookmarksIterator(table, true);
			while (it.hasNext()) {
				var b = it.next();
				if (b.getAddress().compareTo(end) > 0) {
					break;
				}
				if (b.getTypeString().equals(BookmarkType.ERROR) &&
					b.getComment().contains("conflicting data")) {
					keep = Math.min(keep, (int) (b.getAddress().subtract(table) / 2));
					conflicts.add(b.getAddress());
					bookmarks.removeBookmark(b);
				}
			}
			Address cutAt = null;
			for (Address other : tableStarts) {
				if (table.equals(adopted.get(other))) {
					continue;   // its own code-derived start, one entry in (grm-gipk.16.8)
				}
				if (alignedOverlap(table, other)) {
					continue;   // the same table read from one entry over (grm-gipk.16.11)
				}
				if (other.compareTo(table) > 0 && other.compareTo(end) <= 0) {
					int k = (int) (other.subtract(table) / 2);
					if (k < keep) {
						keep = k;
						cutAt = other;
					}
				}
			}
			if (keep == n) {
				continue;
			}
			// Read the kept entries while the array's references still say which are placeholders.
			List<Long> entries = new ArrayList<>();
			for (int i = 0; i < keep; i++) {
				Long e = laidEntry(program, table, i, targetBank);
				if (e == null) {
					break;
				}
				entries.add(e);
			}
			// The cut entries' data references go with the array, so they cannot keep stale
			// targets looking referenced.
			if (!JumpTableArrays.unlay(program, table)) {
				listing.clearCodeUnits(table, end, false);
			}
			Set<Address> kept = new LinkedHashSet<>();
			if (keep > 0) {
				int real = entries.size();
				while (real > 0 && entries.get(real - 1) == W65816JumpTables.UNUSED_ENTRY) {
					real--;   // a trailing placeholder is not part of the table
				}
				boolean complete = entries.size() == keep;
				entries = new ArrayList<>(entries.subList(0, real));
				List<Address> entryTargets = entryTargets(table, entries);
				for (Address et : entryTargets) {
					if (et != null) {
						kept.add(et);
					}
				}
				if (!complete ||
					!JumpTableArrays.layWords(program, table, entryTargets)) {
					AnalyzerLog.info(this, "could not shrink table " + table);
				}
			}
			else {
				tables.remove(table);
			}
			for (Address site : t.getValue()) {
				for (Reference r : program.getReferenceManager().getReferencesFrom(site)) {
					if (r.getReferenceType().isFlow() && r.getReferenceType().isComputed() &&
						!kept.contains(r.getToAddress())) {
						program.getReferenceManager().delete(r);
					}
				}
				Instruction in = listing.getInstructionAt(site);
				refreshOverride(program, in, site);
				if (keep == 0) {
					Dispatch dp = in == null ? null : dispatchOf(listing, in);
					unreferTable(program, dp == null ? site : dp.index().getMinAddress(), table);
					AnalyzerCommentRecord.replaceOwn(program, site, CommentType.EOL,
						COMMENT_PREFIX + table + ": withdrawn, code later decoded at its first " +
							"entry", COMMENT_PREFIX);
				}
				else if (in != null) {
					Dispatch dp = dispatchOf(listing, in);
					AnalyzerCommentRecord.replaceOwn(program, site, CommentType.EOL,
						note(table, keep, kept.size(), context(program, in),
							indexCap(listing, dp == null ? in : dp.index())) +
							(cutAt != null ? "; shortened, another table starts at " + cutAt
									: "; shortened, code later decoded past it"), COMMENT_PREFIX);
				}
			}
			for (Address c : conflicts) {
				new DisassembleCommand(c, null, true).applyTo(program, monitor);
			}
			AnalyzerLog.info(this, "table " + table + " shortened from " + n + " to " + keep +
				" entries: " + (cutAt != null ? "another table starts at " + cutAt
						: "code later decoded at " + conflicts));
		}
	}

	/**
	 * A computed dispatch through a word table.
	 *
	 * @param table the table's first byte
	 * @param targetBank the bank its 16-bit entries jump into (bits 16-23 only)
	 * @param index the instruction whose X indexes the table -- where the index bound is read
	 */
	record Dispatch(Address table, long targetBank, Instruction index) {}

	/**
	 * grm-gipk.16.6: the prior of a start or bias the bytes propose against the code-derived one,
	 * which has prior 1. An alternative must read four times as many entries to outrank the code.
	 */
	static final double ALT_PRIOR = 0.25;

	/**
	 * grm-gipk.16.8: the fewest entries an alternative start must keep to be adopted over a code
	 * reading that keeps none. One or two plausible words are chance; the 41-ROM sweep's adopted
	 * tables keep 3-12.
	 */
	static final int MIN_ADOPTED_ENTRIES = 3;

	/** The bytes a table at {@code table} could occupy, for grm-gipk.16.7's own-reference test. */
	static List<EntryReferences.Extent> extentOf(Address table, int cap) {
		return List.of(new EntryReferences.Extent(table, 2L * cap));
	}

	/** One JMP/JSR (abs,X) table read from {@code table} (grm-gipk.16.6 walks alternatives too). */
	private static TableScorer.Result<Long, W65816JumpTables.End> walkTable(Program program,
			Address table, long targetBank, int cap, Map<Register, Integer> ctx,
			Set<Address> tableStarts, Set<Address> own) {
		// grm-gipk.16.7: references at an entry position that are not the table's own.
		List<EntryReferences.Extent> extent = extentOf(table, cap);
		return W65816JumpTables.trimUnused(W65816JumpTables.score(table.getOffset(), targetBank, cap,
			false, true,
			i -> word(program.getMemory(), table.add(2L * i)),
			b -> tableByteFree(program, table.getNewAddress(b), table, tableStarts),
			t -> plausibleTarget(program, table.getNewAddress(t), ctx),
			i -> EntryReferences.find(program, table.add(2L * i), extent, own)));
	}

	/**
	 * The word table {@code in} dispatches through, either shape; else null. A table whose index
	 * cannot be zero starts at its second entry ({@link #indexNonZero}).
	 */
	static Dispatch dispatchOf(Listing listing, Instruction in) {
		Address t = tableOf(in);
		Dispatch d = t != null ? new Dispatch(t, t.getOffset() & 0xff0000L, in)
				: pointerDispatch(listing, in);
		if (d != null && indexNonZero(listing, d.index())) {
			d = new Dispatch(d.table().add(2), d.targetBank(), d.index());
		}
		return d;
	}

	/** Mnemonics whose result sets Z from the accumulator. */
	private static final Set<String> SETS_Z_FROM_A = Set.of("LDA", "AND", "ORA", "EOR", "ADC",
		"SBC", "ASL", "LSR", "ROL", "ROR", "PLA", "TXA", "TYA", "TDC", "INC", "DEC");

	/**
	 * Whether the index X holds at {@code use} is known nonzero: {@code TAX} reached only by
	 * falling past a {@code BEQ} that tests the accumulator, so entry 0 is never read (FF3
	 * {@code $C2:47F8}: {@code LDA $3A6E / BEQ skip / TAX / JMP ($48F5,X)} -- entry 0's bytes are
	 * code, and the real table starts at {@code $48F7}).
	 */
	static boolean indexNonZero(Listing listing, Instruction use) {
		Instruction tax = fallsFrom(listing, use);
		if (tax == null || !tax.getMnemonicString().equalsIgnoreCase("TAX") || hasFlowInto(tax)) {
			return false;
		}
		Instruction beq = fallsFrom(listing, tax);
		if (beq == null || !beq.getMnemonicString().equalsIgnoreCase("BEQ")) {
			return false;
		}
		Instruction test = fallsFrom(listing, beq);
		if (test == null || hasFlowInto(beq)) {
			return false;
		}
		String mn = test.getMnemonicString().toUpperCase(Locale.ROOT);
		String op = test.getNumOperands() > 0 ? test.getDefaultOperandRepresentation(0) : "";
		boolean onA = !(mn.equals("ASL") || mn.equals("LSR") || mn.equals("ROL") ||
			mn.equals("ROR") || mn.equals("INC") || mn.equals("DEC")) || op.isEmpty() ||
			op.equals("A");
		return SETS_Z_FROM_A.contains(mn) && onA;
	}

	/** The instruction falling straight into {@code in}, or null. */
	private static Instruction fallsFrom(Listing listing, Instruction in) {
		Instruction p = listing.getInstructionBefore(in.getMinAddress());
		return p != null && in.getMinAddress().equals(p.getFallThrough()) ? p : null;
	}

	/** Bound on the instructions searched back from a pointer jump for the stores that built it. */
	private static final int POINTER_LOOKBACK = 12;

	/**
	 * A pointer-variable dispatch (grm-9nxj.5.8): {@code JMP (ptr)} or {@code JML [ptr]} whose
	 * pointer the straight-line code just before it assembled from a word table indexed by X.
	 * The shapes on the snes-analysis rows:
	 * <ul>
	 * <li>16-bit: {@code LDA tbl,X / STA ptr / ... / JMP (ptr)} (FF3 {@code $C0:77FE});</li>
	 * <li>byte pairs: {@code LDA tbl,X / STA ptr / LDA tbl+1,X / STA ptr+1 / JMP (ptr)} (FF2
	 * {@code $00:E0D0});</li>
	 * <li>long: the byte pairs plus {@code LDA #bank / STA ptr+2 / JML [ptr]} (FF2 {@code
	 * $03:869C}).</li>
	 * </ul>
	 * {@code JMP (abs)} reads its pointer from bank 0 and jumps within the program bank; a
	 * direct-page store matches DP + dp exactly where DP is stamped there, and otherwise by its
	 * low byte (FF2 stores {@code $3D} and jumps through {@code ($063D)}). An abs table is taken to be in the program bank.
	 * Anything else -- another write to a pointer byte, a source that is not an X-indexed load
	 * (or an immediate, for the bank byte), X changing between the loads -- is not matched.
	 */
	static Dispatch pointerDispatch(Listing listing, Instruction in) {
		FlowType ft = in.getFlowType();
		if (!ft.isComputed() || ft.isCall() || in.getNumOperands() != 1) {
			return null;
		}
		String mn = in.getMnemonicString().toUpperCase(Locale.ROOT);
		String op = in.getDefaultOperandRepresentation(0);
		int bytes;
		if (mn.equals("JMP") && op.startsWith("(") && !op.contains(",")) {
			bytes = 2;
		}
		else if (mn.equals("JML") && op.startsWith("[")) {
			bytes = 3;
		}
		else {
			return null;
		}
		long ptr = operandValue(in);
		if (ptr < 0) {
			return null;
		}
		ptr &= 0xffff;
		Register mReg = in.getProgram().getRegister("ctx_MF");
		// Walking back: the latest store to each pointer byte, and the chain walked.
		Instruction[] store = new Instruction[bytes];
		List<Instruction> chain = new ArrayList<>();
		Instruction cur = in;
		int found = 0;
		for (int i = 0; i < POINTER_LOOKBACK && found < bytes; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough()) ||
				(!Objects.equals(cur, in) && hasFlowInto(cur))) {
				break;
			}
			cur = prev;
			chain.add(0, cur);
			String m = cur.getMnemonicString().toUpperCase(Locale.ROOT);
			if (!m.startsWith("ST") || m.equals("STP")) {
				continue;
			}
			int k = pointerByte(cur, ptr, bytes);
			if (k < 0) {
				continue;
			}
			if (!m.equals("STA")) {
				return null;   // STX/STY/STZ into the pointer: not a table load
			}
			BigInteger mv = cur.getValue(mReg, false);
			int width = mv != null && mv.intValue() == 0 ? 2 : 1;
			for (int b = k; b < k + width && b < bytes; b++) {
				if (store[b] == null) {
					store[b] = cur;
					found++;
				}
			}
		}
		if (found < bytes) {
			return null;
		}
		// Each store's source is the load just before it.
		Instruction lo = loadBefore(listing, store[0]);
		if (lo == null || !isIndexedX(lo)) {
			return null;
		}
		Address table = loadAddress(in, lo);
		if (table == null) {
			return null;
		}
		List<Instruction> loads = new ArrayList<>(List.of(lo));
		if (!Objects.equals(store[1], store[0])) {
			Instruction hi = loadBefore(listing, store[1]);
			Address hiTable = hi == null || !isIndexedX(hi) ? null : loadAddress(in, hi);
			if (hiTable == null || !hiTable.equals(table.add(1))) {
				return null;
			}
			loads.add(hi);
		}
		long targetBank = in.getMinAddress().getOffset() & 0xff0000L;
		if (bytes == 3) {
			Instruction bank = loadBefore(listing, store[2]);
			if (bank == null || Objects.equals(store[2], store[1]) ||
				!bank.getDefaultOperandRepresentation(0).startsWith("#")) {
				return null;
			}
			targetBank = (operandValue(bank) & 0xff) << 16;
		}
		// X must hold the same index for every load.
		int first = chain.indexOf(loads.get(0));
		int last = chain.indexOf(loads.get(loads.size() - 1));
		for (int i = Math.min(first, last) + 1; i < Math.max(first, last); i++) {
			if (writesX(chain.get(i))) {
				return null;
			}
		}
		return new Dispatch(table, targetBank, lo);
	}

	/**
	 * Which pointer byte (0..bytes-1) a plain dp/abs store writes first, or -1. A direct-page
	 * store is matched exactly, DP + dp == ptr, where {@link W65816DirectPageAnalyzer} has
	 * stamped DP at it (grm-9nxj.26). Where it has not -- including the usual first pass, since
	 * this analyzer runs before that one and resolves each dispatch once -- it falls back to
	 * matching the LOW BYTE only.
	 */
	private static int pointerByte(Instruction st, long ptr, int bytes) {
		String op = st.getDefaultOperandRepresentation(0);
		if (op.contains(",") || op.contains("(") || op.contains("[")) {
			return -1;
		}
		long v = operandValue(st);
		if (v < 0) {
			return -1;
		}
		long k;
		if (op.startsWith("<")) {
			Register dpReg = st.getProgram().getRegister("DP");
			BigInteger dp = dpReg == null ? null : st.getValue(dpReg, false);
			k = dp != null ? ((dp.longValue() + (v & 0xff)) & 0xffff) - ptr
				: (v & 0xff) - (ptr & 0xff);
		}
		else {
			k = (v & 0xffff) - ptr;
		}
		return k >= 0 && k < bytes ? (int) k : -1;
	}

	/** The LDA that falls straight into {@code st}, or null. */
	private static Instruction loadBefore(Listing listing, Instruction st) {
		Instruction p = listing.getInstructionBefore(st.getMinAddress());
		return p != null && st.getMinAddress().equals(p.getFallThrough()) &&
			p.getMnemonicString().equalsIgnoreCase("LDA") ? p : null;
	}

	private static boolean isIndexedX(Instruction ld) {
		String op = ld.getDefaultOperandRepresentation(0);
		return op.endsWith(",X") && !op.startsWith("<") && !op.contains("(") && !op.contains("[");
	}

	/** An abs,X or long,X load's table address; abs is taken in the dispatch's program bank. */
	private static Address loadAddress(Instruction dispatch, Instruction ld) {
		long v = operandValue(ld);
		if (v < 0) {
			return null;
		}
		boolean isLong = ld.getDefaultOperandRepresentation(0).startsWith("!>");
		long full = isLong ? v & 0xffffff
				: (dispatch.getMinAddress().getOffset() & 0xff0000L) | (v & 0xffff);
		return dispatch.getMinAddress().getNewAddress(full);
	}

	private static boolean writesX(Instruction in) {
		return Set.of("LDX", "TAX", "INX", "DEX", "PLX", "TYX", "TSX")
				.contains(in.getMnemonicString().toUpperCase(Locale.ROOT));
	}

	private static long operandValue(Instruction in) {
		for (Object o : in.getOpObjects(0)) {
			if (o instanceof Scalar s) {
				return s.getUnsignedValue();
			}
			if (o instanceof Address a) {
				return a.getOffset();
			}
		}
		return -1;
	}

	/** The table a native {@code JMP/JSR (abs,X)} reads, in the program bank; else null. */
	static Address tableOf(Instruction in) {
		FlowType ft = in.getFlowType();
		if (!ft.isComputed() || ft.isTerminal() || in.getNumOperands() != 1) {
			return null;
		}
		String mn = in.getMnemonicString().toUpperCase(Locale.ROOT);
		if (!mn.equals("JMP") && !mn.equals("JSR")) {
			return null;
		}
		String op = in.getDefaultOperandRepresentation(0);
		if (!op.startsWith("(") || !op.endsWith(",X)")) {
			return null;
		}
		for (Object o : in.getOpObjects(0)) {
			if (o instanceof Scalar s) {
				return in.getMinAddress().getNewAddress(
					(in.getMinAddress().getOffset() & 0xff0000L) | (s.getUnsignedValue() & 0xffff));
			}
			if (o instanceof Address a) {
				return in.getMinAddress().getNewAddress(
					(in.getMinAddress().getOffset() & 0xff0000L) | (a.getOffset() & 0xffff));
			}
		}
		return null;
	}

	/**
	 * When another dispatch already defined a word table at {@code table}, its first {@code cap}
	 * entries' targets (appended to {@code targets}) and that count; else 0.
	 */
	private static int sharedTableEntries(Program program, Address table, long targetBank,
			int cap, List<Long> targets) {
		Data d = program.getListing().getDataAt(table);
		int skip = 0;
		if (d == null || !(d.getDataType() instanceof Array)) {
			// grm-gipk.16.11: inside a table laid from an entry-aligned overlapping start.
			Data c = program.getListing().getDataContaining(table);
			if (c != null && alignedOverlap(c.getMinAddress(), table) &&
				ANALYSIS_LAID.test(program, c)) {
				d = c;
				skip = (int) (table.subtract(c.getMinAddress()) / 2);
			}
		}
		if (d == null || !(d.getDataType() instanceof Array a) ||
			!(a.getDataType() instanceof WordDataType)) {
			return 0;
		}
		int n = Math.min(cap, a.getNumElements() - skip);
		for (int i = 0; i < n; i++) {
			Long e = laidEntry(program, table, i, targetBank);
			if (e == null) {
				return i;
			}
			targets.add(e);
		}
		return n;
	}

	/**
	 * Entry {@code i} of a word table {@link JumpTableArrays#layWords} laid at {@code table}: its
	 * target, or {@link W65816JumpTables#UNUSED_ENTRY} for a zero word the walk took as a
	 * placeholder -- which {@code layWords} marks by giving it no data reference (grm-8lr2). Read
	 * from the references, not re-derived, so this agrees with the walk by construction: where
	 * {@code $bank:0000} is plausible (HiROM) the walk took a zero as a target and referenced it.
	 * Null when the word is unreadable.
	 */
	private static Long laidEntry(Program program, Address table, int i, long targetBank) {
		Address at = table.add(2L * i);
		Integer w = word(program.getMemory(), at);
		if (w == null) {
			return null;
		}
		if (w == 0 && i > 0 && !program.getReferenceManager().hasReferencesFrom(at)) {
			return W65816JumpTables.UNUSED_ENTRY;
		}
		return targetBank | w;
	}

	/** " (k placeholder[s])" for the zero-word entries among {@code targets}, else empty. */
	private static String placeholders(List<Long> targets) {
		int k = W65816JumpTables.unusedCount(targets);
		return k == 0 ? "" : " (" + k + " placeholder" + (k == 1 ? "" : "s") + ")";
	}

	/** Each entry's target as an address in {@code table}'s space, in order; null: placeholder. */
	static List<Address> entryTargets(Address table, List<Long> targets) {
		List<Address> out = new ArrayList<>(targets.size());
		for (long t : targets) {
			out.add(t == W65816JumpTables.UNUSED_ENTRY ? null : table.getNewAddress(t));
		}
		return out;
	}

	private static boolean hasFlowTargets(Instruction in) {
		for (Reference r : in.getReferencesFrom()) {
			if (r.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The entries the index can reach: 128 for an 8-bit X, fewer when the accumulator's
	 * derivation just before the {@code TAX} bounds it (FF3 {@code $C2:1B02}: {@code AND #$0F /
	 * ASL A / TAX} -- sixteen handlers). The walk back collects {@code ASL A}, {@code AND #mask}
	 * and range guards ({@code CMP #k} then {@code BCC}/{@code BCS} falling through toward the
	 * dispatch), and {@link W65816JumpTables#derivedCap} runs them forward over every value A
	 * could hold (grm-9nxj.24, CT {@code $C7:0173}: {@code CMP #$10 / BCC / CMP #$18 / BCS /
	 * AND #$0F / ASL A} -- the guards and mask together allow 8 entries, the mask alone 16).
	 * Besides {@code TAX}, the CT transfer {@code XBA / LDA #$00 / PHA / XBA / PHA / PLX} moves A
	 * into X with a zero high byte ({@link #zeroExtendingTransfer}).
	 */
	static int indexCap(Listing listing, Instruction site) {
		BigInteger xf = site.getValue(site.getProgram().getRegister("ctx_XF"), false);
		int cap = xf != null && xf.intValue() == 1 ? 128 : W65816JumpTables.MAX_ENTRIES;
		Instruction cur = site;
		boolean sawTax = false;
		// The derivation, latest first (the walk runs backward).
		List<W65816JumpTables.IndexOp> chain = new ArrayList<>();
		for (int i = 0; i < 12; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough()) ||
				hasFlowInto(cur)) {
				break;
			}
			String pmn = prev.getMnemonicString().toUpperCase(Locale.ROOT);
			if (prev.getFlowType().isJump()) {
				// Only a carry guard on A, met by falling through, bounds the index.
				Instruction cmp = sawTax && (pmn.equals("BCC") || pmn.equals("BCS")) &&
					!hasFlowInto(prev) ? fallsFrom(listing, prev) : null;
				Long k = cmp != null &&
					cmp.getMnemonicString().equalsIgnoreCase("CMP") ? immediate(cmp) : null;
				if (k == null) {
					break;
				}
				// BCS skips when A >= k, so falling through means A < k; BCC the reverse.
				chain.add(new W65816JumpTables.IndexOp(pmn.equals("BCS")
						? W65816JumpTables.IndexOp.Kind.BELOW
						: W65816JumpTables.IndexOp.Kind.AT_LEAST, k));
				cur = cmp;
				continue;
			}
			cur = prev;
			String mn = pmn;
			String op = cur.getNumOperands() > 0 ? cur.getDefaultOperandRepresentation(0) : "";
			if (!sawTax) {
				if (mn.equals("TAX")) {
					sawTax = true;
					continue;
				}
				if (mn.equals("PLX")) {
					Instruction first = zeroExtendingTransfer(listing, cur);
					if (first == null) {
						break;
					}
					cur = first;
					sawTax = true;
					continue;
				}
				// Anything that neither writes X nor A may sit between TAX and the dispatch.
				if (mn.equals("REP") || mn.equals("SEP") || mn.equals("CLC") || mn.equals("SEC") ||
					mn.equals("PHX") || mn.equals("PHY") || mn.equals("PHA") || mn.equals("PHB") ||
					mn.equals("PHD") || mn.equals("PHP") || mn.equals("NOP")) {
					continue;
				}
				break;
			}
			if (mn.equals("ASL") && (op.isEmpty() || op.equals("A"))) {
				chain.add(new W65816JumpTables.IndexOp(W65816JumpTables.IndexOp.Kind.SHIFT, 1));
				continue;
			}
			if (mn.equals("REP") || mn.equals("SEP") || mn.equals("CLC") || mn.equals("SEC")) {
				continue;
			}
			Long mask = mn.equals("AND") ? immediate(cur) : null;
			if (mask != null) {
				chain.add(new W65816JumpTables.IndexOp(W65816JumpTables.IndexOp.Kind.MASK, mask));
				continue;
			}
			break;
		}
		Collections.reverse(chain);
		return Math.min(cap, W65816JumpTables.derivedCap(chain));
	}

	/** An instruction's immediate operand ({@code #k}), or null. */
	private static Long immediate(Instruction in) {
		if (in.getNumOperands() != 1 || !in.getDefaultOperandRepresentation(0).startsWith("#")) {
			return null;
		}
		for (Object o : in.getOpObjects(0)) {
			if (o instanceof Scalar s) {
				return s.getUnsignedValue();
			}
		}
		return null;
	}

	/**
	 * CT {@code $C7:016D}: {@code XBA / LDA #$00 / PHA / XBA / PHA / PLX} with an 8-bit A pushes
	 * a zero byte then A's byte, so the 16-bit {@code PLX} loads X with A zero-extended -- a
	 * {@code TAX} for the index's purposes. Given the {@code PLX}, returns the first {@code XBA}
	 * when the whole sequence falls straight through with nothing else flowing in, else null.
	 */
	static Instruction zeroExtendingTransfer(Listing listing, Instruction plx) {
		String[] want = { "PHA", "XBA", "PHA", "LDA", "XBA" };
		Instruction cur = plx;
		for (String mn : want) {
			if (hasFlowInto(cur)) {
				return null;
			}
			cur = fallsFrom(listing, cur);
			if (cur == null || !cur.getMnemonicString().equalsIgnoreCase(mn)) {
				return null;
			}
			// LDA #$00 at 8 bits: two bytes long, so PHA pushes one byte.
			if (mn.equals("LDA") && (cur.getLength() != 2 || !Long.valueOf(0).equals(
				immediate(cur)))) {
				return null;
			}
		}
		return cur;
	}

	private static boolean hasFlowInto(Instruction in) {
		for (Reference r : in.getProgram().getReferenceManager()
				.getReferencesTo(in.getMinAddress())) {
			if (r.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	static Integer word(Memory memory, Address at) {
		try {
			return (memory.getByte(at) & 0xff) | (memory.getByte(at.add(1)) & 0xff) << 8;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/** Whether a byte may belong to the table: free of code and data, not another table. */
	static boolean tableByteFree(Program program, Address b, Address table,
			Set<Address> tableStarts) {
		if (!b.equals(table) && tableStarts.contains(b) && !alignedOverlap(table, b)) {
			return false;
		}
		Listing listing = program.getListing();
		if (listing.getInstructionContaining(b) != null) {
			return false;
		}
		Data d = listing.getDefinedDataContaining(b);
		if (d == null) {
			return true;
		}
		// grm-gipk.16.11: the array another dispatch laid from an entry-aligned overlapping start
		// is this table's own bytes; it is re-laid from here (see added()).
		return d.getMinAddress().compareTo(table) > 0 && tableStarts.contains(d.getMinAddress()) &&
			alignedOverlap(table, d.getMinAddress()) && ANALYSIS_LAID.test(program, d);
	}

	/**
	 * Most entries one table's start may sit past another's and still be that table read from one
	 * entry over (grm-gipk.16.11): Timecop's {@code JSR ($AF90,X)} / {@code JSR ($AF92,X)}.
	 */
	static final int MAX_OVERLAP_ENTRIES = 1;

	/**
	 * Whether {@code other} is a start the table at {@code table} may run through: same bank, at
	 * most {@link #MAX_OVERLAP_ENTRIES} entries past it, on an entry boundary. A start any further
	 * on is the next table, and the walk ends there as before.
	 */
	static boolean alignedOverlap(Address table, Address other) {
		if (!table.getAddressSpace().equals(other.getAddressSpace()) ||
			(table.getOffset() & 0xff0000L) != (other.getOffset() & 0xff0000L)) {
			return false;
		}
		long d = other.getOffset() - table.getOffset();
		return d > 0 && d % 2 == 0 && d <= 2L * MAX_OVERLAP_ENTRIES;
	}

	/** Whether {@code d} is a word array this analyzer laid (its first entry has an ANALYSIS ref). */
	private static final java.util.function.BiPredicate<Program, Data> ANALYSIS_LAID =
		(program, d) -> d.getDataType() instanceof Array a &&
			a.getDataType() instanceof WordDataType &&
			program.getReferenceManager().getReferencesFrom(d.getMinAddress()).length > 0;

	/**
	 * Whether {@code t} can start a handler: initialized, executable, read-only memory (ROM), not
	 * inside an instruction or data, and -- if not yet decoded -- its first instructions at the
	 * dispatch's width contain no desync opcode and run into nothing mid-instruction.
	 */
	static boolean plausibleTarget(Program program, Address t, Map<Register, Integer> ctx) {
		return implausibility(program, t, ctx) == null;
	}

	/** Why {@code t} fails {@link #plausibleTarget}, or null when it passes (for decline logs). */
	static String implausibility(Program program, Address t, Map<Register, Integer> ctx) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(t);
		// A byte-mapped mirror reports isInitialized() false even over ROM, and LoROM FastROM code
		// runs in exactly those mirrors (banks $80+, grm-gipk.11): ask the initialized set instead.
		if (block == null || !memory.getAllInitializedAddressSet().contains(t) ||
			!block.isExecute() || block.isWrite()) {
			return "not ROM: " + block;
		}
		Listing listing = program.getListing();
		if (listing.getInstructionAt(t) != null) {
			return null;
		}
		if (listing.getInstructionContaining(t) != null ||
			listing.getDefinedDataContaining(t) != null) {
			return "inside " + listing.getCodeUnitContaining(t);
		}
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		Map<Register, Integer> width = new LinkedHashMap<>(ctx);
		Register mReg = program.getRegister("ctx_MF");
		Register xReg = program.getRegister("ctx_XF");
		Address a = t;
		for (int i = 0; i < LOOKAHEAD; i++) {
			if (i > 0) {
				if (listing.getInstructionAt(a) != null) {
					return null;   // merged into known code
				}
				if (listing.getInstructionContaining(a) != null ||
					listing.getDefinedDataContaining(a) != null) {
					return "runs into " + listing.getCodeUnitContaining(a) + " at " + a;
				}
			}
			PseudoDisassemblerContext pctx =
				new PseudoDisassemblerContext(program.getProgramContext());
			for (Map.Entry<Register, Integer> c : width.entrySet()) {
				pctx.setValue(c.getKey(), a, BigInteger.valueOf(c.getValue()));
			}
			Instruction in;
			try {
				in = pdis.disassemble(a, pctx, false);
			}
			catch (Exception e) {
				return "no decode at " + a + ": " + e.getMessage();
			}
			if (in == null) {
				return "no decode at " + a;
			}
			String mn = in.getMnemonicString().toUpperCase(Locale.ROOT);
			if (DESYNC.contains(mn)) {
				return mn + " at " + a;
			}
			// A constant REP/SEP is followed at its new width (CT $C5:06FE's ninth entry decodes
			// a BRK four instructions past one); anything else that changes width ends the look.
			if (mn.equals("REP") || mn.equals("SEP")) {
				int bits = -1;
				for (Object o : in.getOpObjects(0)) {
					if (o instanceof Scalar s) {
						bits = (int) s.getUnsignedValue();
					}
				}
				if (bits < 0) {
					return null;
				}
				int v = mn.equals("SEP") ? 1 : 0;
				if ((bits & 0x20) != 0 && mReg != null) {
					width.put(mReg, v);
				}
				if ((bits & 0x10) != 0 && xReg != null) {
					width.put(xReg, v);
				}
			}
			else if (WIDTH_CHANGE.contains(mn)) {
				return null;
			}
			FlowType ft = in.getFlowType();
			// A conditional branch is looked past (its fall-through is decoded either way).
			if (ft.isTerminal() || (ft.isJump() && !ft.isConditional()) || !in.hasFallthrough()) {
				return null;
			}
			a = in.getFallThrough();
			if (a == null || !Objects.equals(memory.getBlock(a), block)) {
				return "leaves the block at " + a;
			}
		}
		return null;
	}

	/** E/M/X at the dispatch. */
	static Map<Register, Integer> context(Program program, Instruction site) {
		Map<Register, Integer> ctx = new LinkedHashMap<>();
		for (String name : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
			Register reg = program.getRegister(name);
			BigInteger v = site.getValue(reg, false);
			if (v != null) {
				ctx.put(reg, v.intValue());
			}
		}
		return ctx;
	}

	static boolean stampAndDisassemble(Analyzer owner, Program program, Address t,
			Map<Register, Integer> ctx,
			TaskMonitor monitor) {
		for (Map.Entry<Register, Integer> c : ctx.entrySet()) {
			try {
				program.getProgramContext().setValue(c.getKey(), t, t,
					BigInteger.valueOf(c.getValue()));
			}
			catch (ContextChangeException e) {
				AnalyzerLog.info(owner, "could not stamp " + c.getKey().getName() + " at " + t +
					": " + e.getMessage());
				return false;
			}
		}
		new DisassembleCommand(t, null, true).applyTo(program, monitor);
		return program.getListing().getInstructionAt(t) != null;
	}

	/**
	 * Warns at the dispatch when an already-decoded target's decode depends on a flag the
	 * dispatch holds at the other value.
	 */
	static boolean warnIfOtherWidth(Program program, W65816WidthEffects effects,
			Instruction site, Instruction target) {
		if (effects.emulation(target)) {
			return false;
		}
		W65816WidthEffects.Effect e = effects.effect(target.getMinAddress());
		String which = "";
		if (e.m().needs() &&
			effects.flag(site, effects.mRegister()) != effects.flag(target, effects.mRegister())) {
			which += "M";
		}
		if (e.x().needs() &&
			effects.flag(site, effects.xRegister()) != effects.flag(target, effects.xRegister())) {
			which += "X";
		}
		if (which.isEmpty()) {
			return false;
		}
		program.getBookmarkManager().setBookmark(site.getMinAddress(), BookmarkType.WARNING,
			W65816WidthAnalyzer.BOOKMARK_CATEGORY, "jump-table target " + target.getMinAddress() +
				" is decoded at a different " + which + " width than this dispatch passes, and " +
				"its decode depends on it; one address holds one decode");
		return true;
	}

	static String describe(Map<Register, Integer> ctx) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<Register, Integer> c : ctx.entrySet()) {
			String n = c.getKey().getName();
			sb.append(sb.length() == 0 ? "" : " ")
					.append(n.equals("ctx_EF") ? "E" : n.equals("ctx_MF") ? "M" : "X")
					.append('=').append(c.getValue());
		}
		return sb.toString();
	}
}
