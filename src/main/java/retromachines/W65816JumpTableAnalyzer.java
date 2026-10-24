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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
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
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
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
		repairOverreads(program, tables, monitor);

		List<Instruction> sites = new ArrayList<>();
		for (Instruction in : listing.getInstructions(set, true)) {
			if (tableOf(in) != null && !done.contains(in.getMinAddress())) {
				sites.add(in);
			}
		}
		if (sites.isEmpty()) {
			return true;
		}
		// Every dispatch's table start, program-wide: one table ends where another begins.
		Set<Address> tableStarts = new LinkedHashSet<>();
		for (Instruction in : listing.getInstructions(true)) {
			Address t = tableOf(in);
			if (t != null) {
				tableStarts.add(t);
			}
		}

		int resolved = 0;
		int decoded = 0;
		int warned = 0;
		for (Instruction site : sites) {
			monitor.checkCancelled();
			Address siteAddr = site.getMinAddress();
			done.add(siteAddr);
			site = listing.getInstructionAt(siteAddr);   // an earlier site may have re-decoded it
			Address table = site == null ? null : tableOf(site);
			if (table == null || effects.emulation(site) || hasFlowTargets(site)) {
				continue;
			}
			Map<Register, Integer> ctx = context(program, site);
			int cap = indexCap(listing, site);
			List<Long> targets = new ArrayList<>();
			// Several dispatches often share one table (CT $C1:B80D has four): the first defines
			// it, the rest reuse its extent rather than finding its bytes taken.
			int n = sharedTableEntries(program, table, cap, targets);
			boolean shared = n > 0;
			if (!shared) {
				n = W65816JumpTables.bound(table.getOffset(), cap,
					i -> word(program.getMemory(), table.add(2L * i)),
					b -> tableByteFree(program, table.getNewAddress(b), table, tableStarts),
					t -> plausibleTarget(program, table.getNewAddress(t), ctx),
					targets);
			}
			if (n == 0) {
				AnalyzerLog.info(this, "dispatch " + siteAddr + ": no plausible entry at " + table);
				continue;
			}
			boolean call = site.getFlowType().isCall();
			try {
				if (!shared) {
					listing.createData(table, new ArrayDataType(WordDataType.dataType, n, 2));
				}
			}
			catch (Exception e) {
				AnalyzerLog.info(this, "dispatch " + siteAddr + ": could not define table at " +
					table + ": " + e.getMessage());
				continue;
			}
			RefType type = call ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP;
			Set<Address> unique = new LinkedHashSet<>();
			for (long t : targets) {
				unique.add(table.getNewAddress(t));
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
				else if (stampAndDisassemble(program, t, ctx, monitor)) {
					decoded++;
				}
				if (call && program.getFunctionManager().getFunctionAt(t) == null &&
					listing.getInstructionAt(t) != null) {
					new CreateFunctionCmd(t).applyTo(program, monitor);
				}
			}
			tables.computeIfAbsent(table, t -> new LinkedHashSet<>()).add(siteAddr);
			AnalyzerCommentRecord.replaceOwn(program, siteAddr, CommentType.EOL,
				note(table, n, unique.size(), ctx, cap), COMMENT_PREFIX);
			resolved++;
		}
		if (resolved > 0) {
			AnalyzerLog.info(this, "resolved " + resolved + " jump table(s); decoded " + decoded +
				" new target(s); " + warned + " target(s) already decoded at another width");
		}
		return true;
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
	 */
	private void repairOverreads(Program program, Map<Address, Set<Address>> tables,
			TaskMonitor monitor) throws CancelledException {
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
			if (keep == n) {
				continue;
			}
			listing.clearCodeUnits(table, end, false);
			Set<Address> kept = new LinkedHashSet<>();
			if (keep > 0) {
				try {
					listing.createData(table, new ArrayDataType(WordDataType.dataType, keep, 2));
				}
				catch (Exception e) {
					AnalyzerLog.info(this, "could not shrink table " + table + ": " + e.getMessage());
				}
				for (int i = 0; i < keep; i++) {
					Integer w = word(program.getMemory(), table.add(2L * i));
					if (w != null) {
						kept.add(table.getNewAddress((table.getOffset() & 0xff0000L) | w));
					}
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
				if (keep == 0) {
					AnalyzerCommentRecord.replaceOwn(program, site, CommentType.EOL,
						COMMENT_PREFIX + table + ": withdrawn, code later decoded at its first " +
							"entry", COMMENT_PREFIX);
				}
				else if (in != null) {
					AnalyzerCommentRecord.replaceOwn(program, site, CommentType.EOL,
						note(table, keep, kept.size(), context(program, in), indexCap(listing, in)) +
							"; shortened, code later decoded past it", COMMENT_PREFIX);
				}
			}
			for (Address c : conflicts) {
				new DisassembleCommand(c, null, true).applyTo(program, monitor);
			}
			AnalyzerLog.info(this, "table " + table + " shortened from " + n + " to " + keep +
				" entries: code later decoded at " + conflicts);
		}
	}

	/** The table a native {@code JMP/JSR (abs,X)} reads, in the program bank; else null. */
	static Address tableOf(Instruction in) {
		FlowType ft = in.getFlowType();
		if (!ft.isComputed() || ft.isTerminal() || in.getNumOperands() != 1) {
			return null;
		}
		String mn = in.getMnemonicString().toUpperCase();
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
	private static int sharedTableEntries(Program program, Address table, int cap,
			List<Long> targets) {
		Data d = program.getListing().getDataAt(table);
		if (d == null || !(d.getDataType() instanceof Array a) ||
			!(a.getDataType() instanceof WordDataType)) {
			return 0;
		}
		int n = Math.min(cap, a.getNumElements());
		for (int i = 0; i < n; i++) {
			Integer w = word(program.getMemory(), table.add(2L * i));
			if (w == null) {
				return i;
			}
			targets.add((table.getOffset() & 0xff0000L) | w);
		}
		return n;
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
	 * The entries the index can reach: 128 for an 8-bit X, fewer when {@code AND #mask} reaches X
	 * through {@code ASL A}s and a {@code TAX} immediately before the dispatch (FF3 {@code
	 * $C2:1B02}: {@code AND #$0F / ASL A / TAX} -- sixteen handlers).
	 */
	private static int indexCap(Listing listing, Instruction site) {
		BigInteger xf = site.getValue(site.getProgram().getRegister("ctx_XF"), false);
		int cap = xf != null && xf.intValue() == 1 ? 128 : W65816JumpTables.MAX_ENTRIES;
		Instruction cur = site;
		boolean sawTax = false;
		int shifts = 0;
		for (int i = 0; i < 8; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough()) ||
				prev.getFlowType().isJump() || hasFlowInto(cur)) {
				break;
			}
			cur = prev;
			String mn = cur.getMnemonicString().toUpperCase();
			String op = cur.getNumOperands() > 0 ? cur.getDefaultOperandRepresentation(0) : "";
			if (!sawTax) {
				if (mn.equals("TAX")) {
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
				shifts++;
				continue;
			}
			if (mn.equals("REP") || mn.equals("SEP") || mn.equals("CLC") || mn.equals("SEC")) {
				continue;
			}
			if (mn.equals("AND") && op.startsWith("#")) {
				for (Object o : cur.getOpObjects(0)) {
					if (o instanceof Scalar s) {
						return Math.min(cap, W65816JumpTables.maskCap((int) s.getUnsignedValue(),
							shifts));
					}
				}
			}
			break;
		}
		return cap;
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

	private static Integer word(Memory memory, Address at) {
		try {
			return (memory.getByte(at) & 0xff) | (memory.getByte(at.add(1)) & 0xff) << 8;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/** Whether a byte may belong to the table: free of code and data, not another table. */
	private static boolean tableByteFree(Program program, Address b, Address table,
			Set<Address> tableStarts) {
		if (!b.equals(table) && tableStarts.contains(b)) {
			return false;
		}
		Listing listing = program.getListing();
		return listing.getInstructionContaining(b) == null &&
			listing.getDefinedDataContaining(b) == null;
	}

	/**
	 * Whether {@code t} can start a handler: initialized, executable, read-only memory (ROM), not
	 * inside an instruction or data, and -- if not yet decoded -- its first instructions at the
	 * dispatch's width contain no desync opcode and run into nothing mid-instruction.
	 */
	private static boolean plausibleTarget(Program program, Address t, Map<Register, Integer> ctx) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(t);
		if (block == null || !block.isInitialized() || !block.isExecute() || block.isWrite()) {
			return false;
		}
		Listing listing = program.getListing();
		if (listing.getInstructionAt(t) != null) {
			return true;
		}
		if (listing.getInstructionContaining(t) != null ||
			listing.getDefinedDataContaining(t) != null) {
			return false;
		}
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		Map<Register, Integer> width = new LinkedHashMap<>(ctx);
		Register mReg = program.getRegister("ctx_MF");
		Register xReg = program.getRegister("ctx_XF");
		Address a = t;
		for (int i = 0; i < LOOKAHEAD; i++) {
			if (i > 0) {
				if (listing.getInstructionAt(a) != null) {
					return true;   // merged into known code
				}
				if (listing.getInstructionContaining(a) != null ||
					listing.getDefinedDataContaining(a) != null) {
					return false;
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
				return false;
			}
			if (in == null) {
				return false;
			}
			String mn = in.getMnemonicString().toUpperCase();
			if (DESYNC.contains(mn)) {
				return false;
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
					return true;
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
				return true;
			}
			FlowType ft = in.getFlowType();
			// A conditional branch is looked past (its fall-through is decoded either way).
			if (ft.isTerminal() || (ft.isJump() && !ft.isConditional()) || !in.hasFallthrough()) {
				return true;
			}
			a = in.getFallThrough();
			if (a == null || memory.getBlock(a) != block) {
				return false;
			}
		}
		return true;
	}

	/** E/M/X at the dispatch. */
	private static Map<Register, Integer> context(Program program, Instruction site) {
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

	private boolean stampAndDisassemble(Program program, Address t, Map<Register, Integer> ctx,
			TaskMonitor monitor) {
		for (Map.Entry<Register, Integer> c : ctx.entrySet()) {
			try {
				program.getProgramContext().setValue(c.getKey(), t, t,
					BigInteger.valueOf(c.getValue()));
			}
			catch (ContextChangeException e) {
				AnalyzerLog.info(this, "could not stamp " + c.getKey().getName() + " at " + t +
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
	private static boolean warnIfOtherWidth(Program program, W65816WidthEffects effects,
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

	private static String describe(Map<Register, Integer> ctx) {
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
