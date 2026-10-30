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
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves the 65816 RTS trick (grm-gipk.11): {@code LDA table,R / [DEC A] / PHA / RTS} through a
 * word table of target-minus-one (or exact) entries; see {@link W65816RtsTrick} for the shape.
 * For every recognized, bounded {@code RTS} in the newly-added set this
 * <ol>
 * <li>lays the word table with {@link JumpTableArrays}, one DATA reference per entry to its real
 * target;</li>
 * <li>adds a {@link RefType#COMPUTED_JUMP} reference from the {@code RTS} to each target;</li>
 * <li>stamps the {@code RTS}'s E/M/X at each undecoded target and disassembles it.</li>
 * </ol>
 * No function is created: the cases share the dispatcher's stack frame. Each {@code RTS} is
 * handled once per program, and one that already has flow references is left alone. Priority is
 * that of {@link W65816JumpTableAnalyzer}.
 */
public class W65816RtsTrickAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 RTS Trick Dispatch";
	private static final String DESCRIPTION =
		"Resolves the 65816 RTS trick (LDA table,X / [DEC A] / PHA / RTS through a word table of " +
			"target-minus-one entries): lays the table, references and decodes the targets " +
			"(grm-gipk.11).";
	private static final String COMMENT_PREFIX = "65816 RTS trick ";

	/** RTS sites already handled, per program. */
	private static final Map<Program, Set<Address>> DONE =
		Collections.synchronizedMap(new WeakHashMap<>());

	public W65816RtsTrickAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
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
		Listing listing = program.getListing();
		Set<Address> done =
			DONE.computeIfAbsent(program, p -> Collections.synchronizedSet(new LinkedHashSet<>()));
		W65816WidthEffects effects = new W65816WidthEffects(program);
		List<Instruction> sites = new ArrayList<>();
		for (Instruction in : listing.getInstructions(set, true)) {
			if ("RTS".equals(in.getMnemonicString()) && !done.contains(in.getMinAddress())) {
				sites.add(in);
			}
		}
		int resolved = 0;
		int decoded = 0;
		for (Instruction rts : sites) {
			monitor.checkCancelled();
			Address rtsAddr = rts.getMinAddress();
			if (hasFlow(rts)) {
				done.add(rtsAddr);
				continue;
			}
			W65816RtsTrick.Shape shape = W65816RtsTrick.recognize(program, rts);
			if (shape == null) {
				continue;   // not final: a later pass may decode the window
			}
			done.add(rtsAddr);
			Map<Register, Integer> ctx = W65816JumpTableAnalyzer.context(program, rts);
			if (effects.emulation(rts)) {
				continue;
			}
			Address table = shape.table();
			long bank = rtsAddr.getOffset() & 0xff0000L;
			int bias = shape.bias();
			List<Long> targets = new ArrayList<>();
			int n = sharedEntries(program, table, bank, bias, shape.cap(), targets);
			boolean shared = n > 0;
			if (!shared) {
				n = W65816JumpTables.bound(table.getOffset(), bank, shape.cap(),
					i -> {
						Integer w = W65816JumpTableAnalyzer.word(program.getMemory(),
							table.add(2L * i));
						return w == null ? null : (w + bias) & 0xffff;
					},
					b -> W65816JumpTableAnalyzer.tableByteFree(program, table.getNewAddress(b),
						table, Set.of()),
					t -> sameHalfAsFirst(targets, t) && W65816JumpTableAnalyzer.plausibleTarget(
						program, table.getNewAddress(t), ctx),
					targets);
			}
			if (n < 2) {
				AnalyzerLog.info(this, "RTS " + rtsAddr + ": only " + n + " plausible entr" +
					(n == 1 ? "y" : "ies") + " at " + table + " (" +
					whyEntryFails(program, table, n, bank, bias, ctx) + ")");
				continue;
			}
			if (!shared && !JumpTableArrays.layWords(program, table,
				W65816JumpTableAnalyzer.entryTargets(table, targets))) {
				AnalyzerLog.info(this, "RTS " + rtsAddr + ": could not define table at " + table);
				continue;
			}
			Set<Address> unique = new LinkedHashSet<>();
			for (long t : targets) {
				unique.add(table.getNewAddress(t));
			}
			for (Address t : unique) {
				program.getReferenceManager().addMemoryReference(rtsAddr, t,
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			}
			for (Address t : unique) {
				monitor.checkCancelled();
				Instruction existing = listing.getInstructionAt(t);
				if (existing != null) {
					W65816JumpTableAnalyzer.warnIfOtherWidth(program, effects, rts, existing);
				}
				else if (W65816JumpTableAnalyzer.stampAndDisassemble(this, program, t, ctx,
					monitor)) {
					decoded++;
				}
			}
			AnalyzerCommentRecord.replaceOwn(program, rtsAddr, CommentType.EOL,
				COMMENT_PREFIX + table + ": " + n + " entries, " + unique.size() +
					" target(s) decoded at " + W65816JumpTableAnalyzer.describe(ctx),
				COMMENT_PREFIX);
			resolved++;
		}
		if (resolved > 0) {
			AnalyzerLog.info(this, "resolved " + resolved + " RTS-trick dispatch(es); decoded " +
				decoded + " new target(s)");
		}
		return true;
	}

	private static boolean hasFlow(Instruction in) {
		for (var r : in.getReferencesFrom()) {
			if (r.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Every target lies in the same 32 KB half of the bank as the first. A HiROM bank maps both
	 * halves to ROM, so without this a table runs on into a following one whose words point into
	 * the other half: Madden NFL '94 {@code $C5:A748} has 66 handlers at {@code $82xx-$A5xx}, then
	 * {@code $22B6, $2340, ...}, which decode as plausible code and took the count to 120.
	 */
	private static boolean sameHalfAsFirst(List<Long> accepted, long t) {
		return accepted.isEmpty() || ((accepted.get(0) ^ t) & 0x8000L) == 0;
	}

	/** Which check entry {@code i} fails, for the decline log. */
	private static String whyEntryFails(Program program, Address table, int i, long bank, int bias,
			Map<Register, Integer> ctx) {
		Address at = table.add(2L * i);
		for (Address b : new Address[] { at, at.add(1) }) {
			if (!W65816JumpTableAnalyzer.tableByteFree(program, b, table, Set.of())) {
				var cu = program.getListing().getCodeUnitContaining(b);
				return "entry " + i + " byte " + b + " is taken: " + cu;
			}
		}
		Integer w = W65816JumpTableAnalyzer.word(program.getMemory(), at);
		if (w == null) {
			return "entry " + i + " unreadable";
		}
		Address t = table.getNewAddress(bank | ((w + bias) & 0xffff));
		String why = W65816JumpTableAnalyzer.implausibility(program, t, ctx);
		return "entry " + i + " target " + t + (why == null ? " plausible" : " not plausible: " + why);
	}

	/** An already-laid word table at {@code table}: its first {@code cap} biased targets, else 0. */
	private static int sharedEntries(Program program, Address table, long bank, int bias, int cap,
			List<Long> targets) {
		Data d = program.getListing().getDataAt(table);
		if (d == null || !(d.getDataType() instanceof Array a) ||
			!(a.getDataType() instanceof WordDataType)) {
			return 0;
		}
		int n = Math.min(cap, a.getNumElements());
		for (int i = 0; i < n; i++) {
			Integer w = W65816JumpTableAnalyzer.word(program.getMemory(), table.add(2L * i));
			if (w == null) {
				return i;
			}
			targets.add(bank | ((w + bias) & 0xffff));
		}
		return n;
	}
}
