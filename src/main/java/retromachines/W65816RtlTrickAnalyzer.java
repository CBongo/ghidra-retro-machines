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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves the 65816 RTL trick (grm-gipk.14): {@code bank PHA / word PHA / RTL} through a table of
 * bank:word records; see {@link W65816RtlTrick} for the shape. The record stride (3 or 4) is not
 * in the code, so both are walked and {@link TableScorer#rank ranked}, stride 3 winning a tie. For
 * every recognized {@code RTL} in the newly-added set this
 * <ol>
 * <li>lays the records with {@link JumpTableArrays#layRecords}, one DATA reference per record to
 * its real target;</li>
 * <li>adds a {@link RefType#COMPUTED_JUMP} reference from the {@code RTL} to each target;</li>
 * <li>stamps the {@code RTL}'s E/M/X at each undecoded target and disassembles it.</li>
 * </ol>
 * Each {@code RTL} is handled once per program; one that already has flow references is left alone.
 * The sibling of {@link W65816RtsTrickAnalyzer}, whose behaviour this does not touch.
 */
public class W65816RtlTrickAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 RTL Trick Dispatch";
	private static final String DESCRIPTION =
		"Resolves the 65816 RTL trick (bank PHA / word PHA / RTL through a table of bank:word " +
			"records): ranks the record stride, lays the table, references and decodes the " +
			"targets (grm-gipk.14).";
	private static final String COMMENT_PREFIX = "65816 RTL trick ";

	/** Record strides tried, in tie-break order. */
	private static final int[] STRIDES = { 3, 4 };

	/** RTL sites already handled, per program. */
	private static final Map<Program, Set<Address>> DONE =
		Collections.synchronizedMap(new WeakHashMap<>());

	public W65816RtlTrickAnalyzer() {
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
			if ("RTL".equals(in.getMnemonicString()) && !done.contains(in.getMinAddress())) {
				sites.add(in);
			}
		}
		// Every dispatch in this pass names where its table starts; one table's walk must not run on
		// into another's first record (ABC Monday Night Football $84B9 into $84E1).
		Set<Address> starts = new LinkedHashSet<>();
		for (Instruction rtl : sites) {
			W65816RtlTrick.Shape other = hasFlow(rtl) ? null : W65816RtlTrick.recognize(program, rtl);
			if (other != null) {
				starts.add(other.table());
			}
		}
		int resolved = 0;
		int decoded = 0;
		for (Instruction rtl : sites) {
			monitor.checkCancelled();
			Address rtlAddr = rtl.getMinAddress();
			if (hasFlow(rtl)) {
				done.add(rtlAddr);
				continue;
			}
			W65816RtlTrick.Shape shape = W65816RtlTrick.recognize(program, rtl);
			if (shape == null) {
				continue;   // not final: a later pass may decode the window
			}
			done.add(rtlAddr);
			Map<Register, Integer> ctx = W65816JumpTableAnalyzer.context(program, rtl);
			if (effects.emulation(rtl)) {
				continue;
			}
			Address table = shape.table();
			List<Long> targets = new ArrayList<>();
			int stride = 0;
			int n = 0;
			boolean shared = false;
			for (int s : STRIDES) {
				int laid = JumpTableArrays.laidRecords(program, table, s, shape.bankFirst());
				if (laid > 0) {
					stride = s;
					n = Math.min(laid, capFor(shape, s));
					for (int e = 0; e < n; e++) {
						Long t = entryTarget(program, shape, s, e);
						if (t == null) {
							n = e;
							break;
						}
						targets.add(t);
					}
					shared = true;
					break;
				}
			}
			if (!shared) {
				Set<Address> own = Set.copyOf(shape.own());
				List<TableScorer.Candidate<Integer>> cands = new ArrayList<>();
				for (int s : STRIDES) {
					cands.add(new TableScorer.Candidate<>(s, 1.0));
				}
				var ranked = TableScorer.rank(cands,
					s -> walkTable(program, shape, s, ctx, own, starts));
				var best = ranked.get(0);
				stride = best.key();
				targets.addAll(best.result().targets());
				n = best.result().count();
				while (n > 0 && targets.get(n - 1) == W65816JumpTables.UNUSED_ENTRY) {
					targets.remove(--n);   // trailing placeholders are not part of the table
				}
				StringBuilder sb = new StringBuilder();
				for (var r : ranked) {
					sb.append(sb.length() == 0 ? "" : ", ").append("stride ").append(r.key())
							.append(" keeps ").append(r.result().count()).append(" (")
							.append(r.result().endedBy()).append(')');
				}
				AnalyzerLog.info(this, "RTL " + rtlAddr + ": table " + table + " " +
					(shape.bankFirst() ? "bank-first" : "word-first") + ", stride " + stride +
					" chosen: " + sb);
			}
			long real = targets.stream().filter(t -> t != W65816JumpTables.UNUSED_ENTRY).count();
			if (real < 2) {
				AnalyzerLog.info(this, "RTL " + rtlAddr + ": only " + real + " plausible entr" +
					(real == 1 ? "y" : "ies") + " at " + table);
				continue;
			}
			List<Address> entryAddrs = new ArrayList<>();
			for (long t : targets) {
				entryAddrs.add(t == W65816JumpTables.UNUSED_ENTRY ? null : table.getNewAddress(t));
			}
			if (!shared && !JumpTableArrays.layRecords(program, table, stride, shape.bankFirst(),
				entryAddrs)) {
				AnalyzerLog.info(this, "RTL " + rtlAddr + ": could not define table at " + table);
				continue;
			}
			Set<Address> unique = new LinkedHashSet<>();
			for (Address t : entryAddrs) {
				if (t != null) {
					unique.add(t);
				}
			}
			for (Address t : unique) {
				program.getReferenceManager().addMemoryReference(rtlAddr, t,
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			}
			for (Address t : unique) {
				monitor.checkCancelled();
				Instruction existing = listing.getInstructionAt(t);
				if (existing != null) {
					W65816JumpTableAnalyzer.warnIfOtherWidth(program, effects, rtl, existing);
				}
				else if (W65816JumpTableAnalyzer.stampAndDisassemble(this, program, t, ctx,
					monitor)) {
					decoded++;
				}
			}
			AnalyzerCommentRecord.replaceOwn(program, rtlAddr, CommentType.EOL,
				COMMENT_PREFIX + table + ": " + n + " records of " + stride + " bytes (" + real +
					" used), " +
					unique.size() + " target(s) decoded at " + W65816JumpTableAnalyzer.describe(ctx),
				COMMENT_PREFIX);
			resolved++;
		}
		if (resolved > 0) {
			AnalyzerLog.info(this, "resolved " + resolved + " RTL-trick dispatch(es); decoded " +
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

	/** Most records the index register can reach at {@code stride}. */
	private static int capFor(W65816RtlTrick.Shape shape, int stride) {
		return Math.min(W65816JumpTables.MAX_ENTRIES, shape.indexMax() / stride + 1);
	}

	/** Record {@code i}'s full 24-bit target, or null when its bytes are unreadable. */
	private static Long entryTarget(Program program, W65816RtlTrick.Shape shape, int stride,
			int i) {
		try {
			Address rec = shape.table().add((long) stride * i);
			Address bankAt = rec.add(shape.bankFirst() ? 0 : 2);
			Integer w = W65816JumpTableAnalyzer.word(program.getMemory(),
				rec.add(shape.bankFirst() ? 1 : 0));
			if (w == null) {
				return null;
			}
			long bank = program.getMemory().getByte(bankAt) & 0xffL;
			int offset = (w + shape.bias()) & 0xffff;
			return offset == 0 ? W65816JumpTables.UNUSED_ENTRY : (bank << 16) | offset;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/** One RTL-trick table read at {@code stride}. */
	private static TableScorer.Result<Long, W65816JumpTables.End> walkTable(Program program,
			W65816RtlTrick.Shape shape, int stride, Map<Register, Integer> ctx, Set<Address> own,
			Set<Address> starts) {
		Address table = shape.table();
		int cap = capFor(shape, stride);
		List<EntryReferences.Extent> extent =
			List.of(new EntryReferences.Extent(table, (long) stride * cap));
		return W65816JumpTables.scoreRecords(table.getOffset(), stride, cap,
			i -> entryTarget(program, shape, stride, i),
			b -> W65816JumpTableAnalyzer.tableByteFree(program, table.getNewAddress(b), table,
				starts),
			t -> W65816JumpTableAnalyzer.plausibleTarget(program, table.getNewAddress(t), ctx),
			i -> EntryReferences.find(program, table.add((long) stride * i), extent, own));
	}
}
