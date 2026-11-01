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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongUnaryOperator;

import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;

/**
 * grm-c9d.8.3, check mode: runs the two-ended (leading) forms of the {@link JumpTableBound} trim
 * rules over the tables {@link JumpTableBoundAnalyzer} bounded in one pass, and LOGS what each would
 * drop. It changes nothing -- no listing, reference or override -- so production behaviour is
 * byte-identical; stage 4 of grm-c9d.8 decides which rules to enable from what this reports.
 *
 * <p>Tables are recorded as the analyzer finishes with them (the post-tail view: the kept entries
 * after every tail rule and {@code codePrefix}), and the rules run once both passes are done, so the
 * rules that need OTHER tables ({@link JumpTableBound#leadingByKnownCode},
 * {@link JumpTableBound#leadingByNeighbourEnd}) see every bounded result of the pass, not an
 * order-dependent subset. A table with a recovered index guard is never recorded: the guard beats
 * every trim rule.
 *
 * <p>Each applicable rule logs one line, grep-able and stable:
 * {@code [lead-check] <switch> table <addr> rule <RULE> would drop <k> of <n> (first kept <slot>
 * -> <target>; dropped <targets>)}. The line reaches {@link Msg} only (info), where the real-ROM
 * rows' per-row logs capture it; nothing goes to the MessageLog.
 */
final class LeadingShadow {

	/** Linear-decode budget when measuring a handler's extent; beyond it the extent just ends. */
	private static final int EXTENT_MAX_STEPS = 128;

	/** The most dropped targets one log line names. */
	private static final int LOG_DROPPED_MAX = 8;

	/**
	 * One table after the tail rules. {@code targets} are the kept entries' offsets in slot order
	 * (empty for a distinct-words table, which keeps {@code words} instead), {@code view} describes
	 * their bytes (see {@link JumpTableBound#leadingView}); {@code bounded} says a tail rule proved
	 * the extent (only such tables feed other tables' foreign-start and neighbour-end facts).
	 */
	record Table(Address switchAddr, AddressSpace space, List<Long> targets,
			List<JumpTableBound.LoadTableEntry> view, JumpTableBound.Block block,
			List<Boolean> inCode, List<Boolean> decodes, boolean overlapping, boolean bounded,
			JumpTableBound.Rule tailRule, List<Long> words) {
	}

	private final Map<Address, Table> tables = new LinkedHashMap<>();
	/** The lines already logged: a table seen by several passes logs each line once. */
	private final Set<String> logged = new HashSet<>();

	/**
	 * Records {@code t}, unless an earlier pass already recorded a bounded view of the same switch
	 * and this one is not: once we pin a table by references the decompiler reads it whole again, and
	 * that stale reading must not stand in for the bounded one.
	 */
	void add(Table t) {
		Table old = tables.get(t.switchAddr());
		if (old == null || t.bounded() || !old.bounded()) {
			tables.put(t.switchAddr(), t);
		}
	}

	/** Runs every leading rule on every recorded table and logs what would drop. */
	void run(Program program, Object originator, String source) {
		PseudoDisassembler dis = new PseudoDisassembler(program);
		Map<Long, Long> extents = new HashMap<>();
		for (Table t : tables.values()) {
			try {
				check(t, dis, extents, originator, source);
			}
			catch (RuntimeException e) {
				// Check mode must never disturb the analysis it observes.
				Msg.debug(originator, source + ": [lead-check] " + t.switchAddr() + " skipped: " + e);
			}
		}
	}

	private void check(Table t, PseudoDisassembler dis, Map<Long, Long> extents, Object originator,
			String source) {
		LongUnaryOperator extent = offset -> extents.computeIfAbsent(offset,
			o -> decodedExtentEnd(dis, t.space(), o));
		long viewStart = lowestStart(t.view());
		if (t.words() != null) {
			JumpTableBound.Leading l = JumpTableBound.leadingByDistinctWords(t.words(), viewStart,
				t.view().get(0).num(), extent);
			if (l.applies()) {
				log(t, viewStart, l, t.words().subList(0, t.view().get(0).num()), originator, source);
			}
			return;
		}
		List<Long> foreign = new ArrayList<>();
		List<Long> ends = new ArrayList<>();
		for (Table o : tables.values()) {
			if (o.switchAddr().equals(t.switchAddr()) || !o.bounded() || o.words() != null ||
				!sameMemory(o.space(), t.space())) {
				continue;
			}
			foreign.addAll(o.targets());
			ends.add(JumpTableBound.viewEnd(o.view()));
		}
		JumpTableBound.LeadingFacts facts = new JumpTableBound.LeadingFacts(
			t.switchAddr().getOffset(), t.block(), extent, foreign, ends, t.inCode(), t.decodes(),
			t.overlapping(), t.tailRule());
		for (JumpTableBound.Leading l : JumpTableBound.leadingChecks(t.targets(), t.view(), facts)) {
			log(t, viewStart, l, t.targets(), originator, source);
		}
	}

	private void log(Table t, long viewStart, JumpTableBound.Leading l, List<Long> targets,
			Object originator, String source) {
		int n = targets.size();
		JumpTableBound.LoadTableEntry first = null;
		for (JumpTableBound.LoadTableEntry e : t.view()) {
			if (e.start() == viewStart) {
				first = e;
			}
		}
		long slot = viewStart + (first == null ? 0 : (long) l.drop() * first.entrySize());
		StringBuilder dropped = new StringBuilder();
		for (int i = 0; i < Math.min(l.drop(), LOG_DROPPED_MAX); i++) {
			dropped.append(i == 0 ? "" : ",").append(Long.toHexString(targets.get(i)));
		}
		if (l.drop() > LOG_DROPPED_MAX) {
			dropped.append(",...");
		}
		String line = "[lead-check] " + t.switchAddr() + " table " + Long.toHexString(viewStart) +
			" rule " + l.rule() + " would drop " + l.drop() + " of " + n + " (first kept " +
			Long.toHexString(slot) + " -> " + Long.toHexString(targets.get(l.drop())) +
			"; dropped " + dropped + ")";
		if (logged.add(line)) {
			AnalyzerLog.info(originator, source, line);
		}
	}

	private static long lowestStart(List<JumpTableBound.LoadTableEntry> view) {
		long lowest = Long.MAX_VALUE;
		for (JumpTableBound.LoadTableEntry e : view) {
			lowest = Math.min(lowest, e.start());
		}
		return lowest;
	}

	private static boolean sameMemory(AddressSpace a, AddressSpace b) {
		return a.equals(b) || a.getPhysicalSpace().equals(b) || b.getPhysicalSpace().equals(a);
	}

	/**
	 * The exclusive end of the code decoded linearly (bytes only, via the pseudo disassembler) from
	 * {@code offset}: through the first return or unconditional jump, AT the first call (the bytes
	 * after a {@code JSR} are often its inline arguments, see
	 * {@link InlineJumpTableDispatch#decodesAsCode}), or before the first undefined opcode, {@code
	 * BRK}, or the {@link #EXTENT_MAX_STEPS} budget. An undecodable target has an empty extent
	 * ({@code offset} itself).
	 */
	static long decodedExtentEnd(PseudoDisassembler dis, AddressSpace space, long offset) {
		Address at;
		try {
			at = space.getAddress(offset);
		}
		catch (RuntimeException e) {
			return offset;
		}
		long end = offset;
		for (int i = 0; i < EXTENT_MAX_STEPS && at != null; i++) {
			ghidra.program.model.listing.Instruction instr;
			try {
				instr = dis.disassemble(at);
			}
			catch (Exception e) {
				break; // undefined opcode, or bytes run out mid-instruction
			}
			if (instr == null || "BRK".equals(instr.getMnemonicString())) {
				break;
			}
			end = at.getOffset() + instr.getLength();
			FlowType flow = instr.getFlowType();
			if (flow.isTerminal() || (flow.isJump() && !flow.isConditional()) || flow.isCall()) {
				break;
			}
			at = instr.getFallThrough();
		}
		return end;
	}
}
