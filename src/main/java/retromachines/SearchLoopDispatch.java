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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

/**
 * The cases of a jump table indexed by a KEYED LINEAR SEARCH (grm-jt7s), read exactly from the
 * index values the search can leave in {@code Y}. megaman's bank 5:
 * <pre>
 *   9998  LDY #$2d            ; the last 3-byte (id, lo, hi) record
 *   999f  CMP $99bb,Y   &lt;-+  ; L: compare this record's id
 *   99a2  BEQ $99ab       |  ; found
 *   99a4  DEY / DEY / DEY |  ; previous record
 *   99a7  BPL $999f    ---+
 *   99a9  LDY #$00           ; not found: the first record
 *   99ab  LDA $99bc,Y        ; J
 *   99ae  STA $04 / LDA $99bd,Y / STA $05
 *   99b5  JMP ($0004)
 * </pre>
 * Nothing bounds {@code Y} for the decompiler at the switch, so it reads the two loads at stride 1
 * over 0..256: 257 cases and 184 distinct targets, against 16 records and 9 real targets. No
 * extent rule in {@link JumpTableBound} can cut that, because the real cases are every third one.
 *
 * <p>So this recognizes the loop instead. Y at J is either a value the loop held when its branch
 * to J was taken ({@code n, n-k, ...} while BPL still loops, i.e. while bit 7 is clear) or the
 * immediate of an {@code LDY #imm} that falls into J. The guards keep that claim exact: no
 * instruction from J to the switch writes Y or is entered from anywhere else; J is entered only
 * by that fall-through and that one branch; the loop body from L to the branch writes no Y and is
 * entered only at L, and L only from its own BPL and the straight-line run down from the
 * {@code LDY #n}. Each target is read from the two table bytes at that index. And every target
 * must be one the decompiler also read, so this can only ever shrink a table.
 */
final class SearchLoopDispatch {

	/** How many instructions a straight-line run here may span before the shape is refused. */
	private static final int MAX_RUN = 16;

	private SearchLoopDispatch() {
	}

	/**
	 * The values {@code LDY #start / L: ... / DEY x step / BPL L} holds at L: {@code start},
	 * then down by {@code step} while bit 7 stays clear. Null for a start BPL would not loop on
	 * (bit 7 set) or a step outside 1..8.
	 */
	static List<Integer> loopValues(int start, int step) {
		if (start < 0 || start > 0x7f || step < 1 || step > 8) {
			return null;
		}
		List<Integer> values = new ArrayList<>();
		for (int y = start; y >= 0; y -= step) {
			values.add(y);
		}
		return values;
	}

	/**
	 * The switch's cases, one per index value in ascending order (duplicate targets kept, as a
	 * table holds them), each the {@code realCases} address with that offset; null when the shape
	 * is not this one, a table byte is unreadable, or a target is not among {@code realCases}.
	 */
	static List<Address> cases(Program program, Instruction switchInstr, List<Address> realCases) {
		Register y = program.getRegister("Y");
		Listing listing = program.getListing();
		if (y == null || !switchInstr.getFlowType().isJump() ||
			!switchInstr.getFlowType().isComputed()) {
			return null;
		}
		Long pointer = scalarOperand(switchInstr);
		if (pointer == null) {
			return null;
		}

		// The run from the join J down to the switch: straight-line, entered only at J, no Y write.
		List<Instruction> run = new ArrayList<>();
		Instruction join = switchInstr;
		for (int i = 0; ; i++) {
			if (i >= MAX_RUN || MosOperands.writesRegister(join, y)) {
				return null;
			}
			run.add(0, join);
			if (hasIncomingFlow(program, join)) {
				break;
			}
			Instruction prev = FlowEdges.fallThroughPredecessor(listing, join);
			if (prev == null) {
				return null;
			}
			join = prev;
		}

		// LDA base,Y / STA zp pairs in the run, filling the switch's pointer low then high byte.
		Map<Long, Long> baseByZp = new LinkedHashMap<>();
		for (int i = 0; i + 1 < run.size(); i++) {
			Long base = yIndexedLoadBase(run.get(i), y);
			Instruction store = run.get(i + 1);
			if (base != null && "STA".equalsIgnoreCase(store.getMnemonicString())) {
				Long zp = scalarOperand(store);
				if (zp != null) {
					baseByZp.put(zp, base);
				}
			}
		}
		Long loBase = baseByZp.get(pointer);
		Long hiBase = baseByZp.get(pointer + 1);
		if (loBase == null || hiBase == null) {
			return null;
		}

		// J's predecessors: one search branch, and optionally an LDY #imm falling into it.
		Set<Integer> values = new LinkedHashSet<>();
		Instruction fallback = FlowEdges.fallThroughPredecessor(listing, join);
		if (fallback != null) {
			Integer imm = ldyImmediate(fallback);
			if (imm == null) {
				return null;
			}
			values.add(imm);
		}
		List<Reference> in = incomingFlow(program, join);
		if (in.size() != 1) {
			return null;
		}
		Instruction branch = listing.getInstructionAt(in.get(0).getFromAddress());
		List<Integer> loop = branch == null ? null : searchLoopValues(program, branch, y);
		if (loop == null) {
			return null;
		}
		values.addAll(loop);

		// Read each target, and require the decompiler to have read it too.
		Map<Long, Address> byOffset = new LinkedHashMap<>();
		for (Address a : realCases) {
			byOffset.putIfAbsent(a.getOffset(), a);
		}
		AddressSpace space = switchInstr.getAddress().getAddressSpace();
		List<Integer> sorted = new ArrayList<>(values);
		sorted.sort(null);
		List<Address> cases = new ArrayList<>(sorted.size());
		for (int index : sorted) {
			long target;
			try {
				int lo = program.getMemory().getByte(space.getAddress(loBase + index)) & 0xff;
				int hi = program.getMemory().getByte(space.getAddress(hiBase + index)) & 0xff;
				target = (hi << 8) | lo;
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
				return null;
			}
			Address a = byOffset.get(target);
			if (a == null) {
				return null;
			}
			cases.add(a);
		}
		return cases;
	}

	/**
	 * The values Y holds when the conditional {@code branch} is taken, when it sits in a search
	 * loop {@code LDY #n / ... / L: ... / branch / DEY x k / BPL L}; else null.
	 */
	private static List<Integer> searchLoopValues(Program program, Instruction branch, Register y) {
		Listing listing = program.getListing();
		if (!branch.getFlowType().isConditional()) {
			return null;
		}
		// After the branch: k DEYs, then the BPL back to L.
		int step = 0;
		Instruction cur = FlowEdges.nextFallThrough(listing, branch);
		while (cur != null && "DEY".equalsIgnoreCase(cur.getMnemonicString())) {
			step++;
			cur = FlowEdges.nextFallThrough(listing, cur);
		}
		if (cur == null || step == 0 || !"BPL".equalsIgnoreCase(cur.getMnemonicString()) ||
			cur.getFlows().length != 1) {
			return null;
		}
		Instruction bpl = cur;
		Instruction head = listing.getInstructionAt(bpl.getFlows()[0]);
		if (head == null || head.getMinAddress().compareTo(branch.getMinAddress()) > 0) {
			return null;
		}
		// L .. branch: straight-line, no Y write, entered only at L and L only from the BPL.
		for (Reference r : incomingFlow(program, head)) {
			if (!r.getFromAddress().equals(bpl.getMinAddress())) {
				return null;
			}
		}
		cur = head;
		for (int i = 0; ; i++) {
			if (i >= MAX_RUN || MosOperands.writesRegister(cur, y)) {
				return null;
			}
			if (cur.equals(branch)) {
				break;
			}
			cur = FlowEdges.nextFallThrough(listing, cur);
			if (cur == null || hasIncomingFlow(program, cur)) {
				return null;
			}
		}
		// Before L: a straight-line run up from an LDY #n, entered from nowhere else.
		Instruction before = head;
		for (int i = 0; i < MAX_RUN; i++) {
			Instruction prev = FlowEdges.fallThroughPredecessor(listing, before);
			if (prev == null) {
				return null;
			}
			Integer n = ldyImmediate(prev);
			if (n != null) {
				return loopValues(n, step);
			}
			if (MosOperands.writesRegister(prev, y) || hasIncomingFlow(program, prev)) {
				return null;
			}
			before = prev;
		}
		return null;
	}

	private static List<Reference> incomingFlow(Program program, Instruction instr) {
		List<Reference> flows = new ArrayList<>();
		for (Reference r : program.getReferenceManager().getReferencesTo(instr.getMinAddress())) {
			if (r.getReferenceType().isFlow()) {
				flows.add(r);
			}
		}
		return flows;
	}

	private static boolean hasIncomingFlow(Program program, Instruction instr) {
		return !incomingFlow(program, instr).isEmpty();
	}

	/** {@code n} for {@code LDY #n}, else null. */
	private static Integer ldyImmediate(Instruction instr) {
		if (!"LDY".equalsIgnoreCase(instr.getMnemonicString()) || instr.getLength() != 2) {
			return null;
		}
		Long v = scalarOperand(instr);
		return v == null || !instr.toString().contains("#") ? null : v.intValue() & 0xff;
	}

	/** The base of {@code LDA base,Y} (absolute, indexed by Y), else null. */
	private static Long yIndexedLoadBase(Instruction instr, Register y) {
		if (!"LDA".equalsIgnoreCase(instr.getMnemonicString()) || instr.getLength() != 3) {
			return null;
		}
		boolean byY = false;
		Long base = null;
		for (Object o : instr.getOpObjects(0)) {
			if (o instanceof Register r && r.equals(y)) {
				byY = true;
			}
			else if (o instanceof Scalar sc) {
				base = sc.getUnsignedValue();
			}
			else if (o instanceof Address a) {
				base = a.getOffset();
			}
		}
		return byY ? base : null;
	}

	/** The first operand's scalar or address value, else null. */
	private static Long scalarOperand(Instruction instr) {
		if (instr.getNumOperands() == 0) {
			return null;
		}
		for (Object o : instr.getOpObjects(0)) {
			if (o instanceof Scalar sc) {
				return sc.getUnsignedValue();
			}
			if (o instanceof Address a) {
				return a.getOffset();
			}
		}
		return null;
	}
}
