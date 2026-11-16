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

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

/**
 * Measures how many caller frames a 6502 subroutine discards: its UNWIND LEVEL (grm-ed6h,
 * grm-0fzb). A normal subroutine is level 0. A "pop-return" helper that drops the two
 * return-address bytes its {@code JSR} pushed is level 1: it continues to its CALLER'S caller, so
 * the {@code JSR} never falls through. Three shapes reach level 1 and are one idiom:
 * <ul>
 * <li>{@code PLA / PLA / RTS} (Metroid {@code c376}: {@code LDA #$00 / STA $07a1,X / PLA / PLA /
 * RTS});</li>
 * <li>the inline-table JumpEngine ({@code ASL A / TAY / PLA / STA / PLA / STA / ... JMP (ind)},
 * smb {@code 8e04}), whose dispatched target returns to the caller's caller;</li>
 * <li>the inline-argument far-call trampoline ({@code PLA / PLA}, read the bytes after the
 * {@code JSR}, {@code JMP (ind)}: dbz_saiyan {@code c9c2}).</li>
 * </ul>
 * {@code PLA} x4 before {@code RTS} is level 2, and so on.
 *
 * <p>The walk follows every path from the entry through the listing's existing instructions
 * (both arms of a conditional branch, the target of a {@code JMP abs}), tracking the stack depth
 * relative to entry: {@code PHA/PHP} +1, {@code PLA/PLP} -1, and {@code TSX ... TXS} through X's
 * offset from the entry stack pointer (so {@code TSX / INX / INX / TXS} is -2). An EXIT is:
 * <ul>
 * <li>{@code RTS} at depth {@code d}: level {@code -d/2};</li>
 * <li>an indirect {@code JMP} at a negative depth {@code d}: a tail call into code that returns
 * normally, so the same as {@code RTS} at {@code d} (at depth 0 it is declined: nothing says the
 * function returns at all);</li>
 * <li>a {@code JSR} to a callee of level {@code k >= 1} at depth {@code d}: the callee drops its
 * own frame plus {@code k-1} of ours, so the same as {@code RTS} at {@code d - 2(k-1)}. A far-call
 * stub ({@code JSR helper} + inline bytes, dbz_saiyan {@code c2ad}) is therefore level 0: it
 * returns to its own caller.</li>
 * </ul>
 * Every exit must agree on one level. Anything else on any path is a decline: exits at different
 * levels (Metroid {@code c36b}'s {@code BCC} to the shared RTS), an odd exit depth, an
 * {@code RTI}/{@code BRK}, a {@code TXS} from an untracked X (a stack reset such as
 * {@code LDX #$FF / TXS}: a genuinely non-returning routine stays declined), a {@code JSR} that
 * does not fall through to a callee not known to unwind, a depth outside a small window, or no
 * exit at all (an infinite loop). A {@code JSR} to any other callee is assumed stack-neutral.
 *
 * <p>A path through a NON-overlay block that overlay banks overlap is also a decline: that block
 * is the base-space copy of a switchable window, holding whichever bank the loader laid there,
 * not necessarily the one live at the call (dodge {@code 800c} and smb3 {@code b44a} were
 * recognized on those bytes and cost each row hundreds of real instructions). Overlay blocks
 * (bank already resolved) and fixed blocks (Metroid {@code c376}) are trusted.
 *
 * @see <a href="urn:bead:grm-ed6h">grm-ed6h</a>
 * @see <a href="urn:bead:grm-0fzb">grm-0fzb</a>
 */
final class PopReturnHelper {

	/** Not measurable: mixed exit levels, an unsupported instruction, or no exit. */
	static final int DECLINE = -1;
	/** Every exit returns to the direct caller. */
	static final int NORMAL = 0;

	/** Return-address bytes a 6502 JSR pushes. */
	static final int RETURN_BYTES = 2;
	static final int MAX_LEVEL = 3;
	private static final int MIN_DEPTH = -RETURN_BYTES * MAX_LEVEL;
	private static final int MAX_DEPTH = 16;
	private static final int MAX_STATES = 512;

	private PopReturnHelper() {
	}

	/** Walk state: an address, the stack depth there, and X's offset from the entry SP or null. */
	private record State(Address addr, int depth, Integer xRel) {
	}

	/**
	 * Per-program memo of unwind levels, resolving callees recursively. Conclusive answers are
	 * cached; an inconclusive one is asked again next time. A call cycle reads as a decline.
	 */
	static final class Levels {
		private final Program program;
		private final Map<Address, Integer> cache = new HashMap<>();
		private final Set<Address> inProgress = new HashSet<>();

		Levels(Program program) {
			this.program = program;
		}

		/** Returns the unwind level of the subroutine at {@code entry}, or null if inconclusive. */
		Integer of(Address entry) {
			Integer cached = cache.get(entry);
			if (cached != null) {
				return cached;
			}
			if (!inProgress.add(entry)) {
				return DECLINE;
			}
			Integer level;
			try {
				level = unwindLevel(program, entry, this::of);
			}
			finally {
				inProgress.remove(entry);
			}
			if (level != null) {
				cache.put(entry, level);
			}
			return level;
		}
	}

	/** Level 1 or more: a {@code JSR} to {@code entry} never falls through. */
	static Boolean recognize(Program program, Address entry) {
		Integer level = new Levels(program).of(entry);
		return level == null ? null : level >= 1;
	}

	/**
	 * Measures the subroutine at {@code entry}.
	 *
	 * @param callee the unwind level of a called subroutine, or null if not yet known
	 * @return the unwind level ({@link #NORMAL}, 1..{@link #MAX_LEVEL}), {@link #DECLINE}, or null
	 *     if a path runs into an address that has no instruction yet
	 */
	static Integer unwindLevel(Program program, Address entry,
			Function<Address, Integer> callee) {
		Listing listing = program.getListing();
		ArrayDeque<State> work = new ArrayDeque<>();
		Set<State> seen = new HashSet<>();
		Map<MemoryBlock, Boolean> ambiguous = new HashMap<>();
		work.add(new State(entry, 0, null));
		Integer level = null;
		while (!work.isEmpty()) {
			State s = work.poll();
			if (!seen.add(s)) {
				continue;
			}
			if (seen.size() > MAX_STATES) {
				return DECLINE;
			}
			Instruction instr = listing.getInstructionAt(s.addr());
			if (instr == null) {
				return null;
			}
			MemoryBlock block = program.getMemory().getBlock(s.addr());
			if (block == null || ambiguous.computeIfAbsent(block,
				b -> !b.isOverlay() && SplitDispatchTableAnalyzer.isBanked(program, b))) {
				return DECLINE;
			}
			String mn = instr.getMnemonicString();
			int depth = s.depth();
			Integer xRel = s.xRel();
			Integer exitDepth = null;
			switch (mn) {
				case "PHA", "PHP" -> depth++;
				case "PLA", "PLP" -> depth--;
				// S = S0 - depth, so TSX leaves X = S0 - depth: track X relative to S0
				case "TSX" -> xRel = -depth;
				case "INX" -> xRel = xRel == null ? null : xRel + 1;
				case "DEX" -> xRel = xRel == null ? null : xRel - 1;
				case "LDX", "TAX" -> xRel = null;
				case "TXS" -> {
					if (xRel == null) {
						return DECLINE;
					}
					depth = -xRel;
				}
				case "RTS" -> exitDepth = depth;
				case "RTI", "BRK" -> {
					return DECLINE;
				}
				default -> {
					// fall through to the flow handling below
				}
			}
			if (depth < MIN_DEPTH || depth > MAX_DEPTH) {
				return DECLINE;
			}
			FlowType flow = instr.getFlowType();
			if (exitDepth == null && flow.isCall()) {
				Address[] targets = instr.getFlows();
				Integer k = targets.length == 1 ? callee.apply(targets[0]) : null;
				if (k != null && k >= 1) {
					exitDepth = depth - RETURN_BYTES * (k - 1);
				}
				else if (instr.getFallThrough() != null) {
					work.add(new State(instr.getFallThrough(), depth, xRel));
					continue;
				}
				else {
					return k == null ? null : DECLINE;
				}
			}
			if (exitDepth == null && flow.isComputed() && flow.isJump()) {
				if (depth >= 0) {
					return DECLINE;
				}
				exitDepth = depth;
			}
			if (exitDepth != null) {
				if (exitDepth > 0 || exitDepth % RETURN_BYTES != 0) {
					return DECLINE;
				}
				int exitLevel = -exitDepth / RETURN_BYTES;
				if (exitLevel > MAX_LEVEL || (level != null && level != exitLevel)) {
					return DECLINE;
				}
				level = exitLevel;
				continue;
			}
			if (flow.isComputed() || (flow.isTerminal() && !flow.isJump())) {
				return DECLINE;
			}
			if (flow.isJump()) {
				Address[] targets = instr.getFlows();
				if (targets.length != 1) {
					return DECLINE;
				}
				work.add(new State(targets[0], depth, xRel));
			}
			Address ft = instr.getFallThrough();
			if (ft != null) {
				work.add(new State(ft, depth, xRel));
			}
			else if (!flow.isJump()) {
				return DECLINE;
			}
		}
		return level == null ? DECLINE : level;
	}
}
