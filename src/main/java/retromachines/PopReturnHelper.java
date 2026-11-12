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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;

/**
 * Recognizes a 6502 "pop-return" helper (grm-ed6h): a subroutine whose every exit discards the
 * two return-address bytes its {@code JSR} pushed, so it returns to its CALLER'S caller and the
 * {@code JSR} never falls through. Metroid {@code c376}: {@code LDA #$00 / STA $07a1,X / PLA /
 * PLA / RTS}.
 *
 * <p>The walk follows every path from the entry through the listing's existing instructions
 * (both arms of a conditional branch, the target of a {@code JMP abs}), tracking the stack depth
 * relative to entry: {@code PHA/PHP} +1, {@code PLA/PLP} -1, and {@code TSX ... TXS} through X's
 * offset from the entry stack pointer (so {@code TSX / INX / INX / TXS} is -2). The helper is
 * recognized only if EVERY path ends in an {@code RTS} at depth exactly -2. Anything else on any
 * path is a decline, because one normally-returning path would make the call fall through:
 * an {@code RTS} at another depth (Metroid {@code c36b}'s {@code BCC} to the shared RTS), an
 * {@code RTI}/{@code BRK}, an indirect {@code JMP} (the JumpEngine shape, which
 * {@link InlineJumpTableDispatchAnalyzer} owns), a {@code TXS} from an untracked X, a call that
 * does not fall through (its callee might be a pop-return helper itself, which would unwind
 * THIS helper's frame and return normally to our caller), or a depth outside a small window.
 * A {@code JSR} that does fall through is assumed stack-neutral.
 *
 * <p>A path through a NON-overlay block that overlay banks overlap is also a decline: that block
 * is the base-space copy of a switchable window, holding whichever bank the loader laid there,
 * not necessarily the one live at the call (dodge {@code 800c} and smb3 {@code b44a} were
 * recognized on those bytes and cost each row hundreds of real instructions). Overlay blocks
 * (bank already resolved) and fixed blocks (Metroid {@code c376}) are trusted.
 *
 * <p>Returns {@code null} (inconclusive, ask again later) when a path reaches an address with
 * no instruction yet.
 *
 * @see <a href="urn:bead:grm-ed6h">grm-ed6h</a>
 */
final class PopReturnHelper {

	/** Return-address bytes a 6502 JSR pushes. */
	static final int RETURN_BYTES = 2;
	private static final int MIN_DEPTH = -RETURN_BYTES;
	private static final int MAX_DEPTH = 16;
	private static final int MAX_STATES = 512;

	private PopReturnHelper() {
	}

	/** Walk state: an address, the stack depth there, and X's offset from the entry SP or null. */
	private record State(Address addr, int depth, Integer xRel) {
	}

	/**
	 * Classifies the subroutine at {@code entry}.
	 *
	 * @return TRUE for a pop-return helper, FALSE for a conclusive decline, null if a path runs
	 *     into an address that has no instruction yet
	 */
	static Boolean recognize(Program program, Address entry) {
		Listing listing = program.getListing();
		ArrayDeque<State> work = new ArrayDeque<>();
		Set<State> seen = new HashSet<>();
		Map<MemoryBlock, Boolean> ambiguous = new HashMap<>();
		work.add(new State(entry, 0, null));
		int exits = 0;
		while (!work.isEmpty()) {
			State s = work.poll();
			if (!seen.add(s)) {
				continue;
			}
			if (seen.size() > MAX_STATES) {
				return Boolean.FALSE;
			}
			Instruction instr = listing.getInstructionAt(s.addr());
			if (instr == null) {
				return null;
			}
			MemoryBlock block = program.getMemory().getBlock(s.addr());
			if (block == null || ambiguous.computeIfAbsent(block,
				b -> !b.isOverlay() && SplitDispatchTableAnalyzer.isBanked(program, b))) {
				return Boolean.FALSE;
			}
			String mn = instr.getMnemonicString();
			int depth = s.depth();
			Integer xRel = s.xRel();
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
						return Boolean.FALSE;
					}
					depth = -xRel;
				}
				case "RTS" -> {
					if (depth != -RETURN_BYTES) {
						return Boolean.FALSE;
					}
					exits++;
					continue;
				}
				case "RTI", "BRK" -> {
					return Boolean.FALSE;
				}
				default -> {
					// fall through to the flow handling below
				}
			}
			if (depth < MIN_DEPTH || depth > MAX_DEPTH) {
				return Boolean.FALSE;
			}
			FlowType flow = instr.getFlowType();
			if (flow.isCall()) {
				if (instr.getFallThrough() == null) {
					return Boolean.FALSE;
				}
				work.add(new State(instr.getFallThrough(), depth, xRel));
				continue;
			}
			if (flow.isComputed() || (flow.isTerminal() && !flow.isJump())) {
				return Boolean.FALSE;
			}
			if (flow.isJump()) {
				Address[] targets = instr.getFlows();
				if (targets.length != 1) {
					return Boolean.FALSE;
				}
				work.add(new State(targets[0], depth, xRel));
			}
			Address ft = instr.getFallThrough();
			if (ft != null) {
				work.add(new State(ft, depth, xRel));
			}
			else if (!flow.isJump()) {
				return Boolean.FALSE;
			}
		}
		return exits > 0 ? Boolean.TRUE : Boolean.FALSE;
	}
}
