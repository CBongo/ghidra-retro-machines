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
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;

/**
 * A local proof that a 65816 routine returns to its caller (bead grm-9nxj.39), the 65816
 * counterpart of {@link ProvablyReturningFlagAnalyzer#selfContainedReturn}, which a 65816 body
 * almost never passes: it refuses every push, pull and call, and 65816 routines bracket their
 * bodies with {@code PHP}/{@code PLP} and call freely.
 * <p>
 * Every path from the entry is walked, loops included, tracking the stack depth in bytes this
 * routine has pushed: {@code PHA}/{@code PLA} by the M flag at the instruction,
 * {@code PHX}/{@code PHY}/{@code PLX}/{@code PLY} by X, {@code PHP}/{@code PHB}/{@code PHK} and
 * their pulls one byte, {@code PHD}/{@code PLD}/{@code PEA}/{@code PEI}/{@code PER} two. The
 * proof holds when every address is reached at one depth, no pull goes below the entry depth
 * (into the return address), and every leaf is an {@code RTS} at depth 0, or every leaf an
 * {@code RTL} at depth 0; at least one leaf must exist. A direct call is stepped over (it
 * returns with the stack it found) unless its callee carries Ghidra's no-return flag. It
 * declines on a width it cannot read, computed flow, a call that does not fall through, a jump
 * into another function's entry (a tail call), {@code RTI}, {@code BRK}, {@code COP},
 * {@code STP}, {@code TXS}, {@code TCS}, {@code XCE}, a missing instruction, or more than
 * {@link #MAX_WALK} instructions.
 */
final class W65816ReturnProof {

	/** Cap on instructions visited. */
	static final int MAX_WALK = 4096;

	private W65816ReturnProof() {
	}

	/**
	 * The return mnemonic ({@code "RTS"} or {@code "RTL"}) every path from {@code entry} ends
	 * in with the stack it found, or null when that is not proven.
	 */
	static String provenReturn(Program program, Address entry) {
		if (!W65816WidthEffects.applies(program)) {
			return null;
		}
		W65816WidthEffects fx = new W65816WidthEffects(program);
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		Map<Address, Integer> depthAt = new HashMap<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		ArrayDeque<Integer> depths = new ArrayDeque<>();
		work.push(entry);
		depths.push(0);
		String kind = null;
		while (!work.isEmpty()) {
			Address at = work.pop();
			int d = depths.pop();
			Integer seen = depthAt.get(at);
			if (seen != null) {
				if (seen != d) {
					return null; // two paths meet with different stacks
				}
				continue;
			}
			depthAt.put(at, d);
			if (depthAt.size() > MAX_WALK) {
				return null;
			}
			Instruction i = listing.getInstructionAt(at);
			if (i == null) {
				return null;
			}
			if (W65816Shapes.isReturn(i)) {
				String rk = W65816Shapes.returnKind(i);
				if (d != 0 || (kind != null && !kind.equals(rk))) {
					return null;
				}
				kind = rk;
				continue;
			}
			// RTI stays explicit (R4) and XCE is a mode change, invisible in p-code (R2); BRK, COP
			// and STP are computed jumps and fall to the isComputed test below; TXS/TCS rewrite SP.
			if (MosOperands.isInterruptReturn(i) || W65816Shapes.rebasesStack(i) ||
				i.getMnemonicString().equalsIgnoreCase("XCE")) {
				return null;
			}
			int delta = stackDelta(fx, i);
			if (delta == Integer.MIN_VALUE) {
				return null; // width unknown
			}
			d += delta;
			if (d < 0) {
				return null; // pulls the caller's return address
			}
			FlowType ft = i.getFlowType();
			if (ft.isComputed()) {
				return null;
			}
			if (ft.isCall()) {
				if (!ft.hasFallthrough()) {
					return null;
				}
				for (Address t : i.getFlows()) {
					Function callee = fm.getFunctionAt(t);
					if (callee != null && callee.hasNoReturn()) {
						return null;
					}
				}
			}
			else if (ft.isJump()) {
				for (Address t : i.getFlows()) {
					if (!t.equals(entry) && fm.getFunctionAt(t) != null) {
						return null; // a tail jump: returns wherever that function does
					}
					work.push(t);
					depths.push(d);
				}
			}
			if (i.hasFallthrough()) {
				Address ft2 = i.getFallThrough();
				if (ft2 == null) {
					return null;
				}
				work.push(ft2);
				depths.push(d);
			}
			else if (!ft.isJump()) {
				return null; // ends without a return (e.g. a halt)
			}
		}
		return kind;
	}

	/** Bytes {@code i} pushes (negative: pulls), or {@link Integer#MIN_VALUE} if unknown. */
	private static int stackDelta(W65816WidthEffects fx, Instruction i) {
		W65816Shapes.Push push = W65816Shapes.push(i);
		W65816Shapes.Pull pull = W65816Shapes.pull(i);
		if (push == null && pull == null) {
			return 0;
		}
		// The byte count comes from the p-code, but this proof bails when the width the
		// instruction was decoded at is not a known context value (the width source is kept).
		W65816Shapes.Role role = push != null ? push.role() : pull.role();
		int known = switch (role) {
			case A -> bytes(fx.flag(i, fx.mRegister()));
			case X, Y -> bytes(fx.flag(i, fx.xRegister()));
			default -> 0;
		};
		if (known == Integer.MIN_VALUE) {
			return Integer.MIN_VALUE;
		}
		return push != null ? push.bytes() : -pull.bytes();
	}

	/** A register's size in bytes from its width flag (1 = 8-bit), or MIN_VALUE if unknown. */
	private static int bytes(int flag) {
		return flag == 1 ? 1 : flag == 0 ? 2 : Integer.MIN_VALUE;
	}

}
