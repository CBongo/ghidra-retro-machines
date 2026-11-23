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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
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
 * returns with the stack it found) unless its callee carries Ghidra's no-return flag; a
 * {@code PHK / JSR} into a routine proven to return by {@code RTL} is a hand-rolled {@code JSL}
 * and also pulls the PHK byte (grm-9nxj.52). It
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
		return provenReturn(program, entry, new Proofs());
	}

	/**
	 * The nested proofs of one top-level question: those in progress (a cycle back into one
	 * declines) and those finished. Without the memo every {@code PHK / JSR} and pushed-return
	 * jump re-proved its callee from scratch, and FF2 timed out (grm-9nxj.52).
	 */
	private static final class Proofs {
		final Set<Address> active = new HashSet<>();
		final Map<Address, String> done = new HashMap<>();
	}

	private static String provenReturn(Program program, Address entry, Proofs active) {
		if (active.done.containsKey(entry)) {
			return active.done.get(entry);
		}
		if (!W65816WidthEffects.applies(program) || !active.active.add(entry)) {
			return null;
		}
		String kind;
		try {
			kind = walk(program, entry, active);
		}
		finally {
			active.active.remove(entry);
		}
		active.done.put(entry, kind);
		return kind;
	}

	private static String walk(Program program, Address entry, Proofs active) {
		W65816WidthEffects fx = new W65816WidthEffects(program);
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		Map<Address, Integer> depthAt = new HashMap<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		ArrayDeque<Integer> depths = new ArrayDeque<>();
		Set<Address> resumedAt = new HashSet<>();   // return addresses of pushed-return jumps
		work.push(entry);
		depths.push(0);
		String kind = null;
		while (!work.isEmpty()) {
			Address at = work.pop();
			int d = depths.pop();
			Integer seen = depthAt.get(at);
			if (seen != null) {
				if (seen != d) {
					return fail(entry, at, "paths meet at depths " + seen + " and " + d);
				}
				continue;
			}
			depthAt.put(at, d);
			if (depthAt.size() > MAX_WALK) {
				return fail(entry, at, "MAX_WALK");
			}
			Instruction i = listing.getInstructionAt(at);
			if (i == null && resumedAt.contains(at)) {
				String rk = rawReturn(program, at);
				if (rk != null && d == 0 && (kind == null || kind.equals(rk))) {
					kind = rk;
					continue;
				}
			}
			if (i == null) {
				return fail(entry, at, "no instruction");
			}
			if (W65816Shapes.isReturn(i)) {
				String rk = W65816Shapes.returnKind(i);
				if (d != 0 || (kind != null && !kind.equals(rk))) {
					return fail(entry, at, "return " + rk + " at depth " + d + " (kind so far " + kind + ")");
				}
				kind = rk;
				continue;
			}
			// RTI stays explicit (R4) and XCE is a mode change, invisible in p-code (R2); BRK, COP
			// and STP are computed jumps and fall to the isComputed test below; TXS/TCS rewrite SP.
			if (MosOperands.isInterruptReturn(i) || W65816Shapes.rebasesStack(i) ||
				i.getMnemonicString().equalsIgnoreCase("XCE")) {
				return fail(entry, at, "RTI / stack rebase / XCE");
			}
			int delta = stackDelta(fx, i);
			if (delta == Integer.MIN_VALUE) {
				return fail(entry, at, "width unknown"); // width unknown
			}
			d += delta;
			if (d < 0) {
				return fail(entry, at, "pulls below entry"); // pulls the caller's return address
			}
			FlowType ft = i.getFlowType();
			if (ft.isComputed()) {
				return fail(entry, at, "computed flow");
			}
			Resumed back = pushedReturn(program, listing, i, active);
			if (back != null) {
				resumedAt.add(back.cont());
				work.push(back.cont());
				depths.push(d - back.bytes());
				continue;
			}
			if (ft.isCall()) {
				if (!ft.hasFallthrough()) {
					return fail(entry, at, "call without fall-through");
				}
				for (Address t : i.getFlows()) {
					Function callee = fm.getFunctionAt(t);
					if (callee != null && callee.hasNoReturn()) {
						return fail(entry, at, "call into no-return " + t);
					}
				}
				if (handRolledJsl(program, listing, i, active)) {
					d -= 1;   // the callee's RTL also pulled the PHK byte (d >= 1: PHK pushed it)
				}
			}
			else if (ft.isJump()) {
				for (Address t : i.getFlows()) {
					if (!t.equals(entry) && fm.getFunctionAt(t) != null) {
						return fail(entry, at, "tail jump to " + t); // a tail jump: returns wherever that function does
					}
					work.push(t);
					depths.push(d);
				}
			}
			if (i.hasFallthrough()) {
				Address ft2 = i.getFallThrough();
				if (ft2 == null) {
					return fail(entry, at, "fall-through null");
				}
				work.push(ft2);
				depths.push(d);
			}
			else if (!ft.isJump()) {
				return fail(entry, at, "ends without a return"); // ends without a return (e.g. a halt)
			}
		}
		return kind;
	}

	/**
	 * Env-gated diagnostic (grm-9nxj.52): {@code GRM_RETPROOF_TRACE=1} prints, for every failed
	 * proof, the routine, the instruction where it failed, and why.
	 */
	private static final boolean TRACE = System.getenv("GRM_RETPROOF_TRACE") != null;

	private static String fail(Address entry, Address at, String why) {
		if (TRACE) {
			System.out.println("RETPROOF " + entry + " fails at " + at + ": " + why);
		}
		return null;
	}

	/**
	 * Whether {@code call} is a hand-rolled {@code JSL}: {@code PHK} immediately before a
	 * {@code JSR f} whose every path provably returns by {@code RTL} (grm-9nxj.52). The RTL pulls
	 * three bytes, the JSR's two and the PHK's bank, so control comes back to the JSR's
	 * fall-through with the PHK byte gone. F-Zero {@code $03:9A01 PHK / JSR $8015}, inside the
	 * callee of the far call at {@code $00:D0AA}: stepped over as a plain call, the routine's own
	 * RTL was left one byte deep, the proof failed, and the far call's continuation was never
	 * decoded.
	 */
	private static boolean handRolledJsl(Program program, Listing listing, Instruction call,
			Proofs active) {
		Address[] fl = call.getFlows();
		if (fl.length != 1 || W65816Shapes.callPushBytes(call) != 2) {
			return false;
		}
		Instruction p = adjacentBefore(listing, call);
		if (p == null || !W65816Shapes.pushesProgramBank(p)) {
			return false;
		}
		return "RTL".equals(provenReturn(program, fl[0], active));
	}

	/** Where a jump through a pushed return address comes back, and the bytes it pulled. */
	private record Resumed(Address cont, int bytes) {
	}

	/**
	 * A terminal jump that is a call through a pushed return address (grm-9nxj.52):
	 * {@code PEA r / JML f} into a routine proven to return by {@code RTS} comes back to
	 * {@code r + 1} in {@code f}'s bank, two bytes pulled; {@code PHK / PER r / JML f} into an
	 * {@code RTL} routine comes back to {@code r + 1} in this bank, three. F-Zero's RTL
	 * trampoline {@code $03:8015 PEA $86FB / JML $00:86A9}: the bank-0 routine's RTS lands on the
	 * {@code RTL} at {@code $00:86FC}, which returns to whoever called {@code $8015}. The walk
	 * continues at the return address -- in another routine, even another bank -- with that
	 * depth. Null when the shape or the callee's proof does not hold.
	 */
	private static Resumed pushedReturn(Program program, Listing listing, Instruction jmp,
			Proofs active) {
		FlowType ft = jmp.getFlowType();
		Address[] fl = jmp.getFlows();
		if (ft.isComputed() || ft.isConditional() || fl.length != 1 || jmp.hasFallthrough() ||
			!(ft.isJump() || ft.isCall())) {
			return null;
		}
		Instruction push = adjacentBefore(listing, jmp);
		int w = push == null ? -1 : W65816Shapes.pushedConstantWord(push);
		if (w < 0) {
			return null;
		}
		Instruction phk = adjacentBefore(listing, push);
		boolean far = phk != null && W65816Shapes.pushesProgramBank(phk);
		if (!(far ? "RTL" : "RTS").equals(provenReturn(program, fl[0], active))) {
			return null;
		}
		long bank = ((far ? jmp.getMinAddress() : fl[0]).getOffset() >> 16) & 0xff;
		Address cont = jmp.getMinAddress().getAddressSpace()
				.getAddress(bank << 16 | ((w + 1) & 0xffff));
		return new Resumed(cont, far ? 3 : 2);
	}

	private static Instruction adjacentBefore(Listing listing, Instruction in) {
		Instruction p = listing.getInstructionBefore(in.getMinAddress());
		return p != null && p.getMaxAddress().next() != null &&
			p.getMaxAddress().next().equals(in.getMinAddress()) ? p : null;
	}

	/**
	 * The return a pushed-return jump lands on when nothing has decoded it yet: a single
	 * {@code RTL} ({@code 6B}) or {@code RTS} ({@code 60}) byte in ROM, outside any instruction or
	 * defined data. Only flow through a pushed return address reaches such a byte, so no
	 * disassembly ever does (F-Zero's trampoline {@code $00:86FC RTL}). A one-byte return reads
	 * the same at every width, so the raw byte is safe to judge. Null otherwise.
	 */
	private static String rawReturn(Program program, Address at) {
		MemoryBlock block = program.getMemory().getBlock(at);
		Listing listing = program.getListing();
		if (block == null || !block.isInitialized() || block.isWrite() ||
			listing.getInstructionContaining(at) != null ||
			listing.getDefinedDataContaining(at) != null) {
			return null;
		}
		try {
			int b = program.getMemory().getByte(at) & 0xff;
			return b == 0x6b ? "RTL" : b == 0x60 ? "RTS" : null;
		}
		catch (MemoryAccessException e) {
			return null;
		}
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
