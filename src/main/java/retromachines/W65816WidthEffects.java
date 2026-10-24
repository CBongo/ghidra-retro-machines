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
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;

/**
 * What a stretch of 65816 code does with the M and X width flags, read off the listing (bead
 * grm-9nxj.5.3). The 65816 decodes an accumulator immediate as one or two bytes depending on M,
 * and an index immediate depending on X, so a routine decoded under the wrong inherited width is
 * mis-lengthed from its first such immediate on. Whether that happens is a property of the code,
 * not of the context Ghidra happened to decode it under:
 * <ul>
 * <li>a routine NEEDS a flag if some path from its entry reaches a length-sensitive immediate
 * for that flag before a {@code REP}/{@code SEP} sets it -- FF2's {@code $03:83B9} starts with
 * {@code REP #$20} and needs nothing, however its callers' widths differ;</li>
 * <li>a routine SETS a flag to {@code c} if every {@code RTS}/{@code RTL} it reaches is preceded on
 * its path by a {@code REP}/{@code SEP} leaving it {@code c}; it PRESERVES it if no path touches
 * it; anything else is mixed or unknown.</li>
 * </ul>
 *
 * <p>The walk follows fall-through and jump flows. A direct call inside the walked code is
 * summarized recursively: what the callee needs counts while the flag is still inherited, and the
 * flag afterwards is what the callee leaves (a call already on the walk stack is taken to preserve
 * both and need neither). {@code PLP}, {@code XCE} and a {@code REP}/{@code SEP} whose operand is not a constant make a
 * flag unknown. Computed jumps end a path. Emulation-mode code (E=1) has both flags forced to 1
 * and is never reported as needing either.
 *
 * <p>{@code tools/banktest/W65816WidthDump.java} computes the same thing independently, as the
 * yardstick this is judged by on the {@code snes-analysis} real-ROM rows; a disagreement between
 * the two is itself a finding.
 */
final class W65816WidthEffects {

	/** A flag's state along a path: inherited from the entry, set to 0 or 1, or unknown. */
	static final int INHERITED = -1;
	static final int UNKNOWN = 2;
	/** A routine's exit summary when no return was reached at all. */
	static final int NO_RETURN = 3;

	/** Bound on (address, state) pairs visited per walk, so a pathological listing stays cheap. */
	private static final int WALK_LIMIT = 4000;

	private static final Set<String> M_IMMEDIATES =
		Set.of("LDA", "ADC", "SBC", "CMP", "AND", "ORA", "EOR", "BIT");
	private static final Set<String> X_IMMEDIATES = Set.of("LDX", "LDY", "CPX", "CPY");

	/**
	 * One flag's behaviour in a routine.
	 *
	 * @param needs whether a length-sensitive immediate is reached while the flag is inherited
	 * @param exit {@link #INHERITED} (preserved), 0 or 1 (set on every return), {@link #UNKNOWN}
	 *     (mixed or unknown), or {@link #NO_RETURN}
	 */
	record Flag(boolean needs, int exit) {

		/** Whether every return leaves the flag at one known value. */
		boolean setsConstant() {
			return exit == 0 || exit == 1;
		}
	}

	/** Both flags' behaviour. */
	record Effect(Flag m, Flag x) {}

	private final Listing listing;
	private final Register ctxE;
	private final Register ctxM;
	private final Register ctxX;
	private final Map<Address, Effect> cache = new HashMap<>();
	/** Entries whose walk is on the stack, so a recursive call is not walked again. */
	private final Set<Address> inProgress = new HashSet<>();

	W65816WidthEffects(Program program) {
		this.listing = program.getListing();
		this.ctxE = program.getRegister("ctx_EF");
		this.ctxM = program.getRegister("ctx_MF");
		this.ctxX = program.getRegister("ctx_XF");
	}

	/** Whether the program's language carries the 65816 width context this class reads. */
	static boolean applies(Program program) {
		return program.getRegister("ctx_EF") != null && program.getRegister("ctx_MF") != null &&
			program.getRegister("ctx_XF") != null;
	}

	Register mRegister() {
		return ctxM;
	}

	Register xRegister() {
		return ctxX;
	}

	/** The value of a context flag at an instruction, or -1 when it has none. */
	int flag(Instruction instr, Register reg) {
		BigInteger v = instr.getValue(reg, false);
		return v == null ? -1 : v.intValue();
	}

	/** Whether the instruction was decoded in emulation mode. */
	boolean emulation(Instruction instr) {
		return flag(instr, ctxE) == 1;
	}

	/** Forgets cached summaries, after the listing they were read from has changed. */
	void invalidate() {
		cache.clear();
	}

	/**
	 * The width behaviour of the code starting at {@code entry}: a routine entry, or the
	 * continuation after a call.
	 */
	Effect effect(Address entry) {
		Effect cached = cache.get(entry);
		if (cached != null) {
			return cached;
		}
		inProgress.add(entry);
		boolean needsM = false;
		boolean needsX = false;
		Set<Integer> exitM = new TreeSet<>();
		Set<Integer> exitX = new TreeSet<>();
		Set<Long> seen = new HashSet<>();
		ArrayDeque<long[]> work = new ArrayDeque<>();
		work.push(new long[] { entry.getOffset(), INHERITED, INHERITED });
		int steps = 0;
		while (!work.isEmpty() && steps++ < WALK_LIMIT) {
			long[] w = work.pop();
			int m = (int) w[1];
			int x = (int) w[2];
			// 24-bit address plus two 2-bit states fits a long key.
			if (!seen.add((w[0] << 8) | ((m + 1) << 4) | (x + 1))) {
				continue;
			}
			Address a = entry.getNewAddress(w[0]);
			Instruction in = listing.getInstructionAt(a);
			if (in == null || emulation(in)) {
				continue;
			}
			String mn = in.getMnemonicString().toUpperCase();
			boolean imm = in.getNumOperands() > 0 &&
				in.getDefaultOperandRepresentation(0).startsWith("#");
			needsM |= imm && m == INHERITED && M_IMMEDIATES.contains(mn);
			needsX |= imm && x == INHERITED && X_IMMEDIATES.contains(mn);
			if (mn.equals("REP") || mn.equals("SEP")) {
				int bits = constantOperand(in);
				int v = mn.equals("SEP") ? 1 : 0;
				if (bits < 0) {
					m = UNKNOWN;
					x = UNKNOWN;
				}
				else {
					m = (bits & 0x20) != 0 ? v : m;
					x = (bits & 0x10) != 0 ? v : x;
				}
			}
			else if (mn.equals("PLP") || mn.equals("XCE")) {
				m = UNKNOWN;
				x = UNKNOWN;
			}
			if (mn.equals("RTS") || mn.equals("RTL")) {
				exitM.add(m);
				exitX.add(x);
				continue;
			}
			FlowType ft = in.getFlowType();
			if (ft.isTerminal() || (ft.isComputed() && ft.isJump())) {
				continue;
			}
			if (ft.isCall() && !ft.isComputed()) {
				// A direct call: what the callee needs counts while the flag is still inherited
				// here, and the flag afterwards is what the callee leaves (CT $C1:03F1 starts
				// with JSR $104E, which needs M=1 -- the continuation needs it through the call).
				int mAfter = m;
				int xAfter = x;
				for (Address t : in.getFlows()) {
					Effect ce = inProgress.contains(t) ? null : effect(t);
					if (ce == null) {
						continue;   // recursion: treat as preserving, needing nothing
					}
					needsM |= m == INHERITED && ce.m().needs();
					needsX |= x == INHERITED && ce.x().needs();
					mAfter = after(m, ce.m().exit());
					xAfter = after(x, ce.x().exit());
				}
				m = mAfter;
				x = xAfter;
			}
			if (ft.isJump()) {
				for (Address t : in.getFlows()) {
					work.push(new long[] { t.getOffset(), m, x });
				}
			}
			Address next = in.getFallThrough();
			if (next != null) {
				work.push(new long[] { next.getOffset(), m, x });
			}
		}
		Effect e = new Effect(new Flag(needsM, summarize(exitM)),
			new Flag(needsX, summarize(exitX)));
		inProgress.remove(entry);
		cache.put(entry, e);
		return e;
	}

	/** A flag's state after a call, given its state before and the callee's exit summary. */
	private static int after(int before, int calleeExit) {
		if (calleeExit == INHERITED) {
			return before;
		}
		return calleeExit == 0 || calleeExit == 1 ? calleeExit : UNKNOWN;
	}

	private static int summarize(Set<Integer> exits) {
		if (exits.isEmpty()) {
			return NO_RETURN;
		}
		return exits.size() > 1 ? UNKNOWN : exits.iterator().next();
	}

	private static int constantOperand(Instruction in) {
		Object[] objs = in.getOpObjects(0);
		if (objs.length == 1 && objs[0] instanceof Scalar s) {
			return (int) s.getUnsignedValue();
		}
		return -1;
	}
}
