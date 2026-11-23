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
import java.util.Locale;
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
 * both and need neither). A {@code PLP} restores the flags the matching {@code PHP} on its path
 * saved (grm-9nxj.5.5), so a routine bracketed {@code PHP ... REP/SEP ... PLP} preserves its
 * caller's width -- CT's {@code $C3:0557}, behind a thunk 30 callers use. A {@code PLP} with no
 * {@code PHP} on its path, {@code XCE} and a {@code REP}/{@code SEP} whose operand is not a
 * constant make a flag unknown. A computed jump is followed into the targets analysis resolved
 * for it, and otherwise ends a path. Emulation-mode code (E=1) has both flags forced to 1
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

	/**
	 * Env-gated diagnostic (grm-9nxj.54): {@code GRM_WIDTHFX_TRACE=<hex entries, comma-separated>}
	 * prints, for each listed entry's summary walk, every exit it collects (return or tail call,
	 * with M and X there), every call whose callee summary made a flag unknown, and every
	 * {@code PLP} with no {@code PHP} on its path -- so a mixed exit is attributed to its paths.
	 */
	private static final Set<Long> TRACE = traceEntries();

	private static Set<Long> traceEntries() {
		String spec = System.getenv("GRM_WIDTHFX_TRACE");
		Set<Long> s = new HashSet<>();
		if (spec != null) {
			for (String t : spec.split(",")) {
				if (!t.isBlank()) {
					s.add(Long.parseLong(t.trim(), 16));
				}
			}
		}
		return s;
	}

	private static void trace(Address entry, Address at, String what, int m, int x) {
		if (TRACE.contains(entry.getOffset())) {
			System.out.println("WIDTHFX " + entry + " " + what + " at " + at + ": m=" + m + " x=" + x);
		}
	}

	private static final Set<String> M_IMMEDIATES =
		Set.of("LDA", "ADC", "SBC", "CMP", "AND", "ORA", "EOR", "BIT");
	private static final Set<String> X_IMMEDIATES = Set.of("LDX", "LDY", "CPX", "CPY");

	/**
	 * One flag's behaviour in a routine.
	 *
	 * @param needs whether a length-sensitive immediate is reached while the flag is inherited
	 * @param exit {@link #INHERITED} (preserved), 0 or 1 (set on every return), {@link #UNKNOWN}
	 *     (mixed or unknown), or {@link #NO_RETURN}
	 * @param outcomes every value the returns leave, as a mask of {@link #bit} over
	 *     {@link #INHERITED}, 0, 1 and {@link #UNKNOWN}; empty for {@link #NO_RETURN}. Mixed
	 *     returns that {@code exit} must call UNKNOWN can still resolve against a known caller
	 *     width (grm-9nxj.54): a routine some of whose returns preserve M and the rest
	 *     {@code SEP #$20}, called at M=1, returns at M=1.
	 */
	record Flag(boolean needs, int exit, int outcomes) {

		/** Whether every return leaves the flag at one known value. */
		boolean setsConstant() {
			return exit == 0 || exit == 1;
		}

		/**
		 * The values the flag can have after a call made with it at {@code before}
		 * ({@link #INHERITED}, 0, 1 or {@link #UNKNOWN}), as a mask of {@link #bit}; a callee
		 * that never returns gives {@link #UNKNOWN}.
		 */
		int after(int before) {
			if (outcomes == 0) {
				return bit(UNKNOWN);
			}
			int out = outcomes & ~bit(INHERITED);
			return (outcomes & bit(INHERITED)) != 0 ? out | bit(before) : out;
		}

		/**
		 * The one value the flag has after a call made with it at {@code before}, when there
		 * is exactly one and it is 0 or 1; -1 otherwise.
		 */
		int knownAfter(int before) {
			int a = after(before);
			return a == bit(0) ? 0 : a == bit(1) ? 1 : -1;
		}
	}

	/** The mask bit of one flag state ({@link #INHERITED}, 0, 1 or {@link #UNKNOWN}). */
	static int bit(int state) {
		return 1 << (Math.min(state, UNKNOWN) + 1);
	}

	/** Both flags' behaviour. */
	record Effect(Flag m, Flag x) {}

	private final Listing listing;
	private final Register ctxE;
	private final Register ctxM;
	private final Register ctxX;
	private final Register ctxD;
	private final Map<Address, Effect> cache = new HashMap<>();
	/** Entries whose walk is on the stack, so a recursive call is not walked again. */
	private final Set<Address> inProgress = new HashSet<>();

	W65816WidthEffects(Program program) {
		this.listing = program.getListing();
		this.ctxE = program.getRegister("ctx_EF");
		this.ctxM = program.getRegister("ctx_MF");
		this.ctxX = program.getRegister("ctx_XF");
		this.ctxD = program.getRegister("ctx_DF");
	}

	/** Whether the program's language carries the 65816 width context this class reads. */
	static boolean applies(Program program) {
		return program.getRegister("ctx_EF") != null && program.getRegister("ctx_MF") != null &&
			program.getRegister("ctx_XF") != null;
	}

	Register eRegister() {
		return ctxE;
	}

	Register mRegister() {
		return ctxM;
	}

	Register xRegister() {
		return ctxX;
	}

	/** The decimal-mode decode flag (grm-hf5h.31), or null in a language without it. */
	Register dRegister() {
		return ctxD;
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
		work.push(new long[] { entry.getOffset(), INHERITED, INHERITED, 0 });
		int steps = 0;
		while (!work.isEmpty() && steps++ < WALK_LIMIT) {
			long[] w = work.pop();
			int m = (int) w[1];
			int x = (int) w[2];
			long stack = w[3];
			// 24-bit address, the PHP stack and two 2-bit states fit a long key.
			if (!seen.add((w[0] << 32) | (stack << 8) | ((m + 1) << 4) | (x + 1))) {
				continue;
			}
			Address a = entry.getNewAddress(w[0]);
			Instruction in = listing.getInstructionAt(a);
			if (in == null || emulation(in)) {
				continue;
			}
			String mn = in.getMnemonicString().toUpperCase(Locale.ROOT);
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
			else if (mn.equals("PHP")) {
				stack = push(stack, m, x);
			}
			else if (mn.equals("PLP")) {
				// Restores what the matching PHP on this path saved; a PLP with none pulls a
				// status this walk never saw.
				int[] top = top(stack);
				m = top == null ? UNKNOWN : top[0];
				x = top == null ? UNKNOWN : top[1];
				if (top == null) {
					trace(entry, a, "unmatched PLP", m, x);
				}
				stack = pop(stack);
			}
			else if (mn.equals("XCE")) {
				m = UNKNOWN;
				x = UNKNOWN;
			}
			if (W65816Shapes.isReturn(in)) {
				trace(entry, a, "exit " + mn, m, x);
				exitM.add(m);
				exitX.add(x);
				continue;
			}
			FlowType ft = in.getFlowType();
			if (ft.isCall() && !ft.isComputed() && ft.isTerminal() && W65816Shapes.pushesNothing(in)) {
				// A JMP a CALL_RETURN override made terminal is still a jump: walk on with this
				// path's PHP stack (grm-9nxj.54). F-Zero $03:94D8 PHP / ... / JMP $95D6 into a
				// PLP / RTL that, summarized alone, pulled a status it never saw.
				for (Address t : in.getFlows()) {
					work.push(new long[] { t.getOffset(), m, x, stack });
				}
				continue;
			}
			if (ft.isCall() && !ft.isComputed() && ft.isTerminal()) {
				// A tail call: this path returns wherever the callee does, with what it leaves.
				for (Address t : in.getFlows()) {
					Effect ce = inProgress.contains(t) ? null : effect(t);
					if (ce == null || ce.m().exit() == NO_RETURN) {
						continue;
					}
					needsM |= m == INHERITED && ce.m().needs();
					needsX |= x == INHERITED && ce.x().needs();
					for (int v : states(ce.m().after(m))) {
						exitM.add(v);
					}
					for (int v : states(ce.x().after(x))) {
						exitX.add(v);
					}
					trace(entry, a, "exit tail call " + t, ce.m().exit(), ce.x().exit());
				}
				continue;
			}
			// A computed jump whose targets analysis resolved is followed into them like a direct
			// one (grm-9nxj.53: F-Zero's far-call callees dispatch through JMP ($8077,X) into
			// handlers that each return); unresolved, the path ends here.
			if (ft.isTerminal() || (ft.isComputed() && ft.isJump() && in.getFlows().length == 0)) {
				continue;
			}
			if (ft.isCall() && !ft.isComputed()) {
				// A direct call: what the callee needs counts while the flag is still inherited
				// here, and the flag afterwards is what the callee leaves (CT $C1:03F1 starts
				// with JSR $104E, which needs M=1 -- the continuation needs it through the call).
				// A callee whose returns leave a flag either preserved or at one value forks the
				// path, one continuation per value the flag can have (grm-9nxj.54).
				int mAfter = bit(m);
				int xAfter = bit(x);
				for (Address t : in.getFlows()) {
					Effect ce = inProgress.contains(t) ? null : effect(t);
					if (ce == null) {
						continue;   // recursion: treat as preserving, needing nothing
					}
					needsM |= m == INHERITED && ce.m().needs();
					needsX |= x == INHERITED && ce.x().needs();
					mAfter = ce.m().after(m);
					xAfter = ce.x().after(x);
					if (((mAfter & bit(UNKNOWN)) != 0 && m != UNKNOWN) ||
						((xAfter & bit(UNKNOWN)) != 0 && x != UNKNOWN)) {
						trace(entry, a, "call " + t + " (callee exit m=" + ce.m().exit() + " x=" +
							ce.x().exit() + ") leaves unknown", m, x);
					}
				}
				Address next = in.getFallThrough();
				if (next != null) {
					for (int mv : states(mAfter)) {
						for (int xv : states(xAfter)) {
							work.push(new long[] { next.getOffset(), mv, xv, stack });
						}
					}
				}
				continue;
			}
			if (ft.isJump()) {
				for (Address t : in.getFlows()) {
					work.push(new long[] { t.getOffset(), m, x, stack });
				}
			}
			Address next = in.getFallThrough();
			if (next != null) {
				work.push(new long[] { next.getOffset(), m, x, stack });
			}
		}
		Effect e = new Effect(new Flag(needsM, summarize(exitM), mask(exitM)),
			new Flag(needsX, summarize(exitX), mask(exitX)));
		inProgress.remove(entry);
		cache.put(entry, e);
		return e;
	}

	/*
	 * The statuses PHP saved along a path, as a long: depth in the low 3 bits, then one 4-bit
	 * (M, X) entry per level, innermost lowest. Deeper than STACK_DEPTH poisons it (depth
	 * STACK_POISONED), and every later PLP on that path restores UNKNOWN.
	 */
	private static final int STACK_DEPTH = 4;
	private static final int STACK_POISONED = 7;

	private static long push(long stack, int m, int x) {
		int depth = (int) (stack & 7);
		if (depth >= STACK_DEPTH) {
			return STACK_POISONED;
		}
		long entries = (stack >>> 3) << 4 | ((m + 1) << 2) | (x + 1);
		return entries << 3 | (depth + 1);
	}

	/** The (M, X) the innermost PHP saved, or null when there is none to restore. */
	private static int[] top(long stack) {
		int depth = (int) (stack & 7);
		if (depth == 0 || depth == STACK_POISONED) {
			return null;
		}
		int e = (int) ((stack >>> 3) & 0xf);
		return new int[] { (e >> 2) - 1, (e & 3) - 1 };
	}

	private static long pop(long stack) {
		int depth = (int) (stack & 7);
		if (depth == 0 || depth == STACK_POISONED) {
			return stack;
		}
		return (stack >>> 7) << 3 | (depth - 1);
	}

	private static int mask(Set<Integer> states) {
		int b = 0;
		for (int s : states) {
			b |= bit(s);
		}
		return b;
	}

	/** The flag states in a mask of {@link #bit}, in ascending order. */
	private static int[] states(int mask) {
		int[] out = new int[Integer.bitCount(mask)];
		int n = 0;
		for (int s = INHERITED; s <= UNKNOWN; s++) {
			if ((mask & bit(s)) != 0) {
				out[n++] = s;
			}
		}
		return out;
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
