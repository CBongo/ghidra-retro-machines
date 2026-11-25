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

import java.util.Locale;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/**
 * The hand-made 65816 far call whose jump {@link W65816FarCallContinuationAnalyzer} has turned
 * into a call (bead grm-9nxj.48), and the one place every stack walker asks about it.
 *
 * <p>A far call is {@code PHK / PER r / JML f} into an {@code RTL} routine, or {@code PEA r /
 * JMP f} into an {@code RTS} routine, with {@code r + 1} exactly the jump's own fall-through. The
 * analyzer decodes the continuation at {@code r + 1}, then gives the jump
 * {@link FlowOverride#CALL}: the jump becomes an {@code UNCONDITIONAL_CALL} whose default
 * fall-through is the next instruction, which IS the continuation, so no fall-through override is
 * needed (Ghidra's {@code InstructionDB.getDefaultFallThrough} follows the modified flow type).
 * The continuation then joins the caller's function body and the decompiler follows the call and
 * continues there.
 *
 * <p><b>What a stack walker must know.</b> The caller's {@code PHK}/{@code PER}/{@code PEA}
 * stay on the stack at the call, and the callee's return pulls them: unlike {@code JSR}/{@code JSL}
 * the call pushes nothing of its own, so {@link #pushedBytes} (3 for {@code PHK / PER}, 2 for
 * {@code PEA}) are the caller's bytes the call drops. The decompiler needs nothing special: the
 * push is a p-code store before the {@code CALL}, and the purge
 * ({@link W65816StackPurgeAnalyzer}, 2 for {@code RTS}, 3 for {@code RTL}) pops it after, as for
 * a {@code JSL}.
 *
 * <p>Two walker models exist. A walker with no stack model of its own that steps over calls
 * ({@link W65816ReturnProof}) drops {@link #pushedBytes} at the call. The direct-page and
 * data-bank walkers already model the pre-override form, a terminal jump through a pushed return
 * address ({@code pushedCall}: pull the pushed items, apply the callee's summary, continue at the
 * return address) and keep every result of it; they read such an instruction through
 * {@link #flow} and {@link #fallThrough}, the terminal jump it was before the override, so a call to them
 * is neither lost nor counted twice.
 */
final class W65816FarCall {

	private W65816FarCall() {
	}

	/**
	 * The shape of a far call: {@code bytes} the caller pushed for it (3 with a {@code PHK}, else
	 * 2), {@code fall} the jump's fall-through, which is the continuation.
	 */
	record Shape(int bytes, Address fall) {
		boolean far() {
			return bytes == 3;
		}
	}

	/**
	 * The far-call shape of {@code jmp}, whether or not it has been overridden yet, or null. Only
	 * the shape, with none of the guards that need a proof ({@link W65816FarCallContinuationAnalyzer}
	 * has those): a direct {@code JML}/{@code JMP} with one target, preceded immediately by a
	 * {@code PEA}/{@code PER} of a constant word whose successor is the jump's fall-through, with
	 * a {@code PHK} before that for the three-byte form; the fall-through in the jump's own bank
	 * and, for the two-byte form, the callee in it too (an {@code RTS} returns in the bank it runs in).
	 */
	static Shape shape(Listing listing, Instruction jmp) {
		String mn = jmp.getMnemonicString().toUpperCase(Locale.ROOT);
		if (!(mn.equals("JML") || mn.equals("JMP")) || jmp.getFlowType().isComputed() ||
			jmp.getFlows().length != 1) {
			return null;
		}
		Address fall = jmp.getMaxAddress().next();
		Instruction push = adjacentBefore(listing, jmp);
		if (fall == null || push == null) {
			return null;
		}
		int pushed = W65816Shapes.pushedConstantWord(push);
		if (pushed < 0 || ((pushed + 1) & 0xffff) != (fall.getOffset() & 0xffff)) {
			return null;
		}
		Instruction phk = adjacentBefore(listing, push);
		boolean far = phk != null && W65816Shapes.pushesProgramBank(phk);
		long bank = jmp.getMinAddress().getOffset() & 0xff0000L;
		if (!far && (jmp.getFlows()[0].getOffset() & 0xff0000L) != bank) {
			return null;   // an RTS returns in the callee's bank, not to this one
		}
		if ((fall.getOffset() & 0xff0000L) != bank) {
			return null;   // the jump ends on a bank boundary
		}
		return new Shape(far ? 3 : 2, fall);
	}

	/** Whether {@code ins} is a far-call jump the continuation analyzer turned into a call. */
	static boolean isOverridden(Instruction ins) {
		return ins.getFlowOverride() == FlowOverride.CALL &&
			shape(ins.getProgram().getListing(), ins) != null;
	}

	/**
	 * The bytes the caller pushed for the far call {@code ins} is, which its callee's return
	 * pulls: 3 ({@code PHK / PER}) or 2 ({@code PEA}); 0 for any other instruction.
	 */
	static int pushedBytes(Instruction ins) {
		if (ins.getFlowOverride() != FlowOverride.CALL) {
			return 0;
		}
		Shape s = shape(ins.getProgram().getListing(), ins);
		return s == null ? 0 : s.bytes();
	}

	/**
	 * The flow type {@code ins} had before the continuation analyzer overrode it, for the walkers
	 * that model the far call themselves: a terminal call ({@code CALL_TERMINATOR}), the form the
	 * {@code CALL_RETURN} override Ghidra's Shared Return Calls gives a jump into a function entry
	 * (all twelve F-Zero far calls had it), for a far call; its own flow type for everything else.
	 * The walkers read a terminal call and a plain jump alike here.
	 */
	static FlowType flow(Instruction ins) {
		return ins.getFlowOverride() == FlowOverride.CALL && isOverridden(ins)
				? RefType.CALL_TERMINATOR
				: ins.getFlowType();
	}

	/** The fall-through {@code ins} had before the override: none for a far call. */
	static Address fallThrough(Instruction ins) {
		return ins.getFlowOverride() == FlowOverride.CALL && isOverridden(ins) ? null
				: ins.getFallThrough();
	}

	/** Whether {@code ins} falls through, as it did before the override: not a far call. */
	static boolean hasFallthrough(Instruction ins) {
		return !(ins.getFlowOverride() == FlowOverride.CALL && isOverridden(ins)) &&
			ins.hasFallthrough();
	}

	private static Instruction adjacentBefore(Listing listing, Instruction in) {
		Instruction p = listing.getInstructionBefore(in.getMinAddress());
		return p != null && p.getMaxAddress().next() != null &&
			p.getMaxAddress().next().equals(in.getMinAddress()) ? p : null;
	}
}
