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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * The control-flow edge predicates every backward/forward instruction walk in this extension
 * asks: "does {@code prev} fall straight into {@code cur}" and "is {@code cur} also entered
 * some other way". They were once copied into each walker (and the copies described each other
 * as "private to another class"); they live here, once, as pure structural predicates over a
 * {@link Program}'s reference manager and the instructions' own fall-through addresses.
 */
final class FlowEdges {

	private FlowEdges() {}

	/**
	 * Whether the fall-through path from {@code prev} is exactly {@code cur} -- the block linkage
	 * test every straight-line walk uses. False when {@code prev} has no fall-through at all.
	 */
	static boolean fallsInto(Instruction prev, Instruction cur) {
		return fallsInto(prev, cur.getMinAddress());
	}

	/**
	 * {@link #fallsInto(Instruction, Instruction)} for a {@code target} address that has no
	 * {@link Instruction} in hand (an entry or loop head being walked backwards).
	 */
	static boolean fallsInto(Instruction prev, Address target) {
		Address fallThrough = prev.getFallThrough();
		return fallThrough != null && fallThrough.equals(target);
	}

	/**
	 * The instruction immediately before {@code cur} in the listing when it falls straight into
	 * {@code cur}, or {@code null} (no instruction before, or it does not fall into {@code cur}).
	 */
	static Instruction fallThroughPredecessor(Listing listing, Instruction cur) {
		Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
		return prev != null && fallsInto(prev, cur) ? prev : null;
	}

	/** The instruction at {@code from}'s fall-through address, or {@code null}. */
	static Instruction nextFallThrough(Listing listing, Instruction from) {
		Address ft = from.getFallThrough();
		return ft == null ? null : listing.getInstructionAt(ft);
	}

	/**
	 * Whether {@code cur} is reachable other than by falling through from {@code prev} --
	 * i.e. another instruction branches, jumps, or calls to it, making it a control-flow
	 * join. The backward scan follows only the {@code prev} fall-through path, so at a join
	 * it cannot soundly attribute that path's register value to the store: the other
	 * incoming path(s) may leave a different value.
	 * <p>
	 * A join is detected by an incoming <em>flow</em> reference from an address other than
	 * {@code prev} (a conditional or unconditional branch to {@code cur} records one; the
	 * implicit fall-through from {@code prev} is not a reference, and a branch from
	 * {@code prev} whose target is also its own fall-through is excluded). Unresolved
	 * computed jumps leave no reference and so are not detected -- conservative in the safe
	 * direction (a missed join only forfeits a fold the scan would otherwise have made).
	 * <p>
	 * This stays a pure structural predicate: the one licensed exception (grm-k90) is applied by
	 * each caller as {@code !env.mayCrossJoinAt(...)} alongside it, rather than folded in here,
	 * so "is this a join" and "may this query cross it" remain separable questions and a reader
	 * of either walk can see the licence being spent at the point it is spent.
	 * <p>
	 * Its negation with {@code prev} read as "the one permitted source" is the loop-head test:
	 * {@code !isControlFlowJoin(program, head, backEdge)} holds exactly when every incoming flow
	 * reference to {@code head} comes from {@code backEdge}.
	 */
	static boolean isControlFlowJoin(Program program, Instruction cur, Instruction prev) {
		Address curAddr = cur.getMinAddress();
		Address prevAddr = prev.getMinAddress();
		for (Reference ref : program.getReferenceManager().getReferencesTo(curAddr)) {
			if (ref.getReferenceType().isFlow() && !ref.getFromAddress().equals(prevAddr)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * {@link #isControlFlowJoin} minus CALLS (bead grm-mej.20): another path MERGES into
	 * {@code cur} only by a branch or jump. A call landing on {@code cur} is a second ENTRY into
	 * a helper, which a walk may cross subject to its own guard (see
	 * {@code BankMirrors.Discovery#walkFromMechanismWrite}). Deliberately NOT unified with
	 * {@link #isControlFlowJoin}: a call reference makes that one answer {@code true} and this
	 * one {@code false}.
	 */
	static boolean branchJoin(Program program, Instruction cur, Instruction prev) {
		for (Reference ref : program.getReferenceManager().getReferencesTo(cur.getMinAddress())) {
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isCall() &&
				!ref.getFromAddress().equals(prev.getMinAddress())) {
				return true;
			}
		}
		return false;
	}
}
