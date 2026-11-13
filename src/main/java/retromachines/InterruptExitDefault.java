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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * The game's DEFAULT bank state, learned from how its interrupt handlers exit (bead grm-5tl.21).
 * <p>
 * An interrupt fires from arbitrary mainline context, so a handler that switches a bank and does
 * not restore it leaves that bank live for whatever runs next: Rygar's NMI ends every frame with
 * bank 3 switched in. When EVERY exit of EVERY handler leaves a field at the same constant, that
 * constant is a better guess for the field wherever the analysis knows nothing than the
 * descriptor's {@code banking.initial_state} (which is only the power-on value). It is a
 * DEFAULT, never a fact: it replaces {@code initial_state} as the fallback for UNKNOWN bits
 * ({@link BankState#effective}) and nothing else -- it never marks a bit known and never
 * overrides a recovered value or a hint.
 * <p>
 * Per FIELD, each handler is classified from the in-state at its exits: it PROVIDES v when every
 * exit knows the field at v, CONFLICTs when some exit knows the field but not all agree on one
 * known value, and is NEUTRAL when no exit knows it. A field gets a default iff no handler
 * conflicts, at least one provides, and all providers agree. KNOWN LIMITATION: NEUTRAL conflates
 * "never touched" with "restored relationally" (a save/restore the dataflow cannot prove is a
 * no-op looks like an unknown exit), so a handler that restores the interrupted bank by a
 * mechanism the engine does not model is read as not having an opinion.
 * Fields already known at a handler's entry (fixed-after-init bits, the locked layout mode) are
 * NEUTRAL: their exit value comes from the seed, not from the handler.
 */
final class InterruptExitDefault {

	private InterruptExitDefault() {}

	/** Upper bound on instructions visited while collecting one handler's exits. */
	static final int MAX_WALK = 20000;

	/**
	 * One handler's facts for classification. {@code unresolved} is set when the walk met flow it
	 * cannot follow (a computed jump with no resolved targets, or the instruction budget ran
	 * out): the exits are then not all known, so the handler conflicts on every field.
	 */
	record HandlerExits(Address entry, BankState entryState, boolean unresolved,
			List<BankState> exitStates) {}

	/** One defaulted field: its value, and the lowest handler entry that provides it. */
	record FieldDefault(String name, int positionedMask, int value, Address entry) {}

	/**
	 * The defaults found: {@code knownMask}/{@code bits} are the defaulted fields in packed board
	 * coordinates, {@code fields} is the provenance.
	 */
	record Result(int knownMask, int bits, List<FieldDefault> fields) {

		static final Result NONE = new Result(0, 0, List.of());

		boolean isEmpty() {
			return knownMask == 0;
		}

		/** {@code initialState} with the defaulted fields overwritten: the fallback state. */
		int apply(int initialState) {
			return (initialState & ~knownMask) | (bits & knownMask);
		}

		/**
		 * The provenance text for the defaulted fields covering any bit of {@code unknownBits},
		 * e.g. {@code default: interrupt exit bank=3 (c0f6)}, or null when none does.
		 */
		String describe(int unknownBits) {
			List<String> parts = new ArrayList<>();
			for (FieldDefault f : fields) {
				if ((f.positionedMask() & unknownBits) != 0) {
					parts.add(f.name() + "=" + f.value() + " (" + f.entry() + ")");
				}
			}
			return parts.isEmpty() ? null : "default: interrupt exit " + String.join(", ", parts);
		}
	}

	/** The pure classification over already-collected handlers. */
	static Result derive(Collection<HandlerExits> handlers, List<FieldSpec> fields) {
		int knownMask = 0;
		int bits = 0;
		List<FieldDefault> out = new ArrayList<>();
		for (FieldSpec field : fields) {
			int fieldMask = field.positionedMask();
			Integer agreed = null;
			Address from = null;
			boolean conflict = false;
			for (HandlerExits h : handlers) {
				Verdict v = classify(h, field);
				if (v.kind == Kind.CONFLICT) {
					conflict = true;
					break;
				}
				if (v.kind == Kind.PROVIDES) {
					if (agreed == null) {
						agreed = v.value;
						from = h.entry();
					}
					else if (agreed != v.value) {
						conflict = true;
						break;
					}
					else if (h.entry().compareTo(from) < 0) {
						from = h.entry();
					}
				}
			}
			if (!conflict && agreed != null) {
				knownMask |= fieldMask;
				bits |= (agreed << field.lsb()) & fieldMask;
				out.add(new FieldDefault(field.name(), fieldMask, agreed, from));
			}
		}
		return knownMask == 0 ? Result.NONE : new Result(knownMask, bits, out);
	}

	private enum Kind { PROVIDES, CONFLICT, NEUTRAL }

	private record Verdict(Kind kind, int value) {}

	private static Verdict classify(HandlerExits h, FieldSpec field) {
		if (h.entryState() != null && field.fullyKnownIn(h.entryState())) {
			return new Verdict(Kind.NEUTRAL, 0);
		}
		if (h.unresolved()) {
			return new Verdict(Kind.CONFLICT, 0);
		}
		int knownCount = 0;
		Integer value = null;
		for (BankState s : h.exitStates()) {
			if (field.fullyKnownIn(s)) {
				knownCount++;
				int v = field.valueIn(s.bits());
				if (value == null) {
					value = v;
				}
				else if (value != v) {
					return new Verdict(Kind.CONFLICT, 0);
				}
			}
		}
		if (knownCount == 0) {
			return new Verdict(Kind.NEUTRAL, 0);
		}
		if (knownCount != h.exitStates().size()) {
			return new Verdict(Kind.CONFLICT, 0);
		}
		return new Verdict(Kind.PROVIDES, value);
	}

	/**
	 * Walks {@code entry}'s flow -- fall-through, branches and jumps, never into a call -- and
	 * collects the in-state at every interrupt-return instruction. An exit the dataflow
	 * never reached has no state and is skipped (it is dead as far as the analysis can tell).
	 */
	static HandlerExits collect(Listing listing, Address entry, Map<Address, BankState> stateIn) {
		List<BankState> exits = new ArrayList<>();
		boolean unresolved = false;
		Set<Address> seen = new HashSet<>();
		Deque<Address> work = new ArrayDeque<>();
		work.add(entry);
		while (!work.isEmpty()) {
			Address a = work.poll();
			if (!seen.add(a)) {
				continue;
			}
			if (seen.size() > MAX_WALK) {
				unresolved = true;
				break;
			}
			Instruction instr = listing.getInstructionAt(a);
			if (instr == null) {
				continue;
			}
			FlowType ft = instr.getFlowType();
			if (ft.isTerminal()) {
				// Only an interrupt return is an exit OF THE HANDLER. A handler that JMPs into
				// mainline code (megaman's vector c008 is the reset routine) reaches that code's
				// subroutine returns, which are not the handler's exits; they are skipped, so a
				// handler with no interrupt return at all has no exits and no opinion.
				BankState s = stateIn.get(a);
				if (s != null && isInterruptReturn(instr)) {
					exits.add(s);
				}
				continue;
			}
			if (ft.isJump() && ft.isComputed() && instr.getFlows().length == 0) {
				unresolved = true;
				continue;
			}
			if (!ft.isCall()) {
				for (Address flow : instr.getFlows()) {
					work.add(flow);
				}
			}
			Address fall = instr.getFallThrough();
			if (fall != null) {
				work.add(fall);
			}
		}
		return new HandlerExits(entry, stateIn.get(entry), unresolved, exits);
	}

	/**
	 * True for an interrupt-return instruction (6502/65816 {@code RTI}, Z80 {@code RETI}/{@code
	 * RETN}, SPC700 {@code RETI}, x86 {@code IRET}). By mnemonic, because Ghidra gives every
	 * return the same terminator flow type and the ordinary {@code RTS} must be told apart.
	 */
	static boolean isInterruptReturn(Instruction instr) {
		String m = instr.getMnemonicString().toUpperCase(java.util.Locale.ROOT);
		return m.equals("RTI") || m.equals("RETI") || m.equals("RETN") || m.startsWith("IRET");
	}

	/** Collects every async entry's exits from the converged in-states and classifies them. */
	static Result compute(Listing listing, Collection<Address> asyncEntries,
			Map<Address, BankState> stateIn, List<FieldSpec> fields) {
		List<HandlerExits> handlers = new ArrayList<>();
		for (Address entry : asyncEntries) {
			if (listing.getInstructionAt(entry) != null) {
				handlers.add(collect(listing, entry, stateIn));
			}
		}
		return handlers.isEmpty() ? Result.NONE : derive(handlers, fields);
	}
}
