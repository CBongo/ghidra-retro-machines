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
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;

/**
 * Which recognized mechanism write is the LAST one to touch each tracked bit on every path from
 * a helper's entry to its returns (bead grm-mej.27) -- the real question that
 * {@code HelperDiscovery.HelperModel.switchSite}'s max-address rule only approximates.
 * <p>
 * <b>Why the proxy is not enough.</b> The max-address site is "the last write before the
 * return" only while program order is execution order. A helper whose exit path branches
 * BACKWARD to an earlier switch breaks that, and {@code HelperDiscovery.findHelpers}' javadoc
 * said so in advance. megaman3's commit helper is the case that arrived: it commits two bank
 * registers from RAM shadows, then -- on a deferred-work path only -- switches the sound banks
 * in at HIGHER addresses, runs the driver, and jumps back to its own entry to commit the
 * shadows again before it returns. The max-address site is the sound-bank write, which is never
 * live at any return, and the call sites shipped it as a confident wrong bank.
 * <p>
 * <b>What this computes.</b> A forward may-analysis over the helper's own control flow: for each
 * bit, the SET of writers whose deposit can be the one live at a return. A writer is a
 * recognized site, the helper's ENTRY (the bit was not written on that path -- the caller's
 * value survives), or a CALL (an instruction this walk does not follow, which may write any
 * bit). A site whose ownership is exact replaces the set on the bits it owns; one whose
 * ownership is only a may-write ({@link BankSwitchStrategy#bankFieldCommittedBySite} answers
 * {@code -1}: the field it commits is not decided by the helper's own body) and a call only
 * ADD themselves, never killing an earlier writer. A bit whose exit set is one exact site is
 * that site's; a bit whose set names more than one writer, or ENTRY alongside a site, is written
 * on some paths and not others, and its value at the return is honestly unknown.
 * <p>
 * <b>Everything declines rather than guesses.</b> A gap in the disassembly, a computed jump, a
 * body larger than {@link #MAX_NODES}, or more sites than the set encoding holds answers
 * {@code null}, and the caller keeps its pre-grm-mej.27 behaviour. An edge that LEAVES the
 * function containing the entry -- a tail call, or a jump into another body -- does not decline
 * (bead grm-mej.28): it is an exit through code the walk cannot see, so every bit there counts
 * as possibly rewritten (a CALL writer) and comes out owned-unknown. See {@link #build}.
 */
final class HelperLastWriters {

	private HelperLastWriters() {
	}

	/** A body bigger than this is not the small commit routine this models; decline. */
	static final int MAX_NODES = 512;

	/** Writer-set encoding: bit 0 is ENTRY, bit 1 is CALL, bit {@code 2 + i} is site {@code i}. */
	static final long ENTRY = 1L;
	static final long CALL = 2L;
	static final int MAX_SITES = 62;

	/**
	 * The helper's control-flow graph from {@code entry}: every instruction reachable by
	 * following fall-throughs, branch targets and the return of each call, with its predecessor
	 * edges, its plain returns, the calls it does not follow, and the instructions with an edge
	 * that LEAVES the body ({@code leaves}: a tail call, or a jump into code outside the
	 * function). A leaving edge is an exit whose writers are unknown -- see
	 * {@link #writersAtExits}.
	 */
	record Cfg(Address entry, Map<Address, List<Address>> succs,
			Map<Address, List<Address>> preds, List<Address> exits, Set<Address> calls,
			Set<Address> leaves) {

		/** Whether control can arrive at {@code a} from inside the helper itself. */
		boolean hasInternalPredecessor(Address a) {
			List<Address> p = preds.get(a);
			return p != null && !p.isEmpty();
		}
	}

	/** {@link Cfg} for the body entered at {@code entry}, or {@code null} -- see the class javadoc. */
	static Cfg build(Program program, Address entry) {
		if (entry == null) {
			return null;
		}
		Listing listing = program.getListing();
		// The walk must stay inside the function the entry belongs to: its recognized sites are the
		// only writes the analysis can see, so following a jump into another body would read that
		// body's mechanism writes as no writes at all. An edge that leaves it (a tail call, or a
		// jump into code outside the function) is therefore not followed but recorded in `leaves`:
		// control returns to the caller from code this walk cannot see, so every bit may have been
		// rewritten on that path (bead grm-mej.28 -- smb3's NMI body leaves through JMP $cecf on
		// one arm, and declining the whole analysis for it fell back to the max-address site's
		// confident r7=26).
		Function body = program.getFunctionManager().getFunctionContaining(entry);
		Map<Address, List<Address>> succs = new LinkedHashMap<>();
		Map<Address, List<Address>> preds = new HashMap<>();
		List<Address> exits = new ArrayList<>();
		Set<Address> calls = new LinkedHashSet<>();
		Set<Address> leaves = new LinkedHashSet<>();
		Deque<Address> work = new ArrayDeque<>();
		work.add(entry);
		while (!work.isEmpty()) {
			Address a = work.poll();
			if (succs.containsKey(a)) {
				continue;
			}
			if (succs.size() >= MAX_NODES) {
				return null;
			}
			Instruction instr = listing.getInstructionAt(a);
			if (instr == null) {
				return null;
			}
			FlowType ft = instr.getFlowType();
			List<Address> next = new ArrayList<>();
			if (ft.isTerminal()) {
				if (ft.isCall() || ft.isJump()) {
					if (ft.isComputed()) {
						return null; // targets this walk cannot enumerate, possibly back inside
					}
					leaves.add(a); // a tail call: the exit state is the callee's
				}
				else {
					exits.add(a);
				}
			}
			else if (ft.isCall()) {
				Address fall = instr.getFallThrough();
				if (fall == null) {
					return null;
				}
				calls.add(a);
				next.add(fall);
			}
			else if (ft.isJump()) {
				Address[] flows = instr.getFlows();
				if (flows.length == 0 || ft.isComputed()) {
					return null; // a jump whose targets this walk cannot enumerate
				}
				for (Address f : flows) {
					next.add(f);
				}
				if (ft.isConditional()) {
					Address fall = instr.getFallThrough();
					if (fall == null) {
						return null;
					}
					next.add(fall);
				}
			}
			else {
				Address fall = instr.getFallThrough();
				if (fall == null) {
					return null;
				}
				next.add(fall);
			}
			// A successor outside the body (or in another address space) is a jump OUT: not walked,
			// and the edge makes `a` a leaving node instead.
			List<Address> inside = new ArrayList<>();
			for (Address s : next) {
				if (s.getAddressSpace().equals(entry.getAddressSpace()) &&
					(body == null || body.getBody().contains(s))) {
					inside.add(s);
				}
				else {
					leaves.add(a);
				}
			}
			next = inside;
			succs.put(a, next);
			for (Address s : next) {
				preds.computeIfAbsent(s, k -> new ArrayList<>()).add(a);
				if (!succs.containsKey(s)) {
					work.add(s);
				}
			}
		}
		return new Cfg(entry, succs, preds, exits, calls, leaves);
	}

	/**
	 * Per field-local bit {@code b} (index into the returned array, {@code 0..31}), the union over
	 * every return of the writers whose deposit may be live there, in the encoding above.
	 * {@code masks[i]} is site {@code i}'s field-local ownership and {@code exact[i]} whether that
	 * ownership is decided by the helper's own body (only then does the site kill an earlier
	 * writer). A bit outside {@code stateMask} is always {@code 0}.
	 */
	static long[] writersAtExits(Cfg cfg, List<Address> sites, int[] masks, boolean[] exact,
			int stateMask) {
		Map<Address, Integer> index = new HashMap<>();
		for (int i = 0; i < sites.size(); i++) {
			index.put(sites.get(i), i);
		}
		Map<Address, long[]> in = new HashMap<>();
		long[] start = new long[32];
		for (int b = 0; b < 32; b++) {
			if ((stateMask & (1 << b)) != 0) {
				start[b] = ENTRY;
			}
		}
		in.put(cfg.entry(), start);
		Deque<Address> work = new ArrayDeque<>();
		work.add(cfg.entry());
		while (!work.isEmpty()) {
			Address a = work.poll();
			long[] out = in.get(a).clone();
			Integer i = index.get(a);
			if (i != null) {
				long self = 1L << (2 + i);
				for (int b = 0; b < 32; b++) {
					if ((masks[i] & stateMask & (1 << b)) != 0) {
						out[b] = exact[i] ? self : out[b] | self;
					}
				}
			}
			if (cfg.calls().contains(a)) {
				for (int b = 0; b < 32; b++) {
					if ((stateMask & (1 << b)) != 0) {
						out[b] |= CALL;
					}
				}
			}
			for (Address s : cfg.succs().get(a)) {
				long[] cur = in.get(s);
				if (cur == null) {
					in.put(s, out.clone());
					work.add(s);
					continue;
				}
				boolean changed = false;
				for (int b = 0; b < 32; b++) {
					long merged = cur[b] | out[b];
					if (merged != cur[b]) {
						cur[b] = merged;
						changed = true;
					}
				}
				if (changed) {
					work.add(s);
				}
			}
		}
		long[] result = new long[32];
		for (Address exit : cfg.exits()) {
			long[] at = in.get(exit);
			for (int b = 0; b < 32; b++) {
				result[b] |= at[b];
			}
		}
		// A leaving edge returns through code this walk cannot see: whatever was live on the way
		// out may still survive, and anything may have been rewritten -- both, as a CALL does.
		for (Address leave : cfg.leaves()) {
			long[] at = in.get(leave);
			for (int b = 0; b < 32; b++) {
				if ((stateMask & (1 << b)) != 0) {
					result[b] |= at[b] | CALL;
				}
			}
		}
		return result;
	}
}
