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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;

/**
 * A structural scan of whether control entering a 65816 address can ever come back by
 * {@code RTS}/{@code RTL}/{@code RTI} (grm-hf5h.26; shared with
 * {@link W65816NoReturnFlagAnalyzer} since grm-hf5h.27). Every path from the address is walked:
 * calls are stepped over (a call carrying a {@code CALL_RETURN} override, i.e. a tail call or a
 * call into flagged no-return code, is followed instead), and jumps, branches and resolved
 * computed jumps are followed. The answer has three values:
 * <ul>
 * <li>{@code FALSE}: some path reaches a return;</li>
 * <li>{@code TRUE}: every path was seen and none returns (an endless main loop);</li>
 * <li>{@code null}: proves nothing -- a computed jump with no resolved target ({@code BRK},
 * {@code COP} and {@code STP} vector through one), a missing instruction, or more than
 * {@link #MAX_SCAN} instructions.</li>
 * </ul>
 * The scan keeps looking past an unproven path, since a return elsewhere still decides it.
 */
final class W65816NoReturnProof {

	/** Cap on instructions visited (FF3 {@code $C5:0180}'s handler is several hundred). */
	static final int MAX_SCAN = 4096;

	private W65816NoReturnProof() {
	}

	/** True: no path returns; false: some path reaches a return; null: proves nothing. */
	static Boolean neverReturns(Program program, Address a) {
		Set<Address> seen = new HashSet<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		seen.add(a);
		work.add(a);
		boolean unproven = false;
		while (!work.isEmpty()) {
			if (seen.size() > MAX_SCAN) {
				return null;
			}
			Instruction i = program.getListing().getInstructionAt(work.poll());
			if (i == null) {
				unproven = true;   // keep looking: a return elsewhere still decides it
				continue;
			}
			String mn = i.getMnemonicString().toUpperCase(Locale.ROOT);
			if (mn.equals("RTS") || mn.equals("RTL") || mn.equals("RTI")) {
				return false;
			}
			FlowType ft = i.getFlowType();
			List<Address> next = new ArrayList<>();
			if (ft.isCall()) {
				if (ft.isTerminal()) {
					// a tail call (CALL_RETURN override); one with no known target proves nothing
					if (i.getFlows().length == 0) {
						unproven = true;
					}
					next.addAll(List.of(i.getFlows()));
				}
			}
			else {
				if (ft.isComputed() && i.getFlows().length == 0) {
					unproven = true;
				}
				next.addAll(List.of(i.getFlows()));
			}
			if (!ft.isTerminal() && i.getFallThrough() != null) {
				next.add(i.getFallThrough());
			}
			for (Address n : next) {
				if (seen.add(n)) {
					work.add(n);
				}
			}
		}
		return unproven ? null : Boolean.TRUE;
	}
}
