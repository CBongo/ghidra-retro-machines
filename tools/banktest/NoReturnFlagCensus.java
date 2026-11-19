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
// Census of the no-return flags on a program (bead grm-9nxj.39): every function that carries
// Ghidra's no-return flag, who set it (stock "Non-Returning Function" bookmark or not), how many
// call sites reach it, and a structural scan of every path from the entry -- calls stepped over,
// jumps and branches followed -- reporting which return kinds it reaches (RTS/RTL/RTI), which
// stack/flow features it contains, and the first instructions. Any platform; read-only.
//
//   REALROM_EXTRA_POSTSCRIPT=NoReturnFlagCensus.java REALROM_WORK_DIR=<dir> \
//     bash tools/banktest/realrom-test.sh check snes-analysis
//
// Output: `NRFC fn <entry> stock=<y|n> thunk=<y|n> calls=<n> returns=<kinds> features=<...>`,
// then `NRFC   <addr> <instr> <flowtype>` for the first GRM_NRFC_LINES (default 16)
// instructions, and `NRFC total flagged=<n> stock=<n> reachesReturn=<n>`. Then every call that
// does not fall through (`NRFC stopped`), and every call into a flagged function whose
// fall-through Ghidra never decoded (`NRFC undecodedAfter`, grm-hf5h.27; the Disassembler skips
// it without an override), with a pseudo-disassembly of the bytes that follow.

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

public class NoReturnFlagCensus extends GhidraScript {

	private static final int SCAN_LIMIT = 4096;

	@Override
	protected void run() throws Exception {
		int lines = 16;
		String env = System.getenv("GRM_NRFC_LINES");
		if (env != null && !env.isBlank()) {
			lines = Integer.parseInt(env.trim());
		}
		int flagged = 0;
		int stock = 0;
		int reaches = 0;
		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!fn.hasNoReturn() || fn.isExternal()) {
				continue;
			}
			flagged++;
			Address entry = fn.getEntryPoint();
			boolean isStock = currentProgram.getBookmarkManager().getBookmark(entry,
				BookmarkType.ANALYSIS, "Non-Returning Function") != null;
			if (isStock) {
				stock++;
			}
			int calls = 0;
			for (Reference r : getReferencesTo(entry)) {
				if (r.getReferenceType().isCall()) {
					calls++;
				}
			}
			Set<String> returns = new TreeSet<>();
			Set<String> features = new TreeSet<>();
			scan(entry, returns, features);
			if (!returns.isEmpty()) {
				reaches++;
			}
			println("NRFC fn " + entry + " " + fn.getName() + " stock=" + (isStock ? "y" : "n") +
				" thunk=" + (fn.isThunk() ? "y" : "n") + " calls=" + calls + " returns=" +
				(returns.isEmpty() ? "-" : String.join(",", returns)) + " features=" +
				(features.isEmpty() ? "-" : String.join(",", features)));
			Instruction in = getInstructionAt(entry);
			for (int n = 0; in != null && n < lines; n++) {
				println("NRFC   " + in.getAddress() + " " + in + " " + in.getFlowType());
				Address ft = in.getFallThrough();
				in = ft == null ? null : getInstructionAt(ft);
			}
		}
		println("NRFC total flagged=" + flagged + " stock=" + stock + " reachesReturn=" + reaches);
		// Calls that do not fall through, by target: what a wrong flag leaves behind.
		java.util.Map<String, Integer> stopped = new java.util.TreeMap<>();
		int stoppedTotal = 0;
		for (Instruction i : currentProgram.getListing().getInstructions(true)) {
			FlowType ft = i.getFlowType();
			if (ft.isCall() && !ft.hasFallthrough() && !ft.isComputed()) {
				for (Address t : i.getFlows()) {
					stopped.merge(t + (i.getFlowOverride().name().equals("NONE") ? ""
							: "/" + i.getFlowOverride()), 1, Integer::sum);
				}
				stoppedTotal++;
			}
		}
		for (java.util.Map.Entry<String, Integer> e : stopped.entrySet()) {
			println("NRFC stopped " + e.getKey() + " sites=" + e.getValue());
		}
		println("NRFC total stoppedCalls=" + stoppedTotal);
		undecodedAfterFlaggedCalls();
	}

	/**
	 * Calls into a flagged function that still fall through but whose fall-through was never
	 * decoded (grm-hf5h.27): Ghidra's Disassembler does not follow the fall-through of a call to
	 * a no-return function it meets later, without setting any override, so the stopped-call
	 * list above cannot see these. Each is shown with a pseudo-disassembly of what follows, to
	 * judge whether the bytes skipped look like code.
	 */
	private void undecodedAfterFlaggedCalls() {
		int sites = 0;
		ghidra.app.util.PseudoDisassembler pseudo =
			new ghidra.app.util.PseudoDisassembler(currentProgram);
		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!fn.hasNoReturn() || fn.isExternal()) {
				continue;
			}
			for (Reference r : getReferencesTo(fn.getEntryPoint())) {
				Instruction call = getInstructionAt(r.getFromAddress());
				if (!r.getReferenceType().isCall() || call == null ||
					!call.getFlowType().hasFallthrough() || call.getFallThrough() == null ||
					getInstructionAt(call.getFallThrough()) != null) {
					continue;
				}
				sites++;
				StringBuilder next = new StringBuilder();
				Address at = call.getFallThrough();
				for (int n = 0; at != null && n < 6; n++) {
					try {
						ghidra.app.util.PseudoInstruction pi = pseudo.disassemble(at);
						if (pi == null) {
							next.append(" | ?");
							break;
						}
						next.append(" | ").append(pi);
						at = pi.getFallThrough();
					}
					catch (Exception e) {
						next.append(" | ?");
						break;
					}
				}
				println("NRFC undecodedAfter " + call.getAddress() + " " + call + " -> " +
					fn.getEntryPoint() + " next" + next);
			}
		}
		println("NRFC total undecodedAfter=" + sites);
	}

	private void scan(Address entry, Set<String> returns, Set<String> features) {
		Set<Address> seen = new HashSet<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		work.add(entry);
		while (!work.isEmpty()) {
			Address at = work.poll();
			if (!seen.add(at)) {
				continue;
			}
			if (seen.size() > SCAN_LIMIT) {
				features.add("scanLimit");
				return;
			}
			Instruction i = getInstructionAt(at);
			if (i == null) {
				features.add("noInstr");
				continue;
			}
			String mn = i.getMnemonicString().toUpperCase();
			switch (mn) {
				case "RTS", "RTL", "RTI" -> {
					returns.add(mn);
					continue;
				}
				case "PHA", "PHX", "PHY", "PHP", "PHB", "PHD", "PHK", "PEA", "PEI", "PER",
						"PLA", "PLX", "PLY", "PLP", "PLB", "PLD", "TXS", "TCS", "BRK", "COP",
						"STP", "WAI", "XCE" -> features.add(mn);
				default -> {
				}
			}
			FlowType ft = i.getFlowType();
			if (ft.isCall()) {
				features.add(ft.hasFallthrough() ? "call" : "callTerminator");
			}
			if (ft.isComputed()) {
				features.add(i.getFlows().length == 0 ? "computedUnresolved" : "computed");
			}
			for (Address f : i.getFlows()) {
				if (ft.isJump()) {
					if (f.compareTo(at) <= 0) {
						features.add("backward");
					}
					work.add(f);
				}
			}
			Address next = i.getFallThrough();
			if (next != null) {
				work.add(next);
			}
			else if (ft.isTerminal() && !ft.isCall()) {
				features.add("terminal:" + mn);
			}
		}
	}
}
