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
// Lists every no-return function and the damage it does through thunks (bead grm-0fzb). One
// `NORET <entry> <name> by=<stock|other> thunk=<target|-> calls=<n> stopped=<n> thunks=<n>
// thunkCalls=<n> thunkStopped=<n> head=<first mnemonics>` line per no-return function, where
// `by=stock` means stock FindNoReturnFunctionsAnalyzer's "Non-Returning Function" bookmark is at
// the entry, `calls`/`stopped` count call references to the entry and how many of those call
// instructions have no fall-through, and `thunks*` do the same for every thunk of it (a far-call
// stub made a thunk of a no-return helper strands its own callers: grm-hf5h.12). `head` is the
// first instructions on the entry's straight-line flow, enough to tell a PLA/PLA pop-return or
// far-call helper from an infinite loop. Ends with `NORET total <n> stock <n> thunks <n>
// thunkStopped <n>`. Run as REALROM_EXTRA_POSTSCRIPT. Read-only.

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class NoReturnProbe extends GhidraScript {

	private static final int HEAD = 8;

	@Override
	protected void run() throws Exception {
		int total = 0;
		int stock = 0;
		int thunkTotal = 0;
		int thunkStoppedTotal = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!f.hasNoReturn()) {
				continue;
			}
			total++;
			Address entry = f.getEntryPoint();
			boolean byStock = false;
			for (Bookmark b : currentProgram.getBookmarkManager().getBookmarks(entry)) {
				if (BookmarkType.ANALYSIS.equals(b.getTypeString()) &&
					"Non-Returning Function".equals(b.getCategory())) {
					byStock = true;
				}
			}
			if (byStock) {
				stock++;
			}
			int[] direct = countCalls(entry);
			int thunkCalls = 0;
			int thunkStopped = 0;
			Address[] thunks = f.getFunctionThunkAddresses(true);
			List<String> thunkNames = new ArrayList<>();
			if (thunks != null) {
				for (Address t : thunks) {
					int[] c = countCalls(t);
					thunkCalls += c[0];
					thunkStopped += c[1];
					thunkNames.add(fmt(t));
				}
				thunkTotal += thunks.length;
			}
			thunkStoppedTotal += thunkStopped;
			Function target = f.isThunk() ? f.getThunkedFunction(false) : null;
			println("NORET " + fmt(entry) + " " + f.getName() + " by=" + (byStock ? "stock" : "other") +
				" thunk=" + (target == null ? "-" : fmt(target.getEntryPoint())) + " calls=" +
				direct[0] + " stopped=" + direct[1] + " thunks=" + thunkNames + " thunkCalls=" +
				thunkCalls + " thunkStopped=" + thunkStopped + " head=" + head(entry));
		}
		println("NORET total " + total + " stock " + stock + " thunks " + thunkTotal +
			" thunkStopped " + thunkStoppedTotal);
	}

	/** {calls, calls without fall-through} into {@code to}. */
	private int[] countCalls(Address to) {
		int calls = 0;
		int stopped = 0;
		for (Reference r : currentProgram.getReferenceManager().getReferencesTo(to)) {
			if (!r.getReferenceType().isCall()) {
				continue;
			}
			Instruction call = currentProgram.getListing().getInstructionAt(r.getFromAddress());
			if (call == null) {
				continue;
			}
			calls++;
			if (call.getFallThrough() == null) {
				stopped++;
			}
		}
		return new int[] { calls, stopped };
	}

	private String head(Address entry) {
		StringBuilder sb = new StringBuilder();
		Instruction instr = currentProgram.getListing().getInstructionAt(entry);
		for (int i = 0; i < HEAD && instr != null; i++) {
			if (sb.length() > 0) {
				sb.append('/');
			}
			sb.append(instr.toString().replace(' ', '_'));
			Address next = instr.getFallThrough();
			instr = next == null ? null : currentProgram.getListing().getInstructionAt(next);
		}
		return sb.toString();
	}

	private static String fmt(Address a) {
		return ProbeSupport.fmtAddr(a);
	}
}
