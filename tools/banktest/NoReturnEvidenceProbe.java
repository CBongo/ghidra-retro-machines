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
// Says WHICH evidence stock FindNoReturnFunctionsAnalyzer would count at each call into one
// target (bead grm-z0d7). Re-derives stock's checkNonReturningIndicators (12.2) per call site and
// prints `NOREVID <caller> -> <target> <reason> at=<addr>` or `... none`, then
// `NOREVID total <calls> evidence <n>`. Stock marks the target no-return once 3 sites (its
// default evidence threshold) show evidence.
//
// Run with stock's analyzer OFF, so the listing is the one stock would have judged rather than
// the one its own damage repair left behind:
//
//   REALROM_EXTRA_PRESCRIPT="SetAnalyzerEnabled.java analyzer:Non-Returning_Functions_-_Discovered enabled:false" \
//   NOREVID_TARGET=dd4e REALROM_EXTRA_POSTSCRIPT=NoReturnEvidenceProbe.java \
//     bash tools/banktest/realrom-test.sh check nes --only smb3
//
// NOREVID_TARGET: hex offset(s) in the default space, comma-separated; each also prints its
// refsTo and the function there. REALROM_EXTRA_POSTSCRIPT passes no script
// arguments; where -postScript arguments can be given, target:<hex> works too. Read-only.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class NoReturnEvidenceProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String targetHex = System.getenv("NOREVID_TARGET");
		for (String a : getScriptArgs()) {
			if (a.startsWith("target:")) {
				targetHex = a.substring("target:".length());
			}
		}
		if (targetHex == null) {
			println("NOREVID error: set NOREVID_TARGET=<hex> or pass target:<hex>");
			return;
		}
		for (String one : targetHex.split(",")) {
			Address target = currentProgram.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(Long.parseLong(one.trim(), 16));
			println("NOREVID target " + target + " refsTo=" + refsTo(target) + " func=" +
				currentProgram.getFunctionManager().getFunctionAt(target));
			judge(target);
		}
	}

	private void judge(Address target) {
		int calls = 0;
		int evidence = 0;
		for (Reference r : currentProgram.getReferenceManager().getReferencesTo(target)) {
			if (!r.getReferenceType().isCall()) {
				continue;
			}
			Instruction inst = currentProgram.getListing().getInstructionAt(r.getFromAddress());
			if (inst == null) {
				println("NOREVID " + r.getFromAddress() + " -> " + target + " no-instruction");
				continue;
			}
			calls++;
			String reason = indicators(inst, target);
			if (reason != null) {
				evidence++;
			}
			println("NOREVID " + inst.getMinAddress() + " -> " + target + " " +
				(reason == null ? "none" : reason) + " flow=" + inst.getFlowType());
		}
		println("NOREVID total " + calls + " evidence " + evidence);
	}

	/** Stock's checkNonReturningIndicators, returning the reason instead of a boolean. */
	private String indicators(Instruction callInst, Address target) {
		Address fallThru = callInst.getFallThrough();
		if (fallThru == null) {
			fallThru = callInst.getMaxAddress().next();
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		Function callingFunc = fm.getFunctionContaining(callInst.getMinAddress());
		Address nextFuncAddr = null;
		FunctionIterator it = fm.getFunctions(fallThru, true);
		if (it.hasNext()) {
			nextFuncAddr = it.next().getEntryPoint();
		}
		Listing listing = currentProgram.getListing();
		while (fallThru != null) {
			if (nextFuncAddr != null && nextFuncAddr.equals(fallThru)) {
				return "function-after-call at=" + fallThru + " refsTo=" + refsTo(fallThru);
			}
			CodeUnit cu = listing.getCodeUnitAt(fallThru);
			if (cu == null || cu instanceof Data) {
				Instruction before = listing.getInstructionBefore(fallThru);
				Instruction after = listing.getInstructionAfter(fallThru);
				return "falls-into-data at=" + fallThru +
					(cu == null ? " (no code unit)" : " (" + cu + ")") + " prev=" +
					(before == null ? "-" : before.getMinAddress() + ":" + before) + " next=" +
					(after == null ? "-" : after.getMinAddress() + ":" + after) + " refsTo=" +
					refsTo(fallThru);
			}
			Instruction instr = (Instruction) cu;
			if (nextFuncAddr != null && cu.contains(nextFuncAddr)) {
				return "function-in-instruction-after-call at=" + fallThru;
			}
			String refs = inconsistentRefs(fallThru, fm, callingFunc);
			if (refs != null) {
				return refs;
			}
			fallThru = instr.getFlowType().isFallthrough() ? instr.getFallThrough() : null;
		}
		return null;
	}

	/** Every reference to addr, as from:type[:source], so a stray entry can be traced. */
	private String refsTo(Address addr) {
		StringBuilder sb = new StringBuilder("[");
		for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(addr)) {
			if (sb.length() > 1) {
				sb.append(',');
			}
			sb.append(ref.getFromAddress()).append(':').append(ref.getReferenceType());
			sb.append(':').append(ref.getSource());
		}
		return sb.append(']').toString();
	}

	private String inconsistentRefs(Address addr, FunctionManager fm, Function callingFunc) {
		for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(addr)) {
			RefType t = ref.getReferenceType();
			Address from = ref.getFromAddress();
			if (t.isRead() || t.isWrite()) {
				if (callingFunc != null) {
					if (from.compareTo(addr) < 0 && callingFunc.equals(fm.getFunctionContaining(from))) {
						return "data-ref-same-function at=" + addr + " from=" + from + " " + t;
					}
				}
				else {
					return "data-ref-no-caller-function at=" + addr + " from=" + from + " " + t;
				}
			}
			if (t.isCall()) {
				return "call-ref-after-call at=" + addr + " from=" + from;
			}
		}
		return null;
	}
}
