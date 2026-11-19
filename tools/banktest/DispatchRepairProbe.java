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
// For every computed call carrying a CALL_RETURN flow override, prints what
// W65816NoReturnFlagAnalyzer.repairDispatchCalls() decides on (bead grm-hf5h.33): the
// indirect operand's address as the committed instruction reports it, the operand's references,
// the function getReferencedFunction() returns for it (the Disassembler's first-slot check), its
// thunk target, whether that carries the analyzer's bookmark, and each flow target with its
// no-return flag. Run as REALROM_EXTRA_POSTSCRIPT (with the analyzer enabled by a prescript).
// Read-only.
//
//   REALROM_EXTRA_PRESCRIPT="SetAnalyzerEnabled.java analyzer:Retro_65816_Non-Returning_Functions enabled:true" \
//   REALROM_EXTRA_POSTSCRIPT=DispatchRepairProbe.java \
//     bash tools/banktest/realrom-test.sh check --only w_ct snes-analysis
//
// Output: `DRP site ...`, `DRP  ref ...`, `DRP  flow ...` lines in the log.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class DispatchRepairProbe extends GhidraScript {

	private static final String BOOKMARK = "Non-Returning Function (proven)";

	@Override
	protected void run() throws Exception {
		int n = 0;
		for (Instruction call : currentProgram.getListing().getInstructions(true)) {
			var ft = call.getFlowType();
			if (!ft.isCall() || !ft.isComputed() ||
				call.getFlowOverride() != FlowOverride.CALL_RETURN) {
				continue;
			}
			n++;
			println("DRP site " + call.getAddress() + " " + call + " flow=" + ft);
			for (int op = 0; op < call.getNumOperands(); op++) {
				var rt = call.getOperandRefType(op);
				Address a = call.getAddress(op);
				Function f = a == null ? null :
					currentProgram.getFunctionManager().getReferencedFunction(a);
				Function t = f != null && f.isThunk() ? f.getThunkedFunction(true) : null;
				println("DRP  op" + op + " refType=" + rt + " indirect=" + rt.isIndirect() +
					" addr=" + a + " refFn=" + describe(f) + " thunkTo=" + describe(t));
				for (Reference r : call.getOperandReferences(op)) {
					println("DRP  ref op" + op + " -> " + r.getToAddress() + " " +
						r.getReferenceType() + " primary=" + r.isPrimary() + " src=" + r.getSource());
				}
			}
			for (Address t : call.getFlows()) {
				println("DRP  flow -> " + t + " fn=" +
					describe(currentProgram.getFunctionManager().getFunctionAt(t)));
			}
			if (call.getFlows().length == 0) {
				println("DRP  flow (none)");
			}
		}
		println("DRP total=" + n);
	}

	private String describe(Function f) {
		if (f == null) {
			return "-";
		}
		boolean bm = currentProgram.getBookmarkManager().getBookmark(f.getEntryPoint(),
			BookmarkType.ANALYSIS, BOOKMARK) != null;
		return f.getEntryPoint() + "(noRet=" + f.hasNoReturn() + ",bm=" + bm + ",thunk=" +
			f.isThunk() + ")";
	}
}
