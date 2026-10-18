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
// Measures where BankContext would disagree with a reference Ghidra resolved statically (bead
// grm-1qi7): for every operand reference into a banked window, asks BankContext.resolve(instr,
// to) -- "under the bank state provable at this instruction, which memory does this reach?" --
// and reports each reference whose answer is a DIFFERENT space than the one it names. Each hit
// is bucketed by the consumer shape it matches (const-load: MosConstantReferenceAnalyzer /
// StoredValueScanner; indexed-load: table readers and copy-loop sources; indirect-ptr:
// IndirectJumpConstantPointer; flow: calls/jumps) and flagged in-run-switch=true when a bank
// write earlier in the same straight-line run moved the state (the grm-pwuh shape), false when
// residence alone already names another bank.
//
// Output: `BCP hit <site> <mnemonic> kind=<k> ref=<to> resolves=<r> in-run-switch=<b>` per
// hit, then `BCP count kind=<k> in-run-switch=<b> n=<n>` and `BCP total refs-checked=<n>`.
// Read-only. BankContext is package-private, and widening a production class for a diagnostic
// is ruled out (see BankReachProbe), so it is reached by reflection; `BCP error` says when that
// fails. Run as REALROM_EXTRA_POSTSCRIPT, in its own invocation (the cache key does not see it).
//@category RetroMachines.Test

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class BankContextProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Class<?> cls;
		Object ctx;
		Method resolve;
		Method stateBefore;
		Method run;
		try {
			cls = Class.forName("retromachines.BankContext", true,
				BankContextProbe.class.getClassLoader());
			Method forProgram = cls.getDeclaredMethod("forProgram",
				ghidra.program.model.listing.Program.class);
			forProgram.setAccessible(true);
			ctx = forProgram.invoke(null, currentProgram);
			resolve = cls.getDeclaredMethod("resolve", Instruction.class, Address.class);
			stateBefore = cls.getDeclaredMethod("stateBefore", Instruction.class);
			run = cls.getDeclaredMethod("straightLineRun", Instruction.class);
			resolve.setAccessible(true);
			stateBefore.setAccessible(true);
			run.setAccessible(true);
		}
		catch (ReflectiveOperationException e) {
			println("BCP error cannot reach BankContext: " + e);
			return;
		}
		if (ctx == null) {
			println("BCP none (not a banked-board import)");
			return;
		}

		Map<String, Integer> counts = new TreeMap<>();
		int checked = 0;
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction instr = it.next();
			for (Reference ref : instr.getReferencesFrom()) {
				RefType type = ref.getReferenceType();
				Address to = ref.getToAddress();
				if (!to.isMemoryAddress() || type.isWrite() || type.isFallthrough()) {
					continue;
				}
				checked++;
				Address r = (Address) resolve.invoke(ctx, instr, to);
				if (r == null) {
					continue;
				}
				List<?> runList = (List<?>) run.invoke(ctx, instr);
				Object first = runList.get(0);
				boolean inRun = !stateBefore.invoke(ctx, instr)
						.equals(stateBefore.invoke(ctx, first));
				String kind = kind(instr, ref, type);
				println("BCP hit " + fmt(instr.getMinAddress()) + " " + instr.getMnemonicString() +
					" kind=" + kind + " ref=" + fmt(to) + " resolves=" + fmt(r) +
					" in-run-switch=" + inRun);
				counts.merge("kind=" + kind + " in-run-switch=" + inRun, 1, Integer::sum);
			}
		}
		for (Map.Entry<String, Integer> e : counts.entrySet()) {
			println("BCP count " + e.getKey() + " n=" + e.getValue());
		}
		println("BCP total refs-checked=" + checked);
	}

	private static String kind(Instruction instr, Reference ref, RefType type) {
		if (type.isFlow()) {
			return type.isIndirect() || type.isComputed() ? "indirect-ptr" : "flow";
		}
		if (type.isIndirect()) {
			return "indirect-ptr";
		}
		if (!type.isRead() && !type.isData()) {
			return "other:" + type.getName();
		}
		int op = ref.getOperandIndex();
		if (op >= 0) {
			for (Object o : instr.getOpObjects(op)) {
				if (o instanceof Register) {
					return "indexed-load";
				}
			}
		}
		return "const-load";
	}

	private static String fmt(Address a) {
		return a.getAddressSpace().getName() + "::" + String.format("%04x", a.getOffset());
	}
}
