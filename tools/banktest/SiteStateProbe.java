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
// Prints, for each GRM_SITES address (comma-separated offsets in the default space, or
// space-qualified like PRG_ALL_B2::8573), the owning function, the instruction with its flow type
// and flow override, the EOL comment, and every outgoing reference with its type and source. Written for
// grm-kon2 to tell JumpTableBoundAnalyzer's override path from its reference-pinning path at a
// switch. grm-0pen added what REACHED the site: incoming references, the instruction falling into
// it, and the head of its fall-through run with that head's incoming references. Run as
// REALROM_EXTRA_POSTSCRIPT. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;

public class SiteStateProbe extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_SITES");
		if (spec == null) {
			return;
		}
		for (String s : spec.split(",")) {
			Address a = toAddr(s.trim());
			if (a == null) {
				println("SSP " + s.trim() + " unresolvable (default-space sites take no prefix)");
				continue;
			}
			Function owner = currentProgram.getFunctionManager().getFunctionContaining(a);
			println("SSP " + a + " owner=" + (owner == null ? "NONE" : owner.getName() + "@" +
				owner.getEntryPoint()));
			Instruction instr = currentProgram.getListing().getInstructionAt(a);
			println("SSP " + a + " instr=" + (instr == null ? "NONE" : instr + " flow=" +
				instr.getFlowType() + " override=" + instr.getFlowOverride()));
			println("SSP " + a + " eol=" +
				currentProgram.getListing().getComment(CommentType.EOL, a));
			// grm-jt7s: a jump-table override stored for this switch, and how many cases it holds.
			Namespace overrideSpace = owner == null ? null : HighFunction.findOverrideSpace(owner);
			Namespace jmpSpace = overrideSpace == null ? null
					: HighFunction.findNamespace(currentProgram.getSymbolTable(), overrideSpace,
						"jmp_" + a);
			JumpTable jt = jmpSpace == null ? null
					: JumpTable.readOverride(jmpSpace, currentProgram.getSymbolTable());
			String cases;
			try {
				cases = jt == null ? "NONE" : jt.getCases().length + " cases";
			}
			catch (NullPointerException e) {
				cases = "present (no case table read back)";
			}
			println("SSP " + a + " override=" + cases);
			for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(a)) {
				println("SSP " + a + " ref " + r.getToAddress() + " " + r.getReferenceType() + " " +
					r.getSource() + " primary=" + r.isPrimary());
			}
			// What reached this site (grm-0pen): incoming references, and whether the instruction
			// just before it falls through into it -- the two ways flow disassembles an address.
			for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
				println("SSP " + a + " from " + r.getFromAddress() + " " + r.getReferenceType() + " " +
					r.getSource() + " primary=" + r.isPrimary());
			}
			Instruction prev = currentProgram.getListing().getInstructionBefore(a);
			if (prev != null && prev.getMaxAddress().next() != null &&
				prev.getMaxAddress().next().equals(a)) {
				println("SSP " + a + " prev=" + prev.getMinAddress() + " " + prev + " flow=" +
					prev.getFlowType() + " fallthrough=" + prev.getFallThrough());
			}
			// Walk back through fall-through predecessors to the run's head: the first instruction
			// nothing falls into, which is where some reference (or seed) started this flow.
			Instruction head = currentProgram.getListing().getInstructionAt(a);
			for (int i = 0; head != null && i < 256; i++) {
				Instruction p = currentProgram.getListing().getInstructionBefore(head.getMinAddress());
				if (p == null || !head.getMinAddress().equals(p.getFallThrough())) {
					break;
				}
				head = p;
			}
			if (head != null && !head.getMinAddress().equals(a)) {
				println("SSP " + a + " head=" + head.getMinAddress() + " " + head);
				for (Reference r : currentProgram.getReferenceManager()
						.getReferencesTo(head.getMinAddress())) {
					println("SSP " + a + " head-from " + r.getFromAddress() + " " +
						r.getReferenceType() + " " + r.getSource() + " primary=" + r.isPrimary());
				}
			}
		}
	}
}
