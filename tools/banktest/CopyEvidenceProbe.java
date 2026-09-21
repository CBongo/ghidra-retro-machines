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
// Diagnostic postScript for the real-ROM tier (REALROM_EXTRA_POSTSCRIPT=CopyEvidenceProbe.java):
// what the analyzed program knows about every copy loop CopyLoopAnalyzer saw.
//
// For each DECLINED loop (its NOTE bookmark), every reference landing in the destination
// range -- type, source, whether the source is an instruction -- and whether anything is
// defined there. For each MATERIALIZED copy (a COPY_* block), the listing inside it with
// functions, EOL comments and bookmarks, so a copy that was placed but not disassembled, or
// disassembled but not analyzed, shows as such.
//
// Written for grm-k5m, where two questions had to be answered from the analyzed program rather
// than from the ROM bytes: "why does the program-wide evidence gate not fire on wizwarr's
// $0300/$032d/$033d stubs" (no caller was ever disassembled) and "why did COPY_0300 come out
// initialized but empty" (an undefined1 planted by data-reference analysis blocked the
// disassembler). Output is fenced in COPYEVIDENCE lines and is not part of any golden.
//@category RetroMachines.Diagnostics
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CopyEvidenceProbe extends GhidraScript {

	private static final Pattern DECLINED = Pattern.compile(
		"copy-shaped loop (\\S+):([0-9a-f]+) -> (\\S+):([0-9a-f]+) \\((\\d+) bytes\\)");

	@Override
	public void run() throws Exception {
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		Iterator<Bookmark> it = currentProgram.getBookmarkManager().getBookmarksIterator("Note");
		while (it.hasNext()) {
			Bookmark bm = it.next();
			if (!"CopyLoopAnalyzer".equals(bm.getCategory())) {
				continue;
			}
			Matcher m = DECLINED.matcher(bm.getComment());
			if (!m.find()) {
				continue;
			}
			Address dst = currentProgram.getAddressFactory().getAddressSpace(m.group(3))
					.getAddress(Long.parseLong(m.group(4), 16));
			int len = Integer.parseInt(m.group(5));
			Address end = dst.add(len - 1);
			CodeUnit cu = currentProgram.getListing().getCodeUnitAt(dst);
			println("COPYEVIDENCE declined loop@" + bm.getAddress() + " dst=" + dst + " len=" +
				len + " atDst=" + (cu == null ? "<nothing>" : cu.getClass().getSimpleName() + " " + cu));
			AddressIterator targets =
				refMgr.getReferenceDestinationIterator(new AddressSet(dst, end), true);
			int n = 0;
			while (targets.hasNext()) {
				Address t = targets.next();
				for (Reference r : refMgr.getReferencesTo(t)) {
					n++;
					println("COPYEVIDENCE   ref " + r.getFromAddress() + " -> " + t + " " +
						r.getReferenceType() + " src=" + r.getSource() + " fromInstr=" +
						(currentProgram.getListing().getInstructionAt(r.getFromAddress()) != null));
				}
			}
			println("COPYEVIDENCE   refs=" + n);
		}

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.getName().startsWith("COPY_")) {
				continue;
			}
			AddressSet body = new AddressSet(block.getStart(), block.getEnd());
			println("COPYEVIDENCE materialized " + block.getName() + " " + block.getStart() + "-" +
				block.getEnd() + " init=" + block.isInitialized() + " disassembled=" +
				currentProgram.getListing().getInstructions(body, true).hasNext());
			AddressIterator flowsIn = refMgr.getReferenceDestinationIterator(body, true);
			while (flowsIn.hasNext()) {
				Address t = flowsIn.next();
				for (Reference r : refMgr.getReferencesTo(t)) {
					if (r.getReferenceType().isFlow()) {
						Instruction from = currentProgram.getListing().getInstructionAt(r.getFromAddress());
						println("COPYEVIDENCE   flow " + r.getFromAddress() + " -> " + t + " " +
							r.getReferenceType() + " src=" + r.getSource() + " from=" + from);
					}
				}
			}
			for (Instruction in : currentProgram.getListing().getInstructions(body, true)) {
				String eol = currentProgram.getListing().getComment(CommentType.EOL, in.getAddress());
				Function f = currentProgram.getFunctionManager().getFunctionAt(in.getAddress());
				StringBuilder marks = new StringBuilder();
				for (Bookmark b : currentProgram.getBookmarkManager().getBookmarks(in.getAddress())) {
					marks.append(" [").append(b.getTypeString()).append('/').append(b.getCategory())
							.append("] ").append(b.getComment());
				}
				println("COPYEVIDENCE   " + in.getAddress() + "  " + in +
					(f != null ? "   <FUNCTION " + f.getName() + ">" : "") +
					(eol != null ? "   ; " + eol : "") + marks);
			}
		}
	}
}
