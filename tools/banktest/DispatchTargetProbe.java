// Narrow probe (grm-hf5h.24): are the COMPUTED_JUMP targets of one dispatch site plausible code?
// For each site in GRM_SITES (hex, comma-separated, default space) prints every computed-jump
// reference target with: whether an instruction STARTS exactly there, whether it is inside another
// instruction (mid-instruction) or defined data, its containing function, and the instruction
// text; then the 16 instructions before the site (the table setup) and every data reference from
// that window to a table, with the table's Data type and length. Read-only; lines start "DTP ".
// Run on a kept row: REALROM_EXTRA_POSTSCRIPT=DispatchTargetProbe.java GRM_SITES=03bf43 ...
//@category RetroMachines.Test

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DispatchTargetProbe extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String sites = System.getenv("GRM_SITES");
		if (sites == null || sites.isBlank()) return;
		Listing l = currentProgram.getListing();
		for (String s : sites.split(",")) {
			Address a = ProbeSupport.parseSiteFactory(currentProgram, s);
			Instruction site = l.getInstructionAt(a);
			if (site == null) { println("DTP " + s + " no instruction"); continue; }
			int n = 0, startOk = 0, mid = 0, data = 0, noFn = 0;
			Set<Address> seen = new TreeSet<>();
			for (Reference r : site.getReferencesFrom()) {
				if (r.getReferenceType().isComputed() && r.getReferenceType().isJump()) seen.add(r.getToAddress());
			}
			for (Address t : seen) {
				n++;
				Instruction ti = l.getInstructionAt(t);
				Instruction cont = l.getInstructionContaining(t);
				Data d = l.getDefinedDataContaining(t);
				Function f = currentProgram.getFunctionManager().getFunctionContaining(t);
				String kind;
				if (ti != null) { startOk++; kind = "insn"; }
				else if (cont != null) { mid++; kind = "MID-INSN of " + cont.getAddress(); }
				else if (d != null) { data++; kind = "DATA " + d.getDataType().getName(); }
				else kind = "undefined";
				if (f == null) noFn++;
				println("DTP " + s + " target " + t + " " + kind + " fn=" + (f == null ? "-" : f.getName()) +
					" " + (ti == null ? "" : ti.toString()));
			}
			println("DTP " + s + " targets=" + n + " insnStart=" + startOk + " midInsn=" + mid + " data=" +
				data + " noFunction=" + noFn);
			Instruction p = site;
			for (int i = 0; i < 16 && p != null; i++) p = p.getPrevious();
			for (int i = 0; i < 17 && p != null; i++, p = p.getNext()) {
				StringBuilder sb = new StringBuilder("DTP " + s + " ctx " + p.getAddress() + " " + p);
				for (Reference r : p.getReferencesFrom())
					if (r.isMemoryReference() && !r.getReferenceType().isFlow()) {
						Data d = l.getDataContaining(r.getToAddress());
						sb.append(" [").append(r.getReferenceType()).append("->").append(r.getToAddress());
						if (d != null) sb.append(" ").append(d.getDataType().getName()).append(" len=").append(d.getLength());
						sb.append("]");
					}
				println(sb.toString());
			}
		}
	}
}
