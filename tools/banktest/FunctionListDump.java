// Narrow probe (written for grm-hf5h.3): prints one line per function ("FUNCLIST <entry> <name>
// <body addresses>") and one per switch override under a function ("OVERRIDE <fn> <jmp site>
// <ndests> <first/last dest>, in-body count, dests that are not an instruction start"). Read-only.
// Run as a postScript, one run per build, then diff the two logs' FUNCLIST/OVERRIDE lines:
//   REALROM_EXTRA_POSTSCRIPT=FunctionListDump.java REALROM_WORK_DIR=<dir outside the repo> \
//     bash tools/banktest/realrom-test.sh check snes --only w_fzero,w_ff3
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.List;

public class FunctionListDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		SymbolTable symtab = currentProgram.getSymbolTable();
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			println("FUNCLIST " + f.getEntryPoint() + " " + f.getName() + " " +
				f.getBody().getNumAddresses());
			Namespace ov = HighFunction.findOverrideSpace(f);
			if (ov == null) {
				continue;
			}
			for (Symbol s : symtab.getChildren(ov.getSymbol())) {
				Namespace jmp = (Namespace) s.getObject();
				List<Address> dests = new ArrayList<>();
				for (Symbol c : symtab.getSymbols(jmp)) {
					if (c.getName().startsWith("case")) {
						dests.add(c.getAddress());
					}
				}
				dests.sort(null);
				int inBody = 0;
				int notInstr = 0;
				for (Address d : dests) {
					if (f.getBody().contains(d)) {
						inBody++;
					}
					if (currentProgram.getListing().getInstructionAt(d) == null) {
						notInstr++;
					}
				}
				println("OVERRIDE " + f.getEntryPoint() + " " + s.getName() + " n=" + dests.size() +
					(dests.isEmpty() ? "" : " first=" + dests.get(0) + " last=" +
						dests.get(dests.size() - 1)) +
					" inBody=" + inBody + " notInstrStart=" + notInstr);
				String want = System.getenv("GRM_LIST_SITES");   // e.g. jmp_038074,jmp_c25ade
				if (want != null && (want.equals("1") || want.contains(s.getName()))) {
					for (Address d : dests) {
						Function in = currentProgram.getFunctionManager().getFunctionContaining(d);
						println("OVERRIDE-CASE " + s.getName() + " " + d + " inOwnerBody=" +
							f.getBody().contains(d) + " containingFn=" + (in == null ? "-" : in.getName()) +
							" instr=" + currentProgram.getListing().getInstructionAt(d) + " refFromSite=" +
							hasRef(s.getName(), d));
					}
				}
				if (notInstr > 0 && System.getenv("GRM_LIST_BADDESTS") != null) {
					Address site = currentProgram.getAddressFactory().getAddress(
						s.getName().substring(4));
					println("OVERRIDE-SITE " + s.getName() + " instr=" +
						(site == null ? "?" : currentProgram.getListing().getInstructionAt(site)));
					for (ghidra.program.model.listing.Instruction in :
						currentProgram.getListing().getInstructions(f.getBody(), true)) {
						println("OVERRIDE-BODY " + s.getName() + " " + in.getAddress() + " " + in +
							(in.getFlowType().isComputed() ? " refs=" +
								java.util.Arrays.toString(in.getReferencesFrom()) : ""));
					}
					for (Address d : dests) {
						byte[] b = new byte[4];
						currentProgram.getMemory().getBytes(d, b);
						println("OVERRIDE-DEST " + s.getName() + " " + d + " bytes=" +
							String.format("%02x %02x %02x %02x", b[0], b[1], b[2], b[3]) +
							" instr=" + currentProgram.getListing().getInstructionAt(d) +
							" data=" + currentProgram.getListing().getDefinedDataAt(d) +
							" block=" + currentProgram.getMemory().getBlock(d).getName());
					}
				}
			}
		}
	}

	/** Whether the jump named jmp_<addr> still has a reference to d (grm-hf5h.5). */
	private boolean hasRef(String jmpName, Address d) {
		Address site = currentProgram.getAddressFactory().getAddress(jmpName.substring(4));
		if (site == null) {
			return false;
		}
		for (ghidra.program.model.symbol.Reference r : currentProgram.getReferenceManager().getReferencesFrom(site)) {
			if (r.getToAddress().equals(d)) {
				return true;
			}
		}
		return false;
	}
}
