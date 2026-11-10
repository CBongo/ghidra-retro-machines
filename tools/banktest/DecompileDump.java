// Narrow probe (written for grm-gipk.24): prints the decompiled C, decompile time and function
// body size for the function containing each address in GRM_DUMP_SITES (comma-separated; hex in
// the default space, or "SPACE::hex"). Read-only. Run as a postScript:
//   GRM_DUMP_SITES=W8000_B20::8524 REALROM_EXTRA_POSTSCRIPT=DecompileDump.java \
//     REALROM_WORK_DIR=<dir outside the repo> bash tools/banktest/realrom-test.sh check nes --only cv3
// Output lines start "DUMP " in <dir>/<id>.log. GRM_DUMP_PCODE=1 also prints each function's
// final high p-code ("DUMP PCODE" lines; grm-gipk.25).
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class DecompileDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_DUMP_SITES");
		if (spec == null || spec.isBlank()) {
			println("DUMP GRM_DUMP_SITES is not set; nothing to do");
			return;
		}
		DecompInterface ifc = new DecompInterface();
		ifc.toggleJumpLoads(true);
		ifc.openProgram(currentProgram);
		Set<Function> seen = new HashSet<>();
		for (String s : spec.split(",")) {
			Address a = currentProgram.getAddressFactory().getAddress(s.trim());
			if (a == null && s.contains("::")) a = toAddr(s.substring(s.indexOf("::") + 2).trim());
			Function f = a == null ? null : currentProgram.getFunctionManager().getFunctionContaining(a);
			if (f == null) { println("DUMP " + s + " no function contains it"); continue; }
			if (!seen.add(f)) { println("DUMP " + s + " same function as above: " + f.getName()); continue; }
			long t0 = System.currentTimeMillis();
			DecompileResults res = ifc.decompileFunction(f, 120, monitor);
			long ms = System.currentTimeMillis() - t0;
			println("DUMP ==== " + s + " fn=" + f.getName() + "@" + f.getEntryPoint() + " bodyBytes=" +
				f.getBody().getNumAddresses() + " ms=" + ms + " completed=" + res.decompileCompleted());
			if (!res.decompileCompleted()) { println("DUMP FAILED " + res.getErrorMessage()); continue; }
			for (String line : res.getDecompiledFunction().getC().split("\n")) println("DUMP | " + line);
			if ("1".equals(System.getenv("GRM_DUMP_PCODE"))) dumpPcode(res.getHighFunction());
		}
	}

	/**
	 * GRM_DUMP_PCODE=1 (grm-gipk.25): the HighFunction's final p-code, one op per line, in block
	 * order, each written varnode tagged with its unique id so the def-use chains can be followed
	 * by hand (e.g. how a BRANCHIND input is pieced from two LOAD chains).
	 */
	private void dumpPcode(HighFunction hf) {
		if (hf == null) { println("DUMP PCODE no HighFunction"); return; }
		for (PcodeBlockBasic bb : hf.getBasicBlocks()) {
			println("DUMP PCODE block " + bb.getStart() + ".." + bb.getStop());
			Iterator<PcodeOp> it = bb.getIterator();
			while (it.hasNext()) {
				PcodeOp op = it.next();
				StringBuilder sb = new StringBuilder("DUMP PCODE   ");
				sb.append(op.getSeqnum().getTarget()).append(':').append(op.getSeqnum().getTime())
					.append("  ");
				Varnode out = op.getOutput();
				if (out != null) sb.append(vn(out)).append(" = ");
				sb.append(op.getMnemonic());
				for (int i = 0; i < op.getNumInputs(); i++) sb.append(' ').append(vn(op.getInput(i)));
				println(sb.toString());
			}
		}
	}

	private static String vn(Varnode v) {
		if (v == null) return "null";
		String id = v instanceof VarnodeAST ast ? "#" + ast.getUniqueId() : "";
		if (v.isConstant()) return "0x" + Long.toHexString(v.getOffset()) + ":" + v.getSize();
		return "(" + v.getAddress() + ":" + v.getSize() + ")" + id;
	}
}
