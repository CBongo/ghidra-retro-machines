// Narrow probe (written for grm-gipk.24): prints the decompiled C, decompile time and function
// body size for the function containing each address in GRM_DUMP_SITES (comma-separated; hex in
// the default space, or "SPACE::hex"). Read-only. Run as a postScript:
//   GRM_DUMP_SITES=W8000_B20::8524 REALROM_EXTRA_POSTSCRIPT=DecompileDump.java \
//     REALROM_WORK_DIR=<dir outside the repo> bash tools/banktest/realrom-test.sh check nes --only cv3
// Output lines start "DUMP " in <dir>/<id>.log.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.script.GhidraScript;
import java.util.HashSet;
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
		}
	}
}
