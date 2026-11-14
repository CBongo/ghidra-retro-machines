// Narrow probe (grm-4x8f): every PROGRAM_INFO property on the program, with whether Ghidra's
// About Program / Program Information view shows it. ProgramDB.getMetadata() (12.2) skips any
// name containing Options.DELIMITER ('.') as a "second tier option", so those are marked HIDDEN.
// Long values are cut at GRM_PINFO_WIDTH characters (default 160; 0 = no cut).
// Read-only; every line is prefixed "PINFO ".
//@category RetroMachines.Test

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class ProgramInfoDump extends GhidraScript {

	@Override
	protected void run() throws Exception {
		int width = 160;
		String w = System.getenv("GRM_PINFO_WIDTH");
		if (w != null && !w.isBlank()) {
			width = Integer.parseInt(w.trim());
		}
		Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
		List<String> names = new ArrayList<>(info.getOptionNames());
		Collections.sort(names);
		println("PINFO program " + currentProgram.getName());
		for (String n : names) {
			String v = info.getValueAsString(n);
			if (v == null) {
				continue;
			}
			v = v.replace("\r", "").replace("\n", " | ");
			if (width > 0 && v.length() > width) {
				v = v.substring(0, width) + "... (" + v.length() + " chars)";
			}
			String vis = n.indexOf(Options.DELIMITER) >= 0 ? "HIDDEN " : "shown  ";
			println("PINFO " + vis + n + " = " + v);
		}
	}
}
