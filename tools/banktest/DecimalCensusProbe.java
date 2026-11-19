// Narrow probe (grm-hf5h.31): 65816 decimal-mode census for the ctx_DF decode split. Counts SED,
// CLD, REP/SEP whose operand touches bit 3 (the D flag), PLP and RTI, then every instruction
// decoded under ctx_DF=1 (total, and ADC/SBC split by ctx_DF), so "how much code still decodes the
// runtime decimal arm" and "is a ctx_DF=0 default sound here" are one run.
// Read-only; every line is prefixed "DFC ". Run on `snes-analysis` with
// REALROM_EXTRA_POSTSCRIPT=DecimalCensusProbe.java REALROM_WORK_DIR=<dir>; output is in
// <dir>/<id>.log.
//@category RetroMachines.Test

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class DecimalCensusProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Register df = currentProgram.getRegister("ctx_DF");
		if (df == null) {
			println("DFC none (no ctx_DF)");
			return;
		}
		Map<String, Integer> c = new TreeMap<>();
		int total = 0;
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction in = it.next();
			total++;
			String m = in.getMnemonicString().toUpperCase();
			BigInteger v = in.getValue(df, false);
			boolean d1 = v != null && v.intValue() == 1;
			if (d1) {
				bump(c, "instrs_df1");
			}
			switch (m) {
				case "SED", "CLD", "PLP", "RTI" -> bump(c, m);
				case "REP", "SEP" -> {
					Object[] o = in.getOpObjects(0);
					if (o.length == 1 && o[0] instanceof Scalar s) {
						if ((s.getUnsignedValue() & 8) != 0) {
							bump(c, m + "_bit3");
						}
					}
					else {
						bump(c, m + "_nonconst");
					}
				}
				case "ADC", "SBC" -> {
					bump(c, m + (d1 ? "_df1" : "_df0"));
				}
				default -> {
				}
			}
		}
		println("DFC instrs " + total);
		for (Map.Entry<String, Integer> e : c.entrySet()) {
			println("DFC " + e.getKey() + " " + e.getValue());
		}
	}

	private static void bump(Map<String, Integer> m, String k) {
		m.merge(k, 1, Integer::sum);
	}
}
