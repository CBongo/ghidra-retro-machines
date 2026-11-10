// Narrow probe (grm-gipk.25; recipe in the decompiler-ab-via-junction-shadow-install bd memory):
// prints the decompile.exe Ghidra will actually launch, one "WHICHDECOMP <path>" line per import.
// Use it to verify a junction-shadow install really swapped the binary -- the "== decompiler: =="
// banner fingerprints the file the shadow holds, not what Java launches. Run as a preScript:
//   REALROM_EXTRA_PRESCRIPT=WhichDecompiler.java GHIDRA_HEADLESS=<shadow>/support/analyzeHeadless.bat \
//     GRM_GHIDRA_INSTALL=<shadow> GHIDRA_INSTALL_DIR= bash tools/banktest/realrom-test.sh check --no-build
// then: grep -h WHICHDECOMP <workdir>/*.log | sort | uniq -c   (needs REALROM_WORK_DIR to keep logs)
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;

public class WhichDecompiler extends GhidraScript {
	@Override
	protected void run() throws Exception {
		println("WHICHDECOMP " + Application.getOSFile("decompile.exe").getAbsolutePath());
	}
}
