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
// Headless regression for DescriptorAnnotationAnalyzer's one-shot re-run on an already-imported
// program (bead grm-hb6.16). The JUnit test covers applyAll only; resolving the descriptor data
// file through the installed extension (DescriptorResources.loadMap) does not work in plain
// JUnit, so this is the only place the analyzer's real entry point is exercised.
//
// Run as a POST-verify -postScript on a freshly imported NES program (the descriptor's
// "nes-mmio" symbol set, machines/fragments/nes-common.yaml, is applied at import). It
// simulates "a newer descriptor ships a label this program does not have yet" by mutating the
// labels, then schedules the analyzer one-shot exactly as Analysis -> One Shot would:
//
//   phase 1  PPUMASK ($2001) deleted; PPUSTATUS ($2002) replaced by a USER_DEFINED label;
//            the recorded symbol-set choice flipped to {"nes-mmio": false}.
//            Re-run -> NOTHING restored (a set the loader declined stays declined).
//   phase 2  the recorded choice cleared (a set with no recorded choice falls back to the
//            descriptor's default: on).  Re-run -> PPUMASK restored; the USER_DEFINED label
//            still primary at $2002 and PPUSTATUS NOT re-added there; PPUCTRL untouched.
//   phase 3  re-run again -> total symbol count unchanged (idempotent).
//
// Prints one verdict line outside the BANKDUMP markers (run-banktest.sh greps it):
//   DESCREANALYSIS verdict=PASS|FAIL
// preceded by one DESCREANALYSIS check=<id> ok=<bool> line per check.
//
//@category RetroMachines.Test

import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.classfinder.ClassSearcher;

public class AssertDescriptorReanalysis extends GhidraScript {

	private static final String ANALYZER_NAME = "Descriptor Annotations";
	private static final String SYMBOL_SETS_PROPERTY = "Retro Machines.Symbol Sets";

	private boolean allOk = true;

	@Override
	protected void run() throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		Address ppuCtrl = toAddr(0x2000);
		Address ppuMask = toAddr(0x2001);
		Address ppuStatus = toAddr(0x2002);

		check("pre:labels-imported", has(ppuCtrl, "PPUCTRL") && has(ppuMask, "PPUMASK") &&
			has(ppuStatus, "PPUSTATUS"));
		check("pre:property-recorded", currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(SYMBOL_SETS_PROPERTY, "").contains("nes-mmio"));

		// Mutate: this is the "newer descriptor ships PPUMASK" / "user relabelled $2002" state.
		int tx = currentProgram.startTransaction("mutate labels");
		try {
			for (Symbol s : st.getSymbols(ppuMask)) {
				s.delete();
			}
			for (Symbol s : st.getSymbols(ppuStatus)) {
				s.delete();
			}
			st.createLabel(ppuStatus, "MY_STATUS", SourceType.USER_DEFINED);
			currentProgram.getOptions(Program.PROGRAM_INFO).setString(SYMBOL_SETS_PROPERTY,
				"{\"nes-mmio\":false}");
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		check("mut:ppumask-gone", !has(ppuMask, "PPUMASK"));

		oneShot();
		check("p1:declined-set-not-restored", !has(ppuMask, "PPUMASK"));
		check("p1:user-label-kept", has(ppuStatus, "MY_STATUS") && !has(ppuStatus, "PPUSTATUS"));

		tx = currentProgram.startTransaction("clear recorded choice");
		try {
			currentProgram.getOptions(Program.PROGRAM_INFO).setString(SYMBOL_SETS_PROPERTY, "");
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		oneShot();
		check("p2:label-restored", has(ppuMask, "PPUMASK"));
		Symbol primary = st.getPrimarySymbol(ppuStatus);
		check("p2:user-label-primary-and-user-defined", primary != null &&
			"MY_STATUS".equals(primary.getName()) &&
			primary.getSource() == SourceType.USER_DEFINED);
		check("p2:user-address-not-relabelled", !has(ppuStatus, "PPUSTATUS"));
		check("p2:untouched-label-intact", has(ppuCtrl, "PPUCTRL") &&
			st.getSymbols(ppuCtrl).length == 1);

		int before = st.getNumSymbols();
		oneShot();
		check("p3:idempotent", st.getNumSymbols() == before);

		println("DESCREANALYSIS verdict=" + (allOk ? "PASS" : "FAIL"));
	}

	private boolean has(Address addr, String name) {
		for (Symbol s : currentProgram.getSymbolTable().getSymbols(addr)) {
			if (s.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	private void check(String id, boolean ok) {
		allOk &= ok;
		println("DESCREANALYSIS check=" + id + " ok=" + ok);
	}

	/** Schedules DescriptorAnnotationAnalyzer one-shot over all memory and runs it. */
	private void oneShot() throws Exception {
		Analyzer analyzer = null;
		for (Analyzer a : ClassSearcher.getInstances(Analyzer.class)) {
			if (ANALYZER_NAME.equals(a.getName())) {
				analyzer = a;
			}
		}
		if (analyzer == null) {
			check("oneshot:analyzer-found", false);
			return;
		}
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		mgr.scheduleOneTimeAnalysis(analyzer, currentProgram.getMemory());
		mgr.startAnalysis(monitor);
		mgr.waitForAnalysis(null, monitor);
	}
}
