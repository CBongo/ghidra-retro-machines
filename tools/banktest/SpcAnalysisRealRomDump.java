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
// Read-only golden dump for the SPC700 AUTO-ANALYSIS rows of the OPTIONAL, opt-in real-ROM tier
// (tools/banktest/realrom-test.sh check snes-spc-analysis), bead grm-gipk.10.
//
// No other tier analyzes SPC700 code: the `snes-spc` rows only hash the recovered upload blocks.
// This script recovers the sound-driver upload (SpcUploadRecovery), materializes the SPC700
// program IN MEMORY (SpcProgramMaterializer, never saved, released afterwards), runs
// auto-analysis on it and prints a census: instruction and function counts, every computed
// jump/call with its resolved-target count, the RET/RETI sites a RET-trick analyzer resolved
// (with their targets), and the Error bookmark count. The cartridge itself is imported
// -noanalysis; the analysis that matters here runs on the materialized program from this script.
//
// NO ROM BYTES are emitted, only counts and addresses. Everything is sorted by address; there
// are no timings and no paths, so the dump is deterministic.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

import retromachines.SpcProgramMaterializer;
import retromachines.SpcUploadRecovery;
import retromachines.StopConditions;

public class SpcAnalysisRealRomDump extends GhidraScript {

	@Override
	protected void run() throws Exception {
		// Work BEFORE the fence: recovery and analysis log through Msg, and anything printed
		// between BEGIN and END would be carved into the dump.
		List<String> lines = new ArrayList<>();
		lines.add("REALROM language " + currentProgram.getLanguageID().getIdAsString());
		if (!SpcUploadRecovery.isSnesRom(currentProgram)) {
			lines.add("REALROM spca not a SNES cartridge");
			emit(lines);
			return;
		}
		StopConditions stop = StopConditions.builder()
				.instructionFuel(SpcUploadRecovery.DEFAULT_FUEL).wallClockMillis(150_000L).build();
		SpcUploadRecovery.Result r = new SpcUploadRecovery(currentProgram).recover(stop, monitor);
		lines.add("REALROM spca recovery stop " + r.stop() + " blocks " + r.blocks().size() +
			" entry " + (r.entry() < 0 ? "NONE" : String.format("%04x", r.entry())));
		if (r.blocks().isEmpty()) {
			lines.add("REALROM spca program NONE");
			emit(lines);
			return;
		}
		ProgramDB spc = SpcProgramMaterializer.build(r, currentProgram.getName() + ".spca", this,
			true, monitor);
		try {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(spc);
			int tx = spc.startTransaction("analyze");
			try {
				mgr.initializeOptions();
				mgr.reAnalyzeAll(null);
				mgr.startAnalysis(monitor);
			}
			finally {
				spc.endTransaction(tx, true);
			}
			census(spc, lines);
		}
		finally {
			spc.release(this);
		}
		emit(lines);
	}

	private void census(ProgramDB spc, List<String> lines) {
		Listing listing = spc.getListing();
		int instructions = 0;
		// Address-sorted: the instruction iterator is address ordered already, TreeMap makes the
		// invariant explicit for the sites.
		TreeMap<Long, String> computed = new TreeMap<>();
		TreeMap<Long, String> retSites = new TreeMap<>();
		int computedSites = 0;
		int computedResolved = 0;
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction in = it.next();
			instructions++;
			FlowType ft = in.getFlowType();
			String mn = in.getMnemonicString().toUpperCase();
			boolean isRet = mn.equals("RET") || mn.equals("RETI");
			List<Long> targets = new ArrayList<>();
			for (Reference ref : in.getReferencesFrom()) {
				if (ref.getReferenceType().isComputed() && ref.getReferenceType().isFlow()) {
					targets.add(ref.getToAddress().getOffset());
				}
			}
			targets.sort(Long::compare);
			long at = in.getMinAddress().getOffset();
			if (isRet) {
				if (!targets.isEmpty()) {
					retSites.put(at, mn + " n=" + targets.size() + " " + hexList(targets));
				}
				continue;
			}
			if (!ft.isComputed() || ft.isTerminal()) {
				continue;
			}
			computedSites++;
			if (!targets.isEmpty()) {
				computedResolved++;
			}
			computed.put(at, (ft.isCall() ? "call" : "jump") + " " + mn + " n=" + targets.size() +
				(targets.isEmpty() ? "" : " " + hexList(targets)));
		}
		int functions = 0;
		FunctionIterator fi = spc.getFunctionManager().getFunctions(true);
		while (fi.hasNext()) {
			fi.next();
			functions++;
		}
		int errors = 0;
		var bi = spc.getBookmarkManager().getBookmarksIterator("Error");
		while (bi.hasNext()) {
			Bookmark b = bi.next();
			if (b != null) {
				errors++;
			}
		}
		lines.add("REALROM spca instructions " + instructions);
		lines.add("REALROM spca functions " + functions);
		lines.add("REALROM spca bookmarks.error " + errors);
		lines.add("REALROM spca computed sites=" + computedSites + " withTargets=" + computedResolved);
		for (var e : computed.entrySet()) {
			lines.add(String.format("REALROM spca computed %04x %s", e.getKey(), e.getValue()));
		}
		lines.add("REALROM spca retTrick sites=" + retSites.size());
		for (var e : retSites.entrySet()) {
			lines.add(String.format("REALROM spca retTrick %04x %s", e.getKey(), e.getValue()));
		}
	}

	private static String hexList(List<Long> v) {
		StringBuilder sb = new StringBuilder();
		for (long x : v) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(String.format("%04x", x));
		}
		return sb.toString();
	}

	private void emit(List<String> lines) {
		RealRomDumpSupport out = new RealRomDumpSupport(this, currentProgram);
		out.begin();
		for (String line : lines) {
			println(line);
		}
		out.end();
	}
}
