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
// ReanalysisFixpointProbe (grm-q83o): does auto-analysis REACH A FIXPOINT, the way the GUI
// runs it?
//
// In the GUI, AutoAnalysisManager is a DomainObjectListener: a FUNCTION_ADDED /
// FUNCTION_BODY_CHANGED / CODE_ADDED event fired by ANY change -- including one an analyzer makes
// in its analysisEnded() hook -- queues more analysis, which ends in analysisEnded() again. If
// those hooks change something every time, the GUI never stops analyzing (w_ff3 "Stack
// FUN_c25ada", 2026-11-27). analyzeHeadless runs analysis once and exits, so the gates never see
// it. This probe replays the GUI's cycle after the headless pass: flush events, run whatever got
// queued, repeat, up to ROUNDS times, and prints per round the analysis-relevant events seen and
// whether analysis ran at all. A healthy program prints "FIXPOINT after round N" with N small.
//
// Output lines are prefixed "FIXPOINT ". Addresses and function names only, no ROM bytes.
//
// USAGE (rides on a routine row):
//   REALROM_EXTRA_POSTSCRIPT=ReanalysisFixpointProbe.java \
//     bash tools/banktest/realrom-test.sh check snes-analysis --only w_ff3
//@category RetroMachines.Test

import java.util.Map;
import java.util.TreeMap;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;

public class ReanalysisFixpointProbe extends GhidraScript {

	private static final int ROUNDS = 6;

	/** Functions whose body is printed at each round's start and at analysisEnded:
	 *  GRM_FIXPOINT_WATCH, comma-separated entry addresses. */
	private final java.util.List<String> watched = new java.util.ArrayList<>();

	/**
	 * GRM_FIXPOINT_STEP=&lt;entry&gt;: runs every enabled FUNCTION_ANALYZER that can analyze this
	 * program, one at a time, on {@code entry} alone (what a FUNCTION_BODY_CHANGED there
	 * schedules), and then every analyzer's analysisEnded, printing the function's body after
	 * each one that changed it. Says WHICH analyzer flips a body; the rounds say only that one does.
	 */
	private void stepFunctionAnalyzers(String entry, Map<String, Integer> events)
			throws Exception {
		Address at = toAddr(entry);
		AutoAnalysisManager mgrStep = AutoAnalysisManager.getAnalysisManager(currentProgram);
		java.util.List<Analyzer> all = ClassSearcher.getInstances(Analyzer.class);
		all.sort(java.util.Comparator.comparingInt((Analyzer a) -> a.getPriority().priority()));
		String last = bodyOf(entry);
		println("FIXPOINT step  start " + last);
		for (Analyzer a : all) {
			if (a.getAnalysisType() == AnalyzerType.FUNCTION_ANALYZER && a.canAnalyze(currentProgram)) {
				println("FIXPOINT step  candidate " + a.getName() + " enabled=" + currentProgram
						.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES)
						.getBoolean(a.getName(), a.getDefaultEnablement(currentProgram)));
			}
		}
		for (int pass = 1; pass <= 2; pass++) {
			for (Analyzer a : all) {
				if (a.getAnalysisType() != AnalyzerType.FUNCTION_ANALYZER ||
					!a.canAnalyze(currentProgram) || !currentProgram
							.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES)
							.getBoolean(a.getName(), a.getDefaultEnablement(currentProgram))) {
					continue;
				}
				events.clear();
				a.added(currentProgram, new AddressSet(at), monitor, new MessageLog());
				currentProgram.flushEvents();
				String now = bodyOf(entry);
				if (!now.equals(last) || !events.isEmpty()) {
					println("FIXPOINT step  pass " + pass + " " + a.getName() + " -> " + now +
						" events " + events);
					last = now;
				}
				// What it QUEUED (stock Shared Return Calls schedules CreateFunctionCmd tasks
				// through the manager rather than applying them): drain it, analysisEnded included.
				events.clear();
				mgrStep.startAnalysis(monitor, true);
				currentProgram.flushEvents();
				now = bodyOf(entry);
				if (!now.equals(last) || !events.isEmpty()) {
					println("FIXPOINT step  pass " + pass + " " + a.getName() + " QUEUED -> " +
						now + " events " + events + " tasks " +
						mgrStep.getTaskTimesString().replace("\n", " | "));
					last = now;
				}
			}
			for (Analyzer a : all) {
				if (!a.canAnalyze(currentProgram)) {
					continue;
				}
				events.clear();
				a.analysisEnded(currentProgram);
				currentProgram.flushEvents();
				String now = bodyOf(entry);
				if (!now.equals(last) || !events.isEmpty()) {
					println("FIXPOINT step  pass " + pass + " " + a.getName() +
						".analysisEnded -> " + now + " events " + events);
					last = now;
				}
			}
		}
		println("FIXPOINT step  end " + last);
	}

	private String bodyOf(String entry) {
		Function f = getFunctionAt(toAddr(entry));
		return f == null ? "(none)" : f.getName() + " " + f.getBody();
	}

	@Override
	protected void run() throws Exception {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		String watch = System.getenv("GRM_FIXPOINT_WATCH");
		if (watch != null && !watch.isBlank()) {
			for (String w : watch.split(",")) {
				watched.add(w.trim());
			}
		}
		Map<String, Integer> events = new TreeMap<>();
		int[] ended = { 0 };
		DomainObjectListener l = ev -> {
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord r = ev.getChangeRecord(i);
				if (r.getEventType() == ProgramEvent.FUNCTION_BODY_CHANGED ||
					r.getEventType() == ProgramEvent.FUNCTION_ADDED ||
					r.getEventType() == ProgramEvent.FUNCTION_REMOVED ||
					r.getEventType() == ProgramEvent.CODE_ADDED ||
					r.getEventType() == ProgramEvent.FLOW_OVERRIDE_CHANGED) {
					String what = r.getEventType().toString();
					if (r instanceof ProgramChangeRecord pr && pr.getObject() instanceof Function f) {
						what += " " + f.getName() + "@" + f.getEntryPoint() + " body=" +
							f.getBody().getNumAddresses();
					}
					else if (r instanceof ProgramChangeRecord pr && pr.getStart() != null) {
						what += " " + pr.getStart();
					}
					events.merge(what, 1, Integer::sum);
				}
			}
		};
		Map<String, String> bodiesAtEnd = new TreeMap<>();
		AutoAnalysisManagerListener al = (m, cancelled) -> {
			ended[0]++;
			bodiesAtEnd.clear();
			for (String name : watched) {
				bodiesAtEnd.put(name, bodyOf(name));
			}
		};
		currentProgram.flushEvents(); // drain the headless pass's own events unobserved
		currentProgram.addListener(l);
		mgr.addListener(al);
		String step = System.getenv("GRM_FIXPOINT_STEP");
		println("FIXPOINT === BEGIN ===");
		// GRM_FIXPOINT_LIST=<from>-<to>[,...]: each instruction's address, length, mnemonic, flow type
		// and fall-through, and every reference to it, so the flipping address can be read.
		String list = System.getenv("GRM_FIXPOINT_LIST");
		for (String range : list == null ? new String[0] : list.split(",")) {
			if (!range.contains("-")) {
				continue;
			}
			String[] ft = range.split("-");
			ghidra.program.model.listing.InstructionIterator it = currentProgram.getListing()
					.getInstructions(new AddressSet(toAddr(ft[0].trim()), toAddr(ft[1].trim())), true);
			while (it.hasNext()) {
				ghidra.program.model.listing.Instruction in = it.next();
				Function f = getFunctionContaining(in.getMinAddress());
				println("FIXPOINT list " + in.getMinAddress() + " len=" + in.getLength() + " " +
					in.getMnemonicString() + " flow=" + in.getFlowType() + " override=" +
					in.getFlowOverride() + " ft=" + in.getFallThrough() + " fn=" +
					(f == null ? "-" : f.getName()));
				for (ghidra.program.model.symbol.Reference r : getReferencesTo(in.getMinAddress())) {
					println("FIXPOINT list     <- " + r.getFromAddress() + " " + r.getReferenceType());
				}
			}
		}
		try {
			for (int round = 1; round <= ROUNDS; round++) {
				events.clear();
				int before = ended[0];
				for (String name : watched) {
					println("FIXPOINT   start  " + name + " " + bodyOf(name));
				}
				currentProgram.flushEvents();
				mgr.startAnalysis(monitor, true);
				currentProgram.flushEvents();
				for (Map.Entry<String, String> e : bodiesAtEnd.entrySet()) {
					println("FIXPOINT   ended  " + e.getKey() + " " + e.getValue());
				}
				println("FIXPOINT   tasks " + mgr.getTaskTimesString().replace("\n", " | "));
				boolean ran = ended[0] > before;
				println("FIXPOINT round " + round + ": analysis " + (ran ? "RAN" : "idle") +
					", " + events.size() + " distinct event(s)");
				int shown = 0;
				for (Map.Entry<String, Integer> e : events.entrySet()) {
					if (shown++ >= 40) {
						println("FIXPOINT   ...");
						break;
					}
					println("FIXPOINT   " + e.getValue() + "x " + e.getKey());
				}
				if (!ran) {
					println("FIXPOINT FIXPOINT after round " + round);
					return;
				}
			}
			println("FIXPOINT NO FIXPOINT after " + ROUNDS + " rounds");
			// Stepped from the looping state, which the headless pass's own end state is not.
			if (step != null && !step.isBlank()) {
				stepFunctionAnalyzers(step.trim(), events);
			}
		}
		finally {
			currentProgram.removeListener(l);
			mgr.removeListener(al);
			println("FIXPOINT === END ===");
		}
	}
}
