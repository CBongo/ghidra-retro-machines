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
// Evidence-engine dump (bead grm-etbh, stage E1). Runs the PRODUCTION engine
// retromachines.ParamReturnEvidence over every function and prints per-row case counts in the SAME
// vocabulary as ParamReturnCensusProbe (so tools/recon/param_return_census.py compares engine to
// probe), plus proposal counts (what signature the combination rules would give each function).
//
//   PRC <row> SUMMARY ...        as the probe
//   PRC <row> CASE case=.. callee=.. caller=.. both=..
//   PRC <row> SAMPLE case=.. kind=.. fn=<addr> callers=<k>
//   PRC <row> PROP key=<sig> count=<n>          sig = <params>-><ret>[/incomplete]; #keys are totals
//   PRC <row> PSAMPLE sig=<sig> fn=<addr> callers=<k> comments=<..>
// Appended to <GRM_PRC_OUT>/<program>.prc when that env var names a directory. Read-only. Run as
// REALROM_EXTRA_POSTSCRIPT.
//@category RetroMachines.Test

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import retromachines.ParamReturnEvidence;
import retromachines.ParamReturnEvidence.FnEvidence;
import retromachines.ParamReturnEvidence.Proposal;
import retromachines.ParamReturnEvidence.Result;

public class ParamReturnEvidenceDump extends GhidraScript {

	private static final int RA = ParamReturnEvidence.RA, RX = ParamReturnEvidence.RX,
			RY = ParamReturnEvidence.RY, RC = ParamReturnEvidence.RC, RZ = ParamReturnEvidence.RZ,
			RN = ParamReturnEvidence.RN;
	private static final String[] RNAME = { "a", "x", "y" };

	private static final class Counter {
		int callee;
		int caller;
		int both;
		final Map<String, List<String>> samples = new TreeMap<>();
	}

	private final Map<String, Counter> cases = new TreeMap<>();
	private final Map<String, Integer> props = new TreeMap<>();
	private final Map<String, List<String>> psamples = new TreeMap<>();
	private int samples = 3;

	@Override
	protected void run() throws Exception {
		String lang = currentProgram.getLanguageID().getIdAsString();
		String row = currentProgram.getName();
		String sEnv = System.getenv("GRM_PRC_SAMPLES");
		if (sEnv != null) {
			samples = Integer.parseInt(sEnv.trim());
		}
		Result res = ParamReturnEvidence.analyze(currentProgram);
		List<String> out = new ArrayList<>();
		if (!res.supported()) {
			out.add("PRC " + row + " SUMMARY lang=" + lang + " fns=0 analyzed=0 skippedCap=0 " +
				"noCallers=0 callSites=0 indirectJumps=0 tailExit=0 noReturnPath=0 jumpRefsIn=0 " +
				"carryConstModel=false zpModel=false");
			emit(out, row);
			return;
		}
		int fns = 0, analyzed = 0, noCallers = 0, callSites = 0, indirect = 0, tails = 0,
				noReturns = 0, jumpRefs = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			fns++;
			FnEvidence e = res.get(f.getEntryPoint());
			if (e == null || !e.analyzed) {
				continue;
			}
			analyzed++;
			indirect += e.indirect;
			tails += e.tail ? 1 : 0;
			noReturns += e.returns == 0 ? 1 : 0;
			callSites += e.sites;
			jumpRefs += e.jumpRefs;
			noCallers += e.sites == 0 ? 1 : 0;
			record(e, res.zpModel());
			propose(e, res.is65816());
		}
		out.add("PRC " + row + " SUMMARY lang=" + lang + " fns=" + fns + " analyzed=" + analyzed +
			" skippedCap=" + res.skippedCap() + " noCallers=" + noCallers + " callSites=" +
			callSites + " indirectJumps=" + indirect + " tailExit=" + tails + " noReturnPath=" +
			noReturns + " jumpRefsIn=" + jumpRefs + " carryConstModel=true zpModel=" +
			res.zpModel());
		for (Map.Entry<String, Counter> en : cases.entrySet()) {
			Counter c = en.getValue();
			out.add("PRC " + row + " CASE case=" + en.getKey() + " callee=" + c.callee +
				" caller=" + c.caller + " both=" + c.both);
			for (Map.Entry<String, List<String>> s : c.samples.entrySet()) {
				for (String line : s.getValue()) {
					out.add("PRC " + row + " SAMPLE case=" + en.getKey() + " kind=" + s.getKey() +
						" " + line);
				}
			}
		}
		for (Map.Entry<String, Integer> p : props.entrySet()) {
			out.add("PRC " + row + " PROP key=" + p.getKey() + " count=" + p.getValue());
		}
		for (Map.Entry<String, List<String>> p : psamples.entrySet()) {
			for (String line : p.getValue()) {
				out.add("PRC " + row + " PSAMPLE sig=" + p.getKey() + " " + line);
			}
		}
		emit(out, row);
	}

	private void emit(List<String> out, String row) {
		for (String l : out) {
			println(l);
		}
		String dir = System.getenv("GRM_PRC_OUT");
		if (dir != null && !dir.isBlank()) {
			try {
				Path p = Paths.get(dir);
				Files.createDirectories(p);
				try (PrintWriter w =
					new PrintWriter(new FileWriter(p.resolve(row + ".prc").toFile()))) {
					for (String l : out) {
						w.println(l);
					}
				}
			}
			catch (IOException ex) {
				println("PRC " + row + " WARN cannot write GRM_PRC_OUT: " + ex);
			}
		}
	}

	private void propose(FnEvidence e, boolean is816) {
		Proposal p = ParamReturnEvidence.propose(e, is816);
		String sig = String.join(",", p.params()) + "->" + (p.ret() == null ? "-" : p.ret()) +
			(p.complete() ? "" : "/incomplete");
		props.merge(sig, 1, Integer::sum);
		props.merge("#fns", 1, Integer::sum);
		if (p.complete()) {
			props.merge("#complete", 1, Integer::sum);
			if (p.ret() != null || !p.params().isEmpty()) {
				props.merge("#commitable", 1, Integer::sum);
			}
			if (p.ret() != null) {
				props.merge("#withReturn", 1, Integer::sum);
			}
			if (!p.params().isEmpty()) {
				props.merge("#withParams", 1, Integer::sum);
			}
			if (!p.comments().isEmpty()) {
				props.merge("#withComment", 1, Integer::sum);
			}
		}
		else {
			props.merge("#incomplete", 1, Integer::sum);
		}
		if (p.complete() && e.sites > 0 && (p.ret() != null || !p.params().isEmpty())) {
			List<String> l = psamples.computeIfAbsent(sig, k -> new ArrayList<>());
			if (l.size() < 2) {
				l.add("fn=" + e.entry + " callers=" + e.sites + " comments=" + p.comments());
			}
		}
	}

	private void record(FnEvidence e, boolean zpModel) {
		for (int r : new int[] { RA, RX, RY }) {
			String n = RNAME[r];
			int bit = 1 << r;
			boolean calleeOut = (e.outMask & bit) != 0;
			boolean callerRead = (e.afterRead & bit) != 0;
			add(n + "_ret", calleeOut, callerRead, e);
			boolean in = (e.inMask & bit) != 0;
			boolean wr = (e.beforeWrite & bit) != 0;
			add(n + "_in", in, wr, e);
			if (in && (e.inWide & bit) != 0) {
				add(n + "_in_wide", true, wr, e);
			}
			add(n + "_inout", in && calleeOut, callerRead && wr, e);
		}
		boolean cBranch = (e.afterBranch & (1 << RC)) != 0;
		int c = e.carry;
		boolean some = (c & (ParamReturnEvidence.C_ZERO | ParamReturnEvidence.C_ONE)) != 0;
		boolean strict = e.returns > 0 &&
			(c & (ParamReturnEvidence.C_ENTRY | ParamReturnEvidence.C_UNK)) == 0;
		boolean both = (c & ParamReturnEvidence.C_ZERO) != 0 &&
			(c & ParamReturnEvidence.C_ONE) != 0;
		add("carry_ret_some_const", some, cBranch, e);
		add("carry_ret_all_const", strict, cBranch, e);
		add("carry_ret_both_values", both, cBranch, e);
		add("carry_ret_any_written", e.carryWritten(), cBranch, e);
		add("carry_in", e.carryIn, (e.beforeWrite & (1 << RC)) != 0, e);
		add("z_ret_callerOnly", false, (e.afterBranch & (1 << RZ)) != 0, e);
		add("n_ret_callerOnly", false, (e.afterBranch & (1 << RN)) != 0, e);
		if (zpModel) {
			add("zp_in", !e.zpIn.isEmpty(), e.zpSetBefore, e);
		}
	}

	private void add(String name, boolean callee, boolean caller, FnEvidence e) {
		Counter c = cases.computeIfAbsent(name, k -> new Counter());
		String kind = null;
		if (callee) {
			c.callee++;
		}
		if (caller) {
			c.caller++;
		}
		if (callee && caller) {
			c.both++;
			kind = "both";
		}
		else if (callee) {
			kind = "callee";
		}
		else if (caller) {
			kind = "caller";
		}
		if (kind != null) {
			List<String> l = c.samples.computeIfAbsent(kind, k -> new ArrayList<>());
			if (l.size() < ("both".equals(kind) ? samples : 1)) {
				l.add("fn=" + e.entry + " callers=" + e.sites);
			}
		}
	}
}
