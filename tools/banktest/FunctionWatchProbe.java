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
// Answers "WHICH ANALYZER creates, removes or resizes the function at X?" (written for
// grm-hf5h.5, to find who dropped w_fzero FUN_008acd/FUN_00d0aa). Same mechanism as
// CodeUnitWatchProbe (read its header for why a DomainObjectListener cannot do this: its events
// arrive only after headless analysis has released the program lock): a PRESCRIPT, via
// REALROM_EXTRA_PRESCRIPT, with the addresses in GRM_WATCH, wraps every scheduled analyzer in a
// Proxy and snapshots each watched address before and after every added()/removed() call:
//
//   GRM_WATCH=008acd,00d0aa,0088d8 REALROM_EXTRA_PRESCRIPT=FunctionWatchProbe.java \
//       REALROM_WORK_DIR=<dir outside the repo> \
//       bash tools/banktest/realrom-test.sh check snes --only w_fzero
//
// A snapshot is "FUNC <name> body=<n>" when a function has that entry, "in <name>" when a function
// contains the address, else "none". Each change is logged as
//   FNWATCH <addr> by <analyzer>.<added|removed>: <before> -> <after>
// or "between <prev> and <next>" when a non-analyzer task (a scheduled BackgroundCommand) did it.
// Read-only apart from the wrapping; bless refuses any prescript anyway.
//@category RetroMachines.Test

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class FunctionWatchProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String spec = System.getenv("GRM_WATCH");
		if (spec == null || spec.isBlank()) {
			return;
		}
		List<Address> watched = new ArrayList<>();
		for (String s : spec.split(",")) {
			Address a = toAddr(s.trim());
			if (a != null) {
				watched.add(a);
			}
		}
		if (watched.isEmpty()) {
			return;
		}
		Program program = currentProgram;
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		Watch watch = new Watch(program, watched);
		Field listsField = AutoAnalysisManager.class.getDeclaredField("taskArray");
		listsField.setAccessible(true);
		for (Object list : (Object[]) listsField.get(mgr)) {
			Field tasksField = list.getClass().getDeclaredField("tasks");
			tasksField.setAccessible(true);
			for (Object scheduler : (List<?>) tasksField.get(list)) {
				Field af = scheduler.getClass().getDeclaredField("analyzer");
				af.setAccessible(true);
				af.set(scheduler, wrap((Analyzer) af.get(scheduler), watch));
			}
		}
		mgr.addListener(new AutoAnalysisManagerListener() {
			@Override
			public void analysisEnded(AutoAnalysisManager manager, boolean isCancelled) {
				watch.check("analysis end");
			}
		});
		Msg.info(FunctionWatchProbe.class, "FNWATCH " + program.getName() + " armed");
		watch.check("arm");
	}

	private static Analyzer wrap(Analyzer inner, Watch watch) {
		return (Analyzer) Proxy.newProxyInstance(Analyzer.class.getClassLoader(),
			new Class<?>[] { Analyzer.class }, (proxy, method, args) -> {
				boolean call =
					method.getName().equals("added") || method.getName().equals("removed");
				if (call) {
					watch.check("between " + watch.last + " and " + inner.getName());
				}
				try {
					return method.invoke(inner, args);
				}
				catch (InvocationTargetException e) {
					throw e.getCause();
				}
				finally {
					if (call) {
						watch.last = inner.getName() + "." + method.getName();
						watch.check("by " + watch.last);
					}
				}
			});
	}

	private static final class Watch {
		final Program program;
		final List<Address> addrs;
		final List<String> states = new ArrayList<>();
		String last = "(start)";

		Watch(Program program, List<Address> addrs) {
			this.program = program;
			this.addrs = addrs;
			for (int i = 0; i < addrs.size(); i++) {
				states.add("");
			}
		}

		private final java.util.Set<Address> entries = new java.util.HashSet<>();

		/** GRM_WATCH_NEWFN=1: also log every function entry created/removed since the last check. */
		private void entryDiff(String who) {
			if (System.getenv("GRM_WATCH_NEWFN") == null) {
				return;
			}
			java.util.Set<Address> now = new java.util.HashSet<>();
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				now.add(f.getEntryPoint());
			}
			StringBuilder sb = new StringBuilder();
			for (Address a : now) {
				if (!entries.contains(a)) {
					sb.append(" +").append(a);
				}
			}
			for (Address a : entries) {
				if (!now.contains(a)) {
					sb.append(" -").append(a);
				}
			}
			if (sb.length() > 0) {
				Msg.info(FunctionWatchProbe.class, "FNWATCH-ENTRIES " + who + ":" + sb);
			}
			entries.clear();
			entries.addAll(now);
		}

		synchronized void check(String who) {
			entryDiff(who);
			for (int i = 0; i < addrs.size(); i++) {
				String now = snapshot(addrs.get(i));
				if (!now.equals(states.get(i))) {
					Msg.info(FunctionWatchProbe.class, "FNWATCH " + addrs.get(i) + " " + who +
						": " + states.get(i) + " -> " + now);
					states.set(i, now);
				}
			}
		}

		/** GRM_WATCH_FLOW=<entry>,...: also report whether a flow walk (FollowFlow, no other
		 *  functions) from each entry reaches the watched address, with its instruction/refs. */
		private String flowNote(Address a) {
			String spec = System.getenv("GRM_WATCH_FLOW");
			if (spec == null || spec.isBlank()) {
				return "";
			}
			StringBuilder sb = new StringBuilder(" flow[");
			for (String e : spec.split(",")) {
				Address entry = program.getAddressFactory().getAddress(e.trim());
				if (entry != null) {
					sb.append(' ').append(e.trim()).append('=').append(
						CreateFunctionCmd.getFunctionBody(program, entry, false,
							ghidra.util.task.TaskMonitor.DUMMY).contains(a));
				}
			}
			return sb.append(" ] instr=").append(program.getListing().getInstructionAt(a) != null)
					.append(" refsTo=").append(
						program.getReferenceManager().getReferenceCountTo(a)).toString();
		}

		private String snapshot(Address a) {
			return snapshot0(a) + flowNote(a);
		}

		private String snapshot0(Address a) {
			Function at = program.getFunctionManager().getFunctionAt(a);
			if (at != null) {
				return "FUNC " + at.getName() + " body=" + at.getBody().getNumAddresses();
			}
			Function in = program.getFunctionManager().getFunctionContaining(a);
			return in == null ? "none" : "in " + in.getName() + " body=" +
				in.getBody().getNumAddresses();
		}
	}
}
