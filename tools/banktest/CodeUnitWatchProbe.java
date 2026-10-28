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
// Answers "WHICH ANALYZER changes the code units at X?" (bead grm-vzp2), which no postScript can:
// a postScript sees only the end state. A PRESCRIPT, run via REALROM_EXTRA_PRESCRIPT, with the
// watched addresses in GRM_WATCH (the first address of each code unit you care about):
//
//   GRM_WATCH=W8000_B24::8b3d REALROM_EXTRA_PRESCRIPT=CodeUnitWatchProbe.java \
//       bash tools/banktest/realrom-test.sh check nes --only cv3
//
// An address that does not resolve in a program is skipped, so one batch can watch several rows.
//
// Mechanism: it wraps every scheduled analyzer in a java.lang.reflect.Proxy (Analyzer is an
// interface; AnalysisScheduler's analyzer field is swapped by reflection) and snapshots each
// watched address -- the code unit there, its type and extent, the references from it -- before
// and after every added()/removed() call, on the analysis thread itself. Each change is logged as
//
//   CUWATCH <addr> by <analyzer>: <before> -> <after>
//
// A change seen at the START of a call (since the previous call ended) happened in a task that
// is not an analyzer -- a scheduled BackgroundCommand -- and is logged "between <prev> and
// <next>". The state is also logged once when the probe arms and once more when analysis ends.
//
// Why not a DomainObjectListener: program events are delivered on a timer that waits for the
// program lock, and headless analysis holds that lock throughout, so a listener (even a private
// event queue with a 1 ms delay) receives nothing from analysis until it has finished. Measured
// on cv3, 2026-10-27: one batch before analysis, then nothing.
//
// Analysis results are unchanged, but bless refuses any prescript anyway.
//@category RetroMachines.Test

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

public class CodeUnitWatchProbe extends GhidraScript {

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
		int wrapped = 0;
		Field listsField = AutoAnalysisManager.class.getDeclaredField("taskArray");
		listsField.setAccessible(true);
		for (Object list : (Object[]) listsField.get(mgr)) {
			Field tasksField = list.getClass().getDeclaredField("tasks");
			tasksField.setAccessible(true);
			for (Object scheduler : (List<?>) tasksField.get(list)) {
				Field af = scheduler.getClass().getDeclaredField("analyzer");
				af.setAccessible(true);
				Analyzer inner = (Analyzer) af.get(scheduler);
				af.set(scheduler, wrap(inner, watch));
				wrapped++;
			}
		}
		mgr.addListener(new AutoAnalysisManagerListener() {
			@Override
			public void analysisEnded(AutoAnalysisManager manager, boolean isCancelled) {
				watch.check("analysis end", true);
			}
		});
		Msg.info(CodeUnitWatchProbe.class,
			"CUWATCH " + program.getName() + " armed, " + wrapped + " analyzers wrapped");
		watch.check("arm", true);
	}

	private static Analyzer wrap(Analyzer inner, Watch watch) {
		return (Analyzer) Proxy.newProxyInstance(Analyzer.class.getClassLoader(),
			new Class<?>[] { Analyzer.class }, (proxy, method, args) -> {
				boolean watchedCall =
					method.getName().equals("added") || method.getName().equals("removed");
				if (watchedCall) {
					watch.check("between " + watch.last + " and " + inner.getName(), false);
				}
				try {
					return method.invoke(inner, args);
				}
				catch (InvocationTargetException e) {
					throw e.getCause();
				}
				finally {
					if (watchedCall) {
						watch.last = inner.getName() + "." + method.getName();
						watch.check("by " + watch.last, false);
					}
				}
			});
	}

	/** The watched addresses and the state each had at the previous check. */
	private static final class Watch {
		static final int BEFORE = 4;
		static final int AFTER = 12;
		final Program program;
		final List<Address> addrs;
		final List<String> states = new ArrayList<>();
		String last = "(start)";

		Watch(Program program, List<Address> addrs) {
			this.program = program;
			this.addrs = addrs;
			for (int i = 0; i < addrs.size(); i++) {
				states.add(null);
			}
		}

		void check(String context, boolean always) {
			for (int i = 0; i < addrs.size(); i++) {
				String now = state(addrs.get(i));
				String before = states.get(i);
				if (always || !now.equals(before)) {
					Msg.info(CodeUnitWatchProbe.class, "CUWATCH " + addrs.get(i) + " " + context +
						": " + before + " -> " + now);
					states.set(i, now);
				}
			}
		}

		/** Every defined code unit overlapping [a - BEFORE, a + AFTER], with its references. */
		private String state(Address a) {
			StringJoiner units = new StringJoiner("; ", "{", "}");
			Address lo = a.subtractWrap(BEFORE);
			Address hi = a.addWrap(AFTER);
			Address at = lo;
			while (at != null && at.compareTo(hi) <= 0) {
				CodeUnit cu = program.getListing().getCodeUnitContaining(at);
				if (cu == null) {
					break;
				}
				if (!(cu instanceof Data d && !d.isDefined())) {
					String kind = cu instanceof Data d ? d.getDataType().getName()
							: cu.getMnemonicString();
					StringJoiner refs = new StringJoiner(",");
					for (Reference r : program.getReferenceManager()
							.getReferencesFrom(cu.getMinAddress())) {
						refs.add(r.getReferenceType() + "->" + r.getToAddress().getOffset());
					}
					units.add(kind + "@" + Long.toHexString(cu.getMinAddress().getOffset()) + "-" +
						Long.toHexString(cu.getMaxAddress().getOffset()) +
						(refs.length() == 0 ? "" : "[" + refs + "]"));
				}
				at = cu.getMaxAddress().next();
			}
			return units.toString();
		}
	}
}
