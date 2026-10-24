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
package retromachines;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Seeds the SNES NMI/IRQ handlers that sit behind a RAM trampoline (bead grm-9nxj.5.6).
 *
 * <p>The vectors point at RAM the reset code fills at boot, so the loader cannot seed the
 * handlers. {@link SnesTrampolineScanner} recovers them statically from the constant stores the
 * program makes, and {@link SnesInterruptTrampolines} applies them. It is its own analyzer, not
 * part of {@link SpcUploadAnalyzer}: it needs no emulation, and the SPC analyzer only runs on
 * ROMs that use the APU port. It runs after reference analysis, when the reset code that writes
 * the trampoline has been disassembled, and is idempotent: a vector is retried on later calls
 * until it resolves, and a vector that is plain ROM costs one byte read.
 */
public class SnesTrampolineAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "SNES Interrupt Trampolines";
	private static final String DESCRIPTION =
		"Finds the NMI/IRQ handlers a SNES game reaches through a RAM trampoline that its boot " +
			"code writes, from the constant stores to that RAM, and seeds them as entry points.";

	private static final Map<Program, Set<String>> APPLIED =
		Collections.synchronizedMap(new WeakHashMap<>());

	/** Creates the analyzer. */
	public SnesTrampolineAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return SpcUploadRecovery.isSnesRom(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		Set<String> done = APPLIED.computeIfAbsent(program, k -> new HashSet<>());
		if (done.contains("NMI") && done.contains("IRQ")) {
			return false;
		}
		List<String> notes = new ArrayList<>();
		List<SnesTrampolineScanner.Handler> found = SnesTrampolineScanner.scan(program, notes);
		List<SnesTrampolineScanner.Handler> fresh = new ArrayList<>();
		for (SnesTrampolineScanner.Handler h : found) {
			if (!done.contains(h.name())) {
				fresh.add(h);
			}
		}
		for (SnesTrampolineScanner.Handler h : fresh) {
			done.add(h.name());
		}
		for (SnesTrampolineScanner.Handler h : fresh) {
			AnalyzerLog.info(this, String.format(
				"%s vector $%s -> RAM trampoline $%06X -> handler %s (stores at %s)", h.name(),
				h.vectorTarget(), h.trampoline(), h.entry(), h.sites()));
		}
		SnesInterruptTrampolines.apply(program, fresh, log);
		for (String n : notes) {
			if (done.add("note:" + n)) {
				AnalyzerLog.info(this, n);
			}
		}
		return !fresh.isEmpty();
	}
}
