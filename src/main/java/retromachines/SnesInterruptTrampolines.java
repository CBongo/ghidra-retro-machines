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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Seeds the NMI/IRQ handlers a SNES game reaches only through a RAM trampoline (bead
 * grm-9nxj.5.6), as recovered by {@link SnesTrampolineScanner}.
 *
 * <p>Most games point their native NMI/IRQ vectors ({@code $00:FFEA}/{@code $00:FFEE}) at RAM
 * that the reset code fills with a {@code JML} at boot (or, Chrono Trigger and Final Fantasy III,
 * at a ROM stub that jumps into such RAM). {@link SnesRomLoader} cannot see the handler: the
 * bytes do not exist at import. The handler is applied the way the loader seeds a ROM-resident
 * vector: a label, an external entry point, a native-mode decode context (E=0, M=1, X=1 -- the
 * same stated assumption as {@link SnesRomLoader#stampModeContext}), disassembly, a function, a
 * comment recording the provenance, and an entry in
 * {@link DescriptorHints#ASYNC_ENTRY_POINTS_PROPERTY}.
 */
final class SnesInterruptTrampolines {

	private SnesInterruptTrampolines() {
	}

	/**
	 * Applies every dispatch's handler to the program. Idempotent in effect: an existing label,
	 * function, or instruction is kept.
	 *
	 * @param program the SNES program
	 * @param handlers what the scanner recovered
	 * @param log receives per-handler problems
	 * @return the handler addresses that were applied, in dispatch order
	 */
	static List<Address> apply(Program program, List<SnesTrampolineScanner.Handler> handlers,
			MessageLog log) {
		List<Address> applied = new ArrayList<>();
		Set<Address> async = new LinkedHashSet<>(DescriptorHints.parseAsyncEntryPoints(program));
		for (SnesTrampolineScanner.Handler d : handlers) {
			Address entry = d.entry();
			if (!program.getMemory().contains(entry)) {
				continue;
			}
			String kind = d.name();
			long same = handlers.stream().filter(h -> h.name().equals(kind)).count();
			String name = same == 1 ? kind : String.format("%s_%06x", kind, entry.getOffset());
			label(program, entry, name, log);
			program.getSymbolTable().addExternalEntryPoint(entry);
			if (program.getListing().getInstructionAt(entry) == null) {
				SnesRomLoader.stampModeContext(program, entry, true, log);
			}
			new DisassembleCommand(entry, null, true).applyTo(program, TaskMonitor.DUMMY);
			if (program.getFunctionManager().getFunctionAt(entry) == null) {
				new CreateFunctionCmd(entry).applyTo(program, TaskMonitor.DUMMY);
			}
			AnalyzerCommentRecord.set(program, entry, CommentType.PRE,
				String.format("%s handler, recovered from the constant stores the boot code makes " +
					"to $%06X (store sites: %s; grm-9nxj.5.6)", kind, d.trampoline(),
					d.sites().stream().map(Address::toString)
							.collect(java.util.stream.Collectors.joining(", "))));
			async.add(entry);
			applied.add(entry);
		}
		if (!applied.isEmpty()) {
			program.getOptions(Program.PROGRAM_INFO).setString(
				DescriptorHints.ASYNC_ENTRY_POINTS_PROPERTY,
				DescriptorHints.formatAsyncEntryPoints(async));
		}
		return applied;
	}

	private static void label(Program program, Address entry, String name, MessageLog log) {
		Symbol existing = program.getSymbolTable().getPrimarySymbol(entry);
		if (existing != null && existing.getSource() != SourceType.DEFAULT) {
			return;
		}
		try {
			program.getSymbolTable().createLabel(entry, name, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			log.appendMsg("SnesInterruptTrampolines: could not label " + entry + ": " +
				e.getMessage());
		}
	}
}
