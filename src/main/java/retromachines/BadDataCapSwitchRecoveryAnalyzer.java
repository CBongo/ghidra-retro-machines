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

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the switches stock {@code DecompilerSwitchAnalyzer} abandons at Ghidra 12.2's GP-6945
 * bad-data cap (grm-vrkk.6, upstream #10029).
 *
 * <p>A stock 12.2 decompiler aborts a whole function after 4 flows into undecodable or unmapped
 * bytes. Banked 6502 code routinely flows into more than that (calls into bank windows that cannot
 * be resolved statically), so the stock analyzer recovers none of such a function's jump tables,
 * and the code behind them is never disassembled: tmnt, ff1, cv3, contra, ultimaav, megaman2 and
 * db3 all lost real code to it (grm-6m24). The cap is not a program or tool option, so it cannot
 * be lifted for the stock analyzer; the reference machine lifts it in its locally built
 * decompile.exe instead.
 *
 * <p>This analyzer runs right after the stock one, over the same added set. For each computed
 * jump the stock analyzer left without a computed reference it resolves the function exactly as
 * the stock {@code FindFunctionCallback} does, and decompiles it with the stock analyzer's own
 * configuration. Only when that decompile fails at the cap does it decompile again with no cap
 * ({@link JumpTableBoundAnalyzer#configureDecompiler}) and hand the result to the stock {@link
 * DecompilerSwitchAnalysisCmd}, which lays down the references, {@code switchD_}/{@code caseD_}
 * labels and disassembly an uncapped decompiler would have got. On an uncapped decompile.exe the
 * stock-configured decompile never hits the cap, so nothing is written: the reference machine's
 * results are unchanged by construction.
 *
 * <p>Reacting to what the stock analyzer actually abandoned, rather than predicting it from
 * {@link JumpTableBoundAnalyzer}'s earlier decompile, is deliberate: the stock analyzer decompiles
 * later, after that analyzer's overrides and pins, and a function can pass the cap then that did
 * not before. Measured on ff1 with the cap-kept GP-6936 build: the prediction recovered none of
 * its lost code.
 *
 * <p>A switch that already carries a computed reference is never rewritten, the stock rule for
 * locations applied per table. The stock command's {@code hasAllReferences} compares references to
 * the decompiler's reading, and {@link JumpTableBoundAnalyzer} pins some switches to targets that
 * reading cannot produce (a cross-bank table points into the switched-in bank). Without the rule
 * the command overwrote the pin, the next pass re-pinned it, and deadly_towers went round about
 * 2,000 times.
 */
public class BadDataCapSwitchRecoveryAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Retro Bad-Data Cap Switch Recovery";
	private static final String DESCRIPTION =
		"Recovers jump tables in functions that stock Decompiler Switch Analysis abandons at " +
			"Ghidra 12.2's bad-data cap (banked code flowing into unmapped windows); a no-op on a " +
			"decompiler built without the cap (grm-vrkk.6).";

	/**
	 * What the decompiler's {@code FlowInfo::countBadData} throws once a function passes the cap;
	 * reaches Java inside {@link DecompileResults#getErrorMessage()}.
	 */
	static final String BAD_DATA_CAP_MESSAGE = "Bad instruction count exceeded";

	/** Matches {@code DecompilerSwitchAnalyzer.OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS}. */
	private static final int DECOMPILE_TIMEOUT_SECS = 60;

	public BadDataCapSwitchRecoveryAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Right after the stock DecompilerSwitchAnalyzer (CODE_ANALYSIS), so it sees exactly the
		// locations that analyzer left unresolved.
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return AnalyzerGates.is8BitPcode(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Set<Function> functions = new LinkedHashSet<>();
		InstructionIterator it = program.getListing().getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = it.next();
			FlowType flowType = instr.getFlowType();
			if (!flowType.isJump() || !flowType.isComputed() || hasComputedReference(instr)) {
				continue;
			}
			Function function =
				program.getFunctionManager().getFunctionContaining(instr.getMinAddress());
			if (function == null) {
				function = UndefinedFunction.findFunctionUsingSimpleBlockModel(program,
					instr.getMinAddress(), monitor);
			}
			if (function != null && !function.isThunk()) {
				functions.add(function);
			}
		}
		if (functions.isEmpty()) {
			return true;
		}

		DecompInterface stock = new DecompInterface();
		DecompInterface uncapped = null; // opened only on the first function that hits the cap
		int abandoned = 0;
		int recovered = 0;
		try {
			new SwitchAnalysisDecompileConfigurer(program).configure(stock);
			if (!stock.openProgram(program)) {
				AnalyzerLog.warn(this, log, "decompiler failed to open program: " +
					stock.getLastMessage());
				return true;
			}
			for (Function function : functions) {
				monitor.checkCancelled();
				if (function.isDeleted() ||
					!hitBadDataCap(stock.decompileFunction(function, DECOMPILE_TIMEOUT_SECS,
						monitor))) {
					continue;
				}
				abandoned++;
				if (uncapped == null) {
					uncapped = new DecompInterface();
					JumpTableBoundAnalyzer.configureDecompiler(program, uncapped);
					if (!uncapped.openProgram(program)) {
						AnalyzerLog.warn(this, log, "uncapped decompiler failed to open program: " +
							uncapped.getLastMessage());
						return true;
					}
				}
				DecompileResults results =
					uncapped.decompileFunction(function, DECOMPILE_TIMEOUT_SECS, monitor);
				if (!results.decompileCompleted()) {
					continue;
				}
				new DecompilerSwitchAnalysisCmd(results) {
					@Override
					public boolean hasAllReferences(TaskMonitor m, JumpTable table,
							Instruction instr, Function containingFunction)
							throws CancelledException {
						return hasComputedReference(instr) ||
							super.hasAllReferences(m, table, instr, containingFunction);
					}
				}.applyTo(program, monitor);
				recovered++;
			}
		}
		finally {
			stock.dispose();
			if (uncapped != null) {
				uncapped.dispose();
			}
		}
		if (abandoned > 0) {
			AnalyzerLog.info(this, "recovered switches for " + recovered + " of " + abandoned +
				" function(s) stock switch analysis abandons at the bad-data cap");
		}
		return true;
	}

	/** Whether {@code results} failed because the function passed the GP-6945 bad-data cap. */
	static boolean hitBadDataCap(DecompileResults results) {
		if (results.decompileCompleted()) {
			return false;
		}
		String msg = results.getErrorMessage();
		return msg != null && msg.contains(BAD_DATA_CAP_MESSAGE);
	}

	private static boolean hasComputedReference(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}
}
