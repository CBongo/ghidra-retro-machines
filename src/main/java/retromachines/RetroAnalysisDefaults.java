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

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * Stock auto-analysis options that every loader in this extension sets for the program it
 * creates, because the stock default models hand-written 6502-family code wrongly. Each is set as
 * a program option, so a user can still change it in the Analysis Options dialog.
 */
final class RetroAnalysisDefaults {

	/**
	 * Ghidra's Shared Return Calls analyzer option that lets a CONDITIONAL branch into a function
	 * entry be a tail call. It also, since Ghidra 12.2, switches off GP-6976's filter that
	 * refuses to turn any jump into a call-return when the destination is also the target of a
	 * conditional branch. That filter is an ELF heuristic (a conditional-branch target is taken as
	 * mid-function, which suits compiler output split into .cold parts). In hand-written 6502 code
	 * it misfires constantly: a routine's entry is often its own loop head, and the idiomatic
	 * conditional return is a branch to a neighbouring routine's RTS, which is frequently itself
	 * a table-dispatched function entry (smb3 b4c1/bb80/af23). With the filter on, those tail jumps
	 * stay jumps, the target is absorbed into the caller's function, and bank-helper attribution,
	 * which is per function, loses the call (smb3 'via FUN_841d'). A conditional tail call into a
	 * real entry is modelled exactly by CALL_RETURN. Upstream issue drafted on grm-6m24.
	 */
	static final String ALLOW_CONDITIONAL_TAIL_CALLS =
		"Shared Return Calls.Allow Conditional Jumps";

	private RetroAnalysisDefaults() {
	}

	/** Applies this extension's analysis defaults to {@code program}, noting them in {@code log}. */
	static void apply(Program program, MessageLog log, String loaderName) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.setBoolean(ALLOW_CONDITIONAL_TAIL_CALLS, true);
		log.appendMsg(loaderName + ": " + ALLOW_CONDITIONAL_TAIL_CALLS + " on for this program " +
			"(conditional tail calls and shared RTS tails are idiomatic 6502; see grm-6m24)");
	}
}
