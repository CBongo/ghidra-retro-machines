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

import ghidra.app.services.AnalysisPriority;

/**
 * The {@link W65816RtsTrickAnalyzer} pass again, just after {@link W65816DataBankAnalyzer}
 * (grm-9nxj.45), so an abs-operand RTS-trick table is read in the TRACKED data bank.
 *
 * <p>The first pass cannot simply move: it runs at block-analysis priority because it disassembles
 * targets that function creation and the DBR analyzer itself need. So it keeps that slot, and this
 * pass retries only the {@code RTS} sites whose recognized table the tracked DBR has moved (or that
 * first recognize now, e.g. a table under a tracked DBR in a HiROM {@code $C0+} bank below
 * {@code $8000}); a site already tried with the same table, or that has flow, is skipped. The record
 * is shared with the first pass. A tracked DBR of {@code $7E}/{@code $7F} declines in {@link
 * W65816RtsTrick}, as before.
 *
 * <p>Limitation: like every instruction analyzer this sees only newly-added code, so a DBR stamp
 * that changes in a LATER analysis round (new callers found) does not bring an old {@code RTS}
 * back.
 */
public class W65816RtsTrickPostDbrAnalyzer extends W65816RtsTrickAnalyzer {

	private static final String NAME = "65816 RTS Trick Dispatch (after Data Bank)";
	private static final String DESCRIPTION =
		"Re-runs 65816 RTS Trick Dispatch after the 65816 Data Bank analyzer, for tables whose " +
			"bank the tracked DBR changes (grm-9nxj.45).";

	public W65816RtsTrickPostDbrAnalyzer() {
		super(NAME, DESCRIPTION,
			AnalysisPriority.REFERENCE_ANALYSIS.before().before().before());
	}
}
