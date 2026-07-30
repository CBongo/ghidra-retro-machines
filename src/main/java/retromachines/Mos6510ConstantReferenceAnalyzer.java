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

/**
 * {@link MosConstantReferenceAnalyzer} for the 6510 processor (the C64/C128/1551's on-die
 * I/O port variant of the 6502). Claiming processor {@code "6510"} makes the resulting
 * analyzer's display name "6510 Constant Reference Analyzer".
 *
 * <p>Both {@code 6510.ldefs} variants ({@code 6510:LE:16:default} and
 * {@code 6510:LE:16:undoc}) carry {@code processor="6510"}, so both are covered by this one
 * class.
 *
 * <p><b>Why a second class rather than one class claiming both "6502" and "6510":</b>
 * {@code ConstantPropagationAnalyzer(String processorName)} derives both the analyzer's
 * display name and its single {@code claimProcessor} registration from that one string, and
 * the stock {@code canAnalyze} it must keep (see {@link MosConstantReferenceAnalyzer}'s
 * comment on why it is not overridden) tests the program's processor for equality against
 * exactly that one processor. One class per processor is therefore what keeps the inherited
 * {@code canAnalyze}/{@code claimProcessor} machinery intact while still giving each analyzer
 * the name ("6502 Constant Reference Analyzer" / "6510 Constant Reference Analyzer") a
 * Ghidra user expects to see in the Auto-Analysis options dialog.
 */
public class Mos6510ConstantReferenceAnalyzer extends MosConstantReferenceAnalyzer {

	public Mos6510ConstantReferenceAnalyzer() {
		super("6510");
	}
}
