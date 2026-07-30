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
 * {@link MosConstantReferenceAnalyzer} for the plain 6502 processor. Claiming processor
 * {@code "6502"} makes the resulting analyzer's display name "6502 Constant Reference
 * Analyzer" (derived from {@code processorName + " Constant Reference Analyzer"} in
 * {@code ConstantPropagationAnalyzer}'s constructor).
 *
 * <p>{@code data/languages/6502undoc.ldefs} carries {@code processor="6502"} for its
 * {@code 6502:LE:16:undoc} variant, so that variant is covered for free -- stock
 * {@code canAnalyze} matches on processor identity, not language ID or variant.
 */
public class Mos6502ConstantReferenceAnalyzer extends MosConstantReferenceAnalyzer {

	public Mos6502ConstantReferenceAnalyzer() {
		super("6502");
	}
}
