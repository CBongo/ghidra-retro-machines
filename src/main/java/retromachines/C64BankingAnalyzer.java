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

import ghidra.program.model.listing.Program;

/**
 * The C64 instantiation of the {@link BoardBankAnalyzer} engine: gates on programs
 * imported by {@link C64PrgLoader} (whose "home-in-base" overlay layout the engine's
 * reference retargeting assumes) and points the engine at the bundled
 * {@code machines/c64.map} descriptor. The C64's $01 processor port is a
 * {@code register-write} mechanism ({@link RegisterWriteBankSwitchStrategy}), so all
 * actual analysis logic -- per-bit dataflow, masked-RMW value recovery, annotation,
 * overlay retargeting -- lives in the engine and the strategy library; nothing about
 * the C64 memory map is hardcoded here beyond the descriptor's schema.
 */
public class C64BankingAnalyzer extends BoardBankAnalyzer {

	private static final String NAME = "C64 Bank State";
	private static final String DESCRIPTION =
		"Tracks the C64 CPU port ($01) banking state along control flow and retargets " +
			"references into banked windows (RAM_A000/RAM_D000/CHARGEN/RAM_E000 overlays) " +
			"so they point at the occupant actually being read, written (including write-under-" +
			"ROM), or executed -- not just whatever the loader put in the base address space.";

	public C64BankingAnalyzer() {
		super(NAME, DESCRIPTION);
	}

	@Override
	protected String getLoaderName() {
		return C64PrgLoader.NAME;
	}

	@Override
	protected String getMapPath(Program program) {
		return "machines/c64.map";
	}
}
