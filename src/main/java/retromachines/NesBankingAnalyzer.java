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
 * The NES instantiation of the {@link BoardBankAnalyzer} engine: gates on programs
 * imported by {@link NesRomLoader} (whose "home-in-base" per-bank overlay layout the
 * engine's reference retargeting assumes) and reads the board descriptor path the
 * loader recorded in program info -- unlike the C64, the NES board (and therefore the
 * banking model) varies per import, chosen by iNES mapper through
 * {@link NesBoardRegistry}. Discrete mappers (UxROM/AxROM/GxROM/BNROM) are
 * {@code memory-latch} mechanisms ({@link MemoryLatchBankSwitchStrategy}); unbanked
 * boards (NROM) and CHR-only ones (CNROM's PRG side) cost nothing beyond descriptor
 * parsing.
 */
public class NesBankingAnalyzer extends BoardBankAnalyzer {

	private static final String NAME = "NES Bank State";
	private static final String DESCRIPTION =
		"Tracks the mapper bank latch state along control flow (including bank-switch " +
			"helper functions called with the bank in a register) and retargets references " +
			"into switchable PRG windows so they point at the bank actually mapped in -- " +
			"not just whatever the loader put in the base address space.";

	public NesBankingAnalyzer() {
		super(NAME, DESCRIPTION);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Gate on the loader that produced this program: only NES ROM imports lay out
		// memory "home-in-base" with per-bank overlays the way the engine assumes.
		String format = program.getExecutableFormat();
		return format != null && format.equals(new NesRomLoader().getName());
	}

	@Override
	protected String getMapPath(Program program) {
		// The loader records which board descriptor it imported with; a missing property
		// (imports that predate it) skips analysis rather than guessing a board.
		return program.getOptions(Program.PROGRAM_INFO)
				.getString(DescriptorSupport.MAP_PATH_PROPERTY, null);
	}
}
