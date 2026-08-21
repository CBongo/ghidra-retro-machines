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

import java.util.List;

import ghidra.program.model.listing.Program;
import ghidra.app.util.importer.MessageLog;

/** Commodore 64 instantiation of the shared descriptor-driven CBM PRG loader. */
public class C64PrgLoader extends AbstractCbmPrgLoader {
	public static final String NAME = "Commodore 64 PRG";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	protected String getMapPath() {
		return "machines/c64.map";
	}

	@Override
	protected String getMachineId() {
		return "c64";
	}

	@Override
	protected void afterPrgPlacement(Program program, List<PrgSlice> slices, MessageLog log) {
		// This used to also copy the four "Retro Machines.CBM PRG *" Program-Info
		// properties into a parallel "Retro Machines.C64 PRG *" set for older saved
		// Programs. Retired with the rest of grm-hap item 4: the CBM set itself is down to
		// the slice list, and the other three values are derived from it on demand.
		if (slices.stream().anyMatch(s -> s.target().name().equals("P6510"))) {
			log.appendMsg("PRG bytes were placed at the 6510 port registers $0000/$0001. " +
				"This is a static address image only: loader chronology, DDR effects, and bank " +
				"state changes from $01 are not simulated; descriptor initial banking is unchanged.");
		}
	}
}
