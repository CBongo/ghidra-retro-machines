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
import ghidra.framework.options.Options;

/** Commodore 64 instantiation of the shared descriptor-driven CBM PRG loader. */
public class C64PrgLoader extends AbstractCbmPrgLoader {
	public static final String NAME = "Commodore 64 PRG";

	// Literal legacy keys retained for compatibility with existing saved C64 Programs.
	static final String PRG_LOAD_ADDRESS_PROPERTY = "Retro Machines.C64 PRG Load Address";
	static final String PRG_LENGTH_PROPERTY = "Retro Machines.C64 PRG Payload Length";
	static final String PRG_WRAPPED_PROPERTY = "Retro Machines.C64 PRG Wrapped";
	static final String PRG_SLICES_PROPERTY = "Retro Machines.C64 PRG Slices";

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
		Options info = program.getOptions(Program.PROGRAM_INFO);
		info.setLong(PRG_LOAD_ADDRESS_PROPERTY,
			info.getLong(AbstractCbmPrgLoader.PRG_LOAD_ADDRESS_PROPERTY, -1));
		info.setLong(PRG_LENGTH_PROPERTY,
			info.getLong(AbstractCbmPrgLoader.PRG_LENGTH_PROPERTY, -1));
		info.setBoolean(PRG_WRAPPED_PROPERTY,
			info.getBoolean(AbstractCbmPrgLoader.PRG_WRAPPED_PROPERTY, false));
		info.setString(PRG_SLICES_PROPERTY,
			info.getString(AbstractCbmPrgLoader.PRG_SLICES_PROPERTY, "[]"));
		if (slices.stream().anyMatch(s -> s.target().name().equals("P6510"))) {
			log.appendMsg("PRG bytes were placed at the 6510 port registers $0000/$0001. " +
				"This is a static address image only: loader chronology, DDR effects, and bank " +
				"state changes from $01 are not simulated; descriptor initial banking is unchanged.");
		}
	}
}
