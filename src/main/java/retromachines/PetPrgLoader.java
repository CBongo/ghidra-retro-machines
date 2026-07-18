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

import ghidra.app.util.bin.ByteProvider;

/** Loader for tokenized BASIC PRGs targeting the representative Commodore PET 4032. */
public class PetPrgLoader extends AbstractCbmPrgLoader {
	public static final String NAME = "Commodore PET 4032 PRG";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	protected String getMapPath() {
		return "machines/pet4032.map";
	}

	@Override
	protected String getMachineId() {
		return "pet4032";
	}

	@Override
	protected boolean recognizesPrg(ByteProvider provider, long loadAddress, long payloadLength) {
		// A raw PRG carries no machine identity. Claim only the canonical PET BASIC program
		// start plus a structurally valid line-link chain, so this opinion cannot steal an
		// arbitrary C64 or machine-code PRG. Non-BASIC PET PRGs are deliberately outside
		// this first conservative opinion and can still be imported as raw binary.
		return loadAddress == 0x0401 &&
			looksLikeBasicStart(provider, loadAddress, payloadLength);
	}
}
