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
	/** Creates a loader for PET 4032 BASIC PRG files. */
	public PetPrgLoader() {
	}

	/** The loader name shown by Ghidra for PET 4032 PRG files. */
	public static final String NAME = "Commodore PET 4032 PRG";

	/** Returns the display name registered for this loader. */
	@Override
	public String getName() {
		return NAME;
	}

	/** Returns the compiled PET 4032 memory-map descriptor. */
	@Override
	protected String getMapPath() {
		return "machines/pet4032.map";
	}

	/** Returns the descriptor machine identifier for PET-specific policies. */
	@Override
	protected String getMachineId() {
		return "pet4032";
	}

	/**
	 * Accepts only a structurally valid PET BASIC image at the canonical BASIC start.
	 *
	 * @param provider the candidate PRG byte provider, including its two-byte header
	 * @param loadAddress address encoded by the PRG header
	 * @param payloadLength number of payload bytes after the two-byte header
	 * @return whether this loader recognizes the candidate as a PET BASIC PRG
	 */
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
