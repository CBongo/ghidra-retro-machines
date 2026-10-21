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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

/** Shared {@code canAnalyze} gates for the analyzers. */
final class AnalyzerGates {

	private AnalyzerGates() {
	}

	/**
	 * True when the program's language supports p-code and its default address space is at most
	 * 16 bits wide, i.e. one of the 8-bit machines this extension ships.
	 */
	static boolean is8BitPcode(Program program) {
		if (!program.getLanguage().supportsPcode()) {
			return false;
		}
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		return defaultSpace != null && defaultSpace.getSize() <= 16;
	}
}
