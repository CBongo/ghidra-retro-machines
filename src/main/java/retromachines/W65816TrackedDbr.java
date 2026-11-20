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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;

/**
 * Reads the data-bank register tracked by {@link W65816DataBankAnalyzer} (grm-9nxj.32) from the
 * program context, for consumers that used to assume a bank (grm-9nxj.43). The value is whatever
 * the context holds at the address, whether the analyzer stamped it or the user set it; callers
 * keep their old assumption as the fallback when it is unknown.
 */
final class W65816TrackedDbr {

	/** Returned when DBR is not known at the address. */
	static final int UNKNOWN = -1;

	private W65816TrackedDbr() {
	}

	/** DBR (0-255) in the program context at {@code at}, or {@link #UNKNOWN}. */
	static int at(Program program, Address at) {
		Register dbr = program.getRegister("DBR");
		if (dbr == null) {
			return UNKNOWN;
		}
		RegisterValue v = program.getProgramContext().getRegisterValue(dbr, at);
		return v != null && v.hasValue() ? v.getUnsignedValue().intValue() & 0xFF : UNKNOWN;
	}
}
