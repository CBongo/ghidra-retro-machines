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
package retromachines.data;

import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringLayoutEnum;

/**
 * Null-terminated PETSCII string, hardwired to the {@code x-petscii-shifted} charset (bead
 * grm-1.4 Phase D) served by {@code retromachines.charset.RetroCharsetProvider}.
 */
public class TerminatedPetsciiShiftedStringDataType extends AbstractStringDataType {

	public static final TerminatedPetsciiShiftedStringDataType dataType =
		new TerminatedPetsciiShiftedStringDataType();

	public TerminatedPetsciiShiftedStringDataType() {
		this(null);
	}

	public TerminatedPetsciiShiftedStringDataType(DataTypeManager dtm) {
		super("TerminatedPetsciiShiftedString", // data type name
			"petscii-shifted", // mnemonic
			"PETSCII", // default label
			"PSTRS", // default label prefix
			"pss", // default abbrev label prefix
			"PETSCII String (null terminated, shifted/lowercase)", // description
			"x-petscii-shifted", // charset
			CharDataType.dataType, // replacement data type
			StringLayoutEnum.NULL_TERMINATED_UNBOUNDED, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new TerminatedPetsciiShiftedStringDataType(dtm);
	}
}
