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
 * Fixed-length PETSCII string, hardwired to the {@code x-petscii-unshifted} charset (bead
 * grm-1.4 Phase D) served by {@code retromachines.charset.RetroCharsetProvider}. Mirrors
 * {@link ghidra.program.model.data.StringDataType}'s structure exactly, with a non-null
 * {@code charsetName} so no per-instance charset setting is needed. A {@link DataType}
 * {@code BuiltIn}, so {@code ClassSearcher} auto-registers it -- no extension-side
 * registration list exists in this repo to also update.
 */
public class PetsciiStringDataType extends AbstractStringDataType {

	public static final PetsciiStringDataType dataType = new PetsciiStringDataType();

	public PetsciiStringDataType() {
		this(null);
	}

	public PetsciiStringDataType(DataTypeManager dtm) {
		super("PetsciiString", // data type name
			"petscii", // mnemonic
			"PETSCII", // default label
			"PSTR", // default label prefix
			"ps", // default abbrev label prefix
			"PETSCII String (fixed length, unshifted/graphics)", // description
			"x-petscii-unshifted", // charset
			CharDataType.dataType, // replacement data type
			StringLayoutEnum.FIXED_LEN, // StringLayoutEnum
			dtm// data type manager
		);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PetsciiStringDataType(dtm);
	}
}
