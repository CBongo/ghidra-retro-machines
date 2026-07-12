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

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;

/**
 * {@link BasicTokenLookup} for stock BASIC V2 ($80-$CB), backed entirely by the
 * {@code BASIC_V2_TOKEN} enum compiled into {@code machines/c64.gdt} from
 * {@code machines/generated/basic-tokens.yaml} (bead grm-1.6/grm-odt.1's foundation --
 * see that YAML's header for the full dialect-fork model). This class contains no
 * transcribed token table of its own: it is a thin (bytes consumed, name) adapter over
 * {@code gdtMgr.getDataType(CategoryPath.ROOT, "BASIC_V2_TOKEN")}, read directly from the
 * archive-side enum (no need to resolve it into the program's own data type manager --
 * the analyzer only queries names, it never applies the enum as a data type to a byte,
 * since token bytes are rendered into a listing comment rather than typed -- see
 * {@link C64BasicAnalyzer}'s class comment for that call).
 */
final class BasicV2TokenLookup implements BasicTokenLookup {

	private static final String ENUM_NAME = "BASIC_V2_TOKEN";

	private final ghidra.program.model.data.Enum tokenEnum;

	private BasicV2TokenLookup(ghidra.program.model.data.Enum tokenEnum) {
		this.tokenEnum = tokenEnum;
	}

	/** Opens the lookup from an already-open {@code c64.gdt} archive manager, or returns
	 *  {@code null} if the enum is missing (a broken/old archive -- callers fall back to
	 *  rendering every byte &gt;= $80 as a raw {@code {$xx}} escape via PetsciiMapper). */
	static BasicV2TokenLookup fromGdt(FileDataTypeManager gdtMgr) {
		if (gdtMgr == null) {
			return null;
		}
		DataType dt = gdtMgr.getDataType(CategoryPath.ROOT, ENUM_NAME);
		if (!(dt instanceof ghidra.program.model.data.Enum e)) {
			return null;
		}
		return new BasicV2TokenLookup(e);
	}

	@Override
	public Match lookup(byte[] data, int offset) {
		if (offset < 0 || offset >= data.length) {
			return null;
		}
		int b = data[offset] & 0xFF;
		if (b < 0x80) {
			return null;
		}
		String name;
		try {
			name = tokenEnum.getName(b);
		}
		catch (Exception e) {
			name = null;
		}
		if (name == null) {
			return null; // $CC-$FF: unassigned in BASIC 2 (see basic-tokens.yaml header)
		}
		return new Match(1, name);
	}
}
