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
package retromachines.vectors;

import java.util.List;

/**
 * Describes how a single-byte packed status register decomposes into named flag bits, purely
 * for {@link VectorRunner} mismatch reporting.
 *
 * <p>SPC700's PSW has no per-flag Ghidra register -- the flags are sleigh {@code @define}
 * bitranges over one {@code PSW} register (bead grm-c9d.1/grm-c9d.2 design discussion):
 * {@code PSW[0,1]}=C, {@code [1,1]}=Z, {@code [2,1]}=I, {@code [3,1]}=H, {@code [4,1]}=B,
 * {@code [5,1]}=P, {@code [6,1]}=V, {@code [7,1]}=N. A raw byte diff ({@code "PSW 0x91 != 0x11"})
 * is nearly useless to whoever is rewriting the semantics; this decomposes both sides into named
 * bits so {@link VectorRunner} can report exactly which flag(s) differ (e.g. {@code "PSW.C 1 !=
 * 0"}), which is the actionable form.
 *
 * <p>Language-agnostic: nothing here is SPC700-specific. A caller wires up whichever
 * {@link FlagBit} list matches the register it is decomposing; a language with no packed status
 * register simply supplies no {@link FlagLayout} for any register and gets a plain scalar diff.
 *
 * @param fields the flag bits, LSB position and width each, in any convenient order
 */
public record FlagLayout(List<FlagBit> fields) {

	/**
	 * One named bit (or bitrange) within a packed status byte.
	 *
	 * @param name the flag's short name (e.g. {@code "C"}, {@code "Z"})
	 * @param lsb  the field's least-significant bit position within the byte
	 * @param width the field's width in bits (1 for a single flag bit)
	 */
	public record FlagBit(String name, int lsb, int width) {

		int mask() {
			return (1 << width) - 1;
		}

		/** This field's value as packed into {@code byteValue}. */
		int valueIn(int byteValue) {
			return (byteValue >> lsb) & mask();
		}
	}

	/**
	 * The convenience SPC700 layout (bead grm-c9d.1's PSW bit assignment), reused wherever this
	 * project needs it -- both here (mismatch reporting) and, later, by anything else that wants
	 * SPC700's canonical PSW bit names.
	 */
	public static final FlagLayout SPC700_PSW = new FlagLayout(List.of(
		new FlagBit("C", 0, 1),
		new FlagBit("Z", 1, 1),
		new FlagBit("I", 2, 1),
		new FlagBit("H", 3, 1),
		new FlagBit("B", 4, 1),
		new FlagBit("P", 5, 1),
		new FlagBit("V", 6, 1),
		new FlagBit("N", 7, 1)));

	/**
	 * Every flag bit whose value differs between {@code expected} and {@code actual}, formatted
	 * as {@code "<registerName>.<flag> <actual> != <expected>"}, one per differing bit. Flags
	 * that agree are omitted -- only the actionable bits are reported.
	 */
	public List<String> diff(String registerName, int expected, int actual) {
		return fields.stream()
				.filter(f -> f.valueIn(expected) != f.valueIn(actual))
				.map(f -> registerName + "." + f.name() + " " + f.valueIn(actual) + " != " +
					f.valueIn(expected))
				.toList();
	}
}
