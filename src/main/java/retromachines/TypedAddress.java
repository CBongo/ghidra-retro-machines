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

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

/**
 * Parses an address a human typed -- a script argument, a manifest token -- and fails with a
 * message that says <em>why</em> when it does not resolve (bead grm-h649).
 * <p>
 * {@code GhidraScript.parseAddress} only says "Invalid address", and an unqualified
 * {@code AddressFactory.getAddress} returns null for a {@code SPACE:offset} whose space does not
 * exist. Both hide the one failure that is now routine: an overlay space's name depends on
 * whether the board's layout mode is known ({@code W8000_M3_B1} vs {@code W8000_B1}, grm-ic5), so
 * a hand-typed name that was right yesterday can name no space today. That cost the zelda
 * real-ROM row 4720 bytes of materialized code with only a golden diff to show for it. This
 * names the missing space and suggests the spelling that does exist.
 */
public final class TypedAddress {
	private TypedAddress() {
	}

	/** One {@code _M<mode>} layout-mode segment, as {@link OverlayNaming} builds it. */
	private static final Pattern MODE_SEGMENT = Pattern.compile("_M\\d+(?=_|$)");

	/**
	 * {@code text} as an address in {@code program}: hex, optionally {@code 0x}- or
	 * {@code $}-prefixed, optionally {@code SPACE:offset}.
	 *
	 * @throws IllegalArgumentException naming the missing space (and a near spelling that exists,
	 *     if any) or the bad offset; never returns null
	 */
	public static Address parse(Program program, String text) {
		String token = text.startsWith("$") ? text.substring(1) : text;
		Address addr = program.getAddressFactory().getAddress(token);
		if (addr != null) {
			return addr;
		}
		int colon = token.lastIndexOf(Address.SEPARATOR);
		if (colon < 0) {
			throw new IllegalArgumentException("invalid address '" + text + "'");
		}
		String spaceName = token.substring(0, colon);
		if (program.getAddressFactory().getAddressSpace(spaceName) != null) {
			throw new IllegalArgumentException("invalid offset '" + token.substring(colon + 1) +
				"' in address space " + spaceName + " (address '" + text + "')");
		}
		List<String> names = new ArrayList<>();
		for (AddressSpace space : program.getAddressFactory().getAllAddressSpaces()) {
			names.add(space.getName());
		}
		List<String> near = nearSpaceNames(spaceName, names);
		throw new IllegalArgumentException("no address space named '" + spaceName +
			"' in this program (address '" + text + "')" + (near.isEmpty() ? ""
					: "; did you mean " + String.join(" or ", near) + "? An overlay's _M<mode> " +
						"qualifier appears only while the board's layout mode is unknown (grm-ic5)"));
	}

	/**
	 * The names in {@code existing} that differ from {@code missing} only by one {@code _M<mode>}
	 * segment, in either direction: {@code W8000_M3_B1} suggests {@code W8000_B1}, and
	 * {@code W8000_B1} suggests every {@code W8000_M<m>_B1}. Sorted, empty if none.
	 */
	static List<String> nearSpaceNames(String missing, Iterable<String> existing) {
		TreeSet<String> near = new TreeSet<>();
		for (String name : existing) {
			if (stripsTo(missing, name) || stripsTo(name, missing)) {
				near.add(name);
			}
		}
		return new ArrayList<>(near);
	}

	/** True when deleting one {@code _M<mode>} segment from {@code qualified} gives {@code bare}. */
	private static boolean stripsTo(String qualified, String bare) {
		var m = MODE_SEGMENT.matcher(qualified);
		while (m.find()) {
			if ((qualified.substring(0, m.start()) + qualified.substring(m.end())).equals(bare)) {
				return true;
			}
		}
		return false;
	}
}
