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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

/**
 * The single place that derives a memory-block name from a recovered address -- {@code COPY_} for
 * a run-from-elsewhere transfer ({@link TransferMaterializer}, {@link RunFromElsewhere}) and
 * {@code DECRYPTED_} for a recovered decrypt ({@link C64DecryptLoopAnalyzer}). The name is also
 * the <em>idempotence key</em>: each of those sites decides "was this already recovered on a
 * prior pass?" by asking {@code Memory.getBlock(name)}, so two recoveries that produce the same
 * name are indistinguishable to it.
 *
 * <p><b>Why this class exists (grm-0p7).</b> The name used to be the offset alone
 * ({@code COPY_%04x}), but {@code Memory.getBlock(String)} searches by name across <em>every</em>
 * address space while an {@link Address} is a (space, offset) pair. Two recoveries landing at the
 * same CPU offset in different overlay spaces -- the same window offset in two banks -- therefore
 * collided: the second was reported "already recovered on a prior pass" and never materialized.
 * Qualifying the name with the space makes the key as wide as the address it stands for. Three
 * call sites derive these names, and two of them derived {@code COPY_} independently and could
 * drift, so they all route through here -- the shared-helper rule CLAUDE.md states for
 * {@code NesRomLoader.placementError()}.
 *
 * <p><b>The format is strictly widening.</b> An address in the program's default space keeps
 * exactly the historical name, {@code <prefix><offset:%04x>} -- those names are pinned in golden
 * dumps and in JUnit assertions, and a copy into ordinary base-space RAM is the overwhelmingly
 * common case. Only an address <em>outside</em> the default space gains the space component:
 * {@code <prefix><space>_<offset:%04x>}, e.g. {@code COPY_RAM_E000_e000} for a banked destination
 * homed in the {@code RAM_E000} overlay.
 *
 * <p><b>The test is "is this the default space", not {@code isOverlaySpace()}</b>, because the
 * two are not equivalent: a program has non-overlay spaces that are not the default one
 * (Ghidra's {@code OTHER}, the register space declared by every language here), and an address in
 * one of those aliases a default-space offset just as an overlay address does. Comparing against
 * {@code AddressFactory.getDefaultAddressSpace()} is the test that actually says "this name is
 * unambiguous on its own".
 *
 * <p>Names are deterministic -- a pure function of the address and the program's default space,
 * with no counters and no dependence on discovery order -- so a re-run derives the same key and
 * idempotence still holds. The space component is sanitized to {@code [A-Za-z0-9_]} so the result
 * is legal both as a block name and as the overlay space name Ghidra derives from one
 * ({@code MemoryMapDB.fixupOverlaySpaceName}, which rejects only {@code ':'} and characters
 * {@code <= 0x20}; ours is the stricter rule).
 */
final class RecoveredBlockNames {

	private RecoveredBlockNames() {
	}

	/** The block name for a run-from-elsewhere copy landing at {@code dst}. */
	static String forCopy(Program program, Address dst) {
		return qualify(program, "COPY_", dst);
	}

	/** The block name for a recovered decrypt whose plaintext starts at {@code base}. */
	static String forDecrypted(Program program, Address base) {
		return qualify(program, "DECRYPTED_", base);
	}

	/**
	 * {@code <prefix><offset>} in the default space, {@code <prefix><space>_<offset>} anywhere
	 * else. See the class javadoc for why the space test is a default-space comparison.
	 */
	private static String qualify(Program program, String prefix, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		String offset = String.format("%04x", addr.getOffset());
		if (space.equals(program.getAddressFactory().getDefaultAddressSpace())) {
			return prefix + offset;
		}
		return prefix + sanitizeSpaceName(space.getName()) + "_" + offset;
	}

	/**
	 * A space name reduced to {@code [A-Za-z0-9_]}: anything else becomes {@code '_'}, a run of
	 * such characters collapses to one, and leading/trailing underscores are dropped so the
	 * component cannot blur into the separators around it. A name that reduces to nothing, or
	 * that would start with a digit, is given a fixed prefix rather than a counter, so the
	 * mapping stays a pure function of the input.
	 */
	private static String sanitizeSpaceName(String spaceName) {
		StringBuilder buf = new StringBuilder(spaceName.length());
		for (int i = 0; i < spaceName.length(); i++) {
			char c = spaceName.charAt(i);
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '_') {
				buf.append(c);
			}
			else if (buf.length() > 0 && buf.charAt(buf.length() - 1) != '_') {
				buf.append('_');
			}
		}
		while (buf.length() > 0 && buf.charAt(buf.length() - 1) == '_') {
			buf.setLength(buf.length() - 1);
		}
		while (buf.length() > 0 && buf.charAt(0) == '_') {
			buf.deleteCharAt(0);
		}
		if (buf.length() == 0) {
			return "space";
		}
		if (buf.charAt(0) >= '0' && buf.charAt(0) <= '9') {
			return "s" + buf;
		}
		return buf.toString();
	}
}
