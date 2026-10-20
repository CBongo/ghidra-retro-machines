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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.program.model.address.AddressSpace;

/**
 * Naming convention for a computed window's non-home overlay blocks:
 * {@code <windowName>_B<bankValue>} for a mode-invariant switchable window (the
 * original, single-mode form), extended by mode-dependent-layout support (bead
 * grm-aqf) with two mode-qualified forms: {@code <windowName>_M<modeValue>} for a
 * mode-varying <em>fixed</em> window's non-home layout instance, and
 * {@code <windowName>_M<modeValue>_B<bankValue>} for a mode-varying
 * <em>switchable</em> window's non-home (layout, bank) instance. Used both when a
 * loader creates an instance's overlay block at load time and when an analyzer later
 * needs to resolve a bank/mode value back out of an overlay {@link AddressSpace}'s
 * name.
 *
 * <p>The block name also becomes the overlay {@link AddressSpace}'s name --
 * {@code MemoryBlockUtils} names the overlay space after the block when
 * {@code isOverlay=true} -- empirically confirmed unmangled (tools/banktest
 * checkNesBanktest N3, bead grm-5tl.17): {@code AddressSpace.getName()} equals
 * this exact string, so callers like {@link BoardBankAnalyzer}'s
 * {@code addOverlayRef()} can look the space up by {@code "<window>_B<bank>"}
 * with no separate name-mapping table.
 *
 * <p><b>Naming-contract caveat:</b> the three suffix forms ({@code _B<n>},
 * {@code _M<n>}, {@code _M<n>_B<n>}) are told apart purely by string shape (digits
 * after {@code _B} / {@code _M}, an optional {@code _B} segment after the mode
 * digits). A window name that itself ends in something shaped like {@code _M3} or
 * {@code _B2} would be ambiguous with these suffixes and must be avoided by
 * descriptor authors; none of the shipped or sketch descriptors do this.
 */
final class OverlayNaming {
	private OverlayNaming() {
	}

	/** Builds the {@code <windowName>_B<bankValue>} name for a non-home bank overlay
	 *  of a mode-invariant switchable window. */
	static String bankBlockName(String windowName, int bankValue) {
		return windowName + "_B" + bankValue;
	}

	/**
	 * Parses a bank value back out of an overlay space name, given the owning
	 * window's name. Returns {@code null} if {@code spaceName} does not start
	 * with {@code "<windowName>_B"} or the remainder is not all decimal digits
	 * (e.g. a differently-named overlay space, such as a C64 occupant overlay, or
	 * one of the {@code _M...} mode-qualified forms below).
	 */
	static Integer parseBankValue(String windowName, String spaceName) {
		String prefix = windowName + "_B";
		if (!spaceName.startsWith(prefix)) {
			return null;
		}
		return parseDigits(spaceName.substring(prefix.length()));
	}

	/** Builds the {@code <windowName>_M<modeValue>} name for a mode-varying
	 *  <em>fixed</em> window's non-home layout instance. */
	static String modeBlockName(String windowName, int modeValue) {
		return windowName + "_M" + modeValue;
	}

	/**
	 * Parses a mode value back out of an overlay space name for a mode-varying
	 * fixed window, given the owning window's name. Returns {@code null} if
	 * {@code spaceName} does not start with {@code "<windowName>_M"} or the
	 * remainder is not all decimal digits -- in particular, a
	 * {@code "<windowName>_M<m>_B<v>"} space (see {@link #modeBankBlockName})
	 * fails to parse here because its remainder contains {@code "_B"}.
	 */
	static Integer parseModeValue(String windowName, String spaceName) {
		String prefix = windowName + "_M";
		if (!spaceName.startsWith(prefix)) {
			return null;
		}
		return parseDigits(spaceName.substring(prefix.length()));
	}

	/** A parsed {@code <windowName>_M<mode>_B<bank>} overlay name's (mode, bank)
	 *  pair; see {@link #modeBankBlockName} / {@link #parseModeBankValue}. */
	record ModeBank(int mode, int bank) {}

	/** Builds the {@code <windowName>_M<modeValue>_B<bankValue>} name for a
	 *  mode-varying <em>switchable</em> window's non-home (layout, bank) instance. */
	static String modeBankBlockName(String windowName, int modeValue, int bankValue) {
		return windowName + "_M" + modeValue + "_B" + bankValue;
	}

	/**
	 * Parses the (mode, bank) pair back out of a {@code "<windowName>_M<m>_B<v>"}
	 * overlay space name, given the owning window's name. Returns {@code null} if
	 * {@code spaceName} does not have exactly that shape (both {@code <m>} and
	 * {@code <v>} all decimal digits).
	 */
	static ModeBank parseModeBankValue(String windowName, String spaceName) {
		String prefix = windowName + "_M";
		if (!spaceName.startsWith(prefix)) {
			return null;
		}
		String rest = spaceName.substring(prefix.length());
		int bIdx = rest.indexOf("_B");
		if (bIdx < 0) {
			return null;
		}
		Integer mode = parseDigits(rest.substring(0, bIdx));
		Integer bank = parseDigits(rest.substring(bIdx + 2));
		if (mode == null || bank == null) {
			return null;
		}
		return new ModeBank(mode, bank);
	}

	/** Strict decimal parse: non-empty, decimal digits only (no sign, no
	 *  whitespace -- stricter than {@code Integer.parseInt}), else null. */
	private static Integer parseDigits(String s) {
		if (s.isEmpty()) {
			return null;
		}
		int v = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c < '0' || c > '9') {
				return null;
			}
			v = v * 10 + (c - '0');
		}
		return v;
	}
}
