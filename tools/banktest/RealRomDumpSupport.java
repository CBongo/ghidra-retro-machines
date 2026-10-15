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
// Shared plumbing for the two real-ROM dump scripts, RealRomDump.java (NES) and
// SnesRealRomDump.java (SNES) (bead grm-x4y1.6). NOT a GhidraScript: it has no run() and is
// never named on a -postScript line. It lives beside them in tools/banktest/, which
// realrom-test.sh passes as -scriptPath, and Ghidra's script bundle compiles every .java in a
// script directory together, so the two dump scripts reference it as an ordinary class.
//
// INVARIANT CONVENTION. A fact that is true of every row (a hardware-register symbol that must
// exist, a fixed block range, a count that must equal another) used to be pinned by printing it
// into every golden -- 12 symbol lines plus 2 block lines on each of 35 NES goldens, which a
// reviewer then scrolled past forever. Those facts are now CHECKED instead: the check prints
// nothing when it holds and, when it does not, one distinctive line
//
//   REALROM invariant FAIL <what> <detail>
//
// just before the END fence, so a regression still lands as an ordinary golden diff (the only
// diff that can contain the word "invariant"). Grep a dump for "invariant FAIL" to audit it.
//@category RetroMachines.Test

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class RealRomDumpSupport {

	// Kept as a literal (not an extension constant) so the dump scripts need no extension
	// classes on their path for this.
	public static final String MAP_PATH_PROPERTY = "Retro Machine Map";

	private final GhidraScript script;
	private final Program program;
	private final List<String> failures = new ArrayList<>();

	public RealRomDumpSupport(GhidraScript script, Program program) {
		this.script = script;
		this.program = program;
	}

	/** Opens the fence and prints the two header lines both platforms share. */
	public void begin() {
		script.println("=== REALROM BEGIN ===");
		script.println("REALROM program " + program.getName());
		String sha = program.getExecutableSHA256();
		script.println("REALROM sha256 " + (sha == null ? "NONE" : sha));
	}

	/** Flushes any invariant failures (sorted, so the output is deterministic), closes the fence. */
	public void end() {
		Collections.sort(failures);
		for (String f : failures) {
			script.println("REALROM invariant FAIL " + f);
		}
		script.println("=== REALROM END ===");
	}

	/** The loader-stamped descriptor path, or the string NONE. */
	public String mapPath() {
		String v = program.getOptions(Program.PROGRAM_INFO).getString(MAP_PATH_PROPERTY, null);
		return v == null ? "NONE" : v;
	}

	/** Records an invariant failure; nothing is printed until end(). */
	public void fail(String what, String detail) {
		failures.add(what + " " + detail);
	}

	/** Invariant: expected == actual. */
	public void requireEq(String what, long expected, long actual) {
		if (expected != actual) {
			fail(what, "expected=" + expected + " actual=" + actual);
		}
	}

	/** Number of overlay address spaces in the program. */
	public int overlaySpaceCount() {
		int n = 0;
		for (AddressSpace space : program.getAddressFactory().getAllAddressSpaces()) {
			if (space.isOverlaySpace()) {
				n++;
			}
		}
		return n;
	}

	/**
	 * Deliberately named symbols (bead grm-mej.4): IMPORTED and USER_DEFINED only -- the
	 * exclusion of ANALYSIS is the point (jump-table case labels flood the dump otherwise; see
	 * the long note history in git for RealRomDump). Returns the SORTED lines
	 * {@code <addr> <name> <source>[ primary=<bool>]}; the symbol count is the list size.
	 *
	 * @param digits hex digits of the address column (4 for 6502, 6 for 65816)
	 * @param withPrimary whether to append the primary= column
	 */
	public List<String> deliberateSymbols(int digits, boolean withPrimary) {
		List<String> symbols = new ArrayList<>();
		for (Symbol sym : program.getSymbolTable().getAllSymbols(false)) {
			SourceType src = sym.getSource();
			if (src == SourceType.IMPORTED || src == SourceType.USER_DEFINED) {
				symbols.add(fmt(sym.getAddress(), digits) + " " + sym.getName() + " " + src +
					(withPrimary ? (sym.isPrimary() ? " primary=true" : " primary=false") : ""));
			}
		}
		Collections.sort(symbols);
		return symbols;
	}

	/**
	 * Invariant: every line in {@code required} is present in {@code symbols}. Removes them from
	 * {@code symbols} (so they do not occupy the capped sample) and records a failure for each
	 * missing one. Returns the remaining list.
	 */
	public List<String> requireAndRemove(String what, List<String> symbols, List<String> required) {
		List<String> rest = new ArrayList<>(symbols);
		for (String req : required) {
			if (!rest.remove(req)) {
				fail(what, "missing [" + req + "]");
			}
		}
		return rest;
	}

	/**
	 * Print the first {@code cap} (sorted) entries of a category as {@code REALROM <tag> <line>},
	 * so the golden stays small and stable while still pinning concrete annotation text.
	 *
	 * When the cap actually bites, say so IN THE GOLDEN ({@code <tag>.truncated N of M}). The
	 * truncation used to be silent, which is how it went years without anyone noticing that the
	 * sample is a prefix by address and the high addresses were simply gone (bead grm-3pnz).
	 */
	public void emitSample(String tag, List<String> lines, int cap) {
		int n = Math.min(cap, lines.size());
		for (int i = 0; i < n; i++) {
			script.println("REALROM " + tag + " " + lines.get(i));
		}
		if (n < lines.size()) {
			script.println("REALROM " + tag + ".truncated " + n + " of " + lines.size());
		}
	}

	/** Zero-padded lower-case hex offset: 4 digits on 6502, 6 on 65816. */
	public static String fmt(Address addr, int digits) {
		return String.format("%0" + digits + "x", addr.getOffset());
	}
}
