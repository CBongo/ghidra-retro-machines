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
// The normalized behavior dump and the generic game-identity / async-entry-point criteria,
// moved out of VerifyBankTest.java (bead grm-rx1i.21) so the GhidraScript class holds only the
// Check registry and dispatch. A sibling of the other Verify*Criteria families.

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import retromachines.AbstractCbmPrgLoader;
import retromachines.C64BasicAnalyzer;
import retromachines.C64BankingAnalyzer;
import retromachines.EmulationRecovery;
import retromachines.IoPolicy;
import retromachines.RecoveryResult;
import retromachines.StopConditions;
import retromachines.StopReason;

public class VerifyDumpCriteria extends VerifyBase {

	VerifyDumpCriteria(GhidraScript script, Verdict verdict) {
		super(script, verdict);
	}

	// ------------------------------------------------------------------
	// Normalized behavior dump
	// ------------------------------------------------------------------

	protected void dump() {
		List<String> blocks = new ArrayList<>();
		List<String> comments = new ArrayList<>();
		List<String> bookmarks = new ArrayList<>();
		List<String> refs = new ArrayList<>();
		List<String> symbols = new ArrayList<>();

		// Load-time memory layout (bead grm-5tl.17): locks block names, ranges, and
		// overlay-ness as a regression net for the loader refactor tracked by grm-5tl.14.
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			blocks.add("BLOCK " + block.getName() + " " + fmt(block.getStart()) + "-" +
				fmt(block.getEnd()) + " overlay=" + block.isOverlay());
		}

		InstructionIterator instrs = currentProgram.getListing().getInstructions(true);
		while (instrs.hasNext()) {
			Instruction instr = instrs.next();
			Address at = instr.getMinAddress();

			// Both members of the analyzer's bank-annotation family: a resolved "bank ->" and an
			// unresolved "bank ?" gap comment (grm-3ou part 2). A gap comment is written at
			// exactly the sites that carry a BOOKMARK line below, so the two channels of one
			// golden can be checked against each other by eye.
			String eol = currentProgram.getListing().getComment(CommentType.EOL, at);
			if (eol != null && (eol.contains("bank ->") || eol.contains("bank ?"))) {
				comments.add("COMMENT " + fmt(at) + " " + eol);
			}

			for (Reference r : instr.getReferencesFrom()) {
				AddressSpace toSpace = r.getToAddress().getAddressSpace();
				if (toSpace.isOverlaySpace()) {
					refs.add("REF " + fmt(at) + " -> " + toSpace.getName() + "::" +
						fmt(r.getToAddress()) + " " + r.getReferenceType().getName() +
						" primary=" + r.isPrimary());
				}
			}
		}

		Iterator<Bookmark> bms = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bms.hasNext()) {
			Bookmark bm = bms.next();
			if (CATEGORY_C64.equals(bm.getCategory()) || CATEGORY_NES.equals(bm.getCategory())) {
				bookmarks.add("BOOKMARK " + bm.getTypeString() + " " + fmt(bm.getAddress()));
			}
		}

		// Deliberately named symbols (bead grm-mej.4). Until this landed the dump captured NO
		// symbol at all, so anything that named something -- the loaders' entry points and vector
		// handlers, a descriptor symbol set, and shortly the analyzer's bank-mirror names -- was
		// invisible to every gate in the project.
		//
		// SourceType.DEFAULT IS EXCLUDED, and that filter is the whole design of this list.
		// NOTE the sibling filter in RealRomDump is STRICTER (IMPORTED/USER_DEFINED only): Ghidra's
		// jump-table analyzer tags switch-case labels ANALYSIS, which on a real ROM runs to
		// thousands. No synthetic fixture has a switch table, so DEFAULT is a sufficient filter
		// here -- and it has to be, because an analyzer-created label is ANALYSIS and this is the
		// only golden tier that can see one.
		// Ghidra generates FUN_/LAB_/DAT_ defaults in the thousands; emitting them would bury a
		// handful of intentional names in noise that tracks DISASSEMBLY rather than intent, so
		// every unrelated change would churn it and nobody would read the diff. What is left is
		// exactly the set something chose to create. The source type is printed alongside the name
		// because it is the observable half of the never-overwrite-user-work rule: an annotation
		// that arrived as USER_DEFINED must never be replaced by one of ours.
		for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(false)) {
			if (sym.getSource() != SourceType.DEFAULT) {
				symbols.add("SYMBOL " + fmt(sym.getAddress()) + " " + sym.getName() + " " +
					sym.getSource() + (sym.isPrimary() ? " primary=true" : " primary=false"));
			}
		}

		Collections.sort(blocks);
		Collections.sort(comments);
		Collections.sort(bookmarks);
		Collections.sort(refs);
		Collections.sort(symbols);

		println("=== BANKDUMP BEGIN ===");
		// Per-game identity (bead grm-hb6.1), only when the loader stamped one -- today that is
		// every NES import and no CBM one, so this line is presence-gated to keep the C64/PET/C128
		// goldens still. The criteria that give it meaning are in checkGameIdentity().
		String identity = gameIdentityValue();
		if (identity != null) {
			println("IDENTITY " + identity);
		}
		for (String line : blocks) {
			println(line);
		}
		for (String line : comments) {
			println(line);
		}
		for (String line : bookmarks) {
			println(line);
		}
		for (String line : refs) {
			println(line);
		}
		for (String line : symbols) {
			println(line);
		}
		println("=== BANKDUMP END ===");
	}

	// ------------------------------------------------------------------
	// Per-game identity criteria (bead grm-hb6.1)
	// ------------------------------------------------------------------

	/**
	 * Checks the per-game identity a loader stamped on this program (bead grm-hb6.1). Gated on
	 * the property being present, so it covers all ten NES fixtures and is silently a no-op on
	 * every CBM one -- no loader there writes it. The CRITERION lines print outside the
	 * BANKDUMP markers that run-banktest.sh carves the goldens from, so these cost no golden
	 * churn.
	 * <p>
	 * GID1 pins the grammar on a real import: both halves present, 64 hex digits each,
	 * lowercase, and colon-separated rather than '='-separated (an '=' grammar cannot survive
	 * analyzeHeadless.bat's cmd.exe arg parser). GID2 asserts the {@code file:} half equals
	 * Ghidra's own {@link Program#getExecutableSHA256()}: the extension computes that digest
	 * itself rather than reading Ghidra's, so this is the assertion that ties our hex formatting
	 * to Ghidra's -- and hence to the hashes tools/banktest/realrom/manifest.tsv pins its rows
	 * by.
	 * <p>
	 * GID3 is why this check exists. A golden IDENTITY line blessed from the implementation
	 * proves the hash is stable, never that it covers the right bytes; only an independent
	 * recomputation proves the slice bounds. So GID3 re-reads the imported file from
	 * {@link Program#getExecutablePath()}, parses the 16 iNES header bytes here rather than
	 * asking the loader, and recomputes SHA-256 over
	 * {@code [16 + 512*trainer, + 16384*prgBanks)}. It emits no ROM bytes, only a digest, so it
	 * stays copyright-safe. An unreadable file FAILs with the path in the detail rather than
	 * skipping: these fixtures are generated locally and are always present, so a silent skip
	 * would rot into a criterion that verifies nothing.
	 */
	protected void checkGameIdentity() {
		String value = gameIdentityValue();
		if (value == null) {
			return;
		}

		criterion("GID1", value.matches("^prg:[0-9a-f]{64} file:[0-9a-f]{64}$"),
			"identity property value: " + value);

		String prgHalf = identityToken(value, "prg");
		String fileHalf = identityToken(value, "file");
		String ghidraSha = currentProgram.getExecutableSHA256();
		criterion("GID2", fileHalf != null && fileHalf.equals(ghidraSha),
			"identity file:" + fileHalf + " vs getExecutableSHA256()=" + ghidraSha);

		String path = currentProgram.getExecutablePath();
		String independent;
		String detail;
		try {
			independent = recomputePrgSha256(path);
			detail = "independent recompute -> " + independent + " from " + path;
		}
		catch (Exception e) {
			independent = null;
			detail = "cannot recompute PRG digest from '" + path + "': " + e;
		}
		criterion("GID3", independent != null && independent.equals(prgHalf),
			detail + "; identity prg:" + prgHalf);
	}

	/**
	 * Checks the asynchronous-entry-point property the NES loader stamps (bead grm-913): the
	 * channel that tells {@link BoardBankAnalyzer}'s dataflow which entries it must NOT seed
	 * with {@code banking.initial_state} fully known, because an interrupt fires from arbitrary
	 * mainline context and leaves the interrupted code's bank live on entry.
	 * <p>
	 * This exists because the change it guards is INVISIBLE when it silently does nothing. If
	 * the loader stopped writing the property, every seed would quietly revert to the unsound
	 * fully-known state, no fixture would fail, and the resulting golden would look clean --
	 * the failure direction that reads as "my change moved nothing". AEP1 therefore asserts the
	 * property is present at all, and AEP2/AEP3 assert it names exactly the vectors it should:
	 * the NMI and IRQ handler addresses, and NOT RESET, which is the one entry the initial
	 * state is genuinely true for.
	 * <p>
	 * Gated on the NMI label existing rather than on the property, so a loader that stopped
	 * writing the property FAILS here instead of skipping. Silently a no-op on every CBM
	 * fixture, none of which has a 6502 vector table. Like {@link #checkGameIdentity}, the
	 * CRITERION lines print outside the BANKDUMP markers, so they cost no golden churn.
	 */
	protected void checkAsyncEntryPoints() {
		Address nmi = uniqueGlobalSymbolAddress("NMI");
		if (nmi == null) {
			return;
		}
		Address irq = uniqueGlobalSymbolAddress("IRQ");
		Address reset = uniqueGlobalSymbolAddress("RESET");

		String value = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(ASYNC_ENTRY_POINTS_PROPERTY, null);
		criterion("AEP1", value != null && !value.isBlank(),
			"async entry points property value: " + value);
		if (value == null) {
			return;
		}

		List<String> tokens = List.of(value.trim().split("\\s+"));
		criterion("AEP2", tokens.contains(nmi.toString()) &&
			(irq == null || tokens.contains(irq.toString())),
			"NMI=" + nmi + " IRQ=" + irq + " listed in " + tokens);
		criterion("AEP3", reset == null || !tokens.contains(reset.toString()),
			"RESET=" + reset + " must NOT be listed (reset is the one entry initial_state " +
				"is true for); listed: " + tokens);
	}

	/**
	 * The address of the single global symbol named {@code name}, or null when there is not
	 * exactly one. Null on "several" as well as "none" on purpose: an ambiguous vector label is
	 * not evidence about the property either way, and the caller turns null into a skip.
	 */
	protected Address uniqueGlobalSymbolAddress(String name) {
		List<Symbol> syms = currentProgram.getSymbolTable().getGlobalSymbols(name);
		return syms.size() == 1 ? syms.get(0).getAddress() : null;
	}

	/** The identity property's raw value, or null when no loader stamped one. */
	protected String gameIdentityValue() {
		return currentProgram.getOptions(Program.PROGRAM_INFO)
				.getString(GAME_IDENTITY_PROPERTY, null);
	}

	/** The {@code <key>:} token's digest text out of an identity value, or null if absent. */
	protected static String identityToken(String value, String key) {
		String prefix = key + ":";
		for (String token : value.trim().split("\\s+")) {
			if (token.startsWith(prefix)) {
				return token.substring(prefix.length());
			}
		}
		return null;
	}

	/**
	 * The oracle for GID3: SHA-256 over the PRG slice of the .nes file at {@code executablePath},
	 * computed from a header parse done here so it is independent of the loader's. Throws if the
	 * file cannot be read or is not a usable iNES image -- GID3 turns that into a FAIL.
	 */
	protected static String recomputePrgSha256(String executablePath) throws Exception {
		byte[] image = Files.readAllBytes(resolveImagePath(executablePath));
		if (image.length < 16 || image[0] != 'N' || image[1] != 'E' || image[2] != 'S' ||
			image[3] != 0x1A) {
			throw new IOException("not an iNES image (bad magic or short header)");
		}
		int prgLow = image[4] & 0xFF;
		// Most banktest fixtures are plain iNES 1.0, where h[4] alone is the 16 KiB PRG unit
		// count. An NES 2.0 header ((h[7] & 0x0C) == 0x08) carries a PRG high nibble in h[9],
		// and 0xF there selects the EXPONENT form, where h[4] is not a count at all but
		// EEEEEEMM for a size of 2^E * (2M+1) BYTES. nesnromsubtest is the fixture that uses
		// it, because an 8 KiB PRG is HALF a unit and the linear form cannot express it (beads
		// grm-dfj, grm-7e5o).
		//
		// Re-derived here from the format rather than shared with InesHeader.nes2RomSize on
		// purpose: GID3's entire value is being an INDEPENDENT parse of the same documented
		// header, so calling into the loader would only prove it agrees with itself.
		int prgHi = (image[7] & 0x0C) == 0x08 ? image[9] & 0x0F : 0;
		long length;
		if (prgHi == 0x0F) {
			int exponent = prgLow >> 2;
			// An absurd exponent would overflow long and could go negative, which the fit check
			// below would wave through -- report 0 and let it fail as "no usable slice" instead.
			length = exponent >= 48 ? 0 : (1L << exponent) * (((prgLow & 0x03) * 2L) + 1);
		}
		else {
			length = 16384L * (prgLow | (prgHi << 8));
		}
		int start = 16 + (((image[6] & 0x04) != 0) ? 512 : 0);
		if (length == 0 || start + length > image.length) {
			throw new IOException("PRG slice [" + start + ", +" + length + ") does not fit in " +
				image.length + " bytes");
		}
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(image, start, (int) length);
		StringBuilder hex = new StringBuilder(64);
		for (byte b : digest.digest()) {
			hex.append(String.format("%02x", b & 0xFF));
		}
		return hex.toString();
	}

	/**
	 * The imported file as a readable {@link Path}. {@code getExecutablePath()} may be a Windows
	 * path with mixed separators (which {@code Path.of} handles) and Ghidra sometimes records it
	 * in a URL-ish {@code /C:/dir/file} form (which needs the leading slash trimmed), so both
	 * spellings are tried before giving up.
	 */
	protected static Path resolveImagePath(String executablePath) throws IOException {
		if (executablePath == null || executablePath.isBlank()) {
			throw new IOException("program records no executable path");
		}
		List<String> candidates = new ArrayList<>();
		candidates.add(executablePath);
		if (executablePath.matches("^/[A-Za-z]:.*")) {
			candidates.add(executablePath.substring(1));
		}
		for (String candidate : candidates) {
			try {
				Path p = Path.of(candidate);
				if (Files.isReadable(p)) {
					return p;
				}
			}
			catch (InvalidPathException e) {
				// not spellable as a path on this platform; try the next candidate
			}
		}
		throw new IOException("no readable file at that path");
	}
}
