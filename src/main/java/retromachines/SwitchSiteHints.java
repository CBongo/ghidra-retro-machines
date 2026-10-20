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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Per-game {@code banking.switch_sites} SITE hints (bead grm-hb6.4): "there is a bank-switch
 * store at this address", for the case automation cannot see (the store sits in bytes no flow
 * reaches, so it was never disassembled).
 * <p>
 * <b>Seed, do not inject</b> (docs/per-game-descriptors-design.md section 6.2). A hint never
 * produces a {@code SwitchResult} or an annotation (the optional {@code bank:} value hint, below,
 * is the one exception, and it is a separate key). It does two things only:
 * <ol>
 * <li>{@link #materialize} makes the address analyzable -- disassembles it if no instruction is
 * present and, for {@code entry: true}, creates a function there -- using the same
 * {@code DisassembleCommand}/{@code CreateFunctionCmd} idiom cross-bank flow targets use;</li>
 * <li>{@link #seedAddresses} hands the address to {@link BankDataflowEngine}, which adds it to
 * the same fallback seed set as unreached function entries. The site's own
 * {@code computeSwitch} then decides: a hint at an address that is not a switch store annotates
 * nothing.</li>
 * </ol>
 * Both halves read the hint from the program property the loader published, so a re-analysis
 * (or a descriptor that arrives after import) picks it up, and {@link #materialize} is
 * idempotent: it touches only what is still missing.
 * <p>
 * <b>The optional {@code bank:} VALUE hint</b> (bead grm-hb6.20, design section 6.3 as amended by
 * the owner's 2026-10-18 rulings) is the one place a descriptor states a result rather than a
 * place. {@link #valueHints} hands the engine the hinted addresses and values; the ENGINE applies
 * a valid one at its site in preference to anything it recovered (a per-game hint wins over
 * autodetection and is relied upon), and records a {@link HintNote} per hinted site saying
 * whether it was applied, why not, and what dataflow would have said. {@link #reportValueHints}
 * turns those notes into WARNING bookmarks. A hint is valid at a direct latch store a strategy
 * recognizes and that commits a single bank field (on a multi-field mechanism, the one field that
 * store deposits -- grm-hb6.22), or at a call to a recognized bank-switch helper whose deposit is
 * a single field;
 * validity is cheap self-consistency only (the value fits the field and the window can hold the
 * bank), never a re-run of the analysis.
 */
final class SwitchSiteHints {

	/** Bookmark category marking a site that was seeded from a descriptor, not discovered. */
	static final String BOOKMARK_CATEGORY = "Game descriptor switch site";

	/** Bookmark category of the WARNINGs a {@code bank:} value hint raises (grm-hb6.20). */
	static final String VALUE_HINT_CATEGORY = "Game descriptor bank hint";

	/** End-of-line comment suffix marking a bank value that came from a descriptor hint. */
	static final String HINT_COMMENT_SUFFIX = " (game descriptor hint)";

	/**
	 * One {@code switch_sites[]} entry; {@code block}, {@code comment} and {@code bank} may be null.
	 */
	record Site(long addr, String block, boolean entry, String comment, String provenance,
			Integer bank) {
	}

	/**
	 * What the engine did with one {@code bank:} hint at its final evaluation of the site
	 * (grm-hb6.20). {@code applied} false means the hint was NOT used and {@code problem} says why;
	 * {@code recovered} is non-null only for an applied hint that dataflow DISAGREED with, and
	 * renders the value(s) dataflow had recovered. {@code honestDetail} (shadow_commits,
	 * bead grm-wayn) is non-null when the call was reclassified as a relay of its function's inbound
	 * argument and carries the NOTE text.
	 */
	record HintNote(int bank, boolean applied, String problem, String recovered,
			String honestDetail) {

		/** A note with no relay classification (every {@code bank:} hint's). */
		HintNote(int bank, boolean applied, String problem, String recovered) {
			this(bank, applied, problem, recovered, null);
		}
	}

	private SwitchSiteHints() {
	}

	/** The recorded hint's source path, or null when absent/unreadable. */
	static String source(Program program) {
		return BankingHintKind.SWITCH_SITES.source(program);
	}

	/**
	 * The recorded sites, or empty. A malformed property is reported through {@code problems} and
	 * contributes nothing -- a hint that cannot be read is a hint that is not applied.
	 */
	static List<Site> parse(Program program, List<String> problems) {
		return BankingHintKind.SWITCH_SITES.readOrEmpty(program, problems,
			(o, root) -> new Site(o.get("addr").getAsLong(),
				o.has("block") ? o.get("block").getAsString() : null,
				o.has("entry") && o.get("entry").getAsBoolean(),
				o.has("comment") ? o.get("comment").getAsString() : null,
				o.get("provenance").getAsString(),
				o.has("bank") ? Integer.valueOf(o.get("bank").getAsInt()) : null));
	}

	/** {@code site}'s address in this program (block qualifier as for {@code symbols:}), or null. */
	static Address resolve(Program program, Site site) {
		if (site.block() == null) {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(site.addr());
		}
		return DescriptorApply.blockAddress(program, site.block(), site.addr());
	}

	/**
	 * Makes every hinted address analyzable and records that the descriptor, not analysis,
	 * named it. Idempotent. An address that cannot be resolved, or that is interior to an
	 * existing instruction, or that fails to disassemble, is logged with its reason and skipped.
	 * Must run inside a transaction (the analyzer's, or a test's).
	 *
	 * @return the addresses that now hold an instruction at their start
	 */
	static List<Address> materialize(Program program, TaskMonitor monitor, MessageLog log) {
		List<String> problems = new ArrayList<>();
		List<Site> sites = parse(program, problems);
		for (String problem : problems) {
			log.appendMsg(problem);
		}
		String source = source(program);
		Listing listing = program.getListing();
		BookmarkManager bookmarks = program.getBookmarkManager();
		List<Address> ready = new ArrayList<>();
		for (Site site : sites) {
			String what = "switch_sites hint 0x" + Long.toHexString(site.addr()) +
				(site.block() == null ? "" : " in block '" + site.block() + "'");
			Address addr = resolve(program, site);
			if (addr == null) {
				log.appendMsg(what + ": address does not resolve in this program; skipped");
				continue;
			}
			if (listing.getInstructionAt(addr) == null) {
				Instruction occupant = listing.getInstructionContaining(addr);
				if (occupant != null) {
					log.appendMsg(what + " (" + addr + "): interior to the instruction at " +
						occupant.getMinAddress() + "; not disassembling");
					continue;
				}
				new DisassembleCommand(new AddressSet(addr), null, true).applyTo(program, monitor);
				if (listing.getInstructionAt(addr) == null) {
					log.appendMsg(what + " (" + addr + "): does not disassemble; skipped");
					continue;
				}
			}
			if (site.entry() && program.getFunctionManager().getFunctionAt(addr) == null) {
				new CreateFunctionCmd(addr).applyTo(program, monitor);
			}
			String note = "switch-site hint from game descriptor " + source + ": " +
				site.provenance() + (site.comment() == null ? "" : " (" + site.comment() + ")");
			Bookmark existing = bookmarks.getBookmark(addr, BookmarkType.INFO, BOOKMARK_CATEGORY);
			if (existing == null || !note.equals(existing.getComment())) {
				bookmarks.setBookmark(addr, BookmarkType.INFO, BOOKMARK_CATEGORY, note);
			}
			ready.add(addr);
		}
		return ready;
	}

	/**
	 * The hinted addresses that currently hold an instruction at their start, for the dataflow
	 * engine's fallback seed set. Pure: resolves only, writes nothing.
	 */
	static Set<Address> seedAddresses(Program program) {
		Set<Address> out = new LinkedHashSet<>();
		Listing listing = program.getListing();
		for (Site site : parse(program, new ArrayList<>())) {
			Address addr = resolve(program, site);
			if (addr != null && listing.getInstructionAt(addr) != null) {
				out.add(addr);
			}
		}
		return out;
	}

	/**
	 * The {@code bank:} value hints, keyed by the resolved address of their site (bead grm-hb6.20).
	 * Empty -- and cheap -- when the descriptor states none, which is every shipped descriptor.
	 */
	static Map<Address, Integer> valueHints(Program program) {
		Map<Address, Integer> out = new LinkedHashMap<>();
		for (Site site : parse(program, new ArrayList<>())) {
			if (site.bank() == null) {
				continue;
			}
			Address addr = resolve(program, site);
			if (addr != null) {
				out.put(addr, site.bank());
			}
		}
		return out;
	}

	/**
	 * Raises (and retracts) the WARNING bookmarks for {@code bank:} hints, from the engine's
	 * final-pass {@code notes} (bead grm-hb6.20). One bookmark per hinted site that needs
	 * attention: a hint that was NOT applied (naming the failed check; the site fell back to
	 * dataflow), or an applied hint dataflow disagreed with (naming both values; the hint won).
	 * A hint that was applied and agrees raises nothing. Own category, so it neither displaces nor
	 * is swept with the analyzer's unknown-state warning at the same site, and write-free on a
	 * settled program (a bookmark is rewritten only when its text changed).
	 *
	 * @return the warning texts raised, for the analyzer log
	 */
	static List<String> reportValueHints(Program program, Map<Address, HintNote> notes) {
		String source = source(program);
		Map<Address, String> wanted = new LinkedHashMap<>();
		for (Map.Entry<Address, Integer> hint : valueHints(program).entrySet()) {
			Address addr = hint.getKey();
			HintNote note = notes.get(addr);
			String text = null;
			if (note == null) {
				text = "bank hint " + hint.getValue() + " from game descriptor " + source +
					" was not applied: dataflow never reached this address";
			}
			else if (!note.applied()) {
				text = "bank hint " + note.bank() + " from game descriptor " + source +
					" was not applied (" + note.problem() + "); the site falls back to the " +
					"value dataflow recovers";
			}
			else if (note.recovered() != null) {
				text = "bank hint " + note.bank() + " from game descriptor " + source +
					" WINS over the bank dataflow recovered here (" + note.recovered() +
					"); if the recovered value is right, the hint is stale";
			}
			if (text != null) {
				wanted.put(addr, text);
			}
		}
		BookmarkManager bookmarks = program.getBookmarkManager();
		List<Bookmark> stale = new ArrayList<>();
		Iterator<Bookmark> it = bookmarks.getBookmarksIterator(BookmarkType.WARNING);
		while (it.hasNext()) {
			Bookmark b = it.next();
			if (VALUE_HINT_CATEGORY.equals(b.getCategory()) && !wanted.containsKey(b.getAddress())) {
				stale.add(b);
			}
		}
		for (Bookmark b : stale) {
			bookmarks.removeBookmark(b);
		}
		for (Map.Entry<Address, String> w : wanted.entrySet()) {
			Bookmark existing =
				bookmarks.getBookmark(w.getKey(), BookmarkType.WARNING, VALUE_HINT_CATEGORY);
			if (existing == null || !w.getValue().equals(existing.getComment())) {
				bookmarks.setBookmark(w.getKey(), BookmarkType.WARNING, VALUE_HINT_CATEGORY,
					w.getValue());
			}
		}
		return new ArrayList<>(wanted.values());
	}
}
