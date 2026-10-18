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
import java.util.LinkedHashSet;
import java.util.List;
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
 * produces a {@code SwitchResult} or an annotation. It does two things only:
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
 */
final class SwitchSiteHints {

	/** Bookmark category marking a site that was seeded from a descriptor, not discovered. */
	static final String BOOKMARK_CATEGORY = "Game descriptor switch site";

	/** One {@code switch_sites[]} entry; {@code block} and {@code comment} may be null. */
	record Site(long addr, String block, boolean entry, String comment, String provenance) {
	}

	private SwitchSiteHints() {
	}

	/** The recorded hint's source path, or null when absent/unreadable. */
	private static String source(Program program) {
		String spec = DescriptorSupport.programInfoString(program,
			DescriptorSupport.SWITCH_SITES_PROPERTY);
		if (spec == null || spec.isBlank()) {
			return null;
		}
		try {
			JsonObject root = JsonParser.parseString(spec).getAsJsonObject();
			return root.has("source") ? root.get("source").getAsString() : "";
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	/**
	 * The recorded sites, or empty. A malformed property is reported through {@code problems} and
	 * contributes nothing -- a hint that cannot be read is a hint that is not applied.
	 */
	static List<Site> parse(Program program, List<String> problems) {
		String spec = DescriptorSupport.programInfoString(program,
			DescriptorSupport.SWITCH_SITES_PROPERTY);
		List<Site> sites = new ArrayList<>();
		if (spec == null || spec.isBlank()) {
			return sites;
		}
		try {
			JsonObject root = JsonParser.parseString(spec).getAsJsonObject();
			for (JsonElement el : root.getAsJsonArray("sites")) {
				JsonObject o = el.getAsJsonObject();
				sites.add(new Site(o.get("addr").getAsLong(),
					o.has("block") ? o.get("block").getAsString() : null,
					o.has("entry") && o.get("entry").getAsBoolean(),
					o.has("comment") ? o.get("comment").getAsString() : null,
					o.get("provenance").getAsString()));
			}
		}
		catch (RuntimeException e) {
			problems.add(DescriptorSupport.SWITCH_SITES_PROPERTY + " is malformed (" +
				e.getMessage() + "); no switch_sites hint applied");
			return List.of();
		}
		return sites;
	}

	/** {@code site}'s address in this program (block qualifier as for {@code symbols:}), or null. */
	static Address resolve(Program program, Site site) {
		if (site.block() == null) {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(site.addr());
		}
		return DescriptorSupport.blockAddress(program, site.block(), site.addr());
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
}
