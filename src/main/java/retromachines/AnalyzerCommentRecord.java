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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/**
 * The exact comment text an EXTENSION analyzer or loader wrote at an address, per
 * {@link CommentType} (bead grm-hb6.18) -- the general counterpart of
 * {@link BankCommentProvenance}, which does the same for the bank annotator's EOL comments.
 *
 * <p>Ghidra comments carry no {@code SourceType}, so "a human wrote this" cannot be read off the
 * comment. {@code GameDescriptorExporter} used to guess by text prefix, which both dropped a
 * human's own {@code bank -> 5} and leaked every extension writer whose text did not start with
 * the two known prefixes. Recording the exact written text makes the exporter's removal an exact
 * segment match instead (see {@link BankCommentProvenance}'s javadoc for why prefix matching is
 * wrong).
 *
 * <p>One user-property map per comment type, named
 * {@code "Retro Machines.Analyzer Comment <TYPE>"}. Each address holds the segments written
 * there, joined by {@link #SEPARATOR} (U+001F, which cannot plausibly occur in comment text).
 *
 * <p><b>Write-freedom:</b> nothing is recorded unless the listing was actually changed, and
 * {@link #set} declines to rewrite an identical comment, so a settled re-run mutates nothing
 * here (BoardBankAnalyzer's modification-number gate depends on that).
 *
 * <p>Descriptor-applied symbol comments ({@code DescriptorSupport}) are deliberately NOT routed
 * through here: they came from a game descriptor, and re-exporting them is a correct round trip.
 */
final class AnalyzerCommentRecord {

	/** Prefix of the per-type map names; the type name is appended. */
	static final String PROPERTY_MAP_PREFIX = "Retro Machines.Analyzer Comment ";

	/** Joins several recorded segments at one address. */
	static final char SEPARATOR = '\u001f';

	private final StringPropertyMap map;

	private AnalyzerCommentRecord(StringPropertyMap map) {
		this.map = map;
	}

	static String mapName(CommentType type) {
		return PROPERTY_MAP_PREFIX + type.name();
	}

	/**
	 * Opens (creating if absent) the record for {@code type}, or null when the map name is taken
	 * by a map of another value type. Null must degrade to unrecorded writes, never fail analysis.
	 */
	static AnalyzerCommentRecord open(Program program, CommentType type) {
		var mgr = program.getUsrPropertyManager();
		StringPropertyMap existing = mgr.getStringPropertyMap(mapName(type));
		if (existing != null) {
			return new AnalyzerCommentRecord(existing);
		}
		try {
			return new AnalyzerCommentRecord(mgr.createStringPropertyMap(mapName(type)));
		}
		catch (DuplicateNameException e) {
			return null;
		}
	}

	/** Creates the maps for every comment type; lets "no record map" mean "predates provenance". */
	static void openAll(Program program) {
		for (CommentType t : CommentType.values()) {
			open(program, t);
		}
	}

	/** True when the program has any analyzer-comment record map (any type). */
	static boolean hasAnyMap(Program program) {
		for (CommentType t : CommentType.values()) {
			if (program.getUsrPropertyManager().getStringPropertyMap(mapName(t)) != null) {
				return true;
			}
		}
		return false;
	}

	/** The segments recorded at {@code addr} for {@code type}; never creates a map. */
	static List<String> recorded(Program program, Address addr, CommentType type) {
		List<String> out = new ArrayList<>();
		StringPropertyMap m = program.getUsrPropertyManager().getStringPropertyMap(mapName(type));
		String raw = m == null ? null : m.getString(addr);
		if (raw != null) {
			for (String s : raw.split(String.valueOf(SEPARATOR))) {
				if (!s.isEmpty()) {
					out.add(s);
				}
			}
		}
		return out;
	}

	/**
	 * {@link AnnotationGuard#addComment} plus a record of {@code text} when (and only when) it
	 * wrote. Returns whether the listing was written.
	 */
	static boolean append(Program program, Address addr, CommentType type, String text,
			String... markers) {
		Listing listing = program.getListing();
		boolean wrote = AnnotationGuard.addComment(listing, addr, type, text, markers);
		if (wrote) {
			AnalyzerCommentRecord rec = open(program, type);
			if (rec != null) {
				rec.add(addr, text);
			}
		}
		return wrote;
	}

	/**
	 * Replacing write (for writers that always overwrote): sets {@code text} unless the comment
	 * already reads exactly that, and records it as the SOLE segment (the previous comment, and
	 * whatever was recorded for it, is gone). Returns whether the listing was written.
	 */
	static boolean set(Program program, Address addr, CommentType type, String text) {
		Listing listing = program.getListing();
		if (text.equals(listing.getComment(type, addr))) {
			return false;
		}
		listing.setComment(addr, type, text);
		AnalyzerCommentRecord rec = open(program, type);
		if (rec != null) {
			rec.map.add(addr, text);
		}
		return true;
	}

	/**
	 * Replace-own-text write (bead grm-hb6.25), for a writer that refreshes its OWN earlier
	 * comment on re-run but must never clobber anyone else's: neither {@link #set} (clobbers) nor
	 * {@link #append} (stacks a second copy beside the stale one) fits. Its own text is the
	 * recorded segment carrying {@code ownPrefix}; that segment is replaced in place, so a human's
	 * text added beside it survives. See {@link #planReplace} for the rule.
	 *
	 * @return whether the address now carries this writer's {@code text} -- written now, or
	 *         already there; false means a foreign comment was left alone
	 */
	static boolean replaceOwn(Program program, Address addr, CommentType type, String text,
			String ownPrefix) {
		Listing listing = program.getListing();
		String existing = listing.getComment(type, addr);
		List<String> recorded = recorded(program, addr, type);
		String comment = planReplace(recorded, existing, text, ownPrefix);
		boolean settled = text.equals(existing) ||
			recorded.contains(text) && BankCommentProvenance.containsSegment(existing, text);
		if (comment == null && !settled) {
			return false;
		}
		if (comment != null) {
			listing.setComment(addr, type, comment);
		}
		if (comment != null || !recorded.contains(text)) {
			// A settled legacy comment gets recorded once, then re-runs are write-free.
			AnalyzerCommentRecord rec = open(program, type);
			if (rec != null) {
				rec.replaceOwnRecord(addr, recorded, text, ownPrefix);
			}
		}
		return true;
	}

	/**
	 * The comment {@link #replaceOwn} should install, or null for "leave the listing alone"
	 * (settled, or a foreign comment). Pure, like {@link BankCommentProvenance#plan}:
	 * <ul>
	 * <li>no comment: write {@code text};
	 * <li>a recorded segment carrying {@code ownPrefix} is present as a whole segment: replace it
	 * in place, or nothing if it already reads {@code text};
	 * <li>no own segment is recorded and the WHOLE comment starts with {@code ownPrefix}: a
	 * comment from before provenance was recorded -- replace it, as the writer always did;
	 * <li>otherwise -- foreign text, or our recorded text was edited away: touch nothing.
	 * </ul>
	 */
	static String planReplace(List<String> recorded, String existing, String text,
			String ownPrefix) {
		if (existing == null || existing.isBlank()) {
			return text;
		}
		boolean ownRecorded = false;
		for (String own : recorded) {
			if (!own.startsWith(ownPrefix)) {
				continue;
			}
			ownRecorded = true;
			String replaced = BankCommentProvenance.replaceSegment(existing, own, text);
			if (replaced != null) {
				return replaced.equals(existing) ? null : replaced;
			}
		}
		if (!ownRecorded && existing.startsWith(ownPrefix) && !existing.equals(text)) {
			return text;
		}
		return null;
	}

	/** Records {@code text} in place of every recorded segment carrying {@code ownPrefix}. */
	private void replaceOwnRecord(Address addr, List<String> recorded, String text,
			String ownPrefix) {
		StringBuilder sb = new StringBuilder();
		for (String s : recorded) {
			if (!s.startsWith(ownPrefix)) {
				sb.append(s).append(SEPARATOR);
			}
		}
		map.add(addr, sb.append(text).toString());
	}

	private void add(Address addr, String text) {
		String raw = map.getString(addr);
		if (raw == null || raw.isEmpty()) {
			map.add(addr, text);
		}
		else {
			for (String s : raw.split(String.valueOf(SEPARATOR))) {
				if (s.equals(text)) {
					return;
				}
			}
			map.add(addr, raw + SEPARATOR + text);
		}
	}
}
