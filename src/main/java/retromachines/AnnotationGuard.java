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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

/**
 * Enforces the never-overwrite-user-work rule stated in
 * {@code docs/per-game-descriptors-design.md} 3c.3:
 *
 * <blockquote>Descriptor-applied and analyzer-applied annotations go in as {@code IMPORTED} or
 * {@code ANALYSIS}, never {@code USER_DEFINED}, and never overwrite an existing
 * {@code USER_DEFINED} symbol, comment or reference.</blockquote>
 *
 * <p>
 * This class is the one shared place both loaders ({@link DescriptorSupport}) and analyzers
 * ({@code BoardBankAnalyzer}) route through to honour that rule, so it lives outside
 * {@link DescriptorSupport} (which is descriptor-specific) rather than inside it.
 *
 * <h2>Symbols and references: {@code SourceType} is load-bearing</h2>
 * Ghidra symbols and references carry a real {@link SourceType}, and a user-created label or
 * reference is tagged {@link SourceType#USER_DEFINED}. That makes the symbol/reference half of
 * the rule a straightforward precondition check: before this class writes a label or a reference,
 * it asks whether a {@code USER_DEFINED} one already occupies the address, and declines if so.
 *
 * <h2>Comments: no {@code SourceType}, so a proxy is required</h2>
 * Ghidra comments carry <em>no</em> {@link SourceType} at all -- a {@link Listing} comment is
 * just a string, with no record of who wrote it or when. "Never overwrite a {@code USER_DEFINED}
 * comment" therefore cannot be implemented literally; there is nothing on a comment to test.
 * <p>
 * The defensible proxy already existed in this codebase, proven out at
 * {@code BoardBankAnalyzer.annotateBankSwitch} (formerly inlined at what is now
 * {@code BoardBankAnalyzer.java:3184-3190}) and its sibling
 * {@code BoardBankAnalyzer.annotatePlacementProvenance}: <b>never replace a non-empty comment,
 * only append to it.</b> An append can never destroy user text -- whatever was there survives,
 * verbatim, as a substring of the result. A replace can, silently, the moment the existing text
 * happens to be something a human typed rather than something an analyzer generated. Append is
 * therefore the only direction that is sound without knowing who wrote the existing comment, which
 * is exactly the information comments do not carry.
 * <p>
 * {@link #addComment} generalises that proven idiom, replacing the hardcoded {@code "bank ->"}
 * idempotence key from the original call sites with a caller-supplied {@code marker}: a
 * substring whose presence in the existing comment means "an annotation of this kind is already
 * here, do not stack another one." Without a marker, re-running an analyzer (or reapplying a
 * descriptor) would append a duplicate of the same annotation on every pass; the marker makes the
 * operation idempotent the same way {@link #applyLabel} is idempotent for symbols.
 */
final class AnnotationGuard {

	private AnnotationGuard() {
	}

	/**
	 * True unless the primary symbol at {@code addr} is {@code USER_DEFINED} -- i.e. true iff a
	 * descriptor or analyzer may place a label, or attach a reference, at this address without
	 * risking displacing something a human typed or clicked into place.
	 */
	static boolean mayWrite(Program program, Address addr) {
		Symbol primary = program.getSymbolTable().getPrimarySymbol(addr);
		return primary == null || primary.getSource() != SourceType.USER_DEFINED;
	}

	/**
	 * Guarded, idempotent {@link SymbolTable#createLabel}: creates {@code name} at {@code addr}
	 * with the given (non-{@code USER_DEFINED}) {@code source} unless a {@code USER_DEFINED}
	 * symbol already sits there, in which case it declines and reports {@code false}.
	 * <p>
	 * Idempotent by construction: if a symbol named exactly {@code name} already exists at
	 * {@code addr} -- whatever its source -- this is a no-op that reports success, so re-running a
	 * descriptor apply or an analyzer pass over the same program does not churn the symbol table
	 * or trip over {@code DuplicateNameException}.
	 *
	 * @return whether {@code name} is present at {@code addr} after this call (whether this call
	 *         created it, it was already there, or writing was declined because of an existing
	 *         {@code USER_DEFINED} symbol -- the last case reports {@code false})
	 */
	static boolean applyLabel(Program program, Address addr, String name, SourceType source)
			throws InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		for (Symbol existing : symbolTable.getSymbols(addr)) {
			if (existing.getName().equals(name)) {
				return true;
			}
		}
		if (!mayWrite(program, addr)) {
			return false;
		}
		symbolTable.createLabel(addr, name, source);
		return true;
	}

	/**
	 * True unless {@code ref} is {@code USER_DEFINED} -- the reference-side counterpart of
	 * {@link #mayWrite(Program, Address)}, for call sites that dedup against an existing reference
	 * rather than an existing symbol before deciding whether to add or reuse one.
	 */
	static boolean mayDisplace(Reference ref) {
		return ref == null || ref.getSource() != SourceType.USER_DEFINED;
	}

	/**
	 * Guarded append-only comment write, generalising the proven
	 * "never replace, only append" idiom (see class javadoc) with a caller-supplied
	 * {@code marker} standing in for the analyzer's hardcoded {@code "bank ->"}.
	 * <ul>
	 * <li>No existing comment, or an existing comment that is blank: {@code text} is set
	 * directly.</li>
	 * <li>A non-empty existing comment that does not already contain {@code marker}: {@code text}
	 * is appended (separated by {@code "; "}), so whatever was there -- analyzer-written or
	 * user-written -- survives verbatim.</li>
	 * <li>A non-empty existing comment that already contains {@code marker}: no-op, so repeated
	 * calls (e.g. re-running an analyzer) do not stack duplicate annotations.</li>
	 * </ul>
	 */
	static void addComment(Listing listing, Address addr, CommentType type, String text,
			String marker) {
		String existing = listing.getComment(type, addr);
		if (existing == null || existing.isBlank()) {
			listing.setComment(addr, type, text);
		}
		else if (!existing.contains(marker)) {
			listing.setComment(addr, type, existing + "; " + text);
		}
	}
}
