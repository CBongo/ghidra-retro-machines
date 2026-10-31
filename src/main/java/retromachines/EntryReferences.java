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

import java.util.Collection;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * grm-gipk.16.7: does Ghidra already have a reference or a label at a table's next entry position?
 * When reverse-engineering by hand that is the usual cue that a table has ended: another table
 * follows (its dispatcher's {@code LDA tbl,X} operand made a DATA/READ reference there), or the
 * position is code something else targets.
 *
 * <p>The evidence is only worth anything if it is not the table's own. A reference qualifies when
 * its source
 * <ul>
 * <li>is OUTSIDE the table's possible extent ({@link Extent}) -- that covers our own layWords
 * references and any over-read of the table, which are all sourced inside it;</li>
 * <li>is not one of the owning dispatch's own instructions ({@code own}: the load(s), jump, call
 * or return of this dispatch, whose operand references point into the table by construction);</li>
 * <li>is not a fall-through reference (the previous instruction running on is no cue).</li>
 * </ul>
 * Such a reference is {@linkplain Hit#strong() strong}: a flow reference (code something else
 * reaches), a data/read reference from an instruction (another dispatcher's table load), or a
 * reference from a defined data pointer (another table's entry). Failing that, a non-default
 * symbol at the position is a weak hit. The caller never asks about entry 0.
 */
final class EntryReferences {

	private EntryReferences() {
	}

	/** A contiguous byte range a table could occupy: references sourced in it are its own. */
	record Extent(Address start, long length) {
		boolean contains(Address a) {
			if (!start.getAddressSpace().equals(a.getAddressSpace())) {
				return false;
			}
			long d = a.getOffset() - start.getOffset();
			return d >= 0 && d < length;
		}
	}

	/**
	 * What was found at an entry position.
	 *
	 * @param strong a qualifying reference (a hard end) rather than a bare label (soft)
	 * @param describe {@code from <source> (<kind>)}, for logs
	 */
	record Hit(boolean strong, String describe) {
	}

	/**
	 * The strongest qualifying evidence at {@code pos}, or null. Of several references the one with
	 * the lowest source address is reported, so the answer does not depend on iteration order.
	 */
	static Hit find(Program program, Address pos, Collection<Extent> extents,
			Collection<Address> own) {
		Reference best = null;
		for (Reference ref : program.getReferenceManager().getReferencesTo(pos)) {
			Address from = ref.getFromAddress();
			if (!from.isMemoryAddress() || ref.getReferenceType().isFallthrough() ||
				own.contains(from) || inAny(extents, from)) {
				continue;
			}
			if (best == null || from.compareTo(best.getFromAddress()) < 0) {
				best = ref;
			}
		}
		if (best != null) {
			return new Hit(true, "from " + best.getFromAddress() + " (" +
				best.getReferenceType().getName() + ", " + best.getSource() + ")");
		}
		for (Symbol s : program.getSymbolTable().getSymbols(pos)) {
			if (s.getSource() != SourceType.DEFAULT) {
				return new Hit(false, "from " + pos + " (label " + s.getName() + ")");
			}
		}
		return null;
	}

	private static boolean inAny(Collection<Extent> extents, Address a) {
		for (Extent e : extents) {
			if (e.contains(a)) {
				return true;
			}
		}
		return false;
	}
}
