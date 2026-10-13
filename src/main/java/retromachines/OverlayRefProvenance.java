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
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/**
 * The analyzer's record of which OVERLAY references {@code BankAnnotationAdapter.retargetReferences}
 * placed out of each instruction (bead grm-if81) -- the reference twin of
 * {@link BankCommentProvenance} (grm-3mg0) and of the bookmark sweep (grm-mej.26), so a later
 * analysis round can retract a reference an earlier round derived from a state it no longer
 * holds.
 *
 * <h2>The defect</h2>
 * {@code retargetReferences} is additive across rounds. The analyzer re-runs to a whole-program
 * fixpoint, and an early round can resolve a site against an incomplete program: nesintrawintest's
 * first round runs before the overlay callee {@code PRG_LO_B2::8010} is a function, so helper
 * resolution falls back to base (a bank-1 helper) and {@code PRG_LO_B1} references land at
 * {@code 8008}/{@code 800b}. Round two correctly concludes bank 2 and adds {@code PRG_LO_B2}
 * references -- alongside the stale bank-1 ones, which nothing ever removed. The final listing
 * then depends on the SEQUENCE of rounds rather than on the final program state, the same defect
 * grm-3mg0 fixed for comments.
 *
 * <h2>Why a record, not "every overlay reference we did not place this round"</h2>
 * Not every overlay reference out of an instruction is this pass's. {@code TransferMaterializer}
 * places flow references into overlays from the same instructions, and a user may add one by
 * hand. Retracting by shape would delete theirs. So ownership is recorded: a reference is ours
 * if this pass CREATED it, or created it in an earlier round and has confirmed it since. A
 * reference this pass merely found already present ({@link Placements#confirm}) and never
 * recorded is someone else's, and is never retracted -- confirming it does not adopt it.
 *
 * <h2>Restoring the base reference</h2>
 * grm-bfb retires the stock base-space reference once every live state resolved the access to
 * a non-home occupant. If a later round retracts the overlay reference that replaced it, and
 * nothing else from that operand still reaches that physical offset, the access would vanish
 * from the reference graph entirely -- and that graph is this project's control-flow graph (see
 * the {@code references-are-the-flow-graph} memory). So retraction RESTORES a base-space
 * reference in that case: the state that justified retiring it no longer holds, and base space
 * is what a stock analysis would say. A round that resolves the access to the home occupant is
 * the common way to get there.
 *
 * <h2>Write-freedom</h2>
 * As for {@link BankCommentProvenance}: a round that places exactly what was recorded performs no
 * write at all, so the analyzer's redundant-re-run gate keeps hitting on a settled program.
 */
final class OverlayRefProvenance {

	/** The user-property-map name, namespaced like {@link BankCommentProvenance#PROPERTY_MAP}. */
	static final String PROPERTY_MAP = "Retro Machines.Overlay Reference";

	/** Separates the encoded entries of one instruction's record. */
	private static final String ENTRY_SEP = ",";

	/** Separates the fields of one encoded entry; overlay space names never contain it. */
	private static final String FIELD_SEP = "|";

	/**
	 * One overlay reference out of an instruction: operand index, overlay space name and target
	 * offset. The reference type is deliberately not part of the identity, for the reason
	 * {@code BaseRefKey} gives -- the read-modify-write split re-types references.
	 */
	record Placed(int opIndex, String space, long offset) {

		static final Comparator<Placed> ORDER = Comparator.comparingInt(Placed::opIndex)
				.thenComparing(Placed::space)
				.thenComparingLong(Placed::offset);

		String encode() {
			return opIndex + FIELD_SEP + space + FIELD_SEP + Long.toHexString(offset);
		}

		/** The decoded entry, or null for a malformed one (which is then simply dropped). */
		static Placed decode(String s) {
			String[] f = s.split("\\" + FIELD_SEP, -1);
			if (f.length != 3 || f[1].isEmpty()) {
				return null;
			}
			try {
				return new Placed(Integer.parseInt(f[0]), f[1], Long.parseLong(f[2], 16));
			}
			catch (NumberFormatException e) {
				return null;
			}
		}
	}

	/**
	 * What one instruction's retargeting did this round: references it {@link #create}d, and
	 * references it found already present and {@link #confirm}ed. Kept apart because only the
	 * first kind establishes ownership.
	 */
	static final class Placements {
		private final Set<Placed> created = new TreeSet<>(Placed.ORDER);
		private final Set<Placed> confirmed = new TreeSet<>(Placed.ORDER);

		void create(Placed p) {
			created.add(p);
		}

		void confirm(Placed p) {
			confirmed.add(p);
		}

		/** Whether this round placed or confirmed {@code p} in any way. */
		boolean placed(Placed p) {
			return created.contains(p) || confirmed.contains(p);
		}
	}

	private final Program program;
	private final StringPropertyMap map;

	/** Instructions this round settled; {@link #sweep} retracts the record of every other one. */
	private final Set<Address> touched = new LinkedHashSet<>();

	private OverlayRefProvenance(Program program, StringPropertyMap map) {
		this.program = program;
		this.map = map;
	}

	/**
	 * Opens (creating if absent) this program's record, or null when a map of that name exists
	 * with a different value type. A null result degrades to the old additive behaviour rather
	 * than failing analysis, exactly as {@link BankCommentProvenance#open} does.
	 */
	static OverlayRefProvenance open(Program program) {
		StringPropertyMap existing =
			program.getUsrPropertyManager().getStringPropertyMap(PROPERTY_MAP);
		if (existing != null) {
			return new OverlayRefProvenance(program, existing);
		}
		try {
			return new OverlayRefProvenance(program,
				program.getUsrPropertyManager().createStringPropertyMap(PROPERTY_MAP));
		}
		catch (DuplicateNameException e) {
			return null;
		}
	}

	// ------------------------------------------------------------------
	// The rule, as pure functions over sets (exercised directly by OverlayRefProvenanceTest)
	// ------------------------------------------------------------------

	/** Recorded references this round neither created nor confirmed: the ones to retract. */
	static Set<Placed> stale(Set<Placed> recorded, Placements now) {
		Set<Placed> out = new TreeSet<>(Placed.ORDER);
		for (Placed p : recorded) {
			if (!now.placed(p)) {
				out.add(p);
			}
		}
		return out;
	}

	/**
	 * The record after this round: everything it created, plus what it confirmed that was
	 * already ours. A confirmed reference that was never recorded stays unowned.
	 */
	static Set<Placed> owned(Set<Placed> recorded, Placements now) {
		Set<Placed> out = new TreeSet<>(Placed.ORDER);
		out.addAll(now.created);
		for (Placed p : now.confirmed) {
			if (recorded.contains(p)) {
				out.add(p);
			}
		}
		return out;
	}

	static String encode(Set<Placed> entries) {
		List<String> parts = new ArrayList<>();
		for (Placed p : entries) {
			parts.add(p.encode());
		}
		return String.join(ENTRY_SEP, parts);
	}

	static Set<Placed> decode(String s) {
		Set<Placed> out = new TreeSet<>(Placed.ORDER);
		if (s == null || s.isEmpty()) {
			return out;
		}
		for (String part : s.split(ENTRY_SEP)) {
			Placed p = Placed.decode(part);
			if (p != null) {
				out.add(p);
			}
		}
		return out;
	}

	// ------------------------------------------------------------------
	// Applying it
	// ------------------------------------------------------------------

	/**
	 * Settles {@code instr} after this round's retargeting placed {@code now}: retracts every
	 * recorded reference the round did not place (restoring a base-space reference where that
	 * leaves the access with none -- see the class javadoc), and updates the record. Returns how
	 * many references were retracted. Writes nothing when the record already matches.
	 */
	int settle(ReferenceManager refMgr, Instruction instr, AddressSpace baseSpace, Placements now) {
		Address from = instr.getMinAddress();
		touched.add(from);
		Set<Placed> recorded = decode(map.getString(from));
		int retracted = retract(refMgr, from, baseSpace, stale(recorded, now));
		Set<Placed> owned = owned(recorded, now);
		if (!owned.equals(recorded)) {
			if (owned.isEmpty()) {
				map.remove(from);
			}
			else {
				map.add(from, encode(owned));
			}
		}
		return retracted;
	}

	/**
	 * Retracts the whole record of every instruction this round did NOT settle -- it left the
	 * tracked flow, so nothing this round derived supports its references -- and forgets
	 * records whose instruction no longer exists (clearing code removed its references with it).
	 * Call once, after every instruction of the round has been settled. Returns the addresses
	 * at which at least one reference was retracted.
	 */
	List<Address> sweep(ReferenceManager refMgr, AddressSpace baseSpace) {
		List<Address> stale = new ArrayList<>();
		AddressIterator it = map.getPropertyIterator();
		while (it.hasNext()) {
			Address addr = it.next();
			if (!touched.contains(addr)) {
				stale.add(addr);
			}
		}
		List<Address> retractedAt = new ArrayList<>();
		for (Address addr : stale) {
			Instruction instr = program.getListing().getInstructionAt(addr);
			if (instr != null &&
				retract(refMgr, addr, baseSpace, decode(map.getString(addr))) > 0) {
				retractedAt.add(addr);
			}
			map.remove(addr);
		}
		return retractedAt;
	}

	/**
	 * Deletes each of {@code entries} that still exists out of {@code from} and may be displaced,
	 * then restores a base-space reference for every (operand, offset) the deletions left with
	 * no reference into base space or any of its overlays. An entry whose reference is already
	 * gone -- a human deleted it -- is skipped, and restores nothing: the absence is theirs.
	 */
	private int retract(ReferenceManager refMgr, Address from, AddressSpace baseSpace,
			Set<Placed> entries) {
		// (opIndex, offset) -> the combined type of the references deleted there, for the restore.
		Map<List<Long>, RefType> deletedAt = new LinkedHashMap<>();
		int retracted = 0;
		for (Placed p : entries) {
			AddressSpace space = program.getAddressFactory().getAddressSpace(p.space());
			if (space == null) {
				continue;
			}
			Address to = space.getAddress(p.offset());
			Reference ref = null;
			for (Reference r : refMgr.getReferencesFrom(from, p.opIndex())) {
				if (r.getToAddress().equals(to)) {
					ref = r;
					break;
				}
			}
			if (ref == null || !AnnotationGuard.mayDisplace(ref)) {
				continue;
			}
			deletedAt.merge(List.of((long) p.opIndex(), p.offset()), ref.getReferenceType(),
				OverlayRefProvenance::combine);
			refMgr.delete(ref);
			retracted++;
		}
		for (Map.Entry<List<Long>, RefType> e : deletedAt.entrySet()) {
			int opIndex = e.getKey().get(0).intValue();
			long offset = e.getKey().get(1);
			if (reachesOffset(refMgr, from, opIndex, baseSpace, offset)) {
				continue;
			}
			Reference restored = refMgr.addMemoryReference(from, baseSpace.getAddress(offset),
				e.getValue(), SourceType.ANALYSIS, opIndex);
			if (refMgr.getPrimaryReferenceFrom(from, opIndex) == null) {
				refMgr.setPrimary(restored, true);
			}
		}
		return retracted;
	}

	/** Whether any reference out of {@code from}'s operand reaches {@code offset} in base space
	 *  or one of its overlays. */
	private static boolean reachesOffset(ReferenceManager refMgr, Address from, int opIndex,
			AddressSpace baseSpace, long offset) {
		for (Reference r : refMgr.getReferencesFrom(from, opIndex)) {
			Address to = r.getToAddress();
			AddressSpace space = to.getAddressSpace();
			boolean banked = space.equals(baseSpace) ||
				(space.isOverlaySpace() && baseSpace.equals(space.getPhysicalSpace()));
			if (banked && to.getOffset() == offset) {
				return true;
			}
		}
		return false;
	}

	/** The type a restored base reference takes when a split read-modify-write is retracted. */
	private static RefType combine(RefType a, RefType b) {
		boolean read = a.isRead() || b.isRead();
		boolean write = a.isWrite() || b.isWrite();
		if (read && write && !a.isFlow() && !b.isFlow()) {
			return RefType.READ_WRITE;
		}
		return a;
	}
}
