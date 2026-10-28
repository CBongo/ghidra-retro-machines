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

import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

/**
 * grm-deve: lays a bounded jump table as a {@code word[n]} array whose every entry carries a
 * {@link RefType#DATA} reference to its case target, replacing the byte array stock
 * {@code DecompilerSwitchAnalysisCmd.labelLoadTable} lays by the decompiler's load size (over its
 * own over-read length). The element type is deliberately a word, not a pointer: pointer data
 * resolves in the pointer's own space, which breaks cross-bank and RTS-trick tables; the explicit
 * reference carries the case's own {@link Address}, overlay space included.
 *
 * <p>Only ever called with kept entries, after the bound landed: a reference to an over-read
 * target would count as an incoming reference and stop the grm-vrkk.11 retraction clearing that
 * junk code. Clears data only, never instructions. The per-entry reference sources are all
 * {@link SourceType#ANALYSIS}, which is also how a previous array of ours is recognised.
 */
final class JumpTableArrays {

	private JumpTableArrays() {}

	/** Whether {@code start} already holds exactly the array {@link #layWords} would lay. */
	static boolean isLaid(Program program, Address start, List<Address> targets) {
		Data d = program.getListing().getDefinedDataAt(start);
		if (d == null || !isWordArray(d.getDataType()) ||
			((Array) d.getDataType()).getNumElements() != targets.size()) {
			return false;
		}
		for (int i = 0; i < targets.size(); i++) {
			if (!hasRef(program, start.add(2L * i), targets.get(i))) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Removes a previous array of ours at {@code start} (a word array whose first entry carries an
	 * {@code ANALYSIS} data reference), its references first. Done before a re-bound so the old
	 * entries' references cannot shield stale targets from the retraction. Returns whether it did.
	 */
	static boolean unlay(Program program, Address start) {
		Listing listing = program.getListing();
		Data d = listing.getDefinedDataAt(start);
		if (d == null || !isWordArray(d.getDataType()) || !hasAnyRef(program, start)) {
			return false;
		}
		removeAnalysisDataRefs(program, new AddressSet(d.getMinAddress(), d.getMaxAddress()));
		listing.clearCodeUnits(d.getMinAddress(), d.getMaxAddress(), false);
		return true;
	}

	/**
	 * Lays {@code word[targets.size()]} at {@code start} and one data reference per entry. Clears
	 * stock's byte array at {@code start} (the whole of it, so its over-read tail goes too) and any
	 * undefined or byte data in the extent. Declines, changing nothing, when an instruction or any
	 * other defined data overlaps the extent, or the extent is not addressable. Returns whether the
	 * array was laid.
	 */
	static boolean layWords(Program program, Address start, List<Address> targets) {
		int n = targets.size();
		if (!layRuns(program, List.of(new Run(start, n, 2, WordDataType.dataType)))) {
			return false;
		}
		ReferenceManager refs = program.getReferenceManager();
		for (int i = 0; i < n; i++) {
			refs.addMemoryReference(start.add(2L * i), targets.get(i), RefType.DATA,
				SourceType.ANALYSIS, 0);
		}
		return true;
	}

	/**
	 * grm-d3tu: whether {@code lo} and {@code lo+gap} already hold exactly the pair of byte arrays
	 * {@link #layPlanar} would lay, with the reference from each low-byte entry.
	 */
	static boolean isLaidPlanar(Program program, Address lo, int gap, List<Address> targets) {
		int n = targets.size();
		Address hi;
		try {
			hi = lo.add(gap);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		if (!isByteArray(program.getListing().getDefinedDataAt(lo), n) ||
			!isByteArray(program.getListing().getDefinedDataAt(hi), n)) {
			return false;
		}
		for (int i = 0; i < n; i++) {
			if (!hasRef(program, lo.add(i), targets.get(i))) {
				return false;
			}
		}
		return true;
	}

	/**
	 * grm-d3tu: lays a split lo/hi table as {@code byte[n]} at {@code lo} (low bytes) and at
	 * {@code lo+gap} (high bytes), with one data reference from each LOW entry to its case target
	 * (the high bytes carry none: an entry's target is the pair). Same constraints as
	 * {@link #layWords}, decided for both halves before anything changes; declines when the halves
	 * would overlap ({@code n > gap}). Stock's byte arrays over either half, or one merged array
	 * spanning both, are absorbed. {@code gap} may be NEGATIVE (grm-gipk.7: an RTS-trick table whose
	 * high half sits at the LOWER address, adventure_island bd50); the halves still must not overlap,
	 * {@code n <= |gap|}.
	 */
	static boolean layPlanar(Program program, Address lo, int gap, List<Address> targets) {
		int n = targets.size();
		if (gap == 0 || n < 1 || n > Math.abs(gap)) {
			return false;
		}
		Address hi;
		try {
			hi = lo.add(gap);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		if (!layRuns(program, List.of(new Run(lo, n, 1, ByteDataType.dataType),
			new Run(hi, n, 1, ByteDataType.dataType)))) {
			return false;
		}
		ReferenceManager refs = program.getReferenceManager();
		for (int i = 0; i < n; i++) {
			refs.addMemoryReference(lo.add(i), targets.get(i), RefType.DATA, SourceType.ANALYSIS, 0);
		}
		return true;
	}

	/**
	 * grm-d3tu: removes a previous planar pair of ours ({@code byte[n]} at {@code lo} whose EVERY
	 * entry carries an {@code ANALYSIS} data reference, and the same-length byte array at
	 * {@code lo+gap}), references first. Returns whether it did. Every entry, not just the first:
	 * stock's own byte load table carries an {@code ANALYSIS} data reference on its first byte (its
	 * pointer-table fallback), and that one must survive a switch we do not lay.
	 */
	static boolean unlayPlanar(Program program, Address lo, int gap) {
		Listing listing = program.getListing();
		Data d = listing.getDefinedDataAt(lo);
		if (d == null || !(d.getDataType() instanceof Array a) || !isByteLike(a.getDataType()) ||
			a.getNumElements() < 2) {
			return false;
		}
		for (int i = 0; i < a.getNumElements(); i++) {
			if (!hasAnyRef(program, lo.add(i))) {
				return false;
			}
		}
		removeAnalysisDataRefs(program, new AddressSet(d.getMinAddress(), d.getMaxAddress()));
		listing.clearCodeUnits(d.getMinAddress(), d.getMaxAddress(), false);
		try {
			Data h = listing.getDefinedDataAt(lo.add(gap));
			if (h != null && h.getDataType() instanceof Array ha && isByteLike(ha.getDataType()) &&
				ha.getNumElements() == a.getNumElements()) {
				listing.clearCodeUnits(h.getMinAddress(), h.getMaxAddress(), false);
			}
		}
		catch (AddressOutOfBoundsException e) {
			// no high half
		}
		return true;
	}

	/** One array to lay: {@code count} elements of {@code type} spaced {@code elemLen} apart. */
	private record Run(Address start, int count, int elemLen, DataType type) {}

	/**
	 * Lays every run or none (up to the final data creation): the checks of all runs come first, a
	 * later run seeing the earlier runs' extents as already cleared, so one stock byte array
	 * spanning two runs is absorbed once.
	 */
	private static boolean layRuns(Program program, List<Run> runs) {
		Listing listing = program.getListing();
		AddressSet willClear = new AddressSet();
		for (Run run : runs) {
			Address start = run.start();
			Address end;
			try {
				end = start.add((long) run.elemLen() * run.count() - 1);
			}
			catch (AddressOutOfBoundsException e) {
				return false;
			}
			AddressSet extent = new AddressSet(start, end);
			if (listing.getInstructions(extent, true).hasNext() ||
				listing.getInstructionContaining(start) != null) {
				return false;
			}
			Address clearEnd = end;
			Data atStart = listing.getDefinedDataAt(start);
			Data containing = listing.getDataContaining(start);
			if (containing != null && atStart == null && !willClear.contains(start) &&
				!Undefined.isUndefined(containing.getDataType())) {
				return false; // starts inside someone else's data
			}
			if (atStart != null) {
				DataType dt = atStart.getDataType();
				if (dt instanceof Array a) {
					if (!isByteLike(a.getDataType())) {
						return false;
					}
					if (atStart.getMaxAddress().compareTo(clearEnd) > 0) {
						clearEnd = atStart.getMaxAddress(); // stock's over-read tail
					}
				}
				else if (!isByteLike(dt)) {
					return false;
				}
			}
			for (Data d : listing.getDefinedData(extent, true)) {
				if (d.getMinAddress().equals(start) || willClear.contains(d.getMinAddress())) {
					continue;
				}
				if (d.getDataType() instanceof Array || !isByteLike(d.getDataType())) {
					return false;
				}
			}
			willClear.add(start, clearEnd);
		}
		// Stock's reference from the table's first byte (its pointer-table fallback) goes with its data.
		removeAnalysisDataRefs(program, willClear);
		for (AddressRange r : willClear) {
			listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
		}
		try {
			for (Run run : runs) {
				Data laid = listing.createData(run.start(),
					new ArrayDataType(run.type(), run.count(), run.elemLen()));
				// As stock's markDataAsConstant does: the decompiler folds loads from constant data, and
				// bank-value recovery reads dispatch tables that way.
				for (SettingsDefinition def : laid.getDataType().getSettingsDefinitions()) {
					if (def instanceof MutabilitySettingsDefinition m) {
						m.setChoice(laid, MutabilitySettingsDefinition.CONSTANT);
					}
				}
			}
		}
		catch (Exception e) {
			return false;
		}
		return true;
	}

	private static boolean isByteArray(Data d, int count) {
		return d != null && d.getDataType() instanceof Array a && isByteLike(a.getDataType()) &&
			a.getNumElements() == count;
	}

	private static boolean isWordArray(DataType dt) {
		return dt instanceof Array a && a.getDataType() instanceof WordDataType &&
			a.getElementLength() == 2;
	}

	/** What stock lays by load size 1: an unsigned-byte (or undefined) element, never a string. */
	private static boolean isByteLike(DataType dt) {
		if (dt == null || dt.getLength() != 1 || dt instanceof CharDataType) {
			return false;
		}
		return dt instanceof AbstractIntegerDataType || Undefined.isUndefined(dt);
	}

	private static boolean hasRef(Program program, Address from, Address to) {
		for (Reference r : program.getReferenceManager().getReferencesFrom(from)) {
			if (RefType.DATA.equals(r.getReferenceType()) && r.getSource() == SourceType.ANALYSIS &&
				r.getToAddress().equals(to)) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasAnyRef(Program program, Address from) {
		for (Reference r : program.getReferenceManager().getReferencesFrom(from)) {
			if (RefType.DATA.equals(r.getReferenceType()) && r.getSource() == SourceType.ANALYSIS) {
				return true;
			}
		}
		return false;
	}

	private static void removeAnalysisDataRefs(Program program, AddressSet range) {
		ReferenceManager refs = program.getReferenceManager();
		List<Reference> doomed = new ArrayList<>();
		var sources = refs.getReferenceSourceIterator(range, true);
		while (sources.hasNext()) {
			for (Reference r : refs.getReferencesFrom(sources.next())) {
				if (RefType.DATA.equals(r.getReferenceType()) && r.getSource() == SourceType.ANALYSIS) {
					doomed.add(r);
				}
			}
		}
		for (Reference r : doomed) {
			refs.delete(r);
		}
	}
}
