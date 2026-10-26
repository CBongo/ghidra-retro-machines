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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
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
		Listing listing = program.getListing();
		int n = targets.size();
		Address end;
		try {
			end = start.add(2L * n - 1);
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
		if (listing.getDataContaining(start) != null && atStart == null &&
			!Undefined.isUndefined(listing.getDataContaining(start).getDataType())) {
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
			if (d.getMinAddress().equals(start)) {
				continue;
			}
			if (d.getDataType() instanceof Array || !isByteLike(d.getDataType())) {
				return false;
			}
		}
		AddressSet cleared = new AddressSet(start, clearEnd);
		// Stock's reference from the table's first byte (its pointer-table fallback) goes with its data.
		removeAnalysisDataRefs(program, cleared);
		listing.clearCodeUnits(start, clearEnd, false);
		try {
			Data laid = listing.createData(start, new ArrayDataType(WordDataType.dataType, n, 2));
			// As stock's markDataAsConstant does: the decompiler folds loads from constant data, and
			// bank-value recovery reads dispatch tables that way.
			for (SettingsDefinition def : laid.getDataType().getSettingsDefinitions()) {
				if (def instanceof MutabilitySettingsDefinition m) {
					m.setChoice(laid, MutabilitySettingsDefinition.CONSTANT);
				}
			}
		}
		catch (Exception e) {
			return false;
		}
		ReferenceManager refs = program.getReferenceManager();
		for (int i = 0; i < n; i++) {
			refs.addMemoryReference(start.add(2L * i), targets.get(i), RefType.DATA,
				SourceType.ANALYSIS, 0);
		}
		return true;
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
