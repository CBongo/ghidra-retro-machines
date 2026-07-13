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

import java.util.Collections;
import java.util.NavigableMap;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

/**
 * Outcome of an {@link EmulationRecovery} run. Reports what memory the emulated code
 * wrote ({@link #dirty()}), the bytes it left there ({@link #recoveredBytes(Address, int)}),
 * why the run stopped ({@link #stopReason()}), and what the run observed that bears on
 * trustworthiness ({@link #provenance()}). The caller decides how to materialize the
 * bytes -- patch, overlay block, byte-mapped block, or a fresh program.
 */
public class RecoveryResult {

	private final AddressSetView dirty;
	// Keyed by the minimum address of each coalesced dirty range; value is that range's bytes.
	private final NavigableMap<Address, byte[]> recovered;
	private final StopReason stopReason;
	private final ProvenanceLog provenance;
	private final long stepsExecuted;

	RecoveryResult(AddressSetView dirty, NavigableMap<Address, byte[]> recovered,
			StopReason stopReason, ProvenanceLog provenance, long stepsExecuted) {
		this.dirty = dirty;
		this.recovered = recovered;
		this.stopReason = stopReason;
		this.provenance = provenance;
		this.stepsExecuted = stepsExecuted;
	}

	/** The set of addresses the emulated code wrote (memory space only; registers excluded). */
	public AddressSetView dirty() {
		return dirty;
	}

	/** Why the run stopped. */
	public StopReason stopReason() {
		return stopReason;
	}

	/** The provenance log (I/O reads, uninitialized-RAM reads, warnings). */
	public ProvenanceLog provenance() {
		return provenance;
	}

	/** Number of instructions actually stepped. */
	public long stepsExecuted() {
		return stepsExecuted;
	}

	/** The recovered dirty ranges keyed by start address (unmodifiable). Each value holds the
	 *  post-run bytes for one coalesced range beginning at its key. */
	public NavigableMap<Address, byte[]> recoveredRanges() {
		return Collections.unmodifiableNavigableMap(recovered);
	}

	/**
	 * The recovered bytes for {@code length} bytes starting at {@code start}, or null if that
	 * span was not entirely written by the run (i.e. not fully covered by a single dirty
	 * range). This is the accessor a caller uses when it knows the target range up front --
	 * e.g. a decrypt tier reading back the range its recognized loop rewrote.
	 *
	 * @param start  first address of the wanted span
	 * @param length number of bytes wanted
	 * @return the bytes, or null if not fully recovered
	 */
	public byte[] recoveredBytes(Address start, int length) {
		if (start == null || length <= 0) {
			return null;
		}
		var entry = recovered.floorEntry(start);
		if (entry == null) {
			return null;
		}
		Address base = entry.getKey();
		byte[] bytes = entry.getValue();
		if (!base.getAddressSpace().equals(start.getAddressSpace())) {
			return null;
		}
		long offset = start.subtract(base);
		if (offset < 0 || offset + length > bytes.length) {
			return null;
		}
		byte[] out = new byte[length];
		System.arraycopy(bytes, (int) offset, out, 0, length);
		return out;
	}
}
