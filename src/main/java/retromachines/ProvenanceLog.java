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
import java.util.Collections;
import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Running record of everything an {@link EmulationRecovery} run observed that a caller
 * might need to judge the trustworthiness of the recovered bytes. The two load-bearing
 * kinds are {@link Kind#IO_READ} and {@link Kind#UNINIT_RAM_READ}: either one means the
 * emulator answered a read with a policy value (zero) rather than real data, so a key or
 * control-flow decision derived from it may be wrong -- see {@link #suspect()}.
 */
public class ProvenanceLog {

	/** Classification of a logged event. */
	public enum Kind {
		/** A read of an address the {@link IoPolicy} considers hardware I/O. On real hardware
		 *  this could return a timer/raster/controller value; the emulator returned a policy
		 *  value instead, so a key derived from it is not reproducible. */
		IO_READ,
		/** A read of never-written, non-I/O RAM. Power-on RAM is not zero on real machines, so
		 *  a decryptor keying off it will diverge from the emulated (zero-filled) result. */
		UNINIT_RAM_READ,
		/** A non-fatal problem worth surfacing (readback failure, aborting exception, etc.). */
		WARNING,
		/** Informational breadcrumb with no correctness implication. */
		INFO;
	}

	/**
	 * One logged event.
	 *
	 * @param kind    what happened
	 * @param address the address involved (nullable for events with no single address)
	 * @param size    the byte length involved, or 0 if not applicable
	 * @param detail  free-text explanation
	 */
	public record Entry(Kind kind, Address address, int size, String detail) {}

	private final List<Entry> entries = new ArrayList<>();

	/** Append an event. */
	public void add(Kind kind, Address address, int size, String detail) {
		entries.add(new Entry(kind, address, size, detail));
	}

	/** All logged events, in order, unmodifiable. */
	public List<Entry> entries() {
		return Collections.unmodifiableList(entries);
	}

	/** True if any I/O read was observed during the run. */
	public boolean hasIoReads() {
		return entries.stream().anyMatch(e -> e.kind() == Kind.IO_READ);
	}

	/** True if any read of uninitialized RAM was observed during the run. */
	public boolean hasUninitReads() {
		return entries.stream().anyMatch(e -> e.kind() == Kind.UNINIT_RAM_READ);
	}

	/**
	 * True if the run read a value the emulator could not know (I/O or uninitialized RAM),
	 * meaning the recovered bytes should be treated as suspect. This is the signal callers
	 * (e.g. the decrypt tier) use to downgrade a result from "apply automatically" to
	 * "recovered, but verify" or to recommend a hardware-accurate snapshot instead.
	 */
	public boolean suspect() {
		return hasIoReads() || hasUninitReads();
	}
}
