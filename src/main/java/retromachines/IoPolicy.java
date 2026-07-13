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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Decides which addresses an {@link EmulationRecovery} run should treat as hardware I/O.
 * The harness cannot faithfully emulate chip registers (VIC/SID/CIA timers, PPU state);
 * it answers reads there with a policy value and records them in the provenance log so a
 * caller can tell that a recovered value depended on hardware it did not model.
 *
 * <p>The default policy, {@link #volatileBlocks(Program)}, derives I/O-ness straight from
 * the loaded program: the board descriptor already marks I/O regions volatile at load
 * time (see {@code DescriptorSupport}), so a volatile memory block <em>is</em> the
 * descriptor's statement that its bytes are hardware, not memory. This keeps the I/O
 * policy descriptor-sourced without the harness re-parsing the compiled map.
 */
@FunctionalInterface
public interface IoPolicy {

	/** True if reads of {@code address} hit hardware I/O rather than plain memory. */
	boolean isIo(Address address);

	/**
	 * Descriptor-derived policy: an address is I/O iff the memory block containing it is
	 * marked volatile. The board loaders mark exactly the descriptor's I/O regions volatile,
	 * so this reflects the game's declared memory map with no additional configuration.
	 *
	 * @param program the loaded program whose block volatility encodes the I/O map
	 * @return a policy backed by that program's blocks
	 */
	static IoPolicy volatileBlocks(Program program) {
		return address -> {
			MemoryBlock block = program.getMemory().getBlock(address);
			return block != null && block.isVolatile();
		};
	}

	/** Policy that treats nothing as I/O (every uninitialized read is plain RAM). */
	static IoPolicy none() {
		return address -> false;
	}
}
