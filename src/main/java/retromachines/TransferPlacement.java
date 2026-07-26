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

/**
 * Where a transfer's bytes actually ended up -- {@link TransferMaterializer}'s verdict, reported
 * back through {@link RunFromElsewhere.Result}.
 *
 * <p>The three materializing members are ordered by how well references resolve to the result:
 * {@link #IN_PLACE} and {@link #NEW_BLOCK} both put real bytes at the address the CPU runs them
 * from, so a call site resolves natively; {@link #OVERLAY} does not, and needs bridging.
 */
public enum TransferPlacement {
	/** Carved out of the containing uninitialized block and initialized at the real address. */
	IN_PLACE,
	/**
	 * A fresh non-overlay block at the destination, because nothing was mapped there at all.
	 * There was no containing block to carve and no conflict to avoid, so the bytes go straight
	 * into the base space (grm-1.7.6).
	 */
	NEW_BLOCK,
	/** A byte-mapped overlay in its own address space (destination was not carvable). */
	OVERLAY,
	/** Nothing was materialized. */
	SKIPPED;
}
