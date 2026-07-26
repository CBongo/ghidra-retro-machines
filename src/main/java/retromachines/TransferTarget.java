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
 * Where a transfer's recovered bytes should land. A front-end normally asks for
 * {@link #SAME_SPACE} and lets {@link TransferMaterializer} pick the representation; the explicit
 * members exist for a front-end that knows better (grm-chu).
 *
 * <p>Public because it is part of {@link RunFromElsewhere}'s signature -- a human driving the
 * manual front-end may need to override a placement the materializer would otherwise choose.
 */
public enum TransferTarget {
	/** In the destination's own address space; the materializer chooses how (grm-chu). */
	SAME_SPACE,
	/**
	 * Force the in-place carve: initialize the destination range where it really lives, so
	 * references resolve without bridging. Falls back to an overlay, with a log note, when the
	 * destination cannot be carved.
	 */
	SAME_SPACE_INPLACE,
	/** Force a dual-home byte-mapped overlay in its own address space (grm-1.7.1). */
	SAME_SPACE_OVERLAY,
	/** A separate Program in another processor's space (SPC700 upload, grm-1.7.3). */
	SEPARATE_PROGRAM;
}
