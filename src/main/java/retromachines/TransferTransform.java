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
 * How a transfer's source bytes map to its destination bytes. Only {@link #IDENTITY} is
 * implemented; the other members mark the axis the decrypt beads (grm-1.7.2) fill in.
 *
 * <p>Public because it is part of {@link RunFromElsewhere}'s signature -- the manual script and
 * the GUI plugin both let the analyst pick one.
 */
public enum TransferTransform {
	/** Verbatim 1:1 copy (grm-1.7.1). */
	IDENTITY,
	/** Constant-key EOR (static; unifies grm-1.7.2 tier 1) -- not yet wired here. */
	CONSTANT_XOR,
	/** Rolling/computed-key EOR (emulated; grm-1.7.2 tier 2) -- not yet wired here. */
	ROLLING_XOR;
}
