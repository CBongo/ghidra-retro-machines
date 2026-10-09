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
 * The value+mask shape {@link BankState} (board coordinates) and {@link MechanismState}
 * (field-local coordinates) share. It exists ONLY as a generic bound for the few helpers that
 * never care which coordinate space they hold -- arm enumeration, canonical ordering, log
 * rendering -- so those stay single implementations (bead grm-ze06.2). Do not use it as a
 * parameter type for anything that does care: that would reopen the hole the two types close.
 */
interface BitKnowledge {

	/** Bits whose values are known. */
	int knownMask();

	/** The known bit values; bits outside {@link #knownMask()} are insignificant. */
	int bits();
}
