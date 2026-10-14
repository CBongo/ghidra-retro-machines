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

import static org.junit.Assert.assertEquals;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

/**
 * Shared {@link StoredValueScanner.Hooks} stub and bank-assertion helpers for the scanner tests
 * (bead grm-w9ev.3). Static, so a test file that needs a different flavour (another mask, say)
 * can still declare its own same-named method, which shadows the static import.
 */
final class StoredValueScannerTestSupport {

	private StoredValueScannerTestSupport() {
	}

	/** Hooks that answer neither question: no mechanism writes, no load resolved. */
	static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore) {
			return null;
		}
	};

	/** The low three bits (an 8-bank mechanism) fully known and equal to {@code expected}. */
	static void assertBank(int expected, MechanismState actual) {
		assertEquals("tracked bits not fully known: " + actual, 0x07, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	/** The low three bits (an 8-bank mechanism) fully known and equal to {@code expected}. */
	static void assertBank(int expected, PartialByte actual) {
		assertEquals("tracked bits not fully known: " + actual, 0x07, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	static void assertUnresolved(MechanismState actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
	}

	static void assertUnresolved(PartialByte actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
	}
}
