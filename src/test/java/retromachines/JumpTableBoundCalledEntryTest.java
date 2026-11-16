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
import static org.junit.Assert.assertTrue;

import java.util.Set;

import org.junit.Test;

import retromachines.JumpTableBound.Result;
import retromachines.JumpTableBound.Rule;

/**
 * Pure-logic tests for {@link JumpTableBound#calledEntryCut} and
 * {@link JumpTableBound#boundByCalledEntry} (grm-7ow3): a word table never covers the target of a
 * call. The shape is smb3's {@code a2a9} table (8 words) followed directly by the called routine
 * {@code a2b9} that dispatches through it, which every other rule declined.
 */
public class JumpTableBoundCalledEntryTest {

	private static final long TABLE = 0xa2a9L;

	@Test
	public void aCalledEntryRightAfterTheTableCutsItThere() {
		// entry 8 starts at a2b9, the called routine
		assertEquals(8, JumpTableBound.calledEntryCut(TABLE, 2, 75, a -> a == 0xa2b9L));
	}

	@Test
	public void theCalledByteMayBeTheSecondByteOfAnEntry() {
		assertEquals(8, JumpTableBound.calledEntryCut(TABLE, 2, 75, a -> a == 0xa2baL));
	}

	@Test
	public void aTableWithNoCalledEntryIsLeftWhole() {
		assertEquals(75, JumpTableBound.calledEntryCut(TABLE, 2, 75, a -> false));
	}

	@Test
	public void aCallOutsideTheTableBytesDoesNotCut() {
		assertEquals(10, JumpTableBound.calledEntryCut(TABLE, 2, 10, Set.of(0xa2d0L)::contains));
	}

	@Test
	public void aCutLeavingFewerThanTwoEntriesDeclines() {
		assertEquals(-1, JumpTableBound.calledEntryCut(TABLE, 2, 75, a -> a == TABLE + 2));
		assertEquals(-1, JumpTableBound.calledEntryCut(TABLE, 2, 75, a -> a == TABLE));
	}

	@Test
	public void theFirstCalledEntryWins() {
		assertEquals(3, JumpTableBound.calledEntryCut(TABLE, 2, 75,
			Set.of(TABLE + 6, TABLE + 16)::contains));
	}

	@Test
	public void theBoundCarriesItsRuleAndCount() {
		Result r = JumpTableBound.boundByCalledEntry(8, 0xa2d0L);
		assertTrue(r.isBounded());
		assertEquals(8, r.count());
		assertEquals(Rule.CALLED_ENTRY, r.rule());
	}
}
