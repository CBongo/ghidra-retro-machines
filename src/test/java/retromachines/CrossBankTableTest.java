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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.List;

import org.junit.Test;

/** Pure-logic coverage of {@link CrossBankTable}'s layout fitting (grm-pwuh). */
public class CrossBankTableTest {

	private static CrossBankTable.Bytes bytes(long base, int... values) {
		return offset -> {
			long i = offset - base;
			return i >= 0 && i < values.length ? values[(int) i] : -1;
		};
	}

	@Test
	public void interleavedWordTableFitsAndRereadsOtherBank() {
		CrossBankTable.Bytes wrong = bytes(0x9000, 0x10, 0x80, 0x20, 0x80, 0x30, 0x80);
		CrossBankTable.Model m = CrossBankTable.fit(0x9000, 0, List.of(0x8010L, 0x8020L, 0x8030L), wrong);
		assertNotNull(m);
		assertEquals(new CrossBankTable.Model(2, 1, 0), m);

		CrossBankTable.Bytes right = bytes(0x9000, 0x00, 0xa0, 0x10, 0xa0);
		assertEquals(List.of(0xa000L, 0xa010L), m.read(0x9000, 3, right)); // stops at unreadable
	}

	@Test
	public void planarTablesFitWhenGapGiven() {
		// lo bytes at 0x9000.., hi bytes at 0x9004..
		CrossBankTable.Bytes wrong = bytes(0x9000, 0x10, 0x20, 0x30, 0x40, 0x80, 0x81, 0x82, 0x83);
		CrossBankTable.Model m =
			CrossBankTable.fit(0x9000, 4, List.of(0x8010L, 0x8120L, 0x8230L, 0x8340L), wrong);
		assertEquals(new CrossBankTable.Model(1, 4, 0), m);
	}

	@Test
	public void rtsTrickConstantIsRecovered() {
		// Entries stored as target-1; the decompiler's case targets are target (k = +1).
		CrossBankTable.Bytes wrong = bytes(0x9000, 0x0f, 0x80, 0x1f, 0x80);
		CrossBankTable.Model m = CrossBankTable.fit(0x9000, 0, List.of(0x8010L, 0x8020L), wrong);
		assertEquals(new CrossBankTable.Model(2, 1, 1), m);
	}

	@Test
	public void noLayoutThatReproducesEveryCaseDeclines() {
		CrossBankTable.Bytes wrong = bytes(0x9000, 0x10, 0x80, 0x20, 0x80);
		// Second case disagrees with the bytes under every candidate.
		assertNull(CrossBankTable.fit(0x9000, 0, List.of(0x8010L, 0x9999L), wrong));
	}

	@Test
	public void tooFewCasesDecline() {
		assertNull(CrossBankTable.fit(0x9000, 0, List.of(0x8010L), bytes(0x9000, 0x10, 0x80)));
	}

	private static final java.util.function.LongPredicate IN_WINDOW = v -> v >= 0x8000 && v <= 0xffff;

	@Test
	public void prefixKeepsUpToFirstInvalid() {
		assertEquals(new CrossBankTable.Prefix(0, 2),
			CrossBankTable.validPrefix(List.of(0x8010L, 0x8020L, 0x0100L, 0x8030L), IN_WINDOW));
	}

	@Test
	public void oneLeadingJunkSlotIsSkipped() {
		assertEquals(new CrossBankTable.Prefix(1, 2),
			CrossBankTable.validPrefix(List.of(0x2727L, 0x805bL, 0x8077L, 0xe144L - 0xe000L), IN_WINDOW));
	}

	@Test
	public void twoLeadingInvalidEntriesKeepNothing() {
		assertEquals(0,
			CrossBankTable.validPrefix(List.of(0x00a2L, 0x16a9L, 0x8000L), IN_WINDOW).count());
	}

	@Test
	public void emptyOrAllValidTables() {
		assertEquals(0, CrossBankTable.validPrefix(List.of(), IN_WINDOW).count());
		assertEquals(new CrossBankTable.Prefix(0, 2),
			CrossBankTable.validPrefix(List.of(0x8000L, 0xffffL), IN_WINDOW));
	}
}
