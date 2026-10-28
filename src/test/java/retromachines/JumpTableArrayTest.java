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

/** Pure-logic tests for {@link JumpTableArray} (grm-deve). */
public class JumpTableArrayTest {

	@Test
	public void orderedPlainTable() {
		JumpTableArray.Layout l = JumpTableArray.matchOrdered(List.of(0x8210L, 0x8230L, 0x9999L),
			List.of(0x8210L, 0x8230L));
		assertNotNull(l);
		assertEquals(2, l.count()); // the third word is beyond the kept entries: not laid
		assertEquals(0, l.bias());
	}

	/** grm-d3tu: planar lo/hi halves, plain and RTS-trick, never mixed. */
	@Test
	public void planarPlainRtsTrickAndMismatch() {
		byte[] hi = { (byte) 0x82, (byte) 0x82 };
		JumpTableArray.Layout plain = JumpTableArray.matchPlanar(new byte[] { 0x10, 0x30 }, hi,
			List.of(0x8210L, 0x8230L));
		assertNotNull(plain);
		assertEquals(0, plain.bias());
		assertEquals(2, plain.count());
		JumpTableArray.Layout rts = JumpTableArray.matchPlanar(new byte[] { 0x0f, 0x2f }, hi,
			List.of(0x8210L, 0x8230L));
		assertNotNull(rts);
		assertEquals(1, rts.bias());
		assertNull(JumpTableArray.matchPlanar(new byte[] { 0x10, 0x2f }, hi,
			List.of(0x8210L, 0x8230L)));
		assertNull(JumpTableArray.matchPlanar(new byte[] { 0x10 }, hi, List.of(0x8210L, 0x8230L)));
	}

	@Test
	public void orderedRtsTrickTable() {
		JumpTableArray.Layout l =
			JumpTableArray.matchOrdered(List.of(0x820fL, 0x822fL), List.of(0x8210L, 0x8230L));
		assertNotNull(l);
		assertEquals(1, l.bias());
	}

	@Test
	public void orderedNeverMixesEncodings() {
		assertNull(JumpTableArray.matchOrdered(List.of(0x8210L, 0x822fL),
			List.of(0x8210L, 0x8230L)));
	}

	@Test
	public void orderedDeclinesWhenAnEntryDisagreesOrWordsRunOut() {
		assertNull(JumpTableArray.matchOrdered(List.of(0x8210L, 0x8231L),
			List.of(0x8210L, 0x8230L)));
		assertNull(JumpTableArray.matchOrdered(List.of(0x8210L), List.of(0x8210L, 0x8230L)));
	}

	/** dodge 82bd shape: more words than distinct cases. */
	@Test
	public void distinctWordsExceedCases() {
		long table = 0x82bdL;
		List<Long> words = List.of(0x82e9L, 0x82f0L, 0x82e9L, 0x82f0L, 0x82f0L, 0x9000L);
		JumpTableArray.Layout l =
			JumpTableArray.matchDistinct(words, table, List.of(0x82e9L, 0x82f0L));
		assertNotNull(l);
		assertEquals(5, l.count()); // the 0x9000 word is not a kept target
		assertEquals(List.of(0, 1, 0, 1, 1), l.caseIndex());
	}

	@Test
	public void distinctDeclinesWhenACaseIsNotCovered() {
		assertNull(JumpTableArray.matchDistinct(List.of(0x82e9L, 0x82e9L, 0x82e9L, 0x9000L),
			0x82bdL, List.of(0x82e9L, 0x82f0L)));
	}
}
