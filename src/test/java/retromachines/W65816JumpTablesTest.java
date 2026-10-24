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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * Pure-logic tests for {@link W65816JumpTables} (grm-9nxj.5.4). Shapes are taken from the
 * real-ROM tables the bound was measured on.
 */
public class W65816JumpTablesTest {

	private static int bound(long start, int cap, int[] words, List<Long> out) {
		return W65816JumpTables.bound(start, cap, i -> i < words.length ? words[i] : null,
			b -> true, t -> true, out);
	}

	/** FF3 $C2:0F47: thirteen handlers start right after the table; the walk stops there. */
	@Test
	public void stopsAtItsOwnLowestTarget() {
		int[] words = { 0x0f67, 0x0f61, 0x0f68, 0x0f6f, 0x0f61, 0x0f67, 0x0f6b, 0x0f67, 0x0f68,
			0x0f64, 0x0f67, 0x0f67, 0x0f68, 0x7420, 0x9c0f };
		List<Long> out = new ArrayList<>();
		assertEquals(13, bound(0xc20f47L, 128, words, out));
		assertEquals(0xc20f67L, (long) out.get(0));
	}

	/** Targets below the table never bound it; the cap does. */
	@Test
	public void targetsBelowTheTableLeaveTheCap() {
		int[] words = { 0x469b, 0x45a3, 0x469b, 0x45cb, 0x45df, 0x460b };
		assertEquals(4, bound(0xc246b0L, 4, words, new ArrayList<>()));
		assertEquals(6, bound(0xc246b0L, 128, words, new ArrayList<>()));
	}

	@Test
	public void anEntryPointingIntoTheTableEndsIt() {
		int[] words = { 0x9000, 0x8002, 0x9010 };
		assertEquals(1, bound(0x008000L, 128, words, new ArrayList<>()));
	}

	@Test
	public void takenBytesAndImplausibleTargetsEndIt() {
		List<Long> out = new ArrayList<>();
		int n = W65816JumpTables.bound(0x008000L, 128, i -> 0x9000 + i,
			b -> b < 0x008006L, t -> true, out);
		assertEquals(3, n);
		n = W65816JumpTables.bound(0x008000L, 128, i -> 0x9000 + i, b -> true,
			t -> t != 0x009002L, new ArrayList<>());
		assertEquals(2, n);
	}

	@Test
	public void neverWrapsPastTheBank() {
		assertEquals(2, bound(0x00fffcL, 128, new int[] { 0x8000, 0x8000, 0x8000 },
			new ArrayList<>()));
	}

	/** FF3 $C2:1B02: AND #$0F / ASL A / TAX -- sixteen entries. */
	@Test
	public void maskCap() {
		assertEquals(16, W65816JumpTables.maskCap(0x0f, 1));
		assertEquals(4, W65816JumpTables.maskCap(0x06, 0));   // AND #$06 / TAX: 0,2,4,6
		assertEquals(W65816JumpTables.MAX_ENTRIES, W65816JumpTables.maskCap(0xff, 1));
	}
}
