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

import java.util.Arrays;

import org.junit.Test;

/** EXECVEC (vector table) words in {@link ForthThreads} (grm-arbi.3). */
public class ForthVectorTest {

	private static final int DOCOL = 0x1000;
	private static final int EXECVEC = 0x1300;
	private static final int EXIT = 0x2000;
	private static final int DUP = 0x2030;

	private static final String CONFIG = """
		{"forth": {"ip": 126, "w": 129, "docol": 4096, "exit": [8192],
		 "handlers": {"0x1300": {"role": "EXECVEC"}},
		 "names": {"0x2000": "EXIT", "0x2030": "DUP"}}}
		""";

	private final int[] mem = new int[0x10000];

	private void init() {
		Arrays.fill(mem, -1);
		for (int c : new int[] {EXIT, DUP}) {
			word(c, c + 2);
			mem[c + 2] = 0x60;
		}
	}

	private void word(int a, int v) {
		mem[a] = v & 0xFF;
		mem[a + 1] = (v >> 8) & 0xFF;
	}

	private ForthThreads.Result walk() {
		return ForthThreads.walk(ForthConfig.fromJson(CONFIG),
			a -> a < 0 || a > 0xFFFF ? -1 : mem[a]);
	}

	/** A colon word at {@code at} that just calls the vector word {@code vec}. */
	private void caller(int at, int vec) {
		word(at, DOCOL);
		word(at + 2, vec);
		word(at + 4, EXIT);
	}

	@Test
	public void runStopsAtTheNextWordsDocolAndExitIsAnEntry() {
		init();
		word(0x3400, EXECVEC);
		word(0x3402, DUP);
		word(0x3404, EXIT); // a "do nothing" case is a legal entry
		word(0x3406, DUP);
		word(0x3408, DOCOL); // next word begins here
		word(0x340A, DUP);
		word(0x340C, EXIT);
		caller(0x3500, 0x3400);
		ForthThreads.Result r = walk();
		ForthThreads.Word v = r.words().get(0x3400);
		assertNotNull(r.log().toString(), v);
		assertEquals(ForthThreads.Kind.VECTOR, v.kind());
		assertEquals(3, v.body().size());
		assertEquals("VECTOR: FORTH_3400  DUP EXIT DUP ", ForthThreads.renderVector(v, r));
		assertNotNull(r.words().get(0x3500)); // the caller is no longer rejected
		assertNotNull(r.words().get(0x3408)); // and the next word is a colon word
	}

	@Test
	public void runStopsAtTheFirstInvalidCell() {
		init();
		word(0x3600, EXECVEC);
		word(0x3602, DUP);
		word(0x3604, 0x9999); // not a word
		word(0x3606, DUP); // beyond the stop: not part of the run
		caller(0x3700, 0x3600);
		ForthThreads.Result r = walk();
		ForthThreads.Word v = r.words().get(0x3600);
		assertNotNull(r.log().toString(), v);
		assertEquals(1, v.body().size());
		assertNotNull(r.words().get(0x3700));
	}

	@Test
	public void vectorWithNoValidEntryIsNotAWord() {
		init();
		word(0x3800, EXECVEC);
		word(0x3802, 0x9999);
		caller(0x3900, 0x3800);
		ForthThreads.Result r = walk();
		assertNull(r.words().get(0x3800));
		assertNull(r.words().get(0x3900));
	}
}
