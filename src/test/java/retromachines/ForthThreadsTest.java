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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

/** Pure tests for {@link ForthConfig} and {@link ForthThreads} over a synthetic byte image. */
public class ForthThreadsTest {

	private static final int DOCOL = 0x1000;
	private static final int DOCON = 0x1100;
	private static final int EXIT = 0x2000;
	private static final int LIT = 0x2010;
	private static final int ZBRANCH = 0x2020;
	private static final int DUP = 0x2030;
	private static final int STRP = 0x2040;

	private static final String CONFIG = """
		{"forth": {"ip": "0x7E", "w": "$81", "next": 4096, "docol": "0x1000",
		 "exit": ["0x2000"],
		 "handlers": {"0x1100": "DOCON", "4608": {"role": "DOUSER", "base": 131}},
		 "inline": {"0x2010": "lit16", "0x2020": "branch", "0x2040": "counted_string"},
		 "names": {"0x2000": {"name": "EXIT"}, "0x2010": "LIT", "0x2020": {"name": "0BRANCH"},
		           "0x2030": {"name": "DUP", "comment": "( n -- n n )"},
		           "0x2040": {"name": "(.\\")"}, "0x3000": {"name": "A"}}}}
		""";

	private final int[] mem = new int[0x10000];

	private void init() {
		Arrays.fill(mem, -1);
		for (int c : new int[] {EXIT, LIT, ZBRANCH, DUP, STRP}) {
			word(c, c + 2);
			mem[c + 2] = 0x60;
		}
	}

	private void word(int a, int v) {
		mem[a] = v & 0xFF;
		mem[a + 1] = (v >> 8) & 0xFF;
	}

	private ForthThreads.Result walk() {
		ForthConfig cfg = ForthConfig.fromJson(CONFIG);
		return ForthThreads.walk(cfg, a -> a < 0 || a > 0xFFFF ? -1 : mem[a]);
	}

	@Test
	public void configParsesHexStringsAndDecimalKeys() {
		ForthConfig c = ForthConfig.fromJson(CONFIG);
		assertEquals(0x7E, c.ip());
		assertEquals(0x81, c.w());
		assertEquals(0x1000, c.docol());
		assertEquals(ForthConfig.Role.DOCON, c.handlers().get(0x1100).role());
		assertEquals(131, c.handlers().get(4608).base());
		assertEquals(ForthConfig.InlineMode.COUNTED_STRING, c.inline().get(STRP));
		assertEquals("( n -- n n )", c.names().get(DUP).comment());
		assertEquals(c.names(), ForthConfig.fromJson(c.toJson().toString()).names());
		assertNull(ForthConfig.fromMap(new com.google.gson.JsonObject()));
	}

	@Test
	public void rendersForwardBranchAsLocalLabel() {
		init();
		word(0x3000, DOCOL);
		word(0x3002, DUP);
		word(0x3004, ZBRANCH);
		word(0x3006, 6); // target 0x300C
		word(0x3008, LIT);
		word(0x300A, 3);
		word(0x300C, EXIT);
		ForthThreads.Result r = walk();
		ForthThreads.Word a = r.words().get(0x3000);
		assertNotNull(r.log().toString(), a);
		assertEquals(ForthThreads.Kind.COLON, a.kind());
		assertEquals(6, a.body().size());
		assertEquals(": A  DUP 0BRANCH L1 LIT $0003 L1: ; ", ForthThreads.render(a, r));
		assertEquals(0x300E, a.bodyEnd());
	}

	@Test
	public void bodyContinuesPastExitWhenForwardBranchTargetsBeyond() {
		init();
		word(0x3100, DOCOL);
		word(0x3102, ZBRANCH);
		word(0x3104, 4); // target 0x3108, beyond the EXIT at 0x3106
		word(0x3106, EXIT);
		word(0x3108, DUP);
		word(0x310A, EXIT);
		ForthThreads.Result r = walk();
		ForthThreads.Word b = r.words().get(0x3100);
		assertNotNull(r.log().toString(), b);
		assertEquals(0x310C, b.bodyEnd());
		assertEquals(": FORTH_3100  0BRANCH L1 EXIT L1: DUP ; ", ForthThreads.render(b, r));
	}

	@Test
	public void decodesCountedString() {
		init();
		word(0x3200, DOCOL);
		word(0x3202, STRP);
		mem[0x3204] = 2;
		mem[0x3205] = 'H';
		mem[0x3206] = 'I';
		word(0x3207, EXIT);
		ForthThreads.Result r = walk();
		ForthThreads.Word c = r.words().get(0x3200);
		assertNotNull(r.log().toString(), c);
		assertEquals(ForthThreads.Op.STRING, c.body().get(1).op());
		assertEquals(": FORTH_3200  (.\") \"HI\" ; ", ForthThreads.render(c, r));
	}

	@Test
	public void decoyDocolValueInDataIsRejectedAndLogged() {
		init();
		word(0x4000, DOCOL);
		word(0x4002, 0x1234);
		word(0x4004, 0);
		ForthThreads.Result r = walk();
		assertFalse(r.words().containsKey(0x4000));
		assertTrue(r.log().toString(), r.log().stream().anyMatch(s -> s.contains("$4000")));
	}

	@Test
	public void handlerWordsNeedAReferenceOrName() {
		init();
		word(0x3300, DOCON);
		word(0x3302, 5);
		word(0x3400, DOCON);
		word(0x3402, 7);
		word(0x3310, DOCOL);
		word(0x3312, 0x3300);
		word(0x3314, EXIT);
		ForthThreads.Result r = walk();
		assertEquals(ForthThreads.Kind.CONSTANT, r.words().get(0x3300).kind());
		assertEquals(5, r.words().get(0x3300).param());
		assertNull("unreferenced handler value in data", r.words().get(0x3400));
	}

	@Test
	public void docolOperandInsideAnotherBodyDoesNotBecomeAWord() {
		init();
		word(0x3500, DOCOL);
		word(0x3502, LIT);
		word(0x3504, DOCOL); // the operand: a DOCOL value, followed by a valid-looking suffix
		word(0x3506, DUP);
		word(0x3508, EXIT);
		ForthThreads.Result r = walk();
		assertNotNull(r.words().get(0x3500));
		assertNull(r.words().get(0x3504));
		assertEquals(": FORTH_3500  LIT $1000 DUP ; ",
			ForthThreads.render(r.words().get(0x3500), r));
	}

	@Test
	public void unterminatedBodyIsRejected() {
		init();
		word(0x3600, DOCOL);
		word(0x3602, DUP);
		word(0x3604, DUP); // runs on into unwritten memory
		ForthThreads.Result r = walk();
		assertNull(r.words().get(0x3600));
	}
}
