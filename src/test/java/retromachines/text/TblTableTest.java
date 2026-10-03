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
package retromachines.text;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import retromachines.text.TblTable.Match;
import retromachines.text.TblTable.Run;
import retromachines.text.TblTable.TblFormatException;

/** Tier-1 pure tests for {@link TblTable} (bead grm-pqk): grammar, longest match, runs. */
public class TblTableTest {

	private static byte[] b(int... v) {
		byte[] out = new byte[v.length];
		for (int i = 0; i < v.length; i++) {
			out[i] = (byte) v[i];
		}
		return out;
	}

	@Test
	public void parsesCommentsBlankLinesAndMixedLineEndings() {
		TblTable t = TblTable.parse("# a comment\r\n\r\n41=A\r42=B\n/00=<end>\n");
		assertEquals(3, t.size());
		assertTrue(t.warnings().isEmpty());
		assertEquals("A", t.match(b(0x41), 0).text());
	}

	@Test
	public void stripsLeadingBomAndAcceptsLowercaseHex() {
		TblTable t = TblTable.parse("﻿ab=x\n");
		assertEquals("x", t.match(b(0xAB), 0).text());
	}

	@Test
	public void textIsVerbatimSoSpacesAndEqualsSignsSurvive() {
		TblTable t = TblTable.parse("20= \n3D==\n41=a b\n");
		assertEquals(" ", t.match(b(0x20), 0).text());
		assertEquals("=", t.match(b(0x3D), 0).text());
		assertEquals("a b", t.match(b(0x41), 0).text());
	}

	@Test
	public void longestPrefixWins() {
		TblTable t = TblTable.parse("81=x\n8140=Y\n814041=Z\n");
		Match m = t.match(b(0x81, 0x40, 0x41), 0);
		assertEquals(3, m.length());
		assertEquals("Z", m.text());
		m = t.match(b(0x81, 0x40, 0x42), 0);
		assertEquals(2, m.length());
		assertEquals("Y", m.text());
		m = t.match(b(0x81, 0x99), 0);
		assertEquals(1, m.length());
		assertEquals("x", m.text());
	}

	@Test
	public void matchRespectsEndOfData() {
		TblTable t = TblTable.parse("8140=Y\n81=x\n");
		assertEquals("x", t.match(b(0x81), 0).text());
		assertNull(t.match(b(0x99), 0));
	}

	@Test
	public void endTokenIsRecognizedAndLabelIsKept() {
		TblTable t = TblTable.parse("41=A\n/FF=<end>\n");
		assertTrue(t.isEndToken(0xFF));
		assertFalse(t.isEndToken(0x41));
		Match m = t.match(b(0xFF), 0);
		assertTrue(m.endToken());
		assertEquals("<end>", m.text());
	}

	@Test
	public void legacyLinebreakEntryIsTolerated() {
		TblTable t = TblTable.parse("41=A\n*FE=<br>\n");
		Match m = t.match(b(0xFE), 0);
		assertNotNull(m);
		assertFalse(m.endToken());
		assertEquals("<br>", m.text());
	}

	@Test
	public void deferredDirectivesAreSkippedWithWarnings() {
		TblTable t = TblTable.parse("41=A\n$F0=<wait>,1\n!1=other\n@2\n%x\n");
		assertEquals(1, t.size());
		assertEquals(4, t.warnings().size());
	}

	@Test
	public void duplicateEntryLastWinsWithWarning() {
		TblTable t = TblTable.parse("41=A\n41=Z\n");
		assertEquals("Z", t.match(b(0x41), 0).text());
		assertEquals(1, t.warnings().size());
	}

	@Test
	public void malformedLinesAreRejectedWithLineNumbers() {
		TblFormatException e =
			assertThrows(TblFormatException.class, () -> TblTable.parse("41=A\nZZ=b\n"));
		assertEquals(2, e.lineNumber());
		assertThrows(TblFormatException.class, () -> TblTable.parse("4=A\n"));
		assertThrows(TblFormatException.class, () -> TblTable.parse("41\n"));
		assertThrows(TblFormatException.class, () -> TblTable.parse("=A\n"));
		assertThrows(TblFormatException.class, () -> TblTable.parse("/0102=end\n"));
		assertThrows(TblFormatException.class, () -> TblTable.parse("*0102=br\n"));
	}

	@Test
	public void renderFallsBackToRawByteForUnmappedBytes() {
		TblTable t = TblTable.parse("41=A\n42=B\n");
		assertEquals("A[$99]B[$00]", t.render(b(0x41, 0x99, 0x42, 0x00), 0, 4));
	}

	@Test
	public void decodeRunStopsAtEndTokenInclusiveAndExcludesLabel() {
		TblTable t = TblTable.parse("41=A\n42=B\n/00=<end>\n");
		Run r = t.decodeRun(b(0x41, 0x42, 0x41, 0x00, 0x41), 0, 100);
		assertEquals(4, r.length());
		assertEquals("ABA", r.text());
		assertEquals(3, r.entryCount());
	}

	@Test
	public void decodeRunUsesMultiByteEntries() {
		TblTable t = TblTable.parse("8140=X\n41=A\n/00=<end>\n");
		Run r = t.decodeRun(b(0x41, 0x81, 0x40, 0x00), 0, 100);
		assertEquals("AX", r.text());
		assertEquals(4, r.length());
	}

	@Test
	public void decodeRunFailsOnUnmappedByteTruncationOrEmptyString() {
		TblTable t = TblTable.parse("41=A\n/00=<end>\n");
		assertNull(t.decodeRun(b(0x41, 0x99, 0x00), 0, 100)); // unmapped byte mid-run
		assertNull(t.decodeRun(b(0x41, 0x41), 0, 100)); // runs off the end, no terminator
		assertNull(t.decodeRun(b(0x00), 0, 100)); // empty string
		assertNull(t.decodeRun(b(0x41, 0x41, 0x00), 0, 2)); // terminator beyond maxBytes
		assertNotNull(t.decodeRun(b(0x41, 0x41, 0x00), 0, 3));
	}

	@Test
	public void decodeRunWithMultiByteEntryCrossingMaxBytesFails() {
		TblTable t = TblTable.parse("8140=X\n/00=<end>\n");
		assertNull(t.decodeRun(b(0x81, 0x40, 0x00), 1, 100));
		assertNull(t.decodeRun(b(0x81, 0x40, 0x00), 0, 1));
	}
}
