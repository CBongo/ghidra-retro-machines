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

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.data.EnumDataType;
import retromachines.C64BasicAnalyzer.LineRender;
import retromachines.C64BasicAnalyzer.Segment;
import retromachines.C64BasicAnalyzer.SegmentKind;

/**
 * Tier 1 test of the segmentation {@link C64BasicAnalyzer#renderLine} emits for data typing
 * (grm-td4): which byte runs of a line become PETSCII strings, token enums, or plain bytes.
 */
public class C64BasicSegmentsTest {

	private static final EnumDataType PRIMARY = new EnumDataType("T", 1);
	private static final EnumDataType PAGE = new EnumDataType("P", 1);

	/** $99 PRINT, $8f REM, $83 DATA; prefix $ce -> PAGE with selector $02 = POT. */
	private static final BasicTokenLookup LOOKUP = (data, off) -> {
		int b = data[off] & 0xff;
		return switch (b) {
			case 0x99 -> new BasicTokenLookup.Match(1, "PRINT", PRIMARY, null);
			case 0x8f -> new BasicTokenLookup.Match(1, "REM", PRIMARY, null);
			case 0x83 -> new BasicTokenLookup.Match(1, "DATA", PRIMARY, null);
			case 0xce -> off + 1 >= data.length ? null : (data[off + 1] == 2
					? new BasicTokenLookup.Match(2, "POT", null, PAGE)
					: new BasicTokenLookup.Match(2, null));
			default -> null;
		};
	};

	private static LineRender render(int... bytes) throws IOException {
		byte[] data = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			data[i] = (byte) bytes[i];
		}
		return C64BasicAnalyzer.renderLine(data, LOOKUP, PetsciiMapper.load(),
			PetsciiMapper.Variant.UNSHIFTED_GRAPHICS);
	}

	private static String shape(List<Segment> segs) {
		StringBuilder sb = new StringBuilder();
		for (Segment s : segs) {
			sb.append(s.kind().name().substring(0, 2)).append(s.offset()).append('+').append(s.length())
					.append(' ');
		}
		return sb.toString().trim();
	}

	@Test
	public void tokenThenLiteralThenTextRunsMerge() throws IOException {
		// PRINT"HI";A  -> token, then one merged text run (quote, HI, quote, ;, A)
		LineRender r = render(0x99, 0x22, 'H', 'I', 0x22, ';', 'A');
		assertEquals("TO0+1 TE1+6", shape(r.segments()));
	}

	@Test
	public void remTextIsOneRunEvenWithTokenLookalikes() throws IOException {
		LineRender r = render(0x8f, ' ', 0x99, 'X');
		assertEquals("TO0+1 TE1+3", shape(r.segments()));
		assertEquals(SegmentKind.TOKEN, r.segments().get(0).kind());
		assertEquals(SegmentKind.TEXT, r.segments().get(1).kind());
	}

	@Test
	public void quotedTokenByteStaysText() throws IOException {
		LineRender r = render(0x22, 0x99, 0x22);
		assertEquals(1, r.segments().size());
		assertEquals(SegmentKind.TEXT, r.segments().get(0).kind());
	}

	@Test
	public void prefixPairIsByteThenPageEnum() throws IOException {
		LineRender r = render(0xce, 0x02);
		assertEquals(2, r.segments().size());
		assertEquals(SegmentKind.BYTE, r.segments().get(0).kind());
		assertEquals(SegmentKind.TOKEN, r.segments().get(1).kind());
		assertEquals(PAGE, r.segments().get(1).enumType());
	}

	@Test
	public void unnamedPrefixPairStaysBytes() throws IOException {
		LineRender r = render(0xce, 0x55, ' ');
		assertEquals(SegmentKind.BYTE, r.segments().get(0).kind());
		assertEquals(2, r.segments().get(0).length());
		assertEquals(SegmentKind.TEXT, r.segments().get(1).kind());
	}

	@Test
	public void dataItemsAreTextUntilUnquotedColon() throws IOException {
		// DATA 1:PRINT -> DATA token, text " 1:", PRINT token
		LineRender r = render(0x83, ' ', '1', ':', 0x99);
		assertEquals("TO0+1 TE1+3 TO4+1", shape(r.segments()));
	}

	@Test
	public void emptyLineHasNoSegments() throws IOException {
		assertEquals(0, render().segments().size());
	}
}
