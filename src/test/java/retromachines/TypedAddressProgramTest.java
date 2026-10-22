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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;

/**
 * Pins {@link TypedAddress} (bead grm-h649): a hand-typed {@code SPACE:offset} naming a space
 * that does not exist must fail with that space named and the near spelling suggested, never
 * resolve to null or to some other space. The incident was the zelda real-ROM row's
 * {@code src:W8000_M3_B1:a500} after grm-ic5 renamed that overlay {@code W8000_B1}.
 */
public class TypedAddressProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0xc000", 0x4000);
		builder.createOverlayMemory("W8000_B1", "0x8000", 0x4000);
		builder.createOverlayMemory("W8000_M2_B5", "0x8000", 0x4000);
		builder.createOverlayMemory("W8000_M3_B5", "0x8000", 0x4000);
		program = builder.getProgram();
	}

	private String failure(String text) {
		return assertThrows(IllegalArgumentException.class,
			() -> TypedAddress.parse(program, text)).getMessage();
	}

	@Test
	public void resolvesQualifiedUnqualifiedAndPrefixedForms() {
		Address a = TypedAddress.parse(program, "W8000_B1:a500");
		assertEquals("W8000_B1", a.getAddressSpace().getName());
		assertEquals(0xa500, a.getOffset());
		assertEquals(0xc123, TypedAddress.parse(program, "$c123").getOffset());
		assertEquals(0xc123, TypedAddress.parse(program, "0xc123").getOffset());
		assertFalse(TypedAddress.parse(program, "c123").getAddressSpace().isOverlaySpace());
	}

	/** The incident: a mode-qualified name whose mode became known suggests the bare name. */
	@Test
	public void modeQualifiedNameThatNoLongerExistsSuggestsTheBareName() {
		String msg = failure("W8000_M3_B1:a500");
		assertTrue(msg, msg.contains("no address space named 'W8000_M3_B1'"));
		assertTrue(msg, msg.contains("did you mean W8000_B1?"));
	}

	/** And the reverse: a bare name while the mode is still unknown lists every mode's space. */
	@Test
	public void bareNameWhileModeIsUnknownSuggestsEveryQualifiedName() {
		String msg = failure("W8000_B5:8000");
		assertTrue(msg, msg.contains("did you mean W8000_M2_B5 or W8000_M3_B5?"));
	}

	@Test
	public void unrelatedMissingSpaceIsNamedWithoutASuggestion() {
		String msg = failure("NOSUCH:1234");
		assertTrue(msg, msg.contains("no address space named 'NOSUCH'"));
		assertFalse(msg, msg.contains("did you mean"));
	}

	@Test
	public void badOffsetInARealSpaceIsReportedAsAnOffset() {
		String msg = failure("W8000_B1:zz");
		assertTrue(msg, msg.contains("invalid offset 'zz' in address space W8000_B1"));
		assertTrue(failure("zz").contains("invalid address 'zz'"));
	}

	/** Only a whole {@code _M<digits>} segment counts: {@code _MX} or a bank digit is not one. */
	@Test
	public void nearNamesDifferByExactlyOneModeSegment() {
		List<String> spaces = List.of("W8000_B1", "W8000_M3_B1", "WA000_M3", "WA000", "W8000_B11");
		assertEquals(List.of("W8000_B1"), TypedAddress.nearSpaceNames("W8000_M7_B1", spaces));
		assertEquals(List.of("W8000_M3_B1"), TypedAddress.nearSpaceNames("W8000_B1", spaces));
		assertEquals(List.of("WA000"), TypedAddress.nearSpaceNames("WA000_M1", spaces));
		assertEquals(List.of(), TypedAddress.nearSpaceNames("W8000_MX_B1", spaces));
	}
}
