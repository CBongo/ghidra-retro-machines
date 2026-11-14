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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

/**
 * Pins grm-4x8f: the undotted Game Identity/Descriptor names with their read-only legacy
 * fallback (which must not register the legacy name), and the display decoders.
 */
public class ProgramInfoDisplayProgramTest extends AbstractBundledLanguageTest {

	private static final String MMC3_LIKE = """
		{"layouts":[
		  {"when":{"prg_mode":0},"windows":[
		    {"name":"W8000","start":32768,"maps":{"expr":"PRG[r6 * 0x2000]"}}]},
		  {"when":{"prg_mode":1},"windows":[
		    {"name":"W8000","start":32768,"maps":{"expr":"PRG[second_last]"}},
		    {"name":"WC000","start":49152,"maps":{"expr":"PRG[r6 * 0x2000]"}}]}],
		 "banking":{"state":[
		   {"name":"select","bits":3},{"name":"prg_mode","bits":1},
		   {"name":"r6","bits":6},{"name":"r7","bits":6}]}}
		""";

	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x100);
		program = builder.getProgram();
	}

	private void set(String name, String value) {
		inTx(program, "set " + name, () -> {
			program.getOptions(Program.PROGRAM_INFO).setString(name, value);
		});
	}

	@Test
	public void newNameWinsAndLegacyIsReadWhenNewIsAbsent() {
		assertNull(DescriptorHints.gameIdentity(program));
		set(DescriptorHints.LEGACY_GAME_IDENTITY_PROPERTY, "prg:aa file:bb");
		assertEquals("prg:aa file:bb", DescriptorHints.gameIdentity(program));
		set(DescriptorHints.GAME_IDENTITY_PROPERTY, "prg:cc file:dd");
		assertEquals("prg:cc file:dd", DescriptorHints.gameIdentity(program));

		set(DescriptorHints.LEGACY_GAME_DESCRIPTOR_PROPERTY, "old/path.gmap");
		assertEquals("old/path.gmap", DescriptorHints.gameDescriptorPath(program));
	}

	@Test
	public void readingNeverRegistersEitherName() {
		assertNull(DescriptorHints.gameIdentity(program));
		assertNull(DescriptorHints.gameDescriptorPath(program));
		Options info = program.getOptions(Program.PROGRAM_INFO);
		assertFalse(info.contains(DescriptorHints.GAME_IDENTITY_PROPERTY));
		assertFalse(info.contains(DescriptorHints.LEGACY_GAME_IDENTITY_PROPERTY));
		assertFalse(info.contains(DescriptorHints.GAME_DESCRIPTOR_PROPERTY));
		assertFalse(info.contains(DescriptorHints.LEGACY_GAME_DESCRIPTOR_PROPERTY));
	}

	@Test
	public void newNamesAreUndotted() {
		for (String n : new String[] { DescriptorHints.GAME_IDENTITY_PROPERTY,
			DescriptorHints.GAME_DESCRIPTOR_PROPERTY,
			DescriptorHints.LAYOUT_MODE_DISPLAY_PROPERTY,
			DescriptorHints.INITIAL_STATE_DISPLAY_PROPERTY,
			DescriptorHints.SNES_MAPPING_PROPERTY, DescriptorHints.SNES_ROM_LAYOUT_PROPERTY }) {
			assertFalse(n, n.contains("."));
		}
	}

	@Test
	public void layoutModeIsDecodedIntoItsWindows() {
		JsonObject map = JsonParser.parseString(MMC3_LIKE).getAsJsonObject();
		assertEquals("prg_mode = 1: $8000 = PRG[second_last]; $C000 = PRG[r6 * 0x2000]",
			ProgramInfoDisplay.layoutModeText(map, 1));
		assertEquals("prg_mode = 7", ProgramInfoDisplay.layoutModeText(map, 7));
		assertEquals("3", ProgramInfoDisplay.layoutModeText(new JsonObject(), 3));
	}

	@Test
	public void initialStateIsDecodedIntoNamedFields() {
		JsonObject map = JsonParser.parseString(MMC3_LIKE).getAsJsonObject();
		assertEquals("select=0 prg_mode=1 r6=0 r7=1",
			ProgramInfoDisplay.initialStateText(map, 1032));
		assertEquals("1032", ProgramInfoDisplay.initialStateText(new JsonObject(), 1032));
	}

	@Test
	public void snesMappingNamesTypeSpeedAndMismatch() {
		assertEquals("LoROM (FastROM)", ProgramInfoDisplay.snesMappingText(
			SnesRomHeader.MapType.LOROM, true, true, 0x7fc0));
		String s = ProgramInfoDisplay.snesMappingText(
			SnesRomHeader.MapType.HIROM, false, false, 0x7fc0);
		assertTrue(s, s.startsWith("HiROM (SlowROM); header declares HiROM but was found at $7fc0"));
	}
}
