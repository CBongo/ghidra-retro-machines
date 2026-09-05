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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.test.AbstractGenericTest;

/**
 * Pins the compiled SNES machine descriptor (bead grm-9nxj.9): {@code machines/snes.yaml} ->
 * {@code data/machines/snes.map}, which is what the loader will read.
 *
 * <p>The assertion that matters most is the NEGATIVE one — this descriptor declares an EMPTY
 * {@code windows} list. Every other machine here banks, and {@code MapCompiler} rightly demands
 * the key, so an empty list is how the SNES states "no banked windows" out loud rather than by
 * omission (bead grm-9nxj.6: the 65816 addresses 16 MB, cartridges reach 8 MB, and layout is a
 * static header lookup). If someone later "fixes" this descriptor by adding windows, this test
 * is what asks them to read that decision first.
 */
public class SnesDescriptorTest extends AbstractGenericTest {

	private static JsonObject descriptor() throws Exception {
		String moduleDir = System.getProperty(AbstractBundledLanguageTest.MODULE_DIR_PROPERTY);
		assertNotNull("grm.moduleDir is not set -- run through Gradle", moduleDir);
		File map = new File(new File(moduleDir, "data/machines"), "snes.map");
		assertTrue("data/machines/snes.map is missing -- run `gradle buildMap`", map.isFile());
		try (FileReader reader = new FileReader(map)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	@Test
	public void declaresTheVendoredSixtyFiveEightSixteen() throws Exception {
		JsonObject system = descriptor().getAsJsonObject("system");
		assertEquals("snes", system.get("id").getAsString());
		assertEquals("65816:LE:24:retro", system.get("language").getAsString());
	}

	/** The decision this descriptor exists to record. See the class doc. */
	@Test
	public void declaresNoBankedWindows() throws Exception {
		JsonArray windows = descriptor().getAsJsonArray("windows");
		assertNotNull("windows must be present, even though it is empty", windows);
		assertEquals("the SNES has no banked windows -- see docs/snes-memory-map-decision.md",
			0, windows.size());
	}

	/**
	 * Work RAM and the IO windows, in their bank $00 home. ROM regions are deliberately absent:
	 * where ROM lands depends on the cartridge's map mode, which is a per-file fact the loader
	 * reads, so a fixed region here would be wrong for LoROM or for HiROM.
	 */
	@Test
	public void declaresWorkRamAndIoWindowsButNoRom() throws Exception {
		Map<String, JsonObject> regions = new HashMap<>();
		for (JsonElement e : descriptor().getAsJsonArray("regions")) {
			regions.put(e.getAsJsonObject().get("name").getAsString(), e.getAsJsonObject());
		}
		assertEquals("WRAM, PPU/APU, joypad, CPU/DMA", 4, regions.size());

		JsonObject wram = regions.get("WRAM");
		assertNotNull(wram);
		assertEquals(0x7E0000, wram.get("start").getAsLong());
		assertEquals(0x7FFFFF, wram.get("end").getAsLong());
		assertEquals("ram", wram.get("kind").getAsString());

		for (String io : new String[] { "PPU_APU_IO", "JOYPAD_IO", "CPU_DMA_IO" }) {
			assertEquals(io + " should be typed as IO", "io",
				regions.get(io).get("kind").getAsString());
		}
		for (JsonObject region : regions.values()) {
			assertTrue("no ROM region belongs here -- placement is per-cartridge",
				!"rom".equals(region.get("kind").getAsString()));
		}
	}

	/**
	 * The eight DMA channels are expressed ONCE and repeated, not enumerated. Hand-listing 112
	 * registers invites transcription errors that no test would catch; a repeated typed
	 * subregion cannot drift out of step with itself.
	 */
	@Test
	public void dmaChannelsAreATypedRepeatRatherThanAHandList() throws Exception {
		JsonObject cpuDma = null;
		for (JsonElement e : descriptor().getAsJsonArray("regions")) {
			if ("CPU_DMA_IO".equals(e.getAsJsonObject().get("name").getAsString())) {
				cpuDma = e.getAsJsonObject();
			}
		}
		assertNotNull(cpuDma);
		JsonArray subregions = cpuDma.getAsJsonArray("subregions");
		assertNotNull("CPU_DMA_IO should carry the DMA channel block", subregions);
		assertEquals(1, subregions.size());

		JsonObject channels = subregions.get(0).getAsJsonObject();
		assertEquals(0x004300, channels.get("start").getAsLong());
		assertEquals("16 bytes per channel", 0x10, channels.get("size").getAsLong());
		assertEquals("repeated through channel 7", 0x00437F, channels.get("repeat_to").getAsLong());
		assertEquals("SNES_DMA_CHANNEL", channels.get("type").getAsString());
	}

	/** The CPU vectors, which the loader turns into entry points, and the register names. */
	@Test
	public void declaresVectorsAndRegisterSymbols() throws Exception {
		Map<String, JsonArray> sets = new HashMap<>();
		for (JsonElement e : descriptor().getAsJsonArray("symbols")) {
			JsonObject set = e.getAsJsonObject();
			sets.put(set.get("set").getAsString(), set.getAsJsonArray("entries"));
		}
		assertEquals("cpu-vectors, ppu-registers, cpu-dma-registers", 3, sets.size());

		JsonArray vectors = sets.get("cpu-vectors");
		assertEquals("ten 65816 vectors, native and emulation", 10, vectors.size());

		boolean sawReset = false;
		for (JsonElement e : vectors) {
			JsonObject vector = e.getAsJsonObject();
			assertEquals("vector", vector.get("kind").getAsString());
			if ("VEC_RESET_EMULATION".equals(vector.get("name").getAsString())) {
				assertEquals(0x00FFFC, vector.get("addr").getAsLong());
				sawReset = true;
			}
		}
		assertTrue("the reset vector must be declared -- it is the loader's entry point",
			sawReset);

		assertTrue("PPU registers should be named", sets.get("ppu-registers").size() > 50);
		assertTrue("CPU/DMA registers should be named",
			sets.get("cpu-dma-registers").size() > 20);
	}
}
