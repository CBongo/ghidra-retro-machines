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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;

/**
 * Pure-JUnit coverage of NES placement-override validation (bead grm-n5f): that the legal bank
 * set is derived per window from that window's own {@code maps:} expression and length against
 * the PRG byte size, and not from the iNES header's 16 KiB PRG-bank count.
 * <p>
 * The defect this pins: MMC3's windows are 8 KiB, so a 32 KiB image has four placeable banks
 * while its iNES header counts two 16 KiB ones -- the old check rejected banks 2 and 3 on a
 * board where the loader creates blocks for them. MMC1 is the complementary case, where a
 * window's length is <em>not</em> the bank unit: its mode-0 window spans 32 KiB but its
 * expression takes bank values in 16 KiB units, so "window length" alone would be just as
 * wrong as "header unit".
 * <p>
 * Drives the SHIPPED descriptors (read straight off disk via the {@code grm.moduleDir} system
 * property the {@code test} task sets, so no {@code Application} bootstrap is needed) through
 * the real {@link DescriptorSupport#placeableBanks} and the real
 * {@link NesRomLoader#placementError(Map, Map, String, long)} -- the same two calls the loader
 * makes on both its routes. Only descriptor loading is left out, so a green run here is the
 * GUI ({@code validateOptions}) and headless ({@code load}) verdicts both, which is exactly
 * what makes them agree.
 */
public class NesPlacementValidationTest {

	private static final long KB = 1024;

	private static JsonObject map(String name) throws IOException {
		String moduleDir = System.getProperty("grm.moduleDir");
		assertNotNull("grm.moduleDir is not set -- run these tests through Gradle", moduleDir);
		File f = new File(new File(moduleDir, "data/machines"), name);
		assertTrue("missing shipped descriptor " + f, f.isFile());
		try (InputStreamReader reader =
			new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	private static Map<String, NavigableSet<Integer>> banks(String descriptor, long prgSize)
			throws IOException {
		return DescriptorSupport.placeableBanks(map(descriptor), prgSize, new MessageLog(),
			descriptor);
	}

	/** One-pair convenience over the real validator, mirroring what the loader passes. */
	private static String error(Map<String, NavigableSet<Integer>> placeable, String boardId,
			long prgSize, String window, int bank) {
		return NesRomLoader.placementError(Map.of(window, bank), placeable, boardId, prgSize);
	}

	@Test
	public void mmc3At32KHasFourEightKiBBanks() throws IOException {
		// The bead's headline case: prgBanks == 2 here, but the descriptor's windows are
		// 8 KiB, so 0-3 are all realizable and 4 is not.
		Map<String, NavigableSet<Integer>> placeable = banks("nes-mmc3.map", 32 * KB);
		assertEquals(List.of(0, 1, 2, 3), List.copyOf(placeable.get("W8000")));

		for (int bank = 0; bank <= 3; bank++) {
			assertNull("bank " + bank + " must be accepted",
				error(placeable, "mmc3", 32 * KB, "W8000", bank));
		}
		String err = error(placeable, "mmc3", 32 * KB, "W8000", 4);
		assertNotNull("bank 4 must be rejected", err);
		assertTrue(err, err.contains("bank 4"));
		assertTrue(err, err.contains("W8000"));
		assertTrue("the message must name the real legal set: " + err,
			err.contains("placeable banks: 0-3"));
	}

	@Test
	public void mmc3BankSetTracksImageSize() throws IOException {
		// 64 KiB: eight 8 KiB banks. The old header-derived check capped this at 4 (the
		// 16 KiB count), so banks 4-7 -- which the loader does create blocks for -- were
		// rejected here too.
		Map<String, NavigableSet<Integer>> placeable = banks("nes-mmc3.map", 64 * KB);
		assertEquals(List.of(0, 1, 2, 3, 4, 5, 6, 7), List.copyOf(placeable.get("W8000")));
		assertNull(error(placeable, "mmc3", 64 * KB, "W8000", 7));
		assertNotNull(error(placeable, "mmc3", 64 * KB, "W8000", 8));
	}

	@Test
	public void mmc3FixedWindowTakesNoBank() throws IOException {
		// WE000 is PRG[last] in every layout: nothing to override, and saying so beats
		// accepting a bank number that could never be applied.
		Map<String, NavigableSet<Integer>> placeable = banks("nes-mmc3.map", 32 * KB);
		assertTrue(placeable.get("WE000").isEmpty());
		String err = error(placeable, "mmc3", 32 * KB, "WE000", 0);
		assertNotNull(err);
		assertTrue(err, err.contains("no switchable bank"));
	}

	@Test
	public void mmc1BankUnitComesFromTheExpressionNotTheWindowLength() throws IOException {
		// 128 KiB MMC1: W8000 is a 32 KiB window in prg_mode 0/1 but its expression
		// ((prg_bank >> 1) * 0x8000) selects in 16 KiB units, and a 16 KiB window in
		// prg_mode 3. Both agree on 0-7, which dividing the image by the window length
		// (128/32 = 4) would not. Bank 5 is the nesmmc1overridetest fixture's override.
		Map<String, NavigableSet<Integer>> placeable = banks("nes-mmc1.map", 128 * KB);
		assertEquals(List.of(0, 1, 2, 3, 4, 5, 6, 7), List.copyOf(placeable.get("W8000")));
		assertNull(error(placeable, "mmc1", 128 * KB, "W8000", 5));
		assertNotNull(error(placeable, "mmc1", 128 * KB, "W8000", 8));
	}

	@Test
	public void unknownWindowIsRejectedAndListsTheKnownOnes() throws IOException {
		Map<String, NavigableSet<Integer>> placeable = banks("nes-mmc3.map", 32 * KB);
		String err = error(placeable, "mmc3", 32 * KB, "WFFFF", 0);
		assertNotNull(err);
		assertTrue(err, err.contains("unknown window 'WFFFF'"));
		assertTrue(err, err.contains("W8000"));
	}

	@Test
	public void nromHasNoPlaceableBankAtAll() throws IOException {
		// Both NROM windows are fixed expressions; a placement override is meaningless on
		// this board and must not be silently accepted.
		Map<String, NavigableSet<Integer>> placeable = banks("nes-nrom.map", 32 * KB);
		assertTrue(placeable.get("PRG_LO").isEmpty());
		assertTrue(placeable.get("PRG_HI").isEmpty());
		assertNotNull(error(placeable, "nrom", 32 * KB, "PRG_LO", 0));
	}
}
