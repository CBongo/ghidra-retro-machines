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
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Pure-JUnit pin of {@link DescriptorExpressions#decodedMask} (bead grm-5dgx): which bank-field
 * bits a switchable window's {@code maps:} expression decodes, hence which field values alias
 * the same image and are realized as ONE overlay. Covers the expression shapes directly and then
 * scans every shipped descriptor so a new non-injective window cannot appear unnoticed.
 */
public class DecodedMaskTest {

	@Test
	public void injectiveExpressionDecodesEveryBit() {
		assertEquals(0x7F, DescriptorExpressions.decodedMask("bank * 0x2000", 0x2000, "bank", 7));
		assertEquals(0xF, DescriptorExpressions.decodedMask("r6 * 0x4000", 0x4000, "r6", 4));
	}

	@Test
	public void shiftByOneIgnoresBitZero() {
		assertEquals(0x1E,
			DescriptorExpressions.decodedMask("(prg_bank >> 1) * 0x8000", 0x8000, "prg_bank", 5));
		assertEquals(0x7E, DescriptorExpressions.decodedMask("(bank_5115 >> 1) * 0x4000", 0x4000,
			"bank_5115", 7));
	}

	@Test
	public void shiftByTwoIgnoresTwoBits() {
		assertEquals(0x7C, DescriptorExpressions.decodedMask("(bank_5117 >> 2) * 0x8000", 0x8000,
			"bank_5117", 7));
	}

	@Test
	public void canonicalIsLowestValueSelectingTheSameImage() {
		long mask = DescriptorExpressions.decodedMask("(b >> 1) * 0x4000", 0x4000, "b", 4);
		for (int v = 0; v < 16; v++) {
			long canon = v & mask;
			assertEquals(DescriptorExpressions.evalExpr("(b >> 1) * 0x4000", 1L << 20, 0x4000,
				java.util.Map.of("b", (long) v)),
				DescriptorExpressions.evalExpr("(b >> 1) * 0x4000", 1L << 20, 0x4000,
					java.util.Map.of("b", canon)));
			assertTrue(canon <= v);
		}
	}

	@Test
	public void expandAliasesRestoresTheFieldValueUniverse() {
		FieldSpec field = new FieldSpec("b", 0, 3);
		// quads: only 0 and 4 are realized as overlays
		assertEquals(Set.of(0, 1, 2, 3, 4, 5, 6, 7),
			BankAnnotationAdapter.expandAliases(Set.of(0, 4), field, 0x4));
		// pairs, partial image: 0 and 2 realized
		assertEquals(Set.of(0, 1, 2, 3),
			BankAnnotationAdapter.expandAliases(Set.of(0, 2), field, 0x6));
		// injective: identity
		assertEquals(Set.of(0, 3), BankAnnotationAdapter.expandAliases(Set.of(0, 3), field, 0x7));
	}

	@Test
	public void modelCanonicalizesAndJudgesKnownOnDecodedBitsOnly() {
		FieldSpec field = new FieldSpec("b", 2, 3);
		BoardDescriptorModel.ComputedWindowModel w =
			new BoardDescriptorModel.ComputedWindowModel("W", 0x8000, 0x9fff, field, null, 0x6);
		assertEquals(4, w.canonical(5));
		assertEquals(6, w.canonical(7));
		// bit 0 of the field (state bit 2) unknown, bits 1-2 (state bits 3-4) known
		assertTrue(w.decodedKnownIn(new BankState(0b11000, 0)));
		assertTrue(!field.fullyKnownIn(new BankState(0b11000, 0)));
		assertTrue(!w.decodedKnownIn(new BankState(0b10000, 0)));
	}

	/** Every shipped switchable window is injective except the >> windows below. */
	@Test
	public void shippedDescriptorsAreInjectiveExceptTheKnownShiftWindows() throws Exception {
		String moduleDir = System.getProperty("grm.moduleDir");
		assertNotNull("grm.moduleDir is not set -- run these tests through Gradle", moduleDir);
		File[] files = new File(moduleDir, "data/machines").listFiles((d, n) -> n.endsWith(".map"));
		assertNotNull(files);
		Set<String> found = new TreeSet<>();
		for (File f : files) {
			JsonObject map;
			try (InputStreamReader r =
				new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8)) {
				map = JsonParser.parseReader(r).getAsJsonObject();
			}
			if (!map.has("banking")) {
				continue;
			}
			MessageLog log = new MessageLog();
			DescriptorSupport.LayoutPlan plan = DescriptorSupport.planWindows(map, log, f.getName());
			List<FieldSpec> fields = DescriptorSupport.parseStateFields(map);
			List<DescriptorSupport.PlannedWindow> all = new ArrayList<>(plan.invariant());
			all.addAll(plan.varying());
			for (DescriptorSupport.PlannedWindow pw : all) {
				if (pw.expr() == null) {
					continue;
				}
				Set<String> refs = DescriptorExpressions.referencedFields(pw.expr());
				if (refs.size() != 1) {
					continue;
				}
				FieldSpec field = DescriptorSupport.findField(fields, refs.iterator().next());
				if (field == null) {
					continue;
				}
				long mask = DescriptorExpressions.decodedMask(pw.expr(), pw.length(), field.name(),
					field.width());
				if (mask != (1L << field.width()) - 1) {
					found.add(f.getName() + " " + pw.name() + " mode=" + pw.modeValue() + " " +
						pw.expr() + " mask=0x" + Long.toHexString(mask));
				}
			}
		}
		// Only the shift-shaped windows named on the bead: MMC1 modes 0/1 W8000, MMC5 mode 0
		// W8000 (>> 2), modes 1/2 W8000 and mode 1 WC000 (>> 1).
		for (String s : found) {
			assertTrue("unexpected non-injective window: " + s,
				s.startsWith("nes-mmc1.map W8000") || s.startsWith("nes-mmc5.map "));
			assertTrue(s, s.contains(">>"));
		}
		assertTrue("expected the MMC1 and MMC5 shift windows: " + found, found.size() >= 4);
	}
}
