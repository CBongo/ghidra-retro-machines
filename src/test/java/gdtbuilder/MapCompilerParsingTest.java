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
package gdtbuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * JUnit migration datapoint for {@link MapCompilerVerify} (bead grm-32f.1 spike): a small
 * slice of its {@code verifyFixedRomAndFormats}/{@code verifyDuplicateNames} coverage,
 * reimplemented with {@code @Test} methods and {@link TemporaryFolder} instead of the
 * hand-rolled {@code main()} + {@code VerifyHarness} temp-dir/check()/expectThrows()
 * scaffolding. Pure JUnit + gson: no {@code ghidra.*} runtime is touched (MapCompiler
 * itself only needs Ghidra jars on its compile/runtime classpath for address-space
 * plumbing, never invoked here through anything but its public {@code main} entry point).
 */
public class MapCompilerParsingTest {

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	@Test
	public void fixedRomRegionEmitsOccupantAndImageMetadata() throws Exception {
		Path yaml = tmp.newFile("valid.yaml").toPath();
		Path map = tmp.getRoot().toPath().resolve("valid.map");
		Files.writeString(yaml, """
			schema: 2
			system: { id: fixed, name: Fixed ROM, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xdfff, kind: ram }
			    - { name: KERNAL, start: 0xf000, end: 0xffff, kind: rom, image: kernal }
			  windows: []
			rom_images:
			  kernal: { size: 0x1000, occupant: KERNAL }
			""");

		MapCompiler.main(new String[] { yaml.toString(), map.toString() });

		JsonObject doc = JsonParser.parseString(Files.readString(map)).getAsJsonObject();
		JsonObject kernalRegion = doc.getAsJsonArray("regions").get(1).getAsJsonObject();
		assertEquals("kernal", kernalRegion.get("image").getAsString());
		JsonObject slots = doc.getAsJsonObject("rom_images");
		assertEquals("KERNAL", slots.getAsJsonObject("kernal").get("occupant").getAsString());
	}

	@Test
	public void duplicateRegionNameIsRejected() throws Exception {
		Path yaml = tmp.newFile("dup-region.yaml").toPath();
		Path map = tmp.getRoot().toPath().resolve("dup-region.map");
		Files.writeString(yaml, """
			schema: 2
			system: { id: dup-region, name: Dup Region, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: SAME, start: 0, end: 0x7fff, kind: ram }
			    - { name: SAME, start: 0x8000, end: 0xffff, kind: ram }
			  windows: []
			""");

		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> MapCompiler.main(new String[] { yaml.toString(), map.toString() }));

		assertTrue("expected error mentioning the duplicate name, got: " + e.getMessage(),
			e.getMessage().contains("declared twice"));
	}

	@Test
	public void romTargetMissingOccupantIsRejected() throws Exception {
		Path yaml = tmp.newFile("neither.yaml").toPath();
		Path map = tmp.getRoot().toPath().resolve("neither.map");
		Files.writeString(yaml, """
			schema: 2
			system: { id: error, name: Error, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0x0fff, kind: ram }
			    - { name: KERNAL, start: 0xf000, end: 0xffff, kind: rom, image: test }
			  windows: []
			rom_images:
			  test: { size: 0x1000 }
			""");

		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> MapCompiler.main(new String[] { yaml.toString(), map.toString() }));

		assertTrue("expected error mentioning 'occupant', got: " + e.getMessage(),
			e.getMessage().contains("occupant"));
	}
}
