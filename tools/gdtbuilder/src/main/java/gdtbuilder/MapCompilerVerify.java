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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Focused standalone checks for schema fields emitted by {@link MapCompiler}. */
public class MapCompilerVerify {

	public static void main(String[] args) throws Exception {
		Path temp = Files.createTempDirectory("map-compiler-");
		try {
			verifyFixedRomAndFormats(temp);
			verifyRomTargetErrors(temp);
			verifySystemText(temp);
			verifyRamCoverage(temp);
			verifyDuplicateNames(temp);
			System.err.println("Map compiler verification passed");
		}
		finally {
			try (var paths = Files.walk(temp)) {
				paths.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
			}
		}
	}

	private static void verifyFixedRomAndFormats(Path temp) throws Exception {
		Path yaml = temp.resolve("valid.yaml");
		Path map = temp.resolve("valid.map");
		write(yaml, """
			schema: 2
			system: { id: fixed, name: Fixed ROM, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xdfff, kind: ram }
			    - { name: EDITOR, start: 0xe000, end: 0xefff, kind: rom }
			    - { name: KERNAL, start: 0xf000, end: 0xffff, kind: rom, image: kernal }
			  windows: []
			rom_images:
			  kernal: { size: 0x1000, occupant: KERNAL }
			  editor: { size: 0x1000, occupant: EDITOR }
			  legacy: { size: 0x1000, occupant: LEGACY_ROM }
			formats:
			  prg:
			    extensions: ['.prg']
			    header: [{ field: load_address, size: 2, endian: little }]
			    placement: load_address
			""");
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });

		JsonObject doc = JsonParser.parseString(Files.readString(map)).getAsJsonObject();
		JsonObject kernalRegion = doc.getAsJsonArray("regions").get(2).getAsJsonObject();
		check("kernal".equals(kernalRegion.get("image").getAsString()),
			"region image metadata was not emitted");
		JsonObject slots = doc.getAsJsonObject("rom_images");
		check("KERNAL".equals(slots.getAsJsonObject("kernal").get("occupant").getAsString()),
			"fixed ROM region target was not emitted");
		check("EDITOR".equals(slots.getAsJsonObject("editor").get("occupant").getAsString()),
			"fixed ROM target without a reverse region image was not emitted");
		check("LEGACY_ROM".equals(
			slots.getAsJsonObject("legacy").get("occupant").getAsString()),
			"legacy occupant target was not preserved");
		JsonObject prg = doc.getAsJsonObject("formats").getAsJsonObject("prg");
		check(prg.getAsJsonArray("header").get(0).getAsJsonObject().get("size").getAsInt() == 2,
			"formats tree or numeric header metadata was not preserved");
		check("load_address".equals(prg.get("placement").getAsString()),
			"formats placement was not preserved");
	}

	/** {@code system.text} (bead grm-1.4 Phase E) passes through verbatim, with numeric
	 *  scalars normalized to ints like every other opaque params tree. */
	private static void verifySystemText(Path temp) throws Exception {
		Path yaml = temp.resolve("text.yaml");
		Path map = temp.resolve("text.map");
		write(yaml, """
			schema: 2
			system:
			  id: text-test
			  name: Text Test
			  cpu: { language: '6502:LE:16:default' }
			  text:
			    encoding: petscii
			    variant: unshifted_graphics
			    string_search:
			      min_length: 4
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			""");
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });

		JsonObject doc = JsonParser.parseString(Files.readString(map)).getAsJsonObject();
		JsonObject text = doc.getAsJsonObject("system").getAsJsonObject("text");
		check(text != null, "system.text was not emitted");
		check("petscii".equals(text.get("encoding").getAsString()),
			"system.text.encoding was not preserved");
		check("unshifted_graphics".equals(text.get("variant").getAsString()),
			"system.text.variant was not preserved");
		JsonObject search = text.getAsJsonObject("string_search");
		check(search != null, "system.text.string_search was not emitted");
		check(search.get("min_length").getAsInt() == 4,
			"system.text.string_search.min_length was not normalized to an int");
	}

	private static void verifyRomTargetErrors(Path temp) throws Exception {
		expectError(temp, "neither", "{ size: 0x1000 }", "occupant");
		expectError(temp, "wrong-kind", "{ size: 0x1000, occupant: RAM }", "kind is not 'rom'");
	}

	private static void expectError(Path temp, String name, String slot, String part)
			throws Exception {
		Path yaml = temp.resolve(name + ".yaml");
		write(yaml, """
			schema: 2
			system: { id: error, name: Error, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0x0fff, kind: ram }
			    - { name: KERNAL, start: 0xf000, end: 0xffff, kind: rom, image: test }
			  windows: []
			rom_images:
			  test: %s
			""".formatted(slot));
		try {
			MapCompiler.main(new String[] { yaml.toString(), temp.resolve(name + ".map").toString() });
			throw new AssertionError("expected error containing '" + part + "'");
		}
		catch (IllegalArgumentException e) {
			check(e.getMessage().contains(part),
				"expected error containing '" + part + "', got: " + e.getMessage());
		}
	}

	/** grm-z15.4: MapCompiler.validateRamCoverage must reject a RAM/prg_placeable union with
	 *  an internal gap or overlap, and must accept a {@code prg_placeable: true} io region as
	 *  a legitimate coverage contributor (mirroring C64's P6510). The check only fires for
	 *  descriptors that declare {@code formats.prg.placement: load_address} (the
	 *  AbstractCbmPrgLoader convention), so every fixture here declares that block. */
	private static void verifyRamCoverage(Path temp) throws Exception {
		expectCompileError(temp, "ram-gap", """
			schema: 2
			system: { id: ram-gap, name: RAM Gap, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM_LO, start: 0, end: 0x7fff, kind: ram }
			    - { name: RAM_HI, start: 0x9000, end: 0xffff, kind: ram }
			  windows: []
			formats:
			  prg:
			    extensions: ['.prg']
			    header: [{ field: load_address, size: 2, endian: little }]
			    placement: load_address
			""", "gap");
		expectCompileError(temp, "ram-overlap", """
			schema: 2
			system: { id: ram-overlap, name: RAM Overlap, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM_LO, start: 0, end: 0x8fff, kind: ram }
			    - { name: RAM_HI, start: 0x8000, end: 0xffff, kind: ram }
			  windows: []
			formats:
			  prg:
			    extensions: ['.prg']
			    header: [{ field: load_address, size: 2, endian: little }]
			    placement: load_address
			""", "overlap");

		Path yaml = temp.resolve("ram-prg-placeable.yaml");
		Path map = temp.resolve("ram-prg-placeable.map");
		write(yaml, """
			schema: 2
			system: { id: ram-ok, name: RAM OK, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: P, start: 0, end: 1, kind: io, prg_placeable: true }
			    - { name: RAM, start: 2, end: 0xffff, kind: ram }
			  windows: []
			formats:
			  prg:
			    extensions: ['.prg']
			    header: [{ field: load_address, size: 2, endian: little }]
			    placement: load_address
			""");
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });
		check(Files.exists(map), "gapless map with a prg_placeable io region failed to compile");
	}

	/** MapCompiler.validateUniqueNames must reject duplicate names/keys within
	 *  {@code physical[]}, {@code memory.regions[]}, and {@code symbols[]}. */
	private static void verifyDuplicateNames(Path temp) throws Exception {
		expectCompileError(temp, "dup-region", """
			schema: 2
			system: { id: dup-region, name: Dup Region, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: SAME, start: 0, end: 0x7fff, kind: ram }
			    - { name: SAME, start: 0x8000, end: 0xffff, kind: ram }
			  windows: []
			""", "declared twice");
		expectCompileError(temp, "dup-physical", """
			schema: 2
			system: { id: dup-physical, name: Dup Physical, cpu: { language: '6502:LE:16:default' } }
			physical:
			  - { name: PRG, image: prg_rom }
			  - { name: PRG, image: prg_rom2 }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			""", "declared twice");
		expectCompileError(temp, "dup-symbol-set", """
			schema: 2
			system: { id: dup-symbol-set, name: Dup Symbol Set, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			symbols:
			  - set: mmio
			    default: on
			    inline:
			      - { addr: 0x2000, name: FOO, kind: label }
			  - set: mmio
			    default: on
			    inline:
			      - { addr: 0x3000, name: BAR, kind: label }
			""", "declared twice");
	}

	private static void expectCompileError(Path temp, String name, String yamlBody, String part)
			throws Exception {
		Path yaml = temp.resolve(name + ".yaml");
		write(yaml, yamlBody);
		try {
			MapCompiler.main(new String[] { yaml.toString(), temp.resolve(name + ".map").toString() });
			throw new AssertionError("expected error containing '" + part + "'");
		}
		catch (IllegalArgumentException e) {
			check(e.getMessage().contains(part),
				"expected error containing '" + part + "', got: " + e.getMessage());
		}
	}

	private static void write(Path file, String text) throws Exception {
		Files.writeString(file, text);
	}

	private static void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
