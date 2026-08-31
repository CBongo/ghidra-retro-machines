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
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import retromachines.BankSwitchStrategy;
import retromachines.MemoryLatchBankSwitchStrategy;
import retromachines.RegisterWriteBankSwitchStrategy;
import retromachines.SelectDataBankSwitchStrategy;
import retromachines.SerialShiftBankSwitchStrategy;

/**
 * JUnit migration of {@code tools/gdtbuilder/src/main/java/gdtbuilder/MapCompilerVerify.java}
 * (bead grm-32f.4): focused checks for schema fields emitted by {@link MapCompiler}.
 */
public class MapCompilerTest {

	@Rule
	public TemporaryFolder tmp = new TemporaryFolder();

	@Test
	public void fixedRomAndFormats() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("valid.yaml");
		Path map = temp.resolve("valid.map");
		Files.writeString(yaml, """
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
		assertTrue("region image metadata was not emitted",
			"kernal".equals(kernalRegion.get("image").getAsString()));
		JsonObject slots = doc.getAsJsonObject("rom_images");
		assertTrue("fixed ROM region target was not emitted",
			"KERNAL".equals(slots.getAsJsonObject("kernal").get("occupant").getAsString()));
		assertTrue("fixed ROM target without a reverse region image was not emitted",
			"EDITOR".equals(slots.getAsJsonObject("editor").get("occupant").getAsString()));
		assertTrue("legacy occupant target was not preserved",
			"LEGACY_ROM".equals(slots.getAsJsonObject("legacy").get("occupant").getAsString()));
		JsonObject prg = doc.getAsJsonObject("formats").getAsJsonObject("prg");
		assertTrue("formats tree or numeric header metadata was not preserved",
			prg.getAsJsonArray("header").get(0).getAsJsonObject().get("size").getAsInt() == 2);
		assertTrue("formats placement was not preserved",
			"load_address".equals(prg.get("placement").getAsString()));
	}

	@Test
	public void romTargetErrors() throws Exception {
		Path temp = tmp.getRoot().toPath();
		expectError(temp, "neither", "{ size: 0x1000 }", "occupant");
		expectError(temp, "wrong-kind", "{ size: 0x1000, occupant: RAM }", "kind is not 'rom'");
	}

	private static void expectError(Path temp, String name, String slot, String part)
			throws Exception {
		Path yaml = temp.resolve(name + ".yaml");
		Files.writeString(yaml, """
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
		Path map = temp.resolve(name + ".map");
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> MapCompiler.main(new String[] { yaml.toString(), map.toString() }));
		assertTrue("expected error containing '" + part + "', got: " + e.getMessage(),
			e.getMessage().contains(part));
	}

	/** {@code system.text} (bead grm-1.4 Phase E) passes through verbatim, with numeric
	 *  scalars normalized to ints like every other opaque params tree. */
	@Test
	public void systemText() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("text.yaml");
		Path map = temp.resolve("text.map");
		Files.writeString(yaml, """
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
		assertTrue("system.text was not emitted", text != null);
		assertTrue("system.text.encoding was not preserved",
			"petscii".equals(text.get("encoding").getAsString()));
		assertTrue("system.text.variant was not preserved",
			"unshifted_graphics".equals(text.get("variant").getAsString()));
		JsonObject search = text.getAsJsonObject("string_search");
		assertTrue("system.text.string_search was not emitted", search != null);
		assertTrue("system.text.string_search.min_length was not normalized to an int",
			search.get("min_length").getAsInt() == 4);
	}

	/** grm-z15.4: MapCompiler.validateRamCoverage must reject a RAM/prg_placeable union with
	 *  an internal gap or overlap, and must accept a {@code prg_placeable: true} io region as
	 *  a legitimate coverage contributor (mirroring C64's P6510). The check only fires for
	 *  descriptors that declare {@code formats.prg.placement: load_address} (the
	 *  AbstractCbmPrgLoader convention), so every fixture here declares that block. */
	@Test
	public void ramCoverage() throws Exception {
		Path temp = tmp.getRoot().toPath();
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
		Files.writeString(yaml, """
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
		assertTrue("gapless map with a prg_placeable io region failed to compile",
			Files.exists(map));
	}

	/** MapCompiler.validateUniqueNames must reject duplicate names/keys within
	 *  {@code physical[]}, {@code memory.regions[]}, and {@code symbols[]}. */
	@Test
	public void duplicateNames() throws Exception {
		Path temp = tmp.getRoot().toPath();
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

	/**
	 * grm-1.7.1.2: {@code memory.regions[].copied_from} must survive compilation with every
	 * address key normalized to a JSON <em>number</em>. The normalization is the point of the
	 * test, not decoration: {@code buildRegions} is a {@code copyIfPresent} whitelist, so before
	 * this key was added the whole block vanished silently, and a plain {@code copyIfPresent}
	 * would have passed hex scalars through as strings where the runtime calls {@code getAsLong}.
	 * <p>
	 * The fixture mirrors the shipped C64 shape: the source ({@code KERNAL}) is a window
	 * <b>occupant</b>, not a region, since that is the resolution space {@code on_write} uses.
	 */
	@Test
	public void copiedFrom() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("copyhint.yaml");
		Path map = temp.resolve("copyhint.map");
		Files.writeString(yaml, COPY_HINT_PREAMBLE + """
			      copied_from:
			        - name: CHRGET
			          start: 0x0073
			          end: 0x008a
			          source: KERNAL
			          source_addr: 0xe3a2
			          entry: 0x0075
			          disassemble: true
			          create_function: true
			          comment: "CHRGET fetch routine"
			""" + COPY_HINT_TAIL);
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });

		JsonObject doc = JsonParser.parseString(Files.readString(map)).getAsJsonObject();
		JsonObject zeropage = doc.getAsJsonArray("regions").get(0).getAsJsonObject();
		JsonObject hint = zeropage.getAsJsonArray("copied_from").get(0).getAsJsonObject();
		assertEquals("copied_from name was not preserved", "CHRGET",
			hint.get("name").getAsString());
		assertEquals("copied_from start was not normalized to a number", 0x0073,
			hint.get("start").getAsInt());
		assertEquals("copied_from end was not normalized to a number", 0x008a,
			hint.get("end").getAsInt());
		assertEquals("copied_from source was not preserved", "KERNAL",
			hint.get("source").getAsString());
		assertEquals("copied_from source_addr was not normalized to a number", 0xe3a2,
			hint.get("source_addr").getAsInt());
		assertEquals("copied_from entry was not normalized to a number", 0x0075,
			hint.get("entry").getAsInt());
		assertTrue("copied_from disassemble was not preserved",
			hint.get("disassemble").getAsBoolean());
		assertTrue("copied_from create_function was not preserved",
			hint.get("create_function").getAsBoolean());
		assertTrue("copied_from comment was not preserved",
			"CHRGET fetch routine".equals(hint.get("comment").getAsString()));
		// Numbers, not strings: DescriptorCopyHintAnalyzer calls getAsLong() on all four.
		for (String key : new String[] { "start", "end", "source_addr", "entry" }) {
			assertTrue(key + " was emitted as a JSON string, not a number",
				hint.get(key).getAsJsonPrimitive().isNumber());
		}
	}

	/** A {@code copied_from} typo must fail the build. A silently-dropped key is exactly the
	 *  failure mode this whitelist has already been bitten by, and at runtime a bad hint looks
	 *  identical to the legitimate "no ROM supplied, directive ignored" skip. */
	@Test
	public void copiedFromErrors() throws Exception {
		Path temp = tmp.getRoot().toPath();
		expectCopyHintError(temp, "copy-bad-source", """
			        - { name: CHRGET, start: 0x0073, end: 0x008a, source: KRENAL, source_addr: 0xe3a2 }
			""", "neither a declared region nor a window occupant");
		expectCopyHintError(temp, "copy-reversed", """
			        - { name: CHRGET, start: 0x008a, end: 0x0073, source: KERNAL, source_addr: 0xe3a2 }
			""", "before start");
		expectCopyHintError(temp, "copy-outside-region", """
			        - { name: CHRGET, start: 0x0073, end: 0x0110, source: KERNAL, source_addr: 0xe3a2 }
			""", "is not inside region 'ZEROPAGE'");
		expectCopyHintError(temp, "copy-entry-outside", """
			        - { name: CHRGET, start: 0x0073, end: 0x008a, source: KERNAL, source_addr: 0xe3a2,
			            entry: 0x0090 }
			""", "not inside the copied range");
	}

	/** grm-p7i: {@code memory.layouts[].when} must name exactly one field, that field must be
	 *  the same across every layout, no two layouts may declare the same when: value, and the
	 *  value must be an integer -- the four rules {@code DescriptorSupport.planWindows}
	 *  enforces at load time by silently discarding {@code memory.layouts[]} rather than
	 *  failing. */
	@Test
	public void layoutWhenErrors() throws Exception {
		Path temp = tmp.getRoot().toPath();
		expectCompileError(temp, "layout-multi-field",
			layoutYaml("{ MODE: 0, OTHER: 1 }", "{ MODE: 1 }"), "exactly one field");
		expectCompileError(temp, "layout-mixed-fields",
			layoutYaml("{ MODE: 0 }", "{ OTHER: 1 }"), "mixes mode fields");
		expectCompileError(temp, "layout-dup-value",
			layoutYaml("{ MODE: 0 }", "{ MODE: 0 }"), "duplicate when");
		expectCompileError(temp, "layout-non-integral",
			layoutYaml("{ MODE: 0.5 }", "{ MODE: 1 }"), "is not an integer");
	}

	/** A two-layout descriptor whose {@code when:} maps are supplied by the caller, otherwise
	 *  minimal and schema-valid; used by {@link #layoutWhenErrors}. */
	private static String layoutYaml(String when1, String when2) {
		return """
			schema: 2
			system: { id: layout, name: Layout, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			  layouts:
			    - when: %s
			      windows:
			        - { name: W, start: 0x8000, end: 0x9fff, occupants: [{ name: BANK0, kind: ram }] }
			    - when: %s
			      windows:
			        - { name: W, start: 0x8000, end: 0x9fff, occupants: [{ name: BANK1, kind: ram }] }
			banking:
			  state: [{ name: MODE, bits: 1 }, { name: OTHER, bits: 1 }]
			  mechanisms:
			    - strategy: register-write
			      params: { address: 0x0001, mask: 0x03 }
			      sets: [MODE, OTHER]
			  initial_state: { MODE: 0, OTHER: 0 }
			""".formatted(when1, when2);
	}

	/** grm-sf6 2a: an unrecognized {@code banking.mechanisms[].strategy} name must fail the
	 *  build, naming the mechanism and the accepted vocabulary, rather than silently shipping
	 *  a mechanism {@code BoardBankAnalyzer} will skip at analysis time. */
	@Test
	public void unknownStrategyErrors() throws Exception {
		Path temp = tmp.getRoot().toPath();
		expectCompileError(temp, "bad-strategy", """
			schema: 2
			system: { id: bad-strategy, name: Bad Strategy, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			banking:
			  state: [{ name: MODE, bits: 1 }]
			  mechanisms:
			    - strategy: registerwrite
			      params: { address: 0x0001, mask: 0x01 }
			      sets: [MODE]
			  initial_state: { MODE: 0 }
			""", "not a recognized strategy name");
	}

	/** grm-sf6 2a: a DEFERRED strategy name (schema-valid, no analyzer support yet) must still
	 *  compile -- it is a deliberate placeholder, not a typo. */
	@Test
	public void deferredStrategyCompiles() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("deferred.yaml");
		Path map = temp.resolve("deferred.map");
		Files.writeString(yaml, """
			schema: 2
			system: { id: deferred, name: Deferred, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			banking:
			  state: [{ name: MODE, bits: 1 }]
			  mechanisms:
			    - strategy: io-port
			      params: { address: 0x0001, mask: 0x01 }
			      sets: [MODE]
			  initial_state: { MODE: 0 }
			""");
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });
		assertTrue("deferred strategy 'io-port' must still compile", Files.exists(map));
	}

	/** grm-sf6 2a: notices drift between {@link MapCompiler#IMPLEMENTED_STRATEGIES} (hard-coded,
	 *  since MapCompiler has no ClassSearcher) and the actual shipped
	 *  {@code BankSwitchStrategy} implementations -- every implementation's own
	 *  {@code strategyName()} must appear in the compiler's set. */
	@Test
	public void strategyVocabularyMatchesImplementations() {
		List<BankSwitchStrategy> implementations = List.of(
			new RegisterWriteBankSwitchStrategy(),
			new MemoryLatchBankSwitchStrategy(),
			new SelectDataBankSwitchStrategy(),
			new SerialShiftBankSwitchStrategy());
		for (BankSwitchStrategy s : implementations) {
			assertTrue("BankSwitchStrategy '" + s.strategyName() +
				"' (" + s.getClass().getSimpleName() +
				") is not in MapCompiler.IMPLEMENTED_STRATEGIES -- update the compiler's " +
				"hard-coded vocabulary to match",
				MapCompiler.IMPLEMENTED_STRATEGIES.contains(s.strategyName()));
		}
		assertEquals("MapCompiler.IMPLEMENTED_STRATEGIES has drifted from the shipped " +
			"BankSwitchStrategy implementations", implementations.size(),
			MapCompiler.IMPLEMENTED_STRATEGIES.size());
	}

	/** grm-sf6 2b: {@code end < start} must fail for a plain region, a top-level window, and a
	 *  subregion; a negative address and an address past the descriptor's declared 16-bit
	 *  address space must likewise fail; and a subregion must lie inside its parent window. */
	@Test
	public void geometryErrors() throws Exception {
		Path temp = tmp.getRoot().toPath();
		expectCompileError(temp, "region-reversed", """
			schema: 2
			system: { id: region-reversed, name: Region Reversed, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0x1000, end: 0x0fff, kind: ram }
			  windows: []
			""", "before start");
		expectCompileError(temp, "region-negative", """
			schema: 2
			system: { id: region-negative, name: Region Negative, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: -1, end: 0x0fff, kind: ram }
			  windows: []
			""", "negative start");
		expectCompileError(temp, "region-overflow", """
			schema: 2
			system: { id: region-overflow, name: Region Overflow, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0x10000, kind: ram }
			  windows: []
			""", "exceeds the descriptor's address space");
		expectCompileError(temp, "window-reversed", """
			schema: 2
			system: { id: window-reversed, name: Window Reversed, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows:
			    - { name: W, start: 0x9fff, end: 0x8000, maps: 'PRG[0]' }
			physical:
			  - { name: PRG, image: prg_rom }
			""", "before start");
		expectCompileError(temp, "subregion-outside-window", """
			schema: 2
			system: { id: sub-outside, name: Sub Outside, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0x0fff, kind: ram }
			  windows:
			    - name: IOWIN
			      start: 0xd000
			      end: 0xdfff
			      occupants:
			        - name: IO
			          kind: io
			          subregions:
			            - { name: REG, start: 0xd000, end: 0xe010, kind: io }
			""", "is not inside its window");
		expectCompileError(temp, "subregion-no-extent", """
			schema: 2
			system: { id: sub-no-extent, name: Sub No Extent, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0x0fff, kind: ram }
			  windows:
			    - name: IOWIN
			      start: 0xd000
			      end: 0xdfff
			      occupants:
			        - name: IO
			          kind: io
			          subregions:
			            - { name: REG, start: 0xd000, kind: io }
			""", "needs 'end:', 'size:', or 'repeat_to:'");
	}

	/** grm-sf6 2b: a 1-byte region ({@code end == start}) is legal. */
	@Test
	public void oneByteRegionCompiles() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("one-byte.yaml");
		Path map = temp.resolve("one-byte.map");
		Files.writeString(yaml, """
			schema: 2
			system: { id: one-byte, name: One Byte, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: P, start: 0, end: 0, kind: io }
			    - { name: RAM, start: 1, end: 0xffff, kind: ram }
			  windows: []
			""");
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });
		assertTrue("a 1-byte region (end == start) must compile", Files.exists(map));
	}

	private static void expectCopyHintError(Path temp, String name, String hints, String part)
			throws Exception {
		expectCompileError(temp, name,
			COPY_HINT_PREAMBLE + "      copied_from:\n" + hints + COPY_HINT_TAIL, part);
	}

	/** A minimal C64-shaped descriptor up to (and including) the ZEROPAGE region's keys; the
	 *  test appends a {@code copied_from:} block and {@link #COPY_HINT_TAIL}. */
	private static final String COPY_HINT_PREAMBLE = """
		schema: 2
		system: { id: copyhint, name: Copy Hint, cpu: { language: '6502:LE:16:default' } }
		memory:
		  regions:
		    - name: ZEROPAGE
		      start: 0x0000
		      end: 0x00ff
		      kind: ram
		""";

	/** The banked $E000 window whose KERNAL occupant the hints above name as their source. */
	private static final String COPY_HINT_TAIL = """
		    - { name: RAM_MAIN, start: 0x0100, end: 0xdfff, kind: ram }
		  windows:
		    - name: HIROM
		      start: 0xe000
		      end: 0xffff
		      occupants:
		        - { name: RAM_E000, kind: ram }
		        - { name: KERNAL, kind: rom }
		banking:
		  state: [{ name: HIRAM, bits: 1 }]
		  mechanisms:
		    - strategy: register-write
		      params: { address: 0x0001, mask: 0x02 }
		      sets: [HIRAM]
		  initial_state: { HIRAM: 1 }
		  states:
		    - { HIRAM: 1, HIROM: KERNAL }
		    - { HIRAM: 0, HIROM: RAM_E000 }
		""";

	// ------------------------------------------------------------------
	// banking.initial_state image-relative expressions (bead grm-y0ml)
	// ------------------------------------------------------------------

	/** A descriptor whose initial_state is literals-only -- every descriptor that shipped
	 *  before grm-y0ml -- must emit EXACTLY what it emitted before: a packed int and no
	 *  initial_state_expr key at all. This is the property that keeps every existing .map
	 *  byte-identical. */
	@Test
	public void literalOnlyInitialStateEmitsNoExpressionKey() throws Exception {
		JsonObject banking = compileBanking("literal-seed", "{ MODE: 1, BANK: 5 }");
		assertEquals(1 | (5 << 1), banking.get("initial_state").getAsInt());
		assertTrue("literal-only initial_state must not emit initial_state_expr",
			!banking.has("initial_state_expr"));
	}

	/** An image-relative field stays SYMBOLIC in the .map (the image size is a load-time
	 *  fact), and the packed literal keeps that field at 0 -- the value an older extension,
	 *  which knows nothing of initial_state_expr, still reads and can use. */
	@Test
	public void imageRelativeInitialStateStaysSymbolic() throws Exception {
		JsonObject banking =
			compileBanking("image-seed", "{ MODE: 1, BANK: \"(image_size >> 13) - 1\" }");
		assertEquals("expression field must contribute 0 to the compiled literal",
			1, banking.get("initial_state").getAsInt());
		assertEquals("(image_size >> 13) - 1",
			banking.getAsJsonObject("initial_state_expr").get("BANK").getAsString());
	}

	/** 'last' is a maps:-only keyword and a BYTE OFFSET; a bank-number field wants neither.
	 *  It must be a compile ERROR here, not a silent pass. */
	@Test
	public void initialStateRejectsLastKeyword() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "seed-last",
			bankingYaml("seed-last", "{ MODE: 0, BANK: \"last\" }"), "image_size");
	}

	/** A state-field name in initial_state is an error too: the seed is resolved before any
	 *  state exists. */
	@Test
	public void initialStateRejectsStateFieldName() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "seed-field",
			bankingYaml("seed-field", "{ MODE: 0, BANK: \"MODE + 1\" }"), "image_size");
	}

	/** The range check the compiler CAN make without an image: an expression that overflows
	 *  the field at every plausible image size is rejected. 'image_size - 0x2000' is the
	 *  mistake this feature invites -- a byte offset written where a bank number belongs. */
	@Test
	public void initialStateRejectsExpressionThatCanNeverFitTheField() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "seed-wide",
			bankingYaml("seed-wide", "{ MODE: 0, BANK: \"image_size - 0x2000\" }"),
			"cannot fit the field's 7 bits");
	}

	/** A field named like an expression keyword would be indistinguishable from it inside an
	 *  expression -- and referencedFields() filters those names out at runtime, so such a
	 *  field would silently disappear from a maps: expression's dependency set. */
	@Test
	public void stateFieldNamedLikeAKeywordIsRejected() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "seed-collide", """
			schema: 2
			system: { id: collide, name: Collide, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			banking:
			  state: [{ name: image_size, bits: 2 }]
			  mechanisms:
			    - strategy: memory-latch
			      params: { start: 0x8000, end: 0xffff, mask: 0x03 }
			      sets: [image_size]
			  initial_state: { image_size: 0 }
			""", "reserved expression keyword");
	}

	// ------------------------------------------------------------------
	// banking.bank_wrap (bead grm-p25h)
	// ------------------------------------------------------------------

	/** Absence emits no key at all -- the property that keeps every pre-grm-p25h .map
	 *  byte-identical, and that makes "nothing wraps" the default for every board. */
	@Test
	public void bankWrapIsAbsentUnlessDeclared() throws Exception {
		assertTrue("a descriptor without bank_wrap must not emit the key",
			!compileBanking("wrap-absent", "{ MODE: 0, BANK: 0 }").has("bank_wrap"));
	}

	@Test
	public void declaredBankWrapIsEmitted() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("wrap-image.yaml");
		Path map = temp.resolve("wrap-image.map");
		Files.writeString(yaml, bankingYaml("wrap-image", "{ MODE: 0, BANK: 0 }")
				.replace("  initial_state:", "  bank_wrap: image\n  initial_state:"));
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });
		assertEquals("image", JsonParser.parseString(Files.readString(map)).getAsJsonObject()
				.getAsJsonObject("banking").get("bank_wrap").getAsString());
	}

	/** The second form: an integer is an EXPLICIT mask, emitted as a JSON number so the runtime
	 *  can tell it apart from the derived 'image' keyword. */
	@Test
	public void explicitBankWrapMaskIsEmittedAsANumber() throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve("wrap-mask.yaml");
		Path map = temp.resolve("wrap-mask.map");
		Files.writeString(yaml, bankingYaml("wrap-mask", "{ MODE: 0, BANK: 0 }")
				.replace("  initial_state:", "  bank_wrap: 0x1f\n  initial_state:"));
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });
		assertEquals(0x1F, JsonParser.parseString(Files.readString(map)).getAsJsonObject()
				.getAsJsonObject("banking").get("bank_wrap").getAsInt());
	}

	/** An unrecognized policy is a compile error, not a pass-through: the runtime would have
	 *  to decide what an unknown wrapping rule means, and there is no safe default. */
	@Test
	public void unknownBankWrapPolicyIsRejected() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "wrap-bogus",
			bankingYaml("wrap-bogus", "{ MODE: 0, BANK: 0 }")
					.replace("  initial_state:", "  bank_wrap: mirror\n  initial_state:"),
			"bank_wrap");
	}

	/** A mask is a contiguous run of LOW bits, so mask + 1 must be a power of two. The runtime
	 *  applies an explicit mask with NO guard, which is exactly why this check lives here. */
	@Test
	public void nonContiguousBankWrapMaskIsRejected() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "wrap-holey",
			bankingYaml("wrap-holey", "{ MODE: 0, BANK: 0 }")
					.replace("  initial_state:", "  bank_wrap: 0x12\n  initial_state:"),
			"not a contiguous run of low bits");
	}

	/** A mask wider than every declared state field could never truncate anything. The widest
	 *  field on this board is BANK at 7 bits, so 0xFF is a no-op and therefore a mistake. */
	@Test
	public void bankWrapMaskWiderThanEveryFieldIsRejected() throws Exception {
		expectCompileError(tmp.getRoot().toPath(), "wrap-wide",
			bankingYaml("wrap-wide", "{ MODE: 0, BANK: 0 }")
					.replace("  initial_state:", "  bank_wrap: 0xff\n  initial_state:"),
			"does not fit any banking.state field");
	}

	/** Compiles a minimal 2-field board with the given {@code initial_state:} value and hands
	 *  back its {@code banking} object. */
	private JsonObject compileBanking(String name, String initialState) throws Exception {
		Path temp = tmp.getRoot().toPath();
		Path yaml = temp.resolve(name + ".yaml");
		Path map = temp.resolve(name + ".map");
		Files.writeString(yaml, bankingYaml(name, initialState));
		MapCompiler.main(new String[] { yaml.toString(), map.toString() });
		return JsonParser.parseString(Files.readString(map)).getAsJsonObject()
				.getAsJsonObject("banking");
	}

	/** A minimal compilable descriptor whose banking has a 1-bit MODE and a 7-bit BANK
	 *  (7 bits so it matches MMC5's bank-register width, the shape this feature exists for). */
	private static String bankingYaml(String id, String initialState) {
		return """
			schema: 2
			system: { id: %s, name: Seed, cpu: { language: '6502:LE:16:default' } }
			memory:
			  regions:
			    - { name: RAM, start: 0, end: 0xffff, kind: ram }
			  windows: []
			banking:
			  state: [{ name: MODE, bits: 1 }, { name: BANK, bits: 7 }]
			  mechanisms:
			    - strategy: memory-latch
			      params: { start: 0x8000, end: 0xffff, mask: 0x7f }
			      sets: [BANK]
			  initial_state: %s
			""".formatted(id, initialState);
	}

	private static void expectCompileError(Path temp, String name, String yamlBody, String part)
			throws Exception {
		Path yaml = temp.resolve(name + ".yaml");
		Files.writeString(yaml, yamlBody);
		Path map = temp.resolve(name + ".map");
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> MapCompiler.main(new String[] { yaml.toString(), map.toString() }));
		assertTrue("expected error containing '" + part + "', got: " + e.getMessage(),
			e.getMessage().contains(part));
	}
}
