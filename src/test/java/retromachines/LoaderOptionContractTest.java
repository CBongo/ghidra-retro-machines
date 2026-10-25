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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.Loader;

/**
 * The loaders' import options honour the 12.2 (GP-6483) option contract (grm-vrkk.1): every
 * option carries a tooltip description that survives {@link Option#copy()}, and every headless
 * argument is spelled the way {@code ProgramLoader} matches it -- the WHOLE {@code -loader-...}
 * flag, compared case-insensitively against {@link Option#getArg()}.
 */
public class LoaderOptionContractTest extends AbstractBundledLanguageTest {

	private static List<Option> defaults(Loader loader) {
		return loader.getDefaultOptions(new ByteArrayProvider(new byte[0x8010]), null, null,
			true, false);
	}

	private static final Set<String> STOCK_OPTIONS =
		Set.of(AbstractProgramLoader.APPLY_LABELS_OPTION_NAME,
			AbstractProgramLoader.ANCHOR_LABELS_OPTION_NAME);

	private static void assertContract(Loader loader) {
		List<Option> options = defaults(loader);
		assertFalse(loader.getName() + ": no options", options.isEmpty());
		for (Option option : options) {
			String what = loader.getName() + " / " + option.getName();
			String description = option.getDescription();
			assertNotNull(what + ": no description", description);
			assertFalse(what + ": blank description", description.isBlank());
			// Ours only: AbstractProgramLoader's stock label options keep Ghidra's own text.
			if (!STOCK_OPTIONS.contains(option.getName())) {
				assertTrue(what + ": description not built by OptionTooltip (one unwrapped line)",
					description.startsWith("<html>"));
			}
			assertEquals(what + ": copy() dropped the description", description,
				option.copy().getDescription());
			String arg = option.getArg();
			if (arg != null) {
				assertTrue(what + ": arg '" + arg + "' cannot match a -loader- flag",
					arg.startsWith(Loader.COMMAND_LINE_ARG_PREFIX + "-") ||
						arg.equals("-anchorLabels"));
			}
		}
	}

	@Test
	public void nesOptionsHonourContract() {
		assertContract(new NesRomLoader());
	}

	@Test
	public void snesOptionsHonourContract() {
		assertContract(new SnesRomLoader());
	}

	@Test
	public void cbmOptionsHonourContract() {
		assertContract(new C64PrgLoader());
		assertContract(new C128PrgLoader());
		assertContract(new PetPrgLoader());
	}

	/** The arg was the bare "romLayout" until grm-vrkk.1, which no headless flag matched. */
	@Test
	public void snesLayoutArgMatchesHeadlessFlag() {
		Option layout = defaults(new SnesRomLoader()).stream()
				.filter(o -> o.getName().equals(SnesRomLoader.OPTION_LAYOUT))
				.findFirst()
				.orElseThrow();
		assertTrue("-loader-romLayout".equalsIgnoreCase(layout.getArg()));
		assertTrue(layout.parseAndSetValueByType("Off", null));
		assertEquals("Off", layout.getValue());
	}

	@Test
	public void romFileOptionCopyKeepsEverything() {
		RomFileOption option = new RomFileOption("X ROM path", "a/b.bin", "-loader-xRom", "tip");
		RomFileOption copy = option.copy();
		assertEquals("X ROM path", copy.getName());
		assertEquals("a/b.bin", copy.getValue());
		assertEquals("-loader-xRom", copy.getArg());
		assertEquals("tip", copy.getDescription());
	}
}
