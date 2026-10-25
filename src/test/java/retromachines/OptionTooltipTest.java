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
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** {@link OptionTooltip}: wrapped HTML lines, headless usage on its own line, text escaped. */
public class OptionTooltipTest {

	@Test
	public void shortTextIsOneLine() {
		assertEquals("<html>Short text.", OptionTooltip.of("Short text."));
	}

	@Test
	public void headlessUsageGoesOnItsOwnLineEscaped() {
		assertEquals("<html>Pick a file.<br>Headless: -loader-tbl &lt;path&gt;",
			OptionTooltip.of("Pick a file.", "-loader-tbl <path>"));
	}

	@Test
	public void longTextWrapsAtWordBoundaries() {
		String text = "word ".repeat(40).trim();
		String html = OptionTooltip.of(text).substring("<html>".length());
		String[] lines = html.split("<br>");
		assertTrue("expected wrapping", lines.length > 1);
		for (String line : lines) {
			assertTrue("line too long: " + line, line.length() <= OptionTooltip.WRAP);
			assertFalse("line has edge space: '" + line + "'",
				line.startsWith(" ") || line.endsWith(" "));
		}
		assertEquals(text, html.replace("<br>", " "));
	}

	@Test
	public void descriptionTextIsEscaped() {
		assertEquals("<html>ROM in the $80-$FF banks &amp; IO",
			OptionTooltip.of("ROM in the $80-$FF banks & IO"));
	}
}
