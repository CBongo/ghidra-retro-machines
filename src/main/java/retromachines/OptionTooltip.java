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

import ghidra.util.HTMLUtilities;

/**
 * Builds an import option's description, which 12.2 (GP-6483) shows only as the import dialog's
 * tooltip. A plain-text Swing tooltip is one unbroken line, however long, so the text is wrapped
 * into HTML lines here and the headless usage goes on a line of its own (owner, 2026-10-25,
 * docs/human-research-todo.md 1.8).
 */
final class OptionTooltip {

	/** Characters per tooltip line before wrapping at the next space. */
	static final int WRAP = 70;

	private OptionTooltip() {
	}

	/** A tooltip with no headless line. */
	static String of(String description) {
		return of(description, null);
	}

	/**
	 * {@return {@code description} wrapped into HTML lines, followed by
	 * {@code "Headless: " + headlessUsage} on its own line when {@code headlessUsage} is non-null}
	 */
	static String of(String description, String headlessUsage) {
		StringBuilder html = new StringBuilder("<html>");
		html.append(wrap(description));
		if (headlessUsage != null) {
			html.append("<br>Headless: ").append(HTMLUtilities.escapeHTML(headlessUsage));
		}
		return html.toString();
	}

	private static String wrap(String text) {
		StringBuilder out = new StringBuilder();
		int lineLength = 0;
		for (String word : text.split(" ")) {
			if (lineLength > 0 && lineLength + 1 + word.length() > WRAP) {
				out.append("<br>");
				lineLength = 0;
			}
			else if (lineLength > 0) {
				out.append(' ');
				lineLength++;
			}
			out.append(HTMLUtilities.escapeHTML(word));
			lineLength += word.length();
		}
		return out.toString();
	}
}
