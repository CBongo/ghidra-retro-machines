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

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Computed-window {@code maps:} expression evaluation, split out of {@link DescriptorSupport}
 * (QR-12 increment 5): pure string -&gt; long arithmetic over the descriptor schema's expression
 * grammar (docs/MAP_FORMAT.md), with no Ghidra types on the stack at all.
 */
final class DescriptorExpressions {

	private DescriptorExpressions() {
	}

	// ------------------------------------------------------------------
	// Computed-window expressions (constant subset)
	// ------------------------------------------------------------------

	/**
	 * Evaluates a computed-window {@code maps:} expression whose value does not depend
	 * on bank state — integer literals (decimal or 0x hex), {@code last} /
	 * {@code second_last} (byte offsets of the last / second-to-last window-sized bank
	 * in the image), {@code + - * >>} with normal precedence, and parentheses. This
	 * covers every fixed window (NROM's whole map, the fixed banks of UxROM/MMC3).
	 * State-field identifiers throw {@link IllegalArgumentException} — resolving those
	 * is the bank engine's job (M2+), not the loader's.
	 * <p>
	 * {@code >>} (bead {@code grm-hsv.2}, added for MMC1's 32K PRG mode, which ignores
	 * {@code prg_bank}'s LSB: {@code PRG[(prg_bank >> 1) * 0x8000]}) is a logical
	 * right-shift on the running {@code long} accumulator, binding at the SAME
	 * precedence as {@code *} (left-associative, mirroring how {@code *} is folded into
	 * {@link ExprParser#parseProduct}) — deliberately NOT C's looser-than-{@code +-}
	 * shift precedence, since this grammar has no use case that needs the distinction
	 * and a single, easy-to-state rule ("*, >> chain left-to-right, both bind tighter
	 * than + -") is less surprising here than importing C's historical quirk.
	 * Parenthesize when mixing {@code >>} with {@code *} if a specific grouping is
	 * required. Divide ({@code /}) was considered and rejected: MMC1's actual hardware
	 * operation is a bit shift, and {@code >>} makes that literal rather than relying on
	 * integer-division truncation to coincidentally match.
	 *
	 * @param expr       the expression text from the map's {@code maps.expr}
	 * @param imageSize  size in bytes of the physical space's image
	 * @param windowSize size in bytes of the window being mapped
	 * @return byte offset into the physical space
	 */
	static long evalConstantExpr(String expr, long imageSize, long windowSize) {
		return evalExpr(expr, imageSize, windowSize, Map.of());
	}

	/**
	 * Evaluates a computed-window {@code maps:} expression with concrete values bound
	 * to the bank-state fields it references — the bank-dependent complement of
	 * {@link #evalConstantExpr}, used to place switchable windows (one evaluation per
	 * candidate bank value) and to resolve a reference's effective target bank.
	 * Identifiers not in {@code env} (and not {@code last}/{@code second_last}) throw
	 * {@link IllegalArgumentException}.
	 */
	static long evalExpr(String expr, long imageSize, long windowSize, Map<String, Long> env) {
		ExprParser p = new ExprParser(expr, imageSize, windowSize, env);
		long v = p.parseSum();
		p.expectEnd();
		return v;
	}

	/**
	 * The state-field identifiers a {@code maps:} expression references (everything that
	 * is not a number or the {@code last}/{@code second_last} keywords). The MapCompiler
	 * already validated each against the descriptor's {@code banking.state} tuple.
	 */
	static Set<String> referencedFields(String expr) {
		Set<String> fields = new LinkedHashSet<>();
		Matcher m = IDENT.matcher(expr);
		while (m.find()) {
			String ident = m.group();
			if (!ident.equals("last") && !ident.equals("second_last")) {
				fields.add(ident);
			}
		}
		return fields;
	}

	// lookbehind keeps the 'x4000' inside a hex literal from matching as an identifier
	private static final Pattern IDENT = Pattern.compile("(?<!\\w)[A-Za-z_]\\w*");

	/** Minimal recursive-descent parser for {@code maps:} expressions. */
	private static final class ExprParser {
		private final String expr;
		private final long imageSize;
		private final long windowSize;
		private final Map<String, Long> env;
		private int pos;

		ExprParser(String expr, long imageSize, long windowSize, Map<String, Long> env) {
			this.expr = expr;
			this.imageSize = imageSize;
			this.windowSize = windowSize;
			this.env = env;
		}

		long parseSum() {
			long v = parseProduct();
			while (true) {
				skipSpace();
				if (eat('+')) {
					v += parseProduct();
				}
				else if (eat('-')) {
					v -= parseProduct();
				}
				else {
					return v;
				}
			}
		}

		long parseProduct() {
			long v = parseFactor();
			while (true) {
				skipSpace();
				if (eat('*')) {
					v *= parseFactor();
				}
				else if (eatShr()) {
					v >>>= parseFactor();
				}
				else {
					return v;
				}
			}
		}

		/** Matches the two-character {@code >>} operator (not a bare {@code >}, which
		 *  this grammar has no other use for and so leaves unrecognized). */
		private boolean eatShr() {
			if (pos + 1 < expr.length() && expr.charAt(pos) == '>' && expr.charAt(pos + 1) == '>') {
				pos += 2;
				return true;
			}
			return false;
		}

		long parseFactor() {
			skipSpace();
			if (eat('(')) {
				long v = parseSum();
				skipSpace();
				if (!eat(')')) {
					throw new IllegalArgumentException("unbalanced parentheses in '" + expr + "'");
				}
				return v;
			}
			if (pos < expr.length() && Character.isDigit(expr.charAt(pos))) {
				return parseNumber();
			}
			String ident = parseIdent();
			switch (ident) {
				case "last":
					return imageSize - windowSize;
				case "second_last":
					return imageSize - 2 * windowSize;
				default:
					Long bound = env.get(ident);
					if (bound != null) {
						return bound;
					}
					throw new IllegalArgumentException("expression '" + expr +
						"' depends on bank state ('" + ident +
						"'); only constant windows can be placed at load time");
			}
		}

		private long parseNumber() {
			int start = pos;
			if (expr.startsWith("0x", pos) || expr.startsWith("0X", pos)) {
				pos += 2;
				while (pos < expr.length() && isHexDigit(expr.charAt(pos))) {
					pos++;
				}
				return Long.parseLong(expr.substring(start + 2, pos), 16);
			}
			while (pos < expr.length() && Character.isDigit(expr.charAt(pos))) {
				pos++;
			}
			return Long.parseLong(expr.substring(start, pos));
		}

		private String parseIdent() {
			int start = pos;
			while (pos < expr.length() &&
				(Character.isLetterOrDigit(expr.charAt(pos)) || expr.charAt(pos) == '_')) {
				pos++;
			}
			if (pos == start) {
				throw new IllegalArgumentException(
					"malformed expression '" + expr + "' at offset " + pos);
			}
			return expr.substring(start, pos);
		}

		private static boolean isHexDigit(char c) {
			return Character.digit(c, 16) >= 0;
		}

		private void skipSpace() {
			while (pos < expr.length() && Character.isWhitespace(expr.charAt(pos))) {
				pos++;
			}
		}

		private boolean eat(char c) {
			if (pos < expr.length() && expr.charAt(pos) == c) {
				pos++;
				return true;
			}
			return false;
		}

		void expectEnd() {
			skipSpace();
			if (pos != expr.length()) {
				throw new IllegalArgumentException(
					"trailing garbage in expression '" + expr + "' at offset " + pos);
			}
		}
	}
}
