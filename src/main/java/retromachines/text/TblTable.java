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
package retromachines.text;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A per-game text table in the ROM-hacking community's {@code .tbl} "table file" format
 * (Nightcrawler's Table File Format standard; bead {@code grm-pqk}). Pure Java with zero Ghidra
 * imports so the grammar and the decoder are plain JUnit-testable.
 *
 * <h2>Supported grammar (MVP)</h2>
 * <ul>
 * <li>{@code # ...} comment lines and blank lines are ignored (a line whose first character is
 * {@code #}); CR/LF/CRLF line endings are all accepted, and a leading BOM is dropped.</li>
 * <li>{@code HH...=text} maps one or more bytes (an even number of hex digits, either case)
 * to display text. The text is everything after the FIRST {@code =} up to the end of the line,
 * verbatim: spaces are significant ({@code 20= } maps a space) and the text may itself contain
 * {@code =} ({@code 3D==}). Lookup is longest-prefix: where {@code 81} and {@code 8140} are both
 * defined, {@code 81 40} decodes as the two-byte entry.</li>
 * <li>{@code /HH=label} defines an <em>end-of-string token</em>: a byte that terminates a
 * string. The label is for display only ({@code <end>}, {@code [END]}...). A single byte only.</li>
 * <li>{@code *HH=label} (legacy linebreak entry) is tolerated: it decodes as a normal
 * single-byte entry rendered as the label and does NOT terminate a string.</li>
 * <li>Rendering an undecodable byte falls back to {@code [$XX]} ({@link #render}).</li>
 * </ul>
 *
 * <h2>Deliberately deferred</h2>
 * {@code $XX=} control codes with parameters and the {@code !}/{@code @}/{@code %} table-switching
 * lines are NOT interpreted; they are skipped and reported in {@link #warnings()} so the user can
 * see the table was only partially understood.
 *
 * <p>A table is immutable once parsed.
 */
public final class TblTable {

	/** Raised for a line that cannot be understood at all (bad hex, missing {@code =}). */
	public static final class TblFormatException extends IllegalArgumentException {
		private static final long serialVersionUID = 1L;

		private final int lineNumber;

		TblFormatException(int lineNumber, String message) {
			super("line " + lineNumber + ": " + message);
			this.lineNumber = lineNumber;
		}

		/** Returns the 1-based line number of the offending line. */
		public int lineNumber() {
			return lineNumber;
		}
	}

	/** One successful longest-prefix match: how many bytes were consumed and what they mean. */
	public record Match(int length, String text, boolean endToken) {
	}

	/** Result of {@link #decodeRun}: a terminated string run. */
	public record Run(int length, String text, int entryCount) {
	}

	private static final int MAX_KEY_LEN = 16;

	private static final char[] HEX = "0123456789ABCDEF".toCharArray();

	private record Entry(String text, boolean endToken) {
	}

	private final Map<String, Entry> entries;
	private final int maxKeyLength;
	/** Bit n set when some entry has a key of exactly n bytes; lets match() skip dead lengths. */
	private final int lengthMask;
	private final List<String> warnings;

	private TblTable(Map<String, Entry> entries, int maxKeyLength, List<String> warnings) {
		this.entries = entries;
		this.maxKeyLength = maxKeyLength;
		int mask = 0;
		for (String key : entries.keySet()) {
			mask |= 1 << (key.length() / 2);
		}
		this.lengthMask = mask;
		this.warnings = warnings;
	}

	/**
	 * Parses table-file text.
	 *
	 * @param text the raw contents of a {@code .tbl} file
	 * @return the parsed table
	 * @throws TblFormatException on a malformed entry line
	 */
	public static TblTable parse(String text) {
		if (text == null) {
			throw new IllegalArgumentException("table text is null");
		}
		if (!text.isEmpty() && text.charAt(0) == '﻿') {
			text = text.substring(1);
		}
		Map<String, Entry> entries = new HashMap<>();
		List<String> warnings = new ArrayList<>();
		int maxLen = 0;
		String[] lines = text.split("\r\n|\r|\n", -1);
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			int lineNo = i + 1;
			if (line.isEmpty() || line.charAt(0) == '#') {
				continue;
			}
			char first = line.charAt(0);
			if (first == '$' || first == '!' || first == '@' || first == '%') {
				warnings.add(
					"line " + lineNo + ": '" + first + "' directive not supported, skipped");
				continue;
			}
			boolean end = false;
			boolean linebreak = false;
			String body = line;
			if (first == '/') {
				end = true;
				body = line.substring(1);
			}
			else if (first == '*') {
				linebreak = true;
				body = line.substring(1);
			}
			int eq = body.indexOf('=');
			if (eq < 0) {
				if (body.isBlank()) {
					continue; // whitespace-only line
				}
				throw new TblFormatException(lineNo, "expected HEX=text but found no '='");
			}
			String key = normalizeHex(body.substring(0, eq).trim(), lineNo);
			String value = body.substring(eq + 1);
			int byteLen = key.length() / 2;
			if (byteLen > MAX_KEY_LEN) {
				throw new TblFormatException(lineNo,
					"entry longer than " + MAX_KEY_LEN + " bytes");
			}
			if ((end || linebreak) && byteLen != 1) {
				throw new TblFormatException(lineNo,
					(end ? "end-token" : "linebreak") + " entry must be a single byte");
			}
			if (entries.containsKey(key)) {
				warnings.add(
					"line " + lineNo + ": duplicate entry " + key + ", last definition wins");
			}
			entries.put(key, new Entry(value, end));
			maxLen = Math.max(maxLen, byteLen);
		}
		return new TblTable(Collections.unmodifiableMap(entries), maxLen,
			Collections.unmodifiableList(warnings));
	}

	private static String normalizeHex(String hex, int lineNo) {
		if (hex.isEmpty() || hex.length() % 2 != 0) {
			throw new TblFormatException(lineNo,
				"hex key '" + hex + "' must have an even, non-zero number of digits");
		}
		for (int i = 0; i < hex.length(); i++) {
			char c = hex.charAt(i);
			if (c > 'f' || Character.digit(c, 16) < 0) {
				throw new TblFormatException(lineNo, "invalid hex digit in key '" + hex + "'");
			}
		}
		return hex.toUpperCase(Locale.ROOT);
	}

	/** Returns the number of entries (text, end-token and linebreak entries together). */
	public int size() {
		return entries.size();
	}

	/** Returns human-readable notes about lines that were skipped or overridden. */
	public List<String> warnings() {
		return warnings;
	}

	/** Returns {@code true} when {@code value} is defined as an end-of-string token. */
	public boolean isEndToken(int value) {
		Entry e = entries.get(String.format("%02X", value & 0xFF));
		return e != null && e.endToken();
	}

	/**
	 * Longest-prefix match at {@code offset}.
	 *
	 * @param data the bytes
	 * @param offset where to match
	 * @return the match, or {@code null} when no entry starts with the bytes there
	 */
	public Match match(byte[] data, int offset) {
		int limit = Math.min(maxKeyLength, data.length - offset);
		for (int len = limit; len >= 1; len--) {
			if ((lengthMask & (1 << len)) == 0) {
				continue;
			}
			Entry e = entries.get(hex(data, offset, len));
			if (e != null) {
				return new Match(len, e.text(), e.endToken());
			}
		}
		return null;
	}

	private static String hex(byte[] data, int offset, int len) {
		char[] out = new char[len * 2];
		for (int i = 0; i < len; i++) {
			int v = data[offset + i] & 0xFF;
			out[2 * i] = HEX[v >> 4];
			out[2 * i + 1] = HEX[v & 0xF];
		}
		return new String(out);
	}

	/**
	 * Renders {@code len} bytes for display: longest-prefix entries become their text (end
	 * tokens included, as their label) and any byte no entry covers becomes {@code [$XX]}.
	 *
	 * @param data the bytes
	 * @param offset first byte to render
	 * @param len number of bytes to render
	 * @return the display text
	 */
	public String render(byte[] data, int offset, int len) {
		StringBuilder sb = new StringBuilder();
		int end = offset + len;
		int p = offset;
		while (p < end) {
			Match m = match(data, p);
			if (m == null || p + m.length() > end) {
				sb.append(String.format("[$%02X]", data[p] & 0xFF));
				p++;
			}
			else {
				sb.append(m.text());
				p += m.length();
			}
		}
		return sb.toString();
	}

	/**
	 * Decodes an end-token-terminated string starting exactly at {@code offset}: consecutive
	 * longest-prefix text entries up to and including the first end token.
	 *
	 * @param data the bytes
	 * @param offset where the run starts
	 * @param maxBytes upper bound on the run's byte length (end token included)
	 * @return the run, or {@code null} when an undecodable byte, the end of data, or
	 *         {@code maxBytes} is reached before an end token, or when the first thing at
	 *         {@code offset} is the end token itself (an empty string). {@link Run#text()}
	 *         excludes the end token's label; {@link Run#length()} includes the end token.
	 */
	public Run decodeRun(byte[] data, int offset, int maxBytes) {
		StringBuilder sb = new StringBuilder();
		int entriesSeen = 0;
		int p = offset;
		int stop = (int) Math.min((long) data.length, (long) offset + maxBytes);
		while (p < stop) {
			Match m = match(data, p);
			if (m == null || p + m.length() > stop) {
				return null;
			}
			p += m.length();
			if (m.endToken()) {
				return entriesSeen == 0 ? null : new Run(p - offset, sb.toString(), entriesSeen);
			}
			sb.append(m.text());
			entriesSeen++;
		}
		return null;
	}
}
