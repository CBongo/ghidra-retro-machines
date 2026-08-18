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
package retromachines.corpus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the hand-annotated SPC700 disassembly listings in the project owner's
 * game-music-extraction working tree (bead grm-uy9s). One instance is one {@code *spc.dis} file.
 *
 * <p><b>These listings are NOT an oracle.</b> The 2000-2001 era disassembler that produced them
 * may or may not be as accurate as Ghidra's, so a disagreement between a listing and our output
 * is a question, not a verdict, and which side is wrong is open in every instance. Nothing here
 * should be read as "expected" in the golden-file sense; see the bead for the full framing.
 *
 * <p><b>Line grammar.</b> Every data-bearing line is {@code AAAA bb bb bb   TEXT ; comment},
 * where the byte column is blank-padded to a fixed width that varies per file (som/ct/ff5 pad
 * with spaces, ff3/lem use a tab). Rather than depend on that width, the tokenizer consumes
 * whitespace-separated two-hex-digit tokens greedily and stops at the first token that is not
 * one. That is unambiguous here because no SPC700 mnemonic is two hex digits -- the shortest are
 * {@code EI}/{@code DI}/{@code OR}, none of which is spellable in {@code [0-9A-F]{2}} form (I and
 * R are not hex digits) -- so a mnemonic can never be mistaken for another byte.
 *
 * <p>Three line kinds result:
 * <ul>
 * <li>{@link Kind#CODE} -- bytes followed by mnemonic text.
 * <li>{@link Kind#DATA} -- bytes with no mnemonic text. This is the listing's own code/data
 *     separation, and is an asset independent of whether the mnemonics agree: a fresh Ghidra
 *     import of an SPC image has no such map. Two sub-forms appear: a bare pointer-table entry
 *     carrying an index comment ({@code 1418 63 12  ; 00}) and a bulk hex dump of 16 bytes per
 *     line with a double space every four ({@code 15D8 00 00 00 00  00 00 01 00 ...}).
 * <li>{@link Kind#NARRATIVE} -- a whole line of prose with no address, either a section heading
 *     ({@code ; vcmd dispatch table (D2-FF)}) or a tool banner ({@code SPC700 Disassembler
 *     v0.1}). Retained with the address of the next data-bearing line so headings can be
 *     attributed to the region they introduce.
 * </ul>
 */
public final class DisListing {

	/** What a parsed line turned out to be; see the class doc. */
	public enum Kind {
		CODE, DATA, NARRATIVE
	}

	/**
	 * One parsed line. {@code address} and {@code bytes} are meaningless for {@link
	 * Kind#NARRATIVE} ({@code address} carries the following line's address, or -1 at EOF, and
	 * {@code bytes} is empty). {@code text} is the mnemonic-and-operands field with surrounding
	 * whitespace collapsed to single spaces; {@code comment} is everything after the first
	 * {@code ;}, trimmed, or null when the line carried none.
	 */
	public record Row(int lineNumber, Kind kind, int address, byte[] bytes, String text,
			String comment) {

		/** The listing's own claim about this instruction's length, in bytes. */
		public int length() {
			return bytes.length;
		}

		public String byteText() {
			StringBuilder sb = new StringBuilder();
			for (byte b : bytes) {
				if (sb.length() > 0) {
					sb.append(' ');
				}
				sb.append(String.format("%02X", b & 0xff));
			}
			return sb.toString();
		}
	}

	private final String name;
	private final List<Row> rows;
	private final int[] image;
	private final int minAddress;
	private final int maxAddress;
	private final List<Integer> conflicts;

	private DisListing(String name, List<Row> rows, int[] image, int minAddress, int maxAddress,
			List<Integer> conflicts) {
		this.name = name;
		this.rows = rows;
		this.image = image;
		this.minAddress = minAddress;
		this.maxAddress = maxAddress;
		this.conflicts = conflicts;
	}

	/**
	 * Reads and parses one listing. Decoded as latin-1 deliberately: these are 2001-era files
	 * with occasional high-bit bytes in comments, and latin-1 is the only encoding that cannot
	 * throw on them.
	 */
	public static DisListing parse(Path file) throws IOException {
		List<String> lines = Files.readAllLines(file, StandardCharsets.ISO_8859_1);
		List<Row> rows = new ArrayList<>();
		List<Integer> pendingNarrative = new ArrayList<>();
		Map<Integer, Integer> written = new HashMap<>();
		int[] image = new int[0x10000];
		int min = Integer.MAX_VALUE;
		int max = -1;
		List<Integer> conflicts = new ArrayList<>();

		for (int i = 0; i < lines.size(); i++) {
			String line = stripTrailing(lines.get(i));
			int lineNumber = i + 1;
			if (line.isBlank()) {
				continue;
			}
			Row row = parseLine(lineNumber, line);
			if (row == null) {
				// Prose with no address column. Hold it until the next addressed line so the
				// heading can be attributed to the region it introduces.
				rows.add(new Row(lineNumber, Kind.NARRATIVE, -1, new byte[0], "",
					line.startsWith(";") ? line.substring(1).trim() : line.trim()));
				pendingNarrative.add(rows.size() - 1);
				continue;
			}
			for (int idx : pendingNarrative) {
				Row n = rows.get(idx);
				rows.set(idx, new Row(n.lineNumber(), n.kind(), row.address(), n.bytes(),
					n.text(), n.comment()));
			}
			pendingNarrative.clear();
			rows.add(row);

			for (int b = 0; b < row.bytes().length; b++) {
				int a = (row.address() + b) & 0xffff;
				int value = row.bytes()[b] & 0xff;
				Integer prior = written.put(a, value);
				if (prior != null && prior != value) {
					conflicts.add(a);
				}
				image[a] = value;
				min = Math.min(min, a);
				max = Math.max(max, a);
			}
		}
		String name = file.getFileName().toString();
		return new DisListing(name, List.copyOf(rows), image, min == Integer.MAX_VALUE ? 0 : min,
			max, List.copyOf(conflicts));
	}

	/** Returns null when the line has no {@code AAAA } address column. */
	private static Row parseLine(int lineNumber, String line) {
		if (line.length() < 5 || !isHex(line, 0, 4) || line.charAt(4) != ' ') {
			return null;
		}
		int address = Integer.parseInt(line.substring(0, 4), 16);
		int pos = 5;
		List<Byte> bytes = new ArrayList<>();
		while (true) {
			while (pos < line.length() && line.charAt(pos) == ' ') {
				pos++;
			}
			if (pos + 2 > line.length() || !isHex(line, pos, 2)) {
				break;
			}
			// A two-hex-digit token only counts as a byte if it really is a whole token; a
			// mnemonic like "ADC" starts with two hex digits but continues into a third char.
			int end = pos + 2;
			if (end < line.length() && line.charAt(end) != ' ' && line.charAt(end) != '\t') {
				break;
			}
			bytes.add((byte) Integer.parseInt(line.substring(pos, end), 16));
			pos = end;
		}
		String rest = line.substring(Math.min(pos, line.length())).trim();
		String text;
		String comment;
		int semi = rest.indexOf(';');
		if (semi >= 0) {
			text = rest.substring(0, semi).trim();
			comment = rest.substring(semi + 1).trim();
			if (comment.isEmpty()) {
				comment = null;
			}
		}
		else {
			text = rest;
			comment = null;
		}
		text = text.replaceAll("\\s+", " ");
		byte[] raw = new byte[bytes.size()];
		for (int i = 0; i < raw.length; i++) {
			raw[i] = bytes.get(i);
		}
		// A mnemonic always starts with a letter. Anything else in the text column is a hand
		// annotation on a data row, not an instruction -- lem/lemspc.dis labels its CPU-command
		// jump table with a bare "- F0" rather than the ";  F0" the other listings use, and
		// without this those sixteen table entries parse as sixteen bogus instructions.
		boolean isCode = !text.isEmpty() && Character.isLetter(text.charAt(0));
		if (!isCode && !text.isEmpty()) {
			comment = comment == null ? text : text + " ; " + comment;
			text = "";
		}
		return new Row(lineNumber, isCode ? Kind.CODE : Kind.DATA, address, raw, text, comment);
	}

	private static boolean isHex(String s, int from, int len) {
		if (from + len > s.length()) {
			return false;
		}
		for (int i = from; i < from + len; i++) {
			if (Character.digit(s.charAt(i), 16) < 0) {
				return false;
			}
		}
		return true;
	}

	private static String stripTrailing(String s) {
		int end = s.length();
		while (end > 0 && (s.charAt(end - 1) == '\r' || s.charAt(end - 1) == '\n')) {
			end--;
		}
		return s.substring(0, end);
	}

	public String name() {
		return name;
	}

	public List<Row> rows() {
		return rows;
	}

	public int minAddress() {
		return minAddress;
	}

	public int maxAddress() {
		return maxAddress;
	}

	/**
	 * Addresses whose image byte was written twice with <em>different</em> values, so a flat 64K
	 * image cannot represent both. Two causes, and only the caller can tell them apart, which is
	 * why this is reported rather than thrown: a driver that genuinely uploads overlapping
	 * blocks (in which case the comparison over that region means nothing), or a one-byte slip
	 * in the listing's own address column. Both instances measured across the corpus are the
	 * latter and both land in data -- {@code ctspc.dis} dumps a 13-byte row at {@code $1D87}
	 * where the next row starts at {@code $1D93}, and {@code mariospc.dis} labels a pad byte
	 * {@code 12F0} directly after a pointer that already ends there.
	 */
	public List<Integer> conflicts() {
		return conflicts;
	}

	/** The flat 64K image assembled from every row's bytes; uncovered addresses read as 0. */
	public byte[] imageBytes(int from, int to) {
		byte[] out = new byte[to - from + 1];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) image[from + i];
		}
		return out;
	}
}
