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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Pure, Ghidra-free discovery of headerless indirect-threaded Forth words in a byte image
 * (bead grm-arbi.2), driven by a {@link ForthConfig}. Sees memory as a
 * {@link CbmAutostart.Bytes} function, so it is testable without a {@code Program}.
 * <p>
 * Discovery rules (precision over recall):
 * <ul>
 * <li>Candidate colon words are every address whose 16-bit value is the DOCOL value; candidate
 * handler words are every address holding a handler value. Names, exits and inline words are
 * declared seeds.</li>
 * <li>A colon candidate is accepted only if walking its body succeeds: every cell is a known
 * word (declared, a self-pointing code word, a handler word, or recursively a valid colon
 * word) or a declared inline operand, and the body ends at an exit cell, continuing past an
 * exit while a forward branch targets beyond it. A DOCOL value sitting in data fails this and
 * is logged, never turned into a word.</li>
 * <li>A candidate that lies inside another accepted word's body (for example the operand of a
 * LIT that happens to equal DOCOL) loses to the outer word unless it is named or referenced.</li>
 * <li>Handler words and undeclared code words are accepted only when named or referenced from
 * an accepted thread.</li>
 * </ul>
 */
public final class ForthThreads {

	private static final int MAX_BODY_CELLS = 2048;

	private ForthThreads() {
	}

	/** Kind of word. */
	public enum Kind {
		/** Machine code; the code field points at the code. */
		CODE,
		/** Colon definition: body is a thread of cells. */
		COLON,
		/** DOCON: one 16-bit constant in the parameter field. */
		CONSTANT,
		/** DOVAR: parameter field is data. */
		VARIABLE,
		/** DOUSER: parameter field is a user-area offset. */
		USER,
		/** DODOES: parameter field is [does-thread][data]. */
		DOES
	}

	/** Kind of thread cell. */
	public enum Op {
		/** A word reference; {@code value} is the CFA. */
		WORD,
		/** An inline 16-bit literal (or data cell); {@code value} is the operand. */
		LIT,
		/** An inline signed branch offset; {@code value} is the offset, {@code target} absolute. */
		BRANCH,
		/** An inline counted string; {@code value} is the count, {@code text} the characters. */
		STRING
	}

	/**
	 * One decoded cell of a thread.
	 *
	 * @param addr address of the first byte of the cell
	 * @param op what it is
	 * @param value CFA, literal, offset or count according to {@code op}
	 * @param target absolute branch target ({@code BRANCH} only, else -1)
	 * @param text string characters ({@code STRING} only, else null)
	 */
	public record Cell(int addr, Op op, int value, int target, String text) {
		/** Number of bytes the cell occupies. */
		public int length() {
			return op == Op.STRING ? 1 + value : 2;
		}
	}

	/**
	 * A discovered word.
	 *
	 * @param cfa code-field address
	 * @param kind the kind
	 * @param name declared name or null
	 * @param comment declared stack comment or null
	 * @param codeAddr CODE: address of the machine code; DOES: the does-thread address; else -1
	 * @param param CONSTANT/USER: the operand value; else -1
	 * @param body COLON: the decoded body
	 * @param doesBody DOES: the decoded does-thread (empty if it did not walk)
	 */
	public record Word(int cfa, Kind kind, String name, String comment, int codeAddr, int param,
			List<Cell> body, List<Cell> doesBody) {
		/** Address just past the last body byte (colon words), else {@code cfa + 2}. */
		public int bodyEnd() {
			if (body.isEmpty()) {
				return cfa + 2;
			}
			Cell last = body.get(body.size() - 1);
			return last.addr() + last.length();
		}
	}

	/**
	 * Result of a walk.
	 *
	 * @param words accepted words by CFA
	 * @param log one line per rejected candidate or oddity
	 * @param handlers addresses that are handler/docol code entries mapped to a label stem
	 * @param exits the exit CFAs, for rendering
	 */
	public record Result(Map<Integer, Word> words, List<String> log,
			Map<Integer, String> handlers, Set<Integer> exits) {
		/**
		 * The display label of a CFA: its declared name, else {@code FORTH_xxxx}.
		 *
		 * @param cfa a code-field address
		 * @return the display name
		 */
		public String label(int cfa) {
			Word w = words.get(cfa);
			return w != null && w.name() != null ? w.name() : fallbackName(cfa);
		}
	}

	/** {@code FORTH_xxxx} for an unnamed word. */
	public static String fallbackName(int cfa) {
		return String.format(Locale.ROOT, "FORTH_%04X", cfa);
	}

	private static String hex(int v) {
		return String.format(Locale.ROOT, "$%04X", v & 0xFFFF);
	}

	private static final class Walker {
		final ForthConfig cfg;
		final CbmAutostart.Bytes mem;
		final List<String> log = new ArrayList<>();
		final Map<Integer, List<Cell>> colon = new HashMap<>(); // valid colon bodies
		final Set<Integer> invalid = new HashSet<>();
		final Set<Integer> inProgress = new HashSet<>();
		final Set<Integer> referenced = new HashSet<>();

		Walker(ForthConfig cfg, CbmAutostart.Bytes mem) {
			this.cfg = cfg;
			this.mem = mem;
		}

		int word(int a) {
			if (a < 0 || a > 0xFFFE) {
				return -1;
			}
			int lo = mem.at(a);
			int hi = mem.at(a + 1);
			return lo < 0 || hi < 0 ? -1 : lo | hi << 8;
		}

		boolean declared(int c) {
			return cfg.names().containsKey(c) || cfg.isExit(c) || cfg.inline().containsKey(c);
		}

		/** Is {@code c} a word CFA we trust enough to appear in a thread? */
		boolean isWord(int c) {
			int v = word(c);
			if (v < 0) {
				return false;
			}
			if (v == cfg.docol()) {
				return validColon(c);
			}
			if (cfg.handlers().containsKey(v)) {
				return word(c + 2) >= 0;
			}
			if (declared(c)) {
				return true;
			}
			return v == c + 2 && mem.at(c + 2) >= 0;
		}

		boolean validColon(int cfa) {
			if (colon.containsKey(cfa)) {
				return true;
			}
			if (invalid.contains(cfa)) {
				return false;
			}
			if (!inProgress.add(cfa)) {
				return true; // optimistic for recursion
			}
			String[] why = new String[1];
			List<Cell> body = walkThread(cfa + 2, why);
			inProgress.remove(cfa);
			if (body == null) {
				invalid.add(cfa);
				log.add("rejected colon candidate " + hex(cfa) + ": " + why[0]);
				return false;
			}
			colon.put(cfa, body);
			return true;
		}

		/** Walks a thread from {@code start}; null (with reason) on failure. */
		List<Cell> walkThread(int start, String[] why) {
			List<Cell> cells = new ArrayList<>();
			int a = start;
			int maxTarget = -1;
			for (int n = 0; n < MAX_BODY_CELLS; n++) {
				int c = word(a);
				if (c < 0) {
					why[0] = "unreadable cell at " + hex(a);
					return null;
				}
				boolean ok = isWordInThread(c);
				if (!ok) {
					why[0] = "cell " + hex(c) + " at " + hex(a) + " is not a word";
					return null;
				}
				cells.add(new Cell(a, Op.WORD, c, -1, null));
				a += 2;
				ForthConfig.InlineMode mode = cfg.inline().get(c);
				if (mode != null) {
					switch (mode) {
						case LIT16, CELL16 -> {
							int v = word(a);
							if (v < 0) {
								why[0] = "unreadable literal at " + hex(a);
								return null;
							}
							cells.add(new Cell(a, Op.LIT, v, -1, null));
							a += 2;
						}
						case BRANCH -> {
							int v = word(a);
							if (v < 0) {
								why[0] = "unreadable branch offset at " + hex(a);
								return null;
							}
							int off = (short) v;
							int target = (a + off) & 0xFFFF;
							if (mem.at(target) < 0) {
								why[0] = "branch at " + hex(a) + " targets " + hex(target) +
									" outside the image";
								return null;
							}
							cells.add(new Cell(a, Op.BRANCH, off, target, null));
							maxTarget = Math.max(maxTarget, target);
							a += 2;
						}
						case COUNTED_STRING -> {
							int count = mem.at(a);
							if (count < 0 || mem.at(a + count) < 0) {
								why[0] = "unreadable string at " + hex(a);
								return null;
							}
							StringBuilder sb = new StringBuilder();
							for (int i = 1; i <= count; i++) {
								sb.append(printable(mem.at(a + i)));
							}
							cells.add(new Cell(a, Op.STRING, count, -1, sb.toString()));
							a += 1 + count;
						}
					}
				}
				if (cfg.isExit(c) && maxTarget < a) {
					return cells;
				}
			}
			why[0] = "no exit within " + MAX_BODY_CELLS + " cells";
			return null;
		}

		boolean isWordInThread(int c) {
			if (!isWord(c)) {
				return false;
			}
			referenced.add(c);
			return true;
		}
	}

	private static String printable(int b) {
		if (b >= 0x20 && b < 0x7F && b != '"' && b != '\\') {
			return String.valueOf((char) b);
		}
		return String.format(Locale.ROOT, "\\x%02X", b);
	}

	/**
	 * Discovers the words of {@code cfg} in {@code mem}.
	 *
	 * @param cfg the runtime description
	 * @param mem the image
	 * @return the accepted words and the log of rejected candidates
	 */
	public static Result walk(ForthConfig cfg, CbmAutostart.Bytes mem) {
		Walker w = new Walker(cfg, mem);
		// 1. candidates by scanning
		List<Integer> colonCands = new ArrayList<>();
		List<Integer> handlerCands = new ArrayList<>();
		for (int a = 0; a < 0xFFFF; a++) {
			int v = w.word(a);
			if (v < 0) {
				continue;
			}
			if (v == cfg.docol()) {
				colonCands.add(a);
			}
			else if (cfg.handlers().containsKey(v)) {
				handlerCands.add(a);
			}
		}
		for (Integer c : cfg.names().keySet()) {
			if (w.word(c) == cfg.docol() && !colonCands.contains(c)) {
				colonCands.add(c);
			}
		}
		// 2. validate colon candidates
		List<Integer> valid = new ArrayList<>();
		for (int c : colonCands) {
			if (w.validColon(c)) {
				valid.add(c);
			}
		}
		// 3. resolve overlaps: preferred = named/declared, then referenced, then address order
		java.util.Comparator<Integer> pref = (x, y) -> {
			int rx = rank(w, x);
			int ry = rank(w, y);
			return rx != ry ? Integer.compare(rx, ry) : Integer.compare(x, y);
		};
		valid.sort(pref);
		TreeMap<Integer, Integer> spans = new TreeMap<>(); // start -> end (exclusive)
		Map<Integer, Word> out = new TreeMap<>();
		for (int cfa : valid) {
			List<Cell> body = w.colon.get(cfa);
			Cell last = body.get(body.size() - 1);
			int end = last.addr() + last.length();
			if (overlaps(spans, cfa, end)) {
				w.log.add("rejected colon candidate " + hex(cfa) +
					": lies inside another accepted word");
				continue;
			}
			spans.put(cfa, end);
			out.put(cfa, new Word(cfa, Kind.COLON, nameOf(cfg, cfa), commentOf(cfg, cfa), -1, -1,
				body, List.of()));
		}
		// 4. handler words and code words: declared, or referenced from an accepted thread
		Set<Integer> refd = new HashSet<>();
		for (Word cw : out.values()) {
			for (Cell c : cw.body()) {
				if (c.op() == Op.WORD) {
					refd.add(c.value());
				}
			}
		}
		for (int c : handlerCands) {
			if (out.containsKey(c) || (!refd.contains(c) && !w.declared(c))) {
				continue;
			}
			if (overlaps(spans, c, c + 2)) {
				continue;
			}
			addHandlerWord(w, cfg, out, c);
		}
		// does-threads may reference more words
		for (Word hw : List.copyOf(out.values())) {
			if (hw.kind() == Kind.DOES) {
				for (Cell c : hw.doesBody()) {
					if (c.op() == Op.WORD) {
						refd.add(c.value());
					}
				}
			}
		}
		List<Integer> codeSeeds = new ArrayList<>(refd);
		codeSeeds.addAll(cfg.names().keySet());
		codeSeeds.addAll(cfg.exit());
		codeSeeds.addAll(cfg.inline().keySet());
		for (int c : codeSeeds) {
			if (out.containsKey(c)) {
				continue;
			}
			int v = w.word(c);
			if (v < 0 || v == cfg.docol() || cfg.handlers().containsKey(v)) {
				continue;
			}
			if (v != c + 2 && !w.declared(c)) {
				continue;
			}
			out.put(c, new Word(c, Kind.CODE, nameOf(cfg, c), commentOf(cfg, c), v, -1,
				List.of(), List.of()));
		}
		Map<Integer, String> handlers = new TreeMap<>();
		if (cfg.next() >= 0) {
			handlers.put(cfg.next(), "NEXT");
		}
		handlers.put(cfg.docol(), "DOCOL");
		Map<ForthConfig.Role, Integer> perRole = new HashMap<>();
		cfg.handlers().values().forEach(h -> perRole.merge(h.role(), 1, Integer::sum));
		new TreeMap<>(cfg.handlers()).forEach((addr, h) -> handlers.put(addr,
			perRole.get(h.role()) > 1 ? h.role().name() + "_" + String.format("%04X", addr)
					: h.role().name()));
		return new Result(out, List.copyOf(w.log), handlers, Set.copyOf(cfg.exit()));
	}

	private static void addHandlerWord(Walker w, ForthConfig cfg, Map<Integer, Word> out,
			int cfa) {
		ForthConfig.Handler h = cfg.handlers().get(w.word(cfa));
		int p = w.word(cfa + 2);
		String name = nameOf(cfg, cfa);
		String comment = commentOf(cfg, cfa);
		switch (h.role()) {
			case DOCON -> out.put(cfa, new Word(cfa, Kind.CONSTANT, name, comment, -1, p,
				List.of(), List.of()));
			case DOVAR -> out.put(cfa, new Word(cfa, Kind.VARIABLE, name, comment, -1, -1,
				List.of(), List.of()));
			case DOUSER -> out.put(cfa, new Word(cfa, Kind.USER, name, comment, -1, p,
				List.of(), List.of()));
			case DODOES -> {
				String[] why = new String[1];
				List<Cell> thread = w.walkThread(p, why);
				if (thread == null) {
					w.log.add("does-thread of " + hex(cfa) + " at " + hex(p) +
						" did not walk: " + why[0]);
					thread = List.of();
				}
				out.put(cfa, new Word(cfa, Kind.DOES, name, comment, p, -1, List.of(), thread));
			}
		}
	}

	private static boolean overlaps(TreeMap<Integer, Integer> spans, int start, int end) {
		Map.Entry<Integer, Integer> before = spans.floorEntry(start);
		if (before != null && before.getValue() > start) {
			return true;
		}
		Integer after = spans.ceilingKey(start);
		return after != null && after < end;
	}

	private static int rank(Walker w, int cfa) {
		if (w.cfg.names().containsKey(cfa)) {
			return 0;
		}
		return w.referenced.contains(cfa) ? 1 : 2;
	}

	private static String nameOf(ForthConfig cfg, int cfa) {
		ForthConfig.Name n = cfg.names().get(cfa);
		return n == null ? null : n.name();
	}

	private static String commentOf(ForthConfig cfg, int cfa) {
		ForthConfig.Name n = cfg.names().get(cfa);
		return n == null ? null : n.comment();
	}

	// ------------------------------------------------------------------ rendering

	/**
	 * Renders a colon word as Forth source, e.g.
	 * {@code : NAME  DUP 0BRANCH L1 LIT $0003 L1: + ; }.
	 * Branch targets inside the body become local labels {@code L1}, {@code L2}... numbered in
	 * address order and marked as {@code Ln:} before the cell they name; a target outside the
	 * body prints as a bare address.
	 *
	 * @param word a COLON word
	 * @param r the walk result (for names)
	 * @return the rendering, with a trailing space
	 */
	public static String render(Word word, Result r) {
		return ": " + r.label(word.cfa()) + "  " + renderThread(word.body(), r);
	}

	/**
	 * Renders a DODOES word: its parameter layout and its does-thread.
	 *
	 * @param word a DOES word
	 * @param r the walk result
	 * @return the rendering
	 */
	public static String renderDoes(Word word, Result r) {
		return "CREATE " + r.label(word.cfa()) + "  DOES> " + renderThread(word.doesBody(), r);
	}

	/** Renders a cell list; the final EXIT cell prints as {@code ;}. */
	static String renderThread(List<Cell> cells, Result r) {
		TreeMap<Integer, Integer> labels = new TreeMap<>();
		Set<Integer> starts = new HashSet<>();
		for (Cell c : cells) {
			starts.add(c.addr());
		}
		for (Cell c : cells) {
			if (c.op() == Op.BRANCH && starts.contains(c.target())) {
				labels.put(c.target(), 0);
			}
		}
		int n = 1;
		for (Map.Entry<Integer, Integer> e : labels.entrySet()) {
			e.setValue(n++);
		}
		StringBuilder sb = new StringBuilder();
		int lastWordIdx = cells.size() - 1;
		for (int i = 0; i < cells.size(); i++) {
			Cell c = cells.get(i);
			Integer lab = labels.get(c.addr());
			if (lab != null) {
				sb.append('L').append(lab).append(": ");
			}
			switch (c.op()) {
				case WORD -> {
					boolean isExit = i == lastWordIdx && r.exits().contains(c.value());
					sb.append(isExit ? ";" : r.label(c.value()));
				}
				case LIT -> sb.append(hex(c.value()));
				case BRANCH -> sb.append(labels.containsKey(c.target())
						? "L" + labels.get(c.target()) : hex(c.target()));
				case STRING -> sb.append('"').append(c.text()).append('"');
			}
			sb.append(' ');
		}
		return sb.toString();
	}

}
