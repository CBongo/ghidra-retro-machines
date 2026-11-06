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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Presents an indirect-threaded Forth layer in the listing (bead grm-arbi.2). Entirely driven by
 * a {@link ForthConfig}; without one it does nothing. The config is the program's C64 game
 * descriptor ({@link C64GameDescriptors}): game-level {@code forth} with the member's
 * {@code forth} merged over it (grm-arbi.3). An explicit config in the Program-Info string
 * property {@value ForthConfig#PROPERTY} overrides the descriptor when present. Discovery is {@link ForthThreads}; this class only writes the
 * result: labels, 16-bit pointer data with references, inline operand typing, functions at
 * machine-code entry points, and a plate comment carrying the Forth rendering of each word.
 *
 * <h2>Reference types</h2>
 * A thread cell to its target CFA is {@link RefType#COMPUTED_CALL}: NEXT reaches the target by
 * an indirect jump, and the colon word runs to completion and returns (EXIT), so the semantics
 * are those of a call made through a computed pointer. It is a flow type, so the cells show as
 * callers in xrefs and a word's callers are the words that list it. A CFA to its code (or to
 * DOCOL/handler code) is {@link RefType#COMPUTED_JUMP}: {@code JMP (W)} transfers there and
 * does not return. A branch operand to its target is {@link RefType#COMPUTED_JUMP} too (the
 * branch primitive rewrites IP). A DODOES word to its does-thread is
 * {@code COMPUTED_CALL}, because the thread runs and exits like a colon body.
 *
 * <h2>Safety</h2>
 * Idempotent, and never clobbers: a unit that is already an instruction or non-matching defined
 * data is left alone (logged), a USER_DEFINED label blocks a label, and an existing plate
 * comment is only appended to, once. Addresses outside the program's memory are skipped.
 */
public class C64ForthAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C64 Forth Threads";
	private static final String DESCRIPTION =
		"Presents config-driven indirect-threaded Forth: labels words, types thread cells as " +
			"pointers with call references, decodes inline operands and adds a Forth rendering.";
	static final String CATEGORY = "ForthAnalyzer";
	static final String PLATE_MARKER = "[Forth]";
	private static final int MAX_REJECT_BOOKMARKS = 1000;

	/** Creates the Forth thread analyzer. */
	public C64ForthAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Before disassembly, so typed thread data stops flow instead of being mis-decoded.
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	/** Returns whether the program uses the C64 PRG loader. */
	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		return format != null && format.equals(C64PrgLoader.NAME);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		ForthConfig cfg;
		String json = program.getOptions(Program.PROGRAM_INFO).getString(ForthConfig.PROPERTY,
			null);
		try {
			if (json != null && !json.isBlank()) {
				cfg = ForthConfig.fromJson(json);
			}
			else {
				C64GameDescriptors.Resolution res = C64GameDescriptors.forProgram(program, log);
				if (res == null) {
					return false;
				}
				JsonObject merged = ForthConfig.merge(res.gameForth(), res.memberForth());
				if (merged == null) {
					return false;
				}
				cfg = ForthConfig.fromMap(merged);
				log.appendMsg(NAME, "Forth config from descriptor '" + res.gameId() + "' member " +
					res.memberName());
			}
		}
		catch (IllegalArgumentException e) {
			log.appendMsg(NAME, e.getMessage());
			return false;
		}
		if (cfg == null) {
			return false;
		}
		Memory mem = program.getMemory();
		ForthThreads.Result r = ForthThreads.walk(cfg, a -> readByte(program, mem, a));
		new Applier(program, cfg, r, monitor, log).apply();
		return true;
	}

	private static int readByte(Program program, Memory mem, int a) {
		if (a < 0 || a > 0xFFFF) {
			return -1;
		}
		Address ad = program.getAddressFactory().getDefaultAddressSpace().getAddress(a);
		if (!mem.contains(ad)) {
			return -1;
		}
		try {
			return mem.getByte(ad) & 0xFF;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** Maps Forth punctuation to label-safe text. */
	static String labelOf(String name) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if ((Character.isLetterOrDigit(c) && c < 128) || c == '_') {
				sb.append(c);
				continue;
			}
			String m = switch (c) {
				case '+' -> "PLUS";
				case '-' -> "MINUS";
				case '*' -> "STAR";
				case '/' -> "SLASH";
				case '@' -> "FETCH";
				case '!' -> "STORE";
				case '<' -> "LT";
				case '>' -> "GT";
				case '=' -> "EQ";
				case ';' -> "SEMI";
				case ':' -> "COLON";
				case '.' -> "DOT";
				case ',' -> "COMMA";
				case '?' -> "Q";
				case '\'' -> "TICK";
				case '"' -> "QUOTE";
				default -> "_";
			};
			sb.append(m);
		}
		return sb.length() == 0 ? "_" : sb.toString();
	}

	/** One application of a walk result to a program. */
	private static final class Applier {
		final Program program;
		final ForthConfig cfg;
		final ForthThreads.Result r;
		final TaskMonitor monitor;
		final MessageLog log;
		final Listing listing;
		final Memory mem;
		final List<Address> codeEntries = new ArrayList<>();
		final Set<Integer> typedThreads = new HashSet<>();
		final DataType ptr = PointerDataType.getPointer(null, 2);

		Applier(Program program, ForthConfig cfg, ForthThreads.Result r, TaskMonitor monitor,
				MessageLog log) {
			this.program = program;
			this.cfg = cfg;
			this.r = r;
			this.monitor = monitor;
			this.log = log;
			this.listing = program.getListing();
			this.mem = program.getMemory();
		}

		Address addr(int a) {
			if (a < 0 || a > 0xFFFF) {
				return null;
			}
			Address ad = program.getAddressFactory().getDefaultAddressSpace().getAddress(a);
			return mem.contains(ad) ? ad : null;
		}

		void apply() {
			try {
				labelRegisters();
				for (ForthThreads.Word w : r.words().values()) {
					if (monitor.isCancelled()) {
						return;
					}
					applyWord(w);
				}
				for (String line : r.log()) {
					log.appendMsg(NAME, line);
				}
				log.appendMsg(NAME, "accepted " + r.words().size() + " words, rejected " +
					r.log().stream().filter(l -> l.startsWith("rejected colon candidate"))
							.count() +
					" colon candidates");
				bookmarkRejects();
				entryPoints();
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}

		void label(Address a, String name) {
			if (a == null) {
				return;
			}
			try {
				AnnotationGuard.applyLabel(program, a, name, SourceType.ANALYSIS);
			}
			catch (Exception e) {
				log.appendMsg(NAME, "label " + name + " at " + a + ": " + e.getMessage());
			}
		}

		void labelRegisters() {
			label(addr(cfg.ip()), "FORTH_IP");
			label(addr(cfg.w()), "FORTH_W");
		}

		/** Creates {@code dt} at {@code a} unless something conflicting is there. */
		boolean type(Address a, DataType dt, int len) {
			if (a == null) {
				return false;
			}
			Address end = addr((int) a.getOffset() + len - 1);
			if (end == null) {
				return false;
			}
			for (CodeUnit cu : listing.getCodeUnits(new AddressSet(a, end), true)) {
				if (cu instanceof Data d) {
					if (!d.isDefined()) {
						continue;
					}
					if (d.getMinAddress().equals(a) && d.getLength() == len &&
						d.getDataType().isEquivalent(dt)) {
						return true;
					}
				}
				log.appendMsg(NAME, "not typing " + a + ": existing " +
					(cu instanceof Data ? "data" : "instruction") + " at " + cu.getMinAddress());
				return false;
			}
			try {
				listing.createData(a, dt, len);
				return true;
			}
			catch (Exception e) {
				log.appendMsg(NAME, "createData at " + a + ": " + e.getMessage());
				return false;
			}
		}

		void ref(Address from, int toAddr, RefType type) {
			Address to = addr(toAddr);
			if (from == null || to == null) {
				return;
			}
			for (Reference ex : program.getReferenceManager().getReferencesFrom(from)) {
				if (ex.getToAddress().equals(to)) {
					// A pointer data type auto-creates a plain DATA reference; refine its type.
					if (!ex.getReferenceType().equals(type) && AnnotationGuard.mayDisplace(ex)) {
						program.getReferenceManager().updateRefType(ex, type);
					}
					return;
				}
			}
			program.getReferenceManager().addMemoryReference(from, to, type, SourceType.ANALYSIS,
				0);
		}

		String labelFor(ForthThreads.Word w) {
			return w.name() == null ? ForthThreads.fallbackName(w.cfa()) : labelOf(w.name());
		}

		void applyWord(ForthThreads.Word w) {
			Address cfa = addr(w.cfa());
			if (cfa == null) {
				return;
			}
			label(cfa, labelFor(w));
			if (w.kind() == ForthThreads.Kind.EXTERNAL) {
				return; // name only: its bytes are not in this image
			}
			String plate = null;
			// The code field itself: a pointer to what executes.
			int handlerValue = readWord(w.cfa());
			boolean typed = type(cfa, ptr, 2);
			if (typed && handlerValue >= 0) {
				ref(cfa, handlerValue, RefType.COMPUTED_JUMP);
			}
			switch (w.kind()) {
				case CODE -> {
					Address code = addr(w.codeAddr());
					if (code != null) {
						// shared code (code field not pointing at CFA+2) is not renamed
						if (w.codeAddr() == w.cfa() + 2) {
							label(code, labelFor(w) + "_code");
						}
						codeEntries.add(code);
					}
					plate = "code word " + labelFor(w);
				}
				case COLON -> {
					typeThread(w.body(), w);
					plate = ForthThreads.render(w, r);
				}
				case CONSTANT -> {
					type(addr(w.cfa() + 2), WordDataType.dataType, 2);
					plate = String.format(Locale.ROOT, "$%04X CONSTANT %s", w.param(),
						r.label(w.cfa()));
				}
				case VARIABLE -> {
					type(addr(w.cfa() + 2), WordDataType.dataType, 2);
					plate = "VARIABLE " + r.label(w.cfa());
				}
				case USER -> {
					type(addr(w.cfa() + 2), WordDataType.dataType, 2);
					plate = String.format(Locale.ROOT, "$%04X USER %s", w.param(),
						r.label(w.cfa()));
				}
				case EXTERNAL -> {
					// handled before the switch
				}
				case VECTOR -> {
					typeThread(w.body(), w);
					plate = ForthThreads.renderVector(w, r);
				}
				case DOES -> {
					Address pf = addr(w.cfa() + 2);
					if (type(pf, ptr, 2)) {
						ref(pf, w.codeAddr(), RefType.COMPUTED_CALL);
					}
					Address does = addr(w.codeAddr());
					if (does != null) {
						label(does, labelFor(w) + "_does");
					}
					typeThread(w.doesBody(), w);
					plate = ForthThreads.renderDoes(w, r);
				}
			}
			if (w.comment() != null) {
				plate = plate + "\n" + w.comment();
			}
			AnnotationGuard.addComment(listing, cfa, CommentType.PLATE,
				PLATE_MARKER + " " + plate, PLATE_MARKER);
		}

		int readWord(int a) {
			Address lo = addr(a);
			Address hi = addr(a + 1);
			if (lo == null || hi == null) {
				return -1;
			}
			try {
				return (mem.getByte(lo) & 0xFF) | ((mem.getByte(hi) & 0xFF) << 8);
			}
			catch (MemoryAccessException e) {
				return -1;
			}
		}

		void typeThread(List<ForthThreads.Cell> cells, ForthThreads.Word owner) {
			if (cells.isEmpty() || !typedThreads.add(cells.get(0).addr())) {
				return;
			}
			// Local labels for in-body branch targets, numbered as in the rendering.
			Map<Integer, Integer> numbering = new java.util.TreeMap<>();
			Set<Integer> starts = new HashSet<>();
			cells.forEach(c -> starts.add(c.addr()));
			cells.stream().filter(c -> c.op() == ForthThreads.Op.BRANCH &&
				starts.contains(c.target())).forEach(c -> numbering.put(c.target(), 0));
			int n = 1;
			for (Map.Entry<Integer, Integer> e : numbering.entrySet()) {
				e.setValue(n++);
			}
			for (ForthThreads.Cell c : cells) {
				Address a = addr(c.addr());
				switch (c.op()) {
					case WORD -> {
						if (type(a, ptr, 2)) {
							ref(a, c.value(), RefType.COMPUTED_CALL);
						}
					}
					case LIT -> type(a, WordDataType.dataType, 2);
					case BRANCH -> {
						if (type(a, ShortDataType.dataType, 2)) {
							ref(a, c.target(), RefType.COMPUTED_JUMP);
							Integer num = numbering.get(c.target());
							if (num != null) {
								label(addr(c.target()), labelFor(owner) + "_L" + num);
							}
						}
					}
					case STRING -> type(a, PascalString255DataType.dataType, 1 + c.value());
				}
			}
		}

		void bookmarkRejects() {
			int n = 0;
			for (String line : r.log()) {
				if (!line.startsWith("rejected colon candidate $") || n >= MAX_REJECT_BOOKMARKS) {
					continue;
				}
				int cfa = Integer.parseInt(line.substring(26, 30), 16);
				Address a = addr(cfa);
				if (a != null && !r.words().containsKey(cfa)) {
					program.getBookmarkManager().setBookmark(a, BookmarkType.NOTE, CATEGORY,
						line);
					n++;
				}
			}
		}

		void entryPoints() {
			Map<Integer, String> handlers = r.handlers();
			for (Map.Entry<Integer, String> e : handlers.entrySet()) {
				Address a = addr(e.getKey());
				if (a != null) {
					label(a, "FORTH_" + e.getValue());
					codeEntries.add(a);
				}
			}
			for (Address a : codeEntries) {
				if (monitor.isCancelled()) {
					return;
				}
				if (listing.getInstructionAt(a) == null) {
					new DisassembleCommand(new AddressSet(a), null, true).applyTo(program,
						monitor);
				}
				if (listing.getFunctionAt(a) == null && listing.getInstructionAt(a) != null) {
					new CreateFunctionCmd(a).applyTo(program, monitor);
				}
			}
		}
	}
}
