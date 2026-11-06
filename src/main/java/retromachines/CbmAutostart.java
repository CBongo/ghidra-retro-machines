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
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Detects AUTOSTART entry points from the bytes a PRG places over vectors the machine will
 * run next (bead grm-w0j7). Pure and Ghidra-free: it sees the PRG as a CPU-address to byte
 * function, so it is testable without a {@code Program}; {@link AbstractCbmPrgLoader} is the
 * thin caller that turns each {@link Entry} into a label / entry point / function.
 * <p>
 * Three kinds, each enabled only by what the machine descriptor's {@code autostart:} section
 * declares (so a machine that declares nothing gets nothing):
 * <ul>
 * <li>RAM vectors: counted only if the PRG writes BOTH bytes and the word differs from the
 * OS default. Target = the word.</li>
 * <li>Stack page: the LOAD routine's return addresses live there. The live slot is not
 * derivable statically, so the signal is ONE word repeated many times (a deliberate fill);
 * target = word + 1 (RTS). Anything less is a note, not an entry.</li>
 * <li>Hardware vectors: both bytes written; target = the word.</li>
 * </ul>
 */
public final class CbmAutostart {

	/** Minimum same-parity repeats of one word in the stack page to call it a planted RTS fill. */
	static final int STACK_MIN_REPEATS = 8;

	private CbmAutostart() {
	}

	/** One declared vector. {@code dflt} is -1 for hardware vectors (no OS default). */
	public record Vector(String name, int addr, int dflt) {}

	/** What the descriptor declares; empty parts disable that kind. */
	public record Config(List<Vector> vectors, int stackStart, int stackEnd,
			List<Vector> hardware) {
		/**
		 * Tests whether the descriptor declared nothing to detect.
		 *
		 * @return true when no vectors, stack page or hardware vectors are declared
		 */
		public boolean isEmpty() {
			return vectors.isEmpty() && hardware.isEmpty() && stackStart < 0;
		}
	}

	/** Which mechanism produced an entry. */
	public enum Kind {
		/** A RAM vector the PRG overwrote. */
		RAM_VECTOR,
		/** A repeated word planted in the stack page. */
		STACK,
		/** A hardware vector the PRG overwrote. */
		HARDWARE_VECTOR
	}

	/**
	 * A detected entry. {@code label} is the symbol name to create; {@code word} is the raw
	 * word found; {@code target} is the CPU address that will run (word, or word+1 for the
	 * stack kind).
	 */
	public record Entry(Kind kind, String label, String vector, int word, int target) {}

	/** Result of {@link #detect}: entries plus human-readable notes for the import log. */
	public record Result(List<Entry> entries, List<String> notes) {}

	/** The PRG as a function of CPU address: the byte, or -1 if the PRG wrote nothing there. */
	@FunctionalInterface
	public interface Bytes {
		/**
		 * Reads one placed PRG byte.
		 *
		 * @param cpuAddress a 16-bit CPU address
		 * @return the PRG byte (0-255) placed there, or -1 if the PRG does not cover it
		 */
		int at(int cpuAddress);
	}

	/**
	 * Reads the compiled map's {@code autostart} object.
	 *
	 * @param map the compiled descriptor, or null
	 * @return the declared config (empty if the machine declares none)
	 */
	public static Config fromMap(JsonObject map) {
		JsonObject a = map == null || !map.has("autostart") ? null : map.getAsJsonObject("autostart");
		if (a == null) {
			return new Config(List.of(), -1, -1, List.of());
		}
		int ss = -1;
		int se = -1;
		if (a.has("stack")) {
			ss = a.getAsJsonObject("stack").get("start").getAsInt();
			se = a.getAsJsonObject("stack").get("end").getAsInt();
		}
		return new Config(vectorList(a, "vectors"), ss, se, vectorList(a, "hardware"));
	}

	private static List<Vector> vectorList(JsonObject a, String key) {
		List<Vector> out = new ArrayList<>();
		if (a.has(key)) {
			JsonArray arr = a.getAsJsonArray(key);
			for (JsonElement e : arr) {
				JsonObject o = e.getAsJsonObject();
				out.add(new Vector(o.get("name").getAsString(), o.get("addr").getAsInt(),
					o.has("default") ? o.get("default").getAsInt() : -1));
			}
		}
		return List.copyOf(out);
	}

	private static String hex(int v) {
		return "$" + String.format(Locale.ROOT, "%04X", v);
	}

	/** The little-endian word at {@code addr}, or -1 unless the PRG wrote both bytes. */
	private static int word(Bytes b, int addr) {
		int lo = b.at(addr);
		int hi = b.at(addr + 1);
		return lo < 0 || hi < 0 ? -1 : lo | hi << 8;
	}

	/**
	 * Runs every declared detector over the PRG bytes.
	 *
	 * @param config what the machine declares
	 * @param bytes the placed PRG bytes by CPU address
	 * @return entries in vector order (RAM vectors, stack, hardware) and log notes
	 */
	public static Result detect(Config config, Bytes bytes) {
		List<Entry> entries = new ArrayList<>();
		List<String> notes = new ArrayList<>();
		List<Entry> vectorEntries = new ArrayList<>();
		for (Vector v : config.vectors()) {
			int w = word(bytes, v.addr());
			if (w < 0 || w == v.dflt()) {
				continue;
			}
			if (w == 0) {
				notes.add("autostart: " + v.name() + " (" + hex(v.addr()) +
					") written as $0000; treated as padding, not an entry");
				continue;
			}
			vectorEntries.add(
				new Entry(Kind.RAM_VECTOR, "autostart_" + v.name(), v.name(), w, w));
		}
		// An autostart redirects a few vectors. When MORE THAN HALF of the declared block
		// differs from the OS defaults, the PRG is overwriting the block wholesale. That is
		// still an autostart when the words AGREE (one target) and that target is in the PRG's
		// own bytes -- an installer pointing every vector at its entry. Otherwise (the words
		// disagree, or point outside the PRG) each "vector" is just data: a memory image or a
		// data table (owner ruling 2026-11-06, grm-w0j7).
		if (vectorEntries.size() * 2 > config.vectors().size() &&
			!agreeInsidePrg(vectorEntries, bytes)) {
			notes.add("autostart: " + vectorEntries.size() + " of " + config.vectors().size() +
				" RAM vectors differ from their defaults and their words disagree or point " +
				"outside the PRG; treated as a bulk overwrite (data or memory image), not " +
				"autostart entries");
		}
		else {
			entries.addAll(vectorEntries);
		}
		if (config.stackStart() >= 0) {
			detectStack(config, bytes, entries, notes);
		}
		for (Vector v : config.hardware()) {
			int w = word(bytes, v.addr());
			if (w < 0 || w == 0) {
				continue;
			}
			entries.add(new Entry(Kind.HARDWARE_VECTOR, "autostart_" + v.name(), v.name(), w, w));
		}
		return new Result(List.copyOf(entries), List.copyOf(notes));
	}

	/** True when every entry names the same target and the PRG placed a byte at it. */
	private static boolean agreeInsidePrg(List<Entry> vectorEntries, Bytes bytes) {
		int target = vectorEntries.get(0).target();
		for (Entry e : vectorEntries) {
			if (e.target() != target) {
				return false;
			}
		}
		return bytes.at(target & 0xFFFF) >= 0;
	}

	/** Words that are padding / text fill, never a planted return address. */
	private static boolean paddingWord(int w) {
		return w == 0x0000 || w == 0xFFFF || w == 0x2020;
	}

	private static void detectStack(Config config, Bytes bytes, List<Entry> entries,
			List<String> notes) {
		// Count each word per start parity separately: positions of one parity never overlap,
		// so a count is a count of distinct two-byte slots (an overlapping run of one repeated
		// byte cannot inflate it).
		List<Map<Integer, Integer>> counts = List.of(new HashMap<>(), new HashMap<>());
		int covered = 0;
		for (int a = config.stackStart(); a <= config.stackEnd(); a++) {
			if (bytes.at(a) >= 0) {
				covered++;
			}
			if (a == config.stackEnd()) {
				break;
			}
			int w = word(bytes, a);
			if (w >= 0) {
				counts.get(a & 1).merge(w, 1, Integer::sum);
			}
		}
		if (covered == 0) {
			return;
		}
		// Candidates: the best ELIGIBLE word of each parity, if it clears the threshold. Eligible =
		// not padding, RTS target not in the zero page / CPU port, and the RTS target lies in the
		// PRG's own bytes (a planted return address runs the PRG's code; a repeated word whose
		// target is elsewhere is a data table). Ineligible words are skipped BEFORE picking the
		// best, so a page that is mostly zero padding still yields its real fill.
		List<int[]> cands = new ArrayList<>(); // {word, count}
		for (Map<Integer, Integer> m : counts) {
			int bestW = -1;
			int bestC = 0;
			for (Map.Entry<Integer, Integer> e : m.entrySet()) {
				int w = e.getKey();
				if (paddingWord(w) || w + 1 < 0x0100 || bytes.at((w + 1) & 0xFFFF) < 0) {
					continue;
				}
				if (e.getValue() > bestC || (e.getValue() == bestC && e.getKey() < bestW)) {
					bestW = e.getKey();
					bestC = e.getValue();
				}
			}
			if (bestC >= STACK_MIN_REPEATS) {
				boolean dup = false;
				for (int[] c : cands) {
					dup |= c[0] == bestW;
				}
				if (!dup) {
					cands.add(new int[] {bestW, bestC});
				}
			}
		}
		if (cands.isEmpty()) {
			notes.add("autostart: stack page " + hex(config.stackStart()) + " covered (" + covered +
				" bytes) but no non-padding word whose RTS target is inside the PRG repeats >= " +
				STACK_MIN_REPEATS + " times; not an autostart entry");
			return;
		}
		int[] pick = null;
		if (cands.size() == 1) {
			pick = cands.get(0);
		}
		else {
			// Two eligible words (one per parity). Which is live depends on the unknown SP, so
			// only a count at least twice the other's is decisive; otherwise it is ambiguous.
			int[] a = cands.get(0);
			int[] b = cands.get(1);
			if (a[1] >= 2 * b[1] || b[1] >= 2 * a[1]) {
				pick = a[1] > b[1] ? a : b;
			}
			else {
				notes.add("autostart: stack page fill is ambiguous between words " + hex(a[0]) +
					" and " + hex(b[0]) + " (" + a[1] + " / " + b[1] +
					" repeats); not an autostart entry");
				return;
			}
		}
		entries.add(new Entry(Kind.STACK, "autostart_stack", "stack", pick[0], pick[0] + 1));
	}
}
