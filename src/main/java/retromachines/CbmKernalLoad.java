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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Simulates the stock KERNAL serial LOAD store loop (bead grm-t3n.5): {@code STA ($AE),Y},
 * {@code INC $AE}, {@code BNE}, {@code INC $AF}. The store pointer lives in zero-page RAM that
 * the file itself may overwrite, so it is re-read after every byte; a PRG covering the pointer
 * redirects its own remaining bytes. Also honoured: the verify flag ($93, nonzero = no stores)
 * and the CPU port ($00/$01), which decides whether a store into the I/O window is lost.
 * <p>
 * Pure and Ghidra-free like {@link CbmAutostart}. Which cells exist, and their starting values,
 * come from the machine descriptor's {@code kernal_load:} section; a machine that declares none
 * gets a plain contiguous (wrapping) copy, which is what the loader did before this class.
 * A later store to an address wins. Models the stock KERNAL path only (fast loaders differ).
 */
public final class CbmKernalLoad {

	private static final int SPACE = 0x10000;

	private CbmKernalLoad() {
	}

	/**
	 * The I/O window and the port bits that make it visible.
	 *
	 * @param start first address of the window
	 * @param end last address of the window
	 * @param mask first visibility mask: the window is visible when
	 *        {@code (port & mask) != 0 && (port & any) != 0}
	 * @param any second visibility mask
	 * @param dropBeforePortWrite whether stores are lost even before the PRG wrote the port
	 */
	public record Io(int start, int end, int mask, int any, boolean dropBeforePortWrite) {}

	/**
	 * What the descriptor declares. {@code pointer} is -1 when nothing is declared (contiguous
	 * placement); {@code verify}, {@code ddr}, {@code data} and {@code io} are optional.
	 *
	 * @param pointer zero-page address of the store pointer's low byte, or -1
	 * @param verify zero-page address of the verify flag, or -1
	 * @param ddr zero-page address of the port data-direction register, or -1
	 * @param data zero-page address of the port data register, or -1
	 * @param io the I/O window, or null
	 * @param initial starting value of each cell by address, -1 where undeclared (256 entries)
	 */
	@SuppressWarnings("ArrayRecordComponent") // immutable by convention; never mutated after fromMap
	public record Config(int pointer, int verify, int ddr, int data, Io io, int[] initial) {
		/** The no-redirect contiguous model. */
		public static final Config NONE = new Config(-1, -1, -1, -1, null, new int[256]);

		/**
		 * Tests whether the descriptor declared a store-loop model.
		 *
		 * @return true when nothing is declared
		 */
		public boolean isEmpty() {
			return pointer < 0;
		}
	}

	/**
	 * One maximal run of consecutive stores.
	 *
	 * @param fileOffset payload offset (excluding the 2-byte header) of the run's first byte
	 * @param start CPU address of its first byte
	 * @param length number of bytes
	 */
	public record Run(int fileOffset, int start, int length) {
		int end() {
			return (start + length - 1) & 0xFFFF;
		}
	}

	/**
	 * The simulated outcome.
	 *
	 * @param image final byte by address, -1 where nothing was written
	 * @param source payload offset of the byte that finally landed at each address, -1 if none
	 * @param runs every run of consecutive stores in file order, including ones later overwritten
	 *        or dropped
	 * @param ioDropped bytes lost to the I/O window
	 * @param verifySkipped bytes not stored because the verify flag was set
	 * @param notes human-readable log lines (empty when the load was a plain contiguous copy)
	 */
	@SuppressWarnings("ArrayRecordComponent") // read-only views of the finished simulation
	public record Result(int[] image, int[] source, List<Run> runs, int ioDropped,
			int verifySkipped, List<String> notes) {}

	/**
	 * Reads the compiled map's {@code kernal_load} object.
	 *
	 * @param map the compiled descriptor, or null
	 * @return the declared config ({@link Config#NONE} if the machine declares none)
	 */
	public static Config fromMap(JsonObject map) {
		if (map == null || !map.has("kernal_load")) {
			return Config.NONE;
		}
		JsonObject k = map.getAsJsonObject("kernal_load");
		int[] initial = new int[256];
		Arrays.fill(initial, -1);
		if (k.has("initial")) {
			JsonArray arr = k.getAsJsonArray("initial");
			for (JsonElement e : arr) {
				JsonObject o = e.getAsJsonObject();
				initial[o.get("addr").getAsInt() & 0xFF] = o.get("value").getAsInt() & 0xFF;
			}
		}
		int ddr = -1;
		int data = -1;
		if (k.has("port")) {
			ddr = k.getAsJsonObject("port").get("ddr").getAsInt();
			data = k.getAsJsonObject("port").get("data").getAsInt();
		}
		Io io = null;
		if (k.has("io") && ddr >= 0) {
			JsonObject o = k.getAsJsonObject("io");
			io = new Io(o.get("start").getAsInt(), o.get("end").getAsInt(),
				o.get("mask").getAsInt(), o.get("any").getAsInt(),
				o.has("drop_before_port_write") && o.get("drop_before_port_write").getAsBoolean());
		}
		return new Config(k.get("pointer").getAsInt(), k.has("verify") ? k.get("verify").getAsInt() : -1,
			ddr, data, io, initial);
	}

	private static String hex(int v) {
		return "$" + String.format(Locale.ROOT, "%04X", v);
	}

	/**
	 * Runs the store loop over a payload.
	 *
	 * @param config the declared model (or {@link Config#NONE})
	 * @param loadAddress the PRG header's load address; the pointer cells start here
	 * @param payload the bytes after the 2-byte header
	 * @return the final image, its provenance, the run list and log notes
	 */
	public static Result load(Config config, int loadAddress, byte[] payload) {
		int[] image = new int[SPACE];
		int[] source = new int[SPACE];
		Arrays.fill(image, -1);
		Arrays.fill(source, -1);
		List<Run> runs = new ArrayList<>();
		List<String> notes = new ArrayList<>();
		boolean model = !config.isEmpty();
		boolean portWritten = false;
		int ioDropped = 0;
		int verifySkipped = 0;
		int ptrLo = config.pointer();
		int ptrHi = ptrLo + 1;
		int ptr = loadAddress & 0xFFFF;
		// Cells the loop reads: the written value if the file stored there, else the declared start.
		int[] cellInitial = config.initial().clone();
		if (model) {
			cellInitial[ptrLo] = loadAddress & 0xFF;
			cellInitial[ptrHi] = (loadAddress >> 8) & 0xFF;
		}
		int runStart = -1;
		int runOffset = 0;
		int runLength = 0;
		boolean verifyNoted = false;
		for (int off = 0; off < payload.length; off++) {
			int b = payload[off] & 0xFF;
			boolean store = true;
			if (model && config.verify() >= 0 && cell(image, cellInitial, config.verify()) != 0) {
				store = false;
				verifySkipped++;
				if (!verifyNoted) {
					verifyNoted = true;
					notes.add("KERNAL LOAD simulation: verify flag " + hex(config.verify()) +
						" is nonzero from payload +$" + Integer.toHexString(off).toUpperCase(Locale.ROOT) +
						"; the remaining bytes are compared, not stored");
				}
			}
			else if (model && config.io() != null && ptr >= config.io().start() &&
				ptr <= config.io().end() && ioVisible(config, image, cellInitial, portWritten)) {
				store = false;
				ioDropped++;
			}
			if (store) {
				image[ptr] = b;
				source[ptr] = off;
				if (model && (ptr == config.ddr() || ptr == config.data())) {
					portWritten = true;
				}
			}
			if (runLength > 0 && ((runStart + runLength) & 0xFFFF) == ptr) {
				runLength++;
			}
			else {
				if (runLength > 0) {
					runs.add(new Run(runOffset, runStart, runLength));
				}
				runStart = ptr;
				runOffset = off;
				runLength = 1;
			}
			int next;
			if (model) {
				int lo = (cell(image, cellInitial, ptrLo) + 1) & 0xFF;
				int hi = cell(image, cellInitial, ptrHi);
				if (lo == 0) {
					hi = (hi + 1) & 0xFF;
				}
				// The increments are real stores to the pointer cells: later reads see them.
				image[ptrLo] = lo;
				image[ptrHi] = hi;
				next = lo | hi << 8;
			}
			else {
				next = (ptr + 1) & 0xFFFF;
			}
			if (next != ((ptr + 1) & 0xFFFF) && off + 1 < payload.length) {
				notes.add("KERNAL LOAD simulation: after payload +$" +
					Integer.toHexString(off).toUpperCase(Locale.ROOT) + " (stored at " + hex(ptr) +
					") the store pointer " + hex(config.pointer()) + " now points at " + hex(next) +
					", not " + hex((ptr + 1) & 0xFFFF) + "; the remaining bytes are redirected");
			}
			ptr = next;
		}
		if (runLength > 0) {
			runs.add(new Run(runOffset, runStart, runLength));
		}
		if (model) {
			// The pointer increments above were written into image[] to be re-read; they are not
			// file bytes. Restore provenance: only cells the FILE stored keep an image value.
			for (int a : new int[] {ptrLo, ptrHi}) {
				if (source[a] < 0) {
					image[a] = -1;
				}
				else {
					image[a] = payload[source[a]] & 0xFF;
				}
			}
		}
		if (ioDropped > 0) {
			notes.add("KERNAL LOAD simulation: " + ioDropped + " byte(s) stored into the I/O window " +
				hex(config.io().start()) + "-" + hex(config.io().end()) +
				" while the CPU port maps I/O there; they never reach RAM and are not placed");
		}
		if (verifySkipped > 0) {
			notes.add("KERNAL LOAD simulation: " + verifySkipped + " byte(s) not stored (verify mode)");
		}
		if (!notes.isEmpty()) {
			StringBuilder sb = new StringBuilder("KERNAL LOAD simulation run list (payload offset -> address):");
			for (Run r : runs) {
				sb.append(String.format(Locale.ROOT, " +$%04X->$%04X-$%04X;", r.fileOffset(), r.start(),
					r.end()));
			}
			notes.add(sb.toString());
		}
		return new Result(image, source, List.copyOf(runs), ioDropped, verifySkipped,
			List.copyOf(notes));
	}

	private static int cell(int[] image, int[] initial, int zp) {
		return image[zp] >= 0 ? image[zp] : Math.max(initial[zp], 0);
	}

	private static boolean ioVisible(Config c, int[] image, int[] initial, boolean portWritten) {
		if (!portWritten && !c.io().dropBeforePortWrite()) {
			return false;
		}
		int ddr = cell(image, initial, c.ddr());
		int data = cell(image, initial, c.data());
		// Undriven (DDR=0) port pins read high, which is how the PLA sees them.
		int port = (data | ~ddr) & 0xFF;
		return (port & c.io().mask()) != 0 && (port & c.io().any()) != 0;
	}
}
