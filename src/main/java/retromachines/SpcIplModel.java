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

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The SPC700 IPL boot-ROM side of the SNES {@code $2140-$2143} handshake, as a pure state
 * machine (bead grm-1.7.3). The 65816 talks to four byte-wide APU I/O ports; the SPC700's
 * mask-ROM boot loader answers them. Emulating the 65816 against this model makes a ROM
 * upload its sound driver, and the model records every block the ROM sends. No Ghidra types:
 * it can be driven by any CPU emulator, and unit-tested with synthetic port-write sequences.
 *
 * <p><b>The SPC700 IPL protocol</b> (a hardware convention, the same for every game):
 * <ol>
 * <li>At reset the IPL presents {@code $AA} on port 0 and {@code $BB} on port 1 -- the signature
 * an uploader waits for.</li>
 * <li>A <em>command</em> is: port 2/3 = destination address (low/high), port 1 = nonzero for
 * "transfer" or zero for "jump to that address", then port 0 = {@code $CC} (the kick). The IPL
 * echoes the kick value on port 0.</li>
 * <li>For a transfer, the first data byte is sent with port 1 = data and port 0 = {@code $00};
 * each following byte uses port 0 = the running index (low 8 bits, wrapping at 256). When the
 * IPL has stored a byte it echoes the index on port 0.</li>
 * <li>A new command is signalled by writing port 0 to a value that is <em>ahead</em> of the
 * current index (modelled as {@code ((index - port0) & 0x80) != 0}; uploaders skip at least two
 * past the last index). The new command's port 1 and port 2/3 are latched as above, and port 0
 * is the new command byte (echoed back). A command with port 1 = 0 ends the IPL: the SPC700
 * jumps to the address and the 65816 is no longer talking to a boot ROM.</li>
 * </ol>
 * Writes that do not match the expected index (stale, repeated) are ignored, as on hardware.
 *
 * <p><b>Timing, and the one fact the host must honour.</b> The SPC side reacts at 65816
 * <em>instruction boundaries</em>, not per byte store: a 16-bit {@code STA $2140} is two byte
 * stores (low byte, port 0, first), and reacting after the first would read a stale port 1.
 * So the host calls {@link #portWritten} for each byte store (latch only) and
 * {@link #instructionBoundary} once the instruction has finished.
 */
public final class SpcIplModel {

	/** Where the IPL is in the protocol. */
	public enum State {
		/** Presenting {@code $AA/$BB}, waiting for the {@code $CC} kick. */
		WAIT_KICK,
		/** A transfer command was accepted; waiting for the first byte (port 0 == 0). */
		WAIT_FIRST,
		/** Receiving bytes. */
		TRANSFER,
		/** A jump/entry command was received; the IPL has handed over to the uploaded code. */
		DONE
	}

	/** One uploaded block: destination, bytes, and where in the 65816 program it was commanded. */
	public static final class Block {
		private final int dest;
		private final int ordinal;
		private final long issuerPc;
		private final long startStep;
		private final ByteArrayOutputStream data = new ByteArrayOutputStream();

		Block(int dest, int ordinal, long issuerPc, long startStep) {
			this.dest = dest;
			this.ordinal = ordinal;
			this.issuerPc = issuerPc;
			this.startStep = startStep;
		}

		/** The SPC700 destination address of the first byte.
		 * @return the destination address
		 */
		public int dest() {
			return dest;
		}

		/** The bytes received, in order.
		 * @return a copy of the bytes
		 */
		public byte[] bytes() {
			return data.toByteArray();
		}

		/** The number of bytes received.
		 * @return the length
		 */
		public int length() {
			return data.size();
		}

		/** Zero-based index of this block in upload order.
		 * @return the ordinal
		 */
		public int ordinal() {
			return ordinal;
		}

		/** The 65816 PC of the instruction that issued the command (the uploader site).
		 * @return the issuing PC
		 */
		public long issuerPc() {
			return issuerPc;
		}

		/** The host step count when the command was issued.
		 * @return the step count
		 */
		public long startStep() {
			return startStep;
		}
	}

	private static final int KICK = 0xCC;

	private final int[] out = { 0xAA, 0xBB, 0, 0 };
	private final int[] in = new int[4];
	private State state = State.WAIT_KICK;
	private int index;
	private int addr;
	private boolean port0Dirty;
	private final List<Block> blocks = new ArrayList<>();
	private Block current;
	private int entry = -1;

	/** Creates a model in its power-on state. */
	public SpcIplModel() {
	}

	/**
	 * Latch a byte the 65816 stored to an APU port. Has no effect on the SPC side until
	 * {@link #instructionBoundary}.
	 *
	 * @param port the port number 0-3 (the address modulo 4)
	 * @param value the byte stored
	 */
	public void portWritten(int port, int value) {
		int p = port & 3;
		in[p] = value & 0xFF;
		if (p == 0) {
			port0Dirty = true;
		}
	}

	/**
	 * The 65816 finished an instruction; let the SPC side react to any port-0 write made by it.
	 *
	 * @param instructionPc the 65816 PC of the instruction that just completed (recorded as the
	 *                      uploader site of any command it issued)
	 * @param step the host's instruction count, recorded in new blocks
	 */
	public void instructionBoundary(long instructionPc, long step) {
		if (!port0Dirty) {
			return;
		}
		port0Dirty = false;
		int v = in[0];
		switch (state) {
			case WAIT_KICK:
				if (v == KICK) {
					command(v, instructionPc, step);
				}
				break;
			case WAIT_FIRST:
				if (v == 0) {
					store();
				}
				break;
			case TRANSFER:
				if (v == index) {
					store();
				}
				else if (((index - v) & 0x80) != 0) {
					command(v, instructionPc, step);
				}
				break;
			case DONE:
			default:
				break;
		}
	}

	/**
	 * The byte the 65816 reads from an APU port.
	 *
	 * @param port the port number 0-3
	 * @return the IPL's output on that port
	 */
	public int portRead(int port) {
		return out[port & 3];
	}

	private void command(int v, long pc, long step) {
		addr = in[2] | (in[3] << 8);
		out[0] = v;
		if (in[1] != 0) {
			state = State.WAIT_FIRST;
			index = 0;
			current = new Block(addr, blocks.size(), pc, step);
			blocks.add(current);
		}
		else {
			entry = addr;
			state = State.DONE;
		}
	}

	private void store() {
		current.data.write(in[1]);
		addr = (addr + 1) & 0xFFFF;
		out[0] = index;
		index = (index + 1) & 0xFF;
		state = State.TRANSFER;
	}

	/** The protocol state.
	 * @return the state
	 */
	public State state() {
		return state;
	}

	/** Whether a jump/entry command was received.
	 * @return true once the IPL has handed over
	 */
	public boolean isDone() {
		return state == State.DONE;
	}

	/** The entry address of the jump command.
	 * @return the entry address, or -1 if none was received
	 */
	public int entry() {
		return entry;
	}

	/** The blocks received so far, in upload order.
	 * @return an unmodifiable view
	 */
	public List<Block> blocks() {
		return Collections.unmodifiableList(blocks);
	}
}
