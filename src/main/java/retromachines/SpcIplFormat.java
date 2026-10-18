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
import java.util.Collections;
import java.util.List;

/**
 * Parser for the "SPC700 IPL format" (bead grm-1.7.3): the block stream a SNES program hands to
 * the SPC700 boot ROM (the IPL) to load sound-driver code and samples into APU RAM.
 *
 * <pre>
 *   repeat:  [u16 LE len][u16 LE addr][len bytes]      len != 0
 *   end:     [u16 LE 0  ][u16 LE entry]                the IPL jumps to entry
 * </pre>
 *
 * <p>The name is the project owner's (2026-09-05): the layout is the form the IPL loader itself
 * expects to receive, several ROMs keep their upload data in exactly this shape, and it has no
 * established name. It is a hardware-derived convention, not any extraction tool's format.
 *
 * <p>This class is pure: no Ghidra {@code Program}, no I/O. It validates structure only (blocks
 * fit in the input, fit in the 64 KiB APU address space, and the list terminates within
 * {@link #MAX_BLOCKS}); whether a structurally valid stream is <em>plausible</em> as a real
 * upload is {@link SpcIplScanner}'s question.
 */
public final class SpcIplFormat {

	/** The APU address space; a block's {@code addr + len} may not exceed it. */
	public static final int APU_RAM_SIZE = 0x10000;

	/**
	 * Most blocks parsed before giving up on finding a terminator. Real uploads in the reference
	 * corpus have a handful of blocks; the cap exists so a scan at an arbitrary offset in
	 * unrelated data stops quickly.
	 */
	public static final int MAX_BLOCKS = 256;

	/** Why a parse failed. */
	public enum Failure {
		/** The input ended inside a header or inside a block's data. */
		TRUNCATED,
		/** A block's {@code addr + len} exceeds {@link #APU_RAM_SIZE}. */
		ADDRESS_OVERFLOW,
		/** {@link #MAX_BLOCKS} blocks were read without meeting a {@code len == 0} terminator. */
		NO_TERMINATOR,
		/** The first length field was zero: a terminator with no blocks is not an upload. */
		NO_BLOCKS,
		/** The offset itself lies outside the input. */
		BAD_OFFSET
	}

	/** One uploaded block. {@code sourceOffset} indexes the input array the data came from. */
	public static final class Block {
		private final int addr;
		private final int length;
		private final int sourceOffset;
		private final byte[] data;

		Block(int addr, int length, int sourceOffset, byte[] data) {
			this.addr = addr;
			this.length = length;
			this.sourceOffset = sourceOffset;
			this.data = data;
		}

		/** Destination address in APU RAM. */
		public int addr() {
			return addr;
		}

		public int length() {
			return length;
		}

		/** Offset in the parsed input of the first data byte (after the 4-byte block header). */
		public int sourceOffset() {
			return sourceOffset;
		}

		/** A copy of the block's bytes. */
		public byte[] data() {
			return data.clone();
		}

		/** True when {@code a} (an APU address) lies within this block's destination range. */
		public boolean contains(int a) {
			return a >= addr && a < addr + length;
		}

		@Override
		public String toString() {
			return String.format("%04x bytes @ %04x", length, addr);
		}
	}

	/**
	 * A successfully parsed stream.
	 *
	 * @param offset where in the input the stream starts
	 * @param blocks the blocks in upload order (immutable)
	 * @param entry the IPL jump address from the terminator
	 * @param consumed total bytes occupied in the input, terminator included
	 */
	public record Stream(int offset, List<Block> blocks, int entry, int consumed) {
		/** Sum of block lengths. */
		public int payloadBytes() {
			int sum = 0;
			for (Block b : blocks) {
				sum += b.length();
			}
			return sum;
		}

		/** Offset one past the last byte of the stream (terminator included). */
		public int end() {
			return offset + consumed;
		}
	}

	/** Result of {@link #parse}: exactly one of {@code stream} / {@code failure} is non-null. */
	public record Result(Stream stream, Failure failure, int failureOffset) {
		public boolean ok() {
			return stream != null;
		}
	}

	private SpcIplFormat() {
	}

	/**
	 * Parses a stream starting at {@code offset} in {@code in}.
	 *
	 * @return the stream, or a failure carrying the reason and the input offset it was detected at
	 */
	public static Result parse(byte[] in, int offset) {
		if (offset < 0 || offset >= in.length) {
			return fail(Failure.BAD_OFFSET, offset);
		}
		// Phase 1: validate with no allocation, so scanning every offset of a cartridge is cheap.
		int pos = offset;
		int count = 0;
		while (true) {
			if (pos + 4 > in.length) {
				return fail(Failure.TRUNCATED, pos);
			}
			int len = u16(in, pos);
			int addr = u16(in, pos + 2);
			if (len == 0) {
				if (count == 0) {
					return fail(Failure.NO_BLOCKS, pos);
				}
				break;
			}
			if (count == MAX_BLOCKS) {
				return fail(Failure.NO_TERMINATOR, pos);
			}
			if (addr + len > APU_RAM_SIZE) {
				return fail(Failure.ADDRESS_OVERFLOW, pos);
			}
			if (pos + 4 + len > in.length) {
				return fail(Failure.TRUNCATED, pos);
			}
			pos += 4 + len;
			count++;
		}
		// Phase 2: materialize.
		List<Block> blocks = new ArrayList<>(count);
		pos = offset;
		for (int i = 0; i < count; i++) {
			int len = u16(in, pos);
			int addr = u16(in, pos + 2);
			blocks.add(new Block(addr, len, pos + 4, Arrays.copyOfRange(in, pos + 4, pos + 4 + len)));
			pos += 4 + len;
		}
		int entry = u16(in, pos + 2);
		pos += 4;
		return new Result(new Stream(offset, Collections.unmodifiableList(blocks), entry, pos - offset),
			null, -1);
	}

	private static Result fail(Failure f, int at) {
		return new Result(null, f, at);
	}

	private static int u16(byte[] b, int at) {
		return (b[at] & 0xff) | ((b[at + 1] & 0xff) << 8);
	}
}
