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
import java.util.Comparator;
import java.util.List;

/**
 * Static tier of bead grm-1.7.3: finds "SPC700 IPL format" upload streams (see
 * {@link SpcIplFormat}) embedded in a raw SNES cartridge image, at any byte offset.
 *
 * <p>Every offset is parsed. A structurally valid stream is then accepted only if it passes
 * these plausibility rules, each justified by what the format and the hardware imply rather than
 * by any particular title:
 * <ol>
 * <li><b>Payload of at least {@value #MIN_PAYLOAD} bytes in total.</b> A sound driver plus its
 *     tables is kilobytes; a 12-byte "upload" is overwhelmingly a chance parse of unrelated data.
 *     256 is a round floor chosen to be well under any plausible driver, not fitted to the
 *     corpus.
 * <li><b>The entry address lies inside an uploaded block.</b> The IPL jumps to {@code entry};
 *     jumping to APU RAM the upload did not fill would run whatever the previous program left.
 * <li><b>No two blocks overlap.</b> A later block silently overwriting an earlier one is
 *     possible in principle; rejecting it is a deliberate trade of recall for precision (a real
 *     overlapping stream would be missed -- none is known).
 * <li><b>No block touches {@code $00F0-$00FF}.</b> That page is the SPC700's hardware registers
 *     (TEST, CONTROL, DSP address/data, the CPU I/O ports, timers); an IPL upload writing there
 *     would break the boot ROM's own protocol. The rest of zero page, {@code $0000-$00EF}, is
 *     ordinary RAM and allowed.
 * <li><b>The payload leaves at least {@value #MIN_FREE_RAM} bytes of APU RAM un-uploaded.</b>
 *     Whatever the driver is, it needs working RAM it did not receive from the ROM (stack,
 *     variables, song state); a stream whose blocks tile essentially all 64 KiB is, in
 *     practice, a chance parse of a very long block that happens to be followed by a zero word.
 *     This rule exists because the first version of this scanner, without it, reported nothing
 *     but such streams on every corpus title. The 4 KiB figure is a round number chosen after
 *     seeing that failure, not derived from the corpus's real streams (the largest known is
 *     about 76% of RAM).
 * <li><b>The entry address is at least {@code $0100}.</b> Zero page ($0000-$00EF) holds the
 *     driver's direct-page variables and $00F0-$00FF is hardware; code does not start there. In
 *     practice this removes the largest false-positive family seen in the corpus: a chance
 *     chain whose terminator is followed by zero padding, giving "entry = $0000" which, with a
 *     block at $0000, passes the entry-in-block rule by coincidence.
 * </ol>
 * The IPL itself lives at {@code $FFC0-$FFFF} but is only mapped while CONTROL bit 7 is set, so
 * uploads may legitimately target that RAM; it is not excluded.
 *
 * <p><b>Ranking.</b> Lexicographic: (1) whether the entry address equals the start address of
 * some block -- a driver is uploaded as a unit and begun at its load address, and a chance chain
 * hits that only by a 1-in-blocks-times-64K coincidence; (2) whether the payload is not
 * degenerate: its most common byte is at most {@value #MAX_DOMINANT_BYTE_SHARE} of the whole
 * payload ({@link #dominantByteShare}). A driver upload is SPC700 code plus BRR samples and
 * tables; a chance chain through padding or tile data is dominated by one value. The share is
 * taken over the WHOLE payload, never per block: genuine streams carry blocks that are entirely
 * one byte (zero-filled RAM; F-Zero's and FF2's streams both do), and the three reference streams
 * measure 0.05-0.09 (grm-1.7.7, 2026-10-30); (3) block count, since every extra
 * block is another independently validated {@code [len][addr]} header on the way to a
 * terminator; (4) payload bytes. Encoded as {@code score = (entryAtBlockStart ? 2^30 : 0) +
 * (notDegenerate ? 2^29 : 0) + min(blockCount, 8191) * 65536 + payloadBytes}. (1) and (2) are
 * ranking signals, not rules: nothing in the IPL protocol forces either. <b>Honest limits:</b> the format has very little redundancy, and ROM
 * data is full of zero words, so chance chains of several tiny blocks do pass the rules above;
 * the corpus report shows them. The ordering exists to float genuine streams (all of which in
 * the reference corpus satisfy (1)) above those, and a candidate that does not satisfy (1) should
 * be treated as a lead to confirm, not a finding.

 * <p><b>Suffix suppression.</b> Scanning every offset re-finds the tail of a real stream from
 * each block boundary after the first (and may find a spurious stream inside a block's data).
 * Candidates are taken in descending score and one is dropped when its byte range lies entirely
 * within an already accepted candidate's range.
 *
 * <p><b>Limits, stated honestly.</b> This finds only streams whose destination address is
 * inline. Uploaders that send {@code [u16 len][data]} with the destination held elsewhere in
 * code or a table (Secret of Mana, Final Fantasy 3 in the reference corpus) are invisible to it.
 * Images stored interleaved are not de-interleaved; a stream split across a chunk boundary is
 * missed; a stream the ROM stores compressed is missed.
 */
public final class SpcIplScanner {

	/** Minimum total block payload for a candidate; see class doc. */
	public static final int MIN_PAYLOAD = 256;

	/** Minimum APU RAM the upload must leave untouched; see class doc. */
	public static final int MIN_FREE_RAM = 0x1000;

	/** Largest share of the payload its most common byte may take before ranking lower; see class doc. */
	public static final double MAX_DOMINANT_BYTE_SHARE = 0.15;

	private static final int COPIER_HEADER_LEN = 0x200;

	/**
	 * A plausible stream.
	 *
	 * @param strippedOffset offset in the image with any copier header removed
	 * @param fileOffset offset in the file as given to {@link #scan(byte[])}
	 * @param copierHeader whether a 512-byte copier header was present (and stripped)
	 * @param stream the parsed stream; its offsets are relative to the stripped image
	 * @param score ranking value, see class doc
	 * @param suppressedTails stripped offsets of independently plausible candidates that were
	 *            suppressed because they are exact suffixes (same end) of this one. Usually
	 *            re-finds of its own later blocks; but it is also how a real stream preceded by
	 *            unrelated blocks that happen to chain into it shows up (FF2 in the corpus), so
	 *            it is reported rather than discarded
	 */
	public record Candidate(int strippedOffset, long fileOffset, boolean copierHeader,
			SpcIplFormat.Stream stream, int score, List<Integer> suppressedTails) {
	}

	private SpcIplScanner() {
	}

	/**
	 * Scans a whole file, stripping a copier header when {@link SnesRomHeader} finds a header
	 * for the image that says one is present, or, failing a header, when the file length is 512
	 * bytes past a multiple of 1 KiB (the same rule {@code SnesRomHeader.parse} applies).
	 *
	 * @return candidates, best score first
	 */
	public static List<Candidate> scan(byte[] file) {
		SnesRomHeader header = SnesRomHeader.parse(file);
		boolean copier = header != null ? header.copierHeader()
				: (file.length % 0x400) == COPIER_HEADER_LEN;
		byte[] image = copier ? Arrays.copyOfRange(file, COPIER_HEADER_LEN, file.length) : file;
		return scanImage(image, copier);
	}

	/**
	 * Scans an image that already has any copier header removed.
	 *
	 * @param copierHeader whether a header was stripped by the caller (reported only)
	 */
	public static List<Candidate> scanImage(byte[] image, boolean copierHeader) {
		List<Candidate> found = new ArrayList<>();
		for (int off = 0; off + 4 <= image.length; off++) {
			// Cheap pre-filter: a stream starts with a non-zero length.
			if (image[off] == 0 && image[off + 1] == 0) {
				continue;
			}
			SpcIplFormat.Result r = SpcIplFormat.parse(image, off);
			if (!r.ok() || !plausible(r.stream())) {
				continue;
			}
			SpcIplFormat.Stream s = r.stream();
			int score = (entryAtBlockStart(s) ? 1 << 30 : 0) +
				(dominantByteShare(s) <= MAX_DOMINANT_BYTE_SHARE ? 1 << 29 : 0) +
				Math.min(s.blocks().size(), 8191) * 65536 + s.payloadBytes();
			long fileOff = off + (copierHeader ? COPIER_HEADER_LEN : 0);
			found.add(new Candidate(off, fileOff, copierHeader, s, score, List.of()));
		}
		found.sort(Comparator.comparingInt(Candidate::score).reversed()
				.thenComparingInt(Candidate::strippedOffset));
		List<Candidate> kept = new ArrayList<>();
		List<List<Integer>> tails = new ArrayList<>();
		for (Candidate c : found) {
			boolean inside = false;
			for (int i = 0; i < kept.size(); i++) {
				Candidate k = kept.get(i);
				if (c.stream().offset() >= k.stream().offset() &&
					c.stream().end() <= k.stream().end()) {
					inside = true;
					if (c.stream().end() == k.stream().end()) {
						tails.get(i).add(c.strippedOffset());
					}
					break;
				}
			}
			if (!inside) {
				kept.add(c);
				tails.add(new ArrayList<>());
			}
		}
		List<Candidate> out = new ArrayList<>(kept.size());
		for (int i = 0; i < kept.size(); i++) {
			Candidate k = kept.get(i);
			out.add(new Candidate(k.strippedOffset(), k.fileOffset(), k.copierHeader(), k.stream(),
				k.score(), List.copyOf(tails.get(i))));
		}
		return out;
	}

	/**
	 * The share of the stream's whole payload taken by its most common byte value.
	 *
	 * @param s a parsed stream
	 * @return the share in [0, 1]; 1 for an empty payload
	 */
	public static double dominantByteShare(SpcIplFormat.Stream s) {
		int[] counts = new int[256];
		int total = 0;
		for (SpcIplFormat.Block b : s.blocks()) {
			for (byte v : b.data()) {
				counts[v & 0xFF]++;
			}
			total += b.length();
		}
		int max = 0;
		for (int c : counts) {
			max = Math.max(max, c);
		}
		return total == 0 ? 1.0 : (double) max / total;
	}

	private static boolean entryAtBlockStart(SpcIplFormat.Stream s) {
		for (SpcIplFormat.Block b : s.blocks()) {
			if (b.addr() == s.entry()) {
				return true;
			}
		}
		return false;
	}

	/** The plausibility rules of the class doc. */
	static boolean plausible(SpcIplFormat.Stream s) {
		if (s.payloadBytes() < MIN_PAYLOAD ||
			s.payloadBytes() > SpcIplFormat.APU_RAM_SIZE - MIN_FREE_RAM) {
			return false;
		}
		if (s.entry() < 0x100) {
			return false;
		}
		boolean entryInBlock = false;
		List<SpcIplFormat.Block> bs = s.blocks();
		for (int i = 0; i < bs.size(); i++) {
			SpcIplFormat.Block a = bs.get(i);
			if (a.contains(s.entry())) {
				entryInBlock = true;
			}
			if (a.addr() <= 0xFF && a.addr() + a.length() > 0xF0) {
				return false;
			}
			for (int j = i + 1; j < bs.size(); j++) {
				SpcIplFormat.Block b = bs.get(j);
				if (a.addr() < b.addr() + b.length() && b.addr() < a.addr() + a.length()) {
					return false;
				}
			}
		}
		return entryInBlock;
	}
}
