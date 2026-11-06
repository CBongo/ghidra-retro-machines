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
import java.util.Set;

/**
 * Pure-logic parser for Commodore 1541 {@code .d64} sector images (bead grm-t3n.2). Imports
 * nothing from {@code ghidra.*} so it is JUnit-testable on synthetic byte arrays;
 * {@link D64FileSystem} is the thin Ghidra adapter over it.
 * <p>
 * Layout: 35 or 40 tracks of 256-byte sectors, 21/19/18/17 sectors per track in the zones
 * 1-17 / 18-24 / 25-30 / 31-40. An image may carry a trailing error-info table, one byte per
 * sector in image order (175531 = 35 tracks + 683, 197376 = 40 tracks + 768). The BAM is at
 * 18/0 (bytes 0-1 link to the first directory sector, normally 18/1); the directory is a
 * sector chain of 8 x 32-byte entries.
 * <p>
 * <b>Error-byte convention.</b> The 1541 error codes are stored as the DOS code + 1 in the
 * table: {@code 1} is "no error" ({@code 00 OK} in DOS terms). Some writers leave {@code 0}
 * for sectors they never examined, so both 0 and 1 are treated as OK; any other value on a
 * sector in a file's chain fails that file (its bytes would be unreliable or truncated).
 * <p>
 * <b>REL files</b> are skipped: their first-track/sector pointer addresses the side-sector
 * chain, not data, and reconstructing the data chain is out of scope.
 */
public final class D64Image {

	public static final int SECTOR_SIZE = 256;
	public static final int SIZE_35 = 174848;
	public static final int SIZE_35_ERRORS = 175531;
	public static final int SIZE_40 = 196608;
	public static final int SIZE_40_ERRORS = 197376;

	private static final int BAM_TRACK = 18;
	private static final int MAX_DIR_SECTORS = 64;
	private static final int ENTRY_SIZE = 32;
	private static final int NAME_LENGTH = 16;

	/** File kinds as seen by the host, mapped to the file name suffix they are exposed under. */
	public enum Kind {
		SEQ("seq"), PRG("prg"), USR("usr");

		public final String suffix;

		Kind(String suffix) {
			this.suffix = suffix;
		}
	}

	/** One successfully read file. {@code fileName} is unique within the image. */
	public static final class Member {
		private final String fileName;
		private final Kind kind;
		private final byte[] data;

		Member(String fileName, Kind kind, byte[] data) {
			this.fileName = fileName;
			this.kind = kind;
			this.data = data;
		}

		public String fileName() {
			return fileName;
		}

		public Kind kind() {
			return kind;
		}

		/** The file's bytes (shared, not copied; callers must not modify). */
		public byte[] data() {
			return data;
		}
	}

	private final byte[] image;
	private final int tracks;
	private final boolean hasErrorInfo;
	private final List<Member> members = new ArrayList<>();
	private final List<String> problems = new ArrayList<>();

	private D64Image(byte[] image, int tracks, boolean hasErrorInfo) {
		this.image = image;
		this.tracks = tracks;
		this.hasErrorInfo = hasErrorInfo;
	}

	public List<Member> members() {
		return members;
	}

	/** Human-readable notes for files that were skipped or failed. */
	public List<String> problems() {
		return problems;
	}

	// ------------------------------------------------------------------
	// Geometry
	// ------------------------------------------------------------------

	public static int sectorsPerTrack(int track) {
		if (track < 1 || track > 40) {
			return 0;
		}
		if (track <= 17) {
			return 21;
		}
		if (track <= 24) {
			return 19;
		}
		if (track <= 30) {
			return 18;
		}
		return 17;
	}

	/** Linear sector index (0-based) of track/sector, or -1 when out of range for the image. */
	static int sectorIndex(int track, int sector, int tracks) {
		if (track < 1 || track > tracks || sector < 0 || sector >= sectorsPerTrack(track)) {
			return -1;
		}
		int index = 0;
		for (int t = 1; t < track; t++) {
			index += sectorsPerTrack(t);
		}
		return index + sector;
	}

	/** Test hook: {@link #sectorIndex} for a 40-track geometry. */
	static int sectorIndexForTest(int track, int sector) {
		return sectorIndex(track, sector, 40);
	}

	private static int tracksForLength(int length) {
		switch (length) {
			case SIZE_35:
			case SIZE_35_ERRORS:
				return 35;
			case SIZE_40:
			case SIZE_40_ERRORS:
				return 40;
			default:
				return 0;
		}
	}

	/** True for the sizes that carry a trailing error-info table. */
	private static boolean lengthHasErrors(int length) {
		return length == SIZE_35_ERRORS || length == SIZE_40_ERRORS;
	}

	// ------------------------------------------------------------------
	// Parse / probe
	// ------------------------------------------------------------------

	/** Cheap strict check used by the filesystem probe. */
	public static boolean looksLikeD64(byte[] bytes) {
		return parseOrNull(bytes, false) != null;
	}

	/**
	 * Parses an image: validates the BAM and directory strictly and reads every file. Returns
	 * null when the bytes are not a plausible d64. Per-file problems do not null the result;
	 * they land in {@link #problems()}.
	 */
	public static D64Image parse(byte[] bytes) {
		return parseOrNull(bytes, true);
	}

	private static D64Image parseOrNull(byte[] bytes, boolean readFiles) {
		int tracks = tracksForLength(bytes.length);
		if (tracks == 0) {
			return null;
		}
		D64Image d = new D64Image(bytes, tracks, lengthHasErrors(bytes.length));
		int bam = d.offsetOf(BAM_TRACK, 0);
		int firstDirSector = bytes[bam + 1] & 0xff;
		if ((bytes[bam] & 0xff) != BAM_TRACK || firstDirSector >= sectorsPerTrack(BAM_TRACK)) {
			return null;
		}
		// DOS version byte: 'A' on every real 1541 disk; some tools zero it.
		int dosVersion = bytes[bam + 2] & 0xff;
		if (dosVersion != 0x41 && dosVersion != 0) {
			return null;
		}
		List<int[]> entries = d.walkDirectory(firstDirSector);
		if (entries == null) {
			return null;
		}
		if (readFiles) {
			d.readFiles(entries);
		}
		return d;
	}

	private int offsetOf(int track, int sector) {
		return sectorIndex(track, sector, tracks) * SECTOR_SIZE;
	}

	/**
	 * Walks the directory chain from 18/{@code firstSector}. Returns the offsets of every entry
	 * worth considering, or null when the chain is not sane (leaves track 18, loops, runs long,
	 * or holds an entry whose type byte is not a valid 1541 type).
	 */
	private List<int[]> walkDirectory(int firstSector) {
		List<int[]> result = new ArrayList<>();
		Set<Integer> seen = new HashSet<>();
		int track = BAM_TRACK;
		int sector = firstSector;
		for (int n = 0; n < MAX_DIR_SECTORS; n++) {
			int index = sectorIndex(track, sector, tracks);
			if (index < 0 || !seen.add(index)) {
				return null;
			}
			int base = index * SECTOR_SIZE;
			for (int e = 0; e < 8; e++) {
				int off = base + e * ENTRY_SIZE;
				int type = image[off + 2] & 0xff;
				if (type == 0) {
					continue;
				}
				int kind = type & 0x07;
				if (kind > 4 || (type & 0x30) != 0) {
					return null;
				}
				result.add(new int[] { off + 2 });
			}
			int nextTrack = image[base] & 0xff;
			int nextSector = image[base + 1] & 0xff;
			if (nextTrack == 0) {
				return result;
			}
			if (nextTrack != BAM_TRACK) {
				return null;
			}
			track = nextTrack;
			sector = nextSector;
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Files
	// ------------------------------------------------------------------

	private void readFiles(List<int[]> entries) {
		Set<String> used = new HashSet<>();
		for (int[] e : entries) {
			int off = e[0];
			int type = image[off] & 0xff;
			int kind = type & 0x07;
			byte[] petName = new byte[NAME_LENGTH];
			System.arraycopy(image, off + 3, petName, 0, NAME_LENGTH);
			String base = sanitizeName(petName);
			if (kind == 0 || (type & 0x80) == 0) {
				// DEL (scratched) or unclosed ("splat") file.
				continue;
			}
			if (kind == 4) {
				problems.add(base + ": REL file skipped");
				continue;
			}
			int track = image[off + 1] & 0xff;
			int sector = image[off + 2] & 0xff;
			Kind k = kind == 1 ? Kind.SEQ : kind == 2 ? Kind.PRG : Kind.USR;
			byte[] data;
			try {
				data = followChain(track, sector);
			}
			catch (IllegalStateException ex) {
				problems.add(base + ": " + ex.getMessage());
				continue;
			}
			members.add(new Member(uniqueName(base, k, used), k, data));
		}
		addEaBootImage(used);
	}

	/**
	 * grm-t3n.6: when the disk carries the early EA loader, exposes the sector-loaded, encrypted
	 * boot image as a synthetic PRG member. A recognized loader whose image fails verification
	 * adds a problem and no member.
	 */
	private void addEaBootImage(Set<String> used) {
		EaBootImage.Outcome o = EaBootImage.recover(this);
		if (o == null) {
			return;
		}
		if (o.result() == null) {
			problems.add(EaBootImage.MEMBER_BASE_NAME + ": " + o.problem());
			return;
		}
		members.add(new Member(uniqueName(EaBootImage.MEMBER_BASE_NAME, Kind.PRG, used), Kind.PRG,
			o.result().prg()));
	}

	/**
	 * The 256 raw bytes of a sector, or null when track/sector is out of range or the error-info
	 * table flags it.
	 */
	byte[] rawSector(int track, int sector) {
		int index = sectorIndex(track, sector, tracks);
		if (index < 0) {
			return null;
		}
		if (hasErrorInfo && (image[(tracks == 35 ? SIZE_35 : SIZE_40) + index] & 0xff) > 1) {
			return null;
		}
		byte[] out = new byte[SECTOR_SIZE];
		System.arraycopy(image, index * SECTOR_SIZE, out, 0, SECTOR_SIZE);
		return out;
	}

	private String uniqueName(String base, Kind kind, Set<String> used) {
		String name = base + "." + kind.suffix;
		int n = 2;
		while (!used.add(name.toLowerCase(Locale.ROOT))) {
			name = base + "~" + n++ + "." + kind.suffix;
		}
		return name;
	}

	/**
	 * Follows a file's sector chain. The last sector (next track 0) holds {@code next sector - 1}
	 * data bytes after its two link bytes. Fails on out-of-range links, loops, or a non-OK
	 * error byte.
	 */
	private byte[] followChain(int track, int sector) {
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		Set<Integer> seen = new HashSet<>();
		while (true) {
			int index = sectorIndex(track, sector, tracks);
			if (index < 0) {
				throw new IllegalStateException(
					"sector link " + track + "/" + sector + " is out of range");
			}
			if (!seen.add(index)) {
				throw new IllegalStateException(
					"sector chain loops at " + track + "/" + sector);
			}
			if (hasErrorInfo) {
				int err = image[tracks == 35 ? SIZE_35 + index : SIZE_40 + index] & 0xff;
				if (err > 1) {
					throw new IllegalStateException(
						"sector " + track + "/" + sector + " has error code " + err);
				}
			}
			int base = index * SECTOR_SIZE;
			int nextTrack = image[base] & 0xff;
			int nextSector = image[base + 1] & 0xff;
			if (nextTrack == 0) {
				int count = Math.max(0, nextSector - 1);
				out.write(image, base + 2, count);
				return out.toByteArray();
			}
			out.write(image, base + 2, SECTOR_SIZE - 2);
			track = nextTrack;
			sector = nextSector;
		}
	}

	// ------------------------------------------------------------------
	// Names
	// ------------------------------------------------------------------

	private static final String ALLOWED_PUNCT = " !#$%&'()+,-.;=@[]^_~";

	/**
	 * Converts a 16-byte PETSCII directory name to a host-safe base name: trailing {@code $A0}
	 * padding trimmed, letters (unshifted $41-$5A and shifted $C1-$DA) as upper-case ASCII,
	 * digits kept, a short punctuation set kept, everything else (path separators, wildcards,
	 * graphics, control codes) replaced by {@code _}. Never empty.
	 */
	static String sanitizeName(byte[] petscii) {
		int end = petscii.length;
		while (end > 0 && (petscii[end - 1] & 0xff) == 0xa0) {
			end--;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < end; i++) {
			int b = petscii[i] & 0xff;
			char c;
			if ((b >= 0x41 && b <= 0x5a) || (b >= 0x30 && b <= 0x39)) {
				c = (char) b;
			}
			else if (b >= 0xc1 && b <= 0xda) {
				c = (char) (b - 0x80);
			}
			else if (b == 0xa0) {
				c = ' ';
			}
			else if (b < 0x80 && ALLOWED_PUNCT.indexOf(b) >= 0) {
				c = (char) b;
			}
			else {
				c = '_';
			}
			sb.append(c);
		}
		String s = sb.toString().strip();
		while (s.endsWith(".")) {
			s = s.substring(0, s.length() - 1).strip();
		}
		return s.isEmpty() ? "UNNAMED" : s;
	}
}
