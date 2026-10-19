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

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/**
 * Builds the one {@code SPC700:LE:16:retro} program that a {@link SpcUploadRecovery} result
 * describes (bead grm-1.7.3). The uploads are accumulated into a 64 KiB image -- later writes
 * win, as on hardware -- while remembering which upload last wrote each byte. Every maximal
 * contiguous written range becomes one initialized block named after its start
 * ({@code UPLOAD_0200}); the rest of the address space is covered by uninitialized blocks.
 * Block comments record the provenance: upload ordinals, destination and length, the 65816
 * uploader PC, and the source program name.
 *
 * <p>The SPC700 IPL boot ROM at {@code $FFC0-$FFFF} is Sony's and is deliberately <em>not</em>
 * included: it stays an uninitialized block ({@code IPL_ROM_FFC0}) unless an upload wrote there.
 * The entry address the ROM jumped to gets an entry point and a {@code SPC_ENTRY} label.
 */
public final class SpcProgramMaterializer {

	/** The language of the program this class produces. */
	public static final String LANGUAGE_ID = "SPC700:LE:16:retro";
	/** Label placed on the entry address. */
	public static final String ENTRY_LABEL = "SPC_ENTRY";

	private static final int SPACE = 0x10000;
	private static final int IPL_ROM_START = 0xFFC0;

	private SpcProgramMaterializer() {
	}

	/** The accumulated 64 KiB image: bytes, which bytes were written, and who wrote them. */
	public static final class Image {
		private final byte[] data = new byte[SPACE];
		/** Ordinal of the upload that last wrote each byte, or -1. */
		private final int[] writer = new int[SPACE];

		Image() {
			Arrays.fill(writer, -1);
		}

		/** The image bytes (unwritten bytes are zero).
		 * @return the 64 KiB array (live)
		 */
		public byte[] data() {
			return data;
		}

		/** The last-writer ordinal per address.
		 * @return a 64 K array of upload ordinals, -1 where nothing was written (live)
		 */
		public int[] writers() {
			return writer;
		}

		/** Whether anything was uploaded to an address.
		 * @param addr the SPC700 address
		 * @return true if written
		 */
		public boolean written(int addr) {
			return writer[addr & 0xFFFF] >= 0;
		}
	}

	/**
	 * Accumulate blocks into an image. Later blocks overwrite earlier ones; an upload running
	 * past {@code $FFFF} wraps to {@code $0000}, as the IPL's 16-bit address does.
	 *
	 * @param blocks the uploaded blocks in upload order
	 * @return the image
	 */
	public static Image accumulate(List<SpcIplModel.Block> blocks) {
		Image img = new Image();
		for (SpcIplModel.Block b : blocks) {
			byte[] bytes = b.bytes();
			for (int i = 0; i < bytes.length; i++) {
				int a = (b.dest() + i) & 0xFFFF;
				img.data[a] = bytes[i];
				img.writer[a] = b.ordinal();
			}
		}
		return img;
	}

	/**
	 * Create the SPC700 program.
	 *
	 * @param result a recovery result (its blocks need not be {@link SpcUploadRecovery.Result#success})
	 * @param name the program name
	 * @param consumer the consumer object that owns the returned program (release it when done)
	 * @param disassemble whether to disassemble from the entry address
	 * @param monitor cancellation monitor
	 * @return the new, unsaved program
	 * @throws Exception if the language is unavailable or a block cannot be created
	 */
	public static ProgramDB build(SpcUploadRecovery.Result result, String name, Object consumer,
			boolean disassemble, TaskMonitor monitor) throws Exception {
		Language lang =
			DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(LANGUAGE_ID));
		CompilerSpec cspec = lang.getDefaultCompilerSpec();
		ProgramDB program = new ProgramDB(name, lang, cspec, consumer);
		boolean ok = false;
		int tx = program.startTransaction("Create SPC700 upload image");
		try {
			populate(program, result, monitor);
			ok = true;
		}
		finally {
			program.endTransaction(tx, ok);
			if (!ok) {
				program.release(consumer);
			}
		}
		if (disassemble && result.entry() >= 0) {
			Address entry = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(result.entry());
			int dtx = program.startTransaction("Disassemble SPC700 entry");
			try {
				new DisassembleCommand(entry, null, true).applyTo(program, monitor);
			}
			finally {
				program.endTransaction(dtx, true);
			}
		}
		return program;
	}

	private static void populate(ProgramDB program, SpcUploadRecovery.Result result,
			TaskMonitor monitor) throws Exception {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Image img = accumulate(result.blocks());
		List<SpcIplModel.Block> blocks = result.blocks();

		int a = 0;
		while (a < SPACE) {
			boolean w = img.written(a);
			int end = a;
			// Split the unwritten run at the IPL ROM boundary so it can be named.
			while (end < SPACE && img.written(end) == w && (w || end == a || end != IPL_ROM_START)) {
				end++;
			}
			int len = end - a;
			Address start = space.getAddress(a);
			if (w) {
				MemoryBlock blk = program.getMemory().createInitializedBlock(
					String.format("UPLOAD_%04X", a), start,
					new ByteArrayInputStream(img.data, a, len), len, monitor, false);
				blk.setRead(true);
				blk.setWrite(true);
				blk.setExecute(true);
				blk.setComment(provenance(img, blocks, a, end, result));
			}
			else {
				boolean ipl = a >= IPL_ROM_START;
				MemoryBlock blk = program.getMemory().createUninitializedBlock(
					ipl ? String.format("IPL_ROM_%04X", a) : String.format("RAM_%04X", a), start,
					len, false);
				blk.setRead(true);
				blk.setWrite(!ipl);
				blk.setExecute(true);
				blk.setComment(ipl
						? "SPC700 IPL boot ROM -- not included (not ours to redistribute)"
						: "Not written by any recovered upload");
			}
			a = end;
		}

		if (result.entry() >= 0) {
			Address entry = space.getAddress(result.entry());
			program.getSymbolTable().addExternalEntryPoint(entry);
			program.getSymbolTable().createLabel(entry, ENTRY_LABEL, SourceType.IMPORTED);
			AnalyzerCommentRecord.set(program, entry, CommentType.PLATE,
				"Entry address jumped to by the SPC700 IPL command, recovered from " +
					result.programName() + " (" + result.strategy() + ")");
		}
	}

	private static String provenance(Image img, List<SpcIplModel.Block> blocks, int from, int to,
			SpcUploadRecovery.Result result) {
		// Which uploads still own at least one byte in [from, to)?
		Map<Integer, Integer> surviving = new LinkedHashMap<>();
		for (int i = from; i < to; i++) {
			surviving.merge(img.writer[i], 1, Integer::sum);
		}
		StringBuilder sb = new StringBuilder();
		sb.append("Recovered from ").append(result.programName()).append(" by emulating the 65816 (")
				.append(result.strategy()).append(")\n");
		for (SpcIplModel.Block b : blocks) {
			Integer owned = surviving.get(b.ordinal());
			if (owned == null) {
				continue;
			}
			sb.append(String.format("upload #%d: $%04X..$%04X (%d bytes, %d surviving), " +
				"issued by 65816 $%06X%n", b.ordinal(), b.dest(), (b.dest() + b.length() - 1) & 0xFFFF,
				b.length(), owned, b.issuerPc()));
		}
		return sb.toString();
	}
}
