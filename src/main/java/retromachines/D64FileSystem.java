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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.AbstractFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Exposes the files of a Commodore 1541 {@code .d64} image as a flat Ghidra container (bead
 * grm-t3n.2). PRG members are named {@code <NAME>.prg} so {@link C64PrgLoader} (which keys on that
 * suffix) imports each; SEQ and USR members get {@code .seq}/{@code .usr}. All parsing lives in
 * {@link D64Image}; this class is the adapter.
 */
@FileSystemInfo(
	type = "d64",
	description = "Commodore 1541 disk image",
	factory = D64FileSystemFactory.class,
	priority = FileSystemInfo.PRIORITY_LOW
)
public class D64FileSystem extends AbstractFileSystem<D64Image.Member> {

	private ByteProvider provider;

	public D64FileSystem(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService)
			throws IOException {
		super(fsFSRL, fsService);
		this.provider = provider;
		D64Image image = D64Image.parse(provider.readBytes(0, provider.length()));
		if (image == null) {
			throw new IOException("Not a valid d64 image");
		}
		for (String problem : image.problems()) {
			Msg.warn(this, "d64: " + problem);
		}
		int fileNum = 0;
		for (D64Image.Member m : image.members()) {
			fsIndex.storeFile(m.fileName(), fileNum++, false, m.data().length, m);
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		D64Image.Member m = fsIndex.getMetadata(file);
		if (m != null) {
			result.add(NAME_ATTR, m.fileName());
			result.add(SIZE_ATTR, (long) m.data().length);
			result.add(FILE_TYPE_ATTR, FileType.FILE);
			result.add("CBM type", m.kind().name());
		}
		return result;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		D64Image.Member m = fsIndex.getMetadata(file);
		if (m == null) {
			return null;
		}
		return new ByteArrayProvider(m.data(), file.getFSRL());
	}
}
