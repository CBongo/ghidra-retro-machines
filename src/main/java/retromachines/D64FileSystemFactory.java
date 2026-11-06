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

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Factory and probe for {@link D64FileSystem} (bead grm-t3n.2). A d64 has no magic number, so the
 * probe is by size plus a strict structural check ({@link D64Image#looksLikeD64}); headless
 * resolves probe conflicts with CHOOSEFIRST, so it must not accept arbitrary files.
 */
public class D64FileSystemFactory
		implements GFileSystemFactoryByteProvider<D64FileSystem>, GFileSystemProbeByteProvider {

	@Override
	public D64FileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		return new D64FileSystem(targetFSRL, byteProvider, fsService);
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		long length = byteProvider.length();
		if (length != D64Image.SIZE_35 && length != D64Image.SIZE_35_ERRORS &&
			length != D64Image.SIZE_40 && length != D64Image.SIZE_40_ERRORS) {
			return false;
		}
		return D64Image.looksLikeD64(byteProvider.readBytes(0, length));
	}
}
