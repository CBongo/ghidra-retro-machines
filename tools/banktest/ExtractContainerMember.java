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
// Real-ROM tier container rows (bead grm-t3n.3): writes ONE member of a container image to a
// file. Run by tools/banktest/realrom-test.sh as a program-less headless script (no -import),
// with three script args: <container path> <member name> <output path>.
//
// The container is mounted through D64FileSystem (the same adapter `analyzeHeadless -import
// x.d64 -recursive` uses), so the bytes are exactly what the loader would have been handed,
// including the synthetic EA_BOOT_IMAGE.prg member (grm-t3n.6). The shell side then pins the
// extracted bytes by their own sha256 and imports them as a plain file named after the row id.
// Prints `EXTRACT OK <size>` on success; any failure throws, which the runner reports.
//@category RetroMachines.Test

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;

import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import retromachines.D64FileSystem;

public class ExtractContainerMember extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		if (a.length != 3) {
			throw new IllegalArgumentException("usage: <container> <member> <output>");
		}
		FileSystemService fss = FileSystemService.getInstance();
		FSRL container = fss.getLocalFSRL(new File(a[0]));
		try (D64FileSystem fs =
			fss.mountSpecificFileSystem(container, D64FileSystem.class, monitor)) {
			GFile f = fs.lookup(a[1]);
			if (f == null) {
				throw new IllegalArgumentException("no member '" + a[1] + "' in " + a[0]);
			}
			try (InputStream in = fs.getInputStream(f, monitor)) {
				byte[] data = in.readAllBytes();
				Files.write(new File(a[2]).toPath(), data);
				println("EXTRACT OK " + data.length);
			}
		}
	}
}
