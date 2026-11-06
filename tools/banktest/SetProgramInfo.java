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
// Sets one Program-Info string property from a file's text before auto-analysis runs (bead
// grm-arbi.2): the test-only route that hands the Forth analyzer its config until the descriptor
// section lands (grm-arbi.3). MUST RUN AS A -preScript, like SetAnalyzerEnabled.java.
//
//   -preScript SetProgramInfo.java key:Retro_Machines.Forth_Config file:<path-without-spaces>
//
//   key   the property name, underscores standing for spaces (script args are space-split).
//   file  a UTF-8 text file whose entire content becomes the value.
//
// Fails loudly on a missing argument, unreadable file, or read-back mismatch. Prints one line:
//
//   SETPROGRAMINFO <key> <n> chars
//
//@category RetroMachines.Test

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class SetProgramInfo extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("SetProgramInfo: no program is open");
		}
		String key = null;
		String file = null;
		for (String arg : getScriptArgs()) {
			String[] kv = arg.split(":", 2);
			if (kv.length != 2 || kv[1].isEmpty()) {
				throw new IllegalArgumentException("malformed argument '" + arg + "'");
			}
			switch (kv[0]) {
				case "key" -> key = kv[1].replace('_', ' ');
				case "file" -> file = kv[1];
				default -> throw new IllegalArgumentException("unknown key in '" + arg + "'");
			}
		}
		if (key == null || file == null) {
			throw new IllegalArgumentException("need key:<name> and file:<path>");
		}
		String value = Files.readString(Path.of(file), StandardCharsets.UTF_8);
		Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
		info.setString(key, value);
		if (!value.equals(info.getString(key, null))) {
			throw new IllegalStateException("read-back mismatch for '" + key + "'");
		}
		println("SETPROGRAMINFO " + key + " " + value.length() + " chars");
	}
}
