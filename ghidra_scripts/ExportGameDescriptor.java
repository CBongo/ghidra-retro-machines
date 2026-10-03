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
// Exports the current program's annotation layer as a per-game descriptor YAML (bead grm-hb6.5,
// docs/per-game-descriptors-design.md section 7): the game identity the loader recorded, plus
// the USER_DEFINED labels (and their EOL comments) you added. The output is valid, unedited, as
// BOTH an overlay file (<Ghidra user settings>/retro-machines/games/*.yaml, re-read on the next
// import or re-analysis) AND a machines/games/*.yaml pull request. Analyzer-created labels are
// deliberately not exported. All logic lives in retromachines.GameDescriptorExporter; this
// script only collects arguments.
//
// Interactive: run with no arguments and answer the prompts.
//
// Headless: pass whitespace-free key:value tokens as script arguments, e.g.
//
//   -postScript ExportGameDescriptor.java out:/tmp/zelda.yaml id:zelda note:first_pass
//
//   Required: out   (output file path; refuses to overwrite unless overwrite:true)
//   Optional: id    (game.id, default: slug of the program name)
//             title (game.title, default: the program name; use _ for spaces)
//             note  (free text appended to provenance; use _ for spaces)
//             overwrite (true|false)
//
//@category RetroMachines
//@menupath Tools.Retro Machines.Export Game Descriptor

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import ghidra.app.script.GhidraScript;

import retromachines.GameDescriptorExporter;

public class ExportGameDescriptor extends GhidraScript {

	private static final String TITLE = "Export Game Descriptor";

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no program is open");
			return;
		}

		// Same reason as RunFromElsewhereTransfer: with any script args present, ask* calls
		// consume them positionally, so the headless path parses named tokens itself and calls
		// no ask* method at all.
		File out;
		String id = null;
		String title = null;
		String note = null;
		boolean overwrite = false;
		String[] args = getScriptArgs();
		if (args.length == 0) {
			out = askFile(TITLE, "Save");
			String t = askString(TITLE, "game.title (blank = program name)", "");
			title = t.isBlank() ? null : t;
			String n = askString(TITLE, "Provenance note (optional)", "");
			note = n.isBlank() ? null : n;
			overwrite = out.exists() && askYesNo(TITLE, out + " exists. Overwrite?");
		}
		else {
			String outPath = null;
			for (String arg : args) {
				String[] kv = arg.split(":", 2);
				if (kv.length != 2 || kv[0].isEmpty() || kv[1].isEmpty()) {
					printerr("malformed argument '" + arg + "'; expected key:value, no whitespace");
					return;
				}
				switch (kv[0]) {
					case "out" -> outPath = kv[1];
					case "id" -> id = kv[1];
					case "title" -> title = kv[1].replace('_', ' ');
					case "note" -> note = kv[1].replace('_', ' ');
					case "overwrite" -> overwrite = Boolean.parseBoolean(kv[1]);
					default -> {
						printerr("unknown key '" + kv[0] + "'; expected out, id, title, note, " +
							"overwrite");
						return;
					}
				}
			}
			if (outPath == null) {
				printerr("missing required argument out:<path>");
				return;
			}
			out = new File(outPath);
		}
		if (out.exists() && !overwrite) {
			printerr(out + " exists; pass overwrite:true to replace it");
			return;
		}

		GameDescriptorExporter.Result result;
		try {
			result = GameDescriptorExporter.export(currentProgram,
				GameDescriptorExporter.defaultRequest(currentProgram, id, title, note));
		}
		catch (IllegalStateException e) {
			printerr(e.getMessage());
			return;
		}
		Files.writeString(out.toPath(), result.yaml(), StandardCharsets.UTF_8);
		println("Wrote " + out + ": " + result.labels() + " label(s), " + result.comments() +
			" comment(s)");
		for (String s : result.skipped()) {
			println("  not carried: " + s);
		}
	}
}
