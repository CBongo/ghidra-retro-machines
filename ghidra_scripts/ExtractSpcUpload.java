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
// Recovers the SPC700 sound-driver uploads of the current SNES ROM and saves them as ONE new
// SPC700 program (bead grm-1.7.3). The 65816 is run under p-code emulation against a model of
// the SPC700 IPL boot-ROM handshake on $2140-$2143 (retromachines.SpcUploadRecovery); every
// block the ROM sends is accumulated into a 64 KiB image, and the entry address it finally jumps
// to becomes the SPC700 program's entry point (retromachines.SpcProgramMaterializer). The new
// program is saved beside the ROM, named "<program name>.spc700".
//
// Strategy: the reset vector first; if the ROM does not upload from boot (Secret of Mana boots
// into an interrupt-driven loop and uploads on demand), routines located by the $2140 / #$BBAA
// handshake signature are run directly.
//
// Headless:  -postScript ExtractSpcUpload.java [entry]
//   entry   optional hex address of an uploader routine (e.g. c3002c): skip the reset run and
//           run that routine directly (native mode, 8-bit registers).
//
//@category RetroMachines
//@menupath Tools.Retro Machines.Extract SPC700 Upload

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;

import retromachines.SnesRomLoader;
import retromachines.SpcIplModel;
import retromachines.SpcProgramMaterializer;
import retromachines.SpcUploadRecovery;
import retromachines.StopConditions;

public class ExtractSpcUpload extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no program is open");
			return;
		}
		if (!SpcUploadRecovery.isSnesRom(currentProgram)) {
			printerr("ExtractSpcUpload needs a SNES cartridge imported by the " +
				SnesRomLoader.NAME + " loader (" + SpcUploadRecovery.LANGUAGE_ID + "); got format '" +
				currentProgram.getExecutableFormat() + "', language " + currentProgram.getLanguageID());
			return;
		}
		StopConditions stop = StopConditions.builder()
				.instructionFuel(SpcUploadRecovery.DEFAULT_FUEL)
				.wallClockMillis(SpcUploadRecovery.DEFAULT_WALLCLOCK_MILLIS).build();
		SpcUploadRecovery recovery = new SpcUploadRecovery(currentProgram);
		SpcUploadRecovery.Result result;
		String[] args = getScriptArgs();
		if (args.length > 0) {
			Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace()
					.getAddress(Long.parseLong(args[0].replace("0x", "").replace("$", ""), 16));
			result = recovery.recoverFrom(entry, stop, monitor);
		}
		else {
			result = recovery.recover(stop, monitor);
		}

		println(String.format("SPC upload: strategy=%s stop=%s steps=%d blocks=%d entry=%s",
			result.strategy(), result.stop(), result.steps(), result.blocks().size(),
			result.entry() < 0 ? "none" : String.format("%04x", result.entry())));
		for (SpcIplModel.Block b : result.blocks()) {
			println(String.format("  block %d: dest=%04x len=%04x issuer=%06x", b.ordinal(), b.dest(),
				b.length(), b.issuerPc()));
		}
		if (!result.success()) {
			printerr("no complete upload recovered; not creating a program");
			return;
		}

		String name = currentProgram.getName() + ".spc700";
		ProgramDB spc = SpcProgramMaterializer.build(result, name, this, true, monitor);
		try {
			DomainFolder folder = currentProgram.getDomainFile().getParent();
			if (folder == null && state.getProject() != null) {
				// Headless import: the program is not filed yet, so it reports no parent. It will
				// land in the project root, so put the new program there too.
				folder = state.getProject().getProjectData().getRootFolder();
			}
			if (folder == null) {
				printerr("cannot find the project folder to save into");
				return;
			}
			DomainFile existing = folder.getFile(name);
			if (existing != null) {
				existing.delete();
			}
			folder.createFile(name, spc, monitor);
			println("saved " + folder.getPathname() + "/" + name);
		}
		finally {
			spc.release(this);
		}
	}
}
