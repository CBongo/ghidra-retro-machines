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
// Read-only golden dump for the SNES SPC700-upload rows of the OPTIONAL, hash-pinned real-ROM
// tier (tools/banktest/realrom-test.sh check snes-spc), bead grm-1.7.3.
//
// Runs retromachines.SpcUploadRecovery -- the 65816 under p-code emulation against the SPC700
// IPL handshake model -- and prints, between the shared REALROM fence, which entry strategy
// produced the result, why the run stopped, the SPC700 entry address, and for each uploaded
// block its destination, length, the 65816 address of the instruction that issued the transfer
// command, and the SHA-256 of its bytes.
//
// NO ROM-DERIVED CONTENT IS EMITTED beyond those hashes: the uploaded sound driver and samples
// are copyrighted cartridge data, exactly as the ROM is. Instruction/step counts are left out
// on purpose (they move with any emulator-model change that does not change the result); the
// golden pins what was RECOVERED, not how long it took.
//
// DETERMINISM: the emulator is deterministic and everything printed is in upload order or
// sorted. The wall-clock cap is set high enough that it never decides a result on this tier's
// rows (the slowest, Gradius III, runs about twenty seconds).
//@category RetroMachines.Test

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;

import retromachines.SpcIplModel;
import retromachines.SpcProgramMaterializer;
import retromachines.SpcUploadRecovery;
import retromachines.StopConditions;

public class SpcUploadRealRomDump extends GhidraScript {

	@Override
	protected void run() throws Exception {
		// Emulate BEFORE opening the fence: the emulator logs through Msg, and anything it prints
		// between BEGIN and END would be carved into the dump. Collect the lines, then print
		// them contiguously.
		StopConditions stop = StopConditions.builder()
				.instructionFuel(SpcUploadRecovery.DEFAULT_FUEL).wallClockMillis(150_000L).build();
		SpcUploadRecovery.Result r = new SpcUploadRecovery(currentProgram).recover(stop, monitor);

		List<String> lines = new ArrayList<>();
		lines.add("REALROM language " + currentProgram.getLanguageID().getIdAsString());
		lines.add("REALROM spc strategy " + r.strategy() +
			(r.uploaderEntry() == null ? "" : " at " + r.uploaderEntry()));
		lines.add("REALROM spc stop " + r.stop());
		lines.add("REALROM spc entry " + (r.entry() < 0 ? "NONE" : String.format("%04x", r.entry())));
		lines.add("REALROM spc attempts " + r.attempts().size());
		lines.add("REALROM spc blocks " + r.blocks().size());
		for (SpcIplModel.Block b : r.blocks()) {
			lines.add(String.format("REALROM spc block %d dest=%04x len=%04x issuer=%06x sha256=%s",
				b.ordinal(), b.dest(), b.length(), b.issuerPc(), sha256(b.bytes())));
		}
		SpcProgramMaterializer.Image img = SpcProgramMaterializer.accumulate(r.blocks());
		int written = 0;
		for (int i = 0; i < 0x10000; i++) {
			if (img.written(i)) {
				written++;
			}
		}
		lines.add("REALROM spc image bytes=" + written + " sha256=" + sha256(img.data()));

		RealRomDumpSupport out = new RealRomDumpSupport(this, currentProgram);
		out.begin();
		for (String line : lines) {
			println(line);
		}
		out.end();
	}

	private static String sha256(byte[] data) throws Exception {
		StringBuilder sb = new StringBuilder();
		for (byte x : MessageDigest.getInstance("SHA-256").digest(data)) {
			sb.append(String.format("%02x", x & 0xFF));
		}
		return sb.toString();
	}
}
