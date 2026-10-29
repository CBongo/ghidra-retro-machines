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
// Surveys "push-and-return dispatch" (the RTS trick) on SNES rows (bead grm-gipk.8), so the 6502
// recognizer RtsTrickDispatch can be generalised to the 65816 and SPC700 against a REAL site
// list rather than remembered addresses.
//
// For every RTS/RTL (65816) or RET/RETI (SPC700) it walks back through the straight-line window
// (up to 12 instructions; a call falls through and does NOT end the window; conditional
// branches, jumps and returns do) and keeps the window when it holds a push AND (an indexed load
// OR a PEA/PEI/PER). Each kept window prints as
//   RTSP site <space>::<addr> <RTS|RTL|RET|RETI> cpu=<65816|spc700> incomingMidWindow=<yes|no>
//   RTSP   <addr> <hex bytes> <instruction> [m=.. x=.. e=..]
//   RTSP   computedJump n=<k> <targets>
// incomingMidWindow = some instruction AFTER the window's first has a non-fall-through flow
// reference into it ("yes into <addrs>" names them). computedJump lists the return's resolved
// computed-flow targets, e.g. RtsTrickDispatchAnalyzer's (grm-gipk.8). Summary lines:
// `RTSP summary cpu=.. returns=<n> kept=<n>`.
//
// SPC700: the program is the 65816 SNES ROM, whose sound-driver upload is recovered with
// SpcUploadRecovery and materialized IN MEMORY (never saved, released afterwards), auto-analysed,
// and scanned the same way. A raw byte scan of the 64K image also reports every RET ($6F)
// preceded within 12 bytes by two PUSH A ($2D) bytes, and whether analysis made an instruction
// there (`RTSP spc rawhit ...`, `RTSP spc rawhits=<n>`), to catch code analysis never reached.
//
// Run as REALROM_EXTRA_POSTSCRIPT on snes-analysis (65816 side) and snes-spc (SPC side; those
// rows import -noanalysis so the 65816 side finds almost nothing there). Read-only on the ROM
// program. Prints ROM-derived bytes of a few instructions per site: a local survey, not a golden.
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

import retromachines.SpcProgramMaterializer;
import retromachines.SpcUploadRecovery;
import retromachines.StopConditions;

public class RtsTrickProbe extends GhidraScript {

	private static final int MAX_WINDOW = 12;

	private static final Set<String> PUSH_65816 =
		Set.of("PHA", "PHX", "PHY", "PEA", "PEI", "PER", "PHK", "PHB", "PHD", "PHP");
	private static final Set<String> PUSH_ONLY_IMM_65816 = Set.of("PEA", "PEI", "PER");
	private static final Set<String> PUSH_SPC = Set.of("PUSH");

	@Override
	protected void run() throws Exception {
		String lang = currentProgram.getLanguageID().getIdAsString();
		if (lang.startsWith("65816")) {
			survey(currentProgram, true);
		}
		else {
			println("RTSP skip language " + lang);
		}
		if (SpcUploadRecovery.isSnesRom(currentProgram)) {
			spcStep();
		}
	}

	private void spcStep() throws Exception {
		StopConditions stop = StopConditions.builder()
				.instructionFuel(SpcUploadRecovery.DEFAULT_FUEL).wallClockMillis(150_000L).build();
		SpcUploadRecovery.Result r = new SpcUploadRecovery(currentProgram).recover(stop, monitor);
		println("RTSP spc blocks=" + r.blocks().size() + " entry=" +
			(r.entry() < 0 ? "NONE" : String.format("%04x", r.entry())));
		if (r.blocks().isEmpty()) {
			return;
		}
		ProgramDB spc = SpcProgramMaterializer.build(r, currentProgram.getName() + ".rtsp", this,
			true, monitor);
		try {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(spc);
			int tx = spc.startTransaction("analyze");
			try {
				mgr.initializeOptions();
				mgr.reAnalyzeAll(null);
				mgr.startAnalysis(monitor);
			}
			finally {
				spc.endTransaction(tx, true);
			}
			survey(spc, false);
			rawScan(spc, r);
		}
		finally {
			spc.release(this);
		}
	}

	private void rawScan(Program spc, SpcUploadRecovery.Result r) {
		SpcProgramMaterializer.Image img = SpcProgramMaterializer.accumulate(r.blocks());
		byte[] d = img.data();
		int hits = 0;
		Listing listing = spc.getListing();
		for (int i = 0; i < 0x10000; i++) {
			if ((d[i] & 0xff) != 0x6f || !img.written(i)) {
				continue;
			}
			int pushes = 0;
			int lo = Math.max(0, i - MAX_WINDOW);
			for (int j = lo; j < i; j++) {
				if ((d[j] & 0xff) == 0x2d) {
					pushes++;
				}
			}
			if (pushes < 2) {
				continue;
			}
			hits++;
			Address a = spc.getAddressFactory().getDefaultAddressSpace().getAddress(i);
			Instruction ins = listing.getInstructionAt(a);
			StringBuilder sb = new StringBuilder();
			for (int j = lo; j <= i; j++) {
				sb.append(String.format("%02x", d[j] & 0xff));
			}
			for (int j = lo; j <= i; j++) {
				Instruction x = listing.getInstructionContaining(
					spc.getAddressFactory().getDefaultAddressSpace().getAddress(j));
				if (x != null && x.getMinAddress().getOffset() == j) {
					println(String.format("RTSP spc rawinsn %04x %s", j, x));
				}
			}
			println(String.format("RTSP spc rawhit %04x bytes[%04x..]=%s pushA=%d insnAtRet=%s", i,
				lo, sb, pushes, ins == null ? "no" : "yes"));
		}
		println("RTSP spc rawhits=" + hits);
	}

	private void survey(Program p, boolean is65816) {
		String cpu = is65816 ? "65816" : "spc700";
		Listing listing = p.getListing();
		int returns = 0;
		int kept = 0;
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction ret = it.next();
			String mn = ret.getMnemonicString().toUpperCase();
			boolean isRet = is65816 ? (mn.equals("RTS") || mn.equals("RTL"))
					: (mn.equals("RET") || mn.equals("RETI"));
			if (!isRet) {
				continue;
			}
			returns++;
			List<Instruction> w = new ArrayList<>();
			w.add(ret);
			Instruction cur = ret;
			for (int n = 0; n < MAX_WINDOW; n++) {
				Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
				if (prev == null || !cur.getMinAddress().equals(prev.getFallThrough())) {
					break;
				}
				FlowType ft = prev.getFlowType();
				if (ft.isConditional() || ft.isJump() || ft.isTerminal()) {
					break; // a call falls through and stays in the window; these do not
				}
				w.add(0, prev);
				cur = prev;
			}
			boolean push = false;
			boolean indexed = false;
			boolean immPush = false;
			for (Instruction in : w) {
				String m = in.getMnemonicString().toUpperCase();
				if (is65816 ? PUSH_65816.contains(m) : PUSH_SPC.contains(m)) {
					push = true;
				}
				if (is65816 && PUSH_ONLY_IMM_65816.contains(m)) {
					immPush = true;
				}
				if (hasIndex(in, is65816)) {
					indexed = true;
				}
			}
			if (!(push && (indexed || immPush))) {
				continue;
			}
			kept++;
			StringBuilder into = new StringBuilder();
			for (int k = 1; k < w.size(); k++) {
				if (hasNonFallThroughFlowInto(p, w.get(k).getMinAddress())) {
					into.append(String.format(" %04x", w.get(k).getMinAddress().getOffset()));
				}
			}
			println("RTSP site " + ret.getMinAddress().getAddressSpace().getName() + "::" +
				String.format("%04x", ret.getMinAddress().getOffset()) + " " + mn + " cpu=" + cpu +
				" incomingMidWindow=" + (into.length() > 0 ? "yes into" + into : "no"));
			// What RtsTrickDispatchAnalyzer (or anything else) resolved the return to (grm-gipk.8).
			StringBuilder targets = new StringBuilder();
			int nTargets = 0;
			for (Reference r : ret.getReferencesFrom()) {
				if (r.getReferenceType().isComputed() && r.getReferenceType().isFlow()) {
					nTargets++;
					targets.append(String.format(" %04x", r.getToAddress().getOffset()));
				}
			}
			println("RTSP   computedJump n=" + nTargets + targets);
			for (Instruction in : w) {
				StringBuilder hex = new StringBuilder();
				try {
					for (byte b : in.getBytes()) {
						hex.append(String.format("%02x", b & 0xff));
					}
				}
				catch (Exception e) {
					hex.append("??");
				}
				println("RTSP   " + String.format("%04x", in.getMinAddress().getOffset()) + " " + hex +
					" " + in + (is65816 ? " " + ctxOf(p, in) : ""));
			}
		}
		println("RTSP summary cpu=" + cpu + " returns=" + returns + " kept=" + kept);
	}

	private static boolean hasIndex(Instruction in, boolean is65816) {
		// toString(), not the per-operand representation: the SPC700 index register ("!t+Y") is
		// not part of any operand string there.
		String s = in.toString().toUpperCase();
		return is65816 ? (s.contains(",X") || s.contains(",Y"))
				: (s.contains("+X") || s.contains("+Y"));
	}

	private static String ctxOf(Program p, Instruction in) {
		StringBuilder sb = new StringBuilder("[");
		String[][] regs = { { "ctx_MF", "m" }, { "ctx_XF", "x" }, { "ctx_EF", "e" } };
		for (String[] n : regs) {
			Register r = p.getRegister(n[0]);
			var v = r == null ? null : in.getValue(r, false);
			sb.append(n[1]).append('=').append(v == null ? "?" : v.toString()).append(' ');
		}
		return sb.toString().trim() + "]";
	}

	private static boolean hasNonFallThroughFlowInto(Program p, Address at) {
		for (Reference ref : p.getReferenceManager().getReferencesTo(at)) {
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}
}
