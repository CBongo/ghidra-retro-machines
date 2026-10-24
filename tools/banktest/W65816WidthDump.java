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
// Read-only golden dump for the snes-analysis rows of the real-ROM tier (bead grm-9nxj.5.1):
// how well 65816 auto-analysis tracks the M/X/E register widths on a real cartridge.
//
// WHY A SEPARATE PLATFORM FROM snes/snes-spc. Those rows import with -noanalysis -- they pin the
// LOADER (SnesRealRomDump) and the SPC upload recovery (SpcUploadRealRomDump), neither of which
// needs auto-analysis. Width inference is entirely an analysis question: the 65816 decodes one
// byte stream at different lengths depending on the M/X flags its caller left set, and a wrong
// guess desynchronizes everything downstream of it. Nothing measured that on a real cartridge
// before this dump, so it is the measuring stick every grm-9nxj.5 increment is judged by.
//
// WHAT IT COUNTS, and why each one:
//   instrs / ctx         instructions, bucketed by the (E,M,X) context they were decoded under
//   desync               decoded BRK/COP/WDM/STP: rare in real code, common when width guesses
//                        go wrong and the decoder walks into data or operand bytes
//   bookmarks            Error bookmarks by category, with addresses normalized out of the text
//   vector               each CPU vector: target, whether code was decoded there, and at what
//                        context -- unreached handlers are code the analysis never saw at all
//   calls                JSR/JSL whose target was decoded at a DIFFERENT width than the caller
//                        holds at the call: one address can carry one decode, so the second
//                        caller's view is wrong and Ghidra says nothing (grm-9nxj.5 item 4)
//   exitwidth            functions with a return (RTS/RTL) decoded at a different M/X than the
//                        entry: the callee left the width changed, so the CALLER's fall-through
//                        after the JSR was decoded at a stale width
//   computed             computed jumps/calls, and how many have any resolved target (item 1)
//   ops                  PLP/RTI/PHP/REP/SEP/XCE counts (PLP/RTI restore widths the language
//                        cannot see: item 2)
//
// NO ROM BYTES ARE EVER EMITTED; addresses and counts only. Every list is sorted and every
// sample capped, as in SnesRealRomDump, so the golden is deterministic and bounded.
//@category RetroMachines.Test

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

public class W65816WidthDump extends GhidraScript {

	private static final int SAMPLE = 40;

	// Native-mode vectors first, then emulation mode; offsets in bank $00.
	private static final String[] VECTOR_NAMES = {
		"NATIVE_COP", "NATIVE_BRK", "NATIVE_ABORT", "NATIVE_NMI", "NATIVE_IRQ",
		"EMU_COP", "EMU_ABORT", "EMU_NMI", "EMU_RESET", "EMU_IRQBRK" };
	private static final int[] VECTOR_OFFSETS = {
		0xffe4, 0xffe6, 0xffe8, 0xffea, 0xffee,
		0xfff4, 0xfff8, 0xfffa, 0xfffc, 0xfffe };

	private RealRomDumpSupport out;
	private Register ctxE;
	private Register ctxM;
	private Register ctxX;

	@Override
	protected void run() throws Exception {
		out = new RealRomDumpSupport(this, currentProgram);
		out.begin();
		println("REALROM language " + currentProgram.getLanguageID().getIdAsString());
		ctxE = currentProgram.getRegister("ctx_EF");
		ctxM = currentProgram.getRegister("ctx_MF");
		ctxX = currentProgram.getRegister("ctx_XF");
		if (ctxE == null || ctxM == null || ctxX == null) {
			println("REALROM context NONE (not a 65816 program)");
			out.end();
			return;
		}
		emitInstructions();
		emitBookmarks();
		emitVectors();
		emitCalls();
		emitExitWidths();
		emitComputed();
		out.end();
	}

	// ------------------------------------------------------------------

	private void emitInstructions() {
		Map<String, Integer> byCtx = new TreeMap<>();
		Map<String, Integer> desync = new TreeMap<>();
		Map<String, Integer> ops = new TreeMap<>();
		for (String op : List.of("PLP", "RTI", "PHP", "REP", "SEP", "XCE")) {
			ops.put(op, 0);
		}
		for (String op : List.of("BRK", "COP", "WDM", "STP")) {
			desync.put(op, 0);
		}
		int n = 0;
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			n++;
			byCtx.merge(ctx(instr), 1, Integer::sum);
			String m = instr.getMnemonicString().toUpperCase();
			desync.computeIfPresent(m, (k, v) -> v + 1);
			ops.computeIfPresent(m, (k, v) -> v + 1);
		}
		println("REALROM instrs " + n);
		println("REALROM functions " + currentProgram.getFunctionManager().getFunctionCount());
		byCtx.forEach((k, v) -> println("REALROM ctx " + k + " " + v));
		desync.forEach((k, v) -> println("REALROM desync " + k + " " + v));
		ops.forEach((k, v) -> println("REALROM ops " + k + " " + v));
	}

	private void emitBookmarks() {
		Map<String, Integer> byText = new TreeMap<>();
		var iter = currentProgram.getBookmarkManager().getBookmarksIterator("Error");
		while (iter.hasNext()) {
			Bookmark b = iter.next();
			String text = (b.getCategory() + ": " + b.getComment())
				.replaceAll("[0-9a-fA-F]{4,}", "#")
				.replaceAll("\\s+", " ");
			byText.merge(text, 1, Integer::sum);
		}
		println("REALROM bookmarks.error " + byText.values().stream().mapToInt(i -> i).sum());
		List<String> lines = new ArrayList<>();
		byText.forEach((k, v) -> lines.add(String.format("%6d %s", v, k)));
		lines.sort(Collections.reverseOrder());
		out.emitSample("bookmark", lines, SAMPLE);
	}

	private void emitVectors() {
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Listing listing = currentProgram.getListing();
		for (int i = 0; i < VECTOR_NAMES.length; i++) {
			String line = VECTOR_NAMES[i] + " ";
			try {
				int lo = currentProgram.getMemory().getByte(space.getAddress(VECTOR_OFFSETS[i])) & 0xff;
				int hi = currentProgram.getMemory().getByte(space.getAddress(VECTOR_OFFSETS[i] + 1)) & 0xff;
				int target = lo | (hi << 8);
				Address t = space.getAddress(target);
				Instruction instr = listing.getInstructionAt(t);
				Function f = currentProgram.getFunctionManager().getFunctionAt(t);
				line += String.format("%06x", target) +
					(instr == null ? " code=no" : " code=yes ctx=" + ctx(instr)) +
					" function=" + (f != null);
			}
			catch (MemoryAccessException e) {
				line += "UNREADABLE";
			}
			println("REALROM vector " + line);
		}
	}

	private void emitCalls() {
		Listing listing = currentProgram.getListing();
		int calls = 0;
		int resolved = 0;
		int disagree = 0;
		Set<Address> disagreeTargets = new HashSet<>();
		List<String> sample = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			FlowType ft = instr.getFlowType();
			if (!ft.isCall() || ft.isComputed()) {
				continue;
			}
			calls++;
			for (Address target : instr.getFlows()) {
				Instruction callee = listing.getInstructionAt(target);
				if (callee == null) {
					continue;
				}
				resolved++;
				// The width a caller hands over is its M/X at the call; E too, though a JSR
				// cannot change it.
				if (!ctx(instr).equals(ctx(callee))) {
					disagree++;
					disagreeTargets.add(target);
					sample.add(RealRomDumpSupport.fmt(instr.getMinAddress(), 6) + " " +
						ctx(instr) + " -> " + RealRomDumpSupport.fmt(target, 6) + " " + ctx(callee));
				}
			}
		}
		println("REALROM calls direct=" + calls + " decodedTarget=" + resolved +
			" widthDisagree=" + disagree + " distinctTargets=" + disagreeTargets.size());
		Collections.sort(sample);
		out.emitSample("calls.disagree", sample, SAMPLE);
	}

	private void emitExitWidths() {
		Listing listing = currentProgram.getListing();
		int functions = 0;
		int changed = 0;
		List<String> sample = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			Instruction entry = listing.getInstructionAt(f.getEntryPoint());
			if (entry == null) {
				continue;
			}
			functions++;
			Set<String> exits = new java.util.TreeSet<>();
			for (Instruction instr : listing.getInstructions(f.getBody(), true)) {
				String m = instr.getMnemonicString().toUpperCase();
				if ((m.equals("RTS") || m.equals("RTL")) && !mx(instr).equals(mx(entry))) {
					exits.add(mx(instr));
				}
			}
			if (!exits.isEmpty()) {
				changed++;
				sample.add(RealRomDumpSupport.fmt(f.getEntryPoint(), 6) + " entry=" + mx(entry) +
					" exits=" + String.join(",", exits));
			}
		}
		println("REALROM exitwidth functions=" + functions + " returnsAtOtherWidth=" + changed);
		Collections.sort(sample);
		out.emitSample("exitwidth", sample, SAMPLE);
	}

	private void emitComputed() {
		Map<String, int[]> byMnemonic = new TreeMap<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			FlowType ft = instr.getFlowType();
			if (!ft.isComputed() || ft.isTerminal()) {
				continue;
			}
			boolean any = false;
			for (Reference r : instr.getReferencesFrom()) {
				if (r.getReferenceType().isFlow()) {
					any = true;
					break;
				}
			}
			String key = instr.getMnemonicString().toUpperCase() + " " +
				instr.getDefaultOperandRepresentation(0).replaceAll("[0-9a-fA-F]{2,}", "n");
			int[] c = byMnemonic.computeIfAbsent(key, k -> new int[2]);
			c[0]++;
			if (any) {
				c[1]++;
			}
		}
		byMnemonic.forEach((k, c) ->
			println("REALROM computed " + k + " sites=" + c[0] + " withTargets=" + c[1]));
	}

	// ------------------------------------------------------------------

	private String ctx(Instruction instr) {
		return "E" + bit(instr, ctxE) + mx(instr);
	}

	private String mx(Instruction instr) {
		return "M" + bit(instr, ctxM) + "X" + bit(instr, ctxX);
	}

	private static String bit(Instruction instr, Register reg) {
		BigInteger v = instr.getValue(reg, false);
		return v == null ? "?" : v.toString();
	}
}
