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
// 65816 width/decode-conflict probe (grm-9nxj.5.5/.5.7). Run as REALROM_EXTRA_POSTSCRIPT on an
// snes-analysis row; read-only; every line is prefixed "WCP". Always prints each "conflicting
// instruction" Error bookmark with the E/M/X context of the losing flow's source, the conflicting
// instruction and what flows into it -- equal contexts on both sides mean the conflict is NOT a
// width problem (a bogus flow: table over-read, data). Optional, by environment variable:
//   GRM_SITES=a,b,...      each site's instruction, context, function, EOL, incoming flows, and
//                          the next 12 fall-through instructions
//   GRM_RANGE=s-e[,s-e]    every instruction (or undefined byte) in the range, with incoming flows
//   GRM_HEADS=s-e          block heads in the range (no fall-through predecessor), every ref in
//   GRM_E1=1               emulation-mode (E=1) instructions per 256-byte page, and every flow
//                          into E=1 code from non-E=1 code -- E=1 outside the reset path is
//                          usually code seeded at the pspec default context (grm-9nxj.5.9)
// Addresses are default-space offsets as Ghidra prints them (c22cc1, not $C2:2CC1).
//@category RetroMachines.Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class W65816ConflictProbe extends GhidraScript {
	private String ctx(Address a) {
		Instruction in = a == null ? null : currentProgram.getListing().getInstructionAt(a);
		if (in == null) {
			Instruction c = a == null ? null : currentProgram.getListing().getInstructionContaining(a);
			return c == null ? "NONE" : "INSIDE[" + c.getMinAddress() + " " + c + " " + ctxOf(c) + "]";
		}
		return in + " " + ctxOf(in);
	}

	private String ctxOf(Instruction in) {
		StringBuilder sb = new StringBuilder();
		for (String n : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
			Register r = currentProgram.getRegister(n);
			BigInteger v = in.getValue(r, false);
			sb.append(n.charAt(4)).append(v == null ? "?" : v.toString());
		}
		Function f = currentProgram.getFunctionManager().getFunctionContaining(in.getMinAddress());
		String eol = currentProgram.getListing().getComment(
			ghidra.program.model.listing.CommentType.EOL, in.getMinAddress());
		return sb + (f == null ? " fn=NONE" : " fn=" + f.getEntryPoint()) +
			(eol == null ? "" : " eol=\"" + eol.replace('\n', ' ') + "\"");
	}

	private void refsTo(String tag, Address a) {
		for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
			println(tag + "   <- " + r.getFromAddress() + " " + r.getReferenceType() + " : " +
				ctx(r.getFromAddress()));
		}
		Instruction prev = currentProgram.getListing().getInstructionBefore(a);
		if (prev != null && a.equals(prev.getFallThrough())) {
			println(tag + "   <- fallthrough " + prev.getMinAddress() + " : " + ctx(prev.getMinAddress()));
		}
	}

	@Override
	protected void run() throws Exception {
		Pattern p = Pattern.compile("at ([0-9a-fA-F:]+) due to conflicting instruction at ([0-9a-fA-F:]+) \\(flow from ([0-9a-fA-F:]+)\\)");
		Iterator<Bookmark> it = currentProgram.getBookmarkManager().getBookmarksIterator("Error");
		while (it.hasNext()) {
			Bookmark b = it.next();
			Matcher m = p.matcher(b.getComment());
			if (!m.find()) {
				Matcher f = Pattern.compile("flow from ([0-9a-fA-F:]+)").matcher(b.getComment());
				Address src = f.find() ? toAddr(f.group(1)) : null;
				println("WCP error bm=" + b.getAddress() + " \"" + b.getComment() + "\" from: " +
					(src == null ? "-" : src + " " + ctx(src)));
				continue;
			}
			Address at = toAddr(m.group(1));
			Address conf = toAddr(m.group(2));
			Address from = toAddr(m.group(3));
			println("WCP conflict bm=" + b.getAddress() + " at=" + at + " conf=" + conf + " from=" + from);
			println("WCP   from: " + ctx(from));
			println("WCP   conf: " + ctx(conf));
			println("WCP   at:   " + ctx(at));
			refsTo("WCP conf", conf);
		}
		if (System.getenv("GRM_E1") != null) {
			java.util.Map<String, Integer> pages = new java.util.TreeMap<>();
			Register e = currentProgram.getRegister("ctx_EF");
			for (Instruction in : currentProgram.getListing().getInstructions(true)) {
				BigInteger v = in.getValue(e, false);
				if (v != null && v.intValue() == 1) {
					for (Reference r : currentProgram.getReferenceManager()
							.getReferencesTo(in.getMinAddress())) {
						Instruction src = currentProgram.getListing().getInstructionAt(r.getFromAddress());
						if (r.getReferenceType().isFlow() &&
							(src == null || src.getValue(e, false) == null ||
								src.getValue(e, false).intValue() != 1)) {
							println("WCP e1entry " + in.getMinAddress() + " <- " + r.getFromAddress() +
								" " + r.getReferenceType() + " : " + ctx(r.getFromAddress()));
						}
					}
					pages.merge(in.getMinAddress().toString().replaceAll("..$", "xx"), 1, Integer::sum);
				}
			}
			pages.forEach((k, v) -> println("WCP e1 " + k + " " + v));
		}
		if (System.getenv("GRM_JMPI") != null) {
			for (Instruction in : currentProgram.getListing().getInstructions(true)) {
				String mn = in.getMnemonicString().toUpperCase();
				String op = in.getNumOperands() == 1 ? in.getDefaultOperandRepresentation(0) : "";
				boolean ind = (mn.equals("JMP") || mn.equals("JML")) &&
					((op.startsWith("(") && !op.endsWith(",X)")) || op.startsWith("["));
				if (!ind) {
					continue;
				}
				StringBuilder sb = new StringBuilder();
				Instruction cur = in;
				for (int i = 0; i < 6; i++) {
					Instruction pi = currentProgram.getListing().getInstructionBefore(cur.getMinAddress());
					if (pi == null || !cur.getMinAddress().equals(pi.getFallThrough())) {
						break;
					}
					cur = pi;
					sb.insert(0, " | " + pi + " " + ctxOf(pi).replaceAll(" fn=.*", ""));
				}
				int refs = 0;
				for (Reference r : in.getReferencesFrom()) {
					refs += r.getReferenceType().isFlow() ? 1 : 0;
				}
				println("WCP jmpi " + in.getMinAddress() + " " + in + " flows=" + refs + " ::" + sb);
			}
		}
		String heads = System.getenv("GRM_HEADS");
		if (heads != null) {
			String[] se = heads.split("-");
			ghidra.program.model.address.AddressSet s =
				new ghidra.program.model.address.AddressSet(toAddr(se[0]), toAddr(se[1]));
			for (Instruction in : currentProgram.getListing().getInstructions(s, true)) {
				Instruction prev = currentProgram.getListing().getInstructionBefore(in.getMinAddress());
				if (prev != null && in.getMinAddress().equals(prev.getFallThrough())) {
					continue;
				}
				StringBuilder sb = new StringBuilder();
				for (Reference r : currentProgram.getReferenceManager().getReferencesTo(in.getMinAddress())) {
					sb.append(" <-").append(r.getFromAddress()).append(":").append(r.getReferenceType());
				}
				var sym = currentProgram.getSymbolTable().getPrimarySymbol(in.getMinAddress());
				println("WCP head " + in.getMinAddress() + " " + in + " " + ctxOf(in) +
					(sym == null ? "" : " sym=" + sym.getName() + "/" + sym.getSource()) + sb);
			}
		}
		String range = System.getenv("GRM_RANGE");
		if (range != null) {
			for (String rr : range.split(",")) {
				String[] se = rr.trim().split("-");
				Address a = toAddr(se[0]);
				Address end = toAddr(se[1]);
				while (a != null && a.compareTo(end) <= 0) {
					Instruction in = currentProgram.getListing().getInstructionAt(a);
					if (in == null) {
						println("WCP rng " + a + " .. " + String.format("%02x",
							currentProgram.getMemory().getByte(a) & 0xff));
						a = a.next();
						continue;
					}
					StringBuilder refs = new StringBuilder();
					for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
						if (r.getReferenceType().isFlow()) {
							refs.append(" <-").append(r.getFromAddress());
						}
					}
					println("WCP rng " + a + " " + in + " " + ctxOf(in) + refs);
					a = in.getMaxAddress().next();
				}
			}
		}
		String spec = System.getenv("GRM_SITES");
		if (spec == null) {
			return;
		}
		for (String s : spec.split(",")) {
			Address a = toAddr(s.trim());
			println("WCP site " + a + ": " + ctx(a));
			refsTo("WCP site", a);
			Instruction in = currentProgram.getListing().getInstructionAt(a);
			for (int i = 0; in != null && i < 12; i++) {
				println("WCP site     " + in.getMinAddress() + " " + in + " " + ctxOf(in));
				Address n = in.getFallThrough();
				in = n == null ? null : currentProgram.getListing().getInstructionAt(n);
			}
		}
	}
}
