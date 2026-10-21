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
// Census of mapper-register write sites (bead grm-nh4g): for every instruction (base AND overlay
// spaces) that one of the board's configured BankSwitchStrategy instances recognizes as a
// mechanism write, one line with the site, the store target, the mechanism it hit, the owning
// function, and a neighbour-validity signal (is the surrounding code plausible, or does the
// "register write" sit in junk?). Then a per-program histogram of distinct target addresses per
// mechanism register, with site counts.
//
// RECOGNITION IS PRODUCTION'S, NOT A RE-IMPLEMENTATION: the descriptor is parsed and the
// strategies configured by the same BankStrategyRegistry.configureStrategies the analyzer calls,
// and a site is a hit when that strategy's callerSideHooks().isMechanismWrite(instr) says so (the
// hook StoredValueScanner / CrossBlockStackPairing consult, which for select-data, serial-shift
// and memory-latch delegates to the very registerOffsetWritten / writesInRange the dataflow
// engine's direct-site path uses). Those classes are package-private, so they are reached by
// reflection (as BankContextProbe does); `MWC error` says when that fails. A mechanism whose
// strategy has INERT caller-side hooks (nothing recognized) is named in `MWC mech`.
//
// Output (all lines prefixed `MWC `):
//   MWC program <name> map=<mapPath>
//   MWC mech <i> strategy=<s> hooks=<live|inert>
//   MWC site <space>::<addr> <mnemonic> target=<hex> mech=<i>:<strategy> parity=<even|odd>
//       fn=<name@entry|none> inFn=<Y|N> reach=<Y|N> incoming=<fall,flow,data|none>
//       nbr=<ok|bad:[B-1:undefined,F+2:badbookmark,...]> undoc=<mnemonic|->
//       head=<run head> headBack=<n> origin=<JT(..)|DIRECT(..)|DATA(..)|ENTRY|NONE,...> ins=<instr>
//   (origin = what disassembled the head of the fall-through run holding the site; JT's slot=k/n
//   is the position in the jump's reference array, NOT a verified table index)
//   MWC hist mech=<i>:<strategy> parity=<p> target=<hex> sites=<n>
//   MWC total sites=<n> overlaySites=<n> baseSites=<n>
// `reach` = reachable by flow-closure from the program's external entry points (the same shape
// as ProbeSupport.reachable, which this reuses). NEIGHBOUR WINDOW = N=4 code units before/after,
// walked only along fall-through (a block boundary stops the walk silently).
// Read-only. Run as REALROM_EXTRA_POSTSCRIPT, in its own invocation (the cache key does not see
// it).
//@category RetroMachines.Test

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class MapperWriteCensus extends GhidraScript {

	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";
	private static final int N = 4;

	private static final Set<String> OFFICIAL = Set.of("ADC", "AND", "ASL", "BCC", "BCS", "BEQ",
		"BIT", "BMI", "BNE", "BPL", "BRK", "BVC", "BVS", "CLC", "CLD", "CLI", "CLV", "CMP", "CPX",
		"CPY", "DEC", "DEX", "DEY", "EOR", "INC", "INX", "INY", "JMP", "JSR", "LDA", "LDX", "LDY",
		"LSR", "NOP", "ORA", "PHA", "PHP", "PLA", "PLP", "ROL", "ROR", "RTI", "RTS", "SBC", "SEC",
		"SED", "SEI", "STA", "STX", "STY", "TAX", "TAY", "TSX", "TXA", "TXS", "TYA");

	private record Mech(int index, String strategy, Object hooks, Method isWrite, Object strat,
			Method regOff) {
	}

	@Override
	protected void run() throws Exception {
		Program program = currentProgram;
		String mapPath = program.getOptions(Program.PROGRAM_INFO).getString(MAP_PATH_PROPERTY, null);
		println("MWC program " + program.getName() + " map=" + mapPath);
		if (mapPath == null || mapPath.isBlank()) {
			println("MWC none (no '" + MAP_PATH_PROPERTY + "' property)");
			return;
		}

		List<Mech> mechs = new ArrayList<>();
		try {
			ClassLoader cl = MapperWriteCensus.class.getClassLoader();
			Class<?> res = Class.forName("retromachines.DescriptorResources", true, cl);
			Method loadMap = res.getDeclaredMethod("loadMap", String.class);
			loadMap.setAccessible(true);
			JsonObject map = (JsonObject) loadMap.invoke(null, mapPath);

			Class<?> bdm = Class.forName("retromachines.BoardDescriptorModel$BoardModel", true, cl);
			Method parse = bdm.getDeclaredMethod("parse", JsonObject.class, MessageLog.class,
				String.class, String.class, Integer.class);
			parse.setAccessible(true);
			Class<?> hints = Class.forName("retromachines.DescriptorHints", true, cl);
			Method readInit = hints.getDeclaredMethod("readResolvedInitialState", Program.class);
			readInit.setAccessible(true);
			MessageLog log = new MessageLog();
			Object board = parse.invoke(null, map, log, "MapperWriteCensus", mapPath,
				readInit.invoke(null, program));
			if (board == null) {
				println("MWC none (BoardModel.parse returned null: " + log + ")");
				return;
			}

			Class<?> reg = Class.forName("retromachines.BankStrategyRegistry", true, cl);
			Class<?> analyzerCls = Class.forName("ghidra.app.services.Analyzer", true, cl);
			Method configure = reg.getDeclaredMethod("configureStrategies", analyzerCls,
				Program.class, JsonArray.class, bdm, MessageLog.class);
			configure.setAccessible(true);
			JsonObject banking = map.getAsJsonObject("banking");
			List<?> configured = (List<?>) configure.invoke(null, null, program,
				banking.getAsJsonArray("mechanisms"), board, log);

			Class<?> cmCls = Class.forName("retromachines.BankStrategyRegistry$ConfiguredMechanism",
				true, cl);
			Method strategyOf = cmCls.getDeclaredMethod("strategy");
			strategyOf.setAccessible(true);
			Class<?> bss = Class.forName("retromachines.BankSwitchStrategy", true, cl);
			Method callerHooks = bss.getDeclaredMethod("callerSideHooks");
			callerHooks.setAccessible(true);
			Method strategyName = bss.getDeclaredMethod("strategyName");
			Class<?> hooksCls = Class.forName("retromachines.StoredValueScanner$Hooks", true, cl);
			Method isWrite = hooksCls.getDeclaredMethod("isMechanismWrite", Instruction.class);
			isWrite.setAccessible(true);
			Object inertHooks = null;
			try {
				java.lang.reflect.Field f = hooksCls.getDeclaredField("INERT");
				f.setAccessible(true);
				inertHooks = f.get(null);
			}
			catch (ReflectiveOperationException e) {
				// leave null: every mechanism then reads as live
			}
			int i = 0;
			for (Object cm : configured) {
				Object strat = strategyOf.invoke(cm);
				Object hooks = callerHooks.invoke(strat);
				boolean isInert = inertHooks != null && hooks == inertHooks;
				Method regOff = null;
				try {
					regOff = Class.forName("retromachines.AbstractRangeBankSwitchStrategy", true, cl)
						.getDeclaredMethod("registerOffsetWritten", Instruction.class);
					regOff.setAccessible(true);
					if (!regOff.getDeclaringClass().isInstance(strat) ||
						"memory-latch".equals(strategyName.invoke(strat))) {
						regOff = null;
					}
				}
				catch (ReflectiveOperationException e) {
					regOff = null;
				}
				mechs.add(new Mech(i, (String) strategyName.invoke(strat), hooks, isWrite, strat,
					regOff));
				println("MWC mech " + i + " strategy=" + strategyName.invoke(strat) + " hooks=" +
					(isInert ? "inert" : "live") + " class=" + strat.getClass().getSimpleName());
				i++;
			}
		}
		catch (ReflectiveOperationException e) {
			println("MWC error cannot reach production recognition: " + e + " / " + e.getCause());
			return;
		}
		if (mechs.isEmpty()) {
			println("MWC none (no configured mechanism)");
			return;
		}

		Listing listing = program.getListing();
		Set<Address> seeds = new HashSet<>();
		for (Address a : program.getSymbolTable().getExternalEntryPointIterator()) {
			seeds.add(a);
		}
		Set<Address> reached = ProbeSupport.reachable(listing, seeds, monitor);

		Map<String, Integer> hist = new TreeMap<>();
		int total = 0;
		int overlay = 0;
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction instr = it.next();
			Mech hit = null;
			for (Mech m : mechs) {
				boolean w;
				try {
					w = m.regOff() != null ? m.regOff().invoke(m.strat(), instr) != null
						: (Boolean) m.isWrite().invoke(m.hooks(), instr);
				}
				catch (ReflectiveOperationException e) {
					continue;
				}
				if (w) {
					hit = m;
					break; // first strategy that recognizes wins, as in the engine
				}
			}
			if (hit == null) {
				continue;
			}
			Address site = instr.getMinAddress();
			Long target = targetOffset(instr);
			String parity = target == null ? "?" : ((target & 1) == 0 ? "even" : "odd");
			if (!"select-data".equals(hit.strategy())) {
				parity = "-";
			}
			Function fn = listing.getFunctionContaining(site);
			String mnem = instr.getMnemonicString().toUpperCase();
			println("MWC site " + fmt(site) + " " + mnem + " target=" +
				(target == null ? "?" : String.format("%04x", target)) + " mech=" + hit.index() +
				":" + hit.strategy() + " parity=" + parity + " fn=" +
				(fn == null ? "none" : fn.getName() + "@" + fmt(fn.getEntryPoint())) + " inFn=" +
				(fn == null ? "N" : "Y") + " reach=" + (reached.contains(site) ? "Y" : "N") +
				" incoming=" + incoming(listing, instr) + " nbr=" + neighbours(program, instr) +
				" undoc=" + (OFFICIAL.contains(mnem) ? "-" : mnem) + " " +
				origin(listing, instr, seeds) + " ins=" + instr.toString().replace(' ', '_'));
			hist.merge(hit.index() + ":" + hit.strategy() + " parity=" + parity + " target=" +
				(target == null ? "?" : String.format("%04x", target)), 1, Integer::sum);
			total++;
			if (site.getAddressSpace().isOverlaySpace()) {
				overlay++;
			}
		}
		for (Map.Entry<String, Integer> e : hist.entrySet()) {
			println("MWC hist mech=" + e.getKey() + " sites=" + e.getValue());
		}
		println("MWC total sites=" + total + " overlaySites=" + overlay + " baseSites=" +
			(total - overlay));
	}

	/** The store target offset: the first memory write reference, else the plain absolute
	 *  operand. */
	private static Long targetOffset(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isWrite() && ref.getToAddress().isMemoryAddress()) {
				return ref.getToAddress().getOffset();
			}
		}
		Address a = ProbeSupport.plainAbsoluteTarget(instr);
		return a == null ? null : a.getOffset();
	}

	/** Which kinds of incoming edge reach this instruction: fall (a preceding instruction's
	 *  fall-through lands here), flow (a flow reference), data (a non-flow reference). */
	private static String incoming(Listing listing, Instruction instr) {
		List<String> in = new ArrayList<>();
		Address a = instr.getMinAddress();
		CodeUnit before = listing.getCodeUnitBefore(a);
		if (before instanceof Instruction p && a.equals(p.getFallThrough())) {
			in.add("fall");
		}
		boolean flow = false;
		boolean data = false;
		ReferenceIterator refs = instr.getProgram().getReferenceManager().getReferencesTo(a);
		while (refs.hasNext()) {
			Reference r = refs.next();
			if (r.getReferenceType().isFlow()) {
				flow = true;
			}
			else {
				data = true;
			}
		}
		if (flow) {
			in.add("flow");
		}
		if (data) {
			in.add("data");
		}
		return in.isEmpty() ? "none" : String.join(",", in);
	}

	/** N units each way along fall-through; "ok" or "bad:[tags]". */
	private String neighbours(Program program, Instruction instr) {
		List<String> bad = new ArrayList<>();
		Listing listing = program.getListing();
		if (badBookmark(program, instr.getMinAddress())) {
			bad.add("S:badbookmark");
		}
		Instruction cur = instr;
		for (int i = 1; i <= N; i++) {
			CodeUnit prev = listing.getCodeUnitBefore(cur.getMinAddress());
			if (prev == null || !prev.getMaxAddress().next().equals(cur.getMinAddress())) {
				break;
			}
			if (prev instanceof Instruction pi) {
				if (!cur.getMinAddress().equals(pi.getFallThrough())) {
					break; // block boundary, normal
				}
				if (badBookmark(program, pi.getMinAddress())) {
					bad.add("B-" + i + ":badbookmark");
				}
				cur = pi;
			}
			else {
				bad.add("B-" + i + (isDefinedData(prev) ? ":data" : ":undefined"));
				break;
			}
		}
		cur = instr;
		for (int i = 1; i <= N; i++) {
			Address ft = cur.getFallThrough();
			if (ft == null) {
				break; // terminal (RTS/JMP/...): normal end of block
			}
			CodeUnit next = listing.getCodeUnitAt(ft);
			if (next instanceof Instruction ni) {
				if (badBookmark(program, ni.getMinAddress())) {
					bad.add("F+" + i + ":badbookmark");
				}
				cur = ni;
			}
			else {
				bad.add("F+" + i + (next == null ? ":nomemory"
						: isDefinedData(next) ? ":data" : ":undefined"));
				break;
			}
		}
		return bad.isEmpty() ? "ok" : "bad:[" + String.join(",", bad) + "]";
	}

	/** Flow origin of the fall-through run containing {@code instr}: walks back to the run head
	 *  (SiteStateProbe's logic) and classifies every reference to the head: JT (computed jump or
	 *  call: from, slot k of n flow targets, any [JumpTableBound] comment), DIRECT, DATA; ENTRY
	 *  when the head is an external entry point; NONE otherwise. */
	private String origin(Listing listing, Instruction instr, Set<Address> seeds) {
		Instruction head = instr;
		int back = 0;
		for (int i = 0; i < 4096; i++) {
			Instruction p = listing.getInstructionBefore(head.getMinAddress());
			if (p == null || !head.getMinAddress().equals(p.getFallThrough())) {
				break;
			}
			head = p;
			back++;
		}
		Address h = head.getMinAddress();
		List<String> parts = new ArrayList<>();
		if (seeds.contains(h)) {
			parts.add("ENTRY");
		}
		ReferenceIterator refs = instr.getProgram().getReferenceManager().getReferencesTo(h);
		while (refs.hasNext()) {
			Reference r = refs.next();
			Address from = r.getFromAddress();
			Instruction fi = listing.getInstructionAt(from);
			String x = from.getAddressSpace().equals(h.getAddressSpace()) ? "" : "/xspace";
			if (fi != null && r.getReferenceType().isFlow() && r.getReferenceType().isComputed()) {
				int n = 0;
				int k = -1;
				for (Reference o : fi.getReferencesFrom()) {
					if (o.getReferenceType().isFlow()) {
						if (o.getToAddress().equals(h) && k < 0) {
							k = n;
						}
						n++;
					}
				}
				String eol = listing.getComment(ghidra.program.model.listing.CommentType.EOL, from);
				String bound = eol != null && eol.contains("[JumpTableBound]")
						? " bound=" + eol.replace('\n', ' ').replace(' ', '_') : "";
				parts.add("JT(" + fmt(from) + " " + fi.getMnemonicString() + " slot=" + k + "/" + n +
					bound + ")" + x);
			}
			else if (r.getReferenceType().isFlow()) {
				parts.add("DIRECT(" + r.getReferenceType().getName() + "@" + fmt(from) + ")" + x);
			}
			else {
				parts.add("DATA(" + r.getReferenceType().getName() + "@" + fmt(from) + ")" + x);
			}
		}
		if (parts.isEmpty()) {
			parts.add("NONE");
		}
		return "head=" + fmt(h) + " headBack=" + back + " origin=" + String.join("|", parts);
	}

	private static boolean isDefinedData(CodeUnit cu) {
		return cu instanceof ghidra.program.model.listing.Data d && d.isDefined();
	}

	private static boolean badBookmark(Program program, Address a) {
		for (ghidra.program.model.listing.Bookmark b : program.getBookmarkManager()
				.getBookmarks(a)) {
			String t = b.getTypeString();
			if ("Error".equals(t) || "Bad Instruction".equals(t)) {
				return true;
			}
		}
		return false;
	}

	private static String fmt(Address a) {
		return a.getAddressSpace().getName() + "::" + String.format("%04x", a.getOffset());
	}
}
