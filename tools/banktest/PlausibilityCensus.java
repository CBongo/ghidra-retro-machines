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
// Hardware-plausibility census (bead grm-2zlg, stage 1: measurement only): for every instruction
// (base AND overlay spaces) the NES CPU map says does something real hardware makes pointless or
// impossible, one line per hit. Such an instruction is evidence the bytes are not code (an
// over-read jump table, a fall-through into data, a misaligned decode). Each hit carries the same
// per-site annotation MapperWriteCensus (grm-nh4g) uses, so genuine code and junk can be told apart.
//
// Signals (NES CPU map hardcoded; operand addresses normalised to their physical offset, so an
// overlay-space operand compares like its base-space twin; immediates ignored, indexed modes use
// the base address):
//   ppu_mirror         S1  data access to $2008-$3FFF
//   ram_mirror         S2  data access to $0800-$1FFF
//   read_writeonly     S3  READ (load/compare/BIT/ALU or any RMW) of a write-only register:
//                          $2000,$2001,$2003,$2005,$2006 (and mirrors), $4000-$4014
//   write_readonly     S4  write to $2002 (or mirror)
//   testmode           S5  any access to $4018-$401F
//   rom_write_nonmech  S6  write/RMW to $8000-$FFFF that NO configured strategy's isMechanismWrite
//                          accepts (strategies configured by production's configureStrategies, by
//                          reflection, exactly as MapperWriteCensus does)
//   unmapped           S7  data access with no memory block at the target; or in $4020-$5FFF; or in
//                          $6000-$7FFF with no block (subcase printed as sub=...)
//   flow_into_io       S8  a flow reference (non-fall-through) whose target is in $2000-$5FFF or
//                          has no memory block
//   flow_into_ram      S8b informational: flow target in $0000-$07FF (legit for trampolines)
//   undoc              S9  mnemonic not in MWC's OFFICIAL set
//   flow_mid_instr     S10 a flow reference whose target lies strictly inside an existing
//                          instruction, or on defined data
//
// Output (all lines prefixed `HPC `):
//   HPC program <name> map=<mapPath>
//   HPC hit <signal> <space>::<addr> <mnemonic> target=<hex|?> [sub=<..>] fn=<name@entry|none>
//       inFn=<Y|N> reach=<Y|N> incoming=<fall,flow,data|none> nbr=<ok|bad:[...]> undoc=<mnemonic|->
//       head=<run head> headBack=<n> origin=<JT(..)|DIRECT(..)|DATA(..)|ENTRY|NONE,...> ins=<instr>
//   HPC sum <signal> hits=<n> genuineProxy=<n> suspect=<n> reachN=<n> nbrBad=<n> inFnN=<n> overlay=<n>
//   HPC total instrs=<n>
// Field meanings are MapperWriteCensus's: `reach` = flow-closure from external entry points
// (ProbeSupport.reachable); nbr = +/-4 code units along fall-through; origin = what disassembled
// the head of the fall-through run. genuineProxy = reach=Y AND inFn=Y AND nbr=ok; suspect = every
// other hit. For flow signals `target` is the flow target; otherwise the data operand.
// Read-only. Run as REALROM_EXTRA_POSTSCRIPT, in its own invocation (the cache key does not see
// it).
//@category RetroMachines.Test

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

public class PlausibilityCensus extends GhidraScript {

	private static final String MAP_PATH_PROPERTY = "Retro Machine Map";
	private static final int N = 4;

	private static final Set<String> OFFICIAL = Set.of("ADC", "AND", "ASL", "BCC", "BCS", "BEQ",
		"BIT", "BMI", "BNE", "BPL", "BRK", "BVC", "BVS", "CLC", "CLD", "CLI", "CLV", "CMP", "CPX",
		"CPY", "DEC", "DEX", "DEY", "EOR", "INC", "INX", "INY", "JMP", "JSR", "LDA", "LDX", "LDY",
		"LSR", "NOP", "ORA", "PHA", "PHP", "PLA", "PLP", "ROL", "ROR", "RTI", "RTS", "SBC", "SEC",
		"SED", "SEI", "STA", "STX", "STY", "TAX", "TAY", "TSX", "TXA", "TXS", "TYA");
	private static final Set<String> READS = Set.of("LDA", "LDX", "LDY", "CMP", "CPX", "CPY", "BIT",
		"ADC", "SBC", "AND", "ORA", "EOR");
	private static final Set<String> WRITES = Set.of("STA", "STX", "STY");
	private static final Set<String> RMWS = Set.of("INC", "DEC", "ASL", "LSR", "ROL", "ROR");

	private static final String[] SIGNALS = { "ppu_mirror", "ram_mirror", "read_writeonly",
		"write_readonly", "testmode", "rom_write_nonmech", "unmapped", "flow_into_io",
		"flow_into_ram", "undoc", "flow_mid_instr" };

	private record Mech(int index, String strategy, Object hooks, Method isWrite, Object strat,
			Method regOff) {
	}

	private static final class Sum {
		int hits;
		int genuine;
		int reachN;
		int nbrBad;
		int inFnN;
		int overlay;
	}

	private final Map<String, Sum> sums = new LinkedHashMap<>();

	@Override
	protected void run() throws Exception {
		Program program = currentProgram;
		String mapPath = program.getOptions(Program.PROGRAM_INFO).getString(MAP_PATH_PROPERTY, null);
		println("HPC program " + program.getName() + " map=" + mapPath);
		for (String s : SIGNALS) {
			sums.put(s, new Sum());
		}
		List<Mech> mechs = new ArrayList<>();
		if (mapPath != null && !mapPath.isBlank()) {
			loadMechs(program, mapPath, mechs);
		}

		Listing listing = program.getListing();
		ghidra.program.model.mem.Memory memory = program.getMemory();
		Set<Address> seeds = new HashSet<>();
		for (Address a : program.getSymbolTable().getExternalEntryPointIterator()) {
			seeds.add(a);
		}
		Set<Address> reached = ProbeSupport.reachable(listing, seeds, monitor);

		int total = 0;
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction instr = it.next();
			total++;
			String mnem = instr.getMnemonicString().toUpperCase();
			Ctx ctx = new Ctx(program, listing, instr, mnem, reached, seeds);

			if (!OFFICIAL.contains(mnem)) {
				hit(ctx, "undoc", null, "");
			}

			// ---- data operand signals ----
			boolean rd = READS.contains(mnem) || RMWS.contains(mnem);
			boolean wr = WRITES.contains(mnem) || RMWS.contains(mnem);
			if (rd || wr) {
				Long t = dataTarget(instr);
				if (t != null) {
					long o = t;
					Address ta = dataTargetAddr(instr);
					if (o >= 0x2008 && o <= 0x3FFF) {
						hit(ctx, "ppu_mirror", o, "");
					}
					if (o >= 0x0800 && o <= 0x1FFF) {
						hit(ctx, "ram_mirror", o, "");
					}
					boolean ppuRegion = o >= 0x2000 && o <= 0x3FFF;
					long ppuReg = o & 0x2007;
					if (rd && ((ppuRegion && (ppuReg == 0x2000 || ppuReg == 0x2001 ||
						ppuReg == 0x2003 || ppuReg == 0x2005 || ppuReg == 0x2006)) ||
						(o >= 0x4000 && o <= 0x4014))) {
						hit(ctx, "read_writeonly", o, "");
					}
					if (wr && ppuRegion && ppuReg == 0x2002) {
						hit(ctx, "write_readonly", o, "");
					}
					if (o >= 0x4018 && o <= 0x401F) {
						hit(ctx, "testmode", o, "");
					}
					if (wr && o >= 0x8000 && o <= 0xFFFF && !isMechWrite(mechs, instr)) {
						hit(ctx, "rom_write_nonmech", o, "");
					}
					String sub = null;
					if (o >= 0x4020 && o <= 0x5FFF) {
						sub = "4020-5FFF";
					}
					else if (ta != null && memory.getBlock(ta) == null) {
						sub = (o >= 0x6000 && o <= 0x7FFF) ? "6000-7FFF-noblock" : "noblock";
					}
					else if (ta == null && o >= 0x6000 && o <= 0x7FFF) {
						sub = "6000-7FFF-noblock";
					}
					if (sub != null) {
						hit(ctx, "unmapped", o, " sub=" + sub);
					}
				}
			}

			// ---- flow signals ----
			Set<Long> seen = new HashSet<>();
			for (Reference r : instr.getReferencesFrom()) {
				if (!r.getReferenceType().isFlow() || r.getReferenceType().isFallthrough() ||
					!r.getToAddress().isMemoryAddress()) {
					continue;
				}
				Address t = r.getToAddress();
				long o = t.getOffset();
				if (!seen.add(o)) {
					continue;
				}
				if ((o >= 0x2000 && o <= 0x5FFF) || memory.getBlock(t) == null) {
					hit(ctx, "flow_into_io", o, "");
				}
				if (o < 0x0800) {
					hit(ctx, "flow_into_ram", o, "");
				}
				Instruction in = listing.getInstructionContaining(t);
				boolean mid = in != null && !in.getMinAddress().equals(t);
				if (!mid && in == null) {
					ghidra.program.model.listing.Data d = listing.getDefinedDataContaining(t);
					mid = d != null;
				}
				if (mid) {
					hit(ctx, "flow_mid_instr", o, "");
				}
			}
		}
		for (Map.Entry<String, Sum> e : sums.entrySet()) {
			Sum s = e.getValue();
			println("HPC sum " + e.getKey() + " hits=" + s.hits + " genuineProxy=" + s.genuine +
				" suspect=" + (s.hits - s.genuine) + " reachN=" + s.reachN + " nbrBad=" + s.nbrBad +
				" inFnN=" + s.inFnN + " overlay=" + s.overlay);
		}
		println("HPC total instrs=" + total);
	}

	private record Ctx(Program program, Listing listing, Instruction instr, String mnem,
			Set<Address> reached, Set<Address> seeds) {
	}

	private void hit(Ctx c, String signal, Long target, String extra) {
		Instruction instr = c.instr();
		Address site = instr.getMinAddress();
		Function fn = c.listing().getFunctionContaining(site);
		boolean reach = c.reached().contains(site);
		String nbr = neighbours(c.program(), instr);
		boolean inFn = fn != null;
		Sum s = sums.get(signal);
		s.hits++;
		if (!reach) {
			s.reachN++;
		}
		if (!"ok".equals(nbr)) {
			s.nbrBad++;
		}
		if (!inFn) {
			s.inFnN++;
		}
		if (reach && inFn && "ok".equals(nbr)) {
			s.genuine++;
		}
		if (site.getAddressSpace().isOverlaySpace()) {
			s.overlay++;
		}
		println("HPC hit " + signal + " " + fmt(site) + " " + c.mnem() + " target=" +
			(target == null ? "-" : String.format("%04x", target)) + extra + " fn=" +
			(fn == null ? "none" : fn.getName() + "@" + fmt(fn.getEntryPoint())) + " inFn=" +
			(inFn ? "Y" : "N") + " reach=" + (reach ? "Y" : "N") + " incoming=" +
			incoming(c.listing(), instr) + " nbr=" + nbr + " undoc=" +
			(OFFICIAL.contains(c.mnem()) ? "-" : c.mnem()) + " " + origin(c.listing(), instr, c.seeds()) +
			" ins=" + instr.toString().replace(' ', '_'));
	}

	private static boolean isMechWrite(List<Mech> mechs, Instruction instr) {
		for (Mech m : mechs) {
			try {
				boolean w = m.regOff() != null ? m.regOff().invoke(m.strat(), instr) != null
					: (Boolean) m.isWrite().invoke(m.hooks(), instr);
				if (w) {
					return true;
				}
			}
			catch (ReflectiveOperationException e) {
				// treat as not recognized by this mechanism
			}
		}
		return false;
	}

	/** Address of the memory operand (first non-flow, non-immediate memory reference, else the
	 *  plain absolute / indexed base), or null. */
	private static Address dataTargetAddr(Instruction instr) {
		if (instr.getNumOperands() == 0) {
			return null;
		}
		String op = instr.getDefaultOperandRepresentation(0);
		if (op == null || op.startsWith("#") || op.equalsIgnoreCase("A")) {
			return null;
		}
		for (Reference ref : instr.getReferencesFrom()) {
			if (!ref.getReferenceType().isFlow() && ref.getToAddress().isMemoryAddress() &&
				!ref.getReferenceType().isIndirect()) {
				return ref.getToAddress();
			}
		}
		Address a = ProbeSupport.plainAbsoluteTarget(instr);
		if (a == null) {
			a = ProbeSupport.indexedBase(instr);
		}
		return a;
	}

	private static Long dataTarget(Instruction instr) {
		Address a = dataTargetAddr(instr);
		return a == null ? null : a.getOffset();
	}

	private void loadMechs(Program program, String mapPath, List<Mech> mechs) {
		try {
			ClassLoader cl = PlausibilityCensus.class.getClassLoader();
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
			Object board = parse.invoke(null, map, log, "PlausibilityCensus", mapPath,
				readInit.invoke(null, program));
			if (board == null) {
				println("HPC error BoardModel.parse returned null: " + log);
				return;
			}

			Class<?> reg = Class.forName("retromachines.BankStrategyRegistry", true, cl);
			Class<?> analyzerCls = Class.forName("ghidra.app.services.Analyzer", true, cl);
			Method configure = reg.getDeclaredMethod("configureStrategies", analyzerCls,
				Program.class, JsonArray.class, bdm, MessageLog.class);
			configure.setAccessible(true);
			JsonObject banking = map.getAsJsonObject("banking");
			if (banking == null) {
				return;
			}
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
			int i = 0;
			for (Object cm : configured) {
				Object strat = strategyOf.invoke(cm);
				Object hooks = callerHooks.invoke(strat);
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
				println("HPC mech " + i + " strategy=" + strategyName.invoke(strat));
				i++;
			}
		}
		catch (ReflectiveOperationException e) {
			println("HPC error cannot reach production recognition: " + e + " / " + e.getCause());
		}
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
