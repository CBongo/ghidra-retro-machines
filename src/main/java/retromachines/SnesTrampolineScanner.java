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
package retromachines;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

/**
 * Statically recovers the NMI/IRQ handlers a SNES game reaches only through a RAM trampoline
 * (bead grm-9nxj.5.6).
 *
 * <p>Most games point the native NMI/IRQ vectors ({@code $00:FFEA}/{@code $00:FFEE}) at low RAM
 * that the reset code fills with a {@code JML}/{@code JMP} at boot -- or (Chrono Trigger, Final
 * Fantasy III) at a ROM stub that is itself a {@code JML} into such RAM. This scanner follows the
 * chain: a ROM {@code JMP abs}/{@code JML long} whose destination is low RAM is a hop into RAM;
 * the RAM bytes are recovered from the constant stores the program makes to them; the recovered
 * {@code JMP}/{@code JML} gives the next address. The chain is bounded at {@value #MAX_HOPS} hops
 * and ends at the first ROM address that is not such a hop -- the handler.
 *
 * <p><b>What counts as a recovered byte</b> (deliberately the simplest sound rule): every
 * {@code STA}/{@code STX}/{@code STY}/{@code STZ} in absolute or long addressing whose effective
 * address is in the low-RAM view ({@code $0000-$1FFF} of banks {@code $00-$3F/$80-$BF}, or
 * {@code $7E}) contributes the bytes it writes, the stored value being a constant only when the
 * immediately dominating straight-line instruction loaded it: a {@code LDA/LDX/LDY #imm} found by
 * walking back through fall-through instructions with no other instruction that changes that
 * register in between, and no incoming branch, call or jump into the walked instructions. The
 * store width is the M (A/Z) or X (X/Y) flag in the program context at the store, and must equal
 * the immediate's width. Absolute stores assume DBR is a low-RAM bank. Direct-page, indexed,
 * indirect, block-move and DMA writes are NOT tracked. A byte is usable only if it receives
 * exactly one distinct constant and no write of unknown value; anything else is ambiguous and the
 * hop is not followed.
 */
final class SnesTrampolineScanner {

	/** The longest ROM stub / RAM trampoline chain followed. */
	static final int MAX_HOPS = 4;
	/** The most distinct handlers seeded per vector. */
	static final int MAX_CANDIDATES = 16;
	/** How far (bytes) after the opcode store its operand stores may sit. */
	static final int GROUP_WINDOW = 48;
	private static final int LOOKBACK = 8;

	/**
	 * A recovered handler.
	 *
	 * @param name {@code NMI} or {@code IRQ}
	 * @param vectorTarget where the native vector points (bank $00)
	 * @param entry the handler, a ROM address
	 * @param trampoline the first RAM address of the chain (normalized to {@code $00:xxxx})
	 * @param sites the store instructions that supplied the trampoline bytes
	 */
	record Handler(String name, Address vectorTarget, Address entry, long trampoline,
			List<Address> sites) {}

	private static final class ByteWrites {
		final Set<Integer> values = new LinkedHashSet<>();
		final List<Address> sites = new ArrayList<>();
		boolean unknown;
	}

	private final Program program;
	private final AddressSpace space;
	private final List<String> notes;
	private Map<Long, ByteWrites> writes;
	private List<Rec> recs;
	private Address curRun;

	/** One constant-or-unknown byte written to low RAM by one store, in program order. */
	private record Rec(long t, Integer value, Address site, Address run) {}

	private SnesTrampolineScanner(Program program, List<String> notes) {
		this.program = program;
		this.space = program.getAddressFactory().getDefaultAddressSpace();
		this.notes = notes;
	}

	/**
	 * Resolves both native vectors.
	 *
	 * @param program a SNES program (the code must already be disassembled)
	 * @param notes receives one line per vector that could not be resolved
	 * @return the handlers found behind RAM trampolines; empty when the vectors are plain ROM
	 */
	static List<Handler> scan(Program program, List<String> notes) {
		SnesTrampolineScanner s = new SnesTrampolineScanner(program, notes);
		List<Handler> out = new ArrayList<>();
		s.follow("NMI", 0xFFEA, out);
		s.follow("IRQ", 0xFFEE, out);
		return out;
	}

	/** The low-RAM view offset ({@code 0-0x1FFF}) of an address, or -1 if it is not low RAM. */
	static long ramView(long a) {
		int bank = (int) ((a >> 16) & 0xFF);
		long off = a & 0xFFFF;
		boolean sys = bank <= 0x3F || (bank >= 0x80 && bank <= 0xBF);
		if ((sys || bank == 0x7E) && off < 0x2000) {
			return off;
		}
		return -1;
	}

	private int byteAt(Address a) {
		try {
			return program.getMemory().getByte(a) & 0xFF;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return -1;
		}
	}

	private boolean isRom(Address a) {
		MemoryBlock b = program.getMemory().getBlock(a);
		return b != null && b.getName().startsWith("ROM_");
	}

	/** The destination of a ROM {@code JMP abs}/{@code JML long} at a, or null. */
	private Address jumpDest(Address a) {
		int op = byteAt(a);
		if (op != 0x4C && op != 0x5C) {
			return null;
		}
		int lo = byteAt(a.add(1));
		int hi = byteAt(a.add(2));
		int bank = op == 0x5C ? byteAt(a.add(3)) : (int) ((a.getOffset() >> 16) & 0xFF);
		if (lo < 0 || hi < 0 || bank < 0) {
			return null;
		}
		return space.getAddress(((long) bank << 16) | (hi << 8) | lo);
	}

	/** One resolved trampoline content: the jump destination and the stores that wrote it. */
	private record Cand(Address dest, List<Address> sites) {}

	private void follow(String name, int slot, List<Handler> out) {
		int lo = byteAt(space.getAddress(slot));
		int hi = byteAt(space.getAddress(slot + 1));
		if (lo < 0 || hi < 0) {
			return;
		}
		int target = lo | (hi << 8);
		if (target >= 0xFFE0) {
			return;
		}
		Address vector = space.getAddress(target);
		List<Handler> found = new ArrayList<>();
		expand(name, vector, vector, 0, -1, List.of(), found);
		// One handler per distinct entry, store sites merged.
		Map<Address, Handler> byEntry = new LinkedHashMap<>();
		for (Handler h : found) {
			byEntry.merge(h.entry(), h, (x, y) -> {
				Set<Address> all = new LinkedHashSet<>(x.sites());
				all.addAll(y.sites());
				return new Handler(x.name(), x.vectorTarget(), x.entry(), x.trampoline(),
					List.copyOf(all));
			});
		}
		if (byEntry.size() > MAX_CANDIDATES) {
			notes.add(name + ": " + byEntry.size() + " candidate handlers (more than " +
				MAX_CANDIDATES + "); none seeded");
			return;
		}
		out.addAll(byEntry.values());
	}

	private void expand(String name, Address vector, Address cur, int hop, long firstRam,
			List<Address> sites, List<Handler> found) {
		long t = ramView(cur.getOffset());
		if (t >= 0) {
			if (hop >= MAX_HOPS) {
				notes.add(name + ": more than " + MAX_HOPS + " hops; not followed");
				return;
			}
			long first = firstRam < 0 ? t : firstRam;
			for (Cand c : resolveAll(name, t)) {
				List<Address> s2 = new ArrayList<>(sites);
				s2.addAll(c.sites());
				expand(name, vector, c.dest(), hop + 1, first, s2, found);
			}
			return;
		}
		Address dest = jumpDest(cur);
		if (dest != null && ramView(dest.getOffset()) >= 0) {
			if (hop >= MAX_HOPS) {
				notes.add(name + ": more than " + MAX_HOPS + " hops; not followed");
				return;
			}
			expand(name, vector, dest, hop + 1, firstRam, sites, found);
			return;
		}
		if (firstRam < 0 || cur.equals(vector)) {
			return;
		}
		if (!isRom(cur)) {
			notes.add(name + ": excluded target " + cur + " (not ROM)");
			return;
		}
		found.add(new Handler(name, vector, cur, firstRam,
			List.copyOf(new LinkedHashSet<>(sites))));
	}

	/**
	 * What the program stores at low-RAM offset t, as jump destinations: the single unique-constant
	 * reading if every byte has exactly one constant, otherwise every complete store group.
	 */
	private List<Cand> resolveAll(String name, long t) {
		Cand unique = resolveUnique(t);
		if (unique != null) {
			return List.of(unique);
		}
		return groups(name, t);
	}

	private Cand resolveUnique(long t) {
		Map<Long, ByteWrites> w = writes();
		ByteWrites opW = w.get(t);
		Integer op = single(opW);
		if (op == null || (op != 0x5C && op != 0x4C)) {
			return null;
		}
		int n = op == 0x5C ? 3 : 2;
		int[] v = new int[3];
		List<Address> sites = new ArrayList<>(opW.sites);
		for (int i = 0; i < n; i++) {
			ByteWrites bw = w.get(t + 1 + i);
			Integer x = single(bw);
			if (x == null) {
				return null;
			}
			v[i] = x;
			sites.addAll(bw.sites);
		}
		long dest = op == 0x5C ? ((long) v[2] << 16) | (v[1] << 8) | v[0] : (v[1] << 8) | v[0];
		return new Cand(space.getAddress(dest), sites);
	}

	/**
	 * Complete store groups for the trampoline at t. A group starts at a constant store of
	 * {@code $5C}/{@code $4C} to t and takes, from the SAME straight-line run, the last constant
	 * store to each operand byte after it, before the next store to t, within
	 * {@value #GROUP_WINDOW} bytes. Stores of {@code $6B} (RTL: handler disabled), groups with a
	 * non-constant operand store, and incomplete groups are logged and skipped.
	 */
	private List<Cand> groups(String name, long t) {
		records();
		Map<Address, List<Rec>> byRun = new LinkedHashMap<>();
		for (Rec r : recs) {
			if (r.t() >= t && r.t() <= t + 3) {
				byRun.computeIfAbsent(r.run(), k -> new ArrayList<>()).add(r);
			}
		}
		Map<Address, Cand> byDest = new LinkedHashMap<>();
		int rtl = 0;
		int incomplete = 0;
		int nonConstant = 0;
		for (List<Rec> run : byRun.values()) {
			for (int i = 0; i < run.size(); i++) {
				Rec r = run.get(i);
				if (r.t() != t) {
					continue;
				}
				if (r.value() == null) {
					nonConstant++;
					continue;
				}
				int op = r.value();
				if (op == 0x6B) {
					rtl++;
					continue;
				}
				if (op != 0x5C && op != 0x4C) {
					continue;
				}
				int n = op == 0x5C ? 3 : 2;
				int[] v = new int[3];
				boolean[] have = new boolean[3];
				boolean bad = false;
				List<Address> sites = new ArrayList<>(List.of(r.site()));
				for (int k = i + 1; k < run.size(); k++) {
					Rec q = run.get(k);
					if (q.t() == t) {
						break;
					}
					if (q.site().getOffset() - r.site().getOffset() > GROUP_WINDOW) {
						break;
					}
					int idx = (int) (q.t() - t - 1);
					if (idx >= n) {
						continue;
					}
					if (q.value() == null) {
						bad = true;
						continue;
					}
					v[idx] = q.value();
					have[idx] = true;
					bad = false;
					if (!sites.contains(q.site())) {
						sites.add(q.site());
					}
				}
				for (int k = 0; k < n; k++) {
					bad |= !have[k];
				}
				if (bad) {
					incomplete++;
					continue;
				}
				long dest = op == 0x5C ? ((long) v[2] << 16) | (v[1] << 8) | v[0]
						: (v[1] << 8) | v[0];
				Address d = space.getAddress(dest);
				byDest.merge(d, new Cand(d, sites), (x, y) -> {
					Set<Address> all = new LinkedHashSet<>(x.sites());
					all.addAll(y.sites());
					return new Cand(x.dest(), new ArrayList<>(all));
				});
			}
		}
		notes.add(String.format("%s: trampoline $%04X: %d store group(s), %d RTL (disabled) " +
			"store(s), %d incomplete group(s), %d non-constant opcode store(s)", name, t,
			byDest.size(), rtl, incomplete, nonConstant));
		return new ArrayList<>(byDest.values());
	}

	private static Integer single(ByteWrites w) {
		if (w == null || w.unknown || w.values.size() != 1) {
			return null;
		}
		return w.values.iterator().next();
	}

	// ------------------------------------------------------------------
	// Store scan
	// ------------------------------------------------------------------

	private Map<Long, ByteWrites> writes() {
		records();
		return writes;
	}

	private void records() {
		if (writes != null) {
			return;
		}
		writes = new HashMap<>();
		recs = new ArrayList<>();
		Register mf = program.getRegister("ctx_MF");
		Register xf = program.getRegister("ctx_XF");
		InstructionIterator it = program.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			int op;
			try {
				op = ins.getByte(0) & 0xFF;
			}
			catch (MemoryAccessException e) {
				continue;
			}
			char reg;       // 'A' A or zero via M, 'X', 'Y'
			boolean isLong = false;
			switch (op) {
				case 0x8D -> reg = 'A';
				case 0x8F -> {
					reg = 'A';
					isLong = true;
				}
				case 0x9C -> reg = 'Z';
				case 0x8E -> reg = 'X';
				case 0x8C -> reg = 'Y';
				default -> {
					continue;
				}
			}
			int lo = byteAt(ins.getAddress().add(1));
			int hi = byteAt(ins.getAddress().add(2));
			if (lo < 0 || hi < 0) {
				continue;
			}
			long ea = (hi << 8) | lo;
			if (isLong) {
				int bank = byteAt(ins.getAddress().add(3));
				ea |= (long) Math.max(bank, 0) << 16;
			}
			long t = ramView(ea);
			if (t < 0) {
				continue;
			}
			curRun = runStart(ins);
			Register flag = (reg == 'X' || reg == 'Y') ? xf : mf;
			int width = widthOf(ins, flag);
			if (width == 0) {
				mark(t, null, ins);
				mark(t + 1, null, ins);
				continue;
			}
			Long value = reg == 'Z' ? Long.valueOf(0) : constantBefore(ins, reg, width);
			for (int i = 0; i < width; i++) {
				mark(t + i, value == null ? null : (int) ((value >> (8 * i)) & 0xFF), ins);
			}
		}
	}

	/** First instruction of the straight-line fall-through run containing ins. */
	private Address runStart(Instruction ins) {
		Instruction cur = ins;
		for (int step = 0; step < 64; step++) {
			if (hasNonFallthroughEntry(cur)) {
				break;
			}
			Instruction prev = cur.getPrevious();
			if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) ||
				prev.getFlowType().isCall() || prev.getFlowType().isJump() ||
				prev.getFlowType().isTerminal()) {
				break;
			}
			cur = prev;
		}
		return cur.getAddress();
	}

	private void mark(long t, Integer value, Instruction site) {
		if (t >= 0x2000) {
			return;
		}
		recs.add(new Rec(t, value, site.getAddress(), curRun));
		ByteWrites w = writes.computeIfAbsent(t, k -> new ByteWrites());
		if (value == null) {
			w.unknown = true;
		}
		else {
			w.values.add(value);
		}
		if (!w.sites.contains(site.getAddress())) {
			w.sites.add(site.getAddress());
		}
	}

	/** Bytes a store writes: 1 when the flag is set (8-bit), 2 when clear, 0 if unknown. */
	private int widthOf(Instruction ins, Register flag) {
		if (flag == null) {
			return 0;
		}
		BigInteger v = program.getProgramContext().getValue(flag, ins.getAddress(), true);
		if (v == null) {
			return 0;
		}
		return v.signum() != 0 ? 1 : 2;
	}

	/**
	 * The value register {@code reg} holds at {@code store}: the immediate of the nearest
	 * preceding {@code LDA/LDX/LDY #imm} reached through fall-through instructions only, or null
	 * when anything else touches the register first or control flow could enter in between.
	 */
	private Long constantBefore(Instruction store, char reg, int width) {
		Instruction cur = store;
		for (int step = 0; step < LOOKBACK; step++) {
			if (hasNonFallthroughEntry(cur)) {
				return null;
			}
			Instruction prev = cur.getPrevious();
			if (prev == null || !cur.getAddress().equals(prev.getFallThrough())) {
				return null;
			}
			String m = prev.getMnemonicString();
			if (prev.getFlowType().isCall() || prev.getFlowType().isJump() ||
				prev.getFlowType().isTerminal()) {
				return null;
			}
			if (loads(m, reg)) {
				int op;
				try {
					op = prev.getByte(0) & 0xFF;
				}
				catch (MemoryAccessException e) {
					return null;
				}
				boolean imm = op == 0xA9 || op == 0xA2 || op == 0xA0;
				if (!imm || prev.getLength() - 1 != width) {
					return null;
				}
				long v = 0;
				for (int i = 0; i < width; i++) {
					int b = byteAt(prev.getAddress().add(1 + i));
					if (b < 0) {
						return null;
					}
					v |= (long) b << (8 * i);
				}
				return v;
			}
			if (clobbers(m, reg)) {
				return null;
			}
			cur = prev;
		}
		return null;
	}

	private boolean hasNonFallthroughEntry(Instruction ins) {
		for (Reference r : program.getReferenceManager().getReferencesTo(ins.getAddress())) {
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	private static boolean loads(String m, char reg) {
		return switch (reg) {
			case 'A' -> m.equals("LDA");
			case 'X' -> m.equals("LDX");
			default -> m.equals("LDY");
		};
	}

	private static boolean clobbers(String m, char reg) {
		if (m.equals("MVN") || m.equals("MVP")) {
			return true;
		}
		return switch (reg) {
			case 'A' -> switch (m) {
				case "TXA", "TYA", "TDC", "TSC", "PLA", "ADC", "SBC", "AND", "ORA", "EOR", "ASL",
					"LSR", "ROL", "ROR", "INC", "DEC", "XBA" -> true;
				default -> false;
			};
			case 'X' -> switch (m) {
				case "TAX", "TSX", "TYX", "PLX", "INX", "DEX" -> true;
				default -> false;
			};
			default -> switch (m) {
				case "TAY", "TXY", "PLY", "INY", "DEY" -> true;
				default -> false;
			};
		};
	}
}
