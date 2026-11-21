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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

/**
 * The register ROLES of one CPU language (bead grm-jjuc, wave 0): which {@link Register} plays the
 * accumulator, the index registers, the stack pointer (and its narrower views) and the status
 * flags. {@link PcodeShapes} answers questions about p-code in terms of these roles so a recognizer
 * need not name {@code "A"} or match a mnemonic.
 * <p>
 * Roles are resolved BY NAME from the language, per family, and a role the language lacks is
 * {@code null} (never an exception):
 * <ul>
 * <li><b>6502 / 6510 / undocumented variants</b> -- {@code A X Y}, stack pointer {@code SP} (2 bytes)
 * with the 1-byte alias {@code S} ({@code SH} the high byte), flags {@code C Z N V D} as separate
 * 1-byte registers holding 0 or 1. The 6510 on-die port registers {@code PORT}/{@code PORTDDR} are
 * listed in {@link #ioPorts()}: a write to one is a memory-mapped I/O write, not a CPU register
 * effect.</li>
 * <li><b>65816</b> -- {@code A} (8 bit, the low byte of {@code C}), {@code C} (16-bit accumulator;
 * NOTE {@code C} is the accumulator here and the carry flag is {@code CF}), {@code X}/{@code Y}
 * with low halves {@code XLow}/{@code YLow}, {@code SP} (3 bytes) with the views {@code SPLow},
 * {@code SPHigh}, {@code S16}; flags {@code CF ZF NF VF DF} (also separate 0/1 registers).</li>
 * <li><b>SPC700</b> -- {@code A X Y}, {@code SP} (2 bytes). There are NO separate flag registers: the
 * flags are bits of {@code PSW}, so {@link #carry()} etc. are {@link FlagRef}s naming {@code PSW}
 * and a bit index ({@code CF}=0, {@code ZF}=1, {@code VF}=6, {@code NF}=7). The SPC700 has no
 * decimal flag ({@code H} is half-carry) so {@link #decimal()} is {@code null}.</li>
 * </ul>
 * Instances are cached per {@link Language}.
 */
final class CpuRegs {

	/** The flag roles recognised by {@link PcodeShapes#branchOnFlag}. */
	enum FlagKind {
		CARRY, ZERO, NEGATIVE, OVERFLOW, DECIMAL
	}

	/**
	 * Where a flag lives: bit {@code bit} of register {@code reg}. For a dedicated 0/1 flag
	 * register (6502, 65816) {@code bit} is 0 and {@code reg} is that flag register; for the SPC700
	 * {@code reg} is {@code PSW}.
	 */
	record FlagRef(FlagKind kind, Register reg, int bit) {}

	private static final Map<Language, CpuRegs> CACHE = new WeakHashMap<>();

	private final Language language;
	private final Register acc;
	private final Register accWide;
	private final Register x;
	private final Register y;
	private final Register xLow;
	private final Register yLow;
	private final Register sp;
	private final List<Register> spViews;
	private final Register psw;
	private final List<Register> ioPorts;
	private final FlagRef carry;
	private final FlagRef zero;
	private final FlagRef negative;
	private final FlagRef overflow;
	private final FlagRef decimal;

	/** The roles of {@code language}; cached. */
	static synchronized CpuRegs of(Language language) {
		return CACHE.computeIfAbsent(language, CpuRegs::new);
	}

	private CpuRegs(Language lang) {
		language = lang;
		acc = lang.getRegister("A");
		x = lang.getRegister("X");
		y = lang.getRegister("Y");
		sp = lang.getRegister("SP");
		boolean is65816 = lang.getRegister("SPLow") != null;
		accWide = is65816 ? lang.getRegister("C") : null;
		xLow = lang.getRegister("XLow");
		yLow = lang.getRegister("YLow");
		List<Register> views = new ArrayList<>();
		for (String n : new String[] { "S", "SH", "SPLow", "SPHigh", "S16" }) {
			Register r = lang.getRegister(n);
			if (r != null) {
				views.add(r);
			}
		}
		spViews = List.copyOf(views);
		List<Register> ports = new ArrayList<>();
		for (String n : new String[] { "PORTDDR", "PORT" }) {
			Register r = lang.getRegister(n);
			if (r != null) {
				ports.add(r);
			}
		}
		ioPorts = List.copyOf(ports);
		Register p = lang.getRegister("PSW");
		if (is65816) {
			psw = null;
			carry = flag(FlagKind.CARRY, "CF");
			zero = flag(FlagKind.ZERO, "ZF");
			negative = flag(FlagKind.NEGATIVE, "NF");
			overflow = flag(FlagKind.OVERFLOW, "VF");
			decimal = flag(FlagKind.DECIMAL, "DF");
		}
		else if (p != null && lang.getRegister("YA") != null) {
			psw = p;
			carry = new FlagRef(FlagKind.CARRY, p, 0);
			zero = new FlagRef(FlagKind.ZERO, p, 1);
			overflow = new FlagRef(FlagKind.OVERFLOW, p, 6);
			negative = new FlagRef(FlagKind.NEGATIVE, p, 7);
			decimal = null;
		}
		else {
			psw = null;
			carry = flag(FlagKind.CARRY, "C");
			zero = flag(FlagKind.ZERO, "Z");
			negative = flag(FlagKind.NEGATIVE, "N");
			overflow = flag(FlagKind.OVERFLOW, "V");
			decimal = flag(FlagKind.DECIMAL, "D");
		}
	}

	private FlagRef flag(FlagKind kind, String name) {
		Register r = language.getRegister(name);
		return r == null ? null : new FlagRef(kind, r, 0);
	}

	/** The language these roles were resolved from. */
	Language language() {
		return language;
	}

	/** The accumulator ({@code A}; 8 bits on the 65816), or null. */
	Register acc() {
		return acc;
	}

	/** The 65816's 16-bit accumulator {@code C}, or null on every other CPU. */
	Register accWide() {
		return accWide;
	}

	Register x() {
		return x;
	}

	Register y() {
		return y;
	}

	/** The 65816's 8-bit low half of X, or null. */
	Register xLow() {
		return xLow;
	}

	/** The 65816's 8-bit low half of Y, or null. */
	Register yLow() {
		return yLow;
	}

	/** The full stack pointer register {@code SP}, or null. */
	Register sp() {
		return sp;
	}

	/** Narrower or alternate views of the stack pointer (6502 {@code S}/{@code SH}; 65816 {@code SPLow}/{@code SPHigh}/{@code S16}). */
	List<Register> spViews() {
		return spViews;
	}

	/** The SPC700's {@code PSW} (flags live in its bits), or null elsewhere. */
	Register psw() {
		return psw;
	}

	/** Register-space registers that are really memory-mapped I/O (the 6510 {@code PORT}/{@code PORTDDR}). */
	List<Register> ioPorts() {
		return ioPorts;
	}

	FlagRef carry() {
		return carry;
	}

	FlagRef zero() {
		return zero;
	}

	FlagRef negative() {
		return negative;
	}

	FlagRef overflow() {
		return overflow;
	}

	FlagRef decimal() {
		return decimal;
	}

	/** The flag at bit {@code bit} of {@code reg}, or null when that is not one of the five named flags. */
	FlagKind kindOf(Register reg, int bit) {
		for (FlagRef f : new FlagRef[] { carry, zero, negative, overflow, decimal }) {
			if (f != null && f.reg().equals(reg) && f.bit() == bit) {
				return f.kind();
			}
		}
		return null;
	}

	/** Whether {@code r} stores status flags (one of the dedicated flag registers, or {@code PSW}). */
	boolean isFlagStorage(Register r) {
		if (psw != null && psw.equals(r)) {
			return true;
		}
		for (FlagRef f : new FlagRef[] { carry, zero, negative, overflow, decimal }) {
			if (f != null && f.reg().equals(r)) {
				return true;
			}
		}
		// the remaining status bits (6502 B/I, 65816 IF/BF) and the packed 6502 P register
		// (on the 65816 "B" is the accumulator's high byte, not a flag)
		for (String n : new String[] { "B", "I", "P", "IF", "BF" }) {
			Register o = language.getRegister(n);
			if (o != null && o.equals(r) && !(n.equals("B") && accWide != null)) {
				return true;
			}
		}
		return false;
	}
}
