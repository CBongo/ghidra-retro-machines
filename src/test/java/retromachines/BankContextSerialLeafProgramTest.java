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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Pins bead {@code grm-gipk.38}: {@link BankContext#stateBefore} carries a bank over a leaf
 * helper that is an MMC1 serial-shift run (ultimaav {@code f313}: {@code LDA #0 / STA $5e /
 * INC $fd / STA $ffff x5 / DEC $fd / RTS}). Writes 1-4 report {@code NO_DEPOSIT}; only write 5
 * commits, so the helper is one switch and not several. A helper whose writes all deposit is
 * still rejected (CrossBankJumpTableProgramTest).
 */
public class BankContextSerialLeafProgramTest extends AbstractProgramTest {

	private static final int PRG_BANK_MASK = 0x1F << 4;

	/** Seeds JUST the {@code BankSwitchStrategy} bucket; see CrossBankJumpTableProgramTest. */
	@SuppressWarnings("unchecked")
	private static void injectStrategies() throws Exception {
		Field hasSearchedField = ClassSearcher.class.getDeclaredField("hasSearched");
		hasSearchedField.setAccessible(true);
		Field mapField = ClassSearcher.class.getDeclaredField("extensionPointSuffixToInfoMap");
		mapField.setAccessible(true);
		Map<String, Set<ClassFileInfo>> old =
			(Map<String, Set<ClassFileInfo>>) mapField.get(null);
		Set<ClassFileInfo> bucket = new HashSet<>();
		if (old != null && old.get("BankSwitchStrategy") != null) {
			bucket.addAll(old.get("BankSwitchStrategy"));
		}
		for (Class<?> strategy : new Class<?>[] { SerialShiftBankSwitchStrategy.class,
			MemoryLatchBankSwitchStrategy.class, RegisterWriteBankSwitchStrategy.class }) {
			String name = strategy.getName();
			if (bucket.stream().noneMatch(c -> c.name().equals(name))) {
				bucket.add(new ClassFileInfo("grm-gipk.38-test-injected", name,
					"BankSwitchStrategy", ""));
			}
		}
		Map<String, Set<ClassFileInfo>> map = new HashMap<>();
		if (old != null) {
			map.putAll(old);
		}
		map.put("BankSwitchStrategy", bucket);
		mapField.set(null, map);
		hasSearchedField.set(null, true);
	}

	@Before
	public void setUp() throws Exception {
		injectStrategies();
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		// Known prg_mode 3: W8000 switchable (home occupant bank 0), WC000 fixed to the last bank.
		builder.createMemory("W8000", "0x8000", 0x4000);
		for (int b = 1; b <= 3; b++) {
			builder.createOverlayMemory("W8000_B" + b, "0x8000", 0x4000);
		}
		builder.createMemory("WC000", "0xc000", 0x4000);
		program = builder.getProgram();
		inTx(program, "describe import", () -> {
			program.setExecutableFormat(NesRomLoader.NAME);
			Program p = program;
			p.getOptions(Program.PROGRAM_INFO).setString(DescriptorHints.MAP_PATH_PROPERTY,
				"machines/nes-mmc1.map");
			p.getOptions(Program.PROGRAM_INFO).setString(DescriptorHints.LAYOUT_MODE_PROPERTY,
				"3");
		});
	}

	private static final String STA = "8d ff ff ";

	/** Caller in the fixed bank: JSR $c100, then a use site (LDA $8100) at $c003. */
	private Instruction layCallerAndHelper(String helper) throws Exception {
		put(0xc000, "20 00 c1 ad 00 81 4c 06 c0");
		put(0xc100, helper);
		return instructionAt(addr(0xc003));
	}

	/** f313's shape with a constant zero: five identical stores commit bank 0. */
	@Test
	public void aFiveWriteSerialHelperCommitsItsConstantBank() throws Exception {
		Instruction use = layCallerAndHelper(
			"a9 00 85 5e e6 fd " + STA + STA + STA + STA + STA + "c6 fd 60");
		BankContext ctx = BankContext.forProgram(program);
		assertNotNull("not recognised as a banked-board import", ctx);

		BankState state = ctx.stateBefore(use);
		assertEquals("prg_bank must be fully known", PRG_BANK_MASK,
			state.knownMask() & PRG_BANK_MASK);
		assertEquals(0, state.bits() & PRG_BANK_MASK);
		assertEquals("bank 0 is the home occupant: the base space", addr(0x8100),
			ctx.resolveUnder(state, addr(0x8100)));
	}

	/** An unrolled LSR chain shifts the immediate in LSB first: LDA #$02 commits bank 2. */
	@Test
	public void anUnrolledShiftChainCommitsANonzeroBank() throws Exception {
		Instruction use = layCallerAndHelper(
			"a9 02 " + STA + "4a " + STA + "4a " + STA + "4a " + STA + "4a " + STA + "60");
		BankContext ctx = BankContext.forProgram(program);
		assertNotNull(ctx);

		BankState state = ctx.stateBefore(use);
		assertEquals(PRG_BANK_MASK, state.knownMask() & PRG_BANK_MASK);
		assertEquals(2 << 4, state.bits() & PRG_BANK_MASK);
		Address expected = program.getAddressFactory().getAddressSpace("W8000_B2")
				.getAddress(0x8100);
		assertEquals(expected, ctx.resolve(use, addr(0x8100)));
	}

	/** The value is the caller's A, which the helper never defines: nothing is invented. */
	@Test
	public void aShiftChainOnTheCallersRegisterStaysUnknown() throws Exception {
		Instruction use = layCallerAndHelper(
			STA + "4a " + STA + "4a " + STA + "4a " + STA + "4a " + STA + "60");
		BankContext ctx = BankContext.forProgram(program);
		assertNotNull(ctx);

		BankState state = ctx.stateBefore(use);
		assertEquals(0, state.knownMask() & PRG_BANK_MASK);
		assertNull(ctx.resolve(use, addr(0x8100)));
	}
}
