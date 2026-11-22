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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * grm-gipk.36: a split dispatch whose handlers sit in a banked window, with a SYNTHETIC
 * reproduction of rygar's {@code c190} shape on the UxROM bus-conflict latch. The bank of entry
 * {@code i} is byte {@code i} of a table read by {@code LDX tbl,Y} (before the index is doubled),
 * and a helper the caller calls ({@code LDA $8100,X / STA $8100,X}) switches to it:
 * <pre>
 *   c000: LDY $12 / LDX $c200,Y / TYA / ASL A / TAY
 *         LDA $c300,Y / STA $00 / LDA $c301,Y / STA $01 / JSR $c040 / JMP ($0000)
 *   c040: LDA $c100,X / STA $c100,X / RTS      ($c100 holds 0,1,2,3)
 * </pre>
 * Every entry points at {@code $9000}; each must be placed in its OWN bank's overlay.
 */
public class SplitDispatchBankAwareProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

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
		for (Class<?> strategy : new Class<?>[] { MemoryLatchBankSwitchStrategy.class,
			RegisterWriteBankSwitchStrategy.class }) {
			String name = strategy.getName();
			if (bucket.stream().noneMatch(c -> c.name().equals(name))) {
				bucket.add(new ClassFileInfo("grm-gipk.36-test-injected", name, "BankSwitchStrategy",
					""));
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

	private Address bankAddr(int bank, long offset) {
		return bank == 0 ? builder.addr(hex(offset))
				: program.getAddressFactory().getAddressSpace("PRG_LO_B" + bank)
						.getAddress(offset);
	}

	/** Builds the program; {@code bankBytes} is the per-entry bank table at {@code $c200}. */
	private void build(String bankBytes, String ldx) throws Exception {
		injectStrategies();
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory("PRG_LO", "0x8000", 0x4000); // switched window, home bank 0
		for (int b = 1; b <= 3; b++) {
			builder.createOverlayMemory("PRG_LO_B" + b, "0x8000", 0x4000);
		}
		builder.createMemory("PRG_HI", "0xc000", 0x4000); // fixed bank
		program = builder.getProgram();
		String caller = "a4 12 " + ldx + " 98 0a a8 b9 00 c3 85 00 b9 01 c3 85 01 20 40 c0 6c 00 00";
		builder.setBytes("0xc000", caller, true);
		builder.setBytes("0xc040", "bd 00 c1 9d 00 c1 60", true);
		builder.setBytes("0xc100", "00 01 02 03", false);
		builder.setBytes("0xc200", bankBytes, false);
		// three entries at $9000, then a null slot that ends the table
		builder.setBytes("0xc300", "00 90 00 90 00 90 00 00", false);
		for (int b = 0; b <= 3; b++) {
			builder.setBytes(bankAddr(b, 0x9000).toString(), "60", false);
		}
		inTx(program, "describe import", () -> {
			program.setExecutableFormat(NesRomLoader.NAME);
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorHints.MAP_PATH_PROPERTY, "machines/nes-uxrom.map");
		});
	}

	private Set<Address> run() throws Exception {
		SplitDispatchTableAnalyzer analyzer = new SplitDispatchTableAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(bankAddr(0, 0xc000), bankAddr(0, 0xcfff)), TaskMonitor.DUMMY,
			new MessageLog()));
		Set<Address> targets = new HashSet<>();
		Address jmp = bankAddr(0, 0xc000 + 21);
		assertNotNull(program.getListing().getInstructionAt(jmp));
		for (Reference r : program.getListing().getInstructionAt(jmp).getReferencesFrom()) {
			if (r.getReferenceType().isComputed()) {
				targets.add(r.getToAddress());
			}
		}
		return targets;
	}

	@Before
	public void noop() {
		// each test builds its own program
	}

	@Test
	public void placesEachEntryInItsOwnBanksOverlay() throws Exception {
		build("01 02 03", "be 00 c2");
		assertEquals(Set.of(bankAddr(1, 0x9000), bankAddr(2, 0x9000), bankAddr(3, 0x9000)), run());
	}

	/** The bank byte is not read per entry: nothing proves a bank, so every entry is declined. */
	@Test
	public void declinesEveryEntryWhenNoBankIsProven() throws Exception {
		build("01 02 03", "ea ea ea"); // NOPs where the bank byte would be loaded
		assertEquals(Set.of(), run());
	}
}
