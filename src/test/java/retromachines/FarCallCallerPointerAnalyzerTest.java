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
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * {@link FarCallTrampolineAnalyzer}'s caller-set-pointer variant (grm-gipk.2) on a SYNTHETIC
 * GxROM-shaped far call (one 32K window, banks 1-3 as overlays). No ROM bytes are copied in.
 *
 * <pre>
 *   f000  STA $f2 / JSR f020 / JMP ($0017)      f020  LDA $f2 / ASL x4 / STA $8000 / RTS
 *   9000  const $8008, bank 1          9010  table 9060 at Y=2 (known), bank 2
 *   9080  table 9040, Y unknown, bank 2    9030  const $800f, bank 3 (slot not a JMP)
 * </pre>
 * Table 9040 = 8000 8003 8006 8009 800c: in bank 2 the slot at 8009 is not a JMP, so enumeration
 * must stop there and never reach 800c.
 */
public class FarCallCallerPointerAnalyzerTest extends AbstractBundledLanguageTest {

	private static final long ENTRY = 0xf000;
	private static final long SITE = 0xf005;

	private ProgramBuilder builder;
	private ProgramDB program;

	@SuppressWarnings("unchecked")
	private static void injectMemoryLatchStrategy() throws Exception {
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
				bucket.add(new ClassFileInfo("grm-v60-test-injected", name, "BankSwitchStrategy", ""));
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
				: program.getAddressFactory().getAddressSpace("PRG_ALL_B" + bank)
						.getAddress(offset);
	}

	private ProgramDB build() throws Exception {
		injectMemoryLatchStrategy();
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory("PRG_ALL", "0x8000", 0x8000);
		for (int b = 1; b <= 3; b++) {
			builder.createOverlayMemory("PRG_ALL_B" + b, "0x8000", 0x8000);
		}
		program = builder.getProgram();
		builder.setBytes(hex(ENTRY), "85 f2 20 20 f0 6c 17 00", true);
		builder.setBytes(hex(0xf020), "a5 f2 0a 0a 0a 0a 8d 00 80 60", true);
		builder.setBytes(hex(0x9000), "a9 08 85 17 a9 80 85 18 a9 01 20 00 f0 60", true);
		builder.setBytes(hex(0x9010), "a0 02 b9 60 90 85 17 b9 61 90 85 18 a9 02 20 00 f0 60", true);
		builder.setBytes(hex(0x9030), "a9 0f 85 17 a9 80 85 18 a9 03 20 00 f0 60", true);
		builder.setBytes(hex(0x9040), "00 80 03 80 06 80 09 80 0c 80", false);
		builder.setBytes(hex(0x9060), "0c 80 10 80", false);
		builder.setBytes(hex(0x9080),
			"a5 40 a8 b9 40 90 85 17 b9 41 90 85 18 a9 02 20 00 f0 60", true);
		// stale pointer: set, then a callee that rewrites $17, then the far call (bank 3, $8010)
		builder.setBytes(hex(0x90a0),
			"a9 10 85 17 a9 80 85 18 20 c0 90 a9 03 20 00 f0 60", true);
		builder.setBytes(hex(0x90c0), "a9 00 85 17 60", true);
		for (int b = 1; b <= 3; b++) {
			builder.setBytes(bankAddr(b, 0x9400).toString(), "60", false);
			for (long slot : new long[] { 0x8000, 0x8003, 0x8006, 0x8008, 0x800c, 0x8010 }) {
				builder.setBytes(bankAddr(b, slot).toString(), "4c 00 94", false);
			}
		}
		builder.setBytes(bankAddr(2, 0x8009).toString(), "ea ea ea", false);
		builder.setBytes(bankAddr(3, 0x800f).toString(), "ea ea ea", false);
		inTx(program, "describe import", () -> {
			program.setExecutableFormat(NesRomLoader.NAME);
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorHints.MAP_PATH_PROPERTY, "machines/nes-gxrom.map");
		});
		return program;
	}

	private void analyze() throws Exception {
		FarCallTrampolineAnalyzer analyzer = new FarCallTrampolineAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, new AddressSet(builder.addr(hex(0x8000)),
				builder.addr(hex(0xffff))), TaskMonitor.DUMMY, new MessageLog());
		});
	}

	private Set<Address> siteTargets() {
		Instruction site = program.getListing().getInstructionAt(builder.addr(hex(SITE)));
		assertNotNull(site);
		Set<Address> targets = new HashSet<>();
		for (Reference ref : site.getReferencesFrom()) {
			if (RefType.COMPUTED_CALL.equals(ref.getReferenceType())) {
				targets.add(ref.getToAddress());
			}
		}
		return targets;
	}

	private boolean isCode(Address a) {
		return program.getListing().getInstructionAt(a) != null;
	}

	@Test
	public void placesConstantAndTableTargetsInTheirDestinationBanks() throws Exception {
		build();
		analyze();
		assertEquals(Set.of(bankAddr(1, 0x8008),
			bankAddr(2, 0x8000), bankAddr(2, 0x8003), bankAddr(2, 0x8006),
			bankAddr(2, 0x8010)), siteTargets());
		assertTrue(isCode(bankAddr(1, 0x8008)));
		assertTrue("slot's own JMP followed", isCode(bankAddr(1, 0x9400)));
	}

	@Test
	public void aKnownYUsesExactlyThatTableEntry() throws Exception {
		build();
		analyze();
		assertTrue(siteTargets().contains(bankAddr(2, 0x8010)));
		assertTrue("entry 0 of the Y-known table is not the one called",
			!siteTargets().contains(bankAddr(2, 0x800c)));
	}

	@Test
	public void anUnknownYEnumeratesUntilTheFirstUncorroboratedEntry() throws Exception {
		build();
		analyze();
		assertTrue(siteTargets().containsAll(Set.of(bankAddr(2, 0x8000), bankAddr(2, 0x8003),
			bankAddr(2, 0x8006))));
		assertTrue("8009 is not a JMP in bank 2: enumeration stopped", !isCode(bankAddr(2, 0x8009)));
		assertTrue("... so 800c, though a JMP, was never reached by the table",
			!siteTargets().contains(bankAddr(2, 0x800c)));
	}

	@Test
	public void declinesWhenTheDestinationSlotIsNotAJump() throws Exception {
		build();
		analyze();
		assertTrue(siteTargets().stream().noneMatch(a -> a.getOffset() == 0x800f));
		assertTrue(!isCode(bankAddr(3, 0x800f)));
		var note = program.getBookmarkManager().getBookmark(builder.addr(hex(0x9030 + 10)),
			BookmarkType.NOTE, FarCallTrampolineAnalyzer.BOOKMARK_CATEGORY);
		assertNotNull("the declined call site carries a NOTE", note);
		assertTrue(note.getComment(), note.getComment().contains("not a JMP/JSR entry"));
	}

	@Test
	public void isIdempotentAcrossRepeatedPasses() throws Exception {
		build();
		analyze();
		int first = siteTargets().size();
		analyze();
		assertEquals(first, siteTargets().size());
	}

	@Test
	public void aCallBetweenPointerAndFarCallInvalidatesThePointer() throws Exception {
		build();
		analyze();
		assertTrue(!siteTargets().contains(bankAddr(3, 0x8010)));
		assertTrue(!isCode(bankAddr(3, 0x8010)));
	}
}
