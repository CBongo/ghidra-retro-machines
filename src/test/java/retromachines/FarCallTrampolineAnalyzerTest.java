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
 * {@link FarCallTrampolineAnalyzer} on a SYNTHETIC wizwarr-shaped restoring far-call trampoline
 * (AxROM, one 32K window, banks 1-3 as overlays; grm-v60). No ROM bytes are copied in.
 *
 * <pre>
 *   9000  LDY #$09 / JSR 9100      9100  LDA #$03 / JMP tramp      -> bank 3, $8009
 *   9006  LDY #$0c / JSR 9110      9110  LDA #$01 / JMP tramp      -> bank 1, $800c
 *   9200  LDA #$80 / STA $1c / RTS                                 (the write-once high byte)
 *   tramp STY $1b / STA $1d / LDA $00 / PHA / AND #$18 / ORA $1d / STA $00 / STA $8000
 *         JSR site / PLA / STA $00 / STA $8000 / RTS
 *   site  JMP ($001b)
 * </pre>
 * Banks 1-3 open with {@code JMP $9400} vector slots at {@code $8009} and {@code $800c}.
 */
public class FarCallTrampolineAnalyzerTest extends AbstractBundledLanguageTest {

	private static final long TRAMP = 0xf000;
	private static final long SITE = 0xf020;

	private enum Variant {
		BASELINE,
		/** A second direct write to the high-byte cell: the write-once rule fails. */
		SECOND_HIGH_WRITER,
		/** A read-modify-write of the high-byte cell counts as a writer too. */
		INC_HIGH_WRITER,
		/** Bank 3's slot at $8009 is not a JMP: corroboration declines THAT call site only. */
		BANK3_SLOT_NOT_A_JUMP,
		/** The high byte is not an immediate-derived constant (it comes from RAM). */
		HIGH_BYTE_FROM_RAM,
		/** Two writers of the pointer's low byte: it is not a trampoline's single copy. */
		SECOND_LOW_WRITER,
		/** The trampoline, byte-identical, also disassembled in bank 2 at the same address, with
		 *  its own copy of the high-byte writer: mirror copies are ONE writer. */
		MIRRORED_TRAMPOLINE,
		/** As MIRRORED_TRAMPOLINE, but the copy's STY targets a different cell: a real second writer. */
		DIFFERENT_COPY
	}

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

	private ProgramDB build(Variant variant) throws Exception {
		injectMemoryLatchStrategy();
		builder = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(builder, ".ram", "0x0", 0x800);
		builder.createMemory("PRG_ALL", "0x8000", 0x8000);
		for (int b = 1; b <= 3; b++) {
			builder.createOverlayMemory("PRG_ALL_B" + b, "0x8000", 0x8000);
		}
		program = builder.getProgram();

		builder.setBytes(hex(0x9000), "a0 09 20 00 91 60 a0 0c 20 10 91 60", true);
		builder.setBytes(hex(0x9100), "a9 03 4c 00 f0", true);
		builder.setBytes(hex(0x9110), "a9 01 2c a9 03 4c 00 f0", true);
		// The skip idiom: 9120 LDA #1 / 9122 BIT $03a9 / 9125 JMP tramp, entered either at 9120 or
		// at the hidden LDA #3 inside the BIT (9123). The call into 9123 is a dangling reference.
		builder.setBytes(hex(0x9120), "a9 01 2c a9 03 4c 00 f0", true);
		builder.setBytes(hex(0x9140), "a0 06 20 23 91 60", true);
		builder.setBytes(hex(0x9200), variant == Variant.HIGH_BYTE_FROM_RAM
				? "a5 40 85 1c 60" : "a9 80 85 1c 60", true);
		builder.setBytes(hex(TRAMP), "84 1b 85 1d a5 00 48 29 18 05 1d 85 00 8d 00 80 " +
			"20 20 f0 68 85 00 8d 00 80 60", true);
		builder.setBytes(hex(SITE), "6c 1b 00", true);
		switch (variant) {
			case SECOND_HIGH_WRITER -> builder.setBytes(hex(0x9300), "a9 81 85 1c 60", true);
			case INC_HIGH_WRITER -> builder.setBytes(hex(0x9300), "e6 1c 60", true);
			case SECOND_LOW_WRITER -> builder.setBytes(hex(0x9300), "a9 00 85 1b 60", true);
			default -> {
			}
		}
		for (int b = 1; b <= 3; b++) {
			String slot = b == 3 && variant == Variant.BANK3_SLOT_NOT_A_JUMP ? "ea ea ea"
					: "4c 00 94";
			builder.setBytes(bankAddr(b, 0x8009).toString(), slot, false);
			builder.setBytes(bankAddr(b, 0x800c).toString(), "4c 00 94", false);
			builder.setBytes(bankAddr(b, 0x8006).toString(), "4c 00 94", false);
			builder.setBytes(bankAddr(b, 0x9400).toString(), "60", false);
		}
		// Ghidra marks a JMP to a function entry as a tail call (CALL_RETURN override), which
		// changes its flow type to call-terminator: the stubs' JMPs must be walked regardless.
		if (variant == Variant.MIRRORED_TRAMPOLINE || variant == Variant.DIFFERENT_COPY) {
			String tramp = "84 1b 85 1d a5 00 48 29 18 05 1d 85 00 8d 00 80 " +
				"20 20 f0 68 85 00 8d 00 80 60";
			if (variant == Variant.DIFFERENT_COPY) {
				tramp = tramp.replaceFirst("84 1b", "86 1b");
			}
			builder.setBytes(bankAddr(2, TRAMP).toString(), tramp, true);
			builder.setBytes(bankAddr(2, SITE).toString(), "6c 1b 00", true);
			builder.setBytes(bankAddr(2, 0x9200).toString(), "a9 80 85 1c 60", true);
		}
		inTx(program, "tail-call overrides", () -> {
			for (long jmp : new long[] { 0x9102, 0x9115, 0x9125 }) {
				program.getListing().getInstructionAt(builder.addr(hex(jmp)))
						.setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN);
			}
		});
		inTx(program, "dangling offcut call reference", () -> {
			if (!program.getReferenceManager().hasReferencesTo(builder.addr(hex(0x9123)))) {
				program.getReferenceManager().addMemoryReference(builder.addr(hex(0x9142)),
					builder.addr(hex(0x9123)), RefType.UNCONDITIONAL_CALL,
					ghidra.program.model.symbol.SourceType.ANALYSIS, -1);
			}
		});
		inTx(program, "describe import", () -> {
			program.setExecutableFormat(NesRomLoader.NAME);
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorHints.MAP_PATH_PROPERTY, "machines/nes-axrom.map");
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
			if (ref.getReferenceType() == RefType.COMPUTED_CALL) {
				targets.add(ref.getToAddress());
			}
		}
		return targets;
	}

	private boolean isCode(Address a) {
		return program.getListing().getInstructionAt(a) != null;
	}

	@Test
	public void placesEachCallsTargetInItsDestinationBanksOverlay() throws Exception {
		build(Variant.BASELINE);
		analyze();
		assertEquals(Set.of(bankAddr(3, 0x8009), bankAddr(1, 0x800c), bankAddr(3, 0x8006)),
			siteTargets());
		assertTrue("the hidden-entry call (A=3 from inside the BIT) reached bank 3",
			isCode(bankAddr(3, 0x8006)));
		assertTrue("slot disassembled in bank 3", isCode(bankAddr(3, 0x8009)));
		assertTrue("slot disassembled in bank 1", isCode(bankAddr(1, 0x800c)));
		assertTrue("the slot's own JMP followed within bank 3", isCode(bankAddr(3, 0x9400)));
		assertTrue("... and within bank 1", isCode(bankAddr(1, 0x9400)));
		assertTrue("bank 2 was never a destination", !isCode(bankAddr(2, 0x8009)));
		assertTrue("bank 1's $8009 is not what a call reached", !isCode(bankAddr(1, 0x8009)));
		assertTrue("bank 3's $800c is not what a call reached", !isCode(bankAddr(3, 0x800c)));
		assertNull(program.getBookmarkManager().getBookmark(builder.addr(hex(0x9002)),
			BookmarkType.NOTE, FarCallTrampolineAnalyzer.BOOKMARK_CATEGORY));
	}

	@Test
	public void mirrorCopiesOfTheTrampolineAreOneWriter() throws Exception {
		build(Variant.MIRRORED_TRAMPOLINE);
		assertTrue("the copy is disassembled before the analyzer runs",
			isCode(bankAddr(2, TRAMP)));
		analyze();
		assertEquals(Set.of(bankAddr(3, 0x8009), bankAddr(1, 0x800c), bankAddr(3, 0x8006)),
			siteTargets());
	}

	@Test
	public void aDifferentCopyIsARealSecondWriter() throws Exception {
		build(Variant.DIFFERENT_COPY);
		analyze();
		assertTrue(siteTargets().isEmpty());
	}

	@Test
	public void isIdempotentAcrossRepeatedPasses() throws Exception {
		build(Variant.BASELINE);
		analyze();
		analyze();
		assertEquals(3, siteTargets().size());
	}

	@Test
	public void declinesWhenTheHighByteCellHasASecondWriter() throws Exception {
		build(Variant.SECOND_HIGH_WRITER);
		analyze();
		assertTrue(siteTargets().isEmpty());
		assertTrue(!isCode(bankAddr(3, 0x8009)));
	}

	@Test
	public void aReadModifyWriteOfTheHighByteCellIsAWriter() throws Exception {
		build(Variant.INC_HIGH_WRITER);
		analyze();
		assertTrue(siteTargets().isEmpty());
	}

	@Test
	public void declinesWhenTheHighByteIsNotAnImmediateDerivedConstant() throws Exception {
		build(Variant.HIGH_BYTE_FROM_RAM);
		analyze();
		assertTrue(siteTargets().isEmpty());
	}

	@Test
	public void declinesWhenThePointerLowByteHasASecondWriter() throws Exception {
		build(Variant.SECOND_LOW_WRITER);
		analyze();
		assertTrue(siteTargets().isEmpty());
	}

	@Test
	public void declinesOnlyTheCallSiteWhoseTargetFailsCorroboration() throws Exception {
		build(Variant.BANK3_SLOT_NOT_A_JUMP);
		analyze();
		assertEquals(Set.of(bankAddr(1, 0x800c), bankAddr(3, 0x8006)), siteTargets());
		assertTrue(!isCode(bankAddr(3, 0x8009)));
		var note = program.getBookmarkManager().getBookmark(builder.addr(hex(0x9002)),
			BookmarkType.NOTE, FarCallTrampolineAnalyzer.BOOKMARK_CATEGORY);
		assertNotNull("the declined call site carries a NOTE saying why", note);
		assertTrue(note.getComment(), note.getComment().contains("not corroborated"));
	}
}
