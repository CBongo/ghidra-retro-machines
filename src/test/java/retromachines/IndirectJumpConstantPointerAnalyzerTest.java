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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * End-to-end coverage of {@link IndirectJumpConstantPointerAnalyzer} against a SYNTHETIC 6502
 * far-call trampoline in the dragonpower/shenlong shape (grm-v60.1) -- no ROM bytes are copied
 * in; the ROM is copyrighted and this is a hand-built minimal reproduction of the idiom described
 * in the bead.
 *
 * <p><b>The shape.</b> {@code LDA #$08 / STA $17 / LDA #$80 / STA $18 / LDA #$00 / STA $f9 / LDA
 * #$00 / JMP resume}, then {@code resume: STA $f2 / JSR callee}, where {@code callee} computes an
 * index from {@code $f2}/{@code $f9} into a table it reads and rewrites (mirroring the real
 * {@code ffbe} routine's {@code $FFCC,Y} read-modify-write) and returns, and finally
 * {@code site: JMP ($0017)}. Unlike the real ROM, the callee is placed after the entry code
 * rather than physically embedded between it and the resume point -- an implementation detail of
 * the real ROM's layout, not part of the idiom this analyzer resolves.
 */
public class IndirectJumpConstantPointerAnalyzerTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long BASE = 0x9000;
	private static final long TABLE = 0x9600;
	private static final long MAIN_TARGET = 0x8008; // $17/$18 resolve to this
	private static final long MAIN_BODY = 0x82ac; // the "main program", reached via a plain JMP

	private enum Variant {
		/** The positive case: both pointer bytes constant, index through the callee known. */
		BASELINE,
		/** Negative: the callee clobbers $17 with an unknown value before returning. */
		CLOBBER_BY_CALLEE,
		/** Negative: an indexed store with an unknown index sits between the stores and the jump. */
		INDEXED_UNKNOWN_STORE,
		/** Negative: a conditional branch sits between the stores and the jump. */
		CONDITIONAL_BRANCH,
		/** Negative: only the low pointer byte ($17) is ever stored. */
		ONLY_ONE_BYTE,
		/** Positive: a second bank (overlay) holds identical code, so the ROM store in the callee
		 *  (a possible bank switch) cannot change which instructions run afterwards. */
		OVERLAY_IDENTICAL,
		/** Negative: after that possible bank switch, the other bank's bytes at the jump site
		 *  differ, so the base listing is not proven to be the code that runs. */
		OVERLAY_DIFFERS_AT_SITE
	}

	private ProgramBuilder builder;
	private Address siteAddr;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	/** Tiny backpatching assembler so forward references (JMP to a not-yet-emitted label) don't
	 *  need addresses worked out by hand. */
	private static final class Asm {
		private final List<Integer> bytes = new ArrayList<>();
		private final long base;

		Asm(long base) {
			this.base = base;
		}

		long here() {
			return base + bytes.size();
		}

		void op(int... values) {
			for (int v : values) {
				bytes.add(v & 0xff);
			}
		}

		int reserve16() {
			int idx = bytes.size();
			bytes.add(0);
			bytes.add(0);
			return idx;
		}

		void patch16(int idx, long address) {
			bytes.set(idx, (int) (address & 0xff));
			bytes.set(idx + 1, (int) ((address >> 8) & 0xff));
		}

		String hex() {
			StringBuilder sb = new StringBuilder();
			for (int v : bytes) {
				sb.append(String.format("%02x ", v));
			}
			return sb.toString().trim();
		}
	}

	private ProgramDB buildProgram(Variant variant) throws Exception {
		builder = new ProgramBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x8000); // 0x8000-0xffff, reports non-writable (ROM)

		Asm asm = new Asm(BASE);
		asm.op(0xa9, 0x08); // LDA #$08
		asm.op(0x85, 0x17); // STA $17
		asm.op(0xa9, 0x80); // LDA #$80
		if (variant != Variant.ONLY_ONE_BYTE) {
			asm.op(0x85, 0x18); // STA $18
		}
		if (variant == Variant.INDEXED_UNKNOWN_STORE) {
			asm.op(0x9d, 0x00, 0x95); // STA $9500,X -- X is never set, so unknown
		}
		if (variant == Variant.CONDITIONAL_BRANCH) {
			asm.op(0xd0, 0x00); // BNE +0 -- an always-present conditional branch
		}
		asm.op(0xa9, 0x00); // LDA #$00
		asm.op(0x85, 0xf9); // STA $f9
		asm.op(0xa9, 0x00); // LDA #$00
		asm.op(0x4c); // JMP resume
		int jmpResumeOperand = asm.reserve16();

		long calleeAddr = asm.here();
		asm.op(0xa5, 0xf2); // LDA $f2
		asm.op(0x0a); // ASL A
		asm.op(0x0a); // ASL A
		asm.op(0x05, 0xf9); // ORA $f9
		asm.op(0xa8); // TAY
		asm.op(0xb9, (int) (TABLE & 0xff), (int) ((TABLE >> 8) & 0xff)); // LDA TABLE,Y
		asm.op(0x99, (int) (TABLE & 0xff), (int) ((TABLE >> 8) & 0xff)); // STA TABLE,Y
		if (variant == Variant.CLOBBER_BY_CALLEE) {
			asm.op(0x68); // PLA -- A becomes unknown
			asm.op(0x85, 0x17); // STA $17 -- clobbers the pointer's low byte with an unknown value
		}
		asm.op(0x60); // RTS

		long resumeAddr = asm.here();
		asm.patch16(jmpResumeOperand, resumeAddr);
		asm.op(0x85, 0xf2); // STA $f2
		asm.op(0x20, (int) (calleeAddr & 0xff), (int) ((calleeAddr >> 8) & 0xff)); // JSR callee

		long site = asm.here();
		asm.op(0x6c, 0x17, 0x00); // JMP ($0017)

		builder.setBytes(String.format("0x%x", BASE), asm.hex(), true);
		siteAddr = addr(site);

		if (variant == Variant.OVERLAY_IDENTICAL || variant == Variant.OVERLAY_DIFFERS_AT_SITE) {
			builder.createOverlayMemory("B1", "0x8000", 0x8000);
			String copy = asm.hex();
			if (variant == Variant.OVERLAY_DIFFERS_AT_SITE) {
				// The site's pointer operand low byte: $17 -> $19 in the other bank only.
				int operandIdx = (int) (site - BASE) + 1;
				String[] b = copy.split(" ");
				b[operandIdx] = "19";
				copy = String.join(" ", b);
			}
			builder.setBytes(String.format("B1::%x", BASE), copy, false);
		}

		// The resolved target: initially undefined, so the analyzer's own disassembly/function
		// creation can be verified rather than assumed.
		builder.setBytes(String.format("0x%x", MAIN_TARGET),
			String.format("4c %02x %02x", MAIN_BODY & 0xff, (MAIN_BODY >> 8) & 0xff), false);
		builder.setBytes(String.format("0x%x", MAIN_BODY), "ea", false); // NOP stand-in

		return builder.getProgram();
	}

	private void runAnalyzer(ProgramDB program) throws Exception {
		IndirectJumpConstantPointerAnalyzer analyzer = new IndirectJumpConstantPointerAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		int tx = program.startTransaction("analyze");
		try {
			analyzer.added(program, new AddressSet(addr(BASE), siteAddr.add(2)), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void resolvesConstantPointerThroughCalleeWithKnownIndex() throws Exception {
		ProgramDB program = buildProgram(Variant.BASELINE);
		runAnalyzer(program);

		Instruction siteInstr = program.getListing().getInstructionAt(siteAddr);
		assertNotNull(siteInstr);
		Reference[] refs = siteInstr.getReferencesFrom();
		assertEquals(1, refs.length);
		assertEquals(addr(MAIN_TARGET), refs[0].getToAddress());
		assertEquals(RefType.COMPUTED_CALL, refs[0].getReferenceType());
		assertEquals(SourceType.ANALYSIS, refs[0].getSource());

		assertNotNull("expected the target to be disassembled",
			program.getListing().getInstructionAt(addr(MAIN_TARGET)));
		assertNotNull("expected the target's own JMP to be followed and disassembled too",
			program.getListing().getInstructionAt(addr(MAIN_BODY)));

	}

	@Test
	public void doesNotResolveWhenCalleeClobbersPointerWithUnknownValue() throws Exception {
		ProgramDB program = buildProgram(Variant.CLOBBER_BY_CALLEE);
		runAnalyzer(program);
		assertNoResolution(program);
	}

	@Test
	public void doesNotResolveAcrossIndexedStoreWithUnknownIndex() throws Exception {
		ProgramDB program = buildProgram(Variant.INDEXED_UNKNOWN_STORE);
		runAnalyzer(program);
		assertNoResolution(program);
	}

	@Test
	public void doesNotResolveAcrossConditionalBranch() throws Exception {
		ProgramDB program = buildProgram(Variant.CONDITIONAL_BRANCH);
		runAnalyzer(program);
		assertNoResolution(program);
	}

	@Test
	public void doesNotResolveWhenOnlyOnePointerByteIsStored() throws Exception {
		ProgramDB program = buildProgram(Variant.ONLY_ONE_BYTE);
		runAnalyzer(program);
		assertNoResolution(program);
	}

	@Test
	public void resolvesAfterPossibleBankSwitchWhenEveryBankHoldsTheSameCode() throws Exception {
		ProgramDB program = buildProgram(Variant.OVERLAY_IDENTICAL);
		runAnalyzer(program);
		Reference[] refs = program.getListing().getInstructionAt(siteAddr).getReferencesFrom();
		assertEquals(1, refs.length);
		assertEquals(addr(MAIN_TARGET), refs[0].getToAddress());
	}

	@Test
	public void doesNotResolveWhenAnotherBankDiffersAfterPossibleBankSwitch() throws Exception {
		ProgramDB program = buildProgram(Variant.OVERLAY_DIFFERS_AT_SITE);
		runAnalyzer(program);
		assertNoResolution(program);
	}

	private void assertNoResolution(ProgramDB program) {
		Instruction siteInstr = program.getListing().getInstructionAt(siteAddr);
		assertNotNull(siteInstr);
		assertEquals("analyzer must add no reference when it cannot prove a target", 0,
			siteInstr.getReferencesFrom().length);
		assertNull("analyzer must not disassemble the (unproven) target",
			program.getListing().getInstructionAt(addr(MAIN_TARGET)));
		assertNull("analyzer must not create a function at the (unproven) target",
			program.getFunctionManager().getFunctionAt(addr(MAIN_TARGET)));
	}
}
