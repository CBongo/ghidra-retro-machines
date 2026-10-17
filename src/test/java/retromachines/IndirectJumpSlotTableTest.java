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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * {@link IndirectJumpConstantPointerAnalyzer}'s task-table mode (grm-gipk.3) against a SYNTHETIC
 * cooperative scheduler in megaman3's shape -- hand-built, no ROM bytes copied:
 *
 * <pre>
 *   entry:  LDA #lo; STA $93; LDA #hi; STA $94; LDA #0; JSR create      ; install task 0
 *   sched:  LDX #0; LDA $80,X; CMP #8; BNE done
 *           LDA $82,X; STA $93; LDA $83,X; STA $94; JMP ($93)           ; START a task
 *   done:   RTS
 *   create: ASL A; ASL A; TAX; LDA $93; STA $82,X; LDA $94; STA $83,X; LDA #8; STA $80,X; RTS
 * </pre>
 *
 * The task body at {@link #TASK0} itself installs task 1 at {@link #TASK1}, which is how the
 * cascade (re-resolving an already-referenced site as new code arrives) is exercised.
 */
public class IndirectJumpSlotTableTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";
	private static final long BASE = 0x9000;
	private static final long TASK0 = 0x8008;
	private static final long TASK1 = 0x8100;

	private enum Variant {
		BASELINE,
		/** Negative: the low pointer byte is loaded from RAM, so the installed pointer is unknown. */
		NON_CONSTANT_POINTER,
		/** Negative: the installed pointer is a RAM address, not code. */
		RAM_POINTER,
		/** Negative: the index changes between the dispatcher's two loads -- not one slot. */
		INDEX_CHANGES_IN_DISPATCHER
	}

	private ProgramBuilder builder;
	private Address siteAddr;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

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
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x8000); // ROM: reports non-writable

		long pointer = variant == Variant.RAM_POINTER ? 0x0040 : TASK0;
		Asm asm = new Asm(BASE);
		if (variant == Variant.NON_CONSTANT_POINTER) {
			asm.op(0xa5, 0xf0); // LDA $f0 -- never written: unknown
		}
		else {
			asm.op(0xa9, (int) (pointer & 0xff)); // LDA #lo
		}
		asm.op(0x85, 0x93); // STA $93
		asm.op(0xa9, (int) ((pointer >> 8) & 0xff)); // LDA #hi
		asm.op(0x85, 0x94); // STA $94
		asm.op(0xa9, 0x00); // LDA #0
		asm.op(0x20); // JSR create
		int jsrCreate = asm.reserve16();

		// sched
		asm.op(0xa2, 0x00); // LDX #0
		asm.op(0xb5, 0x80); // LDA $80,X
		asm.op(0xc9, 0x08); // CMP #8
		asm.op(0xd0); // BNE done
		int bneIdx = asm.bytes.size();
		asm.op(0x00);
		long afterBne = asm.here();
		asm.op(0xb5, 0x82); // LDA $82,X
		asm.op(0x85, 0x93); // STA $93
		if (variant == Variant.INDEX_CHANGES_IN_DISPATCHER) {
			asm.op(0xe8); // INX
		}
		asm.op(0xb5, 0x83); // LDA $83,X
		asm.op(0x85, 0x94); // STA $94
		long site = asm.here();
		asm.op(0x6c, 0x93, 0x00); // JMP ($0093)
		long done = asm.here();
		asm.bytes.set(bneIdx, (int) (done - afterBne));
		asm.op(0x60); // RTS

		long create = asm.here();
		asm.patch16(jsrCreate, create);
		emitCreate(asm);

		builder.setBytes(String.format("0x%x", BASE), asm.hex(), true);
		siteAddr = addr(site);

		// Task 0's body: installs task 1 in slot 1 through the same create routine, then returns.
		Asm task = new Asm(TASK0);
		task.op(0xa9, (int) (TASK1 & 0xff)); // LDA #lo
		task.op(0x85, 0x93); // STA $93
		task.op(0xa9, (int) ((TASK1 >> 8) & 0xff)); // LDA #hi
		task.op(0x85, 0x94); // STA $94
		task.op(0xa9, 0x01); // LDA #1
		task.op(0x20, (int) (create & 0xff), (int) ((create >> 8) & 0xff)); // JSR create
		task.op(0x60); // RTS
		builder.setBytes(String.format("0x%x", TASK0), task.hex(), false);
		builder.setBytes(String.format("0x%x", TASK1), "ea 60", false); // NOP; RTS
		return builder.getProgram();
	}

	private static void emitCreate(Asm asm) {
		asm.op(0x0a); // ASL A
		asm.op(0x0a); // ASL A
		asm.op(0xaa); // TAX
		asm.op(0xa5, 0x93); // LDA $93
		asm.op(0x95, 0x82); // STA $82,X
		asm.op(0xa5, 0x94); // LDA $94
		asm.op(0x95, 0x83); // STA $83,X
		asm.op(0xa9, 0x08); // LDA #8
		asm.op(0x95, 0x80); // STA $80,X
		asm.op(0x60); // RTS
	}

	private void run(IndirectJumpConstantPointerAnalyzer analyzer, ProgramDB program,
			AddressSet set) throws Exception {
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> {
			analyzer.added(program, set, TaskMonitor.DUMMY, new MessageLog());
		});
	}

	private Set<Address> targetsAtSite(ProgramDB program) {
		Instruction instr = program.getListing().getInstructionAt(siteAddr);
		assertNotNull(instr);
		Set<Address> out = new HashSet<>();
		for (Reference ref : instr.getReferencesFrom()) {
			assertEquals(RefType.COMPUTED_CALL, ref.getReferenceType());
			out.add(ref.getToAddress());
		}
		return out;
	}

	@Test
	public void resolvesTaskInstalledInSlotTable() throws Exception {
		ProgramDB program = buildProgram(Variant.BASELINE);
		run(new IndirectJumpConstantPointerAnalyzer(), program,
			new AddressSet(addr(BASE), addr(BASE + 0x100)));
		assertEquals(Set.of(addr(TASK0)), targetsAtSite(program));
		assertNotNull("task 0 must be disassembled",
			program.getListing().getInstructionAt(addr(TASK0)));
	}

	@Test
	public void cascadesWhenANewTaskBodyInstallsAnotherTask() throws Exception {
		ProgramDB program = buildProgram(Variant.BASELINE);
		IndirectJumpConstantPointerAnalyzer analyzer = new IndirectJumpConstantPointerAnalyzer();
		run(analyzer, program, new AddressSet(addr(BASE), addr(BASE + 0x100)));
		// What auto-analysis does next: hand the analyzer the code it just disassembled.
		run(analyzer, program, new AddressSet(addr(TASK0), addr(TASK0 + 0x10)));
		assertEquals(Set.of(addr(TASK0), addr(TASK1)), targetsAtSite(program));
		assertNotNull(program.getListing().getInstructionAt(addr(TASK1)));
	}

	@Test
	public void declinesWhenInstalledPointerIsUnknown() throws Exception {
		assertNoResolution(Variant.NON_CONSTANT_POINTER);
	}

	@Test
	public void declinesWhenInstalledPointerIsNotRom() throws Exception {
		assertNoResolution(Variant.RAM_POINTER);
	}

	@Test
	public void declinesWhenDispatcherLoadsFromTwoDifferentSlots() throws Exception {
		assertNoResolution(Variant.INDEX_CHANGES_IN_DISPATCHER);
	}

	private void assertNoResolution(Variant variant) throws Exception {
		ProgramDB program = buildProgram(variant);
		run(new IndirectJumpConstantPointerAnalyzer(), program,
			new AddressSet(addr(BASE), addr(BASE + 0x100)));
		assertEquals(Set.of(), targetsAtSite(program));
		assertNull(program.getListing().getInstructionAt(addr(TASK0)));
	}
}
