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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * {@link ConditionalTailCallNarrowingAnalyzer} against the stock Shared Return Calls command with
 * "Allow Conditional Jumps" on (grm-6m24.1), on a reduction of smb3's $E3F6 BNE $E401:
 * <pre>
 *   8000  LDA $10
 *   8002  BNE $8010   ; the conditional branch under test
 *   8004  RTS
 *   8010  RTS         ; target T, a function entry
 *   8020  JMP $8010   ; always present: T is jump-reached, as $E401 is from $E51B
 *   8030  JSR $8010   ; optional: makes T a genuine entry
 * </pre>
 * Optionally a DATA reference to T (a dispatch-table word, as for smb3's b4c1/bb80/af23 stubs).
 */
public class ConditionalTailCallNarrowingProgramTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB build(boolean jsr, boolean pointer) throws Exception {
		builder = newBuilder("Test", LANG);
		builder.createMemory(".text", "0x8000", 0x100);
		builder.setBytes("0x8000", "a5 10 d0 0c 60", true);
		builder.setBytes("0x8010", "60", true);
		builder.setBytes("0x8020", "4c 10 80", true);
		if (jsr) {
			builder.setBytes("0x8030", "20 10 80", true);
		}
		ProgramDB program = builder.getProgram();
		inTxGet(program, "functions", () -> {
			new CreateFunctionCmd(addr(0x8000)).applyTo(program, TaskMonitor.DUMMY);
			new CreateFunctionCmd(addr(0x8010)).applyTo(program, TaskMonitor.DUMMY);
			if (pointer) {
				program.getReferenceManager().addMemoryReference(addr(0x80f0), addr(0x8010),
					RefType.DATA, SourceType.ANALYSIS, 0);
			}
			return null;
		});
		return program;
	}

	/** Our function-added half, then the stock command, as the analyzer priorities order them. */
	private Instruction analyze(ProgramDB program, boolean stockFirst) throws Exception {
		AddressSet entries = new AddressSet(addr(0x8000)).union(new AddressSet(addr(0x8010)));
		return inTxGet(program, "analyze", () -> {
			ConditionalTailCallNarrowingAnalyzer ours = new ConditionalTailCallNarrowingAnalyzer();
			assertTrue(ours.canAnalyze(program));
			SharedReturnAnalysisCmd stock = new SharedReturnAnalysisCmd(entries, false, true);
			if (stockFirst) {
				stock.applyTo(program, TaskMonitor.DUMMY);
			}
			ours.added(program, entries, TaskMonitor.DUMMY, new MessageLog());
			stock.applyTo(program, TaskMonitor.DUMMY);
			return program.getListing().getInstructionAt(addr(0x8002));
		});
	}

	@Test
	public void control_stockAloneMakesTheBranchATailCall() throws Exception {
		ProgramDB program = build(false, false);
		Instruction bne = inTxGet(program, "stock", () -> {
			new SharedReturnAnalysisCmd(new AddressSet(addr(0x8010)), false, true)
					.applyTo(program, TaskMonitor.DUMMY);
			return program.getListing().getInstructionAt(addr(0x8002));
		});
		assertEquals(FlowOverride.CALL_RETURN, bne.getFlowOverride());
	}

	@Test
	public void branchIntoJumpOnlyTargetIsNotATailCall() throws Exception {
		ProgramDB program = build(false, false);
		Instruction bne = analyze(program, false);
		assertEquals(FlowOverride.BRANCH, bne.getFlowOverride());
		assertFalse(ConditionalTailCallNarrowingAnalyzer.isGenuineEntry(program, addr(0x8010)));
		assertPinIsANoOp(bne);
	}

	/** The stock half got there first (e.g. its code-added twin): the override is replaced. */
	@Test
	public void existingTailCallIntoJumpOnlyTargetIsWithdrawn() throws Exception {
		ProgramDB program = build(false, false);
		Instruction bne = analyze(program, true);
		assertEquals(FlowOverride.BRANCH, bne.getFlowOverride());
	}

	@Test
	public void branchIntoJsrReachedEntryStaysATailCall() throws Exception {
		ProgramDB program = build(true, false);
		Instruction bne = analyze(program, false);
		assertTrue(ConditionalTailCallNarrowingAnalyzer.isGenuineEntry(program, addr(0x8010)));
		assertEquals(FlowOverride.CALL_RETURN, bne.getFlowOverride());
	}

	@Test
	public void branchIntoPointerReachedEntryStaysATailCall() throws Exception {
		ProgramDB program = build(false, true);
		Instruction bne = analyze(program, false);
		assertEquals(FlowOverride.CALL_RETURN, bne.getFlowOverride());
	}

	/** A JMP the stock command made into a call (UNCONDITIONAL_CALL ref) is still a jump. */
	@Test
	public void overriddenJmpDoesNotMakeTheTargetGenuine() throws Exception {
		ProgramDB program = build(false, false);
		analyze(program, true);
		Instruction jmp = program.getListing().getInstructionAt(addr(0x8020));
		assertEquals(FlowOverride.CALL_RETURN, jmp.getFlowOverride());
		assertTrue(jmp.getFlowType().isCall());
		assertFalse(ConditionalTailCallNarrowingAnalyzer.isGenuineEntry(program, addr(0x8010)));
	}

	/** A JSR found after the pin hands the branch back to the stock command. */
	@Test
	public void laterJsrUnpinsTheBranch() throws Exception {
		ProgramDB program = build(false, false);
		analyze(program, false);
		Instruction bne = inTxGet(program, "jsr", () -> {
			builder.setBytes("0x8030", "20 10 80", true);
			new ConditionalTailCallNarrowingJumpAnalyzer().added(program,
				new AddressSet(addr(0x8030), addr(0x8032)), TaskMonitor.DUMMY, new MessageLog());
			new SharedReturnAnalysisCmd(new AddressSet(addr(0x8010)), false, true)
					.applyTo(program, TaskMonitor.DUMMY);
			return program.getListing().getInstructionAt(addr(0x8002));
		});
		assertEquals(FlowOverride.CALL_RETURN, bne.getFlowOverride());
	}

	/** BRANCH on a conditional branch changes neither its flow type nor its p-code. */
	private static void assertPinIsANoOp(Instruction bne) {
		assertEquals(RefType.CONDITIONAL_JUMP, bne.getFlowType());
		boolean cbranch = false;
		for (PcodeOp op : bne.getPcode()) {
			assertFalse("pin added a " + op.getMnemonic(),
				op.getOpcode() == PcodeOp.RETURN || op.getOpcode() == PcodeOp.CALL);
			cbranch |= op.getOpcode() == PcodeOp.CBRANCH;
		}
		assertTrue(cbranch);
	}
}
