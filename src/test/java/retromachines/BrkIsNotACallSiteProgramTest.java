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

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Pins bead {@code grm-htgl}'s settled question 1: a {@code BRK}-derived reference is never a
 * CALL, so it can never enter this codebase's helper call-site machinery, which gates
 * exclusively on {@code Instruction.getFlowType().isCall()}.
 * <p>
 * <b>Background (megaman2's RESET, 2026-09-07 owner finding).</b> megaman2's {@code RESET} is
 * {@code SEI / INC $FFE1 / JMP $f2d1}, and its IRQ vector happens to point at the same address as
 * its RESET vector -- so every {@code BRK} byte in the image (common on a 6502 image wherever
 * undisassembled data decodes as {@code $00}) is, in principle, a reference to {@code RESET}. The
 * worry was that helper-argument recovery ({@link HelperArgumentRecovery#recoverCallArgument})
 * would try to recover an argument at every one of those, scaling with misdisassembled data
 * rather than with anything real -- and that the fix would need to actively filter them out,
 * possibly by cross-referencing {@link DescriptorSupport#ASYNC_ENTRY_POINTS_PROPERTY} (bead
 * {@code grm-913}'s IRQ/NMI entry list).
 * <p>
 * <b>What this test settles.</b> The worry does not apply, and no filter is needed:
 * <ol>
 * <li>{@code BRK}'s p-code is {@code goto [*:2 target]} -- an indirect (computed) jump, not a
 * {@code call} -- in BOTH this repo's own {@code 6502core.sinc} (used by the C64/PET 6510
 * variants) AND, more importantly, Ghidra's own stock {@code 6502.slaspec} (identical
 * definition), which is the language every NES board actually loads with (see
 * {@code machines/nes-mmc1.yaml}'s {@code language: "6502:LE:16:default"} and
 * {@code NesRomLoader.LANGUAGE_ID}) -- so this is not a gap in code this repo controls.</li>
 * <li>{@code FlowType} is fixed at disassembly from the instruction's own p-code template; no
 * later analysis pass promotes a {@code COMPUTED_JUMP} to a {@code CALL}. Verified below even
 * after running full auto-analysis over a fixture where the IRQ vector aliases a real
 * subroutine's entry (megaman2's actual shape): the {@code BRK} instruction gains no
 * {@link Instruction#getFlows()} and no outgoing {@link Reference} at all -- Ghidra does not even
 * resolve the indirect target for this processor by default, so there is not even a spurious
 * JUMP-typed reference to worry about, let alone a CALL-typed one.</li>
 * <li>Every call-site path in this codebase already gates on {@code isCall()}:
 * {@code BankDataflowEngine.runDataflow}'s {@code helpers != null && instr.getFlowType().isCall()}
 * (the sole entry into {@link HelperArgumentRecovery#recoverCallArgument}), and every
 * {@code isCall()} check {@link HelperDiscovery} uses to tell a real call from a same-function
 * tail jump. A {@code BRK} can never satisfy any of them.</li>
 * </ol>
 * The real, already-fixed defect at megaman2's RESET was bead {@code grm-5l14} (the MMC1
 * self-modifying reset idiom being booked as an unrecoverable argument at its 8 real {@code JSR}
 * call sites) -- confirmed by {@code tools/banktest/realrom/expected/megaman2.dump}, whose 8
 * {@code via RESET} sites are the same 8 addresses before and after that fix, all ordinary
 * {@code UNCONDITIONAL_CALL} references, with no BRK-derived site ever appearing.
 */
public class BrkIsNotACallSiteProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		// The stock language every NES board loads with -- see machines/nes-mmc1.yaml and
		// NesRomLoader.LANGUAGE_ID. This is deliberately NOT this repo's own 6510/6502undoc
		// sinc: the point is that BRK's non-call semantics are Ghidra's, not ours to fix.
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/**
	 * megaman2's actual shape: the IRQ vector ($FFFE) and the RESET vector ($FFFC) both target
	 * the same handler, and mainline code also reaches it with a real {@code JSR}. A {@code BRK}
	 * elsewhere in the image reads the IRQ vector and takes an indirect jump there.
	 */
	@Test
	public void brkDoesNotBecomeACallSiteEvenAfterFullAnalysis() throws Exception {
		builder.setBytes("0xfffe", "e0 ff", true); // IRQ vector -> $ffe0
		builder.setBytes("0xfffc", "e0 ff", true); // RESET vector -> $ffe0 too (megaman2's shape)
		builder.setBytes("0xffe0", "78", true); // SEI
		builder.setBytes("0xffe1", "60", true); // RTS -- gives the handler a real body
		builder.setBytes("0x8000", "20 e0 ff", true); // JSR $ffe0 -- a real, legitimate call site
		builder.setBytes("0x8003", "00", true); // BRK -- reads the IRQ vector, jumps to $ffe0 too
		builder.createEntryPoint("0x8000", "STARTJSR");
		builder.createEntryPoint("0xffe0", "RESET");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		int tx = program.startTransaction("analyze");
		try {
			program.getFunctionManager().createFunction("RESET", builder.addr("0xffe0"),
				new AddressSet(builder.addr("0xffe0"), builder.addr("0xffe1")), SourceType.ANALYSIS);
			mgr.reAnalyzeAll(null);
			mgr.startAnalysis(TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(tx, true);
		}

		Instruction brk = program.getListing().getInstructionAt(builder.addr("0x8003"));
		assertFalse("BRK's flow is a computed jump (goto [*:2 target]), never a call -- see the " +
			"identical definition in Ghidra's own stock 6502.slaspec", brk.getFlowType().isCall());
		assertTrue(brk.getFlowType().isComputed());
		assertEquals("Ghidra does not resolve BRK's indirect target for this processor, so there " +
			"is not even a JUMP-typed flow to worry about", 0, brk.getFlows().length);
		Reference[] brkRefs =
			program.getReferenceManager().getReferencesFrom(builder.addr("0x8003"));
		assertEquals("and consequently no outgoing reference of any kind from the BRK site",
			0, brkRefs.length);

		// The only reference actually reaching RESET is the real JSR -- CALL-typed, as expected.
		long callRefs = 0;
		for (Reference r : program.getReferenceManager().getReferencesTo(builder.addr("0xffe0"))) {
			if (r.getReferenceType().isCall()) {
				callRefs++;
			}
		}
		assertEquals("exactly the one real JSR is CALL-typed", 1, callRefs);
	}
}
