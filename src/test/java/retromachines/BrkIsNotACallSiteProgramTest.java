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

import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
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
 * possibly by cross-referencing {@link DescriptorHints#ASYNC_ENTRY_POINTS_PROPERTY} (bead
 * {@code grm-913}'s IRQ/NMI entry list).
 * <p>
 * <b>What this test settles.</b> As first written (grm-htgl), that the worry does not apply and
 * no filter is needed -- half right; see the correction below:
 * <ol>
 * <li>{@code BRK}'s p-code is {@code goto [*:2 target]} -- an indirect (computed) jump, not a
 * {@code call} -- in BOTH this repo's own {@code 6502core.sinc} (used by the C64/PET 6510
 * variants) AND, more importantly, Ghidra's own stock {@code 6502.slaspec} (identical
 * definition), which is the language every NES board actually loads with (see
 * {@code machines/nes-mmc1.yaml}'s {@code language: "6502:LE:16:default"} and
 * {@code NesRomLoader.LANGUAGE_ID}) -- so this is not a gap in code this repo controls.</li>
 * <li>On WRITABLE memory (the first test below) Ghidra does not resolve the indirect target, so
 * the {@code BRK} gains no {@link Instruction#getFlows()} and no outgoing {@link Reference}.</li>
 * </ol>
 * <b>CORRECTED by bead {@code grm-ktne} (2026-10-16).</b> The original point 2 -- "FlowType is
 * fixed at disassembly; no later analysis pass promotes a COMPUTED_JUMP to a CALL" -- is false.
 * {@code getFlowType()} applies the instruction's {@code FlowOverride}. On READ-ONLY PRG, which
 * is what every NES loader creates, constant propagation resolves the vector read and adds a
 * COMPUTED_JUMP reference to the handler; when the handler is a function entry and the
 * {@code BRK} sits outside any function, {@code SharedReturnAnalysisCmd} sets CALL_RETURN and the
 * flow becomes COMPUTED_CALL_TERMINATOR, so {@code isCall()} is TRUE. deadly_towers (BNROM,
 * IRQ = RESET = fcfa, which stores bank 0) paid for it: ~30 filler {@code $00} bytes in bank 2's
 * data each got "bank -> 0 via FUN_PRG_ALL_B2__fcfa". The dataflow's helper-call gate is
 * therefore {@link BankDataflowEngine#isHelperCallSite}, which refuses a promoted computed flow;
 * the second and third tests below pin both halves.
 * <p>
 * The paragraph that stood here claimed megaman2's {@code via RESET} sites were 8 real
 * {@code JSR} call sites. They were not: the pinned image has no {@code JSR}/{@code JMP $FFE0}
 * at all, and every one of its golden {@code via RESET} comments (9060, a000, ... da2e) sat on a
 * {@code $00} byte -- exactly the BRK artifact this test was written to rule out. grm-ktne's fix
 * removed them, along with megaman's 6 (IRQ = RESET = c008, likewise never called) and
 * deadly_towers' 33.
 */
public class BrkIsNotACallSiteProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		// The stock language every NES board loads with -- see machines/nes-mmc1.yaml and
		// NesRomLoader.LANGUAGE_ID. This is deliberately NOT this repo's own 6510/6502undoc
		// sinc: the point is that BRK's non-call semantics are Ghidra's, not ours to fix.
		builder = newBuilder("Test", "6502:LE:16:default");
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
		inTx(program, "analyze", () -> {
			program.getFunctionManager().createFunction("RESET", builder.addr("0xffe0"),
				new AddressSet(builder.addr("0xffe0"), builder.addr("0xffe1")), SourceType.ANALYSIS);
			mgr.reAnalyzeAll(null);
			mgr.startAnalysis(TaskMonitor.DUMMY);
		});

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

	/**
	 * deadly_towers' shape (grm-ktne): IRQ = RESET = a function, and a lone {@code BRK} /
	 * {@code JMP ($FFFC)} outside any function (filler data in bank 2). The import there gives
	 * each a resolved COMPUTED_JUMP reference to the handler (source ANALYSIS: the vector is
	 * read-only PRG, so its target is a constant), and {@code SharedReturnAnalysisCmd} then
	 * promotes it. Auto-analysis in this fixture does not get that far (it creates no functions at
	 * all), so the two steps are driven explicitly: the resolved reference, then Ghidra's own
	 * SharedReturn command, unmodified. The helper-call gate must refuse the promoted computed
	 * jumps, while a real {@code JSR} and a direct tail {@code JMP} into the handler stay call
	 * sites.
	 */
	@Test
	public void promotedComputedJumpIsNotAHelperCallSite() throws Exception {
		builder.setBytes("0xfffe", "e0 ff", true); // IRQ vector -> $ffe0
		builder.setBytes("0xfffc", "e0 ff", true); // RESET vector -> $ffe0 (deadly_towers' fcfa)
		builder.setBytes("0xffe0", "78", true); // SEI
		builder.setBytes("0xffe1", "60", true); // RTS
		builder.setBytes("0x8000", "20 e0 ff 60", true); // JSR $ffe0 / RTS -- a real call
		builder.setBytes("0x8010", "00", true); // BRK -- filler, outside any function
		builder.setBytes("0x8020", "6c fc ff", true); // JMP ($fffc) -- a soft reset (bank 2 824f)
		builder.setBytes("0x8030", "4c e0 ff", true); // JMP $ffe0 -- a DIRECT jump to the entry

		Address reset = builder.addr("0xffe0");
		inTx(program, "shape", () -> {
			for (String at : new String[] { "0xffe0", "0x8000", "0x8010", "0x8020", "0x8030" }) {
				new DisassembleCommand(builder.addr(at), null, false).applyTo(program);
			}
			program.getFunctionManager().createFunction("RESET", reset,
				new AddressSet(reset, builder.addr("0xffe1")), SourceType.ANALYSIS);
			for (String at : new String[] { "0x8010", "0x8020" }) {
				program.getListing().getInstructionAt(builder.addr(at))
						.addMnemonicReference(reset, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
			}
			new SharedReturnAnalysisCmd(new AddressSet(reset), false, false)
					.applyTo(program, TaskMonitor.DUMMY);
		});

		Instruction brk = program.getListing().getInstructionAt(builder.addr("0x8010"));
		Instruction jmpInd = program.getListing().getInstructionAt(builder.addr("0x8020"));
		Instruction jmpDirect = program.getListing().getInstructionAt(builder.addr("0x8030"));
		Instruction jsr = program.getListing().getInstructionAt(builder.addr("0x8000"));

		for (Instruction promoted : new Instruction[] { brk, jmpInd }) {
			assertEquals("SharedReturn promotes a resolved computed jump to a function entry: " +
				promoted, FlowOverride.CALL_RETURN, promoted.getFlowOverride());
			assertTrue("so bare isCall() is TRUE -- the grm-htgl premise fails here: " + promoted,
				promoted.getFlowType().isCall());
			assertFalse("but a promoted COMPUTED jump is never a helper call site: " + promoted,
				BankDataflowEngine.isHelperCallSite(promoted));
		}
		assertEquals("SharedReturn promotes the direct tail JMP too", FlowOverride.CALL_RETURN,
			jmpDirect.getFlowOverride());
		assertTrue("and it stays a helper call site -- a real tail call",
			BankDataflowEngine.isHelperCallSite(jmpDirect));
		assertTrue("a real JSR is a helper call site", BankDataflowEngine.isHelperCallSite(jsr));
	}
}
