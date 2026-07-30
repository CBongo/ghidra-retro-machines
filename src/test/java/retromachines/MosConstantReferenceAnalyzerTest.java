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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Exercises {@link MosConstantReferenceAnalyzer} (grm-phv) end to end through the real,
 * public {@code ConstantPropagationAnalyzer.analyzeLocation} entry point -- no internal seam
 * is needed since that method is already public. Each fixture pairs a {@code LDX}/{@code LDY}
 * immediate load with an indexed access so the constant propagator actually resolves the
 * index value; that resolution is precisely what triggers the bug this analyzer fixes (an
 * unknown index already gets a correct base reference from stock {@code SymbolicPropogator}
 * behavior, so there would be nothing to prove with one).
 *
 * <p>Follows {@link BankStrategyProgramTest}'s {@code ProgramBuilder} +
 * {@code builder.setBytes(addr, hex, true)} pattern for real disassembled instructions, and
 * extends {@link AbstractBundledLanguageTest} (rather than plain {@code AbstractGenericTest})
 * so the {@code 6510:*} bundled languages resolve for the case 8 fixture.
 */
public class MosConstantReferenceAnalyzerTest extends AbstractBundledLanguageTest {

	/**
	 * A program with a zero-page block, a code block, and a data block covering {@code $2000}
	 * -- {@code ConstantPropagationContextEvaluator}'s speculative-reference machinery
	 * (via {@code SymbolicPropogator.makeReference}) drops computed references whose target
	 * is not backed by real program memory, so every fixture below needs its computed
	 * (pre-retarget) address to land inside a real block, not just its retargeted base.
	 */
	private static ProgramBuilder newBuilder(String languageId) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", languageId);
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory(".text", "0x8000", 0x1000);
		builder.createMemory(".data", "0x2000", 0x1000);
		return builder;
	}

	/** Non-flow reference targets from {@code instr} -- what's left once the mnemonic's own
	 *  fall-through/branch flow references are filtered out, i.e. the DATA/READ/WRITE targets
	 *  this analyzer places or suppresses. */
	private static Set<Address> nonFlowTargets(Instruction instr) {
		Set<Address> targets = new HashSet<>();
		for (Reference ref : instr.getReferencesFrom()) {
			if (!ref.getReferenceType().isFlow()) {
				targets.add(ref.getToAddress());
			}
		}
		return targets;
	}

	/** Runs {@code analyzer} over the whole program starting at {@code start}, inside its own
	 *  transaction, the way {@code AutoAnalysisManager} would. */
	private static void analyze(Program program, MosConstantReferenceAnalyzer analyzer,
			Address start) throws Exception {
		assertTrue("canAnalyze should be true for this processor's program",
			analyzer.canAnalyze(program));
		int tx = program.startTransaction("analyze");
		boolean success = false;
		try {
			analyzer.analyzeLocation(program, start, null, TaskMonitor.DUMMY);
			success = true;
		}
		finally {
			program.endTransaction(tx, success);
		}
	}

	@Test
	public void absoluteIndexedXRetargetsToBase() throws Exception {
		// LDX #$05 ; LDA $2000,X -- stock would reference the computed $2005, burying the
		// table's actual base.
		ProgramBuilder builder = newBuilder("6502:LE:16:default");
		builder.setBytes("0x8000", "a2 05", true); // LDX #$05
		builder.setBytes("0x8002", "bd 00 20", true); // LDA $2000,X
		ProgramDB program = builder.getProgram();

		analyze(program, new Mos6502ConstantReferenceAnalyzer(), builder.addr("0x8000"));

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("LDA $2000,X did not disassemble", lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals(Set.of(builder.addr("0x2000")), targets);
		assertFalse("computed $2005 must not appear", targets.contains(builder.addr("0x2005")));
	}

	@Test
	public void absoluteIndexedYRetargetsToBase() throws Exception {
		// LDY #$05 ; LDA $2000,Y -- same shape as abs,X with the Y-indexed opcode/mode.
		ProgramBuilder builder = newBuilder("6502:LE:16:default");
		builder.setBytes("0x8000", "a0 05", true); // LDY #$05
		builder.setBytes("0x8002", "b9 00 20", true); // LDA $2000,Y
		ProgramDB program = builder.getProgram();

		analyze(program, new Mos6502ConstantReferenceAnalyzer(), builder.addr("0x8000"));

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("LDA $2000,Y did not disassemble", lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals(Set.of(builder.addr("0x2000")), targets);
		assertFalse("computed $2005 must not appear", targets.contains(builder.addr("0x2005")));
	}

	@Test
	public void zeroPageIndexedXRetargetsToBase() throws Exception {
		// LDX #$05 ; LDA $80,X -- zero-page indexed, no wraparound (base + index stays < $100).
		ProgramBuilder builder = newBuilder("6502:LE:16:default");
		builder.setBytes("0x8000", "a2 05", true); // LDX #$05
		builder.setBytes("0x8002", "b5 80", true); // LDA $80,X
		ProgramDB program = builder.getProgram();

		analyze(program, new Mos6502ConstantReferenceAnalyzer(), builder.addr("0x8000"));

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("LDA $80,X did not disassemble", lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals(Set.of(builder.addr("0x0080")), targets);
	}

	@Test
	public void zeroPageIndexedXWraparoundUsesOperandScalarNotSubtraction() throws Exception {
		// LDX #$F0 ; LDA $80,X -- sleigh computes tmp:2 = zext(imm8 + X) with imm8+X done in
		// ONE byte first ($80 + $F0 = $170 mod $100 = $70), so the effective (computed)
		// address is $0070, not $FF80. The retargeted base must be the operand's own scalar
		// $0080 -- proving indexedBase's "use the scalar, not address-minus-index" approach is
		// correct: address($0070) - X($F0) would give $FF80, address($0070) is itself wrong to
		// report as the table's identity, and neither matches the real base $0080 the operand
		// names.
		ProgramBuilder builder = newBuilder("6502:LE:16:default");
		builder.setBytes("0x8000", "a2 f0", true); // LDX #$F0
		builder.setBytes("0x8002", "b5 80", true); // LDA $80,X
		ProgramDB program = builder.getProgram();

		analyze(program, new Mos6502ConstantReferenceAnalyzer(), builder.addr("0x8000"));

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("LDA $80,X did not disassemble", lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals(Set.of(builder.addr("0x0080")), targets);
		assertFalse("must not be the wrapped computed address $0070",
			targets.contains(builder.addr("0x0070")));
		assertFalse("must not be the naively-subtracted, non-wrapped $FF80",
			targets.contains(builder.addr("0xFF80")));
	}

	/**
	 * {@code (zp),Y} with a known pointer and known Y.
	 *
	 * <p>This is the one case the task brief flagged as at risk: it depends on the constant
	 * propagator actually dereferencing a compile-time-constant zero-page address through real
	 * program bytes to resolve the pointer, which is a deeper piece of {@code SymbolicPropogator}
	 * machinery than the direct-indexed cases exercise. It DID resolve in this fixture (a
	 * plain {@code ProgramBuilder.createMemory} block is read-only by default -- see
	 * {@link AbstractBundledLanguageTest}'s javadoc on {@code uninitializedRam} -- and
	 * {@code VarnodeContext} trusts reads from read-only memory unconditionally, independent of
	 * the "trust writable memory" option), so this test asserts the full retargeted-base
	 * behavior, not just stock preservation. If a future Ghidra version changes that trust
	 * behavior and this starts failing, downgrade it to asserting only that stock behavior is
	 * preserved, and say so here.
	 *
	 * <p>Getting this fixture to pass surfaced a real subtlety, not just a resolution risk:
	 * {@code (zp),Y} performs TWO memory accesses, and the propagator calls
	 * {@code evaluateReference} once for each on the same {@link Instruction} -- a 2-byte
	 * pointer fetch from the fixed zero-page slot ($0080 here), then the real 1-byte
	 * dereferenced-and-indexed access ($2015, the pointer's target plus Y). Only the second
	 * carries a Y term and so only it is retargeted (to $2010); the pointer fetch is passed
	 * through to stock handling, because the instruction really does read the pointer at $80
	 * and that reference is worth keeping. Hence the expected set is BOTH $0080 and $2010 --
	 * and never $2015. Size is what tells the two calls apart, since on the 6502 every real
	 * data transfer is one byte while the pointer fetch is always two; see the
	 * {@code size != 1} branch in {@code MosConstantReferenceAnalyzer.flowConstants}.
	 */
	@Test
	public void indirectIndexedYRetargetsToPointerTarget() throws Exception {
		ProgramBuilder builder = newBuilder("6502:LE:16:default");
		// Zero-page pointer at $80/$81 -> $2010 (little endian).
		builder.setBytes("0x0080", "10 20");
		builder.setBytes("0x8000", "a0 05", true); // LDY #$05
		builder.setBytes("0x8002", "b1 80", true); // LDA ($80),Y
		ProgramDB program = builder.getProgram();

		analyze(program, new Mos6502ConstantReferenceAnalyzer(), builder.addr("0x8000"));

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("LDA ($80),Y did not disassemble", lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals("the retargeted table base plus the stock pointer-slot reference",
			Set.of(builder.addr("0x0080"), builder.addr("0x2010")), targets);
		assertFalse("computed pointer+Y ($2015) must not appear",
			targets.contains(builder.addr("0x2015")));
	}

	/**
	 * {@code (zp,X)} indexed indirect is deliberately left unretargeted: the index selects
	 * which zero-page pointer is dereferenced, not an offset into one fixed table, so there is
	 * no single base address to name. Expressed as "identical to a run with the option
	 * off" rather than asserting a specific reference set, since what (if anything) stock
	 * {@code SymbolicPropogator} resolves here does not matter to this analyzer -- only that
	 * it is untouched.
	 */
	@Test
	public void indexedIndirectIsLeftToStockBehavior() throws Exception {
		ProgramBuilder onBuilder = newBuilder("6502:LE:16:default");
		onBuilder.setBytes("0x8000", "a2 05", true); // LDX #$05
		onBuilder.setBytes("0x8002", "a1 80", true); // LDA ($80,X)
		ProgramDB onProgram = onBuilder.getProgram();
		analyze(onProgram, new Mos6502ConstantReferenceAnalyzer(), onBuilder.addr("0x8000"));
		Instruction onInstr = onProgram.getListing().getInstructionAt(onBuilder.addr("0x8002"));
		assertNotNull(onInstr);
		Set<Address> onTargets = nonFlowTargets(onInstr);

		ProgramBuilder offBuilder = newBuilder("6502:LE:16:default");
		offBuilder.setBytes("0x8000", "a2 05", true);
		offBuilder.setBytes("0x8002", "a1 80", true);
		ProgramDB offProgram = offBuilder.getProgram();
		Mos6502ConstantReferenceAnalyzer offAnalyzer = new Mos6502ConstantReferenceAnalyzer();
		assertTrue(offAnalyzer.canAnalyze(offProgram)); // also computes per-program defaults
		int tx = offProgram.startTransaction("configure+analyze");
		boolean success = false;
		try {
			Options options = offProgram.getOptions(Program.ANALYSIS_PROPERTIES);
			offAnalyzer.registerOptions(options, offProgram);
			options.setBoolean(MosConstantReferenceAnalyzer.OPTION_NAME_INDEXED_BASE, false);
			offAnalyzer.optionsChanged(options, offProgram);
			assertFalse(offAnalyzer.referenceIndexedBase);
			offAnalyzer.analyzeLocation(offProgram, offBuilder.addr("0x8000"), null,
				TaskMonitor.DUMMY);
			success = true;
		}
		finally {
			offProgram.endTransaction(tx, success);
		}
		Instruction offInstr = offProgram.getListing().getInstructionAt(offBuilder.addr("0x8002"));
		assertNotNull(offInstr);
		Set<Address> offTargets = nonFlowTargets(offInstr);

		assertEquals("(zp,X) must behave identically whether the option is on or off",
			offTargets, onTargets);
		assertFalse("must never retarget to the zero-page pointer slot itself",
			onTargets.contains(onBuilder.addr("0x0080")));
	}

	@Test
	public void optionOffRevertsToStockComputedReference() throws Exception {
		// Same fixture as case 1 (abs,X), but with the real Options plumbing driving the
		// option off: register, flip, and re-read through optionsChanged, exactly as
		// AutoAnalysisManager would when a user unchecks the option in the GUI.
		ProgramBuilder builder = newBuilder("6502:LE:16:default");
		builder.setBytes("0x8000", "a2 05", true); // LDX #$05
		builder.setBytes("0x8002", "bd 00 20", true); // LDA $2000,X
		ProgramDB program = builder.getProgram();

		Mos6502ConstantReferenceAnalyzer analyzer = new Mos6502ConstantReferenceAnalyzer();
		assertTrue(analyzer.canAnalyze(program));

		int tx = program.startTransaction("configure+analyze");
		boolean success = false;
		try {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			analyzer.registerOptions(options, program);
			options.setBoolean(MosConstantReferenceAnalyzer.OPTION_NAME_INDEXED_BASE, false);
			analyzer.optionsChanged(options, program);
			assertFalse(analyzer.referenceIndexedBase);
			analyzer.analyzeLocation(program, builder.addr("0x8000"), null, TaskMonitor.DUMMY);
			success = true;
		}
		finally {
			program.endTransaction(tx, success);
		}

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull(lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals(Set.of(builder.addr("0x2005")), targets);
		assertFalse("must not retarget to the base while the option is off",
			targets.contains(builder.addr("0x2000")));
	}

	@Test
	public void bundled6510LanguageRetargetsToBase() throws Exception {
		// Repeats case 1 (abs,X) with the second subclass on a program built with this
		// module's bundled 6510:LE:16:default language, proving both the 6510 subclass and
		// the bundled-language test layout work together.
		ProgramBuilder builder = newBuilder("6510:LE:16:default");
		builder.setBytes("0x8000", "a2 05", true); // LDX #$05
		builder.setBytes("0x8002", "bd 00 20", true); // LDA $2000,X
		ProgramDB program = builder.getProgram();

		analyze(program, new Mos6510ConstantReferenceAnalyzer(), builder.addr("0x8000"));

		Instruction lda = program.getListing().getInstructionAt(builder.addr("0x8002"));
		assertNotNull("LDA $2000,X did not disassemble", lda);
		Set<Address> targets = nonFlowTargets(lda);
		assertEquals(Set.of(builder.addr("0x2000")), targets);
		assertFalse("computed $2005 must not appear", targets.contains(builder.addr("0x2005")));
	}
}
