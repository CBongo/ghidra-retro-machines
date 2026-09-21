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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Mechanics spike for grm-p3dy, question 1: what Ghidra 12.1.3 does with an
 * {@link Instruction#setFallThrough} whose target lies in an OVERLAY space. Every assertion here
 * is an observation about stock Ghidra, verified against the source
 * ({@code InstructionDB}, {@code FollowFlow}, {@code FunctionManagerDB}, {@code PcodeEmit}) and
 * then pinned by running it, so the design can build on facts rather than on memory.
 *
 * <p>The shape is the M8 "post-switch control flow survives" fixture reduced to five
 * instructions. Base space: {@code LDA #1 / STA $8000 (the commit) / STA $0300 / RTS}. The
 * overlay {@code OV} carries the slice mapped after the commit: {@code STA $0400 / RTS} at the
 * same offsets as the base continuation. A fall-through override on the commit sends execution
 * to {@code OV::c005}; the base {@code STA $0300} becomes code the CPU does not run on that path.
 */
public class FallThroughIntoOverlayProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private Address commit;
	private Address baseNext;
	private Address overlayNext;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		builder.createOverlayMemory("OV", "0xc000", 0x10);
		builder.setBytes("0xc000", "a9 01", true); // LDA #1
		builder.setBytes("0xc002", "8d 00 80", true); // STA $8000 -- the commit
		builder.setBytes("0xc005", "8d 00 03", true); // STA $0300 -- base continuation
		builder.setBytes("0xc008", "60", true); // RTS
		builder.setBytes("OV::c005", "8d 00 04", true); // STA $0400 -- overlay continuation
		builder.setBytes("OV::c008", "60", true); // RTS
		program = builder.getProgram();
		commit = builder.addr("0xc002");
		baseNext = builder.addr("0xc005");
		overlayNext = builder.addr("OV::c005");
	}

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	private Instruction override() throws Exception {
		Instruction instr = program.getListing().getInstructionAt(commit);
		assertNotNull(instr);
		int tx = program.startTransaction("override");
		try {
			instr.setFallThrough(overlayNext);
		}
		finally {
			program.endTransaction(tx, true);
		}
		return instr;
	}

	// ---- 1. the override itself -------------------------------------------------------------

	/**
	 * {@code InstructionDB.setFallThrough} is one {@code FALL_THROUGH} memory reference plus a
	 * flag; nothing checks the target's space, and {@code AddressSpace.subtract} accepts an
	 * overlay against its base space, so the override lands.
	 */
	@Test
	public void overrideIntoAnOverlayIsAccepted() throws Exception {
		Instruction instr = override();
		assertTrue(instr.isFallThroughOverridden());
		assertEquals(overlayNext, instr.getFallThrough());
		assertEquals("the default is untouched", baseNext, instr.getDefaultFallThrough());
	}

	/**
	 * The reference Ghidra records carries {@code SourceType.USER_DEFINED} no matter who set
	 * it -- hard-coded in {@code InstructionDB.setFallThrough}. So an analyzer cannot tell its own
	 * override from a human's by source type; retraction (grm-p3dy Q3) needs its own provenance
	 * record, the way BankCommentProvenance keeps one for comments.
	 */
	@Test
	public void overrideReferenceIsAlwaysUserDefined() throws Exception {
		override();
		Reference ft = null;
		for (Reference r : program.getReferenceManager().getReferencesFrom(commit)) {
			if (r.getReferenceType() == RefType.FALL_THROUGH) {
				ft = r;
			}
		}
		assertNotNull(ft);
		assertEquals(SourceType.USER_DEFINED, ft.getSource());
		assertEquals(overlayNext, ft.getToAddress());
	}

	/**
	 * {@code FALL_THROUGH} is a {@code FlowType}, so {@code InstructionDB.getFlows()} -- which
	 * collects every non-indirect flow reference -- reports the overridden target alongside the
	 * real branches. Anything in this repo that treats {@code getFlows()} as "the jumps" will see
	 * the override as one more edge into the overlay (references-are-the-flow-graph).
	 */
	@Test
	public void overriddenFallThroughShowsUpInGetFlows() throws Exception {
		Instruction instr = override();
		assertTrue(Arrays.asList(instr.getFlows()).contains(overlayNext));
		Instruction lda = program.getListing().getInstructionAt(builder.addr("0xc000"));
		assertEquals("a plain instruction has no flows", 0, lda.getFlows().length);
	}

	/** Clearing restores the default and drops the reference. */
	@Test
	public void overrideCanBeRetracted() throws Exception {
		Instruction instr = override();
		int tx = program.startTransaction("clear");
		try {
			instr.clearFallThroughOverride();
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertFalse(instr.isFallThroughOverridden());
		assertEquals(baseNext, instr.getFallThrough());
		for (Reference r : program.getReferenceManager().getReferencesFrom(commit)) {
			assertFalse(r.getReferenceType() == RefType.FALL_THROUGH);
		}
	}

	// ---- 2. function bodies ---------------------------------------------------------------

	/**
	 * {@code CreateFunctionCmd.getFunctionBody} builds its {@code FollowFlow} with
	 * {@code restrictSingleAddressSpace = true}, and {@code FunctionManagerDB} refuses any body
	 * spanning two spaces. So the base function ENDS AT THE COMMIT: the dead base continuation is
	 * not reached (the override replaced that edge) and the overlay continuation is not admitted
	 * (other space). The overlay copy has to be its own function.
	 */
	@Test
	public void baseFunctionEndsAtTheCommit() throws Exception {
		override();
		Function base = createFunction(builder.addr("0xc000"));
		assertNotNull(base);
		AddressSet expected = new AddressSet(builder.addr("0xc000"), builder.addr("0xc004"));
		assertEquals(expected, new AddressSet(base.getBody()));
		assertNull("base continuation is not part of any function",
			program.getFunctionManager().getFunctionContaining(baseNext));
		assertNull("and neither is the overlay copy, until someone makes it one",
			program.getFunctionManager().getFunctionContaining(overlayNext));
	}

	/** The overlay continuation becomes an ordinary function in its own space. */
	@Test
	public void overlayContinuationIsItsOwnFunction() throws Exception {
		override();
		createFunction(builder.addr("0xc000"));
		Function ov = createFunction(overlayNext);
		assertNotNull(ov);
		assertEquals(overlayNext, ov.getEntryPoint());
		assertEquals(new AddressSet(overlayNext, builder.addr("OV::c008")),
			new AddressSet(ov.getBody()));
	}

	/** Without the override the same base function runs through to its RTS -- the control. */
	@Test
	public void withoutOverrideTheBaseFunctionIsWhole() throws Exception {
		Function base = createFunction(builder.addr("0xc000"));
		assertEquals(new AddressSet(builder.addr("0xc000"), builder.addr("0xc008")),
			new AddressSet(base.getBody()));
	}

	// ---- 3. the decompiler ----------------------------------------------------------------

	/**
	 * THE FINDING THAT DECIDES grm-p3dy's SHAPE (a). {@code PcodeEmit.resolveFinalFallthrough}
	 * turns the override into a final {@code BRANCH} to the overlay address, and the decompiler's
	 * {@code FlowInfo} bounds a function's flow to the ENTRY'S ADDRESS SPACE
	 * ({@code baddr=(space,0)}, {@code eaddr=(space,~0)}, flow.cc:29) -- not to the listing body.
	 * A branch into another space is "out of bounds": {@code newAddress} parks it as unprocessed
	 * with a warning, and when the branch is later resolved {@code FlowInfo::target} throws
	 * {@code "Could not find op at target address"}. The base function is therefore not merely
	 * truncated: it does not decompile AT ALL. Not configurable from the Java side
	 * ({@code error_outofbounds}/{@code ignore_outofbounds} are set only for inlining). The only
	 * cross-space flow the decompiler accepts is a CALL.
	 */
	@Test
	public void decompilerCannotFollowTheOverrideIntoTheOverlay() throws Exception {
		override();
		Function base = createFunction(builder.addr("0xc000"));
		createFunction(overlayNext);
		DecompileResults res = decompileRaw(base);
		assertFalse("expected a hard decompile failure, got: " +
			(res.decompileCompleted() ? res.getDecompiledFunction().getC() : ""),
			res.decompileCompleted());
		assertTrue(res.getErrorMessage(),
			res.getErrorMessage().contains("Could not find op at target address: (OV,0xc005)"));
	}

	/**
	 * The obvious repair does not work either: a {@code FlowOverride.CALL_RETURN} on the commit
	 * cannot turn the fall-through branch into a call, because {@code resolveFinalFallthrough}
	 * dumps its {@code BRANCH} through the raw {@code dump(Address,int,...)} path that bypasses
	 * {@code checkOverrides}, and an {@code STA} has no branch op of its own for the flow override
	 * to rewrite. Same failure.
	 */
	@Test
	public void callReturnFlowOverrideDoesNotRescueIt() throws Exception {
		Instruction instr = override();
		int tx = program.startTransaction("flow override");
		try {
			instr.setFlowOverride(FlowOverride.CALL_RETURN);
		}
		finally {
			program.endTransaction(tx, true);
		}
		Function base = createFunction(builder.addr("0xc000"));
		createFunction(overlayNext);
		DecompileResults res = decompileRaw(base);
		assertFalse(res.decompileCompleted());
		assertTrue(res.getErrorMessage(),
			res.getErrorMessage().contains("Could not find op at target address"));
	}

	/** Control: without the override the decompiler shows the base continuation. */
	@Test
	public void decompilerShowsTheBaseContinuationWithoutOverride() throws Exception {
		Function base = createFunction(builder.addr("0xc000"));
		String c = decompile(base);
		assertTrue(c, c.contains("DAT_0300"));
		assertFalse(c, c.contains("0400"));
	}

	/**
	 * The overlay function on its own decompiles fine -- it is an ordinary function in an
	 * overlay space, which the decompiler models as a space of its own.
	 */
	@Test
	public void overlayFunctionDecompilesOnItsOwn() throws Exception {
		override();
		createFunction(builder.addr("0xc000"));
		Function ov = createFunction(overlayNext);
		String c = decompile(ov);
		assertTrue(c, c.contains("0400"));
	}

	// ---- helpers ---------------------------------------------------------------------------

	private Function createFunction(Address entry) {
		int tx = program.startTransaction("fn");
		try {
			CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
			cmd.applyTo(program, TaskMonitor.DUMMY);
			return cmd.getFunction();
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private DecompileResults decompileRaw(Function f) {
		DecompInterface ifc = new DecompInterface();
		try {
			assertTrue("decompiler did not open: " + ifc.getLastMessage(), ifc.openProgram(program));
			return ifc.decompileFunction(f, 30, TaskMonitor.DUMMY);
		}
		finally {
			ifc.dispose();
		}
	}

	private String decompile(Function f) {
		DecompileResults res = decompileRaw(f);
		assertTrue("decompile failed: " + res.getErrorMessage(), res.decompileCompleted());
		return res.getDecompiledFunction().getC();
	}
}
