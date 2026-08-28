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
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

/**
 * Pins {@link HelperDiscovery#reachableEntries} (grm-nju): where a call actually lands once
 * Ghidra thunks and one-instruction jump trampolines are followed.
 * <p>
 * The shapes here are Bionic Commando's, whose bank switches all route through a jump table of
 * 3-byte slots. Measurement (HelperShapeProbe, real ROM) found every one of its 5 bank call
 * sites and all 59 of Final Fantasy's reaching their helper only through such a hop -- which is
 * why both titles resolved exactly zero bank values before this. Ghidra types the same idiom
 * two ways depending on whether the slot's target happens to be a function entry:
 * <pre>
 *   $D751  JMP $DCC3   -&gt; typed thunk_FUN_dcc3   ($DCC3 is a function entry)
 *   $D6E2  JMP $DCAA   -&gt; ordinary function      ($DCAA is mid-body, so no thunk typing)
 * </pre>
 * so both forms must be followed, and neither subsumes the other.
 * <p>
 * These tests deliberately stop at the address level. {@code reachableEntries} is a function of
 * {@code (program, callInstr)} alone -- no analyzer state, no board descriptor, no helper map --
 * which is exactly what lets them run in the fast JUnit tier at all; the analyzer-level
 * consequence is pinned by the {@code nesmmc1test} headless fixture instead.
 */
public class HelperEntryProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		// Every test calls from here, so only the callee side varies.
		builder.setBytes("0x8000", "20 00 90", true); // JSR $9000
	}

	private Instruction theCall() {
		Instruction call = program.getListing().getInstructionAt(builder.addr("0x8000"));
		assertNotNull("nothing disassembled at the call site", call);
		assertTrue("fixture must actually be a call, or the test proves nothing",
			call.getFlowType().isCall());
		return call;
	}

	/** Reachable entries as plain hex, so a failure reads as addresses rather than objects. */
	private List<String> entries() {
		List<String> out = new ArrayList<>();
		for (Address a : HelperDiscovery.reachableEntries(program, theCall())) {
			out.add(a.toString());
		}
		return out;
	}

	private void makeThunk(Function thunk, Function thunked) throws Exception {
		int tx = program.startTransaction("set thunked function");
		try {
			thunk.setThunkedFunction(thunked);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	// ------------------------------------------------------------------
	// The hops that must be followed
	// ------------------------------------------------------------------

	/** No relay at all: the direct target, and nothing invented beyond it. */
	@Test
	public void plainCallYieldsOnlyItsDirectTarget() throws Exception {
		builder.setBytes("0x9000", "60", true); // RTS
		builder.createEmptyFunction("helper", "0x9000", 1, null);

		assertEquals(List.of("9000"), entries());
	}

	/** The {@code $D751} form: Ghidra typed the slot as a thunk because its target is an entry. */
	@Test
	public void followsAGhidraThunkToTheThunkedEntry() throws Exception {
		builder.setBytes("0x9000", "4c 00 91", true); // JMP $9100
		builder.setBytes("0x9100", "60", true); // RTS
		Function helper = builder.createEmptyFunction("helper", "0x9100", 1, null);
		Function thunk = builder.createEmptyFunction("thunk", "0x9000", 3, null);
		makeThunk(thunk, helper);

		assertEquals(List.of("9000", "9100"), entries());
	}

	/**
	 * The {@code $D6E2} form, and the one the old {@code getFunctionAt} lookup could never see:
	 * a 3-byte relay whose target is INSIDE another function, so Ghidra leaves it an ordinary
	 * one-instruction function rather than typing it a thunk.
	 */
	@Test
	public void followsAOneInstructionRelayIntoAnotherFunctionsBody() throws Exception {
		builder.setBytes("0x9000", "4c 05 91", true); // JMP $9105 -- mid-body
		builder.setBytes("0x9100", "a9 01", true); // LDA #$01   <- helper entry (the prologue)
		builder.setBytes("0x9102", "a9 02", true); // LDA #$02
		builder.setBytes("0x9105", "60", true); // RTS
		builder.createEmptyFunction("helper", "0x9100", 8, null);
		builder.createEmptyFunction("relay", "0x9000", 3, null);

		assertEquals(List.of("9000", "9105"), entries());
	}

	/** A relay Ghidra never made a function of at all: no owner, so nothing to disqualify it. */
	@Test
	public void followsABodilessRelayJump() throws Exception {
		builder.setBytes("0x9000", "4c 00 91", true); // JMP $9100
		builder.setBytes("0x9100", "60", true); // RTS

		assertEquals(List.of("9000", "9100"), entries());
	}

	// ------------------------------------------------------------------
	// The hops that must NOT be followed
	// ------------------------------------------------------------------

	/**
	 * A tail jump is not a relay. The call enters at the top and the body runs before the jump,
	 * so crediting the caller with the jump's target would skip that body -- and that case
	 * already has an owner in {@code composeTailCalls}, which composes both effects instead.
	 */
	@Test
	public void doesNotFollowATailJumpAfterRealWork() throws Exception {
		builder.setBytes("0x9000", "a9 01", true); // LDA #$01   <- the body that would be skipped
		builder.setBytes("0x9002", "4c 00 91", true); // JMP $9100
		builder.setBytes("0x9100", "60", true); // RTS
		builder.createEmptyFunction("tailCaller", "0x9000", 5, null);

		assertEquals(List.of("9000"), entries());
	}

	/**
	 * The body-size guard doing the work the instruction check cannot: the entry IS a jump, but
	 * the function owns more than that jump, so it is not a pure relay.
	 */
	@Test
	public void doesNotFollowAJumpThatOpensALongerBody() throws Exception {
		builder.setBytes("0x9000", "4c 00 91", true); // JMP $9100
		builder.setBytes("0x9003", "60", true); // RTS -- also this function's
		builder.setBytes("0x9100", "60", true); // RTS
		builder.createEmptyFunction("notARelay", "0x9000", 4, null);

		assertEquals(List.of("9000"), entries());
	}

	/**
	 * A computed jump's target is read from memory at run time, so it is not a static
	 * property of the instruction and cannot make the instruction a relay.
	 * <p>
	 * This is not a hypothetical. The 6502's {@code BRK} is specified as
	 * {@code goto [*:2 0xFFFE]}, which Ghidra resolves through the IRQ vector -- so every
	 * filler {@code $00} byte it disassembles looks like a one-instruction jump to the IRQ
	 * handler. Following those on Mega Man 2 reached RESET from unrelated call sites and
	 * poisoned bank state nothing had written, costing 285 resolved overlay instructions.
	 */
	@Test
	public void doesNotFollowAComputedJump() throws Exception {
		builder.setBytes("0xfffe", "00 91", false); // IRQ vector -> $9100
		builder.setBytes("0x9000", "00", true); // BRK  -- i.e. a filler byte
		builder.setBytes("0x9100", "60", true); // RTS

		Instruction brk = program.getListing().getInstructionAt(builder.addr("0x9000"));
		assertNotNull("nothing disassembled at 0x9000", brk);
		assertTrue("fixture must actually produce a jump here, or the test proves nothing: " +
			brk.getFlowType(), brk.getFlowType().isJump());

		assertEquals(List.of("9000"), entries());
	}

	/** A conditional branch leaves two successors; "where the call lands" has no single answer. */
	@Test
	public void doesNotFollowAConditionalBranch() throws Exception {
		builder.setBytes("0x9000", "d0 02", true); // BNE $9004
		builder.setBytes("0x9004", "60", true); // RTS

		assertEquals(List.of("9000"), entries());
	}

	// ------------------------------------------------------------------
	// Termination
	// ------------------------------------------------------------------

	/** Two relays pointing at each other. The visited set, not the cap, is what stops this. */
	@Test
	public void terminatesOnARelayCycle() throws Exception {
		builder.setBytes("0x9000", "4c 03 90", true); // JMP $9003
		builder.setBytes("0x9003", "4c 00 90", true); // JMP $9000

		assertEquals(List.of("9000", "9003"), entries());
	}

	/**
	 * A relay chain longer than {@code MAX_RELAY_HOPS}. The cap is slack over the one link real
	 * jump tables use, so stopping here forfeits nothing real -- and a forfeited hop only costs
	 * an annotation, never a wrong bank.
	 */
	@Test
	public void stopsAtTheHopCap() throws Exception {
		builder.setBytes("0x9000", "4c 10 90", true); // JMP $9010
		builder.setBytes("0x9010", "4c 20 90", true); // JMP $9020
		builder.setBytes("0x9020", "4c 30 90", true); // JMP $9030
		builder.setBytes("0x9030", "4c 40 90", true); // JMP $9040 -- one hop too far
		builder.setBytes("0x9040", "60", true); // RTS

		assertEquals(List.of("9000", "9010", "9020", "9030"), entries());
	}

	/**
	 * A thunk whose target is itself a relay. Both forms compose, and the walk still ends --
	 * the two hop kinds share one budget rather than each getting their own.
	 */
	@Test
	public void composesAThunkHopWithARelayHop() throws Exception {
		builder.setBytes("0x9000", "4c 00 91", true); // JMP $9100 -- typed as a thunk
		builder.setBytes("0x9100", "4c 05 92", true); // JMP $9205 -- an ordinary relay
		builder.setBytes("0x9200", "a9 01", true); // LDA #$01  <- helper prologue
		builder.setBytes("0x9205", "60", true); // RTS
		builder.createEmptyFunction("helper", "0x9200", 8, null);
		Function relay = builder.createEmptyFunction("relay", "0x9100", 3, null);
		Function thunk = builder.createEmptyFunction("thunk", "0x9000", 3, null);
		makeThunk(thunk, relay);

		assertEquals(List.of("9000", "9100", "9205"), entries());
	}
}
