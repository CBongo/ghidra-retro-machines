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

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;

/**
 * Pins {@link BoardBankAnalyzer#isPassThroughInto} (grm-2dr increment 1): whether a wrapper
 * function does nothing but fall straight through into a target address, which is what lets
 * {@code findPassThroughWrappers} re-key a helper's model onto the wrapper's entry.
 * <p>
 * Deliberately shaped like {@link HelperPrologueProgramTest}, since the method under test is
 * itself deliberately shaped like {@link BoardBankAnalyzer#argumentSurvivesPrologue}: one linear
 * cursor walk from an entry to a boundary, admitting only plain fallthrough. These tests stay at
 * the predicate level -- {@code (program, wrapper, target, switchResults)} alone, no analyzer
 * state, no board descriptor -- which is what lets them run in the fast JUnit tier.
 * <p>
 * {@code switchResults} is passed as {@code Map.of()} throughout: {@code SwitchResult} is a
 * private record of {@code BoardBankAnalyzer}, so a test in this package cannot construct one to
 * populate the map. None of the admit/reject shapes below need a populated map to exercise --
 * the mechanism-write exclusion is a straight {@code containsKey} check on whatever map is
 * threaded in, so an always-empty map is sufficient to pin every other branch; only the
 * "wrapper itself writes a mechanism" branch goes untested here; it is not part of this
 * increment's required case list.
 */
public class HelperWrapperProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		// Not load-bearing for this predicate -- isPassThroughInto never reads write
		// references -- but kept to match this tier's fixture idiom (see
		// AbstractBundledLanguageTest / HelperPrologueProgramTest).
		builder.createMemory("RAM", "0x0000", 0x800);
		program = builder.getProgram();
	}

	/** The predicate over a wrapper entered at {@code wrapperEntry}, reads as addresses. */
	private boolean passesThroughInto(String wrapperEntry, String target) {
		Function wrapper =
			program.getFunctionManager().getFunctionAt(builder.addr(wrapperEntry));
		assertNotNull("no function at wrapper entry " + wrapperEntry, wrapper);
		return BoardBankAnalyzer.isPassThroughInto(program, wrapper, builder.addr(target),
			Map.of());
	}

	// ------------------------------------------------------------------
	// Admitted
	// ------------------------------------------------------------------

	/** The minimal forwarding wrapper: one instruction, fallthrough lands exactly on target. */
	@Test
	public void aTwoByteForwardingWrapperFallsThroughIntoTheTarget() throws Exception {
		builder.setBytes("0x9000", "85 20", true); // STA $20  -- forwards, then falls into the helper
		builder.createEmptyFunction("wrapper", "0x9000", 2, null);
		builder.setBytes("0x9002", "8d 00 e0", true); // STA $E000  <- target: the helper's own body

		assertTrue(passesThroughInto("0x9000", "0x9002"));
	}

	/** More than one instruction is fine, as long as every step is plain fall-through. */
	@Test
	public void aMultiInstructionWrapperOfPlainFallThroughsSurvives() throws Exception {
		builder.setBytes("0x9010", "a9 00", true); // LDA #$00
		builder.setBytes("0x9012", "aa", true); // TAX
		builder.createEmptyFunction("wrapper", "0x9010", 3, null);
		builder.setBytes("0x9013", "60", true); // RTS  <- target

		assertTrue(passesThroughInto("0x9010", "0x9013"));
	}

	// ------------------------------------------------------------------
	// Rejected -- each guards a specific real-ROM hazard
	// ------------------------------------------------------------------

	/**
	 * A {@code JSR} in the body is the boundary of this increment: {@code getFlows().length}
	 * is nonzero for a call, so it is excluded exactly like a branch or jump would be. This is
	 * what keeps blmaster's {@code FUN_e61b} -- which reaches its helper by an internal
	 * {@code JSR} rather than a fallthrough -- out of scope, with no special case needed.
	 */
	@Test
	public void aCallInTheBodyIsRejected() throws Exception {
		builder.setBytes("0x9020", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9500", "60", true); // RTS  -- so the JSR disassembles as a real call
		builder.createEmptyFunction("wrapper", "0x9020", 3, null);
		builder.setBytes("0x9023", "8d 00 e0", true); // STA $E000  <- would-be target

		assertFalse(passesThroughInto("0x9020", "0x9023"));
	}

	/**
	 * A conditional branch leaves two successors, so "falls straight through" has no single
	 * answer -- admitting it would let a wrapper's model get re-keyed onto a helper that the
	 * wrapper only sometimes reaches.
	 */
	@Test
	public void aConditionalBranchInTheBodyIsRejected() throws Exception {
		builder.setBytes("0x9030", "d0 02", true); // BNE $9034
		builder.createEmptyFunction("wrapper", "0x9030", 2, null);
		builder.setBytes("0x9032", "8d 00 e0", true); // STA $E000  <- would-be target

		assertFalse(passesThroughInto("0x9030", "0x9032"));
	}

	/**
	 * {@code RTS} has zero flows, which is exactly why the terminal check cannot be folded
	 * into the flows check: a flows-only test would wrongly admit a wrapper that returns
	 * instead of falling into anything.
	 */
	@Test
	public void aBodyEndingInRtsIsRejected() throws Exception {
		builder.setBytes("0x9040", "60", true); // RTS
		builder.createEmptyFunction("wrapper", "0x9040", 1, null);
		builder.setBytes("0x9041", "8d 00 e0", true); // STA $E000  <- would-be target

		assertFalse(passesThroughInto("0x9040", "0x9041"));
	}

	/**
	 * A gap in the disassembly inside the body means an instruction's register/control effects
	 * there are unknown -- not the same as harmless -- so the walk declines rather than
	 * stepping over the hole.
	 */
	@Test
	public void aGapInTheDisassemblyIsRejected() throws Exception {
		builder.setBytes("0x9050", "ea", true); // NOP
		// 0x9051 deliberately left undefined -- the gap
		builder.createEmptyFunction("wrapper", "0x9050", 2, null);
		builder.setBytes("0x9052", "8d 00 e0", true); // STA $E000  <- would-be target

		assertFalse(passesThroughInto("0x9050", "0x9052"));
	}

	/**
	 * The walk must land EXACTLY on the target. Here the wrapper's true fallthrough is one
	 * byte short of the claimed target, so overshoot -- not any of the other guards -- is what
	 * must reject it.
	 */
	@Test
	public void notLandingExactlyOnTheTargetIsRejected() throws Exception {
		builder.setBytes("0x9060", "ea", true); // NOP  -- true fallthrough is 0x9061
		builder.createEmptyFunction("wrapper", "0x9060", 1, null);
		builder.setBytes("0x9061", "8d 00 e0", true); // STA $E000  -- the true fallthrough target

		assertFalse(passesThroughInto("0x9060", "0x9062")); // one byte PAST the true fallthrough
	}

	/**
	 * A fragmented body -- more than one address range -- makes "walk linearly to the end"
	 * meaningless, so it is rejected before a single instruction is even inspected.
	 */
	@Test
	public void aFragmentedFunctionBodyIsRejected() throws Exception {
		builder.setBytes("0x9070", "ea", true); // NOP  -- first range
		builder.setBytes("0x9080", "ea", true); // NOP  -- disjoint second range

		AddressSet body = new AddressSet();
		body.add(builder.addr("0x9070"));
		body.add(builder.addr("0x9080"));
		Function wrapper;
		int tx = program.startTransaction("create fragmented function");
		try {
			wrapper = program.getFunctionManager()
					.createFunction("wrapper", builder.addr("0x9070"), body,
						SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals("fixture must actually be fragmented, or the test proves nothing", 2,
			wrapper.getBody().getNumAddressRanges());

		assertFalse(BoardBankAnalyzer.isPassThroughInto(program, wrapper, builder.addr("0x9071"),
			Map.of()));
	}

	/**
	 * A fallthrough OVERRIDE that redirects away from the instruction's natural next address.
	 * Ghidra allows this even for an instruction with zero flows that is not terminal, which
	 * would otherwise falsify the linear-by-address walk this method (and
	 * {@code argumentSurvivesPrologue}) both rest on.
	 * <p>
	 * The target here is the wrapper's TRUE natural fallthrough address -- not some arbitrary
	 * unreached address -- specifically so that only the override check can be responsible for
	 * the rejection; if the override did not take effect, or if this test used a target the
	 * walk could never reach for some other reason (a gap, an overshoot), a rejection would
	 * prove nothing about the override branch in particular. The
	 * {@code assertEquals} below confirms the override actually took effect in the built
	 * program before the real assertion runs.
	 */
	@Test
	public void aFallThroughOverrideToANonContiguousAddressIsRejected() throws Exception {
		builder.setBytes("0x9090", "ea", true); // NOP  -- natural fallthrough would be 0x9091
		builder.setBytes("0x9091", "8d 00 e0", true); // STA $E000  -- what the target WOULD be
		builder.createEmptyFunction("wrapper", "0x9090", 1, null);

		Instruction instr = program.getListing().getInstructionAt(builder.addr("0x9090"));
		assertNotNull("nothing disassembled at 0x9090", instr);
		Address redirect = builder.addr("0x9200");
		int tx = program.startTransaction("override fallthrough");
		try {
			instr.setFallThrough(redirect);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals("fallthrough override must actually take effect, or this test is vacuous",
			redirect, instr.getFallThrough());

		assertFalse(passesThroughInto("0x9090", "0x9091"));
	}

	// ------------------------------------------------------------------
	// grm-k90: which join a mini-inline scan may cross
	// ------------------------------------------------------------------

	/**
	 * {@link BoardBankAnalyzer#crossableWrapperJoin} over addresses, which is all it reads.
	 * Same predicate-level discipline as {@link #passesThroughInto} above and for the same
	 * reason: {@code HelperModel} is private to {@code BoardBankAnalyzer}, so the method takes
	 * {@code firstSite} and {@code scanStop} loose rather than a model.
	 */
	private Address crossableJoin(String firstSite, String scanStop) {
		return BoardBankAnalyzer.crossableWrapperJoin(program, builder.addr(firstSite),
			builder.addr(scanStop));
	}

	/**
	 * <b>The case grm-k90 exists for.</b> A pass-through wrapper at {@code $9100} falling into a
	 * helper at {@code $9103}: the stop is the wrapper's entry, the helper's own entry lies
	 * strictly between it and {@code firstSite}, and that entry is nominated as crossable.
	 * <p>
	 * Contra's real geometry, one page down: {@code c139 < c13f <= c142}.
	 */
	@Test
	public void aPassThroughWrappersHelperEntryIsNominated() throws Exception {
		builder.setBytes("0x9100", "ad 00 80", true); // LDA $8000  <- wrapper entry
		builder.createEmptyFunction("wrapper", "0x9100", 3, null);
		builder.setBytes("0x9103", "b9 d0 ff", true); // LDA $FFD0,Y  <- helper entry
		builder.setBytes("0x9106", "99 d0 ff", true); // STA $FFD0,Y  <- firstSite
		builder.createEmptyFunction("helper", "0x9103", 6, null);

		assertEquals(builder.addr("0x9103"), crossableJoin("0x9106", "0x9100"));
	}

	/**
	 * An ORDINARY helper nominates nothing: the body containing {@code firstSite} is entered at
	 * the stop itself, so the nominee is not strictly after it. This is the no-change case, and
	 * it is the reason the fix could land without re-blessing goldens -- every helper that is not
	 * behind a wrapper takes exactly the path it always did.
	 */
	@Test
	public void anOrdinaryHelperNominatesNothing() throws Exception {
		builder.setBytes("0x9200", "b9 d0 ff", true); // LDA $FFD0,Y  <- entry AND stop
		builder.setBytes("0x9203", "99 d0 ff", true); // STA $FFD0,Y  <- firstSite
		builder.createEmptyFunction("helper", "0x9200", 6, null);

		assertNull(crossableJoin("0x9203", "0x9200"));
	}

	/**
	 * <b>A MID-BODY ENTRY nominates nothing, and this is the non-regression that matters most.</b>
	 * Bionic Commando's {@code $D6E2 JMP $DCAA} lands past the {@code $DCA8 LDA $65} that would
	 * have clobbered the argument, so the containing function's entry is BEFORE the stop. The
	 * window's strictly-after test rejects it.
	 * <p>
	 * Getting this wrong would be worse than the bug being fixed: licensing a join behind the stop
	 * would walk the scan straight back into the prologue the call deliberately skipped, and
	 * report the value that prologue produces as the caller's.
	 */
	@Test
	public void aMidBodyEntryNominatesNothing() throws Exception {
		builder.setBytes("0x9300", "a5 65", true); // LDA $65   <- function entry, SKIPPED
		builder.setBytes("0x9302", "8d 00 e0", true); // STA $E000 <- mid-body entry AND firstSite
		builder.createEmptyFunction("helper", "0x9300", 5, null);

		assertNull("the containing function's entry is before the stop -- never crossable",
			crossableJoin("0x9302", "0x9302"));
	}

	/**
	 * No function containing {@code firstSite} means no nominee. Not a shape any admitted model
	 * has -- {@code findHelpers} works from function bodies -- but the derivation reads the
	 * function manager, so the null it can return is answered explicitly rather than thrown.
	 */
	@Test
	public void firstSiteOutsideAnyFunctionNominatesNothing() throws Exception {
		builder.setBytes("0x9400", "99 d0 ff", true); // STA $FFD0,Y, in no function at all

		assertNull(crossableJoin("0x9400", "0x9400"));
	}
}
