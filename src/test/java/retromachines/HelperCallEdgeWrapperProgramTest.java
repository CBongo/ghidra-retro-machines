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

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Function;

/**
 * Pins the two gates {@code findCallEdgeWrappers} admits a call-edge wrapper on (bead grm-2dr
 * increment 2): the VALUE gate,
 * {@link HelperArgumentRecovery#argumentSurvivesPrologue(ghidra.program.model.listing.Program, List, char)}
 * over a two-segment prologue, and the STRUCTURAL gate,
 * {@link HelperDiscovery#isPassThroughInto} applied to the wrapper's PREFIX with the relay call
 * site as its target.
 * <p>
 * Both are pinned here because <b>neither subsumes the other</b>, and that is the single least
 * obvious fact in the increment -- see
 * {@link #aBranchBeforeTheRelayIsRejectedStructurallyThoughTheValueGateAcceptsIt}, which
 * constructs a prefix the value gate accepts and the structural gate must reject.
 * <p>
 * Deliberately shaped like {@link HelperWrapperProgramTest}: predicate level only, no analyzer
 * state and no board descriptor, which is what keeps these in the fast JUnit tier.
 * {@code HelperModel} is a package-private record of {@link HelperDiscovery} and
 * {@code SwitchResult} of {@code BankDataflowEngine},
 * so this tier cannot build a helper map; the map-shaped rules (exactly-one-helper-call, the
 * whole-body mechanism scan, the mid-body decline) are pinned by the {@code nesrelaytest}
 * headless fixture instead.
 * <p>
 * {@code switchResults} is {@code Map.of()} throughout, for the same reason
 * {@link HelperWrapperProgramTest} documents.
 */
public class HelperCallEdgeWrapperProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		builder.createMemory("RAM", "0x0000", 0x800);
		program = builder.getProgram();
	}

	/** One prologue segment, reads as addresses. */
	private HelperArgumentRecovery.PrologueSegment seg(String from, String to) {
		return new HelperArgumentRecovery.PrologueSegment(builder.addr(from), builder.addr(to));
	}

	/** The multi-segment value gate over A. */
	private boolean survives(HelperArgumentRecovery.PrologueSegment... segments) {
		return HelperArgumentRecovery.argumentSurvivesPrologue(program, List.of(segments), 'A');
	}

	/** The single-span form, for delegation and anti-vacuity checks. */
	private boolean survivesSpan(String from, String to) {
		return HelperArgumentRecovery.argumentSurvivesPrologue(program, builder.addr(from),
			builder.addr(to), 'A');
	}

	/** The structural gate over a wrapper prefix ending at {@code target}. */
	private boolean passesThroughInto(String wrapperEntry, String target) {
		Function wrapper =
			program.getFunctionManager().getFunctionAt(builder.addr(wrapperEntry));
		assertNotNull("no function at wrapper entry " + wrapperEntry, wrapper);
		return HelperDiscovery.isPassThroughInto(program, wrapper, builder.addr(target),
			Map.of());
	}

	// ------------------------------------------------------------------
	// The value gate: two segments, AND-ed
	// ------------------------------------------------------------------

	/**
	 * blmaster's {@code FUN_e61b} shape: the argument is stashed to a zero-page shadow, A is
	 * then clobbered, and the shadow is reloaded before the relay call -- so the caller's byte
	 * IS what the helper reads. Segment 2 is empty because the wrapped helper's first switch
	 * site is its own entry instruction, exactly as {@code FUN_e63c}'s {@code STA $FFFF} is.
	 */
	@Test
	public void theBlmasterSaveRestoreShapeSurvivesAcrossTheRelayBoundary() throws Exception {
		builder.setBytes("0x9000", "85 db", true); // STA $DB   -- stash the caller's bank
		builder.setBytes("0x9002", "a9 00", true); // LDA #$00  -- and clobber A
		builder.setBytes("0x9004", "a5 db", true); // LDA $DB   -- restore it
		builder.setBytes("0x9006", "20 00 95", true); // JSR $9500 <- the relay, NOT walked

		// Anti-vacuity: the restore is what carries it, not an absence of clobbers.
		assertFalse("fixture is vacuous: A is not actually clobbered before the reload",
			survivesSpan("0x9000", "0x9004"));
		assertTrue(survives(seg("0x9000", "0x9006"), seg("0x9100", "0x9100")));
	}

	/**
	 * An empty segment is trivially true, and that is load-bearing rather than incidental: it
	 * is what makes a helper whose {@code entry} IS its {@code firstSite} costless to wrap.
	 */
	@Test
	public void anEmptySegmentIsTriviallyTrue() throws Exception {
		assertTrue(survives(seg("0x9100", "0x9100")));
	}

	/** An empty list proves nothing, so it must not report survival. */
	@Test
	public void anEmptySegmentListIsFalse() throws Exception {
		assertFalse(HelperArgumentRecovery.argumentSurvivesPrologue(program, List.of(), 'A'));
	}

	/** A clobber in the wrapper's own prefix is a decline, exactly as for a plain helper. */
	@Test
	public void aClobberInSegmentOneIsRejected() throws Exception {
		builder.setBytes("0x9010", "a9 00", true); // LDA #$00 -- eats the argument
		builder.setBytes("0x9012", "20 00 95", true); // JSR $9500

		assertFalse(survives(seg("0x9010", "0x9012"), seg("0x9100", "0x9100")));
	}

	/**
	 * A clobber in the WRAPPED HELPER's own prologue declines too -- proving the result is an
	 * AND over both segments, not just the first. This is the Bionic Commando {@code LDA $65}
	 * shape sitting behind a wrapper.
	 */
	@Test
	public void aClobberInSegmentTwoIsRejected() throws Exception {
		builder.setBytes("0x9020", "aa", true); // TAX -- leaves A alone
		builder.setBytes("0x9021", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9120", "a5 65", true); // LDA $65 -- the helper eats its own argument
		builder.setBytes("0x9122", "8d 00 e0", true); // STA $E000 <- firstSite

		// Anti-vacuity: segment 1 really does pass on its own, so the AND is what rejects.
		assertTrue(survives(seg("0x9020", "0x9021")));
		assertFalse(survives(seg("0x9020", "0x9021"), seg("0x9120", "0x9122")));
	}

	/**
	 * The shadow stack must NOT pair across the boundary: a {@code PHA} in the wrapper and a
	 * {@code PLA} inside the helper are not a save/restore of anything this walk witnessed,
	 * because the relay call itself pushed a return address in between. Removing the
	 * per-segment reset would silently turn this true.
	 */
	@Test
	public void theStackModelDoesNotPairAcrossSegments() throws Exception {
		builder.setBytes("0x9030", "48", true); // PHA
		builder.setBytes("0x9031", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9130", "a9 00", true); // LDA #$00 -- clobber inside the helper
		builder.setBytes("0x9132", "68", true); // PLA -- would "restore" if the deque carried
		builder.setBytes("0x9133", "8d 00 e0", true); // STA $E000 <- firstSite

		assertTrue(survives(seg("0x9030", "0x9031")));
		assertFalse(survives(seg("0x9030", "0x9031"), seg("0x9130", "0x9133")));
	}

	/**
	 * The memory half of the same property: a cell the argument was stored to in the wrapper
	 * must not make a load inside the helper read as a restore.
	 */
	@Test
	public void theMemoryModelDoesNotCarryCellsAcrossSegments() throws Exception {
		builder.setBytes("0x9040", "85 20", true); // STA $20 -- records $20 in segment 1
		builder.setBytes("0x9042", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9140", "a9 00", true); // LDA #$00 -- clobber inside the helper
		builder.setBytes("0x9142", "a5 20", true); // LDA $20 -- would "restore" if cells carried
		builder.setBytes("0x9144", "8d 00 e0", true); // STA $E000 <- firstSite

		assertTrue(survives(seg("0x9040", "0x9042")));
		assertFalse(survives(seg("0x9040", "0x9042"), seg("0x9140", "0x9144")));
	}

	/** A one-element list must answer exactly what the single-span form answers. */
	@Test
	public void oneSegmentDelegatesToTheSingleSpanForm() throws Exception {
		builder.setBytes("0x9050", "aa", true); // TAX
		builder.setBytes("0x9051", "8d 00 e0", true); // STA $E000

		assertEquals(survivesSpan("0x9050", "0x9051"), survives(seg("0x9050", "0x9051")));
		assertTrue(survives(seg("0x9050", "0x9051")));
	}

	// ------------------------------------------------------------------
	// The structural gate: isPassThroughInto over the prefix
	// ------------------------------------------------------------------

	/** The prefix of the blmaster shape is a pass-through into its own relay call site. */
	@Test
	public void aPrefixEndingAtTheRelayCallIsAPassThrough() throws Exception {
		builder.setBytes("0x9060", "85 20", true); // STA $20
		builder.setBytes("0x9062", "a5 20", true); // LDA $20
		builder.setBytes("0x9064", "20 00 95", true); // JSR $9500 <- target: the relay itself
		builder.setBytes("0x9067", "60", true); // RTS
		builder.setBytes("0x9500", "60", true); // RTS -- so the JSR disassembles as a real call
		builder.createEmptyFunction("wrapper", "0x9060", 8, null);

		assertTrue(passesThroughInto("0x9060", "0x9064"));
	}

	/**
	 * <b>The case that proves the two gates are independent, and the reason the structural gate
	 * exists at all.</b> A branch does NOT make {@code argumentSurvivesPrologue} decline -- a
	 * nonzero {@code getFlows().length} only clears its {@code straightLine}/{@code
	 * argumentCells} state and the walk CONTINUES -- so a prefix that branches around the relay
	 * but never touches A passes the value gate. Admitting it would key a helper model onto a
	 * wrapper whose relay call is only conditionally reached, making every claim about the
	 * wrapper's effect rest on a call that might not run.
	 * <p>
	 * The first assertion is the anti-vacuity check AND the statement of the hazard: it must
	 * stay true, because a future change that made the value gate reject branches would render
	 * this test's point silently moot rather than failing it.
	 */
	@Test
	public void aBranchBeforeTheRelayIsRejectedStructurallyThoughTheValueGateAcceptsIt()
			throws Exception {
		builder.setBytes("0x9070", "d0 02", true); // BNE $9074 -- branches around the NOPs
		builder.setBytes("0x9072", "ea ea", true); // NOP NOP  -- nothing touches A
		builder.setBytes("0x9074", "20 00 95", true); // JSR $9500 <- the relay
		builder.setBytes("0x9077", "60", true); // RTS
		builder.setBytes("0x9500", "60", true); // RTS
		builder.createEmptyFunction("wrapper", "0x9070", 8, null);

		assertTrue("the value gate is expected to ACCEPT this prefix -- that is the hazard",
			survivesSpan("0x9070", "0x9074"));
		assertFalse(passesThroughInto("0x9070", "0x9074"));
	}

	/** A gap in the prefix means the walk cannot vouch for what runs before the relay. */
	@Test
	public void aDisassemblyGapBeforeTheRelayIsRejected() throws Exception {
		builder.setBytes("0x9080", "85 20", true); // STA $20
		builder.setBytes("0x9082", "ff ff", false); // never disassembled
		builder.setBytes("0x9084", "20 00 95", true); // JSR $9500 <- target
		builder.setBytes("0x9500", "60", true); // RTS
		builder.createEmptyFunction("wrapper", "0x9080", 7, null);

		assertFalse(passesThroughInto("0x9080", "0x9084"));
	}

	/**
	 * An {@code RTS} before the relay means control never reaches it. Not redundant with the
	 * flows check: a terminator has zero flows too.
	 */
	@Test
	public void aReturnBeforeTheRelayIsRejected() throws Exception {
		builder.setBytes("0x9090", "60", true); // RTS
		builder.setBytes("0x9091", "20 00 95", true); // JSR $9500 <- target
		builder.setBytes("0x9500", "60", true); // RTS
		builder.createEmptyFunction("wrapper", "0x9090", 4, null);

		assertFalse(passesThroughInto("0x9090", "0x9091"));
	}
}
