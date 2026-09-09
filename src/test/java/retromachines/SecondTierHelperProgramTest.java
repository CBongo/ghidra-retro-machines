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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static retromachines.HelperDiscovery.calledHelper;
import static retromachines.HelperDiscovery.findSecondTierHelpers;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

import retromachines.HelperDiscovery.HelperModel;
import retromachines.HelperDiscovery.SecondTierResult;

/**
 * Pins {@link HelperDiscovery#findSecondTierHelpers} (bead grm-ylm6): the megaman2
 * {@code FUN_c628}/{@code FUN_c70c} shape -- a function that forwards a register argument taken
 * from ITS OWN caller into a real helper, then makes a FURTHER call to that same helper (a
 * restore) before returning -- which is exactly the shape {@link HelperDiscovery#findCallEdgeWrappers}
 * declines on ("a second known-helper call").
 * <p>
 * <b>The load-bearing property under test is the CORRECTNESS FIX, not merely admission.</b> An
 * earlier version of this pass modeled the wrapper like an ordinary call-edge wrapper --
 * {@code constState} inherited (null) and {@code argReg} set to the traced register -- which made
 * {@code BankDataflowEngine.runDataflow} deposit the RELAYED ARGUMENT as the state after the
 * wrapper's OWN call sites return: wrong, since the wrapper's further call restores a DIFFERENT,
 * fixed bank before returning. {@link #outerCallSitesGetTheRestoredConstantNeverTheRelayedArgument}
 * is the regression test for exactly that defect, and is the one this file's own review comments
 * call the important deliverable -- every other test here pins a narrower admission/decline
 * boundary, but that one pins the actual VALUE a caller of the wrapper would see.
 * <p>
 * Deliberately shaped like {@link TailCallCompositionProgramTest} and
 * {@link HelperCallEdgeWrapperProgramTest}: hand-built {@link HelperModel}s registered directly in
 * a map, driving the discovery pass with no board descriptor and no analyzer state -- the fast
 * JUnit tier. {@code switchResults} is {@code Map.of()} throughout unless a test needs it to
 * reject a candidate, for the same reason {@link HelperWrapperProgramTest} documents.
 */
public class SecondTierHelperProgramTest extends AbstractBundledLanguageTest {

	private static final int FULL_MASK = 0x0F;

	private ProgramBuilder builder;
	private ProgramDB program;
	private Map<Function, HelperModel> helpers;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		helpers = new LinkedHashMap<>();
	}

	private static String hex(long addr) {
		return String.format("0x%04x", addr);
	}

	private Address addr(long a) {
		return builder.addr(hex(a));
	}

	/**
	 * The wrapped helper: a one-instruction mechanism write ({@code STA $E000}) immediately
	 * followed by {@code RTS}, registered as a caller-dependent (argReg {@code 'A'}) helper whose
	 * {@code firstSite} is its own entry -- Mega Man 2's {@code FUN_c000} shape (recon notes:
	 * "the first instruction of FUN_c000 is STA $29", though this fixture uses an absolute
	 * mechanism address rather than modeling MMC1's actual serial shift, since only the ARGUMENT
	 * plumbing this bead changes is under test). {@code strategy} is left {@code null}, matching
	 * {@link TailCallCompositionProgramTest#argHelper}'s precedent -- {@code recoverCallArgument}
	 * (called both by {@code findSecondTierHelpers} to resolve a restore and, in production, by
	 * {@code runDataflow} for an ordinary call) falls back to the register scan alone when a
	 * helper carries no strategy, which is all a plain {@code LDA #imm} restore needs.
	 */
	private Function wrappedHelper(long at) throws Exception {
		builder.setBytes(hex(at), "8d 00 e0 60", true); // STA $E000 ; RTS
		Function f = builder.createEmptyFunction("wrapped", hex(at), 4, null);
		helpers.put(f, new HelperModel(f, f.getEntryPoint(), null, 'A', FULL_MASK, 0,
			null, f.getEntryPoint(), f.getEntryPoint(), null));
		return f;
	}

	private SecondTierResult discover() {
		return findSecondTierHelpers(program, helpers, Map.of());
	}

	// ------------------------------------------------------------------
	// The correctness fix: the wrapper's OWN model must carry the RESTORED
	// constant, never the relayed argument
	// ------------------------------------------------------------------

	/**
	 * <b>The deliverable.</b> A wrapper that relays a caller's argument into a real helper and
	 * then restores a DIFFERENT, fixed constant before returning. Two distinct outer callers
	 * relay two DIFFERENT values (0x0B and 0x03, megaman2's own real-ROM constants at
	 * {@code 8451}/{@code 96bd}) to prove the wrapper's exposed model does not vary with, and
	 * never surfaces, either one -- only the restored constant (0x0D) may ever reach a caller as
	 * post-call state.
	 * <p>
	 * This is checked at the level that actually decides {@code BankDataflowEngine.runDataflow}'s
	 * fold: that method's call-handling is exactly
	 * {@code helper.constState() != null ? new CallEffect(helper.constState(), helper.effectMask())
	 * : recoverCallArgument(...)} -- with {@code constState} set (as asserted below), the SECOND,
	 * caller-dependent branch is provably unreachable for this model, which is what makes the
	 * relayed argument structurally impossible to ship as post-call state, not merely absent from
	 * this particular fixture.
	 */
	@Test
	public void outerCallSitesGetTheRestoredConstantNeverTheRelayedArgument() throws Exception {
		wrappedHelper(0x9500);
		// The wrapper: relay is its own entry (forwards WHATEVER A holds on entry), some
		// unrelated body work, then a restore to a DIFFERENT fixed constant.
		builder.setBytes("0x9200", "20 00 95", true); // JSR $9500 <- relay, IS the entry
		builder.setBytes("0x9203", "ea", true); // NOP        <- stand-in for body work
		builder.setBytes("0x9204", "a9 0d", true); // LDA #$0D   -- restore: a DIFFERENT constant
		builder.setBytes("0x9206", "20 00 95", true); // JSR $9500  <- restore
		builder.setBytes("0x9209", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapper", "0x9200", 10, null);

		// Two callers relaying two DIFFERENT arguments -- neither may ever surface as post-call
		// state at the OTHER caller, or at either one.
		builder.setBytes("0x9300", "a9 0b", true); // LDA #$0B
		builder.setBytes("0x9302", "20 00 92", true); // JSR wrapper
		builder.setBytes("0x9305", "60", true); // RTS
		builder.createEmptyFunction("callerA", "0x9300", 6, null);

		builder.setBytes("0x9310", "a9 03", true); // LDA #$03
		builder.setBytes("0x9312", "20 00 92", true); // JSR wrapper
		builder.setBytes("0x9315", "60", true); // RTS
		builder.createEmptyFunction("callerB", "0x9310", 6, null);

		SecondTierResult result = discover();
		HelperModel model = result.helpers().get(wrapper);
		assertNotNull("wrapper was not admitted", model);

		BankState restored = BankState.fullyKnown(FULL_MASK, 0x0D);
		assertEquals("the wrapper's own model must carry the RESTORED constant as constState -- "
			+ "not null (which would route outer calls through recoverCallArgument and deposit "
			+ "the relayed argument instead)", restored, model.constState());
		assertNull("argReg must be null: a constState-bearing model is never consulted for one, "
			+ "and a non-null value here would be a latent trap for a future edit", model.argReg());

		Instruction callA = program.getListing().getInstructionAt(addr(0x9302));
		Instruction callB = program.getListing().getInstructionAt(addr(0x9312));
		HelperModel resolvedFromA = calledHelper(program, callA, result.helpers());
		HelperModel resolvedFromB = calledHelper(program, callB, result.helpers());

		assertSame("callerA's JSR must resolve to the wrapper's own model", model, resolvedFromA);
		assertSame("callerB's JSR must resolve to the SAME model as callerA's -- the wrapper "
			+ "exposes exactly one exit state, not one per caller", model, resolvedFromB);
		assertEquals("callerA relayed 0x0B; the model exposed to it must still be the restored "
			+ "0x0D, never the relayed value", restored, resolvedFromA.constState());
		assertEquals("callerB relayed 0x03; the model exposed to it must still be the restored "
			+ "0x0D, never the relayed value", restored, resolvedFromB.constState());
	}

	/**
	 * When the restore call's own argument does NOT resolve, the whole wrapper must be declined
	 * -- never admitted with a guessed or absent exit state, and the relay's own warning must NOT
	 * be reclassified, because there is nothing honest {@code SECOND_TIER_ARGUMENT} could point
	 * the reader at.
	 */
	@Test
	public void aFurtherCallWhoseArgumentDoesNotResolveDeclinesTheWholeWrapper() throws Exception {
		wrappedHelper(0x9500);
		builder.setBytes("0x9060", "20 00 95", true); // JSR $9500 <- relay, IS the entry
		builder.setBytes("0x9063", "ea", true); // NOP
		builder.setBytes("0x9064", "ad 34 12", true); // LDA $1234 -- opaque, unresolvable load
		builder.setBytes("0x9067", "20 00 95", true); // JSR $9500 <- restore, UNRESOLVABLE
		builder.setBytes("0x906a", "60", true); // RTS
		Function wrapper =
			builder.createEmptyFunction("wrapperUnresolvedRestore", "0x9060", 11, null);

		SecondTierResult result = discover();

		assertNull("a wrapper whose restore cannot be resolved must be declined entirely",
			result.helpers().get(wrapper));
		assertFalse("the relay's own warning must not be reclassified without a resolved exit "
			+ "state to back the claim", result.relayCallSites().contains(addr(0x9060)));
	}

	// ------------------------------------------------------------------
	// Structural admission/decline boundary
	// ------------------------------------------------------------------

	/**
	 * Megaman2's {@code FUN_c628}/{@code FUN_c70c} shape byte-for-byte: the relay call IS the
	 * wrapper's own first instruction (so the caller's A must survive zero bytes to reach it --
	 * the trivial case), a NOP or two stand in for the PPU/RAM work between the two calls, then a
	 * constant restore and RTS.
	 */
	@Test
	public void theZeroLengthRelayShapeComposesTheRestoredConstant() throws Exception {
		Function wrapped = wrappedHelper(0x9500);
		builder.setBytes("0x9000", "20 00 95", true); // JSR $9500 <- relay, IS the entry
		builder.setBytes("0x9003", "ea", true); // NOP        <- stand-in for PPU/RAM work
		builder.setBytes("0x9004", "a9 0d", true); // LDA #$0D
		builder.setBytes("0x9006", "20 00 95", true); // JSR $9500 <- restore
		builder.setBytes("0x9009", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapper", "0x9000", 10, null);

		SecondTierResult result = discover();

		HelperModel model = result.helpers().get(wrapper);
		assertNotNull("wrapper was not admitted as a second-tier helper", model);
		assertEquals(BankState.fullyKnown(FULL_MASK, 0x0D), model.constState());
		assertNull("argReg must be null on a constState-bearing composed model", model.argReg());
		assertNull("relay must be null -- nothing downstream consults it once constState is set",
			model.relay());
		assertNull("strategy must be null -- unused once constState is set", model.strategy());
		assertEquals(FULL_MASK, model.effectMask());
		assertTrue("the relay call site must be reported for warning suppression",
			result.relayCallSites().contains(addr(0x9000)));

		// The wrapped helper's own entry, untouched, is a no-op pass-through: findSecondTierHelpers
		// is purely additive.
		assertSame(helpers.get(wrapped), result.helpers().get(wrapped));
	}

	/**
	 * Anti-vacuity: exactly ONE call to the wrapped helper (no restore) must NOT be admitted here
	 * -- that shape is {@code findCallEdgeWrappers}' job, and this pass exists ONLY for the
	 * further-call case that one declines on.
	 */
	@Test
	public void aSingleCallWithNoFurtherCallIsNotAdmittedHere() throws Exception {
		wrappedHelper(0x9500);
		builder.setBytes("0x9010", "20 00 95", true); // JSR $9500 <- the only call
		builder.setBytes("0x9013", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapperNoRestore", "0x9010", 4, null);

		SecondTierResult result = discover();

		assertNull("a single-call body belongs to findCallEdgeWrappers, not this pass",
			result.helpers().get(wrapper));
		assertTrue(result.relayCallSites().isEmpty());
	}

	/**
	 * A SECOND further call to the same wrapped helper (three calls total) is out of scope and
	 * must decline rather than guess how to fold several restores together.
	 */
	@Test
	public void aSecondFurtherCallToTheSameHelperIsRejected() throws Exception {
		wrappedHelper(0x9500);
		builder.setBytes("0x9070", "20 00 95", true); // JSR $9500 <- relay, IS the entry
		builder.setBytes("0x9073", "a9 05", true); // LDA #$05
		builder.setBytes("0x9075", "20 00 95", true); // JSR $9500 <- further call 1
		builder.setBytes("0x9078", "a9 0d", true); // LDA #$0D
		builder.setBytes("0x907a", "20 00 95", true); // JSR $9500 <- further call 2
		builder.setBytes("0x907d", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapperTwoRestores", "0x9070", 14, null);

		SecondTierResult result = discover();

		assertNull("more than one further call must decline, not fold arbitrarily",
			result.helpers().get(wrapper));
		assertFalse(result.relayCallSites().contains(addr(0x9070)));
	}

	/** A second call to a DIFFERENT known helper stays conservative and declines. */
	@Test
	public void aSecondCallToADifferentHelperIsRejected() throws Exception {
		wrappedHelper(0x9500);
		Function otherWrapped = wrappedHelper(0x9600);
		builder.setBytes("0x9020", "20 00 95", true); // JSR $9500 <- relay
		builder.setBytes("0x9023", "20 00 96", true); // JSR $9600 <- a DIFFERENT known helper
		builder.setBytes("0x9026", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapperDiffHelper", "0x9020", 7, null);

		SecondTierResult result = discover();

		assertNull("a second call to a different helper must decline, not guess",
			result.helpers().get(wrapper));
		assertSame(helpers.get(otherWrapped), result.helpers().get(otherWrapped));
	}

	/**
	 * A function that writes a mechanism of its OWN in its body is a helper, not a wrapper --
	 * {@code switchResults} says so, and that must reject regardless of any calls present.
	 */
	@Test
	public void aBodyThatWritesItsOwnMechanismIsRejected() throws Exception {
		Function wrapped = wrappedHelper(0x9500);
		builder.setBytes("0x9030", "8d 10 e0", true); // STA $E010 <- its OWN mechanism write
		builder.setBytes("0x9033", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9036", "a9 0d", true); // LDA #$0D
		builder.setBytes("0x9038", "20 00 95", true); // JSR $9500 again
		builder.setBytes("0x903b", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapperOwnMechanism", "0x9030", 12, null);

		Map<Address, BankDataflowEngine.SwitchResult> switchResults =
			Map.of(addr(0x9030), new BankDataflowEngine.SwitchResult(BankState.unknown(),
				FULL_MASK, 0, null, BankSwitchStrategy.ValueStop.ANALYZER_LIMIT));
		SecondTierResult result = findSecondTierHelpers(program, helpers, switchResults);

		assertNull(result.helpers().get(wrapper));
		assertSame(helpers.get(wrapped), result.helpers().get(wrapped));
	}

	// ------------------------------------------------------------------
	// The register-transfer generalization (c78d's TXA shape)
	// ------------------------------------------------------------------

	/**
	 * Mega Man 2's {@code FUN_c760}/{@code c78d} shape, WITHOUT the branch that makes the real
	 * ROM's prefix fail the straight-line precondition (see
	 * {@link HelperDiscovery#findSecondTierHelpers}'s javadoc for why the real {@code c78d}
	 * itself is not covered): the caller supplies the bank in X, a straight run of unrelated
	 * X-preserving work happens, then {@code TXA} moves it into A immediately before the relay.
	 * Proves admission survives a register-to-register transfer -- the register is not hardcoded
	 * to the accumulator -- even though the resulting model (constState-only, per the correctness
	 * fix) no longer reports the traced register by name.
	 */
	@Test
	public void aRegisterTransferShapeIsStillAdmitted() throws Exception {
		wrappedHelper(0x9500);
		builder.setBytes("0x9040", "18", true); // CLC        -- unrelated, does not touch X
		builder.setBytes("0x9041", "98", true); // TYA        -- unrelated, does not touch X
		builder.setBytes("0x9042", "8a", true); // TXA        <- the transfer: A := X
		builder.setBytes("0x9043", "20 00 95", true); // JSR $9500  <- relay, reads A
		builder.setBytes("0x9046", "ea", true); // NOP        -- stand-in for body work
		builder.setBytes("0x9047", "a9 0d", true); // LDA #$0D
		builder.setBytes("0x9049", "20 00 95", true); // JSR $9500  <- restore
		builder.setBytes("0x904c", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapperTransfer", "0x9040", 13, null);

		SecondTierResult result = discover();

		HelperModel model = result.helpers().get(wrapper);
		assertNotNull("the transfer shape must be admitted", model);
		assertEquals(BankState.fullyKnown(FULL_MASK, 0x0D), model.constState());
		assertTrue(result.relayCallSites().contains(addr(0x9043)));
	}

	/**
	 * A register genuinely defined LOCALLY (an immediate load, not a transfer) between entry and
	 * the relay is NOT a second-tier argument at all, and must decline.
	 */
	@Test
	public void aLocallyDefinedRegisterIsNotASecondTierArgument() throws Exception {
		wrappedHelper(0x9500);
		builder.setBytes("0x9050", "a9 07", true); // LDA #$07   -- A is LOCAL, not inbound
		builder.setBytes("0x9052", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9055", "a9 0d", true); // LDA #$0D
		builder.setBytes("0x9057", "20 00 95", true); // JSR $9500
		builder.setBytes("0x905a", "60", true); // RTS
		Function wrapper = builder.createEmptyFunction("wrapperLocalConst", "0x9050", 11, null);

		SecondTierResult result = discover();

		assertNull("a locally-defined register must decline, not be misreported as inbound",
			result.helpers().get(wrapper));
	}

	/**
	 * The same decline, one level further: the register reaches the relay only via a transfer
	 * whose SOURCE was itself defined locally (an {@code LDX #imm} before the {@code TXA}), which
	 * must decline exactly as a direct local definition does -- proving the trace does not stop
	 * at the first transfer it finds without checking what feeds it.
	 */
	@Test
	public void aLocallyDefinedTransferSourceIsNotASecondTierArgument() throws Exception {
		wrappedHelper(0x9500);
		builder.setBytes("0x9080", "a2 09", true); // LDX #$09   -- X is LOCAL, not inbound
		builder.setBytes("0x9082", "8a", true); // TXA        -- A := X, but X was never inbound
		builder.setBytes("0x9083", "20 00 95", true); // JSR $9500
		builder.setBytes("0x9086", "a9 0d", true); // LDA #$0D
		builder.setBytes("0x9088", "20 00 95", true); // JSR $9500
		builder.setBytes("0x908b", "60", true); // RTS
		Function wrapper =
			builder.createEmptyFunction("wrapperLocalTransferSource", "0x9080", 12, null);

		SecondTierResult result = discover();

		assertNull("a locally-defined transfer SOURCE must decline too",
			result.helpers().get(wrapper));
	}

	/**
	 * A function already recognized some other way (present in the input map) is left alone --
	 * this pass only ever looks at functions {@code helpers} does not already cover, which is what
	 * keeps it from being able to disturb an already-admitted model (blmaster's call-edge wrapper
	 * shape included, though not reproduced here).
	 */
	@Test
	public void anAlreadyRecognizedFunctionIsNeverRevisited() throws Exception {
		Function already = wrappedHelper(0x9060);
		HelperModel original = helpers.get(already);

		SecondTierResult result = discover();

		assertSame(original, result.helpers().get(already));
		assertFalse(result.relayCallSites().contains(already.getEntryPoint()));
	}

	// ------------------------------------------------------------------
	// CallEffect#asSecondTierRelay
	// ------------------------------------------------------------------

	/**
	 * The small record-level contract {@code BankDataflowEngine.runDataflow} relies on: only
	 * {@code secondTierRelay} changes, and only when applied -- everything else about the effect
	 * (including, notably, {@code argumentResolved}, which stays whatever it already was) is
	 * carried through unchanged.
	 */
	@Test
	public void asSecondTierRelayFlipsOnlyItsOwnField() {
		HelperArgumentRecovery.CallEffect base =
			new HelperArgumentRecovery.CallEffect(BankState.unknown(), FULL_MASK, false, false);

		HelperArgumentRecovery.CallEffect flipped = base.asSecondTierRelay();

		assertFalse(base.secondTierRelay());
		assertTrue(flipped.secondTierRelay());
		assertEquals(base.state(), flipped.state());
		assertEquals(base.ownedMask(), flipped.ownedMask());
		assertEquals(base.argumentResolved(), flipped.argumentResolved());
		assertEquals(base.noInboundArgument(), flipped.noInboundArgument());
	}
}
