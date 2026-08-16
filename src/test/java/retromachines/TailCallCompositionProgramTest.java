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
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import retromachines.BoardBankAnalyzer.HelperModel;

/**
 * Pins every DECLINE branch of {@code BoardBankAnalyzer.composeTailCalls} / {@code exitEffect}
 * (bead grm-432). Before this, only the SUCCESS path had coverage -- the {@code nesuxhelpertest}
 * fixture's U9/U10 -- while the four cases the pass exists to be SAFE in (a caller-dependent
 * tail-callee, several exits whose composed effects disagree, a cycle, and the depth cap) were
 * proven by reading the code. A decline is precisely the behaviour that keeps a wrong bank off
 * the screen, so an untested guard is one refactor away from silently becoming a non-guard.
 * <p>
 * <b>The three sites and what reaches each of them here:</b>
 * <ul>
 * <li>{@code exitEffect}'s {@code depth > MAX_TAIL_CALL_DEPTH || !onStack.add(f)} -- ONE
 * predicate covering TWO rules. Both halves are driven separately
 * ({@link #aChainDeepEnoughDeclinesAndTheChainOneShorterStillComposes} has no cycle at all;
 * {@link #aTwoFunctionTailCallCycleDeclinesBothOfItsMembers} and
 * {@link #aSelfTailCallingHelperDeclines} have no depth) so a refactor that splits them
 * cannot leave one silently uncovered.</li>
 * <li>{@code composeWithCallee}'s {@code callee.declined() || callee.constState() == null}
 * -- {@link #aCallerDependentTailCalleeDeclines} and
 * {@link #aDeclinedTailCalleePropagatesToItsCaller} respectively.</li>
 * <li>{@code composeWithCallee}'s final fall-through: the caller's own {@code constState} is
 * null AND the callee does not own every bit of {@code ownMask}
 * ({@link #aCallerDependentHelperWhoseCalleeOwnsOnlySomeOfItsBitsDeclines}).</li>
 * <li>{@code agreeOrDecline} -- {@link #twoExitsWhoseComposedEffectsDisagreeDecline} and
 * {@link #aDirectReturnDisagreeingWithATailCallDeclines}.</li>
 * </ul>
 * <b>Every decline test has an anti-vacuity partner that COMPOSES</b> against an otherwise
 * identical fixture, because a decline is also what you get from a fixture the pass never
 * looked at, and the two must be distinguishable.
 * <p>
 * <b>Modeling note: the {@code FlowOverride.CALL_RETURN} on each tail {@code JMP} is not a
 * test convenience.</b> It is exactly what Ghidra's own {@code SharedReturnAnalysisCmd} stamps
 * on a jump to another function's entry, and it is the only reason {@code exitInstructions}
 * sees the jump at all ({@code getFlowType().isTerminal()}) and {@code exitEffect} treats it as
 * a call ({@code isCall()}). {@link #callReturn} asserts both properties after setting it, so
 * this fixture cannot quietly stop modeling a tail call.
 * <p>
 * Driving {@code composeTailCalls} directly (it is package-private for this test; see the
 * comment on its declaration) rather than through {@code added()}: everything above it needs a
 * board descriptor and a real import, which is the Tier 3 tier. The dump-level half of this
 * bead -- "a decline WARNS at the call site rather than annotating" -- is pinned there, by the
 * {@code nesuxhelpertest} fixture's U11a/U11b/U12, for the CYCLE branch only. The other three
 * branches have no Tier 3 coverage by design (one fixture, one decline shape), and
 * {@link #aSelfTailCallingHelperDeclines} is unreachable from Tier 3 at all -- Ghidra's
 * {@code SharedReturnAnalysisCmd} refuses to retype a jump to its own function's entry as a
 * call, so a literal self-tail-call never reaches this pass through the real pipeline. Measured,
 * not assumed: a self-jump build of that fixture annotated {@code bank -> 1} with no warning.
 */
public class TailCallCompositionProgramTest extends AbstractBundledLanguageTest {

	/** The bank field every helper in this file writes, unless it says otherwise. */
	private static final int FULL_MASK = 0x0F;

	private ProgramBuilder builder;
	private ProgramDB program;
	private BoardBankAnalyzer analyzer;

	/** Insertion-ordered so {@code composeTailCalls}' iteration order is deterministic. */
	private Map<Function, HelperModel> helpers;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		analyzer = new NesBankingAnalyzer();
		helpers = new LinkedHashMap<>();
	}

	// ------------------------------------------------------------------
	// fixture construction
	// ------------------------------------------------------------------

	private static String hex(long addr) {
		return String.format("0x%04x", addr);
	}

	private Address addr(long a) {
		return builder.addr(hex(a));
	}

	/**
	 * A two-instruction body {@code NOP ; RTS} at {@code at}, made a function. Stands in for a
	 * helper that returns normally -- the NOP is there so the body is never a one-instruction
	 * trampoline, which {@code reachableEntries} would hop THROUGH rather than stopping at.
	 */
	private Function returningBody(String name, long at) throws Exception {
		builder.setBytes(hex(at), "ea 60", true);
		return builder.createEmptyFunction(name, hex(at), 2, null);
	}

	/** A body {@code NOP ; JMP target} at {@code at}, with the jump typed as a tail call. */
	private Function tailCallingBody(String name, long at, long target) throws Exception {
		builder.setBytes(hex(at),
			String.format("ea 4c %02x %02x", target & 0xFF, (target >> 8) & 0xFF), true);
		Function f = builder.createEmptyFunction(name, hex(at), 4, null);
		callReturn(at + 1);
		return f;
	}

	/**
	 * A body {@code BNE +3 ; JMP a ; JMP b} at {@code at}: two exits, both tail calls. The
	 * conditional branch is what makes both reachable, which is the whole point.
	 */
	private Function twoExitBody(String name, long at, long a, long b) throws Exception {
		builder.setBytes(hex(at), String.format("d0 03 4c %02x %02x 4c %02x %02x",
			a & 0xFF, (a >> 8) & 0xFF, b & 0xFF, (b >> 8) & 0xFF), true);
		Function f = builder.createEmptyFunction(name, hex(at), 8, null);
		callReturn(at + 2);
		callReturn(at + 5);
		return f;
	}

	/** A body {@code BNE +1 ; RTS ; JMP target}: one plain return, one tail call. */
	private Function returnOrTailCallBody(String name, long at, long target) throws Exception {
		builder.setBytes(hex(at), String.format("d0 01 60 4c %02x %02x",
			target & 0xFF, (target >> 8) & 0xFF), true);
		Function f = builder.createEmptyFunction(name, hex(at), 6, null);
		callReturn(at + 3);
		return f;
	}

	/**
	 * Stamps {@code FlowOverride.CALL_RETURN} on the jump at {@code at}, exactly as Ghidra's
	 * shared-return analysis does, and asserts the two properties {@code exitEffect} reads off
	 * the result. Without the override a {@code JMP} is neither terminal nor a call, so the
	 * whole pass would never look at it and every test here would pass vacuously.
	 */
	private void callReturn(long at) {
		int tx = program.startTransaction("flow override");
		try {
			Instruction instr = program.getListing().getInstructionAt(addr(at));
			assertNotNull("no instruction at " + hex(at), instr);
			instr.setFlowOverride(FlowOverride.CALL_RETURN);
			assertTrue("jump at " + hex(at) + " is not a terminal exit",
				instr.getFlowType().isTerminal());
			assertTrue("jump at " + hex(at) + " is not typed as a call",
				instr.getFlowType().isCall());
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/** Registers {@code f} as a helper that unconditionally leaves {@code bank} in {@code mask}. */
	private Function constHelper(Function f, int bank, int mask) {
		helpers.put(f, new HelperModel(f, f.getEntryPoint(), BankState.fullyKnown(mask, bank),
			null, mask, 0, null, f.getEntryPoint(), f.getEntryPoint(), null));
		return f;
	}

	/** Registers {@code f} as a helper whose deposit is CALLER-SUPPLIED (no constant). */
	private Function argHelper(Function f, int mask) {
		helpers.put(f, new HelperModel(f, f.getEntryPoint(), null, 'A', mask, 0, null,
			f.getEntryPoint(), f.getEntryPoint(), null));
		return f;
	}

	private Map<Function, HelperModel> compose() {
		return analyzer.composeTailCalls(program, helpers);
	}

	// ------------------------------------------------------------------
	// outcome assertions
	// ------------------------------------------------------------------

	/**
	 * {@code f} DECLINED: the pass replaced its model with one owning the mechanism and
	 * asserting no value, which is what makes each call site warn instead of annotate.
	 * {@code assertNotSame} is load-bearing -- a helper the pass never touched also has a null
	 * {@code constState} when it is caller-dependent, and that is a different outcome.
	 */
	private void assertDeclined(Map<Function, HelperModel> composed, Function f) {
		HelperModel m = composed.get(f);
		assertNotNull(f.getName() + " vanished from the composed map", m);
		assertNotSame(f.getName() + " was left untouched, not declined", helpers.get(f), m);
		assertNull(f.getName() + " asserted a bank where it must decline", m.constState());
		assertNull(f.getName() + " kept an argument register across a decline", m.argReg());
		assertNull(f.getName() + " kept a switch site across a decline", m.switchSite());
	}

	/** {@code f} composed to a caller-independent {@code bank} over {@code mask}. */
	private void assertComposedTo(Map<Function, HelperModel> composed, Function f, int bank,
			int mask) {
		HelperModel m = composed.get(f);
		assertNotNull(f.getName() + " vanished from the composed map", m);
		assertNotSame(f.getName() + " was left untouched, not composed", helpers.get(f), m);
		assertEquals(f.getName() + " composed to the wrong state",
			BankState.fullyKnown(mask, bank), m.constState());
		assertEquals(f.getName() + " composed to the wrong mask", mask, m.effectMask());
	}

	/** {@code f} has no tail call to a recognized helper, so its body-local summary stands. */
	private void assertUntouched(Map<Function, HelperModel> composed, Function f) {
		assertSame(f.getName() + " was rewritten though it has no helper tail call",
			helpers.get(f), composed.get(f));
	}

	// ------------------------------------------------------------------
	// SITE 1a: the cycle guard (!onStack.add(f))
	// ------------------------------------------------------------------

	/**
	 * <b>Mega Man's {@code FUN_f105} shape, which tail-jumps to ITSELF at {@code $F10F}</b> --
	 * the only known real-ROM reproduction of any of these branches, and the reason the cycle
	 * guard is load-bearing on a shipped title rather than merely defensive.
	 */
	@Test
	public void aSelfTailCallingHelperDeclines() throws Exception {
		Function f = constHelper(tailCallingBody("selfTail", 0x9000, 0x9000), 3, FULL_MASK);

		assertDeclined(compose(), f);
	}

	/**
	 * The general cycle: two helpers that tail-call each other. BOTH must decline -- the guard
	 * fires on whichever member the outer loop reaches second, and if the decline did not
	 * propagate back out, the first member would keep a confident (and wrong) answer.
	 */
	@Test
	public void aTwoFunctionTailCallCycleDeclinesBothOfItsMembers() throws Exception {
		Function a = constHelper(tailCallingBody("cycleA", 0x9100, 0x9110), 1, FULL_MASK);
		Function b = constHelper(tailCallingBody("cycleB", 0x9110, 0x9100), 2, FULL_MASK);

		Map<Function, HelperModel> composed = compose();
		assertDeclined(composed, a);
		assertDeclined(composed, b);
	}

	/**
	 * ANTI-VACUITY for both of the above: break the cycle by pointing the second helper at a
	 * plain {@code RTS} body and the identical fixture composes to the callee's bank. Whatever
	 * declines the cyclic fixtures, it is not the shape of the fixture.
	 */
	@Test
	public void breakingTheCycleComposes() throws Exception {
		Function a = constHelper(tailCallingBody("chainA", 0x9200, 0x9210), 1, FULL_MASK);
		Function b = constHelper(returningBody("chainB", 0x9210), 2, FULL_MASK);

		Map<Function, HelperModel> composed = compose();
		assertComposedTo(composed, a, 2, FULL_MASK);
		assertUntouched(composed, b);
	}

	// ------------------------------------------------------------------
	// SITE 1b: the depth cap (depth > MAX_TAIL_CALL_DEPTH)
	// ------------------------------------------------------------------

	/**
	 * The cap, driven with NO cycle anywhere -- the other half of the shared predicate.
	 * <p>
	 * One straight chain of 20 helpers, each tail-calling the next, the last returning. Because
	 * {@code composeTailCalls} restarts {@code exitEffect} at depth 0 for EVERY helper, one
	 * program answers the whole question: the chain below some link is short enough to compose
	 * and everything above it declines. The test asserts the boundary EXISTS and is strictly
	 * interior (some links compose, some decline, and the two groups do not interleave) rather
	 * than pinning {@code MAX_TAIL_CALL_DEPTH}'s current value of 8 -- that is a policy bound,
	 * and re-tuning it must not fail this test, whereas deleting the cap must.
	 */
	@Test
	public void aChainDeepEnoughDeclinesAndTheChainOneShorterStillComposes() throws Exception {
		final int links = 20;
		Function[] chain = new Function[links];
		for (int i = 0; i < links - 1; i++) {
			chain[i] = constHelper(
				tailCallingBody("link" + i, 0x9300 + i * 8, 0x9300 + (i + 1) * 8), i, FULL_MASK);
		}
		chain[links - 1] =
			constHelper(returningBody("link" + (links - 1), 0x9300 + (links - 1) * 8), 7,
				FULL_MASK);

		Map<Function, HelperModel> composed = compose();

		// Every link but the last tail-calls, so every one of them either composes or declines;
		// find the lowest that composes.
		int boundary = links - 1;
		for (int i = 0; i < links - 1; i++) {
			if (composed.get(chain[i]).constState() != null) {
				boundary = i;
				break;
			}
		}
		assertTrue("no link in a 20-deep chain hit the depth cap -- the cap is gone",
			boundary > 0);
		assertTrue("the whole chain declined; the cap is not a cap but a blanket refusal",
			boundary < links - 1);

		for (int i = 0; i < boundary; i++) {
			assertDeclined(composed, chain[i]);
		}
		// Below the boundary the chain is short enough: each composes to the LAST link's bank,
		// since every callee overwrites the whole field.
		for (int i = boundary; i < links - 1; i++) {
			assertComposedTo(composed, chain[i], 7, FULL_MASK);
		}
		assertUntouched(composed, chain[links - 1]);
	}

	// ------------------------------------------------------------------
	// SITE 2a: callee.constState() == null -- a caller-dependent tail-callee
	// ------------------------------------------------------------------

	/**
	 * The tail-callee's own effect is whatever ITS caller passed it, so nothing is assertable
	 * about the composite either. This is the branch a "just use the callee's model" shortcut
	 * would get wrong by silently adopting a null constant as a value.
	 */
	@Test
	public void aCallerDependentTailCalleeDeclines() throws Exception {
		Function a = constHelper(tailCallingBody("callsArg", 0x9500, 0x9510), 3, FULL_MASK);
		argHelper(returningBody("argCallee", 0x9510), FULL_MASK);

		assertDeclined(compose(), a);
	}

	/**
	 * ANTI-VACUITY: the same fixture with a CONSTANT callee composes -- and to the callee's
	 * bank, not the caller's own last write. This is {@code nesuxhelpertest}'s U9 at Tier 2,
	 * i.e. Mega Man's {@code FUN_d846 -> FUN_c3b3}.
	 */
	@Test
	public void aConstantTailCalleeComposesOverTheCallersOwnDeposit() throws Exception {
		Function a = constHelper(tailCallingBody("callsConst", 0x9600, 0x9610), 3, FULL_MASK);
		Function b = constHelper(returningBody("constCallee", 0x9610), 2, FULL_MASK);

		Map<Function, HelperModel> composed = compose();
		assertComposedTo(composed, a, 2, FULL_MASK);
		assertUntouched(composed, b);
	}

	// ------------------------------------------------------------------
	// SITE 2b: callee.declined() -- a decline propagates outward
	// ------------------------------------------------------------------

	/**
	 * A helper one hop OUTSIDE a cycle. The cycle guard fires two levels down, and the decline
	 * has to travel back up: {@code outer} never touches a cycle itself, so only the
	 * {@code callee.declined()} half of {@code composeWithCallee}'s first test can save it.
	 */
	@Test
	public void aDeclinedTailCalleePropagatesToItsCaller() throws Exception {
		Function outer = constHelper(tailCallingBody("outer", 0x9700, 0x9710), 1, FULL_MASK);
		Function a = constHelper(tailCallingBody("innerA", 0x9710, 0x9720), 2, FULL_MASK);
		Function b = constHelper(tailCallingBody("innerB", 0x9720, 0x9710), 3, FULL_MASK);

		Map<Function, HelperModel> composed = compose();
		assertDeclined(composed, outer);
		assertDeclined(composed, a);
		assertDeclined(composed, b);
	}

	// ------------------------------------------------------------------
	// SITE 2c: caller-dependent caller whose callee does not own all of ownMask
	// ------------------------------------------------------------------

	/**
	 * The caller's own body is caller-dependent AND the callee only overwrites part of the
	 * field the caller could have touched, so the caller's unknown contribution survives into
	 * the composite. Nothing constant can be asserted, and the surviving bits are exactly what
	 * a "callee wins" shortcut would lose.
	 */
	@Test
	public void aCallerDependentHelperWhoseCalleeOwnsOnlySomeOfItsBitsDeclines()
			throws Exception {
		Function a = argHelper(tailCallingBody("partial", 0x9800, 0x9810), FULL_MASK);
		constHelper(returningBody("narrowCallee", 0x9810), 1, 0x03);

		assertDeclined(compose(), a);
	}

	/**
	 * ANTI-VACUITY, and the case the pass exists to ACCEPT: widen the callee's mask so it
	 * covers every bit the caller's body could touch and the composite becomes
	 * caller-INDEPENDENT even though the caller's own body was not. Mega Man's
	 * {@code FUN_d846} lands here.
	 */
	@Test
	public void aCallerDependentHelperWhoseCalleeOwnsEveryBitComposes() throws Exception {
		Function a = argHelper(tailCallingBody("covered", 0x9900, 0x9910), 0x03);
		Function b = constHelper(returningBody("wideCallee", 0x9910), 5, FULL_MASK);

		Map<Function, HelperModel> composed = compose();
		assertComposedTo(composed, a, 5, FULL_MASK);
		assertUntouched(composed, b);
	}

	// ------------------------------------------------------------------
	// SITE 3: agreeOrDecline -- several exits whose composed effects disagree
	// ------------------------------------------------------------------

	/** Two tail calls out of one body, to helpers that commit different banks. */
	@Test
	public void twoExitsWhoseComposedEffectsDisagreeDecline() throws Exception {
		Function a = constHelper(twoExitBody("forks", 0x9A00, 0x9A10, 0x9A20), 3, FULL_MASK);
		constHelper(returningBody("forkLeft", 0x9A10), 1, FULL_MASK);
		constHelper(returningBody("forkRight", 0x9A20), 2, FULL_MASK);

		assertDeclined(compose(), a);
	}

	/**
	 * ANTI-VACUITY: identical two-exit shape, both callees committing the SAME bank, composes.
	 * So it is the disagreement that declines, not the branch.
	 */
	@Test
	public void twoExitsThatAgreeCompose() throws Exception {
		Function a = constHelper(twoExitBody("forksAgree", 0x9B00, 0x9B10, 0x9B20), 3,
			FULL_MASK);
		constHelper(returningBody("agreeLeft", 0x9B10), 2, FULL_MASK);
		constHelper(returningBody("agreeRight", 0x9B20), 2, FULL_MASK);

		assertComposedTo(compose(), a, 2, FULL_MASK);
	}

	/**
	 * The mixed shape, and the one most likely to be missed: ONE path returns normally (so the
	 * body-local summary describes it) and the other tail-calls a helper that commits something
	 * else. The live bank depends on which path ran, so the helper must decline.
	 */
	@Test
	public void aDirectReturnDisagreeingWithATailCallDeclines() throws Exception {
		Function a = constHelper(returnOrTailCallBody("mixed", 0x9C00, 0x9C10), 3, FULL_MASK);
		constHelper(returningBody("mixedCallee", 0x9C10), 2, FULL_MASK);

		assertDeclined(compose(), a);
	}

	/**
	 * ANTI-VACUITY for the mixed shape: when the tail-callee commits the same bank the body
	 * already deposited, both paths agree and the helper keeps its answer.
	 */
	@Test
	public void aDirectReturnAgreeingWithATailCallComposes() throws Exception {
		Function a = constHelper(returnOrTailCallBody("mixedAgree", 0x9D00, 0x9D10), 2,
			FULL_MASK);
		constHelper(returningBody("mixedAgreeCallee", 0x9D10), 2, FULL_MASK);

		assertComposedTo(compose(), a, 2, FULL_MASK);
	}

	// ------------------------------------------------------------------
	// the NO-OP path: a tail call to a function this engine does not model
	// ------------------------------------------------------------------

	/**
	 * The rule is NARROWED, not replaced: a tail jump to a function that is not a recognized
	 * helper must leave the model completely alone, exactly as {@code runDataflow} folds a call
	 * to one. Without this, every restore-before-RTS trampoline in {@code nesbanktest2} would
	 * start declining.
	 */
	@Test
	public void aTailCallToANonHelperLeavesTheModelUntouched() throws Exception {
		Function a = constHelper(tailCallingBody("callsStranger", 0x9E00, 0x9E10), 3, FULL_MASK);
		returningBody("stranger", 0x9E10); // deliberately NOT registered as a helper

		assertUntouched(compose(), a);
	}
}
