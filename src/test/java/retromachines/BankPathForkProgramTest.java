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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 {@code ProgramBuilder} coverage of {@link BankDataflowEngine}'s path forking (bead
 * {@code grm-wul}, shipped in commit fc059e6 with only E2E golden coverage via
 * {@code tools/banktest/mknesbanktest.py}'s {@code make_prg_fork()}/{@code make_prg_forkbudget()}
 * fixtures). Bead {@code grm-9qm2} adds JUnit coverage at the engine level, calling the
 * package-private {@link BankDataflowEngine#runDataflow} directly with a hand-built
 * {@link BoardDescriptorModel.BoardModel} and a {@link BankStrategyRegistry.ConfiguredMechanism}
 * wrapping a real {@link MemoryLatchBankSwitchStrategy} -- the same shape as
 * {@code MemoryLatchStrategyProgramTest}'s fixtures, one level up (the whole dataflow run rather
 * than one {@code computeSwitch} call), so no NES loader/cartridge machinery is needed: only
 * {@code BankState}/mechanism/board plumbing, mirroring the E2E fixtures' 6502 byte patterns
 * without their ROM/mapper wrapping.
 * <p>
 * Every fixture uses a single 4-bit {@code bank} field ({@code board.mask() == 0xF}) and one
 * {@code memory-latch} mechanism covering {@code $9000-$9100}, matching the E2E fixtures'
 * UxROM shape (mask {@code 0x0F}, no bus conflict needed here since the driven values never
 * collide with a ROM byte).
 */
public class BankPathForkProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	// ------------------------------------------------------------------
	// Fixture plumbing
	// ------------------------------------------------------------------

	private void put(int addr, String hex) throws Exception {
		builder.setBytes(String.format("0x%x", addr), hex, true);
	}

	private Address addr(int a) {
		return builder.addr(String.format("0x%x", a));
	}

	/** A single 4-bit {@code bank} field board, matching every E2E fork fixture's mask. */
	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "bank", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board =
			BoardDescriptorModel.BoardModel.parse(map, new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		return board;
	}

	/** A discrete-mapper memory-latch mechanism over {@code [start, end]}, no bus conflict. */
	private MemoryLatchBankSwitchStrategy latch(BoardDescriptorModel.BoardModel board, int start,
			int end) {
		JsonObject params = new JsonObject();
		params.addProperty("start", start);
		params.addProperty("end", end);
		params.addProperty("mask", board.mask());
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, board.mask());
		return strategy;
	}

	private BankStrategyRegistry.ConfiguredMechanism mechanism(BankSwitchStrategy strategy,
			BoardDescriptorModel.BoardModel board) {
		return new BankStrategyRegistry.ConfiguredMechanism(strategy, board.mask(), 0);
	}

	private void makeFunction(int start, int endInclusive, String name) throws Exception {
		Address startAddr = addr(start);
		Address endAddr = addr(endInclusive);
		int tx = program.startTransaction("create function");
		try {
			program.getFunctionManager().createFunction(name, startAddr,
				new AddressSet(startAddr, endAddr), SourceType.ANALYSIS);
		}
		finally {
			program.endTransaction(tx, true);
		}
		builder.createEntryPoint(String.format("0x%x", start), name);
	}

	private BankDataflowEngine.DataflowResult run(
			List<BankStrategyRegistry.ConfiguredMechanism> mechanisms,
			BoardDescriptorModel.BoardModel board) throws Exception {
		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			mechanisms, board, null, Set.of());
	}

	/**
	 * The nesforktest shape (bead grm-wul), translated 1:1 from
	 * {@code mknesbanktest.py make_prg_fork()}: a RAM flag branches into two arms that load
	 * X with two different constants, both falling into the SAME store -- the merge site,
	 * where a single-state scan must refuse (the join) but path forking evaluates each arm.
	 * Returns the fork site's address ({@code base + 8}, the {@code STX}).
	 *
	 * <pre>
	 * base+00  LDA $10       ; RAM flag -- genuinely runtime, selects the arm
	 * base+02  LDX #$01      ; arm A: X = 1
	 * base+04  BEQ +2        ; ...straight to the merge
	 * base+06  LDX #$02      ; arm B: X = 2, falls into the merge
	 * base+08  STX $9000     ; THE MERGE SITE -- the fork site
	 * </pre>
	 */
	private Address layTwoArmFork(int base) throws Exception {
		put(base, "a5 10"); // LDA $10
		put(base + 2, "a2 01"); // LDX #$01      (arm A)
		put(base + 4, "f0 02"); // BEQ +2 -> merge
		put(base + 6, "a2 02"); // LDX #$02      (arm B)
		put(base + 8, "8e 00 90"); // STX $9000  <- fork site
		return addr(base + 8);
	}

	// ------------------------------------------------------------------
	// (a) Fork rule: an ANALYZER_LIMIT join with 2 constant arms forks and resolves both
	// ------------------------------------------------------------------

	@Test
	public void twoConstantArmsMergingBeforeASwitchForkAndResolveBothArms() throws Exception {
		Address site = layTwoArmFork(0xc000);
		put(0xc00b, "60"); // RTS
		makeFunction(0xc000, 0xc00b, "RESET");

		BoardDescriptorModel.BoardModel board = board();
		BankDataflowEngine.DataflowResult result =
			run(List.of(mechanism(latch(board, 0x9000, 0x9100), board)), board);

		BankDataflowEngine.SwitchResult sr = result.switchResults().get(site);
		assertNotNull("merge site must be recognized as a mechanism write", sr);
		assertTrue("two distinct constant arms, both resolving, must fork", sr.forked());
		assertFalse(sr.armsDenied());
		assertEquals(BankSwitchStrategy.ValueStop.RESOLVED, sr.stop());
		assertEquals("one positioned value per arm, in canonical (bits-ascending) order", 2,
			sr.arms().size());
		assertEquals(0x1, sr.arms().get(0).bits());
		assertEquals(0x2, sr.arms().get(1).bits());
		assertEquals(0xF, sr.arms().get(0).knownMask());
		assertEquals(0xF, sr.arms().get(1).knownMask());

		// Downstream of the fork, BOTH banks stay live as separate whole states.
		List<BankState> forked = result.forkedStates().get(addr(0xc00b));
		assertNotNull("the fall-through of a forked site must carry >1 live states", forked);
		assertEquals(2, forked.size());

		BankDataflowEngine.ForkStats stats = result.forkStats();
		assertEquals(1, stats.sitesForked());
		assertEquals(2, stats.forksCreated());
		assertEquals(0, stats.sitesDenied());
		assertEquals(0, stats.forksDenied());
	}

	// ------------------------------------------------------------------
	// (b) Ordinary merges (not demanded by a switch site) still merge field-wise
	// ------------------------------------------------------------------

	/**
	 * Reuses (a)'s fork, then calls into a plain function. Forks are intraprocedural
	 * (grm-wul's javadoc): a function entry always receives {@code PathId.ROOT}, so the two
	 * live banks reaching the call target merge field-wise into ONE element there -- exactly
	 * what the single-state engine would have held, and exactly why the engine's own javadoc
	 * says an ordinary merge (an entry meeting a caller's context) must never fork, even though
	 * the two paths disagree on every tracked bit here.
	 */
	@Test
	public void functionEntryMergeDoesNotForkEvenWhenArmsCarryDifferentBanks() throws Exception {
		layTwoArmFork(0xc000);
		put(0xc00b, "20 00 c1"); // JSR $C100
		put(0xc100, "60"); // RTS -- the callee, outside the latch's own range
		makeFunction(0xc000, 0xc00d, "RESET");

		BoardDescriptorModel.BoardModel board = board();
		BankDataflowEngine.DataflowResult result =
			run(List.of(mechanism(latch(board, 0x9000, 0x9100), board)), board);

		List<BankState> intoTheCall = result.forkedStates().get(addr(0xc00b));
		assertNotNull("the call site itself is still reached forked", intoTheCall);
		assertEquals(2, intoTheCall.size());

		assertNull("a call target is not intraprocedural -- it must NOT carry the fork",
			result.forkedStates().get(addr(0xc100)));
		BankState calleeState = result.stateIn().get(addr(0xc100));
		assertNotNull(calleeState);
		// bank=1 (0001) and bank=2 (0010) merge field-wise (BankState.merge: a bit survives
		// only where both inputs AGREE): they disagree on the low two bits (knownMask loses
		// 0x3) but agree the high two bits are 0 (knownMask keeps 0xC) -- exactly what the
		// single-state engine would have computed at this join, with no notion of a fork at
		// all. The point is not "everything becomes unknown" but "the two paths merge
		// field-wise instead of staying separate elements".
		assertEquals(
			"bank 1 and bank 2 merge field-wise at the callee entry -- exactly the "
				+ "single-state engine's answer, not a fork",
			0xC, calleeState.knownMask());
		assertEquals(0, calleeState.bits());
	}

	// ------------------------------------------------------------------
	// (c) MAX_LIVE_FORKS_PER_BLOCK: 5 arms is over the 4-per-block cap
	// ------------------------------------------------------------------

	/**
	 * The nesforkbudgettest shape, translated 1:1 from {@code make_prg_forkbudget()}: a
	 * 5-way compare ladder merging into one store. Every arm resolves (the enumeration is not
	 * the problem), but 5 exceeds {@link BankDataflowEngine#MAX_LIVE_FORKS_PER_BLOCK} (4), so
	 * the fork is DENIED and the site is recorded {@code MULTI_VALUED_AT_MERGE} -- the
	 * engine's own log wording for this path is literally "collapsed to unknown"
	 * ({@code BankDataflowEngine.ForkBudget.grant}).
	 */
	private void layFiveArmLadder() throws Exception {
		put(0xc000, "a5 10"); // LDA $10
		put(0xc002, "f0 11"); // BEQ -> C015 (arm 1)
		put(0xc004, "c9 01"); // CMP #$01
		put(0xc006, "f0 12"); // BEQ -> C01A (arm 2)
		put(0xc008, "c9 02"); // CMP #$02
		put(0xc00a, "f0 13"); // BEQ -> C01F (arm 3)
		put(0xc00c, "c9 03"); // CMP #$03
		put(0xc00e, "f0 14"); // BEQ -> C024 (arm 4)
		put(0xc010, "a2 05"); // LDX #$05    (arm 5, the ladder's default)
		put(0xc012, "4c 26 c0"); // JMP C026
		put(0xc015, "a2 01"); // LDX #$01    (arm 1)
		put(0xc017, "4c 26 c0"); // JMP C026
		put(0xc01a, "a2 02"); // LDX #$02    (arm 2)
		put(0xc01c, "4c 26 c0"); // JMP C026
		put(0xc01f, "a2 03"); // LDX #$03    (arm 3)
		put(0xc021, "4c 26 c0"); // JMP C026
		put(0xc024, "a2 04"); // LDX #$04    (arm 4, falls through)
		put(0xc026, "8e 00 90"); // STX $9000 <- THE MERGE SITE (5 preds)
		put(0xc029, "60"); // RTS
	}

	@Test
	public void fiveArmMergeExceedsLiveCapAndIsDeniedNotForked() throws Exception {
		layFiveArmLadder();
		makeFunction(0xc000, 0xc029, "RESET");

		BoardDescriptorModel.BoardModel board = board();
		MemoryLatchBankSwitchStrategy strategy = latch(board, 0x9000, 0x9100);
		BankDataflowEngine.DataflowResult result =
			run(List.of(mechanism(strategy, board)), board);

		Address site = addr(0xc026);
		BankDataflowEngine.SwitchResult sr = result.switchResults().get(site);
		assertNotNull(sr);
		assertFalse("5 arms exceeds the 4-per-block cap -- must NOT fork", sr.forked());
		assertTrue("the budget must record which arm values it declined", sr.armsDenied());
		assertEquals(BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE, sr.stop());
		assertEquals(5, sr.arms().size());

		// THE INVARIANT (grm-wul commit message): a denied site's value is untouched from
		// what the single-state (pre-grm-wul) engine would have computed for this exact
		// instruction -- forking only ever ADDS information via a grant, so a denial must
		// reproduce the old engine's answer exactly. Calling the strategy directly, with no
		// arm awareness at all, IS that old engine's computation.
		Instruction mergeInstr = program.getListing().getInstructionAt(site);
		BankState singleStateAnswer = strategy.computeSwitch(program, mergeInstr, BankState.unknown());
		assertEquals("a denial must reproduce the single-state engine's answer exactly",
			singleStateAnswer, sr.effect());
		assertEquals("the join is genuinely unresolvable without path awareness", 0,
			singleStateAnswer.knownMask());

		BankDataflowEngine.ForkStats stats = result.forkStats();
		assertEquals(0, stats.sitesForked());
		assertEquals(0, stats.forksCreated());
		assertEquals(1, stats.sitesDenied());
		assertEquals(5, stats.forksDenied());
	}

	// ------------------------------------------------------------------
	// (d) MAX_FORKS_PER_FUNCTION: sticky denial once 16 forks are spent in one function
	// ------------------------------------------------------------------

	/** {@code count} independent two-armed fork sites, chained sequentially in one function. */
	private List<Address> layChainOfTwoArmForks(int base, int count) throws Exception {
		List<Address> sites = new ArrayList<>();
		int cur = base;
		for (int i = 0; i < count; i++) {
			put(cur, "a5 10"); // LDA $10
			put(cur + 2, "a2 01"); // LDX #$01      (arm A)
			put(cur + 4, "f0 02"); // BEQ +2 -> merge
			put(cur + 6, "a2 02"); // LDX #$02      (arm B)
			int target = 0x9000 + i * 4;
			put(cur + 8, String.format("8e %02x %02x", target & 0xFF, (target >> 8) & 0xFF));
			sites.add(addr(cur + 8));
			cur += 11;
		}
		put(cur, "60"); // RTS, after the last site
		return sites;
	}

	@Test
	public void stickyDenialOnceSixteenForksAreSpentInOneFunction() throws Exception {
		// 9 sites * 2 arms = 18 would-be forks; the budget is 16, so the 9th is denied and
		// every one of the first 8 (16 forks) is granted.
		List<Address> sites = layChainOfTwoArmForks(0xc000, 9);
		makeFunction(0xc000, 0xc000 + 9 * 11, "RESET");

		BoardDescriptorModel.BoardModel board = board();
		BankDataflowEngine.DataflowResult result =
			run(List.of(mechanism(latch(board, 0x9000, 0x9100), board)), board);

		for (int i = 0; i < 8; i++) {
			BankDataflowEngine.SwitchResult sr = result.switchResults().get(sites.get(i));
			assertNotNull("site " + i, sr);
			assertTrue("site " + i + " is within the 16/function budget and must be granted",
				sr.forked());
		}
		BankDataflowEngine.SwitchResult ninth = result.switchResults().get(sites.get(8));
		assertNotNull(ninth);
		assertFalse("the 9th site would bring the function to 18/16 forks -- must be denied",
			ninth.forked());
		assertEquals(BankSwitchStrategy.ValueStop.MULTI_VALUED_AT_MERGE, ninth.stop());

		BankDataflowEngine.ForkStats stats = result.forkStats();
		assertEquals(8, stats.sitesForked());
		assertEquals(16, stats.forksCreated());
		assertEquals(1, stats.sitesDenied());
		assertEquals(2, stats.forksDenied());
	}

	// ------------------------------------------------------------------
	// (e) Termination: a fork site inside a loop reaches a fixpoint, not path explosion
	// ------------------------------------------------------------------

	/**
	 * The same 2-arm fork as (a), wrapped in a 3-iteration loop so the SAME site is dequeued
	 * repeatedly. {@link BankDataflowEngine.PathId} is a MAP from fork site to value, so
	 * re-forking the same site on a later iteration REPLACES that site's choice rather than
	 * lengthening the path id -- the engine's own termination argument. This also pins that
	 * the budget grant is sticky: charged once for the site, not once per loop iteration.
	 *
	 * <pre>
	 * C000  LDY #$03      ; loop count
	 * C002  LDA $10       ; LOOP head (2 preds: fall-through, and the back edge below)
	 * C004  LDX #$01      ; arm A
	 * C006  BEQ +2        ; -> merge
	 * C008  LDX #$02      ; arm B
	 * C00A  STX $9000     ; THE FORK SITE, re-dequeued every iteration
	 * C00D  DEY
	 * C00E  BNE C002      ; back edge
	 * C010  RTS
	 * </pre>
	 */
	@Test(timeout = 30000)
	public void forkInsideALoopReachesAFixpointRatherThanGrowingPerIteration() throws Exception {
		put(0xc000, "a0 03"); // LDY #$03
		put(0xc002, "a5 10"); // LDA $10       <- LOOP head
		put(0xc004, "a2 01"); // LDX #$01      (arm A)
		put(0xc006, "f0 02"); // BEQ +2 -> merge
		put(0xc008, "a2 02"); // LDX #$02      (arm B)
		put(0xc00a, "8e 00 90"); // STX $9000  <- FORK SITE, inside the loop
		put(0xc00d, "88"); // DEY
		put(0xc00e, "d0 f2"); // BNE C002      (back edge)
		put(0xc010, "60"); // RTS
		makeFunction(0xc000, 0xc010, "RESET");

		BoardDescriptorModel.BoardModel board = board();
		BankDataflowEngine.DataflowResult result =
			run(List.of(mechanism(latch(board, 0x9000, 0x9100), board)), board);

		Address site = addr(0xc00a);
		BankDataflowEngine.SwitchResult sr = result.switchResults().get(site);
		assertNotNull(sr);
		assertTrue("the loop-carried site still forks its 2 constant arms", sr.forked());
		assertEquals(2, sr.arms().size());

		BankDataflowEngine.ForkStats stats = result.forkStats();
		assertEquals(
			"the SAME site is re-dequeued on every loop iteration, but the budget grant is "
				+ "sticky -- charged once, not once per iteration",
			1, stats.sitesForked());
		assertEquals(2, stats.forksCreated());

		List<BankState> afterSite = result.forkedStates().get(addr(0xc00d));
		assertNotNull(afterSite);
		assertEquals(
			"the loop head's live path-id set reaches a fixpoint at exactly 2 elements, not "
				+ "one new element per iteration",
			2, afterSite.size());
	}

	// ------------------------------------------------------------------
	// (f) The may-sound caveat: an in-state-derived arm value can never be created today
	// ------------------------------------------------------------------

	/**
	 * A minimal test double modelling "an arm's value derived from a transient in-state (a
	 * mirror load)" -- the caveat in {@code BankDataflowEngine.runDataflow}'s javadoc ("An
	 * arm's value may depend on the in-state... A fork element created from an earlier,
	 * stronger in-state is never withdrawn... The arm values the shipped strategies actually
	 * recover are immediates, for which the question does not arise.").
	 * <p>
	 * Unlike the shipped strategies (which resolve arm-specific values from the arm's OWN
	 * register environment, via the 4-argument {@code computeSwitchOutcome} override this
	 * strategy deliberately does NOT provide), this strategy answers from {@code inState}
	 * alone. {@link BankSwitchStrategy}'s default 4-argument form then delegates every arm
	 * query to the SAME 3-argument call with the site's single, already-merged {@code inState}
	 * -- {@code evaluateArms} never recomputes a per-arm board state, only a per-arm register
	 * environment. So a strategy that reads only {@code inState} sees an IDENTICAL answer on
	 * every arm and can never diverge per arm, which is what this test pins: the caveat
	 * describes a case the current engine cannot reach, not a live gap.
	 */
	private static final class EchoStrategy implements BankSwitchStrategy {

		private final Address site;

		EchoStrategy(Address site) {
			this.site = site;
		}

		@Override
		public String strategyName() {
			return "test-echo";
		}

		@Override
		public void configure(Program program, JsonObject params, int stateMask) {
			// no-op: nothing to configure
		}

		@Override
		public BankSwitchStrategy.SwitchOutcome computeSwitchOutcome(Program program,
				Instruction instr, BankState inState) {
			if (!instr.getMinAddress().equals(site)) {
				return null; // not this mechanism's instruction
			}
			return BankSwitchStrategy.SwitchOutcome.of(inState,
				BankSwitchStrategy.ValueStop.ANALYZER_LIMIT);
		}
	}

	/**
	 * Two immediate switches (bank=1, bank=0x0E -- chosen so their XOR is {@code 0xF}, the
	 * whole mask, so the field-wise merge of the two arms is wholly unknown) converging on an
	 * {@link EchoStrategy} site.
	 *
	 * <pre>
	 * C000  LDA $10        ; flag
	 * C002  BEQ C00C       ; -> arm B
	 * C004  LDA #$01       ; arm A
	 * C006  STA $9000      ; S1a: immediate switch -> bank=1
	 * C009  JMP C011       ; -> MERGE (the echo site)
	 * C00C  LDA #$0E       ; arm B
	 * C00E  STA $9000      ; S1b: immediate switch -> bank=0x0E
	 * C011  STA $A000      ; THE ECHO SITE -- the merge
	 * C014  RTS
	 * </pre>
	 */
	@Test
	public void forkedValueFromAnInStateDependentStrategyIsNeverCreated() throws Exception {
		put(0xc000, "a5 10"); // LDA $10
		put(0xc002, "f0 08"); // BEQ -> C00C
		put(0xc004, "a9 01"); // LDA #$01       (arm A)
		put(0xc006, "8d 00 90"); // STA $9000   S1a -> bank=1
		put(0xc009, "4c 11 c0"); // JMP C011
		put(0xc00c, "a9 0e"); // LDA #$0E       (arm B)
		put(0xc00e, "8d 00 90"); // STA $9000   S1b -> bank=0x0E
		put(0xc011, "8d 00 a0"); // STA $A000   <- THE ECHO SITE
		put(0xc014, "60"); // RTS
		makeFunction(0xc000, 0xc014, "RESET");

		Address echoSite = addr(0xc011);
		BoardDescriptorModel.BoardModel board = board();
		BankStrategyRegistry.ConfiguredMechanism latchMech =
			mechanism(latch(board, 0x9000, 0x9100), board);
		BankStrategyRegistry.ConfiguredMechanism echoMech =
			mechanism(new EchoStrategy(echoSite), board);
		BankDataflowEngine.DataflowResult result = run(List.of(latchMech, echoMech), board);

		BankDataflowEngine.SwitchResult sr = result.switchResults().get(echoSite);
		assertNotNull("the echo site must still be recognized as a mechanism write", sr);
		assertFalse(
			"an in-state-derived value can never fork today: evaluateArms probes every arm "
				+ "against the SAME already-merged in-state, so a mirror-style strategy sees "
				+ "identical (and here, unresolved) input on every arm and cannot diverge per arm",
			sr.forked());
		assertEquals(BankSwitchStrategy.ValueStop.ANALYZER_LIMIT, sr.stop());
		assertEquals(0, sr.effect().knownMask());

		BankDataflowEngine.ForkStats stats = result.forkStats();
		assertEquals(0, stats.sitesForked());
		assertEquals(0, stats.forksCreated());
	}
}
