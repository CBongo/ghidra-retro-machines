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

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import retromachines.BankSwitchStrategy.HelperDeposit;
import retromachines.BankSwitchStrategy.SwitchOutcome;
import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.CallSiteRegKey;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Tier-2 {@code ProgramBuilder} coverage of bead grm-mej.3 increment 3, "call-crossing PHA/PLA
 * pairing": {@link StoredValueScanner#findMatchingPush} now steps OVER a call (rather than
 * abandoning) while pairing a {@code PLA} to its {@code PHA}, and the walk that resumes from the
 * push resolves against the tracked state AT THE PUSH (via a new
 * {@link StoredValueScanner.Hooks#stateAt} hook), not at the call -- because the pushed byte was
 * read before whatever the intervening call may have switched. See the production diff's own
 * javadoc on {@code StoredValueScanner.Hooks#stateAt}, {@code resumeStateAfterPairing}, and
 * {@code BankDataflowEngine}'s {@code stateDependents} field for the full motivation; this class
 * pins the same claims at the {@code ProgramBuilder} level, modelled on
 * {@link PushPullValueCarryingProgramTest} (scanner-level, direct site, {@code NO_HOOKS}),
 * {@link CallerSideMirrorHooksProgramTest} (recovery-level, {@code StubStrategy} +
 * {@code mirrorHooks}) and {@link BankPathForkProgramTest} (engine-level, hand-built
 * {@code BoardModel}).
 * <p>
 * Fixture note inherited from {@code StoreForwardingProgramTest}: {@link ProgramBuilder} blocks
 * are created read-only, so every RAM block must be made writable explicitly.
 */
public class CallCrossingPushPullProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(zp);
	}

	private void makeWritable(MemoryBlock block) {
		int tx = program.startTransaction("set block write permission");
		try {
			block.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private void put(String address, String hex) throws Exception {
		builder.setBytes(address, hex, true);
	}

	// ==================================================================
	// Scanner-level fixtures -- cases 1, 1b, 6, 7, 8
	// ==================================================================

	/** An AxROM-shaped latch: the whole ROM area, no address decode, 3-bit field. */
	private MemoryLatchBankSwitchStrategy axromLatch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x07);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0x07);
		return strategy;
	}

	private void assertBank(int expected, BankState actual) {
		assertEquals("tracked bits not fully known: " + actual, 0x07, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	private void assertUnresolved(BankState actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
	}

	/**
	 * Hooks with a state AVAILABLE at every address -- wholly unknown, but non-null. This is
	 * what lets a scanner-level case exercise the DEPTH logic of a call-crossing pairing in
	 * isolation: {@code resumeStateAfterPairing} abandons on a {@code null} {@code stateAt}
	 * (see {@link #directSiteWithNoOracleStillAbandonsAtACall}), and an unknown-but-present state
	 * lets an immediate found beyond the push resolve while a mirror would not.
	 */
	private static final StoredValueScanner.Hooks STATE_AVAILABLE_HOOKS =
		new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return null;
			}

			@Override
			public BankState stateAt(Address addr) {
				return BankState.unknown();
			}
		};

	/** The scanner on a direct {@code STA} site under {@link #STATE_AVAILABLE_HOOKS}. */
	private BankState scanWithStateAvailable(String storeAddress) {
		return StoredValueScanner.resolveStoredValue(program, instructionAt(storeAddress), 'A',
			BankState.unknown(), 0x07, STATE_AVAILABLE_HOOKS);
	}

	/**
	 * 1. Depth across one call, immediate value: {@code LDA #$05 / PHA / LDA #$FF / JSR sub / PLA
	 * / STA $8000}. Pins that a call in the span is stepped over (rather than abandoning the
	 * pairing) when a state is available at the push, and that an IMMEDIATE value survives the
	 * crossing untouched -- the value comes from continuing the walk backward from the located
	 * {@code PHA} to its {@code LDA #imm}, never from the state itself, so an unknown-but-present
	 * {@code stateAt} must not stop it.
	 */
	@Test
	public void depthAcrossOneCallWithImmediateValueSurvivesTheCrossing() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a9 ff"); // LDA #$FF   -- clobber
		put("0xc005", "20 20 c0"); // JSR sub
		put("0xc008", "68"); // PLA
		put("0xc009", "8d 00 80"); // STA $8000
		put("0xc020", "60"); // RTS (sub)

		assertBank(5, scanWithStateAvailable("0xc009"));
	}

	/**
	 * 1b. THE SAME PROGRAM on the DIRECT-SITE path -- a real {@link MemoryLatchBankSwitchStrategy}
	 * whose hooks keep the default {@code stateAt} (no oracle) -- must still come back
	 * UNRESOLVED, byte-identical to increment 2. This pins the measured ruling in
	 * {@code resumeStateAfterPairing}: a call-crossing pairing with no state at the push ABANDONS
	 * rather than withdrawing and walking on. Withdrawing here would have let this walk (and the
	 * {@code MirrorProbe} re-run of it) reach loads beyond the push under a state that is unknown
	 * only because we cannot see it, which on ironsword declared a bank-known-on-entry requirement
	 * for a trampoline already proved a no-op and put six violation warnings on its call sites.
	 * Even an IMMEDIATE is forfeited on this path, deliberately: the direct-site strategies are
	 * cacheable and have no oracle to give, and the immediate gain had no measured customer.
	 */
	@Test
	public void directSiteWithNoOracleStillAbandonsAtACall() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a9 ff"); // LDA #$FF   -- clobber
		put("0xc005", "20 20 c0"); // JSR sub
		put("0xc008", "68"); // PLA
		put("0xc009", "8d 00 80"); // STA $8000
		put("0xc020", "60"); // RTS (sub)

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0xc009"),
			BankState.unknown()));
	}

	/**
	 * 6. Nested pairs across calls, depth-correct: {@code LDA #$01 / PHA / JSR sub / LDA #$02 /
	 * PHA / JSR sub / PLA / TAX / PLA / STA $8000}. The discriminating property: a NEAREST-PHA
	 * rule (ignoring depth) would pair the final {@code PLA} to the INNER push (value 2, popped
	 * first by the earlier {@code PLA}/{@code TAX} and discarded) -- but the true match, by stack
	 * depth, is the OUTER push (value 1). Each push/pop pair also crosses its own {@code JSR sub},
	 * so this also exercises that the depth counter stays exact across TWO separate call
	 * crossings, one per pair.
	 */
	@Test
	public void nestedPairsAcrossCallsPairByDepthNotByNearestPush() throws Exception {
		put("0xc000", "a9 01"); // LDA #$01   -- outer value
		put("0xc002", "48"); // PHA        -- outer push
		put("0xc003", "20 20 c0"); // JSR sub    -- crosses the outer span
		put("0xc006", "a9 02"); // LDA #$02   -- inner value
		put("0xc008", "48"); // PHA        -- inner push
		put("0xc009", "20 20 c0"); // JSR sub    -- crosses the inner span
		put("0xc00c", "68"); // PLA        -- inner pop (discarded via TAX)
		put("0xc00d", "aa"); // TAX
		put("0xc00e", "68"); // PLA        -- outer pop
		put("0xc00f", "8d 00 80"); // STA $8000
		put("0xc020", "60"); // RTS (sub)

		assertBank(1, scanWithStateAvailable("0xc00f"));
	}

	/**
	 * 7. Unrelated complete pair between push and pop, across a call (megaman2 {@code cb60}
	 * shape): {@code LDA #$03 / PHA / LDA #$07 / PHA / JSR sub / PLA / JSR sub / PLA / STA
	 * $8000}. The inner pair ({@code PHA 7}/{@code PLA}) balances first, entirely between the
	 * outer {@code PHA} and its own {@code PLA}, with a call crossing on each side -- the outer
	 * {@code PLA} must still land on the outer push (3), not the inner one (7).
	 */
	@Test
	public void unrelatedCompletePairBetweenPushAndPopAcrossACallStillResolvesTheOuterPush()
			throws Exception {
		put("0xc000", "a9 03"); // LDA #$03   -- outer value
		put("0xc002", "48"); // PHA        -- outer push
		put("0xc003", "a9 07"); // LDA #$07   -- inner value
		put("0xc005", "48"); // PHA        -- inner push
		put("0xc006", "20 20 c0"); // JSR sub
		put("0xc009", "68"); // PLA        -- inner pop (discarded, value 7)
		put("0xc00a", "20 20 c0"); // JSR sub
		put("0xc00d", "68"); // PLA        -- outer pop (value 3)
		put("0xc00e", "8d 00 80"); // STA $8000
		put("0xc020", "60"); // RTS (sub)

		assertBank(3, scanWithStateAvailable("0xc00e"));
	}

	/**
	 * 8. A non-call flow in the span still abandons: {@code LDA #$05 / PHA / BNE (self) / PLA /
	 * STA $8000}. Pins that ONLY calls were relaxed by this increment -- an ordinary branch
	 * between the push and the pull still makes the pairing unsound (a different path could have
	 * pushed a different byte) and must still abandon, exactly as before this bead.
	 */
	@Test
	public void nonCallFlowInTheSpanStillAbandons() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "d0 00"); // BNE $c005  -- branches to its own fall-through
		put("0xc005", "68"); // PLA
		put("0xc006", "8d 00 80"); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0xc006"),
			BankState.unknown()));
	}

	// ==================================================================
	// Recovery-level fixtures (HelperArgumentRecovery.recoverCallArgument) -- cases 2, 3, 4, 5
	// ==================================================================

	/**
	 * A minimal {@link BankSwitchStrategy} that deposits {@code argValue} verbatim and captures
	 * whatever {@link RegisterEnv} it is handed -- copied from
	 * {@link CallerSideMirrorHooksProgramTest}'s {@code StubStrategy}.
	 */
	private static final class StubStrategy implements BankSwitchStrategy {

		RegisterEnv captured;
		StoredValueScanner.Hooks callerSideHooksOverride;

		@Override
		public String strategyName() {
			return "call-crossing-probe";
		}

		@Override
		public void configure(ghidra.program.model.listing.Program program, JsonObject params,
				int stateMask) {
			// no configuration needed
		}

		@Override
		public SwitchOutcome computeSwitchOutcome(ghidra.program.model.listing.Program program,
				Instruction instr, BankState inState) {
			return SwitchOutcome.of(BankState.unknown());
		}

		@Override
		public HelperDeposit depositHelperArgument(ghidra.program.model.listing.Program program,
				Instruction switchSite, BankState argValue, BankState inState, int stateMask,
				RegisterEnv callerRegs) {
			this.captured = callerRegs;
			return new HelperDeposit(stateMask, argValue);
		}

		@Override
		public StoredValueScanner.Hooks callerSideHooks() {
			return callerSideHooksOverride == null ? BankSwitchStrategy.super.callerSideHooks()
					: callerSideHooksOverride;
		}
	}

	/**
	 * A {@link StoredValueScanner.Hooks} that answers a mirror load of {@code mirrorAddress} with
	 * {@code inStateAtStore} verbatim, and treats a store to {@code mechanismAddress} as the
	 * mechanism write -- copied from {@link CallerSideMirrorHooksProgramTest}.
	 */
	private static StoredValueScanner.Hooks mirrorHooks(Address mirrorAddress,
			Address mechanismAddress) {
		return new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return instr.getMinAddress().equals(mechanismAddress);
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return null; // scope discipline: caller-side hooks never answer resolveLoad
			}

			@Override
			public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return mirrorAddress.equals(resolvedTarget) ? inStateAtStore : null;
			}
		};
	}

	/** {@code LDA <mirror> / PHA / JSR sub / PLA / JSR helper}, the rcransom fa43 shape. */
	private void layMirrorAcrossCallShape() throws Exception {
		put("0x8000", "a5 10"); // LDA $10    -- mirror read
		put("0x8002", "48"); // PHA
		put("0x8003", "20 00 90"); // JSR sub    ($9000)
		put("0x8006", "68"); // PLA
		put("0x8007", "20 00 91"); // JSR helper ($9100)  <- callInstr
		put("0x9000", "60"); // RTS (sub)
		put("0x9100", "8d 00 e0"); // STA $E000  -- single-instruction helper
	}

	private HelperModel mirrorHelper(BankSwitchStrategy strategy) {
		return new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFF, 0, strategy,
			builder.addr("0x9100"), builder.addr("0x9100"), null);
	}

	/**
	 * 2. The mandatory landmine: a mirror value carried across a call with NO oracle stays
	 * unknown. The six-argument {@code recoverCallArgument} form passes a {@code null} oracle,
	 * so the default {@code stateAt} (always {@code null}) applies -- the call-crossing pairing
	 * must therefore abandon (unknown), NOT resolve against the call site's own in-state (bank
	 * 9), which would be a confidently WRONG answer (the mirror byte was read before the earlier
	 * bank switch, not after it).
	 */
	@Test
	public void mirrorAcrossACallWithNoOracleStaysUnknown() throws Exception {
		layMirrorAcrossCallShape();
		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x10"), builder.addr("0xDEAD"));
		HelperModel helper = mirrorHelper(strategy);

		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8007"), helper, BankState.fullyKnown(0xFF, 9), new HashMap<>(),
			new HashSet<>());

		assertEquals("no oracle -> withdraw, must NOT confidently report bank 9", 0,
			effect.state().knownMask());
	}

	/**
	 * 3. A mirror value carried across a call WITH an oracle resolves from the state AT THE PUSH,
	 * not at the call site. The oracle answers bank 5 at the {@code PHA}'s address and bank 9
	 * everywhere else (matching the call site's own {@code callSiteIn}); the correct recovered
	 * value is 5. Also asserts the oracle was actually consulted about the {@code PHA}'s address,
	 * pinning the specific claim in {@code resumeStateAfterPairing}'s javadoc.
	 */
	@Test
	public void mirrorAcrossACallWithOracleResolvesFromStateAtThePush() throws Exception {
		layMirrorAcrossCallShape();
		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x10"), builder.addr("0xDEAD"));
		HelperModel helper = mirrorHelper(strategy);

		Address phaAddr = builder.addr("0x8002");
		Set<Address> asked = new HashSet<>();
		StateOracle oracle = addr -> {
			asked.add(addr);
			return phaAddr.equals(addr) ? BankState.fullyKnown(0xFF, 5)
					: BankState.fullyKnown(0xFF, 9);
		};

		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8007"), helper, BankState.fullyKnown(0xFF, 9), new HashMap<>(),
			new HashSet<>(), RegisterEnv.NONE, oracle);

		assertEquals("the state at the push (bank 5), not at the call (bank 9)", 0xFF,
			effect.state().knownMask());
		assertEquals(5, effect.state().bits());
		assertTrue("the oracle must be asked about the PHA's own address",
			asked.contains(phaAddr));
	}

	/**
	 * 4. An oracle that answers {@code null} (no state known yet at the push) ABANDONS the
	 * pairing, exactly like the no-oracle case -- {@code resumeStateAfterPairing} treats a
	 * {@code null} answer as "abandon", never as license to fall back to the call site's own
	 * in-state. (In the engine the ask is still recorded as a dependency, so the call is re-asked
	 * once the push's address acquires a state.)
	 */
	@Test
	public void oracleAnsweringNullAbandons() throws Exception {
		layMirrorAcrossCallShape();
		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x10"), builder.addr("0xDEAD"));
		HelperModel helper = mirrorHelper(strategy);

		StateOracle oracle = addr -> null;

		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8007"), helper, BankState.fullyKnown(0xFF, 9), new HashMap<>(),
			new HashSet<>(), RegisterEnv.NONE, oracle);

		assertEquals(0, effect.state().knownMask());
	}

	/**
	 * 5. Memo bypass: two calls at the SAME call site and the SAME {@code callSiteIn}, sharing one
	 * {@code envCache}, but with oracles answering DIFFERENT states at the {@code PHA} (5, then
	 * 6). Both must reflect their own oracle's answer -- if the first call's env were memoized and
	 * served to the second, the second would wrongly see bank 5 again.
	 * <p>
	 * {@link StubStrategy#depositHelperArgument} echoes {@code argValue} (the primary {@code
	 * local} scan) rather than deriving its answer from {@code callerRegs} (the memoized
	 * environment), so the assertion here is on {@code effect.state()} for the "different answers"
	 * half of the claim -- see {@link CallerSideMirrorHooksProgramTest}'s own memo test (case 4,
	 * "two calls at the same address under different in-states") for the sibling case where
	 * {@code callerRegs} is what is inspected. The memo-bypass claim itself (nothing was cached
	 * for an oracle-dependent env) is checked directly against {@code envCache}: the local scan
	 * and the A/X/Y {@code callSiteRegisters} scan share one {@code OracleHooks}, and both cross
	 * the same {@code PHA}/{@code PLA}/call, so {@code callSiteRegisters}'s own consultation count
	 * changes on every call and {@code envCache} is therefore never populated for this call site.
	 */
	@Test
	public void memoIsBypassedForAnOracleDependentEnv() throws Exception {
		layMirrorAcrossCallShape();
		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x10"), builder.addr("0xDEAD"));
		HelperModel helper = mirrorHelper(strategy);
		Address phaAddr = builder.addr("0x8002");

		Map<CallSiteRegKey, RegisterEnv> envCache = new HashMap<>();
		Instruction callInstr = instructionAt("0x8007");

		StateOracle oracleFive = addr -> phaAddr.equals(addr) ? BankState.fullyKnown(0xFF, 5)
				: BankState.fullyKnown(0xFF, 9);
		StateOracle oracleSix = addr -> phaAddr.equals(addr) ? BankState.fullyKnown(0xFF, 6)
				: BankState.fullyKnown(0xFF, 9);

		CallEffect first = HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.fullyKnown(0xFF, 9), envCache, new HashSet<>(), RegisterEnv.NONE,
			oracleFive);
		CallEffect second = HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.fullyKnown(0xFF, 9), envCache, new HashSet<>(), RegisterEnv.NONE, oracleSix);

		assertEquals("first oracle's answer (bank 5) must not leak into the second call", 5,
			first.state().bits());
		assertEquals("the second call must see ITS OWN oracle's answer (bank 6), not a memoized "
				+ "bank 5", 6, second.state().bits());
		assertTrue(
			"an oracle-dependent env must never be memoized -- envCache must stay empty for "
				+ "this call site",
			envCache.isEmpty());
	}

	// ==================================================================
	// Engine-level fixture (BankDataflowEngine.runDataflow) -- case 9
	// ==================================================================

	private Address addr(int a) {
		return builder.addr(String.format("0x%x", a));
	}

	private void putAt(int a, String hex) throws Exception {
		builder.setBytes(String.format("0x%x", a), hex, true);
	}

	private BoardDescriptorModel.BoardModel board4Bit() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "bank", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		return board;
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

	/**
	 * 9. Engine-level dependency edge -- DIRECT verification chosen over a genuine re-enqueue
	 * ordering test (see below for why). The rcransom fa43 / nesmmc3idtest Trampoline shape,
	 * reduced to one field and a real {@link MemoryLatchBankSwitchStrategy}, run through the
	 * production {@link BankDataflowEngine#runDataflow} end to end:
	 *
	 * <pre>
	 * C000  LDA #$01        ; bank 1 known
	 * C002  JSR H16         ; switches to bank 1
	 * C005  LDA $10         ; mirror read -- identifies the CURRENT bank (1), BEFORE the next switch
	 * C007  PHA
	 * C008  LDA #$02
	 * C00A  JSR H16         ; switches to bank 2
	 * C00D  JSR farCall     ; an unrelated call, crossed by the pairing search below
	 * C010  PLA
	 * C011  JSR H16         ; must resolve against the state AT C007 (bank 1), not at C011 (bank 2)
	 * C014  RTS
	 * </pre>
	 *
	 * H16 is a real caller-supplied-argument helper (a bare {@code STA $9000} over the shared
	 * memory-latch mechanism); the mirror at {@code $10} is wired through
	 * {@code MemoryLatchBankSwitchStrategy.observeMirrors}, exactly as production code discovers
	 * it. The call at {@code C011} must resolve to bank 1 (the correct, pre-switch bank), not bank
	 * 2 (the confidently wrong "state at the call" answer this bead's landmine tests guard
	 * against) and not unknown (the honest-but-useless withdrawal this bead improves on).
	 * <p>
	 * <b>Why this, and not a genuine re-enqueue-ordering test.</b> {@code stateDependents}'
	 * re-enqueue path only matters when the call site is FIRST evaluated before the push's state
	 * is known. In a straight-line trampoline like this one, the worklist processes addresses in
	 * program order on the first pass, so {@code C007}'s state is already recorded by the time
	 * {@code C011} is first dequeued -- this test cannot, by construction, distinguish "resolved
	 * on the first evaluation" from "resolved only after a re-enqueue". Constructing a
	 * {@code ProgramBuilder} fixture that forces the OPPOSITE dequeue order (so the call site
	 * really is evaluated once with no state at the push, then must be re-evaluated) would need
	 * either a hand-controlled worklist or a loop shape subtle enough to risk pinning
	 * fixpoint-scheduling behavior rather than the claim itself; that did not converge inside this
	 * task's time budget. The end-to-end claim this test DOES pin -- that the resolved answer at
	 * the end of the fixpoint is correct -- is what {@code build-and-test.sh}'s
	 * {@code nesmmc3idtest} golden (task B) also exercises on the real fixture, so the ordering
	 * mechanism itself is exercised there even though this JUnit test does not isolate it.
	 */
	@Test(timeout = 30000)
	public void engineResolvesCallCrossingMirrorAgainstStateAtThePush() throws Exception {
		putAt(0xC000, "a9 01"); // LDA #$01
		putAt(0xC002, "20 30 c0"); // JSR H16   ($C030)
		putAt(0xC005, "a5 10"); // LDA $10   -- mirror read (pre-switch bank)
		putAt(0xC007, "48"); // PHA
		putAt(0xC008, "a9 02"); // LDA #$02
		putAt(0xC00A, "20 30 c0"); // JSR H16   -- switches to bank 2
		putAt(0xC00D, "20 40 c0"); // JSR farCall
		putAt(0xC010, "68"); // PLA
		putAt(0xC011, "20 30 c0"); // JSR H16   <- must resolve to bank 1
		putAt(0xC014, "60"); // RTS
		putAt(0xC030, "8d 00 90"); // STA $9000 (H16)
		putAt(0xC033, "60"); // RTS
		putAt(0xC040, "60"); // RTS (farCall)

		makeFunction(0xC000, 0xC014, "RESET");
		makeFunction(0xC030, 0xC033, "H16");

		BoardDescriptorModel.BoardModel board = board4Bit();
		MemoryLatchBankSwitchStrategy latch = new MemoryLatchBankSwitchStrategy();
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9100);
		params.addProperty("mask", board.mask());
		latch.configure(program, params, board.mask());
		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		latch.observeMirrors(
			BankMirrors.of(baseSpace, Map.of(0x10L, Set.of(BankMirrors.Kind.ROM_IDENTIFYING))));

		BankStrategyRegistry.ConfiguredMechanism mechanism =
			new BankStrategyRegistry.ConfiguredMechanism(latch, board.mask(), 0);

		Function h16 = program.getFunctionManager().getFunctionAt(addr(0xC030));
		assertNotNull(h16);
		HelperModel helper = new HelperModel(h16, addr(0xC030), null, 'A', board.mask(), 0, latch,
			addr(0xC030), addr(0xC030), null);

		BankDataflowEngine.DataflowResult result = BankDataflowEngine.runDataflow(program,
			TaskMonitor.DUMMY, program.getListing(), List.of(mechanism), board,
			Map.of(h16, helper), Set.of());

		BankDataflowEngine.CallSwitch callSwitch = result.callSwitches().get(addr(0xC011));
		assertNotNull("the final JSR H16 must be recognized as a resolved call switch",
			callSwitch);
		assertTrue("the call argument must resolve", callSwitch.argumentResolved());
		assertEquals("must resolve to bank 1 (the state AT the push), not bank 2 (the call's own "
				+ "in-state) or unknown", 0x0F & board.mask(), callSwitch.effect().knownMask());
		assertEquals(1, callSwitch.effect().bits());
	}
}
