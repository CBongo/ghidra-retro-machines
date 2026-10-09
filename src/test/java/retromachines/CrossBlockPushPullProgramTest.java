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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

/**
 * {@code ProgramBuilder} coverage of bead grm-mej.3 increment X1, "cross-block PHA/PLA pairing":
 * {@link StoredValueScanner#crossBlockMatchingPush}, a bounded backward ALL-PATHS search used as
 * a fallback ONLY where {@link StoredValueScanner#findMatchingPush}'s straight-line walk gives up
 * on a flow break -- a control-flow join (a loop, a diamond) between the {@code PHA} and its
 * {@code PLA}. Modelled on {@link CallCrossingPushPullProgramTest} (increment 3, the identical
 * shape for a CALL crossing rather than a control-flow join), whose scanner-level fixtures this
 * class's {@code STATE_AVAILABLE_ORACLE_HOOKS} pattern is copied from.
 * <p>
 * Every fixture below was traced by hand against the production algorithm before being written
 * down (recursive descent with per-address depth memoization, join forking, and the
 * {@code CrossBlockAbandon} sentinel) -- see the design comment on {@code bd show grm-mej.3}'s
 * 2026-09-27 entries for the megaman2 {@code cb60} and contra {@code c0d3} ROM shapes these
 * fixtures are reduced from.
 */
public class CrossBlockPushPullProgramTest extends AbstractBundledLanguageTest {

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

	private void assertBank(int expected, PartialByte actual) {
		assertEquals("tracked bits not fully known: " + actual, 0xFF, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	private void assertUnresolved(PartialByte actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
	}

	/**
	 * Hooks with a state AVAILABLE at every address (wholly unknown, but non-null) AND a state
	 * oracle -- {@link StoredValueScanner.Hooks#hasStateOracle} true, which is what gates
	 * {@link StoredValueScanner#crossBlockMatchingPush} into running at all. No per-run memo, so
	 * every call recomputes the proof fresh -- fine for these single-scan fixtures.
	 */
	private static final StoredValueScanner.Hooks ORACLE_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				MechanismState inStateAtStore) {
			return null;
		}

		@Override
		public MechanismState stateAt(Address addr) {
			return MechanismState.unknown();
		}

		@Override
		public boolean hasStateOracle() {
			return true;
		}
	};

	/** {@link #ORACLE_HOOKS} plus a KIND answer for one mirror address, for the RESTORED_BANK
	 *  fixtures (megaman2 {@code cb60}'s shape: an unmodified read-back of a live mirror). */
	private static StoredValueScanner.Hooks oracleHooksWithMirror(Address mirror) {
		return new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
					MechanismState inStateAtStore) {
				return null;
			}

			@Override
			public MechanismState stateAt(Address addr) {
				return MechanismState.unknown();
			}

			@Override
			public boolean hasStateOracle() {
				return true;
			}

			@Override
			public boolean isLiveBankMirror(Address target) {
				return mirror.equals(target);
			}
		};
	}

	/** The scanner on a direct {@code STA} site under {@code hooks}. */
	private StoredValueScanner.Scan scan(String storeAddress, StoredValueScanner.Hooks hooks) {
		return StoredValueScanner.resolveStoredValueScan(program, instructionAt(storeAddress), 'A',
			MechanismState.unknown(), 0xFF, hooks, RegisterEnv.NONE);
	}

	// ==================================================================
	// 1. Loop shape (megaman2 cb60), mirror push -> RESTORED
	// ==================================================================

	/**
	 * {@code LDA $10 / PHA / LDY #$02 / [loop head: NOP / DEY / BPL loop head] / PLA / STA
	 * $8000}: the {@code PHA} and its {@code PLA} are split by a real loop, whose head is a
	 * control-flow join (fall-through entry, branch-back edge) -- the same class as megaman2's
	 * {@code cb60} (~40 instructions cb5f back to cb15 there; a two-instruction loop body here).
	 * {@code findMatchingPush} abandons at the {@code BPL} (a non-call flow in the span); the
	 * cross-block search steps over the loop (net stack effect zero) and finds the outer
	 * {@code PHA}, whose own predecessor is an unmodified read of a live bank mirror -- the
	 * caller-side RESTORE shape (bead grm-yflf), reported here across a control-flow span rather
	 * than a call.
	 */
	@Test
	public void loopWithMirrorPushRestores() throws Exception {
		put("0xc000", "a5 10"); // LDA $10   -- mirror read
		put("0xc002", "48"); // PHA
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP        -- loop head (join)
		put("0xc006", "88"); // DEY
		put("0xc007", "10 fc"); // BPL $c005  (c009 + (-4) = c005)
		put("0xc009", "68"); // PLA
		put("0xc00a", "8d 00 80"); // STA $8000

		StoredValueScanner.Scan scan = scan("0xc00a", oracleHooksWithMirror(builder.addr("0x10")));
		assertEquals(BankSwitchStrategy.ValueStop.RESTORED_BANK, scan.stop());
		assertNotNull("a RESTORED_BANK stop must carry a ReadBack", scan.readBack());
		assertEquals(builder.addr("0x10"), scan.readBack().cell());
		assertEquals(builder.addr("0xc000"), scan.readBack().readAt());
		assertEquals("a pure block crossing carries no call detail", null,
			scan.readBack().carriedAcross());
		assertEquals("the push half of the crossed span", builder.addr("0xc002"),
			scan.readBack().crossBlockPush());
		assertEquals("the pull half of the crossed span", builder.addr("0xc009"),
			scan.readBack().crossBlockPull());
	}

	// ==================================================================
	// 2. Loop shape, immediate push -> resolves
	// ==================================================================

	/** The same loop shape, with an ordinary immediate value rather than a mirror: confirms the
	 *  cross-block search's own resumed walk (from the found {@code PHA} backward to its
	 *  {@code LDA #imm}) resolves a plain value, not only a restore. */
	@Test
	public void loopWithImmediatePushResolves() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP        -- loop head (join)
		put("0xc006", "88"); // DEY
		put("0xc007", "10 fc"); // BPL $c005
		put("0xc009", "68"); // PLA
		put("0xc00a", "8d 00 80"); // STA $8000

		assertBank(5, scan("0xc00a", ORACLE_HOOKS).value());
	}

	// ==================================================================
	// 3. Contra-style diamond on A -> pairs
	// ==================================================================

	/**
	 * A single {@code PHA}, then a conditional branch into one of two call-bearing arms that
	 * reconverge at the {@code PLA} itself -- so the {@code PLA}'s OWN address is the join,
	 * exactly like contra's real {@code c0d1} (there on register Y; here on A, in scope for X1).
	 * Each arm crosses a DIFFERENT call, so the pairing still succeeds (both arms agree on the
	 * same {@code PHA}) but {@code ReadBack.carriedAcross} would be null were this a restore --
	 * pinned separately by the disagreement not aborting resolution here, since the value itself
	 * comes from the immediate before the push, not from either call.
	 */
	@Test
	public void contraStyleDiamondOnAPairs() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05        -- the value
		put("0xc002", "48"); // PHA
		put("0xc003", "a5 20"); // LDA $20         -- decide
		put("0xc005", "f0 06"); // BEQ $c00d        (c007 + 6 = c00d, arm B entry)
		put("0xc007", "20 30 c0"); // JSR $c030       -- arm A helper
		put("0xc00a", "4c 10 c0"); // JMP $c010       -- arm A: skip arm B, go straight to join
		put("0xc00d", "20 40 c0"); // JSR $c040       -- arm B helper (falls through to join)
		put("0xc010", "68"); // PLA             -- the join
		put("0xc011", "8d 00 80"); // STA $8000
		put("0xc030", "60"); // RTS (helper 1)
		put("0xc040", "60"); // RTS (helper 2)

		assertBank(5, scan("0xc011", ORACLE_HOOKS).value());
	}

	// ==================================================================
	// 4. Nested pair across a block, depth-correct
	// ==================================================================

	/**
	 * An inner, COMPLETE {@code PHA}/{@code PLA} pair sits entirely inside the loop body, between
	 * the outer push and the loop head -- the depth counter must balance it out before crossing
	 * the join, exactly as {@code findMatchingPush}'s own "nested pairs" case (increment 3's case
	 * 6) requires within one block.
	 */
	@Test
	public void nestedPairAcrossABlockDepthCorrect() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05        -- outer value
		put("0xc002", "48"); // PHA             -- outer push
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP             -- loop head (join)
		put("0xc006", "a9 07"); // LDA #$07        -- inner value (discarded)
		put("0xc008", "48"); // PHA             -- inner push
		put("0xc009", "68"); // PLA             -- inner pop, balances before the join
		put("0xc00a", "88"); // DEY
		put("0xc00b", "10 f8"); // BPL $c005
		put("0xc00d", "68"); // PLA             -- outer pop
		put("0xc00e", "8d 00 80"); // STA $8000

		assertBank(5, scan("0xc00e", ORACLE_HOOKS).value());
	}

	// ==================================================================
	// 5. Traps -- all must come back unknown (today's ANALYZER_LIMIT)
	// ==================================================================

	/** Two DIFFERENT push sites, one per arm of a diamond that reconverges at the {@code PLA}:
	 *  the arms disagree on which {@code PHA} the pop matches, so the whole proof abandons. */
	@Test
	public void differentPushSitesPerArmStaysUnknown() throws Exception {
		put("0xc000", "a5 20"); // LDA $20      -- decide
		put("0xc002", "f0 06"); // BEQ $c00a     (c004 + 6 = c00a, arm B)
		put("0xc004", "a9 01"); // LDA #$01     -- arm A's OWN value
		put("0xc006", "48"); // PHA          -- arm A's OWN push
		put("0xc007", "4c 0d c0"); // JMP $c00d    -- skip arm B, land on its fall-through
		put("0xc00a", "a9 02"); // LDA #$02     -- arm B's OWN value
		put("0xc00c", "48"); // PHA          -- arm B's OWN push (DIFFERENT site)
		put("0xc00d", "68"); // PLA          -- the join (arm B's natural fall-through)
		put("0xc00e", "8d 00 80"); // STA $8000

		assertUnresolved(scan("0xc00e", ORACLE_HOOKS).value());
	}

	/**
	 * A loop whose body pushes without a matching pop (net stack effect nonzero per iteration):
	 * going around the back edge revisits the loop head at a DIFFERENT owed depth than the
	 * fall-through entry established, which the depth-mismatch guard catches and abandons on --
	 * the same soundness rule "depth mismatch at a join" names.
	 */
	@Test
	public void loopWithNetPushStaysUnknown() throws Exception {
		put("0xc000", "48"); // PHA               -- the outer target push
		put("0xc001", "a0 02"); // LDY #$02
		put("0xc003", "ea"); // NOP               -- loop head (join)
		put("0xc004", "48"); // PHA               -- UNBALANCED extra push
		put("0xc005", "88"); // DEY
		put("0xc006", "10 fb"); // BPL $c003          (c008 + (-5) = c003)
		put("0xc008", "68"); // PLA               -- nested pop (bumps owed depth to 2)
		put("0xc009", "68"); // PLA               -- the site's own pop
		put("0xc00a", "8d 00 80"); // STA $8000

		assertUnresolved(scan("0xc00a", ORACLE_HOOKS).value());
	}

	/** A {@code TXS} on one arm of a diamond -- a stack-pointer write that is not a crossed call
	 *  -- abandons, exactly as it would for a straight-line pairing. */
	@Test
	public void txsOnOneArmStaysUnknown() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a5 20"); // LDA $20        -- decide
		put("0xc005", "f0 04"); // BEQ $c00b       (c007 + 4 = c00b, arm B)
		put("0xc007", "9a"); // TXS            -- arm A: stack pointer moves under us
		put("0xc008", "4c 0c c0"); // JMP $c00c
		put("0xc00b", "ea"); // NOP            -- arm B: nothing
		put("0xc00c", "68"); // PLA            -- the join
		put("0xc00d", "8d 00 80"); // STA $8000

		assertUnresolved(scan("0xc00d", ORACLE_HOOKS).value());
	}

	/**
	 * The block containing one of the loop head's predecessor edges is a FUNCTION ENTRY --
	 * entered by callers, not a control-flow edge this proof can account for -- so
	 * {@code closedWorldPredecessors} refuses to enumerate it and the whole search abandons.
	 */
	@Test
	public void functionEntryInSpanStaysUnknown() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP        -- loop head, ABOUT TO BE a function entry
		put("0xc006", "88"); // DEY
		put("0xc007", "10 fc"); // BPL $c005
		put("0xc009", "68"); // PLA
		put("0xc00a", "8d 00 80"); // STA $8000

		int tx = program.startTransaction("mark loop head a function entry");
		try {
			Address head = builder.addr("0xc005");
			program.getFunctionManager()
				.createFunction("loopHead", head, new AddressSet(head, head), SourceType.ANALYSIS);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertUnresolved(scan("0xc00a", ORACLE_HOOKS).value());
	}

	/**
	 * A CALL reference into the loop head -- code elsewhere reaches this address as if calling
	 * it, which no depth or state proof below can account for -- so the whole search abandons,
	 * exactly like a function entry.
	 */
	@Test
	public void callRefIntoSpanStaysUnknown() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP        -- loop head
		put("0xc006", "88"); // DEY
		put("0xc007", "10 fc"); // BPL $c005
		put("0xc009", "68"); // PLA
		put("0xc00a", "8d 00 80"); // STA $8000
		put("0xc020", "60"); // RTS -- a dummy call source

		int tx = program.startTransaction("add a call reference into the span");
		try {
			program.getReferenceManager().addMemoryReference(builder.addr("0xc020"),
				builder.addr("0xc005"), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertUnresolved(scan("0xc00a", ORACLE_HOOKS).value());
	}

	// ==================================================================
	// 6. No oracle -> today's answer exactly
	// ==================================================================

	/** Direct-site hooks (no state oracle) on the SAME loop shape as case 2: the fallback never
	 *  runs, so the pairing declines byte-identically to before this increment. */
	@Test
	public void directSiteWithNoOracleStaysAtTodaysAnswer() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP
		put("0xc006", "88"); // DEY
		put("0xc007", "10 fc"); // BPL $c005
		put("0xc009", "68"); // PLA
		put("0xc00a", "8d 00 80"); // STA $8000

		StoredValueScanner.Hooks noOracle = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
					MechanismState inStateAtStore) {
				return null;
			}
		};
		assertUnresolved(scan("0xc00a", noOracle).value());
	}

	// ==================================================================
	// 7. Budget: over 16 instructions resolves; the search's own 384-node cap is pinned exactly
	// ==================================================================

	/**
	 * Builds {@code LDA #$05 / PHA / NOP * nopCount / BEQ +0 (self-targeting) / PLA / STA $8000}
	 * at {@code 0xc000} and returns the {@code STA}'s address (as a hex string for {@link #put}/
	 * {@link #scan}). The self-targeting branch forces {@code findMatchingPush}'s straight-line
	 * abandon (see {@code nonCallFlowInTheSpanStillAbandons}-style reasoning) WITHOUT creating a
	 * real join, isolating the node-budget claim from the join machinery.
	 */
	private String buildNopChain(int nopCount) throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		for (int i = 0; i < nopCount; i++) {
			put(String.format("0x%x", 0xc003 + i), "ea"); // NOP padding
		}
		int beqAddr = 0xc003 + nopCount;
		put(String.format("0x%x", beqAddr), "f0 00"); // BEQ +0 (targets its own fall-through)
		int plaAddr = beqAddr + 2;
		put(String.format("0x%x", plaAddr), "68"); // PLA
		int staAddr = plaAddr + 1;
		put(String.format("0x%x", staAddr), "8d 00 80"); // STA $8000
		return String.format("0x%x", staAddr);
	}

	/**
	 * PINS THE EXACT NODE-BUDGET BOUNDARY (bead grm-mej.3 X1 follow-up: the double-charge fix).
	 * {@link StoredValueScanner.CrossBlockSearch#spend()} is called exactly once per node visited:
	 * once when the search enters {@code plaAddr} itself (the seed), once for every OTHER
	 * predecessor address it enters (the self-targeting {@code BEQ}, then each padding
	 * {@code NOP}), and once more, directly, for the terminal {@code PHA} (never itself recursed
	 * into, so it has no other entry point to charge it). For {@code nopCount} padding
	 * instructions that is {@code 1 (seed) + 1 (BEQ) + nopCount + 1 (terminal PHA)} spends, i.e.
	 * {@code nopCount + 3}. {@link StoredValueScanner#CROSS_BLOCK_NODE_CAP} is 384 (64 until the
	 * owner's 2026-10-03 approval, grm-mej.7), and {@code spend()} throws on the spend that would
	 * take the budget negative -- so exactly 384 spends succeed and the 385th fails:
	 * {@code nopCount = 381} (384 spends) resolves, {@code nopCount = 382} (385 spends) declines. This is the SAME shape as
	 * {@code spanOverSixteenInstructionsStillResolves} below, just at the exact boundary instead
	 * of comfortably under it.
	 */
	@Test
	public void nodeBudgetBoundaryIsExactlyTheCapNotHalfIt() throws Exception {
		String resolves = buildNopChain(381);
		assertBank(5, scan(resolves, ORACLE_HOOKS).value());
	}

	/** One spend past {@link #nodeBudgetBoundaryIsExactlyTheCapNotHalfIt}'s boundary: 385
	 *  spends, declines. Regression guard for the double-charge bug this fixes, which made a
	 *  genuine 64-node span fail at ~32 under the original cap. */
	@Test
	public void nodeBudgetBoundaryPlusOneDeclines() throws Exception {
		String declines = buildNopChain(382);
		assertUnresolved(scan(declines, ORACLE_HOOKS).value());
	}

	/** A span of ~19 instructions (well past {@code MAX_BACKWARD_SCAN}=16) still resolves,
	 *  because the cross-block search has its OWN 384-node budget and the enclosing walk is
	 *  charged only ONE step for the whole fallback attempt (OWNER RULING Q1). Comfortably under
	 *  the exact boundary {@link #nodeBudgetBoundaryIsExactlyTheCapNotHalfIt} pins. */
	@Test
	public void spanOverSixteenInstructionsStillResolves() throws Exception {
		String site = buildNopChain(18);
		assertBank(5, scan(site, ORACLE_HOOKS).value());
	}

	/** The same shape, padded well past the search's own 384-node cap: declines rather than
	 *  resolving. */
	@Test
	public void spanOverTheSearchsOwnCapDeclines() throws Exception {
		String site = buildNopChain(420);
		assertUnresolved(scan(site, ORACLE_HOOKS).value());
	}

	// ==================================================================
	// 8. Per-run proof memo
	// ==================================================================

	/** Two direct scans of the SAME {@code PLA}, sharing one {@code crossBlockProofMemo}: the
	 *  second must see the memoized proof (same answer) without recomputing -- a functional
	 *  check standing in for the memo's performance claim, which a scanner-level test cannot
	 *  observe directly. */
	@Test
	public void crossBlockProofIsMemoizedPerPla() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "48"); // PHA
		put("0xc003", "a0 02"); // LDY #$02
		put("0xc005", "ea"); // NOP
		put("0xc006", "88"); // DEY
		put("0xc007", "10 fc"); // BPL $c005
		put("0xc009", "68"); // PLA
		put("0xc00a", "8d 00 80"); // STA $8000

		Map<Address, StoredValueScanner.CrossBlockProof> memo = new HashMap<>();
		StoredValueScanner.Hooks memoHooks = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
					MechanismState inStateAtStore) {
				return null;
			}

			@Override
			public MechanismState stateAt(Address addr) {
				return MechanismState.unknown();
			}

			@Override
			public boolean hasStateOracle() {
				return true;
			}

			@Override
			public Map<Address, StoredValueScanner.CrossBlockProof> crossBlockProofMemo() {
				return memo;
			}
		};

		assertBank(5, scan("0xc00a", memoHooks).value());
		assertEquals("the proof must be memoized against the PLA's address", 1, memo.size());
		StoredValueScanner.CrossBlockProof cached = memo.get(builder.addr("0xc009"));
		assertNotNull(cached);
		assertEquals(builder.addr("0xc002"), cached.pha());

		// A second scan reuses the SAME memoized proof rather than recomputing.
		assertBank(5, scan("0xc00a", memoHooks).value());
		assertEquals(1, memo.size());
	}
}
