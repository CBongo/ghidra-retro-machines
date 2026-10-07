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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * {@code ProgramBuilder} coverage of bead grm-zsxz increment Z2, RAM SAVE-SLOT forwarding across
 * calls and joins: {@code StoredValueScanner.saveSlotForwarded}, the RAM-slot model in X1's
 * backward all-paths skeleton (see {@link CrossBlockPushPullProgramTest} for the stack-slot
 * model). The shape is Blaster Master's {@code FUN_e9b8}: {@code LDA $DB / STA $D3 / JSR ... /
 * LDA $D3 / <switch>}, reduced here to a direct {@code STA $8000} site scanned under hooks that
 * carry a state oracle.
 */
public class CrossCallSaveSlotProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		int tx = program.startTransaction("set block write permission");
		try {
			zp.setWrite(true);
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

	private void assertBank(int expected, BankState actual) {
		assertEquals("tracked bits not fully known: " + actual, 0xFF, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	private void assertDeclined(StoredValueScanner.Scan scan) {
		assertEquals("expected no tracked bit pinned down, got " + scan.value(), 0,
			scan.value().knownMask());
		assertEquals("a declined proof must leave today's ANALYZER_LIMIT stop",
			BankSwitchStrategy.ValueStop.ANALYZER_LIMIT, scan.stop());
	}

	/** Oracle hooks: a (wholly unknown, non-null) state everywhere, a state oracle, and $DB as
	 *  the one live-bank mirror. */
	private static StoredValueScanner.Hooks oracleHooks(Address mirror, boolean stateAvailable) {
		return new StoredValueScanner.Hooks() {
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
				return stateAvailable ? BankState.unknown() : null;
			}

			@Override
			public boolean hasStateOracle() {
				return true;
			}

			@Override
			public boolean isLiveBankMirror(Address target) {
				return mirror != null && mirror.equals(target);
			}
		};
	}

	private StoredValueScanner.Hooks oracle() {
		return oracleHooks(builder.addr("0xdb"), true);
	}

	private StoredValueScanner.Scan scan(String storeAddress, StoredValueScanner.Hooks hooks) {
		return StoredValueScanner.resolveStoredValueScan(program, instructionAt(storeAddress), 'A',
			BankState.unknown(), 0xFF, hooks, RegisterEnv.NONE);
	}

	/** {@code <source> / STA $D3 / JSR $C040 / LDA $D3 / STA $8000}; returns the site. */
	private String saveCallRestore(String sourceHex) throws Exception {
		put("0xc000", sourceHex); // 2-byte source: LDA $DB or LDA #imm
		put("0xc002", "85 d3"); // STA $D3      -- the save
		put("0xc004", "20 40 c0"); // JSR $C040
		put("0xc007", "a5 d3"); // LDA $D3      -- the reload
		put("0xc009", "8d 00 80"); // STA $8000
		return "0xc009";
	}

	// ==================================================================
	// 1. Straight-line save / call / restore, non-writing callee
	// ==================================================================

	/** The blmaster shape: a mirror read saved into $D3, a call that writes only $10, the reload
	 *  -> RESTORED_BANK, with the read-back naming $DB and the carrier naming $D3. */
	@Test
	public void saveCallRestoreOfMirrorIsRestored() throws Exception {
		String site = saveCallRestore("a5 db"); // LDA $DB
		put("0xc040", "a9 01"); // LDA #$01
		put("0xc042", "85 10"); // STA $10    -- a different cell
		put("0xc044", "60"); // RTS

		StoredValueScanner.Scan scan = scan(site, oracle());
		assertEquals(BankSwitchStrategy.ValueStop.RESTORED_BANK, scan.stop());
		StoredValueScanner.ReadBack rb = scan.readBack();
		assertNotNull(rb);
		assertEquals(builder.addr("0xdb"), rb.cell());
		assertEquals(builder.addr("0xc000"), rb.readAt());
		assertNotNull("the save slot must be recorded as the carrier", rb.slot());
		assertEquals(builder.addr("0xd3"), rb.slot().cell());
		assertEquals(builder.addr("0xc002"), rb.slot().store());
		assertEquals(builder.addr("0xc007"), rb.slot().load());
		assertFalse(rb.slot().indirectStoresAssumed());
	}

	/** The same shape with an immediate source: resolves to the number. */
	@Test
	public void saveCallRestoreOfImmediateResolves() throws Exception {
		String site = saveCallRestore("a9 05"); // LDA #$05
		put("0xc040", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	/** A transitive callee chain, none writing the slot: still resolves. */
	@Test
	public void transitiveCleanCalleesResolve() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "20 50 c0"); // JSR $C050
		put("0xc043", "60"); // RTS
		put("0xc050", "e6 10"); // INC $10    -- a different cell
		put("0xc052", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	// ==================================================================
	// 2. A writer in the callee closure -> declines
	// ==================================================================

	@Test
	public void calleeStoringTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "85 d3"); // STA $D3    -- the callee overwrites the slot
		put("0xc042", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	@Test
	public void transitiveCalleeWritingTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "20 50 c0"); // JSR $C050
		put("0xc043", "60"); // RTS
		put("0xc050", "e6 d3"); // INC $D3    -- two levels down
		put("0xc052", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** An absolute-indexed store whose reachable window ($00C0..$01BF) covers $D3 is a writer. */
	@Test
	public void indexedStoreCoveringTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "9d c0 00"); // STA $00C0,X
		put("0xc043", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** ... but one whose window misses it is not. */
	@Test
	public void indexedStoreMissingTheSlotResolves() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "9d 00 03"); // STA $0300,X -- $0300..$03FF
		put("0xc043", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	/** blmaster ea3a's shape: {@code LDX #$7A / STA $00,X / STA $01,X} writes exactly $7A/$7B,
	 *  provably not $D3 -- the constant index pins the cell. */
	@Test
	public void constantIndexZeroPageStoreMissingTheSlotResolves() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 7a"); // LDX #$7A
		put("0xc042", "95 00"); // STA $00,X  -> $7A
		put("0xc044", "95 01"); // STA $01,X  -> $7B
		put("0xc046", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	/** The same constant-index form aimed AT the slot is a writer. */
	@Test
	public void constantIndexZeroPageStoreHittingTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 d3"); // LDX #$D3
		put("0xc042", "95 00"); // STA $00,X  -> $D3
		put("0xc044", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** Zero-page wrap: {@code $FF,X} with X=$D4 writes ($FF+$D4) mod $100 = $D3. */
	@Test
	public void constantIndexWrapsInsidePageZeroOntoTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 d4"); // LDX #$D4
		put("0xc042", "95 ff"); // STA $FF,X  -> $D3 (wraps)
		put("0xc044", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** ... and with X=$01 it wraps to $00, missing the slot. */
	@Test
	public void constantIndexWrapMissingTheSlotResolves() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 01"); // LDX #$01
		put("0xc042", "95 ff"); // STA $FF,X  -> $00 (wraps)
		put("0xc044", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	/** Absolute indexed with a constant Y aimed at the slot: {@code $00CE+5 = $00D3}. */
	@Test
	public void constantIndexAbsoluteStoreHittingTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a0 05"); // LDY #$05
		put("0xc042", "99 ce 00"); // STA $00CE,Y -> $00D3
		put("0xc045", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** X redefined from memory between the constant and the store: not provable -> the
	 *  conservative any-zero-page rule applies and the proof declines. */
	@Test
	public void indexRedefinedBetweenDefinitionAndStoreIsConservative() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 7a"); // LDX #$7A
		put("0xc042", "a6 20"); // LDX $20     -- X now unknown
		put("0xc044", "95 00"); // STA $00,X
		put("0xc046", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** A call between the constant and the store that clobbers X: conservative. (A callee that
	 *  provably preserves X -- a bare {@code RTS} -- no longer counts, since grm-mej.13.) */
	@Test
	public void indexClobberedByACallIsConservative() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 7a"); // LDX #$7A
		put("0xc042", "20 60 c0"); // JSR $C060
		put("0xc045", "95 00"); // STA $00,X
		put("0xc047", "60"); // RTS
		put("0xc060", "a6 20"); // LDX $20  -- the callee clobbers X
		put("0xc062", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** X set on only one arm of a join: not a constant at the store -> conservative. */
	@Test
	public void indexAcrossAJoinIsConservative() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a5 21"); // LDA $21
		put("0xc042", "f0 02"); // BEQ $C046
		put("0xc044", "a2 7a"); // LDX #$7A
		put("0xc046", "95 00"); // STA $00,X  -- join: X is $7A or the caller's
		put("0xc048", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** blmaster e6fe/ce02 (bead grm-mej.15): {@code LDX #$1F / LDA #0 / L: STA $58,X / DEX /
	 *  BPL L} writes exactly $58..$77, so a callee holding it does not write $D3. */
	@Test
	public void countedLoopMissingTheSlotResolves() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 1f"); // LDX #$1F
		put("0xc042", "a9 00"); // LDA #0
		put("0xc044", "95 58"); // L: STA $58,X
		put("0xc046", "ca"); // DEX
		put("0xc047", "10 fb"); // BPL L
		put("0xc049", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	/** blmaster e8d8's shape: {@code LDX #1 / L: STA $F5,X / DEX / BPL L} -- $F5..$F6. */
	@Test
	public void shortCountedLoopMissingTheSlotResolves() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 01"); // LDX #1
		put("0xc042", "95 f5"); // L: STA $F5,X
		put("0xc044", "ca"); // DEX
		put("0xc045", "10 fb"); // BPL L
		put("0xc047", "60"); // RTS
		assertBank(5, scan(site, oracle()).value());
	}

	/** The same loop whose window covers the slot ($C0..$DF) is a writer. */
	@Test
	public void countedLoopCoveringTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 1f"); // LDX #$1F
		put("0xc042", "95 c0"); // L: STA $C0,X  -> $C0..$DF
		put("0xc044", "ca"); // DEX
		put("0xc045", "10 fb"); // BPL L
		put("0xc047", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** A counted loop whose zero-page window wraps onto the slot: $E0,X for X in 0..$F3 reaches
	 *  ($E0+$F3) mod $100 = $D3. */
	@Test
	public void countedLoopWrappingOntoTheSlotDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a2 f3"); // LDX #$F3
		put("0xc042", "95 e0"); // L: STA $E0,X
		put("0xc044", "ca"); // DEX
		put("0xc045", "d0 fb"); // BNE L  -> X in 1..$F3
		put("0xc047", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	/** A loop the recognizer cannot bound (unknown seed) keeps the any-zero-page rule. */
	@Test
	public void unboundedLoopIsConservative() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a6 20"); // LDX $20
		put("0xc042", "95 58"); // L: STA $58,X
		put("0xc044", "ca"); // DEX
		put("0xc045", "10 fb"); // BPL L
		put("0xc047", "60"); // RTS
		assertDeclined(scan(site, oracle()));
	}

	// ==================================================================
	// 3. An unresolvable callee closure -> declines
	// ==================================================================

	@Test
	public void indirectJumpInCalleeDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "6c 20 00"); // JMP ($0020)
		assertDeclined(scan(site, oracle()));
	}

	/** A push-then-return dispatch hides its targets from the listing. */
	@Test
	public void returnDispatchInCalleeDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "a9 c0"); // LDA #$C0
		put("0xc042", "48"); // PHA
		put("0xc043", "a9 5f"); // LDA #$5F
		put("0xc045", "48"); // PHA
		put("0xc046", "60"); // RTS        -- "returns" to $C060
		assertDeclined(scan(site, oracle()));
	}

	// ==================================================================
	// 4. The named assumption: an indirect store is not a writer
	// ==================================================================

	@Test
	public void indirectStoreInCalleeResolvesUnderTheNamedAssumption() throws Exception {
		String site = saveCallRestore("a5 db"); // LDA $DB
		put("0xc040", "a0 00"); // LDY #$00
		put("0xc042", "91 20"); // STA ($20),Y -- INDIRECT_STORES_DO_NOT_WRITE_SLOT
		put("0xc044", "60"); // RTS

		StoredValueScanner.Scan scan = scan(site, oracle());
		assertEquals(BankSwitchStrategy.ValueStop.RESTORED_BANK, scan.stop());
		assertNotNull(scan.readBack().slot());
		assertTrue("the proof relied on the named assumption and must say so",
			scan.readBack().slot().indirectStoresAssumed());
	}

	// ==================================================================
	// 5. Joins
	// ==================================================================

	/** Both arms of a diamond reach the same store: resolves. */
	@Test
	public void joinWhereBothArmsReachTheSameStoreResolves() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "85 d3"); // STA $D3
		put("0xc004", "a5 20"); // LDA $20
		put("0xc006", "f0 03"); // BEQ $C00B
		put("0xc008", "20 40 c0"); // JSR $C040
		put("0xc00b", "a5 d3"); // LDA $D3     -- the join
		put("0xc00d", "8d 00 80"); // STA $8000
		put("0xc040", "60"); // RTS
		assertBank(5, scan("0xc00d", oracle()).value());
	}

	/** Each arm stores its own value: different stores on different paths -> declines. */
	@Test
	public void armsStoringDifferentValuesDecline() throws Exception {
		put("0xc000", "a5 20"); // LDA $20
		put("0xc002", "f0 07"); // BEQ $C00B
		put("0xc004", "a9 01"); // LDA #$01
		put("0xc006", "85 d3"); // STA $D3     -- arm A's store
		put("0xc008", "4c 0f c0"); // JMP $C00F
		put("0xc00b", "a9 02"); // LDA #$02
		put("0xc00d", "85 d3"); // STA $D3     -- arm B's store
		put("0xc00f", "20 40 c0"); // JSR $C040 -- the join
		put("0xc012", "a5 d3"); // LDA $D3
		put("0xc014", "8d 00 80"); // STA $8000
		put("0xc040", "60"); // RTS
		assertDeclined(scan("0xc014", oracle()));
	}

	/** A read-modify-write of the slot on the path is a writer, not a source: declines. */
	@Test
	public void readModifyWriteOnThePathDeclines() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "85 d3"); // STA $D3
		put("0xc004", "e6 d3"); // INC $D3
		put("0xc006", "20 40 c0"); // JSR $C040
		put("0xc009", "a5 d3"); // LDA $D3
		put("0xc00b", "8d 00 80"); // STA $8000
		put("0xc040", "60"); // RTS
		assertDeclined(scan("0xc00b", oracle()));
	}

	// ==================================================================
	// 6. Caps
	// ==================================================================

	/** {@code LDA #5 / STA $D3 / NOP * n / LDA $D3 / STA $8000}: one spend for the load node,
	 *  one per NOP, one for the terminal store -- {@code n + 2} against the 384-node cap. */
	private String nopChain(int n) throws Exception {
		put("0xc000", "a9 05");
		put("0xc002", "85 d3");
		for (int k = 0; k < n; k++) {
			put(String.format("0x%x", 0xc004 + k), "ea");
		}
		int load = 0xc004 + n;
		put(String.format("0x%x", load), "a5 d3");
		put(String.format("0x%x", load + 2), "8d 00 80");
		return String.format("0x%x", load + 2);
	}

	@Test
	public void spanAtTheNodeCapResolves() throws Exception {
		assertBank(5, scan(nopChain(382), oracle()).value());
	}

	@Test
	public void spanOverTheNodeCapDeclines() throws Exception {
		assertDeclined(scan(nopChain(383), oracle()));
	}

	// ==================================================================
	// 7. No oracle / no state -> today's answer exactly
	// ==================================================================

	@Test
	public void noOracleHooksDeclineByteIdentically() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "60"); // RTS
		StoredValueScanner.Hooks direct = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return null;
			}
		};
		assertDeclined(scan(site, direct));
	}

	/** An oracle that has no state at the store abandons (never withdraw-and-continue). */
	@Test
	public void noStateAtTheStoreDeclines() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "60"); // RTS
		assertDeclined(scan(site, oracleHooks(builder.addr("0xdb"), false)));
	}

	// ==================================================================
	// 8. Per-run memo
	// ==================================================================

	@Test
	public void proofAndCensusAreMemoized() throws Exception {
		String site = saveCallRestore("a9 05");
		put("0xc040", "60"); // RTS
		StoredValueScanner.ProofMemo memo = new StoredValueScanner.ProofMemo();
		StoredValueScanner.Hooks base = oracle();
		StoredValueScanner.Hooks memoHooks = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return base.isMechanismWrite(instr);
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

			@Override
			public boolean hasStateOracle() {
				return true;
			}

			@Override
			public StoredValueScanner.ProofMemo saveSlotMemo() {
				return memo;
			}
		};
		assertBank(5, scan(site, memoHooks).value());
		assertEquals(1, memo.slotProofs.size());
		assertEquals(1, memo.censuses.size());
		assertBank(5, scan(site, memoHooks).value());
		assertEquals(1, memo.slotProofs.size());
	}
}
