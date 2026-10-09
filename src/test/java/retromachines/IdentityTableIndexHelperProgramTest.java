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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * {@code ProgramBuilder} coverage of bead grm-ld68, "index-register helper argument (TAX/TAY)
 * carries a stack/mirror read-back": contra's {@code c0c1 LDA $8000 / PHA / ... / c0d1 PLA / c0d2
 * TAY / c0d3 JSR $c13f}, where {@code FUN_c13f} is {@code LDA $FFD0,Y / STA $FFD0,Y / RTS} --
 * a memory-latch helper that consumes the bank in Y, while {@code HelperDiscovery} records the
 * argument register as A (the {@code STA}'s own register). Three pieces, modelled on
 * {@link CallCrossingPushPullProgramTest} and {@link CrossBlockPushPullProgramTest}:
 * <ol>
 * <li>scanner-level: {@code StoredValueScanner.resolveStoredValue}'s backward walk renames a
 * tracked Y (or X) to A on meeting a {@code TAY} ({@code TAX}), via
 * {@code StoredValueScanner#transferSource};</li>
 * <li>recovery-level: {@link HelperArgumentRecovery#recoverCallArgument} carries a caller-side
 * read-back through the INDEX register {@code MemoryLatchBankSwitchStrategy} actually consumes,
 * via {@link RegisterEnv#readBack};</li>
 * <li>strategy-level: {@code MemoryLatchBankSwitchStrategy}'s identity-table rule, which answers
 * {@code StoredValueScanner.Hooks#isIdentityTableLoad} for an absolute-indexed load whose table is
 * an identity over the field and whose index arrives as a provable read-back of the bank number.
 * </ol>
 */
public class IdentityTableIndexHelperProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private MemoryBlock prg;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		prg = builder.createMemory("PRG", "0x8000", 0x8000);
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

	private void putData(String address, String hex) throws Exception {
		builder.setBytes(address, hex);
	}

	// ==================================================================
	// Scanner-level fixtures: TAX/TAY renaming (StoredValueScanner.resolveStoredValue)
	// ==================================================================

	/** Hooks that answer neither question -- direct-site, no mirrors, no oracle. */
	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};

	/**
	 * 1. {@code LDA #$05 / TAY / STY $8000}: a Y-tracked walk meeting {@code TAY} renames to A and
	 * keeps resolving -- reaching the {@code LDA #imm} that feeds it -- rather than treating
	 * {@code TAY} as an opaque Y modifier and giving up.
	 */
	@Test
	public void tayRenamingReachesAnImmediateLoad() throws Exception {
		put("0xc000", "a9 05"); // LDA #$05
		put("0xc002", "a8"); // TAY
		put("0xc003", "8c 00 80"); // STY $8000

		PartialByte value = StoredValueScanner.resolveStoredValue(program, instructionAt("0xc003"),
			'Y', BankState.unknown(), 0xFF, NO_HOOKS);
		assertEquals(0xFF, value.knownMask());
		assertEquals(5, value.bits());
	}

	/**
	 * 1b. {@code LDX #$07 / TAX / STX $8000}: the X-channel sibling of the previous case -- pins
	 * that the rename fires for {@code TAX}/tracking-X too, not only {@code TAY}/tracking-Y.
	 */
	@Test
	public void taxRenamingReachesAnImmediateLoad() throws Exception {
		put("0xc000", "a9 07"); // LDA #$07
		put("0xc002", "aa"); // TAX
		put("0xc003", "8e 00 80"); // STX $8000

		PartialByte value = StoredValueScanner.resolveStoredValue(program, instructionAt("0xc003"),
			'X', BankState.unknown(), 0xFF, NO_HOOKS);
		assertEquals(0xFF, value.knownMask());
		assertEquals(7, value.bits());
	}

	/**
	 * 2. {@code LDA $10 (mirror) / PHA / PLA / TAY / STY $8000}: a Y-tracked walk meeting
	 * {@code TAY} renames to A, then reaches an UNMODIFIED read-back of a live-bank mirror through
	 * a same-block {@code PLA}/{@code PHA} pairing -- {@code RESTORED_BANK}, carrying a
	 * {@link StoredValueScanner.ReadBack} naming the mirror cell, exactly as the plain A-channel
	 * case already does (bead grm-yflf) but now reachable from a Y-tracked entry point.
	 */
	@Test
	public void tayRenamingReachesAMirrorReadBack() throws Exception {
		put("0xc000", "a5 10"); // LDA $10   -- mirror read
		put("0xc002", "48"); // PHA
		put("0xc003", "68"); // PLA
		put("0xc004", "a8"); // TAY
		put("0xc005", "8c 00 80"); // STY $8000

		StoredValueScanner.Hooks mirrorHooks = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public PartialByte resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return null;
			}

			@Override
			public boolean isLiveBankMirror(Address target) {
				return builder.addr("0x10").equals(target);
			}
		};

		StoredValueScanner.Scan scan = StoredValueScanner.resolveStoredValueScan(program,
			instructionAt("0xc005"), 'Y', BankState.unknown(), 0xFF, mirrorHooks, RegisterEnv.NONE);
		assertEquals(BankSwitchStrategy.ValueStop.RESTORED_BANK, scan.stop());
		assertNotNull("a RESTORED_BANK stop must carry a ReadBack", scan.readBack());
		assertEquals(builder.addr("0x10"), scan.readBack().cell());
		assertEquals(builder.addr("0xc000"), scan.readBack().readAt());
	}

	/**
	 * 3. {@code LDX #$07 / TXA / STA $8000}: {@code TXA} (A FROM X) must NOT be renamed while
	 * tracking A -- only the {@code TAX}/{@code TAY} direction (A INTO X/Y) renames. A walk
	 * tracking A that meets {@code TXA} still treats it as an opaque A modifier: {@code X}'s own
	 * immediate never enters the mask algebra as a fully-known base the way the renamed cases
	 * above do, so the load-mnemonic branch never fires for it and the walk falls through to
	 * {@code constantRegisterValue} exactly as before this bead. That evaluator DOES model
	 * {@code TXA} (bead grm-4bgh.6, the "other evaluator" fallback) and so still recovers 7 here --
	 * the discriminating claim is that behavior is BYTE-IDENTICAL to pre-grm-ld68, not that this
	 * particular shape declines.
	 */
	@Test
	public void txaIsNotRenamedWhileTrackingA() throws Exception {
		put("0xc000", "a2 07"); // LDX #$07
		put("0xc002", "8a"); // TXA
		put("0xc003", "8d 00 80"); // STA $8000

		PartialByte value = StoredValueScanner.resolveStoredValue(program, instructionAt("0xc003"),
			'A', BankState.unknown(), 0xFF, NO_HOOKS);
		assertEquals("constantRegisterValue's fallback still resolves TXA -- this pins that the "
				+ "answer comes from THAT evaluator, not from a (wrong) rename onto X", 0xFF,
			value.knownMask());
		assertEquals(7, value.bits());
	}

	// ==================================================================
	// Recovery-level fixtures: the full contra c0d3 chain
	// (HelperArgumentRecovery.recoverCallArgument over a real MemoryLatchBankSwitchStrategy)
	// ==================================================================

	/**
	 * {@code LDA $10 (mirror) / PHA / JSR sub / PLA / TAY / JSR helper}, helper
	 * {@code LDA $E000,Y / STA $E000,Y / RTS} over a real {@link MemoryLatchBankSwitchStrategy}
	 * whose latch range is {@code $E000-$FFFF}, {@code mask 0x07} -- contra's {@code FUN_c13f}
	 * shape, reduced. {@code $E000..$E007} holds the identity table {@code 00..07}, and {@code $10}
	 * is a {@code ROM_IDENTIFYING} mirror in plain identity encoding.
	 */
	private void layIdentityTableChain() throws Exception {
		put("0x8000", "a5 10"); // LDA $10      -- mirror read
		put("0x8002", "48"); // PHA
		put("0x8003", "20 00 90"); // JSR sub      ($9000)
		put("0x8006", "68"); // PLA
		put("0x8007", "a8"); // TAY
		put("0x8008", "20 00 91"); // JSR helper   ($9100)  <- callInstr
		put("0x9000", "60"); // RTS (sub)
		put("0x9100", "b9 00 e0"); // LDA $E000,Y  -- table load
		put("0x9103", "99 00 e0"); // STA $E000,Y  -- commits the table byte at Y
		put("0x9106", "60"); // RTS
		putData("0xE000", "00 01 02 03 04 05 06 07"); // identity table
	}

	private MemoryLatchBankSwitchStrategy identityLatch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0xE000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x07);
		MemoryLatchBankSwitchStrategy latch = new MemoryLatchBankSwitchStrategy();
		latch.configure(program, params, 0x07);
		return latch;
	}

	private HelperModel identityHelper(MemoryLatchBankSwitchStrategy latch) {
		return new HelperModel(null, builder.addr("0x9100"), null, 'A', 0x07, 0, latch,
			builder.addr("0x9103"), builder.addr("0x9103"), null);
	}

	private void observeIdentityMirror(MemoryLatchBankSwitchStrategy latch) {
		observeMirror(latch, BankMirrors.Kind.ROM_IDENTIFYING);
	}

	private void observeMirror(MemoryLatchBankSwitchStrategy latch, BankMirrors.Kind kind) {
		AddressSpace baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		latch.observeMirrors(BankMirrors.of(baseSpace, Map.of(0x10L, Set.of(kind))));
	}

	/**
	 * 4. Oracle UNKNOWN at the push: the mirror value at {@code $10} never resolves, so the
	 * caller-side A/Y scans stay unresolved too -- but Y's own scan still ends on a plain
	 * read-back of the {@code $10} mirror (grm-mej.3 increment 3's call-crossing pairing), so the
	 * env carries a {@code ReadBack} for Y. Inside the helper, the identity-table rule fires: the
	 * argument does not resolve to a NUMBER, but {@code CallEffect.readBack} is non-null, carrying
	 * that same read-back through -- the RESTORED note grm-oj20 took away.
	 */
	@Test
	public void identityTableIndexHelperCarriesTheReadBackWhenOracleIsUnknown() throws Exception {
		layIdentityTableChain();
		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeIdentityMirror(latch);
		HelperModel helper = identityHelper(latch);

		StateOracle oracle = addr -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertFalse("the table index (Y) never resolves to a number", effect.argumentResolved());
		StoredValueScanner.ReadBack readBack = effect.readBack();
		assertNotNull("the identity-table rule must carry the caller's read-back through Y",
			readBack);
		assertEquals("the read-back names the ORIGINAL mirror cell the caller read, $10, not "
				+ "anything about the load inside the helper", builder.addr("0x10"),
			readBack.cell());
		assertEquals(builder.addr("0x8000"), readBack.readAt());
	}

	/**
	 * 5. Oracle KNOWN (bank 3) at the push: the mirror resolves to a real value, which survives
	 * {@code TAY} into Y as a known constant -- the ordinary "known in-state" path
	 * ({@code effectiveOperandTarget}'s {@code constantRegisterValue}) resolves the table lookup
	 * to a NUMBER (3) exactly as it already does for a directly-known index, without ever reaching
	 * the identity-table rule at all. Pins that the new rule does not shadow or interfere with the
	 * pre-existing resolved path.
	 */
	@Test
	public void identityTableIndexHelperResolvesWhenOracleIsKnown() throws Exception {
		layIdentityTableChain();
		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeIdentityMirror(latch);
		HelperModel helper = identityHelper(latch);

		Address phaAddr = builder.addr("0x8002");
		StateOracle oracle =
			addr -> phaAddr.equals(addr) ? BankState.fullyKnown(0x07, 3) : BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertTrue("a known in-state at the push must still resolve to a number",
			effect.argumentResolved());
		assertEquals(0x07, effect.state().knownMask());
		assertEquals(3, effect.state().bits());
	}

	// ==================================================================
	// Traps: the identity-table rule must NOT fire, readBack stays null
	// ==================================================================

	/**
	 * 6. Non-identity table: {@code $E003} is {@code 0x04}, not {@code 3} -- the table is not an
	 * identity over the field, so the rule declines. Neither the value nor a read-back is
	 * recovered. (Not {@code 0x63}: the field is only the low 3 bits, {@code mask 0x07}, and
	 * {@code 0x63 & 0x07 == 3} -- a byte that looks different but is not, for an 8-entry table.)
	 */
	@Test
	public void nonIdentityTableDoesNotCarryAReadBack() throws Exception {
		layIdentityTableChain();
		// Overwrite $E003 so table[3] != 3 after the field mask is applied.
		putData("0xE003", "04");
		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeIdentityMirror(latch);
		HelperModel helper = identityHelper(latch);

		StateOracle oracle = addr -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertFalse(effect.argumentResolved());
		assertNull("a non-identity table must not be claimed as a restore", effect.readBack());
	}

	/**
	 * 7. Table not bank-invariant: the latch range is made WRITABLE, so
	 * {@code bankInvariantRomByte} refuses every entry outright ({@code MemoryBlock.isWrite()}) --
	 * the rule cannot prove the table is an identity over content it cannot even read as fixed ROM.
	 */
	@Test
	public void writableTableDoesNotCarryAReadBack() throws Exception {
		layIdentityTableChain();
		makeWritable(prg);
		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeIdentityMirror(latch);
		HelperModel helper = identityHelper(latch);

		StateOracle oracle = addr -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertFalse(effect.argumentResolved());
		assertNull("a writable table is not bank-invariant ROM content", effect.readBack());
	}

	/**
	 * 8. Y redefined inside the helper before the load: {@code LDY $40 / LDA $E000,Y / STA
	 * $E000,Y}, {@code $40} an unrelated, unresolvable RAM cell. The independent scan of Y from the
	 * load's own address no longer reaches the helper's entry with Y untouched (it meets the
	 * {@code LDY $40} first and cannot resolve it), so rule (b) -- "idx is not redefined between
	 * entry and this load" -- fails and the rule declines, even though the env still carries a
	 * read-back for Y from the CALLER's TAY.
	 */
	@Test
	public void indexRedefinedInsideTheHelperDoesNotCarryAReadBack() throws Exception {
		put("0x8000", "a5 10"); // LDA $10      -- mirror read
		put("0x8002", "48"); // PHA
		put("0x8003", "20 00 90"); // JSR sub      ($9000)
		put("0x8006", "68"); // PLA
		put("0x8007", "a8"); // TAY
		put("0x8008", "20 00 91"); // JSR helper   ($9100)  <- callInstr
		put("0x9000", "60"); // RTS (sub)
		put("0x9100", "a4 40"); // LDY $40      -- redefines Y from unrelated RAM
		put("0x9102", "b9 00 e0"); // LDA $E000,Y
		put("0x9105", "99 00 e0"); // STA $E000,Y
		put("0x9108", "60"); // RTS
		putData("0xE000", "00 01 02 03 04 05 06 07");

		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeIdentityMirror(latch);
		// entry == the FIRST instruction actually executed, $9100 (the LDY), so the scan stop
		// used by depositHelperArgument's mini-inline matches production's own insideHelperEntry.
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0x07, 0,
			latch, builder.addr("0x9105"), builder.addr("0x9105"), null);

		StateOracle oracle = addr -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertFalse(effect.argumentResolved());
		assertNull("Y is redefined inside the helper before the load -- the caller's read-back "
				+ "describes nothing this load consumes", effect.readBack());
	}

	/**
	 * 8b. Y reloaded inside the helper FROM THE SAME MIRROR: {@code LDY $10 / LDA $E000,Y / STA
	 * $E000,Y}. The helper then commits the bank live at the CALL, not the one the caller read
	 * back, even though Y's value inside the helper looks exactly like the env's (the same
	 * partially known mirror byte). Rule (b) must therefore be structural -- "the scan of Y reached
	 * the helper's entry" -- never value equality with the env.
	 */
	@Test
	public void indexReloadedFromTheSameMirrorInsideTheHelperDoesNotCarryAReadBack()
			throws Exception {
		put("0x8000", "a5 10"); // LDA $10      -- mirror read
		put("0x8002", "48"); // PHA
		put("0x8003", "20 00 90"); // JSR sub      ($9000)
		put("0x8006", "68"); // PLA
		put("0x8007", "a8"); // TAY
		put("0x8008", "20 00 91"); // JSR helper   ($9100)  <- callInstr
		put("0x9000", "60"); // RTS (sub)
		put("0x9100", "a4 10"); // LDY $10      -- the SAME mirror, read inside the helper
		put("0x9102", "b9 00 e0"); // LDA $E000,Y
		put("0x9105", "99 00 e0"); // STA $E000,Y
		put("0x9108", "60"); // RTS
		putData("0xE000", "00 01 02 03 04 05 06 07");

		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeIdentityMirror(latch);
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0x07, 0,
			latch, builder.addr("0x9105"), builder.addr("0x9105"), null);

		StateOracle oracle = addr -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertNull("Y is reloaded inside the helper -- the caller's read-back is not what the "
				+ "latch commits", effect.readBack());
	}

	/**
	 * 9. The read-back cell is {@code WRITE_THROUGH}, not {@code ROM_IDENTIFYING}: rule (c)
	 * requires a {@code ROM_IDENTIFYING} cell specifically (a shadow's last-committed bank is not
	 * provably {@code [0, fieldMask]} the way a bank-identifying ROM byte is), so the identity-table
	 * rule declines even though the caller-side scan still ends on an unmodified read-back (the
	 * scanner's OWN plain-mirror rule accepts either kind for classification purposes).
	 */
	@Test
	public void writeThroughReadBackCellDoesNotCarryAReadBack() throws Exception {
		layIdentityTableChain();
		MemoryLatchBankSwitchStrategy latch = identityLatch();
		observeMirror(latch, BankMirrors.Kind.WRITE_THROUGH);
		HelperModel helper = identityHelper(latch);

		StateOracle oracle = addr -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8008"), helper, BankState.unknown(), new HashMap<>(), new java.util.HashMap<>(),
			RegisterEnv.NONE, oracle);

		assertFalse(effect.argumentResolved());
		assertNull("a WRITE_THROUGH shadow is not provably the bank number the way a "
				+ "ROM_IDENTIFYING byte is -- the rule must not claim it", effect.readBack());
	}
}
