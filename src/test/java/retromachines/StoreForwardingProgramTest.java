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

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins {@link StoredValueScanner}'s local store-to-load forwarding (grm-mej.1): a value laundered
 * through a memory cell earlier in the same basic block is followed, so a helper that stashes its
 * register argument and splices it back in is <em>derived</em> rather than assumed.
 * <p>
 * The motivating shape is Ironsword's {@code FUN_ffc0}, reproduced by
 * {@link #ironswordCommitSiteDerivesArgumentLaunderedThroughRam()}:
 * <pre>
 *   STA $C3        ; stash the caller's bank argument
 *   LDA $C5 / PHA  ; save the current shadow
 *   AND #$18       ; keep the untracked VRAM bits
 *   ORA $C3        ; splice the argument back in -- NON-IMMEDIATE, the scan used to stop here
 *   STA $8000      ; the commit
 * </pre>
 * <b>Read this before treating that test as a real-ROM claim.</b> Deriving the commit site is not
 * the same as improving Ironsword's analysis today, and measurement says it does not:
 * {@code findHelpers} summarizes {@code FUN_ffc0} by its MAX-ADDRESS switch site, which is the
 * {@code $FFD6} RESTORE ({@code PLA / STA $C5 / STA $8000}), not the {@code $FFCD} commit. So
 * {@code depositHelperArgument} evaluates a chain that begins with a {@code PLA} and forwarding
 * never runs there. That is grm-hum's recorded "max-address switchSite is wrong in BOTH
 * directions" problem and it belongs to grm-mej.3 / the save-restore modeling bead, not here.
 * These tests therefore pin the scanner's capability directly, at the site that actually computes
 * the bank.
 * <p>
 * Fixture note inherited from {@link MemoryLatchStrategyProgramTest}: {@link ProgramBuilder}
 * blocks are created read-only, so every RAM block must be made writable explicitly or
 * {@code bankInvariantRomByte} treats a RAM load as a constant ROM byte and the tests that mean to
 * model an unrecoverable value would quietly recover one.
 */
public class StoreForwardingProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		// Deliberately spans the stack page AND ordinary RAM above it, so the stack-page guard
		// and the "any RAM address, not just zero page" rule can both be exercised.
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(zp);
		makeWritable(ram);
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

	/**
	 * An AxROM-shaped latch: the whole ROM area, no address decode, and a 3-bit field so the
	 * Ironsword fixture's {@code AND #$18} lands entirely outside the tracked bits, exactly as it
	 * does on the real board.
	 */
	private MemoryLatchBankSwitchStrategy axromLatch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x07);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0x07);
		return strategy;
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private void assertBank(int expected, BankState actual) {
		assertEquals("tracked bits not fully known: " + actual, 0x07, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	private void assertUnresolved(BankState actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
	}

	// ------------------------------------------------------------------
	// Forwarding resolves
	// ------------------------------------------------------------------

	/** The simplest launder: store a known byte to RAM, load it back, latch it. */
	@Test
	public void forwardsStoreToLoadThroughZeroPage() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "a5 c3", true); // LDA $C3
		builder.setBytes("0x8006", "8d 00 80", true); // STA $8000

		assertBank(5, axromLatch().computeSwitch(program, instructionAt("0x8006"),
			BankState.unknown()));
	}

	/**
	 * The same launder through an ABSOLUTE RAM address rather than zero page. This is the guard on
	 * the no-zero-page-restriction rule: Contra's save slots are {@code $07EC}/{@code $07ED}, so a
	 * future change that narrowed forwarding to the zero page would silently exclude exactly the
	 * cells grm-mej.3 needs.
	 */
	@Test
	public void forwardsStoreToLoadThroughAbsoluteRamNotJustZeroPage() throws Exception {
		builder.setBytes("0x8000", "a9 06", true); // LDA #$06
		builder.setBytes("0x8002", "8d ec 07", true); // STA $07EC
		builder.setBytes("0x8005", "ad ec 07", true); // LDA $07EC
		builder.setBytes("0x8008", "8d 00 80", true); // STA $8000

		assertBank(6, axromLatch().computeSwitch(program, instructionAt("0x8008"),
			BankState.unknown()));
	}

	/** A non-immediate {@code ORA} operand, which used to end the scan unconditionally. */
	@Test
	public void forwardsNonImmediateOraOperand() throws Exception {
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "a9 00", true); // LDA #$00
		builder.setBytes("0x8006", "05 c3", true); // ORA $C3
		builder.setBytes("0x8008", "8d 00 80", true); // STA $8000

		assertBank(3, axromLatch().computeSwitch(program, instructionAt("0x8008"),
			BankState.unknown()));
	}

	/**
	 * <b>The Ironsword commit site, evaluated under a call site's registers.</b> This is the case
	 * grm-hum could only cover with a convention fallback.
	 * <p>
	 * {@code argValue} is passed {@link BankState#unknown()} deliberately: that is what the
	 * convention would contribute, so a passing assertion can ONLY come from the evaluation
	 * deriving the value through {@code $C3}. If forwarding regresses, this test fails rather than
	 * silently falling back to an assumption that happens to agree.
	 * <p>
	 * Note the {@code PHA} at {@code $8006} sitting between the {@code STA $C3} and the
	 * {@code ORA $C3}. It is load-bearing: treating pushes as opaque memory writes would end the
	 * walk here, which is why the stack is guarded by the CELL being read
	 * ({@code StoredValueScanner.inStackPage}) rather than by the instructions passed over.
	 */
	@Test
	public void ironswordCommitSiteDerivesArgumentLaunderedThroughRam() throws Exception {
		builder.setBytes("0x8000", "84 c1", true); // STY $C1     <- helper entry
		builder.setBytes("0x8002", "85 c3", true); // STA $C3     <- stash the argument
		builder.setBytes("0x8004", "a5 c5", true); // LDA $C5     <- the live shadow
		builder.setBytes("0x8006", "48", true); // PHA         <- save it
		builder.setBytes("0x8007", "29 18", true); // AND #$18    <- keep untracked VRAM bits
		builder.setBytes("0x8009", "05 c3", true); // ORA $C3     <- splice the argument back in
		builder.setBytes("0x800b", "85 c5", true); // STA $C5
		builder.setBytes("0x800d", "8d 00 80", true); // STA $8000    <- the commit

		RegisterEnv callerRegs = new RegisterEnv(builder.addr("0x8000"),
			BankState.fullyKnown(0xFF, 0x05), BankState.unknown(), BankState.unknown());

		BankSwitchStrategy.HelperDeposit deposit =
			axromLatch().depositHelperArgument(program, instructionAt("0x800d"),
				BankState.unknown(), BankState.unknown(), 0x07, callerRegs);

		assertEquals("the call site should own the mechanism's whole field", 0x07,
			deposit.ownedMask());
		assertBank(5, deposit.value());
	}

	/**
	 * <b>The grm-6pi regression guard.</b> The full Ironsword trampoline, including the restore,
	 * evaluated at the site {@code findHelpers} actually picks -- the max-address one, {@code
	 * STA $8000} after the {@code PLA}. That site's value is unrecoverable by construction, and
	 * the deposit must therefore be UNKNOWN.
	 * <p>
	 * {@code argValue} is passed a fully known bank 5 here, the exact opposite of
	 * {@link #ironswordCommitSiteDerivesArgumentLaunderedThroughRam}. If a convention fallback is
	 * ever reintroduced, this test starts reporting bank 5 and fails. That fallback shipped
	 * briefly and was wrong on the real cartridge: callers set the shadow to 0 before calling
	 * ({@code $80AB LDA #$00 / STA $C5}), so the restore returns bank 0 and the caller does NOT
	 * resume in the requested bank. The engine had been retargeting the following calls into bank
	 * 7's and bank 3's overlays, where the ROM bytes are graphics data rather than code.
	 * <p>
	 * The genuinely correct answer for a verified save/restore pair is "unchanged"
	 * ({@code ownedMask == 0}), which needs {@code PHA}/{@code PLA} pairing -- grm-mej.3. Until
	 * then unknown is the honest answer, and this test pins that rather than the ideal one.
	 */
	@Test
	public void restoreSiteOfASaveRestoreTrampolineDepositsUnknownNotTheArgument() throws Exception {
		builder.setBytes("0x8000", "84 c1", true); // STY $C1     <- helper entry
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "a5 c5", true); // LDA $C5
		builder.setBytes("0x8006", "48", true); // PHA         <- save the shadow
		builder.setBytes("0x8007", "29 18", true); // AND #$18
		builder.setBytes("0x8009", "05 c3", true); // ORA $C3
		builder.setBytes("0x800b", "85 c5", true); // STA $C5
		builder.setBytes("0x800d", "8d 00 80", true); // STA $8000    <- COMMIT
		builder.setBytes("0x8010", "20 20 80", true); // JSR $8020    <- run the target routine
		builder.setBytes("0x8013", "68", true); // PLA         <- restore the shadow
		builder.setBytes("0x8014", "85 c5", true); // STA $C5
		builder.setBytes("0x8016", "8d 00 80", true); // STA $8000    <- RESTORE (max-address site)
		builder.setBytes("0x8019", "60", true); // RTS
		builder.setBytes("0x8020", "60", true); // RTS

		RegisterEnv callerRegs = new RegisterEnv(builder.addr("0x8000"),
			BankState.fullyKnown(0xFF, 0x05), BankState.unknown(), BankState.unknown());

		BankSwitchStrategy.HelperDeposit deposit =
			axromLatch().depositHelperArgument(program, instructionAt("0x8016"),
				BankState.fullyKnown(0x07, 0x05), BankState.unknown(), 0x07, callerRegs);

		assertUnresolved(deposit.value());
	}

	// ------------------------------------------------------------------
	// Forwarding declines
	// ------------------------------------------------------------------

	/**
	 * The anti-overreach case, in the spirit of the {@code nesuxhelpertest} fixture's U3: a load
	 * of a RAM cell nothing in this block wrote stays unresolved. If this ever starts passing a
	 * value, forwarding has begun inventing one.
	 */
	@Test
	public void declinesWhenNothingInBlockStoresTheCell() throws Exception {
		builder.setBytes("0x8000", "a5 c3", true); // LDA $C3
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8002"),
			BankState.unknown()));
	}

	/** A read-modify-write on the cell between the store and the load invalidates the value. */
	@Test
	public void declinesWhenReadModifyWriteTouchesTheCell() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "e6 c3", true); // INC $C3
		builder.setBytes("0x8006", "a5 c3", true); // LDA $C3
		builder.setBytes("0x8008", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8008"),
			BankState.unknown()));
	}

	/**
	 * An indexed store whose index is not statically known could be writing the cell, so the walk
	 * declines rather than stepping over it. {@code $0200,X} is chosen to be outside the latch
	 * range, so this exercises the forwarding guard and not the mechanism-write abort.
	 */
	@Test
	public void declinesWhenUnplaceableIndexedStoreIntervenes() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "9d 00 02", true); // STA $0200,X  (X unknown)
		builder.setBytes("0x8007", "a5 c3", true); // LDA $C3
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	/** A subroutine may write anywhere, so a call between store and load ends the walk. */
	@Test
	public void declinesWhenCallIntervenes() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "20 20 80", true); // JSR $8020
		builder.setBytes("0x8007", "a5 c3", true); // LDA $C3
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000
		builder.setBytes("0x8020", "60", true); // RTS

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	/** Forwarding is strictly intra-block: a {@code JMP} between the two ends the walk. */
	@Test
	public void declinesAcrossABasicBlockBoundary() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 c3", true); // STA $C3
		builder.setBytes("0x8004", "4c 07 80", true); // JMP $8007
		builder.setBytes("0x8007", "a5 c3", true); // LDA $C3
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	/**
	 * The stack page is refused outright. {@code PHA}/{@code PHP} write it without naming an
	 * address any of {@code writesMemory}'s detectors can see, so a push between the store and the
	 * load would otherwise be stepped over and a stale value attributed forward. Carrying values
	 * across a push/pull pair is grm-mej.3's job.
	 */
	@Test
	public void declinesForwardingThroughTheStackPage() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "8d 50 01", true); // STA $0150
		builder.setBytes("0x8005", "48", true); // PHA          (invisible stack write)
		builder.setBytes("0x8006", "ad 50 01", true); // LDA $0150
		builder.setBytes("0x8009", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x8009"),
			BankState.unknown()));
	}

	/**
	 * A store of an unrecoverable value forwards the unknown-ness rather than skipping past to an
	 * older, stale store of the same cell.
	 */
	@Test
	public void forwardsTheNearestStoreEvenWhenItsValueIsUnknown() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 c3", true); // STA $C3     <- stale, must NOT be used
		builder.setBytes("0x8004", "a5 40", true); // LDA $40     <- unrecoverable RAM
		builder.setBytes("0x8006", "85 c3", true); // STA $C3     <- nearest store
		builder.setBytes("0x8008", "a5 c3", true); // LDA $C3
		builder.setBytes("0x800a", "8d 00 80", true); // STA $8000

		assertUnresolved(axromLatch().computeSwitch(program, instructionAt("0x800a"),
			BankState.unknown()));
	}
}
