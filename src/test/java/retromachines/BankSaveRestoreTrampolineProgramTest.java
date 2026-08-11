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

import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;

/**
 * Pins {@link BoardBankAnalyzer#restoresEntryBank} (bead grm-mej.3, increment 1): whether a
 * helper's net effect on the tracked bank field is NOTHING, because it saves the live bank on
 * entry, switches, calls out, and puts the saved bank back before returning.
 * <p>
 * Ironsword/Wizards &amp; Warriors 2's {@code FUN_ffc0} is the shape every "accept" test below is a
 * variation on (see the method's own javadoc for the byte-exact original):
 * <pre>
 *   FFC4: LDA $C5 / PHA       ; save the CURRENT bank shadow   ($C5 is a WRITE_THROUGH mirror)
 *   FFC7: AND #$18 / ORA $C3 / STA $C5
 *   FFCD: STA $8000           ; COMMIT -- a mechanism write
 *   FFD0: JSR $FFDA           ; run the target routine in that bank
 *   FFD3: PLA / STA $C5
 *   FFD6: STA $8000           ; RESTORE                        &lt;- helper.switchSite()
 *   FFD9: RTS
 * </pre>
 * The fixtures below simplify away the {@code AND #$18 / ORA $C3} middle (the predicate never
 * inspects it) and keep only what the guard actually reads: a mirror-typed load, a save/restore
 * pair around it, the commit write the {@code switchSites} set records, and the final store at
 * {@code switchSite} itself.
 * <p>
 * {@code HelperModel} is a package-private record of {@code BoardBankAnalyzer} (widened from
 * {@code private} for exactly this test, matching this file's own established pattern of
 * widening a helper method/type a same-package Tier 2 test needs to reach -- see
 * {@code HelperPrologueProgramTest} and {@code HelperWrapperProgramTest} for the sibling
 * predicate-level tests this one is deliberately shaped like). {@code restoresEntryBank} never
 * reads {@code HelperModel.function()}, so every fixture below passes {@code null} for it rather
 * than standing up a real {@code Function} that would add nothing to what is being pinned.
 */
public class BankSaveRestoreTrampolineProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		// Zero page holds the mirror cells ($10, $30); RAM extends far enough to also hold the
		// indirect-jump pointer case's operand ($0300).
		builder.createMemory("RAM", "0x0000", 0x800);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
	}

	// ------------------------------------------------------------------
	// Scaffolding
	// ------------------------------------------------------------------

	/** A mirror set stated outright, exactly {@link BankMirrors#of}'s intended test-only route. */
	private BankMirrors mirrorsOf(long offset, BankMirrors.Kind... kinds) {
		return BankMirrors.of(baseSpace, Map.of(offset, Set.of(kinds)));
	}

	/**
	 * A {@code HelperModel} whose only fields {@code restoresEntryBank} reads are populated:
	 * {@code entry} (where the walk starts -- {@code relay} stays null so
	 * {@code insideHelperEntry} answers it directly) and {@code switchSite} (the restore this
	 * walk must reach to answer at all). Every other field is inert filler.
	 */
	private BoardBankAnalyzer.HelperModel model(Address entry, Address switchSite) {
		return new BoardBankAnalyzer.HelperModel(null, entry, null, null, 0xFF, 0, null,
			switchSite, entry, null);
	}

	private Address addr(String address) {
		return builder.addr(address);
	}

	private boolean restores(Address entry, Address switchSite, BankMirrors mirrors,
			Set<Address> switchSites) {
		return BoardBankAnalyzer.restoresEntryBank(program, model(entry, switchSite), mirrors,
			switchSites);
	}

	// ------------------------------------------------------------------
	// 1. The full shape, accepted
	// ------------------------------------------------------------------

	/**
	 * The complete {@code FUN_ffc0} shape: a {@code WRITE_THROUGH} mirror loaded and saved before
	 * the commit, a call crossed in the middle, and the saved byte put back at
	 * {@code switchSite}. This is the base case every other "accept" test is a variation on, and
	 * every "decline" test below breaks exactly one piece of it.
	 */
	@Test
	public void fullFfc0ShapeWithWriteThroughMirrorIsAVerifiedNoOp() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10       -- mirror read
		builder.setBytes("0x9002", "48", true); // PHA           -- save the entry bank
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000     -- COMMIT (mechanism write)
		builder.setBytes("0x9006", "20 00 91", true); // JSR $9100     -- run the target in that bank
		builder.setBytes("0x9009", "68", true); // PLA           -- restore
		builder.setBytes("0x900a", "8d 00 80", true); // STA $8000     -- RESTORE == switchSite
		builder.setBytes("0x900d", "60", true); // RTS
		builder.setBytes("0x9100", "60", true); // RTS           -- the called-out target

		boolean result = restores(addr("0x9000"), addr("0x900a"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of(addr("0x9003")));

		assertTrue("the full save/switch/call/restore shape is a verified no-op", result);
	}

	// ------------------------------------------------------------------
	// 2. ROM_IDENTIFYING also proves it
	// ------------------------------------------------------------------

	/**
	 * The identical shape, but the saved byte comes from a {@code ROM_IDENTIFYING} offset
	 * ({@code LDA $9050}, TMNT's {@code LDA $8000} API-read idiom) rather than a
	 * {@code WRITE_THROUGH} RAM shadow. {@link BoardBankAnalyzer#isLiveBankMirror} answers both
	 * kinds identically, and this is the proof: only the mirror's KIND changes between this test
	 * and the one above, and the verdict does not.
	 */
	@Test
	public void romIdentifyingSourceAlsoProvesTheNoOp() throws Exception {
		builder.setBytes("0x9000", "ad 50 90", true); // LDA $9050   -- ROM-identifying read
		builder.setBytes("0x9003", "48", true); // PHA
		builder.setBytes("0x9004", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9007", "20 00 91", true); // JSR $9100
		builder.setBytes("0x900a", "68", true); // PLA
		builder.setBytes("0x900b", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900e", "60", true); // RTS
		builder.setBytes("0x9100", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x900b"),
			mirrorsOf(0x9050, BankMirrors.Kind.ROM_IDENTIFYING), Set.of(addr("0x9004")));

		assertTrue("a ROM_IDENTIFYING source proves the no-op exactly like WRITE_THROUGH", result);
	}

	// ------------------------------------------------------------------
	// 3. The inner call is crossed -- because it is permitted, not merely tolerated
	// ------------------------------------------------------------------

	/**
	 * The call is crossed even though the callee clobbers A: {@code holdsEntryBank} is reset to
	 * {@code false} at the call (the callee "may clobber A"), but the ENTRY bank still comes back
	 * out of the stack slot at the {@code PLA} regardless of what the callee did to registers --
	 * the return-mechanism argument, not a claim about the callee's body.
	 */
	@Test
	public void theInnerCallIsCrossedByTheReturnMechanismArgument() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9006", "20 00 91", true); // JSR $9100
		builder.setBytes("0x9009", "68", true); // PLA
		builder.setBytes("0x900a", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900d", "60", true); // RTS
		builder.setBytes("0x9100", "a9 ff", true); // LDA #$FF    -- the callee clobbers A
		builder.setBytes("0x9102", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x900a"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of(addr("0x9003")));

		assertTrue("a callee that clobbers A must not defeat the stack-carried restore", result);
	}

	/**
	 * The mirror image of the case above: no call at all, and it is STILL a no-op. Together the
	 * two tests isolate that the call is PERMITTED by this guard, not REQUIRED by it -- a helper
	 * that saves, switches inline, and restores with no {@code JSR} anywhere is just as much a
	 * verified no-op.
	 */
	@Test
	public void noCallAtAllStillRestoresEntryBank() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9006", "68", true); // PLA         -- restore, no call in between
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900a", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of(addr("0x9003")));

		assertTrue("a call is permitted, not required, by this guard", result);
	}

	// ------------------------------------------------------------------
	// 4. The most important safety test: not a mirror at all
	// ------------------------------------------------------------------

	/**
	 * <b>The most important safety test in this file.</b> The saved byte is loaded from {@code $30},
	 * an ordinary RAM cell the mirror set says nothing about (the set declares only {@code $10}, an
	 * unrelated cell, so this is not the empty-mirror-set short-circuit -- it is specifically "this
	 * load is not one of them"). Nothing about the save/restore shape is otherwise different from
	 * the accepted case. A wrong {@code true} here would mark a REAL bank-mutating call a no-op
	 * with no comment and no warning anywhere -- the single worst failure mode this predicate can
	 * have.
	 */
	@Test
	public void unrelatedRamCellIsNotAMirrorSoDeclines() throws Exception {
		builder.setBytes("0x9000", "a5 30", true); // LDA $30     -- NOT a mirror
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9006", "68", true); // PLA
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900a", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of(addr("0x9003")));

		assertFalse("a load of a cell the mirror set says nothing about must never read as the "
			+ "entry bank", result);
	}

	// ------------------------------------------------------------------
	// 5. The mirror is read AFTER the mechanism write
	// ------------------------------------------------------------------

	/**
	 * The commit runs FIRST, then the mirror is loaded -- so the byte it reads is the bank the
	 * helper JUST installed, not the bank that was live on entry. {@code sawMechanismWrite} exists
	 * precisely to catch this: without it, this shape would be indistinguishable from the accepted
	 * case above, and the reported "entry bank" would actually be the new one.
	 */
	@Test
	public void mirrorReadAfterTheMechanismWriteIsTheNewBankNotTheEntryBank() throws Exception {
		builder.setBytes("0x9000", "8d 00 80", true); // STA $8000   -- COMMIT, first
		builder.setBytes("0x9003", "a5 10", true); // LDA $10     -- read AFTER the commit
		builder.setBytes("0x9005", "48", true); // PHA
		builder.setBytes("0x9006", "68", true); // PLA
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900a", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of(addr("0x9000")));

		assertFalse("a mirror read after the commit holds the bank just installed, not the entry "
			+ "bank -- sawMechanismWrite must refuse it", result);
	}

	// ------------------------------------------------------------------
	// 6. SAVE_SLOT and INPUT are refused -- each isolates the H2 rule alone
	// ------------------------------------------------------------------

	/**
	 * {@code SAVE_SLOT} must never answer as the live bank, even when it is the only thing this
	 * walk ever loads and saves: it holds a bank stashed for later restoration, deliberately NOT
	 * the live one (H2).
	 */
	@Test
	public void saveSlotMirrorIsRefused() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9006", "68", true); // PLA
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900a", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.SAVE_SLOT), Set.of(addr("0x9003")));

		assertFalse("a SAVE_SLOT cell holds a bank deliberately not the live one", result);
	}

	/** {@code INPUT} is refused for the identical H2 reason: it holds the bank a caller is
	 *  ASKING for, live only after a wrapper actually runs. */
	@Test
	public void inputMirrorIsRefused() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9006", "68", true); // PLA
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900a", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.INPUT), Set.of(addr("0x9003")));

		assertFalse("an INPUT cell holds the REQUESTED bank, not yet the live one", result);
	}

	// ------------------------------------------------------------------
	// 7. PHA / PHP / PLA -- the pull balances on the status push
	// ------------------------------------------------------------------

	/**
	 * {@code PHA} (the entry bank) then {@code PHP} (the status flags), but only ONE {@code PLA}:
	 * it pops the most recently pushed entry, which is the flags byte from {@code PHP}, not the
	 * bank from {@code PHA}. {@code PHP}/{@code PLP} are modelled ONLY to keep this depth honest,
	 * so an interleaved status push cannot make a later {@code PLA} pop the wrong byte -- this is
	 * that guard's own positive proof.
	 */
	@Test
	public void phpPlaBalancesOnTheStatusPushSoRestoredByteIsFlags() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA         -- save the entry bank
		builder.setBytes("0x9003", "08", true); // PHP         -- save the flags on top
		builder.setBytes("0x9004", "8d 00 80", true); // STA $8000   -- COMMIT
		builder.setBytes("0x9007", "68", true); // PLA         -- pops PHP's flags, not PHA's bank
		builder.setBytes("0x9008", "8d 00 80", true); // STA $8000   -- RESTORE == switchSite
		builder.setBytes("0x900b", "60", true); // RTS

		boolean result = restores(addr("0x9000"), addr("0x9008"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of(addr("0x9004")));

		assertFalse("one PLA against a PHA/PHP pair pops the flags, not the entry bank", result);
	}

	// ------------------------------------------------------------------
	// 8. PLA with nothing pushed
	// ------------------------------------------------------------------

	/** A {@code PLA} this walk never watched being pushed pops the CALLER's frame, not a saved
	 *  bank -- declines outright rather than guessing what is really under it. */
	@Test
	public void plaWithNothingPushedPopsTheCallersFrame() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10     -- read, but never saved
		builder.setBytes("0x9002", "68", true); // PLA         -- pops the caller's frame
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000   -- would-be switchSite

		boolean result = restores(addr("0x9000"), addr("0x9003"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("a PLA with nothing pushed must not be trusted as a restore", result);
	}

	// ------------------------------------------------------------------
	// 9. TXS between push and pull -- compared by BASE register
	// ------------------------------------------------------------------

	/**
	 * {@code TXS} between the save and the restore desynchronises the stack depth this walk
	 * tracks, so the model is abandoned rather than trusted. This is specifically the
	 * {@code writesStackPointer} BASE-register comparison's own test: the 6502 declares a
	 * two-byte {@code SP} and a one-byte {@code S} over the same bytes, and {@code TXS}'s p-code
	 * writes {@code S} while {@code CompilerSpec.getStackPointer()} answers {@code SP}. If this
	 * test passed under an {@code equals} comparison instead of a base-register one, the depth
	 * would silently go stale and a later {@code PLA} would be trusted to pop the entry bank when
	 * the hardware pops something else entirely.
	 */
	@Test
	public void txsBetweenPushAndPullAbandonsTheModelByBaseRegister() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "9a", true); // TXS         -- stack pointer moved out from under us
		builder.setBytes("0x9004", "68", true); // PLA
		builder.setBytes("0x9005", "8d 00 80", true); // STA $8000   -- would-be switchSite

		boolean result = restores(addr("0x9000"), addr("0x9005"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("a TXS between save and restore must abandon the model, not be missed by an "
			+ "identity comparison on the wrong-width stack-pointer register", result);
	}

	// ------------------------------------------------------------------
	// 10. A conditional branch could skip the restore
	// ------------------------------------------------------------------

	/**
	 * A branch in the body means "restored" is no longer a claim about every path -- the OTHER
	 * edge could skip the {@code PLA}/restore entirely, which would make "no-op" confidently
	 * wrong on that path. Any branch or jump abandons the walk outright, whichever way it goes.
	 */
	@Test
	public void conditionalBranchInTheBodyAbandonsTheModel() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "d0 00", true); // BNE $9005   -- a path could skip the restore
		builder.setBytes("0x9005", "68", true); // PLA
		builder.setBytes("0x9006", "8d 00 80", true); // STA $8000   -- would-be switchSite

		boolean result = restores(addr("0x9000"), addr("0x9006"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("a conditional branch could route around the restore, so the walk must "
			+ "abandon rather than assume the taken path", result);
	}

	// ------------------------------------------------------------------
	// 11. The push-address-and-return idiom -- declines via the fall-through requirement
	// ------------------------------------------------------------------

	/**
	 * <b>{@code LDA #hi / PHA / LDA #lo / PHA / RTS}, the ordinary 6502 indirect-jump idiom,
	 * inline in the helper's own body.</b> The walk's PHA/PLA modelling would happily accept the
	 * two {@code PHA}s (they push whatever {@code holdsEntryBank} is at the time, same as any
	 * other {@code PHA}) -- an {@code RTS} is a TERMINATOR with NO outgoing flows at all, so a
	 * guard written as "no outgoing flows -&gt; keep walking" would sail straight through it and
	 * march the cursor into whatever code happens to sit at the next linear address, which is not
	 * on this path at all. The walk instead requires a REAL fall-through
	 * ({@code instr.getFlows().length > 0 || instr.getFallThrough() == null}), and an
	 * {@code RTS} fails that on the {@code getFallThrough() == null} half precisely because it is
	 * a terminator -- so this declines on the SAME rule a plain {@code RTS} mid-body would, not
	 * because anything here specifically recognizes the push-address idiom as such.
	 */
	@Test
	public void pushAddressAndReturnIdiomDeclines() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA          -- save the entry bank
		builder.setBytes("0x9003", "a9 12", true); // LDA #$12     -- hi byte of a jump target
		builder.setBytes("0x9005", "48", true); // PHA
		builder.setBytes("0x9006", "a9 34", true); // LDA #$34     -- lo byte
		builder.setBytes("0x9008", "48", true); // PHA
		builder.setBytes("0x9009", "60", true); // RTS          -- push-address-and-return idiom
		builder.setBytes("0x900a", "68", true); // PLA          -- never reached by this walk
		builder.setBytes("0x900b", "8d 00 80", true); // STA $8000    -- would-be switchSite

		boolean result = restores(addr("0x9000"), addr("0x900b"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("the push-address-and-return idiom must decline: the walk would otherwise "
			+ "march past the RTS into code that is not on this path and find the PLA there",
			result);
	}

	/**
	 * <b>The shape the fall-through requirement is uniquely needed for</b>, and the reason that
	 * guard is phrased as "must have a fall-through" rather than "must have no outgoing flows".
	 * <p>
	 * An UNRESOLVED computed jump -- {@code JMP ($00C1)} with nothing known at the pointer, which
	 * is exactly Ironsword's own {@code FUN_ffda} -- writes no stack pointer and names no flow
	 * target, so it is invisible to every other guard in the walk: {@code writesStackPointer}
	 * declines to fire, and {@code getFlows().length} is zero. Only the missing fall-through
	 * catches it.
	 * <p>
	 * Contrast the push-address-and-return test above, which is OVER-determined: {@code RTS}'s own
	 * p-code decrements the stack pointer, so {@code writesStackPointer} already declines it and
	 * that test does not pin this line. This one does.
	 */
	@Test
	public void unresolvedComputedJumpDeclinesAndOnlyTheFallThroughGuardCatchesIt()
			throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA          -- save the entry bank
		builder.setBytes("0x9003", "6c c1 00", true); // JMP ($00C1)  -- target not statically known
		builder.setBytes("0x9006", "68", true); // PLA          -- never reached by this walk
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000    -- would-be switchSite

		Instruction jump = program.getListing().getInstructionAt(addr("0x9003"));
		assertNotNull("fixture must actually disassemble the computed jump", jump);
		assertEquals("fixture is only meaningful if the jump target stayed unresolved", 0,
			jump.getFlows().length);

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("an unresolved computed jump names no flow target and writes no stack "
			+ "pointer, so nothing but the missing fall-through can decline it", result);
	}

	// ------------------------------------------------------------------
	// 12. An indirect/computed call between push and pull
	// ------------------------------------------------------------------

	/**
	 * A computed call (an indirect {@code JMP} whose flow is overridden to {@code CALL}, since the
	 * 6502 has no native indirect-{@code JSR} encoding) gives the walk no address to reason about
	 * at all -- it is excluded by the SAME two guards that gate the ordinary direct-call crossing
	 * ({@code isComputed()} first), before the fall-through half is ever consulted.
	 */
	@Test
	public void indirectComputedCallBetweenPushAndPullDeclines() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "6c 00 03", true); // JMP ($0300)  -- overridden to a computed call
		builder.setBytes("0x9006", "68", true); // PLA
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000    -- would-be switchSite

		Instruction jmp = program.getListing().getInstructionAt(addr("0x9003"));
		int tx = program.startTransaction("override indirect jump to a computed call");
		try {
			jmp.setFlowOverride(FlowOverride.CALL);
		}
		finally {
			program.endTransaction(tx, true);
		}

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("a computed call gives no fall-through reasoning at all, so it cannot be "
			+ "crossed the way a direct call is", result);
	}

	// ------------------------------------------------------------------
	// 13. A call with no fall-through -- the callee does not return
	// ------------------------------------------------------------------

	/**
	 * A call whose fall-through is missing is Ghidra saying the callee does not return -- so the
	 * return-mechanism argument (reaching the fall-through is the witness the callee was
	 * balanced) never gets a witness to reach, and the walk must decline rather than assume one.
	 */
	@Test
	public void callWithNoFallThroughDeclines() throws Exception {
		builder.setBytes("0x9000", "a5 10", true); // LDA $10
		builder.setBytes("0x9002", "48", true); // PHA
		builder.setBytes("0x9003", "20 00 91", true); // JSR $9100
		builder.setBytes("0x9006", "68", true); // PLA          -- never reached by this walk
		builder.setBytes("0x9007", "8d 00 80", true); // STA $8000    -- would-be switchSite
		builder.setBytes("0x9100", "60", true); // RTS

		Instruction jsr = program.getListing().getInstructionAt(addr("0x9003"));
		int tx = program.startTransaction("mark the call non-returning");
		try {
			jsr.setFallThrough(null);
		}
		finally {
			program.endTransaction(tx, true);
		}

		boolean result = restores(addr("0x9000"), addr("0x9007"),
			mirrorsOf(0x10, BankMirrors.Kind.WRITE_THROUGH), Set.of());

		assertFalse("a call marked non-returning gives the return-mechanism argument no witness "
			+ "to rest on", result);
	}

	// ------------------------------------------------------------------
	// 14. Empty mirror set -- the cheap short-circuit
	// ------------------------------------------------------------------

	/** An empty mirror set declines before the walk even starts -- the same cheap short-circuit
	 *  every board with no derivable mirror gets, unchanged by this predicate existing at all. */
	@Test
	public void emptyMirrorSetDeclinesCheaply() throws Exception {
		builder.setBytes("0x9000", "60", true); // RTS  -- arbitrary; never inspected

		boolean result =
			restores(addr("0x9000"), addr("0x9000"), BankMirrors.none(), Set.of());

		assertFalse("an empty mirror set must decline before the walk inspects a single "
			+ "instruction", result);
	}
}
