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

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import static retromachines.HelperArgumentRecovery.argumentReloadSource;
import static retromachines.HelperArgumentRecovery.insideHelperEntry;
import static retromachines.HelperArgumentRecovery.writesStackPointer;

import retromachines.HelperDiscovery.HelperModel;

/**
 * Save/restore trampoline detection: whether a helper's NET effect on the tracked bank field is
 * nothing, because it saves the live bank on entry, switches, calls out, and restores the saved
 * bank before returning (bead grm-mej.3) -- so a call to it is a verified no-op rather than an
 * honest-but-pessimistic unknown.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Helper-call propagation" section (bead
 * grm-shnf, QR-12 increment 3b), the smallest of three siblings split along the section's natural
 * fault lines -- see {@link HelperDiscovery}'s class javadoc for the shared move rationale (zero
 * {@code this.} references, zero non-static instance fields, every member already {@code static}
 * as of grm-shnf step 2, so the cut is compile-time verbatim rather than a behavior change).
 *
 * <p>This class holds {@link #restoresEntryBank} and {@link #isLiveBankMirror}.
 * {@code BoardBankAnalyzer.added()} reaches {@link #restoresEntryBank} via {@code import static},
 * the same pattern increments 1-5 established for {@code BoardBankAnalyzer}'s other split-out
 * members.
 *
 * <p>Its one residual cross-class edge, costing an import and nothing more:
 * {@link #restoresEntryBank} calls {@link HelperArgumentRecovery#insideHelperEntry},
 * {@link HelperArgumentRecovery#argumentReloadSource} and
 * {@link HelperArgumentRecovery#writesStackPointer} in the sibling class -- the first two widened
 * from {@code private} to package-private {@code static} by this move, the third already
 * package-private since {@code StoredValueScanner} needed it.
 */
final class SaveRestoreTrampolines {

	private SaveRestoreTrampolines() {
	}

	/**
	 * How many instructions {@link #restoresEntryBank} will walk before giving up. A save/restore
	 * trampoline is a dozen instructions of frame around one inner call; a body that has not
	 * reached its own restore in this many is not the idiom, whatever else it is.
	 */
	private static final int MAX_TRAMPOLINE_SCAN = 64;

	/**
	 * Whether this helper's net effect on the tracked bank field is NOTHING, because it saves the
	 * live bank on entry, switches, calls out, and puts the saved bank back before returning
	 * (bead grm-mej.3). When true, a call to it deposits {@code ownedMask = 0} -- a verified
	 * no-op -- instead of the honest-but-pessimistic unknown that poisons the caller's state and
	 * raises a warning at every call site.
	 * <p>
	 * Ironsword/Wizards &amp; Warriors 2's {@code FUN_ffc0} is the shape, transcribed byte-exact in
	 * {@link MemoryLatchBankSwitchStrategy}'s {@code depositHelperArgument}:
	 * <pre>
	 *   FFC4: LDA $C5 / PHA       ; save the CURRENT bank shadow
	 *   FFC7: AND #$18 / ORA $C3 / STA $C5
	 *   FFCD: STA $8000           ; COMMIT -- switch to the requested bank
	 *   FFD0: JSR $FFDA           ; run the target routine IN that bank
	 *   FFD3: PLA / STA $C5
	 *   FFD6: STA $8000           ; RESTORE -- the saved shadow goes back  &lt;- switchSite
	 * </pre>
	 * The requested bank is live only for the inner call; by the time the caller resumes, the old
	 * bank is back. That is why {@code argValue} is the one answer definitely wrong here, and why
	 * this predicate is about a RELATION ("what comes out equals what went in") rather than a
	 * value -- no value domain is needed, and none is used.
	 * <p>
	 * <b>What makes the pushed byte the ENTRY bank</b> is grm-mej.2, which is exactly why this bead
	 * was blocked on it: {@code $C5} is a derived {@link BankMirrors.Kind#WRITE_THROUGH} mirror, so
	 * a load of it BEFORE any mechanism write reads the bank that was live on entry. A load after
	 * one reads the bank the helper just installed, which is a different claim entirely -- hence
	 * {@code sawMechanismWrite}. {@link BankMirrors.Kind#SAVE_SLOT} and {@link BankMirrors.Kind#INPUT}
	 * are refused for the H2 reason: they hold a bank that is deliberately NOT the live one.
	 * The composite-shadow detail handles itself -- {@code $C5}'s bits 3-4 are VRAM/mirroring, and a
	 * mirror only ever speaks for the tracked field bits, which is precisely the scope of the claim.
	 * <p>
	 * <b>CROSSING THE INNER CALL IS AN ARGUMENT, NOT AN ASSUMPTION, and the distinction is the
	 * whole soundness case.</b> The tempting phrasing is "assume a called subroutine is
	 * stack-balanced", which fails SILENTLY when it is false: the pop would report "this is the
	 * entry bank" while the hardware pulls some other byte, and {@code ownedMask = 0} emits neither
	 * a comment nor a warning. It does not need to be assumed. The pushed byte sits BELOW the
	 * return address, and {@code RTS} pops exactly the two bytes at {@code SP+1,SP+2}. A callee
	 * whose net stack delta at its {@code RTS} is non-zero pops the wrong bytes as a return address
	 * and lands somewhere other than the instruction after the {@code JSR} -- so the restore never
	 * runs. <b>Reaching the fall-through is itself the witness that the callee was balanced and the
	 * slot is intact.</b> A callee that resets {@code SP} with {@code TXS} is covered by the same
	 * argument: it does not then {@code RTS} back to you. An NMI/IRQ arriving mid-span pushes three
	 * bytes and {@code RTI} pops them. The claim is therefore conditional in exactly the way all
	 * dataflow here is -- <em>if this path executes, the callee was balanced</em>.
	 * <p>
	 * <b>Analysing the callee is not an alternative</b>, and it is worth saying so because it is the
	 * obvious next idea. Ironsword's inner call is {@code JSR $FFDA -> JMP ($00C1)}, an indirect
	 * jump into arbitrary game code: any guard that inspects the callee (no {@code TXS} in its body,
	 * balanced push/pull counts) declines here, so the payoff evaporates and the guard buys nothing
	 * the return-mechanism argument has not already given.
	 * <p>
	 * <b>The one shape this cannot see</b>, and it is far narrower than "an unbalanced callee": a
	 * routine that BOTH returns to the fall-through AND consumed the slot beneath its own return
	 * address -- i.e. popped the return address, ran, and deliberately pushed the caller's address
	 * back. That is constructed behaviour, not incidental imbalance.
	 * <p>
	 * <b>The deliberate unbalanced constructions that DO occur are handled, and not by this
	 * argument.</b> 6502 code routinely jumps by pushing {@code target-1} and executing
	 * {@code RTS} ({@code LDA #hi / PHA / LDA #lo / PHA / RTS} -- the standard indirect-jump and
	 * jump-table idiom). Inside a CALLEE it is covered above: such a routine does not return to
	 * our fall-through, so the conditional claim never applies to it. Inside THIS helper's body it
	 * is over-determined -- {@code RTS}'s own p-code decrements the stack pointer, so the
	 * {@code HelperArgumentRecovery.writesStackPointer} guard declines it before the fall-through requirement is even
	 * reached. The shape that genuinely needs the fall-through requirement is an UNRESOLVED
	 * computed jump, which writes no stack pointer and names no flow target; see the comment at
	 * that guard.
	 * <p>
	 * Everything else is refused rather than modelled. Any branch or jump abandons the walk, because
	 * "restored" is a claim that points the UNSAFE way if a path could skip the restore; a
	 * {@code PLA} with nothing pushed, a stack-pointer write, an indirect call, and a call with no
	 * fall-through all end it. Computed once per helper after mirror derivation -- never inside the
	 * fixpoint, where it would be a whole-body walk per dequeue per call site.
	 *
	 * @param switchSites every recognized mechanism-write address from pass 1
	 */
	// Package-private (not private) so BankSaveRestoreTrampolineProgramTest can call this
	// directly with a hand-built HelperModel; see the visibility note on HelperModel itself.
	static boolean restoresEntryBank(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites) {
		return restoredFieldMask(program, helper, mirrors, switchSites, Set.of()) != null;
	}

	/** As above, with the descriptor's hinted save cells (bead grm-mej.9). */
	static boolean restoresEntryBank(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites, Set<Long> saveCells) {
		return restoredFieldMask(program, helper, mirrors, switchSites, saveCells) != null;
	}

	/**
	 * The {@code restoringTrampolines} map value meaning "a call to this helper is a verified
	 * whole-state no-op"; any other value is the positioned field mask the helper alone
	 * restores (bead grm-mej.9), and a call keeps its ordinary effect on every other field.
	 * Being a map value rather than a side channel makes it impossible for a caller to pass
	 * the membership and lose the scope.
	 */
	static final int ALL_FIELDS = -1;

	/**
	 * What a stack slot, or the accumulator, is known to hold: the entry bank or not, and the
	 * live-bank mirror cell the entry bank was read from (null when not the entry bank).
	 */
	private record Holds(boolean entryBank, Address source) {
		static final Holds NO = new Holds(false, null);
	}

	/**
	 * {@link #restoresEntryBank(Program, HelperModel, BankMirrors, Set)} with the grm-mej.9
	 * additions: a HINTED save cell, and the per-site field masks needed to check a biased
	 * identity byte against the field it restores.
	 * <p>
	 * <b>Hinted save cell</b> ({@code banking.save_cells}, a per-game fact). A store of A into a
	 * cell in {@code saveCells} while A holds the entry bank records "this cell holds the entry
	 * bank"; the inner call does NOT invalidate it -- exactly what the hint licenses, the
	 * owner's fact being that the callee does not disturb the cell -- though it still clobbers
	 * every register; any OTHER write to the cell, or any write whose target is not a plain
	 * absolute address (it might be the cell), invalidates it; a later load of the cell sets
	 * "A holds the entry bank". Cells outside the hint are not tracked at all, so with no hint
	 * the walk is exactly what it was. SEED, DO NOT INJECT: the hint never supplies a bank
	 * value, only the one premise the walk cannot prove, and a wrong hint at worst leaves the
	 * claim unmade.
	 * <p>
	 * <b>Biased identity byte</b> (tmnt3's {@code LDA $A000}: {@code $20+N} on even banks N).
	 * Committing that byte back selects the same PHYSICAL bank, because the board ignores the
	 * bit {@code bias} stands for. The walk therefore accepts it as "the entry bank" only when
	 * {@link BankMirrors#restoreAliasesLiveBank} holds (a verified membership hint excludes the
	 * junk odd banks) and every mechanism write on the walk, including the restoring commit,
	 * writes exactly the field that byte's window belongs to -- a helper that also switched some
	 * OTHER field and did not put it back is not a no-op. The claim is "the bank the caller had
	 * is the bank the caller gets back"; the tracked field value may differ by the ignored bit,
	 * which is why the deposit is {@code ownedMask = 0} (the caller's state is left untouched).
	 * <p>
	 * <b>Early-out branch</b> (tmnt3's {@code PHA / LDA $27 / BNE out}, out = {@code PLA / RTS}).
	 * Only when {@code saveCells} is non-empty (the game has opted in), a forward conditional
	 * branch is allowed if its taken path is itself a no-op: it reaches {@code RTS} within a few
	 * instructions with this helper's own stack depth back at zero, without a call, a memory
	 * write, a stack-pointer write other than that {@code RTS}, a mechanism write, or any other
	 * branch. Anything else still declines.
	 *
	 * @param saveCells CPU offsets of the descriptor's hinted save cells
	 * @return null when the helper is not a restoring trampoline; 0 when a call to it is a
	 *         whole-state no-op (every pre-grm-mej.9 claim); a positive positioned field mask
	 *         when it only restores that field (a biased identity byte -- see above)
	 */
	static Integer restoredFieldMask(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites, Set<Long> saveCells) {
		Address switchSite = helper.switchSite();
		if (switchSite == null || mirrors.isEmpty()) {
			return null;
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			return null; // cannot verify the depth model -> do not assume the favorable answer
		}
		Listing listing = program.getListing();
		// One entry per byte this walk watched being pushed.
		Deque<Holds> saved = new ArrayDeque<>();
		Holds a = Holds.NO;
		// Hinted save cells currently known to hold the entry bank, by CPU offset.
		Map<Long, Address> cells = new HashMap<>();
		Set<Address> mechanismWritesSeen = new HashSet<>();
		boolean sawMechanismWrite = false;

		Address cursor = insideHelperEntry(helper);
		for (int i = 0; i < MAX_TRAMPOLINE_SCAN; i++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return null;
			}
			if (cursor.equals(switchSite)) {
				// The restore itself. It commits A, so the helper is a verified no-op exactly when
				// A holds the bank that was live on entry.
				Character stored = StoredValueScanner.storeRegister(instr);
				if (!(a.entryBank() && stored != null && stored.charValue() == 'A')) {
					return null;
				}
				mechanismWritesSeen.add(cursor);
				return fieldScopedMask(program, helper, mirrors, a.source(), mechanismWritesSeen);
			}

			boolean modelled = true;
			switch (instr.getMnemonicString().toUpperCase()) {
				case "PHA" -> saved.push(a);
				case "PLA" -> {
					if (saved.isEmpty()) {
						return null; // popping the caller's frame, or a depth this walk lost
					}
					a = saved.pop();
				}
				// PHP/PLP are modelled ONLY to keep the depth honest, so an interleaved status
				// push cannot make a later PLA pop the wrong byte. A status byte is never a bank.
				case "PHP" -> saved.push(Holds.NO);
				case "PLP" -> {
					if (saved.isEmpty()) {
						return null;
					}
					saved.pop();
				}
				default -> modelled = false;
			}

			if (!modelled) {
				if (instr.getFlowType().isCall()) {
					// The inner call. Allowed, and the pushed slot survives it -- see the javadoc's
					// return-mechanism argument. Two guards first, because that argument is void
					// when control demonstrably does not come back: a computed call gives no
					// fall-through reasoning at all, and a missing fall-through is Ghidra saying
					// the callee does not return.
					if (instr.getFlowType().isComputed() || instr.getFallThrough() == null) {
						return null;
					}
					a = Holds.NO; // the callee may clobber A; the stack slot (and a hinted cell) carry
					cursor = instr.getFallThrough();
					continue;
				}
				if (switchSites.contains(instr.getMinAddress())) {
					sawMechanismWrite = true;
					mechanismWritesSeen.add(instr.getMinAddress());
				}
				Address from = argumentReloadSource(instr, 'A');
				if (!sawMechanismWrite && from != null && isLiveBankMirror(mirrors, from)) {
					a = new Holds(true, from);
				}
				else if (from != null && cells.containsKey(from.getOffset())) {
					a = new Holds(true, cells.get(from.getOffset()));
				}
				else if (StoredValueScanner.modifiesRegister(instr, 'A')) {
					a = Holds.NO;
				}
				if (!saveCells.isEmpty() && StoredValueScanner.writesMemory(instr)) {
					Address target = StoredValueScanner.plainAbsoluteTarget(instr);
					if (target == null) {
						cells.clear(); // an indexed/indirect write might be the cell
					}
					else if (saveCells.contains(target.getOffset())) {
						Character stored = StoredValueScanner.storeRegister(instr);
						if (stored != null && stored.charValue() == 'A' && a.entryBank()) {
							cells.put(target.getOffset(), a.source());
						}
						else {
							cells.remove(target.getOffset());
						}
					}
				}
				if (writesStackPointer(instr, stackPointer)) {
					return null;
				}
				// A forward conditional branch whose taken path is itself a no-op exit (see the
				// javadoc). Opt-in only: the game has stated save cells.
				if (!saveCells.isEmpty() && isForwardConditionalBranch(instr)) {
					if (!takenPathIsNoOpExit(program, instr.getFlows()[0], saved.size(),
						switchSites, stackPointer)) {
						return null;
					}
					cursor = instr.getFallThrough();
					continue;
				}
				// The walk may only advance along a REAL fall-through, and the test is stated that
				// way round on purpose: "has no outgoing flows" is not the same property and does
				// not cover an UNRESOLVED computed jump, which writes no stack pointer and names
				// no flow target, so every other guard here is blind to it. Left to a flows-based
				// test the walk would march straight past one into code that is not on this path
				// and could find a PLA or the restore site sitting there.
				//
				// Requiring a fall-through refuses that plus resolved jumps and conditional
				// branches (whose other edge could skip the restore, making "no-op" confidently
				// wrong). Note the 6502 push-target-and-return idiom -- LDA #hi / PHA / LDA #lo /
				// PHA / RTS, the ordinary way this CPU does an indirect jump -- is caught here
				// too, but it is over-determined rather than a case for this guard: RTS's own
				// p-code decrements SP, so writesStackPointer above already declines it. Do not
				// read the test that covers it as pinning this line specifically.
				if (instr.getFlows().length > 0 || instr.getFallThrough() == null) {
					return null;
				}
			}
			cursor = instr.getFallThrough();
			if (cursor == null) {
				return null; // a modelled stack op with no fall-through: off the line, decline
			}
		}
		return null;
	}

	/**
	 * A stated {@code high == low + offset} pairing between two board state fields (bead
	 * grm-mej.10, {@code banking.paired_fields}), as positioned masks.
	 */
	record FieldPairing(int highMask, int lowMask, int offset) {
	}

	/**
	 * {@link #restoredFieldMask(Program, HelperModel, BankMirrors, Set, Set)} with the
	 * descriptor's stated field pairings (bead grm-mej.10). Whatever the pairing-free walk
	 * proves is returned unchanged; only when it declines, the game states pairings and save
	 * cells, is the {@link #pairedRestoredFieldMask} walk tried. With no pairings this IS the
	 * five-argument form.
	 */
	static Integer restoredFieldMask(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites, Set<Long> saveCells,
			java.util.List<FieldPairing> pairings) {
		Integer plain = restoredFieldMask(program, helper, mirrors, switchSites, saveCells);
		if (plain != null || pairings.isEmpty() || saveCells.isEmpty()) {
			return plain;
		}
		BankStackBrackets.Restore r = pairedRestoredFieldMask(program, helper, mirrors,
			switchSites, saveCells, pairings);
		return r == null ? null : r.restoredMask();
	}

	/**
	 * The computed restore of a helper that only the pairing-aware walk proves (null when the
	 * helper is a pairing-free claim or no claim): the engine folds it per call, computing the
	 * paired field from the low field instead of leaving both at their pre-call values.
	 */
	static BankStackBrackets.Restore pairedRestore(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites, Set<Long> saveCells,
			java.util.List<FieldPairing> pairings) {
		if (pairings.isEmpty() || saveCells.isEmpty() ||
			restoredFieldMask(program, helper, mirrors, switchSites, saveCells) != null) {
			return null;
		}
		return pairedRestoredFieldMask(program, helper, mirrors, switchSites, saveCells,
			pairings);
	}

	/** What a register is known to hold: the entry bank plus {@code plus}, from {@code source}. */
	private record Held(boolean entry, Address source, int plus) {
		static final Held NO = new Held(false, null, 0);
	}

	/**
	 * The two-register, pairing-aware restoring-trampoline walk (bead grm-mej.10; tmnt3's
	 * {@code FUN_9169}, grm-mej.17):
	 * <pre>
	 *   LDA $A000 / STA $F0            ; save the live R7 identity byte in the hinted cell
	 *   LDX #$3A / ... / STX $8001     ; R7 = $3A
	 *   JSR $A1A1                      ; inner call
	 *   LDX $F0 / ... / STX $8001      ; R7 := saved identity               (low, +0)
	 *   INX / ... / STX $8001          ; R6 := saved identity + 1           (high, +1)
	 * </pre>
	 * It follows the same rules as the single-register walk -- hinted cells survive the inner
	 * call, a biased byte needs {@link BankMirrors#restoreAliasesLiveBank}, the early-out branch
	 * is allowed for a game that stated save cells -- and differs in three ways: A and X are both
	 * tracked (with an {@code INX} offset), it does NOT stop at the helper's recorded switch site
	 * but runs to the {@code RTS} with the helper's own stack depth back at zero, and the claim
	 * is the set of fields whose LAST data commit is the saved byte (offset 0 into the identity
	 * cell's own field, or the stated offset into a paired {@code high} field). A data commit
	 * into any field not so restored declines the whole helper: it switched something it did not
	 * put back.
	 */
	private static BankStackBrackets.Restore pairedRestoredFieldMask(Program program, HelperModel helper,
			BankMirrors mirrors, Set<Address> switchSites, Set<Long> saveCells,
			java.util.List<FieldPairing> pairings) {
		if (helper.switchSite() == null || helper.strategy() == null || mirrors.isEmpty()) {
			return null;
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			return null;
		}
		Listing listing = program.getListing();
		Deque<Held> saved = new ArrayDeque<>();
		Held a = Held.NO;
		Held x = Held.NO;
		Map<Long, Address> cells = new HashMap<>();
		boolean sawMechanismWrite = false;
		Map<Integer, Integer> lastCommit = new java.util.LinkedHashMap<>();
		Address source = null;

		Address cursor = insideHelperEntry(helper);
		for (int i = 0; i < MAX_TRAMPOLINE_SCAN; i++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return null;
			}
			String mnemonic = instr.getMnemonicString().toUpperCase();
			if (mnemonic.equals("RTS")) {
				if (!saved.isEmpty() || lastCommit.isEmpty() || source == null) {
					return null;
				}
				return pairedClaim(mirrors, source, lastCommit, pairings);
			}
			boolean modelled = true;
			switch (mnemonic) {
				case "PHA" -> saved.push(a);
				case "PLA" -> {
					if (saved.isEmpty()) {
						return null;
					}
					a = saved.pop();
				}
				case "PHP" -> saved.push(Held.NO);
				case "PLP" -> {
					if (saved.isEmpty()) {
						return null;
					}
					saved.pop();
				}
				default -> modelled = false;
			}
			if (!modelled) {
				if (instr.getFlowType().isCall()) {
					if (instr.getFlowType().isComputed() || instr.getFallThrough() == null) {
						return null;
					}
					a = Held.NO;
					x = Held.NO;
					cursor = instr.getFallThrough();
					continue;
				}
				if (switchSites.contains(instr.getMinAddress())) {
					sawMechanismWrite = true;
					Character stored = StoredValueScanner.storeRegister(instr);
					int committed = helper.strategy().bankFieldCommittedBySite(program, instr);
					if (stored == null || committed < 0) {
						return null;
					}
					if (committed > 0) {
						int field = (committed << helper.lsb()) & helper.effectMask();
						Held h = stored == 'A' ? a : stored == 'X' ? x : Held.NO;
						if (h.entry()) {
							if (source != null && !source.equals(h.source())) {
								return null;
							}
							source = h.source();
						}
						lastCommit.put(field, h.entry() ? h.plus() : -1);
					}
				}
				Held newA = null;
				Held newX = null;
				if (mnemonic.equals("LDA") || mnemonic.equals("LDX")) {
					char reg = mnemonic.charAt(2);
					Address from = argumentReloadSource(instr, reg);
					Held loaded = Held.NO;
					if (from != null && !sawMechanismWrite && isLiveBankMirror(mirrors, from)) {
						loaded = new Held(true, from, 0);
					}
					else if (from != null && cells.containsKey(from.getOffset())) {
						loaded = new Held(true, cells.get(from.getOffset()), 0);
					}
					if (reg == 'A') {
						newA = loaded;
					}
					else {
						newX = loaded;
					}
				}
				else if (mnemonic.equals("INX")) {
					newX = x.entry() ? new Held(true, x.source(), x.plus() + 1) : Held.NO;
				}
				else {
					if (StoredValueScanner.modifiesRegister(instr, 'A')) {
						newA = Held.NO;
					}
					if (StoredValueScanner.modifiesRegister(instr, 'X')) {
						newX = Held.NO;
					}
				}
				if (StoredValueScanner.writesMemory(instr)) {
					Address target = StoredValueScanner.plainAbsoluteTarget(instr);
					if (target == null) {
						cells.clear();
					}
					else if (saveCells.contains(target.getOffset())) {
						Character stored = StoredValueScanner.storeRegister(instr);
						Held h = stored == null ? Held.NO : stored == 'A' ? a : stored == 'X' ? x
								: Held.NO;
						if (h.entry() && h.plus() == 0) {
							cells.put(target.getOffset(), h.source());
						}
						else {
							cells.remove(target.getOffset());
						}
					}
				}
				if (newA != null) {
					a = newA;
				}
				if (newX != null) {
					x = newX;
				}
				if (writesStackPointer(instr, stackPointer)) {
					return null;
				}
				if (isNoOpExitBranch(instr)) {
					if (!takenPathIsNoOpExit(program, instr.getFlows()[0], saved.size(),
						switchSites, stackPointer)) {
						return null;
					}
					cursor = instr.getFallThrough();
					continue;
				}
				if (instr.getFlows().length > 0 || instr.getFallThrough() == null) {
					return null;
				}
			}
			cursor = instr.getFallThrough();
			if (cursor == null) {
				return null;
			}
		}
		return null;
	}

	/** The positioned fields whose last commit restores {@code source}'s field, or null. */
	private static BankStackBrackets.Restore pairedClaim(BankMirrors mirrors, Address source,
			Map<Integer, Integer> lastCommit, java.util.List<FieldPairing> pairings) {
		BoardDescriptorModel.FieldSpec low = mirrors.identifyingField(source);
		if (low == null || !mirrors.restoreAliasesLiveBank(source)) {
			return null;
		}
		int mask = 0;
		java.util.List<FieldPairing> highs = new java.util.ArrayList<>();
		for (FieldPairing p : pairings) {
			if (p.lowMask() == low.positionedMask()) {
				highs.add(p);
			}
		}
		for (Map.Entry<Integer, Integer> commit : lastCommit.entrySet()) {
			int field = commit.getKey();
			int plus = commit.getValue();
			boolean restores = plus == 0 && field == low.positionedMask() ||
				plus > 0 && pairings.stream().anyMatch(p -> p.highMask() == field &&
					p.lowMask() == low.positionedMask() && p.offset() == plus);
			if (!restores) {
				return null;
			}
			mask |= field;
		}
		return mask == 0 ? null : new BankStackBrackets.Restore(mask, low.positionedMask(),
			mirrors.identifyingEncoding(source), highs);
	}

	/**
	 * For a BIASED identity byte (grm-mej.9) as the source of the restored value: the byte must be
	 * trusted to alias the live bank, and every mechanism write on the walk must be either a
	 * write that commits no bank (a register select) or a bank commit into exactly the field the
	 * byte's window belongs to, as the helper's own body establishes
	 * ({@link BankSwitchStrategy#bankFieldCommittedBySite}). Returns that positioned field mask,
	 * or {@code null} to refuse. Any other source (a write-through shadow, an identity or
	 * shift-encoded ROM byte) is accepted exactly as before this bead, as a whole-state no-op
	 * ({@code 0}).
	 */
	private static Integer fieldScopedMask(Program program, HelperModel helper,
			BankMirrors mirrors, Address source, Set<Address> mechanismWrites) {
		BankMirrors.IdentifyingEncoding encoding =
			source == null ? null : mirrors.identifyingEncoding(source);
		if (encoding == null || !encoding.isBiased()) {
			return 0;
		}
		BoardDescriptorModel.FieldSpec field = mirrors.identifyingField(source);
		if (!mirrors.restoreAliasesLiveBank(source) || field == null ||
			helper.strategy() == null) {
			return null;
		}
		int fieldMask = field.positionedMask();
		boolean committedField = false;
		for (Address site : mechanismWrites) {
			Instruction instr = program.getListing().getInstructionAt(site);
			if (instr == null) {
				return null;
			}
			int committed = helper.strategy().bankFieldCommittedBySite(program, instr);
			if (committed < 0) {
				return null;
			}
			if (committed == 0) {
				continue;
			}
			if (((committed << helper.lsb()) & helper.effectMask()) != fieldMask) {
				return null; // commits a bank into some OTHER field, which nothing here restores
			}
			committedField = true;
		}
		return committedField ? fieldMask : null;
	}

	/**
	 * A conditional branch with one target and a fall-through, in EITHER direction (bead
	 * grm-mej.10: tmnt3's FUN_9169 early-outs with {@code BNE $9168}, a backward branch onto a
	 * shared {@code RTS}). Sound without the forward requirement because the taken path is
	 * accepted only by {@link #takenPathIsNoOpExit}, which follows straight-line code to an
	 * {@code RTS} within a few instructions, so no loop can hide behind the direction.
	 */
	private static boolean isNoOpExitBranch(Instruction instr) {
		return instr.getFlowType().isConditional() && !instr.getFlowType().isCall() &&
			!instr.getFlowType().isComputed() && instr.getFlows().length == 1 &&
			instr.getFallThrough() != null;
	}

	private static boolean isForwardConditionalBranch(Instruction instr) {
		return instr.getFlowType().isConditional() && !instr.getFlowType().isCall() &&
			!instr.getFlowType().isComputed() && instr.getFlows().length == 1 &&
			instr.getFallThrough() != null &&
			instr.getFlows()[0].compareTo(instr.getMinAddress()) > 0;
	}

	/** How many instructions {@link #takenPathIsNoOpExit} follows. */
	private static final int MAX_EXIT_PATH = 8;

	/**
	 * Whether the path starting at {@code target} is itself a no-op: straight-line code that
	 * pops back to this helper's entry stack depth and returns, touching no memory, calling
	 * nothing, and writing no mechanism. {@code depth} is the number of bytes this helper has
	 * pushed so far.
	 */
	private static boolean takenPathIsNoOpExit(Program program, Address target, int depth,
			Set<Address> switchSites, Register stackPointer) {
		Listing listing = program.getListing();
		Address cursor = target;
		for (int i = 0; i < MAX_EXIT_PATH; i++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return false;
			}
			String mnemonic = instr.getMnemonicString().toUpperCase();
			switch (mnemonic) {
				case "RTS" -> {
					return depth == 0;
				}
				case "PHA", "PHP" -> depth++;
				case "PLA", "PLP" -> {
					if (depth == 0) {
						return false;
					}
					depth--;
				}
				default -> {
					if (instr.getFlowType().isCall() || switchSites.contains(instr.getMinAddress()) ||
						StoredValueScanner.writesMemory(instr) ||
						writesStackPointer(instr, stackPointer) || instr.getFlows().length > 0) {
						return false;
					}
				}
			}
			cursor = instr.getFallThrough();
			if (cursor == null) {
				return false;
			}
		}
		return false;
	}

	/**
	 * Whether a load of {@code addr} reads the bank that is live right now. Only
	 * {@link BankMirrors.Kind#WRITE_THROUGH} and {@link BankMirrors.Kind#ROM_IDENTIFYING} do --
	 * the same two kinds the strategies answer from tracked state, and for the same H2 reason.
	 */
	static boolean isLiveBankMirror(BankMirrors mirrors, Address addr) {
		return mirrors.is(addr, BankMirrors.Kind.WRITE_THROUGH) ||
			mirrors.is(addr, BankMirrors.Kind.ROM_IDENTIFYING);
	}
}
