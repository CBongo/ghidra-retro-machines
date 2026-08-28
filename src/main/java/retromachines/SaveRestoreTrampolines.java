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
		Address switchSite = helper.switchSite();
		if (switchSite == null || mirrors.isEmpty()) {
			return false;
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			return false; // cannot verify the depth model -> do not assume the favorable answer
		}
		Listing listing = program.getListing();
		// One entry per byte this walk watched being pushed, true when that byte IS the bank that
		// was live on entry.
		Deque<Boolean> saved = new ArrayDeque<>();
		boolean holdsEntryBank = false;
		boolean sawMechanismWrite = false;

		Address cursor = insideHelperEntry(helper);
		for (int i = 0; i < MAX_TRAMPOLINE_SCAN; i++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return false;
			}
			if (cursor.equals(switchSite)) {
				// The restore itself. It commits A, so the helper is a verified no-op exactly when
				// A holds the bank that was live on entry.
				Character stored = StoredValueScanner.storeRegister(instr);
				return holdsEntryBank && stored != null && stored.charValue() == 'A';
			}

			boolean modelled = true;
			switch (instr.getMnemonicString().toUpperCase()) {
				case "PHA" -> saved.push(holdsEntryBank);
				case "PLA" -> {
					if (saved.isEmpty()) {
						return false; // popping the caller's frame, or a depth this walk lost
					}
					holdsEntryBank = saved.pop();
				}
				// PHP/PLP are modelled ONLY to keep the depth honest, so an interleaved status
				// push cannot make a later PLA pop the wrong byte. A status byte is never a bank.
				case "PHP" -> saved.push(Boolean.FALSE);
				case "PLP" -> {
					if (saved.isEmpty()) {
						return false;
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
						return false;
					}
					holdsEntryBank = false; // the callee may clobber A; the stack slot is what carries
					cursor = instr.getFallThrough();
					continue;
				}
				if (switchSites.contains(instr.getMinAddress())) {
					sawMechanismWrite = true;
				}
				Address from = argumentReloadSource(instr, 'A');
				if (!sawMechanismWrite && from != null && isLiveBankMirror(mirrors, from)) {
					holdsEntryBank = true;
				}
				else if (StoredValueScanner.modifiesRegister(instr, 'A')) {
					holdsEntryBank = false;
				}
				if (writesStackPointer(instr, stackPointer)) {
					return false;
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
					return false;
				}
			}
			cursor = instr.getFallThrough();
			if (cursor == null) {
				return false; // a modelled stack op with no fall-through: off the line, decline
			}
		}
		return false;
	}

	/**
	 * Whether a load of {@code addr} reads the bank that is live right now. Only
	 * {@link BankMirrors.Kind#WRITE_THROUGH} and {@link BankMirrors.Kind#ROM_IDENTIFYING} do --
	 * the same two kinds the strategies answer from tracked state, and for the same H2 reason.
	 */
	private static boolean isLiveBankMirror(BankMirrors mirrors, Address addr) {
		return mirrors.is(addr, BankMirrors.Kind.WRITE_THROUGH) ||
			mirrors.is(addr, BankMirrors.Kind.ROM_IDENTIFYING);
	}
}
